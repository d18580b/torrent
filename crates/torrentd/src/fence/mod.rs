//! Fencing a vpn profile, and the resume gates every path keeps to while one
//! stands.
//!
//! A fence marks the profile `vpn_down` and pauses every torrent it holds
//! ([`fence`]). Two things put one on: the VPN monitor
//! ([`crate::vpn_monitor`]), whose verdict on a tunnel is the reason, and the
//! kill-switch watch, through [`KillSwitchFence`], which also lifts its own.
//! Adds and single resumes that race a fence re-check it afterwards
//! ([`hold_if_fenced`], [`resume_unless_fenced`]); bulk resumes are paced
//! ([`lift`]); and the tasks that fence stop where the shutdown chooses
//! ([`stop`]).

use std::net::IpAddr;
use std::sync::atomic;
use std::sync::Arc;

use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentPhase;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ProfileStatus;
use crate::profile_registry::ResumeGate;
use crate::vpn;
use crate::vpn_monitor::recovery_check;
use crate::vpn_monitor::DownReason;
use crate::vpn_monitor::Prober;

mod lift;
mod stop;
#[cfg(test)]
mod tests;

pub(crate) use lift::resume_paced;
#[cfg(test)]
pub(crate) use lift::spawn_lift;
pub(crate) use lift::spawn_run;
pub(crate) use lift::Lift;
pub(crate) use lift::OnlinePace;
#[cfg(test)]
pub(crate) use lift::Resumed;
pub(crate) use stop::FencingGate;
pub(crate) use stop::FencingStop;
pub(crate) use stop::FencingStopped;

/// The `reason` of `profile_vpn_fenced_total` for a fence [`KillSwitchFence`]
/// put on: the kill switch was not in force, whatever the tunnel's health.
pub(crate) const KILL_SWITCH_FENCE_REASON: &str = "kill_switch";

/// Fence `entry`: mark it `vpn_down`, then pause every torrent the state map
/// holds in it. Returns how many it paused.
///
/// The mark goes first. A torrent the session holds but the state map does not
/// yet (its `add_torrent_alert` is still queued) is not in the walk below; the
/// alert loop's add handler pauses it on insert once it reads the profile as
/// fenced, and adds re-check after `add_torrent` ([`hold_if_fenced`]). Marking
/// after the walk left a window in which neither side paused it. The
/// `SeqCst` fence pairs with the one in the add handler between its insert and
/// its read of the mark, so at least one side sees the other.
///
/// The pauses are not paced, unlike every bulk resume ([`resume_paced`]):
/// stopping the profile's traffic is the point of a fence, and pacing it
/// would leave most of a large profile seeding for minutes over a tunnel that
/// is gone. Each paused torrent sends its trackers a `stopped` announce, so
/// fencing tens of thousands of torrents sends that many announces within a
/// second or so, and can overflow the session's alert queue
/// (`TorrentdAlertQueueOverflow`). Its lift is paced, which is the burst a
/// flapping tunnel or ruleset would otherwise repeat at full size.
///
/// The generation is bumped in the same update that marks the profile and
/// starts the count over, so the boot scans, which can read the profile
/// between this fence's mark and its walk, never see the new mark under the
/// old generation ([`ProfileHealth::fence_generation`]).
///
/// [`ProfileHealth::fence_generation`]: crate::profile_registry::ProfileHealth::fence_generation
pub(crate) fn fence(
    entry: &ProfileEntry,
    state: &StateMap,
    current: Option<IpAddr>,
    reason: DownReason,
    metrics: &dyn MetricsSink,
) -> u64 {
    mark_fenced(entry, current, reason.as_str(), metrics);
    walk_fenced(entry, state, metrics)
}

/// The first half of [`fence`]: mark `entry` `vpn_down` under a new fence
/// generation, for `reason`, starting its `paused_for_vpn` count over.
pub(crate) fn mark_fenced(
    entry: &ProfileEntry,
    current: Option<IpAddr>,
    reason: &'static str,
    metrics: &dyn MetricsSink,
) {
    mark_fenced_reading(entry, current, reason, metrics, || ());
}

/// [`mark_fenced`], running `read` once the mark is in and before what a
/// pause or resume noted is forgotten, and returning what it read.
///
/// For the kill-switch fence's re-read of what is running
/// ([`KillSwitchFence`]): a resume that read the profile as not fenced
/// ([`resume_unless_fenced`]) noted itself before the `SeqCst` fence below,
/// so a read here sees its note, which the forget after it would lose.
fn mark_fenced_reading<R>(
    entry: &ProfileEntry,
    current: Option<IpAddr>,
    reason: &'static str,
    metrics: &dyn MetricsSink,
    read: impl FnOnce() -> R,
) -> R {
    let labels = [("profile_id", entry.id().as_str())];
    // `profile_vpn_tunnel_up` goes to 0 with the mark, under the same lock,
    // whoever fences: the kill-switch watch's fence left it at the monitor's
    // last 1, and the monitor never polls a fenced profile to correct it, so
    // a profile its lift left fenced read as healthy to every alert on it.
    // The monitor's healthy poll writes 1 under this lock and skips a profile
    // that reads `vpn_down`, so it never lands on a fence once this one is in.
    // The kill-switch lift writes 1 in the update that returns a `vpn_down`
    // profile to `Active`; it is serialised with the kill-switch fence by
    // `KillSwitchFence::fenced`, held from its mark check through that update.
    entry.update_health(|h| {
        h.status = ProfileStatus::VpnDown;
        h.fence_reason = Some(reason);
        h.tunnel_ip = current;
        h.start_paused_for_vpn_over();
        h.fence_generation += 1;
        metrics.set_gauge("profile_vpn_tunnel_up", 0.0, &labels);
    });
    atomic::fence(atomic::Ordering::SeqCst);
    let read = read();
    // Every torrent is paused by the walk that follows, so what a pause or resume before this
    // noted no longer holds: the kill-switch fence read it in `read`, and
    // a resume noted after the mark sees it and pauses again.
    entry.forget_noted();
    read
}

/// The second half of [`fence`]: pause every torrent the state map holds in
/// `entry`, adding each pause that took to the count, and return how many
/// took.
pub(crate) fn walk_fenced(
    entry: &ProfileEntry,
    state: &StateMap,
    metrics: &dyn MetricsSink,
) -> u64 {
    let profile_id = entry.id();
    let labels = [("profile_id", profile_id.as_str())];
    let mut paused = Vec::new();
    for h in state.handles_for_profile(profile_id) {
        match entry.engine.pause_torrent(h) {
            Ok(()) => paused.push(h.infohash),
            // A torrent the fence did not pause keeps seeding from a
            // profile whose tunnel is down — the one thing fencing is
            // for. The failure was discarded, so nothing said so.
            Err(err) => {
                error!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %profile_id,
                    infohash = %h.infohash,
                    error.cause = %err,
                    "could not pause a torrent while fencing the profile",
                );
                metrics.inc_counter("profile_fence_pause_errors_total", &labels);
            }
        }
    }
    // Added, not assigned: the boot scans' fence (`startup::scan_fence::ScanFence`) acts
    // as soon as it sees the fence's mark, which may be before this walk ends,
    // and adds what it paused to the same count. A torrent it already counted
    // under this fence is not counted again, whichever of the two paused it
    // first. Both writers set the gauge from the sum under the health lock,
    // so the last write is the full sum.
    let walked = paused.len() as u64;
    entry.update_health(|h| {
        h.count_paused_for_vpn(paused);
        metrics.set_gauge(
            "profile_torrents_paused_vpn_down",
            h.paused_for_vpn as f64,
            &labels,
        );
    });
    walked
}

/// Every torrent the state map holds in `profile_id`, each with whether its
/// own paused flag was clear at its last state update.
fn reported_running(profile_id: &ProfileId, state: &StateMap) -> Vec<(TorrentHandle, bool)> {
    state
        .handles_for_profile(profile_id)
        .into_iter()
        .map(|h| {
            let running = state
                .get(&h.infohash)
                .is_some_and(|s| s.phase != TorrentPhase::Paused);
            (h, running)
        })
        .collect()
}

/// Every torrent the state map holds in `entry`, each with whether it is
/// running now: its last state update, overridden by a pause or resume made
/// since that no update has reported yet ([`ProfileEntry::running`]).
///
/// What the kill-switch fence's lift and a set-online's pace resume. The
/// state update comes every couple of seconds, and the kill-switch watch
/// fences and lifts inside one check, so read alone it undid a pause made
/// just before and left a resume made just before paused.
fn running_now(entry: &ProfileEntry, state: &StateMap) -> Vec<(TorrentHandle, bool)> {
    entry.running(reported_running(entry.id(), state))
}

/// The kill-switch watch's fence ([`vpn::killswitch::watch`]): while the
/// nftables backstop is not in force as installed, every vpn profile is fenced
/// exactly as this monitor fences one whose tunnel is down — marked `vpn_down`,
/// every torrent paused, adds held — since each is then seeding with nothing
/// but the source bind between it and the bare interface.
///
/// The watch lifts it only once the ruleset checks intact again. Lifting
/// undoes only this fence: a profile the monitor had fenced already is not
/// touched, a profile set online by the operator meanwhile is left as it is,
/// and one whose tunnel no longer passes [`recovery_check`] stays fenced for
/// the operator, as any fence on a failing tunnel does. Only the torrents that
/// were not paused when it fenced are resumed, so a torrent the operator had
/// paused stays paused. So does one paused while the fence stands, by the
/// operator or for a failed verification, and a pause of the whole profile
/// then leaves all of it paused: the fence opens a resume gate on the profile
/// as it fences ([`FenceRecord::gate`]), which every such pause closes
/// ([`ProfileEntry::exclude_from_resumes`], [`ProfileEntry::halt_resumes`]),
/// and its lift keeps to it. A profile set online and then fenced again
/// resumes what was running at that latest fence.
///
/// The lift resumes them a batch per
/// [`REANNOUNCE_PACE`](crate::pacing::REANNOUNCE_PACE) ([`spawn_lift`](lift::spawn_lift)),
/// from a task that outlives the check that lifted it. A
/// fence that lands before that task ends stops it, and the next lift
/// resumes the torrents it had not reached as well as what was running.
pub(crate) struct KillSwitchFence {
    profiles: Arc<ProfileRegistry>,
    state: Arc<StateMap>,
    metrics: Arc<PromSink>,
    probe: Prober,
    /// The profiles this fence marked `vpn_down`, each with the torrents it
    /// found running and paused.
    fenced: parking_lot::Mutex<Fenced>,
    /// Run by [`vpn::killswitch::Fence::fence_all`] for each profile it
    /// fences, after its first read of what is running and before its mark,
    /// so a test can land a resume in that window.
    #[cfg(test)]
    before_mark: std::sync::OnceLock<BeforeMark>,
}

/// [`KillSwitchFence`]'s test hook between its read and its mark.
#[cfg(test)]
type BeforeMark = Box<dyn Fn(&KillSwitchFence) + Send + Sync>;

/// [`KillSwitchFence`]'s record, under its lock.
#[derive(Default)]
struct Fenced {
    /// How many profiles it has ever marked, the last mark's number.
    marks: u64,
    profiles: std::collections::HashMap<ProfileId, FenceRecord>,
}

/// One profile [`KillSwitchFence`] holds fenced.
pub(crate) struct FenceRecord {
    /// Which mark put the profile under this fence, unique to it: a record
    /// with a number its reader has not seen is a fence that landed since,
    /// though a lift came and went between the two reads.
    pub(crate) mark: u64,
    /// What its lift resumes.
    pub(crate) handles: Vec<TorrentHandle>,
    /// Opened on the profile before the fence read what was running, and
    /// kept to by its lift's run ([`ProfileEntry::begin_resume_with`]): a
    /// torrent paused since is left out of [`FenceRecord::handles`] when the
    /// lift reaches it, and a pause of the whole profile since halts the lift
    /// before it resumes any.
    gate: Arc<ResumeGate>,
}

impl KillSwitchFence {
    pub(crate) fn new(
        profiles: Arc<ProfileRegistry>,
        state: Arc<StateMap>,
        metrics: Arc<PromSink>,
        probe: Prober,
    ) -> Self {
        Self {
            profiles,
            state,
            metrics,
            probe,
            fenced: Default::default(),
            #[cfg(test)]
            before_mark: std::sync::OnceLock::new(),
        }
    }

    /// Run `hold` with this fence's record of what its lift resumes in
    /// `profile_id`: `Some` while this fence holds the profile, `None` while
    /// it does not.
    ///
    /// For the boot scans (`startup::scan_fence::ScanFence`), which add torrents no
    /// state-map walk reaches: a fence that lands mid-scan records none of
    /// them, so its lift would leave paused every one the scans paused for it.
    /// `hold` runs under the lock [`vpn::killswitch::Fence::fence_all`] and
    /// [`vpn::killswitch::Fence::lift`] each hold from their first mark to
    /// their last, so this fence neither marks nor lifts the profile between
    /// `hold`'s read of its status and its record. The record's
    /// [`FenceRecord::mark`] tells `hold` whether the fence is the one it saw
    /// last, so a lift and a new fence between two calls are not mistaken for
    /// the fence still standing.
    pub(crate) fn with_record<R>(
        &self,
        profile_id: &ProfileId,
        hold: impl FnOnce(Option<&mut FenceRecord>) -> R,
    ) -> R {
        hold(self.fenced.lock().profiles.get_mut(profile_id))
    }

    /// Run `hold`, an add path's check and pause of `handle` just added to
    /// `profile_id`, under this fence's lock, and record `handle` for the
    /// lift where `hold` answers that it found the profile fenced and this
    /// fence holds it.
    ///
    /// For the runtime add paths ([`hold_if_fenced`], and the add handler
    /// through `torrentd_engine::FenceHold`). A torrent whose add lands after
    /// [`vpn::killswitch::Fence::fence_all`]'s walk of the state map, or
    /// that the walk read as paused, is otherwise paused with no record, and
    /// stays paused once the lift resumes the rest. Under the lock, this
    /// fence neither marks nor lifts the profile between `hold`'s read of its
    /// status and the record, so a lift either resumed the profile before
    /// `hold` read it (and `hold` pauses nothing) or finds the handle in its
    /// record. Recorded whether or not the pause took, as the boot scans do.
    /// A handle recorded twice, by both add paths or by them and the walk,
    /// is resumed once: the lift drops repeats.
    pub(crate) fn hold_recorded(
        &self,
        profile_id: &ProfileId,
        handle: TorrentHandle,
        hold: impl FnOnce() -> bool,
    ) {
        self.with_record(profile_id, |record| {
            if hold() {
                if let Some(record) = record {
                    record.handles.push(handle);
                }
            }
        });
    }
}

impl vpn::killswitch::Fence for KillSwitchFence {
    fn fence_all_for(&self, cause: vpn::killswitch::FenceCause) {
        let (reason, message) = match cause {
            vpn::killswitch::FenceCause::NotInForce => (
                KILL_SWITCH_FENCE_REASON,
                "network kill switch not in force; paused all profile torrents until it is",
            ),
            vpn::killswitch::FenceCause::Unverifiable => (
                DownReason::ProbeUnavailable.as_str(),
                "network kill switch could not be checked; paused all profile torrents until a \
                 check finds it in force",
            ),
        };
        let mut fenced = self.fenced.lock();
        for e in self
            .profiles
            .iter()
            .filter(|e| e.config.vpn_interface().is_some())
        {
            let health = e.health();
            if health.status == ProfileStatus::VpnDown {
                continue;
            }
            // Opened before the read of what is running, so a pause that
            // lands after that read, too late to read as paused, still closes
            // it, and the lift does not resume what it paused.
            let gate = e.open_gate();
            let mut running: Vec<TorrentHandle> = running_now(e, &self.state)
                .into_iter()
                .filter_map(|(h, running)| running.then_some(h))
                .collect();
            // A lift still resuming this profile a batch at a time is stopped
            // here, and every torrent it was asked to resume is this fence's
            // to resume too: those it has not reached yet read as paused
            // above, and would otherwise stay paused after the next lift.
            let unfinished = e.take_resume().unwrap_or_default();
            #[cfg(test)]
            if let Some(hook) = self.before_mark.get() {
                hook(self);
            }
            // Read again once the mark is in: a resume that landed after the
            // read above read the profile as not fenced, answered that it
            // resumed, and noted it; the walk below pauses it, and only this
            // read keeps it in the record for the lift. The mark forgets
            // that note, so this read runs inside it.
            let marked_running =
                mark_fenced_reading(e, health.tunnel_ip, reason, self.metrics.as_ref(), || {
                    running_now(e, &self.state)
                });
            let mut seen: std::collections::HashSet<TorrentHandle> =
                running.iter().copied().collect();
            let newly_running = marked_running
                .into_iter()
                .filter_map(|(h, running)| running.then_some(h));
            running.extend(newly_running.chain(unfinished).filter(|h| seen.insert(*h)));
            let paused = walk_fenced(e, &self.state, self.metrics.as_ref());
            // Not fenced now, so any earlier record is one the operator's lift
            // already undid: what is running now replaces it.
            fenced.marks += 1;
            let mark = fenced.marks;
            fenced.profiles.insert(
                e.id().clone(),
                FenceRecord {
                    mark,
                    handles: running,
                    gate,
                },
            );
            self.metrics.inc_counter(
                "profile_vpn_fenced_total",
                &[("profile_id", e.id().as_str()), ("reason", reason)],
            );
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %e.id(),
                torrent_count = paused,
                reason,
                "{message}",
            );
        }
    }

    fn lift(&self) {
        // The tunnel checks run first, outside the lock: each shells out to
        // `ip` (up to its timeout), and every add alert on the alert loop's
        // one thread waits on this lock (`hold_recorded`), so probing under
        // it would stall the loop for as long as the probes take. Each
        // verdict is kept with the record's mark and the profile's fence
        // generation, read with the status it was checked under, and applied
        // below only to the record and the fence it was taken for.
        let marked: Vec<(ProfileId, u64)> = self
            .fenced
            .lock()
            .profiles
            .iter()
            .map(|(id, record)| (id.clone(), record.mark))
            .collect();
        let checked: Vec<_> = marked
            .into_iter()
            .map(|(id, mark)| {
                let checked = self.profiles.resolve(&id).active().and_then(|e| {
                    let health = e.health();
                    (health.status == ProfileStatus::VpnDown)
                        .then(|| (health.fence_generation, recovery_check(e, &self.probe)))
                });
                (id, mark, checked)
            })
            .collect();
        // Held from the take of each record to its mark, not taken and
        // released: a boot scan or an add recording what it paused for this
        // fence (`with_record`) between the take and the mark below would
        // find no record, and its torrents would stay paused in a profile
        // lifted around them.
        let mut fenced = self.fenced.lock();
        for (profile_id, mark, checked) in checked {
            // A record whose mark is not the one checked above is a fence
            // that landed since; it stays, unchecked, for the next lift.
            if fenced.profiles.get(&profile_id).map(|r| r.mark) != Some(mark) {
                continue;
            }
            let Some(FenceRecord {
                mut handles, gate, ..
            }) = fenced.profiles.remove(&profile_id)
            else {
                continue;
            };
            // A torrent the scans paused again after a lift stopped part-way
            // can be in the record twice: once from the fence's take of the
            // unfinished lift, once from the scans.
            let mut seen = std::collections::HashSet::with_capacity(handles.len());
            handles.retain(|h| seen.insert(*h));
            // The operator paused the whole profile while it was fenced: its
            // torrents stay paused, though the fence lifts. One paused alone
            // is left out by the gate as the run reaches it.
            if gate.halted() {
                handles.clear();
            }
            let resolved = self.profiles.resolve(&profile_id);
            let Some(entry) = resolved
                .active()
                .filter(|e| e.health().status == ProfileStatus::VpnDown)
            else {
                continue;
            };
            // Not checked: the profile did not read fenced when the checks
            // ran, so whatever fenced it since (the monitor) owns that fence.
            let Some((generation, healthy)) = checked else {
                continue;
            };
            // Fenced again since the check: the operator set the profile
            // online and the monitor fenced it for its tunnel while the other
            // profiles were probed. The mark above cannot tell, since neither
            // touches this fence's record, and the profile reads `vpn_down`
            // as it did; but every fence bumps the generation, so the verdict
            // is one on a tunnel that has failed since. That fence owns the
            // profile now, as it does an unchecked one.
            if entry.health().fence_generation != generation {
                info!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %profile_id,
                    "network kill switch back in force, but this profile was fenced again \
                     after its tunnel was checked; it stays fenced",
                );
                continue;
            }
            if let Err(reason) = healthy {
                warn!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %profile_id,
                    reason = reason.as_str(),
                    "network kill switch back in force, but this profile's tunnel fails the \
                     health check; it stays fenced until it is set online",
                );
                continue;
            }
            let labels = [("profile_id", profile_id.as_str())];
            let torrent_count = handles.len();
            // Recorded before the profile reads active, so a queued re-hash
            // never finds it active with no run to resume its torrents.
            let run = entry.begin_resume_with(handles, gate);
            entry.update_health(|h| {
                h.status = ProfileStatus::Active;
                h.paused_for_vpn = 0;
                // Back to 1 only here, where the profile reads active again:
                // a profile whose tunnel failed the check above stays fenced,
                // and its 0 stands for the alerts on it.
                self.metrics
                    .set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
                self.metrics
                    .set_gauge("profile_torrents_paused_vpn_down", 0.0, &labels);
            });
            info!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                torrent_count,
                "network kill switch back in force; lifted the profile's fence, and resuming \
                 its torrents a batch at a time",
            );
            spawn_run(&self.profiles, &self.metrics, entry, run, Lift::KillSwitch);
        }
    }
}

/// Pause `handle`, which the caller has just added to `profile_id`'s session,
/// if the VPN monitor fenced the profile since the caller last checked.
///
/// Every add path refuses or holds a fenced profile before it adds, but the
/// add itself comes later, and a fence can land in between. The add handler
/// pauses the torrent when its alert lands; this covers the torrent whose
/// alert never does (dropped on an alert-queue overflow), which no fence walk
/// of the state map will find. Pausing twice is harmless.
///
/// What this pauses is not added to `paused_for_vpn` or its gauge, and neither
/// is what the add handler pauses: the two (and the fence's walk) can pause the
/// same torrent, so the count stays what the fence itself paused.
///
/// Where the kill switch is on, `kill_switch` is its watch's fence, which
/// lifts by resuming only what it recorded: this pauses under that fence's
/// lock and records the torrent with it ([`KillSwitchFence::hold_recorded`]),
/// so the lift resumes it too.
pub(crate) fn hold_if_fenced(
    profiles: &ProfileRegistry,
    kill_switch: Option<&KillSwitchFence>,
    profile_id: &ProfileId,
    engine: &dyn TorrentEngine,
    handle: TorrentHandle,
    metrics: &dyn MetricsSink,
) {
    let hold = || pause_if_fenced(profiles, profile_id, engine, handle, metrics);
    match kill_switch {
        Some(ks) => ks.hold_recorded(profile_id, handle, hold),
        None => {
            hold();
        }
    }
}

/// The add handler's [`torrentd_engine::FenceHold`]: its pause of a torrent
/// whose add alert lands in a fenced profile, run as [`hold_if_fenced`] runs
/// its own, recorded with `kill_switch` where the kill switch is on.
pub(crate) fn fence_hold(kill_switch: Option<Arc<KillSwitchFence>>) -> torrentd_engine::FenceHold {
    Arc::new(
        move |id: &ProfileId, handle: TorrentHandle, hold: &mut dyn FnMut() -> bool| {
            match kill_switch.as_deref() {
                Some(ks) => ks.hold_recorded(id, handle, hold),
                None => {
                    hold();
                }
            }
        },
    )
}

/// [`hold_if_fenced`]'s check and pause. Returns whether the profile was
/// fenced, whether or not the pause took.
fn pause_if_fenced(
    profiles: &ProfileRegistry,
    profile_id: &ProfileId,
    engine: &dyn TorrentEngine,
    handle: TorrentHandle,
    metrics: &dyn MetricsSink,
) -> bool {
    atomic::fence(atomic::Ordering::SeqCst);
    let fenced = profiles
        .resolve(profile_id)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if !fenced {
        return false;
    }
    match engine.pause_torrent(handle) {
        Ok(()) => warn!(
            target: "torrentd::vpn_monitor",
            profile_id = %profile_id,
            infohash = %handle.infohash,
            "profile was fenced while the torrent was being added; paused it",
        ),
        Err(err) => {
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                infohash = %handle.infohash,
                error.cause = %err,
                "could not pause a torrent added while its profile was being fenced",
            );
            metrics.inc_counter(
                "profile_fence_pause_errors_total",
                &[("profile_id", profile_id.as_str())],
            );
        }
    }
    true
}

/// How a [`resume_unless_fenced`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SingleResume {
    /// The session resumed the torrent, and the profile was not fenced.
    Resumed,
    /// The profile was fenced as the torrent was resumed; it was paused again.
    Fenced,
}

/// Resume `handle` in `profile_id`'s session, then pause it again if the VPN
/// monitor fenced the profile meanwhile.
///
/// The caller refuses a fenced profile before this, but a fence can land
/// between that check and the resume. The fence marks the profile and then
/// walks the state map pausing what it holds, so a resume that comes after
/// its walk passed this torrent would leave it running in a `vpn_down`
/// profile, and the monitor never fences a profile already marked. The
/// `SeqCst` fence pairs with the fence's, between its mark and its walk:
/// either the read below sees the mark and pauses the torrent again, or the
/// mark, and the walk after it, came after the resume.
///
/// What this pauses is not added to `paused_for_vpn`, for the reason
/// [`hold_if_fenced`] gives.
pub(crate) fn resume_unless_fenced(
    profiles: &ProfileRegistry,
    profile_id: &ProfileId,
    engine: &dyn TorrentEngine,
    handle: TorrentHandle,
    metrics: &dyn MetricsSink,
) -> Result<SingleResume, torrentd_engine::EngineError> {
    let entry = profiles.resolve(profile_id).active();
    // Noted running before the resume ([`ProfileEntry::note_running`]), so a
    // kill-switch fence, or a set-online, that reads what is running before a
    // state update reports it resumes it with the rest.
    let before = entry.map(|e| e.note_running(handle, true));
    if let Err(err) = engine.resume_torrent(handle) {
        if let (Some(e), Some(before)) = (entry, before) {
            e.restore_noted(handle, before);
        }
        return Err(err);
    }
    atomic::fence(atomic::Ordering::SeqCst);
    let fenced = entry.is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if !fenced {
        return Ok(SingleResume::Resumed);
    }
    if let Some(e) = entry {
        e.restore_noted(handle, None);
    }
    match engine.pause_torrent(handle) {
        Ok(()) => warn!(
            target: "torrentd::vpn_monitor",
            profile_id = %profile_id,
            infohash = %handle.infohash,
            "profile was fenced while the torrent was being resumed; paused it again",
        ),
        Err(err) => {
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %profile_id,
                infohash = %handle.infohash,
                error.cause = %err,
                "could not pause again a torrent resumed as its profile was fenced",
            );
            metrics.inc_counter(
                "profile_fence_pause_errors_total",
                &[("profile_id", profile_id.as_str())],
            );
        }
    }
    Ok(SingleResume::Fenced)
}
