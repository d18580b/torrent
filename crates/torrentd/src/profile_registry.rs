//! Runtime profile registry.
//!
//! Holds the per-profile engine plus the VPN/health state that the `/profiles`
//! HTTP API and the VPN health monitor share. Always present: a daemon has at
//! least one profile or it does not boot, so `AppState::profiles` is a plain
//! `Arc<ProfileRegistry>` rather than an `Option`.

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Weak;

use parking_lot::Mutex;
use torrentd_engine::EngineError;
use torrentd_engine::InfoHash;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use torrentd_engine::Settings;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentHandle;

use crate::profile_state::DesiredStates;
use crate::profile_state::PacedHolds;
use crate::profile_state::Record;

/// Mutable per-profile health, updated by the VPN monitor and read by `/profiles`.
#[derive(Clone, Debug)]
pub struct ProfileHealth {
    pub status: ProfileStatus,
    pub tunnel_ip: Option<IpAddr>,
    /// Number of torrents the fence paused when the tunnel went down: the
    /// monitor's walk of the state map and the boot scans' `ScanFence`. A
    /// torrent added into an already-fenced profile and paused by the add
    /// handler or `vpn_monitor::hold_if_fenced` is not counted, because both
    /// of those (and the walk) can pause the same torrent.
    ///
    /// Both writers add to it through [`Self::count_paused_for_vpn`], so a
    /// torrent both of them paused under one fence is counted once.
    pub paused_for_vpn: u64,
    /// The torrents `paused_for_vpn` has counted under the current fence
    /// generation, started over by every fence with the count. Shared, so a
    /// [`ProfileEntry::health`] snapshot does not copy it; a count made while
    /// one is still held copies it then, so a writer holds none across its
    /// count.
    pub counted_for_vpn: Arc<HashSet<InfoHash>>,
    /// How many times the profile has been fenced: bumped by every fence
    /// (`vpn_monitor::fence`, which the monitor and the kill-switch watch's
    /// `fence_all` both run) in the same update that marks it `vpn_down` and
    /// starts `paused_for_vpn` over, and reset by no lift. The boot scans'
    /// `ScanFence` reads a value it has not seen as a new fence, under which
    /// the torrents it paused before are paused again.
    pub fence_generation: u64,
    /// Why the latest fence went on: the `reason` its
    /// `profile_vpn_fenced_total` increment carries (`vpn_monitor`'s
    /// `DownReason::as_str`, or `kill_switch`). Set in the update that marks
    /// the profile `vpn_down`, and left by a lift, so it describes the
    /// profile only while `status` is `VpnDown`; `None` before any fence.
    pub fence_reason: Option<&'static str>,
    /// Current NAT-PMP-negotiated listening port (natpmp profiles only; `None`
    /// for static profiles).
    pub forwarded_port: Option<u16>,
    /// Last gateway epoch seen for this profile's mapping (natpmp only; `0` when
    /// unknown). A drop in this value across renewals means the gateway
    /// rebooted (RFC 6886 §3.6).
    pub forwarded_epoch: u32,
    /// Whether the last port-forward renewal succeeded. Always `true` for
    /// static profiles (nothing to renew).
    pub port_forward_ok: bool,
}

impl ProfileHealth {
    /// Start `paused_for_vpn` over for a new fence: nothing is counted under
    /// it yet.
    pub fn start_paused_for_vpn_over(&mut self) {
        self.paused_for_vpn = 0;
        self.counted_for_vpn = Arc::default();
    }

    /// Add to `paused_for_vpn` each of `paused`, torrents a fence's pause of
    /// took, that no writer has counted under the current fence, returning
    /// how many were added.
    pub fn count_paused_for_vpn(&mut self, paused: impl IntoIterator<Item = InfoHash>) -> u64 {
        let counted = Arc::make_mut(&mut self.counted_for_vpn);
        let added = paused.into_iter().filter(|ih| counted.insert(*ih)).count() as u64;
        self.paused_for_vpn += added;
        added
    }
}

/// One profile's immutable identity (config + engine) plus its mutable health.
pub struct ProfileEntry {
    pub config: ProfileConfig,
    pub engine: Arc<dyn TorrentEngine>,
    /// The tunnel address the session was built on and is bound to. Unlike
    /// `ProfileHealth::tunnel_ip`, which a fence overwrites with whatever the
    /// interface held then, this never changes: lifting a fence needs the
    /// tunnel back on exactly this address, since the session's sockets
    /// cannot move.
    pub session_ip: Option<IpAddr>,
    health: Mutex<ProfileHealth>,
    /// The paced resume that lifting a fence started in this profile, while it
    /// runs. See [`ProfileEntry::begin_resume`].
    resuming: Mutex<Option<Arc<PacedResume>>>,
    /// The gate of every paced resume running in this profile, a lift's and
    /// each resume-all's. See [`ProfileEntry::open_gate`].
    gates: Mutex<Vec<Weak<ResumeGate>>>,
    /// The torrents a paced set-online paused and has not resumed yet, shared
    /// by every profile ([`ProfileRegistry::with_holds`]).
    holds: Arc<PacedHolds>,
    /// Taken across a paced set-online's hold-and-pause of this profile
    /// ([`ProfileRegistry::hold_running`]) and across a hand resume and the
    /// release of its hold ([`ProfileEntry::resume_by_hand`]), so neither
    /// lands inside the other.
    holding: Mutex<()>,
    /// What the daemon last set each torrent's own paused flag to, running
    /// or not, until a state update reports it. See
    /// [`ProfileEntry::note_running`].
    noted: Mutex<HashMap<TorrentHandle, bool>>,
}

/// What the operator paused while one paced resume runs: a pause of the whole
/// profile halts the run, and a single torrent paused is left out of it.
///
/// A paced run reaches its last torrents minutes after it starts, so without
/// this a pause in that window is undone as the run's later batches resume
/// what the pause stopped.
#[derive(Debug, Default)]
pub struct ResumeGate {
    state: Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    halted: bool,
    excluded: HashSet<TorrentHandle>,
}

/// Why [`ResumeGate::resume`] did not resume a torrent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gated {
    /// The profile was paused: the run stops here.
    Halted,
    /// The operator paused this torrent: the run goes on without it.
    Excluded,
}

impl ResumeGate {
    /// Run `resume` for `h` unless a pause got there first.
    ///
    /// The gate's lock is held across `resume`, and a pause takes it before it
    /// pauses anything, so a resume either finishes before the pause's own
    /// pause of that torrent or does not happen.
    pub fn resume<T>(&self, h: TorrentHandle, resume: impl FnOnce() -> T) -> Result<T, Gated> {
        let state = self.state.lock();
        if state.halted {
            return Err(Gated::Halted);
        }
        if state.excluded.contains(&h) {
            return Err(Gated::Excluded);
        }
        Ok(resume())
    }

    /// Whether the profile was paused while this run ran.
    pub fn halted(&self) -> bool {
        self.state.lock().halted
    }

    fn halt(&self) {
        self.state.lock().halted = true;
    }

    fn exclude(&self, h: TorrentHandle) {
        self.state.lock().excluded.insert(h);
    }

    fn excludes(&self, h: &TorrentHandle) -> bool {
        self.state.lock().excluded.contains(h)
    }
}

/// A paced resume a fence's lift started in one profile
/// (`vpn_monitor::spawn_lift`): every torrent it was asked to resume, whether
/// it has been told to stop, and what the operator paused while it ran.
#[derive(Debug)]
pub struct PacedResume {
    handles: Vec<TorrentHandle>,
    cancelled: AtomicBool,
    gate: Arc<ResumeGate>,
}

impl PacedResume {
    /// Every torrent the run was asked to resume, those it already has
    /// included.
    pub fn handles(&self) -> &[TorrentHandle] {
        &self.handles
    }

    /// Whether the run has been told to stop before its next batch.
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// The pauses the run must keep to.
    pub fn gate(&self) -> &Arc<ResumeGate> {
        &self.gate
    }
}

impl ProfileEntry {
    pub fn new(
        config: ProfileConfig,
        engine: Arc<dyn TorrentEngine>,
        // `None` for a host profile, which has no tunnel to lose.
        tunnel_ip: Option<IpAddr>,
        forwarded_port: Option<u16>,
        forwarded_epoch: u32,
    ) -> Self {
        Self {
            config,
            engine,
            session_ip: tunnel_ip,
            health: Mutex::new(ProfileHealth {
                status: ProfileStatus::Active,
                tunnel_ip,
                paused_for_vpn: 0,
                counted_for_vpn: Arc::default(),
                fence_generation: 0,
                fence_reason: None,
                forwarded_port,
                forwarded_epoch,
                port_forward_ok: true,
            }),
            resuming: Mutex::new(None),
            gates: Mutex::new(Vec::new()),
            holds: Arc::new(PacedHolds::in_memory()),
            holding: Mutex::new(()),
            noted: Mutex::new(HashMap::new()),
        }
    }

    pub fn id(&self) -> &ProfileId {
        &self.config.id
    }

    pub fn health(&self) -> ProfileHealth {
        self.health.lock().clone()
    }

    pub fn update_health<F: FnOnce(&mut ProfileHealth)>(&self, f: F) {
        f(&mut self.health.lock());
    }

    /// Record a paced resume of `handles` as the one running in this profile,
    /// telling the one before it, if any, to stop.
    ///
    /// A lift resumes its torrents a batch at a time, so a fence can land
    /// while some are still paused. The fence takes the run back with
    /// [`ProfileEntry::take_resume`], so the torrents it had not reached yet
    /// are not lost to the next lift: they read as paused when the fence
    /// looks for what is running.
    pub fn begin_resume(&self, handles: Vec<TorrentHandle>) -> Arc<PacedResume> {
        self.begin_resume_with(handles, self.open_gate())
    }

    /// [`ProfileEntry::begin_resume`], keeping to `gate`, one opened on this
    /// entry ([`ProfileEntry::open_gate`]) before the run began, rather than
    /// a new one: what a pause in the profile closed it with since it opened
    /// holds for the run too.
    ///
    /// For a kill-switch fence's lift, whose gate opened when the fence
    /// landed, so a torrent the operator paused while the fence stood, or a
    /// pause of the whole profile then, is not resumed by its lift.
    pub fn begin_resume_with(
        &self,
        handles: Vec<TorrentHandle>,
        gate: Arc<ResumeGate>,
    ) -> Arc<PacedResume> {
        let run = Arc::new(PacedResume {
            handles,
            cancelled: AtomicBool::new(false),
            gate,
        });
        if let Some(before) = self.resuming.lock().replace(run.clone()) {
            before.cancelled.store(true, Ordering::SeqCst);
        }
        run
    }

    /// Stop the paced resume running in this profile before its next batch,
    /// and hand back every torrent it was asked to resume, less those the
    /// operator paused while it ran: none of them where the operator paused
    /// the whole profile. `None` when none is running.
    pub fn take_resume(&self) -> Option<Vec<TorrentHandle>> {
        let run = self.resuming.lock().take()?;
        run.cancelled.store(true, Ordering::SeqCst);
        if run.gate.halted() {
            return Some(Vec::new());
        }
        Some(
            run.handles
                .iter()
                .filter(|h| !run.gate.excludes(h))
                .copied()
                .collect(),
        )
    }

    /// Whether the paced resume running in this profile is still to resume
    /// `ih`: the run was asked to resume it, and neither a pause of the
    /// profile nor the operator's pause of the torrent has stopped it.
    ///
    /// A fence's lift marks the profile active and then resumes its torrents
    /// a batch at a time, recording nothing in [`PacedHolds`], so a torrent
    /// its run has not reached yet reads as paused in an active profile. It
    /// is paused by the daemon, not the operator, and runs again once its
    /// batch comes. The run is not told which torrents it has reached, so
    /// one it has already resumed reads as pending too until the run ends,
    /// which is the same answer a moment early.
    ///
    /// A run is cancelled only once it is out of `resuming` (taken, replaced
    /// or halted under this lock), so the run read here is never cancelled.
    pub fn resume_pending(&self, ih: &InfoHash) -> bool {
        let resuming = self.resuming.lock();
        let Some(run) = resuming.as_ref() else {
            return false;
        };
        if run.gate.halted() {
            return false;
        }
        run.handles
            .iter()
            .any(|h| h.infohash == *ih && !run.gate.excludes(h))
    }

    /// A gate for a paced resume about to run in this profile, which every
    /// pause in the profile closes from then until the run drops it.
    pub fn open_gate(&self) -> Arc<ResumeGate> {
        let gate = Arc::new(ResumeGate::default());
        let mut gates = self.gates.lock();
        gates.retain(|g| g.strong_count() > 0);
        gates.push(Arc::downgrade(&gate));
        gate
    }

    /// Halt every paced resume running in this profile, before a pause of the
    /// whole profile walks it. Once this returns no run resumes another
    /// torrent, so the walk's pauses stand. A lift's run is also dropped from
    /// the entry, so a kill-switch fence does not take it back and the next
    /// lift does not resume what the operator paused. A kill-switch fence
    /// standing over the profile holds a gate of its own from the moment it
    /// fenced (`vpn_monitor::KillSwitchFence`), which this halts too, so its
    /// lift resumes nothing.
    ///
    /// What a paced set-online still holds ([`PacedHolds`]) is released too:
    /// the operator's pause now stands over it, so the next boot does not load
    /// it unpaused.
    pub fn halt_resumes(&self) {
        for gate in self.live_gates() {
            gate.halt();
        }
        if let Some(run) = self.resuming.lock().take() {
            run.cancelled.store(true, Ordering::SeqCst);
        }
        if let Err(err) = self.holds.release_all(self.id()) {
            self.holds_unwritten(&err);
        }
    }

    /// Leave `h` out of every paced resume running in this profile, before a
    /// pause of that one torrent. Once this returns none of them resumes it,
    /// nor does the lift of a kill-switch fence standing over the profile,
    /// whose gate opened when it fenced (`vpn_monitor::KillSwitchFence`), and
    /// the next boot does not load it unpaused ([`PacedHolds`]).
    pub fn exclude_from_resumes(&self, h: TorrentHandle) {
        for gate in self.live_gates() {
            gate.exclude(h);
        }
        if let Err(err) = self.holds.release(self.id(), [h.infohash]) {
            self.holds_unwritten(&err);
        }
    }

    /// Take `handles`, which are running again or were left out of a paced
    /// resume for the operator's pause, out of what a paced set-online holds.
    /// A no-op, writing nothing, for any it does not hold.
    pub fn release_holds(&self, handles: &[TorrentHandle]) {
        if let Err(err) = self
            .holds
            .release(self.id(), handles.iter().map(|h| h.infohash))
        {
            self.holds_unwritten(&err);
        }
    }

    /// Resume `h` by the operator's hand through `resume`, then, where
    /// `running` says the outcome left it running, release it from what a
    /// paced set-online holds ([`ProfileEntry::release_holds`]). A failed
    /// resume releases nothing, so the torrent stays held.
    ///
    /// Both steps run under the lock a paced set-online holds while it records
    /// and pauses this profile's running torrents
    /// ([`ProfileRegistry::hold_running`]). Without it a set-online could read
    /// the torrent as running once the resume went out, record its hold, and
    /// pause it only after this released that hold: the torrent would be
    /// paused by the pace and held by nothing, so a re-hash queued before its
    /// batch would start on a stale running phase, and a restart before it
    /// would load it paused as if the operator had paused it. Serialised, the
    /// set-online either holds and pauses the torrent before this resumes it
    /// and releases the hold, or after, when its hold stands until the pace
    /// resumes it.
    pub fn resume_by_hand<T, E>(
        &self,
        h: TorrentHandle,
        resume: impl FnOnce() -> Result<T, E>,
        running: impl FnOnce(&T) -> bool,
    ) -> Result<T, E> {
        let _holding = self.holding.lock();
        let outcome = resume()?;
        if running(&outcome) {
            self.release_holds(&[h]);
        }
        Ok(outcome)
    }

    /// Note that `h`'s own paused flag is about to be cleared (`running`) or
    /// set, ahead of the state update that will report it, and return what
    /// was noted for it before, for [`ProfileEntry::restore_noted`] should the
    /// engine refuse.
    ///
    /// A torrent's paused flag reaches the state map only through a state
    /// update, which comes every couple of seconds, while the kill-switch
    /// watch can fence and lift inside one check. Its fence, and a
    /// set-online, decide what to resume from what is running
    /// ([`ProfileEntry::running`]), so without this a pause just before
    /// either was undone by the lift or the pace, and a resume just before
    /// either was left paused. Noted before the engine call, so a reader that
    /// comes after the note sees the new flag, and one that comes before it
    /// read before the pause or resume began, which the pause's gates
    /// ([`ProfileEntry::exclude_from_resumes`]) and the resume's fence check
    /// cover.
    pub fn note_running(&self, h: TorrentHandle, running: bool) -> Option<bool> {
        self.noted.lock().insert(h, running)
    }

    /// [`ProfileEntry::note_running`] with `running` false, for every one of
    /// `handles`: a pause of the whole profile.
    pub fn note_paused(&self, handles: &[TorrentHandle]) {
        let mut noted = self.noted.lock();
        for &h in handles {
            noted.insert(h, false);
        }
    }

    /// Put back `before`, what [`ProfileEntry::note_running`] returned, for
    /// `h`: the engine refused the call, so its flag did not change. `None`
    /// forgets `h`, so the state map's word on it stands.
    pub fn restore_noted(&self, h: TorrentHandle, before: Option<bool>) {
        let mut noted = self.noted.lock();
        match before {
            Some(running) => noted.insert(h, running),
            None => noted.remove(&h),
        };
    }

    /// Forget everything noted: a fence has just paused every torrent in the
    /// profile, so the state map's next word on each is the right one.
    pub fn forget_noted(&self) {
        self.noted.lock().clear();
    }

    /// Whether each torrent of `reported`, the profile's torrents as the last
    /// state update left their paused flags (`true` where clear), is running
    /// now: what [`ProfileEntry::note_running`] noted for it where that is
    /// not reported yet, and the report otherwise.
    ///
    /// A note the report agrees with is dropped, since the state map now says
    /// the same: one that disagrees stands, since a report requested before
    /// the call reached the session can land after it. Notes for torrents
    /// not in `reported`, gone from the profile, are dropped too.
    pub fn running(&self, reported: Vec<(TorrentHandle, bool)>) -> Vec<(TorrentHandle, bool)> {
        let mut noted = self.noted.lock();
        let mut kept = HashMap::with_capacity(noted.len().min(reported.len()));
        let running = reported
            .into_iter()
            .map(|(h, reported)| match noted.remove(&h) {
                Some(running) if running != reported => {
                    kept.insert(h, running);
                    (h, running)
                }
                _ => (h, reported),
            })
            .collect();
        *noted = kept;
        running
    }

    /// Log a [`PacedHolds`] release that could not be written. The record
    /// then still names those torrents, and the next boot loads them
    /// unpaused, so a pause the operator made since is not kept across it.
    fn holds_unwritten(&self, err: &std::io::Error) {
        tracing::error!(
            profile_id = %self.id(),
            error.cause = %err,
            "could not write the record of what a paced set-online holds; a torrent paused \
             since may come back running at the next boot",
        );
    }

    fn live_gates(&self) -> Vec<Arc<ResumeGate>> {
        let mut gates = self.gates.lock();
        gates.retain(|g| g.strong_count() > 0);
        gates.iter().filter_map(Weak::upgrade).collect()
    }

    /// Clear `run` once it has finished, and release `reached`, the torrents
    /// it resumed or left out for a pause, from what a paced set-online holds
    /// ([`ProfileEntry::release_holds`]) - unless the run was stopped or
    /// replaced first.
    ///
    /// A run that is no longer this profile's has been taken back by a
    /// set-offline, a fence or a pause, or replaced by a newer lift, and
    /// whatever stopped it decided what is held from then on: a set-offline
    /// holds every torrent of the run, and a set-online after it may already
    /// have held and paused the very torrents this run reached. Releasing
    /// them then would leave those paused at the next boot. The check and the
    /// release are made under the lock [`ProfileEntry::take_resume`] and
    /// [`ProfileEntry::begin_resume`] take, so neither can land between them.
    pub fn end_resume(&self, run: &Arc<PacedResume>, reached: &[TorrentHandle]) {
        let mut resuming = self.resuming.lock();
        if resuming.as_ref().is_some_and(|r| Arc::ptr_eq(r, run)) {
            self.release_holds(reached);
            *resuming = None;
        }
    }

    /// Whether a paced resume is running in this profile.
    #[cfg(test)]
    pub fn is_resuming(&self) -> bool {
        self.resuming.lock().is_some()
    }
}

impl std::fmt::Debug for ProfileEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileEntry")
            .field("id", &self.id())
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ProfileRegistry {
    entries: Vec<ProfileEntry>,
    /// Profiles that never got a session, with the reason.
    ///
    /// Safety Rule 1 says a profile whose tunnel fails to come up is "marked
    /// failed and logged" while the others proceed. The logging happened; the
    /// marking did not — the profile was skipped entirely, so it disappeared from
    /// `/profiles` rather than appearing there as failed. An operator checking
    /// why an account is quiet saw no trace of it at all.
    ///
    /// These carry no engine because none was ever constructed, which is the
    /// whole point of the rule.
    failed: Vec<FailedProfile>,
    /// The operator's online/offline choice for each profile, persisted.
    states: DesiredStates,
    /// What each profile's paced set-online paused and has not resumed yet,
    /// persisted. The same `Arc` every entry holds.
    holds: Arc<PacedHolds>,
}

/// Why a change of the profiles' online/offline states did not fully apply.
#[derive(Debug, thiserror::Error)]
pub enum StateChangeError {
    /// The record could not be written, so nothing changed.
    #[error("the profiles' online/offline states could not be written: {0}")]
    Persist(#[from] std::io::Error),
    /// The record changed, and these sessions did not take the pause or
    /// resume that applies it.
    #[error(
        "{} session(s) did not take the change: {}",
        .0.len(),
        .0.iter().map(|(id, why)| format!("{id}: {why}")).collect::<Vec<_>>().join("; ")
    )]
    Apply(Vec<(ProfileId, Refusal)>),
}

/// Why one session did not take an online/offline change.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The session refused the pause or resume.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// Going online, the record of the torrents its paced resume pauses
    /// ([`PacedHolds`]) could not be written, so nothing was paused and the
    /// session stays paused: resuming it unpaced would start every torrent at
    /// once, and pausing them unrecorded would leave them paused after a
    /// restart.
    #[error("the record of what its paced resume holds could not be written: {0}")]
    Holds(std::io::Error),
}

/// What setting a profile online needs from outside the registry: which of
/// its torrents are running, and a way to start their paced resume.
///
/// A session-level resume starts every torrent whose own paused flag is clear
/// at once, so going online pauses each of those first and hands them to
/// [`OnlinePacing::start`] (`vpn_monitor::OnlinePace` in the daemon).
pub trait OnlinePacing {
    /// Every torrent `id` holds, each with whether its own paused flag is
    /// clear, so the session resuming would start it.
    fn torrents(&self, id: &ProfileId) -> Vec<(TorrentHandle, bool)>;
    /// Resume `handles` in `entry` a batch at a time. Called once the
    /// session has resumed, under the online/offline change's lock.
    fn start(&self, entry: &ProfileEntry, handles: Vec<TorrentHandle>);
}

/// [`OnlinePacing`] for a registry whose sessions hold no torrent, in tests.
#[cfg(test)]
pub(crate) struct NoTorrents;

#[cfg(test)]
impl OnlinePacing for NoTorrents {
    fn torrents(&self, _: &ProfileId) -> Vec<(TorrentHandle, bool)> {
        Vec::new()
    }
    fn start(&self, _: &ProfileEntry, handles: Vec<TorrentHandle>) {
        assert!(handles.is_empty(), "NoTorrents paces nothing");
    }
}

/// A profile that could not be brought up.
#[derive(Clone, Debug)]
pub struct FailedProfile {
    pub config: ProfileConfig,
    pub reason: String,
}

/// What [`ProfileRegistry::resolve`] found: the three answers a profile id can
/// have, and the only three.
///
/// An id that is configured and down is not an unknown id, and the difference
/// is what an operator reads to decide whether to fix their config file or
/// their tunnel. Returning it as a value rather than as `Option<&ProfileEntry>`
/// is what stops a route dropping the distinction: there is no way to take the
/// live entry out of this without the other two arms being written down.
pub enum Resolution<'a> {
    /// Configured, brought up, holding a session.
    Active(&'a ProfileEntry),
    /// Configured, and it never got a session. Carries why.
    Failed(&'a FailedProfile),
    /// No `[[profile]]` table declares this id.
    Unknown,
}

impl<'a> Resolution<'a> {
    /// The live entry, or `None` for the two answers that are not one.
    ///
    /// The only way to `&ProfileEntry` from outside this module, and it reads
    /// as what it is: a caller that discards the other two arms has written
    /// down that it is doing so. `ProfileRegistry::get`, which used to be that
    /// way, said nothing.
    pub fn active(self) -> Option<&'a ProfileEntry> {
        match self {
            Resolution::Active(e) => Some(e),
            Resolution::Failed(_) | Resolution::Unknown => None,
        }
    }
}

/// Build a static WireGuard profile entry with the given id and status, for tests
/// across the http/app_state modules.
#[cfg(test)]
pub(crate) fn test_entry(id: &str, status: ProfileStatus) -> ProfileEntry {
    test_vpn_entry(id, status)
}

/// A tunnelled profile, which is what most tests about health and fencing
/// want.
#[cfg(test)]
pub(crate) fn test_vpn_entry(id: &str, status: ProfileStatus) -> ProfileEntry {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use torrentd_engine::MockEngine;
    use torrentd_engine::PortForwardMode;
    use torrentd_engine::ProfileNetwork;
    use torrentd_engine::VpnType;

    let iface = format!("wg-{id}");
    let config = ProfileConfig {
        id: ProfileId::new(id),
        network: ProfileNetwork::Vpn {
            vpn_type: VpnType::Wireguard,
            vpn_config: PathBuf::from(format!("/etc/wireguard/{iface}.conf")),
            vpn_interface: iface,
            listen_port: Some(6881),
            port_forward: PortForwardMode::Static,
            port_forward_gateway: None,
        },
        peer_fingerprint: Some("-AA1000-".to_string()),
        user_agent: Some(format!("ua-{id}")),
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    };
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let entry = ProfileEntry::new(
        config,
        engine,
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2))),
        None,
        0,
    );
    entry.update_health(|h| h.status = status);
    entry
}

/// A configured vpn profile whose bring-up failed, so it never got a session.
#[cfg(test)]
pub(crate) fn test_failed_profile(id: &str, reason: &str) -> FailedProfile {
    FailedProfile {
        config: test_vpn_entry(id, ProfileStatus::Active).config,
        reason: reason.to_string(),
    }
}

/// A host profile, which has no tunnel and therefore no tunnel health.
#[cfg(test)]
pub(crate) fn test_host_entry(id: &str) -> ProfileEntry {
    use torrentd_engine::MockEngine;
    use torrentd_engine::ProfileNetwork;

    let config = ProfileConfig {
        id: ProfileId::new(id),
        network: ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6881".to_string(),
            dht: false,
        },
        peer_fingerprint: None,
        user_agent: None,
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    };
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    ProfileEntry::new(config, engine, None, None, 0)
}

impl ProfileRegistry {
    pub fn new(entries: Vec<ProfileEntry>) -> Self {
        let mut registry = Self {
            entries,
            failed: Vec::new(),
            states: DesiredStates::in_memory(),
            holds: Arc::new(PacedHolds::in_memory()),
        };
        registry.share_holds();
        registry
    }

    /// The persisted record of what each profile's paced set-online holds.
    /// The boot reads it as it loads each profile's torrents.
    pub fn with_holds(mut self, holds: PacedHolds) -> Self {
        self.holds = Arc::new(holds);
        self.share_holds();
        self
    }

    /// What each profile's paced set-online holds.
    pub fn holds(&self) -> &PacedHolds {
        &self.holds
    }

    /// Hand every entry the registry's record, so a pause in any profile
    /// releases what it holds there.
    fn share_holds(&mut self) {
        for e in &mut self.entries {
            e.holds = Arc::clone(&self.holds);
        }
    }

    pub fn with_failed(mut self, failed: Vec<FailedProfile>) -> Self {
        self.failed = failed;
        self
    }

    /// The persisted online/offline states. The sessions are expected to
    /// match them already: boot pauses each offline profile's session as it
    /// builds it.
    pub fn with_states(mut self, states: DesiredStates) -> Self {
        self.states = states;
        self
    }

    /// The online/offline states as they stand.
    pub fn states(&self) -> Record {
        self.states.current()
    }

    /// Whether the operator holds `id` offline, by its own state or by
    /// offline-all.
    pub fn held_offline(&self, id: &ProfileId) -> bool {
        self.states.holds_offline(id)
    }

    /// Set `torrentd_profile_offline` for every configured profile, live or
    /// failed, from `record`.
    fn export_record(&self, record: &Record, metrics: &dyn MetricsSink) {
        let ids = self
            .entries
            .iter()
            .map(|e| e.id())
            .chain(self.failed.iter().map(|f| &f.config.id));
        for id in ids {
            metrics.set_gauge(
                "profile_offline",
                if record.holds_offline(id) { 1.0 } else { 0.0 },
                &[("profile_id", id.as_str())],
            );
        }
    }

    /// Set `torrentd_profile_offline` from the states as they stand.
    pub fn export_offline(&self, metrics: &dyn MetricsSink) {
        self.export_record(&self.states.current(), metrics);
    }

    /// Pause each live session `record` holds offline and resume each one it
    /// does not, returning the sessions that refused.
    ///
    /// A paused session still runs its DHT node, so a host profile with DHT
    /// has it stopped while offline and started again when online. Setting
    /// an unchanged value is a no-op in libtorrent.
    ///
    /// A session going online is not resumed bare: that would start every
    /// torrent in it at once ([`ProfileRegistry::hold_running`]). Going
    /// offline stops the paced resume still running in the profile, and what
    /// it had not reached is held for the next time it goes online.
    fn apply_record(
        &self,
        record: &Record,
        pacing: &dyn OnlinePacing,
    ) -> Vec<(ProfileId, Refusal)> {
        let dht = |on: bool| Settings {
            enable_dht: Some(on),
            ..Settings::default()
        };
        let mut refused = Vec::new();
        for e in &self.entries {
            let has_dht = e.config.dht_enabled();
            let outcome = if record.holds_offline(e.id()) {
                self.hold_unfinished(e);
                e.engine
                    .pause_session()
                    .and_then(|()| {
                        if has_dht {
                            e.engine.apply_settings(&dht(false))
                        } else {
                            Ok(())
                        }
                    })
                    .map_err(Refusal::from)
            } else {
                // Only a session paused now is going online; one already
                // running has nothing to start. One whose state cannot be
                // read is treated as paused: if it was running, its torrents
                // are paused and paced back, rather than a paused one
                // starting every torrent at once.
                let paced = match e.engine.session_paused() {
                    Ok(true) => self.hold_running(e, pacing),
                    Ok(false) => Ok(Vec::new()),
                    Err(err) => {
                        tracing::warn!(
                            profile_id = %e.id(),
                            error.cause = %err,
                            "could not read whether the profile's session is paused; pacing \
                             the resume of its torrents as if it were",
                        );
                        self.hold_running(e, pacing)
                    }
                };
                paced.and_then(|paced| {
                    e.engine.resume_session()?;
                    // The session runs now, so the pace starts whatever the
                    // DHT call returns: the torrents just paused are held,
                    // and a retried set-online finds the session running
                    // and would not reach them.
                    if !paced.is_empty() {
                        pacing.start(e, paced);
                    }
                    if has_dht {
                        e.engine.apply_settings(&dht(true))?;
                    }
                    Ok(())
                })
            };
            if let Err(err) = outcome {
                refused.push((e.id().clone(), err));
            }
        }
        refused
    }

    /// Before `e`'s paused session resumes: record, then pause, every torrent
    /// in it that the resume would start, and return those with the ones an
    /// earlier pace still holds, for [`OnlinePacing::start`] to resume a batch
    /// at a time.
    ///
    /// The session is paused, so these pauses send no announce. The record
    /// ([`PacedHolds`]) is written first and durably: the pauses are saved in
    /// resume data, and it is what lets the boot load them unpaused if the
    /// daemon stops before the pace reaches them. A failed write pauses
    /// nothing, and the caller leaves the session paused.
    ///
    /// Runs under `e`'s hold lock, from reading what runs to the last pause,
    /// so a hand resume and the release of its hold
    /// ([`ProfileEntry::resume_by_hand`]) land wholly before or after it.
    fn hold_running(
        &self,
        e: &ProfileEntry,
        pacing: &dyn OnlinePacing,
    ) -> Result<Vec<TorrentHandle>, Refusal> {
        let _holding = e.holding.lock();
        let held = self.holds.held(e.id());
        let mut running = Vec::new();
        let mut paced = Vec::new();
        for (h, is_running) in pacing.torrents(e.id()) {
            if is_running {
                running.push(h);
                paced.push(h);
            } else if held.contains(&h.infohash) {
                paced.push(h);
            }
        }
        self.holds
            .hold(e.id(), running.iter().map(|h| h.infohash))
            .map_err(Refusal::Holds)?;
        for &h in &running {
            // One that refuses the pause starts with the session, unpaced:
            // the burst this avoids, one torrent large.
            if let Err(err) = e.engine.pause_torrent(h) {
                tracing::warn!(
                    profile_id = %e.id(),
                    infohash = %h.infohash,
                    error.cause = %err,
                    "could not pause a torrent before the profile went online; it starts with \
                     the session rather than in its paced batch",
                );
            }
        }
        Ok(paced)
    }

    /// Stop the paced resume still running in `e` as it goes offline, and
    /// hold what it was asked to resume for the next set-online, which paces
    /// it with the rest. Those it had not reached are paused by it, and would
    /// otherwise read as the operator's.
    fn hold_unfinished(&self, e: &ProfileEntry) {
        let Some(unfinished) = e.take_resume() else {
            return;
        };
        if let Err(err) = self
            .holds
            .hold(e.id(), unfinished.iter().map(|h| h.infohash))
        {
            tracing::error!(
                profile_id = %e.id(),
                torrent_count = unfinished.len(),
                error.cause = %err,
                "could not record what a stopped paced resume had not reached; those torrents \
                 stay paused when the profile is next set online",
            );
        }
    }

    /// Change the online/offline record with `edit`, durably, then apply it
    /// to every live session and export it.
    ///
    /// Blocking: it writes and fsyncs the record and makes engine calls per
    /// profile. A failed write changes nothing. Changes are serialised, so
    /// the sessions end each one in the state the record says. A session that
    /// goes online has its torrents resumed through `pacing`, a batch at a
    /// time, from a task that outlives this call.
    pub fn change_states(
        &self,
        edit: impl FnOnce(&mut Record),
        metrics: &dyn MetricsSink,
        pacing: &dyn OnlinePacing,
    ) -> Result<(), StateChangeError> {
        let refused = self.states.change(edit, |record| {
            let refused = self.apply_record(record, pacing);
            self.export_record(record, metrics);
            refused
        })?;
        if refused.is_empty() {
            Ok(())
        } else {
            Err(StateChangeError::Apply(refused))
        }
    }

    /// Profiles that never got a session, in config order.
    pub fn failed(&self) -> &[FailedProfile] {
        &self.failed
    }

    /// Whether `id` names a profile that failed to come up.
    ///
    /// Half of an answer, like [`ProfileRegistry::get`], and private to this
    /// module for the same reason: a route that pairs the two by hand is a
    /// route that can forget to.
    fn failed_profile(&self, id: &ProfileId) -> Option<&FailedProfile> {
        self.failed.iter().find(|f| &f.config.id == id)
    }

    /// What this registry knows about `id`: the one answer every resolution
    /// site asks for.
    ///
    /// The question "is this a typo, or an account that is down?" has exactly
    /// one correct answer and it takes two lookups to reach — `entries`, then
    /// `failed`. A site that asks only `get` answers 404 "unknown profile_id"
    /// for a configured profile whose tunnel failed, sending the operator to
    /// the config file to look for an id that is already in it. That went
    /// wrong once per route, in three separate repairs, because pairing the
    /// two lookups was left to whoever wrote the route.
    ///
    /// It is not left to them here. This returns a value that cannot be read
    /// without the failed case being named, and both halves it is built from —
    /// [`ProfileRegistry::get`] and [`ProfileRegistry::failed_profile`] — are
    /// private to this module, so there is no second way to ask from outside
    /// it. `get` was `pub(crate)` while that claim was being made, and every
    /// resolution site in this daemon lives in this crate, so the claim bought
    /// nothing: `http/torrents.rs` was already calling it.
    pub fn resolve(&self, id: &ProfileId) -> Resolution<'_> {
        if let Some(entry) = self.get(id) {
            return Resolution::Active(entry);
        }
        match self.failed_profile(id) {
            Some(failed) => Resolution::Failed(failed),
            None => Resolution::Unknown,
        }
    }

    /// The configuration of a **live** profile, for a caller that has already
    /// established it is live.
    ///
    /// The add-time flag policy keys off the profile's declared network, so
    /// every add path needs the config and not just the id.
    ///
    /// `None` here does not mean "no such profile": a configured profile whose
    /// tunnel never came up has a config and no entry, and answers `None` like
    /// a typo does. A route that has to tell those apart — which is every route
    /// that reports an id back to an operator — calls
    /// [`ProfileRegistry::resolve`] and reads the arm. Expressed through
    /// `resolve` rather than through `get` so that is one fact about this type
    /// rather than two implementations of it.
    pub fn config(&self, id: &ProfileId) -> Option<&ProfileConfig> {
        self.resolve(id).active().map(|e| &e.config)
    }

    /// The live entry for `id`, or `None` — **including** when `id` names a
    /// configured profile that failed to come up.
    ///
    /// Half of an answer, like [`ProfileRegistry::failed_profile`], and private
    /// to this module for the same reason: it is the lookup a route has to
    /// remember to pair, and the pairing is [`ProfileRegistry::resolve`]'s job.
    fn get(&self, id: &ProfileId) -> Option<&ProfileEntry> {
        self.entries.iter().find(|e| &e.config.id == id)
    }

    /// Every profile that holds a session, in configured order.
    ///
    /// Reviewed alongside `get` and left public: it answers nothing about an
    /// id, so there is no pairing to forget. A caller walking the live set is
    /// saying which set it wants, and the one that never came up has its own
    /// accessor in [`ProfileRegistry::failed`] — which `/profiles` reads
    /// immediately after this one to build the list an operator sees.
    pub fn iter(&self) -> std::slice::Iter<'_, ProfileEntry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registry holding one live profile and one that never came up, which
    /// is the only state in which the three answers are distinguishable.
    fn registry() -> ProfileRegistry {
        ProfileRegistry::new(vec![test_host_entry("public")]).with_failed(vec![
            test_failed_profile("acct_a", "wg-acct-a did not come up"),
        ])
    }

    #[test]
    fn a_live_profile_resolves_active() {
        let r = registry();
        match r.resolve(&ProfileId::new("public")) {
            Resolution::Active(e) => assert_eq!(e.config.id.as_str(), "public"),
            _ => panic!("a profile holding a session is Active"),
        }
    }

    #[test]
    fn a_configured_profile_that_never_came_up_resolves_failed_with_its_reason() {
        // The answer every route got wrong in turn: this id is in the
        // operator's config file, so an answer calling it unknown sends them
        // to hunt a typo that is not there. `get` alone still returns `None`
        // for it — which is why `get` is not what a route calls.
        let r = registry();
        match r.resolve(&ProfileId::new("acct_a")) {
            Resolution::Failed(f) => {
                assert_eq!(f.config.id.as_str(), "acct_a");
                assert!(
                    f.reason.contains("did not come up"),
                    "the reason is what tells the operator what to fix, got {:?}",
                    f.reason,
                );
            }
            _ => panic!("a configured profile with no session is Failed, not Unknown"),
        }
        assert!(
            r.get(&ProfileId::new("acct_a")).is_none(),
            "and the live lookup on its own cannot tell it from a typo",
        );
    }

    #[test]
    fn an_id_no_profile_declares_resolves_unknown() {
        // The other side of the same distinction: this one really is a typo,
        // and it must stay distinguishable from an account that is down.
        let r = registry();
        assert!(matches!(
            r.resolve(&ProfileId::new("typo")),
            Resolution::Unknown
        ));
    }

    #[test]
    fn the_public_config_lookup_answers_for_a_live_profile_and_nothing_else() {
        // `config` is the public half-answer nothing recorded: it collapses
        // "down" and "not configured" into one `None`, exactly as `get` did,
        // and it is reachable from every module in this crate. Expressing it
        // through `resolve` must not have widened it — a caller reading a
        // failed profile's config here would be reading the config of a
        // profile that holds no session.
        let r = registry();
        assert_eq!(
            r.config(&ProfileId::new("public")).map(|c| c.id.as_str()),
            Some("public"),
        );
        assert!(
            r.config(&ProfileId::new("acct_a")).is_none(),
            "configured and down is not a live profile",
        );
        assert!(
            r.config(&ProfileId::new("typo")).is_none(),
            "and neither is a typo",
        );
    }

    #[test]
    fn taking_the_live_entry_out_of_a_resolution_names_the_other_two_arms() {
        // `Resolution::active` is the only way to a `&ProfileEntry` from
        // outside this module. It must answer for `Active` and for neither of
        // the others, or it is `get` again under a new name.
        let r = registry();
        assert!(r.resolve(&ProfileId::new("public")).active().is_some());
        assert!(r.resolve(&ProfileId::new("acct_a")).active().is_none());
        assert!(r.resolve(&ProfileId::new("typo")).active().is_none());
    }

    /// The session pause leaves libtorrent's DHT node running, so a host
    /// profile with DHT has it stopped while offline and started again when
    /// online; one without DHT is never sent the setting.
    #[test]
    fn a_host_profile_with_dht_has_it_stopped_while_offline() {
        use torrentd_engine::DesiredState;
        use torrentd_engine::MockEngine;
        use torrentd_engine::ProfileNetwork;
        use torrentd_engine::RecordedCall;

        let entry = |id: &str, dht: bool| {
            let mut e = test_host_entry(id);
            e.config.network = ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".to_string(),
                dht,
            };
            let mock = Arc::new(MockEngine::new());
            e.engine = mock.clone();
            (e, mock)
        };
        let (with, with_mock) = entry("with", true);
        let (without, without_mock) = entry("without", false);
        let r = ProfileRegistry::new(vec![with, without]);
        let metrics = crate::metrics_sink::PromSink::new();
        let dht_settings = |mock: &MockEngine| -> Vec<Option<bool>> {
            mock.calls()
                .into_iter()
                .filter_map(|c| match c {
                    RecordedCall::ApplySettings(s) => Some(s.enable_dht),
                    _ => None,
                })
                .collect()
        };

        r.change_states(|rec| rec.offline_all = true, &metrics, &NoTorrents)
            .unwrap();
        assert_eq!(dht_settings(&with_mock), vec![Some(false)]);
        assert!(with_mock.session_paused().unwrap());

        r.change_states(|rec| rec.offline_all = false, &metrics, &NoTorrents)
            .unwrap();
        assert_eq!(dht_settings(&with_mock), vec![Some(false), Some(true)]);
        assert!(!with_mock.session_paused().unwrap());

        r.change_states(
            |rec| rec.set(&ProfileId::new("without"), DesiredState::Offline),
            &metrics,
            &NoTorrents,
        )
        .unwrap();
        assert!(without_mock.session_paused().unwrap());
        assert!(dht_settings(&without_mock).is_empty());
    }

    /// An [`OnlinePacing`] over a fixed set of torrents, recording what it
    /// was asked to pace.
    struct Fixed {
        torrents: Vec<(TorrentHandle, bool)>,
        started: Mutex<Vec<Vec<TorrentHandle>>>,
    }

    impl OnlinePacing for Fixed {
        fn torrents(&self, _: &ProfileId) -> Vec<(TorrentHandle, bool)> {
            self.torrents.clone()
        }
        fn start(&self, _: &ProfileEntry, handles: Vec<TorrentHandle>) {
            self.started.lock().push(handles);
        }
    }

    fn handle(b: u8) -> TorrentHandle {
        TorrentHandle {
            id: u64::from(b),
            infohash: torrentd_engine::InfoHash([b; 20]),
        }
    }

    /// Going online pauses, after recording them, the torrents the session's
    /// resume would start, before it resumes, and hands them to the pace with
    /// what an earlier pace still held. A torrent the operator paused is in
    /// neither. Going offline stops the pace and holds what it was asked to
    /// resume, less what the operator paused while it ran.
    #[test]
    fn going_online_holds_and_pauses_what_would_start_then_paces_it() {
        use torrentd_engine::DesiredState;
        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;

        let mut e = test_host_entry("p");
        let mock = Arc::new(MockEngine::new());
        e.engine = mock.clone();
        let r = ProfileRegistry::new(vec![e]);
        let metrics = crate::metrics_sink::PromSink::new();
        let id = ProfileId::new("p");
        let entry = r.resolve(&id).active().unwrap();
        // 1 and 2 run; 3 the operator paused; 4 an earlier pace still holds.
        r.holds().hold(&id, [handle(4).infohash]).unwrap();
        let pacing = Fixed {
            torrents: vec![
                (handle(1), true),
                (handle(2), true),
                (handle(3), false),
                (handle(4), false),
            ],
            started: Mutex::new(Vec::new()),
        };
        let set = |state| {
            r.change_states(|rec| rec.set(&id, state), &metrics, &pacing)
                .unwrap()
        };

        set(DesiredState::Offline);
        assert!(pacing.started.lock().is_empty(), "offline paces nothing");
        set(DesiredState::Online);
        let calls = mock.calls();
        let paused_at = |h: TorrentHandle| {
            calls
                .iter()
                .position(|c| matches!(c, RecordedCall::PauseTorrent(x) if *x == h))
        };
        let resumed = calls
            .iter()
            .position(|c| matches!(c, RecordedCall::ResumeSession))
            .unwrap();
        for h in [handle(1), handle(2)] {
            assert!(paused_at(h).unwrap() < resumed);
        }
        assert_eq!(paused_at(handle(3)), None);
        assert_eq!(
            *pacing.started.lock(),
            vec![vec![handle(1), handle(2), handle(4)]]
        );
        let want: HashSet<_> = [1, 2, 4].map(|b| handle(b).infohash).into();
        assert_eq!(r.holds().held(&id), want);

        // Online again changes nothing: the session is running.
        set(DesiredState::Online);
        assert_eq!(pacing.started.lock().len(), 1);

        // A pace running as the profile goes offline is stopped, and what it
        // was asked to resume is held, less the one the operator paused.
        r.holds().release_all(&id).unwrap();
        let run = entry.begin_resume(vec![handle(5), handle(6)]);
        entry.exclude_from_resumes(handle(6));
        set(DesiredState::Offline);
        assert!(run.cancelled());
        assert_eq!(r.holds().held(&id), HashSet::from([handle(5).infohash]));
        // And a pause of the whole profile releases every hold.
        entry.halt_resumes();
        assert!(r.holds().held(&id).is_empty());
    }

    /// A hold that cannot be written pauses nothing and leaves the session
    /// paused, so it neither starts every torrent at once nor leaves them
    /// paused unrecorded.
    #[test]
    fn a_hold_that_cannot_be_written_leaves_the_session_paused() {
        use torrentd_engine::DesiredState;
        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;

        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let (holds, _) = PacedHolds::load(state_dir.join("holds.json"));
        std::fs::write(&state_dir, b"").unwrap();
        let mut e = test_host_entry("p");
        let mock = Arc::new(MockEngine::new());
        e.engine = mock.clone();
        let r = ProfileRegistry::new(vec![e]).with_holds(holds);
        let metrics = crate::metrics_sink::PromSink::new();
        let id = ProfileId::new("p");
        let pacing = Fixed {
            torrents: vec![(handle(1), true)],
            started: Mutex::new(Vec::new()),
        };
        r.change_states(|rec| rec.set(&id, DesiredState::Offline), &metrics, &pacing)
            .unwrap();
        let err = r
            .change_states(|rec| rec.set(&id, DesiredState::Online), &metrics, &pacing)
            .unwrap_err();
        assert!(
            matches!(&err, StateChangeError::Apply(v) if matches!(v[..], [(_, Refusal::Holds(_))])),
            "{err}"
        );
        assert!(mock.session_paused().unwrap());
        assert!(!mock
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
        assert!(pacing.started.lock().is_empty());
    }

    /// A DHT start that fails after the session resumed still starts the
    /// pace: the torrents the set-online paused are not left paused and held,
    /// where a retry would not reach them because the session runs.
    #[test]
    fn a_failed_dht_start_still_paces_what_the_set_online_paused() {
        use torrentd_engine::DesiredState;
        use torrentd_engine::EngineError;
        use torrentd_engine::MockEngine;
        use torrentd_engine::ProfileNetwork;

        let mut e = test_host_entry("p");
        e.config.network = ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6881".to_string(),
            dht: true,
        };
        let mock = Arc::new(MockEngine::new());
        e.engine = mock.clone();
        let r = ProfileRegistry::new(vec![e]);
        let metrics = crate::metrics_sink::PromSink::new();
        let id = ProfileId::new("p");
        let pacing = Fixed {
            torrents: vec![(handle(1), true)],
            started: Mutex::new(Vec::new()),
        };
        r.change_states(|rec| rec.set(&id, DesiredState::Offline), &metrics, &pacing)
            .unwrap();
        mock.inject_error(
            "apply_settings",
            EngineError::MockInjected {
                op: "apply_settings",
                message: "boom".into(),
            },
        );
        let err = r
            .change_states(|rec| rec.set(&id, DesiredState::Online), &metrics, &pacing)
            .unwrap_err();
        assert!(
            matches!(&err, StateChangeError::Apply(v) if matches!(v[..], [(_, Refusal::Engine(_))])),
            "{err}"
        );
        assert!(!mock.session_paused().unwrap());
        assert_eq!(*pacing.started.lock(), vec![vec![handle(1)]]);
    }

    /// A session whose paused state cannot be read is paced as if it were
    /// paused, rather than resumed bare with every torrent at once.
    #[test]
    fn an_unreadable_session_state_is_paced_as_paused() {
        use torrentd_engine::DesiredState;
        use torrentd_engine::EngineError;
        use torrentd_engine::MockEngine;
        use torrentd_engine::RecordedCall;

        let mut e = test_host_entry("p");
        let mock = Arc::new(MockEngine::new());
        e.engine = mock.clone();
        let r = ProfileRegistry::new(vec![e]);
        let metrics = crate::metrics_sink::PromSink::new();
        let id = ProfileId::new("p");
        let pacing = Fixed {
            torrents: vec![(handle(1), true), (handle(2), false)],
            started: Mutex::new(Vec::new()),
        };
        r.change_states(|rec| rec.set(&id, DesiredState::Offline), &metrics, &pacing)
            .unwrap();
        mock.inject_error(
            "session_paused",
            EngineError::MockInjected {
                op: "session_paused",
                message: "boom".into(),
            },
        );
        r.change_states(|rec| rec.set(&id, DesiredState::Online), &metrics, &pacing)
            .unwrap();
        let calls = mock.calls();
        let paused = calls
            .iter()
            .position(|c| matches!(c, RecordedCall::PauseTorrent(x) if *x == handle(1)))
            .unwrap();
        let resumed = calls
            .iter()
            .rposition(|c| matches!(c, RecordedCall::ResumeSession))
            .unwrap();
        assert!(paused < resumed);
        assert_eq!(*pacing.started.lock(), vec![vec![handle(1)]]);
        assert_eq!(r.holds().held(&id), HashSet::from([handle(1).infohash]));
    }

    /// A run that ends releases what it reached only while it is still the
    /// profile's: one a set-offline took back, or a newer run replaced,
    /// leaves the holds to whatever stopped it, which may have held those
    /// same torrents again.
    #[test]
    fn only_a_run_still_current_releases_what_it_reached() {
        let r = ProfileRegistry::new(vec![test_host_entry("p")]);
        let id = ProfileId::new("p");
        let entry = r.resolve(&id).active().unwrap();
        let both = HashSet::from([handle(1).infohash, handle(2).infohash]);
        r.holds()
            .hold(&id, [handle(1).infohash, handle(2).infohash])
            .unwrap();

        let taken = entry.begin_resume(vec![handle(1)]);
        entry.take_resume();
        entry.end_resume(&taken, &[handle(1)]);
        assert_eq!(r.holds().held(&id), both, "taken back: nothing released");

        let replaced = entry.begin_resume(vec![handle(1)]);
        let newer = entry.begin_resume(vec![handle(1), handle(2)]);
        entry.end_resume(&replaced, &[handle(1)]);
        assert_eq!(r.holds().held(&id), both, "replaced: nothing released");
        assert!(entry.is_resuming(), "and the newer run is still recorded");

        entry.end_resume(&newer, &[handle(1)]);
        assert_eq!(r.holds().held(&id), HashSet::from([handle(2).infohash]));
        assert!(!entry.is_resuming());
    }

    /// A run begun on a gate opened before it keeps to what a pause closed
    /// that gate with since: a torrent paused alone is not taken back, and a
    /// pause of the whole profile leaves none of it to take back.
    #[test]
    fn a_run_on_an_earlier_gate_keeps_the_pauses_made_since_it_opened() {
        let r = ProfileRegistry::new(vec![test_host_entry("p")]);
        let entry = r.resolve(&ProfileId::new("p")).active().unwrap();

        let gate = entry.open_gate();
        entry.exclude_from_resumes(handle(2));
        let run = entry.begin_resume_with(vec![handle(1), handle(2)], gate);
        assert_eq!(run.gate().resume(handle(2), || ()), Err(Gated::Excluded));
        assert_eq!(entry.take_resume(), Some(vec![handle(1)]));

        let gate = entry.open_gate();
        entry.halt_resumes();
        let run = entry.begin_resume_with(vec![handle(1), handle(2)], gate);
        assert_eq!(run.gate().resume(handle(1), || ()), Err(Gated::Halted));
        assert_eq!(entry.take_resume(), Some(vec![]));
    }
}
