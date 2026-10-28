//! Lifting a pause a batch at a time: every bulk resume, a fence's lift or a
//! profile set online, goes through [`resume_paced`].

use std::sync::atomic;
use std::sync::Arc;
use std::time::Duration;

use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentHandle;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::reported_running;
use super::running_now;
use crate::metrics_sink::PromSink;
use crate::pacing::Pacer;
use crate::pacing::REANNOUNCE_PACE;
use crate::profile_registry::Gated;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ProfileStatus;
use crate::profile_registry::ResumeGate;

/// Which pause a [`spawn_lift`] is undoing, for its logs.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Lift {
    /// The kill-switch watch's fence, once the ruleset checks intact again.
    KillSwitch,
    /// Any fence, by the operator setting the profile online.
    SetOnline,
    /// The operator's offline, by setting the profile online or by
    /// online-all ([`OnlinePace`]).
    Offline,
}

impl Lift {
    fn as_str(self) -> &'static str {
        match self {
            Self::KillSwitch => "kill_switch",
            Self::SetOnline => "set_online",
            Self::Offline => "offline",
        }
    }
}

/// How the daemon paces a profile going online
/// ([`crate::profile_registry::OnlinePacing`]): the running torrents are read
/// from the state map, and resumed through [`spawn_lift`].
pub(crate) struct OnlinePace<'a> {
    pub(crate) profiles: &'a Arc<ProfileRegistry>,
    pub(crate) state: &'a StateMap,
    pub(crate) metrics: &'a Arc<PromSink>,
}

impl crate::profile_registry::OnlinePacing for OnlinePace<'_> {
    fn torrents(&self, id: &ProfileId) -> Vec<(TorrentHandle, bool)> {
        // The torrent's own paused flag: the session's pause does not set it.
        // The kill-switch fence reads what is running the same way.
        match self.profiles.resolve(id).active() {
            Some(entry) => running_now(entry, self.state),
            None => reported_running(id, self.state),
        }
    }

    fn start(&self, entry: &ProfileEntry, handles: Vec<TorrentHandle>) {
        info!(
            target: "torrentd::vpn_monitor",
            profile_id = %entry.id(),
            torrent_count = handles.len(),
            "profile set online; resuming its torrents a batch at a time",
        );
        spawn_lift(self.profiles, self.metrics, entry, handles, Lift::Offline);
    }
}

/// Resume `handles`, the torrents a fence or a profile's offline paused in
/// `entry`, from a task on the runtime through [`resume_paced`]: a batch per
/// [`REANNOUNCE_PACE`], since each one resumed sends its trackers a `started`
/// announce. The profile is marked lifted, or its session resumed, by the
/// caller, before this. A fence's lift instead records its run first and
/// drives it through [`spawn_run`].
///
/// The run is recorded on the entry ([`ProfileEntry::begin_resume`]), so a
/// fence that lands before it ends stops it and takes back what it had not
/// reached, a newer lift replaces and stops it, setting the profile offline
/// stops it and holds what it had not reached, and a pause in the profile
/// halts it or leaves the paused torrent out ([`ProfileEntry::halt_resumes`],
/// [`ProfileEntry::exclude_from_resumes`]). What it resumed, or left out for
/// the operator's pause, is then released from what a paced set-online holds,
/// if the run is still the profile's ([`ProfileEntry::end_resume`]); what it
/// did not reach, or refused, stays held. Must
/// be called inside the runtime: every caller runs on its blocking pool.
pub(crate) fn spawn_lift(
    profiles: &Arc<ProfileRegistry>,
    metrics: &Arc<PromSink>,
    entry: &ProfileEntry,
    handles: Vec<TorrentHandle>,
    lift: Lift,
) -> tokio::task::JoinHandle<Resumed> {
    let run = entry.begin_resume(handles);
    spawn_run(profiles, metrics, entry, run, lift)
}

/// Drive `run`, already recorded on `entry` by [`ProfileEntry::begin_resume`]
/// or [`ProfileEntry::begin_resume_with`], as [`spawn_lift`] does. A fence's
/// lift records its run before it marks the profile active, so a profile that
/// reads active while its torrents still read paused always has the run that
/// will resume them ([`ProfileEntry::resume_pending`]).
pub(crate) fn spawn_run(
    profiles: &Arc<ProfileRegistry>,
    metrics: &Arc<PromSink>,
    entry: &ProfileEntry,
    run: Arc<crate::profile_registry::PacedResume>,
    lift: Lift,
) -> tokio::task::JoinHandle<Resumed> {
    let (profiles, metrics, id) = (profiles.clone(), metrics.clone(), entry.id().clone());
    tokio::runtime::Handle::current().spawn(async move {
        let mut failed = std::collections::HashSet::new();
        let resumed = resume_paced(
            profiles.clone(),
            id.clone(),
            run.handles(),
            REANNOUNCE_PACE,
            {
                let run = run.clone();
                move || run.cancelled()
            },
            run.gate().clone(),
            metrics,
            |h, err| {
                failed.insert(h);
                error!(
                    target: "torrentd::vpn_monitor",
                    profile_id = %id,
                    lift = lift.as_str(),
                    infohash = %h.infohash,
                    error.cause = %err,
                    "could not resume a torrent while lifting the profile's fence",
                )
            },
        )
        .await;
        // The run goes in order, so what it reached is the front of its
        // list: resumed, left out for a pause, or refused. A refused one is
        // still paused by the pace, so it stays held.
        let reached: Vec<TorrentHandle> = run.handles()
            [..run.handles().len() - resumed.not_reached]
            .iter()
            .filter(|h| !failed.contains(*h))
            .copied()
            .collect();
        // Released only while the run is still the profile's: one a
        // set-offline, fence, pause or newer lift stopped leaves what is held
        // to whatever stopped it ([`ProfileEntry::end_resume`]).
        let release = {
            let (profiles, id, run) = (profiles.clone(), id.clone(), run.clone());
            tokio::task::spawn_blocking(move || {
                if let Some(entry) = profiles.resolve(&id).active() {
                    entry.end_resume(&run, &reached);
                }
            })
        };
        if let Err(e) = release.await {
            if e.is_panic() {
                std::panic::resume_unwind(e.into_panic());
            }
        }
        info!(
            target: "torrentd::vpn_monitor",
            profile_id = %id,
            lift = lift.as_str(),
            torrent_count = resumed.resumed,
            failed_count = resumed.refused,
            not_reached = resumed.not_reached,
            excluded_count = resumed.excluded,
            halted = resumed.halted,
            "finished resuming the torrents of a lifted fence; any not reached were stopped \
             by a fence, a newer lift or a pause of the profile that landed first",
        );
        resumed
    })
}

/// What a [`resume_paced`] run reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Resumed {
    /// Torrents the session resumed.
    pub(crate) resumed: u64,
    /// Torrents the session refused to resume.
    pub(crate) refused: u64,
    /// Torrents left paused because the run stopped before them: the profile
    /// was fenced or paused, or the run was cancelled.
    pub(crate) not_reached: usize,
    /// Torrents left out because the operator paused each while the run ran.
    pub(crate) excluded: u64,
    /// Whether a pause of the whole profile stopped the run.
    pub(crate) halted: bool,
}

/// How one batch of [`resume_paced`] ended.
pub(super) enum Batch {
    /// Resumed, each refusal with why, unless a pause stopped it partway.
    Done {
        resumed: u64,
        refused: Vec<(TorrentHandle, torrentd_engine::EngineError)>,
        excluded: u64,
        /// How many of the batch a pause of the profile left unreached.
        halted: Option<usize>,
    },
    /// Not started: the profile is fenced or gone, or the run was cancelled.
    Stopped,
    /// Fenced while the batch went out; what it resumed was paused again.
    Fenced,
}

/// Resume `handles` in `id`'s session a batch at a time, `pace` apart,
/// through the shared [`Pacer`], and count what the session resumed
/// and refused. Each refusal is also handed to `refused`.
///
/// Every bulk resume goes through this. Each torrent resumed announces
/// `started` to its trackers, and one resumed with the rest of a profile at
/// once hands the trackers a flood from one address and the session's alert
/// queue more tracker alerts than it holds. Each batch runs on the blocking
/// pool, since every call takes the session's lock; between batches the run
/// holds no thread.
///
/// The run stops before a batch once the profile is fenced (`vpn_down`) or
/// `cancelled` says so, and what it has not reached stays paused. `cancelled`
/// is read again on the blocking pool once the batch has read the profile
/// unfenced: a lift that replaces this run cancels it before it marks the
/// profile active, so a batch that reads the profile active only because of
/// that lift sees the cancel and leaves its torrents to the lift's own run,
/// rather than resuming them a second time. A fence can
/// also land while a batch is going out, its walk pausing some of the batch
/// before this resumes them. So after each batch the profile's mark is read
/// again: the fence marks before it walks, so either this read sees the mark
/// and pauses the batch again, or the mark, and the walk after it, came after
/// every resume in the batch.
///
/// A pause in the profile while the run goes on is kept to through `gate`
/// ([`ResumeGate`]): a pause of the whole profile stops the run, its
/// remainder counted as not reached, and a torrent paused on its own is left
/// out.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resume_paced(
    profiles: Arc<ProfileRegistry>,
    id: ProfileId,
    handles: &[TorrentHandle],
    pace: Duration,
    cancelled: impl Fn() -> bool + Clone + Send + 'static,
    gate: Arc<ResumeGate>,
    metrics: Arc<PromSink>,
    mut refused: impl FnMut(TorrentHandle, torrentd_engine::EngineError),
) -> Resumed {
    let mut out = Resumed::default();
    let mut pacer = Pacer::new(handles.len(), pace);
    while let Some(range) = pacer.next_batch().await {
        let left = handles.len() - range.start;
        let end = range.end;
        if gate.halted() {
            out.not_reached = left;
            out.halted = true;
            break;
        }
        if cancelled() {
            out.not_reached = left;
            break;
        }
        let batch = handles[range].to_vec();
        let ran = tokio::task::spawn_blocking({
            let (profiles, id, metrics, gate, cancelled) = (
                profiles.clone(),
                id.clone(),
                metrics.clone(),
                gate.clone(),
                cancelled.clone(),
            );
            move || resume_batch(&profiles, &id, batch, &gate, &cancelled, metrics.as_ref())
        })
        .await;
        match ran {
            Ok(Batch::Done {
                resumed,
                refused: failed,
                excluded,
                halted,
            }) => {
                out.resumed += resumed;
                out.refused += failed.len() as u64;
                out.excluded += excluded;
                for (h, err) in failed {
                    refused(h, err);
                }
                if let Some(in_batch) = halted {
                    out.not_reached = in_batch + (handles.len() - end);
                    out.halted = true;
                    break;
                }
            }
            Ok(Batch::Stopped | Batch::Fenced) => {
                out.not_reached = left;
                break;
            }
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            // Only a runtime shutting down cancels a blocking task.
            Err(_) => {
                out.not_reached = left;
                break;
            }
        }
    }
    out
}

/// Run by [`resume_batch`], in the profile it names, with each torrent's
/// index in the batch before the torrent goes through the gate, outside the
/// gate's lock: so a test can land a pause between two resumes of one
/// batch, which the lock held across each resume otherwise leaves to a race.
#[cfg(test)]
pub(super) static BEFORE_GATED_RESUME: std::sync::Mutex<Option<(ProfileId, BeforeGatedResume)>> =
    std::sync::Mutex::new(None);

/// [`BEFORE_GATED_RESUME`]'s hook.
#[cfg(test)]
pub(super) type BeforeGatedResume = Box<dyn Fn(usize) + Send>;

/// One batch of [`resume_paced`], on the blocking pool.
pub(super) fn resume_batch(
    profiles: &ProfileRegistry,
    id: &ProfileId,
    batch: Vec<TorrentHandle>,
    gate: &ResumeGate,
    cancelled: &dyn Fn() -> bool,
    metrics: &dyn MetricsSink,
) -> Batch {
    let Some(entry) = profiles.resolve(id).active() else {
        return Batch::Stopped;
    };
    if entry.health().status == ProfileStatus::VpnDown {
        return Batch::Stopped;
    }
    // Read after the mark: a lift cancels the run it replaces before it marks
    // the profile active, so a run whose check before this batch passed while
    // the profile was fenced, and which reads it active only now, sees that
    // cancel here. Its torrents are the lift's run's to resume.
    if cancelled() {
        return Batch::Stopped;
    }
    let mut resumed = Vec::with_capacity(batch.len());
    let mut refused = Vec::new();
    let mut excluded = 0u64;
    let mut halted = None;
    let total = batch.len();
    for (i, h) in batch.into_iter().enumerate() {
        #[cfg(test)]
        if let Some((hooked, hook)) = &*BEFORE_GATED_RESUME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            if hooked == id {
                hook(i);
            }
        }
        // Noted running before the resume, so a kill-switch fence landing
        // after it, before a state update reports it, resumes it on its
        // lift; put back if the session refuses it.
        let resume = || {
            let before = entry.note_running(h, true);
            entry
                .engine
                .resume_torrent(h)
                .inspect_err(|_| entry.restore_noted(h, before))
        };
        match gate.resume(h, resume) {
            Ok(Ok(())) => resumed.push(h),
            Ok(Err(err)) => refused.push((h, err)),
            Err(Gated::Excluded) => excluded += 1,
            Err(Gated::Halted) => {
                halted = Some(total - i);
                break;
            }
        }
    }
    // Pairs with the fence's, between its mark and its walk.
    atomic::fence(atomic::Ordering::SeqCst);
    if entry.health().status != ProfileStatus::VpnDown {
        return Batch::Done {
            resumed: resumed.len() as u64,
            refused,
            excluded,
            halted,
        };
    }
    let labels = [("profile_id", id.as_str())];
    for h in resumed {
        // Paused again, so its note no longer holds; the fence that landed
        // owns what its lift resumes.
        entry.restore_noted(h, None);
        if let Err(err) = entry.engine.pause_torrent(h) {
            error!(
                target: "torrentd::vpn_monitor",
                profile_id = %id,
                infohash = %h.infohash,
                error.cause = %err,
                "could not pause again a torrent resumed as the profile was fenced",
            );
            metrics.inc_counter("profile_fence_pause_errors_total", &labels);
        }
    }
    warn!(
        target: "torrentd::vpn_monitor",
        profile_id = %id,
        "profile fenced while its torrents were being resumed; paused the last batch again \
         and stopped",
    );
    Batch::Fenced
}
