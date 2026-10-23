//! Resume saves: the periodic sweep, the bounded in-flight dispatch, and the
//! shutdown drain that waits for every save to be answered.

use std::sync::Arc;
use std::time::Duration;

use libtorrent_safe::ResumeFlags;
use tracing::info;
use tracing::warn;

use super::builder::FenceHold;
use super::builder::MagnetGuardLift;
use super::builder::ProfileFenced;
use super::builder::ShutdownReason;
use super::run::dispatch_alert;
use super::RESUME_SAVES_IN_FLIGHT;
use super::SHUTDOWN_DRAIN_INTERVAL;
use crate::clock::Clock;
use crate::engine::TorrentEngine;
use crate::handlers::listen::ListenFailures;
use crate::handlers::warning::TrackerFailureLog;
use crate::metrics::MetricsSink;
use crate::resume_store::ResumeStore;
use crate::source::AlertSource;
use crate::state::StateMap;
use crate::torrent_store::TorrentStore;

pub(super) fn schedule_periodic_resume_saves(state: &Arc<StateMap>) {
    let handles = state.needing_resume_save();
    if handles.is_empty() {
        return;
    }
    info!(
        target: "torrentd_engine::alert_loop",
        torrent_count = handles.len(),
        "periodic resume save sweep",
    );
    for h in handles {
        state.queue_resume_save(h.infohash, ResumeFlags::ONLY_IF_MODIFIED);
    }
}

/// Hand queued resume saves to libtorrent until [`RESUME_SAVES_IN_FLIGHT`]
/// are outstanding.
pub(super) fn dispatch_saves(
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    metrics: &Arc<dyn MetricsSink>,
) {
    for (ih, flags) in state.dispatch_resume_saves(RESUME_SAVES_IN_FLIGHT) {
        // Removed since it was queued: nothing to save, and no alert coming.
        let Some(st) = state.get(&ih) else {
            state.note_resume_settled(&ih);
            continue;
        };
        let Some(engine) = source.engine_for(&st.profile_id) else {
            state.note_resume_settled(&ih);
            continue;
        };
        // A file left stale by a failed write: libtorrent's modified bit went
        // with the data that failed, so only an unconditional save rewrites it.
        let flags = if st.resume_write_failed {
            flags - ResumeFlags::ONLY_IF_MODIFIED
        } else {
            flags
        };
        if let Err(e) = engine.save_resume_data(st.handle, flags) {
            // Failed before reaching libtorrent, so no alert will settle it.
            state.note_resume_settled(&ih);
            warn!(
                target: "torrentd_engine::alert_loop",
                profile_id = %st.profile_id,
                infohash = %ih,
                error.cause = %e,
                "save_resume_data dispatch failed",
            );
            metrics.inc_counter(
                "resume_save_dispatch_errors_total",
                &[("profile_id", st.profile_id.as_str())],
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_shutdown(
    reason: ShutdownReason,
    deadline: Duration,
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    resume: &Arc<dyn ResumeStore>,
    torrents: &Arc<dyn TorrentStore>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
    profile_fenced: Option<&ProfileFenced>,
    fence_hold: Option<&FenceHold>,
    magnet_guard_lift: Option<&MagnetGuardLift>,
    listen_failures: &mut ListenFailures,
    tracker_failures: &mut TrackerFailureLog,
) -> u64 {
    let started = clock.now();
    let started_count = state.len();

    let stop_at = started + deadline;

    // Drain whatever's pending so the resume queue is in a known state. A pop
    // is capped at `MAX_ALERTS_PER_POP`, so one drain may leave a backlog;
    // keep draining while it comes back non-empty, bounded by the deadline.
    while drain_once(
        source,
        state,
        resume,
        torrents,
        metrics,
        clock,
        profile_fenced,
        fence_hold,
        magnet_guard_lift,
        listen_failures,
        tracker_failures,
    ) && clock.now() < stop_at
    {}

    // Queue one save per torrent; the dispatcher below hands them to
    // libtorrent a capped number at a time, and the resume handlers settle
    // each as its alert comes back.
    //
    // `ONLY_IF_MODIFIED`: libtorrent answers a torrent whose state has not
    // changed since its last save with a cheap "not modified" rather than
    // serialising and writing it again. On a 100K-torrent pool that is
    // nearly all of them, and forcing every one was most of what made the
    // drain outlast its deadline. A save whose answer was lost is re-asked
    // without the flag (see the dropped-alerts handler), because libtorrent
    // cleared its modified bit when it produced the answer nobody received.
    //
    // A torrent with a save already queued keeps that one: it is an add's
    // first save or such a re-ask, and both must stay unconditional. A
    // torrent the boot loaded from its own resume file has none queued (the
    // add handler skips it), so the requests here are not crowded out by
    // saves of files the boot has just read.
    let handles = state.handles();
    info!(
        target: "torrentd_engine::alert_loop",
        reason = ?reason,
        torrent_count = handles.len(),
        deadline_secs = deadline.as_secs(),
        "shutdown: requesting resume save for every torrent",
    );
    for h in handles {
        state.queue_resume_save(h.infohash, ResumeFlags::ONLY_IF_MODIFIED);
    }

    while clock.now() < stop_at {
        dispatch_saves(source, state, metrics);
        if state.pending_resume_count() == 0 {
            break;
        }
        let drained = drain_once(
            source,
            state,
            resume,
            torrents,
            metrics,
            clock,
            profile_fenced,
            fence_hold,
            magnet_guard_lift,
            listen_failures,
            tracker_failures,
        );
        if state.pending_resume_count() == 0 {
            break;
        }
        // Sleep only once a drain comes back empty: a pop is capped at
        // `MAX_ALERTS_PER_POP`, and libtorrent's own queue (10000 alerts)
        // drops `save_resume_data_alert`s once full, so a large pool's saves
        // must be drained as fast as they arrive, as the main loop does.
        if !drained {
            clock.sleep(SHUTDOWN_DRAIN_INTERVAL);
        }
    }

    // The answers that did arrive are queued on the stores' writers; they are
    // not saved until they are on disk. Not bounded by the deadline: dropping
    // data libtorrent already produced would be the worse outcome, and a
    // batch is a handful of flushes.
    resume.flush();
    torrents.flush();

    let outstanding = state.pending_resume_count();
    if outstanding > 0 {
        warn!(
            target: "torrentd_engine::alert_loop",
            torrent_count_initial = started_count,
            pending_resume_count = outstanding,
            elapsed_ms = clock.now().saturating_duration_since(started).as_millis() as u64,
            "shutdown deadline elapsed with unsaved resume data",
        );
    } else {
        info!(
            target: "torrentd_engine::alert_loop",
            torrent_count = started_count,
            elapsed_ms = clock.now().saturating_duration_since(started).as_millis() as u64,
            "shutdown clean: all resume data persisted",
        );
    }
    // Returned rather than counted: a `shutdown_unsaved_resumes_total` bumped
    // here was emitted as the process exited, so no scrape ever saw it. The
    // daemon persists this through `AlertLoopHandle::unsaved_at_shutdown`.
    outstanding
}

/// Dispatch one `source.drain()`; true when it returned any alert.
#[allow(clippy::too_many_arguments)]
fn drain_once(
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    resume: &Arc<dyn ResumeStore>,
    torrents: &Arc<dyn TorrentStore>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
    profile_fenced: Option<&ProfileFenced>,
    fence_hold: Option<&FenceHold>,
    magnet_guard_lift: Option<&MagnetGuardLift>,
    listen_failures: &mut ListenFailures,
    tracker_failures: &mut TrackerFailureLog,
) -> bool {
    let alerts = source.drain();
    let drained = !alerts.is_empty();
    for (profile, alert) in alerts {
        dispatch_alert(
            profile,
            alert,
            source,
            state,
            resume,
            torrents,
            metrics,
            clock,
            profile_fenced,
            fence_hold,
            magnet_guard_lift,
            listen_failures,
            tracker_failures,
        );
    }
    drained
}
