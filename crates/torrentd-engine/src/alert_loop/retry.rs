//! The disk-error retry timer: what a due retry does, and when it is put
//! off.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::builder::CheckSlots;
use super::builder::ProfileFenced;
use crate::clock::Clock;
use crate::engine::TorrentEngine;
use crate::metrics::MetricsSink;
use crate::profile::ProfileId;
use crate::source::AlertSource;
use crate::state::StateMap;
use crate::state::TorrentPhase;

pub(super) fn execute_due_retries(
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
    profile_fenced: Option<&ProfileFenced>,
    check_slots: Option<&dyn CheckSlots>,
    now: Instant,
) {
    let due = state.retries_due(now);
    if due.is_empty() {
        return;
    }
    for handle in due {
        let Some(st) = state.get(&handle.infohash) else {
            continue;
        };
        // The VPN monitor pauses every torrent in a profile whose tunnel went
        // down and refuses to restart it without an operator. Resuming one on
        // the disk-error retry timer would un-quarantine it individually,
        // which is the thing fencing exists to prevent.
        //
        // `retries_due` popped this torrent's deadline, so a skip has to
        // schedule another look itself, or a torrent whose fence later lifts
        // is never retried again. Look again after the initial delay, attempt
        // count unchanged: skipping is not an attempt.
        if profile_fenced.is_some_and(|f| f(&st.profile_id)) {
            debug!(
                target: "torrentd_engine::alert_loop",
                profile_id = %st.profile_id,
                infohash = %handle.infohash,
                "retry skipped: profile is fenced",
            );
            defer_retry(state, clock, &handle.infohash);
            continue;
        }
        // What a `file_error_alert` leaves behind under this daemon's flags
        // (vendor/libtorrent/src/torrent.cpp, `handle_disk_error` and
        // `on_piece_hashed`): any failure while checking, or a failed
        // `read_piece`, sets an error on the torrent and pauses it. That
        // error-paused torrent is the first thing to recover, and `resume()`
        // recovers it: `torrent::do_resume` unpauses and calls `clear_error`,
        // which re-checks the files if the error came from a check.
        //
        // The rest set no error and pause nothing. A disk read for a peer's
        // request that fails (vendor/libtorrent/src/peer_connection.cpp,
        // `on_disk_read_complete`) rejects the request, posts the alert and
        // carries on seeding; a write failure of the disk-full / read-only
        // kind only sets upload mode, which every torrent here already
        // carries (`policy::no_download`); ENOMEM only disconnects the peer.
        // The status updates keep such a torrent in `DiskError`, and nothing
        // libtorrent reports says whether its files are readable again, so
        // the retry re-checks it. A check that fails takes the error-paused
        // route above; one that passes leaves the torrent seeding.
        //
        // A torrent in neither state has nothing for the retry to do — it
        // recovered, or an operator paused or resumed it — and acting on it
        // anyway would undo an operator's pause every hour, forever, because
        // nothing else ever clears the timer. Retire it.
        //
        // Except while the torrent is checking. `clear_error` empties the
        // error before the re-check it starts, so a check still running when
        // the timer comes due shows no error although it has not recovered
        // yet. Retiring then would let the check's own `file_error` re-arm
        // the timer from `RetryState::first`, and a torrent whose check
        // outlasts the delay would re-check every minute instead of backing
        // off to hourly. Hold the timer, attempt count unchanged, for another
        // delay at the current backoff, and decide once the check has ended.
        if !st.has_error && st.phase == TorrentPhase::Checking {
            debug!(
                target: "torrentd_engine::alert_loop",
                profile_id = %st.profile_id,
                infohash = %handle.infohash,
                "disk-error retry deferred: torrent is still checking",
            );
            state.update(&handle.infohash, |s| {
                if let Some(r) = s.retry.as_mut() {
                    r.next_attempt =
                        clock.now() + crate::state::RetryState::delay_for_attempt(r.attempts);
                }
            });
            continue;
        }
        if !st.has_error && st.phase != TorrentPhase::DiskError {
            debug!(
                target: "torrentd_engine::alert_loop",
                profile_id = %st.profile_id,
                infohash = %handle.infohash,
                "disk-error retry retired: torrent carries no libtorrent error",
            );
            state.update(&handle.infohash, |s| s.retry = None);
            continue;
        }
        // No session for the profile right now: look again later, as for a
        // fenced profile.
        let Some(engine) = source.engine_for(&st.profile_id) else {
            defer_retry(state, clock, &handle.infohash);
            continue;
        };
        // Either branch below can start a check: the re-check of a torrent
        // libtorrent kept serving, and the resume, whose `clear_error`
        // re-checks the files where the error came from a check. Each takes
        // a slot in the daemon's check limit first, or waits for one as for
        // a fenced profile: skipping is not an attempt.
        if check_slots.is_some_and(|c| !c.try_take(&st.profile_id, handle.infohash)) {
            debug!(
                target: "torrentd_engine::alert_loop",
                profile_id = %st.profile_id,
                infohash = %handle.infohash,
                "disk-error retry deferred: no check slot is free",
            );
            defer_retry(state, clock, &handle.infohash);
            continue;
        }
        if !st.has_error {
            recheck_unpaused_disk_error(engine.as_ref(), state, clock, handle, &st.profile_id);
            continue;
        }
        match engine.resume_torrent(handle) {
            // The fence check above and this resume are not atomic. A fence
            // whose walk paused this torrent between the two would have it
            // running again in a `vpn_down` profile, and the monitor never
            // fences a profile already marked, so nothing would pause it until
            // an operator set the profile online. Ask again after the resume,
            // as the daemon's single resume does: the `SeqCst` fence pairs
            // with the one the VPN monitor's fence issues between its mark and
            // its walk, so either this read sees the mark, or the mark and the
            // walk that pauses this torrent came after the resume. Seeing it,
            // pause the torrent again and look later, as for a skip: the
            // resume was undone, so it is not an attempt.
            Ok(())
                if {
                    std::sync::atomic::fence(Ordering::SeqCst);
                    profile_fenced.is_some_and(|f| f(&st.profile_id))
                } =>
            {
                match engine.pause_torrent(handle) {
                    Ok(()) => warn!(
                        target: "torrentd_engine::alert_loop",
                        profile_id = %st.profile_id,
                        infohash = %handle.infohash,
                        "disk-error retry: profile was fenced while the torrent was being resumed; paused it again",
                    ),
                    Err(e) => {
                        error!(
                            target: "torrentd_engine::alert_loop",
                            profile_id = %st.profile_id,
                            infohash = %handle.infohash,
                            error.cause = %e,
                            "disk-error retry: could not pause again a torrent resumed as its profile was fenced",
                        );
                        metrics.inc_counter(
                            "profile_fence_pause_errors_total",
                            &[("profile_id", st.profile_id.as_str())],
                        );
                    }
                }
                // Paused again before any check could run: the slot it took
                // would otherwise be held until the check it never ran ends.
                if let Some(c) = check_slots {
                    c.release(&handle.infohash);
                }
                defer_retry(state, clock, &handle.infohash);
            }
            Ok(()) => {
                info!(
                    target: "torrentd_engine::alert_loop",
                    profile_id = %st.profile_id,
                    infohash = %handle.infohash,
                    "disk-error retry: resumed torrent to clear its libtorrent error",
                );
                state.update(&handle.infohash, |s| {
                    let attempts = s.retry.as_ref().map(|r| r.attempts).unwrap_or(0);
                    s.retry = Some(crate::state::RetryState::next(clock.now(), attempts));
                });
                metrics.inc_counter(
                    "disk_error_retry_attempts_total",
                    &[("profile_id", st.profile_id.as_str())],
                );
            }
            Err(e) => {
                warn!(
                    target: "torrentd_engine::alert_loop",
                    profile_id = %st.profile_id,
                    infohash = %handle.infohash,
                    error.cause = %e,
                    "disk-error retry: resume failed",
                );
                metrics.inc_counter(
                    "disk_error_retry_errors_total",
                    &[("profile_id", st.profile_id.as_str())],
                );
                // A failed resume is still an attempt: back off and schedule
                // the next one, or the popped deadline was the last.
                state.update(&handle.infohash, |s| {
                    let attempts = s.retry.as_ref().map(|r| r.attempts).unwrap_or(0);
                    s.retry = Some(crate::state::RetryState::next(clock.now(), attempts));
                });
            }
        }
    }
}

/// The disk-error retry for a torrent in `DiskError` that libtorrent kept
/// serving: re-check it, and back off as for a resume.
///
/// The phase moves to `Checking` here rather than waiting for a status update
/// to report it. A check that passes leaves `DiskError` either way: libtorrent
/// posts `torrent_finished_alert` when it does, and that handler sets
/// `Seeding`. Setting `Checking` now does two other things. The phase filter
/// and `/status` show the check from the moment it starts, not `DiskError`
/// until the next update. And a check that fails before any update arrives
/// posts its `file_error` on a `Checking` torrent, which the file-error
/// handler records as libtorrent's error-and-pause; on a torrent still in
/// `DiskError` with no error it would read as one more failed peer read, and
/// `has_error` would stay wrong until the next update reported the error.
///
/// Not counted in `disk_error_retry_attempts_total` or
/// `disk_error_retry_errors_total`, which count resumes; the check it starts
/// is counted in `torrents_checked_total` when it completes.
fn recheck_unpaused_disk_error(
    engine: &dyn TorrentEngine,
    state: &StateMap,
    clock: &Arc<dyn Clock>,
    handle: libtorrent_safe::TorrentHandle,
    profile_id: &ProfileId,
) {
    let outcome = engine.force_recheck(handle);
    match &outcome {
        Ok(()) => info!(
            target: "torrentd_engine::alert_loop",
            profile_id = %profile_id,
            infohash = %handle.infohash,
            "disk-error retry: re-checking a torrent libtorrent kept seeding after a file error",
        ),
        Err(e) => warn!(
            target: "torrentd_engine::alert_loop",
            profile_id = %profile_id,
            infohash = %handle.infohash,
            error.cause = %e,
            "disk-error retry: re-check failed to start",
        ),
    }
    state.update(&handle.infohash, |s| {
        if outcome.is_ok() {
            s.phase = TorrentPhase::Checking;
        }
        let attempts = s.retry.as_ref().map(|r| r.attempts).unwrap_or(0);
        s.retry = Some(crate::state::RetryState::next(clock.now(), attempts));
    });
}

/// Schedule another look at a due retry that was skipped without an attempt,
/// [`RetryState::INITIAL_DELAY`](crate::state::RetryState::INITIAL_DELAY)
/// from now, keeping its attempt count.
fn defer_retry(state: &StateMap, clock: &Arc<dyn Clock>, ih: &libtorrent_safe::InfoHash) {
    state.update(ih, |s| {
        if let Some(r) = s.retry.as_mut() {
            r.next_attempt = clock.now() + crate::state::RetryState::INITIAL_DELAY;
        }
    });
}
