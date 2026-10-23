//! The loop body: one iteration drains alerts, runs the timers, tops up
//! resume saves, and stamps the heartbeat, until a shutdown signal hands
//! over to the shutdown coordinator.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crossbeam_channel::Receiver;
use crossbeam_channel::TryRecvError;
use libtorrent_safe::Alert;
use libtorrent_safe::TorrentFlags;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::warn;

use super::builder::CheckSlots;
use super::builder::FatalCallback;
use super::builder::FenceHold;
use super::builder::ListenDeviceCheck;
use super::builder::MagnetGuardLift;
use super::builder::ProfileFenced;
use super::builder::ShutdownReason;
use super::retry::execute_due_retries;
use super::saves::dispatch_saves;
use super::saves::run_shutdown;
use super::saves::schedule_periodic_resume_saves;
use super::POLL_IDLE_INTERVAL;
use super::POST_STATS_INTERVAL;
use super::POST_UPDATES_INTERVAL;
use super::RESUME_SAVE_INTERVAL;
use crate::clock::Clock;
use crate::engine::TorrentEngine;
use crate::handlers::listen::ListenFailures;
use crate::handlers::warning::TrackerFailureLog;
use crate::handlers::HandlerCtx;
use crate::handlers::{self};
use crate::metrics::MetricsSink;
use crate::port_forward::ListenEvents;
use crate::profile::ProfileId;
use crate::resume_store::ResumeStore;
use crate::source::AlertSource;
use crate::state::StateMap;
use crate::torrent_store::TorrentStore;

/// Wall-clock milliseconds since the Unix epoch. Deliberately not routed
/// through `Clock`: the heartbeat is compared against `SystemTime::now()` by
/// the HTTP layer, which a mocked monotonic clock would not line up with.
pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// How long since the alert loop last completed an iteration.
///
/// Saturates at zero rather than panicking if the clock steps backwards.
pub fn heartbeat_age(heartbeat: &AtomicU64) -> Duration {
    let last = heartbeat.load(Ordering::Relaxed);
    Duration::from_millis(now_millis().saturating_sub(last))
}

/// Out-of-band wiring the loop shares with the daemon: liveness reporting and
/// the fatal-failure escape hatch.
pub(super) struct LoopHooks {
    pub(super) heartbeat: Arc<AtomicU64>,
    pub(super) listen_failed: Arc<AtomicBool>,
    pub(super) fatal_listen_failure: bool,
    pub(super) on_fatal: Option<FatalCallback>,
    pub(super) profile_fenced: Option<ProfileFenced>,
    pub(super) fence_hold: Option<FenceHold>,
    pub(super) magnet_guard_lift: Option<MagnetGuardLift>,
    pub(super) check_slots: Option<Arc<dyn CheckSlots>>,
    pub(super) unsaved_at_shutdown: Arc<AtomicU64>,
    pub(super) listen_events: Option<Arc<ListenEvents>>,
    pub(super) listen_device_check: Option<ListenDeviceCheck>,
    pub(super) shutdown_deadline: Duration,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    shutdown_rx: Receiver<ShutdownReason>,
    source: Arc<dyn AlertSource>,
    state: Arc<StateMap>,
    resume: Arc<dyn ResumeStore>,
    torrents: Arc<dyn TorrentStore>,
    metrics: Arc<dyn MetricsSink>,
    clock: Arc<dyn Clock>,
    hooks: LoopHooks,
) {
    let mut last_post_updates = clock.now();
    let mut last_post_stats = clock.now();
    let mut last_resume_save = clock.now();
    // Which of each profile's listen sockets are failed. Kept here rather
    // than derived from the last listen alert: a profile's sockets each
    // report on their own.
    let mut listen_failures = ListenFailures::default();
    // How many tracker failures each profile has warned about in its current
    // window, so an outage across every torrent is a bounded number of lines.
    let mut tracker_failures = TrackerFailureLog::default();
    // What each profile's translation failure count was when last published.
    let mut translate_errors = TranslateErrors::default();

    loop {
        // 0) Liveness stamp. Written at the top of every iteration so a loop
        //    wedged inside a handler stops refreshing it and /healthz fails.
        hooks.heartbeat.store(now_millis(), Ordering::Relaxed);

        // 1) Shutdown probe. A dropped handle is a shutdown too: nothing can
        //    signal one any more, and treating the closed channel as empty
        //    left the loop running with no way to stop it and no shutdown
        //    save when the process ended.
        let signalled = match shutdown_rx.try_recv() {
            Ok(reason) => Some(reason),
            Err(TryRecvError::Disconnected) => Some(ShutdownReason::HandleDropped),
            Err(TryRecvError::Empty) => None,
        };
        if let Some(reason) = signalled {
            info!(target: "torrentd_engine::alert_loop", reason = ?reason, "shutdown signaled");
            let unsaved = run_shutdown(
                reason,
                hooks.shutdown_deadline,
                &source,
                &state,
                &resume,
                &torrents,
                &metrics,
                &clock,
                hooks.profile_fenced.as_ref(),
                hooks.fence_hold.as_ref(),
                hooks.magnet_guard_lift.as_ref(),
                &mut listen_failures,
                &mut tracker_failures,
            );
            // The shutdown's own drains can lose alerts too, resume answers
            // among them.
            translate_errors.publish(&source, &metrics);
            hooks.unsaved_at_shutdown.store(unsaved, Ordering::Relaxed);
            return;
        }

        // 2) Drain alerts.
        let drained = source.drain();
        let was_empty = drained.is_empty();
        let mut fatal: Option<&'static str> = None;
        for (profile, alert) in drained {
            // A listen socket that fails when this is the only live session
            // is fatal — there is no other session to carry the load, so
            // seeding silently stops. Note it, finish dispatching the batch
            // (so the failure is logged and counted), then unwind. Except
            // where a NAT-PMP rebind is moving the session onto that
            // endpoint's port: the failure is published below to the waiting
            // rebind, which puts the previous port back. Asked before the
            // publish, which is what wakes the rebind and ends it.
            //
            // An accept that ran out of file descriptors is none of this:
            // libtorrent keeps accepting on that socket, so it is neither
            // fatal nor published, and its handler counts it apart.
            let accept_emfile = handlers::listen::is_accept_emfile(&alert);
            if let (Alert::ListenFailed { endpoint, .. }, false) = (&alert, accept_emfile) {
                let rebinding = hooks
                    .listen_events
                    .as_ref()
                    .is_some_and(|events| events.rebind_in_progress(&profile, endpoint));
                if rebinding {
                    warn!(
                        target: "torrentd_engine::alert_loop",
                        profile_id = %profile,
                        endpoint = %endpoint,
                        "listen socket failed on the port a NAT-PMP rebind is moving to; \
                         the rebind reverts to the previous port, so the daemon keeps running",
                    );
                } else if hooks.fatal_listen_failure {
                    fatal.get_or_insert(
                        "the only live session's listen socket failed; shutting down",
                    );
                } else {
                    // Not fatal, and previously visible only as a Prometheus
                    // counter. A session that accepts no incoming connections
                    // is worth a line in the journal too, naming which
                    // account it is.
                    warn!(
                        target: "torrentd_engine::alert_loop",
                        profile_id = %profile,
                        "listen socket failed; this profile accepts no incoming connections. \
                         Other sessions are still live, so the daemon keeps running",
                    );
                }
            }
            // A socket held to the wrong device is fatal with any number of
            // sessions: its uTP and tracker traffic leaves outside the
            // tunnel, and the route probe, which asks the routing table,
            // cannot see it.
            let mut wrong_device = None;
            if let (Alert::ListenSucceeded { endpoint, .. }, Some(check)) =
                (&alert, &hooks.listen_device_check)
            {
                if let Err(cause) = check(&profile, endpoint) {
                    error!(
                        target: "torrentd_engine::alert_loop",
                        profile_id = %profile,
                        endpoint = %endpoint,
                        error.kind = "listen_wrong_device",
                        error.cause = %cause,
                        "a listen socket is not held to the profile's tunnel device",
                    );
                    fatal.get_or_insert(
                        "a listen socket is not held to its profile's tunnel device; shutting down",
                    );
                    // Before the drain, which can last `shutdown_drain_secs`
                    // (up to an hour), and before the failure is published,
                    // which wakes a rebind waiting on it.
                    take_profile_off_the_wire(&profile, &source);
                    wrong_device = Some(cause);
                }
            }
            if let Some(events) = &hooks.listen_events {
                match &alert {
                    // Published as the failure it is, so a rebind waiting on
                    // it reverts instead of announcing the new port.
                    Alert::ListenSucceeded { endpoint, .. } => {
                        events.publish(&profile, endpoint, wrong_device)
                    }
                    Alert::ListenFailed {
                        endpoint, message, ..
                    } if !accept_emfile => {
                        events.publish(&profile, endpoint, Some(message.clone()))
                    }
                    _ => {}
                }
            }
            dispatch_alert(
                profile,
                alert,
                &source,
                &state,
                &resume,
                &torrents,
                &metrics,
                &clock,
                hooks.profile_fenced.as_ref(),
                hooks.fence_hold.as_ref(),
                hooks.magnet_guard_lift.as_ref(),
                &mut listen_failures,
                &mut tracker_failures,
            );
        }
        // After every drain, an empty one included: a pop whose every alert
        // failed to translate comes back empty.
        translate_errors.publish(&source, &metrics);
        if let Some(why) = fatal {
            hooks.listen_failed.store(true, Ordering::Relaxed);
            error!(target: "torrentd_engine::alert_loop", "{why}");
            if let Some(cb) = &hooks.on_fatal {
                cb(ShutdownReason::ListenFailed);
            }
            let unsaved = run_shutdown(
                ShutdownReason::ListenFailed,
                hooks.shutdown_deadline,
                &source,
                &state,
                &resume,
                &torrents,
                &metrics,
                &clock,
                hooks.profile_fenced.as_ref(),
                hooks.fence_hold.as_ref(),
                hooks.magnet_guard_lift.as_ref(),
                &mut listen_failures,
                &mut tracker_failures,
            );
            // The shutdown's own drains can lose alerts too, resume answers
            // among them.
            translate_errors.publish(&source, &metrics);
            hooks.unsaved_at_shutdown.store(unsaved, Ordering::Relaxed);
            return;
        }

        // 2b) Listen outcomes become waitable once a drain comes back empty.
        //     Until then the loop is still working through the boot backlog
        //     (resume data and .torrent scans can queue thousands of alerts),
        //     and a rebind's outcome would sit behind it for longer than a
        //     rebind waits. A rebind before this point is deferred and
        //     retried rather than counted as failed.
        if was_empty {
            if let Some(events) = &hooks.listen_events {
                if !events.is_attached() {
                    events.attach();
                }
            }
        }

        // 3) Tickers.
        let now = clock.now();
        if now.saturating_duration_since(last_post_updates) >= POST_UPDATES_INTERVAL {
            source.post_updates_all();
            last_post_updates = now;
        }
        if now.saturating_duration_since(last_post_stats) >= POST_STATS_INTERVAL {
            source.post_stats_all();
            last_post_stats = now;
        }
        if now.saturating_duration_since(last_resume_save) >= RESUME_SAVE_INTERVAL {
            schedule_periodic_resume_saves(&state);
            last_resume_save = now;
        }
        // Top the in-flight saves back up from the queue: the sweep above,
        // and saves re-queued after an alert overflow.
        dispatch_saves(&source, &state, &metrics);

        // 4) Retry timer.
        execute_due_retries(
            &source,
            &state,
            &metrics,
            &clock,
            hooks.profile_fenced.as_ref(),
            hooks.check_slots.as_deref(),
            now,
        );

        // 5) Sleep if there's nothing to do.
        if was_empty {
            clock.sleep(POLL_IDLE_INTERVAL);
        }
    }
}

/// Each profile's [`TorrentEngine::alert_translate_errors`] as last
/// published, so what is added to `alert_translate_errors_total` is the rise
/// since then.
///
/// Starts at 0 for every profile, which is where a session's count starts:
/// what the boot's backlog lost is published by the first drain, before
/// anything scrapes, and the `boot_alert_translate_errors` gauge carries it.
#[derive(Debug, Default)]
pub(super) struct TranslateErrors {
    published: HashMap<ProfileId, u64>,
}

impl TranslateErrors {
    /// Add each profile's rise to the counter, and warn about it.
    pub(super) fn publish(
        &mut self,
        source: &Arc<dyn AlertSource>,
        metrics: &Arc<dyn MetricsSink>,
    ) {
        for profile in source.profiles() {
            let Some(engine) = source.engine_for(&profile) else {
                continue;
            };
            let count = engine.alert_translate_errors();
            let published = self.published.entry(profile.clone()).or_insert(0);
            // The count is monotonic for a session, so a lower one is a
            // session other than the one last read, counted from its own 0.
            let lost = count.checked_sub(*published).unwrap_or(count);
            *published = count;
            if lost == 0 {
                continue;
            }
            metrics.add_counter(
                "alert_translate_errors_total",
                lost,
                &[("profile_id", profile.as_str())],
            );
            warn!(
                target: "torrentd_engine::alert_loop",
                profile_id = %profile,
                lost,
                total = count,
                "libtorrent alerts were dropped because they could not be translated; the \
                 state map may have missed a torrent's removal or a resume save's answer",
            );
        }
    }
}

/// Close every listen socket of `profile`'s session, then pause the session,
/// so a profile found sending by the wrong device sends nothing more while
/// the daemon drains.
///
/// The order matters. A paused torrent sends libtorrent's `stopped` announce,
/// and libtorrent announces once per listen socket, the wrong one included,
/// so pausing first would announce through the socket being fenced. With
/// `listen_interfaces` empty the session holds no listen socket, and so no
/// uTP, UDP tracker or announce endpoint, and the pause then reaches no
/// tracker. The two calls are queued on the session in that order.
///
/// Each refusal is logged and does not stop the other: the daemon is
/// shutting down either way.
fn take_profile_off_the_wire(profile: &ProfileId, source: &Arc<dyn AlertSource>) {
    let Some(engine) = source.engine_for(profile) else {
        return;
    };
    let close = libtorrent_safe::Settings {
        listen_interfaces: Some(String::new()),
        ..Default::default()
    };
    if let Err(e) = engine.apply_settings(&close) {
        error!(
            target: "torrentd_engine::alert_loop",
            profile_id = %profile,
            error.kind = "listen_close_failed",
            error.cause = %e,
            "could not close the profile's listen sockets; they stay open until the session \
             closes at the end of the shutdown drain",
        );
    }
    if let Err(e) = engine.pause_session() {
        error!(
            target: "torrentd_engine::alert_loop",
            profile_id = %profile,
            error.kind = "session_pause_failed",
            error.cause = %e,
            "could not pause the profile's session; its torrents keep running until the \
             session closes at the end of the shutdown drain",
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_alert(
    profile: ProfileId,
    alert: Alert,
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
) {
    let Some(engine) = source.engine_for(&profile) else {
        warn!(
            target: "torrentd_engine::alert_loop",
            profile_id = %profile,
            "alert for unknown profile; dropping",
        );
        return;
    };
    // The target this span had before the loop was split into submodules,
    // which a log filter or query may name.
    let span = info_span!(
        target: "torrentd_engine::alert_loop",
        "alert",
        profile_id = %profile,
        alert_type = alert.kind().as_str(),
    );
    let mut ctx = HandlerCtx {
        state: state.as_ref(),
        resume: resume.as_ref(),
        torrents: torrents.as_ref(),
        metrics: metrics.as_ref(),
        clock: clock.as_ref(),
        engine: &engine,
        profile_fenced,
        fence_hold,
        profile_id: profile,
        span,
    };
    // Any alert of the profile closes a tracker-failure window that has run
    // its length, so its summary is written even after the tracker goes quiet.
    handlers::warning::close_failure_window(&ctx, tracker_failures);

    match &alert {
        Alert::AddTorrent { .. } | Alert::TorrentRemoved { .. } => {
            handlers::add::handle(&alert, &mut ctx)
        }
        Alert::StateUpdate { .. } | Alert::TorrentFinished { .. } => {
            handlers::state_update::handle(&alert, &mut ctx)
        }
        Alert::SaveResumeData { .. } | Alert::SaveResumeDataFailed { .. } => {
            handlers::resume::handle(&alert, &mut ctx)
        }
        Alert::TorrentError { .. } | Alert::FileError { .. } | Alert::HashFailed { .. } => {
            handlers::error::handle(&alert, &mut ctx)
        }
        Alert::ListenFailed { .. } | Alert::ListenSucceeded { .. } => {
            handlers::listen::handle(&alert, &mut ctx, listen_failures)
        }
        Alert::AlertsDropped { .. } => handlers::dropped::handle(&alert, &mut ctx),
        Alert::TorrentLog { .. } | Alert::Log { .. } => handlers::log_msg::handle(&alert, &mut ctx),
        Alert::SessionStats { .. } => {
            handlers::stats::handle(&alert, &mut ctx);
            // Posted after any reopen whose alerts precede it has returned,
            // so the sockets it kept are known (see `ListenFailures`).
            handlers::listen::recheck(&mut ctx, listen_failures);
        }
        Alert::MetadataReceived { .. } => {
            // libtorrent starts the magnet's check as the metadata lands, on
            // its own thread and before this alert, outside every bound the
            // daemon keeps (`CheckSlots`): counted, so a burst of them is
            // visible beside the checks the daemon admits.
            ctx.metrics
                .inc_counter("checks_started_total", &[("source", "magnet_metadata")]);
            // Without the daemon's answer nothing is lifted: a magnet keeps
            // the guards it was added with.
            let lift = magnet_guard_lift.map_or_else(TorrentFlags::empty, |f| f(&ctx.profile_id));
            handlers::metadata::handle(&alert, &mut ctx, lift)
        }
        Alert::TorrentChecked { .. }
        | Alert::StorageMoved { .. }
        | Alert::StorageMovedFailed { .. } => handlers::storage::handle(&alert, &mut ctx),
        Alert::TrackerError { .. } | Alert::Warning { .. } | Alert::TrackerReply { .. } => {
            handlers::warning::handle(&alert, &mut ctx, tracker_failures)
        }
    }
}
