//! The seeder daemon's heart: a single blocking thread that owns the
//! alert source, the state map, and the orchestration timers.
//!
//!   - Drains alerts from the `AlertSource` and dispatches each through
//!     the `handlers/` modules.
//!   - 1-second tick: `post_torrent_updates` per profile.
//!   - 30-second tick: `post_session_stats` per profile.
//!   - 30-minute tick: scan the state map for torrents flagged
//!     `needs_save_resume` and call `save_resume_data` with
//!     `ONLY_IF_MODIFIED`.
//!   - Disk-error retry timer: a `file_error_alert` arms a `RetryState`;
//!     when `next_attempt <= now` and libtorrent still holds an error on the
//!     torrent, we call `engine.resume_torrent(handle)` (which clears the
//!     error and the pause libtorrent put on it) and schedule the next
//!     attempt with exponential backoff. A torrent with no error left has
//!     its timer retired instead.
//!   - Shutdown: on signal, fire `save_resume_data` for every torrent
//!     concurrently, then loop draining alerts until
//!     `pending_resume_count == 0` or the global 30-second deadline
//!     expires.
//!   - Liveness: every iteration stamps a wall-clock heartbeat that
//!     `GET /healthz` reads. A wedged or panicked loop makes the daemon
//!     report unready instead of quietly serving a stale state map.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crossbeam_channel::bounded;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use libtorrent_safe::Alert;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::TorrentHandle;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::warn;
use tracing::Span;

use crate::clock::Clock;
use crate::engine::TorrentEngine;
use crate::handlers::HandlerCtx;
use crate::handlers::{self};
use crate::metrics::MetricsSink;
use crate::profile::ProfileId;
use crate::resume_store::ResumeStore;
use crate::source::AlertSource;
use crate::state::StateMap;
use crate::state::TorrentPhase;
use crate::torrent_store::TorrentStore;

const POLL_IDLE_INTERVAL: Duration = Duration::from_millis(100);
const POST_UPDATES_INTERVAL: Duration = Duration::from_secs(1);
const POST_STATS_INTERVAL: Duration = Duration::from_secs(30);
const RESUME_SAVE_INTERVAL: Duration = Duration::from_secs(30 * 60);
const SHUTDOWN_DRAIN_INTERVAL: Duration = Duration::from_millis(50);
const SHUTDOWN_DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

/// Why the alert loop is shutting down. Surfaced in logs and tests.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ShutdownReason {
    Sigterm,
    Sigint,
    ListenFailed,
    /// A handler panicked. The loop is the only consumer of the alert queue
    /// and the only writer to the state map, so its death stops seeding,
    /// resume saves and status updates — with nothing else noticing.
    LoopPanicked,
    Test,
}

/// Shared mutable handles + immutable services the alert loop and its
/// handlers consume. Wrapped in `Arc` so the spawning thread can hold a
/// reference for shutdown coordination after the loop thread starts.
pub struct AlertLoopBuilder {
    source: Arc<dyn AlertSource>,
    state: Arc<StateMap>,
    resume: Arc<dyn ResumeStore>,
    torrents: Arc<dyn TorrentStore>,
    metrics: Arc<dyn MetricsSink>,
    clock: Arc<dyn Clock>,
    fatal_listen_failure: bool,
    on_fatal: Option<FatalCallback>,
    profile_fenced: Option<ProfileFenced>,
}

/// Invoked once, from the loop thread, when a fatal condition is detected —
/// torrentd wires this to the shutdown broadcast so the HTTP server unwinds.
pub type FatalCallback = Arc<dyn Fn(ShutdownReason) + Send + Sync>;

/// "Is this profile fenced?" — supplied by the daemon, which owns VPN health.
///
/// The engine has no concept of a tunnel, but it does resume torrents on its
/// own schedule, and resuming one in a profile the VPN monitor has fenced
/// un-quarantines it behind the operator's back.
pub type ProfileFenced = Arc<dyn Fn(&ProfileId) -> bool + Send + Sync>;

impl std::fmt::Debug for AlertLoopBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertLoopBuilder").finish_non_exhaustive()
    }
}

impl AlertLoopBuilder {
    pub fn new(
        source: Arc<dyn AlertSource>,
        state: Arc<StateMap>,
        resume: Arc<dyn ResumeStore>,
        torrents: Arc<dyn TorrentStore>,
        metrics: Arc<dyn MetricsSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            source,
            state,
            resume,
            torrents,
            metrics,
            clock,
            fatal_listen_failure: false,
            on_fatal: None,
            profile_fenced: None,
        }
    }

    /// Treat `listen_failed_alert` as fatal.
    ///
    /// Set when there is exactly **one live session**, whatever the config
    /// declares: nothing else is listening, so seeding would otherwise stop
    /// silently. The condition is live sessions and not configured profiles
    /// precisely so that a daemon configured with two profiles and reduced to
    /// one by a bring-up failure has the same exposure as one configured with
    /// one.
    ///
    /// With two or more live sessions the failure is not fatal: the affected
    /// profile logs, counts and warns, and the others keep serving.
    pub fn fatal_listen_failure(mut self, yes: bool) -> Self {
        self.fatal_listen_failure = yes;
        self
    }

    /// Supply the fenced-profile predicate. Without one, no profile is ever
    /// fenced, which is correct where nothing fences — a deployment of host
    /// profiles alone, and tests.
    pub fn profile_fenced(mut self, f: ProfileFenced) -> Self {
        self.profile_fenced = Some(f);
        self
    }

    /// Callback fired when the loop decides to self-terminate, before it
    /// begins the resume-data drain.
    pub fn on_fatal(mut self, f: FatalCallback) -> Self {
        self.on_fatal = Some(f);
        self
    }

    /// Spawn the loop on a dedicated OS thread. Returns a handle the
    /// caller uses to coordinate shutdown.
    pub fn spawn(self) -> AlertLoopHandle {
        let (tx, rx) = bounded::<ShutdownReason>(1);
        let parent = Span::current();
        let state_arc = Arc::clone(&self.state);
        let heartbeat = Arc::new(AtomicU64::new(now_millis()));
        let listen_failed = Arc::new(AtomicBool::new(false));
        // Observed by the daemon to pick a non-zero exit code. `catch_unwind`
        // means the thread returns normally, so `join()` reports success and
        // the panic would otherwise be invisible to the exit path.
        let panicked = Arc::new(AtomicBool::new(false));

        let join = thread::Builder::new()
            .name("torrentd-alert-loop".into())
            .spawn({
                let source = Arc::clone(&self.source);
                let state = Arc::clone(&self.state);
                let resume = Arc::clone(&self.resume);
                let torrents = Arc::clone(&self.torrents);
                let metrics = Arc::clone(&self.metrics);
                let clock = Arc::clone(&self.clock);
                let heartbeat = Arc::clone(&heartbeat);
                let listen_failed = Arc::clone(&listen_failed);
                let panicked = Arc::clone(&panicked);
                let fatal_listen_failure = self.fatal_listen_failure;
                let on_fatal = self.on_fatal.clone();
                let profile_fenced = self.profile_fenced.clone();
                move || {
                    let span = info_span!(parent: parent, "alert_loop");
                    let _enter = span.enter();
                    info!(target: "torrentd_engine::alert_loop", "alert loop started");
                    let on_fatal_panic = on_fatal.clone();
                    // A panic here unwinds only this thread. `main` would keep
                    // running: HTTP still answering, metrics still scraping,
                    // the state map frozen, no alert ever dispatched again and
                    // no resume data ever written again. Catch it and take the
                    // process down so the supervisor restarts it.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run(
                            rx,
                            source,
                            state,
                            resume,
                            torrents,
                            metrics,
                            clock,
                            LoopHooks {
                                heartbeat,
                                listen_failed,
                                fatal_listen_failure,
                                on_fatal,
                                profile_fenced,
                            },
                        );
                    }));
                    if outcome.is_err() {
                        panicked.store(true, Ordering::Relaxed);
                        error!(
                            target: "torrentd_engine::alert_loop",
                            op = "alert_loop",
                            error.kind = "alert_loop_panic",
                            "alert loop panicked; seeding has stopped and resume data will \
                             no longer be written",
                        );
                        if let Some(cb) = &on_fatal_panic {
                            cb(ShutdownReason::LoopPanicked);
                        }
                        return;
                    }
                    info!(target: "torrentd_engine::alert_loop", "alert loop exited");
                }
            })
            .expect("spawn alert loop thread");

        AlertLoopHandle {
            join,
            shutdown: tx,
            state: state_arc,
            heartbeat,
            listen_failed,
            panicked,
        }
    }
}

/// Handle returned by the builder.
pub struct AlertLoopHandle {
    join: thread::JoinHandle<()>,
    shutdown: Sender<ShutdownReason>,
    state: Arc<StateMap>,
    heartbeat: Arc<AtomicU64>,
    listen_failed: Arc<AtomicBool>,
    panicked: Arc<AtomicBool>,
}

impl AlertLoopHandle {
    /// Get a clone of the shared state map (for HTTP API queries, tests,
    /// etc.).
    pub fn state(&self) -> Arc<StateMap> {
        Arc::clone(&self.state)
    }

    /// Shared liveness stamp: Unix milliseconds at the loop's last
    /// iteration. Handed to the HTTP layer so `/healthz` can fail when the
    /// loop stops making progress. Read it with [`heartbeat_age`].
    pub fn heartbeat(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.heartbeat)
    }

    /// Whether the loop terminated because a listen socket failed fatally.
    /// Read before [`AlertLoopHandle::join`], which consumes the handle.
    pub fn listen_failed(&self) -> bool {
        self.listen_failed.load(Ordering::Relaxed)
    }

    /// Whether the loop died to a panic.
    ///
    /// The thread catches its own unwind so the process can shut down
    /// cleanly, which means `join()` returns `Ok` and says nothing. Without
    /// this the daemon exits 0 and `Restart=on-failure` leaves it down —
    /// the opposite of what catching the panic was for.
    pub fn panicked(&self) -> bool {
        self.panicked.load(Ordering::Relaxed)
    }

    /// Send a shutdown signal. Idempotent; returns true on the first
    /// call, false if the channel was already filled.
    pub fn signal_shutdown(&self, reason: ShutdownReason) -> bool {
        self.shutdown.try_send(reason).is_ok()
    }

    /// Wait for the loop thread to exit. Useful in tests.
    pub fn join(self) -> std::thread::Result<()> {
        self.join.join()
    }
}

impl std::fmt::Debug for AlertLoopHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertLoopHandle").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Loop body
// ---------------------------------------------------------------------------

/// Wall-clock milliseconds since the Unix epoch. Deliberately not routed
/// through `Clock`: the heartbeat is compared against `SystemTime::now()` by
/// the HTTP layer, which a mocked monotonic clock would not line up with.
fn now_millis() -> u64 {
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
struct LoopHooks {
    heartbeat: Arc<AtomicU64>,
    listen_failed: Arc<AtomicBool>,
    fatal_listen_failure: bool,
    on_fatal: Option<FatalCallback>,
    profile_fenced: Option<ProfileFenced>,
}

#[allow(clippy::too_many_arguments)]
fn run(
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

    loop {
        // 0) Liveness stamp. Written at the top of every iteration so a loop
        //    wedged inside a handler stops refreshing it and /healthz fails.
        hooks.heartbeat.store(now_millis(), Ordering::Relaxed);

        // 1) Shutdown probe.
        if let Ok(reason) = shutdown_rx.try_recv() {
            info!(target: "torrentd_engine::alert_loop", reason = ?reason, "shutdown signaled");
            run_shutdown(
                reason,
                SHUTDOWN_DEFAULT_DEADLINE,
                &source,
                &state,
                &resume,
                &torrents,
                &metrics,
                &clock,
            );
            return;
        }

        // 2) Drain alerts.
        let drained = source.drain();
        let was_empty = drained.is_empty();
        let mut fatal = false;
        for (profile, alert) in drained {
            // A listen socket that fails when this is the only live session
            // is fatal — there is no other session to carry the load, so
            // seeding silently stops. Note it, finish dispatching the batch
            // (so the failure is logged and counted), then unwind.
            if matches!(alert, Alert::ListenFailed { .. }) {
                if hooks.fatal_listen_failure {
                    fatal = true;
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
            dispatch_alert(
                profile, alert, &source, &state, &resume, &torrents, &metrics, &clock,
            );
        }
        if fatal {
            hooks.listen_failed.store(true, Ordering::Relaxed);
            error!(
                target: "torrentd_engine::alert_loop",
                "the only live session's listen socket failed; shutting down",
            );
            if let Some(cb) = &hooks.on_fatal {
                cb(ShutdownReason::ListenFailed);
            }
            run_shutdown(
                ShutdownReason::ListenFailed,
                SHUTDOWN_DEFAULT_DEADLINE,
                &source,
                &state,
                &resume,
                &torrents,
                &metrics,
                &clock,
            );
            return;
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
            schedule_periodic_resume_saves(&source, &state, &metrics);
            last_resume_save = now;
        }

        // 4) Retry timer.
        execute_due_retries(
            &source,
            &state,
            &metrics,
            &clock,
            hooks.profile_fenced.as_ref(),
            now,
        );

        // 5) Sleep if there's nothing to do.
        if was_empty {
            clock.sleep(POLL_IDLE_INTERVAL);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_alert(
    profile: ProfileId,
    alert: Alert,
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    resume: &Arc<dyn ResumeStore>,
    torrents: &Arc<dyn TorrentStore>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
) {
    let Some(engine) = source.engine_for(&profile) else {
        warn!(
            target: "torrentd_engine::alert_loop",
            profile_id = %profile,
            "alert for unknown profile; dropping",
        );
        return;
    };
    let span = info_span!(
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
        profile_id: profile,
        span,
    };

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
            handlers::listen::handle(&alert, &mut ctx)
        }
        Alert::AlertsDropped { .. } => handlers::dropped::handle(&alert, &mut ctx),
        Alert::TorrentLog { .. } | Alert::Log { .. } => handlers::log_msg::handle(&alert, &mut ctx),
        Alert::SessionStats { .. } => handlers::stats::handle(&alert, &mut ctx),
        Alert::MetadataReceived { .. } => handlers::metadata::handle(&alert, &mut ctx),
        Alert::TorrentChecked { .. }
        | Alert::StorageMoved { .. }
        | Alert::StorageMovedFailed { .. } => handlers::storage::handle(&alert, &mut ctx),

        // Other alerts (tracker_error, peer_disconnected) are interesting for
        // ops/metrics but not yet wired up; emit a debug log so we can spot
        // them in field traces without losing the loop's progress.
        other => tracing::debug!(
            target: "torrentd_engine::alert_loop",
            alert_type = other.kind().as_str(),
            "unhandled alert kind",
        ),
    }
}

fn schedule_periodic_resume_saves(
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    metrics: &Arc<dyn MetricsSink>,
) {
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
        request_save(source, state, metrics, h, ResumeFlags::ONLY_IF_MODIFIED);
    }
}

fn execute_due_retries(
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
    profile_fenced: Option<&ProfileFenced>,
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
        if profile_fenced.is_some_and(|f| f(&st.profile_id)) {
            debug!(
                target: "torrentd_engine::alert_loop",
                profile_id = %st.profile_id,
                infohash = %handle.infohash,
                "retry skipped: profile is fenced",
            );
            continue;
        }
        // What a `file_error_alert` leaves behind under this daemon's flags
        // (vendor/libtorrent/src/torrent.cpp, `handle_disk_error` and
        // `on_piece_hashed`): a read failure, or any failure while checking,
        // sets an error on the torrent and pauses it. A write failure of the
        // disk-full / read-only kind only sets upload mode, which every
        // torrent here already carries (`policy::no_download`), and ENOMEM
        // only disconnects the peer. So the one thing there is to recover is
        // an error-paused torrent, and `resume()` is what recovers it:
        // `torrent::do_resume` unpauses and calls `clear_error`, which
        // re-checks the files if the error came from a check.
        //
        // A torrent with no error left has nothing for the retry to do — it
        // recovered, an operator resumed it, or the error never paused it —
        // and resuming it anyway would undo an operator's pause every hour,
        // forever, because nothing else ever clears the timer. Retire it.
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
        if !st.has_error {
            debug!(
                target: "torrentd_engine::alert_loop",
                profile_id = %st.profile_id,
                infohash = %handle.infohash,
                "disk-error retry retired: torrent carries no libtorrent error",
            );
            state.update(&handle.infohash, |s| s.retry = None);
            continue;
        }
        let Some(engine) = source.engine_for(&st.profile_id) else {
            continue;
        };
        match engine.resume_torrent(handle) {
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
            }
        }
    }
}

fn request_save(
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    metrics: &Arc<dyn MetricsSink>,
    handle: TorrentHandle,
    flags: ResumeFlags,
) {
    let Some(st) = state.get(&handle.infohash) else {
        return;
    };
    let Some(engine) = source.engine_for(&st.profile_id) else {
        return;
    };
    state.note_resume_requested();
    if let Err(e) = engine.save_resume_data(handle, flags) {
        // Failed before reaching libtorrent — settle immediately or the
        // counter will leak.
        state.note_resume_settled();
        warn!(
            target: "torrentd_engine::alert_loop",
            profile_id = %st.profile_id,
            infohash = %handle.infohash,
            error.cause = %e,
            "save_resume_data dispatch failed",
        );
        metrics.inc_counter(
            "resume_save_dispatch_errors_total",
            &[("profile_id", st.profile_id.as_str())],
        );
    }
}

// ---------------------------------------------------------------------------
// Shutdown coordinator
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_shutdown(
    reason: ShutdownReason,
    deadline: Duration,
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    resume: &Arc<dyn ResumeStore>,
    torrents: &Arc<dyn TorrentStore>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
) {
    let started = clock.now();
    let started_count = state.len();

    // Drain whatever's pending so the resume queue is in a known state.
    drain_once(source, state, resume, torrents, metrics, clock);

    // Trigger one save_resume_data per torrent. Tracking via the shared
    // `pending_resume_count`; the per-handler `note_resume_settled` will
    // decrement as alerts come back.
    let handles = state.handles();
    info!(
        target: "torrentd_engine::alert_loop",
        reason = ?reason,
        torrent_count = handles.len(),
        deadline_secs = deadline.as_secs(),
        "shutdown: requesting resume save for every torrent",
    );
    for h in handles {
        // Force-save (clear ONLY_IF_MODIFIED) — every torrent must persist
        // its current state, even if libtorrent thinks it's unchanged.
        request_save(source, state, metrics, h, ResumeFlags::empty());
    }

    let stop_at = started + deadline;
    while clock.now() < stop_at {
        if state.pending_resume_count() == 0 {
            break;
        }
        drain_once(source, state, resume, torrents, metrics, clock);
        clock.sleep(SHUTDOWN_DRAIN_INTERVAL);
    }

    let outstanding = state.pending_resume_count();
    if outstanding > 0 {
        warn!(
            target: "torrentd_engine::alert_loop",
            torrent_count_initial = started_count,
            pending_resume_count = outstanding,
            elapsed_ms = clock.now().saturating_duration_since(started).as_millis() as u64,
            "shutdown deadline elapsed with unsaved resume data",
        );
        metrics.add_counter("shutdown_unsaved_resumes_total", outstanding, &[]);
    } else {
        info!(
            target: "torrentd_engine::alert_loop",
            torrent_count = started_count,
            elapsed_ms = clock.now().saturating_duration_since(started).as_millis() as u64,
            "shutdown clean: all resume data persisted",
        );
    }
}

fn drain_once(
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    resume: &Arc<dyn ResumeStore>,
    torrents: &Arc<dyn TorrentStore>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
) {
    let alerts = source.drain();
    for (profile, alert) in alerts {
        dispatch_alert(
            profile, alert, source, state, resume, torrents, metrics, clock,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;
    use libtorrent_safe::ResumeData;

    use super::*;
    use crate::clock::MockClock;
    use crate::metrics::MetricCall;
    use crate::metrics::NoopSink;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::resume_store::MemoryResumeStore;
    use crate::source::ProfileSource;

    /// A source with one profile, which is what most of these tests need.
    /// Named rather than inlined so the profile id is one value.
    fn single_profile_source(engine: Arc<dyn TorrentEngine>) -> ProfileSource {
        ProfileSource::new(vec![(ProfileId::new("p"), engine)])
    }
    use crate::torrent_store::MemoryTorrentStore;

    fn add_torrent_alert(byte: u8, id: u64) -> Alert {
        let ih = InfoHash([byte; 20]);
        Alert::AddTorrent {
            hdr: AlertHeader {
                kind: AlertKind::AddTorrent,
                infohash: Some(ih),
                handle: Some(TorrentHandle { id, infohash: ih }),
                timestamp_us: 0,
            },
            error_code: 0,
            message: None,
        }
    }

    fn save_resume_alert(byte: u8, id: u64, payload: &[u8]) -> Alert {
        let ih = InfoHash([byte; 20]);
        Alert::SaveResumeData {
            hdr: AlertHeader {
                kind: AlertKind::SaveResumeData,
                infohash: Some(ih),
                handle: Some(TorrentHandle { id, infohash: ih }),
                timestamp_us: 0,
            },
            data: ResumeData::new(payload.to_vec()),
        }
    }

    fn save_resume_failed_alert(byte: u8, id: u64) -> Alert {
        let ih = InfoHash([byte; 20]);
        Alert::SaveResumeDataFailed {
            hdr: AlertHeader {
                kind: AlertKind::SaveResumeDataFailed,
                infohash: Some(ih),
                handle: Some(TorrentHandle { id, infohash: ih }),
                timestamp_us: 0,
            },
            error_code: 0,
            not_modified: false,
            message: "spurious".into(),
        }
    }

    fn listen_failed_alert() -> Alert {
        Alert::ListenFailed {
            hdr: AlertHeader {
                kind: AlertKind::ListenFailed,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            error_code: 98,
            operation: "bind".into(),
            endpoint: "0.0.0.0:6881".into(),
            iface: "eth0".into(),
            message: "address already in use".into(),
        }
    }

    /// Spin until `cond` holds or the deadline passes. The loop runs on its own
    /// thread, so tests can't assert on its progress synchronously.
    fn wait_for(cond: impl Fn() -> bool) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    fn builder_with(engine: Arc<MockEngine>) -> AlertLoopBuilder {
        AlertLoopBuilder::new(
            Arc::new(single_profile_source(engine)),
            Arc::new(StateMap::new()),
            Arc::new(MemoryResumeStore::new()),
            Arc::new(MemoryTorrentStore::new()),
            Arc::new(NoopSink),
            // A real clock: these tests exercise the spawned loop, and
            // MockClock's zero-cost sleep would spin a core flat out.
            Arc::new(crate::clock::SystemClock),
        )
    }

    #[test]
    fn fatal_listen_failure_stops_the_loop_and_notifies() {
        let engine = Arc::new(MockEngine::new());
        engine.push_alert(listen_failed_alert());

        let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
        let handle = builder_with(engine)
            .fatal_listen_failure(true)
            .on_fatal({
                let seen = Arc::clone(&seen);
                Arc::new(move |r| seen.lock().push(r)) as FatalCallback
            })
            .spawn();

        assert!(
            wait_for(|| handle.listen_failed()),
            "loop should have flagged the fatal listen failure",
        );
        handle.join().expect("loop thread panicked");
        assert_eq!(*seen.lock(), vec![ShutdownReason::ListenFailed]);
    }

    /// A metrics sink that panics, to drive a genuine panic through a handler.
    #[derive(Debug)]
    struct PanickingSink;

    impl crate::metrics::MetricsSink for PanickingSink {
        fn inc_counter(&self, _n: &str, _l: &[(&str, &str)]) {
            panic!("metrics sink exploded");
        }
        fn set_gauge(&self, _n: &str, _v: f64, _l: &[(&str, &str)]) {}
    }

    #[test]
    fn a_fenced_profile_is_not_resumed_by_the_retry_timer() {
        // The VPN monitor pauses every torrent in a profile whose tunnel dropped
        // and deliberately does not restart it. The disk-error retry timer
        // ran on its own schedule with no notion of that, so it un-quarantined
        // torrents one at a time — putting traffic back on a profile the operator
        // was told to go look at.
        // Auto-echo the resume saves, so the shutdown drain settles instead of
        // sitting out its full 30s deadline on a mock that never replies.
        let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
        engine.push_alert(add_torrent_alert(3, 3));
        let handle = builder_with(Arc::clone(&engine))
            .profile_fenced(Arc::new(|_: &ProfileId| true) as ProfileFenced)
            .spawn();

        let ih = InfoHash([3u8; 20]);
        assert!(
            wait_for(|| handle.state().get(&ih).is_some()),
            "the add alert was never dispatched",
        );

        // Make a retry due immediately on a torrent libtorrent error-paused,
        // which is the one case the retry would otherwise resume.
        handle.state().update(&ih, |s| {
            s.has_error = true;
            s.retry = Some(crate::state::RetryState::first(
                std::time::Instant::now() - Duration::from_secs(3600),
            ));
        });

        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !engine
                .calls()
                .iter()
                .any(|c| matches!(c, crate::mock::RecordedCall::ResumeTorrent(_))),
            "a fenced profile's torrent was resumed: {:?}",
            engine.calls(),
        );

        assert!(handle.signal_shutdown(ShutdownReason::Test));
        handle.join().expect("loop thread panicked");
    }

    /// Drive one pass of the retry timer against a single mock-engine
    /// torrent whose retry is already due, and return what it did.
    fn run_due_retry(has_error: bool) -> (Arc<MockEngine>, Arc<StateMap>, Arc<RecordingSink>) {
        run_due_retry_in(has_error, TorrentPhase::Paused, 1)
    }

    /// `run_due_retry` with the torrent's phase and the due timer's attempt
    /// count chosen by the caller.
    fn run_due_retry_in(
        has_error: bool,
        phase: TorrentPhase,
        attempts: u32,
    ) -> (Arc<MockEngine>, Arc<StateMap>, Arc<RecordingSink>) {
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(
            Arc::clone(&engine) as Arc<dyn TorrentEngine>
        ));
        let state = Arc::new(StateMap::new());
        let ih = InfoHash([9u8; 20]);
        let h = TorrentHandle {
            id: 9,
            infohash: ih,
        };
        let now = std::time::Instant::now();
        let mut st = crate::state::TorrentState::newly_added(h, ProfileId::new("p"), now);
        st.has_error = has_error;
        st.phase = phase;
        st.retry = Some(crate::state::RetryState {
            next_attempt: now - Duration::from_secs(1),
            attempts,
        });
        state.insert(ih, st);
        let recording = Arc::new(RecordingSink::new());
        let metrics: Arc<dyn MetricsSink> = Arc::clone(&recording) as Arc<dyn MetricsSink>;
        let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
        execute_due_retries(&source, &state, &metrics, &clock, None, now);
        (engine, state, recording)
    }

    fn resumed(engine: &MockEngine) -> bool {
        engine
            .calls()
            .iter()
            .any(|c| matches!(c, crate::mock::RecordedCall::ResumeTorrent(_)))
    }

    #[test]
    fn the_disk_error_retry_resumes_a_torrent_libtorrent_left_errored() {
        // A read failure or a failed check leaves the torrent paused with an
        // error set, and `resume()` is what clears both. That is the retry's
        // whole job, so it must still happen, back off, and be counted.
        let (engine, state, metrics) = run_due_retry(true);
        assert!(resumed(&engine), "an errored torrent was not resumed");
        let st = state.get(&InfoHash([9u8; 20])).unwrap();
        let retry = st
            .retry
            .expect("the timer stays armed until the error is gone");
        assert_eq!(retry.attempts, 2, "the next attempt backs off");
        assert!(metrics.calls().iter().any(|c| matches!(
            c,
            MetricCall::IncCounter { name, .. } if name == "disk_error_retry_attempts_total"
        )));
    }

    #[test]
    fn the_disk_error_retry_retires_once_no_error_is_left() {
        // Nothing cleared the timer before: once armed, a torrent was resumed
        // every hour forever — undoing any operator pause on it — although
        // libtorrent had nothing left to recover. With no error there is
        // nothing to do, so the timer goes and the torrent is left alone.
        let (engine, state, metrics) = run_due_retry(false);
        assert!(!resumed(&engine), "a torrent with no error was resumed");
        assert!(
            state.get(&InfoHash([9u8; 20])).unwrap().retry.is_none(),
            "the timer must be retired, or it fires again next tick",
        );
        assert!(
            !metrics.calls().iter().any(|c| matches!(
                c,
                MetricCall::IncCounter { name, .. } if name.starts_with("disk_error_retry_")
            )),
            "a retired timer is not a retry attempt",
        );
    }

    #[test]
    fn the_disk_error_retry_waits_out_the_check_its_resume_started() {
        // `resume()` clears the error before the re-check it triggers, so a
        // check still running when the timer comes due shows no error. If
        // that retired the timer, the check's own failure would re-arm it
        // from the first 60 s step, and a large torrent on broken storage
        // would re-check every minute instead of backing off to hourly.
        let before = std::time::Instant::now();
        let (engine, state, metrics) = run_due_retry_in(false, TorrentPhase::Checking, 5);
        assert!(!resumed(&engine), "a checking torrent was resumed");
        let retry = state
            .get(&InfoHash([9u8; 20]))
            .unwrap()
            .retry
            .expect("the timer must survive a check in progress");
        assert_eq!(retry.attempts, 5, "the backoff must not reset or advance");
        assert!(
            retry.next_attempt >= before + crate::state::RetryState::delay_for_attempt(5),
            "the timer waits another delay at the current backoff",
        );
        assert!(
            !metrics.calls().iter().any(|c| matches!(
                c,
                MetricCall::IncCounter { name, .. } if name.starts_with("disk_error_retry_")
            )),
            "a deferred timer is not a retry attempt",
        );
    }

    #[test]
    fn a_check_that_fails_again_resumes_on_the_kept_backoff() {
        // The check the previous resume started failed: libtorrent paused the
        // torrent and set its error again, and the timer held its count. The
        // next resume must advance from there, not from the first step.
        let (engine, state, _) = run_due_retry_in(true, TorrentPhase::Paused, 5);
        assert!(resumed(&engine), "an errored torrent was not resumed");
        let retry = state.get(&InfoHash([9u8; 20])).unwrap().retry.unwrap();
        assert_eq!(retry.attempts, 6);
    }

    #[test]
    fn a_panicking_handler_takes_the_process_down() {
        // The loop is the only consumer of the alert queue and the only writer
        // to the state map. A panic that unwinds just this thread leaves the
        // daemon serving HTTP and metrics with a frozen state map, never
        // dispatching another alert and never writing resume data again —
        // while the systemd watchdog, an independent task, keeps reporting
        // healthy. It has to become a process-level fatal.
        let engine = Arc::new(MockEngine::new());
        engine.push_alert(add_torrent_alert(1, 1));

        let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
        let handle = AlertLoopBuilder::new(
            Arc::new(single_profile_source(engine)),
            Arc::new(StateMap::new()),
            Arc::new(MemoryResumeStore::new()),
            Arc::new(MemoryTorrentStore::new()),
            Arc::new(PanickingSink),
            Arc::new(crate::clock::SystemClock),
        )
        .on_fatal({
            let seen = Arc::clone(&seen);
            Arc::new(move |r| seen.lock().push(r)) as FatalCallback
        })
        .spawn();

        assert!(
            wait_for(|| !seen.lock().is_empty()),
            "a panicking handler did not raise a fatal shutdown",
        );
        assert_eq!(*seen.lock(), vec![ShutdownReason::LoopPanicked]);
        // The thread is gone either way; joining must not itself panic the
        // test, which is what `catch_unwind` buys.
        handle.join().expect("panic should not escape the thread");
    }

    #[test]
    fn listen_failure_is_survivable_when_not_fatal() {
        // Multi-profile mode: the profile is marked failed by the handler, but the
        // daemon keeps seeding the other profiles.
        let engine = Arc::new(MockEngine::new());
        engine.push_alert(listen_failed_alert());
        let handle = builder_with(engine).fatal_listen_failure(false).spawn();

        // Give the loop a chance to process the alert and keep going.
        std::thread::sleep(Duration::from_millis(200));
        assert!(!handle.listen_failed());

        assert!(handle.signal_shutdown(ShutdownReason::Test));
        handle.join().expect("loop thread panicked");
    }

    #[test]
    fn heartbeat_advances_while_the_loop_runs() {
        let handle = builder_with(Arc::new(MockEngine::new())).spawn();
        let hb = handle.heartbeat();
        let first = hb.load(Ordering::Relaxed);

        assert!(
            wait_for(|| hb.load(Ordering::Relaxed) > first),
            "heartbeat should advance on every iteration",
        );
        assert!(heartbeat_age(&hb) < Duration::from_secs(1));

        handle.signal_shutdown(ShutdownReason::Test);
        handle.join().expect("loop thread panicked");
    }

    #[test]
    fn dispatch_add_torrent_inserts_into_state() {
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        dispatch_alert(
            ProfileId::new("p"),
            add_torrent_alert(0x42, 1),
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
        );

        assert_eq!(state.len(), 1);
        assert!(state.contains(&InfoHash([0x42; 20])));
    }

    #[test]
    fn resume_handler_writes_and_decrements() {
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume_store = Arc::new(MemoryResumeStore::new());
        let resume: Arc<dyn ResumeStore> = resume_store.clone();
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        // Simulate one outstanding save.
        state.note_resume_requested();
        // Pre-register the torrent in state so the resume handler can
        // update its needs_save_resume flag.
        state.insert(
            InfoHash([0xAA; 20]),
            crate::state::TorrentState::newly_added(
                TorrentHandle {
                    id: 1,
                    infohash: InfoHash([0xAA; 20]),
                },
                ProfileId::new("p"),
                clock.now(),
            ),
        );

        dispatch_alert(
            ProfileId::new("p"),
            save_resume_alert(0xAA, 1, b"BENCODE"),
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
        );

        assert_eq!(state.pending_resume_count(), 0);
        assert_eq!(resume_store.len(), 1);
    }

    #[test]
    fn save_resume_failed_decrements_counter() {
        let engine = Arc::new(MockEngine::new());
        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        state.note_resume_requested();
        state.note_resume_requested();

        dispatch_alert(
            ProfileId::new("p"),
            save_resume_failed_alert(0xBB, 1),
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
        );

        assert_eq!(state.pending_resume_count(), 1);
    }

    #[test]
    fn shutdown_saves_all_torrents_and_returns_zero() {
        // MockEngine in auto-save-resume mode: every save_resume_data call
        // pushes a SaveResumeData alert, which the shutdown coordinator's
        // drain loop then consumes to settle pending_resume_count. This
        // mirrors libtorrent's real async behaviour.
        let engine = Arc::new(MockEngine::new().with_auto_save_resume(true));
        let h1 = engine.register_handle(InfoHash([0x01; 20]));
        let h2 = engine.register_handle(InfoHash([0x02; 20]));

        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        let now = clock.now();
        state.insert(
            h1.infohash,
            crate::state::TorrentState::newly_added(h1, ProfileId::new("p"), now),
        );
        state.insert(
            h2.infohash,
            crate::state::TorrentState::newly_added(h2, ProfileId::new("p"), now),
        );

        run_shutdown(
            ShutdownReason::Test,
            Duration::from_secs(30),
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
        );

        assert_eq!(state.pending_resume_count(), 0);
        let saves = engine
            .calls()
            .iter()
            .filter(|c| matches!(c, crate::mock::RecordedCall::SaveResumeData { .. }))
            .count();
        assert_eq!(saves, 2);
    }

    #[test]
    fn shutdown_survives_one_save_resume_failed() {
        // Engine: first save call fails, second succeeds. Both must
        // settle pending_resume_count via the alerts handler so shutdown
        // returns to zero.
        let engine = Arc::new(MockEngine::new());
        let h1 = engine.register_handle(InfoHash([0x10; 20]));
        let h2 = engine.register_handle(InfoHash([0x20; 20]));
        // Pre-stage the alerts: a failure for h1 (not_modified=false),
        // success for h2.
        engine.push_alert(save_resume_failed_alert(0x10, h1.id));
        engine.push_alert(save_resume_alert(0x20, h2.id, b"ok"));

        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        let now = clock.now();
        state.insert(
            h1.infohash,
            crate::state::TorrentState::newly_added(h1, ProfileId::new("p"), now),
        );
        state.insert(
            h2.infohash,
            crate::state::TorrentState::newly_added(h2, ProfileId::new("p"), now),
        );

        // Both alerts are queued before run_shutdown. The first drain
        // inside run_shutdown will consume them; both note_resume_settled
        // calls floor at 0 and don't underflow. After requesting saves we
        // get +2 counter. The next drain finds the auto-pushed alerts
        // (engine has auto_save_resume off) — actually NONE, so we rely on
        // the deadline. To unblock here, switch auto_save_resume on.
        engine.set_auto_save_resume(true);

        run_shutdown(
            ShutdownReason::Test,
            Duration::from_secs(30),
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
        );

        assert_eq!(state.pending_resume_count(), 0);
    }

    #[test]
    fn shutdown_respects_deadline_with_outstanding_saves() {
        let engine = Arc::new(MockEngine::new());
        let h = engine.register_handle(InfoHash([0xC0; 20]));

        let source: Arc<dyn AlertSource> = Arc::new(single_profile_source(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        state.insert(
            h.infohash,
            crate::state::TorrentState::newly_added(h, ProfileId::new("p"), clock.now()),
        );

        // No alerts queued; the engine accepts save_resume_data but the
        // settling alert never arrives. The deadline must drop us out.
        run_shutdown(
            ShutdownReason::Test,
            Duration::from_millis(500),
            &source,
            &state,
            &resume,
            &torrents,
            &metrics,
            &clock,
        );

        assert_eq!(state.pending_resume_count(), 1);
    }
}
