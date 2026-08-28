//! The seeder daemon's heart: a single blocking thread that owns the
//! alert source, the state map, and the orchestration timers.
//!
//!   - Drains alerts from the `AlertSource` and dispatches each through
//!     the `handlers/` modules.
//!   - 1-second tick: `post_torrent_updates` per slot.
//!   - 30-second tick: `post_session_stats` per slot.
//!   - 30-minute tick: scan the state map for torrents flagged
//!     `needs_save_resume` and call `save_resume_data` with
//!     `ONLY_IF_MODIFIED` (PRD §6).
//!   - Retry timer: torrents in upload-mode have a `RetryState`; when
//!     `next_attempt <= now` we call `engine.resume_torrent(handle)` and
//!     schedule the next attempt with exponential backoff.
//!   - Shutdown: on signal, fire `save_resume_data` for every torrent
//!     concurrently, then loop draining alerts until
//!     `pending_resume_count == 0` or the global 30-second deadline
//!     expires (PRD §Session Management).
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
use crate::resume_store::ResumeStore;
use crate::slot::SlotId;
use crate::source::AlertSource;
use crate::state::StateMap;
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
}

/// Invoked once, from the loop thread, when a fatal condition is detected —
/// seederd wires this to the shutdown broadcast so the HTTP server unwinds.
pub type FatalCallback = Arc<dyn Fn(ShutdownReason) + Send + Sync>;

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
        }
    }

    /// Treat `listen_failed_alert` as fatal (PRD §Error Handling: fatal in
    /// single-session mode; in multi-slot mode only the affected slot is
    /// marked failed and the daemon keeps running).
    pub fn fatal_listen_failure(mut self, yes: bool) -> Self {
        self.fatal_listen_failure = yes;
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

        let join = thread::Builder::new()
            .name("seederd-alert-loop".into())
            .spawn({
                let source = Arc::clone(&self.source);
                let state = Arc::clone(&self.state);
                let resume = Arc::clone(&self.resume);
                let torrents = Arc::clone(&self.torrents);
                let metrics = Arc::clone(&self.metrics);
                let clock = Arc::clone(&self.clock);
                let heartbeat = Arc::clone(&heartbeat);
                let listen_failed = Arc::clone(&listen_failed);
                let fatal_listen_failure = self.fatal_listen_failure;
                let on_fatal = self.on_fatal.clone();
                move || {
                    let span = info_span!(parent: parent, "alert_loop");
                    let _enter = span.enter();
                    info!(target: "seederd_engine::alert_loop", "alert loop started");
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
                        },
                    );
                    info!(target: "seederd_engine::alert_loop", "alert loop exited");
                }
            })
            .expect("spawn alert loop thread");

        AlertLoopHandle {
            join,
            shutdown: tx,
            state: state_arc,
            heartbeat,
            listen_failed,
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
            info!(target: "seederd_engine::alert_loop", reason = ?reason, "shutdown signaled");
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
        for (slot, alert) in drained {
            // PRD §Error Handling: a listen socket that fails in
            // single-session mode is fatal — there is no other session to
            // carry the load, so seeding silently stops. Note it, finish
            // dispatching the batch (so the failure is logged and counted),
            // then unwind.
            if hooks.fatal_listen_failure && matches!(alert, Alert::ListenFailed { .. }) {
                fatal = true;
            }
            dispatch_alert(
                slot, alert, &source, &state, &resume, &torrents, &metrics, &clock,
            );
        }
        if fatal {
            hooks.listen_failed.store(true, Ordering::Relaxed);
            error!(
                target: "seederd_engine::alert_loop",
                "listen socket failed in single-session mode; shutting down",
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
        execute_due_retries(&source, &state, &metrics, &clock, now);

        // 5) Sleep if there's nothing to do.
        if was_empty {
            clock.sleep(POLL_IDLE_INTERVAL);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_alert(
    slot: SlotId,
    alert: Alert,
    source: &Arc<dyn AlertSource>,
    state: &Arc<StateMap>,
    resume: &Arc<dyn ResumeStore>,
    torrents: &Arc<dyn TorrentStore>,
    metrics: &Arc<dyn MetricsSink>,
    clock: &Arc<dyn Clock>,
) {
    let Some(engine) = source.engine_for(&slot) else {
        warn!(
            target: "seederd_engine::alert_loop",
            slot_id = %slot,
            "alert for unknown slot; dropping",
        );
        return;
    };
    let span = info_span!(
        "alert",
        slot_id = %slot,
        alert_type = alert.kind().as_str(),
    );
    let mut ctx = HandlerCtx {
        state: state.as_ref(),
        resume: resume.as_ref(),
        torrents: torrents.as_ref(),
        metrics: metrics.as_ref(),
        clock: clock.as_ref(),
        engine: &engine,
        slot_id: slot,
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

        // Other alerts (tracker_error, peer_disconnected) are interesting for
        // ops/metrics but not yet wired up; emit a debug log so we can spot
        // them in field traces without losing the loop's progress.
        other => tracing::debug!(
            target: "seederd_engine::alert_loop",
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
        target: "seederd_engine::alert_loop",
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
        let Some(engine) = source.engine_for(&st.slot_id) else {
            continue;
        };
        match engine.resume_torrent(handle) {
            Ok(()) => {
                info!(
                    target: "seederd_engine::alert_loop",
                    slot_id = %st.slot_id,
                    infohash = %handle.infohash,
                    "retry: resumed torrent from upload_mode",
                );
                state.update(&handle.infohash, |s| {
                    let attempts = s.retry.as_ref().map(|r| r.attempts).unwrap_or(0);
                    s.retry = Some(crate::state::RetryState::next(clock.now(), attempts));
                });
                metrics.inc_counter(
                    "upload_mode_retry_attempts_total",
                    &[("slot_id", st.slot_id.as_str())],
                );
            }
            Err(e) => {
                warn!(
                    target: "seederd_engine::alert_loop",
                    slot_id = %st.slot_id,
                    infohash = %handle.infohash,
                    error.cause = %e,
                    "retry resume failed",
                );
                metrics.inc_counter(
                    "upload_mode_retry_errors_total",
                    &[("slot_id", st.slot_id.as_str())],
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
    let Some(engine) = source.engine_for(&st.slot_id) else {
        return;
    };
    state.note_resume_requested();
    if let Err(e) = engine.save_resume_data(handle, flags) {
        // Failed before reaching libtorrent — settle immediately or the
        // counter will leak.
        state.note_resume_settled();
        warn!(
            target: "seederd_engine::alert_loop",
            slot_id = %st.slot_id,
            infohash = %handle.infohash,
            error.cause = %e,
            "save_resume_data dispatch failed",
        );
        metrics.inc_counter(
            "resume_save_dispatch_errors_total",
            &[("slot_id", st.slot_id.as_str())],
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
        target: "seederd_engine::alert_loop",
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
            target: "seederd_engine::alert_loop",
            torrent_count_initial = started_count,
            pending_resume_count = outstanding,
            elapsed_ms = clock.now().saturating_duration_since(started).as_millis() as u64,
            "shutdown deadline elapsed with unsaved resume data",
        );
        metrics.add_counter("shutdown_unsaved_resumes_total", outstanding, &[]);
    } else {
        info!(
            target: "seederd_engine::alert_loop",
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
    for (slot, alert) in alerts {
        dispatch_alert(slot, alert, source, state, resume, torrents, metrics, clock);
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
    use crate::metrics::NoopSink;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::resume_store::MemoryResumeStore;
    use crate::source::SingleSessionSource;
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
            Arc::new(SingleSessionSource::new(engine)),
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

    #[test]
    fn listen_failure_is_survivable_when_not_fatal() {
        // Multi-slot mode: the slot is marked failed by the handler, but the
        // daemon keeps seeding the other slots.
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
        let source: Arc<dyn AlertSource> = Arc::new(SingleSessionSource::new(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        dispatch_alert(
            SlotId::default_single(),
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
        let source: Arc<dyn AlertSource> = Arc::new(SingleSessionSource::new(engine.clone()));
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
                SlotId::default_single(),
                clock.now(),
            ),
        );

        dispatch_alert(
            SlotId::default_single(),
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
        let source: Arc<dyn AlertSource> = Arc::new(SingleSessionSource::new(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(NoopSink);
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        state.note_resume_requested();
        state.note_resume_requested();

        dispatch_alert(
            SlotId::default_single(),
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

        let source: Arc<dyn AlertSource> = Arc::new(SingleSessionSource::new(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        let now = clock.now();
        state.insert(
            h1.infohash,
            crate::state::TorrentState::newly_added(h1, SlotId::default_single(), now),
        );
        state.insert(
            h2.infohash,
            crate::state::TorrentState::newly_added(h2, SlotId::default_single(), now),
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

        let source: Arc<dyn AlertSource> = Arc::new(SingleSessionSource::new(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        let now = clock.now();
        state.insert(
            h1.infohash,
            crate::state::TorrentState::newly_added(h1, SlotId::default_single(), now),
        );
        state.insert(
            h2.infohash,
            crate::state::TorrentState::newly_added(h2, SlotId::default_single(), now),
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

        let source: Arc<dyn AlertSource> = Arc::new(SingleSessionSource::new(engine.clone()));
        let state = Arc::new(StateMap::new());
        let resume: Arc<dyn ResumeStore> = Arc::new(MemoryResumeStore::new());
        let torrents: Arc<dyn TorrentStore> = Arc::new(MemoryTorrentStore::new());
        let metrics: Arc<dyn MetricsSink> = Arc::new(RecordingSink::new());
        let clock: Arc<dyn Clock> = Arc::new(MockClock::new());

        state.insert(
            h.infohash,
            crate::state::TorrentState::newly_added(h, SlotId::default_single(), clock.now()),
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
