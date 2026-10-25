//! Building and spawning the alert loop, and the handle the daemon keeps.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam_channel::bounded;
use crossbeam_channel::Sender;
use libtorrent_safe::TorrentFlags;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::Span;

use super::run::now_millis;
use super::run::run;
use super::run::LoopHooks;
use super::DEFAULT_SHUTDOWN_DEADLINE;
use crate::clock::Clock;
use crate::metrics::MetricsSink;
use crate::port_forward::ListenEvents;
use crate::profile::ProfileId;
use crate::resume_store::ResumeStore;
use crate::source::AlertSource;
use crate::state::StateMap;
use crate::torrent_store::TorrentStore;

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
    /// Every [`AlertLoopHandle`] was dropped, so no signal can arrive.
    HandleDropped,
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
    fence_hold: Option<FenceHold>,
    magnet_guard_lift: Option<MagnetGuardLift>,
    check_slots: Option<Arc<dyn CheckSlots>>,
    listen_events: Option<Arc<ListenEvents>>,
    listen_device_check: Option<ListenDeviceCheck>,
    shutdown_deadline: Duration,
}

/// "Which discovery guards does a magnet in this profile shed once its
/// metadata shows it is public?" — supplied by the daemon, which holds each
/// profile's config, and answered with
/// [`policy::public_magnet_lift`](crate::policy::public_magnet_lift).
///
/// Asked by the `metadata_received` handler. A magnet is added with DHT, PEX
/// and LSD disabled on every profile because its `private` bit is unknown
/// until then; the answer is the part of that guard the profile's own posture
/// does not keep.
pub type MagnetGuardLift = Arc<dyn Fn(&ProfileId) -> TorrentFlags + Send + Sync>;

/// "Are this profile's sockets on this listen endpoint held to the right
/// device?" — supplied by the daemon, which knows each profile's tunnel.
/// Asked with the profile and the `listen_succeeded` alert's `address:port`
/// text; `Err` carries what is wrong, and makes the loop shut the daemon
/// down as it does for a fatal listen failure.
pub type ListenDeviceCheck = Arc<dyn Fn(&ProfileId, &str) -> Result<(), String> + Send + Sync>;

/// Invoked once, from the loop thread, when a fatal condition is detected —
/// torrentd wires this to the shutdown broadcast so the HTTP server unwinds.
pub type FatalCallback = Arc<dyn Fn(ShutdownReason) + Send + Sync>;

/// "Is this profile fenced?" — supplied by the daemon, which owns VPN health.
///
/// The engine has no concept of a tunnel, but it does resume torrents on its
/// own schedule, and resuming one in a profile the VPN monitor has fenced
/// un-quarantines it behind the operator's back.
pub type ProfileFenced = Arc<dyn Fn(&ProfileId) -> bool + Send + Sync>;

/// "Hold this torrent, and tell whoever lifts the fence" — supplied by the
/// daemon, whose kill-switch watch lifts its own fence and resumes only the
/// torrents it recorded.
///
/// Called by the add handler with the profile, the torrent it just took into
/// the state map, and `hold`: the handler's own check of
/// [`ProfileFenced`] and pause, which answers whether it found the profile
/// fenced. The daemon runs `hold` under that fence's lock and, where `hold`
/// answers `true` and the fence holds the profile, records the torrent for
/// its lift. A torrent whose add alert lands after the fence walked the state
/// map is otherwise paused with no record, and stays paused once the fence
/// lifts around it.
pub type FenceHold =
    Arc<dyn Fn(&ProfileId, libtorrent_safe::TorrentHandle, &mut dyn FnMut() -> bool) + Send + Sync>;

/// The daemon's bound on concurrent hash checks, which the disk-error retry
/// takes a slot in before it starts one.
///
/// libtorrent bounds checking only for auto-managed torrents, and none is
/// one here, so the daemon keeps the bound: a queue every check it starts
/// waits in. The retry runs on the loop's own schedule, so it asks rather
/// than queues, and where no slot is free it looks again later, as for a
/// fenced profile.
pub trait CheckSlots: Send + Sync {
    /// Take a slot for a check of `ih` about to start: `false` where none is
    /// free, or the answer would mean waiting. Never blocks.
    fn try_take(&self, profile: &ProfileId, ih: libtorrent_safe::InfoHash) -> bool;
    /// Free the slot `try_take` took for `ih`, whose check did not start.
    fn release(&self, ih: &libtorrent_safe::InfoHash);
}

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
            fence_hold: None,
            magnet_guard_lift: None,
            check_slots: None,
            listen_events: None,
            listen_device_check: None,
            shutdown_deadline: DEFAULT_SHUTDOWN_DEADLINE,
        }
    }

    /// Publish every profile's `listen_succeeded` / `listen_failed` outcome
    /// into `events`, which a NAT-PMP rebind waits on to confirm the session
    /// listens on its new port. The loop is the only consumer of those
    /// alerts, so without this nothing else can learn whether a rebind took.
    /// The loop marks `events` attached after its first drain that returns
    /// no alerts, not at `spawn`: until the boot backlog is cleared, a
    /// rebind's outcome would queue behind it and could outlast the wait.
    pub fn listen_events(mut self, events: Arc<ListenEvents>) -> Self {
        self.listen_events = Some(events);
        self
    }

    /// Ask `check` about every `listen_succeeded` alert, before the alert is
    /// published or handled. A socket held to a device other than its
    /// profile's tunnel sends where no route probe looks, so an `Err` is
    /// fatal whatever the number of live sessions: the loop logs it, signals
    /// [`ShutdownReason::ListenFailed`] and drains, and
    /// [`AlertLoopHandle::listen_failed`] reads `true`.
    pub fn listen_device_check(mut self, check: ListenDeviceCheck) -> Self {
        self.listen_device_check = Some(check);
        self
    }

    /// How long the shutdown drain waits for outstanding resume saves before
    /// giving up on them. The daemon sets it from `shutdown_drain_secs`; a
    /// pool of 100K torrents needs longer than the default to answer.
    pub fn shutdown_deadline(mut self, deadline: Duration) -> Self {
        self.shutdown_deadline = deadline;
        self
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
    /// profile logs, counts and warns, and the others keep serving. Nor is a
    /// failure on the port a NAT-PMP rebind is moving onto, with any
    /// number of sessions ([`ListenEvents::rebind_in_progress`]): the rebind
    /// reverts to its previous port, and a failure of that revert is fatal.
    /// Nor is an `accept()` that failed with `EMFILE`
    /// ([`handlers::listen::is_accept_emfile`]): libtorrent keeps accepting
    /// on that socket.
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

    /// Supply what the add handler runs its hold of a torrent added into a
    /// fenced profile through. Without one, the hold runs alone, which is
    /// correct where no fence lifts by its own record: a deployment without
    /// the kill switch, and tests.
    pub fn fence_hold(mut self, f: FenceHold) -> Self {
        self.fence_hold = Some(f);
        self
    }

    /// Supply which discovery guards a magnet sheds once its metadata shows
    /// it is public. Without one, nothing is lifted: every magnet keeps DHT,
    /// PEX and LSD disabled, which is safe and only costs it peers.
    pub fn magnet_guard_lift(mut self, f: MagnetGuardLift) -> Self {
        self.magnet_guard_lift = Some(f);
        self
    }

    /// Supply the daemon's check limit, which the disk-error retry takes a
    /// slot in before each check it may start. Without one the retry's
    /// checks are unbounded, which is correct where nothing else checks:
    /// tests.
    pub fn check_slots(mut self, slots: Arc<dyn CheckSlots>) -> Self {
        self.check_slots = Some(slots);
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
        let unsaved_at_shutdown = Arc::new(AtomicU64::new(0));

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
                let unsaved_at_shutdown = Arc::clone(&unsaved_at_shutdown);
                let fatal_listen_failure = self.fatal_listen_failure;
                let on_fatal = self.on_fatal.clone();
                let profile_fenced = self.profile_fenced.clone();
                let fence_hold = self.fence_hold.clone();
                let magnet_guard_lift = self.magnet_guard_lift.clone();
                let check_slots = self.check_slots.clone();
                let listen_events = self.listen_events.clone();
                let listen_device_check = self.listen_device_check.clone();
                let shutdown_deadline = self.shutdown_deadline;
                move || {
                    let span = info_span!(
                        target: "torrentd_engine::alert_loop",
                        parent: parent,
                        "alert_loop"
                    );
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
                                fence_hold,
                                magnet_guard_lift,
                                check_slots,
                                unsaved_at_shutdown,
                                listen_events,
                                listen_device_check,
                                shutdown_deadline,
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
            unsaved_at_shutdown,
        }
    }
}

/// Handle returned by the builder.
pub struct AlertLoopHandle {
    join: thread::JoinHandle<()>,
    shutdown: Sender<ShutdownReason>,
    state: Arc<StateMap>,
    heartbeat: Arc<AtomicU64>,
    pub(super) listen_failed: Arc<AtomicBool>,
    panicked: Arc<AtomicBool>,
    unsaved_at_shutdown: Arc<AtomicU64>,
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

    /// Whether the loop terminated because a listen socket failed fatally,
    /// or came up held to the wrong device
    /// ([`AlertLoopBuilder::listen_device_check`]).
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

    /// Shared cell holding how many torrents' resume data was still unsaved
    /// when the shutdown drain's deadline elapsed; 0 until the loop has shut
    /// down, and 0 after a clean one.
    ///
    /// A metric emitted at that moment is never scraped — the process exits
    /// straight after — so the daemon takes the number from here once
    /// [`AlertLoopHandle::join`] returns, persists it, and re-exports it on
    /// the next boot. Taken as a clone before `join` consumes the handle.
    pub fn unsaved_at_shutdown(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.unsaved_at_shutdown)
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
