//! Tracker and session warnings: counted per profile and kind, and logged.
//!
//! None of these changes what the daemon does. Each is an operational signal
//! an operator alerts on — a tracker rejecting announces, a port mapping that
//! failed, fast-resume data libtorrent threw away — and before this handler
//! the tracker error reached only a `debug!` line and the rest were never
//! translated at all.
//!
//! Successful announces are counted too (`kind="reply"`), not logged: they are
//! the denominator an alert divides tracker errors by. An announce that failed
//! because the torrent was stopping — paused, fenced, removed, or the announce
//! cancelled — is counted as `kind="stopped"` and logged at `debug` only: no
//! tracker failed, and counting it as `error` would let a bulk pause raise the
//! failure ratio (see [`stop_cause`]).
//!
//! Two counters, both with a bounded label set: `profile_id` and a `kind` drawn
//! from the fixed lists below. No per-torrent and no per-tracker-URL label:
//! either would give every torrent a series of its own, and the URL carries
//! the passkey. Which torrent and which tracker are in the log line.
//!
//! A tracker failure is warned at most [`TRACKER_FAILURE_WARNS_PER_WINDOW`]
//! times per profile per [`TRACKER_FAILURE_WINDOW`] (see
//! [`TrackerFailureLog`]). A tracker outage or a bulk pause starts a failure
//! streak on every torrent at once, and one warn line each at 100K torrents is
//! enough to trip journald's per-unit rate limit, which then drops the lines an
//! operator needs, such as a fence's own errors.

use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use libtorrent_safe::Alert;
use libtorrent_safe::AlertKind;
use tracing::debug;
use tracing::warn;

use crate::handlers::HandlerCtx;
use crate::profile::ProfileId;
use crate::state::TorrentPhase;

/// How many tracker failures one profile warns about individually in one
/// [`TRACKER_FAILURE_WINDOW`]. The rest are logged at `debug` and counted into
/// one summary warn when the window closes.
pub const TRACKER_FAILURE_WARNS_PER_WINDOW: u64 = 10;

/// The window [`TRACKER_FAILURE_WARNS_PER_WINDOW`] is counted over.
pub const TRACKER_FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// The alert loop's record of how many tracker failures each profile has
/// warned about in its current window, and how many it held back to `debug`.
///
/// A window opens at a profile's first failure and closes on the first alert
/// of that profile dispatched [`TRACKER_FAILURE_WINDOW`] or more after it
/// opened; every profile posts a state update every few seconds, so the
/// summary of a closed window is written within moments of its end. At most
/// `TRACKER_FAILURE_WARNS_PER_WINDOW + 1` warn lines per profile per window,
/// whatever the number of torrents.
#[derive(Debug, Default)]
pub struct TrackerFailureLog {
    windows: HashMap<ProfileId, FailureWindow>,
}

#[derive(Debug)]
struct FailureWindow {
    opened: Instant,
    warned: u64,
    suppressed: u64,
}

impl TrackerFailureLog {
    /// Whether this failure, at `now`, may be warned about individually.
    /// Counts it either way.
    fn admit(&mut self, profile: &ProfileId, now: Instant) -> bool {
        let window = self
            .windows
            .entry(profile.clone())
            .or_insert(FailureWindow {
                opened: now,
                warned: 0,
                suppressed: 0,
            });
        if window.warned < TRACKER_FAILURE_WARNS_PER_WINDOW {
            window.warned += 1;
            true
        } else {
            window.suppressed += 1;
            false
        }
    }

    /// Close `profile`'s window if it is due at `now`, returning how many
    /// failures it held back from `warn`.
    fn close_due(&mut self, profile: &ProfileId, now: Instant) -> Option<u64> {
        let window = self.windows.get(profile)?;
        if now.saturating_duration_since(window.opened) < TRACKER_FAILURE_WINDOW {
            return None;
        }
        let suppressed = window.suppressed;
        self.windows.remove(profile);
        Some(suppressed)
    }
}

/// Close the profile's tracker-failure window if it has run its length, and
/// warn once with the count of failures it logged at `debug` only. The alert
/// loop calls this for every alert it dispatches, so a window closes even
/// after the tracker goes quiet.
pub fn close_failure_window(ctx: &HandlerCtx<'_>, log: &mut TrackerFailureLog) {
    let Some(suppressed) = log.close_due(&ctx.profile_id, ctx.clock.now()) else {
        return;
    };
    if suppressed == 0 {
        return;
    }
    let _enter = ctx.span.enter();
    warn!(
        target: "torrentd_engine::handler::tracker",
        suppressed,
        window_secs = TRACKER_FAILURE_WINDOW.as_secs(),
        "more tracker announces failed than were logged individually; the rest are at debug \
         and every one is in tracker_alerts_total{{kind=\"error\"}}",
    );
}

/// `tracker_alerts_total{kind}`: every value this handler can emit.
/// `stopped` is an announce failure a pause, fence, removal or shutdown
/// caused (see [`stop_cause`]); `error` is every other.
pub const TRACKER_KINDS: &[&str] = &["error", "reply", "warning", "scrape_failed", "stopped"];

/// Why a tracker error was caused by the torrent stopping rather than by the
/// tracker, or `None` when nothing says it was.
///
/// Pausing a torrent (the API's pause, a fence's, or a disk error's) makes
/// libtorrent send a stopped announce, and removing one does the same. That
/// announce gets `stop_tracker_timeout` (5 s by default) where any other gets
/// `tracker_receive_timeout`, so a tracker that a bulk pause floods with
/// stopped announces lets many expire: libtorrent's `errors::timed_out`, 36 in
/// the libtorrent category, with no failure reason. Neither the alert nor its
/// code says which announce failed, so this asks what the daemon knows of the
/// torrent: a paused torrent announces nothing but the stopped event.
///
/// - `aborted`: the announce was cancelled (see `Alert::TrackerError`).
/// - `fenced`: the VPN monitor fenced the profile, which pauses every torrent
///   in it at once, before the next state update says so.
/// - `paused`: the last state update showed the torrent paused.
/// - `removed`: the torrent is gone, so the handle carried no info-hash, or
///   the state map no longer holds it for this profile and handle (an entry
///   for the same info-hash that another profile or handle holds is a later
///   re-add, not this torrent). Every torrent in a session is in the
///   state map from its add alert on, and libtorrent posts that before any
///   announce the torrent makes.
///
/// A pause the state map has not yet seen (state updates come every two
/// seconds) is missed and counted as `error`; a stopped announce that times
/// out does so five seconds after the pause, by when the update has arrived.
fn stop_cause(
    hdr: &libtorrent_safe::alert::AlertHeader,
    aborted: bool,
    ctx: &HandlerCtx<'_>,
) -> Option<&'static str> {
    if aborted {
        return Some("aborted");
    }
    if ctx.profile_fenced.is_some_and(|f| f(&ctx.profile_id)) {
        return Some("fenced");
    }
    let Some(ih) = hdr.infohash else {
        return Some("removed");
    };
    // The map is keyed by info-hash alone: an entry another profile (or
    // another handle) inserted since this torrent was removed describes that
    // torrent, not this one, so this one is gone.
    let phase = ctx
        .state
        .get(&ih)
        .filter(|st| st.profile_id == ctx.profile_id && hdr.handle.is_none_or(|h| h == st.handle))
        .map(|st| st.phase);
    match phase {
        None | Some(TorrentPhase::Removed) => Some("removed"),
        Some(TorrentPhase::Paused) => Some("paused"),
        Some(_) => None,
    }
}

/// `session_alerts_total{kind}`: every value this handler can emit.
pub const SESSION_KINDS: &[&str] = &[
    "portmap_error",
    "udp_error",
    "fastresume_rejected",
    "performance_warning",
];

/// `failures` is the loop's per-profile record of how many tracker failures
/// were warned about in the current window; see [`TrackerFailureLog`].
pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>, failures: &mut TrackerFailureLog) {
    close_failure_window(ctx, failures);
    let _enter = ctx.span.enter();
    let profile = ctx.profile_id.as_str();
    match alert {
        Alert::TrackerError {
            hdr,
            error_code,
            error_category,
            aborted,
            times_in_row,
            message,
            ..
        } => {
            // A pause, fence, removal or shutdown makes libtorrent cancel the
            // torrent's announce or send a stopped one, and a failure of
            // either says nothing about the tracker: logged at `debug` and
            // counted apart, so it neither writes a failure line nor raises
            // the failure ratio the tracker alert divides `kind="error"` by.
            if let Some(cause) = stop_cause(hdr, *aborted, ctx) {
                debug!(
                    target: "torrentd_engine::handler::tracker",
                    infohash = hdr.infohash.map(|i| i.to_string()).unwrap_or_default(),
                    error.code = *error_code,
                    error.category = error_category.as_str(),
                    error.cause = %message,
                    cause,
                    "tracker announce failed while the torrent stopped",
                );
                ctx.metrics.inc_counter(
                    "tracker_alerts_total",
                    &[("profile_id", profile), ("kind", "stopped")],
                );
                return;
            }
            // The URL is deliberately not logged: on a private tracker it
            // carries the passkey. The info-hash identifies the torrent.
            //
            // Warned once per streak — a tracker that is down fails every
            // announce, and one line per announce per torrent would bury the
            // journal. And a streak's start is warned only while the
            // profile's window has room: an outage starts a streak on every
            // torrent at once. The counter sees every one.
            let first = *times_in_row <= 1;
            if first && failures.admit(&ctx.profile_id, ctx.clock.now()) {
                warn!(
                    target: "torrentd_engine::handler::tracker",
                    infohash = hdr.infohash.map(|i| i.to_string()).unwrap_or_default(),
                    error.code = *error_code,
                    error.category = error_category.as_str(),
                    error.cause = %message,
                    "tracker announce failed",
                );
            } else if first {
                // Held back by the window; its summary warn counts this one.
                debug!(
                    target: "torrentd_engine::handler::tracker",
                    infohash = hdr.infohash.map(|i| i.to_string()).unwrap_or_default(),
                    error.code = *error_code,
                    error.category = error_category.as_str(),
                    error.cause = %message,
                    "tracker announce failed",
                );
            } else {
                debug!(
                    target: "torrentd_engine::handler::tracker",
                    infohash = hdr.infohash.map(|i| i.to_string()).unwrap_or_default(),
                    error.code = *error_code,
                    error.category = error_category.as_str(),
                    times_in_row = *times_in_row,
                    error.cause = %message,
                    "tracker announce failed again",
                );
            }
            ctx.metrics.inc_counter(
                "tracker_alerts_total",
                &[("profile_id", profile), ("kind", "error")],
            );
        }
        // Not logged: every torrent announces every few minutes. Counted so the
        // failure alert can divide errors by all announces, which tells one
        // dead tracker among many working ones from trackers that are down.
        Alert::TrackerReply { .. } => {
            ctx.metrics.inc_counter(
                "tracker_alerts_total",
                &[("profile_id", profile), ("kind", "reply")],
            );
        }
        Alert::Warning {
            hdr,
            error_code,
            warning_code,
            message,
        } => {
            let (metric, kind) = match hdr.kind {
                AlertKind::TrackerWarning => ("tracker_alerts_total", "warning"),
                AlertKind::ScrapeFailed => ("tracker_alerts_total", "scrape_failed"),
                AlertKind::PortmapError => ("session_alerts_total", "portmap_error"),
                AlertKind::UdpError => ("session_alerts_total", "udp_error"),
                AlertKind::FastresumeRejected => ("session_alerts_total", "fastresume_rejected"),
                AlertKind::Performance => ("session_alerts_total", "performance_warning"),
                other => unreachable!("warning::handle called with {other:?}"),
            };
            let infohash = hdr.infohash.map(|i| i.to_string()).unwrap_or_default();
            // Tracker warnings and scrape failures are routine on a public
            // tracker and would flood the journal at `warn`; the rest are rare
            // and each one means something is misconfigured or overloaded.
            //
            // libtorrent builds a tracker alert's message from the announce
            // URL, passkey and all. The daemon's log formatter holds this
            // target to host-only redaction (`HOST_ONLY_TARGETS` in
            // `torrentd::tracing_init`), so keep the two in step.
            if metric == "tracker_alerts_total" {
                debug!(
                    target: "torrentd_engine::handler::tracker",
                    infohash = %infohash,
                    kind,
                    error.code = *error_code,
                    error.cause = %message,
                    "tracker warning",
                );
            } else {
                warn!(
                    target: "torrentd_engine::handler::session",
                    infohash = %infohash,
                    kind,
                    error.code = *error_code,
                    warning_code = *warning_code,
                    error.cause = %message,
                    "libtorrent session warning",
                );
            }
            ctx.metrics
                .inc_counter(metric, &[("profile_id", profile), ("kind", kind)]);
        }
        _ => unreachable!("warning::handle called with a non-warning alert"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::alert::ErrorCategory;
    use libtorrent_safe::InfoHash;
    use libtorrent_safe::TorrentHandle;
    use parking_lot::Mutex;

    use super::*;
    use crate::alert_loop::ProfileFenced;
    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::MetricCall;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::state::StateMap;
    use crate::state::TorrentState;
    use crate::torrent_store::MemoryTorrentStore;

    /// The info-hash [`hdr`] gives every alert; [`run`] tracks it as seeding.
    const IH: InfoHash = InfoHash([7; 20]);

    fn hdr(kind: AlertKind) -> AlertHeader {
        AlertHeader {
            kind,
            infohash: Some(IH),
            handle: None,
            timestamp_us: 0,
        }
    }

    /// Put `ih` in `state` in `phase`, as the state updates would.
    fn track(state: &StateMap, ih: InfoHash, phase: TorrentPhase) {
        let mut st = TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: ih,
            },
            ProfileId::new("p"),
            Instant::now(),
        );
        st.phase = phase;
        state.insert(ih, st);
    }

    fn tracker_error(error_code: i32, aborted: bool) -> Alert {
        Alert::TrackerError {
            hdr: hdr(AlertKind::TrackerError),
            error_code,
            error_category: ErrorCategory::Libtorrent,
            aborted,
            times_in_row: 1,
            tracker_url: "http://t/announce?passkey=secret".into(),
            message: String::new(),
        }
    }

    fn run(alert: Alert) -> Vec<MetricCall> {
        run_in(alert, Some(TorrentPhase::Seeding), None).0
    }

    /// Dispatch `alert` with [`IH`] in `phase` (untracked when `None`) and the
    /// given fence, returning the metric calls and how many lines it warned.
    fn run_in(
        alert: Alert,
        phase: Option<TorrentPhase>,
        fenced: Option<ProfileFenced>,
    ) -> (Vec<MetricCall>, usize, TrackerFailureLog) {
        let state = StateMap::new();
        if let Some(phase) = phase {
            track(&state, IH, phase);
        }
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = RecordingSink::new();
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: fenced.as_ref(),
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        let mut failures = TrackerFailureLog::default();
        let counter = Arc::new(WarnCounter::default());
        tracing::subscriber::with_default(Arc::clone(&counter), || {
            handle(&alert, &mut ctx, &mut failures);
        });
        let warns = counter.warns.load(Ordering::Relaxed);
        (metrics.calls(), warns, failures)
    }

    /// Counts the `warn` events dispatched to it and records the
    /// `suppressed` field of each, so a test can bound the journal lines.
    #[derive(Default)]
    struct WarnCounter {
        warns: AtomicUsize,
        suppressed: Mutex<Vec<u64>>,
    }

    struct Suppressed<'a>(&'a Mutex<Vec<u64>>);

    impl tracing::field::Visit for Suppressed<'_> {
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            if field.name() == "suppressed" {
                self.0.lock().push(value);
            }
        }
        fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    }

    impl tracing::Subscriber for WarnCounter {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.warns.fetch_add(1, Ordering::Relaxed);
                event.record(&mut Suppressed(&self.suppressed));
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn first_failure(n: u8) -> Alert {
        Alert::TrackerError {
            hdr: AlertHeader {
                kind: AlertKind::TrackerError,
                infohash: Some(InfoHash([n; 20])),
                handle: None,
                timestamp_us: 0,
            },
            error_code: 36,
            error_category: ErrorCategory::Libtorrent,
            aborted: false,
            times_in_row: 1,
            tracker_url: "http://t/announce?passkey=secret".into(),
            message: String::new(),
        }
    }

    #[test]
    fn ten_thousand_first_failures_on_one_profile_warn_a_bounded_number_of_times() {
        let state = StateMap::new();
        // Seeding, so none of them is put down to the torrent stopping.
        for n in 0..=u8::MAX {
            track(&state, InfoHash([n; 20]), TorrentPhase::Seeding);
        }
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = RecordingSink::new();
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut failures = TrackerFailureLog::default();
        let counter = Arc::new(WarnCounter::default());
        let ctx_for = || HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };

        tracing::subscriber::with_default(Arc::clone(&counter), || {
            for i in 0..10_000u32 {
                handle(
                    &first_failure((i % 251) as u8),
                    &mut ctx_for(),
                    &mut failures,
                );
            }
        });
        let total = TRACKER_FAILURE_WARNS_PER_WINDOW as usize;
        assert_eq!(counter.warns.load(Ordering::Relaxed), total);
        // Every one is still counted.
        assert_eq!(metrics.calls().len(), 10_000);

        // Before the window ends, another alert closes nothing.
        clock.advance(TRACKER_FAILURE_WINDOW - Duration::from_secs(1));
        tracing::subscriber::with_default(Arc::clone(&counter), || {
            close_failure_window(&ctx_for(), &mut failures);
        });
        assert_eq!(counter.warns.load(Ordering::Relaxed), total);

        // The first alert after it closes the window with one summary
        // counting what was held back.
        clock.advance(Duration::from_secs(1));
        tracing::subscriber::with_default(Arc::clone(&counter), || {
            close_failure_window(&ctx_for(), &mut failures);
            close_failure_window(&ctx_for(), &mut failures);
        });
        assert_eq!(counter.warns.load(Ordering::Relaxed), total + 1);
        assert_eq!(
            *counter.suppressed.lock(),
            vec![10_000 - TRACKER_FAILURE_WARNS_PER_WINDOW]
        );

        // A new window warns again.
        tracing::subscriber::with_default(Arc::clone(&counter), || {
            handle(&first_failure(1), &mut ctx_for(), &mut failures);
        });
        assert_eq!(counter.warns.load(Ordering::Relaxed), total + 2);
    }

    #[test]
    fn each_profile_has_its_own_tracker_failure_window() {
        let mut log = TrackerFailureLog::default();
        let now = Instant::now();
        let (a, b) = (ProfileId::new("a"), ProfileId::new("b"));
        for _ in 0..TRACKER_FAILURE_WARNS_PER_WINDOW {
            assert!(log.admit(&a, now));
        }
        assert!(!log.admit(&a, now));
        assert!(log.admit(&b, now), "a's window spilled into b's");
        let later = now + TRACKER_FAILURE_WINDOW;
        assert_eq!(log.close_due(&a, later), Some(1));
        assert_eq!(log.close_due(&b, later), Some(0));
        assert!(log.windows.is_empty(), "a closed window is kept");
    }

    #[test]
    fn a_continuing_streak_never_takes_a_place_in_the_window() {
        let mut failures = TrackerFailureLog::default();
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = RecordingSink::new();
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        track(&state, IH, TorrentPhase::Seeding);
        let again = Alert::TrackerError {
            hdr: hdr(AlertKind::TrackerError),
            error_code: 111,
            error_category: ErrorCategory::System,
            aborted: false,
            times_in_row: 2,
            tracker_url: String::new(),
            message: String::new(),
        };
        for _ in 0..100 {
            handle(&again, &mut ctx, &mut failures);
        }
        assert!(failures.windows.is_empty());
        assert_eq!(metrics.calls().len(), 100);
    }

    fn labels_of(calls: &[MetricCall]) -> Vec<(String, Vec<(String, String)>)> {
        calls
            .iter()
            .map(|c| match c {
                MetricCall::IncCounter { name, labels } => (name.clone(), labels.clone()),
                other => panic!("unexpected metric call {other:?}"),
            })
            .collect()
    }

    fn pair(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[test]
    fn a_tracker_error_counts_as_kind_error_for_its_profile() {
        let calls = run(Alert::TrackerError {
            hdr: hdr(AlertKind::TrackerError),
            error_code: 111,
            error_category: ErrorCategory::System,
            aborted: false,
            times_in_row: 3,
            tracker_url: "http://t/announce?passkey=secret".into(),
            message: "connection refused".into(),
        });
        assert_eq!(
            labels_of(&calls),
            vec![(
                "tracker_alerts_total".to_string(),
                vec![pair("profile_id", "p"), pair("kind", "error")]
            )]
        );
    }

    fn kind_stopped() -> Vec<(String, Vec<(String, String)>)> {
        vec![(
            "tracker_alerts_total".to_string(),
            vec![pair("profile_id", "p"), pair("kind", "stopped")],
        )]
    }

    /// The bulk pause #226's harness ran: libtorrent's `timed_out` (36) on
    /// the stopped announce of a torrent the state map holds as paused.
    #[test]
    fn a_paused_torrents_timed_out_announce_is_counted_as_stopped_and_not_warned() {
        let (calls, warns, failures) =
            run_in(tracker_error(36, false), Some(TorrentPhase::Paused), None);
        assert_eq!(labels_of(&calls), kind_stopped());
        assert_eq!(warns, 0);
        assert!(
            failures.windows.is_empty(),
            "a stop took a place in the failure window"
        );
        assert!(TRACKER_KINDS.contains(&"stopped"));
    }

    #[test]
    fn the_same_timeout_on_a_seeding_torrent_is_a_tracker_failure() {
        let (calls, warns, _) = run_in(tracker_error(36, false), Some(TorrentPhase::Seeding), None);
        assert_eq!(
            labels_of(&calls),
            vec![(
                "tracker_alerts_total".to_string(),
                vec![pair("profile_id", "p"), pair("kind", "error")]
            )]
        );
        assert_eq!(warns, 1);
    }

    #[test]
    fn a_cancelled_announce_is_counted_as_stopped_whatever_the_phase() {
        let (calls, warns, _) = run_in(tracker_error(125, true), Some(TorrentPhase::Seeding), None);
        assert_eq!(labels_of(&calls), kind_stopped());
        assert_eq!(warns, 0);
    }

    /// A fence pauses the whole profile at once, before any state update.
    #[test]
    fn a_failure_in_a_fenced_profile_is_counted_as_stopped() {
        let fenced = Arc::new(|p: &ProfileId| p.as_str() == "p") as ProfileFenced;
        let (calls, warns, _) = run_in(
            tracker_error(36, false),
            Some(TorrentPhase::Seeding),
            Some(fenced),
        );
        assert_eq!(labels_of(&calls), kind_stopped());
        assert_eq!(warns, 0);

        let other = Arc::new(|p: &ProfileId| p.as_str() == "q") as ProfileFenced;
        let (calls, _, _) = run_in(
            tracker_error(36, false),
            Some(TorrentPhase::Seeding),
            Some(other),
        );
        assert_eq!(labels_of(&calls)[0].1[1], pair("kind", "error"));
    }

    /// A removal sends a stopped announce too, and by the time its failure
    /// is dispatched the torrent is out of the state map, or its handle no
    /// longer names it.
    #[test]
    fn a_failure_for_a_removed_torrent_is_counted_as_stopped() {
        for phase in [None, Some(TorrentPhase::Removed)] {
            let (calls, warns, _) = run_in(tracker_error(36, false), phase, None);
            assert_eq!(labels_of(&calls), kind_stopped(), "{phase:?}");
            assert_eq!(warns, 0);
        }
        let mut alert = tracker_error(36, false);
        if let Alert::TrackerError { hdr, .. } = &mut alert {
            hdr.infohash = None;
        }
        let (calls, _, _) = run_in(alert, Some(TorrentPhase::Seeding), None);
        assert_eq!(labels_of(&calls), kind_stopped());
    }

    /// The state map is keyed by info-hash alone: after one profile removes a
    /// torrent and another adds the same one, the entry is the other
    /// profile's, and the removed torrent's stopped-announce failure must not
    /// be read against it.
    #[test]
    fn a_failure_read_against_another_profiles_or_handles_entry_is_stopped() {
        let fenced: Option<ProfileFenced> = None;
        let dispatch = |alert: &Alert, entry: TorrentState| {
            let state = StateMap::new();
            state.insert(IH, entry);
            let resume = MemoryResumeStore::new();
            let torrents = MemoryTorrentStore::new();
            let metrics = RecordingSink::new();
            let clock = MockClock::new();
            let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
            let mut ctx = HandlerCtx {
                state: &state,
                resume: &resume,
                torrents: &torrents,
                metrics: &metrics,
                clock: &clock,
                engine: &engine,
                profile_fenced: fenced.as_ref(),
                profile_id: ProfileId::new("p"),
                span: tracing::info_span!("test"),
            };
            let counter = Arc::new(WarnCounter::default());
            tracing::subscriber::with_default(Arc::clone(&counter), || {
                handle(alert, &mut ctx, &mut TrackerFailureLog::default());
            });
            (metrics.calls(), counter.warns.load(Ordering::Relaxed))
        };
        let entry = |profile: &str, id: u64| {
            let mut st = TorrentState::newly_added(
                TorrentHandle { id, infohash: IH },
                ProfileId::new(profile),
                Instant::now(),
            );
            st.phase = TorrentPhase::Seeding;
            st
        };
        let mut alert = tracker_error(36, false);
        if let Alert::TrackerError { hdr, .. } = &mut alert {
            hdr.handle = Some(TorrentHandle {
                id: 1,
                infohash: IH,
            });
        }

        // Another profile seeds the same info-hash.
        let (calls, warns) = dispatch(&alert, entry("q", 1));
        assert_eq!(labels_of(&calls), kind_stopped());
        assert_eq!(warns, 0);

        // This profile re-added it under another handle.
        let (calls, warns) = dispatch(&alert, entry("p", 2));
        assert_eq!(labels_of(&calls), kind_stopped());
        assert_eq!(warns, 0);

        // Its own entry, same handle: a real tracker failure.
        let (calls, warns) = dispatch(&alert, entry("p", 1));
        assert_eq!(labels_of(&calls)[0].1[1], pair("kind", "error"));
        assert_eq!(warns, 1);
    }

    #[test]
    fn a_tracker_reply_counts_as_kind_reply_for_its_profile() {
        let calls = run(Alert::TrackerReply {
            hdr: hdr(AlertKind::TrackerReply),
        });
        assert_eq!(
            labels_of(&calls),
            vec![(
                "tracker_alerts_total".to_string(),
                vec![pair("profile_id", "p"), pair("kind", "reply")]
            )]
        );
        assert!(TRACKER_KINDS.contains(&"reply"));
    }

    #[test]
    fn every_warning_kind_lands_on_its_own_counter_and_label() {
        let cases = [
            (AlertKind::TrackerWarning, "tracker_alerts_total", "warning"),
            (
                AlertKind::ScrapeFailed,
                "tracker_alerts_total",
                "scrape_failed",
            ),
            (
                AlertKind::PortmapError,
                "session_alerts_total",
                "portmap_error",
            ),
            (AlertKind::UdpError, "session_alerts_total", "udp_error"),
            (
                AlertKind::FastresumeRejected,
                "session_alerts_total",
                "fastresume_rejected",
            ),
            (
                AlertKind::Performance,
                "session_alerts_total",
                "performance_warning",
            ),
        ];
        for (kind, metric, label) in cases {
            let calls = run(Alert::Warning {
                hdr: hdr(kind),
                error_code: 0,
                warning_code: 0,
                message: String::new(),
            });
            assert_eq!(
                labels_of(&calls),
                vec![(
                    metric.to_string(),
                    vec![pair("profile_id", "p"), pair("kind", label)]
                )],
                "{kind:?}",
            );
            let known = if metric == "tracker_alerts_total" {
                TRACKER_KINDS
            } else {
                SESSION_KINDS
            };
            assert!(known.contains(&label), "{label} missing from its kind list");
        }
    }
}
