//! Tracker and session warnings: counted per profile and kind, and logged.
//!
//! None of these changes what the daemon does. Each is an operational signal
//! an operator alerts on — a tracker rejecting announces, a port mapping that
//! failed, fast-resume data libtorrent threw away — and before this handler
//! the tracker error reached only a `debug!` line and the rest were never
//! translated at all.
//!
//! Successful announces are counted too (`kind="reply"`), not logged: they are
//! the denominator an alert divides tracker errors by.
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
pub const TRACKER_KINDS: &[&str] = &["error", "reply", "warning", "scrape_failed"];

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
            times_in_row,
            message,
            ..
        } => {
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
                    error.cause = %message,
                    "tracker announce failed",
                );
            } else if first {
                // Held back by the window; its summary warn counts this one.
                debug!(
                    target: "torrentd_engine::handler::tracker",
                    infohash = hdr.infohash.map(|i| i.to_string()).unwrap_or_default(),
                    error.code = *error_code,
                    error.cause = %message,
                    "tracker announce failed",
                );
            } else {
                debug!(
                    target: "torrentd_engine::handler::tracker",
                    infohash = hdr.infohash.map(|i| i.to_string()).unwrap_or_default(),
                    error.code = *error_code,
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
    use parking_lot::Mutex;

    use super::*;
    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::MetricCall;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::state::StateMap;
    use crate::torrent_store::MemoryTorrentStore;

    fn hdr(kind: AlertKind) -> AlertHeader {
        AlertHeader {
            kind,
            infohash: None,
            handle: None,
            timestamp_us: 0,
        }
    }

    fn run(alert: Alert) -> Vec<MetricCall> {
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
        handle(&alert, &mut ctx, &mut TrackerFailureLog::default());
        metrics.calls()
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
                infohash: Some(libtorrent_safe::InfoHash([n; 20])),
                handle: None,
                timestamp_us: 0,
            },
            error_code: 36,
            times_in_row: 1,
            tracker_url: "http://t/announce?passkey=secret".into(),
            message: String::new(),
        }
    }

    #[test]
    fn ten_thousand_first_failures_on_one_profile_warn_a_bounded_number_of_times() {
        let state = StateMap::new();
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
        let again = Alert::TrackerError {
            hdr: hdr(AlertKind::TrackerError),
            error_code: 111,
            times_in_row: 2,
            tracker_url: String::new(),
            message: String::new(),
        };
        for _ in 0..100 {
            handle(&again, &mut ctx, &mut failures);
        }
        assert!(failures.windows.is_empty());
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
