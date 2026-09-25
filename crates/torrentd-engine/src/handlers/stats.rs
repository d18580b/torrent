//! `SessionStats` handler — maps libtorrent's session-wide counters onto
//! Prometheus counters and gauges.
//!
//! libtorrent delivers `session_stats_alert` as a flat array of `i64`
//! counters indexed by a build-stable metric id. We resolve the ids for the
//! metrics the spec calls out once (via
//! `libtorrent_safe::session_stats_metric_index`) and cache them.
//!
//! libtorrent's array holds two kinds of value, and each is exported as its
//! own Prometheus type. The instantaneous ones (`peer.num_peers_connected`)
//! are gauges carrying the value. The monotonic ones (`net.sent_bytes`) are
//! **counters**, advanced by the increase since the previous alert for the
//! same profile. They used to be gauges carrying libtorrent's absolute value,
//! and `rate()` over a gauge does not treat a drop as a reset — a session
//! rebuilt under a running daemon produced a large negative rate instead of a
//! restart. A value lower than the last one seen is taken as exactly that
//! reset, and the new value is the whole increase.
//!
//! Every series gains a `profile_id` label so multi-profile mode
//! disambiguates sessions.

use std::collections::HashMap;
use std::sync::OnceLock;

use libtorrent_safe::Alert;
use parking_lot::Mutex;

use crate::handlers::HandlerCtx;

/// How a libtorrent value is exported.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StatKind {
    /// Monotonic in libtorrent; exported as a Prometheus counter.
    Counter,
    /// Instantaneous; exported as a gauge.
    Gauge,
}

/// `(prometheus suffix, libtorrent counter name, kind)`. The exported metric
/// is `torrentd_libtorrent_<suffix>` — the `torrentd_` namespace is prepended
/// by the Prometheus registry in the daemon. The kind is libtorrent's own:
/// everything before `num_stats_counters` in `performance_counters.hpp` is a
/// counter, everything after it a gauge.
pub const SESSION_METRICS: &[(&str, &str, StatKind)] = &[
    (
        "net_sent_payload_bytes_total",
        "net.sent_payload_bytes",
        StatKind::Counter,
    ),
    ("net_sent_bytes_total", "net.sent_bytes", StatKind::Counter),
    (
        "peers_connected",
        "peer.num_peers_connected",
        StatKind::Gauge,
    ),
    (
        "peers_up_unchoked",
        "peer.num_peers_up_unchoked",
        StatKind::Gauge,
    ),
    ("disk_queued_jobs", "disk.queued_disk_jobs", StatKind::Gauge),
    (
        "disk_request_latency",
        "disk.request_latency",
        StatKind::Gauge,
    ),
    (
        "disk_file_pool_hits_total",
        "disk.file_pool_hits",
        StatKind::Counter,
    ),
    (
        "disk_file_pool_misses_total",
        "disk.file_pool_misses",
        StatKind::Counter,
    ),
    (
        "peer_error_peers_total",
        "peer.error_peers",
        StatKind::Counter,
    ),
    (
        "peer_disconnected_peers_total",
        "peer.disconnected_peers",
        StatKind::Counter,
    ),
    (
        "num_seeding_torrents",
        "ses.num_seeding_torrents",
        StatKind::Gauge,
    ),
    (
        "num_error_torrents",
        "ses.num_error_torrents",
        StatKind::Gauge,
    ),
    ("limiter_up_queue", "net.limiter_up_queue", StatKind::Gauge),
];

/// Resolved `(metric name, counter index, kind)` triples. Names the running
/// libtorrent build doesn't recognize are dropped at resolve time (logged
/// once).
#[derive(Debug)]
pub struct StatsMetrics {
    resolved: Vec<(String, usize, StatKind)>,
    /// Last value seen per `(profile, index)`, for the counters' increments.
    last: Mutex<HashMap<(String, usize), i64>>,
}

impl StatsMetrics {
    /// Resolve every metric against the linked libtorrent build.
    pub fn resolve() -> Self {
        let mut resolved = Vec::with_capacity(SESSION_METRICS.len());
        for (suffix, lt_name, kind) in SESSION_METRICS {
            match libtorrent_safe::session_stats_metric_index(lt_name) {
                Some(idx) => resolved.push((format!("libtorrent_{suffix}"), idx, *kind)),
                None => tracing::debug!(
                    target: "torrentd_engine::handler::stats",
                    metric = lt_name,
                    "session-stats metric absent from this libtorrent build; skipping",
                ),
            }
        }
        Self {
            resolved,
            last: Mutex::new(HashMap::new()),
        }
    }

    /// Build from explicit `(metric name, index, kind)` triples — for unit
    /// tests that must not depend on the linked libtorrent's metric ordering.
    pub fn from_pairs(pairs: &[(&str, usize, StatKind)]) -> Self {
        Self {
            resolved: pairs
                .iter()
                .map(|(n, i, k)| ((*n).to_string(), *i, *k))
                .collect(),
            last: Mutex::new(HashMap::new()),
        }
    }

    /// The increase since the previous value for `(profile, idx)`, recording
    /// `value` as the new previous one. A first sighting, or a value below the
    /// previous one (the session was rebuilt), counts in full.
    fn increase(&self, profile: &str, idx: usize, value: i64) -> u64 {
        let mut last = self.last.lock();
        let prev = last.insert((profile.to_string(), idx), value);
        let delta = match prev {
            Some(p) if value >= p => value - p,
            _ => value,
        };
        u64::try_from(delta).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.resolved.is_empty()
    }
}

/// Process-wide cache of the metric table. The table is a constant of the
/// libtorrent build, so a `OnceLock` resolved on first use is exactly right.
fn global() -> &'static StatsMetrics {
    static M: OnceLock<StatsMetrics> = OnceLock::new();
    M.get_or_init(StatsMetrics::resolve)
}

/// Production entry point — resolves (and caches) the metric table on first
/// use, then emits gauges.
pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    handle_with(alert, ctx, global());
}

/// Core logic with an explicit metric table (testable without libtorrent).
pub fn handle_with(alert: &Alert, ctx: &mut HandlerCtx<'_>, metrics: &StatsMetrics) {
    let Alert::SessionStats { counters, .. } = alert else {
        unreachable!("stats::handle called with non-session_stats alert");
    };
    let _enter = ctx.span.enter();
    let profile = ctx.profile_id.as_str();
    for (name, idx, kind) in &metrics.resolved {
        let Some(v) = counters.get(*idx) else {
            continue;
        };
        match kind {
            StatKind::Gauge => ctx
                .metrics
                .set_gauge(name, *v as f64, &[("profile_id", profile)]),
            StatKind::Counter => {
                let inc = metrics.increase(profile, *idx, *v);
                ctx.metrics
                    .add_counter(name, inc, &[("profile_id", profile)]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;

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

    fn session_stats(counters: Vec<i64>) -> Alert {
        Alert::SessionStats {
            hdr: AlertHeader {
                kind: AlertKind::SessionStats,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            counters,
            timestamp_ns: 0,
        }
    }

    fn run(table: &StatsMetrics, counters: Vec<i64>) -> Vec<MetricCall> {
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
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        handle_with(&session_stats(counters), &mut ctx, table);
        metrics.calls()
    }

    #[test]
    fn emits_gauge_for_resolved_metric_with_profile_label() {
        let table = StatsMetrics::from_pairs(&[("libtorrent_peers_connected", 2, StatKind::Gauge)]);
        let calls = run(&table, vec![10, 20, 4242, 30]);
        let found = calls.iter().any(|c| {
            matches!(c,
                MetricCall::SetGauge { name, value, labels }
                if name == "libtorrent_peers_connected"
                    && *value == 4242.0
                    && labels.iter().any(|(k, v)| k == "profile_id" && v == "p"))
        });
        assert!(found, "expected gauge for index 2, got {calls:?}");
    }

    fn added(calls: &[MetricCall]) -> Vec<u64> {
        calls
            .iter()
            .filter_map(|c| match c {
                MetricCall::AddCounter { value, .. } => Some(*value),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_monotonic_value_advances_a_counter_by_its_increase() {
        let table =
            StatsMetrics::from_pairs(&[("libtorrent_net_sent_bytes_total", 0, StatKind::Counter)]);
        assert_eq!(added(&run(&table, vec![100])), vec![100]);
        assert_eq!(added(&run(&table, vec![150])), vec![50]);
        assert_eq!(added(&run(&table, vec![150])), vec![0]);
    }

    #[test]
    fn a_monotonic_value_that_drops_is_a_reset_and_counts_in_full() {
        let table =
            StatsMetrics::from_pairs(&[("libtorrent_net_sent_bytes_total", 0, StatKind::Counter)]);
        run(&table, vec![1_000]);
        assert_eq!(added(&run(&table, vec![30])), vec![30]);
    }

    #[test]
    fn every_counter_is_named_as_one_and_no_gauge_is() {
        for (suffix, lt_name, kind) in SESSION_METRICS {
            assert_eq!(
                suffix.ends_with("_total"),
                *kind == StatKind::Counter,
                "{lt_name} is exported as {suffix} but is a {kind:?}",
            );
        }
    }

    #[test]
    fn out_of_range_index_is_skipped_without_panic() {
        // Index 9 against a 3-element counter array must be silently skipped.
        let table = StatsMetrics::from_pairs(&[("libtorrent_absent", 9, StatKind::Gauge)]);
        let calls = run(&table, vec![1, 2, 3]);
        assert!(
            calls.is_empty(),
            "no gauge should be emitted, got {calls:?}"
        );
    }
}
