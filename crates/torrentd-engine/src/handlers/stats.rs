//! `SessionStats` handler — maps libtorrent's session-wide counters
//! onto Prometheus gauges.
//!
//! libtorrent delivers `session_stats_alert` as a flat array of `i64`
//! counters indexed by a build-stable metric id. We resolve the ids for the
//! metrics the spec calls out once (via
//! `libtorrent_safe::session_stats_metric_index`) and cache them. Every
//! counter is exported as a **gauge carrying libtorrent's absolute value**:
//! the monotonic ones (e.g. `net.sent_bytes`) are handled by PromQL `rate()`
//! at query time, the instantaneous ones (e.g. `peer.num_peers_connected`)
//! read directly. Every gauge gains a `slot_id` label so multi-slot mode
//! disambiguates sessions.

use std::sync::OnceLock;

use libtorrent_safe::Alert;

use crate::handlers::HandlerCtx;

/// `(prometheus gauge suffix, libtorrent counter name)`. The exported metric
/// is `torrentd_libtorrent_<suffix>` — the `torrentd_` namespace is prepended by
/// the Prometheus registry in the daemon.
const SESSION_METRICS: &[(&str, &str)] = &[
    ("net_sent_payload_bytes", "net.sent_payload_bytes"),
    ("net_sent_bytes", "net.sent_bytes"),
    ("peers_connected", "peer.num_peers_connected"),
    ("peers_up_unchoked", "peer.num_peers_up_unchoked"),
    ("disk_queued_jobs", "disk.queued_disk_jobs"),
    ("disk_request_latency", "disk.request_latency"),
    ("disk_file_pool_hits", "disk.file_pool_hits"),
    ("disk_file_pool_misses", "disk.file_pool_misses"),
    ("peer_error_peers", "peer.error_peers"),
    ("peer_disconnected_peers", "peer.disconnected_peers"),
    ("num_seeding_torrents", "ses.num_seeding_torrents"),
    ("num_error_torrents", "ses.num_error_torrents"),
    ("limiter_up_queue", "net.limiter_up_queue"),
];

/// Resolved `(gauge name, counter index)` pairs. Names the running libtorrent
/// build doesn't recognize are dropped at resolve time (logged once).
#[derive(Debug, Clone)]
pub struct StatsMetrics {
    resolved: Vec<(String, usize)>,
}

impl StatsMetrics {
    /// Resolve every metric against the linked libtorrent build.
    pub fn resolve() -> Self {
        let mut resolved = Vec::with_capacity(SESSION_METRICS.len());
        for (suffix, lt_name) in SESSION_METRICS {
            match libtorrent_safe::session_stats_metric_index(lt_name) {
                Some(idx) => resolved.push((format!("libtorrent_{suffix}"), idx)),
                None => tracing::debug!(
                    target: "torrentd_engine::handler::stats",
                    metric = lt_name,
                    "session-stats metric absent from this libtorrent build; skipping",
                ),
            }
        }
        Self { resolved }
    }

    /// Build from explicit `(gauge name, index)` pairs — for unit tests that
    /// must not depend on the linked libtorrent's metric ordering.
    pub fn from_pairs(pairs: &[(&str, usize)]) -> Self {
        Self {
            resolved: pairs.iter().map(|(n, i)| ((*n).to_string(), *i)).collect(),
        }
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
    let slot = ctx.slot_id.as_str();
    for (name, idx) in &metrics.resolved {
        if let Some(v) = counters.get(*idx) {
            ctx.metrics.set_gauge(name, *v as f64, &[("slot_id", slot)]);
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
    use crate::resume_store::MemoryResumeStore;
    use crate::slot::SlotId;
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
            slot_id: SlotId::default_single(),
            span: tracing::info_span!("test"),
        };
        handle_with(&session_stats(counters), &mut ctx, table);
        metrics.calls()
    }

    #[test]
    fn emits_gauge_for_resolved_metric_with_slot_label() {
        let table = StatsMetrics::from_pairs(&[("libtorrent_net_sent_bytes", 2)]);
        let calls = run(&table, vec![10, 20, 4242, 30]);
        let found = calls.iter().any(|c| {
            matches!(c,
                MetricCall::SetGauge { name, value, labels }
                if name == "libtorrent_net_sent_bytes"
                    && *value == 4242.0
                    && labels.iter().any(|(k, v)| k == "slot_id" && v == "default"))
        });
        assert!(found, "expected gauge for index 2, got {calls:?}");
    }

    #[test]
    fn out_of_range_index_is_skipped_without_panic() {
        // Index 9 against a 3-element counter array must be silently skipped.
        let table = StatsMetrics::from_pairs(&[("libtorrent_absent", 9)]);
        let calls = run(&table, vec![1, 2, 3]);
        assert!(
            calls.is_empty(),
            "no gauge should be emitted, got {calls:?}"
        );
    }
}
