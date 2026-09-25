//! Tracker and session warnings: counted per profile and kind, and logged.
//!
//! None of these changes what the daemon does. Each is an operational signal
//! an operator alerts on — a tracker rejecting announces, a port mapping that
//! failed, fast-resume data libtorrent threw away — and before this handler
//! the tracker error reached only a `debug!` line and the rest were never
//! translated at all.
//!
//! Two counters, both with a bounded label set: `profile_id` and a `kind` drawn
//! from the fixed lists below. No per-torrent and no per-tracker-URL label:
//! either would give every torrent a series of its own, and the URL carries
//! the passkey. Which torrent and which tracker are in the log line.

use libtorrent_safe::Alert;
use libtorrent_safe::AlertKind;
use tracing::debug;
use tracing::warn;

use crate::handlers::HandlerCtx;

/// `tracker_alerts_total{kind}`: every value this handler can emit.
pub const TRACKER_KINDS: &[&str] = &["error", "warning", "scrape_failed"];

/// `session_alerts_total{kind}`: every value this handler can emit.
pub const SESSION_KINDS: &[&str] = &[
    "portmap_error",
    "udp_error",
    "fastresume_rejected",
    "performance_warning",
];

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
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
            // journal. The counter sees every one.
            if *times_in_row <= 1 {
                warn!(
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
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;

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
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        handle(&alert, &mut ctx);
        metrics.calls()
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
