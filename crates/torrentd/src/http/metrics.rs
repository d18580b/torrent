//! `GET /metrics` — Prometheus text format.

use std::sync::Arc;

use kynos::extract::body::binary::Binary;
use kynos::extract::media::MediaType;
use kynos::prelude::*;
use kynos::security::auth::Scoped;
use torrentd_engine::MetricsSink;

use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Metrics;
use crate::http::v1::Operations;

/// The Prometheus text exposition format, version 0.0.4.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrometheusText;

impl MediaType for PrometheusText {
    const MEDIA_TYPE: &'static str = "text/plain; version=0.0.4";
}

/// Scrape the daemon's metrics.
///
/// Prometheus text format. Needs the `metrics` scope, which no other
/// operation accepts and no session token carries, so a scrape credential can
/// never reach the control plane. `deploy/metrics.md` catalogues every
/// series.
#[kynos::get("/metrics", tag = Operations)]
pub async fn get_metrics(
    _caller: Scoped<Bearer, Metrics>,
    Inject(s): Inject<Arc<AppState>>,
) -> Binary<PrometheusText> {
    // Computed here rather than by a ticking task: a task could itself stall,
    // and the age read at scrape time is exactly the one `/healthz` would
    // report at that moment.
    s.metrics.set_gauge(
        "alert_loop_heartbeat_age_seconds",
        torrentd_engine::heartbeat_age(&s.alert_heartbeat).as_secs_f64(),
        &[],
    );
    Binary::new(s.metrics.render())
}
