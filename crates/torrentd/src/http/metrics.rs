//! `GET /metrics` — Prometheus text format.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use torrentd_engine::MetricsSink;

use crate::app_state::AppState;

pub async fn metrics(State(s): State<AppState>) -> impl IntoResponse {
    // Computed here rather than by a ticking task: a task could itself stall,
    // and the age read at scrape time is exactly the one `/healthz` would
    // report at that moment.
    s.metrics.set_gauge(
        "alert_loop_heartbeat_age_seconds",
        torrentd_engine::heartbeat_age(&s.alert_heartbeat).as_secs_f64(),
        &[],
    );
    let body = s.metrics.render();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}
