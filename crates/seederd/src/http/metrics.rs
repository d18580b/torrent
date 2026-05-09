//! `GET /metrics` — Prometheus text format.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::app_state::AppState;

pub async fn metrics(State(s): State<AppState>) -> impl IntoResponse {
    let body = s.metrics.render();
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}
