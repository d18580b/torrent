//! `GET /healthz` — readiness probe for systemd / load balancers.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::app_state::AppState;

pub async fn healthz(State(s): State<AppState>) -> impl IntoResponse {
    let n_slots = s.source.slots().len();
    if n_slots == 0 {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"ok": false}))).into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true, "slots": n_slots}))).into_response()
}
