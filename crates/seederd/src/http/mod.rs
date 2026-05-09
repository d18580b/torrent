//! axum HTTP control plane.

mod healthz;
mod status;
mod torrents;
mod metrics;

use axum::Router;

use crate::app_state::AppState;

/// Build the full router. Slot-specific endpoints are mounted only when
/// the daemon runs in multi-slot mode.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(healthz::healthz))
        .route("/status",  axum::routing::get(status::status))
        .route("/torrents", axum::routing::get(torrents::list).post(torrents::add))
        .route("/torrents/:infohash", axum::routing::get(torrents::get).delete(torrents::remove))
        .route("/torrents/:infohash/pause",  axum::routing::post(torrents::pause))
        .route("/torrents/:infohash/resume", axum::routing::post(torrents::resume))
        .route("/metrics", axum::routing::get(metrics::metrics))
        .with_state(state)
    // /slots endpoints land in a follow-up; the trait surface is in
    // place but the routes are deferred to keep this commit focused.
}
