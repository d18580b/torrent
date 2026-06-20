//! axum HTTP control plane.

mod healthz;
mod metrics;
mod slots;
mod status;
pub(crate) mod torrents;

use axum::routing::{get, post};
use axum::Router;

use crate::app_state::AppState;

/// Build the full router. Slot-specific endpoints are mounted only when the
/// daemon runs in multi-slot mode (`AppState::slots` is `Some`).
pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz::healthz))
        .route("/status", get(status::status))
        .route("/torrents", get(torrents::list).post(torrents::add))
        .route("/torrents/:infohash", get(torrents::get).delete(torrents::remove))
        .route("/torrents/:infohash/pause", post(torrents::pause))
        .route("/torrents/:infohash/resume", post(torrents::resume))
        .route("/metrics", get(metrics::metrics));

    if state.slots.is_some() {
        router = router
            .route("/slots", get(slots::list))
            .route("/slots/:slot_id", get(slots::get))
            .route("/slots/:slot_id/torrents", get(slots::torrents))
            .route("/slots/:slot_id/pause-all", post(slots::pause_all))
            .route("/slots/:slot_id/resume-all", post(slots::resume_all));
    }

    router
        .layer(axum::extract::DefaultBodyLimit::max(torrents::MAX_BODY_BYTES))
        .with_state(state)
}
