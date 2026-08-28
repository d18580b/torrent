//! axum HTTP control plane.

mod healthz;
mod metrics;
mod pool;
mod slots;
mod status;
pub(crate) mod torrents;

use axum::routing::get;
use axum::routing::post;
use axum::Router;

use crate::app_state::AppState;

/// Build the full router.
///
/// Everything is served under `/api`, with the historical bare paths kept as
/// aliases so deployed scripts and scrapes keep working. Slot and pool routes
/// are mounted only when those features are configured, so an unconfigured
/// daemon returns 404 for them rather than a confusing empty success.
pub fn router(state: AppState) -> Router {
    let mut api = Router::new()
        .route("/status", get(status::status))
        .route("/torrents", get(torrents::list).post(torrents::add))
        .route(
            "/torrents/:infohash",
            get(torrents::get).delete(torrents::remove),
        )
        .route("/torrents/:infohash/pause", post(torrents::pause))
        .route("/torrents/:infohash/resume", post(torrents::resume))
        .route(
            "/torrents/:infohash/upload-limit",
            post(torrents::set_upload_limit),
        )
        .route(
            "/torrents/:infohash/file-priority",
            post(torrents::set_file_priority),
        );

    if state.slots.is_some() {
        api = api
            .route("/slots", get(slots::list))
            .route("/slots/:slot_id", get(slots::get))
            .route("/slots/:slot_id/torrents", get(slots::torrents))
            .route("/slots/:slot_id/pause-all", post(slots::pause_all))
            .route("/slots/:slot_id/resume-all", post(slots::resume_all));
    }

    if state.pool.is_some() {
        api = api
            .route("/pool", get(pool::overview))
            .route("/pool/tree", get(pool::tree))
            .route("/pool/torrents", get(pool::torrents))
            .route("/pool/orphans", get(pool::orphans))
            .route("/pool/drift", get(pool::drift))
            .route("/pool/scan", post(pool::scan))
            .route("/pool/adopt", post(pool::adopt))
            .route("/pool/verify", post(pool::verify));
    }

    Router::new()
        // Health and metrics stay at the root: probes and scrapes are
        // configured once and should not have to move.
        .route("/healthz", get(healthz::healthz))
        .route("/metrics", get(metrics::metrics))
        .nest("/api", api.clone())
        // Back-compat: the pre-/api paths, same handlers.
        .merge(api)
        .layer(axum::extract::DefaultBodyLimit::max(
            torrents::MAX_BODY_BYTES,
        ))
        .with_state(state)
}
