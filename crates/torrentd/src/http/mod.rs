//! axum HTTP control plane.

mod auth_routes;
mod events;
mod healthz;
mod metrics;
mod pool;
mod slots;
mod status;
pub(crate) mod torrents;
#[cfg(feature = "web-ui")]
mod ui;

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
        // Live change notifications for the web client.
        .route("/events", get(events::events))
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
            .route("/pool/verify", post(pool::verify))
            .route("/pool/plans", get(pool::list_plans).post(pool::create_plan))
            .route(
                "/pool/plans/:id",
                get(pool::get_plan).delete(pool::delete_plan),
            )
            .route("/pool/plans/:id/apply", post(pool::apply_plan));
    }

    // Everything in `api` requires a credential; read for safe methods, write
    // for anything that changes state.
    let api = api.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_routes::require_api,
    ));

    // Scraping is gated separately so a Prometheus credential can never reach
    // the control plane.
    let metrics = Router::new()
        .route("/metrics", get(metrics::metrics))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_routes::require_metrics,
        ));

    let router = Router::new()
        // /healthz is deliberately unauthenticated: it carries no data beyond
        // liveness, and a probe that needs a credential is a probe that breaks
        // during the incident it exists to detect.
        .route("/healthz", get(healthz::healthz))
        .merge(metrics)
        // Login must sit outside the gate, or nobody can ever get in.
        .route("/api/login", post(auth_routes::login))
        .route("/api/logout", post(auth_routes::logout))
        .nest("/api", api.clone())
        // Back-compat: the pre-/api paths, same handlers and same gate.
        .merge(api)
        .layer(axum::extract::DefaultBodyLimit::max(
            torrents::MAX_BODY_BYTES,
        ));

    // The UI goes last, as a fallback, so it can never shadow an API route.
    // It is served unauthenticated on purpose: it is a static bundle with no
    // data in it, and it has to load in order to present the login form.
    #[cfg(feature = "web-ui")]
    let router = router.fallback(ui::serve);

    router.with_state(state)
}
