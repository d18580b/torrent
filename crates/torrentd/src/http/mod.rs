//! axum HTTP control plane.

mod auth_routes;
mod events;
#[cfg(feature = "fault-injection")]
pub(crate) mod fault_injection;
pub mod forwarded;
mod healthz;
mod metrics;
mod pool;
mod profiles;
mod reload;
mod status;
pub(crate) mod torrents;

use axum::routing::get;
use axum::routing::post;
use axum::Router;

use crate::app_state::AppState;

/// Build the full router.
///
/// Everything is served under `/api`, and only under `/api`.
///
/// The bare paths used to be mounted a second time as "back-compat aliases".
/// There was nothing to be compatible with — the daemon has never been
/// released — so every route existed twice, under two gates, and any spec
/// describing this surface would have had to describe both. Probes and scrapes
/// keep their root paths (`/healthz`, `/metrics`) because those genuinely are
/// conventional locations.
///
/// Pool routes are mounted only when `[pool]` is configured, so an
/// unconfigured daemon returns 404 rather than a confusing empty success.
pub fn router(state: AppState) -> Router {
    let mut api = Router::new()
        .route("/status", get(status::status))
        // Live change notifications for the web client.
        .route("/events", get(events::events))
        .route("/reload", post(reload::trigger))
        .route("/torrents", get(torrents::list).post(torrents::add))
        .route(
            "/torrents/:infohash",
            get(torrents::get).delete(torrents::remove),
        )
        .route("/torrents/:infohash/pause", post(torrents::pause))
        .route("/torrents/:infohash/resume", post(torrents::resume))
        .route("/torrents/:infohash/recheck", post(torrents::recheck))
        .route("/torrents/:infohash/reannounce", post(torrents::reannounce))
        .route(
            "/torrents/:infohash/upload-limit",
            post(torrents::set_upload_limit),
        )
        .route(
            "/torrents/:infohash/file-priority",
            post(torrents::set_file_priority),
        );

    // Always mounted: a daemon always has at least one profile.
    {
        api = api
            // Daemon-wide: every live profile at once, for an incident.
            .route("/pause-all", post(profiles::pause_everything))
            .route("/resume-all", post(profiles::resume_everything))
            .route("/profiles", get(profiles::list))
            .route("/profiles/:profile_id", get(profiles::get))
            .route("/profiles/:profile_id/torrents", get(profiles::torrents))
            .route("/profiles/:profile_id/pause-all", post(profiles::pause_all))
            .route(
                "/profiles/:profile_id/resume-all",
                post(profiles::resume_all),
            );
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

    // The alert drill's fault injection. Only a `fault-injection` build has
    // it, and it sits behind the same write credential as everything below.
    #[cfg(feature = "fault-injection")]
    {
        api = api.route("/fault", post(fault_injection::inject));
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
        .nest("/api", api)
        .layer(axum::extract::DefaultBodyLimit::max(
            torrents::MAX_BODY_BYTES,
        ));

    router.with_state(state)
}
