//! The HTTP control plane, served by kynos.
//!
//! The API lives under `/v1`; the readiness probe and the Prometheus scrape
//! keep their conventional root paths. Every route — those two included — is
//! described in one OpenAPI 3.2 document derived from the handlers and their
//! types, published at `GET /v1/openapi.json` and committed at
//! `docs/api/openapi.json`, where CI fails if it goes stale.

pub mod ctx;
#[cfg(feature = "fault-injection")]
pub(crate) mod fault_injection;
pub mod forwarded;
mod headers;
mod healthz;
mod metrics;
pub(crate) mod page;
pub mod security;
pub mod v1;
pub(crate) mod validate;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use kynos::extract::body::binary::Binary;
use kynos::extract::media;
use kynos::openapi::Document;
use kynos::openapi::ExternalDocumentation;
use kynos::openapi::Info;
use kynos::openapi::License;
use kynos::prelude::*;
use kynos::router::policy::FallbackPolicy;
use kynos::router::policy::TrailingSlashPolicy;

use crate::http::ctx::AppCtx;
use crate::http::v1::Operations;

/// The published document, rendered once at startup and served verbatim.
#[derive(Clone)]
pub struct OpenApiJson(pub Arc<bytes::Bytes>);

/// Fetch this API's OpenAPI document.
///
/// OpenAPI 3.2 (Server-Sent Events need its `itemSchema`), derived from the
/// handlers and types the daemon runs, so it cannot drift from them. It needs
/// no credential: it describes the contract, not this daemon's state.
#[kynos::get("/v1/openapi.json", tag = Operations)]
pub async fn get_openapi(Inject(doc): Inject<OpenApiJson>) -> Binary<media::Json> {
    Binary::new(bytes::Bytes::clone(&doc.0))
}

/// Every route the daemon serves, as one router.
///
/// A macro rather than a function: each group and interceptor changes the
/// router's type, and the two consumers — the running service and the
/// document — each need the whole of it.
macro_rules! daemon_router {
    () => {{
        let router = Router::<AppCtx>::new()
            .info(info())
            // On the router rather than a group, so every routed response —
            // the root routes included — carries them, and one id source
            // serves every request. kynos answers an unknown path or method
            // before any interceptor runs, so those 404/405s carry neither.
            .intercept(
                kynos::middleware::request_id::RequestId::new()
                    .source(crate::http::headers::RandomRequestId),
            )
            .intercept(crate::http::headers::ApiHeaders)
            // One event per request at each end, the closing one carrying the
            // status, the latency and the request id: the line an operator
            // quoting `X-Request-Id` is looking for.
            .observe(
                kynos::middleware::trace::Trace::new()
                    .correlating::<kynos::middleware::request_id::XRequestId>(),
            )
            .not_found(FallbackPolicy::Problem)
            .method_not_allowed(FallbackPolicy::Problem)
            .trailing_slashes(TrailingSlashPolicy::Strict)
            .mount(kynos::routes![
                healthz::get_health,
                metrics::get_metrics,
                get_openapi
            ]);
        crate::http::v1::mount!(router)
    }};
}

/// The running service for `state`, serving `openapi` at
/// `GET /v1/openapi.json`.
pub fn service(
    state: crate::app_state::AppState,
    openapi: OpenApiJson,
) -> kynos::Result<kynos::router::service::Service<AppCtx>> {
    daemon_router!().build(AppCtx::new(state, openapi))
}

/// The published document, with the document-level members kynos has no
/// setter for.
pub fn document() -> kynos::Result<Document> {
    let mut doc = daemon_router!().openapi()?;
    doc.external_docs = Some(ExternalDocumentation::new(
        "https://github.com/d18580b/torrent/blob/master/docs/api/README.md",
    ));
    // No document-level `security`: every operation declares its own, and a
    // default would be inherited by the three that need no credential
    // (`/healthz`, this document, `POST /v1/sessions`).
    Ok(doc)
}

/// The document as the bytes `docs/api/openapi.json` holds: pretty-printed,
/// with a trailing newline.
pub fn document_json() -> anyhow::Result<String> {
    let doc = document().map_err(|e| anyhow::anyhow!("describe the API: {e}"))?;
    let mut json = serde_json::to_string_pretty(&doc)?;
    json.push('\n');
    Ok(json)
}

fn info() -> Info {
    Info::new("torrentd", "1.0.0")
        .with_summary("Control plane of a headless, multi-account torrent seeding daemon.")
        .with_description(
            "The `/v1` HTTP API of `torrentd`. Conventions — authentication, pagination, \
             errors, and what may change within v1 — are in `docs/api/README.md`; every \
             problem `type` URI resolves to a heading in `docs/api/problems.md`.",
        )
        .with_license(License::spdx("Apache-2.0", "Apache-2.0"))
}
