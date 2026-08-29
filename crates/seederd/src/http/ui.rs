//! Serving the embedded web client.
//!
//! The bundle is compiled into the binary so a deployment is one artifact. It
//! is mounted last, under a catch-all, so it can never shadow an API route:
//! anything the router already matched wins, and only unmatched paths fall
//! through to here.

use axum::http::header;
use axum::http::StatusCode;
use axum::http::Uri;
use axum::response::IntoResponse;
use axum::response::Response;

#[derive(rust_embed::Embed)]
#[folder = "../../web/dist"]
struct Assets;

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    // A single-page app owns its own routing, so an unknown path is not a 404 —
    // it is a deep link the client will resolve. Only asset-looking requests
    // get a real 404, so a mistyped script URL fails loudly instead of being
    // answered with HTML.
    let candidate = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = Assets::get(candidate) {
        let mime = mime_guess::from_path(candidate).first_or_octet_stream();
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime.as_ref()),
                // Vite fingerprints asset filenames, so they are safe to cache
                // hard; index.html must not be, or an upgraded daemon keeps
                // serving the previous app.
                (
                    header::CACHE_CONTROL,
                    if candidate.starts_with("assets/") {
                        "public, max-age=31536000, immutable"
                    } else {
                        "no-cache"
                    },
                ),
            ],
            file.data,
        )
            .into_response();
    }

    if candidate.contains('.') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    match Assets::get("index.html") {
        Some(index) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            index.data,
        )
            .into_response(),
        // Built with the feature on but no bundle present: say so plainly
        // rather than serving a blank page.
        None => (
            StatusCode::NOT_FOUND,
            "the web client was not embedded in this build",
        )
            .into_response(),
    }
}
