//! `POST /api/reload` — re-read the config file, as SIGHUP does.
//!
//! This is the whole of the daemon's runtime-configuration surface, and it is
//! deliberately the whole of it. Several keys *are* reloadable — `log_level`,
//! `upload_rate_limit`, `connections_limit`, `aio_threads`, `enable_lsd`,
//! `max_concurrent_http_announces` — and every one of them belongs to the TOML
//! file. Giving each a setter would make the file and the running daemon
//! disagree the moment anyone used one, and nothing would record which had
//! won.
//!
//! Two of those keys do not reach every session, and this list read as though
//! they did: `enable_lsd` is withheld from every `network = "vpn"` profile
//! (Safety Rule 6 admits no config key there, so a reload cannot be the
//! exception), and `upload_rate_limit` is withheld from a profile that sets
//! its own. See `reload.rs` and `ConfigDiff::to_settings_patch_for`.
//!
//! So a client can ask the daemon to re-read its configuration; it cannot tell
//! the daemon what its configuration is. The file stays the single source of
//! truth, and an operator who wants a change edits it and calls this.
//!
//! Before this, the only way to reload was a signal, which meant shell access
//! on the host — so the web client could not do it at all, and neither could
//! anything holding a `write` token.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use tracing::info;

use crate::app_state::AppState;

pub async fn trigger(
    State(s): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let Some(tx) = s.reload_tx.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "reload is not wired up in this build"})),
        ));
    };
    // The reload pump owns the outcome: it re-reads the file, applies what is
    // reloadable, and warns about what is not. Reporting *here* would mean
    // either blocking on that or inventing a result, so this reports only that
    // the request was accepted — the same contract SIGHUP has.
    match tx.try_send(()) {
        Ok(()) => {
            info!(target: "torrentd::http::reload", "reload requested over the API");
            Ok(StatusCode::ACCEPTED)
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "a reload is already queued"})),
        )),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "the reload task is not running"})),
        )),
    }
}
