//! Session tokens: exchanging the operator password for a bearer token, and
//! giving it back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use kynos::di::Provides;
use kynos::extract::connection::ConnectInfo;
use kynos::extract::describe::Describe;
use kynos::extract::FromRequestParts;
use kynos::http::Parts;
use kynos::prelude::*;
use kynos::response::headers::WithHeaders;
use kynos::router::operation::OperationCx;
use kynos::security::auth::Scoped;
use kynos::HeaderParams;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::MetricsSink;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::auth::Scope;
use crate::http::forwarded::Client;
use crate::http::security::Bearer;
use crate::http::security::Caller;
use crate::http::security::Read;
use crate::http::v1::Sessions;

/// The operator password, exchanged for a session token.
#[derive(Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct CreateSession {
    /// The operator password `[auth] password_hash` was made from.
    pub password: String,
}

/// A newly issued session token.
#[derive(Debug, Schema, Serialize)]
pub struct SessionGrant {
    /// The bearer token (`tds_…`). Send it as `Authorization: Bearer <token>`.
    /// It is shown once: the daemon keeps only its hash.
    pub token: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// What the token may do: `read` and `write`, never `metrics`.
    pub scopes: Vec<Scope>,
    /// When the token stops working, unless revoked sooner.
    pub expires_at: jiff::Timestamp,
}

/// Who the presented credential is.
#[derive(Debug, Schema, Serialize)]
pub struct Principal {
    /// `session` for a token from `POST /v1/sessions`, `token` for a static
    /// token from the config, `anonymous` when authentication is disabled.
    pub kind: PrincipalKind,
    /// The static token's configured name; `null` for any other kind.
    pub name: Option<String>,
    /// What the credential may do.
    pub scopes: Vec<Scope>,
    /// When a session token expires; `null` for any other kind.
    pub expires_at: Option<jiff::Timestamp>,
}

/// What kind of credential authenticated a request.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A session token from `POST /v1/sessions`.
    Session,
    /// A static token from the config's `[[auth.token]]`.
    Token,
    /// No credential: the daemon runs with authentication disabled.
    Anonymous,
}

/// `Retry-After`, on a throttled request.
#[derive(HeaderParams)]
pub struct RetryAfter {
    /// Seconds to wait before trying again. Sent only with
    /// `429 login-throttled`.
    #[header(rename = "Retry-After")]
    retry_after: Option<u64>,
}

/// Why a session was not issued.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum CreateSessionError {
    /// The password is wrong. Which part is never said.
    #[error("invalid password")]
    #[problem(status = 401, title = "Invalid credentials")]
    InvalidCredentials,
    /// The daemon runs with `allow_unauthenticated`; there is no session to
    /// create.
    #[error(
        "this daemon runs without authentication (allow_unauthenticated = true). There is no \
         session to create; access control belongs to whatever sits in front of it. Configure \
         [auth] to log in here."
    )]
    #[problem(status = 409, title = "Authentication is not configured")]
    AuthNotConfigured,
    /// Too many failed attempts from this client, or the daemon-wide
    /// password-verification budget is spent.
    #[error("{detail}")]
    #[problem(status = 429, title = "Too many login attempts")]
    LoginThrottled {
        detail: &'static str,
        /// Seconds until another attempt is admitted; also in `Retry-After`.
        #[problem(extension)]
        retry_after_secs: u64,
    },
}

/// The client behind a request, as far as `trusted_proxies` lets the daemon
/// know it. Not a parameter: the headers it reads are the proxy's, and a
/// client that sets them itself is ignored.
pub struct ClientAddr(pub Client);

impl<C: Provides<Arc<AppState>> + Sync> FromRequestParts<C> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, context: &C) -> Result<Self, Self::Rejection> {
        let ConnectInfo(peer): ConnectInfo =
            ConnectInfo::from_request_parts(parts, context).await?;
        let state = context.provide();
        Ok(Self(crate::http::forwarded::resolve(
            Some::<SocketAddr>(peer),
            &parts.headers,
            &state.trusted_proxies,
        )))
    }
}

impl Describe for ClientAddr {
    fn describe(operation: &mut OperationCx<'_>) {
        let _ = operation;
    }
}

/// Exchange the operator password for a session token.
///
/// The token carries `read` and `write` and expires after
/// `[auth] session_ttl_secs` (`GET /v1/server` reports it). Failed attempts
/// are throttled per client, and every attempt spends from one daemon-wide
/// budget for the memory-hard password hash; either limit answers
/// `429 login-throttled` with `Retry-After`.
#[kynos::post("/sessions", tag = Sessions)]
pub async fn create_session(
    Inject(s): Inject<Arc<AppState>>,
    ClientAddr(client): ClientAddr,
    Json(body): Json<CreateSession>,
) -> Result<Created<Json<SessionGrant>>, WithHeaders<CreateSessionError, RetryAfter>> {
    let plain = |e| WithHeaders::new(e, RetryAfter { retry_after: None });
    let Some(auth) = s.auth.as_ref() else {
        return Err(plain(CreateSessionError::AuthNotConfigured));
    };
    let client_ip = client.ip.map(|i| i.to_string()).unwrap_or_default();
    let refused = |reason: &str| {
        s.metrics
            .inc_counter("auth_login_failures_total", &[("reason", reason)]);
    };
    let throttled = |detail: &'static str, wait: std::time::Duration| {
        let secs = wait.as_secs().max(1);
        WithHeaders::new(
            CreateSessionError::LoginThrottled {
                detail,
                retry_after_secs: secs,
            },
            RetryAfter {
                retry_after: Some(secs),
            },
        )
    };

    // Argon2id costs ~50 ms of CPU on purpose. Unthrottled, an
    // unauthenticated caller can spend the whole machine's CPU on password
    // verification. kynos has already refused any body that is not a
    // well-formed `CreateSession`, and any body that took longer than
    // `REQUEST_DEADLINE` to arrive, so nothing malformed reaches this.
    if let Some(wait) = auth.throttle.retry_after(client.ip) {
        warn!(
            target: "torrentd::auth",
            client_ip,
            retry_after_secs = wait.as_secs(),
            "login throttled after repeated failures",
        );
        refused("throttled");
        return Err(throttled(
            "too many failed attempts; try again shortly",
            wait,
        ));
    }

    // The daemon-wide ceiling, spent only by a request that is about to run
    // the KDF. The per-client consult above cannot bound this on its own:
    // every address a caller holds brings a bucket of its own, so without
    // one shared budget the Argon2 rate — and the guessing rate — scale with
    // the number of addresses. See `LoginThrottle`.
    if let Err(wait) = auth.throttle.admit_verification() {
        warn!(
            target: "torrentd::auth",
            client_ip,
            retry_after_secs = wait.as_secs(),
            "login refused: daemon-wide password verification budget spent",
        );
        refused("verification_budget");
        return Err(throttled(
            "too many login attempts; try again shortly",
            wait,
        ));
    }

    // ~50 ms of deliberate CPU per call: run on the blocking pool, not on an
    // async worker, so a burst of logins cannot stall every other request the
    // runtime is serving. A join failure (the KDF panicked) never
    // authenticates.
    let verifier = auth.clone();
    let verified = tokio::task::spawn_blocking(move || verifier.verify_password(&body.password))
        .await
        .unwrap_or_else(|e| {
            warn!(
                target: "torrentd::auth",
                client_ip,
                error.cause = %e,
                "password verification task failed",
            );
            false
        });
    if !verified {
        auth.throttle.note_failure(client.ip);
        // No detail about which part was wrong, and no username to enumerate.
        warn!(target: "torrentd::auth", client_ip, "failed login attempt");
        refused("bad_password");
        return Err(plain(CreateSessionError::InvalidCredentials));
    }
    auth.throttle.note_success(client.ip);

    let (token, expires_at) = auth.sessions.create();
    info!(
        target: "torrentd::auth",
        client_ip,
        via_https = client.secure,
        "session issued",
    );
    Ok(Created::at(
        // `relative_uri` knows the route, not the group it is mounted under.
        format!(
            "{}{}",
            crate::http::v1::PREFIX,
            get_current_session::relative_uri()
        ),
        Json(SessionGrant {
            token,
            token_type: "Bearer".to_owned(),
            scopes: vec![Scope::Read, Scope::Write],
            expires_at: timestamp(expires_at),
        }),
    ))
}

/// Describe the presented credential.
///
/// What kind of credential it is, what it may do, and when a session token
/// expires. Useful to check a token without side effects.
#[kynos::get("/sessions/current", tag = Sessions)]
pub async fn get_current_session(caller: Scoped<Bearer, Read>) -> Json<Principal> {
    let principal = caller.into_inner();
    let scopes = principal.scopes();
    Json(match principal {
        Caller::Anonymous => Principal {
            kind: PrincipalKind::Anonymous,
            name: None,
            scopes,
            expires_at: None,
        },
        Caller::Session { expires_at, .. } => Principal {
            kind: PrincipalKind::Session,
            name: None,
            scopes,
            expires_at: Some(timestamp(expires_at)),
        },
        Caller::Token { name, .. } => Principal {
            kind: PrincipalKind::Token,
            name: Some(name),
            scopes,
            expires_at: None,
        },
    })
}

/// Why a credential could not be revoked.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum RevokeSessionError {
    /// The credential is a static token from the config (or authentication is
    /// disabled). A static token is revoked by removing it from the config and
    /// restarting the daemon: `[auth]` is read once at startup, so a reload
    /// leaves a removed token working.
    #[error(
        "only a session token can be revoked here; revoke a static token by removing it from the \
         config and restarting the daemon (a reload does not revoke it)"
    )]
    #[problem(status = 409, title = "Not a session token")]
    NotASession,
}

/// Revoke the presented session token.
///
/// Signs out: the token stops working immediately. Static tokens are not
/// sessions and answer `409 not-a-session`.
#[kynos::delete("/sessions/current", tag = Sessions)]
pub async fn delete_current_session(
    caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<NoContent, RevokeSessionError> {
    match (caller.into_inner(), s.auth.as_ref()) {
        (Caller::Session { token, .. }, Some(auth)) => {
            auth.sessions.revoke(&token);
            info!(target: "torrentd::auth", "session revoked");
            Ok(NoContent)
        }
        _ => Err(RevokeSessionError::NotASession),
    }
}

/// A wall-clock time as the API reports it.
pub(crate) fn timestamp(t: SystemTime) -> jiff::Timestamp {
    jiff::Timestamp::try_from(t).unwrap_or(jiff::Timestamp::MAX)
}

#[cfg(test)]
mod tests {
    use super::RevokeSessionError;

    /// The `not-a-session` entry in docs/api/problems.md, heading excluded,
    /// with its line wrapping collapsed to single spaces.
    fn not_a_session_entry() -> String {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/problems.md");
        let catalogue = std::fs::read_to_string(&path).unwrap();
        let (_, rest) = catalogue
            .split_once("## `not-a-session`")
            .expect("problems.md has a `not-a-session` heading");
        let entry = rest.split("\n## ").next().unwrap();
        entry.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The property: an operator told how to revoke a static token is told
    /// the step that does it. `[auth]` is not reloadable, so "remove it from
    /// the config and reload" left a leaked token working after a `202`.
    #[test]
    fn the_not_a_session_answer_sends_a_static_token_to_a_restart() {
        let detail = RevokeSessionError::NotASession.to_string();
        assert!(
            detail.contains("removing it from the config and restarting the daemon"),
            "{detail}",
        );
        assert!(detail.contains("a reload does not revoke it"), "{detail}");

        let entry = not_a_session_entry();
        assert!(
            entry.contains("remove it from the config and restart the daemon"),
            "{entry}",
        );
        assert!(
            !entry.contains("remove it from the config and reload"),
            "problems.md still says a reload revokes a static token: {entry}",
        );
    }
}
