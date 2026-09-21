//! Login, logout, and the middleware that gates everything else.

use axum::extract::Request;
use axum::extract::State;
use axum::http::header;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde::Serialize;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::auth::Scope;
use crate::auth::SESSION_COOKIE;

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    ok: bool,
    /// Seconds until the session expires, so a client can refresh in time.
    expires_in: u64,
}

/// The 409 body, as an API client reads it.
///
/// Broken with `\` continuations rather than left as a bare multi-line
/// literal: without them every line's indentation is *in* the string, and
/// `web/src/lib/api.ts` lifts `body.error` verbatim into the banner an
/// operator sees.
const NO_AUTHENTICATION_CONFIGURED: &str = "this daemon runs without authentication \
     (allow_unauthenticated = true). There is no session to create; access control belongs \
     to whatever sits in front of it. Configure [auth] to log in here.";

pub async fn login(State(s): State<AppState>, req: Request) -> Response {
    // Resolved before the body is consumed, and before the `[auth]` check, so
    // the throttle and the log line have it on every path.
    let client = crate::http::forwarded::resolve(&req, &s.trusted_proxies);

    let Some(auth) = s.auth.as_ref() else {
        // 404 read as "no such route", which is false: the route exists, and
        // the daemon is running in a posture where logging in is not a thing
        // that happens. 409 says that, and this is an API contract for
        // external clients rather than a fix for anything the shipped web
        // client can surface — with `auth: None` the status probe succeeds,
        // `App.tsx` never sets `authed = false`, and the login form is never
        // rendered. A client that offers no login when the daemon
        // authenticates nothing is behaving correctly; this status code is for
        // whoever posts here anyway.
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": NO_AUTHENTICATION_CONFIGURED })),
        )
            .into_response();
    };

    // Argon2id costs ~50 ms of CPU on purpose. Unthrottled, an unauthenticated
    // caller can spend the whole machine's CPU on password verification.
    if let Some(wait) = auth.throttle.retry_after(client.ip) {
        warn!(
            target: "torrentd::auth",
            client_ip = client.ip.map(|i| i.to_string()).unwrap_or_default(),
            retry_after_secs = wait.as_secs(),
            "login throttled after repeated failures",
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", wait.as_secs().max(1).to_string())],
            Json(serde_json::json!({"error": "too many failed attempts; try again shortly"})),
        )
            .into_response();
    }

    let body = match axum::body::to_bytes(req.into_body(), MAX_LOGIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "malformed request body"})),
            )
                .into_response()
        }
    };
    let Ok(login_req) = serde_json::from_slice::<LoginRequest>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "expected {\"password\": \"…\"}"})),
        )
            .into_response();
    };

    if !auth.verify_password(&login_req.password) {
        auth.throttle.note_failure(client.ip);
        // No detail about which part was wrong, and no username to enumerate.
        // The source address is logged, which it never was: a brute-force
        // attempt left no trace of where it came from, so the proxy's log was
        // the only record that it had happened at all.
        warn!(
            target: "torrentd::auth",
            client_ip = client.ip.map(|i| i.to_string()).unwrap_or_default(),
            "failed login attempt",
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid password"})),
        )
            .into_response();
    }
    auth.throttle.note_success(client.ip);

    let id = auth.sessions.create();
    let ttl = auth.config.session_ttl_secs;
    info!(
        target: "torrentd::auth",
        client_ip = client.ip.map(|i| i.to_string()).unwrap_or_default(),
        "operator logged in",
    );

    // HttpOnly keeps the cookie away from page scripts; SameSite=Strict means a
    // cross-site request cannot carry it, which is the CSRF defence for a
    // cookie-authenticated mutating API.
    //
    // `Secure` is set when the *original* request was over TLS, which is only
    // knowable from a trusted proxy. It used to be omitted unconditionally, on
    // the grounds that the daemon speaks plain HTTP and a Secure cookie would
    // break `http://localhost` — true, and it also meant that a deployment
    // fronted by TLS handed out a cookie the browser would send in clear to
    // any plain-HTTP origin on that host. Now loopback still gets a usable
    // cookie and a TLS-fronted deployment gets a protected one.
    let secure = if client.secure { "; Secure" } else { "" };
    let cookie =
        format!("{SESSION_COOKIE}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            ok: true,
            expires_in: ttl,
        }),
    )
        .into_response()
}

/// A login body is one short JSON object; anything larger is not one.
const MAX_LOGIN_BODY_BYTES: usize = 8 * 1024;

pub async fn logout(State(s): State<AppState>, req: Request) -> Response {
    if let Some(auth) = s.auth.as_ref() {
        if let Some(id) = session_cookie(&req) {
            auth.sessions.revoke(&id);
        }
    }
    let cleared = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cleared)]).into_response()
}

/// Whether the caller holds `needed`.
fn authorized(state: &AppState, req: &Request, needed: Scope) -> bool {
    let Some(auth) = state.auth.as_ref() else {
        // No `[auth]` section: the daemon keeps its original posture, where
        // access control is the operator's reverse proxy.
        return true;
    };

    // A browser session is always full access: it is the operator.
    if let Some(id) = session_cookie(req) {
        if auth.sessions.is_valid(&id) {
            return true;
        }
    }

    if let Some(token) = bearer_token(req) {
        if let Some((name, scopes)) = auth.token_scopes(&token) {
            if scopes.iter().any(|s| s.allows(needed)) {
                return true;
            }
            warn!(
                target: "torrentd::auth",
                token_name = %name,
                "token presented without the required scope",
            );
        }
    }
    false
}

/// Gate the API. Read-only methods need `read`; anything that changes state
/// needs `write`.
pub async fn require_api(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let needed = if req.method().is_safe() {
        Scope::Read
    } else {
        Scope::Write
    };
    if !authorized(&s, &req, needed) {
        return unauthorized();
    }
    next.run(req).await
}

/// Gate `/metrics` separately, so a scrape credential never reaches the API.
pub async fn require_metrics(State(s): State<AppState>, req: Request, next: Next) -> Response {
    if !authorized(&s, &req, Scope::Metrics) {
        return unauthorized();
    }
    next.run(req).await
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(serde_json::json!({"error": "authentication required"})),
    )
        .into_response()
}

fn session_cookie(req: &Request) -> Option<String> {
    let raw = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn bearer_token(req: &Request) -> Option<String> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    // Scheme is case-insensitive per RFC 7235.
    let (scheme, value) = raw.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| value.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    use super::*;

    fn req_with(header_name: header::HeaderName, value: &str) -> Request {
        HttpRequest::builder()
            .header(header_name, value)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn the_409_body_is_one_paragraph_of_prose() {
        // It ships to a human: `api.ts` lifts `body.error` into the thrown
        // Error and `Login.tsx` renders it into the banner. A multi-line
        // literal without `\` continuations puts its own source indentation in
        // the string, which is how this one came to contain three runs of 27
        // spaces in the exact diagnostic it exists to improve.
        assert!(
            !NO_AUTHENTICATION_CONFIGURED.contains("  "),
            "no run of consecutive spaces: {NO_AUTHENTICATION_CONFIGURED:?}",
        );
        assert!(!NO_AUTHENTICATION_CONFIGURED.contains('\n'));
        assert!(NO_AUTHENTICATION_CONFIGURED.contains("allow_unauthenticated"));
        assert!(
            NO_AUTHENTICATION_CONFIGURED.contains("[auth]"),
            "it names the way out",
        );
    }

    #[test]
    fn session_cookie_is_found_among_others() {
        let r = req_with(
            header::COOKIE,
            &format!("theme=dark; {SESSION_COOKIE}=abc123; other=1"),
        );
        assert_eq!(session_cookie(&r).as_deref(), Some("abc123"));
    }

    #[test]
    fn an_empty_or_absent_session_cookie_is_none() {
        assert_eq!(
            session_cookie(&req_with(header::COOKIE, &format!("{SESSION_COOKIE}="))),
            None,
        );
        assert_eq!(session_cookie(&req_with(header::COOKIE, "other=1")), None);
        assert_eq!(
            session_cookie(&HttpRequest::builder().body(Body::empty()).unwrap()),
            None,
        );
    }

    #[test]
    fn a_cookie_named_like_a_prefix_is_not_mistaken_for_the_session() {
        // `torrentd_session_backup=` must not satisfy `torrentd_session=`.
        let r = req_with(header::COOKIE, &format!("{SESSION_COOKIE}_backup=nope"));
        assert_eq!(session_cookie(&r), None);
    }

    #[test]
    fn bearer_tokens_parse_case_insensitively() {
        assert_eq!(
            bearer_token(&req_with(header::AUTHORIZATION, "Bearer abc")).as_deref(),
            Some("abc"),
        );
        assert_eq!(
            bearer_token(&req_with(header::AUTHORIZATION, "bearer abc")).as_deref(),
            Some("abc"),
        );
        assert_eq!(
            bearer_token(&req_with(header::AUTHORIZATION, "BEARER abc")).as_deref(),
            Some("abc"),
        );
    }

    #[test]
    fn non_bearer_schemes_are_ignored() {
        assert_eq!(
            bearer_token(&req_with(header::AUTHORIZATION, "Basic abc")),
            None
        );
        assert_eq!(
            bearer_token(&req_with(header::AUTHORIZATION, "Bearer")),
            None
        );
        assert_eq!(
            bearer_token(&req_with(header::AUTHORIZATION, "Bearer  ")),
            None
        );
    }
}
