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
use crate::http::forwarded::Client;

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

    if let Err(res) = authenticate(auth, client, req).await {
        return res;
    }

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
    let cookie = session_cookie_header(&id, ttl, client);
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

/// Everything a login request must survive before a session exists: the media
/// type, the throttle, the body, and the password.
///
/// Split out from [`login`] so the order is testable. The order is the whole
/// point — `crates/torrentd` has no library target, so nothing in the suite
/// can drive the handler itself, and without a seam here the media-type gate
/// below is a claim rather than a tested property.
///
/// `Ok(())` means the caller proved the password. Every `Err` is the response
/// to send.
async fn authenticate(
    auth: &crate::auth::Auth,
    client: Client,
    req: Request,
) -> Result<(), Response> {
    // Checked first, before the throttle is consulted and before the body is
    // read at all.
    //
    // Replacing the `Json<LoginRequest>` extractor with a manual read dropped
    // this, and it was the only thing keeping the route out of reach of a
    // cross-origin page: `application/json` is not a CORS-safelisted media
    // type and `http::router` installs no CORS layer to answer a preflight,
    // so without it this route is a CORS *simple request*. An HTML
    // `<form enctype="text/plain">` can then post a body that parses as JSON,
    // which means any page the operator visits can auto-submit five of them
    // to the deployment's own origin: five ~50 ms Argon2id verifications, and
    // a 30 s lockout on the *victim's* own resolved address. That reinstates,
    // through a different door, exactly the operator lockout that keying the
    // throttle per client removed.
    //
    // `SameSite=Strict` does not cover this. It governs whether the browser
    // attaches the session cookie, and `/api/login` needs no cookie.
    if !declares_json(&req) {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(serde_json::json!({"error": "expected Content-Type: application/json"})),
        )
            .into_response());
    }

    // Argon2id costs ~50 ms of CPU on purpose. Unthrottled, an unauthenticated
    // caller can spend the whole machine's CPU on password verification.
    //
    // Consulted here, before the body is read, so a flood of malformed bodies
    // cannot reach the KDF. The price of that ordering is that this consult
    // happens for requests that never become attempts — the ones that end in
    // the 400 below — which is why `ThrottleState::retry_after` does not
    // refresh the entry's liveness. Refreshing it there made an unparseable
    // body a free way to hold a tracked-client entry alive, and a map held
    // full is a map every other client overflows out of.
    if let Some(wait) = auth.throttle.retry_after(client.ip) {
        warn!(
            target: "torrentd::auth",
            client_ip = client.ip.map(|i| i.to_string()).unwrap_or_default(),
            retry_after_secs = wait.as_secs(),
            "login throttled after repeated failures",
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", wait.as_secs().max(1).to_string())],
            Json(serde_json::json!({"error": "too many failed attempts; try again shortly"})),
        )
            .into_response());
    }

    let body = match axum::body::to_bytes(req.into_body(), MAX_LOGIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "malformed request body"})),
            )
                .into_response())
        }
    };
    let Ok(login_req) = serde_json::from_slice::<LoginRequest>(&body) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "expected {\"password\": \"…\"}"})),
        )
            .into_response());
    };

    // The daemon-wide ceiling, spent only by a request that is about to run
    // the KDF. The per-client consult above cannot bound this on its own:
    // every address a caller holds brings a bucket of its own, so without
    // one shared budget the Argon2 rate — and the guessing rate — scale with
    // the number of addresses. See `LoginThrottle`.
    if let Err(wait) = auth.throttle.admit_verification() {
        warn!(
            target: "torrentd::auth",
            client_ip = client.ip.map(|i| i.to_string()).unwrap_or_default(),
            retry_after_secs = wait.as_secs(),
            "login refused: daemon-wide password verification budget spent",
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", wait.as_secs().max(1).to_string())],
            Json(serde_json::json!({"error": "too many login attempts; try again shortly"})),
        )
            .into_response());
    }

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
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid password"})),
        )
            .into_response());
    }
    auth.throttle.note_success(client.ip);
    Ok(())
}

/// Whether the request declares a JSON body, by the rule the
/// `Json<LoginRequest>` extractor applied: `application/json`, or any
/// `application/…+json` suffix, with parameters ignored.
///
/// An absent `Content-Type` is not a declaration, so it is refused too — that
/// is also what the extractor did.
fn declares_json(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let essence = v.split(';').next().unwrap_or("").trim();
            let Some((ty, sub)) = essence.split_once('/') else {
                return false;
            };
            ty.trim().eq_ignore_ascii_case("application")
                && (sub.trim().eq_ignore_ascii_case("json")
                    || sub
                        .trim()
                        .rsplit_once('+')
                        .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json")))
        })
}

pub async fn logout(State(s): State<AppState>, req: Request) -> Response {
    if let Some(auth) = s.auth.as_ref() {
        if let Some(id) = session_cookie(&req) {
            auth.sessions.revoke(&id);
        }
    }
    // The clearing cookie carries `Secure` exactly when the login cookie
    // would have. A cookie's attributes are part of what identifies it, and
    // the pair that sets and clears one cookie describing it two different
    // ways is an asymmetry with no reason behind it. Harmless in the shipped
    // posture — RFC 6265bis's "leave secure cookies alone" rule keys on the
    // browser's own channel, which is the secure one here — and free to make
    // symmetric, since `resolve` has already been paid for on every other
    // route.
    let client = crate::http::forwarded::resolve(&req, &s.trusted_proxies);
    let cleared = session_cookie_header("", 0, client);
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cleared)]).into_response()
}

/// The `Set-Cookie` value for the session cookie.
///
/// One function builds both the cookie that creates a session and the one
/// that clears it — `id = ""` with `max_age = 0` is the clearing form — so
/// the two cannot describe the same cookie differently. They did: the login
/// cookie could carry `Secure` and the clearing cookie never could, which is
/// an asymmetry in the pair of responses that set and clear one cookie.
///
/// Harmless in the shipped posture, because RFC 6265bis's "leave secure
/// cookies alone" rule keys on the browser's own channel to the proxy, which
/// is the secure one. Free to make symmetric, and one fewer thing that has to
/// stay true by hand.
fn session_cookie_header(id: &str, max_age: u64, client: Client) -> String {
    let secure = if client.secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}")
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

    /// An `Auth` with a real Argon2id hash and a real throttle. Cheap: none
    /// of it needs the engine, the config file or a listener.
    fn test_auth() -> crate::auth::Auth {
        crate::auth::Auth::new(crate::auth::AuthConfig {
            password_hash: crate::auth::hash_password("correct-horse-battery").unwrap(),
            session_ttl_secs: 3600,
            token: vec![],
        })
    }

    fn login_req(content_type: &str, body: &str) -> Request {
        HttpRequest::builder()
            .method("POST")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn a_client() -> Client {
        Client {
            ip: Some("198.51.100.5".parse().unwrap()),
            secure: false,
        }
    }

    #[tokio::test]
    async fn a_login_that_does_not_declare_json_is_refused_before_anything_costs_anything() {
        // Two properties, and the second is the one that matters.
        //
        // 1. A body that does not declare `application/json` is refused 415.
        //    That requirement is what keeps this route out of reach of a
        //    cross-origin page: `application/json` is not CORS-safelisted and
        //    there is no CORS layer here to answer a preflight, so without it
        //    an HTML `<form enctype="text/plain">` reaches the handler.
        //
        // 2. The refusal happens before the password is verified, so
        //    `note_failure` is never called. Without it, the body below —
        //    which is exactly what such a form produces — parses as JSON,
        //    runs a ~50 ms Argon2id verification, fails, and records a
        //    failure against the *victim's* resolved address. Five of those
        //    trip the 30 s lockout, which is the operator lockout keying the
        //    throttle per client was supposed to have removed.
        let auth = test_auth();
        let client = a_client();

        for _ in 0..5 {
            let res = authenticate(
                &auth,
                client,
                login_req("text/plain", r#"{"password":"a=b"}"#),
            )
            .await
            .expect_err("a text/plain body is not a JSON login");
            assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }

        assert!(
            auth.throttle.retry_after(client.ip).is_none(),
            "five refused requests must record no failures: the media-type \
             gate runs before the password is verified, so a page that can \
             only post text/plain cannot spend this client's burst",
        );

        // The same five with the correct declaration do reach the password,
        // and do accrue — which is what shows the assertion above is about
        // the gate rather than about the throttle being inert.
        for _ in 0..5 {
            let res = authenticate(
                &auth,
                client,
                login_req("application/json", r#"{"password":"wrong"}"#),
            )
            .await
            .expect_err("a wrong password is refused");
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        assert!(
            auth.throttle.retry_after(client.ip).is_some(),
            "five declared-JSON failures do trip the lockout",
        );
    }

    #[tokio::test]
    async fn a_declared_json_login_with_the_right_password_still_succeeds() {
        // The gate refuses a media type, not a caller. The shipped web client
        // sends `application/json`, and so does every API client the docs
        // describe.
        let auth = test_auth();
        authenticate(
            &auth,
            a_client(),
            login_req(
                "application/json",
                r#"{"password":"correct-horse-battery"}"#,
            ),
        )
        .await
        .expect("the documented content type and the correct password");
    }

    #[tokio::test]
    async fn a_spent_verification_budget_refuses_before_the_password_is_checked() {
        // A fresh address passes its per-client consult, so the only thing
        // that can refuse it is the daemon-wide ceiling. Refused there, the
        // KDF never runs: the correct password is not accepted, and no
        // failure is recorded against the client.
        let mut auth = test_auth();
        auth.throttle = std::sync::Arc::new(crate::auth::LoginThrottle::with_kdf_budget(
            1,
            std::time::Duration::from_secs(3600),
        ));
        assert!(
            auth.throttle.admit_verification().is_ok(),
            "spend the one run"
        );

        let client = a_client();
        let res = authenticate(
            &auth,
            client,
            login_req(
                "application/json",
                r#"{"password":"correct-horse-battery"}"#,
            ),
        )
        .await
        .expect_err("the budget is spent");
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(res.headers().contains_key("retry-after"));
        assert!(
            auth.throttle.retry_after(client.ip).is_none(),
            "a refusal by the ceiling is not a failed attempt by this client",
        );
    }

    #[test]
    fn the_json_media_type_rule_is_the_one_the_extractor_applied() {
        // Parameters are ignored and a `+json` suffix counts, which is what
        // `Json::from_request` accepts. An absent `Content-Type` is not a
        // declaration — also what the extractor did.
        for accepted in [
            "application/json",
            "application/json; charset=utf-8",
            "APPLICATION/JSON",
            "application/merge-patch+json",
        ] {
            assert!(
                declares_json(&req_with(header::CONTENT_TYPE, accepted)),
                "{accepted} declares JSON",
            );
        }
        for refused in [
            "text/plain",
            "text/plain;charset=UTF-8",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/jsonish",
            "json",
            "",
        ] {
            assert!(
                !declares_json(&req_with(header::CONTENT_TYPE, refused)),
                "{refused:?} does not declare JSON",
            );
        }
        assert!(
            !declares_json(&HttpRequest::builder().body(Body::empty()).unwrap()),
            "no Content-Type at all is not a declaration",
        );
    }

    #[test]
    fn the_clearing_cookie_carries_secure_exactly_when_the_session_cookie_would() {
        // One function decides both, so the pair that sets and clears one
        // cookie cannot describe it two different ways.
        let over_tls = Client {
            ip: None,
            secure: true,
        };
        let plain = Client {
            ip: None,
            secure: false,
        };
        // Behind a TLS-terminating proxy both carry it.
        assert!(
            session_cookie_header("abc", 3600, over_tls).ends_with("; Secure"),
            "the login cookie is Secure over TLS",
        );
        assert!(
            session_cookie_header("", 0, over_tls).ends_with("; Secure"),
            "so is the cookie that clears it — a cookie's attributes are part \
             of what identifies it, and the pair that sets and clears one \
             cookie must not describe it two different ways",
        );

        // On plain HTTP neither does, or `http://localhost` breaks.
        assert!(!session_cookie_header("abc", 3600, plain).contains("Secure"));
        assert!(!session_cookie_header("", 0, plain).contains("Secure"));

        // The clearing form is still a clearing form.
        let cleared = session_cookie_header("", 0, over_tls);
        assert!(cleared.contains(&format!("{SESSION_COOKIE}=;")));
        assert!(cleared.contains("Max-Age=0"));
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
