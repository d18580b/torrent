//! `sessions`: password → session token, the current credential, revocation.

use std::sync::Arc;

use serde_json::json;

use super::support::assert_problem;
use super::support::Coverage;
use super::support::Harness;
use super::support::PASSWORD;
use super::support::SESSION_TTL_SECS;

/// The series `TorrentdTokenScopeDenied` alerts on.
const SCOPE_DENIALS: &str = "torrentd_auth_token_scope_denials_total";

/// The series the login alerts watch, for one `reason`.
fn login_failures(reason: &str) -> String {
    format!("torrentd_auth_login_failures_total{{reason=\"{reason}\"}}")
}

/// `expires_at` is a session TTL from now, to within the time the test took.
fn assert_expires_in_ttl(expires_at: &serde_json::Value) {
    let at: jiff::Timestamp = expires_at
        .as_str()
        .expect("expires_at is a string")
        .parse()
        .expect("expires_at is an RFC 3339 timestamp");
    let lifetime = at.as_second() - jiff::Timestamp::now().as_second();
    let ttl = SESSION_TTL_SECS as i64;
    assert!(
        (ttl - 5..=ttl + 5).contains(&lifetime),
        "a session expires session_ttl_secs ({ttl}) from now, not {lifetime}s",
    );
}

/// Every declared response of the `sessions` tag.
pub(crate) async fn scenarios(cov: &Arc<Coverage>) {
    let h = Harness::authed(cov, |_| {});

    // A session: issued, usable for write, described, revoked, then dead.
    let resp = h
        .send(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD})),
        )
        .await;
    resp.assert_status(kynos::http::StatusCode::CREATED);
    resp.assert_header("location", "/v1/sessions/current");
    let grant: serde_json::Value = resp.json();
    let token = grant["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("tds_"), "{token}");
    assert_eq!(grant["token_type"], "Bearer");
    assert_eq!(grant["scopes"], json!(["read", "write"]));
    assert_expires_in_ttl(&grant["expires_at"]);

    let me: serde_json::Value = h
        .send("GET", "/v1/sessions/current", Some(&token), None)
        .await
        .json();
    assert_eq!(me["kind"], "session");
    assert_eq!(me["name"], serde_json::Value::Null);
    assert_eq!(me["expires_at"], grant["expires_at"]);

    // A session carries `write`, and never `metrics`. Only a static token
    // used beyond its scopes is a scope denial the alert counts: a session
    // is the operator, and nothing it is refused is a leaked credential.
    let resp = h.send("GET", "/metrics", Some(&token), None).await;
    assert_problem(&resp, 403, "insufficient-scope");
    assert_eq!(h.metric(SCOPE_DENIALS).await, 0.0);

    h.send("DELETE", "/v1/sessions/current", Some(&token), None)
        .await
        .assert_status(kynos::http::StatusCode::NO_CONTENT);
    let resp = h
        .send("GET", "/v1/sessions/current", Some(&token), None)
        .await;
    assert_eq!(resp.status().as_u16(), 401, "a revoked token is dead");
    let resp = h.send("DELETE", "/v1/sessions/current", None, None).await;
    assert_eq!(resp.status().as_u16(), 401);
    let resp = h
        .send(
            "DELETE",
            "/v1/sessions/current",
            Some(&h.tokens.metrics.clone()),
            None,
        )
        .await;
    assert_problem(&resp, 403, "insufficient-scope");
    let resp = h
        .send(
            "GET",
            "/v1/sessions/current",
            Some(&h.tokens.metrics.clone()),
            None,
        )
        .await;
    assert_problem(&resp, 403, "insufficient-scope");
    assert_eq!(
        h.metric(SCOPE_DENIALS).await,
        2.0,
        "each refusal of the scrape token is counted once",
    );

    // A static token is described, and cannot be revoked here.
    let me: serde_json::Value = h.read("/v1/sessions/current").await.json();
    assert_eq!(me["kind"], "token");
    assert_eq!(me["name"], "reader");
    assert_eq!(me["scopes"], json!(["read"]));
    let resp = h
        .send(
            "DELETE",
            "/v1/sessions/current",
            Some(&h.tokens.read.clone()),
            None,
        )
        .await;
    assert_problem(&resp, 409, "not-a-session");

    // Malformed requests never reach the password hash.
    let resp = h
        .send("POST", "/v1/sessions", None, Some(json!({"password": 1})))
        .await;
    assert_eq!(resp.status().as_u16(), 422);
    let resp = h
        .send(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD, "remember": true})),
        )
        .await;
    assert_eq!(resp.status().as_u16(), 422, "unknown fields are refused");
    let resp = h
        .client
        .post("/v1/sessions")
        .body("text/plain", "hunter2")
        .send()
        .await;
    assert_eq!(resp.status().as_u16(), 415);
    h.send_with(
        "POST",
        "/v1/sessions",
        None,
        None,
        &[("content-type", "text/plain")],
    )
    .await
    .assert_status(kynos::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let resp = h
        .client
        .post("/v1/sessions")
        .body("application/json", "{")
        .send()
        .await;
    assert_eq!(resp.status().as_u16(), 400);
    h.send_with(
        "POST",
        "/v1/sessions",
        None,
        None,
        &[("content-type", "application/json")],
    )
    .await
    .assert_status(kynos::http::StatusCode::BAD_REQUEST);
    let huge = "x".repeat(crate::http::v1::MAX_BODY_BYTES + 1);
    let resp = h
        .send(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": huge})),
        )
        .await;
    assert_eq!(resp.status().as_u16(), 413);
    // A body that never finishes arriving is cut off, unauthenticated.
    let (status, _) = h.slow_body("POST", "/v1/sessions", None).await;
    assert_eq!(status.as_u16(), 408);

    // Wrong passwords, until the per-client throttle answers with a wait.
    for _ in 0..5 {
        let resp = h
            .send(
                "POST",
                "/v1/sessions",
                None,
                Some(json!({"password": "nope"})),
            )
            .await;
        assert_problem(&resp, 401, "invalid-credentials");
    }
    // Malformed requests above were refused before the hash, so they are not
    // failed logins.
    assert_eq!(h.metric(&login_failures("bad_password")).await, 5.0);
    assert_eq!(h.metric(&login_failures("throttled")).await, 0.0);
    let resp = h
        .send(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD})),
        )
        .await;
    assert_problem(&resp, 429, "login-throttled");
    let wait: u64 = resp.header("retry-after").unwrap().parse().unwrap();
    // The 30 s penalty, in whole seconds rounded down: the lockout began a
    // moment before this request read the clock.
    assert!((29..=30).contains(&wait), "retry-after {wait}");
    let body: serde_json::Value = resp.json();
    assert_eq!(body["retry_after_secs"], wait);
    assert_eq!(h.metric(&login_failures("throttled")).await, 1.0);
    assert_eq!(
        h.metric(&login_failures("bad_password")).await,
        5.0,
        "a throttled attempt never reaches the password check",
    );

    h.assert_conformance();

    // Without `[auth]` there is no session to create.
    let open = Harness::new(
        cov,
        crate::app_state::build_test_state(None),
        Default::default(),
    );
    let resp = open
        .send("POST", "/v1/sessions", None, Some(json!({"password": "x"})))
        .await;
    assert_problem(&resp, 409, "auth-not-configured");
    let me: serde_json::Value = open
        .send("GET", "/v1/sessions/current", None, None)
        .await
        .json();
    assert_eq!(me["kind"], "anonymous");
    let resp = open
        .send("DELETE", "/v1/sessions/current", None, None)
        .await;
    assert_problem(&resp, 409, "not-a-session");
    open.assert_conformance();
}

#[tokio::test]
async fn sessions_behave_as_documented() {
    scenarios(&Coverage::new()).await;
}

#[tokio::test]
async fn a_login_whose_body_stalls_is_cut_off_at_the_deadline_with_408() {
    // The attack: declare a length, send part of the body, stop. Before the
    // deadline nothing ended the exchange, so enough of these held every
    // connection the server would accept, `/healthz` included.
    let h = Harness::authed(&Coverage::new(), |_| {});
    let (status, waited) = h.slow_body("POST", "/v1/sessions", None).await;
    assert_eq!(status.as_u16(), 408);
    let deadline = crate::http::v1::REQUEST_DEADLINE;
    assert!(
        // The server arms its deadline a moment before the clock is paused,
        // so the paused clock sees a hair less than the whole of it.
        waited + std::time::Duration::from_secs(1) > deadline
            && waited <= deadline + std::time::Duration::from_secs(1),
        "cut off at the deadline, not before or long after: {waited:?}",
    );
}

#[tokio::test]
async fn the_login_throttle_keys_on_the_client_a_trusted_proxy_names() {
    // Behind a trusted proxy every request's socket peer is the proxy. The
    // throttle has to key on the client the proxy names, or one client's
    // failures lock out everyone behind the same proxy.
    let proxy = "192.0.2.10"; // the harness's socket peer
    let h = Harness::authed(&Coverage::new(), |s| {
        s.trusted_proxies = crate::http::forwarded::TrustedProxies::parse(&[proxy.to_owned()])
            .expect("a literal address parses");
    });
    let from = |client: &'static str| [("x-forwarded-for", client)];
    for _ in 0..5 {
        let resp = h
            .send_with(
                "POST",
                "/v1/sessions",
                None,
                Some(json!({"password": "nope"})),
                &from("203.0.113.7"),
            )
            .await;
        assert_problem(&resp, 401, "invalid-credentials");
    }
    let resp = h
        .send_with(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD})),
            &from("203.0.113.7"),
        )
        .await;
    assert_problem(&resp, 429, "login-throttled");
    // Another client behind the same proxy is not locked out.
    let resp = h
        .send_with(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD})),
            &from("203.0.113.8"),
        )
        .await;
    resp.assert_status(kynos::http::StatusCode::CREATED);
    // And the proxy's own address holds no bucket: the key was the client.
    let auth = h.state.auth.as_ref().unwrap();
    assert!(auth
        .throttle
        .retry_after(Some(proxy.parse().unwrap()))
        .is_none());
}

#[tokio::test]
async fn a_client_that_logged_in_before_gets_past_a_spent_verification_budget() {
    // Addresses polling in a loop can keep the daemon-wide budget spent.
    // A client that has logged in since the daemon started falls back on a
    // reserve that nobody else can spend; one that has not is refused.
    let proxy = "192.0.2.10"; // the harness's socket peer
    let h = Harness::authed(&Coverage::new(), |s| {
        s.trusted_proxies = crate::http::forwarded::TrustedProxies::parse(&[proxy.to_owned()])
            .expect("a literal address parses");
    });
    let h = &h;
    let login = |client: &'static str| async move {
        h.send_with(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD})),
            &[("x-forwarded-for", client)],
        )
        .await
    };
    login("203.0.113.7")
        .await
        .assert_status(kynos::http::StatusCode::CREATED);

    // Spend the shared budget the way an unidentified poller would.
    let throttle = &h.state.auth.as_ref().unwrap().throttle;
    while throttle.admit_verification(None).is_ok() {}

    let resp = login("203.0.113.8").await;
    assert_problem(&resp, 429, "login-throttled");
    assert!(resp.header("retry-after").is_some());
    login("203.0.113.7")
        .await
        .assert_status(kynos::http::StatusCode::CREATED);
}

#[tokio::test]
async fn a_session_past_its_ttl_is_refused_over_http() {
    // A session this daemon issued, used while live and again once its TTL
    // has run out: the second answer is the expiry's, since the token is
    // otherwise exactly the one that worked.
    let h = Harness::authed_with_session_ttl(&Coverage::new(), 1);
    let resp = h
        .send(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD})),
        )
        .await;
    resp.assert_status(kynos::http::StatusCode::CREATED);
    let token = resp.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    h.send("GET", "/v1/status", Some(&token), None)
        .await
        .assert_status(kynos::http::StatusCode::OK);

    // The store reads the system clock, so the TTL is waited out for real.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let resp = h.send("GET", "/v1/status", Some(&token), None).await;
    assert_eq!(resp.status().as_u16(), 401, "an expired session is dead");
    let resp = h
        .send("GET", "/v1/sessions/current", Some(&token), None)
        .await;
    assert_eq!(resp.status().as_u16(), 401);
    // Refused exactly as an unknown token is: no answer tells a caller which
    // tokens once existed.
    for bad in ["tds_nonsense", "tdp_nonsense", "nonsense"] {
        let unknown = h.send("GET", "/v1/status", Some(bad), None).await;
        assert_eq!(unknown.status().as_u16(), 401, "{bad}");
        assert_eq!(unknown.text(), resp.text(), "{bad}");
    }
    assert_eq!(h.state.auth.as_ref().unwrap().sessions.len(), 0);
}

#[tokio::test]
async fn an_untrusted_peers_forwarded_header_cannot_dodge_the_throttle() {
    // With no trusted proxy, `X-Forwarded-For` is the client's own claim. A
    // client that names a new address on every attempt must still be keyed
    // on its socket peer, or it gets a fresh burst per request.
    let h = Harness::authed(&Coverage::new(), |_| {});
    let clients = [
        "203.0.113.1",
        "203.0.113.2",
        "203.0.113.3",
        "203.0.113.4",
        "203.0.113.5",
        "203.0.113.6",
    ];
    for client in &clients[..5] {
        let resp = h
            .send_with(
                "POST",
                "/v1/sessions",
                None,
                Some(json!({"password": "nope"})),
                &[("x-forwarded-for", client)],
            )
            .await;
        assert_problem(&resp, 401, "invalid-credentials");
    }
    let resp = h
        .send_with(
            "POST",
            "/v1/sessions",
            None,
            Some(json!({"password": PASSWORD})),
            &[("x-forwarded-for", clients[5])],
        )
        .await;
    assert_problem(&resp, 429, "login-throttled");
    let auth = h.state.auth.as_ref().unwrap();
    assert!(
        auth.throttle
            .retry_after(Some("192.0.2.10".parse().unwrap()))
            .is_some(),
        "the bucket is the socket peer's",
    );
    for client in clients {
        assert!(
            auth.throttle
                .retry_after(Some(client.parse().unwrap()))
                .is_none(),
            "{client} holds no bucket",
        );
    }
}
