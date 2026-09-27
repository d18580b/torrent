//! `sessions`: password → session token, the current credential, revocation.

use std::sync::Arc;

use serde_json::json;

use super::support::assert_problem;
use super::support::Coverage;
use super::support::Harness;
use super::support::PASSWORD;

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

    let me: serde_json::Value = h
        .send("GET", "/v1/sessions/current", Some(&token), None)
        .await
        .json();
    assert_eq!(me["kind"], "session");
    assert_eq!(me["name"], serde_json::Value::Null);
    assert!(me["expires_at"].is_string());

    // A session carries `write`, and never `metrics`.
    let resp = h.send("GET", "/metrics", Some(&token), None).await;
    assert_problem(&resp, 403, "insufficient-scope");

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
    assert!(wait >= 1);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["retry_after_secs"], wait);

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
async fn an_expired_session_is_refused_like_an_unknown_one() {
    let h = Harness::authed(&Coverage::new(), |_| {});
    let auth = h.state.auth.as_ref().unwrap();
    let short = crate::auth::SessionStore::new(std::time::Duration::from_millis(1));
    let (token, _) = short.create();
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert!(!short.is_valid(&token));
    // Neither a token from another store nor garbage authenticates here.
    for bad in [token.as_str(), "tds_nonsense", "tdp_nonsense", "nonsense"] {
        let resp = h.send("GET", "/v1/status", Some(bad), None).await;
        assert_eq!(resp.status().as_u16(), 401, "{bad}");
    }
    assert_eq!(auth.sessions.len(), 0);
}
