//! `server` and `operations`: identity, status, events, reload, the probe,
//! the scrape and the document.

use std::sync::Arc;

use super::support::assert_problem;
use super::support::Coverage;
use super::support::Harness;

/// Every declared response of the `server` and `operations` tags.
pub(crate) async fn scenarios(cov: &Arc<Coverage>) {
    events(cov).await;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let h = Harness::authed(cov, |s| s.reload_tx = Some(tx));

    // Identity.
    let info: serde_json::Value = h.read("/v1/server").await.json();
    assert_eq!(info["api_version"], "1");
    assert_eq!(info["auth"]["mode"], "password");
    assert_eq!(info["auth"]["session_ttl_secs"], 3600);
    assert_eq!(info["pool"]["configured"], false);

    // Status, and the headers every `/v1` response carries.
    let resp = h.read("/v1/status").await;
    resp.assert_header("cache-control", "no-store");
    resp.assert_header("x-content-type-options", "nosniff");
    assert!(resp.header("x-request-id").is_some());
    let status: serde_json::Value = resp.json();
    assert_eq!(status["torrents_total"], 0);
    assert_eq!(status["profile_count"], 1);

    // Reload: accepted, then pending while the first is unconsumed, then
    // unavailable once nothing is listening.
    h.write("POST", "/v1/config/reload")
        .await
        .assert_status(kynos::http::StatusCode::ACCEPTED);
    let pending = h.write("POST", "/v1/config/reload").await;
    assert_problem(&pending, 409, "reload-pending");
    rx.close();
    let _ = rx.recv().await;
    let gone = h.write("POST", "/v1/config/reload").await;
    assert_problem(&gone, 503, "reload-unavailable");

    // Every guarded operation refuses a missing credential with a challenge,
    // and a credential without the scope with `insufficient-scope`.
    for (method, path) in [
        ("GET", "/v1/server"),
        ("GET", "/v1/status"),
        ("GET", "/v1/events"),
        ("POST", "/v1/config/reload"),
        ("GET", "/metrics"),
    ] {
        let resp = h.send(method, path, None, None).await;
        assert_eq!(resp.status().as_u16(), 401, "{method} {path}");
        resp.assert_header("www-authenticate", "Bearer");
        let wrong = if path == "/metrics" {
            h.tokens.read.clone()
        } else {
            h.tokens.metrics.clone()
        };
        let resp = h.send(method, path, Some(&wrong), None).await;
        assert_problem(&resp, 403, "insufficient-scope");
    }
    // `read` does not reach a write operation.
    let resp = h
        .send(
            "POST",
            "/v1/config/reload",
            Some(&h.tokens.read.clone()),
            None,
        )
        .await;
    assert_problem(&resp, 403, "insufficient-scope");

    // The scrape.
    let resp = h
        .send("GET", "/metrics", Some(&h.tokens.metrics.clone()), None)
        .await;
    resp.assert_status(kynos::http::StatusCode::OK);
    resp.assert_header("content-type", "text/plain; version=0.0.4");
    assert!(resp.text().contains("alert_loop_heartbeat_age_seconds"));

    // The document, unauthenticated and byte-identical to the committed one's
    // source.
    let resp = h.send("GET", "/v1/openapi.json", None, None).await;
    resp.assert_status(kynos::http::StatusCode::OK);
    assert_eq!(resp.text(), crate::http::document_json().unwrap());

    // The probe: ready, then unready once the heartbeat is stale.
    let resp = h.send("GET", "/healthz", None, None).await;
    resp.assert_status(kynos::http::StatusCode::OK);
    h.state
        .alert_heartbeat
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let resp = h.send("GET", "/healthz", None, None).await;
    resp.assert_status(kynos::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["reason"], "alert_loop_stalled");

    h.assert_conformance();

    // Without `[auth]`: every operation admits an anonymous caller, and the
    // daemon says so.
    let open = Harness::new(
        cov,
        crate::app_state::build_test_state(None),
        Default::default(),
    );
    let info: serde_json::Value = open.send("GET", "/v1/server", None, None).await.json();
    assert_eq!(info["auth"]["mode"], "disabled");
    assert_eq!(info["auth"]["session_ttl_secs"], serde_json::Value::Null);
    let resp = open.send("POST", "/v1/config/reload", None, None).await;
    assert_problem(&resp, 503, "reload-unavailable");
    open.assert_conformance();
}

#[tokio::test]
async fn server_and_operations_behave_as_documented() {
    scenarios(&Coverage::new()).await;
}

#[tokio::test]
async fn events_stream_ticks_carrying_a_typed_event() {
    events(&Coverage::new()).await;
}

async fn events(cov: &Arc<Coverage>) {
    let h = Harness::authed(cov, |_| {});
    // The stream runs until the daemon shuts down; shut it down after the
    // first tick has had time to go out.
    let shutdown = h.state.shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = shutdown.send(torrentd_engine::ShutdownReason::Sigterm);
    });
    let resp = h.read("/v1/events").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    let events = resp.events();
    let first = events.first().expect("at least one tick");
    assert_eq!(first.name.as_deref(), Some("tick"));
    assert_eq!(first.retry, Some(5_000));
    let data: serde_json::Value = serde_json::from_str(&first.data).unwrap();
    assert_eq!(data["kind"], "tick");
    assert_eq!(data["fingerprint"].as_str().unwrap().len(), 16);
    h.assert_conformance();
}

#[tokio::test]
async fn every_response_carries_the_shared_headers_and_its_own_request_id() {
    let h = Harness::authed(&Coverage::new(), |_| {});
    let mut ids = std::collections::BTreeSet::new();
    for (method, path, token) in [
        ("GET", "/healthz", None),
        ("GET", "/v1/openapi.json", None),
        ("GET", "/metrics", Some(h.tokens.metrics.clone())),
        ("GET", "/v1/status", Some(h.tokens.read.clone())),
        ("GET", "/v1/status", Some(h.tokens.read.clone())),
        ("GET", "/v1/nope", None),
        ("PATCH", "/v1/status", None),
        ("POST", "/v1/sessions", None),
    ] {
        let resp = h.send(method, path, token.as_deref(), None).await;
        let at = format!("{method} {path} -> {}", resp.status());
        // kynos answers an unmatched path or method before any interceptor
        // runs, so its 404/405 carries neither these headers nor an id — a
        // framework gap `docs/api/README.md` states. This test says so
        // explicitly, and fails the day that changes.
        if path == "/v1/nope" || method == "PATCH" {
            assert_eq!(resp.header("x-request-id"), None, "{at}");
            continue;
        }
        assert_eq!(resp.header("cache-control"), Some("no-store"), "{at}");
        assert_eq!(
            resp.header("x-content-type-options"),
            Some("nosniff"),
            "{at}"
        );
        let id = resp
            .header("x-request-id")
            .unwrap_or_else(|| panic!("{at}: no id"));
        assert_eq!(id.len(), 32, "{at}: {id}");
        assert!(ids.insert(id.to_owned()), "{at}: id {id} repeated");
    }
}

#[tokio::test]
async fn unknown_paths_and_methods_are_problems_not_the_web_client() {
    let h = Harness::authed(&Coverage::new(), |_| {});
    let resp = h.read("/v1/nope").await;
    assert_eq!(resp.status().as_u16(), 404);
    assert_eq!(
        resp.header("content-type"),
        Some("application/problem+json")
    );
    let resp = h.send("PATCH", "/v1/status", None, None).await;
    assert_eq!(resp.status().as_u16(), 405);
    // Strict trailing slashes: one spelling per route.
    assert_eq!(h.read("/v1/status/").await.status().as_u16(), 404);
    // The old surface is gone.
    let old = format!("/{}/status", "api");
    assert_eq!(h.read(&old).await.status().as_u16(), 404);
}
