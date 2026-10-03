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

    // Past the cap, a stream is refused rather than opened.
    let full = Harness::authed(cov, |s| {
        s.events = Arc::new(crate::http::v1::server::EventFeed::with_capacity(0));
    });
    let refused = full.read("/v1/events").await;
    assert_problem(&refused, 503, "too-many-event-streams");
    assert!(
        !full.state.events.is_running(),
        "a refused stream starts no feed"
    );
    full.assert_conformance();
}

#[tokio::test]
async fn event_streams_share_one_feed_that_stops_with_the_last_and_free_their_slots() {
    use std::time::Duration;
    const CAP: usize = 2;
    let h = Harness::authed(&Coverage::new(), |s| {
        s.events = Arc::new(crate::http::v1::server::EventFeed::with_capacity(CAP));
    });
    let auth = h.state.auth.clone().unwrap();
    let tokens = [auth.sessions.create().0, auth.sessions.create().0];
    // A backstop: the daemon shutting down ends every stream, so a stream
    // that does not end fails the test rather than hanging it.
    let shutdown = h.state.shutdown.clone();
    let backstop = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        let _ = shutdown.send(torrentd_engine::ShutdownReason::Sigterm);
    });

    let h = Arc::new(h);
    let streams: Vec<_> = tokens
        .iter()
        .map(|t| {
            let (h, t) = (Arc::clone(&h), t.clone());
            tokio::spawn(async move { h.send("GET", "/v1/events", Some(&t), None).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(h.state.events.open_streams(CAP), 2);
    assert!(h.state.events.is_running(), "one feed serves both");
    // The cap is reached: a third is refused while both are open.
    assert_problem(&h.read("/v1/events").await, 503, "too-many-event-streams");

    for t in &tokens {
        auth.sessions.revoke(t);
    }
    for s in streams {
        let resp = s.await.unwrap();
        resp.assert_status(kynos::http::StatusCode::OK);
        assert!(!resp.events().is_empty());
    }
    assert_eq!(h.state.events.open_streams(CAP), 0, "every slot is freed");
    // The feed notices it has no listener on its next tick and stops.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while h.state.events.is_running() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !h.state.events.is_running(),
        "the feed outlived its last stream"
    );
    backstop.abort();
}

#[tokio::test]
async fn an_event_stream_ends_when_its_session_is_revoked() {
    // The credential is checked when the stream opens; without a re-check a
    // stream opened with a session outlived the session's revocation for as
    // long as the client kept it open.
    let h = Harness::authed(&Coverage::new(), |_| {});
    let auth = h.state.auth.clone().unwrap();
    let (token, _) = auth.sessions.create();

    let revoker = {
        let (auth, token) = (auth.clone(), token.clone());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            auth.sessions.revoke(&token);
        })
    };
    // A backstop, so a stream that does not end fails the test rather than
    // hanging it: the daemon shutting down ends every stream.
    let shutdown = h.state.shutdown.clone();
    let backstop = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        let _ = shutdown.send(torrentd_engine::ShutdownReason::Sigterm);
    });

    let started = std::time::Instant::now();
    let resp = h.send("GET", "/v1/events", Some(&token), None).await;
    resp.assert_status(kynos::http::StatusCode::OK);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the stream ended with its session, not with the daemon: {:?}",
        started.elapsed(),
    );
    assert!(
        !resp.events().is_empty(),
        "it streamed while the session lived"
    );
    revoker.await.unwrap();
    backstop.abort();
}

#[tokio::test]
async fn an_event_stream_opened_with_a_static_token_is_not_ended_by_the_check() {
    // Only a session can stop being valid while the daemon runs; a stream
    // on a static token runs until the daemon stops.
    let h = Harness::authed(&Coverage::new(), |_| {});
    let shutdown = h.state.shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        let _ = shutdown.send(torrentd_engine::ShutdownReason::Sigterm);
    });
    let started = std::time::Instant::now();
    let resp = h.read("/v1/events").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    assert!(started.elapsed() >= std::time::Duration::from_millis(2400));
}

#[tokio::test]
async fn an_events_stream_opened_after_the_shutdown_ends_at_once() {
    // Subscribed after the broadcast went out, the stream never saw it and
    // held the graceful drain open to its timeout. Nothing sends on the
    // broadcast here: only the latch can end this stream, and if it does not
    // the read below never returns.
    let h = Harness::authed(&Coverage::new(), |_| {});
    h.state.work.cancel();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), h.read("/v1/events"))
        .await
        .expect("the stream must end without waiting for a broadcast");
    resp.assert_status(kynos::http::StatusCode::OK);
    assert!(resp.events().is_empty(), "nothing is sent once shut down");
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
