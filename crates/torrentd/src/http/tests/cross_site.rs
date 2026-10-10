//! A daemon without `[auth]` refuses what a browser sends on another site's
//! behalf: a foreign `Host` (DNS rebinding), and a state-changing request
//! that `Sec-Fetch-Site`, `Origin` or a form body marks as cross-site.

use std::sync::Arc;

use kynos::http::StatusCode;
use kynos::test::TestResponse;

use super::support::Coverage;
use super::support::Harness;
use crate::http::security::HostAllowlist;

/// A daemon run with `allow_unauthenticated`, answering to `allowed_hosts`.
fn open(cov: &Arc<Coverage>, allowed_hosts: &[&str]) -> Harness {
    let mut state = crate::app_state::build_test_state(None);
    let hosts: Vec<String> = allowed_hosts.iter().map(|h| (*h).to_owned()).collect();
    state.allowed_hosts = HostAllowlist::parse(&hosts).unwrap();
    Harness::new(cov, state, Default::default())
}

fn assert_refused(resp: &TestResponse, case: &str) {
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "{case}: {}",
        resp.text()
    );
}

fn assert_admitted(resp: &TestResponse, case: &str) {
    assert!(
        resp.status().is_success(),
        "{case}: {} {}",
        resp.status(),
        resp.text()
    );
}

/// The mutating operations a plain HTML form reaches: no body is read.
const BODYLESS_POSTS: [&str; 4] = [
    "/v1/torrents/pause-all",
    "/v1/torrents/resume-all",
    "/v1/profiles/offline-all",
    "/v1/profiles/online-all",
];

#[tokio::test]
async fn a_foreign_host_is_refused_on_every_operation() {
    let cov = Coverage::new();
    let h = open(&cov, &[]);
    for host in [
        "attacker.example:8080",
        "attacker.example",
        "127.0.0.1.attacker.example",
        "localhost.attacker.example:8080",
        "0.0.0.0:8080",
        "192.168.1.10:8080",
        "not a host",
    ] {
        let resp = h
            .send_with("GET", "/v1/torrents", None, None, &[("host", host)])
            .await;
        assert_refused(&resp, &format!("GET with Host {host}"));
        for path in BODYLESS_POSTS {
            let resp = h
                .send_with("POST", path, None, None, &[("host", host)])
                .await;
            assert_refused(&resp, &format!("POST {path} with Host {host}"));
        }
    }
    h.assert_conformance();
}

#[tokio::test]
async fn a_loopback_or_allowed_host_is_admitted() {
    let cov = Coverage::new();
    let h = open(&cov, &["torrentd.example.com"]);
    for host in [
        "127.0.0.1:8080",
        "127.0.0.1",
        "127.1.2.3:8080",
        "localhost:8080",
        "LocalHost.:8080",
        "[::1]:8080",
        "[::ffff:127.0.0.1]:8080",
        "torrentd.example.com",
        "TORRENTD.example.com:443",
    ] {
        let resp = h
            .send_with("GET", "/v1/torrents", None, None, &[("host", host)])
            .await;
        assert_admitted(&resp, &format!("GET with Host {host}"));
    }
    h.assert_conformance();
}

#[tokio::test]
async fn a_cross_site_state_change_is_refused() {
    let cov = Coverage::new();
    let h = open(&cov, &["torrentd.example.com"]);
    let cases: [(&str, &[(&str, &str)]); 9] = [
        (
            "Sec-Fetch-Site: cross-site",
            &[("host", "127.0.0.1:8080"), ("sec-fetch-site", "cross-site")],
        ),
        (
            "Sec-Fetch-Site: same-site",
            &[("host", "127.0.0.1:8080"), ("sec-fetch-site", "same-site")],
        ),
        (
            "a foreign Origin",
            &[
                ("host", "127.0.0.1:8080"),
                ("origin", "https://attacker.example"),
            ],
        ),
        (
            "another loopback port's Origin",
            &[
                ("host", "localhost:8080"),
                ("origin", "http://localhost:3000"),
            ],
        ),
        (
            "an opaque Origin",
            &[("host", "127.0.0.1:8080"), ("origin", "null")],
        ),
        (
            "an Origin and no Host",
            &[("origin", "http://127.0.0.1:8080")],
        ),
        (
            "an empty form",
            &[
                ("host", "127.0.0.1:8080"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
        ),
        (
            "a text/plain form",
            &[("host", "127.0.0.1:8080"), ("content-type", "text/plain")],
        ),
        (
            "a multipart form",
            &[
                ("host", "torrentd.example.com"),
                ("content-type", "multipart/form-data; boundary=x"),
            ],
        ),
    ];
    for (case, headers) in cases {
        for path in BODYLESS_POSTS {
            let resp = h.send_with("POST", path, None, None, headers).await;
            assert_refused(&resp, &format!("POST {path} with {case}"));
        }
        // A `DELETE` changes state as much as a `POST`.
        let resp = h
            .send_with(
                "DELETE",
                "/v1/torrents/0123456789abcdef0123456789abcdef01234567",
                None,
                None,
                headers,
            )
            .await;
        assert_refused(&resp, &format!("DELETE with {case}"));
    }

    // A cross-site read cannot see its answer, so it is left alone: what the
    // Host check refuses is the rebinding that would let it see one.
    let resp = h
        .send_with(
            "GET",
            "/v1/torrents",
            None,
            None,
            &[
                ("host", "127.0.0.1:8080"),
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://attacker.example"),
            ],
        )
        .await;
    assert_admitted(&resp, "a cross-site GET");
    h.assert_conformance();
}

#[tokio::test]
async fn a_same_origin_or_non_browser_state_change_is_admitted() {
    let cov = Coverage::new();
    let h = open(&cov, &["torrentd.example.com"]);
    let cases: [(&str, &[(&str, &str)]); 7] = [
        // curl and torrentctl: no Origin, no Sec-Fetch-Site, no body.
        ("no Host at all", &[]),
        ("a bare loopback Host", &[("host", "127.0.0.1:8080")]),
        (
            "a JSON content type",
            &[
                ("host", "localhost:8080"),
                ("content-type", "application/json; charset=utf-8"),
            ],
        ),
        (
            "the daemon's own Origin",
            &[
                ("host", "127.0.0.1:8080"),
                ("origin", "http://127.0.0.1:8080"),
                ("sec-fetch-site", "same-origin"),
            ],
        ),
        (
            "a user-initiated navigation",
            &[("host", "[::1]:8080"), ("sec-fetch-site", "none")],
        ),
        (
            "a proxy's name, Host passed through",
            &[
                ("host", "torrentd.example.com"),
                ("origin", "https://torrentd.example.com"),
                ("sec-fetch-site", "same-origin"),
            ],
        ),
        (
            "a proxy's name on an explicit port",
            &[
                ("host", "torrentd.example.com:8443"),
                ("origin", "https://torrentd.example.com:8443"),
            ],
        ),
    ];
    for (case, headers) in cases {
        for path in BODYLESS_POSTS {
            let resp = h.send_with("POST", path, None, None, headers).await;
            assert_admitted(&resp, &format!("POST {path} with {case}"));
        }
    }
    h.assert_conformance();
}

#[tokio::test]
async fn a_daemon_with_auth_judges_the_token_not_the_site() {
    // A page cannot present a bearer token, so with `[auth]` the site checks
    // add nothing, and a proxy's Host needs no allowlist entry.
    let cov = Coverage::new();
    let h = Harness::authed(&cov, |_| {});
    let token = h.tokens.write.clone();
    let resp = h
        .send_with(
            "POST",
            "/v1/torrents/pause-all",
            Some(&token),
            None,
            &[
                ("host", "torrentd.example.com"),
                ("origin", "https://torrentd.example.com"),
            ],
        )
        .await;
    assert_admitted(&resp, "a token behind a proxy's name");
    let resp = h
        .send_with(
            "POST",
            "/v1/torrents/pause-all",
            None,
            None,
            &[("host", "attacker.example")],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{}", resp.text());
    h.assert_conformance();
}
