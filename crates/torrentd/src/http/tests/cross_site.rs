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

/// Send `method uri` with `headers`, as raw bytes, straight to a fresh router
/// over a daemon without `[auth]` answering to `allowed_hosts`.
///
/// The test client takes only an origin-form path and text header values, so
/// it cannot send the two shapes this needs: a request target that carries
/// its own authority (absolute-form, or what HTTP/2's `:authority` becomes),
/// and a `Host` that is not text.
async fn raw(
    allowed_hosts: &[&str],
    method: &str,
    uri: &str,
    headers: &[(&str, &[u8])],
) -> StatusCode {
    use kynos::http::HeaderValue;
    let mut state = crate::app_state::build_test_state(None);
    let hosts: Vec<String> = allowed_hosts.iter().map(|h| (*h).to_owned()).collect();
    state.allowed_hosts = HostAllowlist::parse(&hosts).unwrap();
    let openapi = crate::http::OpenApiJson(Arc::new(bytes::Bytes::from(
        crate::http::document_json().unwrap(),
    )));
    let service = crate::http::service(state, openapi).expect("the router builds");
    let mut request =
        kynos::http::Request::new(kynos::http::body::Body::from_bytes(bytes::Bytes::new()));
    *request.method_mut() = method.parse().unwrap();
    *request.uri_mut() = uri.parse().unwrap();
    for (name, value) in headers {
        request.headers_mut().insert(
            kynos::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value).unwrap(),
        );
    }
    service.call(request).await.status()
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

#[tokio::test]
async fn the_request_targets_authority_is_judged_ahead_of_host() {
    // An absolute-form target, or HTTP/2's `:authority`, is the authority the
    // request is for; RFC 9112 section 3.2.2 has a server ignore `Host` then.
    // A rebound page cannot choose either, but the check reads the one the
    // server routes by.
    for path in ["/v1/torrents", "/v1/torrents/pause-all"] {
        let method = if path.ends_with("pause-all") {
            "POST"
        } else {
            "GET"
        };
        let status = raw(
            &[],
            method,
            &format!("http://attacker.example:8080{path}"),
            &[("host", b"127.0.0.1:8080")],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {path}: a foreign target authority"
        );
        let status = raw(
            &[],
            method,
            &format!("http://127.0.0.1:8080{path}"),
            &[("host", b"attacker.example:8080")],
        )
        .await;
        assert!(
            status.is_success(),
            "{method} {path}: a loopback target authority: {status}"
        );
        let status = raw(
            &["torrentd.example.com"],
            method,
            &format!("https://torrentd.example.com{path}"),
            &[],
        )
        .await;
        assert!(
            status.is_success(),
            "{method} {path}: an allowed target authority: {status}"
        );
    }
}

#[tokio::test]
async fn a_host_that_is_not_text_is_refused() {
    for host in [&b"127.0.0.1\xff"[..], b"\xe2\x80\x8blocalhost:8080"] {
        for (method, path) in [("GET", "/v1/torrents"), ("POST", "/v1/torrents/pause-all")] {
            let status = raw(&[], method, path, &[("host", host)]).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} with Host {host:?}"
            );
        }
    }
}

#[tokio::test]
async fn every_refusal_is_counted_by_the_header_that_refused_it() {
    let cov = Coverage::new();
    let h = open(&cov, &[]);
    let cases: [(&str, &[(&str, &str)]); 4] = [
        ("host", &[("host", "attacker.example")]),
        (
            "sec_fetch_site",
            &[("host", "127.0.0.1:8080"), ("sec-fetch-site", "cross-site")],
        ),
        (
            "origin",
            &[
                ("host", "127.0.0.1:8080"),
                ("origin", "https://attacker.example"),
            ],
        ),
        (
            "content_type",
            &[("host", "127.0.0.1:8080"), ("content-type", "text/plain")],
        ),
    ];
    // More refusals than the log writes lines for: each is counted.
    for (_, headers) in cases {
        for _ in 0..3 {
            let resp = h
                .send_with("POST", "/v1/torrents/pause-all", None, None, headers)
                .await;
            assert_refused(&resp, "a cross-site POST");
        }
    }
    let text = String::from_utf8(h.state.metrics.render()).unwrap();
    for (reason, _) in cases {
        let series = format!("torrentd_auth_cross_site_refusals_total{{reason=\"{reason}\"}} 3");
        assert!(text.contains(&series), "{series} in:\n{text}");
    }
    h.assert_conformance();
}
