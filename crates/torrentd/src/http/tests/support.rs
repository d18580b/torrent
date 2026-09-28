//! Driving the whole router in-process, and recording which declared
//! responses the tests produced.
//!
//! kynos' own `TestClient::assert_declared_responses_covered` checks one
//! client against every operation, but the responses this API declares need
//! different daemons to produce — authentication on and off, a pool configured
//! and not, a profile fenced. So every request here goes through a
//! [`Harness`], which records `(method, path template, status)` into a
//! [`Coverage`] that outlives any one daemon, and `tests::spec` asserts over
//! the union.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

use kynos::http::StatusCode;
use kynos::test::TestClient;
use kynos::test::TestResponse;

use crate::app_state::AppState;
use crate::auth::Auth;
use crate::auth::AuthConfig;
use crate::auth::Scope;
use crate::auth::TokenConfig;
use crate::http::ctx::AppCtx;
use crate::http::OpenApiJson;

/// The operator password every authenticated harness is configured with.
pub const PASSWORD: &str = "correct-horse-battery";

/// Every `(METHOD, path template, status)` a test has produced.
#[derive(Default)]
pub struct Coverage {
    seen: Mutex<BTreeSet<(String, String, u16)>>,
}

impl Coverage {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn saw(&self, method: &str, path: &str, status: StatusCode) {
        let path = path.split('?').next().unwrap_or(path);
        let template = template_of(path).unwrap_or_else(|| path.to_owned());
        self.seen
            .lock()
            .unwrap()
            .insert((method.to_owned(), template, status.as_u16()));
    }

    /// Every declared `(METHOD, template, status)` nobody produced.
    pub fn missing(&self) -> Vec<String> {
        let doc: serde_json::Value = serde_json::from_str(&crate::http::document_json().unwrap())
            .expect("the document is JSON");
        let seen = self.seen.lock().unwrap();
        let mut missing = Vec::new();
        for (template, item) in doc["paths"].as_object().unwrap() {
            for (method, op) in item.as_object().unwrap() {
                for status in op["responses"].as_object().unwrap().keys() {
                    let status: u16 = status.parse().expect("every declared status is exact");
                    let key = (method.to_uppercase(), template.clone(), status);
                    if !seen.contains(&key) {
                        missing.push(format!("{} {} -> {}", key.0, key.1, key.2));
                    }
                }
            }
        }
        missing
    }
}

/// The document's path template matching a concrete `path`.
fn template_of(path: &str) -> Option<String> {
    static TEMPLATES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let templates = TEMPLATES.get_or_init(|| {
        let doc: serde_json::Value =
            serde_json::from_str(&crate::http::document_json().unwrap()).unwrap();
        doc["paths"].as_object().unwrap().keys().cloned().collect()
    });
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // A literal segment beats a parameter, as the router's own matching does:
    // `/v1/torrents/pause-all` is not `/v1/torrents/{infohash}`.
    templates
        .iter()
        .filter_map(|t| {
            let parts: Vec<&str> = t.trim_start_matches('/').split('/').collect();
            if parts.len() != segments.len() {
                return None;
            }
            let mut literals = 0;
            for (p, s) in parts.iter().zip(&segments) {
                if p.starts_with('{') {
                    continue;
                }
                if p != s {
                    return None;
                }
                literals += 1;
            }
            Some((literals, t))
        })
        .max_by_key(|(literals, _)| *literals)
        .map(|(_, t)| t.clone())
}

/// Credentials a harness was configured with.
#[derive(Clone, Debug, Default)]
pub struct Tokens {
    /// Static tokens by the scope set they were issued with.
    pub read: String,
    pub write: String,
    pub metrics: String,
}

/// One daemon's router, and what to authenticate against it with.
pub struct Harness {
    pub client: TestClient<AppCtx>,
    pub state: Arc<AppState>,
    pub tokens: Tokens,
    coverage: Arc<Coverage>,
}

/// Configure `[auth]` on `state` with [`PASSWORD`] and one static token per
/// scope.
pub fn with_auth(state: &mut AppState) -> Tokens {
    let mut tokens = Tokens::default();
    let mut configs = Vec::new();
    for (name, scopes, slot) in [
        ("reader", vec![Scope::Read], &mut tokens.read),
        ("writer", vec![Scope::Write], &mut tokens.write),
        ("scraper", vec![Scope::Metrics], &mut tokens.metrics),
    ] {
        let (token, sha256) = crate::auth::generate_token();
        *slot = token;
        configs.push(TokenConfig {
            name: name.to_owned(),
            sha256,
            scopes,
        });
    }
    state.auth = Some(Auth::new(AuthConfig {
        password_hash: cheap_hash(),
        session_ttl_secs: 3600,
        token: configs,
    }));
    tokens
}

/// The Argon2id hash of [`PASSWORD`], computed once per test binary.
fn cheap_hash() -> String {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::auth::hash_password(PASSWORD).unwrap())
        .clone()
}

impl Harness {
    /// A harness over `state` as given.
    pub fn new(coverage: &Arc<Coverage>, state: AppState, tokens: Tokens) -> Self {
        let openapi = OpenApiJson(Arc::new(bytes::Bytes::from(
            crate::http::document_json().unwrap(),
        )));
        // Every field of `AppState` is shared behind an `Arc`, so this clone
        // sees whatever a request changes.
        let shared = Arc::new(state.clone());
        let service = crate::http::service(state, openapi).expect("the router builds");
        let client = TestClient::new(service);
        Self {
            client,
            state: shared,
            tokens,
            coverage: Arc::clone(coverage),
        }
    }

    /// The default test state (`build_test_state(None)`) with `[auth]`
    /// configured, after `setup` has adjusted it.
    pub fn authed(coverage: &Arc<Coverage>, setup: impl FnOnce(&mut AppState)) -> Self {
        let mut state = crate::app_state::build_test_state(None);
        setup(&mut state);
        let tokens = with_auth(&mut state);
        Self::new(coverage, state, tokens)
    }

    /// Send `method path` with `token` as the bearer credential, if any, and
    /// `body` as JSON, if any.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> TestResponse {
        self.send_with(method, path, token, body, &[]).await
    }

    /// As [`send`](Self::send), with extra request headers.
    pub async fn send_with(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        headers: &[(&str, &str)],
    ) -> TestResponse {
        let mut req = match method {
            "GET" => self.client.get(path),
            "POST" => self.client.post(path),
            "PUT" => self.client.put(path),
            "DELETE" => self.client.delete(path),
            "PATCH" => self.client.patch(path),
            other => panic!("unsupported method {other}"),
        };
        req = req.peer("192.0.2.10:40000".parse().unwrap());
        if let Some(token) = token {
            req = req.header("authorization", &format!("Bearer {token}"));
        }
        for (name, value) in headers {
            req = req.header(name, value);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await;
        self.coverage.saw(method, path, resp.status());
        resp
    }

    /// Shorthand for a request with the `write` token and no body.
    pub async fn write(&self, method: &str, path: &str) -> TestResponse {
        self.send(method, path, Some(&self.tokens.write.clone()), None)
            .await
    }

    /// Shorthand for a `GET` with the `read` token.
    pub async fn read(&self, path: &str) -> TestResponse {
        self.send("GET", path, Some(&self.tokens.read.clone()), None)
            .await
    }

    /// Every response this harness saw conforms to the document.
    pub fn assert_conformance(&self) {
        self.client.assert_conformance();
    }
}

/// Assert `resp` is a problem of `slug` with `status`.
pub fn assert_problem(resp: &TestResponse, status: u16, slug: &str) {
    assert_eq!(
        resp.status().as_u16(),
        status,
        "expected {status} {slug}, got {}: {}",
        resp.status(),
        resp.text()
    );
    resp.assert_problem_type(&format!("{}{slug}", crate::http::security::PROBLEM_BASE));
}
