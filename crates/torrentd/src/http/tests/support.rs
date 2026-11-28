//! Driving the whole router in-process, and recording which declared
//! responses the tests produced.
//!
//! The responses this API declares need different daemons to produce —
//! authentication on and off, a pool configured and not, a profile fenced —
//! so no one client sees them all. Every [`Harness`]'s client records into a
//! [`Coverage`] that outlives any one daemon (kynos'
//! `TestClient::with_coverage`), and `tests::spec` asserts over the union.

use std::sync::Arc;

use kynos::http::Method;
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

/// Every response any harness's client received, held to the published
/// document once every scenario has run.
#[derive(Default)]
pub struct Coverage(kynos::test::Coverage);

impl Coverage {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Every response the document declares was received by some harness.
    ///
    /// # Panics
    ///
    /// Listing every declared response nobody produced.
    pub fn assert_declared_responses_covered(&self) {
        self.0
            .assert_declared_responses_covered(&crate::http::document().unwrap());
    }
}

/// Credentials a harness was configured with.
#[derive(Clone, Debug, Default)]
pub struct Tokens {
    /// Static tokens by the scope set they were issued with.
    pub read: String,
    pub write: String,
    pub metrics: String,
}

/// How a stalled body says how long it is.
#[derive(Clone, Copy)]
enum Framing {
    /// `content-length: 64`, and fewer bytes sent.
    Declared,
    /// `transfer-encoding: chunked`, and no last chunk.
    Chunked,
    /// A `content-length` of this many bytes, and none of them sent.
    Oversized(u64),
}

/// One daemon's router, and what to authenticate against it with.
pub struct Harness {
    pub client: TestClient<AppCtx>,
    pub state: Arc<AppState>,
    pub tokens: Tokens,
    /// What `client` records into, for the clients a stalled body is sent
    /// with.
    coverage: Arc<Coverage>,
}

/// `method path` on `client` from the harnesses' client peer, with `token`
/// as the bearer credential, if any.
fn request_on<'c>(
    client: &'c TestClient<AppCtx>,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> kynos::test::TestRequest<'c, AppCtx> {
    let method = Method::from_bytes(method.as_bytes())
        .unwrap_or_else(|_| panic!("{method:?} is not a method"));
    let mut req = client
        .method(method, path)
        .peer("192.0.2.10:40000".parse().unwrap());
    if let Some(token) = token {
        req = req.header("authorization", &format!("Bearer {token}"));
    }
    req
}

/// The `[auth] session_ttl_secs` an authenticated harness runs with, unless
/// it asks for another.
pub const SESSION_TTL_SECS: u64 = 3600;

/// Configure `[auth]` on `state` with [`PASSWORD`] and one static token per
/// scope.
pub fn with_auth(state: &mut AppState) -> Tokens {
    with_auth_ttl(state, SESSION_TTL_SECS)
}

/// As [`with_auth`], with sessions that live `session_ttl_secs`.
fn with_auth_ttl(state: &mut AppState, session_ttl_secs: u64) -> Tokens {
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
        session_ttl_secs,
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
        let client = TestClient::new(service).with_coverage(&coverage.0);
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

    /// As [`authed`](Self::authed) with no setup, with sessions that live
    /// `session_ttl_secs`. `Auth::new` does not validate, so this may go
    /// below the configurable minimum, which is what lets a test outlive one.
    pub fn authed_with_session_ttl(coverage: &Arc<Coverage>, session_ttl_secs: u64) -> Self {
        let mut state = crate::app_state::build_test_state(None);
        let tokens = with_auth_ttl(&mut state, session_ttl_secs);
        Self::new(coverage, state, tokens)
    }

    /// The `/metrics` sample named exactly `series` (`name{labels}`), read
    /// with the `metrics` token, or 0 where the scrape has none.
    pub async fn metric(&self, series: &str) -> f64 {
        let resp = self
            .send("GET", "/metrics", Some(&self.tokens.metrics.clone()), None)
            .await;
        resp.assert_status(StatusCode::OK);
        resp.text()
            .lines()
            .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
            .map_or(0.0, |v| v.trim().parse().unwrap())
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
        let mut req = self.request(method, path, token);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        req.send().await
    }

    /// `method path` from this harness's client peer, with `token` as the
    /// bearer credential, if any.
    fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> kynos::test::TestRequest<'_, AppCtx> {
        request_on(&self.client, method, path, token)
    }

    /// The server `startup::http_stage::serve_once` runs, over a second router
    /// on this harness's state, so the operation's own deadline answers a
    /// stalled body only where production lets it.
    fn stall_server(&self) -> kynos::server::Server<AppCtx> {
        let openapi = OpenApiJson(Arc::new(bytes::Bytes::from(
            crate::http::document_json().unwrap(),
        )));
        let service = crate::http::service((*self.state).clone(), openapi).unwrap();
        crate::startup::http_server(service)
            // No head deadline: the paused clock would jump to it before the
            // operation's deadline is armed, and arm that one late. Every
            // head here is sent whole before the pause. kynos bounds a
            // connection's first head by the earlier of HTTP/1's header-read
            // timeout and HTTP/2's idle timeout, so both go.
            .http1(kynos::server::protocol::http1::Http1Config::default().header_read_timeout(None))
            .http2(kynos::server::protocol::http2::Http2Config::default().idle_timeout(None))
    }

    /// Send `method path` with a body that declares more bytes than it sends
    /// and then stalls, and return the status it is answered with and how
    /// long, on the tokio clock, that took.
    ///
    /// The request is sent twice, each time to a second router over `state`
    /// served by the `kynos::server::Server` the daemon runs. A test client
    /// sends it over an in-memory connection as a stream that never ends
    /// (`TestRequest::body_stream`), and its answer is the one returned and
    /// recorded in the harness's [`Coverage`]. It is also written by hand
    /// over a loopback socket, which must be answered the same within a
    /// second: a bound only a listener sets would otherwise answer first.
    /// The clock is paused while each waits, so a deadline of
    /// minutes elapses as soon as nothing else can run: the result is exact,
    /// and the test does not wait for it.
    pub async fn slow_body(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> (StatusCode, std::time::Duration) {
        self.stalled_body(method, path, token, Framing::Declared)
            .await
    }

    /// As [`slow_body`](Self::slow_body), with a body that declares no
    /// length: `transfer-encoding: chunked`, one chunk, and then nothing.
    /// kynos' `BodySize` reads such a body whole before the handler runs, so
    /// this is the request that reaches whatever the group checks before it.
    pub async fn stalled_chunked_body(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> (StatusCode, std::time::Duration) {
        self.stalled_body(method, path, token, Framing::Chunked)
            .await
    }

    /// As [`slow_body`](Self::slow_body), with a request that declares a
    /// `content-length` of `declared` bytes and sends none of them, which
    /// shows a body over the limit is refused from the head: a server that
    /// read it before answering would wait out its deadline instead.
    pub async fn oversized_body(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        declared: u64,
    ) -> (StatusCode, std::time::Duration) {
        self.stalled_body(method, path, token, Framing::Oversized(declared))
            .await
    }

    async fn stalled_body(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        framing: Framing,
    ) -> (StatusCode, std::time::Duration) {
        let (status, waited) = self.stalled_in_process(method, path, token, framing).await;
        let (served, served_after) = self.stalled_on_server(method, path, token, framing).await;
        assert_eq!(
            served, status,
            "{method} {path}: the daemon's server answers a stalled body other than the router does"
        );
        assert!(
            served_after.abs_diff(waited) < std::time::Duration::from_secs(1),
            "{method} {path}: the daemon's server answered after {served_after:?}, \
             the router after {waited:?}"
        );
        (status, waited)
    }

    /// The stalled request of `framing` through a test client over the
    /// daemon's server.
    async fn stalled_in_process(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        framing: Framing,
    ) -> (StatusCode, std::time::Duration) {
        use futures_util::StreamExt as _;

        let (first, declared): (&'static [u8], _) = match framing {
            Framing::Declared => (b"{\"pad\": \"", Some(64)),
            Framing::Chunked => (b"{\"pad\": \"", None),
            Framing::Oversized(declared) => (b"", Some(declared)),
        };
        let chunks = futures_util::stream::iter(
            Some(bytes::Bytes::from_static(first)).filter(|chunk| !chunk.is_empty()),
        )
        .chain(futures_util::stream::pending());
        // Through the daemon's server settings: a client over the router
        // alone holds a body to kynos' default 30 s idle timeout, which the
        // daemon turns off (`startup::http_server`).
        let served =
            TestClient::through_server(self.stall_server()).with_coverage(&self.coverage.0);
        let mut req =
            request_on(&served, method, path, token).body_stream("application/json", chunks);
        if let Some(declared) = declared {
            req = req.content_length(declared);
        }
        let (resp, waited) = on_a_paused_clock(method, path, req.send()).await;
        (resp.status(), waited)
    }

    /// The stalled request of `framing`, written by hand over a loopback
    /// socket to the server the daemon runs.
    async fn stalled_on_server(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        framing: Framing,
    ) -> (StatusCode, std::time::Duration) {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(
            self.stall_server()
                .listener(listener.into_std().unwrap())
                .serve(),
        );

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = token
            .map(|t| format!("authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let head = match framing {
            Framing::Declared => format!(
                "{method} {path} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n\
                 content-length: 64\r\n{auth}\r\n{{\"pad\": \""
            ),
            Framing::Chunked => format!(
                "{method} {path} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n\
                 transfer-encoding: chunked\r\n{auth}\r\n9\r\n{{\"pad\": \"\r\n"
            ),
            Framing::Oversized(declared) => format!(
                "{method} {path} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n\
                 content-length: {declared}\r\n{auth}\r\n"
            ),
        };
        stream.write_all(head.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        let read = async {
            while !response.windows(2).any(|w| w == b"\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(
                    n > 0,
                    "{method} {path}: the connection closed with no response"
                );
                response.extend_from_slice(&buf[..n]);
            }
        };
        let ((), waited) = on_a_paused_clock(method, path, read).await;
        server.abort();

        let line = String::from_utf8_lossy(&response);
        let status: u16 = line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("{method} {path}: not a status line: {line}"));
        (StatusCode::from_u16(status).unwrap(), waited)
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

/// Run `answer`, the wait for the response to a stalled `method path`, on a
/// paused tokio clock, and return its output and how long it took on that
/// clock.
///
/// # Panics
///
/// When it has not finished after a minute of real time: a request nothing
/// bounds would otherwise wait forever. The guard is a thread on the real
/// clock, not a tokio timer: a paused clock jumps to the earliest tokio timer
/// the moment nothing can run, which may be before the server has armed its
/// own deadline, and a guard timer would then be what fires.
async fn on_a_paused_clock<T>(
    method: &str,
    path: &str,
    answer: impl std::future::Future<Output = T>,
) -> (T, std::time::Duration) {
    let (done, done_rx) = std::sync::mpsc::channel::<()>();
    let (fire, fired) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        if done_rx.recv_timeout(std::time::Duration::from_secs(60))
            == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        {
            let _ = fire.send(());
        }
    });

    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let answered = tokio::select! {
        output = answer => Some(output),
        _ = fired => None,
    };
    let waited = started.elapsed();
    drop(done);
    tokio::time::resume();
    let output = answered.unwrap_or_else(|| {
        panic!("{method} {path}: no response to a stalled body in a minute of real time")
    });
    (output, waited)
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

/// Assert `resp` refused a valid credential for a scope it lacks: a `403`
/// `insufficient-scope` carrying RFC 6750's `insufficient_scope` challenge,
/// whether the operation's `Scoped` argument refused it from the handler or,
/// in a group that runs it first, from the request head.
pub fn assert_scope_refused(resp: &TestResponse) {
    assert_problem(resp, 403, "insufficient-scope");
    assert_eq!(
        resp.header("www-authenticate"),
        Some("Bearer error=\"insufficient_scope\""),
        "a scope refusal carries the insufficient_scope challenge",
    );
}
