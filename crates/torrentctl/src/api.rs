//! The generated `/v1` client, and the one shape its failures take here.

use std::time::Duration;

use generated::ExposeSecret as _;

/// The client spargen generates from `docs/api/openapi.json` at build time.
#[allow(
    clippy::all,
    clippy::pedantic,
    dead_code,
    unused,
    unreachable_patterns,
    missing_docs
)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}

pub use generated::types;
/// A plan's status, as `GET /v1/pool/plans` filters by it: the document's
/// `PlanStatus` component, which the filter parameter references directly.
pub use generated::types::PlanStatus;
pub use generated::Client;

// `AsProblem` for every generated error enum; see build.rs.
include!(concat!(env!("OUT_DIR"), "/problems.rs"));

/// A documented error body that is an RFC 9457 problem document.
pub trait AsProblem {
    /// The problem document, as JSON.
    fn problem_json(&self) -> Option<serde_json::Value>;
}

/// Prefix of every problem `type` the daemon publishes.
const PROBLEM_BASE: &str = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#";

/// Why a request did not succeed, as the UI shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Failure {
    /// The HTTP status, when there was a response.
    pub status: Option<u16>,
    /// The problem slug (`torrent-not-found`), `about:blank` for a framework
    /// rejection, or `None` when the failure never produced a problem.
    pub slug: Option<String>,
    /// A one-line summary.
    pub title: String,
    /// The occurrence-specific explanation, when there is one.
    pub detail: Option<String>,
    /// The daemon's `X-Request-Id`, to quote in a report.
    pub request_id: Option<String>,
    /// A `validation-failed` problem's violations: `(pointer, detail)`, the
    /// pointer an RFC 6901 JSON Pointer into the body or `#/query/<name>`.
    pub errors: Vec<(String, String)>,
    /// A `profile-unavailable` problem's `profile_status`: `failed` or
    /// `vpn_down`.
    pub profile_status: Option<String>,
}

impl Failure {
    /// A failure with no response behind it.
    pub fn local(title: impl Into<String>, detail: impl Into<Option<String>>) -> Self {
        Self {
            status: None,
            slug: None,
            title: title.into(),
            detail: detail.into(),
            ..Self::default()
        }
    }

    /// Whether the credential was refused and the user must sign in again.
    pub fn is_unauthenticated(&self) -> bool {
        self.status == Some(401)
    }

    /// Whether this is the problem `slug`.
    pub fn is(&self, slug: &str) -> bool {
        self.slug.as_deref() == Some(slug)
    }

    /// `title — detail`, or the title alone.
    pub fn message(&self) -> String {
        match &self.detail {
            Some(detail) if !detail.is_empty() => format!("{}: {detail}", self.title),
            _ => self.title.clone(),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// The daemon's `X-Request-Id` on a response, when it sent a readable one.
pub fn request_id(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

impl<E: AsProblem> From<generated::Error<E>> for Failure {
    fn from(e: generated::Error<E>) -> Self {
        use generated::Error;
        match e {
            Error::Api(response) => {
                let status = response.status().as_u16();
                let request_id = request_id(response.headers());
                let problem = response.into_inner().problem_json().unwrap_or_default();
                from_problem(status, &problem, request_id)
            }
            Error::UnexpectedStatus {
                status,
                headers,
                body,
            } => {
                let request_id = request_id(&headers);
                let problem = serde_json::from_slice(&body).unwrap_or_default();
                from_problem(status.as_u16(), &problem, request_id)
            }
            // A refused connection, as well as a dropped one, arrives here.
            Error::Transport(e) | Error::InterruptedBody(e) => {
                Failure::local("Cannot reach the daemon", Some(root_cause(&e)))
            }
            Error::Timeout(kind) => {
                Failure::local("The daemon did not answer", Some(format!("{kind:?}")))
            }
            Error::Decode { path, .. } => Failure::local(
                "The daemon's answer did not match the API document",
                Some(format!("at {path}")),
            ),
            Error::RequestConstruction(
                e @ (generated::RequestError::MissingCredential { .. }
                | generated::RequestError::CredentialProvider { .. }),
            ) => Failure::local("No credential for this request", Some(e.to_string())),
            // A request that could not be built: a header value no header
            // can carry, an unparseable URL, a body that did not serialize.
            // spargen classifies a refused connection as `Transport` before
            // it can land here, so none of these is an unreachable daemon.
            Error::RequestConstruction(e) => {
                Failure::local("The request could not be sent", Some(root_cause(&e)))
            }
            Error::Protocol(e) => {
                Failure::local("The daemon's answer was malformed", Some(e.to_string()))
            }
            Error::Redirect(e) => Failure::local("Too many redirects", Some(e.to_string())),
            // Only spargen's `Link`-header paginator raises this; the API
            // pages by cursor, so nothing here reaches it.
            Error::PaginationCycle { url } => Failure::local(
                "The daemon's pages led back to one already read",
                Some(url.to_string()),
            ),
        }
    }
}

/// The innermost cause of `e`: reqwest wraps "connection refused" several
/// layers down, and the outer layers only say a request failed.
fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cause: &dyn std::error::Error = e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

/// A problem document, already parsed, as a failure.
pub fn from_problem(
    status: u16,
    problem: &serde_json::Value,
    request_id: Option<String>,
) -> Failure {
    let slug = problem["type"]
        .as_str()
        .map(|t| t.strip_prefix(PROBLEM_BASE).unwrap_or(t).to_owned());
    let title = problem["title"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("HTTP {status}"));
    let errors = problem["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .map(|e| {
                    (
                        e["pointer"].as_str().unwrap_or_default().to_owned(),
                        e["detail"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Failure {
        status: Some(status),
        slug,
        title,
        detail: problem["detail"].as_str().map(str::to_owned),
        request_id,
        errors,
        profile_status: problem["profile_status"].as_str().map(str::to_owned),
    }
}

/// A fresh W3C `traceparent` (version 00, sampled): a new trace for every
/// request, so the daemon's spans for it share one trace id this log
/// records. Neither id is ever all zeros, which the format forbids.
pub fn traceparent() -> String {
    let trace = rand::random::<u128>().max(1);
    let span = rand::random::<u64>().max(1);
    format!("00-{trace:032x}-{span:016x}-01")
}

/// Give `headers` a fresh [`traceparent`], replacing any there, and return it.
fn stamp(headers: &mut reqwest::header::HeaderMap) -> String {
    let traceparent = traceparent();
    if let Ok(value) = reqwest::header::HeaderValue::from_str(&traceparent) {
        headers.insert("traceparent", value);
    }
    traceparent
}

/// The one log line for a request: its `traceparent`, and the daemon's
/// `X-Request-Id` when it answered with one, the two ids a report needs to
/// find the request in the daemon's log and its traces.
fn record(
    method: &reqwest::Method,
    path: &str,
    traceparent: &str,
    started: std::time::Instant,
    outcome: Result<(u16, Option<String>), String>,
) {
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match outcome {
        Ok((status, request_id)) => tracing::info!(
            target: "torrentctl::http",
            %method,
            path,
            status,
            request_id = request_id.as_deref().unwrap_or("none"),
            traceparent,
            elapsed_ms,
            "request"
        ),
        Err(error) => tracing::info!(
            target: "torrentctl::http",
            %method,
            path,
            traceparent,
            elapsed_ms,
            error,
            "request failed"
        ),
    }
}

/// The middleware every request the generated client sends goes through:
/// it carries a fresh [`traceparent`], and is logged once the response's
/// head arrives (or the transport fails).
#[derive(Debug)]
struct Traced;

impl generated::Middleware for Traced {
    fn handle<'a>(
        &'a self,
        mut request: http::Request<generated::HttpBody>,
        next: generated::Next<'a>,
    ) -> generated::ExecuteFuture<'a> {
        let traceparent = stamp(request.headers_mut());
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        Box::pin(async move {
            let started = std::time::Instant::now();
            let outcome = next.run(request).await;
            let logged = match &outcome {
                Ok(response) => Ok((response.status().as_u16(), request_id(response.headers()))),
                Err(e) => Err(root_cause(e)),
            };
            record(&method, &path, &traceparent, started, logged);
            outcome
        })
    }
}

/// Send a request [`Api::post`] built, as the generated client sends its
/// own: with a fresh [`traceparent`], and logged.
pub async fn send(request: reqwest::RequestBuilder) -> reqwest::Result<reqwest::Response> {
    let (client, request) = request.build_split();
    let mut request = request?;
    let traceparent = stamp(request.headers_mut());
    let method = request.method().clone();
    let path = request.url().path().to_owned();
    let started = std::time::Instant::now();
    let outcome = client.execute(request).await;
    let logged = match &outcome {
        Ok(response) => Ok((response.status().as_u16(), request_id(response.headers()))),
        Err(e) => Err(root_cause(e)),
    };
    record(&method, &path, &traceparent, started, logged);
    outcome
}

/// Where the daemon is and how to authenticate to it.
#[derive(Clone)]
pub struct Api {
    pub client: Client,
    /// The HTTP client the generated one executes on, for the requests
    /// [`Api::post`] builds by hand: the generated client builds its own
    /// requests on a default one.
    http: reqwest::Client,
    /// The URL the client talks to, for the header.
    pub base_url: String,
    /// Bumped whenever the credential changes, so what holds a copy — the
    /// event stream — can tell it is stale.
    pub epoch: u64,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base_url", &self.base_url)
            .finish()
    }
}

/// How a `base_url` names the daemon's unix socket: `unix:/run/torrentd/api.sock`.
pub const UNIX_PREFIX: &str = "unix:";

/// The URL requests over a unix socket are written against. Only its path
/// and `Host` reach the daemon; `localhost` is a `Host` every daemon answers.
const UNIX_ORIGIN: &str = "http://localhost";

impl Api {
    /// A client for `base_url`, authenticating with `token` when given. Fails
    /// only locally — an unusable URL — so the error is a message.
    ///
    /// `unix:/path` connects to the daemon's socket at `/path`.
    pub fn new(base_url: &str, token: Option<&str>) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("torrentctl/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(5));
        let origin = match base_url.strip_prefix(UNIX_PREFIX) {
            Some(path) => {
                if !path.starts_with('/') {
                    return Err(format!(
                        "invalid daemon URL {base_url:?}: a socket is named by an absolute \
                         path, as in unix:/run/torrentd/api.sock"
                    ));
                }
                builder = builder.unix_socket(path);
                UNIX_ORIGIN
            }
            None => base_url,
        };
        let http = builder
            .build()
            .map_err(|e| format!("cannot build the HTTP client: {e}"))?;
        let backend = generated::MiddlewareBackend::new(std::sync::Arc::new(
            generated::ReqwestBackend::new(http.clone()),
        ))
        .layer(std::sync::Arc::new(Traced));
        let mut client = Client::with_backend(std::sync::Arc::new(backend), origin)
            .map_err(|e| format!("invalid daemon URL {base_url:?}: {e}"))?;
        if let Some(token) = token {
            client = client.with_credential(
                "bearer",
                generated::Credential::Bearer(generated::SecretString::from(token.to_owned())),
            );
        }
        Ok(Self {
            client,
            http,
            base_url: base_url.to_owned(),
            epoch: 0,
        })
    }

    /// The same daemon, authenticating with `token` instead.
    pub fn with_token(&self, token: &str) -> Result<Self, String> {
        let mut api = Self::new(&self.base_url, Some(token))?;
        api.epoch = self.epoch + 1;
        Ok(api)
    }

    /// A `POST` to the path `segments` names under the daemon's URL, built
    /// by hand through the generated client's own HTTP client, base URL and
    /// credential, for a request the generated client cannot send. Fails
    /// only when the URL cannot take a path. Send it with [`send`], so it
    /// carries a `traceparent` and is logged.
    #[allow(
        clippy::result_large_err,
        reason = "a Failure is built once per failed request and moved straight to the UI"
    )]
    pub fn post(&self, segments: &[&str]) -> Result<reqwest::RequestBuilder, Failure> {
        let core = self.client.core();
        let mut url = core.base_url().clone();
        url.path_segments_mut()
            .map_err(|()| {
                Failure::local(
                    "Invalid daemon URL",
                    Some(format!("{} cannot take a path", core.base_url())),
                )
            })?
            .pop_if_empty()
            .extend(segments);
        let mut request = self.http.post(url);
        if let Some(generated::Credential::Bearer(token)) = core.credential("bearer") {
            request = request.bearer_auth(token.expose_secret());
        }
        Ok(request)
    }
}

/// The bearer presented when no token is configured: see `main`.
pub const ANONYMOUS: &str = "anonymous";

/// How long [`call`] waits for the daemon to answer. Not every request that
/// is not a stream runs under it: work that may take minutes goes through
/// [`call_unbounded`] with no timeout, a `.torrent` upload has a longer one
/// of its own, and revoking a session token gives up sooner, at
/// [`crate::app::REVOKE_TIMEOUT`].
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Run a request under [`REQUEST_TIMEOUT`], flattening every failure into a
/// [`Failure`].
#[allow(
    clippy::result_large_err,
    reason = "a Failure is built once per failed request and moved straight to the UI"
)]
pub async fn call<T, E: AsProblem>(
    request: impl std::future::Future<Output = Result<generated::ResponseValue<T>, generated::Error<E>>>,
) -> Result<T, Failure> {
    match tokio::time::timeout(REQUEST_TIMEOUT, request).await {
        Ok(Ok(value)) => Ok(value.into_inner()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(Failure::local(
            "The daemon did not answer",
            Some(format!("no response within {}s", REQUEST_TIMEOUT.as_secs())),
        )),
    }
}

/// Run a request that may legitimately take minutes — a pool scan, a drift
/// check, applying a plan, an adoption or its preview, resuming every
/// torrent — with no timeout: the daemon answers when the work is done, and
/// giving up early would report a failure for work that went on.
#[allow(
    clippy::result_large_err,
    reason = "a Failure is built once per failed request and moved straight to the UI"
)]
pub async fn call_unbounded<T, E: AsProblem>(
    request: impl std::future::Future<Output = Result<generated::ResponseValue<T>, generated::Error<E>>>,
) -> Result<T, Failure> {
    request
        .await
        .map(generated::ResponseValue::into_inner)
        .map_err(Failure::from)
}

impl AsProblem for std::convert::Infallible {
    fn problem_json(&self) -> Option<serde_json::Value> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn problem(slug: &str, status: u16) -> serde_json::Value {
        json!({
            "type": format!("{PROBLEM_BASE}{slug}"),
            "title": "The request is invalid",
            "status": status,
            "detail": "/limit: must be between 1 and 1000",
            "errors": [{"pointer": "#/query/limit", "detail": "must be between 1 and 1000"}],
        })
    }

    #[test]
    fn a_problem_document_becomes_a_failure_with_its_slug_and_extensions() {
        let f = from_problem(422, &problem("validation-failed", 422), Some("abc".into()));
        assert_eq!(f.status, Some(422));
        assert!(f.is("validation-failed"));
        assert_eq!(f.request_id.as_deref(), Some("abc"));
        assert_eq!(
            f.errors,
            [(
                "#/query/limit".to_owned(),
                "must be between 1 and 1000".to_owned()
            )]
        );
        assert_eq!(
            f.message(),
            "The request is invalid: /limit: must be between 1 and 1000"
        );

        let fenced = from_problem(
            409,
            &json!({"type": format!("{PROBLEM_BASE}profile-unavailable"), "title": "t",
                    "status": 409, "detail": "d", "profile_status": "vpn_down"}),
            None,
        );
        assert_eq!(fenced.profile_status.as_deref(), Some("vpn_down"));

        // A framework rejection keeps `about:blank`; a body with no title
        // still says what status it was.
        let blank = from_problem(400, &json!({"type": "about:blank", "status": 400}), None);
        assert_eq!(blank.slug.as_deref(), Some("about:blank"));
        assert_eq!(blank.title, "HTTP 400");
    }

    #[test]
    fn a_generated_error_reaches_its_problem_through_the_built_accessor() {
        // A documented 404 from `list_torrents`, decoded the way the client
        // decodes it, then flattened by the `AsProblem` impl build.rs wrote.
        let body = json!({
            "type": format!("{PROBLEM_BASE}profile-not-found"),
            "title": "Profile not found",
            "status": 404,
            "detail": "unknown profile_id",
        });
        let decoded = generated::ListTorrentsError::Status404(Box::new(
            serde_json::from_value(body).expect("the 404 body decodes"),
        ));
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-request-id", "0123".parse().unwrap());
        let error = generated::Error::Api(generated::ResponseValue::new(
            reqwest::StatusCode::NOT_FOUND,
            headers,
            decoded,
        ));
        let f = Failure::from(error);
        assert_eq!(f.status, Some(404));
        assert!(f.is("profile-not-found"), "{f:?}");
        assert_eq!(f.detail.as_deref(), Some("unknown profile_id"));
        assert_eq!(f.request_id.as_deref(), Some("0123"));
        assert!(!f.is_unauthenticated());
    }

    #[test]
    fn a_missing_credential_is_not_mistaken_for_an_unreachable_daemon() {
        let missing = generated::Error::<generated::GetStatusError>::RequestConstruction(
            generated::RequestError::MissingCredential {
                alternatives: vec![vec!["bearer"]],
            },
        );
        assert_eq!(
            Failure::from(missing).title,
            "No credential for this request"
        );
        // A request that could not be built is never called an unreachable
        // daemon, whatever its cause's message says.
        let other =
            generated::Error::<generated::GetStatusError>::request_message("connection refused");
        let f = Failure::from(other);
        assert_eq!(f.title, "The request could not be sent");
        assert_eq!(f.detail.as_deref(), Some("connection refused"));
    }

    /// A port nobody listens on: bound, then released.
    fn closed_port() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_refused_connection_is_an_unreachable_daemon() {
        let api = Api::new(&closed_port(), Some("tdp_valid")).unwrap();
        let f = call(api.client.get_status()).await.unwrap_err();
        assert_eq!(f.title, "Cannot reach the daemon", "{f:?}");
        // The detail is the OS's reason, not reqwest's "error sending request".
        let detail = f.detail.clone().unwrap_or_default();
        assert!(detail.contains("refused"), "{f:?}");

        let dir = tempfile::tempdir().unwrap();
        let socket = format!("unix:{}", dir.path().join("absent.sock").display());
        let api = Api::new(&socket, Some("tdp_valid")).unwrap();
        let f = call(api.client.get_status()).await.unwrap_err();
        assert_eq!(f.title, "Cannot reach the daemon", "{f:?}");
        let detail = f.detail.clone().unwrap_or_default();
        assert!(detail.contains("No such file"), "{f:?}");
    }

    /// A token no header can carry fails before anything is sent, and says
    /// so: it is not a daemon that is down. `config` refuses such a token at
    /// startup; this is what remains if one reached the client anyway.
    #[tokio::test]
    async fn a_request_that_cannot_be_built_is_not_an_unreachable_daemon() {
        let api = Api::new(&closed_port(), Some("tdp_bad\ntoken")).unwrap();
        let f = call(api.client.get_status()).await.unwrap_err();
        assert_eq!(f.title, "The request could not be sent", "{f:?}");
    }

    #[test]
    fn a_new_credential_bumps_the_epoch() {
        let api = Api::new("http://127.0.0.1:9", Some("tdp_a")).unwrap();
        assert_eq!(api.epoch, 0);
        let next = api.with_token("tds_b").unwrap();
        assert_eq!(next.epoch, 1);
        assert!(Api::new("not a url", None).is_err());
        assert!(
            !format!("{api:?}").contains("tdp_a"),
            "the token never prints"
        );
    }

    #[test]
    fn a_unix_url_names_a_socket_by_its_absolute_path_and_survives_a_new_credential() {
        let api = Api::new("unix:/run/torrentd/api.sock", None).unwrap();
        assert_eq!(
            api.base_url, "unix:/run/torrentd/api.sock",
            "shown as given"
        );
        let next = api.with_token("tds_b").unwrap();
        assert_eq!(next.base_url, api.base_url);
        let err = Api::new("unix:run/api.sock", None).unwrap_err();
        assert!(err.contains("absolute path"), "{err}");
    }

    /// A `unix:` client connects to that socket, and writes its requests
    /// against the path with `Host: localhost` and its bearer token.
    #[tokio::test]
    async fn a_unix_url_sends_its_requests_over_that_socket() {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let body = serde_json::to_string(&crate::testing::server(false, false)).unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0_u8; 4096];
            while !received.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0, "the request head ended early");
                received.extend_from_slice(&buf[..n]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                 {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&received).into_owned()
        });

        let api = Api::new(&format!("unix:{}", path.display()), Some("tdp_sock")).unwrap();
        let info = call(api.client.get_server())
            .await
            .expect("served over the socket");
        assert_eq!(info.api_version, "1");

        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(
            request.starts_with("get /v1/server http/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("\r\nhost: localhost\r\n"), "{request}");
        assert!(
            request.contains("\r\nauthorization: bearer tdp_sock\r\n"),
            "{request}"
        );
        assert!(
            request.contains(concat!(
                "\r\nuser-agent: torrentctl/",
                env!("CARGO_PKG_VERSION")
            )),
            "{request}"
        );
        assert!(request.contains("\r\ntraceparent: 00-"), "{request}");
    }

    #[test]
    fn a_traceparent_is_w3c_version_00_sampled_and_fresh_each_time() {
        let first = traceparent();
        let parts: Vec<&str> = first.split('-').collect();
        assert_eq!(parts.len(), 4, "{first}");
        assert_eq!(parts[0], "00");
        assert_eq!(parts[1].len(), 32);
        assert_eq!(parts[2].len(), 16);
        assert_eq!(parts[3], "01");
        assert!(
            parts[1..3].iter().all(|id| id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                && id.bytes().any(|b| b != b'0')),
            "{first}"
        );
        assert_ne!(first, traceparent());
    }

    /// A log that a test reads back.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + use<> {
            let log = self.clone();
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || log.clone())
                .finish()
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    /// Answer `count` requests on a unix socket, each with `X-Request-Id:
    /// req-<n>` and `status`, returning each request's head.
    fn serve(
        listener: tokio::net::UnixListener,
        count: usize,
        status: &'static str,
        body: String,
    ) -> tokio::task::JoinHandle<Vec<String>> {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;
        tokio::spawn(async move {
            let mut heads = Vec::new();
            for n in 0..count {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut received = Vec::new();
                let mut buf = [0_u8; 4096];
                while !received.windows(4).any(|w| w == b"\r\n\r\n") {
                    let read = socket.read(&mut buf).await.unwrap();
                    assert!(read > 0, "the request head ended early");
                    received.extend_from_slice(&buf[..read]);
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nx-request-id: \
                     req-{n}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                heads.push(String::from_utf8_lossy(&received).to_ascii_lowercase());
            }
            heads
        })
    }

    fn header<'a>(head: &'a str, name: &str) -> &'a str {
        head.split("\r\n")
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
            .unwrap_or_else(|| panic!("no {name} in {head}"))
    }

    /// Every request carries its own `traceparent`, and its log line
    /// records that and the daemon's `X-Request-Id`.
    #[tokio::test]
    async fn each_request_carries_a_fresh_traceparent_logged_with_the_daemons_request_id() {
        let log = Captured::default();
        let _subscriber = tracing::subscriber::set_default(log.subscriber());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let body = serde_json::to_string(&crate::testing::server(false, false)).unwrap();
        let server = serve(listener, 2, "200 OK", body);

        let api = Api::new(&format!("unix:{}", path.display()), Some("tdp_sock")).unwrap();
        call(api.client.get_server()).await.expect("the first");
        call(api.client.get_server()).await.expect("the second");
        let heads = server.await.unwrap();

        let sent: Vec<&str> = heads.iter().map(|h| header(h, "traceparent")).collect();
        assert_ne!(sent[0], sent[1], "a fresh traceparent per request");
        let text = log.text();
        for (n, traceparent) in sent.iter().enumerate() {
            let line = text
                .lines()
                .find(|l| l.contains(traceparent))
                .unwrap_or_else(|| panic!("no log line for {traceparent}: {text}"));
            assert!(line.contains(&format!("request_id=\"req-{n}\"")), "{line}");
            assert!(line.contains("path=\"/v1/server\""), "{line}");
            assert!(line.contains("status=200"), "{line}");
            assert!(
                !line.contains("tdp_sock"),
                "the token is never logged: {line}"
            );
        }
    }

    /// A request [`Api::post`] builds is sent the same way: traced, logged,
    /// and on the same socket and credential.
    #[tokio::test]
    async fn a_hand_built_post_is_traced_and_logged_too() {
        let log = Captured::default();
        let _subscriber = tracing::subscriber::set_default(log.subscriber());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = serve(listener, 1, "400 Bad Request", "{}".to_owned());

        let api = Api::new(&format!("unix:{}", path.display()), Some("tdp_sock")).unwrap();
        let response = send(api.post(&["v1", "torrents"]).unwrap().json(&json!({})))
            .await
            .expect("answered");
        assert_eq!(response.status().as_u16(), 400);
        let heads = server.await.unwrap();
        let head = &heads[0];
        assert!(head.starts_with("post /v1/torrents http/1.1\r\n"), "{head}");
        assert_eq!(header(head, "authorization"), "bearer tdp_sock");
        let traceparent = header(head, "traceparent");
        let text = log.text();
        let line = text
            .lines()
            .find(|l| l.contains(traceparent))
            .unwrap_or_else(|| panic!("no log line for {traceparent}: {text}"));
        assert!(line.contains("request_id=\"req-0\""), "{line}");
        assert!(line.contains("status=400"), "{line}");
    }

    /// A request that never reached the daemon is logged with its cause.
    #[tokio::test]
    async fn a_request_that_found_no_daemon_is_logged_with_its_cause() {
        let log = Captured::default();
        let _subscriber = tracing::subscriber::set_default(log.subscriber());
        let api = Api::new(&closed_port(), Some("tdp_valid")).unwrap();
        call(api.client.get_status()).await.unwrap_err();
        let text = log.text();
        assert!(
            text.lines().any(|l| l.contains("request failed")
                && l.contains("traceparent=\"00-")
                && l.contains("refused")),
            "{text}"
        );
    }
}
