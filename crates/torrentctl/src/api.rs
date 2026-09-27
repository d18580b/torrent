//! The generated `/v1` client, and the one shape its failures take here.

use std::time::Duration;

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

impl<E: AsProblem> From<generated::Error<E>> for Failure {
    fn from(e: generated::Error<E>) -> Self {
        use generated::Error;
        match e {
            Error::Api(response) => {
                let status = response.status().as_u16();
                let request_id = response
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let problem = response.into_inner().problem_json().unwrap_or_default();
                from_problem(status, &problem, request_id)
            }
            Error::UnexpectedStatus {
                status,
                headers,
                body,
            } => {
                let request_id = headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let problem = serde_json::from_slice(&body).unwrap_or_default();
                from_problem(status.as_u16(), &problem, request_id)
            }
            Error::Transport(e) | Error::InterruptedBody(e) => {
                Failure::local("Cannot reach the daemon", Some(e.to_string()))
            }
            Error::Timeout(kind) => {
                Failure::local("The daemon did not answer", Some(format!("{kind:?}")))
            }
            Error::Decode { path, .. } => Failure::local(
                "The daemon's answer did not match the API document",
                Some(format!("at {path}")),
            ),
            // spargen reports a refused connection here, as reqwest's own
            // request-error class, rather than as `Transport` (gap S12). A
            // credential problem is the only other cause this client can
            // produce, so everything else is an unreachable daemon.
            Error::RequestConstruction(
                e @ (generated::RequestError::MissingCredential { .. }
                | generated::RequestError::CredentialProvider { .. }),
            ) => Failure::local("No credential for this request", Some(e.to_string())),
            Error::RequestConstruction(e) => {
                Failure::local("Cannot reach the daemon", Some(root_cause(&e)))
            }
            Error::Protocol(e) => {
                Failure::local("The daemon's answer was malformed", Some(e.to_string()))
            }
            Error::Redirect(e) => Failure::local("Too many redirects", Some(e.to_string())),
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

/// Where the daemon is and how to authenticate to it.
#[derive(Clone)]
pub struct Api {
    pub client: Client,
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

impl Api {
    /// A client for `base_url`, authenticating with `token` when given. Fails
    /// only locally — an unusable URL — so the error is a message.
    pub fn new(base_url: &str, token: Option<&str>) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("torrentctl/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("cannot build the HTTP client: {e}"))?;
        let mut client = Client::with_client(http, base_url)
            .map_err(|e| format!("invalid daemon URL {base_url:?}: {e}"))?;
        if let Some(token) = token {
            client = client.with_credential(
                "bearer",
                generated::Credential::Bearer(generated::SecretString::from(token.to_owned())),
            );
        }
        Ok(Self {
            client,
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
}

/// The bearer presented when no token is configured: see `main`.
pub const ANONYMOUS: &str = "anonymous";

/// Every `/v1` operation that is not a stream is answered within this.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Run a request under [`REQUEST_TIMEOUT`], flattening every failure into a
/// [`Failure`].
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
/// check, applying a plan — with no timeout: the daemon answers when the work
/// is done, and giving up early would report a failure for work that went on.
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
        let other =
            generated::Error::<generated::GetStatusError>::request_message("connection refused");
        let f = Failure::from(other);
        assert_eq!(f.title, "Cannot reach the daemon");
        assert_eq!(f.detail.as_deref(), Some("connection refused"));
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
}
