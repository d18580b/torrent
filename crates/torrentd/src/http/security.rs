//! The one security scheme `/v1` and `/metrics` declare: an opaque bearer
//! token.
//!
//! Two kinds of token reach it, told apart by prefix (see [`crate::auth`]):
//! static tokens from `torrentd new-token` (`tdp_`), each with the scopes the
//! config grants it, and session tokens from `POST /v1/sessions` (`tds_`),
//! which carry `read` and `write` and never `metrics`.
//!
//! Every operation names the scope it needs as a type — [`Read`], [`Write`] or
//! [`Metrics`] — through `Scoped<Bearer, _>`, so the requirement is visible per
//! operation in the published document and checked by the same declaration.
//!
//! The scheme is written by hand rather than derived for one reason: a daemon
//! run with `allow_unauthenticated` has no credentials at all, and kynos'
//! derived bearer carrier answers an absent `Authorization` header with a 401
//! before the authenticator is asked. [`Bearer`]'s carrier instead reports the
//! absence as a [`Presented`] with no token, and [`Gate`] decides: anonymous
//! access where no `[auth]` is configured, a 401 everywhere else. The document
//! still describes the bearer requirement, which is the contract for every
//! deployment that has credentials; `docs/api/README.md` names the exception.
//!
//! Anonymous access is not access for every browser tab. Loopback is not a
//! browser boundary: any page the operator visits can send a form to
//! `127.0.0.1`, and a page whose name rebinds to `127.0.0.1` is same-origin
//! with the API. So without `[auth]`, [`Gate`] also judges the request head
//! the carrier recorded as a [`Site`]: a `Host` that is not loopback or an
//! `allowed_hosts` entry is refused on every operation, and a request that
//! changes state is refused when `Sec-Fetch-Site` or `Origin` says another
//! site sent it, or when it carries a body a plain HTML form can send.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use kynos::error::rejection::AuthRejection;
use kynos::http::HeaderValue;
use kynos::http::Method;
use kynos::http::Parts;
use kynos::security::auth::Scopes;
use kynos::security::carrier;
use kynos::security::carrier::Carries;
use kynos::security::Authenticator;
use kynos::security::SecurityScheme;
use torrentd_engine::MetricsSink;
use tracing::warn;

use crate::auth::Auth;
use crate::auth::Scope;
use crate::metrics_sink::PromSink;

/// Prefix of every problem `type` URI this API publishes. Each slug is a
/// heading in `docs/api/problems.md`, so the URI resolves to its prose.
///
/// A macro so it can be `concat!`ed into the `const` a scope set's
/// `FORBIDDEN_TYPE` needs. `#[problem(base = …)]` takes only a literal, so the
/// error enums spell it out; `tests::spec` holds every published `type` to
/// this prefix.
macro_rules! problem_base {
    () => {
        "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#"
    };
}

/// [`problem_base!`], as a value.
#[cfg(test)]
pub const PROBLEM_BASE: &str = problem_base!();

/// The bearer scheme.
pub struct Bearer;

/// What the carrier found in the request head.
pub struct Presented {
    /// A syntactically valid bearer token, not yet checked, or `None` where
    /// the request had no `Authorization` header at all.
    token: Option<carrier::BearerToken>,
    /// Where the request says it came from, which only the unauthenticated
    /// posture reads.
    site: Site,
}

/// The request-head fields a browser sets and a page cannot forge, as the
/// carrier found them.
pub struct Site {
    /// Anything but `GET`, `HEAD` and `OPTIONS`.
    changes_state: bool,
    /// The request's authority: the URI's where it has one (HTTP/2's
    /// `:authority`, or an absolute-form request line), else `Host`.
    authority: Option<HeaderValue>,
    origin: Option<HeaderValue>,
    fetch_site: Option<HeaderValue>,
    content_type: Option<HeaderValue>,
}

impl Site {
    fn of(parts: &Parts) -> Self {
        let header = |name: &str| parts.headers.get(name).cloned();
        let authority = parts
            .uri
            .authority()
            .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
            .or_else(|| header("host"));
        Self {
            changes_state: !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS),
            authority,
            origin: header("origin"),
            fetch_site: header("sec-fetch-site"),
            content_type: header("content-type"),
        }
    }

    /// Why a daemon without `[auth]` refuses this request, if it does.
    ///
    /// A request with no `Host` is admitted: every browser sends one, so its
    /// absence marks a client no page drives. A request that names no site
    /// and carries no body is admitted for the same reason, which is what
    /// keeps `curl -X POST` and `torrentctl` working unchanged.
    fn refusal(&self, allowed: &HostAllowlist) -> Option<&'static str> {
        let authority = match self.authority.as_ref().map(HeaderValue::to_str) {
            None => None,
            Some(Ok(authority)) => Some(authority),
            Some(Err(_)) => return Some("the request authority is not text"),
        };
        let own = match authority {
            None => None,
            Some(authority) => {
                let Some((host, port)) = split_authority(authority) else {
                    return Some("the request authority does not parse");
                };
                if !is_loopback_host(&host) && !allowed.contains(&host) {
                    return Some(
                        "the Host is neither loopback nor in allowed_hosts, as a DNS-rebound \
                         page's would be",
                    );
                }
                Some((host, port))
            }
        };
        if !self.changes_state {
            return None;
        }
        if let Some(site) = &self.fetch_site {
            if !matches!(site.to_str(), Ok("same-origin" | "none")) {
                return Some("Sec-Fetch-Site says another site sent this request");
            }
        }
        if let Some(origin) = &self.origin {
            let Some(own) = own else {
                return Some("the request names an Origin and no Host to hold it to");
            };
            let same = origin
                .to_str()
                .ok()
                .and_then(split_origin)
                .is_some_and(|(host, port)| {
                    host == own.0 && own.1.map_or(port.is_default, |p| p == port.number)
                });
            if !same {
                return Some("the Origin is not this daemon's own");
            }
        }
        if let Some(content_type) = &self.content_type {
            let essence = content_type
                .to_str()
                .ok()
                .and_then(|v| v.split(';').next())
                .map(str::trim);
            if !essence.is_some_and(|e| e.eq_ignore_ascii_case("application/json")) {
                return Some("the body is not application/json, so an HTML form could send it");
            }
        }
        None
    }
}

/// A port as an `Origin` states it, or as its scheme implies it.
struct OriginPort {
    number: u16,
    /// Whether the scheme implies it, which is when a `Host` may omit it.
    is_default: bool,
}

/// `host[:port]`, the host lowercased and an IPv6 literal's brackets removed.
fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        host.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (host, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if host.is_empty() || !host.chars().all(is_host_char) {
            return None;
        }
        (host, port)
    };
    let port = match port {
        None => None,
        Some(p) => Some(p.parse::<u16>().ok()?),
    };
    Some((normalize_host(host), port))
}

/// An `Origin`'s host and port: `scheme://host[:port]`, nothing after it.
fn split_origin(origin: &str) -> Option<(String, OriginPort)> {
    let (scheme, authority) = origin.split_once("://")?;
    let default = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (host, port) = split_authority(authority)?;
    Some((
        host,
        OriginPort {
            number: port.unwrap_or(default),
            is_default: port.is_none_or(|p| p == default),
        },
    ))
}

/// A character a registered name or an IPv4 address is spelled with.
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')
}

/// Lowercased, without a trailing root dot: `LocalHost.` is `localhost`.
fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// `localhost`, or a loopback address, IPv4-mapped IPv6 included.
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6
            .to_ipv4_mapped()
            .map_or(v6.is_loopback(), |v4| v4.is_loopback()),
        Err(_) => false,
    }
}

/// The host names, beyond loopback, a daemon without `[auth]` answers to:
/// the names a reverse proxy in front of it passes through as `Host`.
#[derive(Clone, Debug, Default)]
pub struct HostAllowlist(Vec<String>);

impl HostAllowlist {
    /// Parse `allowed_hosts`: each entry a host name or IP address, without
    /// a scheme, port or path. Matching ignores case and a trailing dot.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let mut hosts = Vec::with_capacity(entries.len());
        for entry in entries {
            let bracketless = entry
                .strip_prefix('[')
                .and_then(|e| e.strip_suffix(']'))
                .unwrap_or(entry);
            let is_ip = bracketless.parse::<IpAddr>().is_ok();
            let host = normalize_host(bracketless);
            let well_formed = is_ip || (!host.is_empty() && host.chars().all(is_host_char));
            if !well_formed {
                return Err(format!(
                    "{entry:?} is not a host name or IP address; write the name alone, \
                     without a scheme, port or path"
                ));
            }
            hosts.push(host);
        }
        Ok(Self(hosts))
    }

    fn contains(&self, host: &str) -> bool {
        self.0.iter().any(|h| h == host)
    }
}

/// Who a request is, once its token checked out.
#[derive(Clone, Debug)]
pub enum Caller {
    /// No `[auth]` section: the daemon admits everyone.
    Anonymous,
    /// A session token from `POST /v1/sessions`.
    Session {
        /// The token as presented, needed to revoke it.
        token: String,
        expires_at: SystemTime,
    },
    /// A static token from the config.
    Token { name: String, scopes: Vec<Scope> },
}

impl Caller {
    /// The scopes this principal holds, as the API reports them.
    pub fn scopes(&self) -> Vec<Scope> {
        match self {
            Caller::Anonymous => vec![Scope::Read, Scope::Write, Scope::Metrics],
            Caller::Session { .. } => vec![Scope::Read, Scope::Write],
            Caller::Token { scopes, .. } => scopes.clone(),
        }
    }

    fn allows(&self, needed: Scope) -> bool {
        match self {
            Caller::Anonymous => true,
            // A session is the operator at the keyboard: the whole control
            // plane, and nothing a scraper needs.
            Caller::Session { .. } => Scope::Write.allows(needed),
            Caller::Token { scopes, .. } => scopes.iter().any(|s| s.allows(needed)),
        }
    }
}

impl SecurityScheme for Bearer {
    const NAME: &'static str = "bearer";

    type Credential = Caller;

    fn describe() -> kynos::openapi::SecurityScheme {
        let mut scheme = kynos::openapi::SecurityScheme::bearer(None);
        if let kynos::openapi::SecurityScheme::Http { description, .. } = &mut scheme {
            *description = Some(
                "An opaque token in `Authorization: Bearer <token>`. Static tokens (`tdp_…`) \
                 come from `torrentd new-token` and carry the scopes the config grants them; \
                 session tokens (`tds_…`) come from `POST /v1/sessions` and carry `read` and \
                 `write`. Scopes: `read` for every safe operation, `write` for every operation \
                 that changes state (it implies `read`), `metrics` for `GET /metrics` only."
                    .to_owned(),
            );
        }
        scheme
    }

    fn challenge() -> Option<&'static str> {
        Some("Bearer")
    }
}

impl Carries for Bearer {
    type Presented = Presented;

    fn present(parts: &Parts) -> Result<Option<Presented>, AuthRejection> {
        // Malformed stays a 401 whatever the deployment: a client that sent a
        // broken credential is not an anonymous one.
        Ok(Some(Presented {
            token: carrier::bearer(parts)?,
            site: Site::of(parts),
        }))
    }
}

/// `read`: every safe operation.
pub struct Read;
/// `write`: every operation that changes state. Implies `read`.
pub struct Write;
/// `metrics`: `GET /metrics`, and nothing else.
pub struct Metrics;

const INSUFFICIENT_SCOPE: &str = concat!(problem_base!(), "insufficient-scope");

impl Scopes for Read {
    const SCOPES: &'static [&'static str] = &["read"];
    const FORBIDDEN_TYPE: Option<&'static str> = Some(INSUFFICIENT_SCOPE);
}

impl Scopes for Write {
    const SCOPES: &'static [&'static str] = &["write"];
    const FORBIDDEN_TYPE: Option<&'static str> = Some(INSUFFICIENT_SCOPE);
}

impl Scopes for Metrics {
    const SCOPES: &'static [&'static str] = &["metrics"];
    const FORBIDDEN_TYPE: Option<&'static str> = Some(INSUFFICIENT_SCOPE);
}

/// The authenticator: the daemon's `[auth]` configuration, or its absence.
#[derive(Clone)]
pub struct Gate {
    pub auth: Option<Auth>,
    pub metrics: Arc<PromSink>,
    /// `allowed_hosts`: what a daemon without `[auth]` answers to beyond
    /// loopback. Unread where `[auth]` is configured.
    pub allowed_hosts: HostAllowlist,
}

impl<C: Sync> Authenticator<Bearer, C> for Gate {
    async fn authenticate(
        &self,
        presented: Presented,
        _context: &C,
    ) -> Result<Caller, AuthRejection> {
        let Some(auth) = self.auth.as_ref() else {
            // No `[auth]`: access control belongs to whatever sits in front
            // of the daemon, and the startup posture check has already
            // confined it to loopback. Loopback keeps out the network, not
            // the operator's own browser, so a request a page drove from
            // another site is refused here.
            if let Some(reason) = presented.site.refusal(&self.allowed_hosts) {
                warn!(
                    target: "torrentd::auth",
                    reason,
                    host = ?presented.site.authority,
                    origin = ?presented.site.origin,
                    sec_fetch_site = ?presented.site.fetch_site,
                    "refused a request a browser sent from another site",
                );
                return Err(AuthRejection::forbidden());
            }
            return Ok(Caller::Anonymous);
        };
        let Some(token) = presented.token else {
            return Err(AuthRejection::unauthenticated());
        };
        let token = token.into_inner();
        if let Some(expires_at) = auth.sessions.expiry(&token) {
            return Ok(Caller::Session { token, expires_at });
        }
        if let Some((name, scopes)) = auth.token_scopes(&token) {
            return Ok(Caller::Token {
                name: name.to_owned(),
                scopes: scopes.to_vec(),
            });
        }
        // Unknown, expired and revoked all look alike: telling a caller which
        // it was tells them which tokens once existed.
        Err(AuthRejection::unauthenticated())
    }

    async fn authorize(
        &self,
        principal: &Caller,
        scopes: &'static [&'static str],
        _context: &C,
    ) -> Result<(), AuthRejection> {
        let needed = scopes.iter().filter_map(|s| Scope::parse(s));
        let mut denied = false;
        for scope in needed {
            if !principal.allows(scope) {
                denied = true;
            }
        }
        if !denied {
            return Ok(());
        }
        if let Caller::Token { name, .. } = principal {
            warn!(
                target: "torrentd::auth",
                token_name = %name,
                "token presented without the required scope",
            );
            // A valid credential used for something it was not issued for:
            // a misconfigured client at best, a leaked scrape token probing
            // the API at worst.
            self.metrics
                .inc_counter("auth_token_scope_denials_total", &[]);
        }
        Err(AuthRejection::forbidden_as(INSUFFICIENT_SCOPE))
    }
}
