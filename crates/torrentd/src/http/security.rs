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
//! The scheme is derived, but its carrier is written by hand
//! (`carrier = manual`). A daemon run with `allow_unauthenticated` has no
//! credentials at all, and kynos' default bearer carrier answers an absent
//! `Authorization` header with a 401 before the authenticator is asked; its
//! `carrier = optional` passes the absence through but records nothing else
//! of the request head, which the unauthenticated posture reads (below).
//! [`Bearer`]'s carrier reports the absence as a [`Presented`] with no token,
//! beside the request's [`Site`], and [`Gate`] decides: anonymous
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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
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
use crate::http::forwarded::TrustedProxies;
use crate::metrics_sink::PromSink;

/// Prefix of every problem `type` URI this API publishes. Each slug is a
/// heading in `docs/api/problems.md`, so the URI resolves to its prose.
///
/// A macro so it can be `concat!`ed into the `const` a scope set's
/// `FORBIDDEN_TYPE` needs; `tests::spec` holds every published `type` to this
/// prefix.
macro_rules! problem_base {
    () => {
        "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#"
    };
}

/// [`problem_base!`], as a value: every error enum names it as its
/// `#[problem(base = …)]`.
pub const PROBLEM_BASE: &str = problem_base!();

/// The bearer scheme. Its carrier is [`Bearer`]'s own `Carries` impl
/// (`carrier = manual`), for the reason the module header gives.
#[derive(kynos::SecurityScheme)]
#[security(bearer)]
#[security(name = "bearer", credential = Caller, scope = Scope, carrier = manual)]
#[security(
    description = "An opaque token in `Authorization: Bearer <token>`. Static tokens (`tdp_…`) \
                   come from `torrentd new-token` and carry the scopes the config grants them; \
                   session tokens (`tds_…`) come from `POST /v1/sessions` and carry `read` and \
                   `write`. Scopes: `read` for every safe operation, `write` for every \
                   operation that changes state (it implies `read`), `metrics` for \
                   `GET /metrics` only."
)]
pub struct Bearer;

/// What the carrier found in the request head.
pub struct Presented {
    /// A syntactically valid bearer token, not yet checked, or `None` where
    /// the request had no `Authorization` header at all; the refusal where
    /// the header was not a well-formed bearer credential, which [`Gate`]
    /// counts before returning it.
    token: Result<Option<carrier::BearerToken>, AuthRejection>,
    /// Where the request says it came from, which only the unauthenticated
    /// posture reads.
    site: Site,
    /// Who sent it, for the log line of a refused token.
    from: Origin,
}

/// The socket peer and the forwarding headers a trusted proxy writes, which
/// [`Gate`] resolves to the client against `trusted_proxies`.
struct Origin {
    peer: Option<std::net::SocketAddr>,
    forwarding: kynos::http::HeaderMap,
}

impl Origin {
    fn of(parts: &Parts) -> Self {
        let connection = parts
            .extensions
            .get::<kynos::extract::connection::Connection>();
        let mut forwarding = kynos::http::HeaderMap::new();
        for name in ["forwarded", "x-forwarded-for", "x-forwarded-proto"] {
            for value in parts.headers.get_all(name) {
                forwarding.append(name, value.clone());
            }
        }
        Self {
            peer: connection.map(|c| c.peer_addr()),
            forwarding,
        }
    }

    fn client(&self, trusted: &TrustedProxies) -> Option<IpAddr> {
        crate::http::forwarded::resolve(self.peer, &self.forwarding, trusted).ip
    }
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
    fn refusal(&self, allowed: &HostAllowlist) -> Option<Refusal> {
        let authority = match self.authority.as_ref().map(HeaderValue::to_str) {
            None => None,
            Some(Ok(authority)) => Some(authority),
            Some(Err(_)) => return Some(Refusal::host("the request authority is not text")),
        };
        let own = match authority {
            None => None,
            Some(authority) => {
                let Some((host, port)) = split_authority(authority) else {
                    return Some(Refusal::host("the request authority does not parse"));
                };
                if !is_loopback_host(&host) && !allowed.contains(&host) {
                    return Some(Refusal::host(
                        "the Host is neither loopback nor in allowed_hosts, as a DNS-rebound \
                         page's would be",
                    ));
                }
                Some((host, port))
            }
        };
        if !self.changes_state {
            return None;
        }
        if let Some(site) = &self.fetch_site {
            if !matches!(site.to_str(), Ok("same-origin" | "none")) {
                return Some(Refusal {
                    label: "sec_fetch_site",
                    reason: "Sec-Fetch-Site says another site sent this request",
                });
            }
        }
        if let Some(origin) = &self.origin {
            let Some(own) = own else {
                return Some(Refusal::origin(
                    "the request names an Origin and no Host to hold it to",
                ));
            };
            let same = origin
                .to_str()
                .ok()
                .and_then(split_origin)
                .is_some_and(|(host, port)| {
                    host == own.0 && own.1.map_or(port.is_default, |p| p == port.number)
                });
            if !same {
                return Some(Refusal::origin("the Origin is not this daemon's own"));
            }
        }
        if let Some(content_type) = &self.content_type {
            let essence = content_type
                .to_str()
                .ok()
                .and_then(|v| v.split(';').next())
                .map(str::trim);
            if !essence.is_some_and(|e| e.eq_ignore_ascii_case("application/json")) {
                return Some(Refusal {
                    label: "content_type",
                    reason: "the body is not application/json, so an HTML form could send it",
                });
            }
        }
        None
    }
}

/// Why a daemon without `[auth]` refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Refusal {
    /// The header that refused it, as `auth_cross_site_refusals_total`'s
    /// `reason` label names it.
    label: &'static str,
    /// The same, for the operator reading the log.
    reason: &'static str,
}

impl Refusal {
    fn host(reason: &'static str) -> Self {
        Self {
            label: "host",
            reason,
        }
    }

    fn origin(reason: &'static str) -> Self {
        Self {
            label: "origin",
            reason,
        }
    }
}

/// How often, at most, a cross-site refusal is logged.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// The cross-site refusal's `warn` line, written at most once per
/// [`REFUSAL_LOG_INTERVAL`].
///
/// Any page the operator has open can loop requests the daemon refuses, and a
/// line for each would let that page fill the log. Every refusal is counted
/// in `auth_cross_site_refusals_total` whether or not it is logged, and each
/// line says how many went unlogged since the one before it.
#[derive(Debug, Default)]
pub struct RefusalLog(parking_lot::Mutex<RefusalLogState>);

#[derive(Debug, Default)]
struct RefusalLogState {
    /// When the last line was written, if one has been.
    last: Option<Instant>,
    /// Refusals since then that were not logged.
    suppressed: u64,
}

impl RefusalLog {
    /// Whether a refusal at `now` is logged, and if so, how many refusals
    /// went unlogged before it.
    fn admit(&self, now: Instant) -> Option<u64> {
        self.0.lock().admit(now)
    }
}

impl RefusalLogState {
    /// As [`RefusalLog::admit`], for the refusals this state paces.
    fn admit(&mut self, now: Instant) -> Option<u64> {
        if !self.due(now) {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }

    fn due(&self, now: Instant) -> bool {
        self.last
            .is_none_or(|at| now.saturating_duration_since(at) >= REFUSAL_LOG_INTERVAL)
    }
}

/// How many clients [`RejectionLog`] paces apart. Past this, a client it
/// has not seen shares one pace with every other such client, so a flood
/// from many addresses costs bounded memory and still bounded log lines.
const REJECTION_LOG_CLIENTS: usize = 1024;

/// The refused token's `warn` line, written at most once per
/// [`REFUSAL_LOG_INTERVAL`] for each client, as [`RefusalLog`] does for all.
///
/// Per client rather than daemon-wide, so that one client looping a dead
/// token does not hide another's line. `None` is a client the daemon could
/// not name, and the shared pace of the overflow.
#[derive(Debug, Default)]
pub struct RejectionLog(parking_lot::Mutex<HashMap<Option<IpAddr>, RefusalLogState>>);

impl RejectionLog {
    /// Whether a refusal from `client` at `now` is logged, and if so, how
    /// many of that client's refusals went unlogged before it.
    fn admit(&self, client: Option<IpAddr>, now: Instant) -> Option<u64> {
        let mut clients = self.0.lock();
        let mut key = client;
        if !clients.contains_key(&key) && clients.len() >= REJECTION_LOG_CLIENTS {
            // A client whose last line is a full interval old would be logged
            // at its next refusal anyway, so its entry is dropped. Refusals it
            // held back go unreported in the line, never uncounted:
            // `auth_rejections_total` has every one. Keeping such entries
            // instead would let one burst from 1024 clients fill the map for
            // good and push every later client onto the overflow's one line.
            clients.retain(|_, state| !state.due(now));
            if clients.len() >= REJECTION_LOG_CLIENTS {
                key = None;
            }
        }
        clients.entry(key).or_default().admit(now)
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

    /// Record who this is on `span`, the request's (`http::headers::
    /// RequestSpan`): `principal` and, for a static token, `token_name`.
    /// Never the token itself.
    fn record_on(&self, span: &tracing::Span) {
        let principal = match self {
            Caller::Anonymous => "anonymous",
            Caller::Session { .. } => "session",
            Caller::Token { name, .. } => {
                span.record("token_name", name.as_str());
                "token"
            }
        };
        span.record("principal", principal);
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

impl kynos::security::Scope for Scope {
    fn name(&self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
            Scope::Metrics => "metrics",
        }
    }
}

impl Carries for Bearer {
    type Presented = Presented;

    fn present(parts: &Parts) -> Result<Option<Presented>, AuthRejection> {
        // A malformed credential is handed to `Gate` rather than refused
        // here, so that its refusal is counted and logged as an unknown
        // token's is. `Gate` refuses it before anything else, whatever the
        // deployment: a client that sent a broken credential is not an
        // anonymous one.
        Ok(Some(Presented {
            token: carrier::bearer(parts),
            site: Site::of(parts),
            from: Origin::of(parts),
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
    type Scope = Scope;
    const REQUIRED: &'static [Scope] = &[Scope::Read];
    const FORBIDDEN_TYPE: Option<&'static str> = Some(INSUFFICIENT_SCOPE);
}

impl Scopes for Write {
    type Scope = Scope;
    const REQUIRED: &'static [Scope] = &[Scope::Write];
    const FORBIDDEN_TYPE: Option<&'static str> = Some(INSUFFICIENT_SCOPE);
}

impl Scopes for Metrics {
    type Scope = Scope;
    const REQUIRED: &'static [Scope] = &[Scope::Metrics];
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
    /// Paces the cross-site refusal's log line; shared by every clone.
    pub refusal_log: Arc<RefusalLog>,
    /// Resolves the client a refused token's log line names and is paced by.
    pub trusted_proxies: TrustedProxies,
    /// Paces the refused token's log line, per client; shared by every clone.
    pub rejection_log: Arc<RejectionLog>,
}

/// Why a bearer credential was refused, as `auth_rejections_total`'s
/// `reason` label names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rejected {
    Malformed,
    Unknown,
    Expired,
}

impl Rejected {
    fn label(self) -> &'static str {
        match self {
            Rejected::Malformed => "malformed",
            Rejected::Unknown => "unknown",
            Rejected::Expired => "expired",
        }
    }
}

impl Gate {
    /// Count a refused credential, and log it where `from`'s client has not
    /// had a line in the last [`REFUSAL_LOG_INTERVAL`].
    ///
    /// A client retrying a dead token — a scraper whose token was rotated
    /// fires one every scrape interval — would otherwise write a line per
    /// request; one per client per minute names it, and the counter has
    /// every one.
    fn reject(&self, reason: Rejected, token: Option<&str>, from: &Origin) {
        self.metrics
            .inc_counter("auth_rejections_total", &[("reason", reason.label())]);
        let client = from.client(&self.trusted_proxies);
        if let Some(unlogged) = self.rejection_log.admit(client, Instant::now()) {
            // The kind, never the token: the prefix says whether a static or
            // a session token stopped working, which is what the operator
            // needs to find the client.
            let token_kind = match token {
                Some(t) if t.starts_with(crate::auth::STATIC_TOKEN_PREFIX) => "static",
                Some(t) if t.starts_with(crate::auth::SESSION_TOKEN_PREFIX) => "session",
                Some(_) => "other",
                None => "none",
            };
            warn!(
                target: "torrentd::auth",
                reason = reason.label(),
                token_kind,
                client_ip = ?client,
                refused_unlogged_since_last = unlogged,
                "refused a request's bearer token; further refusals from this client are \
                 logged at most once a minute and all are counted in auth_rejections_total",
            );
        }
    }
}

impl<C: Sync> Authenticator<Bearer, C> for Gate {
    async fn authenticate(
        &self,
        presented: Presented,
        _context: &C,
    ) -> Result<Caller, AuthRejection> {
        let token = match presented.token {
            Ok(token) => token,
            Err(rejection) => {
                self.reject(Rejected::Malformed, None, &presented.from);
                return Err(rejection);
            }
        };
        let Some(auth) = self.auth.as_ref() else {
            // No `[auth]`: access control belongs to whatever sits in front
            // of the daemon, and the startup posture check has already
            // confined it to loopback. Loopback keeps out the network, not
            // the operator's own browser, so a request a page drove from
            // another site is refused here.
            if let Some(refusal) = presented.site.refusal(&self.allowed_hosts) {
                self.metrics.inc_counter(
                    "auth_cross_site_refusals_total",
                    &[("reason", refusal.label)],
                );
                if let Some(unlogged) = self.refusal_log.admit(Instant::now()) {
                    warn!(
                        target: "torrentd::auth",
                        reason = refusal.reason,
                        host = ?presented.site.authority,
                        origin = ?presented.site.origin,
                        sec_fetch_site = ?presented.site.fetch_site,
                        content_type = ?presented.site.content_type,
                        refused_unlogged_since_last = unlogged,
                        "refused a request a browser sent from another site; further refusals \
                         are logged at most once a minute and all are counted in \
                         auth_cross_site_refusals_total",
                    );
                }
                return Err(AuthRejection::forbidden());
            }
            return Ok(Caller::Anonymous);
        };
        // No credential at all is not a refused one: it is not counted.
        let Some(token) = token else {
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
        // Unknown, expired and revoked all look alike to the caller: telling
        // a caller which it was tells them which tokens once existed. The
        // operator's counter and log line tell them apart.
        let reason = if auth.sessions.is_expired(&token) {
            Rejected::Expired
        } else {
            Rejected::Unknown
        };
        self.reject(reason, Some(&token), &presented.from);
        Err(AuthRejection::unauthenticated())
    }

    async fn authorize(
        &self,
        principal: &Caller,
        scopes: &[Scope],
        _context: &C,
    ) -> Result<(), AuthRejection> {
        principal.record_on(&tracing::Span::current());
        if scopes.iter().all(|&scope| principal.allows(scope)) {
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

/// The check `Scoped<Bearer, R>` makes, run from the request head as an
/// interceptor, so that a caller it refuses is answered before a byte of the
/// body is read.
///
/// An extractor runs only once every interceptor of its group has let the
/// request through, and kynos' `BodySize` reads a body that declares no
/// length whole, frame by frame and with no clock, before it does. Checked
/// only in the handler, the credential let anyone who could reach the API
/// hold a connection with a chunked body that never ends, or have the daemon
/// buffer up to the group's limit — 96 MiB for `POST /v1/torrents` — before
/// it answered `401`. Mounted ahead of the body limit on every group whose
/// operations take a body and need `R`, this refuses them first.
///
/// The handler's own `Scoped` argument still runs, and still declares the
/// `401` and `403` in the document: an operation describes itself before its
/// interceptors do, so what this contributes there is already present. A
/// request it admits is checked twice, which costs a hash and a map lookup;
/// one it refuses never reaches the second check, so a cross-site refusal or
/// a scope denial is counted once.
pub struct Authorized<R>(std::marker::PhantomData<fn() -> R>);

impl<R> Authorized<R> {
    pub const fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

/// What [`Authorized`] answers with: exactly what `Scoped<Bearer, _>` would
/// have, and described as it describes it, so that the document is the same
/// with this mounted or not.
pub struct Refused<R> {
    rejection: AuthRejection,
    _scopes: std::marker::PhantomData<fn() -> R>,
}

impl<R> kynos::response::IntoResponse for Refused<R> {
    fn into_response(self) -> kynos::http::Response {
        self.rejection.into_response()
    }
}

impl<R: Scopes> kynos::response::ShortCircuit for Refused<R> {
    const STATUSES: &'static [u16] = &[401, 403];
}

impl<R: Scopes> kynos::response::Responses for Refused<R> {
    /// `ScopedRejection`'s `401` and `403`, with the `WWW-Authenticate`
    /// challenges the `Scoped` guard declares on them.
    ///
    /// kynos merges an operation's descriptions of one status and keeps a
    /// header `required` only where every description requires it, and
    /// `ScopedRejection`'s own omits the header. Without the challenges here,
    /// every operation this is mounted on would lose `required` on its `401`.
    fn responses(registry: &mut kynos::schema::registry::Registry) -> kynos::openapi::Responses {
        use kynos::openapi::model::schema::types::SchemaType;
        use kynos::openapi::Header;
        use kynos::openapi::RefOr;
        use kynos::openapi::Schema;

        let mut responses =
            <kynos::error::rejection::ScopedRejection<R> as kynos::response::Responses>::responses(
                registry,
            );
        let mut challenge = |status: &str, value: Option<&'static str>, header: Header| {
            if let (Some(value), Some(RefOr::Item(response))) =
                (value, responses.responses.get_mut(status))
            {
                response.headers.insert(
                    "WWW-Authenticate".to_owned(),
                    RefOr::Item(header.with_example(value)),
                );
            }
        };
        // The same two headers, in the same words, as kynos' guard declares.
        challenge(
            "401",
            <Bearer as SecurityScheme>::challenge(),
            Header::new(Schema::of_type(SchemaType::String))
                .required(true)
                .with_description(
                    "The challenge the client must answer, per RFC 9110 section 11.6.1.",
                ),
        );
        challenge(
            "403",
            <Bearer as SecurityScheme>::insufficient_scope_challenge(),
            Header::new(Schema::of_type(SchemaType::String)).with_description(
                "Sent when the credential lacks a required scope, per RFC 6750 section 3.1.",
            ),
        );
        responses
    }
}

impl<R: Scopes<Scope = Scope>> kynos::middleware::Interceptor<crate::http::ctx::AppCtx>
    for Authorized<R>
{
    type Reads = ();
    type Adds = ();
    type Short = Refused<R>;

    async fn intercept(
        &self,
        request: kynos::http::Request,
        (): (),
        context: &crate::http::ctx::AppCtx,
        next: kynos::middleware::Next<'_, crate::http::ctx::AppCtx>,
    ) -> Result<kynos::middleware::Continued<()>, Refused<R>> {
        use kynos::security::requirement::ScopeCheckedBy;

        let refused = |rejection: AuthRejection| Refused {
            // The 401's challenge; a 403 refusing a scope already carries
            // the `insufficient_scope` one `check_scoped` attached.
            rejection: rejection.with_challenge(<Bearer as SecurityScheme>::challenge()),
            _scopes: std::marker::PhantomData,
        };
        let (parts, body) = request.into_parts();
        // The scheme's default scopes joined with `R`'s, as `Scoped`
        // demands them.
        Bearer::check_scoped(&parts, context, R::REQUIRED)
            .await
            .map_err(refused)?
            .ok_or_else(|| refused(AuthRejection::unauthenticated()))?;
        Ok(next
            .run(kynos::http::Request::from_parts(parts, body))
            .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scope names the published document requires are the names an
    /// operator writes in `[[auth.token]] scopes`: each one parses back to
    /// the scope that declared it, and every scope is required somewhere.
    /// A rename on either side alone fails here, rather than as a token the
    /// config refuses or one the document cannot describe.
    #[test]
    fn every_declared_scope_parses() {
        #[derive(serde::Deserialize)]
        struct Granted {
            scopes: Vec<Scope>,
        }
        let parse = |name: &str| -> Scope {
            let granted: Granted = toml::from_str(&format!("scopes = [\"{name}\"]"))
                .unwrap_or_else(|e| panic!("scope {name:?} does not parse: {e}"));
            assert_eq!(granted.scopes.len(), 1);
            granted.scopes[0]
        };
        for scope in [Scope::Read, Scope::Write, Scope::Metrics] {
            let name = kynos::security::Scope::name(&scope);
            assert_eq!(parse(name), scope, "{name}");
        }

        let doc: serde_json::Value =
            serde_json::from_str(&crate::http::document_json().unwrap()).unwrap();
        let mut declared = std::collections::BTreeSet::new();
        for item in doc["paths"].as_object().unwrap().values() {
            for op in item.as_object().unwrap().values() {
                for requirement in op["security"].as_array().into_iter().flatten() {
                    for name in requirement["bearer"].as_array().into_iter().flatten() {
                        declared.insert(name.as_str().unwrap().to_owned());
                    }
                }
            }
        }
        assert_eq!(
            declared.iter().map(|n| parse(n)).collect::<Vec<_>>(),
            vec![Scope::Metrics, Scope::Read, Scope::Write],
            "the document requires every scope, by the name the config takes: {declared:?}",
        );
    }

    #[test]
    fn the_refusal_log_writes_one_line_a_minute_and_counts_the_rest() {
        let log = RefusalLog::default();
        let start = Instant::now();
        assert_eq!(log.admit(start), Some(0), "the first refusal is logged");
        for s in [0, 1, 30, 59] {
            assert_eq!(
                log.admit(start + Duration::from_secs(s)),
                None,
                "{s}s later"
            );
        }
        assert_eq!(
            log.admit(start + REFUSAL_LOG_INTERVAL),
            Some(4),
            "the next line says how many went unlogged"
        );
        assert_eq!(log.admit(start + REFUSAL_LOG_INTERVAL), None);
        assert_eq!(log.admit(start + 3 * REFUSAL_LOG_INTERVAL), Some(1));
    }

    #[test]
    fn the_rejection_log_paces_each_client_apart_and_bounds_how_many_it_holds() {
        let log = RejectionLog::default();
        let start = Instant::now();
        let ip = |n: u32| Some(IpAddr::from(std::net::Ipv4Addr::from(n)));
        assert_eq!(log.admit(ip(1), start), Some(0));
        assert_eq!(log.admit(ip(1), start), None, "the same client, at once");
        assert_eq!(
            log.admit(ip(2), start),
            Some(0),
            "another client is not held off"
        );
        assert_eq!(
            log.admit(ip(1), start + REFUSAL_LOG_INTERVAL),
            Some(1),
            "a minute on, with the one it held back"
        );

        // Full of clients still inside their minute: a new one shares the
        // overflow's pace.
        for n in 3..(REJECTION_LOG_CLIENTS as u32 + 1) {
            log.admit(ip(n), start);
        }
        assert_eq!(log.0.lock().len(), REJECTION_LOG_CLIENTS);
        assert_eq!(
            log.admit(ip(100_000), start),
            Some(0),
            "the overflow's first"
        );
        assert_eq!(log.admit(ip(100_001), start), None, "shares the overflow");
        assert!(log.0.lock().len() <= REJECTION_LOG_CLIENTS + 1);
        // Once their minute is up, the quiet ones make room again.
        let later = start + 2 * REFUSAL_LOG_INTERVAL;
        assert_eq!(log.admit(ip(100_002), later), Some(0));
        assert!(log.0.lock().contains_key(&ip(100_002)), "held on its own");
    }

    #[test]
    fn the_rejection_log_makes_room_once_a_held_back_burst_is_a_minute_old() {
        let log = RejectionLog::default();
        let start = Instant::now();
        let ip = |n: u32| Some(IpAddr::from(std::net::Ipv4Addr::from(n)));
        // One burst fills the map, and every client in it has a refusal held
        // back.
        for n in 0..REJECTION_LOG_CLIENTS as u32 {
            assert_eq!(log.admit(ip(n), start), Some(0));
            assert_eq!(log.admit(ip(n), start), None);
        }
        assert_eq!(log.0.lock().len(), REJECTION_LOG_CLIENTS);
        // A minute on, a new client is paced on its own, not as the overflow.
        let later = start + REFUSAL_LOG_INTERVAL;
        assert_eq!(log.admit(ip(200_000), later), Some(0));
        assert_eq!(log.admit(ip(200_001), later), Some(0), "and so is another");
        let clients = log.0.lock();
        assert!(clients.contains_key(&ip(200_000)), "held on its own");
        assert!(!clients.contains_key(&None), "nothing went to the overflow");
    }
}
