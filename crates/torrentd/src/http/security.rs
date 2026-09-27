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
//! absence as [`Presented::Absent`], and [`Gate`] decides: anonymous access
//! where no `[auth]` is configured, a 401 everywhere else. The document still
//! describes the bearer requirement, which is the contract for every deployment
//! that has credentials; `docs/api/README.md` names the exception.

use std::sync::Arc;
use std::time::SystemTime;

use kynos::error::rejection::AuthRejection;
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
pub enum Presented {
    /// No `Authorization` header at all.
    Absent,
    /// A syntactically valid bearer token, not yet checked.
    Token(carrier::BearerToken),
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
        Ok(Some(match carrier::bearer(parts)? {
            Some(token) => Presented::Token(token),
            None => Presented::Absent,
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
            // confined it to loopback.
            return Ok(Caller::Anonymous);
        };
        let Presented::Token(token) = presented else {
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
