//! Authentication for the HTTP control plane.
//!
//! The API was designed to be bound to loopback behind a reverse proxy. A web
//! client changes that: a browser needs a session, and "put a proxy in front of
//! it" is not a session. So the daemon grows its own.
//!
//! Two credential kinds, deliberately hashed differently:
//!
//! * **The operator password** is chosen by a human, so it is low-entropy and
//!   needs a memory-hard hash. Argon2id, verified once per login.
//! * **API tokens** are 256 bits of randomness this daemon generated, so
//!   brute-forcing the *hash* is not the attack — there is nothing to guess.
//!   A fast SHA-256 is correct here, and matters: Argon2 on every Prometheus
//!   scrape would burn ~50ms of CPU per request by design.
//!
//! Sessions are opaque random ids looked up server-side, so the cookie carries
//! no claims to forge and logout is a real deletion rather than a hope that the
//! client discards it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::PasswordHasher;
use argon2::password_hash::SaltString;
use argon2::Algorithm;
use argon2::Argon2;
use argon2::Params;
use argon2::PasswordHash;
use argon2::PasswordVerifier;
use argon2::Version;
use parking_lot::Mutex;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

pub const SESSION_COOKIE: &str = "torrentd_session";

/// What a credential is allowed to do.
///
/// Deliberately coarse. A finer model invites the mistake of handing a scrape
/// token something it did not need; three levels are enough to keep Prometheus
/// away from the mutation endpoints.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Read-only API access.
    Read,
    /// Everything, including adopting and applying mutation plans.
    Write,
    /// `/metrics` only.
    Metrics,
}

impl Scope {
    /// Whether holding `self` satisfies a requirement for `needed`.
    pub fn allows(self, needed: Scope) -> bool {
        match self {
            // Write implies read; it does not imply metrics, and need not —
            // nothing reads /metrics with a write token.
            Scope::Write => matches!(needed, Scope::Write | Scope::Read),
            Scope::Read => needed == Scope::Read,
            Scope::Metrics => needed == Scope::Metrics,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Argon2id PHC string for the operator password. Generate with
    /// `torrentd --config … hash-password`.
    pub password_hash: String,

    /// How long a browser session stays valid. Default 12 hours.
    #[serde(default = "AuthConfig::default_ttl")]
    pub session_ttl_secs: u64,

    /// Long-lived credentials for scripts and scrapers.
    #[serde(default)]
    pub token: Vec<TokenConfig>,
}

impl AuthConfig {
    fn default_ttl() -> u64 {
        12 * 60 * 60
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if PasswordHash::new(&self.password_hash).is_err() {
            anyhow::bail!(
                "[auth] password_hash is not a valid PHC string; \
                 generate one with `torrentd --config … hash-password`"
            );
        }
        for t in &self.token {
            if t.sha256.len() != 64 || hex::decode(&t.sha256).is_err() {
                anyhow::bail!(
                    "[auth] token {:?}: sha256 must be 64 hex characters",
                    t.name,
                );
            }
            if t.scopes.is_empty() {
                anyhow::bail!("[auth] token {:?}: at least one scope is required", t.name);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    /// Operator-facing label; appears in logs so a leaked token is
    /// identifiable without recording the token itself.
    pub name: String,
    /// Lowercase hex SHA-256 of the token value.
    pub sha256: String,
    pub scopes: Vec<Scope>,
}

/// Live sessions. In memory only: a restart logs everyone out, which for a
/// single-operator daemon is a feature — it needs no session store to keep
/// consistent, and there is nothing on disk to steal.
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn create(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let id = hex::encode(bytes);
        let expiry = Instant::now() + self.ttl;
        let mut g = self.inner.lock();
        // Opportunistic sweep; sessions are few and this keeps a long-running
        // daemon from accumulating expired entries with no separate task.
        let now = Instant::now();
        g.retain(|_, exp| *exp > now);
        g.insert(id.clone(), expiry);
        id
    }

    pub fn is_valid(&self, id: &str) -> bool {
        let g = self.inner.lock();
        g.get(id).is_some_and(|exp| *exp > Instant::now())
    }

    pub fn revoke(&self, id: &str) {
        self.inner.lock().remove(id);
    }

    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.inner.lock().values().filter(|e| **e > now).count()
    }
}

/// Everything the middleware needs. `None` config means auth is disabled.
#[derive(Clone)]
pub struct Auth {
    pub config: Arc<AuthConfig>,
    pub sessions: Arc<SessionStore>,
    /// Throttle for failed password attempts. See [`LoginThrottle`].
    pub throttle: Arc<LoginThrottle>,
}

/// Rate limiter for `POST /api/login`.
///
/// Verifying the operator password runs Argon2id, which is *designed* to cost
/// ~50 ms of CPU. Unauthenticated and unthrottled, that is a free
/// CPU-exhaustion lever for anyone who can reach the port — and the operator
/// password is the one credential here a human chose, so it is also the only
/// one worth guessing.
///
/// Deliberately global rather than per-IP: there is one password, the daemon
/// sits behind a reverse proxy where the peer address is usually the proxy,
/// and a per-IP bucket keyed on a spoofable header is worse than none. The
/// cost is that an attacker can lock the operator out of the login form for
/// the backoff window — an inconvenience against a CPU exhaustion that takes
/// the whole daemon down.
#[derive(Debug)]
pub struct LoginThrottle {
    state: parking_lot::Mutex<ThrottleState>,
    max_burst: u32,
    penalty: Duration,
}

#[derive(Debug)]
struct ThrottleState {
    failures: u32,
    locked_until: Option<Instant>,
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self {
            state: parking_lot::Mutex::new(ThrottleState {
                failures: 0,
                locked_until: None,
            }),
            max_burst: 5,
            penalty: Duration::from_secs(30),
        }
    }

    /// How long the caller must wait, or `None` if an attempt is allowed.
    pub fn retry_after(&self) -> Option<Duration> {
        let mut st = self.state.lock();
        match st.locked_until {
            Some(until) if Instant::now() < until => Some(until - Instant::now()),
            Some(_) => {
                // Window elapsed: allow another burst.
                st.locked_until = None;
                st.failures = 0;
                None
            }
            None => None,
        }
    }

    /// Record a failed attempt, locking out once the burst is spent.
    pub fn note_failure(&self) {
        let mut st = self.state.lock();
        st.failures = st.failures.saturating_add(1);
        if st.failures >= self.max_burst {
            st.locked_until = Some(Instant::now() + self.penalty);
        }
    }

    /// A success clears the record; the credential was not being guessed.
    pub fn note_success(&self) {
        let mut st = self.state.lock();
        st.failures = 0;
        st.locked_until = None;
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never Debug the config: it holds credential material.
        f.debug_struct("Auth")
            .field("sessions", &self.sessions.len())
            .field("tokens", &self.config.token.len())
            .finish()
    }
}

impl Auth {
    pub fn new(config: AuthConfig) -> Self {
        let ttl = Duration::from_secs(config.session_ttl_secs);
        Self {
            config: Arc::new(config),
            sessions: Arc::new(SessionStore::new(ttl)),
            throttle: Arc::new(LoginThrottle::new()),
        }
    }

    /// Verify the operator password against the stored Argon2id hash.
    pub fn verify_password(&self, candidate: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(&self.config.password_hash) else {
            return false;
        };
        // The parameters come from the stored PHC string, not from here, so a
        // hash produced at any other cost still verifies.
        argon2id()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok()
    }

    /// Resolve a bearer token to its scopes, or `None` if unknown.
    pub fn token_scopes(&self, presented: &str) -> Option<(&str, &[Scope])> {
        let digest = Sha256::digest(presented.as_bytes());
        for t in &self.config.token {
            let Ok(expected) = hex::decode(&t.sha256) else {
                continue;
            };
            if ct_eq(&digest, &expected) {
                return Some((t.name.as_str(), t.scopes.as_slice()));
            }
        }
        None
    }
}

/// Constant-time byte comparison.
///
/// The digests being compared are not secret-dependent in a way that makes a
/// timing oracle practical here, but a token lookup is exactly the place where
/// that reasoning ages badly, and the cost is nil.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Memory cost in KiB, iterations, and parallelism for Argon2id here.
///
/// Pinned rather than taken from `Argon2::default()`. These are OWASP's
/// current recommendation for Argon2id and they are also what the `argon2`
/// crate happens to default to at the version `Cargo.lock` holds — which is
/// the problem: `README.md` quotes the numbers, so leaving them at a
/// dependency's discretion made a documented security parameter true by
/// coincidence, and a routine `cargo update` past a release that revised those
/// defaults would move the cost of the credential KDF in either direction with
/// nothing in this repository recording that it had.
///
/// Changing these does not invalidate existing credentials: a PHC string
/// carries the parameters it was produced with, and `verify_password` uses
/// those, not these.
const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// The hasher this daemon hashes and verifies with, at the pinned cost.
fn argon2id() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("pinned Argon2id parameters are in range");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password for the config file.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2id()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))
}

/// Generate a new API token and the hash to put in the config.
pub fn generate_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    (token, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(hash: String) -> AuthConfig {
        AuthConfig {
            password_hash: hash,
            session_ttl_secs: 3600,
            token: vec![],
        }
    }

    #[test]
    fn a_correct_password_verifies_and_a_wrong_one_does_not() {
        let auth = Auth::new(cfg(hash_password("correct horse").unwrap()));
        assert!(auth.verify_password("correct horse"));
        assert!(!auth.verify_password("Correct horse"));
        assert!(!auth.verify_password(""));
        assert!(!auth.verify_password("correct horse "));
    }

    #[test]
    fn the_hash_carries_the_cost_readme_quotes() {
        // README.md's authentication section quotes `m=19456, t=2, p=1`. The
        // numbers were the argon2 crate's defaults and appeared nowhere in
        // this tree, so the documentation was true by coincidence of a
        // dependency. They are pinned now, and this is what holds them to it.
        let h = hash_password("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "got {h}",);
        let parsed = PasswordHash::new(&h).unwrap();
        let params = Params::try_from(&parsed).unwrap();
        assert_eq!(params.m_cost(), ARGON2_M_COST_KIB);
        assert_eq!(params.t_cost(), ARGON2_T_COST);
        assert_eq!(params.p_cost(), ARGON2_P_COST);
    }

    #[test]
    fn a_hash_made_at_another_cost_still_verifies() {
        // The pin decides what new hashes cost; it must not invalidate a
        // credential generated before it, or raising the cost later becomes a
        // lockout rather than an upgrade.
        let cheap = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8 * 1024, 1, 1, None).unwrap(),
        );
        let salt = SaltString::generate(&mut OsRng);
        let h = cheap
            .hash_password(b"correct horse", &salt)
            .unwrap()
            .to_string();
        assert!(h.contains("m=8192,t=1,p=1"), "got {h}");

        let auth = Auth::new(cfg(h));
        assert!(auth.verify_password("correct horse"));
        assert!(!auth.verify_password("wrong horse"));
    }

    #[test]
    fn each_hash_of_the_same_password_is_distinct() {
        // Salted: two operators with the same password must not be visibly
        // identical in the config file.
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
        assert!(Auth::new(cfg(a)).verify_password("same"));
        assert!(Auth::new(cfg(b)).verify_password("same"));
    }

    #[test]
    fn a_malformed_password_hash_never_authenticates() {
        // Fail closed: a corrupt config must not become an open door.
        let auth = Auth::new(cfg("not-a-phc-string".into()));
        assert!(!auth.verify_password("anything"));
        assert!(!auth.verify_password(""));
    }

    #[test]
    fn tokens_resolve_to_their_scopes() {
        let (token, digest) = generate_token();
        let mut c = cfg(hash_password("pw").unwrap());
        c.token.push(TokenConfig {
            name: "prometheus".into(),
            sha256: digest,
            scopes: vec![Scope::Metrics],
        });
        let auth = Auth::new(c);

        let (name, scopes) = auth.token_scopes(&token).expect("token should resolve");
        assert_eq!(name, "prometheus");
        assert_eq!(scopes, &[Scope::Metrics]);
        assert!(auth.token_scopes("0000").is_none());
        assert!(auth.token_scopes("").is_none());
    }

    #[test]
    fn scopes_do_not_leak_into_each_other() {
        assert!(Scope::Write.allows(Scope::Read));
        assert!(Scope::Write.allows(Scope::Write));
        assert!(!Scope::Read.allows(Scope::Write));
        // A scrape token must not reach the API, and an API token has no
        // business on /metrics.
        assert!(!Scope::Metrics.allows(Scope::Read));
        assert!(!Scope::Metrics.allows(Scope::Write));
        assert!(!Scope::Write.allows(Scope::Metrics));
        assert!(!Scope::Read.allows(Scope::Metrics));
    }

    #[test]
    fn sessions_are_unguessable_and_revocable() {
        let s = SessionStore::new(Duration::from_secs(60));
        let a = s.create();
        let b = s.create();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "256 bits of hex");
        assert!(s.is_valid(&a));
        s.revoke(&a);
        assert!(!s.is_valid(&a), "logout must actually invalidate");
        assert!(s.is_valid(&b));
        assert!(!s.is_valid("nonsense"));
    }

    #[test]
    fn expired_sessions_stop_being_valid() {
        let s = SessionStore::new(Duration::from_millis(1));
        let id = s.create();
        std::thread::sleep(Duration::from_millis(20));
        assert!(!s.is_valid(&id));
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn config_validation_rejects_unusable_credentials() {
        let mut c = cfg("garbage".into());
        assert!(c.validate().is_err(), "bad password hash");

        c = cfg(hash_password("pw").unwrap());
        assert!(c.validate().is_ok());

        c.token.push(TokenConfig {
            name: "short".into(),
            sha256: "abcd".into(),
            scopes: vec![Scope::Read],
        });
        assert!(c.validate().is_err(), "token hash must be 64 hex chars");

        c.token[0].sha256 = "z".repeat(64);
        assert!(c.validate().is_err(), "token hash must be hex");

        let (_, digest) = generate_token();
        c.token[0].sha256 = digest;
        c.token[0].scopes.clear();
        assert!(c.validate().is_err(), "a token with no scopes is useless");
    }

    #[test]
    fn ct_eq_matches_ordinary_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn repeated_failures_throttle_the_login_route() {
        // Argon2id is deliberately ~50ms of CPU, so an unthrottled login route
        // is a free CPU-exhaustion lever for an unauthenticated caller.
        let t = LoginThrottle::new();
        assert!(t.retry_after().is_none());
        for _ in 0..4 {
            t.note_failure();
            assert!(t.retry_after().is_none(), "locked out too early");
        }
        t.note_failure();
        assert!(t.retry_after().is_some(), "burst was not capped");
    }

    #[test]
    fn a_successful_login_clears_the_throttle() {
        let t = LoginThrottle::new();
        for _ in 0..5 {
            t.note_failure();
        }
        assert!(t.retry_after().is_some());
        t.note_success();
        assert!(t.retry_after().is_none());
    }
}
