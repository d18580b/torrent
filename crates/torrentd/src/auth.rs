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
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::PasswordHasher;
use argon2::password_hash::SaltString;
use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordVerifier;
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
/// Buckets are keyed per client where the client can be *established*, and
/// share one global bucket where it cannot. The distinction matters because
/// of what the alternatives cost:
///
/// * A global bucket alone means anyone who can reach the port can lock the
///   operator out of the login form indefinitely, by failing five times every
///   thirty seconds forever. That was the accepted trade-off while no client
///   address was knowable.
/// * A per-IP bucket keyed on a header anyone can set is worse than none: an
///   attacker simply varies the header and is never throttled.
///
/// So a per-IP bucket is used exactly when the address came from the socket
/// or from a proxy in `trusted_proxies`, and the global bucket when no address
/// could be established at all, or when the per-client map is full and the
/// sweep could not make room for one more.
///
/// Note that this is *not* the previous behaviour with no trusted proxies
/// configured. The socket peer is an address, so the empty default now keys
/// per source IP rather than sharing one bucket. That is the better property —
/// one attacker can no longer lock every operator out — and both overflow
/// paths degrade to the shared bucket rather than to no throttle at all.
#[derive(Debug)]
pub struct LoginThrottle {
    /// The fallback, for requests whose client cannot be established.
    global: Mutex<ThrottleState>,
    /// Per client. Bounded, and swept of entries idle beyond the penalty
    /// window on insert, so a rotating source cannot grow it without limit.
    per_client: Mutex<HashMap<IpAddr, ThrottleState>>,
    max_burst: u32,
    penalty: Duration,
}

/// Cap on distinct clients tracked at once. A real deployment has a handful of
/// operators; a source rotating addresses reaches this cap, and from there the
/// sweep reclaims whatever has gone idle and the global bucket covers whoever
/// the sweep could not make room for.
const MAX_TRACKED_CLIENTS: usize = 1024;

#[derive(Debug)]
struct ThrottleState {
    failures: u32,
    locked_until: Option<Instant>,
    /// When this entry was last read or written. Liveness has to be a time
    /// question: `failures` never decays, so an entry that has one is live
    /// forever, and every entry the throttle creates has one from its first
    /// call.
    last_seen: Instant,
}

impl Default for ThrottleState {
    fn default() -> Self {
        Self {
            failures: 0,
            locked_until: None,
            last_seen: Instant::now(),
        }
    }
}

impl ThrottleState {
    /// How long the caller must wait, or `None` if an attempt is allowed.
    fn retry_after(&mut self) -> Option<Duration> {
        self.last_seen = Instant::now();
        match self.locked_until {
            Some(until) if Instant::now() < until => Some(until - Instant::now()),
            Some(_) => {
                // Window elapsed: allow another burst.
                self.locked_until = None;
                self.failures = 0;
                None
            }
            None => None,
        }
    }

    fn note_failure(&mut self, max_burst: u32, penalty: Duration) {
        self.last_seen = Instant::now();
        self.failures = self.failures.saturating_add(1);
        if self.failures >= max_burst {
            self.locked_until = Some(Instant::now() + penalty);
        }
    }

    /// Whether this entry is worth keeping: it is still locking someone out,
    /// or it has been touched within `idle`.
    ///
    /// Not `failures > 0`. Nothing decays `failures`, and `note_failure`
    /// increments it on the first call, so that disjunct is true for every
    /// entry the throttle ever creates and the sweep can never reclaim
    /// anything — least of all in the case it exists for, a source that
    /// rotates addresses and by definition never revisits a key.
    fn is_live(&self, idle: Duration) -> bool {
        self.locked_until.is_some_and(|u| u > Instant::now()) || self.last_seen.elapsed() < idle
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self {
            global: Mutex::new(ThrottleState::default()),
            per_client: Mutex::new(HashMap::new()),
            max_burst: 5,
            penalty: Duration::from_secs(30),
        }
    }

    /// The same throttle with a shorter penalty, so a test can observe the
    /// idle sweep without sleeping for the production window.
    #[cfg(test)]
    fn with_penalty(penalty: Duration) -> Self {
        Self {
            penalty,
            ..Self::new()
        }
    }

    /// How long `client` must wait, or `None` if an attempt is allowed.
    ///
    /// The read path has to mirror the write path exactly. `note_failure`
    /// routes an identified client with no bucket of its own to the global
    /// bucket once the map is full, so this consults the global bucket in the
    /// same case. Returning `None` there instead would mean that filling the
    /// map — 1024 requests from 1024 addresses, which one routed IPv6 /64
    /// supplies — leaves every address after it permanently unthrottled, and
    /// an unthrottled login route is a free CPU-exhaustion lever for an
    /// unauthenticated caller.
    pub fn retry_after(&self, client: Option<IpAddr>) -> Option<Duration> {
        let Some(ip) = client else {
            return self.global.lock().retry_after();
        };
        let mut g = self.per_client.lock();
        if let Some(state) = g.get_mut(&ip) {
            return state.retry_after();
        }
        if g.len() >= MAX_TRACKED_CLIENTS {
            drop(g);
            return self.global.lock().retry_after();
        }
        None
    }

    /// Record a failed attempt, locking out once the burst is spent.
    pub fn note_failure(&self, client: Option<IpAddr>) {
        let Some(ip) = client else {
            self.global
                .lock()
                .note_failure(self.max_burst, self.penalty);
            return;
        };
        let mut g = self.per_client.lock();
        if g.len() >= MAX_TRACKED_CLIENTS && !g.contains_key(&ip) {
            g.retain(|_, st| st.is_live(self.penalty));
            // Still full of live entries: fall back to the global bucket
            // rather than letting the map grow, since an attack that fills it
            // is exactly when throttling has to keep working.
            if g.len() >= MAX_TRACKED_CLIENTS {
                drop(g);
                self.global
                    .lock()
                    .note_failure(self.max_burst, self.penalty);
                return;
            }
        }
        g.entry(ip)
            .or_default()
            .note_failure(self.max_burst, self.penalty);
    }

    /// A success clears the record; the credential was not being guessed.
    pub fn note_success(&self, client: Option<IpAddr>) {
        match client {
            None => *self.global.lock() = ThrottleState::default(),
            Some(ip) => {
                self.per_client.lock().remove(&ip);
            }
        }
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
        Argon2::default()
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

/// Hash a password for the config file.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
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
        assert!(t.retry_after(None).is_none());
        for _ in 0..4 {
            t.note_failure(None);
            assert!(t.retry_after(None).is_none(), "locked out too early");
        }
        t.note_failure(None);
        assert!(t.retry_after(None).is_some(), "burst was not capped");
    }

    #[test]
    fn a_successful_login_clears_the_throttle() {
        let t = LoginThrottle::new();
        for _ in 0..5 {
            t.note_failure(None);
        }
        assert!(t.retry_after(None).is_some());
        t.note_success(None);
        assert!(t.retry_after(None).is_none());
    }

    fn ip(n: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, n)))
    }

    #[test]
    fn one_clients_failures_do_not_lock_out_another() {
        // The reason to key per client at all: with a single global bucket,
        // anyone who can reach the port can keep the operator out of the login
        // form indefinitely by failing five times every thirty seconds.
        let t = LoginThrottle::new();
        for _ in 0..5 {
            t.note_failure(ip(1));
        }
        assert!(t.retry_after(ip(1)).is_some(), "the offender is locked out");
        assert!(
            t.retry_after(ip(2)).is_none(),
            "an unrelated client must still be able to log in",
        );
    }

    #[test]
    fn an_unidentifiable_client_falls_back_to_the_shared_bucket() {
        // With no trusted proxy configured and no peer address, there is
        // nothing to key on — and a throttle that cannot key is still better
        // than none, because the CPU cost it exists to bound is real.
        let t = LoginThrottle::new();
        for _ in 0..5 {
            t.note_failure(None);
        }
        assert!(t.retry_after(None).is_some());
        assert!(
            t.retry_after(ip(1)).is_none(),
            "the shared bucket must not leak into an identified client",
        );
    }

    #[test]
    fn a_rotating_client_cannot_grow_the_map_without_bound() {
        let t = LoginThrottle::new();
        for n in 0..(MAX_TRACKED_CLIENTS + 64) {
            let a = std::net::Ipv4Addr::from(n as u32);
            t.note_failure(Some(IpAddr::V4(a)));
        }
        assert!(
            t.per_client.lock().len() <= MAX_TRACKED_CLIENTS,
            "tracked clients must stay bounded",
        );
    }

    #[test]
    fn the_sweep_reclaims_a_client_that_never_came_back() {
        // The sweep exists for the rotating source, and the rotating source is
        // exactly the caller it could never reclaim while liveness was
        // `failures > 0`: every entry it creates has `failures == 1`, nothing
        // decays it, and rotating means never revisiting a key to reset it.
        let t = LoginThrottle::with_penalty(Duration::from_millis(10));
        for n in 0..MAX_TRACKED_CLIENTS {
            t.note_failure(Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32))));
        }
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);

        std::thread::sleep(Duration::from_millis(40));
        // The next unknown client is what triggers a sweep on insert.
        t.note_failure(ip(1));
        assert!(
            t.per_client.lock().len() < MAX_TRACKED_CLIENTS,
            "an entry idle beyond the penalty window must be evictable",
        );
    }

    #[test]
    fn a_rotating_client_is_still_throttled_once_the_map_is_full() {
        // The property that matters is not that the map stayed small, it is
        // that filling the map is not a way to stop being throttled. Once it
        // is full `note_failure` routes an unknown client's failures to the
        // global bucket, so `retry_after` has to read that same bucket for the
        // same client — otherwise 1024 addresses buy every address after them
        // unlimited Argon2id verifications and unlimited password guessing.
        let t = LoginThrottle::new();
        for n in 0..MAX_TRACKED_CLIENTS {
            t.note_failure(Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32))));
        }
        assert_eq!(
            t.per_client.lock().len(),
            MAX_TRACKED_CLIENTS,
            "the map has to be full for this test to be testing anything",
        );

        // Addresses the map has never seen, arriving one apiece — the shape of
        // the attack, where rotating means never revisiting a key.
        let fresh = |n: u32| Some(IpAddr::V4(std::net::Ipv4Addr::from(0xc000_0000 + n)));
        for n in 0..5 {
            assert!(
                t.retry_after(fresh(n)).is_none(),
                "the first burst is still allowed",
            );
            t.note_failure(fresh(n));
        }
        assert!(
            t.retry_after(fresh(99)).is_some(),
            "a rotating client must still be throttled once the map is full",
        );
    }

    #[test]
    fn success_clears_only_that_client() {
        let t = LoginThrottle::new();
        for _ in 0..5 {
            t.note_failure(ip(1));
        }
        for _ in 0..5 {
            t.note_failure(ip(2));
        }
        t.note_success(ip(1));
        assert!(t.retry_after(ip(1)).is_none());
        assert!(t.retry_after(ip(2)).is_some());
    }
}
