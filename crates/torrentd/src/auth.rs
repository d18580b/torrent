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
/// per source IP rather than sharing one bucket. That removes the *single*
/// shared bucket, and both overflow paths degrade to a shared bucket rather
/// than to no throttle at all.
///
/// Per-client buckets alone multiply the rate the daemon verifies at by the
/// number of addresses a caller holds: 1024 tracked clients at five attempts
/// per thirty seconds each is ~170 Argon2id runs a second, ~8.5 CPU-seconds
/// every second on the async workers, and a guessing rate ~1000 times the one
/// the single global bucket allowed. One routed IPv6 /64 supplies those
/// addresses. So every verification, whichever bucket admitted it, also
/// spends from one daemon-wide budget ([`KdfBudget`]), and when that is spent
/// the route answers 429 without running the KDF. The per-client buckets
/// decide *who* is throttled below that ceiling; the ceiling alone bounds how
/// much Argon2 the route can be made to run and how fast the password can be
/// guessed, however many addresses the caller has.
///
/// It does not make locking every operator out impossible, and nothing here
/// should be read as claiming it does. A caller with enough distinct source
/// addresses can spend the daemon-wide budget, and while they keep it spent
/// every login — the operator's included — is refused, which is the old
/// global bucket's lockout. The same budget bounds the per-client map: an
/// entry is created only by a verification the budget admitted and stays
/// live for a penalty window after its last one, so at the production
/// constants a few dozen entries at most are live at once, far short of
/// [`MAX_TRACKED_CLIENTS`]. Neither costs the caller more than sending requests:
/// the ~50 ms of Argon2 each failed attempt takes is spent by *this* process,
/// not by whoever sent it, so it is a cost to bound rather than a price the
/// attacker pays. What the per-client key buys is that a caller with one
/// address, or a few, no longer locks everyone else out.
#[derive(Debug)]
pub struct LoginThrottle {
    /// The fallback, for requests whose client cannot be established.
    global: Mutex<ThrottleState>,
    /// Per client. Bounded, and swept of entries idle beyond the penalty
    /// window on insert, so a rotating source cannot grow it without limit.
    per_client: Mutex<HashMap<IpAddr, ThrottleState>>,
    /// The daemon-wide ceiling on password verifications, across every
    /// bucket above.
    kdf: Mutex<KdfBudget>,
    max_burst: u32,
    penalty: Duration,
}

/// The most password verifications the daemon runs back to back before the
/// budget has to refill.
const KDF_BURST: u32 = 10;

/// How long the budget takes to regain one verification. With [`KDF_BURST`]
/// that is at most ten verifications in any thirty seconds once the burst is
/// spent — twice the old global bucket's five failures per thirty seconds,
/// and well under 1% of one core at ~50 ms each.
const KDF_REFILL: Duration = Duration::from_secs(3);

/// A token bucket over Argon2id runs, shared by every client.
///
/// Charged for every verification, successful or not: a correct password
/// costs the same CPU as a wrong one, and a ceiling that only counted
/// failures would let a caller holding the password keep the KDF busy.
#[derive(Debug)]
struct KdfBudget {
    tokens: u32,
    /// When the next token accrues, measured from the last refill.
    refilled_at: Instant,
    burst: u32,
    refill: Duration,
}

impl KdfBudget {
    fn new(burst: u32, refill: Duration) -> Self {
        Self {
            tokens: burst,
            refilled_at: Instant::now(),
            burst,
            refill,
        }
    }

    /// Take one verification, or say how long until one is available.
    fn take(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.refilled_at);
        let accrued = (elapsed.as_nanos() / self.refill.as_nanos().max(1)) as u64;
        if accrued > 0 {
            let room = u64::from(self.burst - self.tokens);
            self.tokens += accrued.min(room) as u32;
            self.refilled_at = if self.tokens == self.burst {
                now
            } else {
                // Keep the fraction of a refill interval already served.
                self.refilled_at + self.refill * accrued as u32
            };
        }
        if self.tokens > 0 {
            if self.tokens == self.burst {
                // A full bucket accrues nothing, so its refill clock starts
                // from the first token taken out of it.
                self.refilled_at = now;
            }
            self.tokens -= 1;
            Ok(())
        } else {
            Err((self.refilled_at + self.refill).saturating_duration_since(now))
        }
    }
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
    ///
    /// Deliberately **not** a liveness touch. This is a consult, and a
    /// consult is not an attempt: the throttle is asked before the request
    /// body has been read, so a request that never becomes an attempt — one
    /// whose body is unparseable, or larger than the cap — reaches here and
    /// then ends in a 400. Refreshing `last_seen` on the way made that 400 a
    /// way to hold a map entry alive at **zero** KDF cost, and the map is
    /// bounded, so holding every entry alive is what pushes every other
    /// client onto the shared bucket.
    ///
    /// Measured: 1024 real failed logins took 31.6 s of Argon2 to create
    /// 1024 entries, and a full pass refreshing all 1024 with an unparseable
    /// body took **0.07 s**. `note_failure` and `note_success` are where an
    /// attempt is recorded, and both touch `last_seen`, so an entry that is
    /// being used is still live.
    fn retry_after(&mut self) -> Option<Duration> {
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
            kdf: Mutex::new(KdfBudget::new(KDF_BURST, KDF_REFILL)),
            max_burst: 5,
            penalty: Duration::from_secs(30),
        }
    }

    /// The same throttle with a shorter penalty, so a test can observe the
    /// idle sweep without sleeping for the production window. The
    /// daemon-wide budget is lifted out of the way: these tests drive the
    /// per-client buckets and never run the KDF.
    #[cfg(test)]
    fn with_penalty(penalty: Duration) -> Self {
        Self {
            penalty,
            kdf: Mutex::new(KdfBudget::new(u32::MAX, Duration::from_nanos(1))),
            ..Self::new()
        }
    }

    /// The same throttle with a daemon-wide budget a test can exhaust and
    /// watch refill.
    #[cfg(test)]
    pub(crate) fn with_kdf_budget(burst: u32, refill: Duration) -> Self {
        Self {
            kdf: Mutex::new(KdfBudget::new(burst, refill)),
            ..Self::new()
        }
    }

    /// Spend one password verification from the daemon-wide budget, or say
    /// how long until one is available.
    ///
    /// Called immediately before the KDF runs and after every per-client
    /// check has passed, so a request refused anywhere earlier — by its
    /// media type, its bucket, or an unparseable body — never spends from it.
    /// Unlike [`Self::retry_after`] this is not keyed at all: it is the
    /// ceiling that holds however many addresses the attempts arrive from.
    pub fn admit_verification(&self) -> Result<(), Duration> {
        self.kdf.lock().take()
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
    ///
    /// Clearing is **replacement, never removal**, and that holds on both
    /// paths. For a client the map already holds, removing the key is how a
    /// client that has just authenticated correctly *loses* the slot the
    /// paragraph below exists to give it: an operator who mistyped a password
    /// once is in the map, and if their successful login deletes their entry
    /// then their next consult finds no key, reads `global` because the map
    /// is full, and is locked out by the next failure from anyone else on the
    /// overflow path. Demonstrated end to end: with the map full, an operator
    /// in it authenticated correctly, six never-seen addresses then failed
    /// once each, and the operator's next correct password returned 429.
    ///
    /// For an identified client the map does not hold, clearing means
    /// *inserting* a cleared entry rather than removing nothing. Once the map
    /// is full `note_failure` routes that client's failures to `global` and
    /// `retry_after` reads `global` back for it, so without a slot of its own
    /// a client that has just authenticated correctly is locked out by the
    /// next failure from anyone else on the overflow path — immediately after
    /// proving it is not the attacker who filled the map. Where the map is
    /// full the entry evicted to make room is the least recently seen one
    /// that is **not** currently locked out — evicting a locked entry would
    /// clear that client's lockout, which is the one thing the sweep above
    /// deliberately preserves. Where every entry is locked, nothing is
    /// inserted and this client stays on the overflow path until a slot
    /// frees.
    ///
    /// `global` itself is **not** cleared. A caller holding one valid
    /// credential could otherwise wipe the shared bucket between guesses at
    /// another and never trip the lockout, which is a bypass rather than a
    /// repair.
    pub fn note_success(&self, client: Option<IpAddr>) {
        let Some(ip) = client else {
            *self.global.lock() = ThrottleState::default();
            return;
        };
        let mut g = self.per_client.lock();
        if let Some(state) = g.get_mut(&ip) {
            // Replaced in place. `remove` would clear the record by
            // surrendering the slot, which is the one thing a success must
            // not cost the client that earned it.
            *state = ThrottleState::default();
            return;
        }
        if g.len() >= MAX_TRACKED_CLIENTS {
            g.retain(|_, st| st.is_live(self.penalty));
        }
        if g.len() >= MAX_TRACKED_CLIENTS {
            // Never a locked one. `retain(is_live)` one line above deliberately
            // keeps entries that are still locking someone out; picking the
            // stalest by `last_seen` alone would then delete exactly what that
            // line took care to preserve, and deleting a locked entry *clears
            // that client's lockout*. Making room for a client who has just
            // authenticated must not hand someone else their burst back.
            let now = Instant::now();
            let stalest = g
                .iter()
                .filter(|(_, st)| st.locked_until.is_none_or(|u| u <= now))
                .min_by_key(|(_, st)| st.last_seen)
                .map(|(addr, _)| *addr);
            match stalest {
                Some(addr) => {
                    g.remove(&addr);
                }
                // Every tracked entry is locked out. There is nothing to
                // discard that would not clear a live lockout, so no insertion
                // is made and this client keeps the overflow path — the global
                // bucket — until a slot frees. That is the same degradation
                // the map's own capacity limit already has, and it lasts as
                // long as the entries holding the map do: an entry stays live
                // while it is locked, and beyond that only while something
                // keeps touching it. Since a consult is no longer a touch,
                // holding one takes a real failed attempt per entry per
                // penalty window — an attempt the daemon-wide KDF budget
                // admits — rather than the penalty window being a bound
                // anyone gets for a malformed body.
                None => return,
            }
        }
        g.insert(ip, ThrottleState::default());
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
/// Pinned rather than taken from `Argon2::default()`. They are what the
/// `argon2` crate happens to default to at the version `Cargo.lock` holds —
/// which is the problem: `README.md` quotes the numbers, so leaving them at a
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
    fn a_consult_that_never_becomes_an_attempt_cannot_hold_the_map_open() {
        // The property: `retry_after` is a consult, not an attempt, and only
        // an attempt keeps a tracked entry alive.
        //
        // The throttle is asked before the login body is read, so a request
        // with an unparseable body reaches the consult and then ends in a 400
        // having done no Argon2 work at all. While that consult refreshed
        // `last_seen`, the 400 was a free way to hold an entry live — and
        // holding all 1024 live means the sweep reclaims nothing and every
        // other client is routed to the shared bucket. Measured against a
        // live daemon: 31.6 s of Argon2 to create the entries, 0.07 s per
        // full pass to keep them.
        let penalty = Duration::from_millis(50);
        let t = LoginThrottle::with_penalty(penalty);
        for n in 0..MAX_TRACKED_CLIENTS {
            t.note_failure(Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32))));
        }
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);

        // Idle past the window, then consult every entry — the refresh pass
        // an attacker gets for the price of a malformed body.
        std::thread::sleep(Duration::from_millis(150));
        for n in 0..MAX_TRACKED_CLIENTS {
            let addr = Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32)));
            assert!(
                t.retry_after(addr).is_none(),
                "none of these is locked out; the consult is the whole point",
            );
        }

        // A never-seen client now fails once. The insert sweeps, and what the
        // sweep finds decides whether this client gets a slot of its own or
        // the shared bucket.
        let newcomer = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        t.note_failure(Some(newcomer));
        assert!(
            t.per_client.lock().contains_key(&newcomer),
            "entries touched only by consults have gone idle and the sweep \
             reclaims them, so a client arriving afterwards is tracked rather \
             than pushed onto the shared bucket",
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
    fn a_success_from_an_overflow_client_is_not_undone_by_someone_else() {
        // With the map full, this client's failures went to the shared bucket
        // and `retry_after` reads that same bucket back for it. Removing an
        // absent key clears nothing, so without a slot of its own the operator
        // authenticates correctly and is then locked out by the next failure
        // from anyone else on the overflow path — the attacker who filled the
        // map in the first place.
        let t = LoginThrottle::new();
        for n in 0..MAX_TRACKED_CLIENTS {
            t.note_failure(Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32))));
        }
        assert_eq!(
            t.per_client.lock().len(),
            MAX_TRACKED_CLIENTS,
            "the map has to be full for this test to be testing anything",
        );

        // Neither address is in the map: both are on the overflow path.
        let operator = ip(1);
        let other = ip(2);
        for _ in 0..4 {
            t.note_failure(operator);
        }
        t.note_success(operator);

        // The fifth failure on the shared path trips its lockout.
        t.note_failure(other);
        assert!(
            t.retry_after(other).is_some(),
            "the shared bucket must still lock out the overflow path",
        );
        assert!(
            t.retry_after(operator).is_none(),
            "a client that has just authenticated must not be locked out by \
             another client's failure on the shared path",
        );
    }

    #[test]
    fn a_success_from_a_client_the_map_holds_keeps_its_slot() {
        // The other half of the same property, and the half the repair above
        // did not reach: the client whose entry the map **already holds**.
        //
        // An operator who mistypes a password once is in the map. Removing
        // their entry on a successful login hands the slot back at the exact
        // moment they proved they are not the attacker — and with the map
        // full, `retry_after` then routes them to the shared bucket, where
        // the next failure from anyone else on the overflow path locks them
        // out. Clearing the record must not cost the record's owner its slot.
        let t = LoginThrottle::new();
        for n in 0..MAX_TRACKED_CLIENTS {
            t.note_failure(Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32))));
        }
        let operator = IpAddr::V4(std::net::Ipv4Addr::from(0u32));
        assert_eq!(
            t.per_client.lock().len(),
            MAX_TRACKED_CLIENTS,
            "the map has to be full for this test to be testing anything",
        );
        assert!(
            t.per_client.lock().contains_key(&operator),
            "and the operator has to be in it",
        );

        t.note_success(Some(operator));

        assert!(
            t.per_client.lock().contains_key(&operator),
            "a success clears the record without surrendering the slot",
        );
        assert_eq!(
            t.per_client.lock().len(),
            MAX_TRACKED_CLIENTS,
            "and does not free capacity for whoever filled the map",
        );

        // The consequence, which is what makes the slot worth holding. Six
        // never-seen addresses fail once each; with the map full they are on
        // the overflow path and the shared bucket locks out after five.
        for n in 0..6u32 {
            t.note_failure(Some(IpAddr::V4(std::net::Ipv4Addr::new(
                198,
                51,
                100,
                n as u8 + 1,
            ))));
        }
        assert!(
            t.retry_after(Some(operator)).is_none(),
            "the operator has a slot of its own, so another client's failures \
             on the shared bucket cannot lock it out moments after it \
             authenticated",
        );
    }

    #[test]
    fn making_room_for_a_successful_client_never_clears_a_live_lockout() {
        // The property: the entry `note_success` evicts to make room is the
        // least recently seen one that is *not* locked out.
        //
        // `retain(is_live)` keeps a locked entry on purpose. A `min_by_key` on
        // `last_seen` alone ignores `locked_until`, so the line that makes
        // room can delete exactly what the line above it preserved — and
        // deleting a locked entry clears that client's lockout. An attacker
        // who holds one valid credential can then free a locked victim, or
        // free themselves, by authenticating from an address the map does not
        // hold.
        let t = LoginThrottle::new();

        // Fill the map with entries that are all locked out. `0.0.0.x` here
        // cannot collide with the `198.51.100.n` helper below.
        for n in 0..MAX_TRACKED_CLIENTS {
            let addr = Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32)));
            for _ in 0..5 {
                t.note_failure(addr);
            }
        }
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);

        // The stalest entry is the first one filled, and it is locked.
        let victim = IpAddr::V4(std::net::Ipv4Addr::from(0u32));
        assert!(
            t.retry_after(Some(victim)).is_some(),
            "the victim has to be locked out for this test to be testing \
             anything",
        );

        // A client the map does not hold authenticates successfully.
        let client = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        t.note_success(Some(client));

        assert!(
            t.retry_after(Some(victim)).is_some(),
            "another client's success must not clear a live lockout to make \
             room for itself",
        );
        assert_eq!(
            t.per_client.lock().len(),
            MAX_TRACKED_CLIENTS,
            "with every entry locked there is nothing evictable, so no \
             insertion is made and the successful client keeps the overflow \
             path",
        );
        assert!(
            !t.per_client.lock().contains_key(&client),
            "no slot is taken by force",
        );
    }

    #[test]
    fn an_unlocked_entry_is_still_evicted_to_make_room() {
        // The other half: the refusal above is about *locked* entries, not
        // about eviction. With something evictable present, a successful
        // client still gets its slot — which is what decision 21's repair is
        // for, and what stops this becoming a way to deny one.
        let t = LoginThrottle::new();

        // One entry that is merely seen, and the rest locked out.
        let idle = IpAddr::V4(std::net::Ipv4Addr::from(0u32));
        t.per_client.lock().insert(idle, ThrottleState::default());
        for n in 1..MAX_TRACKED_CLIENTS {
            let addr = Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32)));
            for _ in 0..5 {
                t.note_failure(addr);
            }
        }
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);

        let client = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        t.note_success(Some(client));

        assert!(
            t.per_client.lock().contains_key(&client),
            "the successful client takes the slot of the unlocked entry",
        );
        assert!(
            !t.per_client.lock().contains_key(&idle),
            "and the unlocked entry is the one that went",
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

    #[test]
    fn many_addresses_share_one_ceiling_on_verifications() {
        // The property: the number of KDF runs the route admits does not
        // scale with the number of addresses the attempts come from. Every
        // address below is fresh, so every per-client consult says "go"; the
        // daemon-wide budget is what stops the eleventh.
        let t = LoginThrottle::new();
        let mut admitted = 0;
        for n in 0..MAX_TRACKED_CLIENTS as u32 {
            let addr = Some(IpAddr::V4(std::net::Ipv4Addr::from(0xc000_0000 + n)));
            assert!(
                t.retry_after(addr).is_none(),
                "a never-seen address is not throttled per client",
            );
            if t.admit_verification().is_ok() {
                admitted += 1;
                t.note_failure(addr);
            }
        }
        assert_eq!(
            admitted, KDF_BURST,
            "1024 addresses get the same burst of verifications as one",
        );
        let wait = t
            .admit_verification()
            .expect_err("the budget is spent until it refills");
        assert!(
            wait <= KDF_REFILL,
            "the wait names the next refill: {wait:?}"
        );
    }

    #[test]
    fn the_verification_budget_refills_one_at_a_time() {
        let refill = Duration::from_millis(40);
        let t = LoginThrottle::with_kdf_budget(2, refill);
        assert!(t.admit_verification().is_ok());
        assert!(t.admit_verification().is_ok());
        assert!(t.admit_verification().is_err(), "burst of two is spent");

        std::thread::sleep(refill + Duration::from_millis(10));
        assert!(
            t.admit_verification().is_ok(),
            "one refill interval, one run"
        );
        assert!(
            t.admit_verification().is_err(),
            "and only one: the budget accrues, it does not reset",
        );

        std::thread::sleep(refill * 4);
        assert!(t.admit_verification().is_ok());
        assert!(t.admit_verification().is_ok());
        assert!(
            t.admit_verification().is_err(),
            "idle time accrues no more than the burst",
        );
    }
}
