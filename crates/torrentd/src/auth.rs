//! Authentication for the HTTP control plane.
//!
//! Every credential is an opaque bearer token (`http::security`). Two kinds,
//! deliberately hashed differently:
//!
//! * **The operator password** is chosen by a human, so it is low-entropy and
//!   needs a memory-hard hash. Argon2id, verified once per `POST /v1/sessions`,
//!   which exchanges it for a short-lived **session token** (`tds_…`).
//! * **API tokens** (`tdp_…`) are 256 bits of randomness this daemon generated,
//!   so brute-forcing the *hash* is not the attack — there is nothing to guess.
//!   A fast SHA-256 is correct here, and matters: Argon2 on every Prometheus
//!   scrape would burn ~50ms of CPU per request by design.
//!
//! The prefixes exist so a leaked token is recognisable for what it is, by a
//! human reading a paste and by a secret scanner alike.
//!
//! Session tokens are looked up server-side, so they carry no claims to forge
//! and revoking one is a real deletion rather than a hope that the client
//! discards it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

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

/// Prefix of a static API token minted by `torrentd new-token`.
pub const STATIC_TOKEN_PREFIX: &str = "tdp_";

/// Prefix of a session token issued by `POST /v1/sessions`.
pub const SESSION_TOKEN_PREFIX: &str = "tds_";

/// The shortest `[auth] session_ttl_secs` the config accepts.
pub const MIN_SESSION_TTL_SECS: u64 = 60;

/// The longest `[auth] session_ttl_secs` the config accepts: 30 days.
pub const MAX_SESSION_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// What a credential is allowed to do.
///
/// Deliberately coarse. A finer model invites the mistake of handing a scrape
/// token something it did not need; three levels are enough to keep Prometheus
/// away from the mutation endpoints.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, kynos::Schema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Read-only API access.
    Read,
    /// Every unsafe method, pool adoption and mutation plans included.
    ///
    /// This is the authentication scope, and it is not the `[pool]
    /// allow_mutations` switch. Holding `Write` is necessary for
    /// `POST /v1/pool/adoptions`, `POST /v1/pool/plans` and applying a plan;
    /// `allow_mutations` separately gates the plan surface — creating a plan
    /// as well as applying one. Creating one touches nothing on disk, and
    /// `http::v1::pool` gives the reason it is gated anyway:
    /// "a plan that can never be applied is a trap, and refusing at the point
    /// the operator asks is the clearer signal." Adoption is not part of that
    /// surface — it records an existing file's ownership in the index — so it
    /// is deliberately outside the switch.
    Write,
    /// `/metrics` only.
    Metrics,
}

impl Scope {
    /// The scope a wire name spells, as the security scheme declares it.
    pub fn parse(name: &str) -> Option<Scope> {
        match name {
            "read" => Some(Scope::Read),
            "write" => Some(Scope::Write),
            "metrics" => Some(Scope::Metrics),
            _ => None,
        }
    }

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

    /// How long a session token from `POST /v1/sessions` stays valid.
    /// Default 12 hours; [`MIN_SESSION_TTL_SECS`] to [`MAX_SESSION_TTL_SECS`].
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
        // Bounded both ways. Zero would issue tokens that are dead on arrival,
        // and an unbounded value overflows the clock arithmetic that computes
        // an expiry — a panic on the login route rather than a config error.
        if !(MIN_SESSION_TTL_SECS..=MAX_SESSION_TTL_SECS).contains(&self.session_ttl_secs) {
            anyhow::bail!(
                "[auth] session_ttl_secs = {} is out of range; it must be between \
                 {MIN_SESSION_TTL_SECS} and {MAX_SESSION_TTL_SECS} (30 days)",
                self.session_ttl_secs,
            );
        }
        let mut names = std::collections::HashSet::new();
        let mut digests = std::collections::HashSet::new();
        for t in &self.token {
            let Ok(digest) = hex::decode(&t.sha256) else {
                anyhow::bail!(
                    "[auth] token {:?}: sha256 must be 64 hex characters",
                    t.name,
                );
            };
            if digest.len() != 32 {
                anyhow::bail!(
                    "[auth] token {:?}: sha256 must be 64 hex characters",
                    t.name,
                );
            }
            if t.scopes.is_empty() {
                anyhow::bail!("[auth] token {:?}: at least one scope is required", t.name);
            }
            // The name is what the log and `GET /v1/sessions/current` report,
            // so two tokens sharing one make a leak unattributable. Two
            // entries sharing a hash are one credential, and the first entry
            // silently decides which scopes it carries.
            if !names.insert(t.name.as_str()) {
                anyhow::bail!("[auth] token name {:?} is used more than once", t.name);
            }
            if !digests.insert(digest) {
                anyhow::bail!(
                    "[auth] token {:?}: its sha256 is already listed under another name; \
                     each [[auth.token]] must be a distinct token",
                    t.name,
                );
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

/// Live session tokens. In memory only: a restart logs everyone out, which for
/// a single-operator daemon is a feature — it needs no session store to keep
/// consistent, and there is nothing on disk to steal.
///
/// Keyed by the SHA-256 of the token rather than the token itself, so a heap
/// dump or a `Debug` slip hands out nothing that authenticates.
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<[u8; 32], (Instant, SystemTime)>>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Mint a session token, returning it and the wall-clock time it expires.
    pub fn create(&self) -> (String, SystemTime) {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = format!("{SESSION_TOKEN_PREFIX}{}", hex::encode(bytes));
        let now = Instant::now();
        // `AuthConfig::validate` bounds the TTL, but the store must not panic
        // on the login route whatever it was built with: `Instant + Duration`
        // and `SystemTime + Duration` both panic on overflow. A TTL too long
        // to represent is clamped to one that is.
        let expires = now
            .checked_add(self.ttl)
            .or_else(|| now.checked_add(Duration::from_secs(MAX_SESSION_TTL_SECS)))
            .unwrap_or(now);
        let lifetime = expires.saturating_duration_since(now);
        let wall_now = SystemTime::now();
        let expires_at = wall_now.checked_add(lifetime).unwrap_or(wall_now);
        let mut g = self.inner.lock();
        // Opportunistic sweep; sessions are few and this keeps a long-running
        // daemon from accumulating expired entries with no separate task.
        g.retain(|_, (exp, _)| *exp > now);
        g.insert(digest(&token), (expires, expires_at));
        (token, expires_at)
    }

    /// When `token` expires, if it is a live session token.
    pub fn expiry(&self, token: &str) -> Option<SystemTime> {
        if !token.starts_with(SESSION_TOKEN_PREFIX) {
            return None;
        }
        let g = self.inner.lock();
        g.get(&digest(token))
            .filter(|(exp, _)| *exp > Instant::now())
            .map(|(_, wall)| *wall)
    }

    #[cfg(test)]
    pub fn is_valid(&self, token: &str) -> bool {
        self.expiry(token).is_some()
    }

    pub fn revoke(&self, token: &str) {
        self.inner.lock().remove(&digest(token));
    }

    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.inner.lock().values().filter(|(e, _)| *e > now).count()
    }
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Everything the middleware needs. `None` config means auth is disabled.
#[derive(Clone)]
pub struct Auth {
    pub config: Arc<AuthConfig>,
    pub sessions: Arc<SessionStore>,
    /// Throttle for failed password attempts. See [`LoginThrottle`].
    pub throttle: Arc<LoginThrottle>,
}

/// Rate limiter for `POST /v1/sessions`, whose Argon2id verification costs
/// ~50 ms of CPU on every attempt.
///
/// Failures are counted per client where the client is established — the
/// socket peer, or an address a trusted proxy supplied ([`throttle_key`]
/// keys IPv6 per /64) — and in one global bucket where it is not, or where
/// the per-client map is full of live entries. Every verification also
/// spends from one daemon-wide budget ([`KdfBudget`]), or, once that is
/// empty and only for a client that has logged in before, from the reserve
/// described below; together they bound how much Argon2 the route runs
/// however many addresses a caller holds.
///
/// That budget can be kept spent, and every login refused while it is, by
/// [`STARVING_ADDRESSES`] addresses (or IPv6 /64s) polling in a loop. A
/// refusal by the budget costs its client nothing, so each address takes a
/// burst of verifications, sits out the penalty, and comes back; three that
/// time their turns well come close, and fewer leave the budget refilling.
/// The per-client buckets bound what one address costs everyone else; they
/// do not stop a handful.
///
/// What gets a client past a spent budget is having logged in before: a
/// client whose key has succeeded since the daemon started draws on a
/// separate reserve ([`RESERVE_BURST`], [`RESERVE_REFILL`]) once the shared
/// budget is empty, and no client that has never logged in can spend it. A
/// client that never has — a new address, or any address after a restart —
/// has only the shared budget, which is why a static `write` token is the
/// break-glass credential.
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
    /// Verifications only a [`known`](Self::known) client may spend, and only
    /// once [`kdf`](Self::kdf) is empty.
    reserve: Mutex<KdfBudget>,
    /// Throttle keys that have logged in, with when each last did. Bounded
    /// by [`MAX_KNOWN_CLIENTS`], dropping the oldest success to make room,
    /// and written only by a correct password, so a caller without it can
    /// neither join nor evict.
    known: Mutex<HashMap<IpAddr, Instant>>,
    max_burst: u32,
    penalty: Duration,
    clock: Clock,
}

/// Where the throttle reads the time. A test drives a fake one, so a
/// scenario minutes long runs in no time and lands exactly on the instants
/// it means to.
#[derive(Debug)]
enum Clock {
    System,
    #[cfg(test)]
    Fake(Mutex<Instant>),
}

impl Clock {
    fn now(&self) -> Instant {
        match self {
            Self::System => Instant::now(),
            #[cfg(test)]
            Self::Fake(at) => *at.lock(),
        }
    }
}

/// The most password verifications the daemon runs back to back before the
/// budget has to refill.
const KDF_BURST: u32 = 10;

/// How long the budget takes to regain one verification. With [`KDF_BURST`]
/// that is at most ten verifications in any thirty seconds once the burst is
/// spent — twice the old global bucket's five failures per thirty seconds,
/// and under 2% of one core at ~50 ms each.
const KDF_REFILL: Duration = Duration::from_secs(3);

/// How many addresses, each polling `POST /v1/sessions` with a wrong
/// password in a loop, keep the shared budget spent so that no client that
/// has never logged in reaches a verification. Each claims five and is then
/// locked out for thirty seconds, so at best it takes five per forty-five
/// seconds (fifteen to collect them at one per [`KDF_REFILL`], then the
/// penalty) while the budget accrues fifteen: three is the floor, for
/// addresses that take turns perfectly. Addresses that simply loop collide,
/// split the tokens, and lock out together, so it takes five; four let a
/// login through every few minutes. `docs/running.md` §6a quotes this
/// number; a test pins it.
#[cfg_attr(not(test), allow(dead_code))]
const STARVING_ADDRESSES: usize = 5;

/// The reserve's burst: a whole per-client burst, so a returning client can
/// mistype its password and still get in.
const RESERVE_BURST: u32 = 5;

/// How long the reserve takes to regain one verification: half the shared
/// budget's rate, so the two together stay under 3% of one core.
const RESERVE_REFILL: Duration = Duration::from_secs(6);

/// Cap on remembered successful clients. A real deployment has a handful of
/// operators, each on a handful of addresses.
const MAX_KNOWN_CLIENTS: usize = 64;

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
    fn new(burst: u32, refill: Duration, now: Instant) -> Self {
        Self {
            tokens: burst,
            refilled_at: now,
            burst,
            refill,
        }
    }

    /// Take one verification, or say how long until one is available.
    fn take(&mut self, now: Instant) -> Result<(), Duration> {
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

/// The key a client's failures are counted under.
///
/// An IPv4 address is its own key. An IPv6 address is keyed by its /64: a
/// single host is routinely handed a whole /64, so keying per address gave
/// one machine 2^64 buckets, each with its own burst, and let it fill the
/// per-client map on its own. An IPv4-mapped IPv6 address is the IPv4 client
/// it names, so a dual-stack socket and a v4 one agree on the key.
pub(crate) fn throttle_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let prefix = u128::from(v6) & !((1u128 << 64) - 1);
                IpAddr::V6(std::net::Ipv6Addr::from(prefix))
            }
        },
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
    /// When an attempt was last recorded here; what [`ThrottleState::is_live`]
    /// judges, since `failures` never decays.
    last_seen: Instant,
}

impl ThrottleState {
    /// A cleared record, as of `now`.
    fn new(now: Instant) -> Self {
        Self {
            failures: 0,
            locked_until: None,
            last_seen: now,
        }
    }

    /// How long the caller must wait, or `None` if an attempt is allowed.
    ///
    /// Not a liveness touch: the throttle is consulted before the body is
    /// read, so a request that ends in a 400 must not keep an entry alive at
    /// no KDF cost.
    fn retry_after(&mut self, now: Instant) -> Option<Duration> {
        match self.locked_until {
            Some(until) if now < until => Some(until - now),
            Some(_) => {
                // Window elapsed: allow another burst.
                self.locked_until = None;
                self.failures = 0;
                None
            }
            None => None,
        }
    }

    fn note_failure(&mut self, max_burst: u32, penalty: Duration, now: Instant) {
        self.last_seen = now;
        self.failures = self.failures.saturating_add(1);
        if self.failures >= max_burst {
            self.locked_until = Some(now + penalty);
        }
    }

    /// Whether this entry is worth keeping: it is still locking someone out,
    /// or it has been touched within `idle`.
    fn is_live(&self, idle: Duration, now: Instant) -> bool {
        self.locked_until.is_some_and(|u| u > now)
            || now.saturating_duration_since(self.last_seen) < idle
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self::with_clock(Clock::System)
    }

    fn with_clock(clock: Clock) -> Self {
        let now = clock.now();
        Self {
            global: Mutex::new(ThrottleState::new(now)),
            per_client: Mutex::new(HashMap::new()),
            kdf: Mutex::new(KdfBudget::new(KDF_BURST, KDF_REFILL, now)),
            reserve: Mutex::new(KdfBudget::new(RESERVE_BURST, RESERVE_REFILL, now)),
            known: Mutex::new(HashMap::new()),
            max_burst: 5,
            penalty: Duration::from_secs(30),
            clock,
        }
    }

    /// The production throttle on a clock only [`advance`](Self::advance)
    /// moves.
    #[cfg(test)]
    fn with_fake_clock() -> Self {
        Self::with_clock(Clock::Fake(Mutex::new(Instant::now())))
    }

    /// Move a fake clock forward by `by`.
    #[cfg(test)]
    fn advance(&self, by: Duration) {
        match &self.clock {
            Clock::Fake(at) => *at.lock() += by,
            Clock::System => panic!("advance() needs with_fake_clock()"),
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
            kdf: Mutex::new(KdfBudget::new(
                u32::MAX,
                Duration::from_nanos(1),
                Instant::now(),
            )),
            ..Self::new()
        }
    }

    /// The same throttle with a daemon-wide budget a test can exhaust and
    /// watch refill.
    #[cfg(test)]
    pub(crate) fn with_kdf_budget(burst: u32, refill: Duration) -> Self {
        Self {
            kdf: Mutex::new(KdfBudget::new(burst, refill, Instant::now())),
            ..Self::new()
        }
    }

    /// Spend one password verification, or say how long until one is
    /// available. Called immediately before the KDF runs, after every other
    /// refusal.
    ///
    /// Every client spends from the daemon-wide budget first. Once that is
    /// empty, a client that has logged in before spends from the reserve
    /// instead, and is told the sooner of the two waits when both are empty;
    /// anyone else is refused with the shared budget's wait.
    pub fn admit_verification(&self, client: Option<IpAddr>) -> Result<Admission, Duration> {
        let now = self.clock.now();
        let Err(wait) = self.kdf.lock().take(now) else {
            return Ok(Admission::Shared);
        };
        let Some(ip) = client.map(throttle_key) else {
            return Err(wait);
        };
        if !self.known.lock().contains_key(&ip) {
            return Err(wait);
        }
        match self.reserve.lock().take(now) {
            Ok(()) => Ok(Admission::Reserve),
            Err(reserve_wait) => Err(wait.min(reserve_wait)),
        }
    }

    /// How long `client` must wait, or `None` if an attempt is allowed.
    ///
    /// Mirrors `note_failure`: a client with no bucket of its own once the map
    /// is full is read from the global bucket its failures are written to.
    pub fn retry_after(&self, client: Option<IpAddr>) -> Option<Duration> {
        let now = self.clock.now();
        let Some(ip) = client.map(throttle_key) else {
            return self.global.lock().retry_after(now);
        };
        let mut g = self.per_client.lock();
        if let Some(state) = g.get_mut(&ip) {
            return state.retry_after(now);
        }
        if g.len() >= MAX_TRACKED_CLIENTS {
            drop(g);
            return self.global.lock().retry_after(now);
        }
        None
    }

    /// Record a failed attempt, locking out once the burst is spent.
    pub fn note_failure(&self, client: Option<IpAddr>) {
        let now = self.clock.now();
        let Some(ip) = client.map(throttle_key) else {
            self.global
                .lock()
                .note_failure(self.max_burst, self.penalty, now);
            return;
        };
        let mut g = self.per_client.lock();
        if g.len() >= MAX_TRACKED_CLIENTS && !g.contains_key(&ip) {
            g.retain(|_, st| st.is_live(self.penalty, now));
            // Still full of live entries: fall back to the global bucket
            // rather than letting the map grow, since an attack that fills it
            // is exactly when throttling has to keep working.
            if g.len() >= MAX_TRACKED_CLIENTS {
                drop(g);
                self.global
                    .lock()
                    .note_failure(self.max_burst, self.penalty, now);
                return;
            }
        }
        g.entry(ip)
            .or_insert_with(|| ThrottleState::new(now))
            .note_failure(self.max_burst, self.penalty, now);
    }

    /// A success clears the client's record, by **replacing** its entry, or
    /// inserting a cleared one, so that a client that has just proved it is
    /// not the attacker keeps a slot of its own off the overflow path. Making
    /// room evicts the stalest entry that is not locked out — evicting a
    /// locked one would clear its lockout — and inserts nothing when every
    /// entry is locked.
    ///
    /// The global bucket is not cleared by an identified client: one valid
    /// credential must not reset the shared bucket between guesses at another.
    ///
    /// An identified client is also remembered as one that has logged in,
    /// which is what lets it spend the reserve
    /// ([`admit_verification`](Self::admit_verification)) from then on.
    pub fn note_success(&self, client: Option<IpAddr>) {
        let now = self.clock.now();
        let Some(ip) = client.map(throttle_key) else {
            *self.global.lock() = ThrottleState::new(now);
            return;
        };
        self.remember(ip, now);
        let mut g = self.per_client.lock();
        if let Some(state) = g.get_mut(&ip) {
            *state = ThrottleState::new(now);
            return;
        }
        if g.len() >= MAX_TRACKED_CLIENTS {
            g.retain(|_, st| st.is_live(self.penalty, now));
        }
        if g.len() >= MAX_TRACKED_CLIENTS {
            let stalest = g
                .iter()
                .filter(|(_, st)| st.locked_until.is_none_or(|u| u <= now))
                .min_by_key(|(_, st)| st.last_seen)
                .map(|(addr, _)| *addr);
            match stalest {
                Some(addr) => {
                    g.remove(&addr);
                }
                // Every entry is locked out: stay on the overflow path.
                None => return,
            }
        }
        g.insert(ip, ThrottleState::new(now));
    }

    /// Record that `ip` (a throttle key) has logged in, dropping the oldest
    /// success when the set is full.
    fn remember(&self, ip: IpAddr, now: Instant) {
        let mut known = self.known.lock();
        if known.len() >= MAX_KNOWN_CLIENTS && !known.contains_key(&ip) {
            let oldest = known
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(addr, _)| *addr);
            if let Some(addr) = oldest {
                known.remove(&addr);
            }
        }
        known.insert(ip, now);
    }
}

/// Which budget paid for an admitted verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The daemon-wide budget every client shares.
    Shared,
    /// The reserve for clients that have logged in before, because the
    /// shared budget was spent.
    Reserve,
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
    let token = format!("{STATIC_TOKEN_PREFIX}{}", hex::encode(bytes));
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
        let (a, a_expires) = s.create();
        let (b, _) = s.create();
        assert_ne!(a, b);
        assert!(a.starts_with(SESSION_TOKEN_PREFIX), "{a}");
        assert_eq!(
            a.len(),
            SESSION_TOKEN_PREFIX.len() + 64,
            "the prefix and 256 bits of hex"
        );
        assert_eq!(s.expiry(&a), Some(a_expires));
        s.revoke(&a);
        assert!(!s.is_valid(&a), "revoking must actually invalidate");
        assert!(s.is_valid(&b));
        assert!(!s.is_valid("nonsense"));
    }

    #[test]
    fn a_static_token_is_never_mistaken_for_a_session() {
        let s = SessionStore::new(Duration::from_secs(60));
        let (static_token, _) = generate_token();
        assert!(static_token.starts_with(STATIC_TOKEN_PREFIX));
        assert_eq!(s.expiry(&static_token), None);
    }

    #[test]
    fn the_store_holds_no_token_it_could_hand_back() {
        let s = SessionStore::new(Duration::from_secs(60));
        let (token, _) = s.create();
        let dump = format!("{s:?}");
        assert!(
            !dump.contains(token.trim_start_matches(SESSION_TOKEN_PREFIX)),
            "the store keeps a digest, not the token: {dump}"
        );
    }

    #[test]
    fn expired_sessions_stop_being_valid() {
        let s = SessionStore::new(Duration::from_millis(1));
        let (token, _) = s.create();
        std::thread::sleep(Duration::from_millis(20));
        assert!(!s.is_valid(&token));
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
    fn config_validation_bounds_the_session_ttl() {
        let mut c = cfg(hash_password("pw").unwrap());
        for bad in [
            0,
            MIN_SESSION_TTL_SECS - 1,
            MAX_SESSION_TTL_SECS + 1,
            u64::MAX,
        ] {
            c.session_ttl_secs = bad;
            assert!(c.validate().is_err(), "ttl {bad} must be refused");
        }
        for good in [MIN_SESSION_TTL_SECS, 43_200, MAX_SESSION_TTL_SECS] {
            c.session_ttl_secs = good;
            assert!(c.validate().is_ok(), "ttl {good} must be accepted");
        }
    }

    #[test]
    fn a_ttl_too_long_to_represent_never_panics_the_login_route() {
        // `Instant + Duration` panics on overflow; the store is built from
        // whatever the config says, so it must clamp rather than panic.
        let s = SessionStore::new(Duration::from_secs(u64::MAX));
        let (token, expires_at) = s.create();
        assert!(s.is_valid(&token));
        assert!(expires_at > SystemTime::now());
    }

    #[test]
    fn config_validation_refuses_duplicate_token_names_and_hashes() {
        let base = cfg(hash_password("pw").unwrap());
        let (_, a) = generate_token();
        let (_, b) = generate_token();
        let token = |name: &str, sha256: &str| TokenConfig {
            name: name.into(),
            sha256: sha256.into(),
            scopes: vec![Scope::Read],
        };

        let mut c = base.clone();
        c.token = vec![token("one", &a), token("two", &b)];
        assert!(c.validate().is_ok());

        c.token = vec![token("same", &a), token("same", &b)];
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("more than once"), "{e}");

        // The same credential twice, even spelled in another case.
        c.token = vec![token("one", &a), token("two", &a.to_uppercase())];
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("already listed"), "{e}");
    }

    #[test]
    fn an_ipv6_client_is_throttled_per_64_not_per_address() {
        // One host is routinely handed a whole /64. Keyed per address, it had
        // 2^64 buckets of five attempts each.
        let t = LoginThrottle::new();
        let addr = |last: u16| {
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, 1, 0, 0, 0, last,
            )))
        };
        for n in 0..5 {
            t.note_failure(addr(n));
        }
        assert!(
            t.retry_after(addr(999)).is_some(),
            "another address in the same /64 is the same client",
        );
        let neighbour = Some(IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 0, 2, 0, 0, 0, 1,
        )));
        assert!(
            t.retry_after(neighbour).is_none(),
            "the next /64 is another client",
        );
        assert_eq!(t.per_client.lock().len(), 1);
    }

    #[test]
    fn an_ipv4_mapped_client_shares_the_ipv4_bucket() {
        let t = LoginThrottle::new();
        let v4 = std::net::Ipv4Addr::new(198, 51, 100, 7);
        for _ in 0..5 {
            t.note_failure(Some(IpAddr::V6(v4.to_ipv6_mapped())));
        }
        assert!(t.retry_after(Some(IpAddr::V4(v4))).is_some());
        assert_eq!(throttle_key(IpAddr::V4(v4)), IpAddr::V4(v4));
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

    /// The `n`th of the addresses that fill the per-client map; none is an
    /// [`ip`] address.
    fn filler(n: usize) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(n as u32))
    }

    /// Fill `t`'s per-client map, each entry with `failures` failures (five
    /// locks it out).
    fn fill(t: &LoginThrottle, failures: u32) {
        for n in 0..MAX_TRACKED_CLIENTS {
            for _ in 0..failures {
                t.note_failure(Some(filler(n)));
            }
        }
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);
    }

    #[test]
    fn a_full_map_stays_bounded_and_overflows_to_the_shared_bucket() {
        let t = LoginThrottle::new();
        fill(&t, 1);
        assert!(
            t.retry_after(ip(99)).is_none(),
            "the first burst is allowed"
        );
        for n in 0..64 {
            t.note_failure(Some(filler(MAX_TRACKED_CLIENTS + n)));
        }
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);
        // The overflow is still throttled: 64 failures went to the shared
        // bucket, so a never-seen client reads it as locked.
        assert!(t.retry_after(ip(99)).is_some());
    }

    /// Only an attempt keeps an entry live; a consult (which a request with an
    /// unparseable body reaches) does not, so idle entries are swept for a
    /// newcomer.
    #[test]
    fn idle_entries_are_swept_for_a_newcomer_even_after_a_consult() {
        let t = LoginThrottle::with_penalty(Duration::from_millis(50));
        fill(&t, 1);
        std::thread::sleep(Duration::from_millis(150));
        for n in 0..MAX_TRACKED_CLIENTS {
            assert!(t.retry_after(Some(filler(n))).is_none());
        }
        t.note_failure(ip(1));
        assert!(t.per_client.lock().contains_key(&ip(1).unwrap()));
    }

    /// A success keeps or gains the client a slot of its own, so a full map's
    /// shared bucket cannot lock it out moments after it authenticated.
    #[test]
    fn a_success_keeps_the_client_off_the_shared_bucket() {
        // A client the map already holds keeps its slot.
        let t = LoginThrottle::new();
        fill(&t, 1);
        t.note_success(Some(filler(0)));
        assert!(t.per_client.lock().contains_key(&filler(0)));
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);
        for n in 2..8 {
            t.note_failure(ip(n));
        }
        assert!(t.retry_after(Some(filler(0))).is_none());

        // A client on the overflow path gains one.
        let t = LoginThrottle::new();
        fill(&t, 1);
        for _ in 0..4 {
            t.note_failure(ip(1));
        }
        t.note_success(ip(1));
        t.note_failure(ip(2));
        assert!(t.retry_after(ip(2)).is_some());
        assert!(t.retry_after(ip(1)).is_none());
    }

    /// Making room for a successful client evicts an unlocked entry, never a
    /// locked one: that would clear someone's lockout.
    #[test]
    fn making_room_never_clears_a_live_lockout() {
        let t = LoginThrottle::new();
        fill(&t, 5);
        t.note_success(ip(1));
        assert!(t.retry_after(Some(filler(0))).is_some());
        assert!(!t.per_client.lock().contains_key(&ip(1).unwrap()));
        assert_eq!(t.per_client.lock().len(), MAX_TRACKED_CLIENTS);

        let t = LoginThrottle::new();
        fill(&t, 5);
        *t.per_client.lock().get_mut(&filler(7)).unwrap() = ThrottleState::new(Instant::now());
        t.note_success(ip(1));
        assert!(t.per_client.lock().contains_key(&ip(1).unwrap()));
        assert!(!t.per_client.lock().contains_key(&filler(7)));
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
            if t.admit_verification(addr).is_ok() {
                admitted += 1;
                t.note_failure(addr);
            }
        }
        assert_eq!(
            admitted, KDF_BURST,
            "1024 addresses get the same burst of verifications as one",
        );
        let wait = t
            .admit_verification(ip(1))
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
        assert!(t.admit_verification(None).is_ok());
        assert!(t.admit_verification(None).is_ok());
        assert!(t.admit_verification(None).is_err(), "burst of two is spent");

        std::thread::sleep(refill + Duration::from_millis(10));
        assert!(
            t.admit_verification(None).is_ok(),
            "one refill interval, one run"
        );
        assert!(
            t.admit_verification(None).is_err(),
            "and only one: the budget accrues, it does not reset",
        );

        std::thread::sleep(refill * 4);
        assert!(t.admit_verification(None).is_ok());
        assert!(t.admit_verification(None).is_ok());
        assert!(
            t.admit_verification(None).is_err(),
            "idle time accrues no more than the burst",
        );
    }

    /// One `POST /v1/sessions` as `create_session` runs it, against `t`'s
    /// clock: the per-client consult, the budget, then the verdict the KDF
    /// would reach. `Ok` names the budget that paid for a verification.
    fn attempt(
        t: &LoginThrottle,
        client: Option<IpAddr>,
        correct: bool,
    ) -> Result<Admission, Duration> {
        if let Some(wait) = t.retry_after(client) {
            return Err(wait);
        }
        let paid = t.admit_verification(client)?;
        if correct {
            t.note_success(client);
        } else {
            t.note_failure(client);
        }
        Ok(paid)
    }

    /// How often each attacking address polls: far tighter than the refill,
    /// so a token is taken within one tick of accruing.
    const POLL: Duration = Duration::from_millis(100);

    /// Advance `t` tick by tick for `span`, each tick letting each of
    /// `attackers` addresses try a wrong password, and then calling
    /// `after(t, elapsed)`, so whatever it does always comes second to the
    /// attackers, as a human's retry does to a loop's.
    fn siege(
        t: &LoginThrottle,
        attackers: usize,
        span: Duration,
        mut after: impl FnMut(&LoginThrottle, Duration),
    ) {
        let attacker = |n: usize| Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, n as u8)));
        let mut elapsed = Duration::ZERO;
        while elapsed < span {
            for n in 0..attackers {
                let _ = attempt(t, attacker(n), false);
            }
            after(t, elapsed);
            t.advance(POLL);
            elapsed += POLL;
        }
    }

    /// How many fresh clients, one a second for fifteen minutes after a
    /// two-minute warm-up, `attackers` addresses polling in a loop let
    /// through to a verification. Each is a new address, so no attempt is
    /// helped by an earlier success.
    fn newcomers_admitted(attackers: usize) -> usize {
        let warm_up = Duration::from_secs(120);
        let t = LoginThrottle::with_fake_clock();
        let mut admitted = 0;
        siege(
            &t,
            attackers,
            warm_up + Duration::from_secs(900),
            |t, elapsed| {
                let ms = elapsed.as_millis();
                if ms % 1000 == 0 && elapsed >= warm_up {
                    let n = (ms / 1000) as u32;
                    let newcomer = Some(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)));
                    if attempt(t, newcomer, true).is_ok() {
                        admitted += 1;
                    }
                }
            },
        );
        admitted
    }

    /// Pins the number `docs/running.md` §6a and [`LoginThrottle`] quote:
    /// [`STARVING_ADDRESSES`] addresses polling in a loop keep a client that
    /// has never logged in from ever reaching a verification, and one fewer
    /// lets some through.
    #[test]
    fn polling_addresses_keep_a_new_client_out_from_the_documented_number() {
        assert_eq!(newcomers_admitted(STARVING_ADDRESSES), 0);
        assert!(newcomers_admitted(STARVING_ADDRESSES - 1) > 0);
    }

    /// The way past a spent budget: addresses polling for fifteen minutes —
    /// three, as in the report, and the number that starves the budget
    /// outright — cannot keep a client that has logged in before from
    /// reaching a verification on its first try, every time it tries, even
    /// after mistyping its password four times running.
    #[test]
    fn a_returning_client_gets_past_addresses_starving_the_budget() {
        for attackers in [3, STARVING_ADDRESSES] {
            let t = LoginThrottle::with_fake_clock();
            let operator = ip(1);
            assert_eq!(attempt(&t, operator, true), Ok(Admission::Shared));

            let mut tries = 0;
            let mut from_reserve = 0;
            let mut admit = |t: &LoginThrottle, correct: bool, elapsed: Duration| {
                let paid = attempt(t, operator, correct).unwrap_or_else(|wait| {
                    panic!(
                        "{attackers} addresses kept the returning client out at {elapsed:?} \
                         for {wait:?}"
                    )
                });
                if paid == Admission::Reserve {
                    from_reserve += 1;
                }
            };
            siege(&t, attackers, Duration::from_secs(900), |t, elapsed| {
                let ms = elapsed.as_millis();
                // Past the warm-up, once a minute: a mistyped burst every
                // fifth time, otherwise a single correct attempt.
                if ms < 120_000 || ms % 60_000 != 0 {
                    return;
                }
                tries += 1;
                if tries % 5 == 0 {
                    for _ in 0..RESERVE_BURST - 1 {
                        admit(t, false, elapsed);
                    }
                }
                admit(t, true, elapsed);
            });
            assert_eq!(tries, 13);
            if attackers == STARVING_ADDRESSES {
                assert_eq!(
                    from_reserve,
                    13 + 2 * (RESERVE_BURST as usize - 1),
                    "with the shared budget spent throughout, the reserve paid for every one",
                );
            }
        }
    }

    /// The reserve is for clients that have logged in, so failing does not
    /// earn it, nor does a success from another address or an anonymous one;
    /// and the shared budget is spent first, so the reserve is untouched
    /// while it lasts.
    #[test]
    fn only_a_client_that_has_logged_in_spends_the_reserve() {
        let t = LoginThrottle::with_fake_clock();
        assert_eq!(attempt(&t, ip(1), true), Ok(Admission::Shared));
        assert_eq!(attempt(&t, None, true), Ok(Admission::Shared));
        for n in 0..KDF_BURST - 2 {
            assert_eq!(attempt(&t, ip(10 + n as u8), false), Ok(Admission::Shared));
        }
        assert!(attempt(&t, ip(2), false).is_err(), "budget spent");
        assert!(attempt(&t, None, true).is_err(), "anonymous has no reserve");
        assert!(attempt(&t, ip(3), true).is_err(), "nor has a newcomer");
        for _ in 0..RESERVE_BURST {
            assert_eq!(attempt(&t, ip(1), true), Ok(Admission::Reserve));
        }
        let wait = attempt(&t, ip(1), true).expect_err("the reserve is spent too");
        assert!(
            wait <= KDF_REFILL,
            "the wait is the sooner of the two refills: {wait:?}",
        );
        t.advance(KDF_REFILL);
        assert_eq!(
            attempt(&t, ip(1), true),
            Ok(Admission::Shared),
            "the shared budget is spent before the reserve",
        );
    }

    /// The remembered set is bounded, and makes room by forgetting the
    /// client whose last success is oldest.
    #[test]
    fn the_remembered_clients_are_bounded_oldest_first() {
        let t = LoginThrottle::with_fake_clock();
        for n in 0..=MAX_KNOWN_CLIENTS {
            t.note_success(Some(filler(n)));
            t.advance(Duration::from_secs(1));
        }
        let known = t.known.lock();
        assert_eq!(known.len(), MAX_KNOWN_CLIENTS);
        assert!(!known.contains_key(&filler(0)));
        assert!(known.contains_key(&filler(MAX_KNOWN_CLIENTS)));
    }
}
