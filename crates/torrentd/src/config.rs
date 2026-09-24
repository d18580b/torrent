//! TOML configuration parser.
//!
//! `serde(deny_unknown_fields)` everywhere — typos in setting names
//! produce fatal startup errors naming the offending key. `Config::diff`
//! separates fields
//! that can be hot-reloaded via SIGHUP from those requiring a full
//! restart.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::ProfileConfig;
use torrentd_engine::ProfileConfigError;
use torrentd_engine::ProfileId;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub default_save_path: PathBuf,
    pub resume_dir: PathBuf,
    pub torrent_dir: PathBuf,
    /// Where the control API listens. Defaults to loopback, which is the only
    /// address it is safe to expose without `[auth]`.
    ///
    /// The `serde(default)` removed a refusal as well as making the README's
    /// claim true: an omitted `http_listen` used to fail to parse with
    /// `missing field http_listen`, and now binds loopback silently. That is
    /// the right default everywhere but inside a network namespace, where the
    /// bind succeeds and the published port reaches nothing. Nothing here
    /// guards against that: `deploy/compose.yaml` only documents it, telling
    /// the operator to set `http_listen = "0.0.0.0:8080"` in the mounted
    /// `torrentd.toml` themselves.
    #[serde(default = "Config::default_http_listen")]
    pub http_listen: SocketAddr,

    /// Permit running with no `[auth]` section.
    ///
    /// Without `[auth]` the daemon authenticates nothing: every route,
    /// including every mutating one, is open to anyone who can reach the
    /// port. That posture is legitimate — a loopback bind behind a reverse
    /// proxy that does its own access control — but it is not something an
    /// operator should arrive at by omission, which is what it used to be.
    ///
    /// So the unsafe choice stays available and has to be typed.
    #[serde(default)]
    pub allow_unauthenticated: bool,
    #[serde(default = "Config::default_log_level")]
    pub log_level: LogLevel,

    /// Where the assignment registry lives. Defaults to
    /// `<resume_dir parent>/profile_assignments.json`.
    #[serde(default)]
    pub registry_path: Option<PathBuf>,

    // libtorrent settings overrides.
    #[serde(default)]
    pub connections_limit: Option<u32>,
    #[serde(default)]
    pub file_pool_size: Option<u32>,
    #[serde(default)]
    pub enable_lsd: Option<bool>,
    #[serde(default)]
    pub aio_threads: Option<u32>,
    #[serde(default)]
    pub max_concurrent_http_announces: Option<u32>,
    #[serde(default)]
    pub upload_rate_limit: Option<u32>,
    #[serde(default)]
    pub peer_fingerprint: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,

    /// Max age of a WireGuard tunnel's latest handshake before the health
    /// monitor treats the profile as down. Catches a tunnel that
    /// keeps its IP but has silently stopped handshaking. Default 180s.
    #[serde(default = "Config::default_handshake_max_age")]
    pub vpn_handshake_max_age_secs: u64,

    /// Install a fail-closed nftables kill switch that
    /// confines the daemon's egress to loopback + the profiles' tunnel interfaces.
    /// Off by default; requires `CAP_NET_ADMIN` and that torrentd runs as its own
    /// user. See `vpn::killswitch`.
    #[serde(default)]
    pub network_kill_switch: bool,

    /// `[[profile]]` array. Empty is refused: `ProfileConfigError::NoProfiles`.
    /// There is no implicit profile, because the only thing an implicit one
    /// could be is the least private posture the daemon has.
    #[serde(default)]
    pub profile: Vec<ProfileConfig>,

    /// HTTP authentication. Absent → unauthenticated, as before.
    #[serde(default)]
    pub auth: Option<crate::auth::AuthConfig>,

    /// Managed-pool configuration. Absent → the pool index is not maintained
    /// and the daemon behaves exactly as before.
    #[serde(default)]
    pub pool: Option<PoolConfig>,
}

/// The directories torrentd indexes, and where it keeps the index.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// Directories the daemon indexes. Read-only during scanning.
    pub roots: Vec<PathBuf>,

    /// Directory of `.torrent` files to match against. For a migration this is
    /// the other client's state directory — qBittorrent's `BT_backup`, which
    /// also holds the `.fastresume` sidecars the scanner reads for save-path,
    /// category and tag hints.
    pub library_dir: PathBuf,

    /// Index location. Defaults to `<resume_dir parent>/pool.db`.
    #[serde(default)]
    pub db_path: Option<PathBuf>,

    /// How many torrents may be hashing at once during a bulk adopt. Adopting
    /// a large subtree otherwise saturates the disk and starves whatever is
    /// already seeding.
    #[serde(default = "PoolConfig::default_max_concurrent_verify")]
    pub max_concurrent_verify: usize,

    /// Fold a legacy assignment registry into the index on the next scan.
    /// The JSON is left on disk; existing in-index assignments always win.
    #[serde(default = "PoolConfig::default_true")]
    pub import_legacy_registry: bool,

    /// Allow the daemon to move, relocate and delete files inside the managed
    /// roots.
    ///
    /// Off by default, and deliberately so. Indexing, matching, adoption and
    /// reporting are all read-only and need nothing here; the plan/apply
    /// machinery is the only part that can destroy data, and an operator who
    /// has not decided to reorganise their pool should not be one malformed
    /// request away from it. Turning this on does not disable any of the
    /// refusals — it only stops the whole surface returning 403.
    #[serde(default)]
    pub allow_mutations: bool,
}

impl PoolConfig {
    fn default_true() -> bool {
        true
    }
    fn default_max_concurrent_verify() -> usize {
        4
    }
}

/// Where torrent-to-profile assignments are persisted.
const REGISTRY_FILE: &str = "profile_assignments.json";
/// Its name before profiles replaced slots. Read once, then written under the
/// current name.
const LEGACY_REGISTRY_FILE: &str = "slot_assignments.json";

impl Config {
    fn default_http_listen() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8080))
    }

    fn default_log_level() -> LogLevel {
        LogLevel::Info
    }

    fn default_handshake_max_age() -> u64 {
        180
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let cfg = Self::parse(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load for an operator subcommand — `hash-password`, `new-token`,
    /// `pool …`, `vpn check` — which validates everything except the
    /// authentication posture.
    ///
    /// Those subcommands construct no session, bind no socket and serve no
    /// request, so the posture check is judging something they do not do. It
    /// still has to be judged for them, though, because the only documented
    /// way onto `[auth]` runs through `hash-password`: a deployment whose
    /// `http_listen` is not loopback — every container deployment, since the
    /// published port cannot reach a loopback bind inside the namespace —
    /// cannot write `allow_unauthenticated = true` to get past the refusal,
    /// because the opt-out on a routable address is itself refused. With the
    /// check in front of the subcommand there is no first step: the only way
    /// out is to flip `http_listen` to loopback, generate, write `[auth]`, and
    /// flip it back, which is four edits for a bootstrap and is documented
    /// nowhere.
    pub fn load_for_operator_tool(path: &Path) -> anyhow::Result<Self> {
        let cfg = Self::parse(path)?;
        cfg.validate_without_auth_posture()?;
        Ok(cfg)
    }

    fn parse(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&bytes).with_context(|| format!("parse {}", path.display()))
    }

    /// Refuse a configuration that authenticates nothing without saying so.
    ///
    /// Three separate refusals, because they fail for different reasons:
    ///
    /// * no `[auth]` and no explicit opt-out — the operator has not chosen,
    ///   and the default of "no authentication at all" is not one to arrive at
    ///   by omission;
    /// * no `[auth]` on a non-loopback bind, even *with* the opt-out — that is
    ///   an unauthenticated mutating API on a routable address, and
    ///   `allow_unauthenticated` is for delegating access control to something
    ///   in front, not for having none;
    /// * `[auth]` *and* the opt-out together — the flag is inert, and an inert
    ///   security-relevant flag left in a config file is a standing misreading
    ///   of the very question this check exists to make explicit.
    ///
    /// The whole point is that the posture is stated rather than inferred, so
    /// a config that states two postures is no better than one that states
    /// none.
    fn validate_auth_posture(&self) -> anyhow::Result<()> {
        if self.auth.is_some() {
            if self.allow_unauthenticated {
                anyhow::bail!(
                    "[auth] is configured and allow_unauthenticated = true is set as well. \
                     The flag has no effect here — a daemon with [auth] authenticates — but \
                     it is the one line anyone reads to answer \"does this daemon \
                     authenticate?\", and left in place it answers no. Delete \
                     `allow_unauthenticated` from the config."
                );
            }
            return Ok(());
        }
        if !self.allow_unauthenticated {
            anyhow::bail!(
                "no [auth] section, and allow_unauthenticated is not set. Without [auth] the \
                 daemon authenticates nothing: every route, including every mutating one, is \
                 open to anyone who can reach {listen}. Either configure authentication —\n\
                 \n    torrentd --config <path> hash-password\n\
                 \n— or, if access control genuinely belongs to something in front of this \
                 daemon, write `allow_unauthenticated = true` to say so deliberately.",
                listen = self.http_listen,
            );
        }
        // Unwrap `::ffff:127.0.0.1` before asking. `IpAddr::is_loopback`
        // delegates to `Ipv6Addr::is_loopback`, which is true only of `::1`,
        // so an IPv4-mapped loopback bind — reachable from the host and
        // nowhere else — was refused by a message asserting it is "reachable
        // from the network". The refusal errs closed either way; a false
        // statement in a refusal is worth one line to remove rather than one
        // line to excuse.
        let listen_ip = match self.http_listen.ip() {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
            v4 => v4,
        };
        if !listen_ip.is_loopback() {
            anyhow::bail!(
                "allow_unauthenticated = true with http_listen = {listen}, which is not a \
                 loopback address. That is an unauthenticated API that mutates state, \
                 reachable from the network. Bind to 127.0.0.1 and put a reverse proxy in \
                 front, or configure [auth].\n\
                 \nThis judges the address as configured, and nothing else: a bind that is \
                 routable only inside a network namespace is still refused, because the \
                 configured address is all `--check-config` has to go on and a namespace is \
                 not something the daemon can verify it is in. A container that must bind \
                 0.0.0.0 configures [auth] — `compose run --rm torrentd hash-password` \
                 generates the values without starting a listener.",
                listen = self.http_listen,
            );
        }
        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_inner(true)
    }

    /// Everything [`Config::validate`] checks except the authentication
    /// posture. See [`Config::load_for_operator_tool`] for who gets this and
    /// why.
    ///
    /// `pub(crate)`, not `pub`. The exemption seam this crate records is
    /// `load_for_operator_tool`; a second entry point that runs every check
    /// except the security one is a door nobody recorded opening. There is no
    /// library target today, so nothing outside the crate can reach it either
    /// way — which is what makes narrowing it free now and a wager later.
    pub(crate) fn validate_without_auth_posture(&self) -> anyhow::Result<()> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, check_auth_posture: bool) -> anyhow::Result<()> {
        // Unconditional: an empty set is itself a refusal now, because there
        // is no implicit profile to fall back to.
        ProfileConfig::validate_set(&self.profile).context("[[profile]] validation failed")?;
        self.validate_effective_identities()
            .context("[[profile]] validation failed")?;
        self.validate_effective_store_dirs()
            .context("[[profile]] validation failed")?;

        // Range-check the numeric overrides. These are handed to libtorrent as
        // ints; a zero connection limit or aio_threads silently produces a
        // daemon that cannot seed, and there is no reason to find that out
        // from a metrics graph rather than at startup.
        let range = |name: &str, v: Option<u32>, lo: u32, hi: u32| -> anyhow::Result<()> {
            if let Some(v) = v {
                if v < lo || v > hi {
                    anyhow::bail!("{name} = {v} is out of range ({lo}..={hi})");
                }
            }
            Ok(())
        };
        range("connections_limit", self.connections_limit, 1, 1_000_000)?;
        range("file_pool_size", self.file_pool_size, 1, 1_000_000)?;
        range("aio_threads", self.aio_threads, 1, 1024)?;
        range(
            "max_concurrent_http_announces",
            self.max_concurrent_http_announces,
            1,
            100_000,
        )?;
        // upload_rate_limit is a byte/sec cap where 0 means unlimited, so 0 is
        // valid and only the absurd upper end is worth rejecting.
        range("upload_rate_limit", self.upload_rate_limit, 0, u32::MAX)?;

        if let Some(auth) = &self.auth {
            auth.validate()?;
        }
        if let Some(pool) = &self.pool {
            if pool.roots.is_empty() {
                anyhow::bail!("[pool] is configured but `roots` is empty");
            }
            // Nested roots index the same bytes twice under two root ids.
            // Claims land under exactly one of them, so `orphan_files` reports
            // the very same protected payload as unclaimed under the other —
            // and that is what a delete plan acts on. Compare resolved paths,
            // so a symlinked or non-normalised alias cannot slip past.
            let resolved: Vec<PathBuf> = pool
                .roots
                .iter()
                .map(|r| r.canonicalize().unwrap_or_else(|_| r.clone()))
                .collect();
            for (i, a) in resolved.iter().enumerate() {
                for b in resolved.iter().skip(i + 1) {
                    if a.starts_with(b) || b.starts_with(a) {
                        anyhow::bail!(
                            "[pool] roots must not nest: {} and {}",
                            a.display(),
                            b.display(),
                        );
                    }
                }
            }

            // The daemon's own state must not sit inside a managed root.
            // Nothing in the library claims those files, so they are orphans by
            // definition — and `delete_orphans` over the root would erase the
            // torrent library, the resume store, or the index itself.
            // Session-state files are per profile and live in state_dir,
            // which resume_dir's parent already covers.
            let state: [(&str, &Path); 5] = [
                ("resume_dir", &self.resume_dir),
                ("torrent_dir", &self.torrent_dir),
                ("[pool] library_dir", &pool.library_dir),
                ("[pool] db_path", &self.pool_db_path()),
                ("registry_path", &self.registry_path()),
            ];
            for (name, path) in state {
                let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
                for root in &resolved {
                    if path.starts_with(root) {
                        anyhow::bail!(
                            "{name} ({}) is inside the managed root {} — no torrent claims \
                             those files, so they would be reported as orphans and could be \
                             deleted; move it outside every root",
                            path.display(),
                            root.display(),
                        );
                    }
                }
            }
        }

        // The boot rule, which is a pure function of the config file and so
        // belongs above the policy check with every other one. It used to run
        // in `main::check_config`, after `Config::load` had already returned —
        // so two configs differing only in whether a posture was stated gave
        // "no [auth] section…" for one and "Configure a vpn profile, or unset
        // network_kill_switch" for the other, and the operator saw the thing
        // they must physically change only once the policy refusal was
        // cleared. Demonstrated on both. Running it here also gives it to the
        // operator subcommands, which `load_for_operator_tool` never ran it
        // for.
        self.check_boot_rules()?;

        // Shape before policy, last of all: every check above names something
        // the operator must physically change — a duplicate `listen_port`, a
        // zero `aio_threads`, a `password_hash` that is not a PHC string, two
        // `[pool]` roots that nest, a kill switch with no tunnel to confine
        // egress to — while a config with no stated posture is well-formed and
        // not permitted. Running the policy check first meant a malformed
        // value was reported only once the posture was settled, and
        // `hash-password`, which the posture refusal names as the way out,
        // then refused for a reason `--check-config` had never shown the
        // operator: `load_for_operator_tool` skips this check and runs every
        // one above it. Last is also the position that makes "shape before
        // policy" describe this function end to end, rather than only the
        // `[[profile]]` block.
        //
        // `--check-config` runs one further refusal after this one, and it is
        // deliberately not here: whether the `nft` binary exists is a fact
        // about the host, not about the file. `Config::load` is also what the
        // SIGHUP pump and every operator subcommand call, so a probe of the
        // host placed here would refuse a reload, and refuse `hash-password`,
        // on a machine without nftables — demonstrated, including on
        // `hash-password`, which is the invocation the posture refusal names
        // as the way out. See `main::check_config`.
        if check_auth_posture {
            self.validate_auth_posture()?;
        }
        Ok(())
    }

    /// Compute a diff against an old config. Used by SIGHUP reload to
    /// apply only the fields that may change without restart.
    pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
        // `new`, destructured exhaustively and with no `..`, so that adding a
        // field to `Config` does not compile until this function reaches it.
        // Naming the field in the pattern is not enough on its own: the field
        // has to be compared as well.
        //
        // The two halves are not enforced by the same thing, and this note
        // used to run them together:
        //
        // * A field **not named** is `error[E0027]: pattern does not mention
        //   field` — a hard compile error under a bare `cargo build`, with no
        //   flags and no lint configuration involved.
        // * A field **named but never compared** is `warning: unused
        //   variable`, which is a *rustc* lint. `Cargo.toml`'s
        //   `[workspace.lints.clippy] all = "deny"` does not reach it — that
        //   denies clippy's lints, not rustc's. It becomes an error under
        //   `mise run lint` (`cargo clippy … -- -D warnings`) and under any
        //   build carrying `RUSTFLAGS=-D warnings`, which
        //   `.github/workflows/ci.yml` sets for the whole workflow. A plain
        //   local `cargo build` compiles it and prints a warning.
        //
        // So the first half is a build error everywhere and the second half
        // holds wherever warnings are denied, which is the lint task and CI.
        // Both were demonstrated.
        //
        // Neither half sees `field: _`. That binds nothing, so there is no
        // unused binding to warn about and the field simply leaves the diff —
        // verified. `diff_profiles` uses `id: _` deliberately, because `id` is
        // the index key rather than a compared field; it is the one spelling
        // this invariant cannot detect, and it is not a pattern to copy.
        //
        // This replaces a hand-maintained obligation. `reload.rs` states that
        // no changed key is silently dropped, and the previous note here asked
        // whoever added a field to remember; a field added and not compared
        // compiled clean and was absent from the reported set, so the one
        // compile-time seam this module had protected the test fixture and not
        // the invariant.
        let Config {
            default_save_path: new_default_save_path,
            resume_dir: new_resume_dir,
            torrent_dir: new_torrent_dir,
            http_listen: new_http_listen,
            allow_unauthenticated: new_allow_unauthenticated,
            log_level: new_log_level,
            registry_path: new_registry_path,
            connections_limit: new_connections_limit,
            file_pool_size: new_file_pool_size,
            enable_lsd: new_enable_lsd,
            aio_threads: new_aio_threads,
            max_concurrent_http_announces: new_max_concurrent_http_announces,
            upload_rate_limit: new_upload_rate_limit,
            peer_fingerprint: new_peer_fingerprint,
            user_agent: new_user_agent,
            vpn_handshake_max_age_secs: new_vpn_handshake_max_age_secs,
            network_kill_switch: new_network_kill_switch,
            profile: new_profile,
            auth: new_auth,
            pool: new_pool,
        } = new;

        let mut d = ConfigDiff::default();
        // Assigning the new value is not the same as reporting the
        // difference. Each of the five below is `Option` on both sides, so
        // deleting the key assigns `None` — indistinguishable from "this key
        // did not change" to `is_empty`, which is what read the assignment.
        // `record_reloadable` is what makes the difference itself the record,
        // and it is called from the same `if` that assigns, so the two cannot
        // disagree about whether a key changed.
        if old.connections_limit != *new_connections_limit {
            d.connections_limit = *new_connections_limit;
            d.record_reloadable("connections_limit", new_connections_limit.is_some());
        }
        if old.upload_rate_limit != *new_upload_rate_limit {
            d.upload_rate_limit = *new_upload_rate_limit;
            d.record_reloadable("upload_rate_limit", new_upload_rate_limit.is_some());
        }
        if old.max_concurrent_http_announces != *new_max_concurrent_http_announces {
            d.max_concurrent_http_announces = *new_max_concurrent_http_announces;
            d.record_reloadable(
                "max_concurrent_http_announces",
                new_max_concurrent_http_announces.is_some(),
            );
        }
        if old.aio_threads != *new_aio_threads {
            d.aio_threads = *new_aio_threads;
            d.record_reloadable("aio_threads", new_aio_threads.is_some());
        }
        if old.enable_lsd != *new_enable_lsd {
            d.enable_lsd = *new_enable_lsd;
            d.record_reloadable("enable_lsd", new_enable_lsd.is_some());
        }
        // `log_level` is reloadable but is not one of the five: it has a
        // serde default, so `Config` holds a `LogLevel` rather than an
        // `Option`, and deleting the key produces the default value rather
        // than an absence. `Some(..)` here is therefore always a real
        // difference, which is why `is_empty` can read it directly. See
        // `ConfigDiff::reloadable_changes`.
        if old.log_level != *new_log_level {
            d.log_level = Some(*new_log_level);
        }

        // Identity-critical / non-reloadable fields. The rule is that a change
        // to a key this daemon cannot apply is *reported* rather than
        // swallowed: a key that is neither applied nor mentioned leaves the
        // operator believing a reload took.
        //
        // The list below is the whole of `Config` except the six reloadable
        // keys above and `[[profile]]`, which `diff_profiles` reports
        // separately — so every field of the struct reaches one branch or the
        // other.
        //
        // The destructuring at the top of this function is what keeps that
        // true. It used to be a manual obligation, which is a different
        // claim: adding a field and not a branch reopened the gap and
        // compiled.
        //
        // Reaching a branch is not by itself enough to keep a changed file
        // from answering `SIGHUP: config unchanged`, and this comment used to
        // say it was. A branch in this list pushes a **name**, which survives
        // whatever the new value is; the reloadable branches above assign an
        // `Option`, and an assigned `None` — the operator deleting the key —
        // is what `is_empty` reads as "did not change". That is why those
        // branches now record a name too. Neither half is redundant: this one
        // says the field cannot be applied, that one says the field differed.
        if old.default_save_path != *new_default_save_path {
            d.non_reloadable_changes.push("default_save_path");
        }
        if old.resume_dir != *new_resume_dir {
            d.non_reloadable_changes.push("resume_dir");
        }
        if old.torrent_dir != *new_torrent_dir {
            d.non_reloadable_changes.push("torrent_dir");
        }
        if old.file_pool_size != *new_file_pool_size {
            // Not reloadable, and it used to be the one non-reloadable key
            // that was not *reported* either: `diff` skipped it entirely, so a
            // change was neither applied nor mentioned, unlike every other
            // field in this list.
            d.non_reloadable_changes.push("file_pool_size");
        }
        if old.peer_fingerprint != *new_peer_fingerprint {
            d.non_reloadable_changes.push("peer_fingerprint");
        }
        if old.user_agent != *new_user_agent {
            d.non_reloadable_changes.push("user_agent");
        }
        // The authentication posture and the bind address are settled at boot:
        // `AppState.auth` is built once in `startup::boot` and the listener is
        // bound once, so neither can follow a running daemon's config. They
        // are reported here for the same reason as everything above, and one
        // more: an operator who added `[auth]` and reloaded got
        // `SIGHUP: config unchanged` from the journal and `202 Accepted` from
        // `POST /api/reload` while the daemon went on authenticating nothing.
        // Silence there reads as confirmation, which is worse than no signal.
        if old.auth != *new_auth {
            d.non_reloadable_changes.push("auth");
        }
        if old.allow_unauthenticated != *new_allow_unauthenticated {
            d.non_reloadable_changes.push("allow_unauthenticated");
        }
        if old.http_listen != *new_http_listen {
            d.non_reloadable_changes.push("http_listen");
        }
        // These three arrived with the posture check, and five more came with
        // it: eight non-reloadable keys `diff` did not look at, not three.
        // Four of those five are immediately below; the fifth,
        // `default_save_path`, heads this block.
        // Each is read exactly once and then never consulted again —
        // `registry_path` and `pool` when `startup::boot` opens the registry
        // and the pool, `vpn_handshake_max_age_secs` when the health monitor
        // is constructed, `network_kill_switch` when `killswitch::enable`
        // runs at boot — so none of them can follow a running daemon either.
        //
        // `network_kill_switch` is the one that matters: an operator who
        // turns the fail-closed kill switch on and reloads was told the
        // config was unchanged, and would believe a security control had
        // taken effect that had not.
        if old.registry_path != *new_registry_path {
            d.non_reloadable_changes.push("registry_path");
        }
        if old.vpn_handshake_max_age_secs != *new_vpn_handshake_max_age_secs {
            d.non_reloadable_changes.push("vpn_handshake_max_age_secs");
        }
        if old.network_kill_switch != *new_network_kill_switch {
            d.non_reloadable_changes.push("network_kill_switch");
        }
        if old.pool != *new_pool {
            d.non_reloadable_changes.push("pool");
        }
        d.profile_changes = diff_profiles(&old.profile, new_profile);
        d
    }

    /// Compose libtorrent settings from the spec high_performance_seed
    /// preset overrides plus the operator's overrides in this Config.
    pub fn libtorrent_settings(&self) -> libtorrent_safe::Settings {
        let mut s = libtorrent_safe::Settings::server_seed_overrides();
        if let Some(v) = self.connections_limit {
            s.connections_limit = Some(v);
        }
        if let Some(v) = self.file_pool_size {
            s.file_pool_size = Some(v);
        }
        if let Some(v) = self.enable_lsd {
            s.enable_lsd = Some(v);
        }
        if let Some(v) = self.aio_threads {
            s.aio_threads = Some(v);
        }
        if let Some(v) = self.max_concurrent_http_announces {
            s.max_concurrent_http_announces = Some(v);
        }
        if let Some(v) = self.upload_rate_limit {
            s.upload_rate_limit = Some(v);
        }
        if let Some(v) = self.peer_fingerprint.as_ref() {
            s.peer_fingerprint = Some(v.clone());
        }
        if let Some(v) = self.user_agent.as_ref() {
            s.user_agent = Some(v.clone());
            s.handshake_client_version = Some(v.clone());
        }
        s
    }

    /// The boot refusals that are pure functions of the config file.
    ///
    /// `startup::boot` refuses `network_kill_switch = true` with no tunnel to
    /// confine egress to, or with a host profile the ruleset would silently
    /// cut off, and `--check-config` — which
    /// `deploy/torrentd.service` runs as its `ExecStartPre`, so that a bad
    /// configuration fails before `ExecStart` rather than under
    /// `Restart=on-failure` — did not. The configuration that reaches it, a
    /// set of profiles with zero tunnels, is new in this change.
    ///
    /// Called from [`Config::validate_inner`], above the authentication
    /// posture, so it reaches everything that loads a config: the daemon,
    /// `--check-config`, the SIGHUP pump and the operator subcommands alike.
    ///
    /// It was kept out of [`Config::validate`] on the ground that a boot rule
    /// is not a well-formedness rule and that `vpn check` and the `pool`
    /// subcommands "have no business refusing it". Two things were wrong with
    /// that. It *is* a pure function of the config file — this function reads
    /// nothing else — which is the definition "shape before policy" uses; and
    /// running it after `Config::load` returned put it below the posture
    /// check, so the operator was told to configure authentication before
    /// being told the kill switch had no tunnel to confine egress to.
    ///
    /// Refusing an operator subcommand here is the intended consequence: a
    /// configuration the daemon will not boot from is one `pool scan` should
    /// not be writing an index from either.
    pub fn check_boot_rules(&self) -> anyhow::Result<()> {
        if self.network_kill_switch && !self.profile.iter().any(|p| p.is_vpn()) {
            anyhow::bail!(
                "network_kill_switch = true but no profile uses network = \"vpn\". \
                 The kill switch confines the daemon's egress to its profiles' tunnel \
                 interfaces; with no tunnel there is nothing to confine it to, and \
                 every profile would keep seeding from the host's own address with no \
                 backstop. Configure a vpn profile, or unset network_kill_switch.",
            );
        }
        // The ruleset matches on the daemon's uid, which every profile's
        // sessions share, and admits only loopback and the tunnel interfaces.
        // A host profile's sockets are bound to the host's own interfaces, so
        // under the kill switch every packet it sends is dropped while the
        // profile stays Active and `/healthz` answers 200. Admitting the host
        // interfaces instead would admit every vpn profile's leak through them
        // too, which is the one thing the switch exists to stop.
        if self.network_kill_switch {
            let host: Vec<&str> = self
                .profile
                .iter()
                .filter(|p| !p.is_vpn())
                .map(|p| p.id.as_str())
                .collect();
            if !host.is_empty() {
                anyhow::bail!(
                    "network_kill_switch = true but host profile(s) {} are configured. The \
                     kill switch confines the whole daemon's egress to its vpn tunnel \
                     interfaces, so a network = \"host\" profile could send nothing at all \
                     while reporting itself healthy. Run host profiles in a separate daemon \
                     without the kill switch, or unset network_kill_switch.",
                    host.join(", "),
                );
            }
        }
        Ok(())
    }

    /// A profile's effective `peer_fingerprint_hex` and `user_agent` — its own
    /// values, or the top-level defaults it inherits where it sets none.
    ///
    /// `libtorrent_settings()` seeds every session from the top-level keys and
    /// `startup.rs` overrides only where the profile set its own, so this pair
    /// is what actually goes on the wire.
    fn effective_identity<'a>(
        &'a self,
        p: &'a ProfileConfig,
    ) -> (Option<&'a str>, Option<&'a str>) {
        (
            p.peer_fingerprint_hex
                .as_deref()
                .or(self.peer_fingerprint.as_deref()),
            p.user_agent.as_deref().or(self.user_agent.as_deref()),
        )
    }

    /// Refuse two profiles that would announce one identity.
    ///
    /// `ProfileConfig::validate_set` sees only what a `[[profile]]` spells out,
    /// so it closes the copy-paste spelling and not the inherited one: a host
    /// profile that declares neither key — the documented way to use a
    /// top-level default — inherits the same 8-byte peer-id prefix and client
    /// string as a vpn profile that declares them explicitly, and both
    /// sessions put them on the wire, one from the tunnel address and one from
    /// the machine's real address. That is the cross-account correlation
    /// `torrentd_engine::profile`'s Safety Rules 2-4 exist to prevent, and its
    /// stated consequence is a permanent tracker ban.
    ///
    /// Both keys reach one `libtorrent_safe::Settings` field in one encoding,
    /// so the collision is expressible however it is spelled.
    ///
    /// **A pair that both inherit the top-level default is exempt.** The
    /// collision this guards is one profile inheriting while another declares,
    /// across postures — that is the shape where an operator cannot see from
    /// the file that two sessions share an identity. Two profiles that both
    /// write nothing are using the key exactly as the sample documents it
    /// ("Default peer identity for profiles that do not set their own"), and
    /// refusing them contradicts the recorded answer to "require identity
    /// fields on host profiles too?" — No, because two host profiles are one
    /// host and requiring them to differ would be theatre. Before the check
    /// moved to *effective* values only explicit ones entered the sets, so
    /// two omitting profiles could not collide; the exemption restores that.
    ///
    /// The error names the key the operator actually wrote. When the value
    /// came from the top level that is `peer_fingerprint`, not
    /// `peer_fingerprint_hex` — a key that appears nowhere in their file.
    fn validate_effective_identities(&self) -> Result<(), ProfileConfigError> {
        let mut seen_fp: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut seen_ua: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for p in &self.profile {
            let (fp, ua) = self.effective_identity(p);
            if let Some(fp) = fp {
                // Inherited by this profile *and* by the one already holding
                // the value: both wrote nothing, so there is nothing to
                // distinguish and nothing hidden.
                let inherited = p.peer_fingerprint_hex.is_none();
                // The default-prefix refusal, on the *effective* fingerprint.
                //
                // `ProfileConfig::validate_set` applies it to a declared
                // `peer_fingerprint_hex` and to nothing else, so a value
                // written once at the top level reached every session that
                // inherited it unchecked — and the value it reached them with
                // was libtorrent's own default prefix, which is what the
                // refusal exists to stop a config from claiming as a
                // deliberate identity. `Config::to_settings` seeds every
                // session from the top-level key and `startup.rs:323`
                // overrides it only where the profile declared its own, so the
                // effective value is what announces, and it is what has to
                // satisfy the rule.
                //
                // Demonstrated before this check existed: a top-level
                // `peer_fingerprint` plus one host profile that writes neither
                // key printed `config OK`, for the hex spelling and for the
                // raw one — while the identical string written as the
                // profile's own `peer_fingerprint_hex` was refused.
                //
                // The *length* rule is deliberately not applied here. It is an
                // encoding rule for the key that names an encoding:
                // `peer_fingerprint_hex` is sixteen hex characters, while the
                // top-level `peer_fingerprint` has been documented as a raw
                // eight-character prefix in every sample this repository has
                // shipped (`"-LT20C0-"` before this change, `"-XX1234-"`
                // after). Applying "16 hex chars" to it would refuse the
                // shipped sample's own value, and unifying the two encodings
                // is a change to a pre-existing operator-facing key rather
                // than to anything this change introduced.
                //
                // The key named is the one the operator wrote, as it is for
                // the duplicate errors below.
                if ProfileConfig::is_libtorrent_default_fingerprint(fp) {
                    return Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key: if inherited {
                            "peer_fingerprint"
                        } else {
                            "peer_fingerprint_hex"
                        },
                    });
                }
                match seen_fp.insert(fp, p.id.as_str()) {
                    Some(prev) if inherited && self.inherits_fingerprint(prev) => {}
                    Some(_) => {
                        return Err(ProfileConfigError::DuplicateFingerprint {
                            key: if inherited {
                                "peer_fingerprint"
                            } else {
                                "peer_fingerprint_hex"
                            },
                            value: fp.to_string(),
                        })
                    }
                    None => {}
                }
            }
            if let Some(ua) = ua {
                let inherited = p.user_agent.is_none();
                match seen_ua.insert(ua, p.id.as_str()) {
                    Some(prev) if inherited && self.inherits_user_agent(prev) => {}
                    Some(_) => {
                        return Err(ProfileConfigError::DuplicateUserAgent {
                            key: "user_agent",
                            value: ua.to_string(),
                        })
                    }
                    None => {}
                }
            }
        }
        Ok(())
    }

    /// Whether the profile named `id` declares no `peer_fingerprint_hex`.
    fn inherits_fingerprint(&self, id: &str) -> bool {
        self.profile
            .iter()
            .find(|p| p.id.as_str() == id)
            .is_some_and(|p| p.peer_fingerprint_hex.is_none())
    }

    /// Whether the profile named `id` declares no `user_agent`.
    fn inherits_user_agent(&self, id: &str) -> bool {
        self.profile
            .iter()
            .find(|p| p.id.as_str() == id)
            .is_some_and(|p| p.user_agent.is_none())
    }

    /// A profile's effective resume and `.torrent` directories — its own
    /// overrides, or the `<base>/<id>` the two stores derive.
    ///
    /// Mirrors `FsResumeStore::dir_for` and `FsTorrentStore::dir_for`, which is
    /// what `startup.rs` assembles from exactly these two fields.
    pub(crate) fn effective_store_dirs(&self, p: &ProfileConfig) -> (PathBuf, PathBuf) {
        let resolve = |explicit: Option<&PathBuf>, base: &Path| -> PathBuf {
            let raw = explicit
                .cloned()
                .unwrap_or_else(|| base.join(p.id.as_str()));
            // On a first run the directory may not exist yet, so fall back to
            // the literal value and let startup create it.
            raw.canonicalize().unwrap_or(raw)
        };
        (
            resolve(p.resume_dir.as_ref(), &self.resume_dir),
            resolve(p.torrent_dir.as_ref(), &self.torrent_dir),
        )
    }

    /// Refuse two profiles that would share a store directory.
    ///
    /// `validate_set` de-duplicates only the *explicit* overrides against each
    /// other and cannot see a derived path, so an override set to another
    /// profile's `<base>/<id>` validated clean and two sessions then read one
    /// store. On a fresh registry the first-declared profile claims every
    /// info-hash it finds there and seeds another account's torrents under its
    /// own fingerprint, user agent and tunnel address.
    ///
    /// **Equality only.** This rule also refused *containment*, on the stated
    /// ground that "`load_all` filters on the file name alone, so a profile
    /// pointed at a directory that contains another's loads that profile's
    /// state as its own". That is not true of either store:
    /// `FsResumeStore::load_all` and `FsTorrentStore::load_all` both walk one
    /// level with `fs::read_dir` and skip any entry whose name does not end in
    /// `.resume` / `.torrent`, which a sibling `<id>/` directory never does. A
    /// contained profile's files sit in a subdirectory the outer profile's
    /// scan does not descend into, so containment costs nothing.
    ///
    /// It was not free, though: the documented upgrade is to point the
    /// pre-profiles profile's `resume_dir` and `torrent_dir` at the old roots
    /// (`docs/running.md` step 3, and `deploy/torrentd.sample.toml` says an
    /// override is "also how you point a profile at directories from a
    /// pre-profiles deployment"). Every other profile's derived
    /// `<base>/<id>` is inside those roots, so a deployment adding its second
    /// account — the whole subject of this change — was refused for following
    /// the two places that tell it what to write.
    fn validate_effective_store_dirs(&self) -> Result<(), ProfileConfigError> {
        let dirs: Vec<(&str, PathBuf, PathBuf)> = self
            .profile
            .iter()
            .map(|p| {
                let (r, t) = self.effective_store_dirs(p);
                (p.id.as_str(), r, t)
            })
            .collect();

        for (i, (_, a_resume, a_torrent)) in dirs.iter().enumerate() {
            for (_, b_resume, b_torrent) in dirs.iter().skip(i + 1) {
                for (key, a, b) in [
                    ("resume_dir", a_resume, b_resume),
                    ("torrent_dir", a_torrent, b_torrent),
                ] {
                    if a == b {
                        return Err(match key {
                            "resume_dir" => ProfileConfigError::DuplicateResumeDir(a.clone()),
                            _ => ProfileConfigError::DuplicateTorrentDir(a.clone()),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Where the assignment registry should be persisted.
    pub fn registry_path(&self) -> PathBuf {
        self.registry_path
            .clone()
            .unwrap_or_else(|| self.state_dir().join(REGISTRY_FILE))
    }

    /// The pre-rename registry file, if it is the only one present.
    ///
    /// Renaming slots to profiles renamed this file too, and a daemon that
    /// simply started with an empty registry would have no record of which
    /// profile owns which info-hash — which is the authority for the
    /// cross-profile uniqueness rule. It would then happily load the same
    /// torrent into two profiles. Read the old name once instead.
    pub fn legacy_registry_path(&self) -> Option<PathBuf> {
        if self.registry_path.is_some() {
            return None;
        }
        let legacy = self.state_dir().join(LEGACY_REGISTRY_FILE);
        (legacy.exists() && !self.registry_path().exists()).then_some(legacy)
    }

    /// Where the pool index lives.
    pub fn pool_db_path(&self) -> PathBuf {
        self.pool
            .as_ref()
            .and_then(|p| p.db_path.clone())
            .unwrap_or_else(|| self.state_dir().join("pool.db"))
    }

    /// Directory the daemon keeps its own state in, derived from `resume_dir`.
    pub fn state_dir(&self) -> PathBuf {
        self.resume_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/var/lib/torrentd"))
    }

    /// Where a profile's DHT/session state is persisted.
    ///
    /// Per profile, because more than one host profile can run DHT and a
    /// single shared file would have them overwriting each other's routing
    /// table. This replaces the top-level `session_state_path` key, which
    /// could only ever have described one session.
    ///
    /// A pre-profiles `session_state.dat` beside this one is **not** migrated,
    /// while the assignment registry in the same directory is — the asymmetry
    /// is deliberate. The registry cannot be reconstructed: losing it loses
    /// which torrent belonged to which account, which is the property the
    /// engine's Safety Rules exist to protect. A DHT routing table rebuilds
    /// from the bootstrap nodes within minutes, and picking a profile to
    /// inherit one would seed that profile's session with another's peer
    /// history. The upgrade note in `docs/running.md` tells the operator to
    /// delete the orphan.
    pub fn session_state_path(&self, profile: &ProfileId) -> PathBuf {
        self.state_dir()
            .join(format!("session_state-{}.dat", profile.as_str()))
    }
}

/// Which of the two non-reloadable warnings a `[[profile]]` change is owed.
///
/// Both classes are equally non-reloadable. They differ in what the operator
/// is told and in what an alert rule can watch for: Safety Rule 7's warning
/// exists for the privacy event of an identity changing under a live session,
/// so a rate-cap edit must not emit it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProfileChangeKind {
    /// The account a tracker sees: the network block, the peer fingerprint,
    /// the user agent, and the profile set itself.
    ///
    /// The store directories are deliberately **not** here, though they were.
    /// The definition below is what decides it: nothing a tracker reads is not
    /// identity, and no announce, handshake or peer message carries where a
    /// profile keeps its resume and `.torrent` files. Classing them here made
    /// `docs/running.md`'s own upgrade step 3 — the documented way to keep
    /// your library across the move to per-profile subdirectories — emit
    /// Safety Rule 7's privacy warning, which is the line an alert rule
    /// watches for an identity changing under a live session.
    Identity,
    /// Non-reloadable for its own reason, but nothing a tracker reads: the
    /// per-profile rate cap, the tracker-domain list, and the store
    /// directories, which are fixed at startup because the stores are opened
    /// then.
    NonIdentity,
}

/// One `[[profile]]` change a reload cannot apply, with the class it belongs
/// to.
///
/// The class travels with the change rather than being recovered from the
/// key's name afterwards. `reload.rs` kept a two-element list of the
/// non-identity key names and a comment saying out loud that a key added to
/// `diff_profiles` belonged in it — a pairing with nothing enforcing it, one
/// module away from the comparison that creates the obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileChange {
    /// `"<profile_id>.<key>"`, or a sentence for a profile added or removed.
    pub what: String,
    pub kind: ProfileChangeKind,
}

impl std::fmt::Display for ProfileChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.what)
    }
}

/// Result of `Config::diff`. Reloadable fields are populated with the
/// Report `[[profile]]` changes that a reload cannot apply.
///
/// Most of what is compared here is identity-critical: the tunnel a session is
/// bound to, the port it announces, and the peer fingerprint and user agent a
/// tracker sees. Changing any of them means a different account identity to the
/// tracker, which is a restart — not something to swap under a live session.
/// Adding or removing profiles is likewise a restart, since the profile set is
/// fixed when sessions are built.
///
/// The rest is non-reloadable without being identity, and says so here: the
/// per-profile rate cap and tracker-domain list, and the two store
/// directories, which are fixed at startup because the stores are opened then
/// and which nothing on the wire carries.
fn diff_profiles(old: &[ProfileConfig], new: &[ProfileConfig]) -> Vec<ProfileChange> {
    use std::collections::BTreeMap;

    use ProfileChangeKind::Identity;
    use ProfileChangeKind::NonIdentity;
    let index = |v: &[ProfileConfig]| -> BTreeMap<String, ProfileConfig> {
        v.iter()
            .map(|s| (s.id.as_str().to_string(), s.clone()))
            .collect()
    };
    let (o, n) = (index(old), index(new));
    let mut out = Vec::new();

    for id in n.keys() {
        if !o.contains_key(id) {
            out.push(ProfileChange {
                what: format!("{id}: added (the profile set is fixed at startup)"),
                // Which accounts exist is as fixed at startup as who they
                // announce as.
                kind: Identity,
            });
        }
    }
    for (id, a) in &o {
        let Some(b) = n.get(id) else {
            out.push(ProfileChange {
                what: format!("{id}: removed (the profile set is fixed at startup)"),
                kind: Identity,
            });
            continue;
        };
        let mut field = |name: &str, changed: bool, kind: ProfileChangeKind| {
            if changed {
                out.push(ProfileChange {
                    what: format!("{id}.{name}"),
                    kind,
                });
            }
        };
        // Destructured exhaustively, with no `..`, and that is the point.
        //
        // The class each field is owed now travels on `ProfileChange`, so a
        // field compared here cannot be left unclassified — but nothing made a
        // field added to `ProfileConfig` get compared here *at all*. The
        // hand-maintained list of key names that used to live in `reload.rs`
        // was deleted for being an obligation written down rather than
        // enforced; the set of compared fields was the same list one module
        // over, and it was still hand-maintained.
        //
        // `ProfileNetwork`'s own fields were already safe, because the block is
        // compared as a single value. These seven were not. Naming every one
        // of them in a pattern is what makes adding an eighth stop compiling
        // until somebody says which warning it is owed — which is the
        // consequence of forgetting, and it is silent: a SIGHUP that changed
        // only the forgotten key produced an empty diff and logged "SIGHUP:
        // config unchanged" over a file that plainly had changed.
        //
        // `id` is bound and ignored deliberately: it is the map key these two
        // were matched on, so it cannot differ here.
        //
        // `id: _` is how that is spelled, and it is also the one spelling this
        // invariant cannot detect: `_` binds nothing, so there is no unused
        // binding for the second half of the check to catch, and a field given
        // it leaves the diff in silence. It is correct here and is not to be
        // copied to a field that has something to compare.
        let ProfileConfig {
            id: _,
            network,
            peer_fingerprint_hex,
            user_agent,
            resume_dir,
            torrent_dir,
            allowed_tracker_domains,
            upload_rate_limit,
        } = a;
        let ProfileConfig {
            id: _,
            network: b_network,
            peer_fingerprint_hex: b_peer_fingerprint_hex,
            user_agent: b_user_agent,
            resume_dir: b_resume_dir,
            torrent_dir: b_torrent_dir,
            allowed_tracker_domains: b_allowed_tracker_domains,
            upload_rate_limit: b_upload_rate_limit,
        } = b;
        // The whole network block is identity: which tunnel, which port,
        // whether DHT runs. Comparing it as one value means a new field
        // cannot be forgotten here the way `file_pool_size` was forgotten
        // from the top-level diff.
        field("network", network != b_network, Identity);
        field(
            "peer_fingerprint_hex",
            peer_fingerprint_hex != b_peer_fingerprint_hex,
            Identity,
        );
        field("user_agent", user_agent != b_user_agent, Identity);
        // Not identity. `ProfileChangeKind`'s own definitions decide this:
        // `Identity` is "the account a tracker sees" and `NonIdentity` is
        // "nothing a tracker reads" — and where a profile keeps its resume and
        // `.torrent` files is the second. No announce carries it, no handshake
        // carries it, and nothing on the wire changes when it moves.
        //
        // They are still non-reloadable, for their own reason: the stores are
        // opened once at startup and the partitioning is fixed with them. What
        // changes is which of the two warnings the operator gets.
        // `reload.rs` says the privacy string exists for "the privacy event"
        // and that "nothing that is not identity may emit it", and it is the
        // line an alert rule watches. Classing the store directories as
        // identity made the runbook's own upgrade step 3 — "set that profile's
        // own `resume_dir` and `torrent_dir` to the old paths", the documented
        // way to avoid losing the library on upgrade — fire a privacy alert
        // for doing exactly what the runbook says.
        field("resume_dir", resume_dir != b_resume_dir, NonIdentity);
        field("torrent_dir", torrent_dir != b_torrent_dir, NonIdentity);
        // The two keys outside the network block. Neither is applied by a
        // reload — the add path reads `ProfileRegistry`'s immutable startup
        // snapshot and nothing rebuilds it — and without them here a SIGHUP
        // that changed only one of them produced an empty diff and logged
        // "SIGHUP: config unchanged" over a file that plainly had. They are
        // exactly the fields the comment above claimed could not be
        // forgotten — and the third argument is what stops the *class* being
        // forgotten now that a field can have one.
        field(
            "upload_rate_limit",
            upload_rate_limit != b_upload_rate_limit,
            NonIdentity,
        );
        field(
            "allowed_tracker_domains",
            allowed_tracker_domains != b_allowed_tracker_domains,
            NonIdentity,
        );
    }
    out
}

/// new value; `non_reloadable_changes` lists the names that differ but
/// can't be applied without restart.
#[derive(Debug, Default)]
pub struct ConfigDiff {
    pub connections_limit: Option<u32>,
    pub upload_rate_limit: Option<u32>,
    pub max_concurrent_http_announces: Option<u32>,
    pub aio_threads: Option<u32>,
    pub enable_lsd: Option<bool>,
    pub log_level: Option<LogLevel>,
    /// The reloadable settings keys that **differed**, named independently of
    /// the value they differ to.
    ///
    /// The five `Option` fields above cannot carry that on their own. All five
    /// are `Option` in `Config` too, so deleting one leaves the comparison
    /// with nothing to assign but `None` — and `None` is exactly what
    /// "unchanged" looks like to [`ConfigDiff::is_empty`]. Every one of these
    /// keys is documented as optional in `deploy/torrentd.sample.toml` ("omit
    /// any to use the preset's default"), so deleting one is the documented
    /// way back to the default, and it answered `SIGHUP: config unchanged` on
    /// all five.
    ///
    /// `log_level` is not in this list: it has a serde default, so `Config`
    /// holds a `LogLevel` rather than an `Option` and deleting the key
    /// produces the default value rather than an absence. `Some(..)` on the
    /// field above is therefore always a real difference, which is why
    /// [`ConfigDiff::is_empty`] can read it directly. It is also not a
    /// `libtorrent_safe::Settings` key, so `reload::withheld_reloadable_keys`
    /// — which subtracts a profile's patch field set from this list — must not
    /// see it.
    pub reloadable_changes: Vec<&'static str>,
    /// The subset of `reloadable_changes` the new file gives no value to,
    /// because the operator deleted the key.
    ///
    /// Reported on its own: the preset default such a key falls back to is
    /// chosen when the session is built, and a `Settings` patch has no way to
    /// say "unset this", so a deletion cannot be applied to a live session at
    /// all. That is a different fact from a key withheld from one profile by
    /// Safety Rule 6, and the journal says so in different words.
    pub reloadable_deletions: Vec<&'static str>,
    pub non_reloadable_changes: Vec<&'static str>,
    /// Per-profile fields that changed and were ignored, each carrying the
    /// class its warning is owed. Safety Rule 7 requires a warning for the
    /// identity ones and `Config::diff` used to skip `[[profile]]` entirely, so
    /// changing a profile's VPN interface, port, fingerprint, user agent or
    /// directories on SIGHUP was swallowed in silence.
    pub profile_changes: Vec<ProfileChange>,
}

impl ConfigDiff {
    /// Build the `Settings` patch for `profile`, containing only the
    /// reloadable fields that changed and are permitted to reach it.
    ///
    /// `enable_lsd` is withheld from every tunnelled profile. Safety Rule 6
    /// says such a profile runs with DHT, PEX and LSD off unconditionally and
    /// that no config key can turn them on — but `enable_lsd` is a top-level
    /// *reloadable* key that was applied to every session alike, so
    /// `enable_lsd = true` plus a SIGHUP quietly re-enabled local peer
    /// discovery on exactly the sessions that must never have it. A host
    /// profile still honours the key, which is the only place it means
    /// anything.
    ///
    /// `upload_rate_limit` is withheld in the same shape, from a profile that
    /// sets its own. `startup.rs` applies a per-profile `upload_rate_limit`
    /// over the top-level one at boot; passing the top-level value through
    /// here meant that editing only the top-level key and sending SIGHUP
    /// patched every session alike and silently discarded the override until
    /// the next restart. A profile that sets nothing still takes the
    /// top-level value, which is what makes it a default.
    pub fn to_settings_patch_for(&self, profile: &ProfileConfig) -> SettingsPatch {
        // Set one field and name it, in one statement, so the patch and the
        // record of what it carries cannot be written apart from each other.
        macro_rules! set {
            ($patch:expr, $field:ident, $value:expr) => {
                if let Some(v) = $value {
                    $patch.settings.$field = Some(v);
                    $patch.fields.push(stringify!($field));
                }
            };
        }

        let mut patch = SettingsPatch::default();
        set!(patch, connections_limit, self.connections_limit);
        set!(
            patch,
            upload_rate_limit,
            if profile.upload_rate_limit.is_some() {
                None
            } else {
                self.upload_rate_limit
            }
        );
        set!(
            patch,
            max_concurrent_http_announces,
            self.max_concurrent_http_announces
        );
        set!(patch, aio_threads, self.aio_threads);
        set!(
            patch,
            enable_lsd,
            if profile.is_vpn() {
                None
            } else {
                self.enable_lsd
            }
        );
        patch
    }

    /// True when the patch `to_settings_patch_for` built sets nothing, so
    /// handing it to `apply_settings` would be a no-op.
    ///
    /// The reload pump logs `SIGHUP: settings applied` per profile after that
    /// call, and once the non-reloadable keys are reported the diff for an
    /// edit that touched *only* them is no longer empty — so the pump fell
    /// through its warnings into the settings loop and closed the reload with
    /// a positive confirmation that nothing had been applied. A journal read
    /// at the default `info` level shows that line last.
    ///
    /// This reads [`SettingsPatch::fields`] — the names
    /// `to_settings_patch_for` recorded as it set them — rather than
    /// enumerating the fields a patch can carry. An enumeration here was a
    /// second, hand-maintained copy of the reloadable set: a key added to
    /// `ConfigDiff`, to `Config::diff` and to `to_settings_patch_for` and not
    /// to the enumeration made this return `true` over a patch that carried
    /// it, so the pump skipped `apply_settings` and `withheld_reloadable_keys`
    /// had nothing to report, and the whole journal for that reload was
    /// `received SIGHUP`. Nothing about that failed to compile.
    pub fn settings_patch_is_empty(patch: &SettingsPatch) -> bool {
        patch.fields.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        // `reloadable_changes` covers the five settings keys, including the
        // ones a deletion leaves as `None`. `log_level` is read directly; see
        // the field's own documentation for why it is not in the list.
        self.reloadable_changes.is_empty()
            && self.log_level.is_none()
            && self.non_reloadable_changes.is_empty()
            && self.profile_changes.is_empty()
    }

    /// Record that a reloadable settings key differed, whatever it differs to.
    ///
    /// `has_value` is false when the new file deletes the key, which is the
    /// case the assignment alone could not express.
    fn record_reloadable(&mut self, key: &'static str, has_value: bool) {
        self.reloadable_changes.push(key);
        if !has_value {
            self.reloadable_deletions.push(key);
        }
    }
}

/// A `libtorrent_safe::Settings` patch together with the names of the fields
/// it sets.
///
/// The names are pushed by the same statement that sets the field, in
/// [`ConfigDiff::to_settings_patch_for`], so there is one place a reloadable
/// key is written down and nothing downstream re-enumerates the set.
/// [`ConfigDiff::settings_patch_is_empty`] and
/// `reload::withheld_reloadable_keys` both read [`SettingsPatch::fields`]; before
/// they did, each carried its own five-item list over a struct with roughly
/// twenty-five fields, and a key added to the reloadable set and to neither
/// list was neither applied nor reported.
#[derive(Debug, Default)]
pub struct SettingsPatch {
    /// What `apply_settings` is handed.
    pub settings: libtorrent_safe::Settings,
    /// The `Settings` field names this patch sets, in the order it set them.
    pub fields: Vec<&'static str>,
}

impl Config {
    /// A minimal one-profile config with `[pool]` rooted at `dir/pool`.
    ///
    /// Test-only, and deliberately built from the real types rather than from
    /// TOML, so a required field added to `Config` breaks this at compile time
    /// instead of leaving the tests exercising a shape the daemon never sees.
    ///
    /// It was `toml::from_str` until the authentication posture became a
    /// required statement, and the promised compile break did not happen. The
    /// helper went on building a config with no `[auth]` and no opt-out —
    /// exactly the shape `Config::validate` now refuses — and its callers
    /// build `AppState`/`PoolService` from it without ever validating, so the
    /// seam meant to catch that was the one asserting it already had. Every
    /// field is listed below with no `..Default::default()`, which is what
    /// makes the paragraph above true rather than aspirational.
    ///
    /// The posture stated is the opt-out on a loopback bind: the shape
    /// `deploy/torrentd.sample.toml` ships, and the one these tests mean.
    #[cfg(test)]
    pub fn minimal_for_tests(dir: &Path, allow_mutations: bool) -> Self {
        std::fs::create_dir_all(dir.join("pool")).unwrap();
        std::fs::create_dir_all(dir.join("library")).unwrap();
        Config {
            default_save_path: dir.join("data"),
            resume_dir: dir.join("resume"),
            torrent_dir: dir.join("torrents"),
            http_listen: Self::default_http_listen(),
            allow_unauthenticated: true,
            log_level: Self::default_log_level(),
            registry_path: None,
            connections_limit: None,
            file_pool_size: None,
            enable_lsd: None,
            aio_threads: None,
            max_concurrent_http_announces: None,
            upload_rate_limit: None,
            peer_fingerprint: None,
            user_agent: None,
            vpn_handshake_max_age_secs: Self::default_handshake_max_age(),
            network_kill_switch: false,
            profile: vec![],
            auth: None,
            pool: Some(PoolConfig {
                roots: vec![dir.join("pool")],
                library_dir: dir.join("library"),
                db_path: Some(dir.join("pool.db")),
                max_concurrent_verify: 1,
                import_legacy_registry: false,
                allow_mutations,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn write_cfg(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("torrentd.toml");
        fs::write(&p, body).unwrap();
        p
    }

    /// Top-level keys only. `[[profile]]` is a TOML *table*, so anything a
    /// test appends has to land before it — hence the split.
    const TOP_LEVEL: &str = r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
log_level = "info"
connections_limit = 10000
allow_unauthenticated = true
"#;

    const ONE_HOST_PROFILE: &str = r#"
[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
"#;

    /// A minimal valid config.
    fn single_session() -> String {
        format!("{TOP_LEVEL}{ONE_HOST_PROFILE}")
    }

    /// A valid config with `extra` appended to the top-level keys.
    fn with_top_level(extra: &str) -> String {
        format!("{TOP_LEVEL}{extra}\n{ONE_HOST_PROFILE}")
    }

    #[test]
    fn a_file_pool_size_change_is_reported_rather_than_swallowed() {
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.file_pool_size = Some(2048);
        let d = Config::diff(&a, &b);
        assert!(
            d.non_reloadable_changes.contains(&"file_pool_size"),
            "got {:?}",
            d.non_reloadable_changes,
        );
    }

    #[test]
    fn an_auth_only_edit_is_reported_rather_than_called_unchanged() {
        // The property: a config edit that changes nothing but the
        // authentication posture is a *change*, and `diff` must say so. If it
        // does not, `ConfigDiff::is_empty` is true and `reload::run` logs
        // `SIGHUP: config unchanged` — positive confirmation that a reload
        // took, to an operator whose daemon is still authenticating nothing.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();

        let mut with_auth = a.clone();
        with_auth.auth = Some(crate::auth::AuthConfig {
            password_hash: crate::auth::hash_password("hunter2").unwrap(),
            session_ttl_secs: 43_200,
            token: vec![],
        });
        with_auth.allow_unauthenticated = false;
        let d = Config::diff(&a, &with_auth);
        assert!(
            !d.is_empty(),
            "an auth-only edit must not look like an unchanged config",
        );
        assert!(
            d.non_reloadable_changes.contains(&"auth"),
            "got {:?}",
            d.non_reloadable_changes,
        );
        assert!(
            d.non_reloadable_changes.contains(&"allow_unauthenticated"),
            "got {:?}",
            d.non_reloadable_changes,
        );

        // The bind address is settled once, at `TcpListener::bind`, and is
        // half of the posture the refusal in `validate_auth_posture` judges.
        let mut moved = a.clone();
        moved.http_listen = SocketAddr::from(([127, 0, 0, 1], 9090));
        let d = Config::diff(&a, &moved);
        assert!(!d.is_empty());
        assert!(
            d.non_reloadable_changes.contains(&"http_listen"),
            "got {:?}",
            d.non_reloadable_changes,
        );
    }

    fn host_profile() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("public"),
            network: torrentd_engine::ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".into(),
                dht: false,
            },
            peer_fingerprint_hex: None,
            user_agent: None,
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
        }
    }

    fn vpn_profile() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("acct_a"),
            network: torrentd_engine::ProfileNetwork::Vpn {
                vpn_type: torrentd_engine::VpnType::Wireguard,
                vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
                vpn_interface: "wg0".into(),
                listen_port: Some(6881),
                port_forward: Default::default(),
                port_forward_gateway: None,
            },
            peer_fingerprint_hex: Some("a1b2c3d4e5f60718".into()),
            user_agent: Some("qB/5.0".into()),
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
        }
    }

    #[test]
    fn enable_lsd_never_reaches_a_private_profile() {
        // Safety Rule 6: a private profile has LSD off unconditionally, and no
        // config key may turn it on. `enable_lsd` is top-level and reloadable,
        // so without this filter a SIGHUP re-enabled local peer discovery on
        // exactly the sessions that must never have it.
        let diff = ConfigDiff {
            enable_lsd: Some(true),
            ..Default::default()
        };
        assert_eq!(
            diff.to_settings_patch_for(&host_profile())
                .settings
                .enable_lsd,
            Some(true),
            "a host profile still honours the key",
        );
        assert_eq!(
            diff.to_settings_patch_for(&vpn_profile())
                .settings
                .enable_lsd,
            None,
            "a tunnelled profile must not receive it",
        );
    }

    // -----------------------------------------------------------------
    // Effective identity — the uniqueness rule `validate_set` cannot decide.
    // -----------------------------------------------------------------

    /// Top-level keys, then a vpn profile, then a host profile.
    ///
    /// `top` lands in the daemon-wide block; `host_extra` inside the host
    /// profile's table. The ports are distinct so Safety Rule 8 does not fire
    /// first and mask what is being asserted.
    fn vpn_plus_host(top: &str, host_extra: &str) -> String {
        format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
{top}

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "qBittorrent/5.0.3"

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882"
{host_extra}
"#
        )
    }

    fn refusal(body: &str) -> String {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), body);
        let err = Config::load(&p).expect_err("this configuration must be refused");
        format!("{err:#}")
    }

    #[test]
    fn a_host_profile_may_not_wear_a_vpn_profiles_identity() {
        // The configuration this is written from: the operator writes the VPN
        // profile, copies the table to make the public one, and edits `id`,
        // `network` and `listen_interfaces`. The fingerprint and user agent
        // come along. `startup.rs` applies `peer_fingerprint_hex` to every
        // session with no posture guard, so the private tracker then sees one
        // peer-id prefix announcing from the tunnel address and from the
        // host's real address — the cross-account correlation whose stated
        // consequence is a permanent ban.
        let msg = refusal(&vpn_plus_host(
            "",
            r#"peer_fingerprint_hex = "a1b2c3d4e5f60718""#,
        ));
        assert!(
            msg.contains("peer_fingerprint_hex") && msg.contains("a1b2c3d4e5f60718"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_host_profile_may_not_wear_a_vpn_profiles_user_agent() {
        let msg = refusal(&vpn_plus_host("", r#"user_agent = "qBittorrent/5.0.3""#));
        assert!(
            msg.contains("user_agent") && msg.contains("qBittorrent/5.0.3"),
            "got: {msg}",
        );
    }

    #[test]
    fn two_profiles_may_not_share_a_fingerprint() {
        let dir = tempdir().unwrap();
        let body = format!(
            r#"{TOP_LEVEL}
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "ua-a"

[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg1.conf"
vpn_interface        = "wg1"
listen_port          = 6882
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "ua-b"
"#
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("peer_fingerprint_hex"), "got: {msg}");
    }

    #[test]
    fn a_host_profile_inheriting_the_top_level_identity_collides_with_a_vpn_profile() {
        // F4, reopened. The host profile sets *neither* identity key — the
        // documented way to use a top-level default (`docs/running.md`) — and
        // the vpn profile spells out the same two values. Nothing in
        // `[[profile]]` looks duplicated, so `validate_set` returns `Ok` and
        // `--check-config` printed `config OK`; but `libtorrent_settings()`
        // seeds every session from the top-level keys and `startup.rs`
        // overrides only where a profile set its own, so both sessions put one
        // 8-byte peer-id prefix and one client string on the wire — one from
        // the tunnel address, one from the machine's real address.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(
            msg.contains("a1b2c3d4e5f60718"),
            "the colliding value is named, got: {msg}",
        );
        // The key named is the one the *inheriting* profile would have to
        // change — `peer_fingerprint`, which is what this operator wrote.
        assert!(
            msg.contains("peer_fingerprint") && !msg.contains("peer_fingerprint_hex"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_top_level_user_agent_inherited_by_two_profiles_is_refused() {
        // The user-agent half of the same mechanism, reached on its own: the
        // vpn profile spells out its own fingerprint but takes the top-level
        // user agent, and so does the host profile.
        let msg = refusal(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
user_agent = "qBittorrent/5.0.3"

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "qBittorrent/5.0.3"

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882"
"#,
        );
        assert!(msg.contains("user_agent"), "got: {msg}");
    }

    #[test]
    fn two_host_profiles_both_inheriting_the_top_level_identity_are_accepted() {
        // C48. Two host profiles are one host, so requiring them to differ is
        // theatre — the recorded answer to "require identity fields on host
        // profiles too?" is No, and `validate_set`'s own doc says the same.
        //
        // Checking *effective* values put them in one set by construction:
        // neither writes a key, so both take the top-level default and the
        // pair collided. The operator's only remedies were to delete the
        // top-level keys the sample documents as "Default peer identity for
        // profiles that do not set their own", or to give the pair the
        // distinct values the record calls theatre.
        let dir = tempdir().unwrap();
        let body = format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
peer_fingerprint = "-XX1234-"
user_agent = "libtorrent/2.0"
{}
"#,
            two_host_profiles("", "")
                .split_once("http_listen = \"127.0.0.1:8080\"")
                .unwrap()
                .1
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).expect(
            "two host profiles that both write nothing are using the top-level default \
             exactly as it is documented",
        );
    }

    #[test]
    fn a_top_level_fingerprint_may_not_be_the_libtorrent_default_either() {
        // F49. The refusal bound to `peer_fingerprint_hex` and to nothing
        // else, while `to_settings` hands the top-level `peer_fingerprint` to
        // every session and `startup.rs:323` overrides it only for a profile
        // that declared its own. So a host profile that writes neither key
        // announced whatever the top level said, unchecked — including the one
        // value the refusal exists for, and `--check-config` printed
        // `config OK`.
        //
        // Both spellings, because the two keys spell those eight bytes
        // differently and nothing decodes either: `-LT20C0-` is what actually
        // reaches libtorrent from this key, and it is the value the sample
        // documented for it before this change.
        for spelling in ["-LT20C0-", "2d4c54323043302d"] {
            let msg = refusal(&two_host_profiles_with_top(&format!(
                "peer_fingerprint = {spelling:?}"
            )));
            assert!(
                msg.contains("must not equal libtorrent default"),
                "the {spelling:?} spelling must be refused, got: {msg}",
            );
            assert!(
                msg.contains("peer_fingerprint ") && !msg.contains("peer_fingerprint_hex"),
                "and named as the key the operator actually wrote, got: {msg}",
            );
        }
    }

    #[test]
    fn a_top_level_fingerprint_that_is_not_the_default_is_still_accepted() {
        // The other side: the key is a documented default for profiles that
        // set none, so the refusal must reach the default prefix and nothing
        // else. `"-XX1234-"` is the value the shipped sample carries.
        let dir = tempdir().unwrap();
        let p = write_cfg(
            dir.path(),
            &two_host_profiles_with_top(r#"peer_fingerprint = "-XX1234-""#),
        );
        Config::load(&p).expect("the sample's own top-level value must keep loading");
    }

    /// Two host profiles that declare no identity, under `top`.
    fn two_host_profiles_with_top(top: &str) -> String {
        format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
{top}
{}
"#,
            two_host_profiles("", "")
                .split_once("http_listen = \"127.0.0.1:8080\"")
                .unwrap()
                .1
        )
    }

    #[test]
    fn the_exemption_does_not_reach_a_profile_that_declares_the_value() {
        // The collision the rule guards is one profile inheriting while
        // another declares — the shape where the file does not show that two
        // sessions share an identity. The exemption must not swallow it.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(msg.contains("a1b2c3d4e5f60718"), "got: {msg}");
    }

    #[test]
    fn an_inherited_collision_names_the_key_the_operator_wrote() {
        // The message named `peer_fingerprint_hex` — a key that appears
        // nowhere in a file whose author wrote `peer_fingerprint` at the top
        // level — so it described a line the operator could not find.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(
            !msg.contains("peer_fingerprint_hex"),
            "naming peer_fingerprint_hex sends the operator to a key that appears nowhere \
             in this file, got: {msg}",
        );
        assert!(
            msg.contains("peer_fingerprint"),
            "and the key it does name is the one they wrote, got: {msg}",
        );
    }

    #[test]
    fn a_top_level_identity_with_exactly_one_profile_is_still_accepted() {
        // The configuration the top-level default exists for. Refusing the
        // keys outright would close F4 too, and break this.
        let dir = tempdir().unwrap();
        let body = with_top_level(
            r#"peer_fingerprint = "a1b2c3d4e5f60718"
user_agent = "qBittorrent/5.0.3""#,
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).expect("one profile inheriting the top-level identity is legal");
    }

    // -----------------------------------------------------------------
    // Effective store directories.
    // -----------------------------------------------------------------

    /// Two host profiles with `extra_a` / `extra_b` appended to their tables.
    fn two_host_profiles(extra_a: &str, extra_b: &str) -> String {
        format!(
            r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id                = "acct_a"
network           = "host"
listen_interfaces = "0.0.0.0:6881"
{extra_a}

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882"
{extra_b}
"#
        )
    }

    #[test]
    fn an_override_equal_to_another_profiles_derived_resume_dir_is_refused() {
        // F15. `acct_a` names `<base>/public` explicitly; `public` sets no
        // override, so `FsResumeStore::dir_for` derives exactly that path for
        // it. `validate_set` de-duplicates only the explicit overrides against
        // each other and cannot see a derived path, so this validated clean
        // and both sessions then read one store — and on a fresh registry the
        // first-declared profile claims every info-hash it finds there.
        let msg = refusal(&two_host_profiles(
            r#"resume_dir = "/var/lib/torrentd/resume/public""#,
            "",
        ));
        assert!(
            msg.contains("resume_dir") && msg.contains("/var/lib/torrentd/resume/public"),
            "got: {msg}",
        );
    }

    #[test]
    fn an_override_equal_to_another_profiles_derived_torrent_dir_is_refused() {
        let msg = refusal(&two_host_profiles(
            r#"torrent_dir = "/var/lib/torrentd/torrents/public""#,
            "",
        ));
        assert!(
            msg.contains("torrent_dir") && msg.contains("/var/lib/torrentd/torrents/public"),
            "got: {msg}",
        );
    }

    #[test]
    fn two_explicit_overrides_naming_one_resume_dir_are_refused() {
        let msg = refusal(&two_host_profiles(
            r#"resume_dir = "/srv/shared""#,
            r#"resume_dir = "/srv/shared""#,
        ));
        assert!(msg.contains("resume_dir"), "got: {msg}");
    }

    #[test]
    fn an_override_containing_another_profiles_resume_dir_is_accepted() {
        // C47, first half. This is the documented upgrade: `docs/running.md`
        // step 3 tells an operator to point the pre-profiles profile's
        // `resume_dir` at the old root, and every other profile's derived
        // `<base>/<id>` is inside that root by construction. Refusing
        // containment made that configuration unwritable for any deployment
        // with more than one profile — which is every deployment this change
        // exists for.
        let dir = tempdir().unwrap();
        let p = write_cfg(
            dir.path(),
            &two_host_profiles(r#"resume_dir = "/var/lib/torrentd/resume""#, ""),
        );
        Config::load(&p).expect(
            "an outer resume_dir containing an inner one is the documented upgrade, and \
             neither store descends into a subdirectory",
        );
    }

    #[test]
    fn a_contained_profiles_files_are_invisible_to_the_outer_profiles_load_all() {
        // C47, second half — the property the refusal claimed to protect,
        // pinned rather than assumed. The refusal asserted that "both
        // profiles' sessions would read one store" because "`load_all`
        // filters on the file name alone". Both stores walk exactly one level
        // with `fs::read_dir` and keep only names ending in `.resume`, so the
        // inner profile's directory — whose name is its id — is skipped, and
        // the file inside it is never reached.
        //
        // Without this, dropping the containment rule rests on reading the
        // stores correctly today and nothing notices when that stops being
        // true.
        use torrentd_engine::FsResumeStore;
        use torrentd_engine::ProfileId;
        use torrentd_engine::ResumeStore;

        let dir = tempdir().unwrap();
        let outer_dir = dir.path().join("resume");
        let inner_dir = outer_dir.join("acct_a");
        std::fs::create_dir_all(&inner_dir).unwrap();

        let outer_ih = "aa".repeat(20);
        let inner_ih = "bb".repeat(20);
        std::fs::write(outer_dir.join(format!("{outer_ih}.resume")), b"outer").unwrap();
        std::fs::write(inner_dir.join(format!("{inner_ih}.resume")), b"inner").unwrap();

        // `default` overrides to the outer root; `acct_a` derives
        // `<outer>/acct_a` — exactly the contained pair above.
        let store = FsResumeStore::new(outer_dir.clone())
            .with_profile_dir(ProfileId::new("default"), outer_dir.clone());

        let outer = store.load_all(&ProfileId::new("default")).unwrap();
        assert_eq!(
            outer.len(),
            1,
            "the outer profile must load only its own file, got {outer:?}",
        );
        assert_eq!(outer[0].0.to_hex(), outer_ih);

        let inner = store.load_all(&ProfileId::new("acct_a")).unwrap();
        assert_eq!(inner.len(), 1, "and the inner profile loads only its own");
        assert_eq!(inner[0].0.to_hex(), inner_ih);
    }

    #[test]
    fn a_contained_profiles_torrents_are_invisible_to_the_outer_profiles_load_all() {
        // C53. The rule above is dropped for **both** stores —
        // `validate_effective_store_dirs` says so, and `torrent_dir` is
        // overridable in exactly the same way `resume_dir` is — but only the
        // resume store's half was pinned. The torrent-directory inventory scan
        // is what re-assigns an info-hash whose resume file is gone, so an
        // outer profile that reached into an inner one's directory here would
        // adopt another account's torrents under its own fingerprint, user
        // agent and tunnel address: the same failure the refusal named, by the
        // path nothing was watching.
        use torrentd_engine::FsTorrentStore;
        use torrentd_engine::ProfileId;
        use torrentd_engine::TorrentStore;

        let dir = tempdir().unwrap();
        let outer_dir = dir.path().join("torrents");
        let inner_dir = outer_dir.join("acct_a");
        std::fs::create_dir_all(&inner_dir).unwrap();

        let outer_ih = "aa".repeat(20);
        let inner_ih = "bb".repeat(20);
        std::fs::write(outer_dir.join(format!("{outer_ih}.torrent")), b"outer").unwrap();
        std::fs::write(inner_dir.join(format!("{inner_ih}.torrent")), b"inner").unwrap();

        // `default` overrides to the old root, `acct_a` derives
        // `<outer>/acct_a` inside it: the documented upgrade, which the
        // validator now accepts.
        let store = FsTorrentStore::new(outer_dir.clone())
            .with_profile_dir(ProfileId::new("default"), outer_dir.clone());

        let outer = store.load_all(&ProfileId::new("default")).unwrap();
        assert_eq!(
            outer.len(),
            1,
            "the outer profile must load only its own .torrent, got {outer:?}",
        );
        assert_eq!(outer[0].0.to_hex(), outer_ih);

        let inner = store.load_all(&ProfileId::new("acct_a")).unwrap();
        assert_eq!(inner.len(), 1, "and the inner profile loads only its own");
        assert_eq!(inner[0].0.to_hex(), inner_ih);
    }

    #[test]
    fn distinct_derived_store_directories_are_accepted() {
        // The ordinary case, so the new rule cannot pass by refusing
        // everything: neither profile overrides anything and the derived
        // `<base>/<id>` paths differ by construction.
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &two_host_profiles("", ""));
        Config::load(&p).expect("derived per-profile directories are distinct");
    }

    // -----------------------------------------------------------------
    // The shipped samples.
    // -----------------------------------------------------------------

    /// Nothing in this repository parsed either sample: no test, no CI step.
    /// That is why 265 changed lines of `torrentd.sample.toml` shipped with a
    /// duplicate listen port, a duplicate fingerprint and a duplicate user
    /// agent between its own examples, two daemon-wide keys stranded behind a
    /// `[[profile]]` header where TOML binds them to the table, and a
    /// `network = "host"` profile that made the documented `vpn check`
    /// invocation panic — while a 41-test suite stayed green.
    fn sample(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy")
            .join(name)
    }

    fn load_sample(name: &str) -> Config {
        let path = sample(name);
        Config::load(&path).unwrap_or_else(|e| panic!("{name} must load and validate: {e:#}"))
    }

    #[test]
    fn the_shipped_sample_loads_and_validates() {
        let cfg = load_sample("torrentd.sample.toml");
        assert_eq!(cfg.profile.len(), 1);
        assert_eq!(cfg.profile[0].id.as_str(), "public");
        assert!(
            !cfg.profile[0].is_vpn(),
            "the shipped sample is a host-only deployment; `vpn check` has to cope with it",
        );
    }

    #[test]
    fn the_multi_account_sample_loads_and_validates() {
        // The case the other sample only describes in comments. A commented
        // block is unreachable by any test and by `--check-config`, which is
        // the whole mechanism: the operator uncomments it and finds out then.
        let cfg = load_sample("torrentd.multi-account.sample.toml");
        assert_eq!(cfg.profile.len(), 3);
        assert_eq!(
            cfg.profile.iter().filter(|p| p.is_vpn()).count(),
            2,
            "two accounts, each with its own tunnel",
        );
        assert!(
            cfg.peer_fingerprint.is_none() && cfg.user_agent.is_none(),
            "no top-level identity for a profile to inherit",
        );
        // It ships the kill switch off because it carries a host profile, and
        // turning it on as written must be refused rather than cut `public`
        // off while it reports itself healthy.
        let mut cfg = cfg;
        cfg.check_boot_rules().unwrap();
        cfg.network_kill_switch = true;
        let msg = format!("{:#}", cfg.check_boot_rules().unwrap_err());
        assert!(msg.contains("public"), "got: {msg}");
    }

    #[test]
    fn the_samples_daemon_wide_keys_are_not_stranded_behind_a_profile_table() {
        // TOML binds any key after a `[[table]]` header to that table, so a
        // daemon-wide key written below the first `[[profile]]` cannot be
        // uncommented: `deny_unknown_fields` rejects it as an unknown
        // `[[profile]]` field, and the message lists the profile keys — which
        // reads as "this key does not exist", about the kill switch the file
        // calls defence-in-depth.
        for name in ["torrentd.sample.toml", "torrentd.multi-account.sample.toml"] {
            let text = fs::read_to_string(sample(name)).unwrap();
            let first_table = text
                .find("\n[[profile]]")
                .expect("every sample configures at least one profile");
            for key in ["vpn_handshake_max_age_secs", "network_kill_switch"] {
                let at = text
                    .find(key)
                    .unwrap_or_else(|| panic!("{name} should document {key}"));
                assert!(
                    at < first_table,
                    "{name}: {key} sits below the first [[profile]] header, \
                     where TOML binds it to that table",
                );
            }
        }
    }

    #[test]
    fn a_reload_does_not_overwrite_a_per_profile_upload_rate_limit() {
        // `startup.rs` applies a per-profile `upload_rate_limit` over the
        // top-level one at boot. Passing the top-level value through here
        // meant an operator who edited only the top-level key and sent SIGHUP
        // patched every session alike — the override was silently discarded
        // until the next restart, with nothing logged.
        let diff = ConfigDiff {
            upload_rate_limit: Some(2_000_000),
            ..Default::default()
        };
        let mut capped = host_profile();
        capped.upload_rate_limit = Some(100_000);

        assert_eq!(
            diff.to_settings_patch_for(&capped)
                .settings
                .upload_rate_limit,
            None,
            "a profile that set its own must not be patched from the top level",
        );
        assert_eq!(
            diff.to_settings_patch_for(&host_profile())
                .settings
                .upload_rate_limit,
            Some(2_000_000),
            "a profile that set nothing still takes the default; that is what makes it one",
        );
    }

    #[test]
    fn a_per_profile_upload_rate_limit_of_zero_means_unlimited_not_unset() {
        // F40. `0` is the value both shipped samples use to illustrate this
        // override, and the top-level key's own comment defines it as
        // "unlimited". While the field was a plain `u32` the reload guard and
        // the boot path both read an explicit `0` as an absent key and pushed
        // the daemon-wide cap onto a session the operator had uncapped — with
        // nothing logged, and nothing in `diff_profiles` to report it, because
        // the two values compared equal.
        let diff = ConfigDiff {
            upload_rate_limit: Some(2_000_000),
            ..Default::default()
        };
        let mut uncapped = host_profile();
        uncapped.upload_rate_limit = Some(0);

        assert_eq!(
            diff.to_settings_patch_for(&uncapped)
                .settings
                .upload_rate_limit,
            None,
            "an explicit 0 is a value the profile set, so the reload must not overwrite it",
        );

        // And the two are distinguishable at the type, which is what the boot
        // path keys on.
        assert_ne!(uncapped.upload_rate_limit, host_profile().upload_rate_limit);
        assert_eq!(
            host_profile().upload_rate_limit,
            None,
            "absent stays absent"
        );
    }

    #[test]
    fn an_explicit_zero_upload_rate_limit_round_trips_through_toml() {
        // The distinction has to survive the parser, or the field is `Option`
        // for nothing: `#[serde(default)]` over a `u32` turned a written `0`
        // and an absent key into the same value before it ever reached a
        // guard.
        let dir = tempdir().unwrap();
        let body = two_host_profiles(r#"upload_rate_limit = 0"#, "");
        let p = write_cfg(dir.path(), &body);
        let cfg = Config::load(&p).unwrap();
        assert_eq!(
            cfg.profile[0].upload_rate_limit,
            Some(0),
            "a written 0 is a value",
        );
        assert_eq!(
            cfg.profile[1].upload_rate_limit, None,
            "and an unwritten key is not",
        );
    }

    #[test]
    fn a_profile_only_upload_rate_limit_change_is_reported_rather_than_swallowed() {
        // `ConfigDiff::is_empty()` was true for this edit, so `reload.rs`
        // logged "SIGHUP: config unchanged" over a file that plainly had.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile[0].upload_rate_limit = Some(100_000);

        let d = Config::diff(&a, &b);
        assert!(!d.is_empty(), "the file changed and the daemon must say so");
        assert!(
            d.profile_changes
                .iter()
                .any(|c| c.what == "public.upload_rate_limit"),
            "got {:?}",
            d.profile_changes,
        );
    }

    #[test]
    fn a_profile_only_allowed_tracker_domains_change_is_reported_rather_than_swallowed() {
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile[0].allowed_tracker_domains = vec!["tracker.example.com".into()];

        let d = Config::diff(&a, &b);
        assert!(!d.is_empty());
        assert!(
            d.profile_changes
                .iter()
                .any(|c| c.what == "public.allowed_tracker_domains"),
            "got {:?}",
            d.profile_changes,
        );
    }

    #[test]
    fn every_profile_field_the_diff_reports_states_which_warning_it_is_owed() {
        // The classification that `reload.rs` used to keep as a list of key
        // names beside a comment asking whoever edits this function to update
        // it. Changing every `[[profile]]` field at once pins the classes: a
        // field compared in `diff_profiles` cannot be recorded without one,
        // and a field that changes class shows up here.
        //
        // What this cannot pin is a field added to `ProfileConfig` and never
        // compared at all — it would not appear in `got`, and `want` would not
        // ask for it, so no assertion here can notice. That is a compile
        // property and not a test: `diff_profiles` destructures
        // `ProfileConfig` exhaustively with no `..`, so a new field is
        // `error[E0027]: pattern does not mention field` until somebody names
        // it. No `#[test]` in this crate observes that, and none can.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        let p = &mut b.profile[0];
        p.network = torrentd_engine::ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6899".into(),
            dht: true,
        };
        p.peer_fingerprint_hex = Some("a1b2c3d4e5f60718".into());
        p.user_agent = Some("ua/1.0".into());
        p.resume_dir = Some("/var/lib/torrentd/resume-public".into());
        p.torrent_dir = Some("/var/lib/torrentd/torrents-public".into());
        p.upload_rate_limit = Some(100_000);
        p.allowed_tracker_domains = vec!["tracker.example.com".into()];

        let mut got: Vec<(String, ProfileChangeKind)> = Config::diff(&a, &b)
            .profile_changes
            .into_iter()
            .map(|c| (c.what, c.kind))
            .collect();
        got.sort_by(|x, y| x.0.cmp(&y.0));
        let mut want = vec![
            ("public.network", ProfileChangeKind::Identity),
            ("public.peer_fingerprint_hex", ProfileChangeKind::Identity),
            ("public.user_agent", ProfileChangeKind::Identity),
            ("public.resume_dir", ProfileChangeKind::NonIdentity),
            ("public.torrent_dir", ProfileChangeKind::NonIdentity),
            ("public.upload_rate_limit", ProfileChangeKind::NonIdentity),
            (
                "public.allowed_tracker_domains",
                ProfileChangeKind::NonIdentity,
            ),
        ]
        .into_iter()
        .map(|(w, k)| (w.to_string(), k))
        .collect::<Vec<_>>();
        want.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(got, want);
    }

    #[test]
    fn the_runbooks_own_upgrade_step_does_not_fire_a_privacy_alert() {
        // D36/Q23. Upgrade step 3 in `docs/running.md` tells an operator to
        // "set that profile's own `resume_dir` and `torrent_dir` to the old
        // paths" — the documented way to keep a library across the move to
        // per-profile subdirectories. With the store directories classed as
        // identity, doing exactly that emitted Safety Rule 7's privacy
        // warning, which `reload.rs` reserves for "the privacy event" and
        // which is the line an alert rule watches.
        //
        // They are still non-reloadable: the stores are opened at startup. The
        // class is about which of the two warnings the operator is owed, and
        // nothing a tracker reads carries where a profile keeps its files.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile[0].resume_dir = Some("/var/lib/torrentd/resume".into());
        b.profile[0].torrent_dir = Some("/var/lib/torrentd/torrents".into());

        let d = Config::diff(&a, &b);
        assert_eq!(d.profile_changes.len(), 2, "got {:?}", d.profile_changes);
        for c in &d.profile_changes {
            assert_eq!(
                c.kind,
                ProfileChangeKind::NonIdentity,
                "{} must not be reported as an identity change",
                c.what,
            );
        }
        // Still reported — not reloadable is not the same as not a change.
        let mut names: Vec<&str> = d.profile_changes.iter().map(|c| c.what.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["public.resume_dir", "public.torrent_dir"]);
    }

    #[test]
    fn a_profile_leaving_the_set_is_an_identity_change() {
        // `diff_profiles`'s entries with no `.key`. Which accounts exist is as
        // fixed at startup as who they announce as, so both must land in the
        // class that keeps Safety Rule 7's wording.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut b = a.clone();
        b.profile.clear();
        let d = Config::diff(&a, &b);
        assert_eq!(d.profile_changes.len(), 1, "got {:?}", d.profile_changes);
        assert!(d.profile_changes[0].what.starts_with("public: removed"));
        assert_eq!(d.profile_changes[0].kind, ProfileChangeKind::Identity);

        let d = Config::diff(&b, &a);
        assert_eq!(d.profile_changes.len(), 1, "got {:?}", d.profile_changes);
        assert!(d.profile_changes[0].what.starts_with("public: added"));
        assert_eq!(d.profile_changes[0].kind, ProfileChangeKind::Identity);
    }

    #[test]
    fn parses_one_host_profile() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &single_session());
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.connections_limit, Some(10000));
        assert_eq!(cfg.profile.len(), 1);
        assert_eq!(cfg.profile[0].id.as_str(), "public");
        assert!(!cfg.profile[0].is_vpn());
        assert!(
            !cfg.profile[0].dht_enabled(),
            "dht is off unless the profile writes it",
        );
    }

    /// The top-level block without the opt-out, for the auth-posture tests.
    fn top_level_no_opt_out() -> String {
        TOP_LEVEL.replace("allow_unauthenticated = true\n", "")
    }

    #[test]
    fn an_unauthenticated_config_is_refused_unless_it_says_so() {
        let dir = tempdir().unwrap();
        let body = format!("{}{ONE_HOST_PROFILE}", top_level_no_opt_out());
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("allow_unauthenticated"), "got: {msg}");
        assert!(msg.contains("hash-password"), "the error names the way out");
    }

    #[test]
    fn a_malformed_value_is_reported_before_the_posture() {
        // The property: shape before policy, for every shape check and not
        // only the `[[profile]]` block. A zero `aio_threads`, a
        // `password_hash` that is not a PHC string, and two `[pool]` roots
        // that nest each name something the operator must physically change;
        // a config with no stated posture is well-formed and not permitted.
        //
        // The order matters beyond tidiness. `load_for_operator_tool` skips
        // the posture check and runs every other one, so while the posture
        // was reported first, the refusal sent the operator to
        // `hash-password` — the way out it names — and `hash-password` then
        // refused for a malformed value `--check-config` had never shown
        // them. Each configuration here is wrong in two ways at once, which
        // is the only way to observe an ordering.
        let dir = tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(root.join("inner")).unwrap();

        let cases = [
            (
                format!(
                    "{}aio_threads = 0\n{ONE_HOST_PROFILE}",
                    top_level_no_opt_out(),
                ),
                "aio_threads = 0 is out of range",
            ),
            (
                // `[auth]` beside the opt-out is the policy refusal here.
                format!("{TOP_LEVEL}\n[auth]\npassword_hash = \"not-a-phc-string\"\n{ONE_HOST_PROFILE}"),
                "password_hash is not a valid PHC string",
            ),
            (
                format!(
                    "{}\n[pool]\nroots = [\"{}\", \"{}\"]\nlibrary_dir = \"{}\"\n{ONE_HOST_PROFILE}",
                    top_level_no_opt_out(),
                    root.display(),
                    root.join("inner").display(),
                    dir.path().join("library").display(),
                ),
                "[pool] roots must not nest",
            ),
        ];

        for (body, expected) in cases {
            let msg = refusal(&body);
            assert!(
                msg.contains(expected),
                "the malformed value must be reported before the posture; got: {msg}",
            );
        }
    }

    #[test]
    fn the_opt_out_is_honoured_on_loopback() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &single_session());
        assert!(Config::load(&p).is_ok());
    }

    #[test]
    fn the_opt_out_does_not_extend_to_a_routable_address() {
        // `allow_unauthenticated` is for delegating access control to
        // something in front, not for having none.
        let dir = tempdir().unwrap();
        let body = single_session().replace("127.0.0.1:8080", "0.0.0.0:8080");
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("loopback"), "got: {msg}");
    }

    #[test]
    fn a_loopback_bind_is_loopback_however_it_is_spelled() {
        // `IpAddr::is_loopback` is false for `::ffff:127.0.0.1`, so the
        // literal test refused an address reachable only from the host — and
        // told the operator it was "reachable from the network".
        let dir = tempdir().unwrap();
        for form in ["[::1]:8080", "[::ffff:127.0.0.1]:8080"] {
            let body = single_session().replace("127.0.0.1:8080", form);
            let p = write_cfg(dir.path(), &body);
            assert!(
                Config::load(&p).is_ok(),
                "{form} is loopback and must be accepted",
            );
        }
        // Unwrapping must not soften the check it is inside: the wildcard
        // binds stay refused in both families.
        for form in ["[::]:8080", "0.0.0.0:8080"] {
            let body = single_session().replace("127.0.0.1:8080", form);
            let p = write_cfg(dir.path(), &body);
            let msg = format!("{:#}", Config::load(&p).unwrap_err());
            assert!(
                msg.contains("loopback"),
                "{form} must be refused; got: {msg}"
            );
        }
    }

    #[test]
    fn configured_auth_needs_no_opt_out_and_may_bind_anywhere() {
        let dir = tempdir().unwrap();
        let body = format!(
            "{}{ONE_HOST_PROFILE}\n[auth]\npassword_hash = \"{}\"\n",
            top_level_no_opt_out().replace("127.0.0.1:8080", "0.0.0.0:8080"),
            crate::auth::hash_password("hunter2").unwrap(),
        );
        let p = write_cfg(dir.path(), &body);
        assert!(Config::load(&p).is_ok());
    }

    #[test]
    fn the_opt_out_alongside_configured_auth_is_refused() {
        // The property: a config states one posture. `[auth]` plus the opt-out
        // states two, and the flag is the one a reader checks — so a daemon
        // that authenticates ships a config file saying it does not.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}{ONE_HOST_PROFILE}\n[auth]\npassword_hash = \"{}\"\n",
            crate::auth::hash_password("hunter2").unwrap(),
        );
        assert!(
            body.contains("allow_unauthenticated = true"),
            "TOP_LEVEL carries the opt-out; this test is about it being there",
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("allow_unauthenticated"), "got: {msg}");
        assert!(
            msg.contains("Delete"),
            "the error names the edit that fixes it; got: {msg}",
        );
    }

    #[test]
    fn http_listen_defaults_to_loopback() {
        // The README claimed this default for a long time while the key was
        // in fact required; the claim is now true.
        let dir = tempdir().unwrap();
        let top = TOP_LEVEL.replace("http_listen = \"127.0.0.1:8080\"\n", "");
        let p = write_cfg(dir.path(), &format!("{top}{ONE_HOST_PROFILE}"));
        let cfg = Config::load(&p).unwrap();
        assert!(cfg.http_listen.ip().is_loopback());
        assert_eq!(cfg.http_listen.port(), 8080);
    }

    #[test]
    fn a_config_with_no_profiles_is_refused() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), TOP_LEVEL);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("[[profile]]"), "got: {msg}");
    }

    #[test]
    fn a_key_from_the_other_posture_is_refused() {
        // Not an unknown key — a key that would never be read. Flattening the
        // network enum into the table would have accepted this silently.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"public\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\nvpn_interface = \"wg0\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("vpn_interface"), "got: {msg}");
    }

    #[test]
    fn dht_false_on_a_vpn_profile_is_refused_like_every_other_wrong_posture_key() {
        // `dht` was a `#[serde(default)] bool`, so `dht = false` was
        // indistinguishable from absent and slipped through — alone among the
        // wrong-posture keys, every other one being an `Option` rejected on
        // presence. It reads to an operator as a setting that took, on the
        // posture where Safety Rule 6 says no key can reach it at all.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nlisten_port = 6891\n\
             peer_fingerprint_hex = \"a1b2c3d4e5f60718\"\nuser_agent = \"ua-a\"\n\
             dht = false\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("dht"), "got: {msg}");
    }

    #[test]
    fn a_listen_port_under_natpmp_is_refused_rather_than_ignored() {
        // The gateway assigns the port at runtime and renews its lease, so
        // nothing binds the configured one and Safety Rule 8 never enters it
        // into the uniqueness set — and `/api/profiles` then reports it back
        // under a field documented as `null` for natpmp profiles. Accepting
        // and ignoring a key is the shape every other rule in this conversion
        // exists to refuse.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nport_forward = \"natpmp\"\nlisten_port = 6891\n\
             peer_fingerprint_hex = \"a1b2c3d4e5f60718\"\nuser_agent = \"ua-a\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("listen_port") && msg.contains("natpmp"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_natpmp_profile_without_a_listen_port_is_accepted() {
        // The shape the rule above exists to leave alone.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nport_forward = \"natpmp\"\n\
             peer_fingerprint_hex = \"a1b2c3d4e5f60718\"\nuser_agent = \"ua-a\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).expect("a natpmp profile names no port; that is the point");
    }

    #[test]
    fn a_profile_id_that_is_not_a_path_component_is_refused_at_deserialization() {
        // The charset rule as a property of the *type*, not of having called
        // `validate_set`. The config file is not the only door a `ProfileId`
        // comes through: `profile_assignments.json` deserializes straight into
        // one and never passes the validator, so a hand-edited registry
        // naming `../..` reached `dir_for` and was joined onto a path with
        // nothing in between. Deserializing the bare value is that door.
        for bad in ["../..", "/etc", "a/b", "acct.a", "", &"x".repeat(65)] {
            let err = serde_json::from_value::<ProfileId>(serde_json::json!(bad))
                .err()
                .unwrap_or_else(|| panic!("id {bad:?} was accepted by Deserialize"));
            assert!(
                err.to_string().contains("[A-Za-z0-9_-]"),
                "id {bad:?} gave: {err}",
            );
        }
        for good in ["default", "acct_a", "acct-b", "Public2", &"a".repeat(64)] {
            serde_json::from_value::<ProfileId>(serde_json::json!(good))
                .unwrap_or_else(|e| panic!("id {good:?} was refused: {e}"));
        }
    }

    #[test]
    fn a_registry_file_naming_an_escaping_profile_id_does_not_load() {
        // The file the rule above exists for. `AssignmentRegistry` maps its
        // JSON values straight into `ProfileId`.
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_assignments.json");
        fs::write(
            &path,
            r#"{"0101010101010101010101010101010101010101":"../../etc"}"#,
        )
        .unwrap();
        assert!(
            torrentd_engine::AssignmentRegistry::load(&path).is_err(),
            "a registry naming an id that escapes its directory must not load",
        );
    }

    #[test]
    fn check_config_refuses_a_kill_switch_with_no_tunnel_to_confine_egress_to() {
        // `deploy/torrentd.service` runs `--check-config` as its
        // `ExecStartPre` so a bad configuration fails before `ExecStart`
        // rather than under `Restart=on-failure`. This refusal is a pure
        // function of the file and `boot` makes it anyway, so the pre-flight
        // has no reason not to.
        //
        // It is a refusal of `Config::load` itself, not of a second pass over
        // a config that already loaded: being a pure function of the file is
        // what puts it with the rest of the shape checks.
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &with_top_level("network_kill_switch = true"));
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("network_kill_switch") && msg.contains("vpn"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_boot_rule_is_reported_before_the_authentication_posture() {
        // The property: of two configs differing only in whether a posture is
        // stated, the one that states none must still be told about the thing
        // it has to physically change. `check_boot_rules` ran in
        // `main::check_config`, after `Config::load` had returned, so it sat
        // below the policy check: `--check-config` on a kill switch with no
        // vpn profile and no posture answered "no [auth] section…", and the
        // operator saw "Configure a vpn profile, or unset
        // network_kill_switch" only on the next run. Demonstrated on both
        // configs.
        let dir = tempdir().unwrap();

        let stated = write_cfg(dir.path(), &with_top_level("network_kill_switch = true"));
        let msg = format!("{:#}", Config::load(&stated).unwrap_err());
        assert!(
            msg.contains("network_kill_switch"),
            "the posture is stated, so the boot rule is what is left; got: {msg}",
        );

        // The same file with the opt-out line removed, so no posture is
        // stated and both refusals apply.
        let body = with_top_level("network_kill_switch = true")
            .replace("allow_unauthenticated = true\n", "");
        assert!(!body.contains("allow_unauthenticated"));
        let sub = dir.path().join("b");
        fs::create_dir_all(&sub).unwrap();
        let unstated = write_cfg(&sub, &body);
        let msg = format!("{:#}", Config::load(&unstated).unwrap_err());
        assert!(
            msg.contains("network_kill_switch"),
            "shape before policy: the kill switch names something the operator \
             must physically change, and it is reported first; got: {msg}",
        );
    }

    #[test]
    fn an_operator_subcommand_gets_the_boot_rules_too() {
        // The property: the exemption `load_for_operator_tool` carries is from
        // the *posture* check and nothing else. A boot rule that is a pure
        // function of the file is not about serving, so a subcommand is held
        // to it — demonstrated before this change by `pool status` running
        // happily against a config `--check-config` refuses.
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &with_top_level("network_kill_switch = true"));
        let msg = format!("{:#}", Config::load_for_operator_tool(&p).unwrap_err());
        assert!(
            msg.contains("network_kill_switch") && msg.contains("vpn"),
            "got: {msg}",
        );
    }

    #[test]
    fn a_kill_switch_with_a_vpn_profile_passes_the_pre_flight() {
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\nnetwork_kill_switch = true\n\n[[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
             listen_port = 6891\npeer_fingerprint_hex = \"a1b2c3d4e5f60718\"\n\
             user_agent = \"ua-a\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        Config::load(&p).unwrap().check_boot_rules().unwrap();
    }

    #[test]
    fn a_kill_switch_beside_a_host_profile_is_refused() {
        // The ruleset matches the daemon's uid and admits only the tunnel
        // interfaces, so a host profile under it sends nothing at all while
        // it stays Active and `/healthz` answers 200.
        //
        // Boot rules run inside `Config::validate`, so this is a refusal of
        // `Config::load` itself and reaches `--check-config` with the rest.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\nnetwork_kill_switch = true\n\n[[profile]]\nid = \"public\"\n\
             network = \"host\"\nlisten_interfaces = \"0.0.0.0:6881\"\n\n\
             [[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
             listen_port = 6891\npeer_fingerprint_hex = \"a1b2c3d4e5f60718\"\n\
             user_agent = \"ua-a\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("network_kill_switch") && msg.contains("public"),
            "got: {msg}",
        );
    }

    #[test]
    fn the_default_config_has_no_boot_rule_to_break() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &single_session());
        Config::load(&p).unwrap().check_boot_rules().unwrap();
    }

    #[test]
    fn a_typo_in_a_profile_table_is_still_fatal() {
        // The property `deny_unknown_fields` gives the rest of the config, kept
        // for `[[profile]]` by parsing a flat shape and converting.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"public\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\nlisten_interface = \"typo\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("listen_interface"), "got: {msg}");
    }

    #[test]
    fn unknown_key_is_fatal() {
        let dir = tempdir().unwrap();
        let bad = with_top_level("unknown_setting = 42");
        let p = write_cfg(dir.path(), &bad);
        let err = Config::load(&p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown_setting"), "got: {msg}");
    }

    #[test]
    fn pool_mutations_are_off_unless_asked_for() {
        // The daemon can move and delete inside its managed roots. An operator
        // who only wanted an index should never be one request away from that,
        // so the default has to stay false — asserted here because a stray
        // `#[serde(default = "...true")]` would be silent otherwise.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}{ONE_HOST_PROFILE}\n[pool]\nroots = [\"/data/torrents\"]\n\
             library_dir = \"/var/lib/torrentd/library\"\n"
        );
        let p = write_cfg(dir.path(), &body);
        let cfg = Config::load(&p).unwrap();
        assert!(!cfg.pool.as_ref().unwrap().allow_mutations);

        let on = body + "allow_mutations = true\n";
        let p = write_cfg(dir.path(), &on);
        assert!(Config::load(&p).unwrap().pool.unwrap().allow_mutations);
    }

    #[test]
    fn daemon_state_inside_a_managed_root_is_rejected() {
        // Nothing in the library claims the torrent library or the resume
        // store, so under a managed root they are orphans by definition and
        // `delete_orphans` over that root would erase them.
        let dir = tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let body = format!(
            r#"
default_save_path = "{r}"
resume_dir = "{r}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"

[pool]
roots = ["{r}"]
library_dir = "{d}/library"
"#,
            r = root.display(),
            d = dir.path().display(),
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("resume_dir"), "got: {msg}");
        assert!(msg.contains("inside the managed root"), "got: {msg}");
    }

    #[test]
    fn roots_that_nest_through_a_symlink_are_rejected() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("pool");
        std::fs::create_dir_all(real.join("inner")).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let body = format!(
            r#"
default_save_path = "{d}/data"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"

[pool]
roots = ["{r}", "{a}/inner"]
library_dir = "{d}/library"
"#,
            d = dir.path().display(),
            r = real.display(),
            a = alias.display(),
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("must not nest"), "got: {msg}");
    }

    #[test]
    fn out_of_range_numbers_are_rejected_at_startup() {
        let dir = tempdir().unwrap();
        let bad = with_top_level("aio_threads = 0");
        let p = write_cfg(dir.path(), &bad);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("aio_threads"), "got: {msg}");
        assert!(msg.contains("out of range"), "got: {msg}");
    }

    #[test]
    fn diff_separates_reloadable_from_non() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), &single_session());
        let old = Config::load(&p).unwrap();
        let mut new = old.clone();
        new.connections_limit = Some(20000);
        new.torrent_dir = std::path::PathBuf::from("/var/lib/torrentd/other");
        let d = Config::diff(&old, &new);
        assert_eq!(d.connections_limit, Some(20000));
        assert_eq!(d.non_reloadable_changes, vec!["torrent_dir"]);
    }

    #[test]
    fn the_shared_test_fixture_states_a_posture() {
        // The property: the config the HTTP and pool test modules build their
        // `AppState`/`PoolService` from is a shape the daemon would start
        // from, at least as far as the posture goes. It stated none — no
        // `[auth]`, no opt-out — which is the one shape `--check-config`
        // refuses outright, so every handler test using it exercised the
        // serving path against a configuration the daemon refuses to serve.
        //
        // The fixture has no `[[profile]]`, so `validate()` as a whole is not
        // what it can satisfy; the posture is, and the posture is what this
        // change made a required statement.
        let dir = tempdir().unwrap();
        let cfg = Config::minimal_for_tests(dir.path(), false);
        cfg.validate_auth_posture()
            .expect("the shared fixture must state a posture the daemon accepts");
    }

    #[test]
    fn an_edit_to_any_non_reloadable_key_is_reported() {
        // The property: a config that differs in exactly one key the daemon
        // cannot apply is not an unchanged config, and the warning names the
        // key that changed. Five keys reached no branch of `diff` at all, so
        // `is_empty()` stayed true and `reload::run` answered
        // `SIGHUP: config unchanged` to a file that plainly had. Each is
        // exercised on its own, because a change that only *happens* to
        // travel with a reported key is not the failure this is about.
        //
        // `network_kill_switch` is the one with a security consequence: an
        // operator who turns the fail-closed kill switch on and reloads was
        // told nothing had changed.
        let dir = tempdir().unwrap();
        let base = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();

        let mut save_path = base.clone();
        save_path.default_save_path = PathBuf::from("/data/elsewhere");

        let mut registry = base.clone();
        registry.registry_path = Some(PathBuf::from("/var/lib/torrentd/assignments.json"));

        let mut handshake = base.clone();
        handshake.vpn_handshake_max_age_secs = base.vpn_handshake_max_age_secs + 60;

        let mut kill_switch = base.clone();
        kill_switch.network_kill_switch = !base.network_kill_switch;

        let mut pool = base.clone();
        pool.pool = Some(PoolConfig {
            roots: vec![PathBuf::from("/data/pool")],
            library_dir: PathBuf::from("/data/library"),
            db_path: None,
            max_concurrent_verify: 1,
            import_legacy_registry: false,
            allow_mutations: false,
        });

        for (field, edited) in [
            ("default_save_path", &save_path),
            ("registry_path", &registry),
            ("vpn_handshake_max_age_secs", &handshake),
            ("network_kill_switch", &kill_switch),
            ("pool", &pool),
        ] {
            let d = Config::diff(&base, edited);
            assert!(
                !d.is_empty(),
                "a config differing only in {field} must not look unchanged",
            );
            assert!(
                d.non_reloadable_changes.contains(&field),
                "the warning for a changed {field} must name it; got {:?}",
                d.non_reloadable_changes,
            );
        }
    }

    #[test]
    fn deleting_a_reloadable_key_is_a_difference_and_is_named() {
        // The property: a config that **deletes** one reloadable key is not an
        // unchanged config, and the diff names the key that went away.
        //
        // The five below are `Option` on both sides, so the comparison that
        // reports them had nothing to assign but `None` — and `None` is what
        // `is_empty()` reads as "this key did not change". Every one of them
        // answered `SIGHUP: config unchanged` on a live daemon, one deletion
        // per reload; worse, that answer `continue`s before `current = next`,
        // so the deletion stayed invisible to every later reload too. The
        // sample config documents deleting a key as the way back to the
        // preset default, so this is the documented edit and not an exotic
        // one.
        //
        // Each is exercised on its own: a deletion that only *happens* to
        // travel with a key that is reported some other way is not this.
        let dir = tempdir().unwrap();
        let base = Config::load(&write_cfg(
            dir.path(),
            &with_top_level(
                "aio_threads = 8\nenable_lsd = true\nupload_rate_limit = 1000000\n\
                 max_concurrent_http_announces = 30",
            ),
        ))
        .unwrap();
        // The fixture must actually set all five, or a "deletion" below would
        // be a no-op and the test would pass on nothing.
        assert!(
            base.connections_limit.is_some()
                && base.aio_threads.is_some()
                && base.enable_lsd.is_some()
                && base.upload_rate_limit.is_some()
                && base.max_concurrent_http_announces.is_some(),
            "the fixture must set every key this test deletes",
        );

        let mut connections_limit = base.clone();
        connections_limit.connections_limit = None;

        let mut aio_threads = base.clone();
        aio_threads.aio_threads = None;

        let mut enable_lsd = base.clone();
        enable_lsd.enable_lsd = None;

        let mut upload_rate_limit = base.clone();
        upload_rate_limit.upload_rate_limit = None;

        let mut announces = base.clone();
        announces.max_concurrent_http_announces = None;

        for (field, edited) in [
            ("connections_limit", &connections_limit),
            ("aio_threads", &aio_threads),
            ("enable_lsd", &enable_lsd),
            ("upload_rate_limit", &upload_rate_limit),
            ("max_concurrent_http_announces", &announces),
        ] {
            let d = Config::diff(&base, edited);
            assert!(
                !d.is_empty(),
                "a config that deleted {field} must not look unchanged",
            );
            assert!(
                d.reloadable_changes.contains(&field),
                "the diff must name {field} as changed; got {:?}",
                d.reloadable_changes,
            );
            assert!(
                d.reloadable_deletions.contains(&field),
                "the diff must name {field} as deleted, so the pump can say the \
                 preset default needs a restart; got {:?}",
                d.reloadable_deletions,
            );
        }
    }

    #[test]
    fn an_edit_to_only_non_reloadable_keys_applies_no_settings() {
        // The property: the reload pump's per-profile settings loop is
        // skipped for an edit it cannot apply anything from, so such a reload
        // does not close with `INFO SIGHUP: settings applied`.
        //
        // Once the non-reloadable keys are reported, `is_empty()` is false for
        // an edit that touched only them, so the pump falls through its
        // warnings into that loop and calls `apply_settings` with a patch that
        // sets nothing. It succeeds, and the journal's last word on a reload
        // that was ignored is a success line. `reload::run` guards on this
        // predicate; nothing in the workspace drives the pump itself, so the
        // guard is pinned here rather than through `run`.
        let dir = tempdir().unwrap();
        let base = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();

        // The documented operator edit: add `[auth]`, delete the opt-out.
        let mut with_auth = base.clone();
        with_auth.auth = Some(crate::auth::AuthConfig {
            password_hash: crate::auth::hash_password("hunter2").unwrap(),
            session_ttl_secs: 43_200,
            token: vec![],
        });
        with_auth.allow_unauthenticated = false;

        let d = Config::diff(&base, &with_auth);
        assert!(
            !d.is_empty(),
            "the edit is reported, so the diff is not empty"
        );
        for profile in [host_profile(), vpn_profile()] {
            assert!(
                ConfigDiff::settings_patch_is_empty(&d.to_settings_patch_for(&profile)),
                "an auth-only edit has nothing to apply to profile {}",
                profile.id,
            );
        }

        // A reloadable key in the same edit still reaches the loop: the guard
        // withholds a no-op call, not every call.
        let mut also_reloadable = with_auth.clone();
        also_reloadable.connections_limit = Some(20_000);
        let d = Config::diff(&base, &also_reloadable);
        assert!(
            !ConfigDiff::settings_patch_is_empty(&d.to_settings_patch_for(&host_profile())),
            "a changed connections_limit must still be applied",
        );
    }
}
