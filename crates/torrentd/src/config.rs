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
use torrentd_engine::JsonImport;
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
    /// Where the control API listens. Defaults to loopback, the only address
    /// safe without `[auth]`; inside a network namespace (a container) it has
    /// to be set to a routable address for the published port to reach it.
    #[serde(default = "Config::default_http_listen")]
    pub http_listen: SocketAddr,

    /// Peers whose forwarding headers are believed, as IPs or CIDR blocks:
    /// the address the reverse proxy connects from, and only that, since
    /// anything listed can claim to be any client. Empty by default, so no
    /// forwarding header is read and the socket peer is the client. See
    /// `http::forwarded` and `LoginThrottle`.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Permit running with no `[auth]` section, which authenticates nothing.
    /// Legitimate behind a proxy that does its own access control, and so
    /// available — but it has to be typed, never arrived at by omission.
    #[serde(default)]
    pub allow_unauthenticated: bool,

    /// Host names, beyond loopback, that a daemon with
    /// `allow_unauthenticated` answers to: the names a reverse proxy in front
    /// of it passes through as `Host`. A request naming any other `Host` is
    /// refused, which is what stops a DNS-rebound page from reading the API.
    /// Refused beside `[auth]`, where nothing reads it.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default = "Config::default_log_level")]
    pub log_level: LogLevel,

    /// Where the assignment registry database lives. Defaults to
    /// `<resume_dir parent>/registry.db`. A path ending in `.json` is a
    /// pre-SQLite config naming the JSON file: see [`Config::registry_path`].
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
    /// A fixed number of peers to unchoke per session.
    ///
    /// Absent, the session runs libtorrent's rate-based choker, which opens
    /// slots while the upload rate achieved to them supports it (see
    /// `Settings::server_seed_overrides`). Set, it selects the fixed-slots
    /// choker with exactly this many. Read at startup.
    #[serde(default)]
    pub unchoke_slots_limit: Option<u32>,
    #[serde(default)]
    pub peer_fingerprint: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,

    /// Max age of a WireGuard tunnel's latest handshake before the health
    /// monitor treats the profile as down. Catches a tunnel that
    /// keeps its IP but has silently stopped handshaking. Default 180s.
    #[serde(default = "Config::default_handshake_max_age")]
    pub vpn_handshake_max_age_secs: u64,

    /// How long the shutdown drain waits for outstanding resume saves before
    /// giving up on them, in seconds. Default 60. A pool of 100K torrents
    /// answers a whole-pool save in batches of `RESUME_SAVES_IN_FLIGHT`, so a
    /// large pool on slow storage may need more; `deploy/torrentd.service`'s
    /// `TimeoutStopSec` is sized to the default.
    #[serde(default = "Config::default_shutdown_drain_secs")]
    pub shutdown_drain_secs: u64,

    /// Install a fail-closed nftables kill switch that
    /// confines the daemon's egress to loopback + the profiles' tunnel interfaces.
    /// Off by default; requires `CAP_NET_ADMIN` and that torrentd runs as its own
    /// non-root user. WireGuard profiles only: `validate` refuses it beside an
    /// OpenVPN profile. See `vpn::killswitch` for what that leaves runnable.
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
    /// roots. Off by default: only the plan/apply surface can destroy data,
    /// and with this off it answers 403. Turning it on disables no refusal.
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
const REGISTRY_FILE: &str = "registry.db";
/// The JSON file the database replaced. Imported once, then renamed.
const JSON_REGISTRY_FILE: &str = "profile_assignments.json";
/// Its name before profiles replaced slots. Imported once, then renamed, where
/// neither the database nor the JSON file above exists.
const LEGACY_REGISTRY_FILE: &str = "slot_assignments.json";
/// The single-instance lock `boot` holds for the life of the process.
const INSTANCE_LOCK_FILE: &str = "torrentd.lock";

/// Whether a configured `registry_path` names a pre-SQLite JSON registry.
fn is_json(p: &Path) -> bool {
    p.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
}

/// How a fingerprint error names the top-level key, which shares its name
/// with the per-profile key it is the default for.
const TOP_LEVEL_FINGERPRINT: &str = "top-level peer_fingerprint";

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

    fn default_shutdown_drain_secs() -> u64 {
        60
    }

    /// The largest `shutdown_drain_secs` accepted. An hour is already far
    /// past any stop budget a supervisor would grant.
    pub const MAX_SHUTDOWN_DRAIN_SECS: u64 = 3600;

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let cfg = Self::parse(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load for an operator subcommand — `hash-password`, `new-token`,
    /// `pool …`, `vpn check` — which validates everything except the
    /// authentication posture. They serve nothing, and `hash-password` is the
    /// way out of the posture refusal, so it must run against the config that
    /// refusal names.
    pub fn load_for_operator_tool(path: &Path) -> anyhow::Result<Self> {
        let cfg = Self::parse(path)?;
        cfg.validate_without_auth_posture()?;
        Ok(cfg)
    }

    /// Load for `net-cleanup`, which validates nothing: it reads only
    /// [`Config::state_dir`] and the profiles' tunnel interface names, which
    /// it compares against the OpenVPN records it finds, and it runs as the
    /// unit's `ExecStopPost=`
    /// after the daemon is gone. A config edited while the daemon ran into
    /// one any validation refuses must still let it remove that daemon's kill
    /// switch and tunnels. Only a file that does not parse refuses.
    pub fn load_for_net_cleanup(path: &Path) -> anyhow::Result<Self> {
        Self::parse(path)
    }

    fn parse(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&bytes).with_context(|| format!("parse {}", path.display()))
    }

    /// Refuse a configuration that does not state its authentication posture
    /// exactly once: no `[auth]` and no opt-out; the opt-out on a non-loopback
    /// bind; or `[auth]` and the opt-out together, where the flag is inert and
    /// misleading.
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
            if !self.allowed_hosts.is_empty() {
                anyhow::bail!(
                    "[auth] is configured and allowed_hosts is set as well. allowed_hosts \
                     only widens which Host names a daemon without [auth] answers to; a \
                     daemon with [auth] answers to any, because a page cannot present its \
                     token. Delete `allowed_hosts` from the config."
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
        // `::ffff:127.0.0.1` is loopback too; `Ipv6Addr::is_loopback` says
        // so only of `::1`.
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
    /// posture: see [`Config::load_for_operator_tool`].
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
        self.validate_http_listen_port()?;

        // Not gated on `check_auth_posture`: a malformed or `/0` entry is a
        // refusal for operator tools too.
        crate::http::forwarded::TrustedProxies::parse(&self.trusted_proxies)
            .map_err(|e| anyhow::anyhow!("trusted_proxies: {e}"))?;
        crate::http::security::HostAllowlist::parse(&self.allowed_hosts)
            .map_err(|e| anyhow::anyhow!("allowed_hosts: {e}"))?;
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
        // Zero would skip the drain outright and lose every unsaved resume.
        if !(1..=Self::MAX_SHUTDOWN_DRAIN_SECS).contains(&self.shutdown_drain_secs) {
            anyhow::bail!(
                "shutdown_drain_secs = {} is out of range (1..={})",
                self.shutdown_drain_secs,
                Self::MAX_SHUTDOWN_DRAIN_SECS,
            );
        }
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
        // valid. The upper end is i32::MAX because the shim hands the value to
        // libtorrent's int-typed setting through a narrowing cast; anything
        // larger would arrive there as a negative rate limit.
        range(
            "upload_rate_limit",
            self.upload_rate_limit,
            0,
            i32::MAX as u32,
        )?;
        // Zero unchokes nobody, which is a seeder that uploads nothing; the
        // upper end keeps the value inside libtorrent's int setting.
        range(
            "unchoke_slots_limit",
            self.unchoke_slots_limit,
            1,
            1_000_000,
        )?;

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
            // which resume_dir's parent already covers. A profile's own
            // resume_dir / torrent_dir override can point anywhere, so each
            // profile's effective store directories are checked too.
            let mut state: Vec<(String, PathBuf)> = vec![
                ("resume_dir".into(), self.resume_dir.clone()),
                ("torrent_dir".into(), self.torrent_dir.clone()),
                ("[pool] library_dir".into(), pool.library_dir.clone()),
                ("[pool] db_path".into(), self.pool_db_path()),
                ("registry_path".into(), self.registry_path()),
            ];
            for p in &self.profile {
                let (resume, torrent) = self.effective_store_dirs(p);
                let id = p.id.as_str();
                state.push((format!("[[profile]] id = \"{id}\" resume_dir"), resume));
                state.push((format!("[[profile]] id = \"{id}\" torrent_dir"), torrent));
            }
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

        self.check_boot_rules()?;

        // Shape before policy: every check above names something the operator
        // must change, and is reported before the posture, which operator
        // tools skip. Host probes (`nft`) are not here but in
        // `main::check_config`, since reloads and operator tools run this too.
        if check_auth_posture {
            self.validate_auth_posture()?;
        }
        Ok(())
    }

    /// Compute a diff against an old config. Used by SIGHUP reload to
    /// apply only the fields that may change without restart.
    pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
        // Destructured exhaustively, with no `..` and no `field: _`: a field
        // added to `Config` does not compile until it is named here, and one
        // named but never compared is an unused-variable warning, which the
        // lint task and CI deny. Every changed key is then reported.
        let Config {
            default_save_path: new_default_save_path,
            resume_dir: new_resume_dir,
            torrent_dir: new_torrent_dir,
            http_listen: new_http_listen,
            allow_unauthenticated: new_allow_unauthenticated,
            allowed_hosts: new_allowed_hosts,
            log_level: new_log_level,
            registry_path: new_registry_path,
            connections_limit: new_connections_limit,
            file_pool_size: new_file_pool_size,
            enable_lsd: new_enable_lsd,
            aio_threads: new_aio_threads,
            max_concurrent_http_announces: new_max_concurrent_http_announces,
            upload_rate_limit: new_upload_rate_limit,
            unchoke_slots_limit: new_unchoke_slots_limit,
            peer_fingerprint: new_peer_fingerprint,
            user_agent: new_user_agent,
            vpn_handshake_max_age_secs: new_vpn_handshake_max_age_secs,
            shutdown_drain_secs: new_shutdown_drain_secs,
            network_kill_switch: new_network_kill_switch,
            profile: new_profile,
            auth: new_auth,
            pool: new_pool,
            trusted_proxies: new_trusted_proxies,
        } = new;

        let mut d = ConfigDiff::default();
        // Each of the five is `Option`, so a deleted key assigns `None`;
        // `record_reloadable` records the difference itself.
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
        // Not an `Option`: deleting the key yields the default, a real value.
        if old.log_level != *new_log_level {
            d.log_level = Some(*new_log_level);
        }

        // Every other field but `[[profile]]` (`diff_profiles`) cannot be
        // applied by a reload, and a change to one is reported by name rather
        // than swallowed.
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
            d.non_reloadable_changes.push("file_pool_size");
        }
        // It also chooses the choker, which is never switched under live peers.
        if old.unchoke_slots_limit != *new_unchoke_slots_limit {
            d.non_reloadable_changes.push("unchoke_slots_limit");
        }
        if old.peer_fingerprint != *new_peer_fingerprint {
            d.non_reloadable_changes.push("peer_fingerprint");
        }
        if old.user_agent != *new_user_agent {
            d.non_reloadable_changes.push("user_agent");
        }
        if old.auth != *new_auth {
            d.non_reloadable_changes.push("auth");
        }
        if old.allow_unauthenticated != *new_allow_unauthenticated {
            d.non_reloadable_changes.push("allow_unauthenticated");
        }
        if old.allowed_hosts != *new_allowed_hosts {
            d.non_reloadable_changes.push("allowed_hosts");
        }
        if old.http_listen != *new_http_listen {
            d.non_reloadable_changes.push("http_listen");
        }
        if old.trusted_proxies != *new_trusted_proxies {
            d.non_reloadable_changes.push("trusted_proxies");
        }
        if old.registry_path != *new_registry_path {
            d.non_reloadable_changes.push("registry_path");
        }
        if old.vpn_handshake_max_age_secs != *new_vpn_handshake_max_age_secs {
            d.non_reloadable_changes.push("vpn_handshake_max_age_secs");
        }
        if old.shutdown_drain_secs != *new_shutdown_drain_secs {
            d.non_reloadable_changes.push("shutdown_drain_secs");
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
        if let Some(v) = self.unchoke_slots_limit {
            // `validate` holds it to 1..=1_000_000, so it fits the i32.
            s.choking_algorithm = Some(libtorrent_safe::Settings::FIXED_SLOTS_CHOKER);
            s.unchoke_slots_limit = Some(i32::try_from(v).unwrap_or(i32::MAX));
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

    /// The boot refusals that are pure functions of the config file: the kill
    /// switch beside no vpn profile, beside a host profile, or beside an
    /// OpenVPN profile. Run by [`Config::validate_inner`], so the daemon,
    /// `--check-config`, a reload and every operator subcommand refuse alike.
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
        // The ruleset admits the daemon's uid only on loopback and tunnels, so
        // a host profile would send nothing while reporting itself healthy.
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
        // `openvpn` runs under the daemon's uid, so the ruleset would drop its
        // own connection to the provider.
        if self.network_kill_switch {
            if let Some(p) = self
                .profile
                .iter()
                .find(|p| p.vpn_type() == Some(torrentd_engine::VpnType::Openvpn))
            {
                anyhow::bail!(
                    "network_kill_switch = true cannot be used with an OpenVPN profile \
                     ([[profile]] id = \"{}\"): the kill switch matches the daemon's uid, \
                     `openvpn` runs under that uid, and its connection to the provider \
                     leaves by the physical interface, so the ruleset drops it and the \
                     tunnel never comes up. The kill switch supports WireGuard profiles only.",
                    p.id.as_str(),
                );
            }
        }
        Ok(())
    }

    /// A profile's effective `peer_fingerprint` and `user_agent` — its own
    /// values, or the top-level defaults it inherits — which is what goes on
    /// the wire.
    fn effective_identity<'a>(
        &'a self,
        p: &'a ProfileConfig,
    ) -> (Option<&'a str>, Option<&'a str>) {
        (
            p.peer_fingerprint
                .as_deref()
                .or(self.peer_fingerprint.as_deref()),
            p.user_agent.as_deref().or(self.user_agent.as_deref()),
        )
    }

    /// Refuse two profiles that would announce one identity, by their
    /// *effective* values: a profile inheriting the top-level default collides
    /// with one declaring the same value, which `ProfileConfig::validate_set`
    /// cannot see (Safety Rules 2-4 in `torrentd_engine::profile`).
    ///
    /// Two profiles that both inherit the default are exempt: that is the
    /// documented use of the top-level key. An error names the key the
    /// operator wrote, `top-level peer_fingerprint` for an inherited value.
    fn validate_effective_identities(&self) -> Result<(), ProfileConfigError> {
        if let Some(fp) = self.peer_fingerprint.as_deref() {
            if !ProfileConfig::is_valid_fingerprint(fp) {
                return Err(ProfileConfigError::BadFingerprint {
                    key: TOP_LEVEL_FINGERPRINT,
                    value: fp.to_string(),
                });
            }
        }
        let mut seen_fp: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut seen_ua: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for p in &self.profile {
            let (fp, ua) = self.effective_identity(p);
            if let Some(fp) = fp {
                let inherited = p.peer_fingerprint.is_none();
                let key = if inherited {
                    TOP_LEVEL_FINGERPRINT
                } else {
                    "peer_fingerprint"
                };
                // On the effective fingerprint, so an inherited default prefix
                // is refused as a declared one is.
                if ProfileConfig::is_libtorrent_default_fingerprint(fp) {
                    return Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key,
                        value: fp.to_string(),
                        default: ProfileConfig::LIBTORRENT_DEFAULT_FINGERPRINT,
                    });
                }
                match seen_fp.insert(fp, p.id.as_str()) {
                    Some(prev) if inherited && self.inherits_fingerprint(prev) => {}
                    Some(_) => {
                        return Err(ProfileConfigError::DuplicateFingerprint {
                            key,
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

    /// Whether the profile named `id` declares no `peer_fingerprint`.
    fn inherits_fingerprint(&self, id: &str) -> bool {
        self.profile
            .iter()
            .find(|p| p.id.as_str() == id)
            .is_some_and(|p| p.peer_fingerprint.is_none())
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

    /// Refuse two profiles that would share a store directory, by effective
    /// path, so an override equal to another profile's derived `<base>/<id>`
    /// is caught. Equality only: a store scans one level, so a directory
    /// containing another's is harmless, and is the documented upgrade.
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

    /// Refuse an `http_listen` port a profile's session also listens on: the
    /// session binds first and the HTTP listener then fails. Compared on the
    /// port alone, since a vpn profile's address is known only at runtime.
    fn validate_http_listen_port(&self) -> anyhow::Result<()> {
        let port = self.http_listen.port();
        if let Some(p) = self
            .profile
            .iter()
            .find(|p| p.configured_listen_ports().contains(&port))
        {
            anyhow::bail!(
                "http_listen = {} uses port {port}, which [[profile]] id = \"{}\" also \
                 listens on. The session binds it first and the HTTP API then fails to \
                 start. Give http_listen a port no profile uses.",
                self.http_listen,
                p.id.as_str(),
            );
        }
        Ok(())
    }

    /// The assignment registry database: `registry_path` as configured, or
    /// `registry.db` in [`Config::state_dir`]. A configured path ending in
    /// `.json` names the pre-SQLite file [`Config::registry_import`] imports,
    /// and the database goes beside it with a `.db` extension.
    pub fn registry_path(&self) -> PathBuf {
        match &self.registry_path {
            Some(p) if is_json(p) => p.with_extension("db"),
            Some(p) => p.clone(),
            None => self.state_dir().join(REGISTRY_FILE),
        }
    }

    /// The JSON registry to import into the database on open, if one is on
    /// disk.
    ///
    /// Every boot asks, and the import renames what it read, so a file is
    /// read once. In order:
    ///
    /// - a configured `registry_path` ending in `.json`, as above;
    /// - otherwise, with no `registry_path` configured,
    ///   `profile_assignments.json` in the state directory;
    /// - failing that, the pre-profiles `slot_assignments.json`, but only
    ///   while the database does not exist yet; beside a database it is an
    ///   earlier release's rollback copy.
    pub fn registry_import(&self) -> Option<JsonImport> {
        let found = |path: PathBuf, pre_profiles: bool| {
            path.exists().then_some(JsonImport { path, pre_profiles })
        };
        match &self.registry_path {
            Some(p) if is_json(p) => found(p.clone(), false),
            Some(_) => None,
            None => found(self.state_dir().join(JSON_REGISTRY_FILE), false).or_else(|| {
                if self.registry_path().exists() {
                    None
                } else {
                    found(self.state_dir().join(LEGACY_REGISTRY_FILE), true)
                }
            }),
        }
    }

    /// Where the pool index lives.
    pub fn pool_db_path(&self) -> PathBuf {
        self.pool
            .as_ref()
            .and_then(|p| p.db_path.clone())
            .unwrap_or_else(|| self.state_dir().join("pool.db"))
    }

    /// Directory the daemon keeps its own state in, derived from `resume_dir`.
    ///
    /// One daemon per state directory: `boot` locks
    /// [`Config::instance_lock_path`] here before it does anything else.
    pub fn state_dir(&self) -> PathBuf {
        self.resume_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/var/lib/torrentd"))
    }

    /// The file `boot` holds an exclusive lock on for the life of the
    /// process, so a second daemon against the same state directory refuses
    /// before it touches the kill switch, a tunnel, or a state file.
    pub fn instance_lock_path(&self) -> PathBuf {
        self.state_dir().join(INSTANCE_LOCK_FILE)
    }

    /// Where a profile's DHT/session state is persisted: per profile, so two
    /// host profiles running DHT do not share a routing table. A pre-profiles
    /// `session_state.dat` is not migrated; the table rebuilds in minutes.
    pub fn session_state_path(&self, profile: &ProfileId) -> PathBuf {
        self.state_dir()
            .join(format!("session_state-{}.dat", profile.as_str()))
    }

    /// Where the operator's online/offline choice for each profile is kept;
    /// see `profile_state`.
    pub fn profile_state_path(&self) -> PathBuf {
        self.state_dir()
            .join(crate::profile_state::PROFILE_STATE_FILE)
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
    Identity,
    /// Non-reloadable for its own reason, but nothing a tracker reads: the
    /// per-profile rate cap, the tracker-domain list, and the store
    /// directories, which are fixed at startup because the stores are opened
    /// then.
    NonIdentity,
}

/// One `[[profile]]` change a reload cannot apply, carrying its class so
/// nothing downstream recovers it from the key's name.
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

/// Report `[[profile]]` changes, none of which a reload can apply: the
/// identity a tracker sees and the profile set itself are [`Identity`], the
/// rest [`NonIdentity`].
///
/// [`Identity`]: ProfileChangeKind::Identity
/// [`NonIdentity`]: ProfileChangeKind::NonIdentity
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
        // Destructured exhaustively, as in `Config::diff`, so a field added to
        // `ProfileConfig` does not compile until it is compared and given a
        // class. `id: _` is the one exception: it is the key these two were
        // matched on.
        let ProfileConfig {
            id: _,
            network,
            peer_fingerprint,
            user_agent,
            resume_dir,
            torrent_dir,
            allowed_tracker_domains,
            upload_rate_limit,
        } = a;
        let ProfileConfig {
            id: _,
            network: b_network,
            peer_fingerprint: b_peer_fingerprint,
            user_agent: b_user_agent,
            resume_dir: b_resume_dir,
            torrent_dir: b_torrent_dir,
            allowed_tracker_domains: b_allowed_tracker_domains,
            upload_rate_limit: b_upload_rate_limit,
        } = b;
        // Compared whole: which tunnel, which port, whether DHT runs.
        field("network", network != b_network, Identity);
        field(
            "peer_fingerprint",
            peer_fingerprint != b_peer_fingerprint,
            Identity,
        );
        field("user_agent", user_agent != b_user_agent, Identity);
        // Nothing a tracker reads: the stores are opened at startup, and the
        // add path reads the startup snapshot of the profile registry.
        field("resume_dir", resume_dir != b_resume_dir, NonIdentity);
        field("torrent_dir", torrent_dir != b_torrent_dir, NonIdentity);
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

/// Result of `Config::diff`. Reloadable fields are populated with the
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
    /// The five settings keys above that **differed**, named whatever they
    /// differ to: a deleted key assigns `None`, which alone reads as
    /// unchanged. Not `log_level`, which is never `None` when it differs and
    /// is not a `Settings` key.
    pub reloadable_changes: Vec<&'static str>,
    /// The subset of `reloadable_changes` the operator deleted. A `Settings`
    /// patch cannot unset a key, so a deletion is reported, never applied.
    pub reloadable_deletions: Vec<&'static str>,
    pub non_reloadable_changes: Vec<&'static str>,
    /// Per-profile fields that changed and were ignored, each with the class
    /// of warning it is owed (Safety Rule 7).
    pub profile_changes: Vec<ProfileChange>,
}

impl ConfigDiff {
    /// Build the `Settings` patch for `profile`, containing only the
    /// reloadable fields that changed and are permitted to reach it:
    /// `enable_lsd` never reaches a vpn profile (Safety Rule 6), and the
    /// top-level `upload_rate_limit` never reaches a profile with its own.
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

    /// True when the patch `to_settings_patch_for` built sets nothing, so the
    /// reload pump neither applies it nor logs `settings applied`.
    pub fn settings_patch_is_empty(patch: &SettingsPatch) -> bool {
        patch.fields.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.reloadable_changes.is_empty()
            && self.log_level.is_none()
            && self.non_reloadable_changes.is_empty()
            && self.profile_changes.is_empty()
    }

    /// Record that a reloadable settings key differed; `has_value` is false
    /// when the new file deletes it.
    fn record_reloadable(&mut self, key: &'static str, has_value: bool) {
        self.reloadable_changes.push(key);
        if !has_value {
            self.reloadable_deletions.push(key);
        }
    }
}

/// A `libtorrent_safe::Settings` patch together with the names of the fields
/// it sets, pushed by the statement that sets each one, so nothing downstream
/// keeps its own list of the reloadable keys.
#[derive(Debug, Default)]
pub struct SettingsPatch {
    /// What `apply_settings` is handed.
    pub settings: libtorrent_safe::Settings,
    /// The `Settings` field names this patch sets, in the order it set them.
    pub fields: Vec<&'static str>,
}

impl Config {
    /// A minimal config with `[pool]` rooted at `dir/pool` and the opt-out
    /// on a loopback bind, as the sample ships. Every field is listed, so one
    /// added to `Config` breaks this at compile time.
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
            allowed_hosts: vec![],
            log_level: Self::default_log_level(),
            registry_path: None,
            connections_limit: None,
            file_pool_size: None,
            enable_lsd: None,
            aio_threads: None,
            max_concurrent_http_announces: None,
            upload_rate_limit: None,
            unchoke_slots_limit: None,
            peer_fingerprint: None,
            user_agent: None,
            vpn_handshake_max_age_secs: Self::default_handshake_max_age(),
            shutdown_drain_secs: Self::default_shutdown_drain_secs(),
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
            trusted_proxies: vec![],
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
    fn a_trusted_proxies_entry_that_trusts_everyone_is_refused() {
        // A `/0` prefix, in any spelling, makes every caller a trusted proxy,
        // and so does a v4-mapped entry whose effective prefix is `/0`.
        let dir = tempdir().unwrap();

        for wide in [
            "0.0.0.0/0",
            "0.0.0.0/00",
            "0.0.0.0/000",
            "0.0.0.0/+0",
            "::/0",
            "::/00",
            "::/000",
            "::/+0",
            // v4-mapped: matched as 0.0.0.0/0, every IPv4 peer.
            "::ffff:0:0/96",
        ] {
            let body = with_top_level(&format!("trusted_proxies = [\"{wide}\"]"));
            // `parse` alone, so the refusal is attributed to `validate`
            // rather than to the file being unreadable.
            let cfg = Config::parse(&write_cfg(dir.path(), &body)).unwrap();
            let err = cfg
                .validate()
                .expect_err("a /0 prefix trusts every peer and must be refused");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(wide),
                "the refusal must name the offending entry; got {msg}",
            );

            // And it is not a posture judgement, so the operator subcommands
            // that skip the posture check — `--check-config` among them — get
            // it too. That is the command run before a restart.
            assert!(
                cfg.validate_without_auth_posture().is_err(),
                "{wide} must be refused for operator tools as well",
            );

            // Which means loading the file fails outright.
            assert!(
                Config::load(&write_cfg(dir.path(), &body)).is_err(),
                "{wide} must not produce a daemon that starts",
            );
        }

        // The refusal is about breadth, not about prefixes. A real proxy
        // network still validates, and so does the empty default.
        for ok in ["\"172.28.0.2\"", "\"10.0.0.0/8\"", "\"2001:db8::/32\""] {
            let body = with_top_level(&format!("trusted_proxies = [{ok}]"));
            Config::load(&write_cfg(dir.path(), &body))
                .unwrap_or_else(|e| panic!("{ok} is a legitimate trust set: {e:#}"));
        }
        Config::load(&write_cfg(dir.path(), &single_session()))
            .expect("the empty default is the safe one and must still load");
    }

    fn host_profile() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("public"),
            network: torrentd_engine::ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".into(),
                dht: false,
            },
            peer_fingerprint: None,
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
            peer_fingerprint: Some("-AA1000-".into()),
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
peer_fingerprint     = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
allowed_tracker_domains = ["t.example"]

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "eth0:6882"
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
        // A copied table: one peer-id prefix from the tunnel and the host.
        let msg = refusal(&vpn_plus_host("", r#"peer_fingerprint = "-AA1000-""#));
        assert!(
            msg.contains("peer_fingerprint")
                && !msg.contains("top-level")
                && msg.contains("-AA1000-"),
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
peer_fingerprint     = "-AA1000-"
user_agent           = "ua-a"
allowed_tracker_domains = ["t.example"]

[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg1.conf"
vpn_interface        = "wg1"
listen_port          = 6882
peer_fingerprint     = "-AA1000-"
user_agent           = "ua-b"
allowed_tracker_domains = ["t.example"]
"#
        );
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("peer_fingerprint") && !msg.contains("top-level"),
            "got: {msg}"
        );
    }

    #[test]
    fn a_host_profile_inheriting_the_top_level_identity_collides_with_a_vpn_profile() {
        // The host profile inherits the values the vpn profile declares.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "-AA1000-"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(
            msg.contains("-AA1000-"),
            "the colliding value is named, got: {msg}",
        );
        // The key named is the one the *inheriting* profile would have to
        // change — the top-level `peer_fingerprint`, which is what this
        // operator wrote.
        assert!(msg.contains("top-level peer_fingerprint"), "got: {msg}");
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
peer_fingerprint     = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
allowed_tracker_domains = ["t.example"]

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "eth0:6882"
"#,
        );
        assert!(msg.contains("user_agent"), "got: {msg}");
    }

    #[test]
    fn two_host_profiles_both_inheriting_the_top_level_identity_are_accepted() {
        // Two host profiles are one host; sharing the default is its use.
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
        // An inherited fingerprint announces as a declared one does.
        let msg = refusal(&two_host_profiles_with_top(
            r#"peer_fingerprint = "-LT20C0-""#,
        ));
        assert!(
            msg.contains("uses libtorrent's own client code"),
            "got: {msg}"
        );
        assert!(
            msg.contains("top-level peer_fingerprint "),
            "and named as the key the operator actually wrote, got: {msg}",
        );
    }

    #[test]
    fn a_top_level_fingerprint_must_be_an_eight_character_prefix() {
        // The top-level key and the per-profile one are the same field in the
        // same encoding, so they are held to the same shape. The hex spelling
        // of libtorrent's default is the case that matters most: it was once
        // refused as the default, and it is now refused before that question
        // is asked, because it is not eight bytes at all.
        for bad in ["2d4c54323043302d", "a1b2c3d4e5f60718", "-XX123-"] {
            let msg = refusal(&two_host_profiles_with_top(&format!(
                "peer_fingerprint = {bad:?}"
            )));
            assert!(
                msg.contains("top-level peer_fingerprint")
                    && msg.contains(bad)
                    && msg.contains("exactly 8 printable ASCII characters"),
                "{bad:?} must be refused as a malformed prefix, got: {msg}",
            );
        }
    }

    #[test]
    fn the_retired_hex_key_is_refused_with_its_replacement_named() {
        // `peer_fingerprint_hex` was documented as sixteen hex characters that
        // nothing decoded. Reading it under either meaning would change the
        // identity a tracker sees without the operator changing anything, and
        // `deny_unknown_fields` alone would say only "unknown field".
        let msg = refusal(&vpn_plus_host(
            "",
            r#"peer_fingerprint_hex = "b7c6d5e4f3a29180""#,
        ));
        assert!(
            msg.contains("\"public\"")
                && msg.contains("peer_fingerprint_hex")
                && msg.contains("no longer read")
                && msg.contains("as peer_fingerprint")
                && msg.contains("-XX1234-"),
            "got: {msg}",
        );
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
            r#"peer_fingerprint = "-AA1000-"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(msg.contains("-AA1000-"), "got: {msg}");
    }

    #[test]
    fn an_inherited_collision_names_the_key_the_operator_wrote() {
        // The per-profile and top-level keys share a name. An inherited value
        // is named as the top-level one, so the operator is not sent to a
        // `[[profile]]` table that does not contain the line.
        let msg = refusal(&vpn_plus_host(
            r#"peer_fingerprint = "-AA1000-"
user_agent = "qBittorrent/5.0.3""#,
            "",
        ));
        assert!(
            msg.contains("top-level peer_fingerprint"),
            "the key it names is the one they wrote, got: {msg}",
        );
    }

    #[test]
    fn a_top_level_identity_with_exactly_one_profile_is_still_accepted() {
        // The configuration the top-level default exists for. Refusing the
        // keys outright would close F4 too, and break this.
        let dir = tempdir().unwrap();
        let body = with_top_level(
            r#"peer_fingerprint = "-AA1000-"
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
listen_interfaces = "eth0:6882"
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
        // The documented upgrade (`docs/running.md` step 3).
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
        // Why containment is allowed: a store scans one level, so the inner
        // profile's `<id>/` directory is never read by the outer one.
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
        // The torrent store's half of the same property.
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

    /// A shipped sample config, which the tests below hold to loading.
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

    /// The `"..."` value of a `key = "..."` line, commented or not. `None` for
    /// any other line, including a longer key that `key` is a prefix of.
    fn sample_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let rest = line.trim_start_matches(['#', ' ']).strip_prefix(key)?;
        let rest = rest.trim_start().strip_prefix('=')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        Some(&rest[..rest.find('"')?])
    }

    #[test]
    fn every_sample_identity_names_a_libtorrent_based_client() {
        // Only the peer-id prefix and the user agent change; the rest of the
        // peer id, the extension handshake and the announces stay
        // libtorrent's. A Transmission identity on that wire is one a tracker
        // can tell is spoofed, so the samples name only clients built on
        // libtorrent, each prefix beside its own client's user agent. The
        // scan covers commented lines too: an example the operator uncomments
        // is never parsed before then.
        const LIBTORRENT_CLIENTS: [(&str, &str); 2] = [("-qB", "qBittorrent/"), ("-DE", "Deluge/")];
        for name in ["torrentd.sample.toml", "torrentd.multi-account.sample.toml"] {
            let text = fs::read_to_string(sample(name)).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            let mut seen = 0;
            for (i, line) in lines.iter().enumerate() {
                let Some(fp) = sample_value(line, "peer_fingerprint") else {
                    continue;
                };
                seen += 1;
                let (_, agent_prefix) = LIBTORRENT_CLIENTS
                    .iter()
                    .find(|(prefix, _)| fp.starts_with(prefix))
                    .unwrap_or_else(|| {
                        panic!("{name}:{}: {fp:?} is not a libtorrent-based client", i + 1)
                    });
                let agent = lines[i + 1..]
                    .iter()
                    .find_map(|l| sample_value(l, "user_agent"))
                    .unwrap_or_else(|| panic!("{name}:{}: {fp:?} has no user_agent", i + 1));
                assert!(
                    agent.starts_with(agent_prefix),
                    "{name}:{}: {fp:?} beside user agent {agent:?}",
                    i + 1,
                );
            }
            assert!(seen > 0, "{name} shows no peer_fingerprint at all");
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
        // An explicit 0 is a value: the top-level cap must not override it.
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

    /// A profile key, the class its change is owed, and the profile with only
    /// that key changed.
    type FieldEdit = (&'static str, ProfileChangeKind, ProfileConfig);

    /// Every `[[profile]]` field of `base` changed alone, each paired with the
    /// key and class `diff_profiles` owes it. Destructured with no `..`, so a
    /// new field needs a row; each row is asserted to be a real change.
    fn each_profile_field_changed_alone(base: &ProfileConfig) -> Vec<FieldEdit> {
        let ProfileConfig {
            id: _,
            network,
            peer_fingerprint,
            user_agent,
            resume_dir,
            torrent_dir,
            allowed_tracker_domains,
            upload_rate_limit,
        } = base;
        let with = |edit: &dyn Fn(&mut ProfileConfig)| {
            let mut p = base.clone();
            edit(&mut p);
            p
        };

        let new_network = torrentd_engine::ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6899".into(),
            dht: false,
        };
        let new_fingerprint = Some("-AA1000-".to_string());
        let new_user_agent = Some("ua/1.0".to_string());
        let new_resume_dir = Some(PathBuf::from("/var/lib/torrentd/resume-public"));
        let new_torrent_dir = Some(PathBuf::from("/var/lib/torrentd/torrents-public"));
        let new_domains = vec!["tracker.example.com".to_string()];
        let new_rate = Some(100_000);
        assert_ne!(network, &new_network);
        assert_ne!(peer_fingerprint, &new_fingerprint);
        assert_ne!(user_agent, &new_user_agent);
        assert_ne!(resume_dir, &new_resume_dir);
        assert_ne!(torrent_dir, &new_torrent_dir);
        assert_ne!(allowed_tracker_domains, &new_domains);
        assert_ne!(upload_rate_limit, &new_rate);

        use ProfileChangeKind::Identity;
        use ProfileChangeKind::NonIdentity;
        vec![
            (
                "network",
                Identity,
                with(&|p| p.network = new_network.clone()),
            ),
            (
                "peer_fingerprint",
                Identity,
                with(&|p| p.peer_fingerprint = new_fingerprint.clone()),
            ),
            (
                "user_agent",
                Identity,
                with(&|p| p.user_agent = new_user_agent.clone()),
            ),
            (
                "resume_dir",
                NonIdentity,
                with(&|p| p.resume_dir = new_resume_dir.clone()),
            ),
            (
                "torrent_dir",
                NonIdentity,
                with(&|p| p.torrent_dir = new_torrent_dir.clone()),
            ),
            (
                "allowed_tracker_domains",
                NonIdentity,
                with(&|p| p.allowed_tracker_domains = new_domains.clone()),
            ),
            (
                "upload_rate_limit",
                NonIdentity,
                with(&|p| p.upload_rate_limit = new_rate),
            ),
        ]
    }

    #[test]
    fn each_profile_field_changed_alone_is_reported_alone_with_its_class() {
        // Each alone, so none is reported only alongside another.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        for (key, kind, changed) in each_profile_field_changed_alone(&a.profile[0]) {
            let mut b = a.clone();
            b.profile[0] = changed;
            let d = Config::diff(&a, &b);
            assert_eq!(
                d.profile_changes,
                vec![ProfileChange {
                    what: format!("public.{key}"),
                    kind,
                }],
                "{key} changed alone",
            );
            assert!(
                !d.is_empty(),
                "{key}: the file changed and the daemon must say so"
            );
            assert!(
                d.non_reloadable_changes.is_empty(),
                "{key} is a profile key, not a top-level one: got {:?}",
                d.non_reloadable_changes,
            );
        }
    }

    #[test]
    fn any_change_inside_the_network_block_is_one_identity_change() {
        // The block is compared as one value so that a field added to
        // `ProfileNetwork` cannot be forgotten. That only holds if every
        // field it already has reaches the comparison, and if switching the
        // variant does too: which tunnel, which port, whether DHT runs.
        use torrentd_engine::ProfileNetwork;
        let dir = tempdir().unwrap();
        let host = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let mut vpn = host.clone();
        vpn.profile[0].network = ProfileNetwork::Vpn {
            vpn_type: torrentd_engine::VpnType::Wireguard,
            vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
            vpn_interface: "wg0".into(),
            listen_port: Some(6881),
            port_forward: Default::default(),
            port_forward_gateway: None,
        };

        let edits: Vec<(&str, &Config, ProfileNetwork)> = vec![
            (
                "host listen_interfaces",
                &host,
                ProfileNetwork::Host {
                    listen_interfaces: "0.0.0.0:6899".into(),
                    dht: false,
                },
            ),
            (
                "host dht",
                &host,
                ProfileNetwork::Host {
                    listen_interfaces: "0.0.0.0:6881".into(),
                    dht: true,
                },
            ),
            ("host to vpn", &host, vpn.profile[0].network.clone()),
            (
                "vpn interface",
                &vpn,
                ProfileNetwork::Vpn {
                    vpn_type: torrentd_engine::VpnType::Wireguard,
                    vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
                    vpn_interface: "wg1".into(),
                    listen_port: Some(6881),
                    port_forward: Default::default(),
                    port_forward_gateway: None,
                },
            ),
            (
                "vpn listen_port",
                &vpn,
                ProfileNetwork::Vpn {
                    vpn_type: torrentd_engine::VpnType::Wireguard,
                    vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
                    vpn_interface: "wg0".into(),
                    listen_port: Some(51413),
                    port_forward: Default::default(),
                    port_forward_gateway: None,
                },
            ),
            ("vpn to host", &vpn, host.profile[0].network.clone()),
        ];
        for (label, old, network) in edits {
            assert_ne!(old.profile[0].network, network, "{label} must be a change");
            let mut new = old.clone();
            new.profile[0].network = network;
            assert_eq!(
                Config::diff(old, &new).profile_changes,
                vec![ProfileChange {
                    what: "public.network".into(),
                    kind: ProfileChangeKind::Identity,
                }],
                "{label}",
            );
        }
    }

    #[test]
    fn an_unchanged_profile_set_produces_an_empty_diff() {
        // The other half of "every change is reported": a SIGHUP over a file
        // nobody edited must not warn about an identity change, or the
        // privacy warning stops meaning anything. Profiles are matched by id,
        // so the order they are written in is not a change either.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(
            dir.path(),
            &two_host_profiles(
                r#"user_agent = "ua/1.0"
upload_rate_limit = 0"#,
                r#"allowed_tracker_domains = ["tracker.example.com"]"#,
            ),
        ))
        .unwrap();
        assert_eq!(a.profile.len(), 2);

        let d = Config::diff(&a, &a.clone());
        assert!(d.profile_changes.is_empty(), "got {:?}", d.profile_changes);
        assert!(d.is_empty());

        let mut reordered = a.clone();
        reordered.profile.reverse();
        let d = Config::diff(&a, &reordered);
        assert!(
            d.profile_changes.is_empty(),
            "reordering profiles changes no account: got {:?}",
            d.profile_changes,
        );
        assert!(d.is_empty());
    }

    #[test]
    fn a_reloadable_top_level_change_does_not_leak_into_profile_changes() {
        // `profile_changes` is what emits Safety Rule 7's warning. A key the
        // reload applies live must reach its own field of `ConfigDiff` and
        // nothing in that list — least of all the top-level
        // `upload_rate_limit`, which shares its name with a profile key.
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        type TopLevelEdit = (&'static str, fn(&mut Config));
        let edits: Vec<TopLevelEdit> = vec![
            ("connections_limit", |c| c.connections_limit = Some(20_000)),
            ("upload_rate_limit", |c| c.upload_rate_limit = Some(100_000)),
            ("max_concurrent_http_announces", |c| {
                c.max_concurrent_http_announces = Some(8)
            }),
            ("aio_threads", |c| c.aio_threads = Some(8)),
            ("enable_lsd", |c| c.enable_lsd = Some(true)),
        ];
        for (key, edit) in edits {
            let mut b = a.clone();
            edit(&mut b);
            let d = Config::diff(&a, &b);
            assert!(
                d.profile_changes.is_empty(),
                "{key} is reloadable and not a profile change: got {:?}",
                d.profile_changes,
            );
            assert!(
                d.non_reloadable_changes.is_empty(),
                "{key}: got {:?}",
                d.non_reloadable_changes,
            );
            assert_eq!(d.reloadable_changes, vec![key], "{key} is still reported");
        }
    }

    /// A reload cannot apply any other top-level key, so a file differing in
    /// exactly one of them is reported as that key, and is not unchanged.
    #[test]
    fn each_non_reloadable_top_level_key_changed_alone_is_reported_alone() {
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        type TopLevelEdit = (&'static str, fn(&mut Config));
        let edits: Vec<TopLevelEdit> = vec![
            ("default_save_path", |c| {
                c.default_save_path = "/data/elsewhere".into()
            }),
            ("resume_dir", |c| c.resume_dir = "/var/lib/other/r".into()),
            ("torrent_dir", |c| c.torrent_dir = "/var/lib/other/t".into()),
            ("file_pool_size", |c| c.file_pool_size = Some(2048)),
            ("unchoke_slots_limit", |c| c.unchoke_slots_limit = Some(128)),
            ("peer_fingerprint", |c| {
                c.peer_fingerprint = Some("-ZZ1000-".into())
            }),
            ("user_agent", |c| c.user_agent = Some("other/1.0".into())),
            ("auth", |c| {
                c.auth = Some(crate::auth::AuthConfig {
                    password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
                    session_ttl_secs: 43_200,
                    token: vec![],
                })
            }),
            ("allow_unauthenticated", |c| {
                c.allow_unauthenticated = !c.allow_unauthenticated
            }),
            ("http_listen", |c| {
                c.http_listen = SocketAddr::from(([127, 0, 0, 1], 9090))
            }),
            ("trusted_proxies", |c| {
                c.trusted_proxies = vec!["172.28.0.2".into()]
            }),
            ("allowed_hosts", |c| {
                c.allowed_hosts = vec!["torrentd.example.com".into()]
            }),
            ("registry_path", |c| {
                c.registry_path = Some("/var/lib/torrentd/assignments.json".into())
            }),
            ("vpn_handshake_max_age_secs", |c| {
                c.vpn_handshake_max_age_secs += 60
            }),
            ("shutdown_drain_secs", |c| c.shutdown_drain_secs += 30),
            ("network_kill_switch", |c| {
                c.network_kill_switch = !c.network_kill_switch
            }),
            ("pool", |c| {
                c.pool = Some(PoolConfig {
                    roots: vec!["/data/pool".into()],
                    library_dir: "/data/library".into(),
                    db_path: None,
                    max_concurrent_verify: 1,
                    import_legacy_registry: false,
                    allow_mutations: false,
                })
            }),
        ];
        for (key, edit) in edits {
            let mut b = a.clone();
            edit(&mut b);
            let d = Config::diff(&a, &b);
            assert!(!d.is_empty(), "{key}");
            assert_eq!(d.non_reloadable_changes, vec![key]);
            assert!(d.reloadable_changes.is_empty(), "{key}");
            assert!(d.profile_changes.is_empty(), "{key}");
        }
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
        // Shape before policy: each config is wrong in shape and in posture,
        // and the shape is what is reported.
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

    /// `TOP_LEVEL`, with `allowed_hosts = [<hosts>]` after the opt-out.
    fn top_level_allowing(hosts: &str) -> String {
        TOP_LEVEL.replace(
            "allow_unauthenticated = true\n",
            &format!("allow_unauthenticated = true\nallowed_hosts = [{hosts}]\n"),
        )
    }

    #[test]
    fn allowed_hosts_takes_bare_names_and_addresses() {
        let dir = tempdir().unwrap();
        let body = format!(
            "{}{ONE_HOST_PROFILE}",
            top_level_allowing(r#""torrentd.example.com", "192.0.2.7", "[2001:db8::1]""#),
        );
        let cfg = Config::load(&write_cfg(dir.path(), &body)).unwrap();
        assert_eq!(cfg.allowed_hosts.len(), 3);

        for entry in [
            r#""https://torrentd.example.com""#,
            r#""torrentd.example.com:443""#,
            r#""torrentd.example.com/v1""#,
            r#""""#,
        ] {
            let msg = refusal(&format!("{}{ONE_HOST_PROFILE}", top_level_allowing(entry)));
            assert!(msg.contains("allowed_hosts"), "{entry}: got: {msg}");
        }
    }

    #[test]
    fn allowed_hosts_alongside_configured_auth_is_refused() {
        // Nothing reads it there, and left in place it reads as though the
        // daemon confined its Host names.
        let dir = tempdir().unwrap();
        let body = format!(
            "{}{ONE_HOST_PROFILE}\n[auth]\npassword_hash = \"{}\"\n",
            top_level_no_opt_out().replace(
                "http_listen",
                "allowed_hosts = [\"torrentd.example.com\"]\nhttp_listen"
            ),
            crate::auth::hash_password("hunter2").unwrap(),
        );
        assert!(body.contains("allowed_hosts = ["));
        let msg = format!(
            "{:#}",
            Config::load(&write_cfg(dir.path(), &body)).unwrap_err()
        );
        assert!(msg.contains("allowed_hosts"), "got: {msg}");
        assert!(msg.contains("Delete"), "got: {msg}");
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
             peer_fingerprint = \"-AA1000-\"\nuser_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n\
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
        // into the uniqueness set — and `/v1/profiles` then reports it back
        // under a field documented as `null` for natpmp profiles. Accepting
        // and ignoring a key is the shape every other rule in this conversion
        // exists to refuse.
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nport_forward = \"natpmp\"\nlisten_port = 6891\n\
             peer_fingerprint = \"-AA1000-\"\nuser_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
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
             peer_fingerprint = \"-AA1000-\"\nuser_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
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
        // The file the rule above exists for. `AssignmentRegistry`'s import
        // maps its JSON values straight into `ProfileId`.
        let dir = tempdir().unwrap();
        let path = dir.path().join("profile_assignments.json");
        fs::write(
            &path,
            r#"{"0101010101010101010101010101010101010101":"../../etc"}"#,
        )
        .unwrap();
        let import = JsonImport {
            path: path.clone(),
            pre_profiles: false,
        };
        assert!(
            torrentd_engine::AssignmentRegistry::open(dir.path().join("registry.db"), Some(import))
                .is_err(),
            "a registry naming an id that escapes its directory must not load",
        );
        assert!(path.exists(), "and a refused import moves nothing aside");
    }

    #[test]
    fn the_registry_is_a_database_in_the_state_dir_importing_the_json_beside_it() {
        let dir = tempdir().unwrap();
        let mut cfg = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        cfg.resume_dir = dir.path().join("resume");
        let state = cfg.state_dir();
        assert_eq!(state, dir.path());
        assert_eq!(cfg.registry_path(), state.join("registry.db"));
        assert_eq!(
            cfg.registry_import(),
            None,
            "nothing on disk, nothing to import"
        );

        fs::write(state.join("slot_assignments.json"), "{}").unwrap();
        assert_eq!(
            cfg.registry_import(),
            Some(JsonImport {
                path: state.join("slot_assignments.json"),
                pre_profiles: true,
            }),
            "a slot-era deployment's only file",
        );

        fs::write(state.join("profile_assignments.json"), "{}").unwrap();
        assert_eq!(
            cfg.registry_import(),
            Some(JsonImport {
                path: state.join("profile_assignments.json"),
                pre_profiles: false,
            }),
            "the current JSON file wins; the slot file beside it is a rollback copy",
        );

        fs::remove_file(state.join("profile_assignments.json")).unwrap();
        fs::write(cfg.registry_path(), b"").unwrap();
        assert_eq!(
            cfg.registry_import(),
            None,
            "once the database exists, a slot file is never read again",
        );
    }

    #[test]
    fn a_configured_json_registry_path_is_imported_into_a_database_beside_it() {
        // A config written before the database named the JSON file here.
        // Opening that as SQLite refuses the boot; reading it as the import
        // keeps those configs working.
        let dir = tempdir().unwrap();
        let mut cfg = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        cfg.resume_dir = dir.path().join("resume");
        let json = dir.path().join("assignments.json");
        cfg.registry_path = Some(json.clone());
        assert_eq!(cfg.registry_path(), dir.path().join("assignments.db"));
        assert_eq!(cfg.registry_import(), None);
        fs::write(&json, "{}").unwrap();
        assert_eq!(
            cfg.registry_import(),
            Some(JsonImport {
                path: json,
                pre_profiles: false,
            }),
        );

        let db = dir.path().join("elsewhere.db");
        cfg.registry_path = Some(db.clone());
        assert_eq!(cfg.registry_path(), db);
        fs::write(cfg.state_dir().join("profile_assignments.json"), "{}").unwrap();
        assert_eq!(
            cfg.registry_import(),
            None,
            "a configured database path imports nothing from the state dir",
        );
    }

    #[test]
    fn check_config_refuses_a_kill_switch_with_no_tunnel_to_confine_egress_to() {
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

    /// `openvpn` runs under the daemon's uid, so the kill switch drops its
    /// connection to the provider; the combination is refused at load, and a
    /// WireGuard-only set with the kill switch is not.
    #[test]
    fn the_kill_switch_is_refused_beside_an_openvpn_profile() {
        let dir = tempdir().unwrap();
        let wg = "[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
                  vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
                  listen_port = 6891\npeer_fingerprint = \"-AA1000-\"\n\
                  user_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n";
        let ovpn = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"openvpn\"\n\
                    vpn_config = \"/etc/openvpn/acct_b.conf\"\nvpn_interface = \"tun-b\"\n\
                    listen_port = 6892\npeer_fingerprint = \"-BB1000-\"\n\
                    user_agent = \"ua-b\"\nallowed_tracker_domains = [\"t.example\"]\n";

        let body = format!("{TOP_LEVEL}\nnetwork_kill_switch = true\n\n{wg}\n{ovpn}");
        let msg = format!(
            "{:#}",
            Config::load(&write_cfg(dir.path(), &body)).unwrap_err()
        );
        assert!(
            msg.contains("OpenVPN profile") && msg.contains("acct_b"),
            "got: {msg}"
        );

        let body = format!("{TOP_LEVEL}\n{wg}\n{ovpn}");
        Config::load(&write_cfg(dir.path(), &body))
            .expect("an OpenVPN profile without the kill switch is accepted");
    }

    #[test]
    fn a_kill_switch_with_a_vpn_profile_passes_the_pre_flight() {
        let dir = tempdir().unwrap();
        let body = format!(
            "{TOP_LEVEL}\nnetwork_kill_switch = true\n\n[[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
             listen_port = 6891\npeer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
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
             network = \"host\"\nlisten_interfaces = \"eth0:6881\"\n\n\
             [[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
             listen_port = 6891\npeer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
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

    /// A config whose top-level state is outside the root `dir/pool`, with
    /// one profile carrying `override_line` (a store-directory override).
    fn profile_override_under_pool(dir: &Path, override_line: &str) -> String {
        let root = dir.join("pool");
        std::fs::create_dir_all(&root).unwrap();
        format!(
            r#"
default_save_path = "{r}"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
{override_line}

[pool]
roots = ["{r}"]
library_dir = "{d}/library"
"#,
            r = root.display(),
            d = dir.display(),
        )
    }

    #[test]
    fn profile_resume_dir_inside_a_managed_root_is_rejected() {
        // The top-level stores are outside the root, but a profile's own
        // resume_dir override is not: its resume files would be orphans.
        let dir = tempdir().unwrap();
        let line = format!(
            "resume_dir = \"{}/pool/.acct_b/resume\"",
            dir.path().display()
        );
        let p = write_cfg(dir.path(), &profile_override_under_pool(dir.path(), &line));
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("[[profile]] id = \"public\" resume_dir"),
            "got: {msg}"
        );
        assert!(msg.contains("inside the managed root"), "got: {msg}");
    }

    #[test]
    fn profile_torrent_dir_inside_a_managed_root_is_rejected() {
        let dir = tempdir().unwrap();
        let line = format!(
            "torrent_dir = \"{}/pool/.acct_b/torrents\"",
            dir.path().display()
        );
        let p = write_cfg(dir.path(), &profile_override_under_pool(dir.path(), &line));
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("[[profile]] id = \"public\" torrent_dir"),
            "got: {msg}"
        );
        assert!(msg.contains("inside the managed root"), "got: {msg}");
    }

    #[test]
    fn profile_store_dirs_outside_every_managed_root_are_accepted() {
        // The control for the two tests above: the same config, with the
        // overrides pointing outside the root, loads.
        let dir = tempdir().unwrap();
        let line = format!(
            "resume_dir = \"{d}/acct_b/resume\"\ntorrent_dir = \"{d}/acct_b/torrents\"",
            d = dir.path().display()
        );
        let p = write_cfg(dir.path(), &profile_override_under_pool(dir.path(), &line));
        Config::load(&p).expect("profile stores outside the root are allowed");
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
    fn upload_rate_limit_is_bounded_by_what_libtorrent_can_carry() {
        let dir = tempdir().unwrap();
        let at_bound = with_top_level(&format!("upload_rate_limit = {}", i32::MAX));
        let p = write_cfg(dir.path(), &at_bound);
        Config::load(&p).expect("i32::MAX fits libtorrent's int setting");

        let past_bound = with_top_level(&format!("upload_rate_limit = {}", i32::MAX as u32 + 1));
        let p = write_cfg(dir.path(), &past_bound);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("upload_rate_limit"), "got: {msg}");
        assert!(msg.contains("out of range"), "got: {msg}");
    }

    #[test]
    fn an_http_listen_port_a_profile_listens_on_is_refused() {
        let dir = tempdir().unwrap();
        // A host profile's `listen_interfaces`, on another address.
        let host = single_session().replace("0.0.0.0:6881", "0.0.0.0:6881,[::]:8080");
        let msg = format!(
            "{:#}",
            Config::load(&write_cfg(dir.path(), &host)).unwrap_err()
        );
        assert!(
            msg.contains("http_listen") && msg.contains("8080"),
            "got: {msg}"
        );
        assert!(msg.contains("\"public\""), "names the profile: {msg}");

        // A vpn profile's static `listen_port`.
        let mut c = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        c.profile[0] = ProfileConfig {
            id: torrentd_engine::ProfileId::new("acct_a"),
            network: torrentd_engine::ProfileNetwork::Vpn {
                vpn_type: torrentd_engine::VpnType::Wireguard,
                vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
                vpn_interface: "wg0".into(),
                listen_port: Some(8080),
                port_forward: Default::default(),
                port_forward_gateway: None,
            },
            peer_fingerprint: Some("-AA1000-".into()),
            user_agent: Some("qB/5.0".into()),
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
        };
        let msg = format!("{:#}", c.validate_http_listen_port().unwrap_err());
        assert!(msg.contains("\"acct_a\""), "got: {msg}");

        // Distinct ports are fine.
        Config::load(&write_cfg(dir.path(), &single_session()))
            .expect("8080 and 6881 do not collide");
    }

    #[test]
    fn an_absent_unchoke_slots_limit_leaves_the_rate_based_choker() {
        let dir = tempdir().unwrap();
        let c = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        let s = c.libtorrent_settings();
        assert_eq!(
            s.choking_algorithm,
            Some(libtorrent_safe::Settings::RATE_BASED_CHOKER)
        );
        assert_eq!(
            s.unchoke_slots_limit,
            Some(libtorrent_safe::Settings::DEFAULT_UNCHOKE_SLOTS)
        );
    }

    #[test]
    fn an_unchoke_slots_limit_selects_the_fixed_slots_choker_with_that_many() {
        let dir = tempdir().unwrap();
        let body = with_top_level("unchoke_slots_limit = 64");
        let c = Config::load(&write_cfg(dir.path(), &body)).unwrap();
        let s = c.libtorrent_settings();
        assert_eq!(
            s.choking_algorithm,
            Some(libtorrent_safe::Settings::FIXED_SLOTS_CHOKER)
        );
        assert_eq!(s.unchoke_slots_limit, Some(64));

        let zero = with_top_level("unchoke_slots_limit = 0");
        let msg = format!(
            "{:#}",
            Config::load(&write_cfg(dir.path(), &zero)).unwrap_err()
        );
        assert!(msg.contains("unchoke_slots_limit"), "got: {msg}");

        let mut other = c.clone();
        other.unchoke_slots_limit = Some(128);
        assert_eq!(
            Config::diff(&c, &other).non_reloadable_changes,
            vec!["unchoke_slots_limit"],
        );
    }

    #[test]
    fn the_shared_test_fixture_states_a_posture() {
        // The fixture has no profile, so the posture is what it can satisfy.
        let dir = tempdir().unwrap();
        let cfg = Config::minimal_for_tests(dir.path(), false);
        cfg.validate_auth_posture()
            .expect("the shared fixture must state a posture the daemon accepts");
    }

    #[test]
    fn the_shutdown_drain_defaults_to_a_minute_and_refuses_zero() {
        let dir = tempdir().unwrap();
        let base = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
        assert_eq!(base.shutdown_drain_secs, 60);
        // Zero would skip the drain and lose every unsaved resume.
        let text = format!("shutdown_drain_secs = 0\n{}", single_session());
        let e = Config::load(&write_cfg(dir.path(), &text)).unwrap_err();
        assert!(
            format!("{e:#}").contains("shutdown_drain_secs"),
            "got {e:#}"
        );
    }

    #[test]
    fn deleting_a_reloadable_key_is_a_difference_and_is_named() {
        // Deleting a key is the documented way back to the preset default.
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
        // So such a reload does not end with `SIGHUP: settings applied`.
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
