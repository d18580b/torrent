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
use torrentd_engine::ProfileId;

use crate::registry::JsonImport;

mod diff;
mod mounts;
mod validate;

pub use diff::ConfigDiff;
pub use diff::ProfileChange;
pub use diff::ProfileChangeKind;

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

/// Where the control API listens: a TCP address, or a unix socket written
/// `unix:/run/torrentd/api.sock`.
///
/// A TCP port on loopback is reachable by every uid on the host, and while
/// the daemon is down any of them can bind it and receive the next client's
/// credentials. A unix socket is reachable only by those its file mode and
/// group admit, and its path cannot be taken over by a user who cannot write
/// to its directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpListen {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

/// What a `unix:` value is written with.
const UNIX_PREFIX: &str = "unix:";

/// The longest socket path the kernel binds: `sun_path` is 108 bytes on
/// Linux, one of them the terminating NUL.
const MAX_UNIX_PATH_BYTES: usize = 107;

impl HttpListen {
    /// The TCP address, when this is one.
    pub fn tcp(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(addr) => Some(*addr),
            Self::Unix(_) => None,
        }
    }
}

impl std::fmt::Display for HttpListen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            Self::Unix(path) => write!(f, "{UNIX_PREFIX}{}", path.display()),
        }
    }
}

impl std::str::FromStr for HttpListen {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(path) = s.strip_prefix(UNIX_PREFIX) {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(format!(
                    "{s:?} names a relative socket path; write an absolute one, as in \
                     \"unix:/run/torrentd/api.sock\""
                ));
            }
            // The daemon binds the socket first at a staging path beside this
            // one, which is longer: that is the path the kernel must accept.
            let Some((_, staged)) = crate::api_socket::staging_paths(&path, u32::MAX) else {
                return Err(format!("{s:?} names a directory, not a socket file"));
            };
            if staged.as_os_str().len() > MAX_UNIX_PATH_BYTES {
                let longest =
                    MAX_UNIX_PATH_BYTES - (staged.as_os_str().len() - path.as_os_str().len());
                return Err(format!(
                    "{s:?} is longer than the {longest} bytes a socket path may be here: the \
                     daemon binds it first at a staging path beside it, and a unix socket path \
                     may be at most {MAX_UNIX_PATH_BYTES} bytes"
                ));
            }
            return Ok(Self::Unix(path));
        }
        s.parse::<SocketAddr>().map(Self::Tcp).map_err(|_| {
            format!(
                "{s:?} is neither an IP address and port (\"127.0.0.1:8080\") nor a unix \
                 socket (\"unix:/run/torrentd/api.sock\")"
            )
        })
    }
}

impl Serialize for HttpListen {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HttpListen {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The mode a `unix:` socket is created with when `http_socket_mode` is
/// absent: the daemon's user and its group, nobody else.
pub const DEFAULT_HTTP_SOCKET_MODE: u32 = 0o660;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub default_save_path: PathBuf,
    pub resume_dir: PathBuf,
    pub torrent_dir: PathBuf,
    /// Where the control API listens. Defaults to loopback, the only TCP
    /// address safe without `[auth]`; inside a network namespace (a
    /// container) it has to be set to a routable address for the published
    /// port to reach it. `unix:/path` serves it on a unix socket instead, and
    /// on no TCP port at all.
    #[serde(default = "Config::default_http_listen")]
    pub http_listen: HttpListen,

    /// Permission bits a `unix:` `http_listen` socket is given, written as an
    /// octal TOML integer (`0o660`). Default [`DEFAULT_HTTP_SOCKET_MODE`].
    /// Connecting takes write permission, so these bits are who may call the
    /// API. Refused beside a TCP `http_listen`, where nothing reads it.
    #[serde(default)]
    pub http_socket_mode: Option<u32>,

    /// The group a `unix:` `http_listen` socket is given, by name or number,
    /// so its members reach the API through the group bits of
    /// `http_socket_mode`. Absent, the socket keeps the daemon's own group.
    /// Refused beside a TCP `http_listen`.
    #[serde(default)]
    pub http_socket_group: Option<String>,

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

    /// How many torrents may be hashing at once: adoptions' verifications,
    /// re-hashes, the first check of a `.torrent` added with no resume data
    /// and the disk-error retry's checks together. Adopting a large subtree,
    /// re-hashing a library or adding many `.torrent`s otherwise saturates
    /// the disk and starves whatever is already seeding. Without `[pool]` the
    /// same checks share the default.
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
    /// Also the daemon's check limit where `[pool]` is not configured.
    pub(crate) fn default_max_concurrent_verify() -> usize {
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
    fn default_http_listen() -> HttpListen {
        HttpListen::Tcp(SocketAddr::from(([127, 0, 0, 1], 8080)))
    }

    /// The mode a `unix:` `http_listen` socket is created with.
    pub fn http_socket_mode(&self) -> u32 {
        self.http_socket_mode.unwrap_or(DEFAULT_HTTP_SOCKET_MODE)
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
            http_socket_mode: None,
            http_socket_group: None,
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
mod tests;
