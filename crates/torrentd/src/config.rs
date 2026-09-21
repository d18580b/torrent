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
    /// monitor treats the profile as down (multi-profile mode). Catches a tunnel that
    /// keeps its IP but has silently stopped handshaking. Default 180s.
    #[serde(default = "Config::default_handshake_max_age")]
    pub vpn_handshake_max_age_secs: u64,

    /// Install a fail-closed nftables kill switch (multi-profile mode) that
    /// confines the daemon's egress to loopback + the profiles' tunnel interfaces.
    /// Off by default; requires `CAP_NET_ADMIN` and that torrentd runs as its own
    /// user. See `vpn::killswitch`.
    #[serde(default)]
    pub network_kill_switch: bool,

    /// `[[profile]]` array. Empty → single-session mode.
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
    ///   in front, not for having none.
    fn validate_auth_posture(&self) -> anyhow::Result<()> {
        if self.auth.is_some() {
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
        if !self.http_listen.ip().is_loopback() {
            anyhow::bail!(
                "allow_unauthenticated = true with http_listen = {listen}, which is not a \
                 loopback address. That is an unauthenticated API that mutates state, \
                 reachable from the network. Bind to 127.0.0.1 and put a reverse proxy in \
                 front, or configure [auth].",
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
    pub fn validate_without_auth_posture(&self) -> anyhow::Result<()> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, check_auth_posture: bool) -> anyhow::Result<()> {
        // Unconditional: an empty set is itself a refusal now, because there
        // is no implicit profile to fall back to.
        ProfileConfig::validate_set(&self.profile).context("[[profile]] validation failed")?;

        if check_auth_posture {
            self.validate_auth_posture()?;
        }
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
        Ok(())
    }

    /// Compute a diff against an old config. Used by SIGHUP reload to
    /// apply only the fields that may change without restart.
    pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
        let mut d = ConfigDiff::default();
        if old.connections_limit != new.connections_limit {
            d.connections_limit = new.connections_limit;
        }
        if old.upload_rate_limit != new.upload_rate_limit {
            d.upload_rate_limit = new.upload_rate_limit;
        }
        if old.max_concurrent_http_announces != new.max_concurrent_http_announces {
            d.max_concurrent_http_announces = new.max_concurrent_http_announces;
        }
        if old.aio_threads != new.aio_threads {
            d.aio_threads = new.aio_threads;
        }
        if old.enable_lsd != new.enable_lsd {
            d.enable_lsd = new.enable_lsd;
        }
        if old.log_level != new.log_level {
            d.log_level = Some(new.log_level);
        }

        // Identity-critical / non-reloadable fields. Every one of them is
        // reported in `non_reloadable_changes` so SIGHUP can log+ignore; a
        // key that is neither applied nor mentioned leaves the operator
        // believing a reload took.
        if old.resume_dir != new.resume_dir {
            d.non_reloadable_changes.push("resume_dir");
        }
        if old.torrent_dir != new.torrent_dir {
            d.non_reloadable_changes.push("torrent_dir");
        }
        if old.file_pool_size != new.file_pool_size {
            // Not reloadable, and it used to be the one non-reloadable key
            // that was not *reported* either: `diff` skipped it entirely, so a
            // change was neither applied nor mentioned, unlike every other
            // field in this list.
            d.non_reloadable_changes.push("file_pool_size");
        }
        if old.peer_fingerprint != new.peer_fingerprint {
            d.non_reloadable_changes.push("peer_fingerprint");
        }
        if old.user_agent != new.user_agent {
            d.non_reloadable_changes.push("user_agent");
        }
        // The authentication posture and the bind address are settled at boot:
        // `AppState.auth` is built once in `startup::boot` and the listener is
        // bound once, so neither can follow a running daemon's config. They
        // are reported here for the same reason as everything above, and one
        // more: these three were the only non-reloadable keys `diff` did not
        // look at, so an operator who added `[auth]` and reloaded got
        // `SIGHUP: config unchanged` from the journal and `202 Accepted` from
        // `POST /api/reload` while the daemon went on authenticating nothing.
        // Silence there reads as confirmation, which is worse than no signal.
        if old.auth != new.auth {
            d.non_reloadable_changes.push("auth");
        }
        if old.allow_unauthenticated != new.allow_unauthenticated {
            d.non_reloadable_changes.push("allow_unauthenticated");
        }
        if old.http_listen != new.http_listen {
            d.non_reloadable_changes.push("http_listen");
        }
        d.profile_changes = diff_profiles(&old.profile, &new.profile);
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

    /// Where the assignment registry should be persisted.
    pub fn registry_path(&self) -> PathBuf {
        self.registry_path
            .clone()
            .unwrap_or_else(|| self.state_dir().join(REGISTRY_FILE))
    }

    /// The pre-rename registry file, if it is the only one present.
    ///
    /// Renaming profiles to profiles renamed this file too, and a daemon that
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
    pub fn session_state_path(&self, profile: &ProfileId) -> PathBuf {
        self.state_dir()
            .join(format!("session_state-{}.dat", profile.as_str()))
    }
}

/// Result of `Config::diff`. Reloadable fields are populated with the
/// Report `[[profile]]` changes that a reload cannot apply.
///
/// Every field here is identity-critical: the tunnel a session is bound to,
/// the port it announces, the peer fingerprint and user agent a tracker sees,
/// and where its resume and torrent files live. Changing any of them means a
/// different account identity to the tracker, which is a restart — not
/// something to swap under a live session. Adding or removing profiles is
/// likewise a restart, since the profile set is fixed when sessions are built.
fn diff_profiles(old: &[ProfileConfig], new: &[ProfileConfig]) -> Vec<String> {
    use std::collections::BTreeMap;
    let index = |v: &[ProfileConfig]| -> BTreeMap<String, ProfileConfig> {
        v.iter()
            .map(|s| (s.id.as_str().to_string(), s.clone()))
            .collect()
    };
    let (o, n) = (index(old), index(new));
    let mut out = Vec::new();

    for id in n.keys() {
        if !o.contains_key(id) {
            out.push(format!("{id}: added (the profile set is fixed at startup)"));
        }
    }
    for (id, a) in &o {
        let Some(b) = n.get(id) else {
            out.push(format!(
                "{id}: removed (the profile set is fixed at startup)"
            ));
            continue;
        };
        let mut field = |name: &str, changed: bool| {
            if changed {
                out.push(format!("{id}.{name}"));
            }
        };
        // The whole network block is identity: which tunnel, which port,
        // whether DHT runs. Comparing it as one value means a new field
        // cannot be forgotten here the way `file_pool_size` was forgotten
        // from the top-level diff.
        field("network", a.network != b.network);
        field(
            "peer_fingerprint_hex",
            a.peer_fingerprint_hex != b.peer_fingerprint_hex,
        );
        field("user_agent", a.user_agent != b.user_agent);
        field("resume_dir", a.resume_dir != b.resume_dir);
        field("torrent_dir", a.torrent_dir != b.torrent_dir);
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
    pub non_reloadable_changes: Vec<&'static str>,
    /// Per-profile identity fields that changed and were ignored, as
    /// `"<profile_id>.<field>"`. Safety Rule 7 requires a warning for these and
    /// `Config::diff` used to skip `[[profile]]` entirely, so changing a profile's
    /// VPN interface, port, fingerprint, user agent or directories on SIGHUP
    /// was swallowed in silence.
    pub profile_changes: Vec<String>,
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
    pub fn to_settings_patch_for(&self, profile: &ProfileConfig) -> libtorrent_safe::Settings {
        libtorrent_safe::Settings {
            connections_limit: self.connections_limit,
            upload_rate_limit: self.upload_rate_limit,
            max_concurrent_http_announces: self.max_concurrent_http_announces,
            aio_threads: self.aio_threads,
            enable_lsd: if profile.is_vpn() {
                None
            } else {
                self.enable_lsd
            },
            ..Default::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.connections_limit.is_none()
            && self.upload_rate_limit.is_none()
            && self.max_concurrent_http_announces.is_none()
            && self.aio_threads.is_none()
            && self.enable_lsd.is_none()
            && self.log_level.is_none()
            && self.non_reloadable_changes.is_empty()
            && self.profile_changes.is_empty()
    }
}

impl Config {
    /// A minimal single-session config with `[pool]` rooted at `dir/pool`.
    ///
    /// Test-only, and deliberately built from the real types rather than from
    /// TOML, so a required field added to `Config` breaks this at compile time
    /// instead of leaving the tests exercising a shape the daemon never sees.
    #[cfg(test)]
    pub fn minimal_for_tests(dir: &Path, allow_mutations: bool) -> Self {
        let mut cfg: Config = toml::from_str(&format!(
            r#"
default_save_path = "{d}/data"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
"#,
            d = dir.display(),
        ))
        .expect("minimal config parses");
        cfg.pool = Some(PoolConfig {
            roots: vec![dir.join("pool")],
            library_dir: dir.join("library"),
            db_path: Some(dir.join("pool.db")),
            max_concurrent_verify: 1,
            import_legacy_registry: false,
            allow_mutations,
        });
        std::fs::create_dir_all(dir.join("pool")).unwrap();
        std::fs::create_dir_all(dir.join("library")).unwrap();
        cfg
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
            upload_rate_limit: 0,
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
            upload_rate_limit: 0,
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
            diff.to_settings_patch_for(&host_profile()).enable_lsd,
            Some(true),
            "a host profile still honours the key",
        );
        assert_eq!(
            diff.to_settings_patch_for(&vpn_profile()).enable_lsd,
            None,
            "a tunnelled profile must not receive it",
        );
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
}
