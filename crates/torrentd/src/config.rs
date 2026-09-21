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
use torrentd_engine::SlotConfig;
use torrentd_engine::SlotId;

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
    /// libtorrent listen_interfaces (e.g. "0.0.0.0:6881,[::]:6881").
    pub listen_interfaces: String,
    pub default_save_path: PathBuf,
    pub resume_dir: PathBuf,
    pub torrent_dir: PathBuf,
    pub http_listen: SocketAddr,
    #[serde(default = "Config::default_log_level")]
    pub log_level: LogLevel,

    /// Where the assignment registry lives. Defaults to
    /// `<resume_dir parent>/slot_assignments.json`.
    #[serde(default)]
    pub registry_path: Option<PathBuf>,

    /// Where DHT/session state is persisted across restarts (single-session
    /// mode only; slots run with `enable_dht=false`). Defaults to
    /// `<resume_dir parent>/session_state.dat`.
    #[serde(default)]
    pub session_state_path: Option<PathBuf>,

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
    /// monitor treats the slot as down (multi-slot mode). Catches a tunnel that
    /// keeps its IP but has silently stopped handshaking. Default 180s.
    #[serde(default = "Config::default_handshake_max_age")]
    pub vpn_handshake_max_age_secs: u64,

    /// Install a fail-closed nftables kill switch (multi-slot mode) that
    /// confines the daemon's egress to loopback + the slots' tunnel interfaces.
    /// Off by default; requires `CAP_NET_ADMIN` and that torrentd runs as its own
    /// user. See `vpn::killswitch`.
    #[serde(default)]
    pub network_kill_switch: bool,

    /// `[[slot]]` array. Empty → single-session mode.
    #[serde(default)]
    pub slot: Vec<SlotConfig>,

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

    /// Fold a legacy `slot_assignments.json` into the index on the next scan.
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

impl Config {
    fn default_log_level() -> LogLevel {
        LogLevel::Info
    }

    fn default_handshake_max_age() -> u64 {
        180
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&bytes).with_context(|| format!("parse {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.slot.is_empty() {
            SlotConfig::validate_set(&self.slot).context("[[slot]] validation failed")?;
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
            let state: [(&str, &Path); 6] = [
                ("resume_dir", &self.resume_dir),
                ("torrent_dir", &self.torrent_dir),
                ("[pool] library_dir", &pool.library_dir),
                ("[pool] db_path", &self.pool_db_path()),
                ("registry_path", &self.registry_path()),
                ("session_state_path", &self.session_state_path()),
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

        // Identity-critical / non-reloadable fields: listen_interfaces,
        // resume_dir, torrent_dir, peer_fingerprint, user_agent. Any change
        // to these is reported in `non_reloadable_changes` so SIGHUP can
        // log+ignore.
        if old.listen_interfaces != new.listen_interfaces {
            d.non_reloadable_changes.push("listen_interfaces");
        }
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
        if old.session_state_path != new.session_state_path {
            d.non_reloadable_changes.push("session_state_path");
        }
        d.slot_changes = diff_slots(&old.slot, &new.slot);
        d.slots_with_own_upload_limit = new
            .slot
            .iter()
            .filter(|s| s.upload_rate_limit.is_some())
            .map(|s| s.id.clone())
            .collect();
        d
    }

    /// Compose libtorrent settings from the spec high_performance_seed
    /// preset overrides plus the operator's overrides in this Config.
    pub fn libtorrent_settings(&self) -> libtorrent_safe::Settings {
        let mut s = libtorrent_safe::Settings::server_seed_overrides();
        s.listen_interfaces = Some(self.listen_interfaces.clone());
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
            .unwrap_or_else(|| self.state_dir().join("slot_assignments.json"))
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

    /// Where DHT/session state should be persisted (single-session mode).
    pub fn session_state_path(&self) -> PathBuf {
        self.session_state_path
            .clone()
            .unwrap_or_else(|| self.state_dir().join("session_state.dat"))
    }
}

/// Result of `Config::diff`. Reloadable fields are populated with the
/// Report `[[slot]]` changes that a reload cannot apply.
///
/// Most fields here are identity-critical: the tunnel a session is bound to,
/// the port it announces, the peer fingerprint and user agent a tracker sees,
/// and where its resume and torrent files live. Changing any of them means a
/// different account identity to the tracker, which is a restart — not
/// something to swap under a live session. Adding or removing slots is
/// likewise a restart, since the slot set is fixed when sessions are built.
///
/// `upload_rate_limit` is the exception: it is not identity-critical, it is
/// merely not reloadable per slot (the reload path patches settings by slot
/// id, not by slot config). It is listed for the reason stated on
/// `ConfigDiff::non_reloadable_changes` — a change that is neither applied
/// nor reported leaves the operator believing a SIGHUP took when it did not,
/// which is the exact defect this same change fixes for `file_pool_size`.
fn diff_slots(old: &[SlotConfig], new: &[SlotConfig]) -> Vec<String> {
    use std::collections::BTreeMap;
    let index = |v: &[SlotConfig]| -> BTreeMap<String, SlotConfig> {
        v.iter()
            .map(|s| (s.id.as_str().to_string(), s.clone()))
            .collect()
    };
    let (o, n) = (index(old), index(new));
    let mut out = Vec::new();

    for id in n.keys() {
        if !o.contains_key(id) {
            out.push(format!("{id}: added (the slot set is fixed at startup)"));
        }
    }
    for (id, a) in &o {
        let Some(b) = n.get(id) else {
            out.push(format!("{id}: removed (the slot set is fixed at startup)"));
            continue;
        };
        let mut field = |name: &str, changed: bool| {
            if changed {
                out.push(format!("{id}.{name}"));
            }
        };
        field("vpn_profile", a.vpn_profile != b.vpn_profile);
        field("vpn_type", a.vpn_type != b.vpn_type);
        field("vpn_interface", a.vpn_interface != b.vpn_interface);
        field("listen_port", a.listen_port != b.listen_port);
        field(
            "peer_fingerprint_hex",
            a.peer_fingerprint_hex != b.peer_fingerprint_hex,
        );
        field("user_agent", a.user_agent != b.user_agent);
        field("resume_dir", a.resume_dir != b.resume_dir);
        field("torrent_dir", a.torrent_dir != b.torrent_dir);
        field("port_forward", a.port_forward != b.port_forward);
        field(
            "port_forward_gateway",
            a.port_forward_gateway != b.port_forward_gateway,
        );
        field(
            "upload_rate_limit",
            a.upload_rate_limit != b.upload_rate_limit,
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
    pub non_reloadable_changes: Vec<&'static str>,
    /// Per-slot identity fields that changed and were ignored, as
    /// `"<slot_id>.<field>"`. Safety Rule 7 requires a warning for these and
    /// `Config::diff` used to skip `[[slot]]` entirely, so changing a slot's
    /// VPN interface, port, fingerprint, user agent or directories on SIGHUP
    /// was swallowed in silence.
    pub slot_changes: Vec<String>,
    /// Slots that state their own `[[slot]] upload_rate_limit`.
    ///
    /// The top-level reloadable value is withheld from these, the way
    /// `enable_lsd` is withheld from every non-default slot. A slot's own
    /// limit is applied once, at boot; without this filter the first SIGHUP
    /// that changed the *global* limit overwrote every slot's, logged
    /// `SIGHUP: settings applied`, and left nothing to restore it but a
    /// restart.
    ///
    /// Not part of `is_empty`: it describes the current config, not a change.
    pub slots_with_own_upload_limit: Vec<SlotId>,
}

impl ConfigDiff {
    /// Build the `Settings` patch for `slot`, containing only the reloadable
    /// fields that changed and are permitted to reach that slot.
    ///
    /// `enable_lsd` is withheld from every slot but the single-session
    /// default. Safety Rule 6 says a private slot runs with DHT, PEX and LSD
    /// off unconditionally and that no config key can turn them on — but
    /// `enable_lsd` is a top-level *reloadable* key that was applied to every
    /// session alike, so `enable_lsd = true` plus a SIGHUP quietly re-enabled
    /// local peer discovery on exactly the sessions that must never have it.
    /// The daemon still honours the key for the public single session, which
    /// is the only place it means anything.
    ///
    /// `upload_rate_limit` is withheld on the same principle, for a different
    /// reason: a slot that states its own limit had it applied at boot, and a
    /// top-level reload has no business silently replacing it. See
    /// `slots_with_own_upload_limit`.
    pub fn to_settings_patch_for(&self, slot: &SlotId) -> libtorrent_safe::Settings {
        libtorrent_safe::Settings {
            connections_limit: self.connections_limit,
            upload_rate_limit: if self.slots_with_own_upload_limit.contains(slot) {
                None
            } else {
                self.upload_rate_limit
            },
            max_concurrent_http_announces: self.max_concurrent_http_announces,
            aio_threads: self.aio_threads,
            enable_lsd: if slot.is_default() {
                self.enable_lsd
            } else {
                None
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
            && self.slot_changes.is_empty()
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
listen_interfaces = "0.0.0.0:6881"
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

    const SINGLE_SESSION: &str = r#"
listen_interfaces = "0.0.0.0:6881"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
log_level = "info"
connections_limit = 10000
"#;

    #[test]
    fn a_file_pool_size_change_is_reported_rather_than_swallowed() {
        let dir = tempdir().unwrap();
        let a = Config::load(&write_cfg(dir.path(), SINGLE_SESSION)).unwrap();
        let mut b = a.clone();
        b.file_pool_size = Some(2048);
        let d = Config::diff(&a, &b);
        assert!(
            d.non_reloadable_changes.contains(&"file_pool_size"),
            "got {:?}",
            d.non_reloadable_changes,
        );
    }

    /// A `[[slot]]` with its own upload cap, for the two tests below.
    fn slot_with_limit(id: &str, limit: Option<u32>) -> SlotConfig {
        SlotConfig {
            id: SlotId::new(id),
            vpn_profile: PathBuf::from(format!("/etc/wireguard/wg-{id}.conf")),
            vpn_type: torrentd_engine::VpnType::Wireguard,
            vpn_interface: format!("wg-{id}"),
            listen_port: Some(6881),
            peer_fingerprint_hex: "a1b2c3d4e5f60718".to_string(),
            user_agent: format!("ua-{id}"),
            resume_dir: PathBuf::from(format!("/var/lib/torrentd/resume/{id}")),
            torrent_dir: PathBuf::from(format!("/var/lib/torrentd/torrents/{id}")),
            allowed_tracker_domains: vec![],
            upload_rate_limit: limit,
            port_forward: torrentd_engine::PortForwardMode::Static,
            port_forward_gateway: None,
        }
    }

    #[test]
    fn a_top_level_reload_cannot_overwrite_a_slots_own_upload_limit() {
        // The operator caps `acct_a` at 500 KB/s and leaves the top level
        // alone. Later they set a global 20 MB/s and SIGHUP. Without the
        // filter, `to_settings_patch_for` carries the top-level value to
        // every slot alike: `acct_a` starts uploading at 20 MB/s, `SIGHUP:
        // settings applied` is logged as a success, and nothing restores the
        // slot's own limit short of a restart.
        let dir = tempdir().unwrap();
        let mut a = Config::load(&write_cfg(dir.path(), SINGLE_SESSION)).unwrap();
        a.slot = vec![
            slot_with_limit("acct_a", Some(500_000)),
            slot_with_limit("acct_b", None),
        ];
        let mut b = a.clone();
        b.upload_rate_limit = Some(20_000_000);

        let d = Config::diff(&a, &b);
        assert_eq!(d.upload_rate_limit, Some(20_000_000));
        assert_eq!(
            d.to_settings_patch_for(&SlotId::new("acct_a"))
                .upload_rate_limit,
            None,
            "a slot that states its own limit keeps it",
        );
        assert_eq!(
            d.to_settings_patch_for(&SlotId::new("acct_b"))
                .upload_rate_limit,
            Some(20_000_000),
            "a slot that states none still inherits the top-level limit",
        );
    }

    #[test]
    fn a_slot_upload_rate_limit_change_is_reported_rather_than_swallowed() {
        // The key became real at boot with this change. Per-slot settings
        // patching is not something the reload path can do, so the change is
        // not applied — but `is_empty()` would otherwise be true, reload
        // would log `SIGHUP: config unchanged`, and the operator would be
        // told their edit took effect when it did not.
        let dir = tempdir().unwrap();
        let mut a = Config::load(&write_cfg(dir.path(), SINGLE_SESSION)).unwrap();
        a.slot = vec![slot_with_limit("acct_a", Some(500_000))];
        let mut b = a.clone();
        b.slot = vec![slot_with_limit("acct_a", Some(900_000))];

        let d = Config::diff(&a, &b);
        assert!(
            d.slot_changes
                .contains(&"acct_a.upload_rate_limit".to_string()),
            "got {:?}",
            d.slot_changes,
        );
        assert!(!d.is_empty(), "a reported change is not an empty diff");
    }

    #[test]
    fn an_explicit_slot_zero_is_unlimited_rather_than_inherited() {
        // `Some(0)` and `None` are different configurations: `0` is what the
        // identically named top-level key means by unlimited, and a slot that
        // simply omits the key inherits. Collapsing them — which a plain
        // `u32` field forces — leaves no way to state that one slot is
        // uncapped under a global cap.
        let explicit = slot_with_limit("acct_a", Some(0));
        let inherited = slot_with_limit("acct_a", None);
        assert_ne!(explicit.upload_rate_limit, inherited.upload_rate_limit);

        let dir = tempdir().unwrap();
        let mut a = Config::load(&write_cfg(dir.path(), SINGLE_SESSION)).unwrap();
        a.upload_rate_limit = Some(1_000_000);
        a.slot = vec![explicit];
        let mut b = a.clone();
        b.upload_rate_limit = Some(2_000_000);
        let d = Config::diff(&a, &b);
        assert_eq!(
            d.to_settings_patch_for(&SlotId::new("acct_a"))
                .upload_rate_limit,
            None,
            "an explicitly unlimited slot is not re-capped by a global change",
        );
    }

    #[test]
    fn enable_lsd_never_reaches_a_private_slot() {
        // Safety Rule 6: a private slot has LSD off unconditionally, and no
        // config key may turn it on. `enable_lsd` is top-level and reloadable,
        // so without this filter a SIGHUP re-enabled local peer discovery on
        // exactly the sessions that must never have it.
        let diff = ConfigDiff {
            enable_lsd: Some(true),
            ..Default::default()
        };
        assert_eq!(
            diff.to_settings_patch_for(&SlotId::default_single())
                .enable_lsd,
            Some(true),
            "the public single session still honours the key",
        );
        assert_eq!(
            diff.to_settings_patch_for(&SlotId::new("acct_a"))
                .enable_lsd,
            None,
            "a private slot must not receive it",
        );
    }

    #[test]
    fn parses_single_session() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), SINGLE_SESSION);
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.connections_limit, Some(10000));
        assert!(cfg.slot.is_empty());
    }

    #[test]
    fn unknown_key_is_fatal() {
        let dir = tempdir().unwrap();
        let bad = SINGLE_SESSION.to_string() + "\nunknown_setting = 42\n";
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
        let body = SINGLE_SESSION.to_string()
            + "\n[pool]\nroots = [\"/data/torrents\"]\nlibrary_dir = \"/var/lib/torrentd/library\"\n";
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
listen_interfaces = "0.0.0.0:6881"
default_save_path = "{r}"
resume_dir = "{r}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"

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
listen_interfaces = "0.0.0.0:6881"
default_save_path = "{d}/data"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"

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
        let bad = SINGLE_SESSION.to_string() + "\naio_threads = 0\n";
        let p = write_cfg(dir.path(), &bad);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(msg.contains("aio_threads"), "got: {msg}");
        assert!(msg.contains("out of range"), "got: {msg}");
    }

    #[test]
    fn diff_separates_reloadable_from_non() {
        let dir = tempdir().unwrap();
        let p = write_cfg(dir.path(), SINGLE_SESSION);
        let old = Config::load(&p).unwrap();
        let mut new = old.clone();
        new.connections_limit = Some(20000);
        new.listen_interfaces = "0.0.0.0:9999".into();
        let d = Config::diff(&old, &new);
        assert_eq!(d.connections_limit, Some(20000));
        assert_eq!(d.non_reloadable_changes, vec!["listen_interfaces"]);
    }
}
