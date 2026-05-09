//! TOML configuration parser.
//!
//! `serde(deny_unknown_fields)` everywhere — typos in setting names
//! produce fatal startup errors with the offending key (PRD: "Unknown
//! keys cause a fatal startup error"). `Config::diff` separates fields
//! that can be hot-reloaded via SIGHUP from those requiring a full
//! restart (PRD §Session Management).

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use seederd_engine::SlotConfig;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel { Error, Warn, Info, Debug }

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn  => "warn",
            LogLevel::Info  => "info",
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

    // libtorrent settings overrides (PRD §5).
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

    /// `[[slot]]` array. Empty → single-session mode.
    #[serde(default)]
    pub slot: Vec<SlotConfig>,
}

impl Config {
    fn default_log_level() -> LogLevel { LogLevel::Info }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let cfg: Config = toml::from_str(&bytes)
            .with_context(|| format!("parse {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.slot.is_empty() {
            SlotConfig::validate_set(&self.slot)
                .context("[[slot]] validation failed")?;
        }
        Ok(())
    }

    /// Compute a diff against an old config. Used by SIGHUP reload to
    /// apply only the fields that may change without restart.
    pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
        let mut d = ConfigDiff::default();
        if old.connections_limit != new.connections_limit { d.connections_limit = new.connections_limit; }
        if old.upload_rate_limit != new.upload_rate_limit { d.upload_rate_limit = new.upload_rate_limit; }
        if old.max_concurrent_http_announces != new.max_concurrent_http_announces {
            d.max_concurrent_http_announces = new.max_concurrent_http_announces;
        }
        if old.aio_threads != new.aio_threads { d.aio_threads = new.aio_threads; }
        if old.enable_lsd != new.enable_lsd { d.enable_lsd = new.enable_lsd; }
        if old.log_level != new.log_level { d.log_level = Some(new.log_level); }

        // Identity-critical / non-reloadable fields (PRD): listen_interfaces,
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
        if old.peer_fingerprint != new.peer_fingerprint {
            d.non_reloadable_changes.push("peer_fingerprint");
        }
        if old.user_agent != new.user_agent {
            d.non_reloadable_changes.push("user_agent");
        }
        d
    }

    /// Compose libtorrent settings from the PRD high_performance_seed
    /// preset overrides plus the operator's overrides in this Config.
    pub fn libtorrent_settings(&self) -> libtorrent_safe::Settings {
        let mut s = libtorrent_safe::Settings::server_seed_overrides();
        s.listen_interfaces = Some(self.listen_interfaces.clone());
        if let Some(v) = self.connections_limit { s.connections_limit = Some(v); }
        if let Some(v) = self.file_pool_size { s.file_pool_size = Some(v); }
        if let Some(v) = self.enable_lsd { s.enable_lsd = Some(v); }
        if let Some(v) = self.aio_threads { s.aio_threads = Some(v); }
        if let Some(v) = self.max_concurrent_http_announces { s.max_concurrent_http_announces = Some(v); }
        if let Some(v) = self.upload_rate_limit { s.upload_rate_limit = Some(v); }
        if let Some(v) = self.peer_fingerprint.as_ref() { s.peer_fingerprint = Some(v.clone()); }
        if let Some(v) = self.user_agent.as_ref() {
            s.user_agent = Some(v.clone());
            s.handshake_client_version = Some(v.clone());
        }
        s
    }

    /// Where the assignment registry should be persisted.
    pub fn registry_path(&self) -> PathBuf {
        self.registry_path.clone().unwrap_or_else(|| {
            self.resume_dir
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("/var/lib/seederd"))
                .join("slot_assignments.json")
        })
    }
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
    pub non_reloadable_changes: Vec<&'static str>,
}

impl ConfigDiff {
    /// Build a `Settings` patch containing only the reloadable fields
    /// that changed.
    pub fn into_settings_patch(&self) -> libtorrent_safe::Settings {
        let mut s = libtorrent_safe::Settings::default();
        s.connections_limit = self.connections_limit;
        s.upload_rate_limit = self.upload_rate_limit;
        s.max_concurrent_http_announces = self.max_concurrent_http_announces;
        s.aio_threads = self.aio_threads;
        s.enable_lsd = self.enable_lsd;
        s
    }

    pub fn is_empty(&self) -> bool {
        self.connections_limit.is_none()
            && self.upload_rate_limit.is_none()
            && self.max_concurrent_http_announces.is_none()
            && self.aio_threads.is_none()
            && self.enable_lsd.is_none()
            && self.log_level.is_none()
            && self.non_reloadable_changes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_cfg(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("seederd.toml");
        fs::write(&p, body).unwrap();
        p
    }

    const SINGLE_SESSION: &str = r#"
listen_interfaces = "0.0.0.0:6881"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/seederd/resume"
torrent_dir = "/var/lib/seederd/torrents"
http_listen = "127.0.0.1:8080"
log_level = "info"
connections_limit = 10000
"#;

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
