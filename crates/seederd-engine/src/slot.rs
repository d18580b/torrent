//! Slot identification + per-slot data.
//!
//! `SlotId` is the cheap-to-clone key used in StateMap, registry, and
//! every `(slot_id, alert)` pair. `SlotConfig` is the operator-supplied
//! shape parsed from TOML (PRD §Multi-Account `[[slot]]`); validation
//! cross-checks lives here so SIGHUP reload and startup share one path.
//! `Slot` bundles the config with the runtime engine so the daemon's
//! HTTP handlers can answer `/slots/{slot_id}` queries.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::engine::TorrentEngine;
use crate::vpn::{VpnProfile, VpnType};

// ---------------------------------------------------------------------------
// SlotId
// ---------------------------------------------------------------------------

/// Stable, cheap-to-clone slot identifier.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SlotId(Arc<str>);

impl SlotId {
    pub const DEFAULT: &'static str = "default";

    pub fn new(id: impl Into<String>) -> Self { Self(Arc::from(id.into())) }
    pub fn default_single() -> Self { Self(Arc::from(Self::DEFAULT)) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn is_default(&self) -> bool { &*self.0 == Self::DEFAULT }
}

impl fmt::Display for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl fmt::Debug for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotId({})", self.0)
    }
}
impl From<&str> for SlotId   { fn from(s: &str)   -> Self { Self::new(s) } }
impl From<String> for SlotId { fn from(s: String) -> Self { Self::new(s) } }

impl Serialize for SlotId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for SlotId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(SlotId::new(s))
    }
}

// ---------------------------------------------------------------------------
// SlotConfig — operator-supplied (TOML)
// ---------------------------------------------------------------------------

/// Per-slot configuration, mirroring the `[[slot]]` table in the daemon's
/// config file (PRD §Multi-Account "Configuration Format"). Validation
/// (uniqueness rules etc.) is handled by `SlotConfig::validate_set`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotConfig {
    pub id: SlotId,
    pub vpn_profile: PathBuf,
    pub vpn_type: VpnType,
    pub vpn_interface: String,
    pub listen_port: u16,
    pub peer_fingerprint_hex: String,
    pub user_agent: String,
    pub resume_dir: PathBuf,
    pub torrent_dir: PathBuf,
    #[serde(default)]
    pub allowed_tracker_domains: Vec<String>,
    #[serde(default)]
    pub upload_rate_limit: u32,
}

#[derive(Debug, Error)]
pub enum SlotConfigError {
    #[error("slot id {0:?} appears more than once")]
    DuplicateId(String),
    #[error("listen_port {0} appears more than once")]
    DuplicatePort(u16),
    #[error("vpn_interface {0:?} appears more than once")]
    DuplicateInterface(String),
    #[error("peer_fingerprint_hex {0:?} appears more than once")]
    DuplicateFingerprint(String),
    #[error("user_agent {0:?} appears more than once")]
    DuplicateUserAgent(String),
    #[error("resume_dir {0:?} appears more than once (after symlink resolution)")]
    DuplicateResumeDir(PathBuf),
    #[error("torrent_dir {0:?} appears more than once (after symlink resolution)")]
    DuplicateTorrentDir(PathBuf),
    #[error("peer_fingerprint_hex must not equal libtorrent default (-LT20C0-)")]
    DefaultFingerprintForbidden,
    #[error("peer_fingerprint_hex {0:?} is not 16 hex chars")]
    BadFingerprintLength(String),
}

impl SlotConfig {
    /// Build a `VpnProfile` from this slot's VPN fields.
    pub fn vpn_profile(&self) -> VpnProfile {
        VpnProfile {
            r#type: self.vpn_type,
            config_path: self.vpn_profile.clone(),
            interface: self.vpn_interface.clone(),
        }
    }

    /// PRD: hex form of `-LT20C0-` is `2d4c5432304330_2d` (16 hex). The
    /// underscore here is illustrative; real check compares lowercased
    /// hex.
    fn is_libtorrent_default_fingerprint(hex: &str) -> bool {
        hex.eq_ignore_ascii_case("2d4c5432304330\x002d")
            // The literal above is wrong-ish — keep also a friendlier
            // ASCII compare.
            || hex.eq_ignore_ascii_case("2d4c54323043302d")
    }

    /// Validate the global uniqueness invariants across all slots.
    /// Should be called at startup (PRD §Multi-Account constraints) and
    /// on SIGHUP for the new config.
    pub fn validate_set(slots: &[SlotConfig]) -> Result<(), SlotConfigError> {
        let mut seen_id   = std::collections::HashSet::new();
        let mut seen_port = std::collections::HashSet::new();
        let mut seen_iface = std::collections::HashSet::new();
        let mut seen_fp   = std::collections::HashSet::new();
        let mut seen_ua   = std::collections::HashSet::new();
        let mut seen_resume = std::collections::HashSet::new();
        let mut seen_torrent = std::collections::HashSet::new();

        for s in slots {
            if !seen_id.insert(s.id.as_str().to_string()) {
                return Err(SlotConfigError::DuplicateId(s.id.as_str().to_string()));
            }
            if !seen_port.insert(s.listen_port) {
                return Err(SlotConfigError::DuplicatePort(s.listen_port));
            }
            if !seen_iface.insert(s.vpn_interface.clone()) {
                return Err(SlotConfigError::DuplicateInterface(s.vpn_interface.clone()));
            }
            if s.peer_fingerprint_hex.len() != 16 {
                return Err(SlotConfigError::BadFingerprintLength(s.peer_fingerprint_hex.clone()));
            }
            if Self::is_libtorrent_default_fingerprint(&s.peer_fingerprint_hex) {
                return Err(SlotConfigError::DefaultFingerprintForbidden);
            }
            if !seen_fp.insert(s.peer_fingerprint_hex.clone()) {
                return Err(SlotConfigError::DuplicateFingerprint(s.peer_fingerprint_hex.clone()));
            }
            if !seen_ua.insert(s.user_agent.clone()) {
                return Err(SlotConfigError::DuplicateUserAgent(s.user_agent.clone()));
            }
            // Resolve symlinks to canonical paths. If the dir doesn't yet
            // exist (first run), fall back to the literal value — startup
            // will create it.
            let r = s.resume_dir.canonicalize().unwrap_or_else(|_| s.resume_dir.clone());
            if !seen_resume.insert(r.clone()) {
                return Err(SlotConfigError::DuplicateResumeDir(r));
            }
            let t = s.torrent_dir.canonicalize().unwrap_or_else(|_| s.torrent_dir.clone());
            if !seen_torrent.insert(t.clone()) {
                return Err(SlotConfigError::DuplicateTorrentDir(t));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Slot — runtime state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SlotStatus {
    /// VPN bring-up succeeded and the engine is constructed.
    Active,
    /// VPN bring-up failed at startup; engine never constructed.
    Failed,
    /// VPN tunnel went down mid-session; all torrents in this slot are
    /// paused awaiting operator intervention (PRD: no auto-restart).
    VpnDown,
}

/// Runtime per-slot state. Owns an `Arc<dyn TorrentEngine>` so the
/// `MultiSlotSource` and HTTP handlers can share it.
#[derive(Debug)]
pub struct Slot {
    pub config: SlotConfig,
    pub engine: Arc<dyn TorrentEngine>,
    pub status: SlotStatus,
    /// Last observed tunnel IP. None if VPN has never come up.
    pub tunnel_ip: Option<std::net::IpAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(id: &str, port: u16, iface: &str, fp: &str, ua: &str) -> SlotConfig {
        SlotConfig {
            id: SlotId::new(id),
            vpn_profile: PathBuf::from(format!("/etc/wg/{id}.conf")),
            vpn_type: VpnType::Wireguard,
            vpn_interface: iface.to_string(),
            listen_port: port,
            peer_fingerprint_hex: fp.to_string(),
            user_agent: ua.to_string(),
            resume_dir: PathBuf::from(format!("/var/lib/seederd/resume/{id}")),
            torrent_dir: PathBuf::from(format!("/var/lib/seederd/torrents/{id}")),
            allowed_tracker_domains: vec![],
            upload_rate_limit: 0,
        }
    }

    #[test]
    fn default_is_special() {
        assert!(SlotId::default_single().is_default());
        assert!(!SlotId::new("acct_a").is_default());
    }

    #[test]
    fn validate_set_accepts_unique_slots() {
        let slots = vec![
            cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "qBittorrent/5.0.3"),
            cfg("b", 6882, "wg1", "9f8e7d6c5b4a3210", "Transmission/4.0.6"),
        ];
        SlotConfig::validate_set(&slots).unwrap();
    }

    #[test]
    fn duplicate_listen_port_rejected() {
        let slots = vec![
            cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a"),
            cfg("b", 6881, "wg1", "9f8e7d6c5b4a3210", "ua-b"),
        ];
        assert!(matches!(
            SlotConfig::validate_set(&slots),
            Err(SlotConfigError::DuplicatePort(6881))
        ));
    }

    #[test]
    fn duplicate_fingerprint_rejected() {
        let same = "a1b2c3d4e5f60718";
        let slots = vec![
            cfg("a", 6881, "wg0", same, "ua-a"),
            cfg("b", 6882, "wg1", same, "ua-b"),
        ];
        assert!(matches!(
            SlotConfig::validate_set(&slots),
            Err(SlotConfigError::DuplicateFingerprint(_))
        ));
    }

    #[test]
    fn libtorrent_default_fingerprint_rejected() {
        let slots = vec![cfg(
            "a",
            6881,
            "wg0",
            "2d4c54323043302d", // hex of "-LT20C0-"
            "ua-a",
        )];
        assert!(matches!(
            SlotConfig::validate_set(&slots),
            Err(SlotConfigError::DefaultFingerprintForbidden)
        ));
    }

    #[test]
    fn fingerprint_length_must_be_16() {
        let slots = vec![cfg("a", 6881, "wg0", "abcd", "ua-a")];
        assert!(matches!(
            SlotConfig::validate_set(&slots),
            Err(SlotConfigError::BadFingerprintLength(_))
        ));
    }
}
