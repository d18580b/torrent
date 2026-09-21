//! Profile identification + per-profile data.
//!
//! `ProfileId` is the cheap-to-clone key used in StateMap, registry, and
//! every `(profile_id, alert)` pair. `ProfileConfig` is the operator-supplied
//! shape parsed from TOML; validation cross-checks live here so SIGHUP
//! reload and startup share one path. `Profile` bundles the config with the
//! runtime engine so the daemon's HTTP handlers can answer
//! `/profiles/{profile_id}` queries.
//!
//! # Why a profile is a whole separate session
//!
//! libtorrent identifies a torrent solely by info-hash. One `lt::session`
//! cannot hold two entries with the same info-hash however much their tracker
//! URLs differ — a duplicate add either errors or hands back the existing
//! handle with the second torrent's tracker URL ignored. Two accounts on one
//! private tracker will routinely share content, which means identical
//! info-hashes with different passkeys in the announce URLs. Multiplexing
//! accounts inside one session is therefore not a design choice that was
//! rejected; it is impossible. The isolation boundary is a session per profile.
//!
//! # Safety rules
//!
//! Private trackers ban for cross-contamination between accounts, and the ban
//! is permanent. These are hard constraints with no configuration option to
//! disable them. Each has a test; each is here rather than in a design
//! document because the next person to touch this file is the one who needs
//! to read them.
//!
//! 1. **No bare-IP fallback.** If a profile's tunnel does not come up, that
//!    profile's session is never constructed. The daemon does not fall back to
//!    the host's public IP. The profile is recorded failed and reported; the
//!    others proceed.
//! 2. **No cross-profile announce.** `outgoing_interfaces` is pinned to the
//!    tunnel IP, so libtorrent binds outgoing connections to it at the socket
//!    level. If the tunnel drops, subsequent attempts fail at `bind()` rather
//!    than falling out over the bare interface.
//! 3. **Global info-hash uniqueness.** An add is refused with 409 if the
//!    info-hash is loaded in *any* profile, not just the target. The same torrent
//!    seeding under two accounts is visible to the tracker as one info-hash
//!    announcing from two IPs it can associate with one operator.
//! 4. **The assignment registry is consulted before every load.** At API add,
//!    at the startup scan, and at resume load. The session layer never
//!    receives a torrent whose profile has not been verified.
//! 5. **PEX is always disabled.** `disable_pex` is set unconditionally on
//!    every torrent in every profile, including on resume load. libtorrent does
//!    refuse to instantiate the PEX plugin for torrents carrying the `private`
//!    flag — but that relies on the torrent's own metadata being correct, and
//!    this guard is what catches a non-private torrent added to a profile by
//!    mistake.
//! 6. **DHT is always disabled** on profile sessions. BEP 42 derives part of a
//!    DHT node ID from the external IP, so even with separate IPs a profile
//!    running DHT leaves a correlatable node ID in other peers' routing
//!    tables. There is no config key that can turn it on.
//! 7. **SIGHUP cannot change identity-critical fields.** The tunnel
//!    interface, listen port, peer fingerprint, user agent and per-profile
//!    directories are what a tracker sees as an account's identity. Changes
//!    are detected, warned about, and ignored; applying them means a restart.
//! 8. **Listen ports are unique across profiles.** The port is announced, so two
//!    profiles sharing one would be correlatable by a tracker operator even from
//!    different IPs. Enforced for static profiles; gateway-assigned NAT-PMP ports
//!    are unique by construction.
//!
//! `allowed_tracker_domains` is *not* in this list. It is a misconfiguration
//! guard against loading one profile's `.torrent` into another, checked at add
//! time — not an egress control, and not a security boundary.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use thiserror::Error;

use crate::port_forward::PortForwardMode;
use crate::vpn::VpnTunnel;
use crate::vpn::VpnType;

// ---------------------------------------------------------------------------
// ProfileId
// ---------------------------------------------------------------------------

/// Stable, cheap-to-clone profile identifier.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ProfileId(Arc<str>);

impl ProfileId {
    pub const DEFAULT: &'static str = "default";

    pub fn new(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }
    pub fn default_single() -> Self {
        Self(Arc::from(Self::DEFAULT))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_default(&self) -> bool {
        &*self.0 == Self::DEFAULT
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Debug for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProfileId({})", self.0)
    }
}
impl From<&str> for ProfileId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}
impl From<String> for ProfileId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl Serialize for ProfileId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for ProfileId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(ProfileId::new(s))
    }
}

// ---------------------------------------------------------------------------
// ProfileConfig — operator-supplied (TOML)
// ---------------------------------------------------------------------------

/// Per-profile configuration, mirroring the `[[profile]]` table in the daemon's
/// config file. Validation
/// (uniqueness rules etc.) is handled by `ProfileConfig::validate_set`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub id: ProfileId,
    pub vpn_config: PathBuf,
    pub vpn_type: VpnType,
    pub vpn_interface: String,
    /// Static listening port. Required for `port_forward = "static"`; unused
    /// (and typically omitted) for `port_forward = "natpmp"`, where the port
    /// is negotiated with the gateway at runtime.
    #[serde(default)]
    pub listen_port: Option<u16>,
    pub peer_fingerprint_hex: String,
    pub user_agent: String,
    pub resume_dir: PathBuf,
    pub torrent_dir: PathBuf,
    #[serde(default)]
    pub allowed_tracker_domains: Vec<String>,
    #[serde(default)]
    pub upload_rate_limit: u32,
    /// How this profile's listening port is chosen (default: static).
    #[serde(default)]
    pub port_forward: PortForwardMode,
    /// NAT-PMP gateway to negotiate the forwarded port against (natpmp mode).
    /// Defaults to `10.2.0.1` (the ProtonVPN WireGuard gateway) at use.
    #[serde(default)]
    pub port_forward_gateway: Option<String>,
}

impl ProfileConfig {
    /// The NAT-PMP gateway for this profile, defaulting to ProtonVPN's WireGuard
    /// gateway. Only meaningful when `port_forward == Natpmp`.
    pub const DEFAULT_NATPMP_GATEWAY: &'static str = "10.2.0.1";

    pub fn port_forward_gateway_or_default(&self) -> &str {
        self.port_forward_gateway
            .as_deref()
            .unwrap_or(Self::DEFAULT_NATPMP_GATEWAY)
    }
}

/// Format `ip:port` the way libtorrent's `listen_interfaces` expects.
///
/// `format!("{ip}:{port}")` is correct for IPv4 and produces an unparseable
/// string for IPv6, where the address has to be bracketed. Nothing can return
/// a v6 tunnel address today — the interface lookup is IPv4-only — so this is
/// a latent bug rather than a live one, and it is the kind that surfaces as a
/// profile silently failing to bind on the day that changes.
pub fn bind_endpoint(ip: std::net::IpAddr, port: u16) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

#[derive(Debug, Error)]
pub enum ProfileConfigError {
    #[error("profile id {0:?} appears more than once")]
    DuplicateId(String),
    #[error("listen_port {0} appears more than once")]
    DuplicatePort(u16),
    #[error("profile {0:?} uses port_forward = \"static\" but has no listen_port")]
    MissingListenPort(String),
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
    #[error(
        "profile id {0:?} is reserved for the single-session profile and cannot name a configured profile"
    )]
    ReservedId(String),
    #[error(
        "profile {profile:?}: vpn_interface {iface:?} must equal the file stem of vpn_config \
         ({vpn_config:?}); wg-quick derives the interface name from the file name, so these \
         cannot differ"
    )]
    InterfaceConfigMismatch {
        profile: String,
        iface: String,
        vpn_config: String,
    },
}

impl ProfileConfig {
    /// Build a `VpnTunnel` from this profile's VPN fields.
    pub fn vpn_config(&self) -> VpnTunnel {
        VpnTunnel {
            r#type: self.vpn_type,
            config_path: self.vpn_config.clone(),
            interface: self.vpn_interface.clone(),
        }
    }

    /// The hex form of libtorrent's default fingerprint `-LT20C0-` (16 hex
    /// chars). Profiles must set a distinct fingerprint so peers can't trivially
    /// tie them back to the default client identity.
    fn is_libtorrent_default_fingerprint(hex: &str) -> bool {
        hex.eq_ignore_ascii_case("2d4c54323043302d")
    }

    /// Validate the global uniqueness invariants across all profiles.
    /// Should be called at startup and
    /// on SIGHUP for the new config.
    pub fn validate_set(profiles: &[ProfileConfig]) -> Result<(), ProfileConfigError> {
        let mut seen_id = std::collections::HashSet::new();
        let mut seen_port = std::collections::HashSet::new();
        let mut seen_iface = std::collections::HashSet::new();
        let mut seen_fp = std::collections::HashSet::new();
        let mut seen_ua = std::collections::HashSet::new();
        let mut seen_resume = std::collections::HashSet::new();
        let mut seen_torrent = std::collections::HashSet::new();

        for s in profiles {
            // `default` is the id the single-session profile carries, and
            // `ProfileId::is_default` is what every per-torrent privacy guard
            // branches on. A configured profile allowed to take that name would
            // be a private, VPN-bound profile that silently seeds with PEX, DHT
            // and LSD left on — Safety Rules 5 and 6 defeated by a string.
            if s.id.is_default() {
                return Err(ProfileConfigError::ReservedId(s.id.as_str().to_string()));
            }
            if !seen_id.insert(s.id.as_str().to_string()) {
                return Err(ProfileConfigError::DuplicateId(s.id.as_str().to_string()));
            }
            match s.port_forward {
                PortForwardMode::Static => {
                    // Static profiles must pin a unique listen_port.
                    let port = s.listen_port.ok_or_else(|| {
                        ProfileConfigError::MissingListenPort(s.id.as_str().to_string())
                    })?;
                    if !seen_port.insert(port) {
                        return Err(ProfileConfigError::DuplicatePort(port));
                    }
                }
                PortForwardMode::Natpmp => {
                    // The port is negotiated with the gateway at runtime and is
                    // provider-assigned-unique; no static uniqueness to enforce.
                }
            }
            if !seen_iface.insert(s.vpn_interface.clone()) {
                return Err(ProfileConfigError::DuplicateInterface(
                    s.vpn_interface.clone(),
                ));
            }
            // `wg-quick up <path>` names the interface after the file, and
            // `wg-quick down <iface>` looks the file back up from the name.
            // A profile whose two fields disagree therefore brings a tunnel up
            // under one name, waits 30s for an address on another, fails, and
            // — if it ever did come up — could never be torn down. Refuse the
            // config instead of discovering it at the timeout.
            if s.vpn_type == VpnType::Wireguard {
                let stem = s
                    .vpn_config
                    .file_stem()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if stem != s.vpn_interface {
                    return Err(ProfileConfigError::InterfaceConfigMismatch {
                        profile: s.id.as_str().to_string(),
                        iface: s.vpn_interface.clone(),
                        vpn_config: s.vpn_config.display().to_string(),
                    });
                }
            }
            if s.peer_fingerprint_hex.len() != 16 {
                return Err(ProfileConfigError::BadFingerprintLength(
                    s.peer_fingerprint_hex.clone(),
                ));
            }
            if Self::is_libtorrent_default_fingerprint(&s.peer_fingerprint_hex) {
                return Err(ProfileConfigError::DefaultFingerprintForbidden);
            }
            if !seen_fp.insert(s.peer_fingerprint_hex.clone()) {
                return Err(ProfileConfigError::DuplicateFingerprint(
                    s.peer_fingerprint_hex.clone(),
                ));
            }
            if !seen_ua.insert(s.user_agent.clone()) {
                return Err(ProfileConfigError::DuplicateUserAgent(s.user_agent.clone()));
            }
            // Resolve symlinks to canonical paths. If the dir doesn't yet
            // exist (first run), fall back to the literal value — startup
            // will create it.
            let r = s
                .resume_dir
                .canonicalize()
                .unwrap_or_else(|_| s.resume_dir.clone());
            if !seen_resume.insert(r.clone()) {
                return Err(ProfileConfigError::DuplicateResumeDir(r));
            }
            let t = s
                .torrent_dir
                .canonicalize()
                .unwrap_or_else(|_| s.torrent_dir.clone());
            if !seen_torrent.insert(t.clone()) {
                return Err(ProfileConfigError::DuplicateTorrentDir(t));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Profile — runtime state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProfileStatus {
    /// VPN bring-up succeeded and the engine is constructed.
    Active,
    /// VPN bring-up failed at startup; engine never constructed.
    Failed,
    /// VPN tunnel went down mid-session; all torrents in this profile are
    /// paused awaiting operator intervention.
    VpnDown,
}

impl ProfileStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProfileStatus::Active => "active",
            ProfileStatus::Failed => "failed",
            ProfileStatus::VpnDown => "vpn_down",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn cfg(id: &str, port: u16, iface: &str, fp: &str, ua: &str) -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new(id),
            vpn_config: PathBuf::from(format!("/etc/wg/{iface}.conf")),
            vpn_type: VpnType::Wireguard,
            vpn_interface: iface.to_string(),
            listen_port: Some(port),
            peer_fingerprint_hex: fp.to_string(),
            user_agent: ua.to_string(),
            resume_dir: PathBuf::from(format!("/var/lib/torrentd/resume/{id}")),
            torrent_dir: PathBuf::from(format!("/var/lib/torrentd/torrents/{id}")),
            allowed_tracker_domains: vec![],
            upload_rate_limit: 0,
            port_forward: PortForwardMode::Static,
            port_forward_gateway: None,
        }
    }

    #[test]
    fn wireguard_interface_must_match_its_profile_file() {
        let mut s = cfg("acct_a", 6881, "wg-a", "a1b2c3d4e5f60718", "qB/5.0");
        s.vpn_config = PathBuf::from("/etc/wireguard/something-else.conf");
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::InterfaceConfigMismatch { .. })
        ));
    }

    #[test]
    fn openvpn_profiles_are_not_subject_to_the_wireguard_naming_rule() {
        // openvpn takes --dev explicitly, so its profile file name carries no
        // meaning for the interface.
        let mut s = cfg("acct_a", 6881, "tun0", "a1b2c3d4e5f60718", "qB/5.0");
        s.vpn_type = VpnType::Openvpn;
        s.vpn_config = PathBuf::from("/etc/openvpn/account-a.conf");
        assert!(ProfileConfig::validate_set(&[s]).is_ok());
    }

    #[test]
    fn reserved_default_id_is_refused() {
        // A configured profile named `default` reads as the single-session profile
        // to `is_default`, which every per-torrent privacy guard branches on.
        let s = cfg("default", 6881, "wg0", "a1b2c3d4e5f60718", "qB/5.0");
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::ReservedId(id)) if id == "default"
        ));
    }

    #[test]
    fn default_is_special() {
        assert!(ProfileId::default_single().is_default());
        assert!(!ProfileId::new("acct_a").is_default());
    }

    #[test]
    fn validate_set_accepts_unique_profiles() {
        let profiles = vec![
            cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "qBittorrent/5.0.3"),
            cfg("b", 6882, "wg1", "9f8e7d6c5b4a3210", "Transmission/4.0.6"),
        ];
        ProfileConfig::validate_set(&profiles).unwrap();
    }

    #[test]
    fn duplicate_listen_port_rejected() {
        let profiles = vec![
            cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a"),
            cfg("b", 6881, "wg1", "9f8e7d6c5b4a3210", "ua-b"),
        ];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::DuplicatePort(6881))
        ));
    }

    #[test]
    fn duplicate_fingerprint_rejected() {
        let same = "a1b2c3d4e5f60718";
        let profiles = vec![
            cfg("a", 6881, "wg0", same, "ua-a"),
            cfg("b", 6882, "wg1", same, "ua-b"),
        ];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::DuplicateFingerprint(_))
        ));
    }

    #[test]
    fn libtorrent_default_fingerprint_rejected() {
        let profiles = vec![cfg(
            "a",
            6881,
            "wg0",
            "2d4c54323043302d", // hex of "-LT20C0-"
            "ua-a",
        )];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::DefaultFingerprintForbidden)
        ));
    }

    #[test]
    fn fingerprint_length_must_be_16() {
        let profiles = vec![cfg("a", 6881, "wg0", "abcd", "ua-a")];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::BadFingerprintLength(_))
        ));
    }

    #[test]
    fn static_profile_without_listen_port_rejected() {
        let mut s = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        s.listen_port = None; // stays in static mode
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::MissingListenPort(_))
        ));
    }

    #[test]
    fn natpmp_profile_may_omit_listen_port() {
        let mut s = cfg("a", 0, "wg0", "a1b2c3d4e5f60718", "ua-a");
        s.port_forward = PortForwardMode::Natpmp;
        s.listen_port = None;
        ProfileConfig::validate_set(&[s]).unwrap();
    }

    #[test]
    fn natpmp_profiles_skip_port_uniqueness() {
        // Two natpmp profiles: the (ignored) listen_port collision must NOT fail —
        // their ports are gateway-assigned at runtime.
        let mut a = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        let mut b = cfg("b", 6881, "wg1", "9f8e7d6c5b4a3210", "ua-b");
        a.port_forward = PortForwardMode::Natpmp;
        b.port_forward = PortForwardMode::Natpmp;
        a.listen_port = None;
        b.listen_port = None;
        ProfileConfig::validate_set(&[a, b]).unwrap();
    }

    #[test]
    fn gateway_defaults_to_proton() {
        let s = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        assert_eq!(s.port_forward_gateway_or_default(), "10.2.0.1");
        let mut s2 = s;
        s2.port_forward_gateway = Some("10.9.9.1".to_string());
        assert_eq!(s2.port_forward_gateway_or_default(), "10.9.9.1");
    }
}
