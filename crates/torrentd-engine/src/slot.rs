//! Slot identification + per-slot data.
//!
//! `SlotId` is the cheap-to-clone key used in StateMap, registry, and
//! every `(slot_id, alert)` pair. `SlotConfig` is the operator-supplied
//! shape parsed from TOML; validation cross-checks live here so SIGHUP
//! reload and startup share one path. `Slot` bundles the config with the
//! runtime engine so the daemon's HTTP handlers can answer
//! `/slots/{slot_id}` queries.
//!
//! # Why a slot is a whole separate session
//!
//! libtorrent identifies a torrent solely by info-hash. One `lt::session`
//! cannot hold two entries with the same info-hash however much their tracker
//! URLs differ — a duplicate add either errors or hands back the existing
//! handle with the second torrent's tracker URL ignored. Two accounts on one
//! private tracker will routinely share content, which means identical
//! info-hashes with different passkeys in the announce URLs. Multiplexing
//! accounts inside one session is therefore not a design choice that was
//! rejected; it is impossible. The isolation boundary is a session per slot.
//!
//! # Safety rules
//!
//! Private trackers ban for cross-contamination between accounts, and the ban
//! is permanent. These are hard constraints with no configuration option to
//! disable them. Each has a test; each is here rather than in a design
//! document because the next person to touch this file is the one who needs
//! to read them.
//!
//! 1. **No bare-IP fallback.** If a slot's tunnel does not come up, that
//!    slot's session is never constructed. The daemon does not fall back to
//!    the host's public IP. The slot is recorded failed and reported; the
//!    others proceed.
//! 2. **No cross-slot announce.** `outgoing_interfaces` is pinned to the
//!    tunnel IP, so libtorrent binds outgoing connections to it at the socket
//!    level. If the tunnel drops, subsequent attempts fail at `bind()` rather
//!    than falling out over the bare interface.
//! 3. **Global info-hash uniqueness.** An add is refused with 409 if the
//!    info-hash is loaded in *any* slot, not just the target. The same torrent
//!    seeding under two accounts is visible to the tracker as one info-hash
//!    announcing from two IPs it can associate with one operator.
//! 4. **The assignment registry is consulted before every load.** At API add,
//!    at the startup scan, and at resume load. The session layer never
//!    receives a torrent whose slot has not been verified.
//! 5. **PEX is always disabled.** `disable_pex` is set unconditionally on
//!    every torrent in every slot, including on resume load. libtorrent does
//!    refuse to instantiate the PEX plugin for torrents carrying the `private`
//!    flag — but that relies on the torrent's own metadata being correct, and
//!    this guard is what catches a non-private torrent added to a slot by
//!    mistake.
//! 6. **DHT is always disabled** on slot sessions. BEP 42 derives part of a
//!    DHT node ID from the external IP, so even with separate IPs a slot
//!    running DHT leaves a correlatable node ID in other peers' routing
//!    tables. There is no config key that can turn it on.
//! 7. **SIGHUP cannot change identity-critical fields.** The tunnel
//!    interface, listen port, peer fingerprint, user agent and per-slot
//!    directories are what a tracker sees as an account's identity. Changes
//!    are detected, warned about, and ignored; applying them means a restart.
//! 8. **Listen ports are unique across slots.** The port is announced, so two
//!    slots sharing one would be correlatable by a tracker operator even from
//!    different IPs. Enforced for static slots; gateway-assigned NAT-PMP ports
//!    are unique by construction.
//!
//! `allowed_tracker_domains` is *not* in this list. It is a misconfiguration
//! guard against loading one slot's `.torrent` into another, checked at add
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
use crate::vpn::VpnProfile;
use crate::vpn::VpnType;

// ---------------------------------------------------------------------------
// SlotId
// ---------------------------------------------------------------------------

/// Stable, cheap-to-clone slot identifier.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SlotId(Arc<str>);

impl SlotId {
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

impl fmt::Display for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Debug for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotId({})", self.0)
    }
}
impl From<&str> for SlotId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}
impl From<String> for SlotId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

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
/// config file. Validation
/// (uniqueness rules etc.) is handled by `SlotConfig::validate_set`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotConfig {
    pub id: SlotId,
    pub vpn_profile: PathBuf,
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
    /// This slot's own upload cap, in bytes/sec.
    ///
    /// Absent means "inherit the top-level `upload_rate_limit`"; `Some(0)`
    /// means *explicitly unlimited*, which is what `0` means for the
    /// identically named top-level key and everywhere else in this
    /// configuration. A plain `u32` could express only one of those two, and
    /// reading `0` as "inherit" — as this key briefly did — left no way to
    /// state that one slot is uncapped under a global cap while the key name
    /// meant two opposite things one table apart.
    ///
    /// Applied at boot. A change to it is **not** reloadable, but it is
    /// reported on SIGHUP (`Config::diff`), and a top-level reload is
    /// withheld from any slot that sets it.
    #[serde(default)]
    pub upload_rate_limit: Option<u32>,
    /// How this slot's listening port is chosen (default: static).
    #[serde(default)]
    pub port_forward: PortForwardMode,
    /// NAT-PMP gateway to negotiate the forwarded port against (natpmp mode).
    /// Defaults to `10.2.0.1` (the ProtonVPN WireGuard gateway) at use.
    #[serde(default)]
    pub port_forward_gateway: Option<String>,
}

impl SlotConfig {
    /// The NAT-PMP gateway for this slot, defaulting to ProtonVPN's WireGuard
    /// gateway. Only meaningful when `port_forward == Natpmp`.
    pub const DEFAULT_NATPMP_GATEWAY: &'static str = "10.2.0.1";

    /// The largest `upload_rate_limit` a slot may state, in bytes/sec.
    ///
    /// Not a policy about bandwidth — a slot may legally exceed the top-level
    /// `upload_rate_limit`, which is a default rather than a cap — but the
    /// point past which the number stops meaning what it says. Settings reach
    /// libtorrent's `settings_pack` through a `static_cast<int>`, so a value
    /// above `i32::MAX` arrives as a *negative* rate limit: the slot is
    /// configured for 3 GB/s and seeds at whatever libtorrent makes of a
    /// negative cap. Refused at validation, where the operator can still read
    /// what they typed.
    pub const MAX_UPLOAD_RATE_LIMIT: u32 = i32::MAX as u32;

    /// The only directory a WireGuard `vpn_profile` may live in.
    ///
    /// `wg-quick`'s own default, and the only one it will resolve a bare
    /// interface name against at teardown. torrentd never sets
    /// `WG_CONFIG_DIR`, so this is not configurable here either.
    pub const WG_CONFIG_DIR: &'static str = "/etc/wireguard";

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
/// slot silently failing to bind on the day that changes.
pub fn bind_endpoint(ip: std::net::IpAddr, port: u16) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

#[derive(Debug, Error)]
pub enum SlotConfigError {
    #[error("slot id {0:?} appears more than once")]
    DuplicateId(String),
    #[error("listen_port {0} appears more than once")]
    DuplicatePort(u16),
    #[error("slot {0:?} uses port_forward = \"static\" but has no listen_port")]
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
        "slot id {0:?} is reserved for the single-session slot and cannot name a configured slot"
    )]
    ReservedId(String),
    #[error(
        "slot {slot:?}: a wireguard vpn_profile must be {dir}/{iface}.conf, not {profile:?}. \
         `wg-quick up <path>` names the interface after the file, and `wg-quick down <iface>` \
         resolves that bare name only against {dir} (or $WG_CONFIG_DIR, which torrentd does \
         not set) — so a profile under any other name, or in any other directory, brings up a \
         tunnel that can never be torn down"
    )]
    InterfaceProfileMismatch {
        slot: String,
        iface: String,
        profile: String,
        dir: &'static str,
    },
    #[error(
        "slot {slot:?}: upload_rate_limit = {value} is out of range (0..={max}). A slot may \
         exceed the top-level upload_rate_limit, but the value reaches libtorrent as a C int, \
         so anything above {max} would be applied as a negative rate limit"
    )]
    UploadRateLimitOutOfRange {
        slot: String,
        value: u32,
        max: u32,
    },
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

    /// The hex form of libtorrent's default fingerprint `-LT20C0-` (16 hex
    /// chars). Slots must set a distinct fingerprint so peers can't trivially
    /// tie them back to the default client identity.
    fn is_libtorrent_default_fingerprint(hex: &str) -> bool {
        hex.eq_ignore_ascii_case("2d4c54323043302d")
    }

    /// Validate the global uniqueness invariants across all slots.
    /// Should be called at startup and
    /// on SIGHUP for the new config.
    pub fn validate_set(slots: &[SlotConfig]) -> Result<(), SlotConfigError> {
        let mut seen_id = std::collections::HashSet::new();
        let mut seen_port = std::collections::HashSet::new();
        let mut seen_iface = std::collections::HashSet::new();
        let mut seen_fp = std::collections::HashSet::new();
        let mut seen_ua = std::collections::HashSet::new();
        let mut seen_resume = std::collections::HashSet::new();
        let mut seen_torrent = std::collections::HashSet::new();

        for s in slots {
            // `default` is the id the single-session slot carries, and
            // `SlotId::is_default` is what every per-torrent privacy guard
            // branches on. A configured slot allowed to take that name would
            // be a private, VPN-bound slot that silently seeds with PEX, DHT
            // and LSD left on — Safety Rules 5 and 6 defeated by a string.
            if s.id.is_default() {
                return Err(SlotConfigError::ReservedId(s.id.as_str().to_string()));
            }
            if !seen_id.insert(s.id.as_str().to_string()) {
                return Err(SlotConfigError::DuplicateId(s.id.as_str().to_string()));
            }
            match s.port_forward {
                PortForwardMode::Static => {
                    // Static slots must pin a unique listen_port.
                    let port = s.listen_port.ok_or_else(|| {
                        SlotConfigError::MissingListenPort(s.id.as_str().to_string())
                    })?;
                    if !seen_port.insert(port) {
                        return Err(SlotConfigError::DuplicatePort(port));
                    }
                }
                PortForwardMode::Natpmp => {
                    // The port is negotiated with the gateway at runtime and is
                    // provider-assigned-unique; no static uniqueness to enforce.
                }
            }
            if !seen_iface.insert(s.vpn_interface.clone()) {
                return Err(SlotConfigError::DuplicateInterface(s.vpn_interface.clone()));
            }
            // `wg-quick up <path>` names the interface after the file, and
            // `wg-quick down <iface>` looks the file back up from the name —
            // resolving a bare name *only* against `WG_CONFIG_DIR`, default
            // `/etc/wireguard`. A slot whose two fields disagree therefore
            // brings a tunnel up under one name, waits 30s for an address on
            // another, fails, and — if it ever did come up — could never be
            // torn down. So does a slot whose profile lives anywhere else,
            // even with a matching stem: `wg-quick down` dies looking for the
            // file before it ever reaches `del_if`, and that surviving tunnel
            // is the headline defect this validation exists to make
            // unreachable. `bring_down` is handed only the interface name
            // (`VpnManager::bring_down(&self, iface: &str)`), so the
            // directory has to be pinned here rather than threaded through.
            // Refuse the config instead of discovering it at the timeout.
            if s.vpn_type == VpnType::Wireguard {
                let stem = s
                    .vpn_profile
                    .file_stem()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let dir = s.vpn_profile.parent();
                if stem != s.vpn_interface || dir != Some(std::path::Path::new(Self::WG_CONFIG_DIR))
                {
                    return Err(SlotConfigError::InterfaceProfileMismatch {
                        slot: s.id.as_str().to_string(),
                        iface: s.vpn_interface.clone(),
                        profile: s.vpn_profile.display().to_string(),
                        dir: Self::WG_CONFIG_DIR,
                    });
                }
            }
            // A slot's own limit is range-checked the way the top-level key
            // of the same name is, and is *not* bounded by it: clamping a
            // slot to the global default would remove the main reason to
            // give one its own limit. The bound that matters is the one the
            // value has to survive on its way to libtorrent — see
            // `MAX_UPLOAD_RATE_LIMIT`.
            if let Some(v) = s.upload_rate_limit {
                if v > Self::MAX_UPLOAD_RATE_LIMIT {
                    return Err(SlotConfigError::UploadRateLimitOutOfRange {
                        slot: s.id.as_str().to_string(),
                        value: v,
                        max: Self::MAX_UPLOAD_RATE_LIMIT,
                    });
                }
            }
            if s.peer_fingerprint_hex.len() != 16 {
                return Err(SlotConfigError::BadFingerprintLength(
                    s.peer_fingerprint_hex.clone(),
                ));
            }
            if Self::is_libtorrent_default_fingerprint(&s.peer_fingerprint_hex) {
                return Err(SlotConfigError::DefaultFingerprintForbidden);
            }
            if !seen_fp.insert(s.peer_fingerprint_hex.clone()) {
                return Err(SlotConfigError::DuplicateFingerprint(
                    s.peer_fingerprint_hex.clone(),
                ));
            }
            if !seen_ua.insert(s.user_agent.clone()) {
                return Err(SlotConfigError::DuplicateUserAgent(s.user_agent.clone()));
            }
            // Resolve symlinks to canonical paths. If the dir doesn't yet
            // exist (first run), fall back to the literal value — startup
            // will create it.
            let r = s
                .resume_dir
                .canonicalize()
                .unwrap_or_else(|_| s.resume_dir.clone());
            if !seen_resume.insert(r.clone()) {
                return Err(SlotConfigError::DuplicateResumeDir(r));
            }
            let t = s
                .torrent_dir
                .canonicalize()
                .unwrap_or_else(|_| s.torrent_dir.clone());
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
    /// paused awaiting operator intervention.
    VpnDown,
}

impl SlotStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SlotStatus::Active => "active",
            SlotStatus::Failed => "failed",
            SlotStatus::VpnDown => "vpn_down",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn cfg(id: &str, port: u16, iface: &str, fp: &str, ua: &str) -> SlotConfig {
        SlotConfig {
            id: SlotId::new(id),
            vpn_profile: PathBuf::from(format!("{}/{iface}.conf", SlotConfig::WG_CONFIG_DIR)),
            vpn_type: VpnType::Wireguard,
            vpn_interface: iface.to_string(),
            listen_port: Some(port),
            peer_fingerprint_hex: fp.to_string(),
            user_agent: ua.to_string(),
            resume_dir: PathBuf::from(format!("/var/lib/torrentd/resume/{id}")),
            torrent_dir: PathBuf::from(format!("/var/lib/torrentd/torrents/{id}")),
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
            port_forward: PortForwardMode::Static,
            port_forward_gateway: None,
        }
    }

    #[test]
    fn a_slot_upload_rate_limit_libtorrent_cannot_hold_is_refused() {
        // The value is handed to `settings_pack` through a
        // `static_cast<int>`, so `u32::MAX` arrives as -1 and the slot the
        // operator configured for 4 GB/s seeds under a negative cap. The
        // sibling top-level key is range-checked; this one was not checked
        // at all.
        let mut s = cfg("acct_a", 6881, "wg-a", "a1b2c3d4e5f60718", "qB/5.0");
        s.upload_rate_limit = Some(u32::MAX);
        assert!(matches!(
            SlotConfig::validate_set(&[s]),
            Err(SlotConfigError::UploadRateLimitOutOfRange { .. })
        ));
    }

    #[test]
    fn a_slot_may_exceed_the_top_level_upload_rate_limit() {
        // The top-level key is a default, not a ceiling: giving one account
        // more bandwidth than the rest is the main reason to set a per-slot
        // limit, so the check bounds the representable range and nothing
        // else. `0` -- explicitly unlimited -- is in range too.
        for v in [0, 1, SlotConfig::MAX_UPLOAD_RATE_LIMIT] {
            let mut s = cfg("acct_a", 6881, "wg-a", "a1b2c3d4e5f60718", "qB/5.0");
            s.upload_rate_limit = Some(v);
            assert!(
                SlotConfig::validate_set(&[s]).is_ok(),
                "upload_rate_limit = {v} is a legal slot limit",
            );
        }
    }

    #[test]
    fn wireguard_interface_must_match_its_profile_file() {
        let mut s = cfg("acct_a", 6881, "wg-a", "a1b2c3d4e5f60718", "qB/5.0");
        s.vpn_profile = PathBuf::from("/etc/wireguard/something-else.conf");
        assert!(matches!(
            SlotConfig::validate_set(&[s]),
            Err(SlotConfigError::InterfaceProfileMismatch { .. })
        ));
    }

    #[test]
    fn a_wireguard_profile_outside_etc_wireguard_is_refused() {
        // The stem matches here; only the directory does not. `wg-quick up`
        // takes the full path and brings the tunnel up regardless, but
        // `wg-quick down wg-a` resolves the bare name against /etc/wireguard,
        // finds nothing, and dies before `del_if` — so the tunnel survives
        // graceful shutdown and every restart, which is the very defect the
        // rest of this change exists to fix.
        let mut s = cfg("acct_a", 6881, "wg-a", "a1b2c3d4e5f60718", "qB/5.0");
        s.vpn_profile = PathBuf::from("/etc/torrentd/wg-a.conf");
        assert!(matches!(
            SlotConfig::validate_set(&[s]),
            Err(SlotConfigError::InterfaceProfileMismatch { .. })
        ));
    }

    #[test]
    fn a_wireguard_profile_with_no_parent_directory_is_refused() {
        // `file_stem()` alone accepts a bare relative name; `wg-quick down`
        // still has only /etc/wireguard to look in.
        let mut s = cfg("acct_a", 6881, "wg-a", "a1b2c3d4e5f60718", "qB/5.0");
        s.vpn_profile = PathBuf::from("wg-a.conf");
        assert!(matches!(
            SlotConfig::validate_set(&[s]),
            Err(SlotConfigError::InterfaceProfileMismatch { .. })
        ));
    }

    #[test]
    fn openvpn_slots_are_not_subject_to_the_wireguard_naming_rule() {
        // openvpn takes --dev explicitly, so its profile file name carries no
        // meaning for the interface.
        let mut s = cfg("acct_a", 6881, "tun0", "a1b2c3d4e5f60718", "qB/5.0");
        s.vpn_type = VpnType::Openvpn;
        s.vpn_profile = PathBuf::from("/etc/openvpn/account-a.conf");
        assert!(SlotConfig::validate_set(&[s]).is_ok());
    }

    #[test]
    fn reserved_default_id_is_refused() {
        // A configured slot named `default` reads as the single-session slot
        // to `is_default`, which every per-torrent privacy guard branches on.
        let s = cfg("default", 6881, "wg0", "a1b2c3d4e5f60718", "qB/5.0");
        assert!(matches!(
            SlotConfig::validate_set(&[s]),
            Err(SlotConfigError::ReservedId(id)) if id == "default"
        ));
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

    #[test]
    fn static_slot_without_listen_port_rejected() {
        let mut s = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        s.listen_port = None; // stays in static mode
        assert!(matches!(
            SlotConfig::validate_set(&[s]),
            Err(SlotConfigError::MissingListenPort(_))
        ));
    }

    #[test]
    fn natpmp_slot_may_omit_listen_port() {
        let mut s = cfg("a", 0, "wg0", "a1b2c3d4e5f60718", "ua-a");
        s.port_forward = PortForwardMode::Natpmp;
        s.listen_port = None;
        SlotConfig::validate_set(&[s]).unwrap();
    }

    #[test]
    fn natpmp_slots_skip_port_uniqueness() {
        // Two natpmp slots: the (ignored) listen_port collision must NOT fail —
        // their ports are gateway-assigned at runtime.
        let mut a = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        let mut b = cfg("b", 6881, "wg1", "9f8e7d6c5b4a3210", "ua-b");
        a.port_forward = PortForwardMode::Natpmp;
        b.port_forward = PortForwardMode::Natpmp;
        a.listen_port = None;
        b.listen_port = None;
        SlotConfig::validate_set(&[a, b]).unwrap();
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
