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
    pub fn new(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
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

/// How a profile reaches the network.
///
/// Written out in every profile, never inferred. The daemon used to decide
/// this by counting tables: no `[[slot]]` meant one session on the host's own
/// interfaces with DHT enabled, which is the least private posture it has, and
/// it was what an operator got by writing nothing at all. A posture with these
/// consequences is one the config has to state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileNetwork {
    /// Binds the host's own interfaces. Peers and trackers see the host's
    /// address; nothing is hidden. Appropriate for public trackers and DHT
    /// content, and for nothing that must not be traced to this machine.
    Host {
        /// e.g. `"0.0.0.0:6881,[::]:6881"`.
        listen_interfaces: String,
        /// Off unless written. DHT is a public, global announcement of what
        /// this host holds, so an operator who wants it says so.
        dht: bool,
    },
    /// Binds a VPN tunnel. Every socket in the profile is source-bound to the
    /// tunnel address, and DHT, PEX and LSD are disabled unconditionally —
    /// there is no key here that can turn them on.
    Vpn {
        vpn_type: VpnType,
        /// Path to the WireGuard/OpenVPN profile for the tunnel.
        vpn_config: PathBuf,
        vpn_interface: String,
        /// Static listening port. Required for `port_forward = "static"`;
        /// omitted for `natpmp`, where the gateway assigns one at runtime.
        listen_port: Option<u16>,
        /// How this profile's listening port is chosen (default: static).
        port_forward: PortForwardMode,
        /// NAT-PMP gateway to negotiate against. Defaults to `10.2.0.1`, the
        /// ProtonVPN WireGuard gateway.
        port_forward_gateway: Option<String>,
    },
}

/// Per-profile configuration, mirroring one `[[profile]]` table.
///
/// Uniqueness and cross-field rules are enforced by
/// [`ProfileConfig::validate_set`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileConfig {
    pub id: ProfileId,
    pub network: ProfileNetwork,
    /// Peer identity. Required for a VPN profile, where two profiles sharing
    /// one is precisely the cross-contamination the separation exists to
    /// prevent; optional on the host, where there is one identity anyway.
    pub peer_fingerprint_hex: Option<String>,
    pub user_agent: Option<String>,
    /// Overrides the top-level directory, which is otherwise partitioned by
    /// profile id.
    pub resume_dir: Option<PathBuf>,
    pub torrent_dir: Option<PathBuf>,
    pub allowed_tracker_domains: Vec<String>,
    pub upload_rate_limit: u32,
}

/// Which posture a `[[profile]]` declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NetworkKind {
    Host,
    Vpn,
}

/// The flat shape a `[[profile]]` table actually has on disk.
///
/// `ProfileConfig` holds a `ProfileNetwork` enum, whose variants have
/// different keys; serde cannot express that *and* keep
/// `deny_unknown_fields`, because `flatten` disables it. Since "unknown keys
/// are a fatal startup error" is a property this config is supposed to have —
/// and `[[profile]]` is the table where a silently-ignored typo does the most
/// damage — the flat shape is parsed strictly and then converted.
///
/// The conversion also rejects keys that belong to the *other* posture, which
/// flattening could not have caught at all: a `vpn_interface` on a host
/// profile is not an unknown key, it is a key that will never be read.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    id: ProfileId,
    network: NetworkKind,

    // host
    #[serde(default, skip_serializing_if = "Option::is_none")]
    listen_interfaces: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    dht: bool,

    // vpn
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_type: Option<VpnType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_config: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port_forward: Option<PortForwardMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port_forward_gateway: Option<String>,

    // either
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_fingerprint_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    torrent_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_tracker_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    upload_rate_limit: u32,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl RawProfile {
    /// Reject a key that belongs to the posture this profile is not.
    fn reject(&self, id: &ProfileId, present: bool, key: &str, wanted: &str) -> Result<(), String> {
        if present {
            return Err(format!(
                "profile {:?} declares network = \"{}\" but sets {key}, which only applies to \
                 network = \"{wanted}\"",
                id.as_str(),
                match self.network {
                    NetworkKind::Host => "host",
                    NetworkKind::Vpn => "vpn",
                },
            ));
        }
        Ok(())
    }
}

impl TryFrom<RawProfile> for ProfileConfig {
    type Error = String;

    fn try_from(r: RawProfile) -> Result<Self, Self::Error> {
        let id = r.id.clone();
        let network = match r.network {
            NetworkKind::Host => {
                r.reject(&id, r.vpn_type.is_some(), "vpn_type", "vpn")?;
                r.reject(&id, r.vpn_config.is_some(), "vpn_config", "vpn")?;
                r.reject(&id, r.vpn_interface.is_some(), "vpn_interface", "vpn")?;
                r.reject(&id, r.listen_port.is_some(), "listen_port", "vpn")?;
                r.reject(&id, r.port_forward.is_some(), "port_forward", "vpn")?;
                r.reject(
                    &id,
                    r.port_forward_gateway.is_some(),
                    "port_forward_gateway",
                    "vpn",
                )?;
                ProfileNetwork::Host {
                    listen_interfaces: r.listen_interfaces.clone().ok_or_else(|| {
                        format!(
                            "profile {:?} declares network = \"host\" and must set \
                             listen_interfaces",
                            id.as_str()
                        )
                    })?,
                    dht: r.dht,
                }
            }
            NetworkKind::Vpn => {
                r.reject(
                    &id,
                    r.listen_interfaces.is_some(),
                    "listen_interfaces",
                    "host",
                )?;
                r.reject(&id, r.dht, "dht", "host")?;
                let missing = |key: &str| {
                    format!(
                        "profile {:?} declares network = \"vpn\" and must set {key}",
                        id.as_str()
                    )
                };
                ProfileNetwork::Vpn {
                    vpn_type: r.vpn_type.ok_or_else(|| missing("vpn_type"))?,
                    vpn_config: r.vpn_config.clone().ok_or_else(|| missing("vpn_config"))?,
                    vpn_interface: r
                        .vpn_interface
                        .clone()
                        .ok_or_else(|| missing("vpn_interface"))?,
                    listen_port: r.listen_port,
                    port_forward: r.port_forward.unwrap_or_default(),
                    port_forward_gateway: r.port_forward_gateway.clone(),
                }
            }
        };
        Ok(ProfileConfig {
            id,
            network,
            peer_fingerprint_hex: r.peer_fingerprint_hex,
            user_agent: r.user_agent,
            resume_dir: r.resume_dir,
            torrent_dir: r.torrent_dir,
            allowed_tracker_domains: r.allowed_tracker_domains,
            upload_rate_limit: r.upload_rate_limit,
        })
    }
}

impl From<&ProfileConfig> for RawProfile {
    fn from(c: &ProfileConfig) -> Self {
        let mut raw = RawProfile {
            id: c.id.clone(),
            network: NetworkKind::Host,
            listen_interfaces: None,
            dht: false,
            vpn_type: None,
            vpn_config: None,
            vpn_interface: None,
            listen_port: None,
            port_forward: None,
            port_forward_gateway: None,
            peer_fingerprint_hex: c.peer_fingerprint_hex.clone(),
            user_agent: c.user_agent.clone(),
            resume_dir: c.resume_dir.clone(),
            torrent_dir: c.torrent_dir.clone(),
            allowed_tracker_domains: c.allowed_tracker_domains.clone(),
            upload_rate_limit: c.upload_rate_limit,
        };
        match &c.network {
            ProfileNetwork::Host {
                listen_interfaces,
                dht,
            } => {
                raw.listen_interfaces = Some(listen_interfaces.clone());
                raw.dht = *dht;
            }
            ProfileNetwork::Vpn {
                vpn_type,
                vpn_config,
                vpn_interface,
                listen_port,
                port_forward,
                port_forward_gateway,
            } => {
                raw.network = NetworkKind::Vpn;
                raw.vpn_type = Some(*vpn_type);
                raw.vpn_config = Some(vpn_config.clone());
                raw.vpn_interface = Some(vpn_interface.clone());
                raw.listen_port = *listen_port;
                raw.port_forward = Some(*port_forward);
                raw.port_forward_gateway = port_forward_gateway.clone();
            }
        }
        raw
    }
}

impl<'de> Deserialize<'de> for ProfileConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawProfile::deserialize(d)?;
        ProfileConfig::try_from(raw).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ProfileConfig {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        RawProfile::from(self).serialize(s)
    }
}

impl ProfileConfig {
    /// The NAT-PMP gateway for this profile, defaulting to ProtonVPN's
    /// WireGuard gateway. Only meaningful for a VPN profile in natpmp mode.
    pub const DEFAULT_NATPMP_GATEWAY: &'static str = "10.2.0.1";

    /// Whether this profile's traffic leaves through a tunnel.
    ///
    /// This is what the discovery guards branch on. It replaces branching on
    /// whether the profile happened to be *named* `default`, which a config
    /// could satisfy by accident.
    pub fn is_vpn(&self) -> bool {
        matches!(self.network, ProfileNetwork::Vpn { .. })
    }

    /// Whether DHT may run in this profile's session. Never true for a VPN
    /// profile: BEP 42 derives part of a node id from the external address, so
    /// a tunnelled profile running DHT leaves a correlatable id in other
    /// peers' routing tables.
    pub fn dht_enabled(&self) -> bool {
        match &self.network {
            ProfileNetwork::Host { dht, .. } => *dht,
            ProfileNetwork::Vpn { .. } => false,
        }
    }

    /// The tunnel interface, for a VPN profile.
    pub fn vpn_interface(&self) -> Option<&str> {
        match &self.network {
            ProfileNetwork::Vpn { vpn_interface, .. } => Some(vpn_interface),
            ProfileNetwork::Host { .. } => None,
        }
    }

    /// The VPN type, for a VPN profile.
    pub fn vpn_type(&self) -> Option<VpnType> {
        match &self.network {
            ProfileNetwork::Vpn { vpn_type, .. } => Some(*vpn_type),
            ProfileNetwork::Host { .. } => None,
        }
    }

    /// How this profile chooses its listening port.
    pub fn port_forward(&self) -> PortForwardMode {
        match &self.network {
            ProfileNetwork::Vpn { port_forward, .. } => *port_forward,
            ProfileNetwork::Host { .. } => PortForwardMode::Static,
        }
    }

    pub fn listen_port(&self) -> Option<u16> {
        match &self.network {
            ProfileNetwork::Vpn { listen_port, .. } => *listen_port,
            ProfileNetwork::Host { .. } => None,
        }
    }

    /// The `listen_interfaces` string for a host profile.
    pub fn host_listen_interfaces(&self) -> Option<&str> {
        match &self.network {
            ProfileNetwork::Host {
                listen_interfaces, ..
            } => Some(listen_interfaces),
            ProfileNetwork::Vpn { .. } => None,
        }
    }

    pub fn port_forward_gateway_or_default(&self) -> &str {
        match &self.network {
            ProfileNetwork::Vpn {
                port_forward_gateway,
                ..
            } => port_forward_gateway
                .as_deref()
                .unwrap_or(Self::DEFAULT_NATPMP_GATEWAY),
            ProfileNetwork::Host { .. } => Self::DEFAULT_NATPMP_GATEWAY,
        }
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
        "no [[profile]] tables are configured. torrentd has no implicit profile: every \
         profile states how it reaches the network, because the alternative — defaulting \
         to the host's own interfaces — is the least private posture there is. See \
         deploy/torrentd.sample.toml."
    )]
    NoProfiles,
    #[error("profile {profile:?} is a vpn profile and must set {field}")]
    MissingIdentity {
        profile: String,
        field: &'static str,
    },
    #[error("profile {0:?} has an empty listen_interfaces")]
    EmptyListenInterfaces(String),
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
    /// Build a `VpnTunnel` from this profile's VPN fields, if it has any.
    pub fn vpn_tunnel(&self) -> Option<VpnTunnel> {
        match &self.network {
            ProfileNetwork::Vpn {
                vpn_type,
                vpn_config,
                vpn_interface,
                ..
            } => Some(VpnTunnel {
                r#type: *vpn_type,
                config_path: vpn_config.clone(),
                interface: vpn_interface.clone(),
            }),
            ProfileNetwork::Host { .. } => None,
        }
    }

    /// The hex form of libtorrent's default fingerprint `-LT20C0-` (16 hex
    /// chars). A VPN profile must set a distinct fingerprint so peers cannot
    /// trivially tie it back to the default client identity.
    fn is_libtorrent_default_fingerprint(hex: &str) -> bool {
        hex.eq_ignore_ascii_case("2d4c54323043302d")
    }

    /// Validate the whole configured set.
    ///
    /// Called at startup and on SIGHUP. Most rules here are uniqueness rules,
    /// and they apply to VPN profiles specifically: two accounts on one
    /// tracker are distinguishable only by the things this enforces are
    /// distinct. Host profiles share one identity because they *are* one host,
    /// so requiring them to differ would be theatre.
    pub fn validate_set(profiles: &[ProfileConfig]) -> Result<(), ProfileConfigError> {
        if profiles.is_empty() {
            return Err(ProfileConfigError::NoProfiles);
        }

        let mut seen_id = std::collections::HashSet::new();
        let mut seen_port = std::collections::HashSet::new();
        let mut seen_iface = std::collections::HashSet::new();
        let mut seen_fp = std::collections::HashSet::new();
        let mut seen_ua = std::collections::HashSet::new();
        let mut seen_resume = std::collections::HashSet::new();
        let mut seen_torrent = std::collections::HashSet::new();

        for p in profiles {
            if !seen_id.insert(p.id.as_str().to_string()) {
                return Err(ProfileConfigError::DuplicateId(p.id.as_str().to_string()));
            }

            match &p.network {
                ProfileNetwork::Host {
                    listen_interfaces, ..
                } => {
                    if listen_interfaces.trim().is_empty() {
                        return Err(ProfileConfigError::EmptyListenInterfaces(
                            p.id.as_str().to_string(),
                        ));
                    }
                }
                ProfileNetwork::Vpn {
                    vpn_type,
                    vpn_config,
                    vpn_interface,
                    listen_port,
                    port_forward,
                    ..
                } => {
                    match port_forward {
                        PortForwardMode::Static => {
                            // The port is announced, so two profiles sharing
                            // one are correlatable by a tracker operator even
                            // from different addresses.
                            let port = listen_port.ok_or_else(|| {
                                ProfileConfigError::MissingListenPort(p.id.as_str().to_string())
                            })?;
                            if !seen_port.insert(port) {
                                return Err(ProfileConfigError::DuplicatePort(port));
                            }
                        }
                        PortForwardMode::Natpmp => {
                            // Assigned by the gateway at runtime, and unique by
                            // construction.
                        }
                    }
                    if !seen_iface.insert(vpn_interface.clone()) {
                        return Err(ProfileConfigError::DuplicateInterface(
                            vpn_interface.clone(),
                        ));
                    }
                    // `wg-quick up <path>` names the interface after the file,
                    // and `wg-quick down <iface>` looks the file back up from
                    // the name. A profile whose two fields disagree brings a
                    // tunnel up under one name, waits 30s for an address on
                    // another, fails, and could never be torn down if it
                    // somehow succeeded.
                    if *vpn_type == VpnType::Wireguard {
                        let stem = vpn_config
                            .file_stem()
                            .map(|f| f.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if stem != *vpn_interface {
                            return Err(ProfileConfigError::InterfaceConfigMismatch {
                                profile: p.id.as_str().to_string(),
                                iface: vpn_interface.clone(),
                                vpn_config: vpn_config.display().to_string(),
                            });
                        }
                    }

                    // Identity, required here and only here.
                    let fp = p.peer_fingerprint_hex.as_deref().ok_or_else(|| {
                        ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "peer_fingerprint_hex",
                        }
                    })?;
                    if fp.len() != 16 {
                        return Err(ProfileConfigError::BadFingerprintLength(fp.to_string()));
                    }
                    if Self::is_libtorrent_default_fingerprint(fp) {
                        return Err(ProfileConfigError::DefaultFingerprintForbidden);
                    }
                    if !seen_fp.insert(fp.to_string()) {
                        return Err(ProfileConfigError::DuplicateFingerprint(fp.to_string()));
                    }
                    let ua = p.user_agent.as_deref().ok_or_else(|| {
                        ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "user_agent",
                        }
                    })?;
                    if !seen_ua.insert(ua.to_string()) {
                        return Err(ProfileConfigError::DuplicateUserAgent(ua.to_string()));
                    }
                }
            }

            // Directories, where they are named explicitly. Resolve symlinks;
            // on a first run the directory may not exist yet, so fall back to
            // the literal value and let startup create it.
            if let Some(dir) = &p.resume_dir {
                let r = dir.canonicalize().unwrap_or_else(|_| dir.clone());
                if !seen_resume.insert(r.clone()) {
                    return Err(ProfileConfigError::DuplicateResumeDir(r));
                }
            }
            if let Some(dir) = &p.torrent_dir {
                let t = dir.canonicalize().unwrap_or_else(|_| dir.clone());
                if !seen_torrent.insert(t.clone()) {
                    return Err(ProfileConfigError::DuplicateTorrentDir(t));
                }
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

    /// A VPN profile, which is the shape almost every rule here is about.
    fn cfg(id: &str, port: u16, iface: &str, fp: &str, ua: &str) -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new(id),
            network: ProfileNetwork::Vpn {
                vpn_type: VpnType::Wireguard,
                vpn_config: PathBuf::from(format!("/etc/wg/{iface}.conf")),
                vpn_interface: iface.to_string(),
                listen_port: Some(port),
                port_forward: PortForwardMode::Static,
                port_forward_gateway: None,
            },
            peer_fingerprint_hex: Some(fp.to_string()),
            user_agent: Some(ua.to_string()),
            resume_dir: Some(PathBuf::from(format!("/var/lib/torrentd/resume/{id}"))),
            torrent_dir: Some(PathBuf::from(format!("/var/lib/torrentd/torrents/{id}"))),
            allowed_tracker_domains: vec![],
            upload_rate_limit: 0,
        }
    }

    /// A host profile, which needs none of the identity separation.
    fn host(id: &str, listen: &str, dht: bool) -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new(id),
            network: ProfileNetwork::Host {
                listen_interfaces: listen.to_string(),
                dht,
            },
            peer_fingerprint_hex: None,
            user_agent: None,
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: 0,
        }
    }

    /// Mutate a test profile's VPN network in place.
    fn with_vpn(mut c: ProfileConfig, f: impl FnOnce(&mut ProfileNetwork)) -> ProfileConfig {
        f(&mut c.network);
        c
    }

    #[test]
    fn wireguard_interface_must_match_its_profile_file() {
        let s = with_vpn(
            cfg("acct_a", 6881, "wg-a", "a1b2c3d4e5f60718", "qB/5.0"),
            |n| {
                if let ProfileNetwork::Vpn { vpn_config, .. } = n {
                    *vpn_config = PathBuf::from("/etc/wireguard/something-else.conf");
                }
            },
        );
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::InterfaceConfigMismatch { .. })
        ));
    }

    #[test]
    fn openvpn_profiles_are_not_subject_to_the_wireguard_naming_rule() {
        // openvpn takes --dev explicitly, so its profile file name carries no
        // meaning for the interface.
        let s = with_vpn(
            cfg("acct_a", 6881, "tun0", "a1b2c3d4e5f60718", "qB/5.0"),
            |n| {
                if let ProfileNetwork::Vpn {
                    vpn_type,
                    vpn_config,
                    ..
                } = n
                {
                    *vpn_type = VpnType::Openvpn;
                    *vpn_config = PathBuf::from("/etc/openvpn/account-a.conf");
                }
            },
        );
        assert!(ProfileConfig::validate_set(&[s]).is_ok());
    }

    #[test]
    fn a_config_with_no_profiles_is_refused() {
        // The whole point of the model: there is no implicit profile, so
        // writing nothing gets an explanation rather than the least private
        // posture the daemon has.
        assert!(matches!(
            ProfileConfig::validate_set(&[]),
            Err(ProfileConfigError::NoProfiles)
        ));
    }

    #[test]
    fn a_host_profile_needs_no_identity_separation() {
        // Two host profiles are one host. Requiring distinct fingerprints and
        // user agents of them would be theatre.
        let profiles = vec![
            host("public", "0.0.0.0:6881", true),
            host("public2", "0.0.0.0:6882", false),
        ];
        ProfileConfig::validate_set(&profiles).unwrap();
    }

    #[test]
    fn a_vpn_profile_must_declare_its_identity() {
        let mut p = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        p.user_agent = None;
        assert!(matches!(
            ProfileConfig::validate_set(&[p]),
            Err(ProfileConfigError::MissingIdentity {
                field: "user_agent",
                ..
            })
        ));
    }

    #[test]
    fn dht_is_off_unless_a_host_profile_asks_for_it() {
        assert!(host("p", "0.0.0.0:6881", true).dht_enabled());
        assert!(!host("p", "0.0.0.0:6881", false).dht_enabled());
    }

    #[test]
    fn a_vpn_profile_can_never_enable_dht() {
        // BEP 42 derives part of a node id from the external address, so a
        // tunnelled profile running DHT leaves a correlatable id behind. There
        // is deliberately no key that reaches this.
        let p = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        assert!(p.is_vpn());
        assert!(!p.dht_enabled());
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
        let s = with_vpn(cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a"), |n| {
            if let ProfileNetwork::Vpn { listen_port, .. } = n {
                *listen_port = None; // stays in static mode
            }
        });
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::MissingListenPort(_))
        ));
    }

    #[test]
    fn natpmp_profile_may_omit_listen_port() {
        let s = with_vpn(cfg("a", 0, "wg0", "a1b2c3d4e5f60718", "ua-a"), |n| {
            if let ProfileNetwork::Vpn {
                port_forward,
                listen_port,
                ..
            } = n
            {
                *port_forward = PortForwardMode::Natpmp;
                *listen_port = None;
            }
        });
        ProfileConfig::validate_set(&[s]).unwrap();
    }

    #[test]
    fn natpmp_profiles_skip_port_uniqueness() {
        // Two natpmp profiles: the (ignored) listen_port collision must NOT fail —
        // their ports are gateway-assigned at runtime.
        let natpmp = |n: &mut ProfileNetwork| {
            if let ProfileNetwork::Vpn {
                port_forward,
                listen_port,
                ..
            } = n
            {
                *port_forward = PortForwardMode::Natpmp;
                *listen_port = None;
            }
        };
        let a = with_vpn(cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a"), natpmp);
        let b = with_vpn(cfg("b", 6881, "wg1", "9f8e7d6c5b4a3210", "ua-b"), natpmp);
        ProfileConfig::validate_set(&[a, b]).unwrap();
    }

    #[test]
    fn gateway_defaults_to_proton() {
        let s = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        assert_eq!(s.port_forward_gateway_or_default(), "10.2.0.1");
        let s2 = with_vpn(s, |n| {
            if let ProfileNetwork::Vpn {
                port_forward_gateway,
                ..
            } = n
            {
                *port_forward_gateway = Some("10.9.9.1".to_string());
            }
        });
        assert_eq!(s2.port_forward_gateway_or_default(), "10.9.9.1");
    }
}
