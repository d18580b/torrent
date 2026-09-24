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
//! 5. **PEX and LSD are always disabled on a `vpn` profile.** `disable_pex`
//!    and `disable_lsd` are set unconditionally on every torrent in every
//!    tunnelled profile, including on resume load, and no config key reaches
//!    them. libtorrent does refuse to instantiate the PEX plugin for torrents
//!    carrying the `private` flag — but that relies on the torrent's own
//!    metadata being correct, and this guard is what catches a non-private
//!    torrent added to a tunnelled profile by mistake. A `host` profile keeps
//!    both: it announces from the host's own address, so peer exchange and
//!    local discovery reveal nothing the posture has not already conceded.
//! 6. **DHT is always disabled on a `vpn` profile.** BEP 42 derives part of a
//!    DHT node ID from the external IP, so even with separate IPs a tunnelled
//!    profile running DHT leaves a correlatable node ID in other peers'
//!    routing tables. There is no config key that can turn it on there:
//!    `dht` exists only on `ProfileNetwork::Host`, and it is off unless
//!    written.
//!
//!    Rules 5 and 6 bind to the posture, not to the profile's name. The guard
//!    is composed in one place — `policy::discovery_guards` — for all four add
//!    paths, because it used to be spelled per path against whether the id
//!    happened to be `default`, which a config could satisfy by accident.
//! 7. **SIGHUP cannot change identity-critical fields.** The tunnel
//!    interface, listen port, peer fingerprint and user agent are what a
//!    tracker sees as an account's identity. Changes are detected, warned
//!    about, and ignored; applying them means a restart.
//!
//!    The per-profile `resume_dir` and `torrent_dir` are equally unreloadable
//!    — the stores are opened at startup — but they are not identity: no
//!    announce, handshake or peer message carries where a profile keeps its
//!    files. They get the ordinary non-reloadable warning, so this rule's
//!    warning stays the privacy event an alert rule can watch for, and the
//!    upgrade step in `docs/running.md` that tells an operator to set those
//!    two keys does not fire it.
//! 8. **Listen ports are unique across profiles.** The port is announced, so two
//!    profiles sharing one would be correlatable by a tracker operator even from
//!    different IPs. Enforced for every profile that names its own port — a
//!    `vpn` profile's static `listen_port`, and every port a `host` profile's
//!    `listen_interfaces` binds. Gateway-assigned NAT-PMP ports are unique by
//!    construction and are the one case nothing here checks.
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
/// Enforces the charset rule at the only door untrusted text comes through.
///
/// `[A-Za-z0-9_-]{1,64}`, the same rule
/// [`ProfileConfig::validate_set`] applies — see
/// [`ProfileConfig::is_valid_id`] for why the set is what it is.
///
/// It is checked here as well because two files deserialize into `ProfileId`
/// and only one of them passes through the validator: the config file does,
/// and `profile_assignments.json` does not. An id read from a hand-edited
/// registry reached `dir_for` and was joined onto a path with nothing between
/// it and the filesystem, so the safety of `<resume_dir>/<id>` rested entirely
/// on the startup bail staying correct. Making it a property of the type
/// rather than of having called something means the raw string cannot get that
/// far.
///
/// `ProfileId::new` stays infallible. Making it fallible and routing every
/// construction through it is the tidier end state, but it ripples through
/// every internal call site for no additional safety once this door is closed
/// — the remaining callers build ids from values that already validated.
impl<'de> Deserialize<'de> for ProfileId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if !ProfileConfig::is_valid_id(&s) {
            return Err(serde::de::Error::custom(format!(
                "profile id {s:?} is not usable: {ID_CHARSET_RULE}"
            )));
        }
        Ok(ProfileId::new(s))
    }
}

/// Why an id outside `[A-Za-z0-9_-]{1,64}` cannot be used, in one sentence.
///
/// Shared rather than written twice. Two doors refuse an id — this module's
/// `Deserialize`, and the pre-profiles registry conversion in
/// [`crate::registry`], which has to say the same thing in a message built by
/// hand. Two spellings of one rule is how the two stop agreeing.
pub(crate) const ID_CHARSET_RULE: &str =
    "an id may be 1-64 characters of [A-Za-z0-9_-] only. The id is a path component in three \
     places (<resume_dir>/<id>, <torrent_dir>/<id>, session_state-<id>.dat) and a URL path \
     segment, so anything else either escapes those directories or cannot be addressed.";

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
    /// Per-profile upload cap in bytes/sec, overriding the daemon-wide key.
    ///
    /// `Option`, not a plain `u32`, because `0` means *unlimited* — the
    /// top-level key's own comment says so — and a plain `u32` made it mean
    /// "unset" as well. A profile writing `upload_rate_limit = 0` to say "this
    /// account is uncapped" was silently given the daemon-wide cap at boot and
    /// again on every reload, with nothing logged and nothing in
    /// `diff_profiles` to report it, because the two values compare equal.
    /// Both shipped samples use exactly that line as the illustration of the
    /// override.
    pub upload_rate_limit: Option<u32>,
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
    /// `Option`, not `bool`, so the vpn arm can reject it **on presence**.
    ///
    /// As a `#[serde(default)] bool` it was indistinguishable from absent when
    /// written `dht = false`, so that spelling was silently accepted on a vpn
    /// profile — alone among the wrong-posture keys, every one of which is an
    /// `Option` rejected on presence. It reads to an operator as a setting
    /// that took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dht: Option<bool>,

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload_rate_limit: Option<u32>,
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
                    dht: r.dht.unwrap_or(false),
                }
            }
            NetworkKind::Vpn => {
                r.reject(
                    &id,
                    r.listen_interfaces.is_some(),
                    "listen_interfaces",
                    "host",
                )?;
                r.reject(&id, r.dht.is_some(), "dht", "host")?;
                let missing = |key: &str| {
                    format!(
                        "profile {:?} declares network = \"vpn\" and must set {key}",
                        id.as_str()
                    )
                };
                // `listen_port` under NAT-PMP is a value nothing reads. The
                // gateway assigns the port at runtime, nothing binds the
                // configured one, Safety Rule 8 does not enter it into
                // `seen_port` — and `/api/profiles` then reports it back
                // under a field documented as "`null` for natpmp profiles".
                // Accepting and ignoring it is the shape every other
                // wrong-posture rule in this function exists to refuse.
                if r.port_forward == Some(PortForwardMode::Natpmp) && r.listen_port.is_some() {
                    return Err(format!(
                        "profile {:?} sets port_forward = \"natpmp\" and listen_port. The \
                         gateway assigns the port at runtime and renews its lease, so nothing \
                         binds the configured one; read the negotiated port from \
                         GET /api/profiles/{} instead.",
                        id.as_str(),
                        id.as_str(),
                    ));
                }
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

impl ProfileConfig {
    /// The flat TOML shape this profile deserialized from.
    ///
    /// Private, and reachable only through `Serialize` below. It shipped as a
    /// public `From<&ProfileConfig> for RawProfile` with no caller at all:
    /// `/api/profiles` builds its own wire structs, and nothing serializes a
    /// `Config`. A public conversion direction nobody exercises is how a
    /// serializer and a deserializer stop agreeing without anything saying so.
    fn to_raw(&self) -> RawProfile {
        let c = self;
        let mut raw = RawProfile {
            id: c.id.clone(),
            network: NetworkKind::Host,
            listen_interfaces: None,
            dht: None,
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
                raw.dht = Some(*dht);
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
        self.to_raw().serialize(s)
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
    #[error(
        "profile id {0:?} is not usable: an id may be 1-64 characters of \
         [A-Za-z0-9_-] only. The id is a path component in three places \
         (<resume_dir>/<id>, <torrent_dir>/<id>, session_state-<id>.dat) and a \
         URL path segment, so anything else either escapes those directories or \
         cannot be addressed."
    )]
    BadId(String),
    #[error("listen_port {0} appears more than once")]
    DuplicatePort(u16),
    #[error("profile {0:?} uses port_forward = \"static\" but has no listen_port")]
    MissingListenPort(String),
    #[error("vpn_interface {0:?} appears more than once")]
    DuplicateInterface(String),
    /// Two profiles announce one peer-id prefix.
    ///
    /// `key` is the key the *operator wrote*, which is not always the one this
    /// field is called. A profile that declares nothing takes the top-level
    /// `peer_fingerprint`, and naming `peer_fingerprint_hex` at it sent the
    /// operator hunting a key that appears nowhere in their file.
    #[error("{key} {value:?} appears more than once")]
    DuplicateFingerprint { key: &'static str, value: String },
    #[error("{key} {value:?} appears more than once")]
    DuplicateUserAgent { key: &'static str, value: String },
    #[error("resume_dir {0:?} appears more than once (after symlink resolution)")]
    DuplicateResumeDir(PathBuf),
    #[error("torrent_dir {0:?} appears more than once (after symlink resolution)")]
    DuplicateTorrentDir(PathBuf),
    /// The value equals libtorrent's own default peer-id prefix.
    ///
    /// `key` is the key the *operator wrote*, for the reason
    /// [`ProfileConfigError::DuplicateFingerprint`] carries one: the same value
    /// reaches a session from the per-profile `peer_fingerprint_hex` and from
    /// the top-level `peer_fingerprint` it inherits, and naming the wrong one
    /// sends the operator hunting a key that appears nowhere in their file.
    #[error("{key} must not equal libtorrent default (-LT20C0-)")]
    DefaultFingerprintForbidden { key: &'static str },
    /// The value is not sixteen hex characters. `key` as above.
    #[error("{key} {value:?} is not 16 hex chars")]
    BadFingerprintLength { key: &'static str, value: String },
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
    /// Distinct from [`ProfileConfigError::EmptyListenInterfaces`]: the
    /// operator wrote something, and none of it names a port.
    #[error(
        "profile {profile:?}: listen_interfaces {listen_interfaces:?} names no port that can be \
         read. The format is a comma-separated list of <ip>:<port>, with an optional device name \
         in place of the address and optional s/l flags — \"0.0.0.0:6881,[::]:6881\", \
         \"eth0:6881s\". A profile that binds no port accepts no incoming connections and is \
         exempt from the listen-port uniqueness rule, while the daemon reports itself healthy."
    )]
    UnreadableListenInterfaces {
        profile: String,
        listen_interfaces: String,
    },
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
    /// Whether `fp` is libtorrent's own default peer-id prefix, in either of
    /// the two spellings this configuration accepts.
    ///
    /// `-LT20C0-` is the eight bytes libtorrent puts at the front of a peer id
    /// nobody configured. The two keys that can supply those bytes spell them
    /// differently: `peer_fingerprint_hex` states them as sixteen hex
    /// characters, and the top-level `peer_fingerprint` states them as
    /// themselves — `deploy/torrentd.sample.toml` documented that key as
    /// `peer_fingerprint = "-LT20C0-"` before this change and as
    /// `"-XX1234-"` after it, and nothing between the config file and
    /// libtorrent decodes either spelling.
    ///
    /// So a test that knew only the hex spelling read straight past the raw
    /// one — which is both the spelling that actually reaches the wire from
    /// that key and the one an operator copies out of libtorrent's own
    /// documentation. Both are refused, and neither is refused *because of*
    /// its length: that is a separate rule belonging to the key that declares
    /// an encoding in its name.
    pub fn is_libtorrent_default_fingerprint(fp: &str) -> bool {
        fp.eq_ignore_ascii_case("2d4c54323043302d") || fp == "-LT20C0-"
    }

    /// The distinct ports a libtorrent `listen_interfaces` string binds.
    ///
    /// The format is a comma-separated list of `<ip>:<port>` with an optional
    /// device suffix and optional `s`/`l` flags — `"0.0.0.0:6881,[::]:6881"`,
    /// `"eth0:6881s"`. The address may itself contain colons (`[::]`), so the
    /// port is read from the last one. A set, not a list: one profile naming
    /// the same port on v4 and v6 is the ordinary case and is not a collision.
    ///
    /// An entry whose port cannot be read is skipped rather than refused.
    /// libtorrent owns this grammar; refusing a string this function merely
    /// failed to parse would reject configurations the session accepts.
    fn listen_ports(listen_interfaces: &str) -> std::collections::BTreeSet<u16> {
        listen_interfaces
            .split(',')
            .filter_map(|entry| {
                let (_, tail) = entry.trim().rsplit_once(':')?;
                let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
                digits.parse().ok()
            })
            .collect()
    }

    /// `[A-Za-z0-9_-]{1,64}`.
    ///
    /// Deliberately narrower than what a filesystem accepts. The set excludes
    /// `.`, so `.` and `..` are unrepresentable without a special case, and
    /// excludes `/` and `\`, so an id is always exactly one path component. It
    /// is also URL-safe unescaped, which is what `/api/profiles/<id>` needs.
    /// The 64-character bound keeps `session_state-<id>.dat` inside a
    /// filename-length limit on every platform the daemon targets.
    pub(crate) fn is_valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }

    /// Validate the whole configured set.
    ///
    /// Called at startup and on SIGHUP. Most rules here are uniqueness rules:
    /// two accounts on one tracker are distinguishable only by the things this
    /// enforces are distinct.
    ///
    /// Requiredness and uniqueness are separate questions, and they have
    /// different answers. A host profile may *omit* `peer_fingerprint_hex` and
    /// `user_agent` — it is the host, and two host profiles are one host, so
    /// requiring them to differ would be theatre. But a value a host profile
    /// does set must still be distinct from every other profile's, because a
    /// fingerprint shared with a tunnelled profile puts one peer-id prefix on
    /// the wire from both the tunnel address and the host's real address,
    /// which is exactly the cross-account correlation these rules exist to
    /// prevent. So requiredness is checked per posture, below, and the length
    /// and the libtorrent-default ban run for any profile that sets the field,
    /// whatever its posture.
    ///
    /// Two rules are deliberately **not** here, because they are not decidable
    /// from `&[ProfileConfig]` alone:
    ///
    /// - identity uniqueness, which has to compare each profile's *effective*
    ///   `peer_fingerprint_hex` / `user_agent` — its own value or the
    ///   top-level default it inherits when it sets none; and
    /// - store-directory uniqueness, which has to compare each profile's
    ///   *effective* resume and `.torrent` directory — its own override or the
    ///   `<base>/<id>` [`crate::resume_store::FsResumeStore::dir_for`] derives
    ///   from the top-level root.
    ///
    /// Both need the top-level `Config`, so both live in `Config::validate`.
    /// Checking only the explicit spellings here is what let a host profile
    /// inherit a vpn profile's identity, and an explicit `resume_dir` equal
    /// another profile's derived one, while `--check-config` printed
    /// `config OK`.
    pub fn validate_set(profiles: &[ProfileConfig]) -> Result<(), ProfileConfigError> {
        if profiles.is_empty() {
            return Err(ProfileConfigError::NoProfiles);
        }

        let mut seen_id = std::collections::HashSet::new();
        let mut seen_port = std::collections::HashSet::new();
        let mut seen_iface = std::collections::HashSet::new();

        for p in profiles {
            // The id is not just a label. It is a path component in
            // `<resume_dir>/<id>`, `<torrent_dir>/<id>` and
            // `session_state-<id>.dat`, and a segment of `/api/profiles/<id>`.
            // `PathBuf::join` with an absolute id replaces the base outright,
            // so `id = "/etc"` would write resume data to `/etc`, and
            // `id = "../.."` escapes upward. Constrain the id itself rather
            // than sanitising at three filesystem call sites and a URL, each
            // one a place to forget.
            if !Self::is_valid_id(p.id.as_str()) {
                return Err(ProfileConfigError::BadId(p.id.as_str().to_string()));
            }
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
                    // Non-empty, and yields nothing. `listen_ports` skips an
                    // entry it cannot read because libtorrent owns the
                    // grammar — but a string where *every* entry is
                    // unreadable is not a grammar this validator merely
                    // failed to keep up with, it is a profile that contributes
                    // nothing to `seen_port` and is therefore exempt from
                    // Safety Rule 8 entirely. With two live profiles
                    // `fatal_listen_failure` is false, so the session binds
                    // nothing while `--check-config` prints `config OK` and
                    // `/healthz` answers 200 — exactly what the rule below
                    // exists to prevent. Per-entry skipping stays for a list
                    // with at least one readable entry.
                    let ports = Self::listen_ports(listen_interfaces);
                    if ports.is_empty() {
                        return Err(ProfileConfigError::UnreadableListenInterfaces {
                            profile: p.id.as_str().to_string(),
                            listen_interfaces: listen_interfaces.clone(),
                        });
                    }
                    // Safety Rule 8. Its enforcement clause names static VPN
                    // profiles, but its rationale — an announced port
                    // correlating two profiles — applies verbatim to two host
                    // profiles, and a host profile is now something an
                    // operator configures, more than once. Unenforced,
                    // `--check-config` prints `config OK`, one session binds,
                    // the other's `listen_failed` is warned and swallowed, and
                    // `/healthz` reports 200 with `profiles_fenced: 0` while a
                    // profile accepts no incoming connections at all.
                    //
                    // It refuses two host profiles that bind one port on
                    // *different* NICs (`192.168.1.5:6881` and
                    // `10.0.0.5:6881`) deliberately, even though the OS would
                    // allow it. Keying the set on the `(address, port)` pair
                    // instead does not decide the question it appears to: the
                    // address in `listen_interfaces` need not be a literal —
                    // an interface name is legal and `0.0.0.0` overlaps every
                    // literal — and the rule's own reasoning is that two host
                    // profiles are one host, which the split-NIC case does not
                    // contradict. Refusing a configuration that would have
                    // worked is one line to reverse; accepting one that
                    // collides is a listen failure reported healthy.
                    for port in ports {
                        if !seen_port.insert(port) {
                            return Err(ProfileConfigError::DuplicatePort(port));
                        }
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

                    // Identity is *required* here and only here. A tunnelled
                    // profile with no fingerprint of its own announces under
                    // the default one, which ties it to every other default
                    // client the tracker sees.
                    if p.peer_fingerprint_hex.is_none() {
                        return Err(ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "peer_fingerprint_hex",
                        });
                    }
                    if p.user_agent.is_none() {
                        return Err(ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "user_agent",
                        });
                    }
                }
            }

            // Identity, for any profile that set one.
            //
            // Outside the match on purpose. `startup.rs` applies
            // `peer_fingerprint_hex` to every session with no posture guard,
            // so a host profile that copies a VPN profile's table and edits
            // only `id`, `network` and `listen_interfaces` — which is how the
            // second profile in a config usually gets written — puts the same
            // 8-byte peer-id prefix on the wire from the tunnel and from the
            // host's real address. Keeping these checks inside the `Vpn` arm
            // made that configuration validate clean.
            //
            // Shape only. *Uniqueness* is not decidable here: a profile that
            // sets neither key inherits the top-level `peer_fingerprint` /
            // `user_agent`, which this function cannot see, so a set of
            // `ProfileConfig`s that looks distinct here can still put one
            // peer-id prefix on the wire from two postures. `Config::validate`
            // resolves each profile's effective identity and owns the
            // uniqueness rule.
            if let Some(fp) = p.peer_fingerprint_hex.as_deref() {
                if fp.len() != 16 {
                    return Err(ProfileConfigError::BadFingerprintLength {
                        key: "peer_fingerprint_hex",
                        value: fp.to_string(),
                    });
                }
                if Self::is_libtorrent_default_fingerprint(fp) {
                    return Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key: "peer_fingerprint_hex",
                    });
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
            upload_rate_limit: None,
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
            upload_rate_limit: None,
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
    fn a_profile_survives_a_serialize_deserialize_round_trip() {
        // `Config` derives `Serialize`, which is what keeps this direction
        // compiled; nothing in the daemon calls it. Untested, the serializer
        // and the deserializer can drift apart silently — a field added to one
        // and not the other costs nothing until something finally does
        // serialize a config.
        for original in [
            cfg("acct_a", 6881, "wg0", "a1b2c3d4e5f60718", "qB/5.0"),
            host("public", "0.0.0.0:6881,[::]:6881", true),
            host("public2", "0.0.0.0:6882", false),
        ] {
            let wire = serde_json::to_string(&original).expect("serialize");
            let back: ProfileConfig = serde_json::from_str(&wire).expect("deserialize");
            assert_eq!(back, original, "round trip lost something:\n{wire}");
        }
    }

    #[test]
    fn two_host_profiles_may_not_share_a_listen_port() {
        // Safety Rule 8, for the posture this model introduces. Unenforced,
        // `--check-config` prints `config OK` and one of the two sessions
        // accepts no incoming connections while `/healthz` answers 200.
        let profiles = vec![
            host("public", "0.0.0.0:6881", false),
            host("public2", "0.0.0.0:6881", false),
        ];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::DuplicatePort(6881))
        ));
    }

    #[test]
    fn a_host_profile_may_not_take_a_vpn_profiles_static_port() {
        // The port is what a tracker sees; which posture announced it makes no
        // difference to the correlation.
        let profiles = vec![
            cfg("acct_a", 6881, "wg0", "a1b2c3d4e5f60718", "qB/5.0"),
            host("public", "0.0.0.0:6881", false),
        ];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::DuplicatePort(6881))
        ));
    }

    #[test]
    fn one_host_profile_may_bind_the_same_port_on_v4_and_v6() {
        // The ordinary case, and not a collision: the rule is about two
        // profiles, not two addresses of one.
        let profiles = vec![
            host("public", "0.0.0.0:6881,[::]:6881", false),
            host("public2", "0.0.0.0:6882,[::]:6882", false),
        ];
        ProfileConfig::validate_set(&profiles).unwrap();
    }

    #[test]
    fn listen_ports_reads_every_shape_libtorrent_accepts() {
        let ports = |s| {
            ProfileConfig::listen_ports(s)
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(ports("0.0.0.0:6881"), vec![6881]);
        assert_eq!(ports("0.0.0.0:6881,[::]:6881"), vec![6881]);
        assert_eq!(ports("0.0.0.0:6881, [::]:6882"), vec![6881, 6882]);
        // Device name instead of an address, and the ssl/local flag suffixes.
        assert_eq!(ports("eth0:6881s"), vec![6881]);
        assert_eq!(ports("eth0:6881l,[::]:6882s"), vec![6881, 6882]);
        // An unreadable entry *beside a readable one* is skipped, not guessed
        // at: libtorrent owns this grammar and a parse failure here must not
        // refuse a config the session would accept.
        assert_eq!(ports("nonsense,0.0.0.0:6881"), vec![6881]);

        // A string where every entry is unreadable yields nothing — and the
        // validator refuses it. This assertion used to read
        // `assert!(ports("nonsense").is_empty())` as though the empty result
        // were the correct outcome, which locked the hole in: such a profile
        // contributes nothing to `seen_port`, so it is exempt from Safety
        // Rule 8, and it binds nothing while `--check-config` prints
        // `config OK`.
        assert!(ports("nonsense").is_empty());
        let mut p = host("public", "nonsense", false);
        assert!(
            matches!(
                ProfileConfig::validate_set(std::slice::from_ref(&p)),
                Err(ProfileConfigError::UnreadableListenInterfaces { .. })
            ),
            "a host profile that binds no port must be refused, not accepted",
        );

        // And distinctly from the empty case, which is a different mistake
        // with a different remedy.
        p.network = ProfileNetwork::Host {
            listen_interfaces: "   ".to_string(),
            dht: false,
        };
        assert!(matches!(
            ProfileConfig::validate_set(&[p]),
            Err(ProfileConfigError::EmptyListenInterfaces(_))
        ));
    }

    #[test]
    fn a_profile_id_that_escapes_its_directory_is_refused() {
        // The id lands in `<resume_dir>/<id>`, `<torrent_dir>/<id>` and
        // `session_state-<id>.dat`. `PathBuf::join` with an absolute path
        // replaces the base outright, so an unconstrained id writes resume
        // data wherever it says.
        for bad in ["/etc", "../..", "a/b", "has space", "dot.dot", "", "a\\b"] {
            let mut p = host("placeholder", "0.0.0.0:6881", false);
            p.id = ProfileId::new(bad);
            assert!(
                matches!(
                    ProfileConfig::validate_set(&[p]),
                    Err(ProfileConfigError::BadId(_))
                ),
                "id {bad:?} was accepted",
            );
        }
    }

    #[test]
    fn a_profile_id_longer_than_64_characters_is_refused() {
        let mut p = host("placeholder", "0.0.0.0:6881", false);
        p.id = ProfileId::new("a".repeat(65));
        assert!(matches!(
            ProfileConfig::validate_set(&[p]),
            Err(ProfileConfigError::BadId(_))
        ));
    }

    #[test]
    fn ordinary_profile_ids_are_accepted() {
        // Including `default`: #12 banned that name because it collided with
        // the implicit single-session slot, and this model deletes that
        // concept, so the collision the ban protected against is gone. It is
        // also the one id that lets a migrated registry resolve without
        // hand-editing.
        for good in ["default", "acct_a", "acct-b", "Public2", &"a".repeat(64)] {
            let mut p = host("placeholder", "0.0.0.0:6881", false);
            p.id = ProfileId::new(good);
            assert!(
                ProfileConfig::validate_set(&[p]).is_ok(),
                "id {good:?} was refused",
            );
        }
    }

    // Cross-posture identity uniqueness — a host profile wearing a vpn
    // profile's fingerprint or user agent, spelled explicitly or inherited
    // from the top-level default — is `Config::validate`'s rule now, because
    // the inherited spelling is not decidable from `&[ProfileConfig]` alone.
    // The tests live beside it, in `crates/torrentd/src/config.rs`.

    #[test]
    fn a_host_profiles_fingerprint_is_length_checked_like_any_other() {
        // A fingerprint that is not 8 bytes is not a fingerprint, and the
        // posture that set it makes no difference to that.
        let mut public = host("public", "0.0.0.0:6881", false);
        public.peer_fingerprint_hex = Some("abc".to_string());
        assert!(matches!(
            ProfileConfig::validate_set(&[public]),
            Err(ProfileConfigError::BadFingerprintLength {
                key: "peer_fingerprint_hex",
                ..
            })
        ));
    }

    #[test]
    fn a_host_profile_may_not_announce_the_libtorrent_default_fingerprint() {
        // Setting the default explicitly is worse than leaving it unset: it
        // reads as a deliberate identity while being the one every unmodified
        // client already wears.
        let mut public = host("public", "0.0.0.0:6881", false);
        public.peer_fingerprint_hex = Some("2d4c54323043302d".to_string());
        assert!(matches!(
            ProfileConfig::validate_set(&[public]),
            Err(ProfileConfigError::DefaultFingerprintForbidden {
                key: "peer_fingerprint_hex"
            })
        ));
    }

    #[test]
    fn a_host_profile_that_sets_no_identity_is_still_accepted() {
        // Uniqueness applies to a value that is set; requiredness stays
        // VPN-only. Two host profiles are one host, and a config that names
        // neither field has to keep validating.
        let profiles = vec![
            cfg("acct_a", 6881, "wg0", "a1b2c3d4e5f60718", "qB/5.0"),
            host("public", "0.0.0.0:6882", false),
            host("public2", "0.0.0.0:6883", false),
        ];
        ProfileConfig::validate_set(&profiles).unwrap();
    }

    #[test]
    fn a_vpn_profile_missing_only_its_fingerprint_is_refused() {
        // The `peer_fingerprint_hex` arm of `MissingIdentity`; only the
        // `user_agent` arm was reached before.
        let mut p = cfg("a", 6881, "wg0", "a1b2c3d4e5f60718", "ua-a");
        p.peer_fingerprint_hex = None;
        assert!(matches!(
            ProfileConfig::validate_set(&[p]),
            Err(ProfileConfigError::MissingIdentity {
                field: "peer_fingerprint_hex",
                ..
            })
        ));
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
            Err(ProfileConfigError::DefaultFingerprintForbidden {
                key: "peer_fingerprint_hex"
            })
        ));
    }

    #[test]
    fn fingerprint_length_must_be_16() {
        let profiles = vec![cfg("a", 6881, "wg0", "abcd", "ua-a")];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::BadFingerprintLength {
                key: "peer_fingerprint_hex",
                ..
            })
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
