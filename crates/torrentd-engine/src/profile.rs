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
//!    tunnel device, so libtorrent binds outgoing peer connections to it at
//!    the socket level (`SO_BINDTODEVICE`). If the tunnel drops, subsequent
//!    attempts fail at `bind()` rather than falling out over the bare
//!    interface, and a lost routing rule cannot route them there either.
//!    Everything else — the listen sockets and what answers on them — is
//!    bound to the tunnel address, and routed by the tunnel's source rule,
//!    which the health monitor checks every poll.
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
//!    `listen_interfaces` binds. Gateway-assigned NAT-PMP ports are not
//!    unique by construction — two gateways assign independently — so they
//!    are checked where they are assigned: a profile whose startup
//!    negotiation lands on a port another profile holds is disabled, and a
//!    renewal that moves onto one is not bound (`port_forward::renew_and_rebind`).
//!
//! `allowed_tracker_domains` is *not* in this list, but it is required on
//! every `vpn` profile. It is the account-isolation guard: a profile that
//! sets it takes only a torrent whose every tracker is on it, on every add
//! path (`policy::check_trackers`), so one account's torrent and its passkey
//! are never announced from another account's session. It is not an egress
//! control. Beside it, two load-time rules: a host profile may not listen on
//! the unspecified address while a `vpn` profile exists, since libtorrent
//! expands it to the tunnels' addresses too; and no profile may wear
//! libtorrent's own `-LT` peer-id code.

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
    ///
    /// The eight-character peer-id prefix itself (`"-XX1234-"`), in the same
    /// raw encoding as the top-level `peer_fingerprint` it overrides: both
    /// reach `libtorrent_safe::Settings::peer_fingerprint` verbatim.
    pub peer_fingerprint: Option<String>,
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
    peer_fingerprint: Option<String>,
    /// The key `peer_fingerprint` replaced, parsed only so that it can be
    /// refused by name.
    ///
    /// It documented its value as sixteen hex characters, and nothing decoded
    /// them: the string reached libtorrent as sixteen ASCII characters, not
    /// the eight bytes it spelled. Left to `deny_unknown_fields` it would be
    /// refused as an unknown field with no word of what replaced it; accepted
    /// under either meaning it would change what a tracker sees without the
    /// operator changing anything.
    #[serde(default, skip_serializing)]
    peer_fingerprint_hex: Option<serde::de::IgnoredAny>,
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
        if r.peer_fingerprint_hex.is_some() {
            return Err(format!(
                "profile {:?} sets peer_fingerprint_hex, which is no longer read. Write the \
                 eight-character peer-id prefix itself as peer_fingerprint (for example \
                 peer_fingerprint = \"-XX1234-\"), the same form the top-level key takes. \
                 The old key's sixteen hex characters were passed to libtorrent undecoded, so \
                 the prefix a tracker saw was never the eight bytes they spelled",
                id.as_str(),
            ));
        }
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
                // `seen_port` — and `/v1/profiles` then reports it back
                // under a field documented as "`null` for natpmp profiles".
                // Accepting and ignoring it is the shape every other
                // wrong-posture rule in this function exists to refuse.
                if r.port_forward == Some(PortForwardMode::Natpmp) && r.listen_port.is_some() {
                    return Err(format!(
                        "profile {:?} sets port_forward = \"natpmp\" and listen_port. The \
                         gateway assigns the port at runtime and renews its lease, so nothing \
                         binds the configured one; read the negotiated port from \
                         GET /v1/profiles/{} instead.",
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
            peer_fingerprint: r.peer_fingerprint,
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
    /// `/v1/profiles` builds its own wire structs, and nothing serializes a
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
            peer_fingerprint: c.peer_fingerprint.clone(),
            peer_fingerprint_hex: None,
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

    /// The largest `upload_rate_limit` a profile may state, in bytes/sec.
    ///
    /// Not a policy about bandwidth — a profile may legally exceed the
    /// top-level `upload_rate_limit`, which is a default rather than a cap —
    /// but the point past which the number stops meaning what it says.
    /// Settings reach libtorrent's `settings_pack` through a
    /// `static_cast<int>`, so a value above `i32::MAX` arrives as a *negative*
    /// rate limit: the profile is configured for 3 GB/s and seeds at whatever
    /// libtorrent makes of a negative cap. Refused at validation, where the
    /// operator can still read what they typed.
    pub const MAX_UPLOAD_RATE_LIMIT: u32 = i32::MAX as u32;

    /// The only directory a WireGuard `vpn_config` may live in.
    ///
    /// `wg-quick`'s own default, and the only one it will resolve a bare
    /// interface name against at teardown. torrentd never sets
    /// `WG_CONFIG_DIR`, so this is not configurable here either.
    pub const WG_CONFIG_DIR: &'static str = "/etc/wireguard";

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

    /// Every port this profile's session is configured to listen on: each
    /// port a host profile's `listen_interfaces` names, or a vpn profile's
    /// static `listen_port`. Empty for a NAT-PMP profile, whose port the
    /// gateway assigns at runtime.
    pub fn configured_listen_ports(&self) -> std::collections::BTreeSet<u16> {
        match &self.network {
            ProfileNetwork::Host {
                listen_interfaces, ..
            } => Self::listen_ports(listen_interfaces),
            ProfileNetwork::Vpn { listen_port, .. } => listen_port.iter().copied().collect(),
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
    #[error(
        "profile {profile:?}: vpn_interface {iface:?} is not a usable interface name: a name \
         may be 1-15 characters of [A-Za-z0-9_=+.-] only, and not \".\" or \"..\". The kernel \
         refuses a longer device name, and the network kill switch writes this name into an \
         nftables ruleset that cannot carry any other character"
    )]
    BadInterface { profile: String, iface: String },
    /// Two profiles announce one peer-id prefix.
    ///
    /// `key` is the key the *operator wrote*: the profile's own
    /// `peer_fingerprint`, or the top-level one a profile that declares
    /// nothing inherits. The two share a name, so the inherited case says
    /// "top-level" rather than sending the operator to a `[[profile]]` table
    /// that does not contain it.
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
    /// reaches a session from a profile's own `peer_fingerprint` and from the
    /// top-level one it inherits.
    #[error(
        "{key} {value:?} uses libtorrent's own client code (\"-LT\"), the prefix every \
         libtorrent session that configures nothing announces — {default} in the libtorrent \
         this daemon is built on. Choose the peer-id prefix of the client this profile presents \
         as, such as \"-qB5030-\" with user_agent \"qBittorrent/5.0.3\""
    )]
    DefaultFingerprintForbidden {
        key: &'static str,
        value: String,
        default: &'static str,
    },
    /// The value is not a peer-id prefix. `key` as above.
    #[error(
        "{key} {value:?} is not a peer-id prefix: it must be exactly 8 printable ASCII \
         characters, such as \"-XX1234-\". The value is handed to libtorrent verbatim as the \
         first 8 bytes of the peer id"
    )]
    BadFingerprint { key: &'static str, value: String },
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
    /// A3: a tunnelled profile is an account, and the allow-list is what
    /// keeps another account's torrent — and its passkey — out of it.
    #[error(
        "profile {0:?} is a vpn profile and must set allowed_tracker_domains: the domains of \
         the trackers this account belongs to, such as [\"tracker.example.com\"]. Every \
         torrent the profile takes must announce only to those, which is what stops one \
         account's torrent, and its passkey, from being announced from another"
    )]
    MissingTrackerDomains(String),
    #[error(
        "profile {profile:?}: allowed_tracker_domains entry {domain:?} is not a domain: an \
         entry must be non-empty and contain no ',' or whitespace"
    )]
    BadTrackerDomain { profile: String, domain: String },
    /// D12: an unspecified listen address beside a tunnel.
    #[error(
        "profile {profile:?}: listen_interfaces {listen_interfaces:?} binds the unspecified \
         address, and a vpn profile is configured. libtorrent expands 0.0.0.0 and [::] to every \
         interface that is up — the vpn profile's tunnel included — so this host profile would \
         also listen, and announce, from the tunnel's address, tying the host to that account. \
         Name the host's own address or device instead, such as \"192.0.2.10:6881\" or \
         \"eth0:6881\""
    )]
    WildcardListenBesideVpn {
        profile: String,
        listen_interfaces: String,
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
        "profile {profile:?}: a wireguard vpn_config must be {dir}/{iface}.conf, not \
         {vpn_config:?}. `wg-quick up <path>` names the interface after the file, and \
         `wg-quick down <iface>` resolves that bare name only against {dir} (or \
         $WG_CONFIG_DIR, which torrentd does not set) — so a config under any other name, or \
         in any other directory, brings up a tunnel that can never be torn down"
    )]
    InterfaceConfigMismatch {
        profile: String,
        iface: String,
        vpn_config: String,
        dir: &'static str,
    },
    #[error(
        "profile {profile:?}: upload_rate_limit = {value} is out of range (0..={max}). A \
         profile may exceed the top-level upload_rate_limit, but the value reaches libtorrent \
         as a C int, so anything above {max} would be applied as a negative rate limit"
    )]
    UploadRateLimitOutOfRange {
        profile: String,
        value: u32,
        max: u32,
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

    /// Whether `fp` is a peer-id prefix libtorrent can put on the wire as
    /// written: exactly eight printable, non-space ASCII characters.
    ///
    /// Both `peer_fingerprint` keys — the top-level default and a profile's
    /// own — reach `libtorrent_safe::Settings::peer_fingerprint` verbatim, and
    /// libtorrent copies the string into the front of the 20-byte peer id. So
    /// the rule is about bytes: eight of them, and ASCII so that eight
    /// characters *are* eight bytes. Space is excluded because a prefix that
    /// ends in one reads in the file as a shorter value than it is.
    pub fn is_valid_fingerprint(fp: &str) -> bool {
        fp.len() == 8 && fp.bytes().all(|b| b.is_ascii_graphic())
    }

    /// libtorrent's own default peer-id prefix in the version this daemon is
    /// built against (`settings_pack.cpp`: `peer_fingerprint`, `-LT20E0-` for
    /// 2.0.14). Named in the refusal; the check itself does not depend on it.
    pub const LIBTORRENT_DEFAULT_FINGERPRINT: &'static str = "-LT20E0-";

    /// Whether `fp` is a libtorrent default peer-id prefix — of any version.
    ///
    /// libtorrent puts `-LT` followed by its own version at the front of a
    /// peer id nobody configured: `-LT20C0-` for 2.0.12, `-LT20E0-` for the
    /// 2.0.14 vendored here. Comparing against one version's spelling is what
    /// let the other through, and the version moves with every vendored
    /// update, so the whole `-LT` client code is refused: it is the client
    /// every unconfigured libtorrent announces as, which ties a profile to
    /// all of them. Every key that supplies a fingerprint takes it in that
    /// raw form and nothing decodes it; the sixteen-hex spelling the retired
    /// `peer_fingerprint_hex` key took is refused as a malformed prefix by
    /// [`ProfileConfig::is_valid_fingerprint`] before this is asked.
    pub fn is_libtorrent_default_fingerprint(fp: &str) -> bool {
        fp.starts_with("-LT")
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
    /// is also URL-safe unescaped, which is what `/v1/profiles/<id>` needs.
    /// The 64-character bound keeps `session_state-<id>.dat` inside a
    /// filename-length limit on every platform the daemon targets.
    pub(crate) fn is_valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }

    /// `[A-Za-z0-9_=+.-]{1,15}`, excluding `.` and `..`.
    ///
    /// A `vpn_interface` is a Linux device name, and it is interpolated into
    /// the kill switch's nftables ruleset as a quoted string. The kernel's own
    /// rule (`dev_valid_name`) caps a name at 15 bytes (`IFNAMSIZ` less the
    /// NUL) and refuses `/`, `:`, whitespace, `.` and `..`, but it accepts a
    /// `"`, which closes the ruleset's quoted token early, so the kernel's rule
    /// alone would still let a name through that the ruleset cannot carry.
    /// This set is the one `wg-quick` enforces on the interface it names after
    /// its config file; every character in it is also safe inside an nftables
    /// quoted string.
    pub fn is_valid_interface_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 15
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'=' | b'+' | b'.' | b'-'))
    }

    /// Validate the whole configured set.
    ///
    /// Called at startup and on SIGHUP. Most rules here are uniqueness rules:
    /// two accounts on one tracker are distinguishable only by the things this
    /// enforces are distinct.
    ///
    /// Requiredness and uniqueness are separate questions, and they have
    /// different answers. A host profile may *omit* `peer_fingerprint` and
    /// `user_agent` — it is the host, and two host profiles are one host, so
    /// requiring them to differ would be theatre. But a value a host profile
    /// does set must still be distinct from every other profile's, because a
    /// fingerprint shared with a tunnelled profile puts one peer-id prefix on
    /// the wire from both the tunnel address and the host's real address,
    /// which is exactly the cross-account correlation these rules exist to
    /// prevent. So requiredness is checked per posture, below, and the shape
    /// rule and the libtorrent-default ban run for any profile that sets the field,
    /// whatever its posture.
    ///
    /// Two rules are deliberately **not** here, because they are not decidable
    /// from `&[ProfileConfig]` alone:
    ///
    /// - identity uniqueness, which has to compare each profile's *effective*
    ///   `peer_fingerprint` / `user_agent` — its own value or the
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
            // `session_state-<id>.dat`, and a segment of `/v1/profiles/<id>`.
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
                    // Shape before uniqueness: a name the kernel would never
                    // accept, or one the kill switch's ruleset cannot carry,
                    // otherwise passes `--check-config` and then aborts boot
                    // with an `nft` syntax error pointing at a file the
                    // operator never wrote.
                    if !Self::is_valid_interface_name(vpn_interface) {
                        return Err(ProfileConfigError::BadInterface {
                            profile: p.id.as_str().to_string(),
                            iface: vpn_interface.clone(),
                        });
                    }
                    if !seen_iface.insert(vpn_interface.clone()) {
                        return Err(ProfileConfigError::DuplicateInterface(
                            vpn_interface.clone(),
                        ));
                    }
                    // `wg-quick up <path>` names the interface after the file,
                    // and `wg-quick down <iface>` looks the file back up from
                    // the name — resolving a bare name *only* against
                    // `WG_CONFIG_DIR`, default `/etc/wireguard`. A profile
                    // whose two fields disagree brings a tunnel up under one
                    // name, waits 30s for an address on another, fails, and
                    // could never be torn down if it somehow succeeded. So
                    // does a profile whose config lives anywhere else, even
                    // with a matching stem: `wg-quick down` dies looking for
                    // the file before it ever reaches `del_if`, and that
                    // surviving tunnel is the defect this validation exists to
                    // make unreachable. `bring_down` is handed only the
                    // interface name (`VpnManager::bring_down(&self, iface:
                    // &str)`), so the directory has to be pinned here rather
                    // than threaded through.
                    if *vpn_type == VpnType::Wireguard {
                        let stem = vpn_config
                            .file_stem()
                            .map(|f| f.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let dir = vpn_config.parent();
                        if stem != *vpn_interface
                            || dir != Some(std::path::Path::new(Self::WG_CONFIG_DIR))
                        {
                            return Err(ProfileConfigError::InterfaceConfigMismatch {
                                profile: p.id.as_str().to_string(),
                                iface: vpn_interface.clone(),
                                vpn_config: vpn_config.display().to_string(),
                                dir: Self::WG_CONFIG_DIR,
                            });
                        }
                    }

                    // Identity is *required* here and only here. A tunnelled
                    // profile with no fingerprint of its own announces under
                    // the default one, which ties it to every other default
                    // client the tracker sees.
                    if p.peer_fingerprint.is_none() {
                        return Err(ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "peer_fingerprint",
                        });
                    }
                    if p.user_agent.is_none() {
                        return Err(ProfileConfigError::MissingIdentity {
                            profile: p.id.as_str().to_string(),
                            field: "user_agent",
                        });
                    }
                    // A tunnelled profile is an account, and the allow-list
                    // is the guard every add path runs
                    // (`policy::check_trackers`) to keep another account's
                    // torrent out of it. Optional, it was the guard nobody
                    // had switched on.
                    if p.allowed_tracker_domains.is_empty() {
                        return Err(ProfileConfigError::MissingTrackerDomains(
                            p.id.as_str().to_string(),
                        ));
                    }
                }
            }

            // Shape, for any profile that sets the list. The list reaches the
            // shim comma-joined, and an empty entry matches nothing, so
            // either would silently narrow the list to something other than
            // what the operator wrote.
            if let Some(bad) = p
                .allowed_tracker_domains
                .iter()
                .find(|d| d.trim().is_empty() || d.contains(',') || d.contains(char::is_whitespace))
            {
                return Err(ProfileConfigError::BadTrackerDomain {
                    profile: p.id.as_str().to_string(),
                    domain: bad.clone(),
                });
            }

            // A profile's own limit is range-checked the way the top-level
            // key of the same name is, and is *not* bounded by it: clamping a
            // profile to the global default would remove the main reason to
            // give one its own limit. The bound that matters is the one the
            // value has to survive on its way to libtorrent — see
            // `MAX_UPLOAD_RATE_LIMIT`.
            if let Some(v) = p.upload_rate_limit {
                if v > Self::MAX_UPLOAD_RATE_LIMIT {
                    return Err(ProfileConfigError::UploadRateLimitOutOfRange {
                        profile: p.id.as_str().to_string(),
                        value: v,
                        max: Self::MAX_UPLOAD_RATE_LIMIT,
                    });
                }
            }

            // Identity, for any profile that set one.
            //
            // Outside the match on purpose. `startup.rs` applies
            // `peer_fingerprint` to every session with no posture guard,
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
            if let Some(fp) = p.peer_fingerprint.as_deref() {
                if !Self::is_valid_fingerprint(fp) {
                    return Err(ProfileConfigError::BadFingerprint {
                        key: "peer_fingerprint",
                        value: fp.to_string(),
                    });
                }
                if Self::is_libtorrent_default_fingerprint(fp) {
                    return Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key: "peer_fingerprint",
                        value: fp.to_string(),
                        default: Self::LIBTORRENT_DEFAULT_FINGERPRINT,
                    });
                }
            }
        }

        // D12. libtorrent expands an unspecified listen address to one socket
        // per interface that is up (`expand_unspecified_address` in
        // session_impl.cpp), a WireGuard tunnel included, and announces over
        // every listen socket it has. A host profile on `0.0.0.0` beside a
        // vpn profile therefore listens and announces from the tunnel's
        // address as well as the host's, which ties the two together. Alone,
        // a host profile has no tunnel to leak into, and keeps the wildcard.
        if profiles.iter().any(ProfileConfig::is_vpn) {
            for p in profiles {
                if let ProfileNetwork::Host {
                    listen_interfaces, ..
                } = &p.network
                {
                    if Self::binds_unspecified(listen_interfaces) {
                        return Err(ProfileConfigError::WildcardListenBesideVpn {
                            profile: p.id.as_str().to_string(),
                            listen_interfaces: listen_interfaces.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether any entry of a libtorrent `listen_interfaces` string binds the
    /// unspecified address (`0.0.0.0`, `[::]`), rather than a literal address
    /// or a device.
    ///
    /// The grammar is [`ProfileConfig::listen_ports`]'s: `<addr>:<port>` with
    /// optional `s`/`l` flags, the address possibly bracketed. A device name
    /// does not parse as an address and is not unspecified.
    fn binds_unspecified(listen_interfaces: &str) -> bool {
        listen_interfaces.split(',').any(|entry| {
            let Some((addr, _)) = entry.trim().rsplit_once(':') else {
                return false;
            };
            let addr = addr
                .strip_prefix('[')
                .and_then(|a| a.strip_suffix(']'))
                .unwrap_or(addr);
            addr.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified())
        })
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
                vpn_config: PathBuf::from(format!("{}/{iface}.conf", ProfileConfig::WG_CONFIG_DIR)),
                vpn_interface: iface.to_string(),
                listen_port: Some(port),
                port_forward: PortForwardMode::Static,
                port_forward_gateway: None,
            },
            peer_fingerprint: Some(fp.to_string()),
            user_agent: Some(ua.to_string()),
            resume_dir: Some(PathBuf::from(format!("/var/lib/torrentd/resume/{id}"))),
            torrent_dir: Some(PathBuf::from(format!("/var/lib/torrentd/torrents/{id}"))),
            allowed_tracker_domains: vec!["tracker.example.com".to_string()],
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
            peer_fingerprint: None,
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
        let s = with_vpn(cfg("acct_a", 6881, "wg-a", "-AA1000-", "qB/5.0"), |n| {
            if let ProfileNetwork::Vpn { vpn_config, .. } = n {
                *vpn_config = PathBuf::from("/etc/wireguard/something-else.conf");
            }
        });
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::InterfaceConfigMismatch { .. })
        ));
    }

    #[test]
    fn a_profile_upload_rate_limit_libtorrent_cannot_hold_is_refused() {
        // The value is handed to `settings_pack` through a
        // `static_cast<int>`, so `u32::MAX` arrives as -1 and the profile the
        // operator configured for 4 GB/s seeds under a negative cap. The
        // sibling top-level key is range-checked; this one was not checked
        // at all.
        let mut s = cfg("acct_a", 6881, "wg-a", "-AA1000-", "qB/5.0");
        s.upload_rate_limit = Some(u32::MAX);
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::UploadRateLimitOutOfRange { .. })
        ));
    }

    #[test]
    fn a_profile_may_exceed_the_top_level_upload_rate_limit() {
        // The top-level key is a default, not a ceiling: giving one account
        // more bandwidth than the rest is the main reason to set a
        // per-profile limit, so the check bounds the representable range and
        // nothing else. `0` -- explicitly unlimited -- is in range too.
        for v in [0, 1, ProfileConfig::MAX_UPLOAD_RATE_LIMIT] {
            let mut s = cfg("acct_a", 6881, "wg-a", "-AA1000-", "qB/5.0");
            s.upload_rate_limit = Some(v);
            assert!(
                ProfileConfig::validate_set(&[s]).is_ok(),
                "upload_rate_limit = {v} is a legal profile limit",
            );
        }
    }

    #[test]
    fn a_wireguard_config_outside_etc_wireguard_is_refused() {
        // The stem matches here; only the directory does not. `wg-quick up`
        // takes the full path and brings the tunnel up regardless, but
        // `wg-quick down wg-a` resolves the bare name against /etc/wireguard,
        // finds nothing, and dies before `del_if` — so the tunnel survives
        // graceful shutdown and every restart.
        let s = with_vpn(cfg("acct_a", 6881, "wg-a", "-AA1000-", "qB/5.0"), |n| {
            if let ProfileNetwork::Vpn { vpn_config, .. } = n {
                *vpn_config = PathBuf::from("/etc/torrentd/wg-a.conf");
            }
        });
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::InterfaceConfigMismatch { .. })
        ));
    }

    #[test]
    fn a_wireguard_config_with_no_parent_directory_is_refused() {
        // `file_stem()` alone accepts a bare relative name; `wg-quick down`
        // still has only /etc/wireguard to look in.
        let s = with_vpn(cfg("acct_a", 6881, "wg-a", "-AA1000-", "qB/5.0"), |n| {
            if let ProfileNetwork::Vpn { vpn_config, .. } = n {
                *vpn_config = PathBuf::from("wg-a.conf");
            }
        });
        assert!(matches!(
            ProfileConfig::validate_set(&[s]),
            Err(ProfileConfigError::InterfaceConfigMismatch { .. })
        ));
    }

    #[test]
    fn openvpn_profiles_are_not_subject_to_the_wireguard_naming_rule() {
        // openvpn takes --dev explicitly, so its profile file name carries no
        // meaning for the interface.
        let s = with_vpn(cfg("acct_a", 6881, "tun0", "-AA1000-", "qB/5.0"), |n| {
            if let ProfileNetwork::Vpn {
                vpn_type,
                vpn_config,
                ..
            } = n
            {
                *vpn_type = VpnType::Openvpn;
                *vpn_config = PathBuf::from("/etc/openvpn/account-a.conf");
            }
        });
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
            cfg("acct_a", 6881, "wg0", "-AA1000-", "qB/5.0"),
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
            cfg("acct_a", 6881, "wg0", "-AA1000-", "qB/5.0"),
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
    fn a_host_profiles_fingerprint_is_shape_checked_like_any_other() {
        // A fingerprint that is not 8 bytes is not a fingerprint, and the
        // posture that set it makes no difference to that.
        let mut public = host("public", "0.0.0.0:6881", false);
        public.peer_fingerprint = Some("abc".to_string());
        assert!(matches!(
            ProfileConfig::validate_set(&[public]),
            Err(ProfileConfigError::BadFingerprint {
                key: "peer_fingerprint",
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
        public.peer_fingerprint = Some("-LT20C0-".to_string());
        assert!(matches!(
            ProfileConfig::validate_set(&[public]),
            Err(ProfileConfigError::DefaultFingerprintForbidden {
                key: "peer_fingerprint",
                ..
            })
        ));
    }

    #[test]
    fn a_host_profile_that_sets_no_identity_is_still_accepted() {
        // Uniqueness applies to a value that is set; requiredness stays
        // VPN-only. Two host profiles are one host, and a config that names
        // neither field has to keep validating.
        let profiles = vec![
            cfg("acct_a", 6881, "wg0", "-AA1000-", "qB/5.0"),
            host("public", "192.0.2.10:6882", false),
            host("public2", "eth0:6883", false),
        ];
        ProfileConfig::validate_set(&profiles).unwrap();
    }

    #[test]
    fn a_vpn_profile_missing_only_its_fingerprint_is_refused() {
        // The `peer_fingerprint` arm of `MissingIdentity`; only the
        // `user_agent` arm was reached before.
        let mut p = cfg("a", 6881, "wg0", "-AA1000-", "ua-a");
        p.peer_fingerprint = None;
        assert!(matches!(
            ProfileConfig::validate_set(&[p]),
            Err(ProfileConfigError::MissingIdentity {
                field: "peer_fingerprint",
                ..
            })
        ));
    }

    #[test]
    fn a_vpn_profile_must_declare_its_identity() {
        let mut p = cfg("a", 6881, "wg0", "-AA1000-", "ua-a");
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
        let p = cfg("a", 6881, "wg0", "-AA1000-", "ua-a");
        assert!(p.is_vpn());
        assert!(!p.dht_enabled());
    }

    #[test]
    fn validate_set_accepts_unique_profiles() {
        let profiles = vec![
            cfg("a", 6881, "wg0", "-AA1000-", "qBittorrent/5.0.3"),
            cfg("b", 6882, "wg1", "-CC1000-", "Transmission/4.0.6"),
        ];
        ProfileConfig::validate_set(&profiles).unwrap();
    }

    /// A name the kill switch's ruleset cannot carry, or the kernel would
    /// never create, is refused at load with the profile and value named —
    /// rather than passing `--check-config` and aborting boot inside `nft`.
    /// The config path is set to match, so the wireguard stem rule that runs
    /// after this one cannot be what refuses it.
    #[test]
    fn malformed_vpn_interface_rejected() {
        for bad in [
            "",
            "wg\"x",
            "wg}x",
            "wg\nx",
            "wg x",
            "wg/x",
            "wg:x",
            ".",
            "..",
            "sixteen-chars-xx",
        ] {
            let profiles = vec![cfg("a", 6881, bad, "-AA1000-", "ua-a")];
            match ProfileConfig::validate_set(&profiles) {
                Err(ProfileConfigError::BadInterface { profile, iface }) => {
                    assert_eq!(profile, "a");
                    assert_eq!(iface, bad);
                }
                other => panic!("{bad:?} must be refused as BadInterface, got {other:?}"),
            }
        }
    }

    #[test]
    fn well_formed_vpn_interface_names_accepted() {
        for good in [
            "wg0",
            "proton-a",
            "wg-acct-a",
            "tun_b.1",
            "wg=+",
            "fifteen-chars-x",
        ] {
            assert!(
                ProfileConfig::is_valid_interface_name(good),
                "{good:?} is a usable device name",
            );
            let profiles = vec![cfg("a", 6881, good, "-AA1000-", "ua-a")];
            ProfileConfig::validate_set(&profiles)
                .unwrap_or_else(|e| panic!("{good:?} must be accepted, got {e}"));
        }
    }

    #[test]
    fn duplicate_listen_port_rejected() {
        let profiles = vec![
            cfg("a", 6881, "wg0", "-AA1000-", "ua-a"),
            cfg("b", 6881, "wg1", "-CC1000-", "ua-b"),
        ];
        assert!(matches!(
            ProfileConfig::validate_set(&profiles),
            Err(ProfileConfigError::DuplicatePort(6881))
        ));
    }

    #[test]
    fn libtorrent_default_fingerprint_rejected() {
        // The vendored 2.0.14's own default, the 2.0.12 one the check used to
        // compare against, and the next version's: the `-LT` client code is
        // refused whatever version follows it.
        for fp in [
            ProfileConfig::LIBTORRENT_DEFAULT_FINGERPRINT,
            "-LT20C0-",
            "-LT20F0-",
        ] {
            let profiles = vec![cfg("a", 6881, "wg0", fp, "ua-a")];
            assert!(
                matches!(
                    ProfileConfig::validate_set(&profiles),
                    Err(ProfileConfigError::DefaultFingerprintForbidden {
                        key: "peer_fingerprint",
                        ..
                    })
                ),
                "{fp}"
            );
        }
        assert_eq!(ProfileConfig::LIBTORRENT_DEFAULT_FINGERPRINT, "-LT20E0-");
        // Another client's code is fine, `lt` (rtorrent's libtorrent) included.
        let profiles = vec![cfg("a", 6881, "wg0", "-lt0D80-", "rtorrent/0.9.8")];
        assert!(ProfileConfig::validate_set(&profiles).is_ok());
    }

    #[test]
    fn a_vpn_profile_must_name_its_tracker_domains() {
        let mut p = cfg("acct_a", 6881, "wg0", "-qB5030-", "qBittorrent/5.0.3");
        p.allowed_tracker_domains.clear();
        assert!(matches!(
            ProfileConfig::validate_set(&[p.clone()]),
            Err(ProfileConfigError::MissingTrackerDomains(id)) if id == "acct_a"
        ));
        // A host profile may leave it unset.
        assert!(ProfileConfig::validate_set(&[host("public", "eth0:6881", true)]).is_ok());
        // An entry that is blank, or would split in the shim's list, is not
        // a domain on either posture.
        for bad in ["", "  ", "a.example,b.example", "a.example b.example"] {
            p.allowed_tracker_domains = vec!["tracker.example.com".into(), bad.into()];
            assert!(
                matches!(
                    ProfileConfig::validate_set(&[p.clone()]),
                    Err(ProfileConfigError::BadTrackerDomain { domain, .. }) if domain == bad
                ),
                "{bad:?}"
            );
            let mut h = host("public", "eth0:6881", true);
            h.allowed_tracker_domains = vec![bad.into()];
            assert!(
                matches!(
                    ProfileConfig::validate_set(&[h]),
                    Err(ProfileConfigError::BadTrackerDomain { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_wildcard_host_listen_is_refused_only_beside_a_vpn_profile() {
        let vpn = cfg("acct_a", 6891, "wg0", "-qB5030-", "qBittorrent/5.0.3");
        for wildcard in [
            "0.0.0.0:6881",
            "[::]:6881",
            "eth0:6882,0.0.0.0:6881s",
            "[::0]:6881",
        ] {
            assert!(
                matches!(
                    ProfileConfig::validate_set(&[host("public", wildcard, true), vpn.clone()]),
                    Err(ProfileConfigError::WildcardListenBesideVpn { profile, .. })
                        if profile == "public"
                ),
                "{wildcard}"
            );
            // With no tunnel to expand into, the wildcard is the host's own.
            assert!(
                ProfileConfig::validate_set(&[host("public", wildcard, true)]).is_ok(),
                "{wildcard}"
            );
        }
        for named in [
            "eth0:6881",
            "192.0.2.10:6881",
            "[2001:db8::1]:6881,eth0:6881",
        ] {
            assert!(
                ProfileConfig::validate_set(&[host("public", named, true), vpn.clone()]).is_ok(),
                "{named}"
            );
        }
    }

    #[test]
    fn a_fingerprint_must_be_eight_printable_ascii_characters() {
        // The sixteen-hex spelling the retired `peer_fingerprint_hex` took is
        // the first case: it reached libtorrent as sixteen ASCII characters,
        // not the eight bytes it spelled, so it must not validate under the
        // raw key either — including the hex of libtorrent's own default.
        for bad in [
            "a1b2c3d4e5f60718",
            "2d4c54323043302d",
            "abcd",
            "",
            "-XX123-",
            "-XX12345-",
            "-XX 234-",
            "-XX\t234-",
            "-XX1é4-",
        ] {
            let profiles = vec![cfg("a", 6881, "wg0", bad, "ua-a")];
            match ProfileConfig::validate_set(&profiles) {
                Err(ProfileConfigError::BadFingerprint { key, value }) => {
                    assert_eq!(key, "peer_fingerprint");
                    assert_eq!(value, bad);
                }
                other => panic!("{bad:?} must be refused as BadFingerprint, got {other:?}"),
            }
        }
        for good in ["-XX1234-", "-qB5030-", "M7-2-3--"] {
            assert!(ProfileConfig::is_valid_fingerprint(good), "{good:?}");
        }
    }

    #[test]
    fn static_profile_without_listen_port_rejected() {
        let s = with_vpn(cfg("a", 6881, "wg0", "-AA1000-", "ua-a"), |n| {
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
        let s = with_vpn(cfg("a", 0, "wg0", "-AA1000-", "ua-a"), |n| {
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
        let a = with_vpn(cfg("a", 6881, "wg0", "-AA1000-", "ua-a"), natpmp);
        let b = with_vpn(cfg("b", 6881, "wg1", "-CC1000-", "ua-b"), natpmp);
        ProfileConfig::validate_set(&[a, b]).unwrap();
    }

    #[test]
    fn gateway_defaults_to_proton() {
        let s = cfg("a", 6881, "wg0", "-AA1000-", "ua-a");
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
