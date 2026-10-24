//! `ProfileConfig` — operator-supplied (TOML): the `[[profile]]` shape, its
//! on-disk form, and the accessors the daemon reads it through.

use std::path::PathBuf;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use super::ProfileId;
use crate::port_forward::PortForwardMode;
use crate::vpn::VpnTunnel;
use crate::vpn::VpnType;

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
    /// The account binding: announce-URL prefixes, each carrying this
    /// account's passkey, that every tracker the profile announces to must
    /// fall under, beside being on `allowed_tracker_domains`. Empty unless
    /// written; required on two profiles whose domain lists overlap, since
    /// the host alone cannot tell two accounts on one tracker apart.
    ///
    /// Each entry holds a passkey, so it is never reported by the API nor
    /// named in an error: refusals cite the entry's index.
    pub allowed_tracker_urls: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_tracker_urls: Vec<String>,
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
            allowed_tracker_urls: r.allowed_tracker_urls,
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
            allowed_tracker_urls: c.allowed_tracker_urls.clone(),
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
    /// `wg-quick`'s own default: `wg-quick up <iface>` and `wg-quick@<iface>`
    /// read `/etc/wireguard/<iface>.conf`, which is how root raises a link
    /// before the daemon starts for the daemon to adopt. The daemon never runs
    /// `wg-quick` itself; pinning the profile's config to this one path keeps
    /// it the same file root raises that interface from.
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
}

/// The `listen_interfaces` entry for a vpn session: the tunnel **device**
/// and the port, `wg0:6881`.
///
/// Naming the device, not the tunnel address, is what holds the listen
/// sockets in the tunnel. libtorrent binds every listen socket to a device
/// (`SO_BINDTODEVICE`). Given a device name it binds each address that device
/// holds to that device. Given an address, it picks the first interface whose
/// network contains the address, and a physical interface whose network
/// covers the tunnel address (a `10.0.0.0/8` LAN beside Proton's
/// `10.2.0.2/32`) comes first. A socket bound to a device skips policy
/// routing, so the listen sockets, which also send uTP and UDP tracker
/// traffic and whose device HTTP tracker connections reuse, then left by the
/// LAN with the tunnel's address, and no route probe could see it.
///
/// The cost is that the session listens on every address the device holds,
/// an IPv6 `Address` in a WireGuard config included. Every one of those
/// sockets is held to the device just the same.
pub fn bind_endpoint(iface: &str, port: u16) -> String {
    format!("{iface}:{port}")
}
