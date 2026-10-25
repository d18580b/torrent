//! Profile identification + per-profile data.
//!
//! `ProfileId` is the cheap-to-clone key used in StateMap, registry, and
//! every `(profile_id, alert)` pair. `ProfileConfig` is the operator-supplied
//! shape parsed from TOML; validation cross-checks live here so SIGHUP
//! reload and startup share one path. Nothing here holds a profile's
//! engine: the daemon pairs each `ProfileId` with its engine (as
//! [`ProfileSource`](crate::source::ProfileSource)'s entries do), and its
//! HTTP handlers answer the profile endpoints from that pairing.
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
//!    interface, and where the device binding takes, a lost routing rule
//!    cannot route them there either. Where the kernel refuses it (no
//!    `CAP_NET_RAW` before Linux 5.7) libtorrent binds the device's address
//!    alone, and the route is the routing table's. Everything else — the
//!    listen sockets, which also carry uTP and UDP tracker traffic, and what
//!    answers on them — is bound to the tunnel address (and device-bound only
//!    as far as libtorrent's own best effort goes), and routed by the
//!    tunnel's source rule, which the health monitor checks every poll.
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
//!    Rules 5 and 6 bind to the posture, not to the profile's name. The
//!    posture's guard is composed in one place — `policy::discovery_guards` —
//!    for all four add paths, because it used to be spelled per path against
//!    whether the id happened to be `default`, which a config could satisfy by
//!    accident. A torrent without metadata is the one exception, on every
//!    profile: `policy::magnet_flags` (a magnet add) and
//!    `policy::resume_flags_set_without_metadata` (a boot resume entry with no
//!    `.torrent`) disable all three whatever the posture, because its
//!    `private` bit is not yet known.
//! 7. **SIGHUP cannot change identity-critical fields.** The tunnel
//!    interface, listen port, peer fingerprint and user agent are what a
//!    tracker sees as an account's identity. Changes are detected, warned
//!    about, and ignored; applying them means a restart.
//!
//!    The per-profile `resume_dir` and `torrent_dir` are equally unreloadable
//!    — the stores are opened at startup — but they are not identity: no
//!    announce, handshake or peer message carries where a profile keeps its
//!    files. They get the ordinary non-reloadable warning, so this rule's
//!    warning stays the privacy event an alert rule can watch for, and an
//!    operator setting those two keys does not fire it.
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
//! every `vpn` profile. It is the tracker guard: a profile that sets it takes
//! only a torrent whose every tracker is on it, on every add path
//! (`policy::check_trackers`). It compares the tracker's host and nothing
//! else, so it keeps apart accounts on *different* trackers, and cannot tell
//! two accounts on one tracker apart: their announce URLs differ only in the
//! passkey, in the path or query. That is what `allowed_tracker_urls` binds —
//! announce-URL prefixes carrying the account's passkey, which every tracker
//! must also fall under — and two profiles whose domain lists overlap are
//! refused at load unless both set it, with prefixes that do not overlap
//! (`ProfileConfig::validate_set`). Together they keep one account's torrent
//! and its passkey from being announced from another account's session.
//! Neither is an egress control. Beside them, two load-time rules: a host profile may not listen on
//! the unspecified address while a `vpn` profile exists, since libtorrent
//! expands it to the tunnels' addresses too; and no profile may wear
//! libtorrent's own `-LT` peer-id code.
//!
//! `id` holds [`ProfileId`]; `config` the `[[profile]]` shape and its
//! accessors; `validate` the per-profile and cross-profile rules above.

mod config;
mod id;
#[cfg(test)]
mod tests;
mod validate;

pub use config::bind_endpoint;
pub use config::ProfileConfig;
pub use config::ProfileNetwork;
pub use id::ProfileId;
pub use id::ID_CHARSET_RULE;
pub use validate::ProfileConfigError;

#[cfg(test)]
mod props {
    use std::path::PathBuf;

    use proptest::prelude::*;

    use super::*;
    use crate::port_forward::PortForwardMode;
    use crate::vpn::VpnType;

    /// One fault a profile can carry, alone or against its neighbours.
    #[derive(Clone, Copy, Debug)]
    enum Flaw {
        None,
        BadId,
        SameId,
        SamePort,
        SameInterface,
        NoPort,
        ConfigMismatch,
        NoFingerprint,
        NoTrackers,
        EmptyListen,
        HugeRateLimit,
    }

    /// The `i`th profile of a set: a valid vpn or host profile whose id,
    /// port, interface and identity are its own, unless `flaw` says
    /// otherwise.
    fn profile(i: usize, vpn: bool, flaw: Flaw) -> ProfileConfig {
        let id = match flaw {
            Flaw::BadId => "bad id".to_owned(),
            Flaw::SameId => "p0".to_owned(),
            _ => format!("p{i}"),
        };
        let port = if matches!(flaw, Flaw::SamePort) {
            6881
        } else {
            6881 + i as u16
        };
        let iface = if matches!(flaw, Flaw::SameInterface) {
            "wg0".to_owned()
        } else {
            format!("wg{i}")
        };
        let network = if vpn {
            ProfileNetwork::Vpn {
                vpn_type: VpnType::Wireguard,
                vpn_config: PathBuf::from(format!(
                    "{}/{}.conf",
                    ProfileConfig::WG_CONFIG_DIR,
                    if matches!(flaw, Flaw::ConfigMismatch) {
                        "other"
                    } else {
                        &iface
                    },
                )),
                vpn_interface: iface,
                listen_port: (!matches!(flaw, Flaw::NoPort)).then_some(port),
                port_forward: PortForwardMode::Static,
                port_forward_gateway: None,
            }
        } else {
            ProfileNetwork::Host {
                listen_interfaces: if matches!(flaw, Flaw::EmptyListen) {
                    String::new()
                } else {
                    format!("eth0:{port}")
                },
                dht: i.is_multiple_of(2),
            }
        };
        ProfileConfig {
            id: ProfileId::new(id),
            network,
            peer_fingerprint: (vpn && !matches!(flaw, Flaw::NoFingerprint))
                .then(|| format!("-A{}1000-", (b'A' + i as u8) as char)),
            user_agent: vpn.then(|| format!("qBittorrent/5.0.{i}")),
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: if vpn && !matches!(flaw, Flaw::NoTrackers) {
                vec![format!("tracker-{i}.example.com")]
            } else {
                vec![]
            },
            allowed_tracker_urls: vec![],
            upload_rate_limit: matches!(flaw, Flaw::HugeRateLimit).then_some(u32::MAX),
        }
    }

    fn set_and_shuffle() -> impl Strategy<Value = (Vec<ProfileConfig>, Vec<ProfileConfig>)> {
        let flaw = prop_oneof![
            20 => Just(Flaw::None),
            1 => Just(Flaw::BadId),
            1 => Just(Flaw::SameId),
            1 => Just(Flaw::SamePort),
            1 => Just(Flaw::SameInterface),
            1 => Just(Flaw::NoPort),
            1 => Just(Flaw::ConfigMismatch),
            1 => Just(Flaw::NoFingerprint),
            1 => Just(Flaw::NoTrackers),
            1 => Just(Flaw::EmptyListen),
            1 => Just(Flaw::HugeRateLimit),
        ];
        prop::collection::vec((any::<bool>(), flaw), 1..5).prop_flat_map(|spec| {
            let set: Vec<ProfileConfig> = spec
                .into_iter()
                .enumerate()
                .map(|(i, (vpn, flaw))| profile(i, vpn, flaw))
                .collect();
            (Just(set.clone()), Just(set).prop_shuffle())
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// Whether a set of profiles is accepted does not depend on the
        /// order the `[[profile]]` tables were written in.
        #[test]
        fn validate_set_is_order_independent((set, shuffled) in set_and_shuffle()) {
            let (a, b) = (ProfileConfig::validate_set(&set), ProfileConfig::validate_set(&shuffled));
            prop_assert_eq!(a.is_ok(), b.is_ok(), "{:?} vs {:?}", a, b);
        }
    }
}
