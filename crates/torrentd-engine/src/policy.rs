//! Add-time torrent flag policy.
//!
//! Every flag the daemon asserts on a torrent is composed here, because the
//! same invariants have to hold on four independent add paths — the HTTP API,
//! the startup torrent-dir scan, the startup resume reload, and pool adoption
//! — and a guard that lapses on one of them is not a guard. Each path used to
//! spell its own `if profile.is_default() { … } else { … }`, which is how
//! `UPLOAD_MODE` came to be asserted on none of them.

use libtorrent_safe::TorrentFlags;

use crate::profile::ProfileConfig;

/// Flags carried by every add, on every path, in every mode.
///
/// `UPLOAD_MODE` is the enforcement behind "torrentd never downloads payload".
/// It is not decoration on top of `SEED_MODE`, because `SEED_MODE` does not
/// hold:
///
/// * libtorrent documents it as **a no-op for a torrent added without
///   metadata**, so a magnet add is not covered by it at all, and it cannot be
///   set after the fact once the metadata arrives;
/// * libtorrent drops it on a piece-hash failure, on `force_recheck`, and on a
///   file-priority change that resumes a download.
///
/// `upload_mode` is what actually holds — "the torrent will not make any piece
/// requests" — and libtorrent only takes a torrent out of it on its own when
/// the torrent is `auto_managed`. This daemon never sets that bit, but resume
/// data can carry it: a `.fastresume` written by qBittorrent or Deluge has
/// `auto_managed=1`, and libtorrent then lifts upload mode after
/// `optimistic_disk_retry`. So [`forbidden`] is cleared on every path that
/// starts from resume data, and the shim clears it, and sets `UPLOAD_MODE`,
/// on every add whatever the caller passes.
///
/// Magnet *metadata* is not a piece request, so metadata still arrives: the
/// daemon can still learn what a magnet describes, which is the one thing it
/// has always claimed to fetch.
fn no_download() -> TorrentFlags {
    TorrentFlags::UPLOAD_MODE
}

/// Flags no torrent this daemon adds may carry: each can take a torrent out of
/// upload mode (`AUTO_MANAGED`), request pieces by design (`SHARE_MODE`), or
/// is a downloading client's knob with no meaning for a torrent that never
/// leaves upload mode. The shim enforces the same set on every add; stating it
/// here keeps each add path's intent readable and testable without libtorrent.
pub fn forbidden() -> TorrentFlags {
    TorrentFlags::AUTO_MANAGED
        | TorrentFlags::SHARE_MODE
        | TorrentFlags::SUPER_SEEDING
        | TorrentFlags::SEQUENTIAL_DOWNLOAD
        | TorrentFlags::STOP_WHEN_READY
}

/// Per-torrent discovery guards for a torrent living in `profile`.
///
/// Safety Rules 5 and 6: PEX, DHT and LSD are disabled unconditionally on
/// every torrent in a tunnelled profile, belt-and-braces against the torrent's
/// own `private` bit being wrong. A host profile keeps them — that posture is
/// public by definition, and its DHT is whatever it asked for.
///
/// This keys off the profile's declared network, not off its *name*. It used
/// to branch on whether the id happened to be `default`, which a config could
/// satisfy by accident and thereby seed a tunnelled profile with PEX on.
pub fn discovery_guards(profile: &ProfileConfig) -> TorrentFlags {
    if profile.is_vpn() {
        TorrentFlags::DISABLE_PEX | TorrentFlags::DISABLE_DHT | TorrentFlags::DISABLE_LSD
    } else {
        TorrentFlags::empty()
    }
}

/// Flags for an add whose payload is believed complete, so libtorrent may skip
/// hashing (`SEED_MODE`) and seed immediately.
pub fn seed_flags(profile: &ProfileConfig) -> TorrentFlags {
    TorrentFlags::SEED_MODE | no_download() | discovery_guards(profile)
}

/// Flags for an add that must be hash-checked before it seeds. Deliberately no
/// `SEED_MODE` — its absence is what makes libtorrent verify the payload — but
/// the no-download invariant still applies, and applies *most* here: this is
/// the path where a failed check would otherwise turn the torrent into a
/// leecher.
pub fn verify_flags(profile: &ProfileConfig) -> TorrentFlags {
    no_download() | discovery_guards(profile)
}

/// Flags re-asserted when loading resume data.
///
/// Resume data carries the flags it was saved with, which is why this does not
/// re-assert `SEED_MODE` — that would embed a full piece-hash table in every
/// resume file. It *does* re-assert everything that must never lapse, because
/// resume data written before a guard existed would otherwise come back
/// without it.
pub fn resume_flags_set(profile: &ProfileConfig) -> TorrentFlags {
    no_download() | discovery_guards(profile)
}

/// Flags cleared when loading resume data: everything [`forbidden`], which
/// resume data written by another client (or by this one, before the guard)
/// may carry. A caller adds what it clears for its own reasons, such as
/// `PAUSED`.
pub fn resume_flags_clear() -> TorrentFlags {
    forbidden()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::profile::ProfileId;
    use crate::profile::ProfileNetwork;
    use crate::vpn::VpnType;

    fn vpn() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("acct_a"),
            network: ProfileNetwork::Vpn {
                vpn_type: VpnType::Wireguard,
                vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
                vpn_interface: "wg0".into(),
                listen_port: Some(6881),
                port_forward: Default::default(),
                port_forward_gateway: None,
            },
            peer_fingerprint: Some("-AA1000-".into()),
            user_agent: Some("qB/5.0".into()),
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
        }
    }

    fn host() -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new("public"),
            network: ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".into(),
                dht: true,
            },
            peer_fingerprint: None,
            user_agent: None,
            resume_dir: None,
            torrent_dir: None,
            allowed_tracker_domains: vec![],
            upload_rate_limit: None,
        }
    }

    #[test]
    fn every_path_forbids_downloading() {
        for p in [host(), vpn()] {
            for flags in [seed_flags(&p), verify_flags(&p), resume_flags_set(&p)] {
                assert!(
                    flags.contains(TorrentFlags::UPLOAD_MODE),
                    "no-download invariant missing for {}",
                    p.id,
                );
            }
        }
    }

    #[test]
    fn no_path_sets_a_forbidden_flag_and_resume_clears_them_all() {
        for p in [host(), vpn()] {
            for flags in [seed_flags(&p), verify_flags(&p), resume_flags_set(&p)] {
                assert!(
                    !flags.intersects(forbidden()),
                    "{flags:?} sets a forbidden flag"
                );
            }
        }
        assert!(resume_flags_clear().contains(forbidden()));
        assert!(forbidden().contains(TorrentFlags::AUTO_MANAGED));
        assert!(!forbidden().contains(TorrentFlags::UPLOAD_MODE));
    }

    #[test]
    fn only_the_seed_path_skips_hashing() {
        let p = host();
        assert!(seed_flags(&p).contains(TorrentFlags::SEED_MODE));
        assert!(!verify_flags(&p).contains(TorrentFlags::SEED_MODE));
        assert!(!resume_flags_set(&p).contains(TorrentFlags::SEED_MODE));
    }

    #[test]
    fn a_tunnelled_profile_disables_discovery_on_every_path() {
        let p = vpn();
        for flags in [seed_flags(&p), verify_flags(&p), resume_flags_set(&p)] {
            assert!(flags.contains(TorrentFlags::DISABLE_PEX));
            assert!(flags.contains(TorrentFlags::DISABLE_DHT));
            assert!(flags.contains(TorrentFlags::DISABLE_LSD));
        }
    }

    #[test]
    fn a_host_profile_keeps_discovery() {
        let p = host();
        assert!(!seed_flags(&p).contains(TorrentFlags::DISABLE_DHT));
        assert!(!seed_flags(&p).contains(TorrentFlags::DISABLE_PEX));
    }

    #[test]
    fn the_guard_keys_off_posture_not_the_profile_name() {
        // The hole this replaced: a profile *named* `default` used to read as
        // the public one whatever its network said.
        let mut p = vpn();
        p.id = ProfileId::new("default");
        assert!(seed_flags(&p).contains(TorrentFlags::DISABLE_PEX));
    }
}
