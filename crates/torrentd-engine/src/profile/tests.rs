use std::path::PathBuf;

use super::*;
use crate::port_forward::PortForwardMode;
use crate::vpn::VpnType;

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
        // A tracker of its own, so that two of these are two accounts
        // on different trackers unless a test says otherwise.
        allowed_tracker_domains: vec![format!("tracker-{id}.example.com")],
        allowed_tracker_urls: vec![],
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
        allowed_tracker_urls: vec![],
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
    // The stem matches here; only the directory does not. Root's
    // `wg-quick up wg-a` reads /etc/wireguard/wg-a.conf, so this profile
    // would compare an adopted link's key against a different file.
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
    // `file_stem()` alone accepts a bare relative name; the file root
    // raises the link from is still /etc/wireguard/wg-a.conf.
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
// The tests live beside it, in `crates/torrentd/src/config/tests.rs`.

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

/// Two profiles under one id would share a resume directory, a torrent
/// directory and a `/v1/profiles/<id>` route. Everything else about the
/// pair is distinct, so the id is the only thing that can refuse it.
#[test]
fn two_profiles_with_one_id_are_refused() {
    let profiles = vec![
        cfg("a", 6881, "wg0", "-AA1000-", "qBittorrent/5.0.3"),
        cfg("a", 6882, "wg1", "-CC1000-", "Transmission/4.0.6"),
    ];
    match ProfileConfig::validate_set(&profiles) {
        Err(ProfileConfigError::DuplicateId(id)) => assert_eq!(id, "a"),
        other => panic!("a repeated id must be refused as DuplicateId, got {other:?}"),
    }
}

/// Two VPN profiles on one tunnel interface would route both accounts
/// out of one address. Everything else about the pair is distinct, so
/// the interface is the only thing that can refuse it.
#[test]
fn two_vpn_profiles_on_one_interface_are_refused() {
    let profiles = vec![
        cfg("a", 6881, "wg0", "-AA1000-", "qBittorrent/5.0.3"),
        cfg("b", 6882, "wg0", "-CC1000-", "Transmission/4.0.6"),
    ];
    match ProfileConfig::validate_set(&profiles) {
        Err(ProfileConfigError::DuplicateInterface(iface)) => assert_eq!(iface, "wg0"),
        other => {
            panic!("a shared interface must be refused as DuplicateInterface, got {other:?}")
        }
    }
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
        "all",
        "interfaces",
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

/// Two accounts on one tracker: `acct_a` and `acct_b`, both listing
/// `domain_a` / `domain_b`, which the caller makes overlap.
fn same_tracker(domain_a: &str, domain_b: &str) -> [ProfileConfig; 2] {
    let mut a = cfg("acct_a", 6881, "wg0", "-qB5030-", "qBittorrent/5.0.3");
    let mut b = cfg("acct_b", 6882, "wg1", "-DE211s-", "Deluge/2.1.1");
    a.allowed_tracker_domains = vec![domain_a.into()];
    b.allowed_tracker_domains = vec![domain_b.into()];
    [a, b]
}

/// The scenario of issue 166: the host is all the domain guard compares,
/// so two profiles whose lists overlap — the same entry, a parent domain
/// of the other's, or one spelled differently — are refused at load
/// unless both bind their accounts.
#[test]
fn overlapping_tracker_domains_are_refused_without_an_account_binding() {
    for (da, db, narrower) in [
        (
            "tracker.example.com",
            "tracker.example.com",
            "tracker.example.com",
        ),
        ("tracker.example.com", "example.com", "tracker.example.com"),
        (
            "example.com",
            "announce.tracker.example.com",
            "announce.tracker.example.com",
        ),
        (
            "Tracker.Example.COM.",
            "tracker.example.com",
            "tracker.example.com",
        ),
    ] {
        let set = same_tracker(da, db);
        match ProfileConfig::validate_set(&set) {
            Err(ProfileConfigError::OverlappingTrackerDomains {
                a,
                b,
                domain,
                a_domain,
                b_domain,
            }) => {
                assert_eq!((a.as_str(), b.as_str()), ("acct_a", "acct_b"));
                assert_eq!(domain, narrower, "{da:?} {db:?}");
                assert_eq!((a_domain.as_str(), b_domain.as_str()), (da, db));
            }
            other => panic!("{da:?} beside {db:?} must be refused, got {other:?}"),
        }
        // One binding is not enough: the other account's torrent still
        // passes the unbound profile.
        let [mut a, b] = same_tracker(da, db);
        a.allowed_tracker_urls = vec!["https://tracker.example.com/PASS-A/".into()];
        assert!(matches!(
            ProfileConfig::validate_set(&[a, b]),
            Err(ProfileConfigError::OverlappingTrackerDomains { .. })
        ));
    }
    // A label boundary is not crossed: `eviltracker.example.com` is not
    // under `tracker.example.com`.
    ProfileConfig::validate_set(&same_tracker(
        "tracker.example.com",
        "eviltracker.example.com",
    ))
    .unwrap();
    // A host profile with a list is an account too.
    let [a, _] = same_tracker("tracker.example.com", "unused.example");
    let mut h = host("public", "eth0:6899", false);
    h.allowed_tracker_domains = vec!["example.com".into()];
    assert!(matches!(
        ProfileConfig::validate_set(&[a.clone(), h]),
        Err(ProfileConfigError::OverlappingTrackerDomains { .. })
    ));
    // A host profile with no list is not checked, and overlaps nothing.
    ProfileConfig::validate_set(&[a, host("public", "eth0:6899", false)]).unwrap();
}

#[test]
fn overlapping_domains_are_accepted_with_disjoint_account_bindings() {
    let [mut a, mut b] = same_tracker("tracker.example.com", "tracker.example.com");
    a.allowed_tracker_urls = vec!["https://tracker.example.com/announce?passkey=aaaa".into()];
    b.allowed_tracker_urls = vec![
        "https://tracker.example.com/announce?passkey=aaaab".into(),
        "udp://tracker.example.com:6969/bbbb/".into(),
    ];
    ProfileConfig::validate_set(&[a.clone(), b.clone()]).unwrap();

    // A prefix one account's announce URLs fall under, and the other's
    // too, binds nothing.
    for overlapping in [
        "https://tracker.example.com/announce?passkey=aaaa",
        "https://TRACKER.example.com/announce?passkey=aaaa&x=1",
        "https://tracker.example.com/",
        "https://tracker.example.com/announce?",
    ] {
        let mut b = b.clone();
        b.allowed_tracker_urls.push(overlapping.into());
        match ProfileConfig::validate_set(&[a.clone(), b]) {
            Err(ProfileConfigError::OverlappingTrackerUrls {
                a,
                a_index,
                b,
                b_index,
            }) => {
                assert_eq!((a.as_str(), a_index), ("acct_a", 0));
                assert_eq!((b.as_str(), b_index), ("acct_b", 2));
            }
            other => panic!("{overlapping:?} must be refused, got {other:?}"),
        }
    }
}

#[test]
fn an_account_binding_must_be_a_prefix_on_the_profiles_own_domains() {
    let mut p = cfg("acct_a", 6881, "wg0", "-qB5030-", "qBittorrent/5.0.3");
    p.allowed_tracker_domains = vec!["tracker.example.com".into()];
    for good in [
        "https://tracker.example.com/PASS/",
        "udp://announce.tracker.example.com:6969/PASS/announce",
        "http://Tracker.Example.com/announce.php?passkey=PASS",
    ] {
        p.allowed_tracker_urls = vec![good.into()];
        ProfileConfig::validate_set(&[p.clone()])
            .unwrap_or_else(|e| panic!("{good:?} must be accepted, got {e}"));
    }
    for bad in [
        "",
        "tracker.example.com/PASS/",
        "https://tracker.example.com",
        "https:///PASS/",
        "https://user@tracker.example.com/PASS/",
        "https://tracker.example.com?x/PASS/",
        "https://tracker.example.com:/PASS/",
        "https://tracker.example.com:x/PASS/",
        "https://tracker.example.com./PASS/",
        "https://tracker.example.com/PA SS/",
        "1http://tracker.example.com/PASS/",
    ] {
        p.allowed_tracker_urls = vec!["https://tracker.example.com/OK/".into(), bad.into()];
        match ProfileConfig::validate_set(&[p.clone()]) {
            Err(e @ ProfileConfigError::BadTrackerUrl { index: 1, .. }) => {
                // Named by index: the value holds a passkey.
                assert!(!e.to_string().contains("PASS"), "{e}");
            }
            other => panic!("{bad:?} must be refused as BadTrackerUrl, got {other:?}"),
        }
    }
    for off in [
        "https://other.example.com/PASS/",
        "https://eviltracker.example.com/PASS/",
        "https://example.com/PASS/",
    ] {
        p.allowed_tracker_urls = vec![off.into()];
        assert!(
            matches!(
                ProfileConfig::validate_set(&[p.clone()]),
                Err(ProfileConfigError::TrackerUrlOffDomains { index: 0, .. })
            ),
            "{off:?}"
        );
    }
    // A binding with no domain list binds nothing the guard reads.
    let mut h = host("public", "eth0:6881", false);
    h.allowed_tracker_urls = vec!["https://tracker.example.com/PASS/".into()];
    assert!(matches!(
        ProfileConfig::validate_set(&[h]),
        Err(ProfileConfigError::TrackerUrlOffDomains { .. })
    ));
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
    // their ports are gateway-assigned at runtime. Both keep
    // `Some(6881)`: with no port on either there is no collision, and the
    // test would pass with natpmp ports entered into the uniqueness set.
    // Deserialization refuses a natpmp `listen_port`; `validate_set`
    // alone must still not count one.
    let natpmp = |n: &mut ProfileNetwork| {
        if let ProfileNetwork::Vpn {
            port_forward,
            listen_port,
            ..
        } = n
        {
            *port_forward = PortForwardMode::Natpmp;
            assert_eq!(*listen_port, Some(6881));
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
