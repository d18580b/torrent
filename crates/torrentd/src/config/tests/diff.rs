//! `Config::diff`: which class each changed key lands in, and that a
//! change is reported alone.

use super::*;

#[test]
fn a_profile_leaving_the_set_is_an_identity_change() {
    // `diff_profiles`'s entries with no `.key`. Which accounts exist is as
    // fixed at startup as who they announce as, so both must land in the
    // class that keeps Safety Rule 7's wording.
    let dir = tempdir().unwrap();
    let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    let mut b = a.clone();
    b.profile.clear();
    let d = Config::diff(&a, &b);
    assert_eq!(d.profile_changes.len(), 1, "got {:?}", d.profile_changes);
    assert!(d.profile_changes[0].what.starts_with("public: removed"));
    assert_eq!(d.profile_changes[0].kind, ProfileChangeKind::Identity);

    let d = Config::diff(&b, &a);
    assert_eq!(d.profile_changes.len(), 1, "got {:?}", d.profile_changes);
    assert!(d.profile_changes[0].what.starts_with("public: added"));
    assert_eq!(d.profile_changes[0].kind, ProfileChangeKind::Identity);
}

/// A profile key, the class its change is owed, and the profile with only
/// that key changed.
type FieldEdit = (&'static str, ProfileChangeKind, ProfileConfig);

/// Every `[[profile]]` field of `base` changed alone, each paired with the
/// key and class `diff_profiles` owes it. Destructured with no `..`, so a
/// new field needs a row; each row is asserted to be a real change.
fn each_profile_field_changed_alone(base: &ProfileConfig) -> Vec<FieldEdit> {
    let ProfileConfig {
        id: _,
        network,
        peer_fingerprint,
        user_agent,
        resume_dir,
        torrent_dir,
        allowed_tracker_domains,
        allowed_tracker_urls,
        upload_rate_limit,
    } = base;
    let with = |edit: &dyn Fn(&mut ProfileConfig)| {
        let mut p = base.clone();
        edit(&mut p);
        p
    };

    let new_network = torrentd_engine::ProfileNetwork::Host {
        listen_interfaces: "0.0.0.0:6899".into(),
        dht: false,
    };
    let new_fingerprint = Some("-AA1000-".to_string());
    let new_user_agent = Some("ua/1.0".to_string());
    let new_resume_dir = Some(PathBuf::from("/var/lib/torrentd/resume-public"));
    let new_torrent_dir = Some(PathBuf::from("/var/lib/torrentd/torrents-public"));
    let new_domains = vec!["tracker.example.com".to_string()];
    let new_urls = vec!["https://tracker.example.com/PASS/".to_string()];
    let new_rate = Some(100_000);
    assert_ne!(network, &new_network);
    assert_ne!(peer_fingerprint, &new_fingerprint);
    assert_ne!(user_agent, &new_user_agent);
    assert_ne!(resume_dir, &new_resume_dir);
    assert_ne!(torrent_dir, &new_torrent_dir);
    assert_ne!(allowed_tracker_domains, &new_domains);
    assert_ne!(allowed_tracker_urls, &new_urls);
    assert_ne!(upload_rate_limit, &new_rate);

    use ProfileChangeKind::Identity;
    use ProfileChangeKind::NonIdentity;
    vec![
        (
            "network",
            Identity,
            with(&|p| p.network = new_network.clone()),
        ),
        (
            "peer_fingerprint",
            Identity,
            with(&|p| p.peer_fingerprint = new_fingerprint.clone()),
        ),
        (
            "user_agent",
            Identity,
            with(&|p| p.user_agent = new_user_agent.clone()),
        ),
        (
            "resume_dir",
            NonIdentity,
            with(&|p| p.resume_dir = new_resume_dir.clone()),
        ),
        (
            "torrent_dir",
            NonIdentity,
            with(&|p| p.torrent_dir = new_torrent_dir.clone()),
        ),
        (
            "allowed_tracker_domains",
            NonIdentity,
            with(&|p| p.allowed_tracker_domains = new_domains.clone()),
        ),
        (
            "allowed_tracker_urls",
            NonIdentity,
            with(&|p| p.allowed_tracker_urls = new_urls.clone()),
        ),
        (
            "upload_rate_limit",
            NonIdentity,
            with(&|p| p.upload_rate_limit = new_rate),
        ),
    ]
}

#[test]
fn each_profile_field_changed_alone_is_reported_alone_with_its_class() {
    // Each alone, so none is reported only alongside another.
    let dir = tempdir().unwrap();
    let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    for (key, kind, changed) in each_profile_field_changed_alone(&a.profile[0]) {
        let mut b = a.clone();
        b.profile[0] = changed;
        let d = Config::diff(&a, &b);
        assert_eq!(
            d.profile_changes,
            vec![ProfileChange {
                what: format!("public.{key}"),
                kind,
            }],
            "{key} changed alone",
        );
        assert!(
            !d.is_empty(),
            "{key}: the file changed and the daemon must say so"
        );
        assert!(
            d.non_reloadable_changes.is_empty(),
            "{key} is a profile key, not a top-level one: got {:?}",
            d.non_reloadable_changes,
        );
    }
}

#[test]
fn any_change_inside_the_network_block_is_one_identity_change() {
    // The block is compared as one value so that a field added to
    // `ProfileNetwork` cannot be forgotten. That only holds if every
    // field it already has reaches the comparison, and if switching the
    // variant does too: which tunnel, which port, whether DHT runs.
    use torrentd_engine::ProfileNetwork;
    use torrentd_engine::TrackerDns;
    let dir = tempdir().unwrap();
    let host = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    let mut vpn = host.clone();
    // wg0, port 6881, static, the host's tracker DNS.
    vpn.profile[0].network = vpn_profile().network;
    // `vpn`'s network with one of its fields edited.
    type Edit<'a> = &'a dyn Fn(&mut String, &mut Option<u16>, &mut TrackerDns);
    let vpn_edit = |edit: Edit<'_>| {
        let mut n = vpn.profile[0].network.clone();
        if let ProfileNetwork::Vpn {
            vpn_interface,
            listen_port,
            tracker_dns,
            ..
        } = &mut n
        {
            edit(vpn_interface, listen_port, tracker_dns);
        }
        n
    };

    let edits: Vec<(&str, &Config, ProfileNetwork)> = vec![
        (
            "host listen_interfaces",
            &host,
            ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6899".into(),
                dht: false,
            },
        ),
        (
            "host dht",
            &host,
            ProfileNetwork::Host {
                listen_interfaces: "0.0.0.0:6881".into(),
                dht: true,
            },
        ),
        ("host to vpn", &host, vpn.profile[0].network.clone()),
        (
            "vpn interface",
            &vpn,
            vpn_edit(&|i, _, _| *i = "wg1".into()),
        ),
        (
            "vpn listen_port",
            &vpn,
            vpn_edit(&|_, p, _| *p = Some(51413)),
        ),
        (
            "vpn tracker_dns",
            &vpn,
            vpn_edit(&|_, _, d| *d = TrackerDns::Tunnel { servers: vec![] }),
        ),
        ("vpn to host", &vpn, host.profile[0].network.clone()),
    ];
    for (label, old, network) in edits {
        assert_ne!(old.profile[0].network, network, "{label} must be a change");
        let mut new = old.clone();
        new.profile[0].network = network;
        assert_eq!(
            Config::diff(old, &new).profile_changes,
            vec![ProfileChange {
                what: "public.network".into(),
                kind: ProfileChangeKind::Identity,
            }],
            "{label}",
        );
    }
}

#[test]
fn an_unchanged_profile_set_produces_an_empty_diff() {
    // The other half of "every change is reported": a SIGHUP over a file
    // nobody edited must not warn about an identity change, or the
    // privacy warning stops meaning anything. Profiles are matched by id,
    // so the order they are written in is not a change either.
    let dir = tempdir().unwrap();
    let a = Config::load(&write_cfg(
        dir.path(),
        &two_host_profiles(
            r#"user_agent = "ua/1.0"
upload_rate_limit = 0"#,
            r#"allowed_tracker_domains = ["tracker.example.com"]"#,
        ),
    ))
    .unwrap();
    assert_eq!(a.profile.len(), 2);

    let d = Config::diff(&a, &a.clone());
    assert!(d.profile_changes.is_empty(), "got {:?}", d.profile_changes);
    assert!(d.is_empty());

    let mut reordered = a.clone();
    reordered.profile.reverse();
    let d = Config::diff(&a, &reordered);
    assert!(
        d.profile_changes.is_empty(),
        "reordering profiles changes no account: got {:?}",
        d.profile_changes,
    );
    assert!(d.is_empty());
}

#[test]
fn a_reloadable_top_level_change_does_not_leak_into_profile_changes() {
    // `profile_changes` is what emits Safety Rule 7's warning. A key the
    // reload applies live must reach its own field of `ConfigDiff` and
    // nothing in that list — least of all the top-level
    // `upload_rate_limit`, which shares its name with a profile key.
    let dir = tempdir().unwrap();
    let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    type TopLevelEdit = (&'static str, fn(&mut Config));
    let edits: Vec<TopLevelEdit> = vec![
        ("connections_limit", |c| c.connections_limit = Some(20_000)),
        ("upload_rate_limit", |c| c.upload_rate_limit = Some(100_000)),
        ("max_concurrent_http_announces", |c| {
            c.max_concurrent_http_announces = Some(8)
        }),
        ("aio_threads", |c| c.aio_threads = Some(8)),
        ("enable_lsd", |c| c.enable_lsd = Some(true)),
    ];
    for (key, edit) in edits {
        let mut b = a.clone();
        edit(&mut b);
        let d = Config::diff(&a, &b);
        assert!(
            d.profile_changes.is_empty(),
            "{key} is reloadable and not a profile change: got {:?}",
            d.profile_changes,
        );
        assert!(
            d.non_reloadable_changes.is_empty(),
            "{key}: got {:?}",
            d.non_reloadable_changes,
        );
        assert_eq!(d.reloadable_changes, vec![key], "{key} is still reported");
    }
}

/// `log_filter` is unset by default, loads whatever directives it holds (a
/// reload judges them, as its own stage), and a change to it — deletion
/// included — is a reloadable difference and nothing else.
#[test]
fn log_filter_loads_and_every_change_to_it_is_reloadable() {
    let dir = tempdir().unwrap();
    let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    assert_eq!(a.log_filter, None);
    let b = Config::load(&write_cfg(
        dir.path(),
        &with_top_level("log_filter = \"torrentd_pool::apply=debug,torrentd::vpn=trace\""),
    ))
    .unwrap();
    assert_eq!(
        b.log_filter.as_deref(),
        Some("torrentd_pool::apply=debug,torrentd::vpn=trace")
    );
    Config::load(&write_cfg(
        dir.path(),
        &with_top_level("log_filter = \"torrentd=loud\""),
    ))
    .expect("the load does not judge the directives");
    for (old, new, want) in [
        (&a, &b, Some(b.log_filter.clone())),
        (&b, &a, Some(None)),
        (&b, &b, None),
    ] {
        let d = Config::diff(old, new);
        assert_eq!(d.log_filter, want);
        assert!(d.non_reloadable_changes.is_empty(), "{d:?}");
        assert!(d.reloadable_changes.is_empty(), "{d:?}");
        assert!(d.restart_pending().is_empty(), "{d:?}");
        assert_eq!(d.is_empty(), want.is_none());
    }
}

/// A reload cannot apply any other top-level key, so a file differing in
/// exactly one of them is reported as that key, and is not unchanged.
#[test]
fn each_non_reloadable_top_level_key_changed_alone_is_reported_alone() {
    let dir = tempdir().unwrap();
    let a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    type TopLevelEdit = (&'static str, fn(&mut Config));
    let edits: Vec<TopLevelEdit> = vec![
        ("default_save_path", |c| {
            c.default_save_path = "/data/elsewhere".into()
        }),
        ("resume_dir", |c| c.resume_dir = "/var/lib/other/r".into()),
        ("torrent_dir", |c| c.torrent_dir = "/var/lib/other/t".into()),
        ("file_pool_size", |c| c.file_pool_size = Some(2048)),
        ("unchoke_slots_limit", |c| c.unchoke_slots_limit = Some(128)),
        ("peer_fingerprint", |c| {
            c.peer_fingerprint = Some("-ZZ1000-".into())
        }),
        ("user_agent", |c| c.user_agent = Some("other/1.0".into())),
        ("auth", |c| {
            c.auth = Some(crate::auth::AuthConfig {
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
                session_ttl_secs: 43_200,
                token: vec![],
            })
        }),
        ("allow_unauthenticated", |c| {
            c.allow_unauthenticated = !c.allow_unauthenticated
        }),
        ("http_listen", |c| {
            c.http_listen = HttpListen::Tcp(SocketAddr::from(([127, 0, 0, 1], 9090)))
        }),
        ("http_socket_mode", |c| c.http_socket_mode = Some(0o600)),
        ("http_socket_group", |c| {
            c.http_socket_group = Some("torrentd".into())
        }),
        ("trusted_proxies", |c| {
            c.trusted_proxies = vec!["172.28.0.2".into()]
        }),
        ("allowed_hosts", |c| {
            c.allowed_hosts = vec!["torrentd.example.com".into()]
        }),
        ("registry_path", |c| {
            c.registry_path = Some("/var/lib/torrentd/assignments.json".into())
        }),
        ("vpn_handshake_max_age_secs", |c| {
            c.vpn_handshake_max_age_secs += 60
        }),
        ("shutdown_drain_secs", |c| c.shutdown_drain_secs += 30),
        ("network_kill_switch", |c| {
            c.network_kill_switch = !c.network_kill_switch
        }),
        ("kill_switch_api_interfaces", |c| {
            c.kill_switch_api_interfaces = vec!["eth0".into()]
        }),
        ("kill_switch_dns_servers", |c| {
            c.kill_switch_dns_servers = vec![[10, 43, 0, 10].into()]
        }),
        ("pool", |c| {
            c.pool = Some(PoolConfig {
                roots: vec!["/data/pool".into()],
                library_dir: "/data/library".into(),
                db_path: None,
                max_concurrent_verify: 1,
                import_legacy_registry: false,
                allow_mutations: false,
            })
        }),
    ];
    for (key, edit) in edits {
        let mut b = a.clone();
        edit(&mut b);
        let d = Config::diff(&a, &b);
        assert!(!d.is_empty(), "{key}");
        assert_eq!(d.non_reloadable_changes, vec![key]);
        assert!(d.reloadable_changes.is_empty(), "{key}");
        assert!(d.profile_changes.is_empty(), "{key}");
    }
}

/// Removing one `[[auth.token]]` is the revocation an operator reaches
/// for, and it is an `[auth]` change like any other: reported as
/// needing a restart, and never applied.
#[test]
fn removing_one_static_token_is_a_non_reloadable_auth_change() {
    use crate::auth::AuthConfig;
    use crate::auth::Scope;
    use crate::auth::TokenConfig;
    let token = |name: &str, sha: char| TokenConfig {
        name: name.into(),
        sha256: sha.to_string().repeat(64),
        scopes: vec![Scope::Read],
    };
    let auth = |token: Vec<TokenConfig>| AuthConfig {
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
        session_ttl_secs: 43_200,
        token,
    };
    let dir = tempdir().unwrap();
    let mut a = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    a.auth = Some(auth(vec![token("ci", 'a'), token("scrape", 'b')]));
    let mut b = a.clone();
    b.auth = Some(auth(vec![token("scrape", 'b')]));
    let d = Config::diff(&a, &b);
    assert!(!d.is_empty());
    assert_eq!(d.non_reloadable_changes, vec!["auth"]);
    assert!(d.reloadable_changes.is_empty(), "{d:?}");
    assert!(d.profile_changes.is_empty(), "{d:?}");
}
