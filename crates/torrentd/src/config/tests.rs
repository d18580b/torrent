use tempfile::tempdir;

use super::mounts::check_roots_do_not_alias;
use super::mounts::locate_on_filesystem;
use super::mounts::parse_mountinfo;
use super::*;

fn write_cfg(dir: &Path, body: &str) -> PathBuf {
    let p = dir.join("torrentd.toml");
    fs::write(&p, body).unwrap();
    p
}

/// Top-level keys only. `[[profile]]` is a TOML *table*, so anything a
/// test appends has to land before it — hence the split.
const TOP_LEVEL: &str = r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
log_level = "info"
connections_limit = 10000
allow_unauthenticated = true
"#;

const ONE_HOST_PROFILE: &str = r#"
[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
"#;

/// A minimal valid config.
fn single_session() -> String {
    format!("{TOP_LEVEL}{ONE_HOST_PROFILE}")
}

/// A valid config with `extra` appended to the top-level keys.
fn with_top_level(extra: &str) -> String {
    format!("{TOP_LEVEL}{extra}\n{ONE_HOST_PROFILE}")
}

#[test]
fn a_trusted_proxies_entry_that_trusts_everyone_is_refused() {
    // A `/0` prefix, in any spelling, makes every caller a trusted proxy,
    // and so does a v4-mapped entry whose effective prefix is `/0`.
    let dir = tempdir().unwrap();

    for wide in [
        "0.0.0.0/0",
        "0.0.0.0/00",
        "0.0.0.0/000",
        "0.0.0.0/+0",
        "::/0",
        "::/00",
        "::/000",
        "::/+0",
        // v4-mapped: matched as 0.0.0.0/0, every IPv4 peer.
        "::ffff:0:0/96",
    ] {
        let body = with_top_level(&format!("trusted_proxies = [\"{wide}\"]"));
        // `parse` alone, so the refusal is attributed to `validate`
        // rather than to the file being unreadable.
        let cfg = Config::parse(&write_cfg(dir.path(), &body)).unwrap();
        let err = cfg
            .validate()
            .expect_err("a /0 prefix trusts every peer and must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(wide),
            "the refusal must name the offending entry; got {msg}",
        );

        // And it is not a posture judgement, so the operator subcommands
        // that skip the posture check — `--check-config` among them — get
        // it too. That is the command run before a restart.
        assert!(
            cfg.validate_without_auth_posture().is_err(),
            "{wide} must be refused for operator tools as well",
        );

        // Which means loading the file fails outright.
        assert!(
            Config::load(&write_cfg(dir.path(), &body)).is_err(),
            "{wide} must not produce a daemon that starts",
        );
    }

    // The refusal is about breadth, not about prefixes. A real proxy
    // network still validates, and so does the empty default.
    for ok in ["\"172.28.0.2\"", "\"10.0.0.0/8\"", "\"2001:db8::/32\""] {
        let body = with_top_level(&format!("trusted_proxies = [{ok}]"));
        Config::load(&write_cfg(dir.path(), &body))
            .unwrap_or_else(|e| panic!("{ok} is a legitimate trust set: {e:#}"));
    }
    Config::load(&write_cfg(dir.path(), &single_session()))
        .expect("the empty default is the safe one and must still load");
}

fn host_profile() -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new("public"),
        network: torrentd_engine::ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6881".into(),
            dht: false,
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

fn vpn_profile() -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new("acct_a"),
        network: torrentd_engine::ProfileNetwork::Vpn {
            vpn_type: torrentd_engine::VpnType::Wireguard,
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
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    }
}

#[test]
fn enable_lsd_never_reaches_a_private_profile() {
    // Safety Rule 6: a private profile has LSD off unconditionally, and no
    // config key may turn it on. `enable_lsd` is top-level and reloadable,
    // so without this filter a SIGHUP re-enabled local peer discovery on
    // exactly the sessions that must never have it.
    let diff = ConfigDiff {
        enable_lsd: Some(true),
        ..Default::default()
    };
    assert_eq!(
        diff.to_settings_patch_for(&host_profile())
            .settings
            .enable_lsd,
        Some(true),
        "a host profile still honours the key",
    );
    assert_eq!(
        diff.to_settings_patch_for(&vpn_profile())
            .settings
            .enable_lsd,
        None,
        "a tunnelled profile must not receive it",
    );
}

// -----------------------------------------------------------------
// Effective identity — the uniqueness rule `validate_set` cannot decide.
// -----------------------------------------------------------------

/// Top-level keys, then a vpn profile, then a host profile.
///
/// `top` lands in the daemon-wide block; `host_extra` inside the host
/// profile's table. The ports are distinct so Safety Rule 8 does not fire
/// first and mask what is being asserted.
fn vpn_plus_host(top: &str, host_extra: &str) -> String {
    format!(
        r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
{top}

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint     = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
allowed_tracker_domains = ["t.example"]

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "eth0:6882"
{host_extra}
"#
    )
}

fn refusal(body: &str) -> String {
    let dir = tempdir().unwrap();
    let p = write_cfg(dir.path(), body);
    let err = Config::load(&p).expect_err("this configuration must be refused");
    format!("{err:#}")
}

#[test]
fn a_host_profile_may_not_wear_a_vpn_profiles_identity() {
    // A copied table: one peer-id prefix from the tunnel and the host.
    let msg = refusal(&vpn_plus_host("", r#"peer_fingerprint = "-AA1000-""#));
    assert!(
        msg.contains("peer_fingerprint") && !msg.contains("top-level") && msg.contains("-AA1000-"),
        "got: {msg}",
    );
}

#[test]
fn a_host_profile_may_not_wear_a_vpn_profiles_user_agent() {
    let msg = refusal(&vpn_plus_host("", r#"user_agent = "qBittorrent/5.0.3""#));
    assert!(
        msg.contains("user_agent") && msg.contains("qBittorrent/5.0.3"),
        "got: {msg}",
    );
}

#[test]
fn two_profiles_may_not_share_a_fingerprint() {
    let dir = tempdir().unwrap();
    let body = format!(
        r#"{TOP_LEVEL}
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint     = "-AA1000-"
user_agent           = "ua-a"
allowed_tracker_domains = ["t.example"]

[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg1.conf"
vpn_interface        = "wg1"
listen_port          = 6882
peer_fingerprint     = "-AA1000-"
user_agent           = "ua-b"
allowed_tracker_domains = ["u.example"]
"#
    );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(
        msg.contains("peer_fingerprint") && !msg.contains("top-level"),
        "got: {msg}"
    );
}

#[test]
fn a_host_profile_inheriting_the_top_level_identity_collides_with_a_vpn_profile() {
    // The host profile inherits the values the vpn profile declares.
    let msg = refusal(&vpn_plus_host(
        r#"peer_fingerprint = "-AA1000-"
user_agent = "qBittorrent/5.0.3""#,
        "",
    ));
    assert!(
        msg.contains("-AA1000-"),
        "the colliding value is named, got: {msg}",
    );
    // The key named is the one the *inheriting* profile would have to
    // change — the top-level `peer_fingerprint`, which is what this
    // operator wrote.
    assert!(msg.contains("top-level peer_fingerprint"), "got: {msg}");
}

#[test]
fn a_top_level_user_agent_inherited_by_two_profiles_is_refused() {
    // The user-agent half of the same mechanism, reached on its own: the
    // vpn profile spells out its own fingerprint but takes the top-level
    // user agent, and so does the host profile.
    let msg = refusal(
        r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
user_agent = "qBittorrent/5.0.3"

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg0.conf"
vpn_interface        = "wg0"
listen_port          = 6881
peer_fingerprint     = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
allowed_tracker_domains = ["t.example"]

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "eth0:6882"
"#,
    );
    assert!(msg.contains("user_agent"), "got: {msg}");
}

#[test]
fn two_host_profiles_both_inheriting_the_top_level_identity_are_accepted() {
    // Two host profiles are one host; sharing the default is its use.
    let dir = tempdir().unwrap();
    let body = format!(
        r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
peer_fingerprint = "-XX1234-"
user_agent = "libtorrent/2.0"
{}
"#,
        two_host_profiles("", "")
            .split_once("http_listen = \"127.0.0.1:8080\"")
            .unwrap()
            .1
    );
    let p = write_cfg(dir.path(), &body);
    Config::load(&p).expect(
        "two host profiles that both write nothing are using the top-level default \
             exactly as it is documented",
    );
}

#[test]
fn a_top_level_fingerprint_may_not_be_the_libtorrent_default_either() {
    // An inherited fingerprint announces as a declared one does.
    let msg = refusal(&two_host_profiles_with_top(
        r#"peer_fingerprint = "-LT20C0-""#,
    ));
    assert!(
        msg.contains("uses libtorrent's own client code"),
        "got: {msg}"
    );
    assert!(
        msg.contains("top-level peer_fingerprint "),
        "and named as the key the operator actually wrote, got: {msg}",
    );
}

#[test]
fn a_top_level_fingerprint_must_be_an_eight_character_prefix() {
    // The top-level key and the per-profile one are the same field in the
    // same encoding, so they are held to the same shape. The hex spelling
    // of libtorrent's default is the case that matters most: it was once
    // refused as the default, and it is now refused before that question
    // is asked, because it is not eight bytes at all.
    for bad in ["2d4c54323043302d", "a1b2c3d4e5f60718", "-XX123-"] {
        let msg = refusal(&two_host_profiles_with_top(&format!(
            "peer_fingerprint = {bad:?}"
        )));
        assert!(
            msg.contains("top-level peer_fingerprint")
                && msg.contains(bad)
                && msg.contains("exactly 8 printable ASCII characters"),
            "{bad:?} must be refused as a malformed prefix, got: {msg}",
        );
    }
}

#[test]
fn the_retired_hex_key_is_refused_with_its_replacement_named() {
    // `peer_fingerprint_hex` was documented as sixteen hex characters that
    // nothing decoded. Reading it under either meaning would change the
    // identity a tracker sees without the operator changing anything, and
    // `deny_unknown_fields` alone would say only "unknown field".
    let msg = refusal(&vpn_plus_host(
        "",
        r#"peer_fingerprint_hex = "b7c6d5e4f3a29180""#,
    ));
    assert!(
        msg.contains("\"public\"")
            && msg.contains("peer_fingerprint_hex")
            && msg.contains("no longer read")
            && msg.contains("as peer_fingerprint")
            && msg.contains("-XX1234-"),
        "got: {msg}",
    );
}

#[test]
fn a_top_level_fingerprint_that_is_not_the_default_is_still_accepted() {
    // The other side: the key is a documented default for profiles that
    // set none, so the refusal must reach the default prefix and nothing
    // else. `"-XX1234-"` is the value the shipped sample carries.
    let dir = tempdir().unwrap();
    let p = write_cfg(
        dir.path(),
        &two_host_profiles_with_top(r#"peer_fingerprint = "-XX1234-""#),
    );
    Config::load(&p).expect("the sample's own top-level value must keep loading");
}

/// Two host profiles that declare no identity, under `top`.
fn two_host_profiles_with_top(top: &str) -> String {
    format!(
        r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
{top}
{}
"#,
        two_host_profiles("", "")
            .split_once("http_listen = \"127.0.0.1:8080\"")
            .unwrap()
            .1
    )
}

#[test]
fn the_exemption_does_not_reach_a_profile_that_declares_the_value() {
    // The collision the rule guards is one profile inheriting while
    // another declares — the shape where the file does not show that two
    // sessions share an identity. The exemption must not swallow it.
    let msg = refusal(&vpn_plus_host(
        r#"peer_fingerprint = "-AA1000-"
user_agent = "qBittorrent/5.0.3""#,
        "",
    ));
    assert!(msg.contains("-AA1000-"), "got: {msg}");
}

#[test]
fn an_inherited_collision_names_the_key_the_operator_wrote() {
    // The per-profile and top-level keys share a name. An inherited value
    // is named as the top-level one, so the operator is not sent to a
    // `[[profile]]` table that does not contain the line.
    let msg = refusal(&vpn_plus_host(
        r#"peer_fingerprint = "-AA1000-"
user_agent = "qBittorrent/5.0.3""#,
        "",
    ));
    assert!(
        msg.contains("top-level peer_fingerprint"),
        "the key it names is the one they wrote, got: {msg}",
    );
}

#[test]
fn a_top_level_identity_with_exactly_one_profile_is_still_accepted() {
    // The configuration the top-level default exists for. Refusing the
    // keys outright would close F4 too, and break this.
    let dir = tempdir().unwrap();
    let body = with_top_level(
        r#"peer_fingerprint = "-AA1000-"
user_agent = "qBittorrent/5.0.3""#,
    );
    let p = write_cfg(dir.path(), &body);
    Config::load(&p).expect("one profile inheriting the top-level identity is legal");
}

// -----------------------------------------------------------------
// Effective store directories.
// -----------------------------------------------------------------

/// Two host profiles with `extra_a` / `extra_b` appended to their tables.
fn two_host_profiles(extra_a: &str, extra_b: &str) -> String {
    format!(
        r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id                = "acct_a"
network           = "host"
listen_interfaces = "0.0.0.0:6881"
{extra_a}

[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "eth0:6882"
{extra_b}
"#
    )
}

#[test]
fn an_override_equal_to_another_profiles_derived_resume_dir_is_refused() {
    // F15. `acct_a` names `<base>/public` explicitly; `public` sets no
    // override, so `FsResumeStore::dir_for` derives exactly that path for
    // it. `validate_set` de-duplicates only the explicit overrides against
    // each other and cannot see a derived path, so this validated clean
    // and both sessions then read one store — and on a fresh registry the
    // first-declared profile claims every info-hash it finds there.
    let msg = refusal(&two_host_profiles(
        r#"resume_dir = "/var/lib/torrentd/resume/public""#,
        "",
    ));
    assert!(
        msg.contains("resume_dir") && msg.contains("/var/lib/torrentd/resume/public"),
        "got: {msg}",
    );
}

#[test]
fn an_override_equal_to_another_profiles_derived_torrent_dir_is_refused() {
    let msg = refusal(&two_host_profiles(
        r#"torrent_dir = "/var/lib/torrentd/torrents/public""#,
        "",
    ));
    assert!(
        msg.contains("torrent_dir") && msg.contains("/var/lib/torrentd/torrents/public"),
        "got: {msg}",
    );
}

#[test]
fn two_explicit_overrides_naming_one_resume_dir_are_refused() {
    let msg = refusal(&two_host_profiles(
        r#"resume_dir = "/srv/shared""#,
        r#"resume_dir = "/srv/shared""#,
    ));
    assert!(msg.contains("resume_dir"), "got: {msg}");
}

#[test]
fn an_override_containing_another_profiles_resume_dir_is_accepted() {
    // One profile pointed at the shared root that holds another profile's
    // default subdirectory.
    let dir = tempdir().unwrap();
    let p = write_cfg(
        dir.path(),
        &two_host_profiles(r#"resume_dir = "/var/lib/torrentd/resume""#, ""),
    );
    Config::load(&p).expect(
        "an outer resume_dir containing an inner one is a valid layout, and \
             neither store descends into a subdirectory",
    );
}

#[test]
fn a_contained_profiles_files_are_invisible_to_the_outer_profiles_load_all() {
    // Why containment is allowed: a store scans one level, so the inner
    // profile's `<id>/` directory is never read by the outer one.
    use torrentd_engine::FsResumeStore;
    use torrentd_engine::ProfileId;
    use torrentd_engine::ResumeStore;

    let dir = tempdir().unwrap();
    let outer_dir = dir.path().join("resume");
    let inner_dir = outer_dir.join("acct_a");
    std::fs::create_dir_all(&inner_dir).unwrap();

    let outer_ih = "aa".repeat(20);
    let inner_ih = "bb".repeat(20);
    std::fs::write(outer_dir.join(format!("{outer_ih}.resume")), b"outer").unwrap();
    std::fs::write(inner_dir.join(format!("{inner_ih}.resume")), b"inner").unwrap();

    // `default` overrides to the outer root; `acct_a` derives
    // `<outer>/acct_a` — exactly the contained pair above.
    let store = FsResumeStore::new(outer_dir.clone())
        .with_profile_dir(ProfileId::new("default"), outer_dir.clone());

    let outer = store.load_all(&ProfileId::new("default")).unwrap();
    assert_eq!(
        outer.len(),
        1,
        "the outer profile must load only its own file, got {outer:?}",
    );
    assert_eq!(outer[0].0.to_hex(), outer_ih);

    let inner = store.load_all(&ProfileId::new("acct_a")).unwrap();
    assert_eq!(inner.len(), 1, "and the inner profile loads only its own");
    assert_eq!(inner[0].0.to_hex(), inner_ih);
}

#[test]
fn a_contained_profiles_torrents_are_invisible_to_the_outer_profiles_load_all() {
    // The torrent store's half of the same property.
    use torrentd_engine::FsTorrentStore;
    use torrentd_engine::ProfileId;
    use torrentd_engine::TorrentStore;

    let dir = tempdir().unwrap();
    let outer_dir = dir.path().join("torrents");
    let inner_dir = outer_dir.join("acct_a");
    std::fs::create_dir_all(&inner_dir).unwrap();

    let outer_ih = "aa".repeat(20);
    let inner_ih = "bb".repeat(20);
    std::fs::write(outer_dir.join(format!("{outer_ih}.torrent")), b"outer").unwrap();
    std::fs::write(inner_dir.join(format!("{inner_ih}.torrent")), b"inner").unwrap();

    // `default` overrides to the old root, `acct_a` derives
    // `<outer>/acct_a` inside it: a layout the validator accepts.
    let store = FsTorrentStore::new(outer_dir.clone())
        .with_profile_dir(ProfileId::new("default"), outer_dir.clone());

    let outer = store.load_all(&ProfileId::new("default")).unwrap();
    assert_eq!(
        outer.len(),
        1,
        "the outer profile must load only its own .torrent, got {outer:?}",
    );
    assert_eq!(outer[0].0.to_hex(), outer_ih);

    let inner = store.load_all(&ProfileId::new("acct_a")).unwrap();
    assert_eq!(inner.len(), 1, "and the inner profile loads only its own");
    assert_eq!(inner[0].0.to_hex(), inner_ih);
}

#[test]
fn distinct_derived_store_directories_are_accepted() {
    // The ordinary case, so the new rule cannot pass by refusing
    // everything: neither profile overrides anything and the derived
    // `<base>/<id>` paths differ by construction.
    let dir = tempdir().unwrap();
    let p = write_cfg(dir.path(), &two_host_profiles("", ""));
    Config::load(&p).expect("derived per-profile directories are distinct");
}

// -----------------------------------------------------------------
// The shipped samples.
// -----------------------------------------------------------------

/// A shipped sample config, which the tests below hold to loading.
fn sample(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy")
        .join(name)
}

fn load_sample(name: &str) -> Config {
    let path = sample(name);
    Config::load(&path).unwrap_or_else(|e| panic!("{name} must load and validate: {e:#}"))
}

#[test]
fn the_shipped_sample_loads_and_validates() {
    let cfg = load_sample("torrentd.sample.toml");
    assert_eq!(cfg.profile.len(), 1);
    assert_eq!(cfg.profile[0].id.as_str(), "public");
    assert!(
        !cfg.profile[0].is_vpn(),
        "the shipped sample is a host-only deployment; `vpn check` has to cope with it",
    );
}

#[test]
fn the_multi_account_sample_loads_and_validates() {
    // The case the other sample only describes in comments. A commented
    // block is unreachable by any test and by `--check-config`, which is
    // the whole mechanism: the operator uncomments it and finds out then.
    let cfg = load_sample("torrentd.multi-account.sample.toml");
    assert_eq!(cfg.profile.len(), 3);
    assert_eq!(
        cfg.profile.iter().filter(|p| p.is_vpn()).count(),
        2,
        "two accounts, each with its own tunnel",
    );
    assert!(
        cfg.peer_fingerprint.is_none() && cfg.user_agent.is_none(),
        "no top-level identity for a profile to inherit",
    );
    // It ships the kill switch off because it carries a host profile, and
    // turning it on as written must be refused rather than cut `public`
    // off while it reports itself healthy.
    let mut cfg = cfg;
    cfg.check_boot_rules().unwrap();
    cfg.network_kill_switch = true;
    let msg = format!("{:#}", cfg.check_boot_rules().unwrap_err());
    assert!(msg.contains("public"), "got: {msg}");
}

#[test]
fn the_samples_daemon_wide_keys_are_not_stranded_behind_a_profile_table() {
    // TOML binds any key after a `[[table]]` header to that table, so a
    // daemon-wide key written below the first `[[profile]]` cannot be
    // uncommented: `deny_unknown_fields` rejects it as an unknown
    // `[[profile]]` field, and the message lists the profile keys — which
    // reads as "this key does not exist", about the kill switch the file
    // calls defence-in-depth.
    for name in ["torrentd.sample.toml", "torrentd.multi-account.sample.toml"] {
        let text = fs::read_to_string(sample(name)).unwrap();
        let first_table = text
            .find("\n[[profile]]")
            .expect("every sample configures at least one profile");
        for key in ["vpn_handshake_max_age_secs", "network_kill_switch"] {
            let at = text
                .find(key)
                .unwrap_or_else(|| panic!("{name} should document {key}"));
            assert!(
                at < first_table,
                "{name}: {key} sits below the first [[profile]] header, \
                     where TOML binds it to that table",
            );
        }
    }
}

/// The `"..."` value of a `key = "..."` line, commented or not. `None` for
/// any other line, including a longer key that `key` is a prefix of.
fn sample_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start_matches(['#', ' ']).strip_prefix(key)?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(&rest[..rest.find('"')?])
}

#[test]
fn every_sample_identity_names_a_libtorrent_based_client() {
    // Only the peer-id prefix and the user agent change; the rest of the
    // peer id, the extension handshake and the announces stay
    // libtorrent's. A Transmission identity on that wire is one a tracker
    // can tell is spoofed, so the samples name only clients built on
    // libtorrent, each prefix beside its own client's user agent. The
    // scan covers commented lines too: an example the operator uncomments
    // is never parsed before then.
    const LIBTORRENT_CLIENTS: [(&str, &str); 2] = [("-qB", "qBittorrent/"), ("-DE", "Deluge/")];
    for name in ["torrentd.sample.toml", "torrentd.multi-account.sample.toml"] {
        let text = fs::read_to_string(sample(name)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut seen = 0;
        for (i, line) in lines.iter().enumerate() {
            let Some(fp) = sample_value(line, "peer_fingerprint") else {
                continue;
            };
            seen += 1;
            let (_, agent_prefix) = LIBTORRENT_CLIENTS
                .iter()
                .find(|(prefix, _)| fp.starts_with(prefix))
                .unwrap_or_else(|| {
                    panic!("{name}:{}: {fp:?} is not a libtorrent-based client", i + 1)
                });
            let agent = lines[i + 1..]
                .iter()
                .find_map(|l| sample_value(l, "user_agent"))
                .unwrap_or_else(|| panic!("{name}:{}: {fp:?} has no user_agent", i + 1));
            assert!(
                agent.starts_with(agent_prefix),
                "{name}:{}: {fp:?} beside user agent {agent:?}",
                i + 1,
            );
        }
        assert!(seen > 0, "{name} shows no peer_fingerprint at all");
    }
}

#[test]
fn a_reload_does_not_overwrite_a_per_profile_upload_rate_limit() {
    // `startup.rs` applies a per-profile `upload_rate_limit` over the
    // top-level one at boot. Passing the top-level value through here
    // meant an operator who edited only the top-level key and sent SIGHUP
    // patched every session alike — the override was silently discarded
    // until the next restart, with nothing logged.
    let diff = ConfigDiff {
        upload_rate_limit: Some(2_000_000),
        ..Default::default()
    };
    let mut capped = host_profile();
    capped.upload_rate_limit = Some(100_000);

    assert_eq!(
        diff.to_settings_patch_for(&capped)
            .settings
            .upload_rate_limit,
        None,
        "a profile that set its own must not be patched from the top level",
    );
    assert_eq!(
        diff.to_settings_patch_for(&host_profile())
            .settings
            .upload_rate_limit,
        Some(2_000_000),
        "a profile that set nothing still takes the default; that is what makes it one",
    );
}

#[test]
fn a_per_profile_upload_rate_limit_of_zero_means_unlimited_not_unset() {
    // An explicit 0 is a value: the top-level cap must not override it.
    let diff = ConfigDiff {
        upload_rate_limit: Some(2_000_000),
        ..Default::default()
    };
    let mut uncapped = host_profile();
    uncapped.upload_rate_limit = Some(0);

    assert_eq!(
        diff.to_settings_patch_for(&uncapped)
            .settings
            .upload_rate_limit,
        None,
        "an explicit 0 is a value the profile set, so the reload must not overwrite it",
    );

    // And the two are distinguishable at the type, which is what the boot
    // path keys on.
    assert_ne!(uncapped.upload_rate_limit, host_profile().upload_rate_limit);
    assert_eq!(
        host_profile().upload_rate_limit,
        None,
        "absent stays absent"
    );
}

#[test]
fn an_explicit_zero_upload_rate_limit_round_trips_through_toml() {
    // The distinction has to survive the parser, or the field is `Option`
    // for nothing: `#[serde(default)]` over a `u32` turned a written `0`
    // and an absent key into the same value before it ever reached a
    // guard.
    let dir = tempdir().unwrap();
    let body = two_host_profiles(r#"upload_rate_limit = 0"#, "");
    let p = write_cfg(dir.path(), &body);
    let cfg = Config::load(&p).unwrap();
    assert_eq!(
        cfg.profile[0].upload_rate_limit,
        Some(0),
        "a written 0 is a value",
    );
    assert_eq!(
        cfg.profile[1].upload_rate_limit, None,
        "and an unwritten key is not",
    );
}

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
    let dir = tempdir().unwrap();
    let host = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    let mut vpn = host.clone();
    vpn.profile[0].network = ProfileNetwork::Vpn {
        vpn_type: torrentd_engine::VpnType::Wireguard,
        vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
        vpn_interface: "wg0".into(),
        listen_port: Some(6881),
        port_forward: Default::default(),
        port_forward_gateway: None,
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
            ProfileNetwork::Vpn {
                vpn_type: torrentd_engine::VpnType::Wireguard,
                vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
                vpn_interface: "wg1".into(),
                listen_port: Some(6881),
                port_forward: Default::default(),
                port_forward_gateway: None,
            },
        ),
        (
            "vpn listen_port",
            &vpn,
            ProfileNetwork::Vpn {
                vpn_type: torrentd_engine::VpnType::Wireguard,
                vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
                vpn_interface: "wg0".into(),
                listen_port: Some(51413),
                port_forward: Default::default(),
                port_forward_gateway: None,
            },
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

#[test]
fn parses_one_host_profile() {
    let dir = tempdir().unwrap();
    let p = write_cfg(dir.path(), &single_session());
    let cfg = Config::load(&p).unwrap();
    assert_eq!(cfg.connections_limit, Some(10000));
    assert_eq!(cfg.profile.len(), 1);
    assert_eq!(cfg.profile[0].id.as_str(), "public");
    assert!(!cfg.profile[0].is_vpn());
    assert!(
        !cfg.profile[0].dht_enabled(),
        "dht is off unless the profile writes it",
    );
}

/// The top-level block without the opt-out, for the auth-posture tests.
fn top_level_no_opt_out() -> String {
    TOP_LEVEL.replace("allow_unauthenticated = true\n", "")
}

#[test]
fn an_unauthenticated_config_is_refused_unless_it_says_so() {
    let dir = tempdir().unwrap();
    let body = format!("{}{ONE_HOST_PROFILE}", top_level_no_opt_out());
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("allow_unauthenticated"), "got: {msg}");
    assert!(msg.contains("hash-password"), "the error names the way out");
}

#[test]
fn a_malformed_value_is_reported_before_the_posture() {
    // Shape before policy: each config is wrong in shape and in posture,
    // and the shape is what is reported.
    let dir = tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(root.join("inner")).unwrap();

    let cases = [
        (
            format!(
                "{}aio_threads = 0\n{ONE_HOST_PROFILE}",
                top_level_no_opt_out(),
            ),
            "aio_threads = 0 is out of range",
        ),
        (
            // `[auth]` beside the opt-out is the policy refusal here.
            format!(
                "{TOP_LEVEL}\n[auth]\npassword_hash = \"not-a-phc-string\"\n{ONE_HOST_PROFILE}"
            ),
            "password_hash is not a valid PHC string",
        ),
        (
            format!(
                "{}\n[pool]\nroots = [\"{}\", \"{}\"]\nlibrary_dir = \"{}\"\n{ONE_HOST_PROFILE}",
                top_level_no_opt_out(),
                root.display(),
                root.join("inner").display(),
                dir.path().join("library").display(),
            ),
            "[pool] roots must not nest",
        ),
    ];

    for (body, expected) in cases {
        let msg = refusal(&body);
        assert!(
            msg.contains(expected),
            "the malformed value must be reported before the posture; got: {msg}",
        );
    }
}

#[test]
fn the_opt_out_is_honoured_on_loopback() {
    let dir = tempdir().unwrap();
    let p = write_cfg(dir.path(), &single_session());
    assert!(Config::load(&p).is_ok());
}

#[test]
fn the_opt_out_does_not_extend_to_a_routable_address() {
    // `allow_unauthenticated` is for delegating access control to
    // something in front, not for having none.
    let dir = tempdir().unwrap();
    let body = single_session().replace("127.0.0.1:8080", "0.0.0.0:8080");
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("loopback"), "got: {msg}");
}

#[test]
fn a_loopback_bind_is_loopback_however_it_is_spelled() {
    // `IpAddr::is_loopback` is false for `::ffff:127.0.0.1`, so the
    // literal test refused an address reachable only from the host — and
    // told the operator it was "reachable from the network".
    let dir = tempdir().unwrap();
    for form in ["[::1]:8080", "[::ffff:127.0.0.1]:8080"] {
        let body = single_session().replace("127.0.0.1:8080", form);
        let p = write_cfg(dir.path(), &body);
        assert!(
            Config::load(&p).is_ok(),
            "{form} is loopback and must be accepted",
        );
    }
    // Unwrapping must not soften the check it is inside: the wildcard
    // binds stay refused in both families.
    for form in ["[::]:8080", "0.0.0.0:8080"] {
        let body = single_session().replace("127.0.0.1:8080", form);
        let p = write_cfg(dir.path(), &body);
        let msg = format!("{:#}", Config::load(&p).unwrap_err());
        assert!(
            msg.contains("loopback"),
            "{form} must be refused; got: {msg}"
        );
    }
}

#[test]
fn configured_auth_needs_no_opt_out_and_may_bind_anywhere() {
    let dir = tempdir().unwrap();
    let body = format!(
        "{}{ONE_HOST_PROFILE}\n[auth]\npassword_hash = \"{}\"\n",
        top_level_no_opt_out().replace("127.0.0.1:8080", "0.0.0.0:8080"),
        crate::auth::hash_password("hunter2").unwrap(),
    );
    let p = write_cfg(dir.path(), &body);
    assert!(Config::load(&p).is_ok());
}

#[test]
fn the_opt_out_alongside_configured_auth_is_refused() {
    // The property: a config states one posture. `[auth]` plus the opt-out
    // states two, and the flag is the one a reader checks — so a daemon
    // that authenticates ships a config file saying it does not.
    let dir = tempdir().unwrap();
    let body = format!(
        "{TOP_LEVEL}{ONE_HOST_PROFILE}\n[auth]\npassword_hash = \"{}\"\n",
        crate::auth::hash_password("hunter2").unwrap(),
    );
    assert!(
        body.contains("allow_unauthenticated = true"),
        "TOP_LEVEL carries the opt-out; this test is about it being there",
    );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("allow_unauthenticated"), "got: {msg}");
    assert!(
        msg.contains("Delete"),
        "the error names the edit that fixes it; got: {msg}",
    );
}

/// `TOP_LEVEL`, with `allowed_hosts = [<hosts>]` after the opt-out.
fn top_level_allowing(hosts: &str) -> String {
    TOP_LEVEL.replace(
        "allow_unauthenticated = true\n",
        &format!("allow_unauthenticated = true\nallowed_hosts = [{hosts}]\n"),
    )
}

#[test]
fn allowed_hosts_takes_bare_names_and_addresses() {
    let dir = tempdir().unwrap();
    let body = format!(
        "{}{ONE_HOST_PROFILE}",
        top_level_allowing(r#""torrentd.example.com", "192.0.2.7", "[2001:db8::1]""#),
    );
    let cfg = Config::load(&write_cfg(dir.path(), &body)).unwrap();
    assert_eq!(cfg.allowed_hosts.len(), 3);

    for entry in [
        r#""https://torrentd.example.com""#,
        r#""torrentd.example.com:443""#,
        r#""torrentd.example.com/v1""#,
        r#""""#,
    ] {
        let msg = refusal(&format!("{}{ONE_HOST_PROFILE}", top_level_allowing(entry)));
        assert!(msg.contains("allowed_hosts"), "{entry}: got: {msg}");
    }
}

#[test]
fn allowed_hosts_alongside_configured_auth_is_refused() {
    // Nothing reads it there, and left in place it reads as though the
    // daemon confined its Host names.
    let dir = tempdir().unwrap();
    let body = format!(
        "{}{ONE_HOST_PROFILE}\n[auth]\npassword_hash = \"{}\"\n",
        top_level_no_opt_out().replace(
            "http_listen",
            "allowed_hosts = [\"torrentd.example.com\"]\nhttp_listen"
        ),
        crate::auth::hash_password("hunter2").unwrap(),
    );
    assert!(body.contains("allowed_hosts = ["));
    let msg = format!(
        "{:#}",
        Config::load(&write_cfg(dir.path(), &body)).unwrap_err()
    );
    assert!(msg.contains("allowed_hosts"), "got: {msg}");
    assert!(msg.contains("Delete"), "got: {msg}");
}

#[test]
fn http_listen_defaults_to_loopback() {
    // The README claimed this default for a long time while the key was
    // in fact required; the claim is now true.
    let dir = tempdir().unwrap();
    let top = TOP_LEVEL.replace("http_listen = \"127.0.0.1:8080\"\n", "");
    let p = write_cfg(dir.path(), &format!("{top}{ONE_HOST_PROFILE}"));
    let cfg = Config::load(&p).unwrap();
    let addr = cfg.http_listen.tcp().expect("a TCP address by default");
    assert!(addr.ip().is_loopback());
    assert_eq!(addr.port(), 8080);
}

#[test]
fn a_unix_http_listen_parses_and_round_trips() {
    let listen: HttpListen = "unix:/run/torrentd/api.sock".parse().unwrap();
    assert_eq!(listen, HttpListen::Unix("/run/torrentd/api.sock".into()));
    assert_eq!(listen.to_string(), "unix:/run/torrentd/api.sock");
    assert_eq!(listen.tcp(), None);
    let tcp: HttpListen = "127.0.0.1:8080".parse().unwrap();
    assert_eq!(tcp.to_string(), "127.0.0.1:8080");

    for bad in [
        "unix:run/api.sock",
        "unix:",
        "localhost:8080",
        "unix:/",
        &format!("unix:/{}", "a".repeat(MAX_UNIX_PATH_BYTES)),
    ] {
        assert!(bad.parse::<HttpListen>().is_err(), "{bad} must be refused");
    }
}

/// Validation holds a socket path to the length of the staging path it is
/// bound at first, so a path `--check-config` accepts is one boot binds.
#[test]
fn a_unix_path_is_refused_when_its_staging_path_would_not_bind() {
    let dir = tempdir().unwrap();
    let base = dir.path().as_os_str().len() + 1;
    let accepted = (1..=MAX_UNIX_PATH_BYTES - base)
        .rev()
        .map(|n| dir.path().join("a".repeat(n)))
        .find(|p| {
            format!("unix:{}", p.display())
                .parse::<HttpListen>()
                .is_ok()
        })
        .expect("some path in a temp dir is short enough");
    // The longest accepted path binds, and one byte more is refused.
    let socket = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { crate::api_socket::bind(&accepted, 0o600, None).map(drop) });
    socket.unwrap_or_else(|e| panic!("{} bytes: {e:#}", accepted.as_os_str().len()));
    let longer = format!("unix:{}a", accepted.display());
    let msg = longer.parse::<HttpListen>().unwrap_err();
    assert!(msg.contains("staging path"), "{msg}");
    // Without the staging allowance, a path the kernel accepts as is
    // would have passed and failed at boot.
    assert!(longer.len() - "unix:".len() <= MAX_UNIX_PATH_BYTES);
}

/// `TOP_LEVEL` with `http_listen` replaced by `listen`, and `extra` keys
/// after it, plus one host profile.
fn with_listen(dir: &Path, listen: &str, extra: &str) -> anyhow::Result<Config> {
    let top = TOP_LEVEL.replace(
        "http_listen = \"127.0.0.1:8080\"\n",
        &format!("http_listen = \"{listen}\"\n{extra}"),
    );
    Config::load(&write_cfg(dir, &format!("{top}{ONE_HOST_PROFILE}")))
}

#[test]
fn a_unix_socket_is_local_enough_for_allow_unauthenticated_unless_everyone_may_connect() {
    let dir = tempdir().unwrap();
    assert!(TOP_LEVEL.contains("allow_unauthenticated = true"));
    let cfg = with_listen(dir.path(), "unix:/run/torrentd/api.sock", "").unwrap();
    assert_eq!(cfg.http_socket_mode(), DEFAULT_HTTP_SOCKET_MODE);
    with_listen(
        dir.path(),
        "unix:/run/torrentd/api.sock",
        "http_socket_mode = 0o660\nhttp_socket_group = \"torrentd\"\n",
    )
    .unwrap();

    let msg = format!(
        "{:#}",
        with_listen(
            dir.path(),
            "unix:/run/torrentd/api.sock",
            "http_socket_mode = 0o666\n"
        )
        .unwrap_err()
    );
    assert!(msg.contains("every user on the host"), "got: {msg}");
}

#[test]
fn socket_keys_are_refused_beside_a_tcp_listen_and_checked_beside_a_socket() {
    let dir = tempdir().unwrap();
    for extra in [
        "http_socket_mode = 0o660\n",
        "http_socket_group = \"torrentd\"\n",
    ] {
        let msg = format!(
            "{:#}",
            with_listen(dir.path(), "127.0.0.1:8080", extra).unwrap_err()
        );
        assert!(
            msg.contains("applies only to a unix socket"),
            "{extra}: {msg}"
        );
    }
    for extra in ["http_socket_mode = 0o4660\n", "http_socket_group = \" \"\n"] {
        assert!(
            with_listen(dir.path(), "unix:/run/torrentd/api.sock", extra).is_err(),
            "{extra} must be refused"
        );
    }
}

#[test]
fn a_config_with_no_profiles_is_refused() {
    let dir = tempdir().unwrap();
    let p = write_cfg(dir.path(), TOP_LEVEL);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("[[profile]]"), "got: {msg}");
}

#[test]
fn a_key_from_the_other_posture_is_refused() {
    // Not an unknown key — a key that would never be read. Flattening the
    // network enum into the table would have accepted this silently.
    let dir = tempdir().unwrap();
    let body = format!(
        "{TOP_LEVEL}\n[[profile]]\nid = \"public\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\nvpn_interface = \"wg0\"\n"
    );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("vpn_interface"), "got: {msg}");
}

#[test]
fn dht_false_on_a_vpn_profile_is_refused_like_every_other_wrong_posture_key() {
    // `dht` was a `#[serde(default)] bool`, so `dht = false` was
    // indistinguishable from absent and slipped through — alone among the
    // wrong-posture keys, every other one being an `Option` rejected on
    // presence. It reads to an operator as a setting that took, on the
    // posture where Safety Rule 6 says no key can reach it at all.
    let dir = tempdir().unwrap();
    let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nlisten_port = 6891\n\
             peer_fingerprint = \"-AA1000-\"\nuser_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n\
             dht = false\n"
        );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("dht"), "got: {msg}");
}

#[test]
fn a_listen_port_under_natpmp_is_refused_rather_than_ignored() {
    // The gateway assigns the port at runtime and renews its lease, so
    // nothing binds the configured one and Safety Rule 8 never enters it
    // into the uniqueness set — and `/v1/profiles` then reports it back
    // under a field documented as `null` for natpmp profiles. Accepting
    // and ignoring a key is the shape every other rule in this conversion
    // exists to refuse.
    let dir = tempdir().unwrap();
    let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nport_forward = \"natpmp\"\nlisten_port = 6891\n\
             peer_fingerprint = \"-AA1000-\"\nuser_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
        );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(
        msg.contains("listen_port") && msg.contains("natpmp"),
        "got: {msg}",
    );
}

#[test]
fn a_natpmp_profile_without_a_listen_port_is_accepted() {
    // The shape the rule above exists to leave alone.
    let dir = tempdir().unwrap();
    let body = format!(
            "{TOP_LEVEL}\n[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\n\
             vpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg0.conf\"\n\
             vpn_interface = \"wg0\"\nport_forward = \"natpmp\"\n\
             peer_fingerprint = \"-AA1000-\"\nuser_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
        );
    let p = write_cfg(dir.path(), &body);
    Config::load(&p).expect("a natpmp profile names no port; that is the point");
}

#[test]
fn a_profile_id_that_is_not_a_path_component_is_refused_at_deserialization() {
    // The charset rule as a property of the *type*, not of having called
    // `validate_set`. The config file is not the only door a `ProfileId`
    // comes through: `profile_assignments.json` deserializes straight into
    // one and never passes the validator, so a hand-edited registry
    // naming `../..` reached `dir_for` and was joined onto a path with
    // nothing in between. Deserializing the bare value is that door.
    for bad in ["../..", "/etc", "a/b", "acct.a", "", &"x".repeat(65)] {
        let err = serde_json::from_value::<ProfileId>(serde_json::json!(bad))
            .err()
            .unwrap_or_else(|| panic!("id {bad:?} was accepted by Deserialize"));
        assert!(
            err.to_string().contains("[A-Za-z0-9_-]"),
            "id {bad:?} gave: {err}",
        );
    }
    for good in ["default", "acct_a", "acct-b", "Public2", &"a".repeat(64)] {
        serde_json::from_value::<ProfileId>(serde_json::json!(good))
            .unwrap_or_else(|e| panic!("id {good:?} was refused: {e}"));
    }
}

#[test]
fn a_registry_file_naming_an_escaping_profile_id_does_not_load() {
    // The file the rule above exists for. `AssignmentRegistry`'s import
    // maps its JSON values straight into `ProfileId`.
    let dir = tempdir().unwrap();
    let path = dir.path().join("profile_assignments.json");
    fs::write(
        &path,
        r#"{"0101010101010101010101010101010101010101":"../../etc"}"#,
    )
    .unwrap();
    let import = JsonImport {
        path: path.clone(),
        pre_profiles: false,
    };
    assert!(
        crate::registry::AssignmentRegistry::open(dir.path().join("registry.db"), Some(import))
            .is_err(),
        "a registry naming an id that escapes its directory must not load",
    );
    assert!(path.exists(), "and a refused import moves nothing aside");
}

#[test]
fn the_registry_is_a_database_in_the_state_dir_importing_the_json_beside_it() {
    let dir = tempdir().unwrap();
    let mut cfg = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    cfg.resume_dir = dir.path().join("resume");
    let state = cfg.state_dir();
    assert_eq!(state, dir.path());
    assert_eq!(cfg.registry_path(), state.join("registry.db"));
    assert_eq!(
        cfg.registry_import(),
        None,
        "nothing on disk, nothing to import"
    );

    fs::write(state.join("slot_assignments.json"), "{}").unwrap();
    assert_eq!(
        cfg.registry_import(),
        Some(JsonImport {
            path: state.join("slot_assignments.json"),
            pre_profiles: true,
        }),
        "a slot-era deployment's only file",
    );

    fs::write(state.join("profile_assignments.json"), "{}").unwrap();
    assert_eq!(
        cfg.registry_import(),
        Some(JsonImport {
            path: state.join("profile_assignments.json"),
            pre_profiles: false,
        }),
        "the current JSON file wins; the slot file beside it is a rollback copy",
    );

    fs::remove_file(state.join("profile_assignments.json")).unwrap();
    fs::write(cfg.registry_path(), b"").unwrap();
    assert_eq!(
        cfg.registry_import(),
        None,
        "once the database exists, a slot file is never read again",
    );
}

#[test]
fn a_configured_json_registry_path_is_imported_into_a_database_beside_it() {
    // A config written before the database named the JSON file here.
    // Opening that as SQLite refuses the boot; reading it as the import
    // keeps those configs working.
    let dir = tempdir().unwrap();
    let mut cfg = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    cfg.resume_dir = dir.path().join("resume");
    let json = dir.path().join("assignments.json");
    cfg.registry_path = Some(json.clone());
    assert_eq!(cfg.registry_path(), dir.path().join("assignments.db"));
    assert_eq!(cfg.registry_import(), None);
    fs::write(&json, "{}").unwrap();
    assert_eq!(
        cfg.registry_import(),
        Some(JsonImport {
            path: json,
            pre_profiles: false,
        }),
    );

    let db = dir.path().join("elsewhere.db");
    cfg.registry_path = Some(db.clone());
    assert_eq!(cfg.registry_path(), db);
    fs::write(cfg.state_dir().join("profile_assignments.json"), "{}").unwrap();
    assert_eq!(
        cfg.registry_import(),
        None,
        "a configured database path imports nothing from the state dir",
    );
}

#[test]
fn check_config_refuses_a_kill_switch_with_no_tunnel_to_confine_egress_to() {
    let dir = tempdir().unwrap();
    let p = write_cfg(dir.path(), &with_top_level("network_kill_switch = true"));
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(
        msg.contains("network_kill_switch") && msg.contains("vpn"),
        "got: {msg}",
    );
}

#[test]
fn a_boot_rule_is_reported_before_the_authentication_posture() {
    let dir = tempdir().unwrap();

    let stated = write_cfg(dir.path(), &with_top_level("network_kill_switch = true"));
    let msg = format!("{:#}", Config::load(&stated).unwrap_err());
    assert!(
        msg.contains("network_kill_switch"),
        "the posture is stated, so the boot rule is what is left; got: {msg}",
    );

    // The same file with the opt-out line removed, so no posture is
    // stated and both refusals apply.
    let body =
        with_top_level("network_kill_switch = true").replace("allow_unauthenticated = true\n", "");
    assert!(!body.contains("allow_unauthenticated"));
    let sub = dir.path().join("b");
    fs::create_dir_all(&sub).unwrap();
    let unstated = write_cfg(&sub, &body);
    let msg = format!("{:#}", Config::load(&unstated).unwrap_err());
    assert!(
        msg.contains("network_kill_switch"),
        "shape before policy: the kill switch names something the operator \
             must physically change, and it is reported first; got: {msg}",
    );
}

#[test]
fn an_operator_subcommand_gets_the_boot_rules_too() {
    // The property: the exemption `load_for_operator_tool` carries is from
    // the *posture* check and nothing else. A boot rule that is a pure
    // function of the file is not about serving, so a subcommand is held
    // to it — demonstrated before this change by `pool status` running
    // happily against a config `--check-config` refuses.
    let dir = tempdir().unwrap();
    let p = write_cfg(dir.path(), &with_top_level("network_kill_switch = true"));
    let msg = format!("{:#}", Config::load_for_operator_tool(&p).unwrap_err());
    assert!(
        msg.contains("network_kill_switch") && msg.contains("vpn"),
        "got: {msg}",
    );
}

/// `openvpn` runs under the daemon's uid, so the kill switch drops its
/// connection to the provider; the combination is refused at load, and a
/// WireGuard-only set with the kill switch is not.
#[test]
fn the_kill_switch_is_refused_beside_an_openvpn_profile() {
    let dir = tempdir().unwrap();
    let wg = "[[profile]]\nid = \"acct_a\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
                  vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
                  listen_port = 6891\npeer_fingerprint = \"-AA1000-\"\n\
                  user_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n";
    let ovpn = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"openvpn\"\n\
                    vpn_config = \"/etc/openvpn/acct_b.conf\"\nvpn_interface = \"tun-b\"\n\
                    listen_port = 6892\npeer_fingerprint = \"-BB1000-\"\n\
                    user_agent = \"ua-b\"\nallowed_tracker_domains = [\"u.example\"]\n";

    let body = format!("{TOP_LEVEL}\nnetwork_kill_switch = true\n\n{wg}\n{ovpn}");
    let msg = format!(
        "{:#}",
        Config::load(&write_cfg(dir.path(), &body)).unwrap_err()
    );
    assert!(
        msg.contains("OpenVPN profile") && msg.contains("acct_b"),
        "got: {msg}"
    );

    let body = format!("{TOP_LEVEL}\n{wg}\n{ovpn}");
    Config::load(&write_cfg(dir.path(), &body))
        .expect("an OpenVPN profile without the kill switch is accepted");
}

/// Issue 166: two accounts on one tracker. The domain lists alone cannot
/// tell them apart, so the load — and with it `--check-config` and a
/// reload — refuses them until each binds its account's announce URL, and
/// the refusal never echoes a passkey.
#[test]
fn two_accounts_on_one_tracker_are_refused_until_each_binds_its_passkey() {
    let dir = tempdir().unwrap();
    let account = |id: &str, n: u8, extra: &str| {
        format!(
            "[[profile]]\nid = \"{id}\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
                 vpn_config = \"/etc/wireguard/wg{n}.conf\"\nvpn_interface = \"wg{n}\"\n\
                 listen_port = 689{n}\npeer_fingerprint = \"-AA100{n}-\"\n\
                 user_agent = \"ua-{n}\"\nallowed_tracker_domains = [\"tracker.example.com\"]\n\
                 {extra}\n"
        )
    };
    let load = |a: &str, b: &str| {
        let body = format!(
            "{TOP_LEVEL}\n{}\n{}",
            account("acct_a", 1, a),
            account("acct_b", 2, b)
        );
        Config::load(&write_cfg(dir.path(), &body)).map_err(|e| format!("{e:#}"))
    };
    let msg = load("", "").unwrap_err();
    assert!(
        msg.contains("acct_a") && msg.contains("acct_b") && msg.contains("allowed_tracker_urls"),
        "got: {msg}"
    );
    let a = r#"allowed_tracker_urls = ["https://tracker.example.com/PASSKEY-A/"]"#;
    let b = r#"allowed_tracker_urls = ["https://tracker.example.com/PASSKEY-B/"]"#;
    load(a, "").unwrap_err();
    load(a, b).expect("two accounts bound to their own passkeys are accepted");
    let msg = load(a, a.replace("PASSKEY-A", "PASSKEY-A/x").as_str()).unwrap_err();
    assert!(
        msg.contains("overlap") && !msg.contains("PASSKEY"),
        "got: {msg}"
    );
    let msg = load(
        a,
        r#"allowed_tracker_urls = ["tracker.example.com/PASSKEY-B/"]"#,
    )
    .unwrap_err();
    assert!(
        msg.contains("allowed_tracker_urls[0]") && !msg.contains("PASSKEY"),
        "got: {msg}"
    );
}

#[test]
fn a_kill_switch_with_a_vpn_profile_passes_the_pre_flight() {
    let dir = tempdir().unwrap();
    let body = format!(
        "{TOP_LEVEL}\nnetwork_kill_switch = true\n\n[[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
             listen_port = 6891\npeer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
    );
    let p = write_cfg(dir.path(), &body);
    // `Config::load` runs the boot rules, so loading is the pre-flight;
    // what it loaded is the tunnelled profile the file describes.
    let cfg = Config::load(&p).unwrap();
    assert!(cfg.network_kill_switch);
    assert_eq!(cfg.profile.len(), 1);
    let profile = &cfg.profile[0];
    assert_eq!(profile.id.as_str(), "acct_a");
    assert_eq!(
        profile.network,
        torrentd_engine::ProfileNetwork::Vpn {
            vpn_type: torrentd_engine::VpnType::Wireguard,
            vpn_config: "/etc/wireguard/wg0.conf".into(),
            vpn_interface: "wg0".into(),
            listen_port: Some(6891),
            port_forward: torrentd_engine::PortForwardMode::Static,
            port_forward_gateway: None,
        },
    );
    assert_eq!(profile.peer_fingerprint.as_deref(), Some("-AA1000-"));
    assert_eq!(profile.user_agent.as_deref(), Some("ua-a"));
    assert_eq!(profile.allowed_tracker_domains, vec!["t.example"]);
}

#[test]
fn a_kill_switch_beside_a_host_profile_is_refused() {
    // The ruleset matches the daemon's uid and admits only the tunnel
    // interfaces, so a host profile under it sends nothing at all while
    // it stays Active and `/healthz` answers 200.
    //
    // Boot rules run inside `Config::validate`, so this is a refusal of
    // `Config::load` itself and reaches `--check-config` with the rest.
    let dir = tempdir().unwrap();
    let body = format!(
        "{TOP_LEVEL}\nnetwork_kill_switch = true\n\n[[profile]]\nid = \"public\"\n\
             network = \"host\"\nlisten_interfaces = \"eth0:6881\"\n\n\
             [[profile]]\nid = \"acct_a\"\n\
             network = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg0.conf\"\nvpn_interface = \"wg0\"\n\
             listen_port = 6891\npeer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\nallowed_tracker_domains = [\"t.example\"]\n"
    );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(
        msg.contains("network_kill_switch") && msg.contains("public"),
        "got: {msg}",
    );
}

#[test]
fn a_typo_in_a_profile_table_is_still_fatal() {
    // The property `deny_unknown_fields` gives the rest of the config, kept
    // for `[[profile]]` by parsing a flat shape and converting.
    let dir = tempdir().unwrap();
    let body = format!(
        "{TOP_LEVEL}\n[[profile]]\nid = \"public\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\nlisten_interface = \"typo\"\n"
    );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("listen_interface"), "got: {msg}");
}

#[test]
fn unknown_key_is_fatal() {
    let dir = tempdir().unwrap();
    let bad = with_top_level("unknown_setting = 42");
    let p = write_cfg(dir.path(), &bad);
    let err = Config::load(&p).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("unknown_setting"), "got: {msg}");
}

#[test]
fn pool_mutations_are_off_unless_asked_for() {
    // The daemon can move and delete inside its managed roots. An operator
    // who only wanted an index should never be one request away from that,
    // so the default has to stay false — asserted here because a stray
    // `#[serde(default = "...true")]` would be silent otherwise.
    let dir = tempdir().unwrap();
    let body = format!(
        "{TOP_LEVEL}{ONE_HOST_PROFILE}\n[pool]\nroots = [\"/data/torrents\"]\n\
             library_dir = \"/var/lib/torrentd/library\"\n"
    );
    let p = write_cfg(dir.path(), &body);
    let cfg = Config::load(&p).unwrap();
    assert!(!cfg.pool.as_ref().unwrap().allow_mutations);

    let on = body + "allow_mutations = true\n";
    let p = write_cfg(dir.path(), &on);
    assert!(Config::load(&p).unwrap().pool.unwrap().allow_mutations);
}

#[test]
fn daemon_state_inside_a_managed_root_is_rejected() {
    // Nothing in the library claims the torrent library or the resume
    // store, so under a managed root they are orphans by definition and
    // `delete_orphans` over that root would erase them.
    let dir = tempdir().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(&root).unwrap();
    let body = format!(
        r#"
default_save_path = "{r}"
resume_dir = "{r}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"

[pool]
roots = ["{r}"]
library_dir = "{d}/library"
"#,
        r = root.display(),
        d = dir.path().display(),
    );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("resume_dir"), "got: {msg}");
    assert!(msg.contains("inside the managed root"), "got: {msg}");
}

/// A config whose top-level state is outside the root `dir/pool`, with
/// one profile carrying `override_line` (a store-directory override).
fn profile_override_under_pool(dir: &Path, override_line: &str) -> String {
    let root = dir.join("pool");
    std::fs::create_dir_all(&root).unwrap();
    format!(
        r#"
default_save_path = "{r}"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
{override_line}

[pool]
roots = ["{r}"]
library_dir = "{d}/library"
"#,
        r = root.display(),
        d = dir.display(),
    )
}

#[test]
fn profile_resume_dir_inside_a_managed_root_is_rejected() {
    // The top-level stores are outside the root, but a profile's own
    // resume_dir override is not: its resume files would be orphans.
    let dir = tempdir().unwrap();
    let line = format!(
        "resume_dir = \"{}/pool/.acct_b/resume\"",
        dir.path().display()
    );
    let p = write_cfg(dir.path(), &profile_override_under_pool(dir.path(), &line));
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(
        msg.contains("[[profile]] id = \"public\" resume_dir"),
        "got: {msg}"
    );
    assert!(msg.contains("inside the managed root"), "got: {msg}");
}

#[test]
fn profile_torrent_dir_inside_a_managed_root_is_rejected() {
    let dir = tempdir().unwrap();
    let line = format!(
        "torrent_dir = \"{}/pool/.acct_b/torrents\"",
        dir.path().display()
    );
    let p = write_cfg(dir.path(), &profile_override_under_pool(dir.path(), &line));
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(
        msg.contains("[[profile]] id = \"public\" torrent_dir"),
        "got: {msg}"
    );
    assert!(msg.contains("inside the managed root"), "got: {msg}");
}

#[test]
fn profile_store_dirs_outside_every_managed_root_are_accepted() {
    // The control for the two tests above: the same config, with the
    // overrides pointing outside the root, loads.
    let dir = tempdir().unwrap();
    let line = format!(
        "resume_dir = \"{d}/acct_b/resume\"\ntorrent_dir = \"{d}/acct_b/torrents\"",
        d = dir.path().display()
    );
    let p = write_cfg(dir.path(), &profile_override_under_pool(dir.path(), &line));
    Config::load(&p).expect("profile stores outside the root are allowed");
}

#[test]
fn roots_that_nest_through_a_symlink_are_rejected() {
    let dir = tempdir().unwrap();
    let real = dir.path().join("pool");
    std::fs::create_dir_all(real.join("inner")).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let body = format!(
        r#"
default_save_path = "{d}/data"
resume_dir = "{d}/resume"
torrent_dir = "{d}/torrents"
http_listen = "127.0.0.1:8080"
allow_unauthenticated = true

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"

[pool]
roots = ["{r}", "{a}/inner"]
library_dir = "{d}/library"
"#,
        d = dir.path().display(),
        r = real.display(),
        a = alias.display(),
    );
    let p = write_cfg(dir.path(), &body);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("must not nest"), "got: {msg}");
}

/// A root whose `(st_dev, st_ino)` is an ancestor of another root is the
/// same tree, whatever its path. A bind mount needs privileges a test
/// lacks, so an uncanonicalised symlink stands in for the second path:
/// `metadata` follows it to the ancestor's identity just as it would see
/// through a bind mount.
#[test]
fn a_root_that_is_another_roots_ancestor_by_identity_is_refused() {
    let dir = tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("inner")).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&tree, &alias).unwrap();

    let msg = check_roots_do_not_alias(&[tree.join("inner"), alias.clone()], None)
        .unwrap_err()
        .to_string();
    assert!(msg.contains("alias the same files"), "got: {msg}");
    let msg = check_roots_do_not_alias(&[alias, tree.join("inner")], None)
        .unwrap_err()
        .to_string();
    assert!(msg.contains("alias the same files"), "got: {msg}");

    // Siblings share an ancestor, which is not an alias.
    std::fs::create_dir_all(tree.join("other")).unwrap();
    check_roots_do_not_alias(&[tree.join("inner"), tree.join("other")], None)
        .expect("sibling roots are allowed");
}

/// `/data/b` is a bind mount of `/srv/a`, a descendant of the root `/srv`:
/// no ancestor of either root has the other's identity, and only the
/// mount table relates them.
#[test]
fn a_bind_mount_of_a_directory_inside_another_root_is_refused() {
    let mountinfo = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 8:1 /srv/a /data/b rw,relatime shared:1 - ext4 /dev/sda1 rw
41 22 0:50 / /mnt/usb rw,relatime shared:9 - vfat /dev/sdb1 rw
";
    let roots = |a: &str, b: &str| [PathBuf::from(a), PathBuf::from(b)];
    let msg = check_roots_do_not_alias(&roots("/srv", "/data/b"), Some(mountinfo))
        .unwrap_err()
        .to_string();
    assert!(msg.contains("alias the same files"), "got: {msg}");
    assert!(msg.contains("/srv/a"), "names the filesystem path: {msg}");
    check_roots_do_not_alias(&roots("/data/b/x", "/srv/a"), Some(mountinfo))
        .expect_err("a root inside the bind mount nests in the other");

    // A sibling of the bound directory, and another device, are distinct.
    check_roots_do_not_alias(&roots("/srv/c", "/data/b"), Some(mountinfo))
        .expect("siblings on one filesystem are allowed");
    check_roots_do_not_alias(&roots("/mnt/usb/media", "/media"), Some(mountinfo))
        .expect("roots on different devices are allowed");
}

#[test]
fn mountinfo_paths_are_unescaped_and_the_deepest_mount_wins() {
    let mountinfo = "\
22 1 8:1 / / rw - ext4 /dev/sda1 rw
40 22 8:1 /my\\040disk /mnt/a\\040b rw - ext4 /dev/sda1 rw
41 40 0:60 / /mnt/a\\040b/over rw - tmpfs tmpfs rw
";
    let mounts = parse_mountinfo(mountinfo);
    let (dev, fs_path) = locate_on_filesystem(&mounts, Path::new("/mnt/a b/x")).unwrap();
    assert_eq!((dev, fs_path), ("8:1", PathBuf::from("/my disk/x")));
    let (dev, fs_path) = locate_on_filesystem(&mounts, Path::new("/mnt/a b/over/y")).unwrap();
    assert_eq!((dev, fs_path), ("0:60", PathBuf::from("/y")));
    check_roots_do_not_alias(
        &[PathBuf::from("/my disk"), PathBuf::from("/mnt/a b/x")],
        Some(mountinfo),
    )
    .expect_err("the escaped bind mount is seen through");
}

/// The real mount table, with two sibling roots, refuses nothing.
#[test]
fn sibling_roots_pass_against_this_hosts_mount_table() {
    let dir = tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok();
    let roots = [a.canonicalize().unwrap(), b.canonicalize().unwrap()];
    check_roots_do_not_alias(&roots, mountinfo.as_deref()).expect("siblings are allowed");
}

#[test]
fn out_of_range_numbers_are_rejected_at_startup() {
    let dir = tempdir().unwrap();
    let bad = with_top_level("aio_threads = 0");
    let p = write_cfg(dir.path(), &bad);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("aio_threads"), "got: {msg}");
    assert!(msg.contains("out of range"), "got: {msg}");
}

#[test]
fn upload_rate_limit_is_bounded_by_what_libtorrent_can_carry() {
    let dir = tempdir().unwrap();
    let at_bound = with_top_level(&format!("upload_rate_limit = {}", i32::MAX));
    let p = write_cfg(dir.path(), &at_bound);
    Config::load(&p).expect("i32::MAX fits libtorrent's int setting");

    let past_bound = with_top_level(&format!("upload_rate_limit = {}", i32::MAX as u32 + 1));
    let p = write_cfg(dir.path(), &past_bound);
    let msg = format!("{:#}", Config::load(&p).unwrap_err());
    assert!(msg.contains("upload_rate_limit"), "got: {msg}");
    assert!(msg.contains("out of range"), "got: {msg}");
}

#[test]
fn an_http_listen_port_a_profile_listens_on_is_refused() {
    let dir = tempdir().unwrap();
    // A host profile's `listen_interfaces`, on another address.
    let host = single_session().replace("0.0.0.0:6881", "0.0.0.0:6881,[::]:8080");
    let msg = format!(
        "{:#}",
        Config::load(&write_cfg(dir.path(), &host)).unwrap_err()
    );
    assert!(
        msg.contains("http_listen") && msg.contains("8080"),
        "got: {msg}"
    );
    assert!(msg.contains("\"public\""), "names the profile: {msg}");

    // A vpn profile's static `listen_port`.
    let mut c = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    c.profile[0] = ProfileConfig {
        id: torrentd_engine::ProfileId::new("acct_a"),
        network: torrentd_engine::ProfileNetwork::Vpn {
            vpn_type: torrentd_engine::VpnType::Wireguard,
            vpn_config: PathBuf::from("/etc/wireguard/wg0.conf"),
            vpn_interface: "wg0".into(),
            listen_port: Some(8080),
            port_forward: Default::default(),
            port_forward_gateway: None,
        },
        peer_fingerprint: Some("-AA1000-".into()),
        user_agent: Some("qB/5.0".into()),
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    };
    let msg = format!("{:#}", c.validate_http_listen_port().unwrap_err());
    assert!(msg.contains("\"acct_a\""), "got: {msg}");

    // Distinct ports are fine.
    Config::load(&write_cfg(dir.path(), &single_session())).expect("8080 and 6881 do not collide");
}

#[test]
fn an_absent_unchoke_slots_limit_leaves_the_rate_based_choker() {
    let dir = tempdir().unwrap();
    let c = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    let s = c.libtorrent_settings();
    assert_eq!(
        s.choking_algorithm,
        Some(libtorrent_safe::Settings::RATE_BASED_CHOKER)
    );
    assert_eq!(
        s.unchoke_slots_limit,
        Some(libtorrent_safe::Settings::DEFAULT_UNCHOKE_SLOTS)
    );
}

#[test]
fn an_unchoke_slots_limit_selects_the_fixed_slots_choker_with_that_many() {
    let dir = tempdir().unwrap();
    let body = with_top_level("unchoke_slots_limit = 64");
    let c = Config::load(&write_cfg(dir.path(), &body)).unwrap();
    let s = c.libtorrent_settings();
    assert_eq!(
        s.choking_algorithm,
        Some(libtorrent_safe::Settings::FIXED_SLOTS_CHOKER)
    );
    assert_eq!(s.unchoke_slots_limit, Some(64));

    let zero = with_top_level("unchoke_slots_limit = 0");
    let msg = format!(
        "{:#}",
        Config::load(&write_cfg(dir.path(), &zero)).unwrap_err()
    );
    assert!(msg.contains("unchoke_slots_limit"), "got: {msg}");

    let mut other = c.clone();
    other.unchoke_slots_limit = Some(128);
    assert_eq!(
        Config::diff(&c, &other).non_reloadable_changes,
        vec!["unchoke_slots_limit"],
    );
}

#[test]
fn the_shared_test_fixture_states_a_posture() {
    // The fixture has no profile, so the posture is what it can satisfy.
    let dir = tempdir().unwrap();
    let cfg = Config::minimal_for_tests(dir.path(), false);
    cfg.validate_auth_posture()
        .expect("the shared fixture must state a posture the daemon accepts");
}

#[test]
fn the_shutdown_drain_defaults_to_a_minute_and_refuses_zero() {
    let dir = tempdir().unwrap();
    let base = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();
    assert_eq!(base.shutdown_drain_secs, 60);
    // Zero would skip the drain and lose every unsaved resume.
    let text = format!("shutdown_drain_secs = 0\n{}", single_session());
    let e = Config::load(&write_cfg(dir.path(), &text)).unwrap_err();
    assert!(
        format!("{e:#}").contains("shutdown_drain_secs"),
        "got {e:#}"
    );
}

#[test]
fn deleting_a_reloadable_key_is_a_difference_and_is_named() {
    // Deleting a key is the documented way back to the preset default.
    let dir = tempdir().unwrap();
    let base = Config::load(&write_cfg(
        dir.path(),
        &with_top_level(
            "aio_threads = 8\nenable_lsd = true\nupload_rate_limit = 1000000\n\
                 max_concurrent_http_announces = 30",
        ),
    ))
    .unwrap();
    // The fixture must actually set all five, or a "deletion" below would
    // be a no-op and the test would pass on nothing.
    assert!(
        base.connections_limit.is_some()
            && base.aio_threads.is_some()
            && base.enable_lsd.is_some()
            && base.upload_rate_limit.is_some()
            && base.max_concurrent_http_announces.is_some(),
        "the fixture must set every key this test deletes",
    );

    let mut connections_limit = base.clone();
    connections_limit.connections_limit = None;

    let mut aio_threads = base.clone();
    aio_threads.aio_threads = None;

    let mut enable_lsd = base.clone();
    enable_lsd.enable_lsd = None;

    let mut upload_rate_limit = base.clone();
    upload_rate_limit.upload_rate_limit = None;

    let mut announces = base.clone();
    announces.max_concurrent_http_announces = None;

    for (field, edited) in [
        ("connections_limit", &connections_limit),
        ("aio_threads", &aio_threads),
        ("enable_lsd", &enable_lsd),
        ("upload_rate_limit", &upload_rate_limit),
        ("max_concurrent_http_announces", &announces),
    ] {
        let d = Config::diff(&base, edited);
        assert!(
            !d.is_empty(),
            "a config that deleted {field} must not look unchanged",
        );
        assert!(
            d.reloadable_changes.contains(&field),
            "the diff must name {field} as changed; got {:?}",
            d.reloadable_changes,
        );
        assert!(
            d.reloadable_deletions.contains(&field),
            "the diff must name {field} as deleted, so the pump can say the \
                 preset default needs a restart; got {:?}",
            d.reloadable_deletions,
        );
    }
}

#[test]
fn an_edit_to_only_non_reloadable_keys_applies_no_settings() {
    // So such a reload does not end with `SIGHUP: settings applied`.
    let dir = tempdir().unwrap();
    let base = Config::load(&write_cfg(dir.path(), &single_session())).unwrap();

    // The documented operator edit: add `[auth]`, delete the opt-out.
    let mut with_auth = base.clone();
    with_auth.auth = Some(crate::auth::AuthConfig {
        password_hash: crate::auth::hash_password("hunter2").unwrap(),
        session_ttl_secs: 43_200,
        token: vec![],
    });
    with_auth.allow_unauthenticated = false;

    let d = Config::diff(&base, &with_auth);
    assert!(
        !d.is_empty(),
        "the edit is reported, so the diff is not empty"
    );
    for profile in [host_profile(), vpn_profile()] {
        assert!(
            ConfigDiff::settings_patch_is_empty(&d.to_settings_patch_for(&profile)),
            "an auth-only edit has nothing to apply to profile {}",
            profile.id,
        );
    }

    // A reloadable key in the same edit still reaches the loop: the guard
    // withholds a no-op call, not every call.
    let mut also_reloadable = with_auth.clone();
    also_reloadable.connections_limit = Some(20_000);
    let d = Config::diff(&base, &also_reloadable);
    assert!(
        !ConfigDiff::settings_patch_is_empty(&d.to_settings_patch_for(&host_profile())),
        "a changed connections_limit must still be applied",
    );
}

mod props {
    use proptest::prelude::*;

    use super::*;

    /// `key = value`, or nothing, with the value drawn from `values`:
    /// sane settings beside the edges (zero, the type's maximum, empty,
    /// relative, overlapping) a hand-edited file can hold. Every value
    /// deserializes, so what varies is what `validate` is handed.
    fn line(key: &'static str, values: &[&'static str]) -> impl Strategy<Value = String> {
        prop::option::weighted(0.3, pick(key, values)).prop_map(Option::unwrap_or_default)
    }

    /// `key = value`, always present.
    fn pick(key: &'static str, values: &[&'static str]) -> impl Strategy<Value = String> {
        prop::sample::select(values.to_vec()).prop_map(move |v| format!("{key} = {v}\n"))
    }

    fn top_level() -> impl Strategy<Value = String> {
        let path = &[
            "\"/data/torrents\"",
            "\"\"",
            "\"relative/dir\"",
            "\"/\"",
            "\"/data/torrents/sub\"",
        ];
        let count = &["0", "1", "10000", "4294967295"];
        let secs = &["0", "180", "9223372036854775807"];
        (
            (
                pick("default_save_path", path),
                pick("resume_dir", path),
                pick("torrent_dir", path),
                line(
                    "http_listen",
                    &[
                        "\"127.0.0.1:8080\"",
                        "\"0.0.0.0:8080\"",
                        "\"[::1]:0\"",
                        "\"unix:/run/t.sock\"",
                    ],
                ),
                line("http_socket_mode", &["0", "432", "511", "4095", "65535"]),
                line("http_socket_group", &["\"torrentd\"", "\"\"", "\" \""]),
                line(
                    "trusted_proxies",
                    &[
                        "[]",
                        "[\"10.0.0.0/8\"]",
                        "[\"0.0.0.0/0\"]",
                        "[\"bogus\"]",
                        "[\"::ffff:0:0/96\"]",
                    ],
                ),
                pick("allow_unauthenticated", &["true", "true", "false"]),
            ),
            (
                line("allowed_hosts", &["[]", "[\"example.org\"]", "[\"\"]"]),
                line("log_level", &["\"info\"", "\"debug\"", "\"error\""]),
                line("registry_path", path),
                line("connections_limit", count),
                line("aio_threads", count),
                line("upload_rate_limit", count),
                line("enable_lsd", &["true", "false"]),
                line(
                    "peer_fingerprint",
                    &["\"-ZZ1000-\"", "\"-ZZ1000-\"", "\"\"", "\"-XX\""],
                ),
            ),
            (
                line("vpn_handshake_max_age_secs", secs),
                line("shutdown_drain_secs", secs),
                line("network_kill_switch", &["true", "false"]),
            ),
        )
            .prop_map(|(a, b, c)| {
                [
                    a.0, a.1, a.2, a.3, a.4, a.5, a.6, a.7, b.0, b.1, b.2, b.3, b.4, b.5, b.6, b.7,
                    c.0, c.1, c.2,
                ]
                .concat()
            })
    }

    /// One fault a profile table can carry, or none.
    #[derive(Clone, Copy, Debug)]
    enum Flaw {
        None,
        EmptyListen,
        EmptyInterface,
        NoFingerprint,
        SameId,
        SamePort,
        OwnDirsUnderSave,
    }

    /// The `i`th profile table: a well-formed host or vpn profile whose
    /// id and port are its own, unless `flaw` says otherwise.
    fn profile_table(i: usize, vpn: bool, flaw: Flaw) -> String {
        let id = if matches!(flaw, Flaw::SameId) {
            "p0".to_owned()
        } else {
            format!("p{i}")
        };
        let port = if matches!(flaw, Flaw::SamePort) {
            6881
        } else {
            6881 + i
        };
        let mut t = format!("[[profile]]\nid = \"{id}\"\n");
        if vpn {
            let iface = if matches!(flaw, Flaw::EmptyInterface) {
                String::new()
            } else {
                format!("wg{i}")
            };
            t += &format!(
                    "network = \"vpn\"\nvpn_type = \"wireguard\"\nvpn_config = \"/etc/wireguard/wg{i}.conf\"\n\
                     vpn_interface = \"{iface}\"\nlisten_port = {port}\nuser_agent = \"qBittorrent/5.0.{i}\"\n\
                     allowed_tracker_domains = [\"t{i}.example\"]\n"
                );
            if !matches!(flaw, Flaw::NoFingerprint) {
                t += &format!("peer_fingerprint = \"-AA100{i}-\"\n");
            }
        } else {
            let listen = if matches!(flaw, Flaw::EmptyListen) {
                String::new()
            } else {
                format!("eth0:{port}")
            };
            t += &format!("network = \"host\"\nlisten_interfaces = \"{listen}\"\n");
        }
        if matches!(flaw, Flaw::OwnDirsUnderSave) {
            t += "resume_dir = \"/data/torrents\"\n";
        }
        t + "\n"
    }

    fn profiles() -> impl Strategy<Value = String> {
        let flaw = prop_oneof![
            12 => Just(Flaw::None),
            1 => Just(Flaw::EmptyListen),
            1 => Just(Flaw::EmptyInterface),
            1 => Just(Flaw::NoFingerprint),
            1 => Just(Flaw::SameId),
            1 => Just(Flaw::SamePort),
            1 => Just(Flaw::OwnDirsUnderSave),
        ];
        prop::collection::vec((any::<bool>(), flaw), 1..4).prop_map(|ps| {
            ps.into_iter()
                .enumerate()
                .map(|(i, (vpn, flaw))| profile_table(i, vpn, flaw))
                .collect()
        })
    }

    fn tables() -> impl Strategy<Value = String> {
        let pool = prop::sample::select(vec![
                "",
                "",
                "",
                "[pool]\nroots = []\nlibrary_dir = \"/var/lib/torrentd/library\"\n",
                "[pool]\nroots = [\"/data/torrents\"]\nlibrary_dir = \"/var/lib/torrentd/library\"\n",
                "[pool]\nroots = [\"/data\", \"/data/torrents\"]\nlibrary_dir = \"/data/torrents/library\"\n",
                "[pool]\nroots = [\"rel\"]\nlibrary_dir = \"\"\n",
            ]);
        let auth = prop::sample::select(vec![
            "",
            "",
            "",
            "[auth]\npassword_hash = \"not-a-phc-string\"\n",
            "[auth]\npassword_hash = \"\"\nsession_ttl_secs = 0\n",
        ]);
        (pool, auth).prop_map(|(pool, auth)| format!("{pool}\n{auth}"))
    }

    /// A config file as an operator might write one: some keys, some
    /// profiles, maybe a pool and an auth table, many of them wrong.
    fn document() -> impl Strategy<Value = String> {
        (top_level(), profiles(), tables())
            .prop_map(|(top, profiles, tables)| format!("{top}\n{profiles}\n{tables}"))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// A parsed config validates without panicking, either way, and
        /// diffs against itself as no change at all.
        #[test]
        fn a_parsed_config_validates_without_panic_and_diffs_empty_against_itself(doc in document()) {
            let cfg = toml::from_str::<Config>(&doc);
            prop_assert!(cfg.is_ok(), "the generator's document did not parse: {:?}\n{}", cfg, doc);
            let cfg = cfg.unwrap();
            let _ = cfg.validate();
            let _ = cfg.validate_without_auth_posture();
            let d = Config::diff(&cfg, &cfg.clone());
            prop_assert!(d.is_empty(), "{:?} for\n{}", d, doc);
            prop_assert!(d.reloadable_deletions.is_empty());
        }

        /// A damaged file (cut short, or with a stray line spliced in)
        /// neither panics the parser nor, where it still parses, the
        /// validator.
        #[test]
        fn a_damaged_file_never_panics_parse_or_validate(
            doc in document(),
            cut in any::<prop::sample::Index>(),
            at in any::<prop::sample::Index>(),
            stray in "[ -~]{0,40}",
        ) {
            let ends: Vec<usize> = doc.char_indices().map(|(i, _)| i).chain([doc.len()]).collect();
            let short = &doc[..*cut.get(&ends)];
            let mut lines: Vec<&str> = doc.lines().collect();
            lines.insert(at.index(lines.len() + 1), &stray);
            for damaged in [short.to_owned(), lines.join("\n")] {
                if let Ok(cfg) = toml::from_str::<Config>(&damaged) {
                    let _ = cfg.validate();
                    prop_assert!(Config::diff(&cfg, &cfg).is_empty());
                }
            }
        }
    }
}
