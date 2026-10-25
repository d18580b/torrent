//! Hybrid (v1+v2) and v2-only torrents: the key they are filed under.

use super::*;

/// A hybrid torrent added from a btih-only magnet: the metadata it fetches
/// gives it a v2 hash too, and the daemon must go on knowing it by the v1 one.
/// Keyed by libtorrent's `get_best()`, every alert after the metadata named
/// the truncated v2 hash instead: the state stayed `awaiting_metadata`, the
/// `.torrent` was written under the v2 key, the shutdown drain waited on a
/// resume save that never settled, and a `DELETE` left the v1 resume file to
/// bring the torrent back at the next boot.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_hybrid_torrent_added_by_a_v1_magnet_keeps_its_v1_key() {
    use libtorrent_safe::Alert;

    // The repository's own hybrid fixture: CI runs this suite without the
    // vendor submodules, so libtorrent's test corpus is not on disk.
    let torrent = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent"),
    )
    .expect("read the hybrid test torrent");
    let hashes = libtorrent_safe::info_hashes_from_torrent(&torrent).unwrap();
    let v1 = hashes.v1.expect("hybrid has v1").to_hex();
    let v2 = hashes.v2.expect("hybrid has v2").truncated().to_hex();

    // A second session serves the metadata over loopback, and nothing but the
    // magnet's `x.pe` points the daemon at it.
    let seed_dir = tempfile::tempdir().unwrap();
    let mut settings = libtorrent_safe::Settings::server_seed_overrides();
    settings.enable_dht = Some(false);
    settings.enable_lsd = Some(false);
    settings.enable_upnp = Some(false);
    settings.enable_natpmp = Some(false);
    settings.listen_interfaces = Some("127.0.0.1:0".into());
    let seed = libtorrent_safe::Session::new(&settings).expect("seed session");
    seed.add_torrent(libtorrent_safe::AddParams::File {
        bytes: torrent,
        save_path: seed_dir.path().to_string_lossy().into_owned(),
        flags: libtorrent_safe::TorrentFlags::empty(),
        trackers: Vec::new(),
    })
    .expect("seed add");
    let (mut seed_port, mut checked) = (None, false);
    poll(
        "the seed's listen port and check",
        Duration::from_secs(10),
        || {
            for a in seed.drain_alerts() {
                match a {
                    Alert::ListenSucceeded { endpoint, .. } => {
                        seed_port = endpoint
                            .rsplit_once(':')
                            .and_then(|(_, p)| p.parse::<u16>().ok())
                            .filter(|p| *p != 0)
                            .or(seed_port);
                    }
                    Alert::TorrentChecked { .. } => checked = true,
                    _ => {}
                }
            }
            (seed_port.is_some() && checked).then_some(())
        },
    );
    let seed_port = seed_port.unwrap();

    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let listen_port = free_port();
    let daemon = Running(spawn_daemon(p, listen_port, addr));
    wait_healthy(addr);

    let magnet = format!("magnet:?xt=urn:btih:{v1}&x.pe=127.0.0.1:{seed_port}");
    let (code, body) = http(addr, "POST", "/v1/torrents", Some(&add_magnet(&magnet)));
    assert_eq!(code, 201, "add: {body}");

    // The metadata arrives, and the state map's entry follows it.
    let phase = poll(
        "a phase past awaiting_metadata",
        Duration::from_secs(30),
        || {
            seed.drain_alerts();
            let (code, body) = http(addr, "GET", &format!("/v1/torrents/{v1}"), None);
            assert_eq!(code, 200, "the torrent is found under v1: {body}");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let phase = v["phase"].as_str().unwrap_or_default().to_owned();
            (!matches!(phase.as_str(), "awaiting_metadata" | "unknown")).then_some(phase)
        },
    );
    let torrents = p.join("torrents").join(PROFILE);
    poll(
        "the fetched .torrent under v1",
        Duration::from_secs(10),
        || {
            torrents
                .join(format!("{v1}.torrent"))
                .exists()
                .then_some(())
        },
    );
    assert!(
        !torrents.join(format!("{v2}.torrent")).exists(),
        "nothing is written under the truncated v2 hash"
    );
    let (code, _) = http(addr, "GET", &format!("/v1/torrents/{v2}"), None);
    assert_eq!(code, 404, "the torrent has one key; phase was {phase}");

    // A shutdown now drains its resume save: the save it asks for settles.
    daemon.stop();
    let report = std::fs::read_to_string(p.join("last_shutdown.json")).expect("shutdown report");
    assert!(report.contains("\"unsaved_resumes\":0"), "{report}");
    let resumes = p.join("resume").join(PROFILE);
    assert!(resumes.join(format!("{v1}.resume")).exists());
    assert!(!resumes.join(format!("{v2}.resume")).exists());

    // Back from that resume file under the same key, then deleted for good.
    let daemon = Running(spawn_daemon(p, listen_port, addr));
    wait_healthy(addr);
    poll(
        "the torrent back from its resume file",
        Duration::from_secs(10),
        || (http(addr, "GET", &format!("/v1/torrents/{v1}"), None).0 == 200).then_some(()),
    );
    let (code, body) = http(addr, "DELETE", &format!("/v1/torrents/{v1}"), None);
    assert_eq!(code, 204, "delete: {body}");
    poll("the resume file removed", Duration::from_secs(10), || {
        (!resumes.join(format!("{v1}.resume")).exists()).then_some(())
    });
    daemon.stop();
    assert!(
        !resumes.join(format!("{v1}.resume")).exists(),
        "a deleted torrent's resume file must not survive the shutdown drain"
    );

    // And it stays deleted across a restart.
    let daemon = Running(spawn_daemon(p, listen_port, addr));
    wait_healthy(addr);
    let (code, body) = http(addr, "GET", "/v1/torrents", None);
    assert_eq!(code, 200);
    assert!(!body.contains(&v1), "the deleted torrent came back: {body}");
    daemon.stop();
}

/// Issue #251: a hybrid torrent an earlier build filed under its truncated v2
/// hash — `<v2>.resume` and `<v2>.torrent` — is keyed by its v1 hash by the
/// session now. The boot refuses it and counts it, rather than loading a
/// torrent every alert of which names a key no record is kept under.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_hybrid_torrent_filed_under_its_truncated_v2_hash_is_refused_at_boot() {
    boot_a_hybrid_filed_under_its_truncated_v2_hash(HybridFiling {
        with_torrent: true,
        ..HybridFiling::default()
    });
}

/// The same with no `.torrent` beside the resume file: the v1 hash the resume
/// data names is the session's key, which the scan reads before the add
/// (issue #412), so nothing is added.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_hybrid_resume_file_filed_under_its_truncated_v2_hash_is_refused_at_boot() {
    boot_a_hybrid_filed_under_its_truncated_v2_hash(HybridFiling::default());
}

/// Issue #412: resume data naming only a v2 hash, with no metadata and no
/// `.torrent` beside it, as another client writes it for a btmh-only magnet
/// whose metadata it never fetched. The session would key it by the
/// truncated v2 hash it is filed under until hybrid metadata arrived and
/// rekeyed it by its v1 hash, so the boot refuses it, as `POST /v1/torrents`
/// refuses a btmh-only magnet.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn v2_only_resume_data_with_no_metadata_is_refused_at_boot() {
    boot_a_hybrid_filed_under_its_truncated_v2_hash(HybridFiling {
        v2_only: true,
        ..HybridFiling::default()
    });
}

/// Issue #251 as an earlier build left it: the registry claims the torrent
/// under its truncated v2 hash too. The refusal before the add keeps that
/// claim for the operator to reconcile, and the unloaded-claims gauge names
/// it.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_hybrid_claimed_under_its_truncated_v2_hash_is_refused_with_its_claim_kept() {
    boot_a_hybrid_filed_under_its_truncated_v2_hash(HybridFiling {
        with_torrent: true,
        v2_claimed: true,
        ..HybridFiling::default()
    });
}

/// The same with no `.torrent` beside the resume file: the resume data's own
/// v1 hash refuses it before the add, and the claim it held before the boot
/// is kept.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_hybrid_resume_file_claimed_under_its_truncated_v2_hash_keeps_its_claim() {
    boot_a_hybrid_filed_under_its_truncated_v2_hash(HybridFiling {
        v2_claimed: true,
        ..HybridFiling::default()
    });
}

/// Where the profile files a `.torrent` under the session's key as well, the
/// resume scan refuses the resume file filed under the truncated v2 hash
/// before the add, and the torrent-dir scan loads that `.torrent` under the
/// session's key: claimed there and counted loaded, so it is neither seeded
/// unclaimed nor reported as an unloaded claim.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_hybrid_left_loaded_under_its_session_key_is_claimed_there() {
    boot_a_hybrid_filed_under_its_truncated_v2_hash(HybridFiling {
        v1_torrent: true,
        ..HybridFiling::default()
    });
}

/// What an earlier build left of a hybrid torrent filed under its truncated
/// v2 hash, beside its `<v2>.resume`.
#[derive(Clone, Copy, Default)]
struct HybridFiling {
    /// `<v2>.torrent` beside the resume file.
    with_torrent: bool,
    /// The registry claims the truncated v2 hash for the profile.
    v2_claimed: bool,
    /// A `.torrent` filed under the v1 hash, the session's key.
    v1_torrent: bool,
    /// The resume data names the v2 hash alone, not the v1 hash too.
    v2_only: bool,
}

fn boot_a_hybrid_filed_under_its_truncated_v2_hash(case: HybridFiling) {
    let HybridFiling {
        with_torrent,
        v2_claimed,
        v1_torrent,
        v2_only,
    } = case;
    let torrent = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent"),
    )
    .expect("read the hybrid test torrent");
    let hashes = libtorrent_safe::info_hashes_from_torrent(&torrent).unwrap();
    let v1 = hashes.v1.expect("hybrid has v1");
    let v2 = hashes.v2.expect("hybrid has v2");
    let filed = v2.truncated().to_hex();

    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let resumes = p.join("resume").join(PROFILE);
    let torrents = p.join("torrents").join(PROFILE);
    std::fs::create_dir_all(&resumes).unwrap();
    std::fs::create_dir_all(&torrents).unwrap();
    // Resume data as libtorrent writes it for a hybrid: both hashes and a save
    // path, no info dict. Or the v2 hash alone, as for a btmh-only magnet.
    let mut resume = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
    if !v2_only {
        resume.extend_from_slice(b"9:info-hash20:");
        resume.extend_from_slice(&v1.0);
    }
    resume.extend_from_slice(b"10:info-hash232:");
    resume.extend_from_slice(&v2.0);
    let save_path = p.join("data").display().to_string();
    resume.extend_from_slice(format!("9:save_path{}:{save_path}e", save_path.len()).as_bytes());
    let resume_file = resumes.join(format!("{filed}.resume"));
    let torrent_file = torrents.join(format!("{filed}.torrent"));
    std::fs::write(&resume_file, &resume).unwrap();
    if with_torrent {
        std::fs::write(&torrent_file, &torrent).unwrap();
    }
    let v1_torrent_file = torrents.join(format!("{}.torrent", v1.to_hex()));
    if v1_torrent {
        std::fs::write(&v1_torrent_file, &torrent).unwrap();
    }
    if v2_claimed {
        // The pre-registry file, which the boot imports into `registry.db`.
        std::fs::write(
            p.join("slot_assignments.json"),
            format!("{{\"{filed}\":\"{PROFILE}\"}}"),
        )
        .unwrap();
    }

    let daemon = Running(spawn_daemon(p, free_port(), addr));
    wait_healthy(addr);

    if v1_torrent {
        // Left in the session, under the session's key only.
        poll(
            "the torrent in the session under its v1 key",
            Duration::from_secs(10),
            || {
                let (code, list) = http(addr, "GET", "/v1/torrents", None);
                assert_eq!(code, 200, "{list}");
                assert!(!list.contains(&filed), "{list}");
                list.contains(&v1.to_hex()).then_some(())
            },
        );
    } else {
        // In no session under either key, once a removal has landed. A claim
        // kept under the filed key is listed, as every claim is, unloaded.
        poll(
            "the torrent out of the session",
            Duration::from_secs(10),
            || {
                let (code, list) = http(addr, "GET", "/v1/torrents", None);
                assert_eq!(code, 200, "{list}");
                (!list.contains(&v1.to_hex()) && (v2_claimed || !list.contains(&filed)))
                    .then_some(())
            },
        );
        if v2_claimed {
            let (code, one) = http(addr, "GET", &format!("/v1/torrents/{filed}"), None);
            assert_eq!(code, 200, "{one}");
            assert!(
                one.contains("\"session\":null"),
                "no session holds it: {one}"
            );
        }
    }
    // Counted once, by the resume scan, and not again by the torrent-dir scan
    // that finds the `.torrent` beside it.
    let (code, metrics) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200);
    for (source, n) in [("resume_add", 1), ("torrent_dir_add", 0)] {
        assert!(
            metrics.lines().any(|l| {
                l.starts_with("torrentd_boot_torrent_load_failures{")
                    && l.contains(&format!("profile_id=\"{PROFILE}\""))
                    && l.contains(&format!("source=\"{source}\""))
                    && l.ends_with(&format!(" {n}"))
            }),
            "boot_torrent_load_failures{{source={source}}} should read {n}:\n{metrics}"
        );
    }
    // The claim the resume scan made before the add is released with the
    // refusal, and one held before the boot is kept, for the operator to
    // reconcile: the gauge names it. A torrent left loaded is claimed under
    // the session's key and counted loaded against that claim.
    let n = u8::from(v2_claimed);
    let unloaded =
        format!("torrentd_profile_unloaded_registry_torrents{{profile_id=\"{PROFILE}\"}} {n}");
    assert!(
        metrics.lines().any(|l| l == unloaded),
        "the registry should claim {n} unloaded ({unloaded}):\n{metrics}"
    );
    // Every claim, loaded or not, is listed, ordered by infohash.
    let (code, list) = http(addr, "GET", "/v1/torrents", None);
    assert_eq!(code, 200, "{list}");
    let list: serde_json::Value = serde_json::from_str(&list).unwrap();
    assert_eq!(list["next_cursor"], serde_json::Value::Null, "{list}");
    let claims: Vec<(String, String)> = list["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no items: {list}"))
        .iter()
        .map(|t| {
            (
                t["infohash"].as_str().unwrap().to_owned(),
                t["profile_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    daemon.stop();
    let mut expected = Vec::new();
    if v2_claimed {
        expected.push((filed.clone(), PROFILE.to_owned()));
    }
    if v1_torrent {
        expected.push((v1.to_hex(), PROFILE.to_owned()));
    }
    expected.sort();
    assert_eq!(claims, expected, "the registry's claims after the boot");

    // Left for the operator to reconcile: nothing is deleted, and nothing
    // written under the session's key, save by the torrent left loaded there.
    assert!(resume_file.exists(), "the refused resume file is kept");
    assert_eq!(torrent_file.exists(), with_torrent);
    assert_eq!(v1_torrent_file.exists(), v1_torrent);
    if !v1_torrent {
        assert!(!resumes.join(format!("{}.resume", v1.to_hex())).exists());
    }
}
