//! The startup scans: tracker guards, claimed torrents re-added, and a torrent
//! the boot left unloaded.

use super::*;

/// libtorrent resume data for `torrent`, with no info dict, and with a
/// `trackers` list of `trackers` when given — the list that replaces the
/// `.torrent`'s own on the add.
fn resume_for(torrent: &[u8], trackers: Option<&str>) -> Vec<u8> {
    let ih = libtorrent_safe::info_hash_from_torrent(torrent).unwrap();
    let mut r =
        b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
    r.extend_from_slice(&ih.0);
    if let Some(url) = trackers {
        r.extend_from_slice(format!("8:trackersll{}:{url}ee", url.len()).as_bytes());
    }
    r.extend_from_slice(b"e");
    r
}

/// Issue #72's daemon acceptance: the startup scans hold every torrent to the
/// profile's `allowed_tracker_domains`, the way `POST /v1/torrents` does.
///
/// Five torrents in the profile's two directories, against a list naming
/// `tracker.allowed.example`:
///
/// - `dir_ok`, a `.torrent` announcing there: loaded by the torrent-dir scan;
/// - `dir_foreign`, a `.torrent` announcing elsewhere: refused;
/// - `resume_ok`, resume data without a tracker list beside an allowed
///   `.torrent`: loaded from resume data;
/// - `resume_override`, resume data whose own `trackers` list names a foreign
///   tracker, beside an allowed `.torrent`: the resume data is refused, and
///   the `.torrent` alone is loaded by the torrent-dir scan, so the foreign
///   tracker is never announced to;
/// - `resume_only`, the same foreign resume data with no `.torrent`: refused,
///   and nothing loads it.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn the_boot_scans_hold_every_torrent_to_the_profiles_tracker_domains() {
    const ALLOWED: &str = "http://tracker.allowed.example/announce";
    const FOREIGN: &str = "http://tracker.foreign.example/announce";
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str("allowed_tracker_domains = [\"allowed.example\"]\n");
    std::fs::write(&cfg, text).unwrap();
    let torrents = p.join("torrents").join(PROFILE);
    let resumes = p.join("resume").join(PROFILE);
    std::fs::create_dir_all(&torrents).unwrap();
    std::fs::create_dir_all(&resumes).unwrap();
    let hex = |t: &[u8]| libtorrent_safe::info_hash_from_torrent(t).unwrap().to_hex();
    let put = |d: &std::path::Path, ih: &str, ext: &str, bytes: &[u8]| {
        std::fs::write(d.join(format!("{ih}.{ext}")), bytes).unwrap();
    };

    let dir_ok = metainfo("dir_ok", ALLOWED);
    put(&torrents, &hex(&dir_ok), "torrent", &dir_ok);
    let dir_foreign = metainfo("dir_foreign", FOREIGN);
    put(&torrents, &hex(&dir_foreign), "torrent", &dir_foreign);
    let resume_ok = metainfo("resume_ok", ALLOWED);
    put(&torrents, &hex(&resume_ok), "torrent", &resume_ok);
    put(
        &resumes,
        &hex(&resume_ok),
        "resume",
        &resume_for(&resume_ok, None),
    );
    let resume_override = metainfo("resume_override", ALLOWED);
    put(
        &torrents,
        &hex(&resume_override),
        "torrent",
        &resume_override,
    );
    put(
        &resumes,
        &hex(&resume_override),
        "resume",
        &resume_for(&resume_override, Some(FOREIGN)),
    );
    let resume_only = metainfo("resume_only", ALLOWED);
    put(
        &resumes,
        &hex(&resume_only),
        "resume",
        &resume_for(&resume_only, Some(FOREIGN)),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .spawn()
        .expect("spawn daemon");
    wait_healthy(addr);

    let (code, list) = http(addr, "GET", "/v1/torrents", None);
    assert_eq!(code, 200, "{list}");
    for (name, t, loaded) in [
        ("dir_ok", &dir_ok, true),
        ("dir_foreign", &dir_foreign, false),
        ("resume_ok", &resume_ok, true),
        ("resume_override", &resume_override, true),
        ("resume_only", &resume_only, false),
    ] {
        assert_eq!(
            list.contains(&hex(t)),
            loaded,
            "{name} should be {}: {list}",
            if loaded { "loaded" } else { "refused" },
        );
    }
    // The torrent whose resume data was refused announces to its `.torrent`'s
    // tracker only.
    let (code, trackers) = http(
        addr,
        "GET",
        &format!("/v1/torrents/{}/trackers", hex(&resume_override)),
        None,
    );
    assert_eq!(code, 200, "{trackers}");
    assert!(trackers.contains("tracker.allowed.example"), "{trackers}");
    assert!(!trackers.contains("foreign"), "{trackers}");

    // Each refusal is counted where an API refusal is.
    let (code, metrics) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200);
    assert!(
        metrics.lines().any(|l| {
            l.starts_with("torrentd_profile_assignment_registry_errors_total{")
                && l.contains(&format!("profile_id=\"{PROFILE}\""))
                && l.ends_with(" 3")
        }),
        "three refusals should be counted:\n{metrics}"
    );
    // They are the boot's, already in the counter's first sample, where
    // increase() cannot see them; the boot gauge holds them for the alert.
    let boot = format!("torrentd_boot_registry_errors{{profile_id=\"{PROFILE}\"}} 3");
    assert!(
        metrics.lines().any(|l| l == boot),
        "the boot's refusals should be exported as {boot}:\n{metrics}"
    );

    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
}

/// Issue #186's acceptance: a torrent added through `POST /v1/torrents` whose
/// resume file is lost is re-added at the save path recorded beside its
/// `.torrent`, not left unloaded.
///
/// The add claims the info-hash before it loads, and the claim outlives the
/// resume file. The torrent-dir scan used to skip every claimed info-hash,
/// so the torrent came back in no session, counted as one the registry
/// claims and the scans did not load.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_claimed_torrent_with_no_resume_file_is_re_added_at_its_recorded_save_path() {
    boot_a_claimed_torrent_with_no_resume_file(false);
}

/// The other side of #186's re-add: a claimed torrent with no resume file
/// that the pool index records `drifted` failed its verification and was
/// paused for it, so the torrent-dir scan leaves it unloaded rather than
/// re-add it in seed mode, announcing a payload its piece hashes rejected.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_claimed_torrent_the_pool_records_drifted_is_not_re_added_with_no_resume_file() {
    boot_a_claimed_torrent_with_no_resume_file(true);
}

/// Boot over what an API add leaves once its resume file is gone; with
/// `drifted`, also record the torrent `drifted` in `pool.db` first. Asserts
/// it is re-added at its recorded save path, or with `drifted` that it is
/// left unloaded.
fn boot_a_claimed_torrent_with_no_resume_file(drifted: bool) {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    let pool_db = p.join("pool.db");
    if drifted {
        let (root, library) = (p.join("root"), p.join("library"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&library).unwrap();
        let mut text = std::fs::read_to_string(&cfg).unwrap();
        text.push_str(&format!(
            "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\ndb_path = \"{}\"\n",
            root.display(),
            library.display(),
            pool_db.display(),
        ));
        std::fs::write(&cfg, text).unwrap();
    }
    // Inside `default_save_path`, as an API add requires, and not it, so a
    // fallback to `default_save_path` shows.
    let recorded = p.join("data").join("elsewhere");
    std::fs::create_dir_all(&recorded).unwrap();
    let torrent = metainfo("lost_resume", "http://tracker.example/announce");
    let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
        .unwrap()
        .to_hex();
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let spawn = || {
        let child = KillOnDrop(
            Command::new(env!("CARGO_BIN_EXE_torrentd"))
                .arg("--config")
                .arg(&cfg)
                .spawn()
                .expect("spawn daemon"),
        );
        wait_healthy(addr);
        child
    };
    let session_save_path = |ih: &str| -> Option<String> {
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        if code != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        v["session"]["save_path"].as_str().map(str::to_owned)
    };

    // What an API add leaves after a crash before the first save, or with
    // its resume file unreadable: the claim, the `.torrent` and its recorded
    // save path, and no resume file. The claim is written as the
    // pre-registry file, which the boot imports.
    let torrents = p.join("torrents").join(PROFILE);
    std::fs::create_dir_all(&torrents).unwrap();
    std::fs::write(torrents.join(format!("{ih}.torrent")), &torrent).unwrap();
    std::fs::write(
        torrents.join(format!("{ih}.save_path")),
        recorded.to_str().unwrap(),
    )
    .unwrap();
    std::fs::write(
        p.join("profile_assignments.json"),
        format!("{{\"{ih}\":\"{PROFILE}\"}}"),
    )
    .unwrap();
    if drifted {
        // What a failed verification records (`record_verify_outcome`).
        let store = torrentd_pool::PoolStore::open(&pool_db).unwrap();
        store
            .upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: ih.clone(),
                    infohash_v1: Some(ih.clone()),
                    infohash_v2: None,
                    name: "lost_resume".into(),
                    total_size: 1,
                    num_files: 1,
                    source_path: torrents.join(format!("{ih}.torrent")),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: Vec::new(),
                    profile: Some(PROFILE.into()),
                },
                0,
            )
            .unwrap();
        store
            .set_adoption(
                &ih,
                torrentd_pool::AdoptionState::Drifted,
                None,
                None,
                None,
                Some(1),
                Some("verification failed"),
            )
            .unwrap();
    }

    let mut child = spawn();
    if drifted {
        // The gauge is set once both scans have run.
        let unloaded =
            format!("torrentd_profile_unloaded_registry_torrents{{profile_id=\"{PROFILE}\"}} 1");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (_, metrics) = http(addr, "GET", "/metrics", None);
            if metrics.lines().any(|l| l == unloaded) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the drifted torrent was not counted unloaded:\n{metrics}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        assert_eq!(
            session_name(addr, &ih, Duration::from_secs(2)),
            None,
            "a torrent the pool records drifted was re-added",
        );
        sigterm(&child.0);
        assert_exits_zero(&mut child.0, Duration::from_secs(30));
        return;
    }
    assert_eq!(
        session_name(addr, &ih, Duration::from_secs(30)).as_deref(),
        Some("lost_resume"),
        "the torrent with no resume file was left unloaded",
    );
    assert_eq!(
        session_save_path(&ih).as_deref(),
        Some(recorded.to_str().unwrap()),
        "re-added somewhere other than its recorded save path",
    );
    let (code, metrics) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200);
    for (series, what) in [
        (
            "torrentd_profile_unloaded_registry_torrents{",
            "counted as a claim the scans did not load",
        ),
        (
            "torrentd_boot_save_path_fallbacks_total{",
            "re-added at default_save_path",
        ),
        (
            "torrentd_profile_assignment_registry_errors_total{",
            "counted as a registry error",
        ),
    ] {
        assert!(
            !metrics.lines().any(|l| l.starts_with(series)
                && l.contains(&format!("profile_id=\"{PROFILE}\""))
                && !l.ends_with(" 0")),
            "{what}:\n{metrics}"
        );
    }

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}

/// Issue #354's regression: a plain `DELETE` of a torrent the boot left
/// unloaded because its resume add failed keeps its resume file, which is
/// what the next boot loads it from, and refuses with `torrent-unloaded`
/// naming it.
///
/// The resume file has no info-hash, so libtorrent refuses the add, as it
/// does a save path on a disk not mounted yet: the resume scan claims the
/// info-hash, the add fails, and the claim stays with nothing loaded. The
/// `DELETE` the "After a crash" runbook runs over every unloaded claim used to
/// answer `204` and delete the resume file with the claim.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_plain_delete_of_a_torrent_whose_resume_add_failed_keeps_its_resume_file() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    let ih = "cd".repeat(20);
    let resume_dir = p.join("resume").join(PROFILE);
    std::fs::create_dir_all(&resume_dir).unwrap();
    let resume = resume_dir.join(format!("{ih}.resume"));
    let bytes = b"d11:file-format22:libtorrent resume file12:file-versioni1ee".to_vec();
    std::fs::write(&resume, &bytes).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .spawn()
        .expect("spawn daemon");
    wait_healthy(addr);

    // Both are set once the scans have run.
    let series = [
        format!("torrentd_boot_torrent_load_failures{{profile_id=\"{PROFILE}\",source=\"resume_add\"}} 1"),
        format!("torrentd_profile_unloaded_registry_torrents{{profile_id=\"{PROFILE}\"}} 1"),
    ];
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (_, metrics) = http(addr, "GET", "/metrics", None);
        if series.iter().all(|s| metrics.lines().any(|l| l == s)) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the failed resume add was not counted as {series:?}:\n{metrics}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let (code, body) = http(addr, "DELETE", &format!("/v1/torrents/{ih}"), None);
    assert_eq!(code, 409, "{body}");
    let problem: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        problem["type"]
            .as_str()
            .is_some_and(|t| t.ends_with("#torrent-unloaded")),
        "{body}"
    );
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|d| d.contains(&format!("{ih}.resume"))),
        "the refusal does not name the resume file: {body}"
    );
    assert_eq!(
        std::fs::read(&resume).ok(),
        Some(bytes.clone()),
        "the refused delete touched the resume file"
    );
    let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
    assert_eq!(code, 200, "the refused delete cleared the claim: {body}");

    // Retiring it anyway: with the file moved out of the store, the claim has
    // nothing behind it and the delete clears it.
    let kept = p.join("kept.resume");
    std::fs::rename(&resume, &kept).unwrap();
    let (code, body) = http(addr, "DELETE", &format!("/v1/torrents/{ih}"), None);
    assert_eq!(code, 204, "{body}");
    let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
    assert_eq!(code, 404, "{body}");
    assert_eq!(std::fs::read(&kept).ok(), Some(bytes));

    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
}
