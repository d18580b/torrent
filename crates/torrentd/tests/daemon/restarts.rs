//! What survives a SIGTERM or a SIGKILL: deletes, recheck verdicts, resume
//! saves, the boot scan, and delete plans.

use super::*;

/// Issue #189: a `DELETE` answered `204` stays deleted across a SIGKILL.
///
/// The resume file and `.torrent` used to be deleted only when the alert
/// loop handled `torrent_removed`, after the answer, with no directory fsync:
/// a `kill -9` straight after the `204` left the resume file, and the next
/// boot claimed it and loaded the torrent again, in 3 trials out of 3. Each
/// round here adds a torrent, waits for its resume file, deletes it, kills
/// the daemon at once, restarts it, and asks for the torrent.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_delete_answered_204_stays_deleted_across_a_sigkill() {
    use base64::Engine as _;

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
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
    let profile_dir = |store: &str| p.join(store).join(PROFILE);

    let mut child = spawn();
    for round in 0..3 {
        let torrent = metainfo(&format!("kill{round}"), "http://127.0.0.1:1/announce");
        let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
            .unwrap()
            .to_hex();
        let (code, body) = http(
            addr,
            "POST",
            "/v1/torrents",
            Some(&format!(
                "{{\"profile_id\":\"{PROFILE}\",\"source\":{{\"kind\":\"metainfo\",\
                 \"data\":\"{}\"}}}}",
                base64::engine::general_purpose::STANDARD.encode(&torrent),
            )),
        );
        assert_eq!(code, 201, "round {round}: {body}");
        let resume = profile_dir("resume").join(format!("{ih}.resume"));
        assert!(
            read_within(&resume, Duration::from_secs(10)).is_some(),
            "round {round}: the add never wrote its resume file",
        );

        let (code, body) = http(addr, "DELETE", &format!("/v1/torrents/{ih}"), None);
        assert_eq!(code, 204, "round {round}: {body}");
        // SIGKILL: no drain, no alert handled after this.
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        for leftover in [
            resume.clone(),
            profile_dir("torrents").join(format!("{ih}.torrent")),
            profile_dir("torrents").join(format!("{ih}.save_path")),
        ] {
            assert!(
                !leftover.exists(),
                "round {round}: {} outlived the 204",
                leftover.display()
            );
        }

        child = spawn();
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        assert_eq!(
            code, 404,
            "round {round}: the deleted torrent came back: {body}"
        );
        assert!(
            !profile_dir("resume").join(format!("{ih}.removed")).exists(),
            "round {round}: the boot did not spend the tombstone",
        );
    }

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}

/// Which pieces a two-piece torrent's resume file records as held: the
/// top-level `pieces` string, one byte a piece, bit 0 set for a piece held.
/// The info dict's `pieces` holds 40 bytes of hashes, so `6:pieces2:` is the
/// top-level one alone.
fn resume_pieces(resume: &[u8]) -> Option<[bool; 2]> {
    const KEY: &[u8] = b"6:pieces2:";
    let at = resume.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let held = resume.get(at..at + 2)?;
    Some([held[0] & 1 == 1, held[1] & 1 == 1])
}

/// Issue #182's acceptance, left to #311: a recheck's verdict survives a
/// SIGKILL straight after it.
///
/// A recheck used to queue no resume save, so until the next 30-minute sweep
/// the resume file still said what the last graceful stop wrote: every piece
/// held, `seed_mode 0`. A crash in that window booted the torrent from it as
/// complete, without hashing, and it seeded a piece it no longer had. Here a
/// two-piece torrent is stopped gracefully, one of its pieces is corrupted in
/// place with the file's size unchanged, and a recheck finds it out; the
/// daemon is killed once the verdict reaches the resume file, and the boot
/// after must not report the torrent complete.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_recheck_verdict_survives_a_sigkill() {
    use std::os::unix::fs::FileExt as _;

    use base64::Engine as _;
    use sha1::Digest;

    const PIECE: usize = 16384;
    let payload: Vec<u8> = (0..2 * PIECE).map(|i| (i % 251) as u8).collect();
    let mut torrent = format!(
        "d4:infod6:lengthi{}e4:name7:recheck12:piece lengthi{PIECE}e6:pieces40:",
        payload.len()
    )
    .into_bytes();
    for piece in payload.chunks(PIECE) {
        torrent.extend_from_slice(&sha1::Sha1::digest(piece));
    }
    torrent.extend_from_slice(b"ee");
    let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
        .unwrap()
        .to_hex();

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let data = p.join("data").join("recheck");
    std::fs::write(&data, &payload).unwrap();
    let resume = p.join("resume").join(PROFILE).join(format!("{ih}.resume"));
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
    let seeding = |what: &str| {
        let seen = settled_in(addr, &ih, Duration::from_secs(60), |phase, progress| {
            phase == "seeding" && progress == 1.0
        });
        assert!(
            seen.is_ok(),
            "{what}: the complete torrent never reached seeding: {seen:?}"
        );
    };

    // Added and hashed complete, then stopped gracefully: its resume file
    // says every piece is held, and not in seed mode.
    let mut child = spawn();
    let (code, body) = http(
        addr,
        "POST",
        "/v1/torrents",
        Some(&format!(
            "{{\"profile_id\":\"{PROFILE}\",\"source\":{{\"kind\":\"metainfo\",\
             \"data\":\"{}\"}}}}",
            base64::engine::general_purpose::STANDARD.encode(&torrent),
        )),
    );
    assert_eq!(code, 201, "{body}");
    seeding("after the add");
    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
    let stopped = std::fs::read(&resume).expect("the graceful stop wrote no resume file");
    assert_eq!(resume_pieces(&stopped), Some([true, true]));
    assert!(
        stopped.windows(14).any(|w| w == b"9:seed_modei0e"),
        "the resume file is not seed_mode 0"
    );

    // Booted from it, the first piece corrupted in place, and rechecked.
    let mut child = spawn();
    seeding("after the restart");
    let file = std::fs::OpenOptions::new().write(true).open(&data).unwrap();
    file.write_all_at(&[!payload[0]], 0).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let (code, body) = http(addr, "POST", &format!("/v1/torrents/{ih}/recheck"), None);
    assert_eq!(code, 202, "{body}");
    let seen = settled_in(addr, &ih, Duration::from_secs(60), |phase, progress| {
        phase == "incomplete" && progress == 0.5
    });
    assert!(
        seen.is_ok(),
        "the recheck did not find the corrupted piece: {seen:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while std::fs::read(&resume)
        .ok()
        .as_deref()
        .and_then(resume_pieces)
        != Some([false, true])
    {
        assert!(
            Instant::now() < deadline,
            "the recheck's verdict did not reach the resume file within 30s",
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // SIGKILL: no drain, no save after this.
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let mut child = spawn();
    // Settled either way: incomplete with the one piece it holds counted, or
    // seeding complete, which is the regression.
    let after = settled_in(addr, &ih, Duration::from_secs(60), |phase, progress| {
        (phase == "incomplete" && progress > 0.0) || (phase == "seeding" && progress == 1.0)
    });
    assert!(
        after
            .as_ref()
            .is_ok_and(|(phase, progress)| phase == "incomplete" && *progress < 1.0),
        "booted after the SIGKILL as {after:?}, not incomplete",
    );

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}

/// Spawn the daemon against `cfg`, its output appended to `log`.
fn start(cfg: &std::path::Path, log: &DaemonLog) -> Running {
    Running(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(cfg)
            .stdout(log.stdio())
            .stderr(log.stdio())
            .spawn()
            .expect("spawn daemon"),
    )
}

/// SIGKILL `child` and reap it: no drain, nothing after this runs.
fn sigkill(mut child: Running) {
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL),
        "the daemon had already exited, as {status:?}, before the kill",
    );
}

/// Add a magnet for each of `ihs` to [`PROFILE`] through the API.
fn add_magnets<'a>(addr: &str, ihs: impl IntoIterator<Item = &'a String>) {
    for ih in ihs {
        let body = add_magnet(&format!("magnet:?xt=urn:btih:{ih}"));
        let (code, answer) = http(addr, "POST", "/v1/torrents", Some(&body));
        assert_eq!(code, 201, "add {ih}: {answer}");
    }
}

/// Wait until the daemon lists exactly `ihs`, each of them once, and every
/// one is loaded into a session: its phase is anything but `unknown`, which
/// the listing reports for a torrent assigned and held by no session.
/// Returns each one's phase.
fn every_one_loaded_once(
    addr: &str,
    ihs: &std::collections::BTreeSet<String>,
    within: Duration,
) -> std::collections::BTreeMap<String, String> {
    let deadline = Instant::now() + within;
    loop {
        let list = listed(addr);
        let phases: std::collections::BTreeMap<String, String> = list.iter().cloned().collect();
        assert_eq!(phases.len(), list.len(), "a torrent is listed twice");
        let missing: Vec<&String> = ihs.iter().filter(|ih| !phases.contains_key(*ih)).collect();
        let extra: Vec<&String> = phases.keys().filter(|ih| !ihs.contains(*ih)).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{} torrents lost, {} never added listed; first lost {:?}, first extra {:?}",
            missing.len(),
            extra.len(),
            missing.first(),
            extra.first(),
        );
        let unloaded = phases.values().filter(|ph| *ph == "unknown").count();
        if unloaded == 0 {
            return phases;
        }
        assert!(
            Instant::now() < deadline,
            "{unloaded} of {} torrents were never loaded into a session within {within:?}",
            ihs.len(),
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The infohash of every `<infohash>.resume` file in [`PROFILE`]'s resume
/// directory under `p`.
fn resume_files(p: &std::path::Path) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(p.join("resume").join(PROFILE))
        .map(|dir| {
            dir.filter_map(|e| {
                let name = e.unwrap().file_name().into_string().ok()?;
                name.strip_suffix(".resume").map(str::to_owned)
            })
            .collect()
        })
        .unwrap_or_default()
}

/// The SIGTERM drain saves every torrent's resume data, not only the ones
/// whose files already exist: a pause made just before the SIGTERM reaches
/// no resume file but by the drain (the periodic sweep is 30 minutes off),
/// and the next boot on the same directory has to load every torrent, that
/// one still paused.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_sigterm_saves_every_torrent_and_a_pause_for_the_next_boot() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let log = DaemonLog::new(p);
    let ihs = infohashes(0x40_0000, 200);
    let paused = ihs.first().unwrap().clone();

    let child = start(&cfg, &log);
    wait_healthy(addr);
    add_magnets(addr, &ihs);
    let (code, body) = http(addr, "POST", &format!("/v1/torrents/{paused}/pause"), None);
    assert!((200..300).contains(&code), "pause: {code} {body}");
    poll("the pause to take", Duration::from_secs(30), || {
        (torrent_phase(addr, &paused).as_deref() == Some("paused")).then_some(())
    });
    child.stop();

    assert_eq!(
        resume_files(p),
        ihs,
        "every torrent has a resume file after the drain"
    );
    let report = std::fs::read_to_string(p.join("last_shutdown.json")).expect("shutdown report");
    assert!(report.contains("\"unsaved_resumes\":0"), "{report}");

    let child = start(&cfg, &log);
    wait_healthy(addr);
    every_one_loaded_once(addr, &ihs, Duration::from_secs(60));
    // A magnet reads `awaiting_metadata` from its add until its first state
    // update, and one never paused goes on reading it after: only the paused
    // one leaves it, so wait for that, which a lost pause never does. For the
    // rest the placeholder cannot be told from the session's word, so the
    // check that none came back paused holds once their updates have landed,
    // which the paused one's having landed makes likely but does not prove.
    let phases = poll(
        "the paused torrent's first state update (none: the pause made before the SIGTERM was \
         lost)",
        Duration::from_secs(60),
        || {
            let phases: std::collections::BTreeMap<String, String> =
                listed(addr).into_iter().collect();
            (phases.values().all(|phase| phase != "unknown")
                && phases
                    .get(&paused)
                    .is_some_and(|phase| phase != "awaiting_metadata"))
            .then_some(phases)
        },
    );
    assert_eq!(
        phases[&paused], "paused",
        "the pause made before the SIGTERM was lost"
    );
    let also_paused: Vec<_> = phases
        .iter()
        .filter(|(ih, phase)| **ih != paused && *phase == "paused")
        .collect();
    assert!(
        also_paused.is_empty(),
        "torrents never paused came back paused: {also_paused:?}"
    );
    child.stop();
}

/// A `kill -9` anywhere in the boot, with 5,000 resume files to scan, loses
/// none of them and duplicates none: the next boot loads every torrent
/// exactly once.
///
/// The boot claims each resume file's torrent in the assignment registry as
/// it loads it, so a kill partway through leaves some claimed and some not.
/// A clean boot is timed first, and three later boots are each killed at a
/// fraction of that while `/healthz` has not yet answered: the HTTP listener
/// binds only once the boot's scans have returned, so an unanswered
/// `/healthz` is a boot that had not finished. A kill that finds the boot
/// already done is repeated sooner.
#[test]
#[ignore = "spawns the real daemon + libtorrent with 5,000 torrents; run with --ignored"]
fn a_sigkill_mid_boot_scan_reloads_every_torrent_once() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let log = DaemonLog::new(p);
    let boot_budget = Duration::from_secs(300);

    // Through the torrent dir, which the first boot adds in one scan: 5,000
    // API adds, each a durable write, take many minutes. The SIGTERM then
    // writes every one's resume file, and from there on the resume scan
    // loads them.
    let store = p.join("torrents").join(PROFILE);
    std::fs::create_dir_all(&store).unwrap();
    let ihs: std::collections::BTreeSet<String> = (0..5_000)
        .map(|i| {
            let torrent = metainfo(&format!("boot{i:04}"), "http://127.0.0.1:1/announce");
            let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
                .unwrap()
                .to_hex();
            std::fs::write(store.join(format!("{ih}.torrent")), &torrent).unwrap();
            ih
        })
        .collect();
    assert_eq!(ihs.len(), 5_000);
    let child = start(&cfg, &log);
    wait_healthy_within(addr, boot_budget);
    every_one_loaded_once(addr, &ihs, boot_budget);
    child.stop();
    assert_eq!(resume_files(p), ihs);

    let started = Instant::now();
    let child = start(&cfg, &log);
    wait_healthy_within(addr, boot_budget);
    let boot = started.elapsed();
    child.stop();

    // A boot runs faster or slower than the timed one, so a kill that lands
    // after it finished is retried at half the delay until one lands inside
    // it. Every kill, inside the boot or not, must lose nothing.
    for fraction in [0.6, 0.4, 0.2] {
        let mut delay = boot.mul_f64(fraction);
        let mut landed = false;
        for _ in 0..6 {
            let child = start(&cfg, &log);
            std::thread::sleep(delay);
            let finished = try_http_as(addr, "GET", "/healthz", None, "localhost")
                .is_ok_and(|(code, _)| code == 200);
            sigkill(child);
            assert_eq!(
                resume_files(p),
                ihs,
                "a kill {delay:?} into the boot lost or made a resume file"
            );
            if !finished {
                landed = true;
                break;
            }
            delay /= 2;
        }
        assert!(
            landed,
            "no kill landed inside the boot, down to {delay:?} of a {boot:?} boot",
        );
    }

    let child = start(&cfg, &log);
    wait_healthy_within(addr, boot_budget);
    every_one_loaded_once(addr, &ihs, boot_budget);
    child.stop();
}

/// Every step of `plan_id`, across every page, as `(seq, status, src)`.
fn plan_steps(addr: &str, plan_id: i64) -> Vec<(i64, String, String)> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(c) => format!("/v1/pool/plans/{plan_id}/steps?limit=1000&cursor={c}"),
            None => format!("/v1/pool/plans/{plan_id}/steps?limit=1000"),
        };
        let (code, body) = http(addr, "GET", &path, None);
        assert_eq!(code, 200, "{path}: {body}");
        let page: serde_json::Value = serde_json::from_str(&body).unwrap();
        for s in page["items"].as_array().expect("items") {
            out.push((
                s["seq"].as_i64().unwrap(),
                s["status"].as_str().unwrap().to_owned(),
                s["src"].as_str().unwrap().to_owned(),
            ));
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => return out,
        }
    }
}

/// Every regular file under `dir`, recursively.
fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                todo.push(e.path());
            } else {
                out.push(e.path());
            }
        }
    }
    out
}

/// A `kill -9` while a large delete plan is applying leaves every step in a
/// state the next boot can account for: a `done` step's file is gone, a
/// `pending` one's is still in place, and the only steps whose outcome is
/// unknown (`in_progress`) are one journal batch's, at most 64 contiguous
/// steps. Nothing is lost either way: every file is in the root or in its
/// trash. The boot's re-drive then finishes the plan when no step's outcome
/// is unknown, and parks it `failed` for a human when one is.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_sigkill_mid_delete_plan_leaves_every_step_recoverable() {
    const FILES: usize = 1_500;
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let root = p.join("pool");
    let library = p.join("library");
    let junk = root.join("junk");
    std::fs::create_dir_all(&library).unwrap();
    for i in 0..FILES {
        let f = junk.join(format!("d{:02}/f{i:05}.bin", i % 20));
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, [1u8]).unwrap();
    }
    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\nallow_mutations = true\n",
        root.display(),
        library.display()
    ));
    std::fs::write(&cfg, text).unwrap();
    let log = DaemonLog::new(p);

    let child = start(&cfg, &log);
    wait_healthy(addr);
    let (code, body) = http_within(addr, "POST", "/v1/pool/scan", Duration::from_secs(120));
    assert_eq!(code, 200, "{body}");
    let (code, body) = http(addr, "GET", "/v1/pool", None);
    assert_eq!(code, 200, "{body}");
    let pool: serde_json::Value = serde_json::from_str(&body).unwrap();
    let root_id = pool["roots"][0]["root_id"].as_i64().expect("a root id");
    let (code, body) = http(
        addr,
        "POST",
        "/v1/pool/plans",
        Some(&format!(
            "{{\"kind\":\"delete_orphans\",\"root_id\":{root_id},\"prefix\":\"junk\"}}"
        )),
    );
    assert_eq!(code, 201, "{body}");
    let plan: serde_json::Value = serde_json::from_str(&body).unwrap();
    let plan_id = plan["id"].as_i64().unwrap();
    assert_eq!(plan["step_counts"]["total"].as_u64(), Some(FILES as u64));
    let token = plan["confirm_token"].as_str().expect("a delete's token");

    // The apply answers only once it is done, which the kill forestalls.
    let apply = {
        let (addr, body) = (addr.clone(), format!("{{\"confirm_token\":\"{token}\"}}"));
        std::thread::spawn(move || {
            let path = format!("/v1/pool/plans/{plan_id}/apply");
            try_http_as(&addr, "POST", &path, Some(&body), "localhost")
        })
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let left = files_under(&junk).len();
        assert!(
            left > 0,
            "the plan finished before the kill; nothing was interrupted"
        );
        if left <= FILES - 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the apply never got going: {left} files left"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    sigkill(child);
    let _ = apply.join();

    let left = files_under(&junk);
    let trashed = files_under(&root.join(".torrentd-trash"));
    assert_eq!(
        left.len() + trashed.len(),
        FILES,
        "a file was lost: {} left in place and {} in the trash",
        left.len(),
        trashed.len(),
    );

    let child = start(&cfg, &log);
    wait_healthy(addr);
    let status = poll(
        "the boot's re-drive to settle the plan",
        Duration::from_secs(120),
        || {
            let (code, body) = http(addr, "GET", &format!("/v1/pool/plans/{plan_id}"), None);
            assert_eq!(code, 200, "{body}");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let status = v["status"].as_str().unwrap().to_owned();
            (status != "applying").then_some(status)
        },
    );
    let steps = plan_steps(addr, plan_id);
    assert_eq!(steps.len(), FILES);
    let unknown: Vec<i64> = steps
        .iter()
        .filter(|(_, status, _)| status == "in_progress")
        .map(|(seq, _, _)| *seq)
        .collect();
    for (seq, status, src) in &steps {
        let present = std::path::Path::new(src).exists();
        match status.as_str() {
            "done" => assert!(!present, "step {seq} is done and {src} is still there"),
            "pending" => assert!(present, "step {seq} is pending and {src} is gone"),
            "in_progress" => {}
            other => panic!("step {seq} is {other} after a kill and a re-drive"),
        }
    }
    if unknown.is_empty() {
        assert_eq!(
            status, "applied",
            "nothing was unknown, so the re-drive finishes"
        );
        assert!(files_under(&junk).is_empty());
    } else {
        assert_eq!(status, "failed", "a step of unknown outcome parks the plan");
        assert!(
            unknown.len() <= 64,
            "{} steps of unknown outcome, more than one journal batch",
            unknown.len(),
        );
        assert!(
            unknown.windows(2).all(|w| w[1] == w[0] + 1),
            "the unknown steps are not one batch: {unknown:?}",
        );
    }
    let trashed = files_under(&root.join(".torrentd-trash"));
    assert_eq!(files_under(&junk).len() + trashed.len(), FILES);
    child.stop();
}
