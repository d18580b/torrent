//! The pool: scans, adoption and its verification, and payload deletes.

use super::*;

/// Issue #76's acceptance: a scan of a million files leaves the daemon
/// responsive. While it runs, `/healthz` keeps answering 200, the systemd
/// watchdog keeps being pinged, and every page of `/v1/pool/torrents` answers
/// in under 200 ms.
///
/// Before, every pool read waited on the one index mutex the scan holds for
/// its whole run, so a page answered only when the scan ended. The library
/// is indexed by a first scan before the files exist, so the pages read
/// during the second are a real library's, from the last committed index.
///
/// `TORRENTD_SCALE_FILES` sets the file count; a million when unset.
#[test]
#[ignore = "spawns the real daemon + libtorrent and writes a million files; run with --ignored"]
fn a_million_file_scan_leaves_the_daemon_responsive() {
    const PAGE_BUDGET: Duration = Duration::from_millis(200);
    const LIBRARY: usize = 2_000;
    const WATCHDOG_USEC: u64 = 2_000_000;
    let files: usize = std::env::var("TORRENTD_SCALE_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let root = p.join("pool");
    let library = p.join("library");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&library).unwrap();
    for i in 0..LIBRARY {
        std::fs::write(
            library.join(format!("t{i}.torrent")),
            metainfo(&format!("payload-{i}"), "http://tracker.example/announce"),
        )
        .unwrap();
    }

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\n",
        root.display(),
        library.display()
    ));
    std::fs::write(&cfg, text).unwrap();

    // systemd's side of the watchdog: a datagram socket the daemon pings,
    // every `WATCHDOG_USEC / 2`.
    let sock_path = p.join("notify.sock");
    let sock = std::os::unix::net::UnixDatagram::bind(&sock_path).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let pings = std::sync::Arc::new(parking_lot::Mutex::new(Vec::<Instant>::new()));
    let listening = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let listener = {
        let (pings, listening) = (pings.clone(), listening.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while listening.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(n) = sock.recv(&mut buf) {
                    if String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .any(|l| l == "WATCHDOG=1")
                    {
                        pings.lock().push(Instant::now());
                    }
                }
            }
        })
    };

    // Killed if an assertion below panics, before the directory it writes
    // into is removed, rather than left running.
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // Its output, printed if anything below panics: declared before `child`,
    // so it is read once the daemon is dead.
    let log = DaemonLog::new(p);
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .env("NOTIFY_SOCKET", &sock_path)
            .env("WATCHDOG_USEC", WATCHDOG_USEC.to_string())
            .env_remove("WATCHDOG_PID")
            .stdout(log.stdio())
            .stderr(log.stdio())
            .spawn()
            .expect("spawn daemon"),
    );
    // A longer boot deadline than the other tests': this one boots while the
    // rest of Layer 3 starts its own daemons and libtorrent sessions on the
    // same runner, and 30s once proved too little on CI (issue #359).
    wait_healthy_within(addr, Duration::from_secs(120));

    // The library alone, so the index the second scan replaces holds it.
    let (code, body) = http_within(addr, "POST", "/v1/pool/scan", Duration::from_secs(600));
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(&format!("\"torrents\":{LIBRARY}")), "{body}");

    // A million files, a thousand to a directory.
    for i in 0..files {
        let dir = root.join(format!("d{:04}", i / 1000));
        if i % 1000 == 0 {
            std::fs::create_dir_all(&dir).unwrap();
        }
        std::fs::File::create(dir.join(format!("f{i}"))).unwrap();
    }

    let scan = {
        let addr = addr.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            let r = http_within(&addr, "POST", "/v1/pool/scan", Duration::from_secs(3600));
            (r, started.elapsed())
        })
    };

    let mut samples = 0usize;
    let mut slowest = Duration::ZERO;
    let mut cursor: Option<String> = None;
    let started = Instant::now();
    while !scan.is_finished() {
        // A generous read timeout, so a slow answer fails on its measured
        // latency rather than on a socket error.
        let (code, body) = http_within(addr, "GET", "/healthz", Duration::from_secs(60));
        assert_eq!(code, 200, "/healthz during the scan: {body}");

        let path = match &cursor {
            Some(c) => format!("/v1/pool/torrents?limit=100&cursor={c}"),
            None => "/v1/pool/torrents?limit=100".to_owned(),
        };
        let asked = Instant::now();
        let (code, body) = http_within(addr, "GET", &path, Duration::from_secs(60));
        let took = asked.elapsed();
        assert_eq!(code, 200, "{path} during the scan: {body}");
        assert!(
            took < PAGE_BUDGET,
            "{path} took {took:?} during the scan, over {PAGE_BUDGET:?}",
        );
        let page: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(page["items"].as_array().map(Vec::len), Some(100), "{body}");
        cursor = page["next_cursor"].as_str().map(str::to_owned);
        slowest = slowest.max(took);
        samples += 1;
        std::thread::sleep(Duration::from_millis(250));
    }
    let ((code, body), took) = scan.join().unwrap();
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(&format!("\"files\":{files}")), "{body}");
    assert!(
        samples >= 4,
        "the scan ended after {took:?}, too soon to have been observed ({samples} samples)",
    );

    // The watchdog kept being pinged throughout: no gap between pings across
    // the scan is longer than the interval systemd would kill the unit at.
    let pings = pings.lock().clone();
    let during: Vec<Instant> = pings
        .iter()
        .copied()
        .filter(|t| *t >= started && *t <= started + took)
        .collect();
    assert!(
        during.len() >= 2,
        "{} watchdog pings during a {took:?} scan",
        during.len()
    );
    let mut edges = vec![started];
    edges.extend(&during);
    edges.push(started + took);
    let widest = edges
        .windows(2)
        .map(|w| w[1] - w[0])
        .max()
        .unwrap_or_default();
    assert!(
        widest < Duration::from_micros(WATCHDOG_USEC),
        "the watchdog went {widest:?} without a ping during the scan",
    );
    eprintln!(
        "{files} files scanned in {took:?}; {samples} pages, slowest {slowest:?}; {} pings",
        during.len()
    );

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(60));
    listening.store(false, std::sync::atomic::Ordering::Relaxed);
    listener.join().unwrap();
}

/// Issue #432: a bulk adopt of ten thousand torrents never has more than
/// `[pool] max_concurrent_verify` of them verifying at once. `GET /v1/pool`
/// is sampled from when the adopt request is sent, through the request
/// adding every torrent, until the queue drains or fifteen seconds of
/// verification have been watched after it answered: `verify_in_flight`
/// never exceeds the limit, the queue never holds more than was adopted, and
/// checks keep completing.
///
/// `TORRENTD_SCALE_ADOPT` sets the torrent count; ten thousand when unset.
/// At ten thousand the test takes minutes in a debug build, nearly all of it
/// the adopt request itself.
#[test]
#[ignore = "spawns the real daemon + libtorrent and adopts ten thousand torrents; run with --ignored"]
fn a_bulk_adopt_verifies_at_most_the_verify_limit_at_once() {
    use sha1::Digest;

    const LIMIT: u64 = 4;
    const WATCH: Duration = Duration::from_secs(15);
    let count: u64 = std::env::var("TORRENTD_SCALE_ADOPT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let root = p.join("pool");
    let library = p.join("library");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&library).unwrap();
    // One one-byte payload file per torrent, and a `.torrent` whose piece
    // hash it matches, so every verification passes.
    let piece = sha1::Sha1::digest(b"x");
    for i in 0..count {
        let name = format!("p{i}");
        std::fs::write(root.join(&name), b"x").unwrap();
        let mut t = format!(
            "d4:infod6:lengthi1e4:name{}:{name}12:piece lengthi16384e6:pieces20:",
            name.len()
        )
        .into_bytes();
        t.extend_from_slice(&piece);
        t.extend_from_slice(b"ee");
        std::fs::write(library.join(format!("{name}.torrent")), t).unwrap();
    }

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\nmax_concurrent_verify = {LIMIT}\n",
        root.display(),
        library.display()
    ));
    std::fs::write(&cfg, text).unwrap();

    // Killed if an assertion below panics, rather than left running.
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let log = DaemonLog::new(p);
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .stdout(log.stdio())
            .stderr(log.stdio())
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy_within(addr, Duration::from_secs(120));

    let (code, body) = http_within(addr, "POST", "/v1/pool/scan", Duration::from_secs(600));
    assert_eq!(code, 200, "{body}");
    let scan: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(scan["torrents"], count, "{body}");
    assert_eq!(scan["matched"], count, "{body}");
    let (code, body) = http(addr, "GET", "/v1/pool", None);
    assert_eq!(code, 200, "{body}");
    let pool: serde_json::Value = serde_json::from_str(&body).unwrap();
    let root_id = pool["roots"][0]["root_id"].as_i64().unwrap();

    let adopt = {
        let addr = addr.clone();
        let req = format!(
            "{{\"profile_id\":\"{PROFILE}\",\"selector\":{{\"kind\":\"subtree\",\
             \"root_id\":{root_id},\"path\":\"\"}}}}"
        );
        std::thread::spawn(move || {
            http_body_within(
                &addr,
                "POST",
                "/v1/pool/adoptions",
                &req,
                Duration::from_secs(1800),
            )
        })
    };

    let mut samples = 0u64;
    let mut widest = 0u64;
    let mut adopted: Option<Instant> = None;
    // Fewest torrents seen waiting or verifying since the adopt answered.
    let mut least_left = count;
    loop {
        let (code, body) = http(addr, "GET", "/v1/pool", None);
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let in_flight = v["verify_in_flight"].as_u64().unwrap();
        let depth = v["verify_queue_depth"].as_u64().unwrap();
        assert!(
            in_flight <= LIMIT,
            "{in_flight} verifying at once, over max_concurrent_verify = {LIMIT}: {body}",
        );
        assert!(
            depth + in_flight <= count,
            "{depth} waiting and {in_flight} verifying, of {count} adopted: {body}",
        );
        widest = widest.max(in_flight);
        samples += 1;
        if adopted.is_none() && adopt.is_finished() {
            adopted = Some(Instant::now());
        }
        if let Some(at) = adopted {
            least_left = least_left.min(depth + in_flight);
            if depth + in_flight == 0 || at.elapsed() >= WATCH {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let (code, body) = adopt.join().unwrap();
    assert_eq!(code, 200, "{body}");
    let result: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        result["queued_for_verification"].as_array().map(Vec::len),
        Some(count as usize),
        "every torrent goes down the verify path: {}",
        &body[..body.len().min(500)],
    );
    // The bound was met under load, not merely never approached: the queue
    // filled every slot, and enough checks finished for several rounds of
    // admission to have been watched.
    assert_eq!(widest, LIMIT.min(count), "never saw every slot in use");
    let done = count - least_left;
    assert!(
        done >= (3 * LIMIT).min(count),
        "only {done} of {count} verifications finished in {WATCH:?}",
    );
    eprintln!("{count} adopted; {samples} samples, at most {widest} verifying; {done} verified");

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(120));
}

/// Issue #108's acceptance: a torrent the pool adopts keeps its metadata
/// across a restart.
///
/// The resume scan attaches metadata from the torrent store alone, and
/// adoption never wrote there, so an adopted torrent came back with none —
/// and on a private profile never seeded again. The adoption now writes its
/// `.torrent` to the store; and a torrent adopted before it did, with no
/// `.torrent` in the store, is re-attached from the library's copy, which
/// the boot writes back.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn an_adopted_torrent_keeps_its_metadata_across_a_restart() {
    use sha1::Digest;

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let root = p.join("pool");
    let library = p.join("library");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&library).unwrap();
    // A one-byte payload and a `.torrent` whose piece hash it matches, so the
    // verify the adoption runs passes.
    std::fs::write(root.join("a"), b"x").unwrap();
    let mut torrent = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    torrent.extend_from_slice(&sha1::Sha1::digest(b"x"));
    torrent.extend_from_slice(b"ee");
    std::fs::write(library.join("t.torrent"), &torrent).unwrap();
    let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
        .unwrap()
        .to_hex();

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\n",
        root.display(),
        library.display()
    ));
    std::fs::write(&cfg, text).unwrap();
    let stored = p
        .join("torrents")
        .join(PROFILE)
        .join(format!("{ih}.torrent"));
    // Killed if an assertion below panics, rather than left running with the
    // test harness's output pipes open.
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
    let stop = |mut child: KillOnDrop| {
        sigterm(&child.0);
        assert_exits_zero(&mut child.0, Duration::from_secs(30));
    };

    let child = spawn();
    let (code, body) = http(addr, "POST", "/v1/pool/scan", None);
    assert_eq!(code, 200, "{body}");
    let (code, body) = http(
        addr,
        "POST",
        "/v1/pool/adoptions",
        Some(&format!(
            "{{\"profile_id\":\"{PROFILE}\",\"selector\":{{\"kind\":\"infohashes\",\
             \"infohashes\":[\"{ih}\"]}}}}"
        )),
    );
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(&ih), "{body}");
    // The verify queue admits it within a tick or two.
    assert_eq!(
        session_name(addr, &ih, Duration::from_secs(30)).as_deref(),
        Some("a"),
        "the adopted torrent never loaded",
    );
    // The verify queue writes the `.torrent` once the session holds the
    // torrent, so the session can report it a moment before the write lands.
    assert_eq!(
        read_within(&stored, Duration::from_secs(10)).as_deref(),
        Some(torrent.as_slice()),
        "the adoption did not write its .torrent to the torrent store",
    );
    stop(child);

    // Restarted, it loads from its resume data with its metadata.
    let child = spawn();
    assert_eq!(
        session_name(addr, &ih, Duration::from_secs(10)).as_deref(),
        Some("a"),
        "the adopted torrent came back from a restart without its metadata",
    );
    stop(child);

    // Adopted before the store was written to: no `.torrent` there. The boot
    // takes the library's, and keeps it.
    std::fs::remove_file(&stored).unwrap();
    let child = spawn();
    assert_eq!(
        session_name(addr, &ih, Duration::from_secs(10)).as_deref(),
        Some("a"),
        "the resume scan did not fall back to the pool library's .torrent",
    );
    assert_eq!(
        std::fs::read(&stored).ok().as_deref(),
        Some(torrent.as_slice()),
        "the boot did not write the library's .torrent back to the store",
    );
    stop(child);
}

/// Issue #215's acceptance: a `.torrent` added over the API, or found in the
/// profile's `torrent_dir` at boot, is hash-checked before it seeds.
///
/// Both paths used to add in libtorrent's seed mode, which assumes every
/// piece is correct and checks no more than file sizes, so a torrent whose
/// payload was the right length but not yet written reported `seeding` and
/// announced itself complete until a peer's request failed a piece. Here a
/// complete payload still reaches `seeding`; an absent, a truncated and an
/// unwritten one over the API, and an unwritten one from the torrent-dir
/// scan, settle `incomplete` and are never `seeding`.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn an_add_whose_payload_is_absent_or_wrong_is_never_reported_seeding() {
    use base64::Engine as _;
    use sha1::Digest;

    // A one-file, one-piece `.torrent` named `name` over `payload`.
    let torrent = |name: &str, payload: &[u8]| {
        let mut t = format!(
            "d4:infod6:lengthi{}e4:name{}:{name}12:piece lengthi16384e6:pieces20:",
            payload.len(),
            name.len()
        )
        .into_bytes();
        t.extend_from_slice(&sha1::Sha1::digest(payload));
        t.extend_from_slice(b"ee");
        t
    };
    let hex = |t: &[u8]| libtorrent_safe::info_hash_from_torrent(t).unwrap().to_hex();

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let data = p.join("data");
    let complete = torrent("complete", b"xy");
    std::fs::write(data.join("complete"), b"xy").unwrap();
    let absent = torrent("absent", b"xy");
    let truncated = torrent("truncated", b"xy");
    std::fs::write(data.join("truncated"), b"x").unwrap();
    // Full length, wrong bytes: a copy still in flight into a preallocated
    // file. A size check passes it, and only hashing finds it out.
    let unwritten = torrent("unwritten", b"xy");
    std::fs::write(data.join("unwritten"), [0u8; 2]).unwrap();
    let dir_unwritten = torrent("dir_unwritten", b"xy");
    std::fs::write(data.join("dir_unwritten"), [0u8; 2]).unwrap();
    let torrents = p.join("torrents").join(PROFILE);
    std::fs::create_dir_all(&torrents).unwrap();
    std::fs::write(
        torrents.join(format!("{}.torrent", hex(&dir_unwritten))),
        &dir_unwritten,
    )
    .unwrap();

    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy(addr);

    for t in [&complete, &absent, &truncated, &unwritten] {
        let (code, body) = http(
            addr,
            "POST",
            "/v1/torrents",
            Some(&format!(
                "{{\"profile_id\":\"{PROFILE}\",\"source\":{{\"kind\":\"metainfo\",\
                 \"data\":\"{}\"}}}}",
                base64::engine::general_purpose::STANDARD.encode(t),
            )),
        );
        assert_eq!(code, 201, "{body}");
    }

    let unverifiable = [
        ("absent", hex(&absent)),
        ("truncated", hex(&truncated)),
        ("unwritten", hex(&unwritten)),
        ("dir_unwritten", hex(&dir_unwritten)),
    ];
    let complete = hex(&complete);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut settled = torrent_phase(addr, &complete).as_deref() == Some("seeding");
        for (name, ih) in &unverifiable {
            let phase = torrent_phase(addr, ih);
            assert_ne!(
                phase.as_deref(),
                Some("seeding"),
                "{name}: reported seeding with its payload unverifiable",
            );
            settled &= phase.as_deref() == Some("incomplete");
        }
        if settled {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not settled within 60s: complete {:?}, {:?}",
            torrent_phase(addr, &complete),
            unverifiable
                .iter()
                .map(|(name, ih)| (name, torrent_phase(addr, ih)))
                .collect::<Vec<_>>(),
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}

/// Issue #187's acceptance: a restart while an adoption is still hashing
/// records the verdict the boot's check reaches, as the adoption would have
/// without the restart.
///
/// An 8 GiB sparse payload with one wrong byte in its last piece is adopted
/// without resume data, so the verify queue hashes it. One graceful SIGTERM
/// lands while it is still `checking`. The worker used to forget the
/// adoption's persisted queue entry once the session held the torrent, and
/// the boot forgot every entry a scan loaded, so after the restart nothing
/// waited for the check: the torrent came back `incomplete`, unpaused and
/// announcing, and the pool index said `matched`. It has to end `paused` and
/// `drifted`.
#[test]
#[ignore = "spawns the real daemon + libtorrent and hashes 8 GiB; run with --ignored"]
fn a_restart_while_an_adoption_hashes_still_records_its_verdict() {
    restart_mid_verification(Stop::Term, Interrupt::WhileChecking);
}

/// [`a_restart_while_an_adoption_hashes_still_records_its_verdict`] with
/// the daemon killed rather than stopped: no drain, no resume save, no
/// shutdown of the verify queue. The adoption's queue entry is all the next
/// boot has to go on, and it must still hash the payload and record the
/// verdict.
#[test]
#[ignore = "spawns the real daemon + libtorrent and hashes 8 GiB; run with --ignored"]
fn a_sigkill_while_an_adoption_hashes_still_records_its_verdict() {
    restart_mid_verification(Stop::Kill, Interrupt::WhileChecking);
}

/// A SIGKILL straight after the adoption is answered
/// `queued_for_verification`, while the verify queue is admitting it: the
/// persisted queue entry is requeued at the next boot, and the payload is
/// hashed and its verdict recorded as if nothing had happened.
#[test]
#[ignore = "spawns the real daemon + libtorrent and hashes 8 GiB; run with --ignored"]
fn a_sigkill_during_verify_admission_requeues_the_adoption() {
    restart_mid_verification(Stop::Kill, Interrupt::AtAdmission);
}

/// How a test ends a daemon it restarts.
#[derive(Clone, Copy, Debug)]
enum Stop {
    /// SIGTERM, and a clean exit within the bound.
    Term,
    /// SIGKILL: nothing after it runs.
    Kill,
}

/// Where [`restart_mid_verification`] interrupts the adoption.
#[derive(Clone, Copy, Debug)]
enum Interrupt {
    /// As soon as the adoption is answered, before or while the verify queue
    /// admits it.
    AtAdmission,
    /// Once libtorrent reports it `checking`.
    WhileChecking,
}

/// Adopt an 8 GiB payload with one wrong byte, stop the daemon at `at` by
/// `stop`, and boot it again: the torrent has to end `paused` and the index
/// `drifted`, whatever the stop interrupted.
fn restart_mid_verification(stop: Stop, at: Interrupt) {
    use sha1::Digest;

    const PIECE: u64 = 16 << 20;
    const SIZE: u64 = 8 << 30;
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let root = p.join("pool");
    let library = p.join("library");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&library).unwrap();
    // Sparse, so it costs no disk: every byte reads as zero but the last.
    let payload = std::fs::File::create(root.join("big")).unwrap();
    payload.set_len(SIZE).unwrap();
    {
        use std::os::unix::fs::FileExt;
        payload.write_at(&[1], SIZE - 1).unwrap();
    }
    drop(payload);
    // Every piece's hash is the all-zero piece's, so the last one fails.
    let zero = sha1::Sha1::digest(vec![0u8; PIECE as usize]);
    let mut torrent = format!(
        "d4:infod6:lengthi{SIZE}e4:name3:big12:piece lengthi{PIECE}e6:pieces{}:",
        SIZE / PIECE * 20
    )
    .into_bytes();
    for _ in 0..SIZE / PIECE {
        torrent.extend_from_slice(&zero);
    }
    torrent.extend_from_slice(b"ee");
    std::fs::write(library.join("t.torrent"), &torrent).unwrap();
    let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
        .unwrap()
        .to_hex();

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\n",
        root.display(),
        library.display()
    ));
    std::fs::write(&cfg, text).unwrap();
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

    let mut child = spawn();
    let (code, body) = http(addr, "POST", "/v1/pool/scan", None);
    assert_eq!(code, 200, "{body}");
    let (code, body) = http(
        addr,
        "POST",
        "/v1/pool/adoptions",
        Some(&format!(
            "{{\"profile_id\":\"{PROFILE}\",\"selector\":{{\"kind\":\"infohashes\",\
             \"infohashes\":[\"{ih}\"]}}}}"
        )),
    );
    assert_eq!(code, 200, "{body}");
    assert!(body.contains("queued_for_verification"), "{body}");
    if let Interrupt::WhileChecking = at {
        // The verify queue admits it within a tick or two, and 8 GiB takes
        // libtorrent a good while longer than that to hash.
        let deadline = Instant::now() + Duration::from_secs(30);
        while torrent_phase(addr, &ih).as_deref() != Some("checking") {
            assert!(
                Instant::now() < deadline,
                "the adoption never started hashing: {:?}",
                torrent_phase(addr, &ih),
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    match stop {
        Stop::Term => {
            sigterm(&child.0);
            assert_exits_zero(&mut child.0, Duration::from_secs(60));
        }
        Stop::Kill => {
            child.0.kill().unwrap();
            child.0.wait().unwrap();
        }
    }

    let _child = spawn();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let phase = torrent_phase(addr, &ih);
        let state = pool_state(addr, &ih);
        if phase.as_deref() == Some("paused") && state.as_deref() == Some("drifted") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "after a {stop:?} {at:?} the failed payload was left {phase:?} and \
             indexed {state:?}, not paused and drifted",
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Issue #192's acceptance: `delete_files` refuses a payload another loaded
/// torrent has files at, however that torrent was added.
///
/// T1 is adopted from the pool into one profile, so the index records it
/// claiming the file. T2 — the same file, another infohash, as a cross-seed
/// tool would add it — goes through `POST /v1/torrents` into a second
/// profile with a `save_path` over the same directory, and claims nothing.
/// The co-claimant check reads the index alone, so it used to find nobody
/// sharing T1's payload and move the file T2 was serving into the trash.
/// The delete has to be refused, and the file left where T2 reads it; once
/// T2 is gone, the same delete goes through.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn delete_files_refuses_a_payload_a_torrent_added_over_it_still_serves() {
    use base64::Engine as _;
    use sha1::Digest;

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let root = p.join("pool");
    let library = p.join("library");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&library).unwrap();
    let file = root.join("a");
    std::fs::write(&file, b"x").unwrap();
    // One file, `a`, whose piece hash the payload matches. T2 differs only by
    // a `source` key in its info dict, which changes the infohash and
    // nothing about the files.
    let torrent = |source: &str| {
        let mut t = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
        t.extend_from_slice(&sha1::Sha1::digest(b"x"));
        if !source.is_empty() {
            t.extend_from_slice(format!("6:source{}:{source}", source.len()).as_bytes());
        }
        t.extend_from_slice(b"ee");
        t
    };
    let (t1, t2) = (torrent(""), torrent("cross-seed"));
    std::fs::write(library.join("t1.torrent"), &t1).unwrap();
    let hex = |t: &[u8]| libtorrent_safe::info_hash_from_torrent(t).unwrap().to_hex();
    let (ih1, ih2) = (hex(&t1), hex(&t2));
    assert_ne!(ih1, ih2);

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[[profile]]\nid = \"cross\"\nnetwork = \"host\"\n\
         listen_interfaces = \"127.0.0.1:{}\"\n\
         \n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\nallow_mutations = true\n",
        free_port(),
        root.display(),
        library.display()
    ));
    std::fs::write(&cfg, text).unwrap();
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy(addr);

    let (code, body) = http(addr, "POST", "/v1/pool/scan", None);
    assert_eq!(code, 200, "{body}");
    let (code, body) = http(
        addr,
        "POST",
        "/v1/pool/adoptions",
        Some(&format!(
            "{{\"profile_id\":\"{PROFILE}\",\"selector\":{{\"kind\":\"infohashes\",\
             \"infohashes\":[\"{ih1}\"]}}}}"
        )),
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        session_name(addr, &ih1, Duration::from_secs(30)).as_deref(),
        Some("a"),
        "the adopted torrent never loaded",
    );
    let (code, body) = http(
        addr,
        "POST",
        "/v1/torrents",
        Some(&format!(
            "{{\"profile_id\":\"cross\",\"save_path\":\"{}\",\"source\":{{\"kind\":\
             \"metainfo\",\"data\":\"{}\"}}}}",
            root.display(),
            base64::engine::general_purpose::STANDARD.encode(&t2),
        )),
    );
    assert_eq!(code, 201, "{body}");
    assert_eq!(
        session_name(addr, &ih2, Duration::from_secs(30)).as_deref(),
        Some("a"),
        "the cross-seed never loaded",
    );

    let delete_t1 = format!("/v1/torrents/{ih1}?delete_files=true&confirm={ih1}");
    let (code, body) = http(addr, "DELETE", &delete_t1, None);
    assert_eq!(code, 409, "{body}");
    assert!(body.contains("payload-shared"), "{body}");
    assert!(
        body.contains(&ih2),
        "the refusal names the cross-seed: {body}"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"x",
        "the cross-seed's file left its place"
    );
    assert!(!root.join(".torrentd-trash").exists());
    assert!(torrent_phase(addr, &ih1).is_some(), "T1 left its session");

    // With the cross-seed gone, nothing else serves the file, and the same
    // delete moves it to the trash. Its session settles the removal a moment
    // after the 204, until when the file is still its.
    let (code, body) = http(addr, "DELETE", &format!("/v1/torrents/{ih2}"), None);
    assert_eq!(code, 204, "{body}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (code, body) = http(addr, "DELETE", &delete_t1, None);
        if code == 204 {
            break;
        }
        assert!(
            code == 409 && Instant::now() < deadline,
            "the delete with the cross-seed gone: {code} {body}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(!file.exists(), "the payload was not moved to the trash");

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}

/// Issue #199's acceptance: a rescan never relabels an adopted torrent a
/// session still holds, whatever its payload reads as.
///
/// A root unmounted for maintenance used to commit an empty index for it, so
/// the rescan turned every adopted torrent on it `missing` while its session
/// went on seeding, and the rescan after the remount `matched`: the index
/// offered them all for adoption again. Removed, the root keeps its previous
/// index; with the root present but the payload gone, the matcher keeps the
/// verdict of a torrent a session holds. Back in place, it is still adopted.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_rescan_with_the_root_or_payload_gone_keeps_a_loaded_torrent_adopted() {
    use sha1::Digest;

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let root = p.join("pool");
    let away = p.join("pool-unmounted");
    let library = p.join("library");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&library).unwrap();
    std::fs::write(root.join("a"), b"x").unwrap();
    let mut torrent = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    torrent.extend_from_slice(&sha1::Sha1::digest(b"x"));
    torrent.extend_from_slice(b"ee");
    std::fs::write(library.join("t.torrent"), &torrent).unwrap();
    let ih = libtorrent_safe::info_hash_from_torrent(&torrent)
        .unwrap()
        .to_hex();

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\n",
        root.display(),
        library.display()
    ));
    std::fs::write(&cfg, text).unwrap();
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy(addr);

    let scan = || {
        let (code, body) = http(addr, "POST", "/v1/pool/scan", None);
        assert_eq!(code, 200, "{body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()
    };
    scan();
    let (code, body) = http(
        addr,
        "POST",
        "/v1/pool/adoptions",
        Some(&format!(
            "{{\"profile_id\":\"{PROFILE}\",\"selector\":{{\"kind\":\"infohashes\",\
             \"infohashes\":[\"{ih}\"]}}}}"
        )),
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        session_name(addr, &ih, Duration::from_secs(30)).as_deref(),
        Some("a"),
        "the adopted torrent never loaded",
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while pool_state(addr, &ih).as_deref() != Some("adopted") {
        assert!(
            Instant::now() < deadline,
            "the adoption never recorded `adopted`: {:?}",
            pool_state(addr, &ih),
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // The root unmounted: counted as an error, and its previous index kept.
    std::fs::rename(&root, &away).unwrap();
    let summary = scan();
    assert!(summary["errors"].as_u64().unwrap() >= 1, "{summary}");
    assert_eq!(
        pool_state(addr, &ih).as_deref(),
        Some("adopted"),
        "{summary}"
    );

    // The root back without the payload: the index finds nothing, and the
    // session still holds the torrent.
    std::fs::create_dir_all(&root).unwrap();
    let summary = scan();
    assert_eq!(summary["missing"], 1, "{summary}");
    assert_eq!(
        pool_state(addr, &ih).as_deref(),
        Some("adopted"),
        "{summary}"
    );

    // The payload back.
    std::fs::remove_dir(&root).unwrap();
    std::fs::rename(&away, &root).unwrap();
    let summary = scan();
    assert_eq!(summary["matched"], 1, "{summary}");
    assert_eq!(
        pool_state(addr, &ih).as_deref(),
        Some("adopted"),
        "{summary}"
    );

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}
