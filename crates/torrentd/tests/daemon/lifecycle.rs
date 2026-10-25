//! One daemon per state directory and uid, and a SIGTERM's drain and exit.

use super::*;

/// An HTTP bind failure happens after `boot` has handed teardown to the
/// shutdown path, so it must run that path rather than return past it: exit
/// 70, and drain exactly as a SIGTERM does. The dht profile's session state is
/// the observable half of that drain on a host profile; the kill switch and
/// tunnel teardown that follow it in the same fall-through need a VPN and are
/// not reachable here.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn daemon_http_bind_failure_still_drains() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy an HTTP port");
    let addr = occupied.local_addr().unwrap().to_string();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, free_port(), &addr);

    let status = wait_exit(&mut child, Duration::from_secs(30))
        .expect("daemon did not exit within 30s of failing to bind its HTTP listener");
    assert_eq!(status.code(), Some(70), "bind failure must exit 70");
    assert!(
        p.join(format!("session_state-{PROFILE}.dat")).exists(),
        "a bind failure must run the shutdown drain, which writes session state"
    );
}

/// A second daemon against the same state directory refuses at once, naming
/// the running one, and leaves it serving.
///
/// The second start is given ports of its own, so nothing but the
/// single-instance lock can stop it. Without the lock it came up healthy
/// beside the first — and with `network_kill_switch` it would have replaced
/// the first one's nftables table on the way, which is the harm the lock is
/// for and which needs a VPN to observe directly.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_second_daemon_on_the_same_state_dir_refuses_and_leaves_the_first_running() {
    let addr = free_http();
    let addr = addr.as_str();
    let second_addr = free_http();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut first = spawn_daemon(p, free_port(), addr);
    wait_healthy(addr);

    // Same state directory, different ports. The first daemon has already
    // read `cfg.toml`, so rewriting it for the second changes nothing for it.
    let cfg = write_config(p, free_port(), &second_addr);
    let mut second = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn second daemon");

    let exited = wait_exit(&mut second, Duration::from_secs(10));
    let mut out = String::new();
    second
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .unwrap();
    second
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut out)
        .unwrap();
    let exited = exited
        .unwrap_or_else(|| panic!("the second daemon did not refuse within 10s; output: {out}"));
    assert_eq!(
        exited.code(),
        Some(70),
        "a refused start exits 70 like every other startup failure; output: {out}"
    );
    assert!(
        out.contains("single-instance lock") && out.contains(&format!("pid {}", first.id())),
        "the refusal names the lock and the running daemon's pid: {out}"
    );
    assert!(
        TcpStream::connect(&second_addr).is_err(),
        "the second daemon got as far as binding its HTTP port"
    );

    // The first is untouched and still serving.
    assert_eq!(http(addr, "GET", "/healthz", None).0, 200);
    sigterm(&first);
    assert_exits_zero(&mut first, Duration::from_secs(30));
}

/// A second start under the same uid on a *different* state directory, which
/// the single-instance lock cannot see, is refused by the kill-switch table
/// lock: the `inet torrentd_ks_<uid>` table is per uid, and every boot
/// replaces it (switch on) or removes it as stale (switch off). The refusal
/// exits 78, which the unit does not restart, and names the running daemon's
/// pid. Without the lock the second came up healthy beside the first, and a
/// boot of it would have removed or replaced the first one's kill switch.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_second_daemon_of_the_same_uid_on_another_state_dir_exits_ex_config() {
    let addr = free_http();
    let addr = addr.as_str();
    let second_addr = free_http();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    // Killed on a panic: left running, it would hold the lock against every
    // test after this one.
    let first = Running(spawn_daemon(first_dir.path(), free_port(), addr));
    wait_healthy(addr);

    // At info, so the second's output shows how far its boot got: a boot
    // that reaches the HTTP bind logs `HTTP server listening`, which the
    // successful boot at the end of this test proves.
    let cfg = write_config(second_dir.path(), free_port(), &second_addr);
    let text = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        text.replace("log_level = \"warn\"\n", "log_level = \"info\"\n"),
    )
    .unwrap();
    let (code, out) = run_to_exit(&cfg, false, None);
    assert_eq!(code, 78, "a same-uid second daemon exits EX_CONFIG: {out}");
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(second_dir.path()).unwrap());
    assert!(
        out.contains(&format!("@torrentd_ks_{uid}"))
            && out.contains(&format!("pid {}", first.0.id())),
        "the refusal names the socket and the running daemon's pid: {out}"
    );
    assert!(
        out.contains("starting torrentd"),
        "the second's info lines reach its output: {out}"
    );
    assert!(
        !out.contains("HTTP server listening"),
        "the second daemon got as far as binding its HTTP port: {out}"
    );

    // The first is untouched and still serving.
    assert_eq!(http(addr, "GET", "/healthz", None).0, 200);
    first.stop();

    // With the first gone the name is free, and the same config boots, as
    // far as the HTTP bind the refused one never logged.
    let mut second = Running(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .env_remove("RUST_LOG")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn second daemon"),
    );
    // Read on its own thread, so a full pipe cannot stall the daemon.
    let mut stdout = second.0.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        stdout.read_to_string(&mut out).unwrap();
        out
    });
    wait_healthy(&second_addr);
    second.stop();
    let out = reader.join().unwrap();
    assert!(
        out.contains("HTTP server listening"),
        "a boot that binds its HTTP port logs it: {out}"
    );
}

/// The table lock is held until the teardown has removed the table, not only
/// while the daemon serves: a second start under the same uid while the
/// first is still draining after a SIGTERM is refused the same way. A request
/// whose body never arrives holds the first's HTTP drain to its 10 s bound,
/// which is the window the second start lands in. A lock released when the
/// shutdown begins, rather than with the daemon's last act, lets the second
/// boot replace or remove the table the first's teardown is about to remove.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_same_uid_start_during_the_first_daemon_s_shutdown_drain_exits_ex_config() {
    let addr = free_http();
    let addr = addr.as_str();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    // Killed on a panic: left running, it would hold the lock against every
    // test after this one.
    let mut first = Running(spawn_daemon(first_dir.path(), free_port(), addr));
    wait_healthy(addr);

    // In flight until the drain gives up on it.
    let mut stuck = TcpStream::connect(addr).expect("connect");
    stuck
        .write_all(
            b"POST /v1/torrents HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
              Content-Length: 4096\r\n\r\n{\"profile_id\":",
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    sigterm(&first.0);
    // The listener closes when the graceful shutdown begins: from then on
    // the first is draining.
    poll(
        "the first daemon's listener to close",
        Duration::from_secs(5),
        || TcpStream::connect(addr).is_err().then_some(()),
    );

    let cfg = write_config(second_dir.path(), free_port(), &free_http());
    let (code, out) = run_to_exit(&cfg, false, None);
    assert!(
        matches!(first.0.try_wait(), Ok(None)),
        "the first daemon exited before the second start, {:?} after its SIGTERM",
        started.elapsed()
    );
    assert_eq!(
        code, 78,
        "a same-uid start during the first's drain exits EX_CONFIG: {out}"
    );
    assert!(
        out.contains(&format!("pid {}", first.0.id())),
        "the refusal names the draining daemon's pid: {out}"
    );

    assert_exits_zero(&mut first.0, Duration::from_secs(45));
    drop(stuck);
}

/// Graceful shutdown must stay graceful under load: with many torrents added,
/// a SIGTERM still drains and exits within the timeout and persists session
/// state. Guards against a shutdown coordinator that hangs as torrent count
/// grows.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn daemon_graceful_shutdown_under_load() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, free_port(), addr);

    wait_healthy(addr);

    // Add 100 distinct magnets (unique infohashes derived from the index).
    let n = 100;
    for i in 1..=n {
        let ih = format!("{i:040x}");
        let payload = add_magnet(&format!("magnet:?xt=urn:btih:{ih}"));
        let (code, body) = http(addr, "POST", "/v1/torrents", Some(&payload));
        assert_eq!(code, 201, "add #{i} should be 201: {body}");
    }

    let (code, body) = http(addr, "GET", "/v1/status", None);
    assert_eq!(code, 200, "status: {body}");

    // SIGTERM under load: must exit cleanly within the timeout.
    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
    assert!(
        p.join(format!("session_state-{PROFILE}.dat")).exists(),
        "a dht profile's session state should be written on SIGTERM"
    );
}

/// Clients that do not let go cannot turn a SIGTERM into a failure.
///
/// An events stream and a request whose body never finishes arriving are both
/// open when the signal lands. The stream must end with the daemon; the stuck
/// request holds the HTTP drain to its bound, and a drain that runs out is a
/// warning, not exit 70 — which `Restart=on-failure` would have answered by
/// starting the daemon it had just been asked to stop. Against kynos's
/// default 25 s bound and the old exit code this fails on the status.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_sigterm_with_a_stream_and_a_stuck_request_open_exits_zero_within_the_bound() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, free_port(), addr);
    wait_healthy(addr);

    // The events stream, read until its first tick so it is established.
    let mut events = TcpStream::connect(addr).expect("connect");
    events
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    events
        .write_all(
            b"GET /v1/events HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n",
        )
        .unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains("event: tick") {
        let n = events
            .read(&mut buf)
            .expect("the stream sends its first tick");
        assert!(n > 0, "the stream closed before its first tick");
        seen.extend_from_slice(&buf[..n]);
    }

    // A request whose declared body never arrives: in flight until the drain
    // gives up on it.
    let mut stuck = TcpStream::connect(addr).expect("connect");
    stuck
        .write_all(
            b"POST /v1/torrents HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
              Content-Length: 4096\r\n\r\n{\"profile_id\":",
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    sigterm(&child);
    let status = wait_exit(&mut child, Duration::from_secs(45))
        .expect("daemon did not exit within 45s of SIGTERM with clients holding on");
    let elapsed = started.elapsed();
    assert_eq!(
        status.code(),
        Some(0),
        "a drain cut short by a client is not a failure: {status:?} after {elapsed:?}",
    );
    // The stuck request holds the HTTP drain to its 10 s bound
    // (`HTTP_DRAIN_TIMEOUT`), and the rest of the teardown has nothing to
    // wait on. Under 20 s rules out kynos's 25 s default; at least 9 s shows
    // the stuck request really held the drain to its bound.
    assert!(
        (Duration::from_secs(9)..Duration::from_secs(20)).contains(&elapsed),
        "the exit should land near the 10 s HTTP drain bound, took {elapsed:?}",
    );
    drop((stuck, events));
}

/// A configured `shutdown_drain_secs` is the deadline the alert loop's drain
/// runs under, read from the loop's own report of the drain it starts.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn the_configured_drain_deadline_reaches_the_alert_loop() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    let text = std::fs::read_to_string(&cfg).unwrap();
    // Neither the config default (60) nor the engine's (30).
    let text = text.replace(
        "log_level = \"warn\"\n",
        "log_level = \"info\"\nshutdown_drain_secs = 7\n",
    );
    std::fs::write(&cfg, text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .env_remove("RUST_LOG")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    // Read on its own thread, so a full pipe cannot stall the daemon.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        stdout.read_to_string(&mut out).unwrap();
        out
    });
    wait_healthy(addr);

    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
    let out = reader.join().unwrap();
    let drain = out
        .lines()
        .find(|l| l.contains("shutdown: requesting resume save for every torrent"))
        .unwrap_or_else(|| panic!("the drain did not report its start:\n{out}"));
    assert!(
        drain.contains("\"deadline_secs\":7"),
        "the drain ran under another deadline: {drain}"
    );
}
