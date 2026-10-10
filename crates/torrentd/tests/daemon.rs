//! Layer 3 daemon integration test.
//!
//! Spawns the real `torrentd` binary against a real libtorrent session and
//! drives the HTTP control plane end-to-end: add, list, duplicate-409,
//! metrics, then a SIGTERM graceful shutdown that must persist DHT/session
//! state. Marked `#[ignore]` (binds ports, starts libtorrent) so it stays
//! out of the default `cargo test`; run with:
//!
//!   cargo test -p torrentd --test daemon -- --ignored

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::process::Child;
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

/// Minimal blocking HTTP/1.1 client: sends `Connection: close` and reads the
/// whole response to EOF. Returns `(status, body)`.
fn http(addr: &str, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    http_as(addr, method, path, body, "localhost")
}

/// As [`http`], naming `host` as the request's `Host`.
fn http_as(addr: &str, method: &str, path: &str, body: Option<&str>, host: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf);
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
        .to_string();
    (status, body)
}

/// The `POST /v1/torrents` body adding `magnet` to the test profile.
fn add_magnet(magnet: &str) -> String {
    format!(
        "{{\"profile_id\":\"{PROFILE}\",\"source\":{{\"kind\":\"magnet\",\"uri\":\"{magnet}\"}}}}"
    )
}

fn wait_healthy(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() && http(addr, "GET", "/healthz", None).0 == 200 {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("daemon did not become healthy within 30s");
}

/// The profile every torrent in these tests belongs to.
pub const PROFILE: &str = "test";

/// A loopback port free for both TCP and UDP right now, from the kernel's
/// ephemeral range.
///
/// Every test here used to hard-code its ports, and two pairs collided:
/// `the_first_scrape_holds_every_series_present_from_boot` served HTTP on
/// 18096 and listened on 16896, which the single-instance test used for its
/// second daemon, and the bind-failure and migrated-registry tests shared
/// 16893. `cargo test` runs tests in parallel, so a collision was a test that
/// failed for the other one's sake. A session listens on TCP and UDP, so the
/// port is checked free for both.
fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// `127.0.0.1:<free port>`, for `http_listen`.
fn free_http() -> String {
    format!("127.0.0.1:{}", free_port())
}

/// Write a daemon config into `p`, returning its path.
///
/// `resume_dir` is `p/resume`, so the daemon's state dir — where the
/// assignment registry lives — is `p` itself.
fn write_config(p: &std::path::Path, listen_port: u16, http_addr: &str) -> std::path::PathBuf {
    for sub in ["data", "resume", "torrents"] {
        std::fs::create_dir_all(p.join(sub)).unwrap();
    }
    let cfg = p.join("cfg.toml");
    std::fs::write(
        &cfg,
        format!(
            "default_save_path = \"{d}/data\"\n\
             resume_dir = \"{d}/resume\"\n\
             torrent_dir = \"{d}/torrents\"\n\
             http_listen = \"{http_addr}\"\n\
             log_level = \"warn\"\n\
             allow_unauthenticated = true\n\
             enable_lsd = false\n\
             \n\
             [[profile]]\n\
             id = \"{PROFILE}\"\n\
             network = \"host\"\n\
             listen_interfaces = \"127.0.0.1:{listen_port}\"\n\
             dht = true\n",
            d = p.display()
        ),
    )
    .unwrap();
    cfg
}

/// Write a daemon config into `p` and spawn the binary against it.
fn spawn_daemon(p: &std::path::Path, listen_port: u16, http_addr: &str) -> Child {
    let cfg = write_config(p, listen_port, http_addr);
    Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .spawn()
        .expect("spawn daemon")
}

fn sigterm(child: &Child) {
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
}

fn wait_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return false,
        }
    }
    let _ = child.kill();
    false
}

#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn daemon_end_to_end() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, free_port(), addr);

    wait_healthy(addr);

    let magnet = "magnet:?xt=urn:btih:0101010101010101010101010101010101010101&dn=itest";
    let payload = add_magnet(magnet);
    let ih = "0101010101010101010101010101010101010101";

    let (code, body) = http(addr, "POST", "/v1/torrents", Some(&payload));
    assert_eq!(code, 201, "add should be 201: {body}");
    assert!(body.contains(ih), "add response: {body}");

    let (code, body) = http(addr, "GET", "/v1/torrents", None);
    assert_eq!(code, 200);
    assert!(body.contains(ih), "list should contain the torrent: {body}");

    let (code, body) = http(addr, "POST", "/v1/torrents", Some(&payload));
    assert_eq!(code, 409, "duplicate add must be 409");
    assert!(
        body.contains("problems.md#torrent-exists"),
        "a duplicate is a torrent-exists problem: {body}"
    );

    // The document the daemon serves is the one committed beside the code.
    let (code, doc) = http(addr, "GET", "/v1/openapi.json", None);
    assert_eq!(code, 200);
    let committed = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json"),
    )
    .expect("read docs/api/openapi.json");
    assert_eq!(doc, committed, "the served document is the committed one");

    let (code, metrics) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200);
    assert!(metrics.contains("torrentd_"), "metrics output: {metrics}");

    // Graceful shutdown via SIGTERM (shell out to `kill`, no extra dep).
    sigterm(&child);
    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM"
    );

    // DHT/session state must be persisted on a graceful shutdown (Commit C).
    assert!(
        p.join(format!("session_state-{PROFILE}.dat")).exists(),
        "a dht profile's session state should be written on SIGTERM"
    );
}

#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_configured_allowed_host_is_answered_and_another_is_refused() {
    // The router tests set the allowlist on the state they build; this holds
    // the path from the config file to the running daemon's gate.
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        format!("allowed_hosts = [\"torrentd.example.com\"]\n{body}"),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .spawn()
        .expect("spawn daemon");

    wait_healthy(addr);

    for host in ["torrentd.example.com", "torrentd.example.com:8443"] {
        let (code, body) = http_as(addr, "GET", "/v1/torrents", None, host);
        assert_eq!(code, 200, "GET with Host {host}: {body}");
        let (code, body) = http_as(addr, "POST", "/v1/torrents/pause-all", None, host);
        assert!(
            (200..300).contains(&code),
            "POST with Host {host}: {code} {body}"
        );
    }
    let (code, body) = http_as(addr, "GET", "/v1/torrents", None, "attacker.example");
    assert_eq!(code, 403, "a Host not in allowed_hosts: {body}");

    sigterm(&child);
    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM"
    );
}

/// The rows of `deploy/metrics.md` a host-profile daemon with no pool and no
/// kill switch must export from its first scrape: `(name, labels column)`.
fn series_present_from_boot() -> Vec<(String, String)> {
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/metrics.md"),
    )
    .expect("read deploy/metrics.md");
    doc.lines()
        .filter(|l| l.starts_with("| `torrentd_"))
        .filter_map(|l| {
            let cells: Vec<&str> = l.split(" | ").collect();
            let name = cells[0]
                .trim_start_matches("| ")
                .trim_matches('`')
                .to_string();
            let (labels, instances, present) = (cells[2], cells[3], cells[4]);
            let applies = matches!(instances, "daemon" | "each profile")
                && matches!(
                    present,
                    "from boot, at 0" | "from boot: always" | "from boot: live profiles"
                );
            applies.then(|| (name, labels.to_string()))
        })
        .collect()
}

/// The values a labels column lists, as `label="value"` matchers.
fn listed_values(labels: &str) -> Vec<String> {
    labels
        .split("; ")
        .filter_map(|part| part.split_once(": "))
        .flat_map(|(name, values)| {
            let name = name.trim_matches('`').to_string();
            values
                .split(", ")
                .map(move |v| format!("{name}=\"{}\"", v.trim_matches('`')))
        })
        .collect()
}

/// Everything an alert rule reads has to exist before the condition it
/// watches first happens, or `increase()` never sees that first event. So the
/// very first scrape of a fresh daemon must already hold every series the
/// reference table says is there from boot, for this profile and for every
/// listed label value. Then a reload that cannot parse its config is counted.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn the_first_scrape_holds_every_series_present_from_boot() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, free_port(), addr);
    wait_healthy(addr);

    let (code, metrics) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200);
    let expected = series_present_from_boot();
    assert!(expected.len() > 30, "parsed too few rows: {expected:?}");
    let mut missing = Vec::new();
    for (name, labels) in &expected {
        if !metrics.contains(&format!("# TYPE {name} ")) {
            missing.push(name.clone());
            continue;
        }
        // `task_up` lists every task there is; only the ones this config
        // starts exist.
        if name == "torrentd_task_up" {
            continue;
        }
        for value in listed_values(labels) {
            let found = metrics.lines().any(|l| {
                l.starts_with(&format!("{name}{{"))
                    && l.contains(&value)
                    && (!labels.contains("profile_id") || l.contains("profile_id=\"test\""))
            });
            if !found {
                missing.push(format!("{name}{{{value}}}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "absent from the first scrape: {missing:?}\n\n{metrics}"
    );
    for task in ["vpn_monitor", "reload"] {
        assert!(
            metrics.contains(&format!("torrentd_task_up{{task=\"{task}\"}} 1")),
            "{task} is supervised from boot:\n{metrics}"
        );
    }

    // A reload that cannot parse the file keeps the old settings and says so
    // in a series an alert can read, not only in the journal.
    std::fs::write(p.join("cfg.toml"), "this is = = not toml").unwrap();
    let (code, body) = http(addr, "POST", "/v1/config/reload", None);
    assert!((200..300).contains(&code), "reload trigger: {code} {body}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, metrics) = http(addr, "GET", "/metrics", None);
        if metrics.contains("torrentd_config_reload_failures_total{stage=\"load\"} 1") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the failed reload was not counted:\n{metrics}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    sigterm(&child);
    assert!(wait_exit(&mut child, Duration::from_secs(30)));
    // A clean exit still writes the report the next boot re-exports, and it
    // says nothing was left behind.
    let report = std::fs::read_to_string(p.join("last_shutdown.json")).expect("shutdown report");
    assert!(report.contains("\"unsaved_resumes\":0"), "{report}");
    assert!(
        report.contains("\"kill_switch_removal_failed\":false"),
        "{report}"
    );
}

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

    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "daemon did not exit within 30s of failing to bind its HTTP listener"
    );
    let status = child.wait().expect("reap daemon");
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
    assert!(
        exited,
        "the second daemon did not refuse within 10s; output: {out}"
    );
    assert_eq!(
        second.wait().unwrap().code(),
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
    assert!(
        wait_exit(&mut first, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM"
    );
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
    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM under {n}-torrent load"
    );
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
    // Ports of its own: the reconciliation test's daemon holds 18094, and a
    // client that reached it instead held nothing across this one's stop.
    const HTTP: &str = "127.0.0.1:18101";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, 16901, HTTP);
    wait_healthy(HTTP);

    // The events stream, read until its first tick so it is established.
    let mut events = TcpStream::connect(HTTP).expect("connect");
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
    let mut stuck = TcpStream::connect(HTTP).expect("connect");
    stuck
        .write_all(
            b"POST /v1/torrents HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
              Content-Length: 4096\r\n\r\n{\"profile_id\":",
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    sigterm(&child);
    assert!(
        wait_exit(&mut child, Duration::from_secs(45)),
        "daemon did not exit within 45s of SIGTERM with clients holding on"
    );
    let elapsed = started.elapsed();
    let status = child.wait().unwrap();
    assert!(
        status.success(),
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
    const HTTP: &str = "127.0.0.1:18097";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, 16897, HTTP);
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
    wait_healthy(HTTP);

    sigterm(&child);
    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM"
    );
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

/// The upgrade every pre-profiles deployment takes, and the one the published
/// upgrade note does not cover.
///
/// A single-session deployment's `slot_assignments.json` maps every info-hash
/// to `default`. The operator writes a `[[profile]]` table with some other id
/// and starts the daemon. The registry migration carries those entries over
/// verbatim, and nothing reconciles them: the per-profile resume and torrent
/// scans never look at the old un-partitioned paths, so nothing loads; the
/// registry says every one of those info-hashes is taken, so re-adding answers
/// 409; and `DELETE` cannot clear an entry whose profile has no session
/// either. The daemon serves `/healthz` 200 throughout, seeding nothing.
///
/// Without the reconciliation this test fails by timing out on a daemon that
/// came up perfectly happy.
#[test]
#[ignore = "spawns the real daemon; run with --ignored"]
fn a_migrated_registry_naming_an_unconfigured_profile_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), &free_http());

    // The pre-profiles registry, under its pre-profiles name. `write_config`
    // puts `resume_dir` at `p/resume`, so the state dir is `p`.
    std::fs::write(
        p.join("slot_assignments.json"),
        br#"{"0101010101010101010101010101010101010101":"default",
             "0202020202020202020202020202020202020202":"default"}"#,
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    let exited = wait_exit(&mut child, Duration::from_secs(30));
    // The refusal is a tracing ERROR, which this daemon writes to stdout as
    // JSON; read both streams so the assertions below do not depend on which.
    let mut err = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut err)
        .unwrap();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut err)
        .unwrap();

    assert!(
        exited,
        "the daemon started against a registry it cannot serve; stderr: {err}"
    );
    assert_eq!(
        child.wait().unwrap().code(),
        Some(78),
        "a refusal no restart can fix exits EX_CONFIG, which the unit does not restart; \
         stderr: {err}"
    );

    // The refusal has to be actionable: it names the id it does not recognise,
    // the ids it does, and both ways out.
    assert!(err.contains("default"), "must name the unknown id: {err}");
    assert!(
        err.contains(PROFILE),
        "must name the configured profiles: {err}"
    );
    assert!(
        err.contains("[[profile]]"),
        "must say what declares a profile: {err}"
    );
    assert!(
        err.contains("registry.db"),
        "must name the database to edit: {err}"
    );
    assert!(
        err.contains("DELETE FROM assignment WHERE profile_id IN ('default')"),
        "and the statement that clears those rows: {err}"
    );

    // And it must not have been a silent success followed by a crash: nothing
    // should have been loaded.
    assert!(
        !p.join(format!("session_state-{PROFILE}.dat")).exists(),
        "the daemon got far enough to persist session state"
    );
}

/// A resume file and a torrent-dir `.torrent` the boot scans cannot read are
/// skipped, the daemon comes up anyway, and boot exports each under its own
/// `source` of `boot_torrent_load_failures`. A directory stands where each
/// file goes, which no uid can read as a file.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn unreadable_scan_files_are_exported_by_source_at_boot() {
    const HTTP: &str = "127.0.0.1:18100";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, 16900, HTTP);
    let ih = "ab".repeat(20);
    std::fs::create_dir_all(p.join("resume").join(PROFILE).join(format!("{ih}.resume"))).unwrap();
    std::fs::create_dir_all(
        p.join("torrents")
            .join(PROFILE)
            .join(format!("{ih}.torrent")),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .spawn()
        .expect("spawn daemon");
    wait_healthy(HTTP);

    let (code, metrics) = http(HTTP, "GET", "/metrics", None);
    assert_eq!(code, 200);
    for source in ["resume_file", "torrent_file"] {
        assert!(
            metrics.lines().any(|l| {
                l.starts_with("torrentd_boot_torrent_load_failures{")
                    && l.contains(&format!("profile_id=\"{PROFILE}\""))
                    && l.contains(&format!("source=\"{source}\""))
                    && l.ends_with(" 1")
            }),
            "boot_torrent_load_failures{{source={source}}} should read 1:\n{metrics}"
        );
    }

    sigterm(&child);
    assert!(wait_exit(&mut child, Duration::from_secs(30)));
}

/// Run the binary against `cfg` to its exit, with `--check-config` when
/// `check`, and `PATH` limited to `path` when given. Returns the exit code
/// and both output streams.
fn run_to_exit(
    cfg: &std::path::Path,
    check: bool,
    path: Option<&std::path::Path>,
) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_torrentd"));
    cmd.arg("--config").arg(cfg);
    if check {
        cmd.arg("--check-config");
    }
    if let Some(path) = path {
        cmd.env("PATH", path);
    }
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "a refused config must not start the daemon"
    );
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .unwrap();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut out)
        .unwrap();
    let code = child.wait().unwrap().code().expect("exited, not signalled");
    (code, out)
}

/// A config that does not load exits 78 (`EX_CONFIG`), from the daemon and
/// from `--check-config` alike, which is what `RestartPreventExitStatus=78`
/// reads to leave the unit stopped.
#[test]
#[ignore = "spawns the real daemon; run with --ignored"]
fn a_config_that_fails_to_load_exits_ex_config() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, 16898, "127.0.0.1:18098");
    let text = std::fs::read_to_string(&cfg).unwrap();
    // Out of `shutdown_drain_secs`'s `1..=3600`: parses, then fails validation.
    std::fs::write(&cfg, format!("shutdown_drain_secs = 0\n{text}")).unwrap();

    for check in [false, true] {
        let (code, out) = run_to_exit(&cfg, check, None);
        assert_eq!(code, 78, "--check-config: {check}; output: {out}");
        assert!(
            out.contains("shutdown_drain_secs"),
            "the refusal names the key: {out}"
        );
    }

    let (code, out) = run_to_exit(&p.join("missing.toml"), false, None);
    assert_eq!(code, 78, "a config file that is not there: {out}");

    // An operator subcommand is not the daemon: `vpn check` documents only
    // 0/1/2, and a config it cannot load is its 1.
    let status = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .args(["vpn", "check"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn torrentd vpn check");
    assert_eq!(
        status.code(),
        Some(1),
        "vpn check on a config that fails to load"
    );
}

/// `--check-config`'s host probe (`nft` present under
/// `network_kill_switch = true`) exits 78 when it fails, and so does the
/// daemon, which makes the same probe itself before it raises anything. `nft`
/// is made absent by running with a `PATH` holding nothing.
#[test]
#[ignore = "spawns the real daemon; run with --ignored"]
fn a_kill_switch_with_no_nft_exits_ex_config() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    for sub in ["data", "resume", "torrents", "empty-path"] {
        std::fs::create_dir_all(p.join(sub)).unwrap();
    }
    let cfg = p.join("cfg.toml");
    std::fs::write(
        &cfg,
        format!(
            "default_save_path = \"{d}/data\"\n\
             resume_dir = \"{d}/resume\"\n\
             torrent_dir = \"{d}/torrents\"\n\
             http_listen = \"127.0.0.1:18099\"\n\
             log_level = \"warn\"\n\
             allow_unauthenticated = true\n\
             network_kill_switch = true\n\
             \n\
             [[profile]]\n\
             id = \"acct_a\"\n\
             network = \"vpn\"\n\
             vpn_type = \"wireguard\"\n\
             vpn_config = \"{d}/wg0.conf\"\n\
             vpn_interface = \"wg-nonft\"\n\
             listen_port = 16899\n\
             peer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\n\
             allowed_tracker_domains = [\"t.example\"]\n",
            d = p.display()
        ),
    )
    .unwrap();

    for check in [true, false] {
        let (code, out) = run_to_exit(&cfg, check, Some(&p.join("empty-path")));
        assert_eq!(code, 78, "--check-config: {check}; output: {out}");
        assert!(out.contains("nft"), "the refusal names `nft`: {out}");
    }
}

/// The reconciliation warning on an import boot names the database to edit,
/// not only the file the entries came from.
///
/// A registry that survives the boot check — every id it names is configured —
/// can still claim torrents no scan loaded, which is the silent total outage
/// that warning exists to catch. On this one boot the entries were imported
/// from the pre-rename `slot_assignments.json`, and that is the file
/// `docs/running.md` tells the operator explicitly *not* to edit: the daemon
/// imports it into `registry.db` on the same boot, renames it, and reads only
/// the database from here on. Naming the old file alone sent them to the
/// wrong one.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn the_reconciliation_warning_names_both_registry_files() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);

    // Assignments for the profile that *is* configured, so the boot check
    // passes and the reconciliation below is reached — and no resume file for
    // either, so the scan loads none of them.
    std::fs::write(
        p.join("slot_assignments.json"),
        format!(
            "{{\"0101010101010101010101010101010101010101\":\"{PROFILE}\",
               \"0202020202020202020202020202020202020202\":\"{PROFILE}\"}}"
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    wait_healthy(addr);
    sigterm(&child);
    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM"
    );
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .unwrap();

    let warning = out
        .lines()
        .find(|l| l.contains("the assignment registry claims more torrents"))
        .unwrap_or_else(|| panic!("the reconciliation warning did not fire; output: {out}"));

    assert!(
        warning.contains("\"registry_path\":\"") && warning.contains("registry.db"),
        "must name the database the operator edits from here on: {warning}",
    );
    assert!(
        warning.contains("\"registry_read_from\":\"")
            && warning.contains("slot_assignments.json.imported"),
        "and the file these entries were imported from, where it now is: {warning}",
    );

    // The import happened once: the JSON is moved aside and a second boot
    // reads the database alone, still holding both entries — which is why
    // the same warning fires again, counting the same two.
    assert!(!p.join("slot_assignments.json").exists());
    assert!(p.join("slot_assignments.json.imported").exists());
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    wait_healthy(addr);
    sigterm(&child);
    assert!(
        wait_exit(&mut child, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM"
    );
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .unwrap();
    let warning = out
        .lines()
        .find(|l| l.contains("the assignment registry claims more torrents"))
        .unwrap_or_else(|| panic!("the second boot lost the imported entries; output: {out}"));
    assert!(
        warning.contains("\"registry_torrents\":2"),
        "both entries survive into the second boot: {warning}",
    );
}

/// A non-reloadable edit is reported on every reload until a restart takes
/// it, not only on the first.
///
/// The reload pump used to record the whole new file as the running config
/// after each reload, so the second reload of the same edit answered
/// `SIGHUP: config unchanged` about a `file_pool_size` the daemon was still
/// not running.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_non_reloadable_change_is_reported_on_the_second_reload_too() {
    const WARNING: &str = "non-reloadable field requires daemon restart";
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    // Killed if an assertion below panics, rather than left running and
    // holding the test runner's stderr open.
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
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn daemon"),
    );
    // The daemon logs JSON lines to stdout; a reader thread keeps the pipe
    // drained and hands each line over as it arrives.
    let (tx, lines) = std::sync::mpsc::channel::<String>();
    let stdout = child.0.stdout.take().expect("piped stdout");
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    wait_healthy(addr);

    // A top-level key, so it goes above the `[[profile]]` table.
    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        body.replace(
            "enable_lsd = false\n",
            "enable_lsd = false\nfile_pool_size = 2000\n",
        ),
    )
    .unwrap();

    // Wait for the next reload's verdict: the restart warning naming the key,
    // or `config unchanged`.
    let verdict = |seen: &mut Vec<String>| -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match lines.recv_timeout(left) {
                Ok(line) => {
                    seen.push(line.clone());
                    if (line.contains(WARNING) && line.contains("file_pool_size"))
                        || line.contains("SIGHUP: config unchanged")
                    {
                        return line;
                    }
                }
                Err(_) => panic!("no reload verdict within 10s; output:\n{}", seen.join("\n")),
            }
        }
    };
    let mut seen = Vec::new();
    for reload in ["first", "second"] {
        let (code, body) = http(addr, "POST", "/v1/config/reload", None);
        assert!((200..300).contains(&code), "reload trigger: {code} {body}");
        let line = verdict(&mut seen);
        assert!(
            line.contains(WARNING),
            "the {reload} reload must still report the restart it needs: {line}",
        );
    }

    sigterm(&child.0);
    assert!(
        wait_exit(&mut child.0, Duration::from_secs(30)),
        "daemon did not exit within 30s of SIGTERM"
    );
}

/// A one-file `.torrent` named `name`, announcing to `announce`.
fn metainfo(name: &str, announce: &str) -> Vec<u8> {
    let mut t = format!(
        "d8:announce{}:{announce}4:infod6:lengthi1e4:name{}:{name}12:piece lengthi16384e\
         6:pieces20:",
        announce.len(),
        name.len()
    )
    .into_bytes();
    t.extend_from_slice(&[0u8; 20]);
    t.extend_from_slice(b"ee");
    t
}

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

    sigterm(&child);
    assert!(wait_exit(&mut child, Duration::from_secs(30)));
}

/// [`http`] with a read timeout of `timeout`, for a request that runs long.
fn http_within(addr: &str, method: &str, path: &str, timeout: Duration) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(timeout)).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Length: 0\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf);
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

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
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .env("NOTIFY_SOCKET", &sock_path)
            .env("WATCHDOG_USEC", WATCHDOG_USEC.to_string())
            .env_remove("WATCHDOG_PID")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy(addr);

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
    assert!(wait_exit(&mut child.0, Duration::from_secs(60)));
    listening.store(false, std::sync::atomic::Ordering::Relaxed);
    listener.join().unwrap();
}

/// Poll `GET /v1/torrents/{ih}` until its session reports a name, returning
/// it, or `None` once `within` has passed. A torrent with no metadata has
/// none.
fn session_name(addr: &str, ih: &str, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    loop {
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        if code == 200 {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            if let Some(name) = v["session"]["name"].as_str() {
                return Some(name.to_owned());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Poll `path` until it can be read, returning its bytes, or `None` once
/// `within` has passed.
fn read_within(path: &std::path::Path, within: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + within;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            return Some(bytes);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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
        assert!(wait_exit(&mut child.0, Duration::from_secs(30)));
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

/// The phase `GET /v1/torrents/{ih}` reports, or `None` while it answers
/// anything but 200.
fn torrent_phase(addr: &str, ih: &str) -> Option<String> {
    let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
    if code != 200 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["phase"].as_str().map(str::to_owned)
}

/// The adoption state `GET /v1/pool/torrents` reports for `ih`.
fn pool_state(addr: &str, ih: &str) -> Option<String> {
    let (code, body) = http(addr, "GET", "/v1/pool/torrents?limit=1000", None);
    assert_eq!(code, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["infohash"].as_str() == Some(ih))
        .and_then(|t| t["state"].as_str().map(str::to_owned))
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
    sigterm(&child.0);
    assert!(wait_exit(&mut child.0, Duration::from_secs(60)));

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
            "after a restart mid-verify the failed payload was left {phase:?} and \
             indexed {state:?}, not paused and drifted",
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
