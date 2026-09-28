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
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
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
    const HTTP: &str = "127.0.0.1:18091";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, 16891, HTTP);

    wait_healthy(HTTP);

    let magnet = "magnet:?xt=urn:btih:0101010101010101010101010101010101010101&dn=itest";
    let payload = add_magnet(magnet);
    let ih = "0101010101010101010101010101010101010101";

    let (code, body) = http(HTTP, "POST", "/v1/torrents", Some(&payload));
    assert_eq!(code, 201, "add should be 201: {body}");
    assert!(body.contains(ih), "add response: {body}");

    let (code, body) = http(HTTP, "GET", "/v1/torrents", None);
    assert_eq!(code, 200);
    assert!(body.contains(ih), "list should contain the torrent: {body}");

    let (code, body) = http(HTTP, "POST", "/v1/torrents", Some(&payload));
    assert_eq!(code, 409, "duplicate add must be 409");
    assert!(
        body.contains("problems.md#torrent-exists"),
        "a duplicate is a torrent-exists problem: {body}"
    );

    // The document the daemon serves is the one committed beside the code.
    let (code, doc) = http(HTTP, "GET", "/v1/openapi.json", None);
    assert_eq!(code, 200);
    let committed = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json"),
    )
    .expect("read docs/api/openapi.json");
    assert_eq!(doc, committed, "the served document is the committed one");

    let (code, metrics) = http(HTTP, "GET", "/metrics", None);
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
    const HTTP: &str = "127.0.0.1:18096";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, 16896, HTTP);
    wait_healthy(HTTP);

    let (code, metrics) = http(HTTP, "GET", "/metrics", None);
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
    let (code, body) = http(HTTP, "POST", "/v1/config/reload", None);
    assert!((200..300).contains(&code), "reload trigger: {code} {body}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, metrics) = http(HTTP, "GET", "/metrics", None);
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
    const HTTP: &str = "127.0.0.1:18093";
    let _occupied = std::net::TcpListener::bind(HTTP).expect("occupy the HTTP port");
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, 16893, HTTP);

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
    const HTTP: &str = "127.0.0.1:18095";
    const HTTP_SECOND: &str = "127.0.0.1:18096";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut first = spawn_daemon(p, 16895, HTTP);
    wait_healthy(HTTP);

    // Same state directory, different ports. The first daemon has already
    // read `cfg.toml`, so rewriting it for the second changes nothing for it.
    let cfg = write_config(p, 16896, HTTP_SECOND);
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
        TcpStream::connect(HTTP_SECOND).is_err(),
        "the second daemon got as far as binding its HTTP port"
    );

    // The first is untouched and still serving.
    assert_eq!(http(HTTP, "GET", "/healthz", None).0, 200);
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
    const HTTP: &str = "127.0.0.1:18092";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, 16892, HTTP);

    wait_healthy(HTTP);

    // Add 100 distinct magnets (unique infohashes derived from the index).
    let n = 100;
    for i in 1..=n {
        let ih = format!("{i:040x}");
        let payload = add_magnet(&format!("magnet:?xt=urn:btih:{ih}"));
        let (code, body) = http(HTTP, "POST", "/v1/torrents", Some(&payload));
        assert_eq!(code, 201, "add #{i} should be 201: {body}");
    }

    let (code, body) = http(HTTP, "GET", "/v1/status", None);
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
    let cfg = write_config(p, 16893, "127.0.0.1:18093");

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
        err.contains("profile_assignments.json"),
        "must name the file to edit: {err}"
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
             user_agent = \"ua-a\"\n",
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

/// The reconciliation warning on a migration boot names the file to edit, not
/// only the file the entries came from.
///
/// A registry that survives the boot check — every id it names is configured —
/// can still claim torrents no scan loaded, which is the silent total outage
/// that warning exists to catch. On this one boot the entries were read from
/// the pre-rename `slot_assignments.json`, and that is the file
/// `docs/running.md` tells the operator explicitly *not* to edit: the daemon
/// writes `profile_assignments.json` on the same boot and reads only that one
/// from here on. Naming the old file alone sent them to the wrong one.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn the_reconciliation_warning_names_both_registry_files() {
    const HTTP: &str = "127.0.0.1:18094";
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, 16894, HTTP);

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

    wait_healthy(HTTP);
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
        warning.contains("\"registry_path\":\"") && warning.contains("profile_assignments.json"),
        "must name the file the operator edits from here on: {warning}",
    );
    assert!(
        warning.contains("\"registry_read_from\":\"") && warning.contains("slot_assignments.json"),
        "and the file these entries were read from: {warning}",
    );
}
