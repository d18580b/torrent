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
    assert!(
        !child.wait().unwrap().success(),
        "exit status must be a failure; stderr: {err}"
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
