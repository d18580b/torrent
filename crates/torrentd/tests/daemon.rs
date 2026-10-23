//! Layer 3 daemon integration test.
//!
//! Spawns the real `torrentd` binary against a real libtorrent session and
//! drives it over HTTP and signals: what only the whole process shows, such as
//! the boot, a SIGTERM's drain and exit status, reloads, and state that must
//! survive a restart. What one handler answers is the unit tests'
//! (`src/http/tests`), and the generated client's reading of the API is
//! torrentctl's e2e. Marked `#[ignore]` (binds ports, starts libtorrent) so it
//! stays out of the default `cargo test`; run with:
//!
//!   cargo test -p torrentd --test daemon -- --ignored --test-threads=1
//!
//! One test at a time (`mise run test-daemon` passes the flag): every daemon
//! a test spawns runs as this user, and a daemon holds its uid's kill-switch
//! table lock for its life, so a second one running beside it exits 78.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::time::Duration;
use std::time::Instant;

/// Minimal blocking HTTP/1.1 client: sends `Connection: close` and reads the
/// whole response to EOF. Returns `(status, body)`.
fn http(addr: &str, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    http_as(addr, method, path, body, "localhost")
}

/// As [`http`], naming `host` as the request's `Host`.
fn http_as(addr: &str, method: &str, path: &str, body: Option<&str>, host: &str) -> (u16, String) {
    try_http_as(addr, method, path, body, host)
        .unwrap_or_else(|e| panic!("{method} {path} on {addr}: {e}"))
}

/// As [`http_as`], returning a failure to connect, write or read instead of
/// panicking on it.
fn try_http_as(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    host: &str,
) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
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
    Ok((status, body))
}

/// The `POST /v1/torrents` body adding `magnet` to the test profile.
fn add_magnet(magnet: &str) -> String {
    format!(
        "{{\"profile_id\":\"{PROFILE}\",\"source\":{{\"kind\":\"magnet\",\"uri\":\"{magnet}\"}}}}"
    )
}

fn wait_healthy(addr: &str) {
    wait_healthy_within(addr, Duration::from_secs(30));
}

/// As [`wait_healthy`], with a boot deadline of `budget`. The panic names the
/// last `/healthz` answer, or the error that kept one from arriving, so a boot
/// that never came up says whether nothing listened or what it answered.
fn wait_healthy_within(addr: &str, budget: Duration) {
    let deadline = Instant::now() + budget;
    let last = loop {
        let last = match try_http_as(addr, "GET", "/healthz", None, "localhost") {
            Ok((200, _)) => return,
            Ok((status, body)) => format!("the last /healthz answered {status}: {body}"),
            Err(e) => format!("the last /healthz attempt failed: {e}"),
        };
        if Instant::now() >= deadline {
            break last;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    panic!("daemon on {addr} did not become healthy within {budget:?}; {last}");
}

/// The daemon's stdout and stderr, written to `daemon.log` in a test's
/// tempdir, whose tail is printed if the test panics.
///
/// The daemon logs to stdout, so a test that discarded it lost the reason a
/// boot failed. Declare the guard before the child it captures, so the child
/// is killed first and the log is complete when it is read, and after the
/// tempdir, so the file is still there.
struct DaemonLog(std::path::PathBuf);

impl DaemonLog {
    /// Lines of the log printed on a panic.
    const TAIL: usize = 200;

    fn new(dir: &std::path::Path) -> Self {
        let path = dir.join("daemon.log");
        std::fs::File::create(&path).expect("create daemon.log");
        Self(path)
    }

    /// A handle for the child's stdout or stderr. Opened for append, so the
    /// two streams interleave rather than overwrite each other.
    fn stdio(&self) -> std::process::Stdio {
        std::fs::OpenOptions::new()
            .append(true)
            .open(&self.0)
            .expect("open daemon.log")
            .into()
    }
}

impl Drop for DaemonLog {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let text = std::fs::read_to_string(&self.0)
            .unwrap_or_else(|e| format!("<could not read {}: {e}>", self.0.display()));
        let lines: Vec<&str> = text.lines().collect();
        let tail = &lines[lines.len().saturating_sub(Self::TAIL)..];
        eprintln!(
            "--- the last {} of {} lines of the daemon's output ---\n{}\n--- end of the daemon's output ---",
            tail.len(),
            lines.len(),
            tail.join("\n")
        );
    }
}

/// The profile every torrent in these tests belongs to.
pub const PROFILE: &str = "test";

/// A loopback port free for both TCP and UDP right now, from below the
/// kernel's ephemeral range.
///
/// Every test here used to hard-code its ports, and two pairs collided:
/// `the_first_scrape_holds_every_series_present_from_boot` served HTTP on
/// 18096 and listened on 16896, which the single-instance test used for its
/// second daemon, and the bind-failure and migrated-registry tests shared
/// 16893. `cargo test` runs tests in parallel, so a collision was a test that
/// failed for the other one's sake. A session listens on TCP and UDP, so the
/// port is checked free for both.
///
/// The probe socket is closed on return, so the kernel may hand the same
/// port to the next probe: a test that took its `http_listen` port and then
/// its session's listen port got one port for both, and the daemon refused
/// the config. No port is returned twice in one test process.
///
/// The probe is released before the daemon binds the port, so something may
/// take it in between. Taken from the ephemeral range, as it was, the likely
/// taker was the kernel itself: every outgoing connection, this test's own
/// HTTP client's included, and every `bind(0)` draws its port from there.
/// Below the range only a process that names the port can take it. Each test
/// process starts its walk at its own offset, so two suites side by side do
/// not probe the same ports in the same order.
fn free_port() -> u16 {
    static ISSUED: std::sync::Mutex<std::collections::BTreeSet<u16>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    const FLOOR: u32 = 10_000;
    let ephemeral_low: u32 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|r| r.split_whitespace().next()?.parse().ok())
        .unwrap_or(32_768);
    let span = ephemeral_low
        .checked_sub(FLOOR)
        .filter(|span| *span >= 1_000)
        .unwrap_or_else(|| panic!("the ephemeral range starts at {ephemeral_low}, too low"));
    let start = std::process::id().wrapping_mul(7_919) % span;
    let mut issued = ISSUED.lock().unwrap();
    (0..span)
        .map(|i| u16::try_from(FLOOR + (start + i) % span).unwrap())
        .find(|&port| {
            !issued.contains(&port)
                && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
                && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
                && issued.insert(port)
        })
        .unwrap_or_else(|| panic!("no port below {ephemeral_low} is free for TCP and UDP"))
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

/// How `child` exited, once it has, or `None` (and `child` killed) when it
/// has not within `timeout`. The status, not only the fact of an exit: a
/// daemon that panicked or aborted on its way down has exited too.
fn wait_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return None,
        }
    }
    let _ = child.kill();
    None
}

/// Wait out a daemon sent SIGTERM: it must exit within `timeout`, and with
/// status 0. A drain that panicked, or a teardown that failed, exits
/// otherwise, and a test that only waited for the exit passed over it.
fn assert_exits_zero(child: &mut Child, timeout: Duration) {
    let status = wait_exit(child, timeout)
        .unwrap_or_else(|| panic!("the daemon did not exit within {timeout:?} of SIGTERM"));
    assert_eq!(
        status.code(),
        Some(0),
        "a SIGTERM must end in a clean exit, not {status:?}"
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
    assert_exits_zero(&mut child, Duration::from_secs(30));
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
    assert_exits_zero(&mut child, Duration::from_secs(30));
    // A clean exit still writes the report the next boot re-exports, and it
    // says nothing was left behind. This daemon has no kill switch, so
    // `kill_switch_removal_failed` is false with nothing to remove: the
    // removal itself is asserted with the switch on, and the table checked
    // gone, in tests/vpn_netns_e2e.rs.
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

/// The upgrade every pre-profiles deployment takes.
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

    let exited = exited.unwrap_or_else(|| {
        panic!("the daemon started against a registry it cannot serve; stderr: {err}")
    });
    assert_eq!(
        exited.code(),
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
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
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
    wait_healthy(addr);

    let (code, metrics) = http(addr, "GET", "/metrics", None);
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
    assert_exits_zero(&mut child, Duration::from_secs(30));
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
    let status = wait_exit(&mut child, Duration::from_secs(30))
        .expect("a refused config must not start the daemon");
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
    let code = status.code().expect("exited, not signalled");
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
    let cfg = write_config(p, free_port(), &free_http());
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
    let out = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .args(["vpn", "check"])
        .output()
        .expect("spawn torrentd vpn check");
    assert_eq!(
        out.status.code(),
        Some(1),
        "vpn check on a config that fails to load; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
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
             http_listen = \"{http}\"\n\
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
             listen_port = {listen_port}\n\
             peer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\n\
             allowed_tracker_domains = [\"t.example\"]\n",
            d = p.display(),
            http = free_http(),
            listen_port = free_port(),
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
/// from the pre-rename `slot_assignments.json`, and editing that file changes
/// nothing: the daemon imports it into `registry.db` on the same boot, renames
/// it, and reads only the database from here on. Naming the old file alone sent them to the
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
    assert_exits_zero(&mut child, Duration::from_secs(30));
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
    assert_exits_zero(&mut child, Duration::from_secs(30));
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
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}

/// A real `SIGHUP`, not `POST /v1/config/reload`, reaches the reload pump,
/// and a `connections_limit` edit is applied to the profile's live libtorrent
/// session: `SIGHUP: settings applied` is logged only once that session's
/// `apply_settings` has returned, and nothing is counted as a failed reload.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_sighup_applies_connections_limit_to_the_live_session() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    // `settings applied` is an info line.
    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        body.replace("log_level = \"warn\"\n", "log_level = \"info\"\n"),
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
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn daemon"),
    );
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

    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        body.replace(
            "enable_lsd = false\n",
            "enable_lsd = false\nconnections_limit = 321\n",
        ),
    )
    .unwrap();
    Command::new("kill")
        .args(["-HUP", &child.0.id().to_string()])
        .status()
        .expect("send SIGHUP");

    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let applied = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(line) = lines.recv_timeout(left) else {
            panic!("no reload verdict within 10s; output:\n{}", seen.join("\n"));
        };
        seen.push(line.clone());
        if line.contains("SIGHUP: settings applied")
            || line.contains("SIGHUP: apply_settings failed")
            || line.contains("SIGHUP: config unchanged")
            || line.contains("connections_limit refused")
        {
            break line;
        }
    };
    assert!(
        seen.iter().any(|l| l.contains("received SIGHUP")),
        "the signal, not the HTTP trigger, started this reload: {}",
        seen.join("\n"),
    );
    assert!(
        applied.contains("SIGHUP: settings applied")
            && applied.contains(&format!("\"profile_id\":\"{PROFILE}\"")),
        "the edit reached the profile's session: {applied}",
    );
    assert_eq!(
        metric(
            addr,
            "torrentd_config_reload_failures_total{stage=\"apply_settings\"}"
        ),
        0.0,
    );

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
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

/// Poll `GET /v1/torrents/{ih}` until its `(phase, progress)` satisfies
/// `done`, returning it; or, once `within` has passed, the last one seen as
/// the error. The phase can move a status update before the progress does,
/// so a wait names both.
fn settled_in(
    addr: &str,
    ih: &str,
    within: Duration,
    done: impl Fn(&str, f64) -> bool,
) -> Result<(String, f64), Option<(String, f64)>> {
    let deadline = Instant::now() + within;
    let mut last = None;
    loop {
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        if code == 200 {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let seen = (
                v["phase"].as_str().unwrap_or_default().to_owned(),
                v["progress"].as_f64().unwrap_or_default(),
            );
            if done(&seen.0, seen.1) {
                return Ok(seen);
            }
            last = Some(seen);
        }
        if Instant::now() >= deadline {
            return Err(last);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
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

/// A spawned daemon, killed if the test panics before stopping it: an
/// orphaned daemon holds the test's stdout open, and whatever reads it waits.
struct Running(Child);

impl Running {
    fn stop(mut self) {
        sigterm(&self.0);
        assert_exits_zero(&mut self.0, Duration::from_secs(30));
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Poll `f` every 200 ms until it returns `Some`, or panic naming `what`.
fn poll<T>(what: &str, within: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + within;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

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

#[path = "../../torrentd-pool/tests/fixtures/bt_backup.rs"]
mod bt_backup;

/// `POST path` with the JSON `body`, as [`http`] does, waiting up to
/// `timeout` for the answer.
fn post_within(addr: &str, path: &str, body: &str, timeout: Duration) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(timeout)).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("POST {path} on {addr}: {e}"));
    let resp = String::from_utf8_lossy(&buf);
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

/// The value of the `/metrics` sample named exactly `series`, or 0 where the
/// scrape has none yet.
fn metric(addr: &str, series: &str) -> f64 {
    let (code, body) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200, "{body}");
    body.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
        .map_or(0.0, |v| v.trim().parse().unwrap())
}

/// Issue #430's acceptance: a qBittorrent `BT_backup` imports through the
/// real daemon and real libtorrent, each torrent the way its pair says.
///
/// Every case the generator knows, twice. One adoption takes them all:
///
/// - complete, renamed through `mapped_files`, and with a save path that is
///   not UTF-8: the fast path, the previous client's resume data handed to
///   libtorrent in seed mode, `adopted` at once and seeding without a check;
///   the renamed one at the name libtorrent learns from that resume data;
/// - incomplete, and with its sidecar cut off halfway: the verify queue,
///   hashed, then seeding and `adopted`;
/// - `NoSubfolder`: refused, since libtorrent cannot be told about a layout
///   only qBittorrent recorded, and never loaded;
/// - an orphan sidecar: never indexed, and refused as not in the library.
///
/// `torrentd_checks_started_total{source="adoption"}` counts the verify
/// queue's checks only, so it ends at the verified torrents' number. Each
/// adopted torrent's session holds it at the base the pool matched, and the
/// resume data libtorrent writes at the graceful stop records it in upload
/// mode — the daemon never downloads — and in seed mode for the fast path
/// alone.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_bt_backup_directory_imports_fast_path_and_verify_mixed() {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use bt_backup::Case;
    use torrentd_pool::adopt::refusal;

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let backup = p.join("BT_backup");
    let root = p.join("pool");
    let generated = bt_backup::generate(&backup, &root, 2 * Case::ALL.len(), |b| {
        use sha1::Digest;
        sha1::Sha1::digest(b).into()
    });
    let of = |cases: &[Case]| -> BTreeSet<String> {
        generated
            .iter()
            .filter(|g| cases.contains(&g.case))
            .map(|g| g.infohash.clone())
            .collect()
    };
    let fast = of(&[Case::Complete, Case::Renamed, Case::NonUtf8SavePath]);
    let verify = of(&[Case::Incomplete, Case::TruncatedSidecar]);

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\n",
        root.display(),
        backup.display()
    ));
    std::fs::write(&cfg, text).unwrap();
    let log = DaemonLog::new(p);
    let child = Running(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .stdout(log.stdio())
            .stderr(log.stdio())
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy(addr);

    let (code, body) = http(addr, "POST", "/v1/pool/scan", None);
    assert_eq!(code, 200, "{body}");
    for g in &generated {
        let expected = (g.case != Case::OrphanSidecar).then(|| "matched".to_owned());
        assert_eq!(pool_state(addr, &g.infohash), expected, "{g:?}");
    }

    let all: Vec<String> = generated
        .iter()
        .map(|g| format!("\"{}\"", g.infohash))
        .collect();
    // Answered once every torrent is added or queued, which runs past
    // `http`'s five-second read timeout for this many.
    let (code, body) = post_within(
        addr,
        "/v1/pool/adoptions",
        &format!(
            "{{\"profile_id\":\"{PROFILE}\",\"selector\":{{\"kind\":\"infohashes\",\
             \"infohashes\":[{}]}}}}",
            all.join(",")
        ),
        Duration::from_secs(120),
    );
    assert_eq!(code, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let set = |key: &str| -> BTreeSet<String> {
        v[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|ih| ih.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(set("fast_path"), fast, "{body}");
    assert_eq!(set("queued_for_verification"), verify, "{body}");
    let refused: BTreeMap<String, String> = v["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["infohash"].as_str().unwrap().to_owned(),
                r["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected_refused: BTreeMap<String, String> = generated
        .iter()
        .filter_map(|g| match g.case {
            Case::NoSubfolder => Some((g.infohash.clone(), refusal::LAYOUT_NOT_IN_RESUME)),
            Case::OrphanSidecar => Some((g.infohash.clone(), refusal::NOT_IN_LIBRARY)),
            _ => None,
        })
        .map(|(ih, r)| (ih, r.to_owned()))
        .collect();
    assert_eq!(refused, expected_refused, "{body}");

    // The fast path records the adoption as it adds, before any check could
    // have run.
    for ih in &fast {
        assert_eq!(pool_state(addr, ih).as_deref(), Some("adopted"), "{ih}");
    }

    let adopted: Vec<&bt_backup::Generated> = generated
        .iter()
        .filter(|g| fast.contains(&g.infohash) || verify.contains(&g.infohash))
        .collect();
    for g in &adopted {
        let ih = &g.infohash;
        if let Err(last) = settled_in(addr, ih, Duration::from_secs(60), |phase, _| {
            phase == "seeding"
        }) {
            panic!("{g:?} never reached seeding; last seen {last:?}");
        }
        poll(
            &format!("{ih} to be recorded adopted"),
            Duration::from_secs(30),
            || (pool_state(addr, ih).as_deref() == Some("adopted")).then_some(()),
        );

        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        assert_eq!(code, 200, "{body}");
        let t: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            t["session"]["name"].as_str(),
            Some(g.name.as_str()),
            "{g:?}"
        );
        assert_eq!(
            t["session"]["save_path"]
                .as_str()
                .map(std::path::PathBuf::from),
            Some(root.join(&g.base_rel)),
            "{g:?}"
        );
        // The paths libtorrent opens, which for the renamed torrent are the
        // ones only its resume data names.
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}/files"), None);
        assert_eq!(code, 200, "{body}");
        let files: serde_json::Value = serde_json::from_str(&body).unwrap();
        let paths: Vec<&str> = files["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, g.file_paths, "{g:?}");
    }

    // Refused, and so never handed to a session.
    for ih in &of(&[Case::NoSubfolder]) {
        assert_eq!(pool_state(addr, ih).as_deref(), Some("matched"), "{ih}");
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        assert_eq!(code, 404, "{ih}: {body}");
    }

    // One check per verified torrent, and none for the fast path.
    assert_eq!(
        metric(addr, "torrentd_checks_started_total{source=\"adoption\"}"),
        verify.len() as f64,
    );

    child.stop();

    for g in &adopted {
        let resume = p
            .join("resume")
            .join(PROFILE)
            .join(format!("{}.resume", g.infohash));
        let bytes = std::fs::read(&resume)
            .unwrap_or_else(|e| panic!("{g:?}: no resume file at the graceful stop: {e}"));
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"11:upload_modei1e"), "{g:?} is not in upload mode");
        let seed_mode: &[u8] = if fast.contains(&g.infohash) {
            b"9:seed_modei1e"
        } else {
            b"9:seed_modei0e"
        };
        assert!(
            has(seed_mode),
            "{g:?}: expected {}",
            String::from_utf8_lossy(seed_mode)
        );
    }
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

/// `n` distinct infohashes, numbered from `base`.
fn infohashes(base: u64, n: u64) -> std::collections::BTreeSet<String> {
    (base..base + n).map(|i| format!("{i:040x}")).collect()
}

/// Add a magnet for each of `ihs` to [`PROFILE`] through the API.
fn add_magnets<'a>(addr: &str, ihs: impl IntoIterator<Item = &'a String>) {
    for ih in ihs {
        let body = add_magnet(&format!("magnet:?xt=urn:btih:{ih}"));
        let (code, answer) = http(addr, "POST", "/v1/torrents", Some(&body));
        assert_eq!(code, 201, "add {ih}: {answer}");
    }
}

/// Every torrent `GET /v1/torrents` lists, as `(infohash, phase)`, across
/// every page and in the order listed.
fn listed(addr: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(c) => format!("/v1/torrents?limit=1000&cursor={c}"),
            None => "/v1/torrents?limit=1000".to_owned(),
        };
        let (code, body) = http(addr, "GET", &path, None);
        assert_eq!(code, 200, "{path}: {body}");
        let page: serde_json::Value = serde_json::from_str(&body).unwrap();
        for t in page["items"].as_array().expect("items") {
            out.push((
                t["infohash"].as_str().unwrap().to_owned(),
                t["phase"].as_str().unwrap().to_owned(),
            ));
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => return out,
        }
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
