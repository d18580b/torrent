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

// The tests, by scenario family, under `daemon/`; what they share is below.
// A crate root's modules would otherwise be looked for beside it, in
// `tests/`, where Cargo would take each for a test binary of its own.
#[path = "daemon/boot.rs"]
mod boot;
#[path = "daemon/boot_scans.rs"]
mod boot_scans;
#[path = "daemon/hybrid.rs"]
mod hybrid;
#[path = "daemon/import.rs"]
mod import;
#[path = "daemon/lifecycle.rs"]
mod lifecycle;
#[path = "daemon/pool.rs"]
mod pool;
#[path = "daemon/restarts.rs"]
mod restarts;
#[path = "daemon/serving.rs"]
mod serving;

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

/// [`http`] with a read timeout of `timeout`, for a request that runs long.
fn http_within(addr: &str, method: &str, path: &str, timeout: Duration) -> (u16, String) {
    http_body_within(addr, method, path, "", timeout)
}

/// [`http_within`], sending `body` as JSON.
fn http_body_within(
    addr: &str,
    method: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(timeout)).unwrap();
    let json = if body.is_empty() {
        ""
    } else {
        "Content-Type: application/json\r\n"
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         {json}Content-Length: {}\r\n\r\n{body}",
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
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
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

#[path = "../../torrentd-pool/tests/fixtures/bt_backup.rs"]
mod bt_backup;

/// The value of the `/metrics` sample named exactly `series`, or 0 where the
/// scrape has none yet.
fn metric(addr: &str, series: &str) -> f64 {
    let (code, body) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200, "{body}");
    body.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
        .map_or(0.0, |v| v.trim().parse().unwrap())
}

/// `n` distinct infohashes, numbered from `base`.
fn infohashes(base: u64, n: u64) -> std::collections::BTreeSet<String> {
    (base..base + n).map(|i| format!("{i:040x}")).collect()
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
