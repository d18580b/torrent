//! The real daemon over a real WireGuard link under a real nftables kill
//! switch, in a network namespace of its own: nothing it sends reaches the
//! physical link outside the tunnel, whatever happens to the tunnel, the
//! ruleset, or the routing rules underneath it.
//!
//! Every other test of the kill switch either renders its ruleset, installs
//! it with no daemon (`vpn::killswitch` and `vpn::wireguard`'s ignored
//! tests), or drives the daemon over fakes. These run the built binary as a
//! dedicated non-root uid with `network_kill_switch = true`, as a deployment
//! does, and break what it rests on one piece at a time.
//!
//! The topology each test builds, in a fresh user and network namespace it
//! re-runs itself in as uid 998:
//!
//! ```text
//!   this namespace ("host")                  the peer namespace ("provider")
//!   veth-ks 10.9.0.1/24 2001:db8:9::1/64 --- veth-peer 10.9.0.2/24 2001:db8:9::2/64
//!   wg-e2e 10.200.0.1/32 (the daemon's)      wg-peer 10.200.0.2/24 listen 51820
//!          2001:db8:200::1/128                       2001:db8:200::2/64
//! ```
//!
//! `veth-ks` is the host's physical link, holding both default routes, so a
//! packet that escapes the tunnel has somewhere to go. Everything arriving on
//! `veth-peer` that is not the tunnel's own transport (UDP to 51820, and the
//! kernel's port-unreachable answer to it once the link is deleted) or IPv6
//! neighbour discovery is counted by an nftables counter in the peer
//! namespace, per family: those counts are the leaks, and they must stay 0.
//!
//! Needs `ip`, `wg`, `nft`, `unshare` (util-linux 2.38 or later, for
//! `--map-user`), `nsenter` and `setpriv`, `setcap` (libcap) for the
//! file-capability case, an `/etc/wireguard` directory to mount a
//! tmpfs over (`wireguard-tools` ships one), and a kernel that lets this user
//! create user namespaces and WireGuard links; so they are ignored by
//! default.
//! `mise run test-netns` runs them, and the `vpn-netns` CI job runs that.
//! Alone:
//!
//! ```text
//! cargo test -p torrentd --test vpn_netns_e2e -- --ignored --test-threads=1
//! ```

use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::process::Child;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// Set in the re-run that is inside the namespace.
const IN_NAMESPACE: &str = "TORRENTD_TEST_VPN_NETNS_E2E";

/// The uid the daemon runs as: not 0, which the kill switch refuses.
const UID: u32 = 998;

const PROFILE: &str = "e2e";
const WG: &str = "wg-e2e";
const HTTP: &str = "127.0.0.1:8080";
const TUNNEL: &str = "10.200.0.1";
const PEER_TUNNEL: &str = "10.200.0.2";
/// The tunnel's IPv6 address, so the kill switch's IPv6 fence is live.
const TUNNEL_V6: &str = "2001:db8:200::1";
const PEER_TUNNEL_V6: &str = "2001:db8:200::2";
const HOST_V4: &str = "10.9.0.1";
const PEER_V4: &str = "10.9.0.2";
const HOST_V6: &str = "2001:db8:9::1";
const PEER_V6: &str = "2001:db8:9::2";
const WG_PEER_PORT: u16 = 51820;
const TRACKER_PORT: u16 = 6969;
/// The hostname the tunnel-DNS test announces to, which only the resolver
/// inside the tunnel knows.
const TRACKER_NAME: &str = "tracker.e2e";
/// Where the peer namespace listens for the daemon's peer connections.
const SWARM_PORT: u16 = 6881;
/// The static profile's listen port.
const LISTEN_PORT: u16 = 51413;

/// How long the kill switch's watch may take to notice a loss and repair it:
/// its 30 s interval, and the reinstall.
const WATCH_BOUND: Duration = Duration::from_secs(35);
/// How long the VPN monitor may take to fence: its 30 s poll, and the pause.
const MONITOR_BOUND: Duration = Duration::from_secs(40);
/// How long each fault is given to leak, with the daemon prompted to send.
const LEAK_WINDOW: Duration = Duration::from_secs(5);

/// Re-run `test` inside a fresh user, network and mount namespace as uid
/// [`UID`], with its capabilities kept, and fail with its output if it
/// fails. Returns `true` in the re-run, where the test body runs.
///
/// The mount namespace is for `/etc/wireguard`: a WireGuard profile's
/// `vpn_config` must be `/etc/wireguard/<vpn_interface>.conf`, so the re-run
/// mounts a tmpfs of its own there ([`topology`]), which nothing outside it
/// sees.
fn in_own_namespace(test: &str) -> bool {
    if std::env::var_os(IN_NAMESPACE).is_some() {
        return true;
    }
    let out = Command::new("unshare")
        .args([
            "--user",
            &format!("--map-user={UID}"),
            &format!("--map-group={UID}"),
            "--net",
            "--mount",
            "--keep-caps",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            test,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(IN_NAMESPACE, "1")
        .output()
        .expect("run unshare");
    assert!(
        out.status.success(),
        "the run inside the namespace failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    false
}

/// Where the re-run [`in_file_capability_namespace`] makes finds the copy of
/// the daemon that carries the file capability.
const CAP_BIN: &str = "TORRENTD_TEST_CAP_BIN";

/// [`in_own_namespace`], one user namespace deeper, with a copy of the
/// daemon carrying the file capability `cap_net_admin+p`, as
/// `deploy/Containerfile` sets it. Returns that copy's path in the re-run.
///
/// The outer namespace maps this user to root, and there mounts a tmpfs,
/// copies the daemon onto it and runs `setcap`; the test then runs as uid
/// [`UID`] in a namespace that outer root created. Both levels are needed: a
/// file capability is honoured only in a namespace whose root, or an
/// ancestor's, owns it, and the one [`in_own_namespace`] makes maps no root.
/// The test keeps its own capabilities as before, to build the topology, but
/// an `execve` of a binary with a file capability clears the ambient set, so
/// the daemon holds `CAP_NET_ADMIN` from the file and from nothing else.
fn in_file_capability_namespace(test: &str) -> Option<std::path::PathBuf> {
    if std::env::var_os(IN_NAMESPACE).is_some() {
        let bin = std::env::var_os(CAP_BIN).expect("set by the launcher");
        return Some(bin.into());
    }
    let capdir = tempfile::tempdir().unwrap();
    let setup = "set -eu\n\
                 mount -t tmpfs -o mode=0755 torrentd-cap \"$1\"\n\
                 cp \"$2\" \"$1/torrentd\"\n\
                 setcap cap_net_admin+p \"$1/torrentd\"\n\
                 shift 2\n\
                 exec \"$@\"\n";
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .args(["sh", "-c", setup, "sh"])
        .arg(capdir.path())
        .arg(env!("CARGO_BIN_EXE_torrentd"))
        .args([
            "unshare",
            "--user",
            &format!("--map-user={UID}"),
            &format!("--map-group={UID}"),
            "--net",
            "--mount",
            "--keep-caps",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            test,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(IN_NAMESPACE, "1")
        .env(CAP_BIN, capdir.path().join("torrentd"))
        .output()
        .expect("run unshare");
    assert!(
        out.status.success(),
        "the run inside the namespace failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    None
}

/// One capability set of process `pid`, from its `/proc/<pid>/status`.
fn cap_set(pid: u32, line: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix(line))
        .unwrap_or_else(|| panic!("no {line} in {status}"))
        .trim();
    u64::from_str_radix(hex, 16).unwrap()
}

/// Run `cmd` through `sh -c`, asserting it succeeds; its trimmed stdout.
fn sh(cmd: &str) -> String {
    let out = Command::new("sh").arg("-c").arg(cmd).output().unwrap();
    assert!(
        out.status.success(),
        "`{cmd}`: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Poll `f` every 200 ms until it returns `Some`, or panic naming `what`.
fn poll<T>(what: &str, within: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + within;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {within:?} waiting for {what}"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

/// Move the calling thread, and only it, into the network namespace of
/// process `pid`: a socket it opens from then on lives there.
fn enter_netns(pid: u32) {
    let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).expect("open the namespace");
    // SAFETY: `ns` is an open network-namespace descriptor for the duration
    // of the call; `setns` with `CLONE_NEWNET` changes the calling thread's
    // network namespace and nothing else.
    let rc = unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns: {}", std::io::Error::last_os_error());
}

/// The provider's side: a process sleeping in a network namespace of its
/// own, one veth away, holding the WireGuard peer, the leak counters, and
/// whatever the test serves there.
struct Peer {
    sleeper: Child,
    pid: u32,
}

impl Peer {
    fn new() -> Self {
        let sleeper = Command::new("unshare")
            .args(["-n", "sleep", "3600"])
            .spawn()
            .unwrap();
        let pid = sleeper.id();
        let ours = std::fs::read_link("/proc/self/ns/net").unwrap();
        poll("the peer namespace", Duration::from_secs(5), || {
            let theirs = std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()?;
            (theirs != ours).then_some(())
        });
        Self { sleeper, pid }
    }

    /// Run `script` with `sh -ec` in the peer namespace; its stdout.
    fn sh(&self, script: &str) -> String {
        let out = Command::new("nsenter")
            .args(["-t", &self.pid.to_string(), "-n", "sh", "-ec", script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "in the peer namespace, `{script}`: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Run `f` on a thread of its own inside the peer namespace.
    fn spawn(&self, f: impl FnOnce() + Send + 'static) {
        let pid = self.pid;
        thread::spawn(move || {
            enter_netns(pid);
            f();
        });
    }

    /// Bind `bind` inside the peer namespace and hand every connection it
    /// accepts to `serve`, each on the accepting thread.
    fn serve_tcp(&self, bind: SocketAddr, serve: impl Fn(TcpStream) + Send + 'static) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.spawn(move || {
            let listener = TcpListener::bind(bind);
            let ok = listener.is_ok();
            tx.send(listener.as_ref().map(|_| ()).map_err(|e| e.to_string()))
                .unwrap();
            if !ok {
                return;
            }
            for conn in listener.unwrap().incoming().flatten() {
                serve(conn);
            }
        });
        rx.recv()
            .unwrap()
            .unwrap_or_else(|e| panic!("bind {bind} in the peer namespace: {e}"));
    }

    /// The packets counted as leaks so far, `(ipv4, ipv6)`.
    fn leaks(&self) -> (u64, u64) {
        let read = |name: &str| -> u64 {
            let json = self.sh(&format!("nft -j list counter inet leak {name}"));
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            v["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .find_map(|o| o["counter"]["packets"].as_u64())
                .unwrap_or_else(|| panic!("no packet count in {json}"))
        };
        (read("v4"), read("v6"))
    }

    /// Panic, naming what was seen, if any leak was counted beyond `base`.
    fn assert_no_leak(&self, base: (u64, u64), after: &str) {
        let now = self.leaks();
        assert_eq!(
            now,
            base,
            "{after}: packets reached the physical link outside the tunnel \
             (ipv4, ipv6 counts; base {base:?}):\n{}",
            self.sh("nft list table inet leak")
        );
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.sleeper.kill();
        let _ = self.sleeper.wait();
    }
}

/// The daemon's WireGuard config.
fn wg_config() -> String {
    format!("/etc/wireguard/{WG}.conf")
}

/// The topology in the module documentation, with the leak counters armed
/// and checked to count, and the daemon's WireGuard config written to
/// [`wg_config`]. Returns the peer namespace.
fn topology(dir: &std::path::Path) -> Peer {
    let peer = Peer::new();
    let key_path = |name: &str| dir.join(name).display().to_string();
    let ours_key = sh("wg genkey");
    let peer_key = sh("wg genkey");
    std::fs::write(key_path("peer.key"), &peer_key).unwrap();
    let ours_pub = sh(&format!("echo {ours_key} | wg pubkey"));
    let peer_pub = sh(&format!("echo {peer_key} | wg pubkey"));

    sh("ip link set lo up");
    sh(&format!(
        "ip link add veth-ks type veth peer name veth-peer netns {}",
        peer.pid
    ));
    sh(&format!(
        "ip addr add {HOST_V4}/24 dev veth-ks && \
         ip -6 addr add {HOST_V6}/64 dev veth-ks nodad && ip link set veth-ks up && \
         ip route add default via {PEER_V4} && ip -6 route add default via {PEER_V6}"
    ));
    peer.sh(&format!(
        "ip link set lo up; \
         ip addr add {PEER_V4}/24 dev veth-peer; \
         ip -6 addr add {PEER_V6}/64 dev veth-peer nodad; ip link set veth-peer up; \
         ip link add wg-peer type wireguard; \
         wg set wg-peer private-key {} listen-port {WG_PEER_PORT} \
             peer {ours_pub} allowed-ips {TUNNEL}/32,{TUNNEL_V6}/128; \
         ip addr add {PEER_TUNNEL}/24 dev wg-peer; \
         ip -6 addr add {PEER_TUNNEL_V6}/64 dev wg-peer nodad; ip link set wg-peer up",
        key_path("peer.key"),
    ));
    // Anything arriving on the physical link but the tunnel's transport, the
    // kernel's port-unreachable answer to the provider's transport once the
    // tunnel's socket is gone (the ICMP error quoting a datagram from UDP
    // 51820: the inner UDP source port, 28 bytes into an ICMP message and 48
    // into an ICMPv6 one), and the neighbour discovery IPv6 needs to work at
    // all.
    peer.sh(
        "nft -f - <<'EOF'
table inet leak {
	counter v4 {
	}
	counter v6 {
	}
	set seen4 {
		type ipv4_addr . ipv4_addr . inet_proto
		flags dynamic
	}
	set seen6 {
		type ipv6_addr . ipv6_addr . inet_proto
		flags dynamic
	}
	chain watch {
		type filter hook prerouting priority -300; policy accept;
		iifname != \"veth-peer\" return
		udp dport 51820 return
		icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-report, mld2-listener-report } return
		icmp type destination-unreachable icmp code port-unreachable @th,224,16 51820 return
		icmpv6 type destination-unreachable icmpv6 code port-unreachable @th,384,16 51820 return
		meta nfproto ipv4 add @seen4 { ip saddr . ip daddr . meta l4proto } counter name \"v4\"
		meta nfproto ipv6 add @seen6 { ip6 saddr . ip6 daddr . meta l4proto } counter name \"v6\"
	}
}
EOF",
    );
    // The control: before any kill switch, this uid's datagram on the bare
    // link is counted, in each family, so a 0 later means none was sent.
    let base = peer.leaks();
    UdpSocket::bind((HOST_V4, 0))
        .unwrap()
        .send_to(b"x", (PEER_V4, 9))
        .expect("send on the bare link");
    UdpSocket::bind((HOST_V6, 0))
        .unwrap()
        .send_to(b"x", (PEER_V6, 9))
        .expect("send on the bare link over IPv6");
    poll(
        "the control datagrams to be counted as leaks",
        Duration::from_secs(5),
        || (peer.leaks() == (base.0 + 1, base.1 + 1)).then_some(()),
    );

    // A provider-shaped config: full-tunnel AllowedIPs, raised by the daemon,
    // at the one path a profile may name, on a tmpfs only this namespace sees.
    sh("mount -t tmpfs -o mode=0700 vpn-netns-e2e /etc/wireguard");
    std::fs::write(
        wg_config(),
        format!(
            "[Interface]\nPrivateKey = {ours_key}\nAddress = {TUNNEL}/32, {TUNNEL_V6}/128\n\n\
             [Peer]\nPublicKey = {peer_pub}\nEndpoint = {PEER_V4}:{WG_PEER_PORT}\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n"
        ),
    )
    .unwrap();
    peer
}

/// Minimal blocking HTTP/1.1 client: `(status, body)`, or the error that
/// kept an answer from arriving.
fn try_http(method: &str, path: &str, body: Option<&str>) -> std::io::Result<(u16, String)> {
    try_http_at(HTTP, method, path, body, "", Duration::from_secs(10))
}

/// [`try_http`] to `addr`, with `headers` (each line ending `\r\n`) added and
/// `wait` as the read timeout.
fn try_http_at(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: &str,
    wait: Duration,
) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(wait))?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf);
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    Ok((status, body.to_string()))
}

fn http(method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    try_http(method, path, body).unwrap_or_else(|e| panic!("{method} {path}: {e}"))
}

/// The value of the series `series` (name and labels, as exposed) in one
/// scrape, or `None` where it is absent.
fn metric(series: &str) -> Option<f64> {
    let (_, text) = http("GET", "/metrics", None);
    text.lines().find_map(|l| {
        l.strip_prefix(series)?
            .strip_prefix(' ')?
            .trim()
            .parse()
            .ok()
    })
}

/// The profile as `GET /v1/profiles/{id}` reports it.
fn profile() -> serde_json::Value {
    let (code, body) = http("GET", &format!("/v1/profiles/{PROFILE}"), None);
    assert_eq!(code, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// The profile's `status` in `GET /v1/profiles`, the list an operator reads.
fn listed_status() -> String {
    let (code, body) = http("GET", "/v1/profiles", None);
    assert_eq!(code, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["profile_id"] == PROFILE)
        .unwrap_or_else(|| panic!("{PROFILE} is not listed: {body}"))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The running daemon: its stdout and stderr in `daemon.log`, printed on a
/// panic, and the process killed if the test ends with it still running.
struct Daemon {
    child: Child,
    log: std::path::PathBuf,
}

impl Daemon {
    /// Write `dir/cfg.toml` ([`write_config`]), spawn the daemon on it, and
    /// wait for the profile to come up on its tunnel.
    fn start(dir: &std::path::Path, profile_extra: &str) -> Self {
        Self::start_from(
            std::path::Path::new(env!("CARGO_BIN_EXE_torrentd")),
            dir,
            profile_extra,
        )
    }

    /// [`Daemon::start`], running the daemon from `bin`.
    fn start_from(bin: &std::path::Path, dir: &std::path::Path, profile_extra: &str) -> Self {
        let cfg = write_config(dir, profile_extra);
        let mut daemon = Self::spawn(bin, dir, &cfg);
        poll(
            "the profile to come up on its tunnel",
            Duration::from_secs(60),
            || {
                if let Some(status) = daemon.child.try_wait().unwrap() {
                    panic!("the daemon exited {status} before its profile came up");
                }
                let (code, body) =
                    try_http("GET", &format!("/v1/profiles/{PROFILE}"), None).ok()?;
                let v: serde_json::Value = serde_json::from_str(&body).ok()?;
                (code == 200 && v["status"] == "active" && v["tunnel_ip"] == TUNNEL).then_some(())
            },
        );
        daemon
    }

    /// Spawn the daemon from `bin` on `cfg`, its output in `dir/daemon.log`,
    /// and wait for nothing.
    fn spawn(bin: &std::path::Path, dir: &std::path::Path, cfg: &std::path::Path) -> Self {
        let log = dir.join("daemon.log");
        let out = std::fs::File::create(&log).unwrap();
        let child = Command::new(bin)
            .arg("--config")
            .arg(cfg)
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .expect("spawn the daemon");
        Self { child, log }
    }
}

/// Write `dir/cfg.toml` — the kill switch on, and one vpn profile on [`WG`]
/// carrying `profile_extra` — with the directories it names, and return its
/// path.
fn write_config(dir: &std::path::Path, profile_extra: &str) -> std::path::PathBuf {
    write_config_top(
        dir,
        &format!("http_listen = \"{HTTP}\"\nallow_unauthenticated = true"),
        profile_extra,
    )
}

/// [`write_config`], with `top` in place of its `http_listen` and
/// authentication lines.
fn write_config_top(dir: &std::path::Path, top: &str, profile_extra: &str) -> std::path::PathBuf {
    for sub in ["data", "resume", "torrents"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let cfg = dir.join("cfg.toml");
    std::fs::write(
        &cfg,
        format!(
            "default_save_path = \"{d}/data\"\n\
                 resume_dir = \"{d}/resume\"\n\
                 torrent_dir = \"{d}/torrents\"\n\
                 log_level = \"info\"\n\
                 network_kill_switch = true\n\
                 {top}\n\
                 \n\
                 [[profile]]\n\
                 id = \"{PROFILE}\"\n\
                 network = \"vpn\"\n\
                 vpn_type = \"wireguard\"\n\
                 vpn_config = \"{wg}\"\n\
                 vpn_interface = \"{WG}\"\n\
                 peer_fingerprint = \"-qB5030-\"\n\
                 user_agent = \"qBittorrent/5.0.3\"\n\
                 allowed_tracker_domains = [\"{PEER_TUNNEL}\", \"{PEER_TUNNEL_V6}\", \"{TRACKER_NAME}\"]\n\
                 {profile_extra}\n",
            d = dir.display(),
            wg = wg_config(),
        ),
    )
    .unwrap();
    cfg
}

impl Daemon {
    /// SIGTERM, and wait for the exit.
    fn stop(&mut self) {
        sh(&format!("kill -TERM {}", self.child.id()));
        let status = poll(
            "the daemon to exit on SIGTERM",
            Duration::from_secs(90),
            || self.child.try_wait().unwrap(),
        );
        assert!(status.success(), "the daemon exited {status}");
    }

    /// SIGKILL, and reap it: the exit a `kill -9` or the OOM killer makes,
    /// running none of the shutdown's teardown.
    fn crash(&mut self) {
        self.child.kill().expect("SIGKILL the daemon");
        let status = self.child.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL),
            "the daemon exited {status}, not on SIGKILL"
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if thread::panicking() {
            let text = std::fs::read_to_string(&self.log).unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            eprintln!(
                "--- the daemon's output, last 200 lines ---\n{}\n--- end ---",
                lines[lines.len().saturating_sub(200)..].join("\n")
            );
        }
    }
}

/// A compact peer list entry, as a tracker answers it.
fn compact(addr: SocketAddr) -> Vec<u8> {
    let mut out = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// A one-request HTTP tracker in the peer namespace on both of its tunnel
/// addresses, [`PEER_TUNNEL`] and [`PEER_TUNNEL_V6`], so the daemon's listen
/// socket in each family announces to it; recording each announce's source
/// address, and answering with peers the daemon will try to reach: one inside
/// the tunnel, and one on each family of the physical link, which a socket
/// that escaped the tunnel would reach directly.
fn tracker(peer: &Peer) -> Arc<Mutex<Vec<SocketAddr>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut body = b"d8:intervali30e12:min intervali5e5:peers".to_vec();
    let v4: Vec<u8> = [
        format!("{PEER_TUNNEL}:{SWARM_PORT}"),
        format!("{PEER_V4}:{SWARM_PORT}"),
    ]
    .iter()
    .flat_map(|a| compact(a.parse().unwrap()))
    .collect();
    body.extend_from_slice(format!("{}:", v4.len()).as_bytes());
    body.extend_from_slice(&v4);
    let v6 = compact(format!("[{PEER_V6}]:{SWARM_PORT}").parse().unwrap());
    body.extend_from_slice(format!("6:peers6{}:", v6.len()).as_bytes());
    body.extend_from_slice(&v6);
    body.push(b'e');
    let body = Arc::new(body);
    for bind in [
        format!("{PEER_TUNNEL}:{TRACKER_PORT}"),
        format!("[{PEER_TUNNEL_V6}]:{TRACKER_PORT}"),
    ] {
        let recorded = seen.clone();
        let body = body.clone();
        peer.serve_tcp(bind.parse().unwrap(), move |mut conn| {
            let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            if let Ok(from) = conn.peer_addr() {
                recorded.lock().unwrap().push(from);
            }
            let _ = conn.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = conn.write_all(&body);
        });
    }
    seen
}

/// The info-hash of the magnet [`add_magnet`] adds.
const IH: &str = "4e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e";

/// Add [`IH`] to the profile as a magnet announcing to [`tracker`] on both
/// of its addresses: the add's `(status, body)`.
fn add_magnet() -> (u16, String) {
    let magnet = format!(
        "magnet:?xt=urn:btih:{IH}&dn=e2e\
         &tr=http%3A%2F%2F{PEER_TUNNEL}%3A{TRACKER_PORT}%2Fannounce\
         &tr=http%3A%2F%2F%5B{PEER_TUNNEL_V6}%5D%3A{TRACKER_PORT}%2Fannounce"
    );
    http(
        "POST",
        "/v1/torrents",
        Some(&format!(
            "{{\"profile_id\":\"{PROFILE}\",\"source\":{{\"kind\":\"magnet\",\"uri\":\"{magnet}\"}}}}"
        )),
    )
}

/// How many of the connections `seen` recorded came from `addr`.
fn from(seen: &Mutex<Vec<SocketAddr>>, addr: &str) -> usize {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|a| a.ip().to_string().trim_start_matches("::ffff:") == addr)
        .count()
}

/// How many of the connections `seen` recorded came through the tunnel.
fn tunnelled(seen: &Mutex<Vec<SocketAddr>>) -> usize {
    from(seen, TUNNEL)
}

/// Prompt the daemon to send: reannounce the torrent, whose answer hands it
/// the peers above to connect to. Refused while the profile is fenced, which
/// is the point of a fence; the leak check holds either way.
fn prompt(ih: &str) {
    let _ = try_http("POST", &format!("/v1/torrents/{ih}/reannounce"), None);
}

/// The kill switch table this test's uid owns, as `nft list tables` lists it.
fn table_listed() -> bool {
    sh("nft list tables").lines().any(|l| {
        l.split_whitespace()
            .eq(["table", "inet", &format!("torrentd_ks_{UID}")])
    })
}

/// Whether the daemon's WireGuard link, [`WG`], stands.
fn tunnel_standing() -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", WG])
        .output()
        .unwrap()
        .status
        .success()
}

/// The routing rules steering the tunnel's addresses into its table, in
/// both families, as `ip rule` lists them; empty where there are none.
fn tunnel_rules() -> String {
    sh(&format!(
        "ip rule show from {TUNNEL}; ip -6 rule show from {TUNNEL_V6}"
    ))
}

/// Prove that only the kill switch stands between this uid — the daemon's —
/// and the physical link: a datagram from each address in `sources` to the
/// peer's bare-link address in its family is refused with `EPERM`, which is
/// an nftables drop, and not `ENETUNREACH`, which would mean the kernel had
/// no route out of the physical link to leak by in the first place.
///
/// Without the kill switch each datagram would be sent and counted as a
/// leak; the caller's [`Peer::assert_no_leak`] then fails as well.
fn assert_only_the_kill_switch_stops(sources: &[&str], after: &str) {
    for src in sources {
        let src: std::net::IpAddr = src.parse().unwrap();
        let dst = if src.is_ipv4() { PEER_V4 } else { PEER_V6 };
        let sent = UdpSocket::bind((src, 0))
            .unwrap_or_else(|e| panic!("{after}: bind {src}: {e}"))
            .send_to(b"x", (dst, 9));
        let err = match sent {
            Ok(_) => panic!(
                "{after}: a datagram from {src} to {dst} was sent: the kill switch did not drop it"
            ),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{after}: a datagram from {src} to {dst} failed with `{err}`, not the kill switch's \
             EPERM: the kernel had no route to the physical link, so nothing could have leaked \
             by it, and the no-leak count proves nothing\n{}",
            sh("ip rule; ip -6 rule")
        );
    }
}

/// `ip rule flush` removes every rule but `local`'s, so `main`'s and
/// `default`'s with the tunnel's: with them gone the kernel routes nothing,
/// and a leak would be impossible rather than prevented. Put back the rules
/// a host has before any tunnel, so only the tunnel's is missing.
fn restore_base_rules(flush: &str) {
    if flush.starts_with("ip -6") {
        sh("ip -6 rule add pref 32766 table main");
    } else {
        sh("ip rule add pref 32766 table main && ip rule add pref 32767 table default");
    }
}

/// The daemon, with the kill switch on and one torrent announcing through the
/// tunnel to a tracker that hands out peers on both families of the bare
/// link, has its tunnel's protections removed one at a time:
///
/// 1. `nft flush ruleset`: the kill switch's watch notices, reinstalls it,
///    and counts `kill_switch_lost_total{outcome="reinstalled"}`, within
///    [`WATCH_BOUND`]; until it does, the source bind alone keeps the
///    daemon's traffic in the tunnel, and it does;
/// 2. the tunnel's IPv6 `from <address>` rule deleted alone: the IPv4 route
///    is still the tunnel's, and the VPN monitor fences the profile
///    `route_mismatch` on the IPv6 one; the rule put back, setting the
///    profile online lifts the fence;
/// 3. `ip -6 rule flush`, then `ip rule flush`: the tunnel's routing rules
///    are gone and the host's own put back ([`restore_base_rules`]), so the
///    physical link's default routes are live; nothing leaves by them, and
///    a datagram from the tunnel's addresses is refused by the kill switch
///    ([`assert_only_the_kill_switch_stops`]);
/// 4. `ip link del wg-e2e`: the tunnel is gone; nothing leaks, and the VPN
///    monitor fences the profile, which `GET /v1/profiles` reports.
///
/// The faults that leave the tunnel carrying come first, so the daemon is
/// still sending through it when they land. After each, the daemon is
/// prompted to send, and nothing may arrive on the physical link outside
/// the tunnel's own transport. A SIGTERM then removes the kill switch, and
/// the shutdown report says so; the VPN monitor and the kill-switch watch
/// fenced until the drain before it was over
/// ([`assert_fencing_held_through_the_drain`]).
#[test]
#[ignore = "needs ip, wg, nft, unshare and nsenter, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_no_leak() {
    if !in_own_namespace("vpn_netns_e2e_no_leak") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let peer = topology(p);
    let base = peer.leaks();
    let announces = tracker(&peer);
    let connects = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
    let recorded = connects.clone();
    peer.serve_tcp(format!("[::]:{SWARM_PORT}").parse().unwrap(), move |conn| {
        if let Ok(from) = conn.peer_addr() {
            recorded.lock().unwrap().push(from);
        }
    });

    let mut daemon = Daemon::start(p, &format!("listen_port = {LISTEN_PORT}"));
    assert_eq!(metric("torrentd_kill_switch_active"), Some(1.0));
    assert_eq!(metric("torrentd_kill_switch_table_present"), Some(1.0));
    assert!(table_listed(), "the kill switch table is installed");

    let ih = IH;
    let (code, body) = add_magnet();
    assert_eq!(code, 201, "add the torrent: {body}");

    // The positive control: the daemon announces and reaches a peer, both
    // through the tunnel and from its address.
    poll(
        "an announce through the tunnel",
        Duration::from_secs(30),
        || (tunnelled(&announces) > 0).then_some(()),
    );
    poll(
        "a peer connection through the tunnel",
        Duration::from_secs(30),
        || (tunnelled(&connects) > 0).then_some(()),
    );
    // The daemon sends IPv6 too, through the tunnel, announcing from its IPv6
    // listen socket to the tracker's IPv6 address: the IPv6 count below is of
    // a family it uses.
    poll(
        "an IPv6 announce through the tunnel",
        Duration::from_secs(30),
        || (from(&announces, TUNNEL_V6) > 0).then_some(()),
    );
    peer.assert_no_leak(base, "with the tunnel and the kill switch intact");

    // 1. The ruleset flushed out from under the daemon.
    let flushed = Instant::now();
    sh("nft flush ruleset");
    assert!(!table_listed());
    let before = tunnelled(&announces);
    // Prompted again every 2 s: a watch check landing now fences the
    // profile for the moment its reinstall takes, and refuses a prompt then.
    let mut polls = 0;
    poll(
        "an announce through the tunnel with no kill switch in force",
        Duration::from_secs(20),
        || {
            if polls % 10 == 0 {
                prompt(ih);
            }
            polls += 1;
            (tunnelled(&announces) > before).then_some(())
        },
    );
    poll(
        "the watch to reinstall the kill switch",
        WATCH_BOUND.saturating_sub(flushed.elapsed()),
        || {
            (metric("torrentd_kill_switch_lost_total{outcome=\"reinstalled\"}") == Some(1.0)
                && metric("torrentd_kill_switch_table_present") == Some(1.0))
            .then_some(())
        },
    );
    assert!(table_listed(), "the reinstalled table is in the kernel");
    assert_eq!(
        metric("torrentd_kill_switch_lost_total{outcome=\"lost\"}"),
        Some(0.0)
    );
    poll("the watch's fence to lift", Duration::from_secs(10), || {
        (listed_status() == "active").then_some(())
    });
    peer.assert_no_leak(base, "across `nft flush ruleset` and the reinstall");

    // 2. The tunnel's IPv6 routing rule alone. Its IPv4 route still leaves by
    //    the tunnel and its address and handshake are healthy, so only the
    //    route probe from its IPv6 address sees that IPv6 leaves by the
    //    physical link. Put back, the fence lifts on setting it online.
    let rule = sh(&format!("ip -6 rule show from {TUNNEL_V6}"));
    let table = rule
        .split_whitespace()
        .skip_while(|t| *t != "lookup")
        .nth(1)
        .unwrap_or_else(|| panic!("the tunnel's IPv6 rule names its table: {rule:?}"))
        .to_string();
    sh(&format!("ip -6 rule del from {TUNNEL_V6} table {table}"));
    prompt(ih);
    poll(
        "the VPN monitor to fence the profile on its IPv6 route",
        MONITOR_BOUND,
        || (listed_status() == "vpn_down").then_some(()),
    );
    assert_eq!(
        metric(&format!(
            "torrentd_profile_vpn_fenced_total{{profile_id=\"{PROFILE}\",reason=\"route_mismatch\"}}"
        )),
        Some(1.0),
        "fenced as route_mismatch with the IPv6 rule gone",
    );
    assert_only_the_kill_switch_stops(&[TUNNEL_V6], "with the tunnel's IPv6 rule gone");
    peer.assert_no_leak(base, "with the tunnel's IPv6 rule gone");
    sh(&format!("ip -6 rule add from {TUNNEL_V6} table {table}"));
    let (code, body) = http(
        "PATCH",
        &format!("/v1/profiles/{PROFILE}"),
        Some("{\"state\":\"online\"}"),
    );
    assert_eq!(code, 200, "the fence lifts with the rule back: {body}");
    poll("the fence to lift", Duration::from_secs(10), || {
        (listed_status() == "active").then_some(())
    });

    // 3. The routing rules: IPv6's, then IPv4's, each carrying the tunnel's
    //    `from <tunnel address>` rule. Each flush leaves a source of the
    //    tunnel's routed out of the physical link; IPv4's still goes through
    //    the tunnel until its own rule is flushed.
    for (flush, sources) in [
        ("ip -6 rule flush", &[TUNNEL_V6, HOST_V4, HOST_V6][..]),
        ("ip rule flush", &[TUNNEL, TUNNEL_V6, HOST_V4, HOST_V6][..]),
    ] {
        sh(flush);
        restore_base_rules(flush);
        prompt(ih);
        thread::sleep(LEAK_WINDOW);
        let after = format!("after `{flush}`");
        assert_only_the_kill_switch_stops(sources, &after);
        peer.assert_no_leak(base, &after);
    }

    // 4. The tunnel itself, and its addresses with it.
    sh(&format!("ip link del {WG}"));
    prompt(ih);
    thread::sleep(LEAK_WINDOW);
    let after = format!("after `ip link del {WG}`");
    assert_only_the_kill_switch_stops(&[HOST_V4, HOST_V6], &after);
    peer.assert_no_leak(base, &after);
    poll(
        "the VPN monitor to fence the profile",
        MONITOR_BOUND,
        || (listed_status() == "vpn_down").then_some(()),
    );
    let fenced = profile();
    assert!(
        fenced["paused_for_vpn"].as_u64().unwrap_or(0) >= 1,
        "the fence paused the torrent: {fenced}"
    );
    prompt(ih);
    thread::sleep(LEAK_WINDOW);
    assert_only_the_kill_switch_stops(&[HOST_V4, HOST_V6], "with the profile fenced");
    peer.assert_no_leak(base, "with the profile fenced");

    // The kill switch is removed on a clean stop, and the report says so —
    // the one run where `kill_switch_removal_failed` has a switch to remove.
    daemon.stop();
    let report = std::fs::read_to_string(p.join("last_shutdown.json")).expect("shutdown report");
    assert!(
        report.contains("\"kill_switch_removal_failed\":false"),
        "{report}"
    );
    assert!(!table_listed(), "the kill switch table is removed on stop");
    assert_fencing_held_through_the_drain(&daemon.log);
    assert_torn_down_in_order(&daemon.log);
    peer.assert_no_leak(base, "across the clean stop");
}

/// The line of the first entry in `text`, the daemon's log, that holds
/// `needle`; a panic naming `what`, with the log, where none does.
fn log_line(text: &str, what: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line for {what} in the daemon's log:\n{text}"))
}

/// The stop as `daemon.log` records it took the daemon off the network in
/// the order that leaks nothing: the sessions closed before the kill switch
/// was removed, so no session was left to send once nothing confined it.
///
/// The leak counter alone cannot see this order broken: a session's sockets
/// are bound to the tunnel's address, so while the tunnel stands they still
/// leave by it, and once it is gone they cannot send at all.
fn assert_torn_down_in_order(log: &std::path::Path) {
    let text = std::fs::read_to_string(log).expect("the daemon's log");
    let closed = log_line(&text, "the sessions closing", "sessions closed");
    let removed = log_line(
        &text,
        "the kill switch's removal",
        "network kill switch removed",
    );
    assert!(
        closed < removed,
        "the kill switch was removed at line {removed}, before the sessions closed at line \
         {closed}:\n{text}"
    );
}

/// The stop as `daemon.log` records it: the VPN monitor and the kill-switch
/// watch keep fencing through the shutdown's drain, which ends when the
/// alert loop exits, and stop only after it, before the sessions close.
///
/// Stopped on the shutdown broadcast instead, both would return as the
/// SIGTERM landed, and a tunnel lost or a ruleset flushed while the sessions
/// still seeded through the drain would go unfenced.
fn assert_fencing_held_through_the_drain(log: &std::path::Path) {
    let text = std::fs::read_to_string(log).expect("the daemon's log");
    let drained = log_line(&text, "the alert loop's exit", "alert loop exited");
    let closed = log_line(&text, "the sessions closing", "sessions closed");
    for (task, line) in [
        ("the VPN monitor", "vpn monitor shutting down"),
        ("the kill-switch watch", "kill switch watch stopping"),
    ] {
        let stopped = log_line(&text, &format!("{task}'s stop"), line);
        assert!(
            drained < stopped && stopped < closed,
            "{task} stopped at line {stopped}, not between the drain's end (line {drained}) \
             and the sessions closing (line {closed}):\n{text}"
        );
    }
}

/// A NAT-PMP gateway behind the tunnel, as a provider runs one.
///
/// Answers every mapping request for `port` with a 4 s lease, so the daemon
/// renews every 2 s; its epoch advances by one per answer, and `reboot` sets
/// it back to 1 once, as a gateway that restarted would.
struct Gateway {
    port: Arc<AtomicU16>,
    reboot: Arc<AtomicBool>,
}

impl Gateway {
    fn start(peer: &Peer, port: u16) -> Self {
        let gw = Self {
            port: Arc::new(AtomicU16::new(port)),
            reboot: Arc::new(AtomicBool::new(false)),
        };
        let (port, reboot) = (gw.port.clone(), gw.reboot.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        peer.spawn(move || {
            let sock = UdpSocket::bind((PEER_TUNNEL, 5351)).expect("bind the gateway");
            tx.send(()).unwrap();
            let mut epoch: u32 = 1000;
            let mut buf = [0u8; 64];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if n < 12 || buf[0] != 0 || !(1..=2).contains(&buf[1]) {
                    continue;
                }
                if reboot.swap(false, Ordering::SeqCst) {
                    epoch = 1;
                }
                epoch += 1;
                let delete = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) == 0;
                let (mapped, lease) = if delete {
                    (0, 0)
                } else {
                    (port.load(Ordering::SeqCst), 4u32)
                };
                let mut resp = vec![0, buf[1] | 0x80, 0, 0];
                resp.extend_from_slice(&epoch.to_be_bytes());
                resp.extend_from_slice(&buf[4..6]);
                resp.extend_from_slice(&mapped.to_be_bytes());
                resp.extend_from_slice(&lease.to_be_bytes());
                let _ = sock.send_to(&resp, from);
            }
        });
        rx.recv().unwrap();
        gw
    }
}

/// Whether a TCP connection from the peer namespace to `port` on the
/// tunnel address is accepted: through the tunnel, as a remote peer would
/// reach the session's listen socket.
fn reachable_through_tunnel(peer: &Peer, port: u16) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    peer.spawn(move || {
        let addr: SocketAddr = format!("{TUNNEL}:{port}").parse().unwrap();
        let _ = tx.send(TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok());
    });
    rx.recv().unwrap()
}

/// NAT-PMP against a gateway behind a real tunnel, under the kill switch:
/// the daemon negotiates port A at boot and listens there; the gateway moves
/// it to B, and the session follows, with `profile_forwarded_port` saying
/// so; the gateway's epoch then goes backwards, and the daemon counts one
/// gateway reboot and stays on B.
#[test]
#[ignore = "needs ip, wg, nft, unshare and nsenter, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_natpmp_follows_the_gateway() {
    if !in_own_namespace("vpn_netns_e2e_natpmp_follows_the_gateway") {
        return;
    }
    const PORT_A: u16 = 40001;
    const PORT_B: u16 = 40002;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let peer = topology(p);
    let base = peer.leaks();
    let gw = Gateway::start(&peer, PORT_A);

    let mut daemon = Daemon::start(
        p,
        &format!("port_forward = \"natpmp\"\nport_forward_gateway = \"{PEER_TUNNEL}\""),
    );
    let forwarded = format!("torrentd_profile_forwarded_port{{profile_id=\"{PROFILE}\"}}");
    let reboots = format!("torrentd_profile_vpn_gateway_reboots_total{{profile_id=\"{PROFILE}\"}}");

    poll(
        "the session to listen on port A",
        Duration::from_secs(30),
        || {
            (metric(&forwarded) == Some(f64::from(PORT_A))
                && reachable_through_tunnel(&peer, PORT_A))
            .then_some(())
        },
    );
    assert_eq!(profile()["forwarded_port"], PORT_A);

    gw.port.store(PORT_B, Ordering::SeqCst);
    poll(
        "the session to follow the gateway to port B",
        Duration::from_secs(30),
        || {
            (metric(&forwarded) == Some(f64::from(PORT_B))
                && reachable_through_tunnel(&peer, PORT_B))
            .then_some(())
        },
    );
    assert_eq!(profile()["forwarded_port"], PORT_B);
    poll("port A to be released", Duration::from_secs(10), || {
        (!reachable_through_tunnel(&peer, PORT_A)).then_some(())
    });
    assert_eq!(metric(&reboots), Some(0.0), "no reboot yet");

    gw.reboot.store(true, Ordering::SeqCst);
    poll(
        "the gateway reboot to be counted",
        Duration::from_secs(30),
        || (metric(&reboots) == Some(1.0)).then_some(()),
    );
    // Renewals after the reboot advance from the new epoch: one reboot.
    thread::sleep(Duration::from_secs(5));
    assert_eq!(metric(&reboots), Some(1.0), "counted once");
    assert_eq!(metric(&forwarded), Some(f64::from(PORT_B)));
    assert!(
        reachable_through_tunnel(&peer, PORT_B),
        "still listening on B"
    );

    peer.assert_no_leak(base, "across the NAT-PMP negotiation and its renewals");
    daemon.stop();
    assert!(!table_listed(), "the kill switch table is removed on stop");
    assert_torn_down_in_order(&daemon.log);
    peer.assert_no_leak(base, "across the clean stop");
}

/// `torrentd net-cleanup` on the config [`Daemon::start`] wrote in `dir`, as
/// the packaged unit's `ExecStopPost=` runs it, asserting it succeeds.
fn net_cleanup(dir: &std::path::Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(dir.join("cfg.toml"))
        .arg("net-cleanup")
        .output()
        .expect("run net-cleanup");
    assert!(
        out.status.success(),
        "net-cleanup exited {}:\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// The daemon, announcing through the tunnel under the kill switch, is
/// SIGKILLed, so none of its teardown runs:
///
/// 1. the kill switch, the tunnel and its routing rules all outlive it, and
///    the kill switch still refuses this uid the physical link;
/// 2. `torrentd net-cleanup` removes all three, as the packaged unit's
///    `ExecStopPost=` does after such an exit;
/// 3. the daemon restarts on the same state directory, raises the tunnel and
///    the kill switch again, loads the torrent back from what its add
///    persisted, and announces through the tunnel;
/// 4. a clean stop then takes it off the network in order.
///
/// Nothing reaches the physical link outside the tunnel at any point: with
/// the daemon dead, between the cleanup and the restart, while the restart
/// brings the tunnel and the kill switch up, or across the stop.
#[test]
#[ignore = "needs ip, wg, nft, unshare and nsenter, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_no_leak_across_a_crash_and_restart() {
    if !in_own_namespace("vpn_netns_e2e_no_leak_across_a_crash_and_restart") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let peer = topology(p);
    let base = peer.leaks();
    let announces = tracker(&peer);

    let listen = format!("listen_port = {LISTEN_PORT}");
    let mut daemon = Daemon::start(p, &listen);
    let (code, body) = add_magnet();
    assert_eq!(code, 201, "add the torrent: {body}");
    poll(
        "an announce through the tunnel",
        Duration::from_secs(30),
        || (tunnelled(&announces) > 0).then_some(()),
    );
    peer.assert_no_leak(base, "before the crash");

    // 1. Killed outright: everything it put on the network stays.
    daemon.crash();
    assert!(table_listed(), "a SIGKILL leaves the kill switch installed");
    assert!(tunnel_standing(), "a SIGKILL leaves the tunnel standing");
    assert!(
        !tunnel_rules().is_empty(),
        "a SIGKILL leaves the tunnel's routing rules"
    );
    assert_only_the_kill_switch_stops(&[HOST_V4, HOST_V6], "with the daemon killed");
    peer.assert_no_leak(base, "with the daemon killed");

    // 2. The cleanup a crash leaves to the unit's `ExecStopPost=`.
    net_cleanup(p);
    assert!(!table_listed(), "net-cleanup removes the kill switch table");
    assert!(!tunnel_standing(), "net-cleanup removes the tunnel");
    assert_eq!(
        tunnel_rules(),
        "",
        "net-cleanup removes the tunnel's routing rules"
    );
    peer.assert_no_leak(base, "after net-cleanup");

    // 3. The restart, on the same state directory. The boot loads the torrent
    //    back from what its add persisted before the API answers, so a
    //    reannounce, which needs a loaded torrent and not just the registry
    //    claim that outlived the kill, is accepted at once. `before` is read
    //    ahead of the start, so the reloaded torrent's first announce counts
    //    however soon it lands.
    let before = tunnelled(&announces);
    daemon = Daemon::start(p, &listen);
    assert!(table_listed(), "the restart installs the kill switch again");
    let (code, body) = http("POST", &format!("/v1/torrents/{IH}/reannounce"), None);
    assert_eq!(code, 202, "the restart loads the torrent back: {body}");
    poll(
        "an announce through the tunnel after the restart",
        Duration::from_secs(30),
        || (tunnelled(&announces) > before).then_some(()),
    );
    prompt(IH);
    thread::sleep(LEAK_WINDOW);
    assert_only_the_kill_switch_stops(&[HOST_V4, HOST_V6], "after the restart");
    peer.assert_no_leak(base, "across the restart");

    // 4. A clean stop.
    daemon.stop();
    assert!(!table_listed(), "the kill switch table is removed on stop");
    assert!(!tunnel_standing(), "the tunnel is removed on stop");
    assert_torn_down_in_order(&daemon.log);
    peer.assert_no_leak(base, "across the clean stop after the restart");
}

/// The container's privilege model: the daemon runs as a non-root uid with
/// `CAP_NET_ADMIN` from its binary's file capability alone, no ambient grant
/// from outside, and still raises its WireGuard link and installs its kill
/// switch, because it hands the capability to the `ip`, `wg` and `nft` it
/// runs. Without that hand-off each of them runs with nothing, and the
/// profile never comes up.
#[test]
#[ignore = "needs ip, wg, nft, unshare, nsenter and setcap, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_file_capability_alone_raises_the_tunnel_and_the_kill_switch() {
    let Some(bin) = in_file_capability_namespace(
        "vpn_netns_e2e_file_capability_alone_raises_the_tunnel_and_the_kill_switch",
    ) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let _peer = topology(p);

    let mut daemon = Daemon::start_from(&bin, p, &format!("listen_port = {LISTEN_PORT}"));
    let pid = daemon.child.id();
    let net_admin = 1u64 << 12;
    assert_eq!(
        cap_set(pid, "CapPrm:"),
        net_admin,
        "the daemon holds CAP_NET_ADMIN and nothing else, from the file"
    );
    assert_eq!(
        cap_set(pid, "CapAmb:"),
        0,
        "no ambient grant: the tools get it only through the daemon's own raise"
    );
    assert_eq!(metric("torrentd_kill_switch_active"), Some(1.0));
    assert!(table_listed(), "the kill switch table is installed");
    assert!(tunnel_standing(), "the daemon raised its WireGuard link");
    let log = std::fs::read_to_string(&daemon.log).unwrap();
    assert!(
        log.contains("came from the binary's file capability"),
        "the boot says how it holds the capability: {log}"
    );

    daemon.stop();
    assert!(!table_listed(), "the kill switch table is removed on stop");
    assert!(!tunnel_standing(), "the tunnel is removed on stop");
}

/// Without `CAP_NET_ADMIN` a vpn profile with the kill switch exits 78, the
/// status `RestartPreventExitStatus=78` and a container's restart policy read
/// as the configuration's, naming both ways to grant it, before anything is
/// raised.
#[test]
#[ignore = "needs ip, wg, nft, unshare and nsenter, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_without_the_capability_exits_78_naming_both_fixes() {
    if !in_own_namespace("vpn_netns_e2e_without_the_capability_exits_78_naming_both_fixes") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &format!("listen_port = {LISTEN_PORT}"));
    // The test holds every capability as ambient; the daemon is run with
    // none, as a pod without `add: [NET_ADMIN]` runs it.
    let out = Command::new("setpriv")
        .args(["--inh-caps=-all", "--ambient-caps=-all", "--"])
        .arg(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .output()
        .expect("run setpriv");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(78), "{text}");
    for needle in [
        "CAP_NET_ADMIN",
        "AmbientCapabilities=CAP_NET_ADMIN",
        "securityContext",
        "allowPrivilegeEscalation: true",
    ] {
        assert!(text.contains(needle), "{needle}: {text}");
    }
    assert!(!tunnel_standing(), "nothing was raised");
    assert!(!table_listed(), "nothing was installed");
}

/// An `nft` that is installed but whose `nft list tables` fails, as one
/// without the kernel's nf_tables does: `--check-config` refuses it with 78,
/// and the boot fails with 70 at the preflight, naming `nft_runs`, before it
/// raises the tunnel the topology is ready for. Without the preflight the
/// boot raised every tunnel and only then failed to install the kill switch.
#[test]
#[ignore = "needs ip, wg, nft, unshare and nsenter, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_a_kill_switch_whose_nft_does_not_run_is_refused_before_any_tunnel() {
    if !in_own_namespace(
        "vpn_netns_e2e_a_kill_switch_whose_nft_does_not_run_is_refused_before_any_tunnel",
    ) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let _peer = topology(p);
    let cfg = write_config(p, &format!("listen_port = {LISTEN_PORT}"));

    // First on the daemon's `PATH`: answers `--version`, so `nft` counts as
    // installed, and fails everything else.
    let fake = p.join("fake-nft");
    std::fs::create_dir_all(&fake).unwrap();
    let nft = fake.join("nft");
    std::fs::write(
        &nft,
        "#!/bin/sh\n\
         [ \"$1\" = --version ] && { echo 'nftables v1.0.9'; exit 0; }\n\
         echo 'netlink: Error: cache initialization failed: Operation not supported' >&2\n\
         exit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&nft, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        fake.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    for (check, code) in [(true, 78), (false, 70)] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_torrentd"));
        cmd.arg("--config").arg(&cfg).env("PATH", &path);
        if check {
            cmd.arg("--check-config");
        }
        let out = cmd.output().expect("run the daemon");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.status.code(),
            Some(code),
            "--check-config: {check}; {text}"
        );
        for needle in ["preflight nft_runs", "Operation not supported"] {
            assert!(
                text.contains(needle),
                "--check-config: {check}; {needle}: {text}"
            );
        }
        assert!(
            !tunnel_standing(),
            "--check-config: {check}; no tunnel was raised"
        );
        assert!(
            !table_listed(),
            "--check-config: {check}; nothing was installed"
        );
    }
}

/// The scrape credential the cluster test's `[auth]` holds, shaped as
/// `new-token` prints one.
const METRICS_TOKEN: &str = "tdp_e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0";
/// A second physical link, which no carve-out names.
const OTHER_HOST_V4: &str = "10.10.0.1";
const OTHER_PEER_V4: &str = "10.10.0.2";
/// An address on the peer's side of the physical link that is no resolver
/// the config names, though it answers on port 53.
const UNNAMED_RESOLVER: &str = "10.9.0.3";

/// `f`'s result, run on a thread of its own inside the peer namespace.
fn in_peer<T: Send + 'static>(peer: &Peer, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    peer.spawn(move || tx.send(f()).unwrap());
    rx.recv().unwrap()
}

/// Answer every UDP datagram to port `port` on any address of the peer
/// namespace with its own bytes, and every TCP connection to it with `ok`.
fn resolver(peer: &Peer, port: u16) {
    let (tx, rx) = std::sync::mpsc::channel();
    peer.spawn(move || {
        let sock = UdpSocket::bind(("0.0.0.0", port));
        tx.send(sock.as_ref().map(|_| ()).map_err(|e| e.to_string()))
            .unwrap();
        let Ok(sock) = sock else { return };
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&buf[..n], from);
        }
    });
    rx.recv()
        .unwrap()
        .unwrap_or_else(|e| panic!("bind udp {port} in the peer namespace: {e}"));
    peer.serve_tcp(SocketAddr::from(([0, 0, 0, 0], port)), |mut conn| {
        let _ = conn.write_all(b"ok");
    });
}

/// Whether this uid's datagram to `to` is answered within two seconds.
fn udp_answered(to: &str) -> bool {
    let sock = UdpSocket::bind((HOST_V4, 0)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let _ = sock.send_to(b"q", to);
    let mut buf = [0u8; 8];
    sock.recv_from(&mut buf).is_ok()
}

/// Whether this uid's TCP connection to `to` is answered with `ok` within
/// two seconds. The kernel answers a SYN with no socket of the uid's
/// attached, so only the bytes after it say whether the uid's own packets
/// leave.
fn tcp_answered(to: &str) -> bool {
    let Ok(mut conn) = TcpStream::connect_timeout(&to.parse().unwrap(), Duration::from_secs(2))
    else {
        return false;
    };
    conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 2];
    conn.read_exact(&mut buf).is_ok() && &buf == b"ok"
}

/// The kill switch's carve-outs for a cluster, in a real kernel: with
/// `kill_switch_api_interfaces = ["veth-ks"]` and `kill_switch_dns_servers`
/// naming the peer's address,
///
/// (a) a probe of `/healthz` and a scrape of `/metrics` from outside the
///     daemon's namespace, on `veth-ks`, are answered, and both report the
///     DNS carve-out;
/// (b) this uid's DNS to the named resolver is answered, over UDP and TCP;
/// (c) every other egress of the uid outside the tunnel is still dropped:
///     the API's replies on an interface no carve-out names, port 53 to an
///     address the config does not name, another port to the named
///     resolver, and any other datagram, none of which reach the physical
///     link.
#[test]
#[ignore = "needs ip, wg, nft, unshare and nsenter, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_cluster_carve_outs_let_out_the_api_and_dns_and_nothing_else() {
    if !in_own_namespace(
        "vpn_netns_e2e_cluster_carve_outs_let_out_the_api_and_dns_and_nothing_else",
    ) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let peer = topology(p);
    sh(&format!(
        "ip link add veth-ks2 type veth peer name veth-peer2 netns {} && \
         ip addr add {OTHER_HOST_V4}/24 dev veth-ks2 && ip link set veth-ks2 up",
        peer.pid
    ));
    peer.sh(&format!(
        "ip addr add {OTHER_PEER_V4}/24 dev veth-peer2; ip link set veth-peer2 up; \
         ip addr add {UNNAMED_RESOLVER}/24 dev veth-peer"
    ));
    resolver(&peer, 53);
    resolver(&peer, 5353);

    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        METRICS_TOKEN.as_bytes(),
    ));
    // A routable bind takes `[auth]`; no test logs in, so any password does.
    let password_hash = argon2::PasswordHasher::hash_password(
        &argon2::Argon2::default(),
        b"unused",
        &argon2::password_hash::SaltString::from_b64("dnBuLW5ldG5zLWUyZQ").unwrap(),
    )
    .unwrap()
    .to_string();
    let top = format!(
        "http_listen = \"0.0.0.0:8080\"\n\
         kill_switch_api_interfaces = [\"veth-ks\"]\n\
         kill_switch_dns_servers = [\"{PEER_V4}\"]\n\
         [auth]\n\
         password_hash = \"{password_hash}\"\n\
         [[auth.token]]\n\
         name = \"scrape\"\n\
         sha256 = \"{sha}\"\n\
         scopes = [\"metrics\"]"
    );
    let cfg = write_config_top(p, &top, &format!("listen_port = {LISTEN_PORT}"));
    let mut daemon = Daemon::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_torrentd")),
        p,
        &cfg,
    );
    poll(
        "the daemon to report ready",
        Duration::from_secs(60),
        || {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                panic!("the daemon exited {status} before it was ready");
            }
            let (code, _) = try_http("GET", "/healthz", None).ok()?;
            (code == 200).then_some(())
        },
    );
    assert!(table_listed(), "the kill switch table is installed");
    let log = std::fs::read_to_string(&daemon.log).unwrap();
    assert!(
        log.contains("tracker hostname") && log.contains(PEER_V4),
        "the boot warns, naming the resolver: {log}"
    );

    // (a) From the peer, over veth-ks: the probe and the scrape.
    let api = format!("{HOST_V4}:8080");
    let auth = format!("Authorization: Bearer {METRICS_TOKEN}\r\n");
    let (health, metrics) = in_peer(&peer, move || {
        let wait = Duration::from_secs(10);
        (
            try_http_at(&api, "GET", "/healthz", None, "", wait),
            try_http_at(&api, "GET", "/metrics", None, &auth, wait),
        )
    });
    let (code, body) = health.expect("the probe is answered over veth-ks");
    assert_eq!(code, 200, "{body}");
    let report: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(report["kill_switch_dns_exempt"], true, "{body}");
    let (code, text) = metrics.expect("the scrape is answered over veth-ks");
    assert_eq!(code, 200, "{text}");
    assert!(
        text.lines()
            .any(|l| l.trim() == "torrentd_kill_switch_dns_exempt 1"),
        "{text}"
    );

    // (c) The API's reply on veth-ks2, which no carve-out names: the
    // connection opens, as the kernel answers the SYN, and the reply from
    // the daemon's socket never leaves.
    let other = format!("{OTHER_HOST_V4}:8080");
    let unnamed = in_peer(&peer, move || {
        try_http_at(&other, "GET", "/healthz", None, "", Duration::from_secs(3))
    });
    assert!(
        unnamed.as_ref().map_or(true, |(code, _)| *code == 0),
        "the API answered on an interface no carve-out names: {unnamed:?}"
    );

    // (b) This uid's DNS to the named resolver, both protocols.
    assert!(
        udp_answered(&format!("{PEER_V4}:53")),
        "DNS over UDP to the named resolver"
    );
    assert!(
        tcp_answered(&format!("{PEER_V4}:53")),
        "DNS over TCP to the named resolver"
    );

    // (c) Everything else the uid sends outside the tunnel: dropped before
    // the physical link, so the peer counts none of it.
    let base = peer.leaks();
    for to in [
        format!("{UNNAMED_RESOLVER}:53"),
        format!("{PEER_V4}:5353"),
        format!("{PEER_V4}:9"),
    ] {
        assert!(!udp_answered(&to), "udp to {to} left by the physical link");
    }
    for to in [format!("{UNNAMED_RESOLVER}:53"), format!("{PEER_V4}:5353")] {
        assert!(!tcp_answered(&to), "tcp to {to} left by the physical link");
    }
    peer.assert_no_leak(base, "the uid's other egress under the carve-outs");

    daemon.stop();
    assert!(!table_listed(), "the kill switch table is removed on stop");
}

/// The UDP port the tunnel-DNS test's UDP tracker answers on.
const UDP_TRACKER_PORT: u16 = 6970;

/// A DNS server in the peer namespace on `bind`:53, answering
/// [`TRACKER_NAME`]'s A question with [`PEER_TUNNEL`] and every other
/// question with no address; the source of each question it was asked.
fn tunnel_dns(peer: &Peer, bind: &str) -> Arc<Mutex<Vec<SocketAddr>>> {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let recorded = asked.clone();
    let bind: SocketAddr = format!("{bind}:53").parse().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    peer.spawn(move || {
        let sock = UdpSocket::bind(bind);
        tx.send(sock.as_ref().map(|_| ()).map_err(|e| e.to_string()))
            .unwrap();
        let Ok(sock) = sock else { return };
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            recorded.lock().unwrap().push(from);
            let q = &buf[..n];
            let Some(end) = q.iter().skip(12).position(|b| *b == 0).map(|i| i + 13) else {
                continue;
            };
            let Some(qtail) = q.get(end..end + 4) else {
                continue;
            };
            let mut name = Vec::new();
            let mut at = 12;
            while at < end - 1 {
                let len = usize::from(q[at]);
                name.push(String::from_utf8_lossy(&q[at + 1..at + 1 + len]).to_string());
                at += 1 + len;
            }
            let found = name.join(".").eq_ignore_ascii_case(TRACKER_NAME) && qtail[..2] == [0, 1];
            let mut out = q[..2].to_vec();
            out.extend_from_slice(&[0x81, 0x80, 0, 1, 0, u8::from(found), 0, 0, 0, 0]);
            out.extend_from_slice(&q[12..end + 4]);
            if found {
                out.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                out.extend_from_slice(&PEER_TUNNEL.parse::<std::net::Ipv4Addr>().unwrap().octets());
            }
            let _ = sock.send_to(&out, from);
        }
    });
    rx.recv()
        .unwrap()
        .unwrap_or_else(|e| panic!("bind {bind} in the peer namespace: {e}"));
    asked
}

/// A UDP tracker (BEP 15) in the peer namespace on [`PEER_TUNNEL`]: it
/// answers every connect and every announce, the latter with no peers; the
/// source of each announce.
fn udp_tracker(peer: &Peer) -> Arc<Mutex<Vec<SocketAddr>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    let bind: SocketAddr = format!("{PEER_TUNNEL}:{UDP_TRACKER_PORT}").parse().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    peer.spawn(move || {
        let sock = UdpSocket::bind(bind);
        tx.send(sock.as_ref().map(|_| ()).map_err(|e| e.to_string()))
            .unwrap();
        let Ok(sock) = sock else { return };
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if n < 16 {
                continue;
            }
            let action = &buf[8..12];
            let tid = &buf[12..16];
            let mut out = Vec::new();
            if action == [0, 0, 0, 0] {
                out.extend_from_slice(&[0, 0, 0, 0]);
                out.extend_from_slice(tid);
                out.extend_from_slice(&0x0e2e_0e2e_0e2e_0e2e_u64.to_be_bytes());
            } else if action == [0, 0, 0, 1] && n >= 98 {
                recorded.lock().unwrap().push(from);
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(tid);
                // interval, leechers, seeders; no peers.
                out.extend_from_slice(&[0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0]);
            } else {
                continue;
            }
            let _ = sock.send_to(&out, from);
        }
    });
    rx.recv()
        .unwrap()
        .unwrap_or_else(|e| panic!("bind udp {bind} in the peer namespace: {e}"));
    seen
}

/// Add a magnet for `ih` announcing to `tracker` alone.
fn add_magnet_to(ih: &str, tracker: &str) -> (u16, String) {
    let tracker: String = tracker
        .bytes()
        .map(|b| match b {
            b':' => "%3A".to_string(),
            b'/' => "%2F".to_string(),
            _ => char::from(b).to_string(),
        })
        .collect();
    let magnet = format!("magnet:?xt=urn:btih:{ih}&dn=e2e&tr={tracker}");
    http(
        "POST",
        "/v1/torrents",
        Some(&format!(
            "{{\"profile_id\":\"{PROFILE}\",\"source\":{{\"kind\":\"magnet\",\"uri\":\"{magnet}\"}}}}"
        )),
    )
}

/// `tracker_dns = "tunnel"` under the kill switch with no
/// `kill_switch_dns_servers`: the profile's trackers are named by a hostname
/// only the resolver inside the tunnel (the WireGuard config's `DNS =`)
/// knows, and the host's own resolver is on the physical link, where it
/// answers too. Both the HTTP and the UDP tracker are announced to through
/// the tunnel, the tunnel's resolver is asked from the tunnel address, the
/// host's resolver is asked nothing, and no packet, port 53 or other,
/// reaches the physical link outside the tunnel.
#[test]
#[ignore = "needs ip, wg, nft, unshare and nsenter, and user namespaces; run by mise run test-netns"]
fn vpn_netns_e2e_tracker_hostnames_resolve_through_the_tunnel() {
    if !in_own_namespace("vpn_netns_e2e_tracker_hostnames_resolve_through_the_tunnel") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let peer = topology(p);
    // The provider's resolver, inside the tunnel, named by the config.
    let config = std::fs::read_to_string(wg_config()).unwrap();
    std::fs::write(
        wg_config(),
        config.replacen("[Peer]", &format!("DNS = {PEER_TUNNEL}\n\n[Peer]"), 1),
    )
    .unwrap();
    // The host's resolver, on the physical link: what libc would ask.
    std::fs::write(p.join("resolv.conf"), format!("nameserver {PEER_V4}\n")).unwrap();
    sh(&format!(
        "mount --bind {} /etc/resolv.conf",
        p.join("resolv.conf").display()
    ));
    let in_tunnel = tunnel_dns(&peer, PEER_TUNNEL);
    let on_host = tunnel_dns(&peer, PEER_V4);
    let announces = tracker(&peer);
    let udp_announces = udp_tracker(&peer);
    let base = peer.leaks();

    let mut daemon = Daemon::start(
        p,
        &format!("listen_port = {LISTEN_PORT}\ntracker_dns = \"tunnel\""),
    );
    assert_eq!(metric("torrentd_kill_switch_active"), Some(1.0));

    let (code, body) = add_magnet_to(
        IH,
        &format!("http://{TRACKER_NAME}:{TRACKER_PORT}/announce"),
    );
    assert_eq!(code, 201, "add the torrent: {body}");
    let udp_ih = "5e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e";
    let (code, body) = add_magnet_to(udp_ih, &format!("udp://{TRACKER_NAME}:{UDP_TRACKER_PORT}"));
    assert_eq!(code, 201, "add the torrent: {body}");

    poll(
        "an HTTP announce to the tracker by name, through the tunnel",
        Duration::from_secs(30),
        || (tunnelled(&announces) > 0).then_some(()),
    );
    poll(
        "a UDP announce to the tracker by name, through the tunnel",
        Duration::from_secs(30),
        || (tunnelled(&udp_announces) > 0).then_some(()),
    );
    let asked = in_tunnel.lock().unwrap().clone();
    assert!(!asked.is_empty(), "the tunnel's resolver was asked");
    assert!(
        asked.iter().all(|a| a.ip().to_string() == TUNNEL),
        "every question came from the tunnel address: {asked:?}"
    );
    assert!(
        on_host.lock().unwrap().is_empty(),
        "the host's resolver was asked nothing"
    );
    peer.assert_no_leak(base, "resolving and announcing through the tunnel");

    daemon.stop();
    peer.assert_no_leak(base, "across the clean stop");
}
