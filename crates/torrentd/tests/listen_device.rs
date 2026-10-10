//! A vpn session's listen sockets are held to the tunnel device, even where a
//! LAN's network covers the tunnel address (#165).
//!
//! libtorrent binds a listen endpoint named by address to the first interface
//! whose network contains it. A `10.0.0.0/8` LAN beside Proton's
//! `10.2.0.2/32` comes first, the listen sockets are held to the LAN, and
//! their uTP and tracker traffic leaves there with the tunnel's address. The
//! daemon now names the tunnel device (`torrentd_engine::bind_endpoint`).
//!
//! The test builds that host in a network namespace of its own: a dummy
//! `lan0` holding `10.0.0.5/8`, then a dummy `wg0` holding `10.2.0.2/32`,
//! created second as a tunnel is. It re-runs itself under
//! `unshare --user --map-root-user --net`, so it needs no privilege, only a
//! kernel that lets an unprivileged user create user namespaces, and `ip`.
//! Where either is missing it says so and passes without having run.

use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

use torrentd_engine::handlers::listen::sockets_at;
use torrentd_engine::handlers::listen::BoundSocket;

/// Set in the re-run that is inside the namespace.
const IN_NAMESPACE: &str = "TORRENTD_TEST_LISTEN_DEVICE_NETNS";
const TEST: &str = "a_vpn_session_listens_on_the_tunnel_device_where_a_lan_covers_its_address";

#[test]
fn a_vpn_session_listens_on_the_tunnel_device_where_a_lan_covers_its_address() {
    if std::env::var_os(IN_NAMESPACE).is_some() {
        in_namespace();
        return;
    }
    let probe = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--net",
            "--",
            "ip",
            "link",
            "show",
            "lo",
        ])
        .output();
    match probe {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            eprintln!(
                "skipped: cannot create a network namespace here: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return;
        }
        Err(e) => {
            eprintln!("skipped: cannot run unshare: {e}");
            return;
        }
    }
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(IN_NAMESPACE, "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the run inside the namespace failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn dummy(name: &str, cidr: &str) {
    ip(&["link", "add", name, "type", "dummy"]);
    ip(&["address", "add", cidr, "dev", name]);
    ip(&["link", "set", name, "up"]);
}

/// A session configured as a vpn profile's is, but listening on `listen`.
fn session(listen: String) -> libtorrent_safe::Session {
    libtorrent_safe::Session::new(&libtorrent_safe::Settings {
        listen_interfaces: Some(listen),
        outgoing_interfaces: Some("wg0".into()),
        enable_dht: Some(false),
        enable_lsd: Some(false),
        enable_upnp: Some(false),
        enable_natpmp: Some(false),
        ..Default::default()
    })
    .expect("session")
}

/// This process's sockets on `at`, once both the TCP listener and the UDP
/// socket are up.
fn listen_sockets(at: SocketAddr) -> Vec<BoundSocket> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let found = sockets_at(at).unwrap();
        let has = |kind| found.iter().any(|s| s.kind == kind);
        if has("tcp") && has("udp") {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "no TCP and UDP listen sockets on {at} within 10s: {found:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn in_namespace() {
    dummy("lan0", "10.0.0.5/8");
    dummy("wg0", "10.2.0.2/32");

    // As the daemon binds a vpn session now: by the tunnel device.
    let fixed = session(torrentd_engine::bind_endpoint("wg0", 6881));
    let sockets = listen_sockets("10.2.0.2:6881".parse().unwrap());
    assert!(
        sockets.iter().all(|s| s.device.as_deref() == Some("wg0")),
        "every listen socket on the tunnel address is held to wg0: {sockets:?}"
    );

    // As it used to: by the address, which this host gives to the LAN. Shown
    // so the fixture is known to reproduce the fault, and the check to see it.
    let by_address = session("10.2.0.2:6882".into());
    let sockets = listen_sockets("10.2.0.2:6882".parse().unwrap());
    assert!(
        sockets.iter().all(|s| s.device.as_deref() == Some("lan0")),
        "an address-named endpoint is held to the LAN that covers it: {sockets:?}"
    );

    drop((fixed, by_address));
}
