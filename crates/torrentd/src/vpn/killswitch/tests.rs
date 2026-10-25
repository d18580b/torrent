use super::*;

/// The table every test install, for uid 998, owns.
const TABLE: &str = "torrentd_ks_998";

/// An abstract socket name no other test, and no daemon, binds.
fn lock_name(test: &str) -> String {
    format!("torrentd_ks_test_{}_{test}", std::process::id())
}

/// A second holder is refused while the first lives, with the
/// `AddrInUse` kind boot reads as the configuration's refusal and a
/// message naming this process as the holder; once the first is
/// dropped the name is free again.
#[test]
fn a_second_table_lock_refuses_and_names_the_holder() {
    let name = lock_name("second");
    let first = TableLock::acquire_named(&name).expect("first lock");
    let err = TableLock::acquire_named(&name).expect_err("second lock must refuse");
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    let msg = err.to_string();
    assert!(
        msg.contains(&format!("(pid {})", std::process::id())),
        "the refusal names the holder's pid: {msg}"
    );
    assert!(
        msg.contains(&format!("@{name}")) && msg.contains(&format!("inet {name}")),
        "the refusal names the socket and the table: {msg}"
    );
    drop(first);
    TableLock::acquire_named(&name).expect("the lock is free once the holder is gone");
}

/// The lock is on the table's own name, so a lock on another uid's
/// table does not stand in the way: separate uids are the supported
/// layout.
#[test]
fn another_uids_table_lock_does_not_refuse() {
    let a = lock_name("uid_a");
    let b = lock_name("uid_b");
    let _a = TableLock::acquire_named(&a).expect("one uid's lock");
    TableLock::acquire_named(&b).expect("another uid's lock is not refused");
    assert_eq!(table_name(1000), "torrentd_ks_1000");
}

/// The table an operator is told to delete is this process's own.
#[test]
fn the_own_table_is_this_uids() {
    assert_eq!(own_table_name(), table_name(current_uid().unwrap()));
}

/// The uid the ruleset confines is this process's effective one, as the
/// kernel reports it.
#[test]
fn the_current_uid_is_the_effective_uid() {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    assert_eq!(current_uid().unwrap(), unsafe { libc::geteuid() });
}

/// `--check-config` reports nftables usable exactly when `nft --version`
/// runs and exits zero on this host.
#[test]
fn nft_is_available_exactly_when_it_runs() {
    let runs = std::process::Command::new("nft")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    assert_eq!(nft_available(), runs);
}

/// A link that does not exist has no listen port to exempt, whether `wg`
/// is installed or not.
#[test]
fn a_link_that_does_not_exist_has_no_listen_port() {
    listen_port("tdks-nolink0").expect_err("no such link");
}

/// Set in the process [`a_bind_failure_without_a_holder_is_no_refusal`]
/// starts, the only one in which its half that exhausts descriptors runs.
const EXHAUST_DESCRIPTORS: &str = "TORRENTD_TEST_KS_EXHAUST_DESCRIPTORS";

/// A bind that fails for want of a descriptor keeps its own kind, and says
/// what failed, instead of reading as another process holding the lock.
/// The descriptor limit is shared by every test in the binary, so the half
/// that exhausts it runs in a process of its own: this test binary again,
/// filtered to that one test.
#[test]
fn a_bind_failure_without_a_holder_is_no_refusal() {
    let name = "vpn::killswitch::tests::bind_without_a_descriptor";
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            name,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(EXHAUST_DESCRIPTORS, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the filter ran no test: {stdout}"
    );
}

#[test]
#[ignore = "run by a_bind_failure_without_a_holder_is_no_refusal"]
fn bind_without_a_descriptor() {
    if std::env::var_os(EXHAUST_DESCRIPTORS).is_none() {
        return;
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit`.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) },
        0
    );
    // No descriptor above those already open.
    let lowered = libc::rlimit {
        rlim_cur: 0,
        rlim_max: limit.rlim_max,
    };
    // SAFETY: `lowered` is a valid `rlimit` no higher than the hard limit.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) },
        0
    );
    let lock = TableLock::acquire_named(&lock_name("emfile"));
    // SAFETY: `limit` is the `rlimit` read above.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) },
        0
    );
    let err = lock.expect_err("no descriptor is left for the socket");
    assert_ne!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
    assert!(
        err.to_string()
            .starts_with("bind the abstract unix socket @"),
        "{err}"
    );
}

/// `/proc/net/unix`'s abstract entries are found by their exact name and
/// no other: a longer name sharing the prefix is not the socket.
#[test]
fn the_holders_inode_is_read_from_proc_net_unix() {
    let table = "Num       RefCount Protocol Flags    Type St Inode Path\n\
                     0000000000000000: 00000002 00000000 00000000 0002 01 4242 @torrentd_ks_10000\n\
                     0000000000000000: 00000002 00000000 00000000 0002 01 777 @torrentd_ks_1000\n\
                     0000000000000000: 00000002 00000000 00010000 0001 01 99\n";
    assert_eq!(unix_socket_inode(table, "torrentd_ks_1000"), Some(777));
    assert_eq!(unix_socket_inode(table, "torrentd_ks_100"), None);
}

const ADDR_A: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 2);
const ADDR_B: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 7);

/// The address scripted for each test tunnel: `wg-a` holds `ADDR_A`,
/// every other link `ADDR_B`.
fn addr_of(iface: &str) -> io::Result<Ipv4Addr> {
    Ok(if iface == "wg-a" { ADDR_A } else { ADDR_B })
}

fn tunnel(iface: &str) -> Tunnel {
    Tunnel::new(iface, addr_of(iface).unwrap())
}

/// A link with no IPv6 address, which is most of them.
fn no_v6(_: &str) -> Vec<Ipv6Addr> {
    Vec::new()
}

/// The IPv6 address scripted for `wg-a` where a test gives it one.
const ADDR_A6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

/// The provider endpoint every test tunnel's peer has.
const ENDPOINT: &str = "198.51.100.1:51820";

/// A transport on `port` to [`ENDPOINT`].
fn transport_on(port: u16) -> Transport {
    Transport::new(port, [ENDPOINT.parse().unwrap()])
}

/// One packet leaving the host, as the output hook sees it.
#[derive(Clone, Copy)]
struct Packet<'a> {
    /// The socket owner's uid, `None` for one the kernel built with no
    /// socket attached: a reset, an ICMP error.
    uid: Option<u32>,
    saddr: IpAddr,
    oif: &'a str,
    /// `(sport, daddr, dport)` for a UDP packet.
    udp: Option<(u16, std::net::IpAddr, u16)>,
}

fn pkt(uid: u32, saddr: impl Into<IpAddr>, oif: &str) -> Packet<'_> {
    Packet {
        uid: Some(uid),
        saddr: saddr.into(),
        oif,
        udp: None,
    }
}

impl<'a> Packet<'a> {
    fn udp(mut self, sport: u16, to: &str) -> Self {
        let to: SocketAddr = to.parse().unwrap();
        self.udp = Some((sport, to.ip(), to.port()));
        self
    }
    fn kernel(mut self) -> Self {
        self.uid = None;
        self
    }
}

/// What the rendered chain does with one packet, read the way nftables
/// reads it: the first rule whose every match holds decides, and a packet
/// no rule decides takes the chain's `accept` policy.
///
/// Reads only the shapes this module renders — `meta skuid`,
/// `ip saddr`/`ip6 saddr`, `ip daddr`/`ip6 daddr`, `oifname` (one name or
/// a set, `!=` a set), `udp sport`/`udp dport` (a set or one value) — and
/// panics on anything else, so a new kind of match cannot be silently
/// ignored here. An `ip` match holds only for an IPv4 packet and an
/// `ip6` one only for an IPv6 packet, as in an `inet` table.
fn verdict(ruleset: &str, p: Packet<'_>) -> &'static str {
    const MATCHES: [&str; 8] = [
        "meta skuid ",
        "ip saddr ",
        "ip6 saddr ",
        "ip daddr ",
        "ip6 daddr ",
        "oifname ",
        "udp sport ",
        "udp dport ",
    ];
    for line in ruleset.lines().map(str::trim) {
        if !(line.starts_with("meta skuid ")
            || line.starts_with("ip saddr ")
            || line.starts_with("ip6 saddr "))
        {
            continue;
        }
        let (mut rest, verdict) = if let Some(m) = line.strip_suffix(" accept") {
            (m, "accept")
        } else if let Some(m) = line.strip_suffix(" counter drop") {
            (m, "drop")
        } else if let Some(m) = line.strip_suffix(" drop") {
            (m, "drop")
        } else {
            panic!("unread verdict in {line:?}");
        };
        let mut holds = true;
        while !rest.is_empty() {
            let (key, r) = MATCHES
                .iter()
                .find_map(|k| rest.strip_prefix(k).map(|r| (*k, r)))
                .unwrap_or_else(|| panic!("unread match {rest:?} in {line:?}"));
            let (negated, r) = match r.strip_prefix("!= ") {
                Some(r) => (true, r),
                None => (false, r),
            };
            let end = if r.starts_with('{') {
                r.find('}').expect("a closed set") + 1
            } else {
                r.find(' ').unwrap_or(r.len())
            };
            let values: Vec<&str> = r[..end]
                .trim_matches(['{', '}', ' '])
                .split(", ")
                .map(|v| v.trim_matches('"'))
                .collect();
            let field = match key {
                "meta skuid " => p.uid.map(|u| u.to_string()),
                "ip saddr " => Some(p.saddr).filter(IpAddr::is_ipv4).map(|a| a.to_string()),
                "ip6 saddr " => Some(p.saddr).filter(IpAddr::is_ipv6).map(|a| a.to_string()),
                "oifname " => Some(p.oif.to_string()),
                "udp sport " => p.udp.map(|(s, ..)| s.to_string()),
                "udp dport " => p.udp.map(|(.., d)| d.to_string()),
                "ip daddr " => p
                    .udp
                    .filter(|(_, a, _)| a.is_ipv4())
                    .map(|(_, a, _)| a.to_string()),
                _ => p
                    .udp
                    .filter(|(_, a, _)| a.is_ipv6())
                    .map(|(_, a, _)| a.to_string()),
            };
            holds &= field.is_some_and(|f| values.contains(&f.as_str()) != negated);
            rest = r[end..].trim_start();
        }
        if holds {
            return verdict;
        }
    }
    "accept"
}

#[test]
fn enable_refuses_to_install_a_ruleset_as_root() {
    let called = std::cell::Cell::new(false);
    let e = enable_for_uid(
        0,
        &["wg-a".to_string()],
        addr_of,
        no_v6,
        |_| Ok(transport_on(51820)),
        |_| {
            called.set(true);
            Ok(())
        },
    )
    .expect_err("uid 0 must be refused");
    assert!(
        e.to_string().contains("non-root user"),
        "the refusal has to say what to do instead; got {e}",
    );
    assert!(
        is_uid_refusal(&e),
        "boot tells this refusal apart from an nft failure by it"
    );
    assert!(!is_uid_refusal(&io::Error::other("nft: permission denied")));
    assert!(
        !called.get(),
        "the refusal comes before anything is handed to nft — so a refused \
             enable cannot disarm a kill switch a previous run installed either",
    );
}

/// The success path, driven through `enable_for_uid`'s real control flow:
/// exactly one `nft` call, carrying the replace and the new table in one
/// transaction.
///
/// At a9eb5a1 this was two calls — a `disable` and then the load — with no
/// kill switch in force between them, and none at all for the rest of the
/// run if the load then failed. Split the install into a delete and a load
/// again and the call count fails.
#[test]
fn enable_replaces_the_stale_table_and_installs_the_new_one_in_one_transaction() {
    let calls = std::cell::RefCell::new(Vec::<String>::new());
    let uid = enable_for_uid(
        998,
        &["wg-b".to_string(), "wg-a".to_string()],
        addr_of,
        no_v6,
        |iface| {
            Ok(if iface == "wg-a" {
                transport_on(51820)
            } else {
                Transport::new(40001, ["[2001:db8::7]:4500".parse().unwrap()])
            })
        },
        |script| {
            calls.borrow_mut().push(script.to_string());
            Ok(())
        },
    )
    .expect("the supported shape — User=torrentd with CAP_NET_ADMIN — is not refused")
    .uid;

    assert_eq!(uid, 998, "the uid the ruleset was written for is returned");
    let calls = calls.borrow();
    assert_eq!(calls.len(), 1, "one transaction; got {calls:?}");
    let expected = "\
add table inet torrentd_ks_998
delete table inet torrentd_ks_998
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\" } drop
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg-b\" } drop
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
\t\tmeta skuid 998 ip6 daddr 2001:db8::7 udp sport 40001 udp dport 4500 accept
\t\tmeta skuid 998 ip daddr 198.51.100.1 udp sport 51820 udp dport 51820 accept
\t\tmeta skuid 998 counter drop
\t}
}
";
    assert_eq!(
        calls[0], expected,
        "the stale table is replaced and this uid's ruleset, over these \
             tunnels with each one's listen port exempted, loaded — together",
    );
}

/// A tunnel whose listen port will not read stops the install before
/// anything reaches nft: installing without its exemption would silence
/// that tunnel, and the previous run's switch stays armed.
#[test]
fn a_transport_port_that_will_not_read_stops_the_install_before_nft() {
    let applied = std::cell::Cell::new(false);
    let e = enable_for_uid(
        998,
        &["wg-a".to_string()],
        addr_of,
        no_v6,
        |_| Err(io::Error::other("wg show wg-a listen-port exited 1")),
        |_| {
            applied.set(true);
            Ok(())
        },
    )
    .expect_err("a port that will not read is not an absent exemption");
    assert!(e.to_string().contains("listen-port"), "got {e}");
    assert!(!applied.get(), "nothing is handed to nft");
}

/// A tunnel whose address will not read stops the install the same way:
/// with no address to pair its interface with, the ruleset could only
/// silence it, or accept its interface for every address — the shared
/// accept this pairing replaced.
#[test]
fn a_tunnel_address_that_will_not_read_stops_the_install_before_nft() {
    let applied = std::cell::Cell::new(false);
    let e = enable_for_uid(
        998,
        &["wg-a".to_string(), "wg-b".to_string()],
        |iface| {
            if iface == "wg-b" {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no IPv4 address on wg-b",
                ))
            } else {
                addr_of(iface)
            }
        },
        no_v6,
        |_| Ok(transport_on(51820)),
        |_| {
            applied.set(true);
            Ok(())
        },
    )
    .expect_err("a tunnel with no address is not installed unpaired");
    assert!(
        e.to_string().contains("wg-b") && e.to_string().contains("tunnel address"),
        "got {e}"
    );
    assert!(!applied.get(), "nothing is handed to nft");
}

/// The scenario in #101: profile A's per-source rule is lost, so a packet
/// from A's tunnel address routes out of B's tunnel. Each profile's
/// address is accepted on its own interface only, so that packet matches
/// no accept and the drop takes it — where the shared
/// `oifname { "wg-a", "wg-b" }` accept let it out with B's exit address.
#[test]
fn a_profiles_address_on_another_profiles_tunnel_falls_through_to_the_drop() {
    let rs = render_ruleset_with_transport(
        998,
        &[tunnel("wg-a"), tunnel("wg-b")],
        &[transport_on(51820)],
    )
    .unwrap();

    assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a")), "accept");
    assert_eq!(verdict(&rs, pkt(998, ADDR_B, "wg-b")), "accept");
    assert_eq!(
        verdict(&rs, pkt(998, ADDR_A, "wg-b")),
        "drop",
        "A's address on B's tunnel is dropped:\n{rs}"
    );
    assert_eq!(
        verdict(&rs, pkt(998, ADDR_B, "wg-a").udp(6881, "203.0.113.9:6881")),
        "drop",
        "and B's on A's, UDP included:\n{rs}"
    );
    assert_eq!(
        verdict(&rs, pkt(998, Ipv4Addr::new(192, 168, 1, 20), "wg-a")),
        "drop",
        "an address no profile holds is dropped on every tunnel:\n{rs}"
    );
    assert_eq!(
        verdict(&rs, pkt(1000, Ipv4Addr::new(192, 168, 1, 20), "eth0")),
        "accept",
        "another uid's traffic from another address is not this ruleset's to judge"
    );

    // The control: the shared accept this replaced let A out of B's tunnel.
    let shared = "\
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 oifname { \"wg-a\", \"wg-b\" } accept
\t\tmeta skuid 998 counter drop
";
    assert_eq!(verdict(shared, pkt(998, ADDR_A, "wg-b")), "accept");
}

/// #136, the stale exemption: once a link is down its listen port is
/// free, and a socket holding it — bound to it, or handed it as an
/// ephemeral port by a resolver query — sent out of the physical
/// interface through a port-only exemption. Scoped to the provider's
/// endpoint, only the tunnel's own transport passes.
#[test]
fn the_transport_exemption_reaches_the_provider_endpoint_and_nowhere_else() {
    let rs = render_ruleset_with_transport(998, &[tunnel("wg-a")], &[transport_on(51820)]).unwrap();
    let phys = Ipv4Addr::new(192, 0, 2, 1);

    assert_eq!(
        verdict(&rs, pkt(998, phys, "eth0").udp(51820, ENDPOINT)),
        "accept",
        "the encrypted transport to the provider leaves:\n{rs}"
    );
    for (label, to) in [
        ("a datagram to another host", "192.0.2.2:7"),
        ("a resolver query", "192.0.2.53:53"),
        ("another port on the provider", "198.51.100.1:53"),
    ] {
        assert_eq!(
            verdict(&rs, pkt(998, phys, "eth0").udp(51820, to)),
            "drop",
            "{label} from the freed listen port is dropped:\n{rs}"
        );
    }
    assert_eq!(
        verdict(&rs, pkt(998, phys, "eth0").udp(40000, ENDPOINT)),
        "drop",
        "another source port to the provider is dropped:\n{rs}"
    );

    // The control: the port-only exemption this replaced let both out.
    let port_only = "\
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 udp sport { 51820 } accept
\t\tmeta skuid 998 counter drop
";
    assert_eq!(
        verdict(
            port_only,
            pkt(998, phys, "eth0").udp(51820, "192.0.2.53:53")
        ),
        "accept"
    );
}

/// #136, the kernel's replies: a reset or an ICMP error carries no socket
/// of the daemon's, so no uid rule judges it. With the tunnel's source
/// rule lost it left by the physical interface from the tunnel address.
/// The address fence drops it whoever built it, and still lets the
/// tunnel and loopback carry that address.
#[test]
fn a_tunnel_address_leaves_by_its_own_tunnel_or_loopback_whoever_sent_it() {
    let rs = render_ruleset_with_transport(
        998,
        &[tunnel("wg-a"), tunnel("wg-b")],
        &[transport_on(51820)],
    )
    .unwrap();
    for (label, p) in [
        ("a kernel reset", pkt(998, ADDR_A, "eth0").kernel()),
        ("another uid's socket", pkt(0, ADDR_A, "eth0")),
        ("into the other tunnel", pkt(0, ADDR_A, "wg-b")),
    ] {
        assert_eq!(verdict(&rs, p), "drop", "{label}:\n{rs}");
    }
    assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a").kernel()), "accept");
    assert_eq!(verdict(&rs, pkt(0, ADDR_A, "lo")), "accept");
    assert_eq!(
        verdict(&rs, pkt(0, Ipv4Addr::new(192, 0, 2, 1), "eth0").kernel()),
        "accept",
        "the host's own address is not the ruleset's to judge"
    );
}

/// Providers that hand every client the same address: two tunnels on it
/// share one fence that allows both, or each would drop the other.
#[test]
fn tunnels_sharing_an_address_share_its_fence() {
    let rs = render_ruleset(
        998,
        &[Tunnel::new("wg-b", ADDR_A), Tunnel::new("wg-a", ADDR_A)],
    )
    .unwrap();
    // One fence for the address, ahead of every accept.
    let expected = "\
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\", \"wg-b\" } drop
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-b\" accept
\t\tmeta skuid 998 counter drop
\t}
}
";
    assert_eq!(rs, expected);
    assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a")), "accept");
    assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-b")), "accept");
}

/// A session listening on its tunnel device listens and announces on the
/// device's IPv6 addresses too. Each is paired with its own tunnel as the
/// IPv4 address is: accepted there, dropped on another tunnel or off the
/// tunnels whoever sent it, and an IPv6 address no tunnel holds is still
/// dropped.
#[test]
fn a_tunnel_s_ipv6_addresses_are_paired_with_it_as_its_ipv4_address_is() {
    let rs = render_ruleset(998, &[tunnel("wg-a").with_v6([ADDR_A6]), tunnel("wg-b")]).unwrap();
    assert!(
        rs.contains("\t\tip6 saddr 2001:db8::2 oifname != { \"lo\", \"wg-a\" } drop\n")
            && rs.contains("\t\tmeta skuid 998 ip6 saddr 2001:db8::2 oifname \"wg-a\" accept\n"),
        "{rs}"
    );
    assert_eq!(verdict(&rs, pkt(998, ADDR_A6, "wg-a")), "accept");
    assert_eq!(
        verdict(&rs, pkt(998, ADDR_A6, "wg-b")),
        "drop",
        "A's IPv6 address on B's tunnel is dropped:\n{rs}"
    );
    assert_eq!(
        verdict(&rs, pkt(998, ADDR_A6, "eth0").kernel()),
        "drop",
        "a kernel-built packet from it off the tunnel is dropped:\n{rs}"
    );
    assert_eq!(
        verdict(
            &rs,
            pkt(998, "2001:db8::99".parse::<Ipv6Addr>().unwrap(), "wg-a")
        ),
        "drop",
        "an IPv6 address no tunnel holds is dropped:\n{rs}"
    );
    assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a")), "accept");
    assert_eq!(verdict(&rs, pkt(998, ADDR_B, "wg-b")), "accept");
}

/// A link whose IPv6 addresses cannot be read is paired with none, which
/// drops its IPv6 traffic, and the reason is logged. The name is one no
/// tool may be handed, so the read fails before anything is run.
#[test]
fn a_failed_ipv6_read_pairs_no_address_and_says_why() {
    let log = crate::tracing_init::Buf::default();
    let (_handle, subscriber) =
        crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
    let _guard = torrentd_engine::testing::set_subscriber(subscriber);

    assert_eq!(tunnel_ipv6("-wg-a"), Vec::<Ipv6Addr>::new());

    let log = log.text();
    assert!(
        log.contains("\"level\":\"WARN\"")
            && log.contains("could not read the tunnel's IPv6 addresses")
            && log.contains("-wg-a")
            && log.contains("cannot be passed to a tool"),
        "{log}"
    );
}

/// `enable` pairs what the IPv6 probe reads for each link, and a link it
/// reads none for gets no IPv6 rule.
#[test]
fn enable_pairs_each_link_s_ipv6_addresses() {
    let installed = enable_for_uid(
        998,
        &["wg-a".to_string(), "wg-b".to_string()],
        addr_of,
        |iface| {
            if iface == "wg-a" {
                vec![ADDR_A6]
            } else {
                Vec::new()
            }
        },
        |_| Ok(transport_on(51820)),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        installed.tunnels,
        vec![tunnel("wg-a").with_v6([ADDR_A6]), tunnel("wg-b")]
    );
    // wg-a's IPv6 address is fenced and accepted beside its IPv4 one;
    // wg-b, with none, gets IPv4 rules only.
    let expected = "\
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\" } drop
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg-b\" } drop
\t\tip6 saddr 2001:db8::2 oifname != { \"lo\", \"wg-a\" } drop
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip6 saddr 2001:db8::2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
\t\tmeta skuid 998 ip daddr 198.51.100.1 udp sport 51820 udp dport 51820 accept
\t\tmeta skuid 998 counter drop
\t}
}
";
    assert_eq!(installed.table, expected);
}

#[test]
fn endpoints_are_read_and_a_link_with_none_is_refused() {
    let out = "a2V5MQ==\t198.51.100.1:51820\nb2V5Mg==\t(none)\nc2V5Mw==\t[2001:db8::7]:4500\n";
    assert_eq!(
        parse_endpoints("wg-a", out).unwrap(),
        vec![
            "198.51.100.1:51820".parse::<SocketAddr>().unwrap(),
            "[2001:db8::7]:4500".parse().unwrap(),
        ],
    );
    let e = parse_endpoints("wg-a", "a2V5MQ==\t(none)\n").expect_err("no endpoint");
    assert!(e.to_string().contains("no peer endpoint"), "got {e}");
    parse_endpoints("wg-a", "").expect_err("no peers at all");
    parse_endpoints("wg-a", "a2V5MQ==\tsomewhere\n").expect_err("not an endpoint");
}

#[test]
fn a_listen_port_is_read_as_a_port_and_zero_is_refused() {
    assert_eq!(parse_listen_port("wg-a", "51820\n").unwrap(), 51820);
    let e = parse_listen_port("wg-a", "0\n").expect_err("a down link has no socket");
    assert!(e.to_string().contains("no listen port"), "got {e}");
    parse_listen_port("wg-a", "").expect_err("empty output is not a port");
    parse_listen_port("wg-a", "70000\n").expect_err("out of range is not a port");
}

/// The exemption, byte for byte: after the tunnel accept and before the
/// drop, keyed on this uid, the source port **and** the provider
/// endpoint, so it lets out the WireGuard socket's encrypted UDP and
/// nothing else this uid owns. One line per endpoint, de-duplicated.
#[test]
fn ruleset_exempts_each_tunnels_transport_ahead_of_the_drop() {
    let two_peers = Transport::new(
        40001,
        [
            "203.0.113.5:51820".parse().unwrap(),
            "198.51.100.1:51820".parse().unwrap(),
        ],
    );
    let rs = render_ruleset_with_transport(
        998,
        &[tunnel("wg-a"), tunnel("wg-b")],
        &[transport_on(51820), two_peers, transport_on(51820)],
    )
    .unwrap();
    let expected = "\
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\" } drop
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg-b\" } drop
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
\t\tmeta skuid 998 ip daddr 198.51.100.1 udp sport 40001 udp dport 51820 accept
\t\tmeta skuid 998 ip daddr 203.0.113.5 udp sport 40001 udp dport 51820 accept
\t\tmeta skuid 998 ip daddr 198.51.100.1 udp sport 51820 udp dport 51820 accept
\t\tmeta skuid 998 counter drop
\t}
}
";
    assert_eq!(rs, expected);
}

/// A transaction nft refuses is reported, not swallowed. Because it is
/// one transaction, nft has changed nothing: the previous table, if any,
/// is still in force.
#[test]
fn a_refused_transaction_is_reported() {
    let e = enable_for_uid(
        998,
        &[],
        |_| unreachable!("no tunnels, no addresses"),
        |_| unreachable!("no tunnels, no IPv6 addresses"),
        |_| unreachable!("no tunnels, no ports"),
        |_| {
            Err(io::Error::other(
                "`nft -f -` exited 1: Operation not permitted",
            ))
        },
    )
    .expect_err("a failed install is not swallowed");
    assert!(e.to_string().contains("nft -f"), "got {e}");
}

/// The first boot with the kill switch on: no table yet. `disable` must
/// succeed without attempting the delete, whatever language `nft` would
/// have failed it in — the absence is read from the listing, not from a
/// localised error message.
#[test]
fn disable_succeeds_without_deleting_when_the_table_is_absent() {
    let deleted = std::cell::Cell::new(false);
    let removed = disable_with(
        998,
        || Ok("table ip filter\ntable inet other\n".to_string()),
        |_| panic!("no legacy table is listed, so none is read"),
        |_| {
            deleted.set(true);
            Err(io::Error::other(
                "nft delete table exited 1: Fehler: Datei oder Verzeichnis nicht gefunden",
            ))
        },
    )
    .expect("an absent table is success");
    assert!(!deleted.get(), "nothing to delete, so no delete is run");
    assert!(!removed, "and no table is reported removed");

    let removed = disable_with(
        998,
        || Ok(String::new()),
        |_| panic!("no tables at all"),
        |_| panic!("no tables at all"),
    )
    .expect("an empty listing is an absent table");
    assert!(!removed);
}

#[test]
fn disable_deletes_a_listed_table_and_reports_its_failure() {
    let deleted = std::cell::RefCell::new(Vec::new());
    let removed = disable_with(
        998,
        || Ok(format!("table ip filter\ntable inet {TABLE}\n")),
        |_| panic!("no legacy table is listed"),
        |name| {
            deleted.borrow_mut().push(name.to_string());
            Ok(())
        },
    )
    .expect("a delete that succeeded");
    assert_eq!(*deleted.borrow(), [TABLE], "the listed table is deleted");
    assert!(
        removed,
        "and reported removed, so a caller can say it found one"
    );

    let e = disable_with(
        998,
        || Ok(format!("table inet {TABLE}\n")),
        |_| panic!("no legacy table is listed"),
        |_| Err(io::Error::other("nft delete table exited 1: busy")),
    )
    .expect_err("a table that exists and would not delete is not swallowed");
    assert!(e.to_string().contains("nft delete table"), "got {e}");
}

/// #168: a daemon with the kill switch off — an OpenVPN daemon beside a
/// WireGuard one, as docs/running.md prescribes — runs this at every boot
/// and, through `net-cleanup`, at every stop. Another uid's table is the
/// other daemon's kill switch in force, and is never deleted.
#[test]
fn disable_leaves_another_uids_table_standing() {
    let removed = disable_with(
        1000,
        || {
            Ok(format!(
                "table inet {TABLE}\ntable inet torrentd_ks_10000\n"
            ))
        },
        |_| panic!("no legacy table is listed"),
        |name| panic!("{name} is another daemon's kill switch, and is not deleted"),
    )
    .expect("nothing of this uid's is listed: success");
    assert!(!removed);

    let deleted = std::cell::RefCell::new(Vec::new());
    disable_with(
        998,
        || Ok(format!("table inet torrentd_ks_1000\ntable inet {TABLE}\n")),
        |_| panic!("no legacy table is listed"),
        |name| {
            deleted.borrow_mut().push(name.to_string());
            Ok(())
        },
    )
    .expect("this uid's table deletes");
    assert_eq!(*deleted.borrow(), [TABLE], "and only this uid's");
}

/// `nft -j list table inet torrentd_ks` for a table an earlier release
/// installed for `uid`: the fence, which names no uid, then the drop.
fn legacy_listing(uid: u32) -> String {
    format!(
        r#"{{"nftables": [{{"metainfo": {{"json_schema_version": 1}}}}, {{"table": {{"family": "inet", "name": "torrentd_ks", "handle": 1}}}}, {{"rule": {{"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 2, "expr": [{{"match": {{"op": "==", "left": {{"payload": {{"protocol": "ip", "field": "saddr"}}}}, "right": "10.2.0.2"}}}}, {{"drop": null}}]}}}}, {{"rule": {{"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 3, "expr": [{{"match": {{"op": "==", "left": {{"meta": {{"key": "skuid"}}}}, "right": {uid}}}}}, {{"counter": {{"packets": 0, "bytes": 0}}}}, {{"drop": null}}]}}}}]}}"#
    )
}

/// A table an earlier release left under the shared name is removed by
/// the uid it confines, and by no other.
#[test]
fn a_legacy_table_is_removed_only_by_the_uid_it_confines() {
    let deleted = std::cell::RefCell::new(Vec::new());
    let delete = |name: &str| {
        deleted.borrow_mut().push(name.to_string());
        Ok(())
    };
    let listing = || Ok(format!("table inet torrentd_ks\ntable inet {TABLE}\n"));

    let removed =
        disable_with(998, listing, |_| Ok(legacy_listing(998)), delete).expect("both delete");
    assert!(removed);
    assert_eq!(*deleted.borrow(), [TABLE, "torrentd_ks"]);

    deleted.borrow_mut().clear();
    let removed = disable_with(
        998,
        || Ok("table inet torrentd_ks\n".to_string()),
        |_| Ok(legacy_listing(1000)),
        delete,
    )
    .expect("another uid's legacy table is no failure");
    assert!(!removed, "it is left standing");
    assert!(deleted.borrow().is_empty(), "got {:?}", deleted.borrow());

    let no_uid =
        r#"{"nftables": [{"table": {"family": "inet", "name": "torrentd_ks", "handle": 1}}]}"#;
    let removed = disable_with(
        998,
        || Ok("table inet torrentd_ks\n".to_string()),
        |_| Ok(no_uid.to_string()),
        delete,
    )
    .expect("a table naming no uid is no failure");
    assert!(!removed, "and is nobody's to remove");
    assert!(deleted.borrow().is_empty());

    let e = disable_with(
        998,
        || Ok("table inet torrentd_ks\n".to_string()),
        |_| Err(io::Error::other("nft -j list table exited 1")),
        |_| panic!("nothing is deleted on a table nobody could read"),
    )
    .expect_err("a legacy table that could not be read is not taken for absent");
    assert!(e.to_string().contains("nft -j list table"), "got {e}");
    assert!(
        e.to_string().contains("shared name torrentd_ks:"),
        "the error names the legacy table, not this uid's: {e}"
    );
}

/// Once this uid's own table is deleted, a legacy table that cannot be
/// read or deleted is a warning, not the call's failure: shutdown would
/// otherwise report this uid's table as still confining it.
#[test]
fn a_legacy_failure_after_the_own_table_is_removed_is_a_warning() {
    let listing = || Ok(format!("table inet torrentd_ks\ntable inet {TABLE}\n"));

    let deleted = std::cell::RefCell::new(Vec::new());
    let removed = disable_with(
        998,
        listing,
        |_| Err(io::Error::other("nft -j list table exited 1")),
        |name| {
            deleted.borrow_mut().push(name.to_string());
            Ok(())
        },
    )
    .expect("the own table is gone, so the call succeeds");
    assert!(removed);
    assert_eq!(*deleted.borrow(), [TABLE], "only the own table is deleted");

    let deleted = std::cell::RefCell::new(Vec::new());
    let removed = disable_with(
        998,
        listing,
        |_| Ok(legacy_listing(998)),
        |name| {
            deleted.borrow_mut().push(name.to_string());
            if name == TABLE_PREFIX {
                Err(io::Error::other("nft delete table exited 1: busy"))
            } else {
                Ok(())
            }
        },
    )
    .expect("a legacy delete that failed does not fail the own table's removal");
    assert!(removed);
    assert_eq!(*deleted.borrow(), [TABLE, TABLE_PREFIX]);
}

#[test]
fn a_table_naming_two_uids_is_nobodys() {
    let json: serde_json::Value =
        serde_json::from_str(&listing(&[LO, &DROP.replace("998", "1000")])).unwrap();
    assert_eq!(skuids(&json), BTreeSet::from([998, 1000]));
    assert_eq!(
        skuids(&serde_json::from_str(&legacy_listing(998)).unwrap()),
        BTreeSet::from([998])
    );
}

/// A listing that fails — no `CAP_NET_ADMIN`, say — is an error, not an
/// absent table: otherwise a stale table this run cannot see would be
/// left in force beneath the new rules.
#[test]
fn disable_reports_a_failed_listing_without_deleting() {
    let e = disable_with(
        998,
        || {
            Err(io::Error::other(
                "nft list tables exited 1: Operation not permitted",
            ))
        },
        |_| panic!("nothing is read on a listing nobody could read"),
        |_| panic!("nothing is deleted on a listing nobody could read"),
    )
    .expect_err("a failed listing is not an absent table");
    assert!(e.to_string().contains("nft list tables"), "got {e}");
}

/// `disable` against a real `nft`: absent, then present, then absent
/// again. Needs `CAP_NET_ADMIN` in a network namespace of its own, so it
/// is ignored by default. `mise run test-netns` runs it with every other
/// real-kernel test (the `vpn-netns` CI job does, on every pull request);
/// alone, unprivileged and under a non-English locale:
///
/// ```text
/// LC_ALL=de_DE.UTF-8 unshare -rn cargo test -p torrentd --bin torrentd \
///     disable_against_real_nft -- --ignored
/// ```
#[test]
#[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
fn disable_against_real_nft() {
    remove_table_for(998).expect("no table yet: success, in any locale");
    let first = Installed::render(998, vec![tunnel("wg0")], vec![]).unwrap();
    apply(&first.script()).expect("install onto no table");
    let second = Installed::render(
        998,
        vec![tunnel("wg1")],
        vec![("wg1".to_string(), transport_on(51820))],
    )
    .unwrap();
    apply(&second.script()).expect("and replace a standing one in the same transaction");
    // Read back through `verify`, which compares the live table rule for
    // rule with what was rendered, rather than through `nft list`'s
    // pretty-printed text, whose layout differs between nft releases.
    assert_eq!(
        verify(&second).unwrap(),
        Verdict::Intact,
        "the replace leaves exactly this install's rules"
    );
    assert!(
        matches!(verify(&first).unwrap(), Verdict::Drifted(_)),
        "and none of the one it replaced"
    );
    // #168: a second daemon's, under another uid, beside it.
    apply(&install_script(1000, &[tunnel("wg2")], &[]).unwrap()).expect("install uid 1000's");
    assert!(table_listed(&list_tables().expect("list"), TABLE));
    assert!(
        remove_table_for(998).expect("an installed table is deleted"),
        "and reported removed"
    );
    let listing = list_tables().expect("list");
    assert!(!table_listed(&listing, TABLE));
    assert!(
        table_listed(&listing, "torrentd_ks_1000"),
        "the other uid's table survives: {listing}"
    );
    assert!(!remove_table_for(998).expect("and deleting it again is still success"));
    assert!(remove_table_for(1000).expect("uid 1000's own removal takes it"));
}

/// A table an earlier release left under the shared name, against a real
/// `nft`: another uid's removal leaves it, its own uid's removes it. Run
/// it as [`disable_against_real_nft`] says.
/// The renderer writes `!=` only against a set of interface names, so a
/// listing reading `oifname != "<one name>"` is not a rule it installed.
#[test]
fn a_negated_single_interface_match_is_not_a_rule_the_kill_switch_installs() {
    let set = serde_json::json!([
        {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}},
                   "right": {"set": ["wg0", "lo"]}}},
        {"drop": null},
    ]);
    assert_eq!(
        rule_line(&set).unwrap(),
        "oifname != { \"lo\", \"wg0\" } drop"
    );
    let single = serde_json::json!([
        {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}},
        {"drop": null},
    ]);
    rule_line(&single).expect_err("never installed");
}

/// `remove_table` and `disable` act on this process's own uid's table, and
/// say whether there was one.
#[test]
#[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
fn removing_the_own_table_against_real_nft() {
    let own = own_table_name();
    let table = render_ruleset(current_uid().unwrap(), &[tunnel("wg0")]).unwrap();
    apply(&table).expect("install this uid's table");
    assert!(remove_table().expect("remove it"), "there was a table");
    assert!(!table_listed(&list_tables().expect("list"), &own));
    assert!(!remove_table().expect("nothing left"), "there was none");
    apply(&table).expect("install it again");
    disable().expect("disable removes it");
    assert!(!table_listed(&list_tables().expect("list"), &own));
}

#[test]
#[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
fn a_legacy_table_against_real_nft() {
    let legacy = render_ruleset(998, &[tunnel("wg0")])
        .unwrap()
        .replace(TABLE, TABLE_PREFIX);
    apply(&legacy).expect("install a table under the shared name");
    assert!(!remove_table_for(1000).expect("another uid's removal"));
    assert!(table_listed(&list_tables().expect("list"), TABLE_PREFIX));
    assert!(remove_table_for(998).expect("its own uid's removal"));
    assert!(!table_listed(&list_tables().expect("list"), TABLE_PREFIX));
}

#[test]
fn only_this_family_and_name_count_as_the_table() {
    assert!(table_listed(&format!("table inet {TABLE}\n"), TABLE));
    assert!(table_listed(
        &format!("table ip nat\ntable inet {TABLE}"),
        TABLE
    ));
    assert!(!table_listed(&format!("table ip {TABLE}\n"), TABLE));
    assert!(!table_listed(&format!("table inet {TABLE}_old\n"), TABLE));
    assert!(!table_listed("", TABLE));
    // The shared legacy name is not any uid's table, nor the reverse.
    assert!(!table_listed("table inet torrentd_ks\n", TABLE));
    assert!(!table_listed(
        &format!("table inet {TABLE}\n"),
        TABLE_PREFIX
    ));
}

#[test]
fn each_uid_owns_its_own_table() {
    assert_eq!(table_name(998), TABLE);
    assert_ne!(table_name(998), table_name(1000));
    let rs = render_ruleset(1000, &[tunnel("wg-a")]).unwrap();
    assert!(rs.starts_with("table inet torrentd_ks_1000 {\n"), "{rs}");
    let script = install_script(1000, &[tunnel("wg-a")], &[]).unwrap();
    assert!(
        script.starts_with("add table inet torrentd_ks_1000\ndelete table inet torrentd_ks_1000\n"),
        "the replace touches only this uid's table: {script}"
    );
}

#[test]
fn ruleset_confines_uid_to_lo_and_tunnels() {
    let rs = render_ruleset(998, &[tunnel("wg-b"), tunnel("wg-a")]).unwrap();
    let expected = "\
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\" } drop
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg-b\" } drop
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
\t\tmeta skuid 998 counter drop
\t}
}
";
    assert_eq!(rs, expected);
}

/// One fence and one accept for the interface, and still fail-closed: the
/// loopback accept, the tunnel's accept, then the drop, in that order.
#[test]
fn ruleset_dedups_shared_interface() {
    let rs = render_ruleset(1000, &[tunnel("wg0"), tunnel("wg0")]).unwrap();
    let expected = "\
table inet torrentd_ks_1000 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg0\" } drop
\t\tmeta skuid 1000 oifname \"lo\" accept
\t\tmeta skuid 1000 ip saddr 10.64.0.7 oifname \"wg0\" accept
\t\tmeta skuid 1000 counter drop
\t}
}
";
    assert_eq!(rs, expected);
}

/// No fence and no tunnel accept: the loopback accept, then the drop.
#[test]
fn ruleset_with_no_tunnels_allows_only_loopback() {
    let rs = render_ruleset(1000, &[]).unwrap();
    let expected = "\
table inet torrentd_ks_1000 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 1000 oifname \"lo\" accept
\t\tmeta skuid 1000 counter drop
\t}
}
";
    assert_eq!(rs, expected);
}

/// The shape from #33: a quote closes the set's quoted token early and
/// `nft` rejects the whole table. The renderer refuses it by name instead
/// of emitting a ruleset it knows will not parse.
#[test]
fn ruleset_refuses_a_name_it_cannot_quote() {
    for bad in ["wg\"x", "wg}x", "wg\nx", ""] {
        let e = render_ruleset(2000, &[tunnel("lo"), Tunnel::new(bad, ADDR_A)])
            .expect_err("an unquotable name is refused, not rendered");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains(&format!("{bad:?}")), "got {e}");
    }
}

/// And `enable` refuses it before anything reaches nft, so a previous run's kill
/// switch stays armed rather than being deleted and never replaced.
#[test]
fn enable_refuses_an_unquotable_name_before_nft() {
    let applied = std::cell::Cell::new(false);
    enable_for_uid(
        998,
        &["wg\"x".to_string()],
        addr_of,
        no_v6,
        |_| Ok(transport_on(51820)),
        |_| {
            applied.set(true);
            Ok(())
        },
    )
    .expect_err("an unquotable name stops the install");
    assert!(
        !applied.get(),
        "nothing is handed to nft, so the existing table is left in force"
    );
}

fn gauge(metrics: &torrentd_engine::RecordingSink) -> Option<f64> {
    metrics.calls().iter().rev().find_map(|c| match c {
        torrentd_engine::metrics::MetricCall::SetGauge { name, value, .. }
            if name == "kill_switch_table_present" =>
        {
            Some(*value)
        }
        _ => None,
    })
}

/// The transport [`installed`] exempts: two peers, one on IPv6.
fn two_peer_transport() -> Transport {
    Transport::new(
        51820,
        [
            ENDPOINT.parse().unwrap(),
            "[2001:db8::7]:4500".parse().unwrap(),
        ],
    )
}

/// What `enable` installs for uid 998 over `wg-a` with two peer
/// endpoints: the table the listings below are nft's listing of.
fn installed() -> Installed {
    Installed::render(
        998,
        vec![tunnel("wg-a")],
        vec![("wg-a".to_string(), two_peer_transport())],
    )
    .unwrap()
}

const META: &str = r#"{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "torrentd_ks_998", "handle": 1}}, {"chain": {"family": "inet", "table": "torrentd_ks_998", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}"#;
const FENCE: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 2, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.2.0.2"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": {"set": ["lo", "wg-a"]}}}, {"drop": null}]}}"#;
const LO: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 2, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"accept": null}]}}"#;
const WG_A: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 3, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.2.0.2"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg-a"}}, {"accept": null}]}}"#;
const PORT_V4: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 4, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "198.51.100.1"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "sport"}}, "right": 51820}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 51820}}, {"accept": null}]}}"#;
const PORT_V6: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 5, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "daddr"}}, "right": "2001:db8::7"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "sport"}}, "right": 51820}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 4500}}, {"accept": null}]}}"#;
const DROP: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 6, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"counter": {"packets": 12, "bytes": 960}}, {"drop": null}]}}"#;

/// `nft -j list table` as nftables 1.1.6 printed it for [`installed`]'s
/// table, entries in the order given.
fn listing(entries: &[&str]) -> String {
    format!(r#"{{"nftables": [{}]}}"#, entries.join(", "))
}

fn verify_listing(json: String) -> io::Result<Verdict> {
    verify_with(
        &installed(),
        || Ok(format!("table ip filter\ntable inet {TABLE}\n")),
        move || Ok(json.clone()),
    )
}

#[test]
fn the_table_as_installed_verifies_intact() {
    assert_eq!(
        verify_listing(listing(&[META, FENCE, LO, WG_A, PORT_V4, PORT_V6, DROP])).unwrap(),
        Verdict::Intact,
        "counter values and rule handles are not drift",
    );
}

/// A tunnel with an IPv6 address reads back intact: the `ip6 saddr`
/// matches its fence and its accept carry are read as rendered.
#[test]
fn a_table_pairing_an_ipv6_address_verifies_intact() {
    const FENCE_V6: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 7, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "2001:db8::2"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": {"set": ["lo", "wg-a"]}}}, {"drop": null}]}}"#;
    const WG_A_V6: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 8, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "2001:db8::2"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg-a"}}, {"accept": null}]}}"#;
    let installed = Installed::render(
        998,
        vec![tunnel("wg-a").with_v6([ADDR_A6])],
        vec![("wg-a".to_string(), two_peer_transport())],
    )
    .unwrap();
    let json = listing(&[
        META, FENCE, FENCE_V6, LO, WG_A, WG_A_V6, PORT_V4, PORT_V6, DROP,
    ]);
    let verdict = verify_with(
        &installed,
        || Ok(format!("table inet {TABLE}\n")),
        move || Ok(json.clone()),
    )
    .unwrap();
    assert_eq!(verdict, Verdict::Intact);
}

/// The scenario in #102: the chain flushed, the table still listed. Its
/// name alone read as present, and `kill_switch_table_present` stayed 1.
#[test]
fn a_flushed_chain_is_drift_though_the_table_is_listed() {
    let verdict = verify_listing(listing(&[META])).unwrap();
    let Verdict::Drifted(why) = verdict else {
        panic!("a flushed chain is drift; got {verdict:?}");
    };
    assert!(
        why.starts_with(
            "installed \"ip saddr 10.2.0.2 oifname != { \\\"lo\\\", \\\"wg-a\\\" } drop\""
        ),
        "says which rule is missing; got {why}",
    );
}

#[test]
fn a_missing_table_is_absent_and_its_contents_are_not_asked() {
    let verdict = verify_with(
        &installed(),
        || Ok("table ip filter\n".to_string()),
        || panic!("no table to list"),
    )
    .unwrap();
    assert_eq!(verdict, Verdict::Absent);
}

/// Anything else in the table is not the table installed: a rule
/// replaced, one added, a chain policy changed, a set this module never
/// writes.
#[test]
fn a_changed_or_extended_table_is_drift() {
    let accept_all = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 7, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"accept": null}]}}"#;
    let other_addr = WG_A.replace("10.2.0.2", "10.9.9.9");
    let drop_policy = META.replace(r#""policy": "accept""#, r#""policy": "drop""#);
    let set = r#"{"set": {"family": "inet", "name": "s", "table": "torrentd_ks_998", "type": "ipv4_addr", "handle": 4}}"#;
    let unread = DROP.replace(r#"{"drop": null}"#, r#"{"jump": {"target": "x"}}"#);
    let fence_widened = FENCE.replace(r#"["lo", "wg-a"]"#, r#"["eth0", "lo", "wg-a"]"#);
    let fence_eq = FENCE.replace(r#""op": "!=""#, r#""op": "==""#);
    let other_endpoint = PORT_V4.replace("198.51.100.1", "192.0.2.53");
    let port_only = PORT_V4.replace(
            r#"{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "198.51.100.1"}}, "#,
            "",
        );
    let rest = [LO, WG_A, PORT_V4, PORT_V6, DROP];
    let with = |head: &[&str], tail: &[&str]| listing(&[head, tail].concat());
    for (label, json) in [
        (
            "an accept ahead of the drop",
            with(&[META, FENCE, LO, accept_all], &rest[1..]),
        ),
        (
            "a tunnel address replaced",
            listing(&[META, FENCE, LO, &other_addr, PORT_V4, PORT_V6, DROP]),
        ),
        ("the policy changed", with(&[&drop_policy, FENCE], &rest)),
        ("a set", with(&[META, set, FENCE], &rest)),
        (
            "an unread verdict",
            listing(&[META, FENCE, LO, WG_A, PORT_V4, PORT_V6, &unread]),
        ),
        ("the fence gone", with(&[META], &rest)),
        ("the fence widened", with(&[META, &fence_widened], &rest)),
        ("the fence inverted", with(&[META, &fence_eq], &rest)),
        (
            "an exemption to another endpoint",
            listing(&[META, FENCE, LO, WG_A, &other_endpoint, PORT_V6, DROP]),
        ),
        (
            "an exemption by port alone",
            listing(&[META, FENCE, LO, WG_A, &port_only, PORT_V6, DROP]),
        ),
    ] {
        assert!(
            matches!(verify_listing(json).unwrap(), Verdict::Drifted(_)),
            "{label} is drift",
        );
    }
}

/// A set's elements are compared in the order the renderer writes them,
/// whatever order the listing gives them in.
#[test]
fn a_fence_set_listed_in_another_order_reads_back_as_rendered() {
    let reordered = FENCE.replace(r#"["lo", "wg-a"]"#, r#"["wg-a", "lo"]"#);
    assert_eq!(
        verify_listing(listing(&[
            META, &reordered, LO, WG_A, PORT_V4, PORT_V6, DROP
        ]))
        .unwrap(),
        Verdict::Intact,
    );
}

/// The transport read at the next check, scripted per interface.
fn reads<'a>(
    answers: &'a [(&'static str, io::Result<Transport>)],
) -> impl Fn(&str) -> io::Result<Transport> + 'a {
    move |iface| match answers.iter().find(|(i, _)| *i == iface) {
        Some((_, Ok(t))) => Ok(t.clone()),
        Some((_, Err(e))) => Err(io::Error::new(e.kind(), e.to_string())),
        None => panic!("{iface} was not scripted"),
    }
}

/// #136, the re-raised link: back on a port the kernel picked, the
/// exemption installed at boot named the old one, and the tunnel
/// handshook and carried nothing until a restart. The next check reads
/// the new port and installs the ruleset again with it.
#[test]
fn a_transport_that_changed_is_installed_again_with_the_live_one() {
    let mut installed = installed();
    let before = installed.clone();
    let applied = std::cell::RefCell::new(Vec::<String>::new());
    let moved = Transport::new(45136, [ENDPOINT.parse().unwrap()]);
    let changed = refresh(
        &mut installed,
        addr_of,
        unchanged_v6,
        reads(&[("wg-a", Ok(moved.clone()))]),
        |script| {
            applied.borrow_mut().push(script.to_string());
            Ok(())
        },
    );
    assert!(changed);
    assert_eq!(installed.transports, vec![("wg-a".to_string(), moved)]);
    assert_eq!(installed.tunnels, before.tunnels, "the pairing is kept");
    let applied = applied.borrow();
    assert_eq!(applied.len(), 1, "one install: {applied:?}");
    assert_eq!(applied[0], installed.script());
    assert!(
        applied[0].contains("udp sport 45136 udp dport 51820 accept")
            && !applied[0].contains("udp sport 51820"),
        "the live port is exempted and the old one no longer is: {}",
        applied[0],
    );
}

#[test]
fn an_unchanged_transport_installs_nothing() {
    let mut installed = installed();
    let before = installed.clone();
    let changed = refresh(
        &mut installed,
        addr_of,
        unchanged_v6,
        reads(&[("wg-a", Ok(two_peer_transport()))]),
        |_| panic!("nothing changed, nothing to install"),
    );
    assert!(!changed);
    assert_eq!(installed, before);
}

/// A link that cannot be read keeps the exemption last read: scoped to
/// the endpoint it reaches nothing else, and a read that failed for any
/// other reason must not silence a working tunnel.
#[test]
fn a_transport_that_will_not_read_keeps_the_last_one() {
    let mut installed = installed();
    let before = installed.clone();
    let changed = refresh(
        &mut installed,
        addr_of,
        unchanged_v6,
        reads(&[("wg-a", Err(io::Error::other("Unable to access interface")))]),
        |_| panic!("nothing read, nothing to install"),
    );
    assert!(!changed);
    assert_eq!(installed, before);
}

/// An install of the live transport that fails still replaces what the
/// watch compares the live table with, so the check that follows reads
/// the old table as drift and fences every vpn profile.
#[test]
fn a_failed_install_of_the_live_transport_is_drift_at_the_check() {
    let mut installed = installed();
    let changed = refresh(
        &mut installed,
        addr_of,
        unchanged_v6,
        reads(&[("wg-a", Ok(transport_on(45136)))]),
        |_| Err(io::Error::other("nft -f - exited 1")),
    );
    assert!(changed);
    let live = listing(&[META, FENCE, LO, WG_A, PORT_V4, PORT_V6, DROP]);
    let verdict = verify_with(
        &installed,
        || Ok(format!("table inet {TABLE}\n")),
        move || Ok(live.clone()),
    )
    .unwrap();
    assert!(matches!(verdict, Verdict::Drifted(_)), "got {verdict:?}");
}

/// [`installed`]'s link as it was at install: no IPv6 address.
fn unchanged_v6(_: &str) -> io::Result<Vec<Ipv6Addr>> {
    Ok(Vec::new())
}

/// #446: an IPv6 address the link gained after boot. The pairing was
/// fixed at install, so the ruleset kept dropping every packet the
/// session sent from it for the rest of the run. The next check reads it
/// and installs the ruleset again with it paired.
#[test]
fn a_v6_address_added_after_boot_is_paired() {
    let mut installed = installed();
    let before = installed.clone();
    assert!(!before.table.contains(&ADDR_A6.to_string()));
    let applied = std::cell::RefCell::new(Vec::<String>::new());
    let changed = refresh(
        &mut installed,
        addr_of,
        |_| Ok(vec![ADDR_A6]),
        reads(&[("wg-a", Ok(two_peer_transport()))]),
        |script| {
            applied.borrow_mut().push(script.to_string());
            Ok(())
        },
    );
    assert!(changed);
    assert_eq!(installed.tunnels, vec![tunnel("wg-a").with_v6([ADDR_A6])]);
    assert_eq!(
        installed.transports, before.transports,
        "the transport is kept"
    );
    let applied = applied.borrow();
    assert_eq!(applied.len(), 1, "one install: {applied:?}");
    assert_eq!(applied[0], installed.script());
    assert!(
        applied[0].contains(&format!(
            "meta skuid 998 ip6 saddr {ADDR_A6} oifname \"wg-a\" accept"
        )),
        "the new address is paired with its tunnel: {}",
        applied[0],
    );
}

/// A changed IPv4 address is paired in its place, and an IPv6 address
/// the link no longer holds is no longer paired.
#[test]
fn a_changed_or_removed_address_is_installed_again_with_the_live_ones() {
    let moved = Ipv4Addr::new(10, 2, 0, 9);
    let mut installed = Installed::render(
        998,
        vec![tunnel("wg-a").with_v6([ADDR_A6])],
        vec![("wg-a".to_string(), two_peer_transport())],
    )
    .unwrap();
    let changed = refresh(
        &mut installed,
        |_| Ok(moved),
        unchanged_v6,
        reads(&[("wg-a", Ok(two_peer_transport()))]),
        |_| Ok(()),
    );
    assert!(changed);
    assert_eq!(installed.tunnels, vec![Tunnel::new("wg-a", moved)]);
    assert!(
        installed
            .table
            .contains(&format!("ip saddr {moved} oifname \"wg-a\" accept"))
            && !installed.table.contains(&ADDR_A.to_string())
            && !installed.table.contains(&ADDR_A6.to_string()),
        "{}",
        installed.table,
    );
}

/// Addresses that will not read keep the pairing last read, as a
/// transport that will not read keeps its exemption.
#[test]
fn addresses_that_will_not_read_keep_the_last_ones() {
    let mut installed = Installed::render(
        998,
        vec![tunnel("wg-a").with_v6([ADDR_A6])],
        vec![("wg-a".to_string(), two_peer_transport())],
    )
    .unwrap();
    let before = installed.clone();
    let changed = refresh(
        &mut installed,
        |_| {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no IPv4 address on wg-a",
            ))
        },
        |_| Err(io::Error::other("Device \"wg-a\" does not exist.")),
        reads(&[("wg-a", Ok(two_peer_transport()))]),
        |_| panic!("nothing read, nothing to install"),
    );
    assert!(!changed);
    assert_eq!(installed, before);
}

/// A check that cannot run is an error, not a verdict: not knowing is
/// neither absent nor drifted.
#[test]
fn a_check_that_cannot_run_is_an_error() {
    verify_with(
        &installed(),
        || Err(io::Error::other("nft: permission denied")),
        || panic!("not reached"),
    )
    .expect_err("a failed listing");
    verify_listing("Error: busy".to_string()).expect_err("output that is not JSON");
}

/// What the watch asked of the profiles, in order.
#[derive(Default)]
struct Recorded(std::sync::Mutex<Vec<&'static str>>);

impl Fence for Recorded {
    fn fence_all_for(&self, cause: FenceCause) {
        self.0.lock().unwrap().push(match cause {
            FenceCause::NotInForce => "fence",
            FenceCause::Unverifiable => "fence unverifiable",
        });
    }
    fn lift(&self) {
        self.0.lock().unwrap().push("lift");
    }
}

impl Recorded {
    fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// The watch runs until its own stop, which the shutdown fires only once
/// its drain is over, and returns at it without a further check: it
/// does not end with the shutdown broadcast that starts the drain.
#[tokio::test(start_paused = true)]
async fn the_watch_runs_until_its_stop_and_returns_at_it() {
    let stop = crate::fence::FencingStop::new();
    let fence = std::sync::Arc::new(Recorded::default());
    let task = tokio::spawn(watch(
        installed(),
        fence.clone(),
        std::sync::Arc::new(crate::metrics_sink::PromSink::new()),
        stop.subscribe(),
    ));
    tokio::time::sleep(WATCH_INTERVAL / 2).await;
    assert!(!task.is_finished(), "nothing has stopped the watch");
    assert!(
        stop.stop(std::time::Duration::from_secs(5)).await,
        "the watch returned"
    );
    task.await.unwrap();
    assert_eq!(fence.take(), Vec::<&str>::new(), "no check ran");
}

/// A check still on the blocking pool when the shutdown's stop closes
/// the gate reads the teardown's removal of the table as a loss, and
/// neither installs the table again nor fences the closing sessions;
/// before the stop the same check does both.
#[tokio::test]
async fn a_check_past_the_stop_neither_reinstalls_nor_fences() {
    let stop = crate::fence::FencingStop::new();
    let gate = stop.subscribe().gate();
    let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
    let applied = std::sync::Mutex::new(0);
    let apply = gated_apply(&gate, |_| {
        *applied.lock().unwrap() += 1;
        Ok(())
    });
    let gated = Gated {
        fence: &fence,
        gate: &gate,
    };

    let next = tick(
        Watch::Intact,
        verdicts(vec![Ok(Verdict::Absent), Ok(Verdict::Intact)]),
        || apply("script"),
        &gated,
        &metrics,
    );
    assert_eq!(next, Watch::Intact);
    assert_eq!(
        fence.take(),
        ["fence", "lift"],
        "the open gate lets both through"
    );
    assert_eq!(*applied.lock().unwrap(), 1);

    assert!(stop.stop(std::time::Duration::from_secs(5)).await);
    let next = tick(
        Watch::Intact,
        verdicts(vec![Ok(Verdict::Absent)]),
        || apply("script"),
        &gated,
        &metrics,
    );
    assert_eq!(
        next,
        Watch::Lost,
        "the refused reinstall is not taken for a repair"
    );
    assert_eq!(
        fence.take(),
        Vec::<&str>::new(),
        "nothing fenced past the stop"
    );
    assert_eq!(*applied.lock().unwrap(), 1, "the table not installed again");
}

/// Verdicts handed out in order, one per call.
fn verdicts(v: Vec<io::Result<Verdict>>) -> impl Fn() -> io::Result<Verdict> {
    let v = std::cell::RefCell::new(std::collections::VecDeque::from(v));
    move || v.borrow_mut().pop_front().expect("no more checks scripted")
}

fn drifted() -> io::Result<Verdict> {
    Ok(Verdict::Drifted("installed x, live <nothing>".into()))
}

/// What `kill_switch_lost_total{outcome}` was raised by.
fn lost_for(metrics: &torrentd_engine::RecordingSink, outcome: &str) -> u64 {
    metrics
        .calls()
        .iter()
        .filter(|c| {
            matches!(
                c,
                torrentd_engine::metrics::MetricCall::IncCounter { name, labels }
                    if name == "kill_switch_lost_total"
                        && labels[..] == [("outcome".to_string(), outcome.to_string())]
            )
        })
        .count() as u64
}

/// The loss a reinstall repairs is over within one check, so the gauge a
/// scrape reads is back at 1; the counter is what keeps it.
#[test]
fn a_loss_the_reinstall_repairs_is_counted_once_and_reads_present() {
    let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
    let next = tick(
        Watch::Intact,
        verdicts(vec![Ok(Verdict::Absent), Ok(Verdict::Intact)]),
        || Ok(()),
        &fence,
        &metrics,
    );
    assert_eq!(next, Watch::Intact);
    assert_eq!(lost_for(&metrics, "reinstalled"), 1);
    assert_eq!(lost_for(&metrics, "lost"), 0);
    assert_eq!(metrics.count_for("kill_switch_lost_total"), 1);
    assert_eq!(gauge(&metrics), Some(1.0));

    let next = tick(
        next,
        verdicts(vec![Ok(Verdict::Intact)]),
        || panic!("nothing to reinstall"),
        &fence,
        &metrics,
    );
    assert_eq!(next, Watch::Intact);
    assert_eq!(
        metrics.count_for("kill_switch_lost_total"),
        1,
        "an intact check counts nothing"
    );
}

#[test]
fn an_intact_table_fences_nothing_and_reads_present() {
    let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
    let next = tick(
        Watch::Intact,
        verdicts(vec![Ok(Verdict::Intact)]),
        || panic!("nothing to reinstall"),
        &fence,
        &metrics,
    );
    assert_eq!(next, Watch::Intact);
    assert_eq!(fence.take(), Vec::<&str>::new());
    assert_eq!(gauge(&metrics), Some(1.0));
}

/// A flushed chain and a missing table each fence every vpn profile
/// before anything else, and the fence comes off only once the one
/// reinstall checks intact.
#[test]
fn a_lost_table_fences_then_lifts_only_on_a_verified_reinstall() {
    for (label, lost) in [("flushed", drifted()), ("missing", Ok(Verdict::Absent))] {
        let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
        let reinstalled = std::cell::Cell::new(0);
        let next = tick(
            Watch::Intact,
            verdicts(vec![lost, Ok(Verdict::Intact)]),
            || {
                reinstalled.set(reinstalled.get() + 1);
                Ok(())
            },
            &fence,
            &metrics,
        );
        assert_eq!(next, Watch::Intact, "{label}");
        assert_eq!(fence.take(), ["fence", "lift"], "{label}");
        assert_eq!(reinstalled.get(), 1, "{label}: one reinstall");
        assert_eq!(lost_for(&metrics, "reinstalled"), 1, "{label}");
        assert_eq!(gauge(&metrics), Some(1.0), "{label}");
        assert!(
            metrics.calls().iter().any(|c| matches!(
                c,
                torrentd_engine::metrics::MetricCall::SetGauge { name, value, .. }
                    if name == "kill_switch_table_present" && *value == 0.0
            )),
            "{label}: the loss is read as absent first",
        );
    }
}

/// A reinstall that fails, or that does not check intact, leaves every
/// profile fenced. Later checks fence again — a profile set online
/// meanwhile is fenced once more — without a second reinstall, and the
/// fence comes off at the first check that finds the table intact.
#[test]
fn a_reinstall_that_does_not_verify_keeps_the_fence() {
    for (label, after) in [
        ("refused", Err(io::Error::other("nft -f - exited 1"))),
        ("still drifted", Ok(())),
    ] {
        let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
        let after = std::cell::RefCell::new(Some(after));
        let reinstall = || after.borrow_mut().take().expect("one reinstall per loss");
        let check = verdicts(vec![Ok(Verdict::Absent), drifted()]);
        let next = tick(Watch::Intact, &check, reinstall, &fence, &metrics);
        assert_eq!(next, Watch::Lost, "{label}");
        assert_eq!(gauge(&metrics), Some(0.0), "{label}");
        assert_eq!(fence.take(), ["fence"], "{label}: fenced, not lifted");

        let next = tick(
            next,
            verdicts(vec![Ok(Verdict::Absent)]),
            reinstall,
            &fence,
            &metrics,
        );
        assert_eq!(next, Watch::Lost, "{label}");
        assert_eq!(
            fence.take(),
            ["fence"],
            "{label}: fenced again, no reinstall"
        );

        let next = tick(
            next,
            verdicts(vec![Ok(Verdict::Intact)]),
            reinstall,
            &fence,
            &metrics,
        );
        assert_eq!(next, Watch::Intact, "{label}");
        assert_eq!(fence.take(), ["lift"], "{label}: lifted once found intact");
        assert_eq!(gauge(&metrics), Some(1.0), "{label}");
        assert_eq!(
            lost_for(&metrics, "lost"),
            1,
            "{label}: one loss, counted once"
        );
        assert_eq!(lost_for(&metrics, "reinstalled"), 0, "{label}");
    }
}

fn cannot_run() -> io::Result<Verdict> {
    Err(io::Error::other("nft: permission denied"))
}

/// One check that cannot run is counted and fences nothing: not knowing
/// is not absent. While the watch is lost, every profile is fenced
/// already, and it stays lost.
#[test]
fn a_check_that_cannot_run_is_counted_and_changes_nothing() {
    for (state, after) in [
        (Watch::Intact, Watch::Unchecked(1)),
        (Watch::Lost, Watch::Lost),
    ] {
        let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
        let next = tick(
            state,
            verdicts(vec![cannot_run()]),
            || panic!("nothing is reinstalled on a check that did not run"),
            &fence,
            &metrics,
        );
        assert_eq!(next, after);
        assert_eq!(gauge(&metrics), None, "not knowing is not absent");
        assert_eq!(fence.take(), Vec::<&str>::new());
        assert_eq!(metrics.count_for("kill_switch_probe_errors_total"), 1);
        assert_eq!(metrics.count_for("kill_switch_lost_total"), 0);
    }
}

/// `PROBE_FAILURES_TO_FENCE` checks in a row that cannot run fence every
/// vpn profile `probe_unavailable`; every later one fences again, and the
/// first that finds the table intact lifts it. A check that reaches a
/// verdict between them starts the count over.
#[test]
fn a_check_that_cannot_run_n_times_fences() {
    use crate::vpn_monitor::PROBE_FAILURES_TO_FENCE;
    let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
    let no_reinstall = || panic!("nothing is reinstalled on a check that did not run");
    let mut state = Watch::Intact;
    for _ in 1..PROBE_FAILURES_TO_FENCE {
        state = tick(state, cannot_run, no_reinstall, &fence, &metrics);
    }
    assert_eq!(fence.take(), Vec::<&str>::new(), "one short of the count");
    // A verdict between them starts the count over.
    state = tick(
        state,
        || Ok(Verdict::Intact),
        no_reinstall,
        &fence,
        &metrics,
    );
    assert_eq!(state, Watch::Intact);
    assert_eq!(fence.take(), Vec::<&str>::new(), "nothing fenced to lift");
    for _ in 1..PROBE_FAILURES_TO_FENCE {
        state = tick(state, cannot_run, no_reinstall, &fence, &metrics);
    }
    assert_eq!(fence.take(), Vec::<&str>::new());

    state = tick(state, cannot_run, no_reinstall, &fence, &metrics);
    assert_eq!(state, Watch::Unverified);
    assert_eq!(fence.take(), ["fence unverifiable"]);
    assert_eq!(
        gauge(&metrics),
        Some(1.0),
        "not knowing is still not absent"
    );
    assert_eq!(metrics.count_for("kill_switch_lost_total"), 0);

    state = tick(state, cannot_run, no_reinstall, &fence, &metrics);
    assert_eq!(state, Watch::Unverified);
    assert_eq!(
        fence.take(),
        ["fence unverifiable"],
        "fenced again, for a profile set online meanwhile"
    );

    state = tick(
        state,
        || Ok(Verdict::Intact),
        no_reinstall,
        &fence,
        &metrics,
    );
    assert_eq!(state, Watch::Intact);
    assert_eq!(fence.take(), ["lift"]);
    assert_eq!(
        metrics.count_for("kill_switch_probe_errors_total"),
        u64::from(PROBE_FAILURES_TO_FENCE) * 2,
    );
}

/// A table found gone while the watch is fenced for checks that could not
/// run is a loss like any other: fenced, reinstalled once, counted once.
#[test]
fn a_loss_found_after_unverified_checks_gets_its_reinstall() {
    let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
    let reinstalled = std::cell::Cell::new(0);
    let next = tick(
        Watch::Unverified,
        verdicts(vec![Ok(Verdict::Absent), Ok(Verdict::Intact)]),
        || {
            reinstalled.set(reinstalled.get() + 1);
            Ok(())
        },
        &fence,
        &metrics,
    );
    assert_eq!(next, Watch::Intact);
    assert_eq!(fence.take(), ["fence", "lift"]);
    assert_eq!(reinstalled.get(), 1);
    assert_eq!(lost_for(&metrics, "reinstalled"), 1);
}

/// `verify` against a real `nft`: intact as installed, drift once the
/// chain is flushed, absent once the table is deleted. Run it as
/// [`disable_against_real_nft`] says; run together, the two share the one
/// table and need `--test-threads=1`.
#[test]
#[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
fn verify_against_real_nft() {
    let installed = installed();
    apply(&installed.script()).expect("install");
    assert_eq!(verify(&installed).unwrap(), Verdict::Intact);
    exec::run_ok(
        "nft",
        &["flush", "chain", "inet", TABLE, "output"],
        None,
        exec::CHANGE,
    )
    .expect("flush the chain");
    assert!(matches!(verify(&installed).unwrap(), Verdict::Drifted(_)));
    apply(&installed.script()).expect("reinstall");
    assert_eq!(verify(&installed).unwrap(), Verdict::Intact);
    remove_table_for(998).expect("remove");
    assert_eq!(verify(&installed).unwrap(), Verdict::Absent);
}

/// #178 against a real `nft`: a tunnel holding an IPv6 address installs
/// its `ip6 saddr` fence, the live table verifies intact with it, and a
/// table without it is drift. Run it as [`disable_against_real_nft`]
/// says, with `--test-threads=1` beside the others.
#[test]
#[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
fn an_ipv6_fence_against_real_nft() {
    let installed = Installed::render(
        998,
        vec![tunnel("wg-a").with_v6([ADDR_A6])],
        vec![("wg-a".to_string(), two_peer_transport())],
    )
    .unwrap();
    assert!(
        installed
            .table
            .contains("ip6 saddr 2001:db8::2 oifname != { \"lo\", \"wg-a\" } drop"),
        "the rendered table carries the IPv6 fence: {}",
        installed.table
    );
    apply(&installed.script()).expect("install");
    // The live table matches the rendered one rule for rule, the fence
    // included; read through `verify` rather than `nft list`'s
    // pretty-printed text, whose layout differs between nft releases.
    assert_eq!(verify(&installed).unwrap(), Verdict::Intact);
    apply(&self::installed().script()).expect("install the table without it");
    assert!(matches!(verify(&installed).unwrap(), Verdict::Drifted(_)));
    remove_table_for(998).expect("remove");
}

mod props {
    use std::fmt::Debug;

    use proptest::prelude::*;
    use serde_json::json;
    use serde_json::Value;

    use super::*;

    /// The words an `nft -j` listing is made of, and anything else.
    fn word() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                "nftables", "metainfo", "table", "chain", "rule", "set", "expr", "match", "left",
                "right", "op", "meta", "key", "payload", "protocol", "field", "counter", "accept",
                "drop", "name", "type", "hook", "prio", "policy", "skuid", "oifname", "ip", "ip6",
                "udp", "saddr", "daddr", "sport", "dport", "==", "!=", TABLE, "output",
            ])
            .prop_map(str::to_owned),
            ".{0,8}",
        ]
    }

    /// Any JSON value, its keys and strings drawn mostly from [`word`].
    fn json_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::from),
            any::<i64>().prop_map(Value::from),
            any::<u64>().prop_map(Value::from),
            any::<f64>().prop_map(Value::from),
            word().prop_map(Value::from),
        ];
        leaf.prop_recursive(5, 96, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::vec((word(), inner), 0..6)
                    .prop_map(|kv| Value::Object(kv.into_iter().collect())),
            ]
        })
    }

    /// The listing of [`installed`]'s table, as nft printed it.
    fn intact() -> Value {
        serde_json::from_str(&listing(&[META, FENCE, LO, WG_A, PORT_V4, PORT_V6, DROP])).unwrap()
    }

    /// One change to one expression of one rule.
    #[derive(Clone, Debug)]
    enum Change {
        /// Remove it.
        Remove,
        /// Put an expression the kill switch never installs in its place.
        Foreign,
        /// Give its match another right-hand side, or its verdict the
        /// other verdict.
        Value(String),
        /// Turn its match's operator round.
        Op,
        /// Match on another key.
        Key,
    }

    fn change() -> impl Strategy<Value = Change> {
        prop_oneof![
            Just(Change::Remove),
            Just(Change::Foreign),
            "[0-9a-z.:-]{1,12}".prop_map(Change::Value),
            Just(Change::Op),
            Just(Change::Key),
        ]
    }

    /// `listing` with `change` made to expression `expr` of rule `rule`.
    fn changed(
        mut listing: Value,
        rule: prop::sample::Index,
        expr: prop::sample::Index,
        change: &Change,
    ) -> Value {
        let rules: Vec<usize> = (0..listing["nftables"].as_array().unwrap().len())
            .filter(|&i| listing["nftables"][i].get("rule").is_some())
            .collect();
        let exprs = listing["nftables"][rules[rule.index(rules.len())]]["rule"]["expr"]
            .as_array_mut()
            .unwrap();
        let at = expr.index(exprs.len());
        if let Change::Remove = change {
            exprs.remove(at);
            return listing;
        }
        let e = &mut exprs[at];
        match change {
            Change::Remove => unreachable!("removed above"),
            Change::Foreign => *e = json!({"jump": {"target": "elsewhere"}}),
            Change::Value(v) => {
                if let Some(m) = e.get_mut("match") {
                    let right = &mut m["right"];
                    *right = match right {
                        Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                        Value::Object(set) => {
                            // A name the set does not hold: a repeat
                            // would read back as the same set.
                            let mut set = set.clone();
                            set["set"]
                                .as_array_mut()
                                .unwrap()
                                .push(json!(format!("{v}-x")));
                            Value::Object(set)
                        }
                        Value::String(s) if *s == *v => json!(format!("{v}x")),
                        _ => json!(v),
                    };
                } else if e.get("accept").is_some() {
                    *e = json!({"drop": null});
                } else {
                    *e = json!({"accept": null});
                }
            }
            Change::Op => {
                if let Some(m) = e.get_mut("match") {
                    let op = if m["op"] == "==" { "!=" } else { "==" };
                    m["op"] = json!(op);
                } else {
                    *e = json!({"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": 998}});
                }
            }
            Change::Key => match e.get_mut("match") {
                Some(m) => m["left"] = json!({"meta": {"key": "mark"}}),
                None => *e = json!({"reject": null}),
            },
        }
        listing
    }

    /// `items` in any order, with any of them repeated.
    fn reordered<T: Clone + Debug>(items: Vec<T>) -> impl Strategy<Value = Vec<T>> {
        let n = items.len();
        prop::collection::vec(any::<prop::sample::Index>(), 0..4).prop_flat_map(move |dups| {
            let mut all = items.clone();
            if n > 0 {
                all.extend(dups.iter().map(|i| items[i.index(n)].clone()));
            }
            Just(all).prop_shuffle()
        })
    }

    fn tunnels() -> impl Strategy<Value = Vec<Tunnel>> {
        prop::collection::vec(
            (
                prop::sample::select(vec!["wg-a", "wg-b", "tun0", "wg_c.1"]),
                any::<Ipv4Addr>(),
                prop::collection::vec(any::<Ipv6Addr>(), 0..3),
            )
                .prop_map(|(iface, addr, v6)| Tunnel::new(iface, addr).with_v6(v6)),
            0..5,
        )
    }

    fn transports() -> impl Strategy<Value = Vec<Transport>> {
        prop::collection::vec(
            (
                any::<u16>(),
                prop::collection::vec(any::<SocketAddr>(), 0..3),
            )
                .prop_map(|(port, endpoints)| Transport::new(port, endpoints)),
            0..4,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Whatever `nft -j` prints, reading it back answers.
        #[test]
        fn reading_a_listing_never_panics(
            value in json_value(),
            entries in prop::collection::vec(json_value(), 0..6),
        ) {
            let _ = live_table(&value, TABLE);
            let _ = skuids(&value);
            let listing = json!({"nftables": entries});
            let _ = live_table(&listing, TABLE);
            let _ = skuids(&listing);
        }

        /// No change to any one expression of the installed table goes
        /// unseen.
        #[test]
        fn any_single_expression_change_is_drift(
            rule in any::<prop::sample::Index>(),
            expr in any::<prop::sample::Index>(),
            change in change(),
        ) {
            let json = changed(intact(), rule, expr, &change).to_string();
            let verdict = verify_listing(json.clone()).unwrap();
            prop_assert!(matches!(verdict, Verdict::Drifted(_)), "{:?}: {}", verdict, json);
        }

        /// The rendered ruleset depends on the set of tunnels and
        /// transports, not on their order or on repeats.
        #[test]
        fn rendering_ignores_order_and_repeats(
            (tunnels, tunnels2) in tunnels().prop_flat_map(|t| (Just(t.clone()), reordered(t))),
            (transports, transports2) in
                transports().prop_flat_map(|t| (Just(t.clone()), reordered(t))),
            uid in any::<u32>(),
        ) {
            prop_assert_eq!(
                render_ruleset_with_transport(uid, &tunnels, &transports).unwrap(),
                render_ruleset_with_transport(uid, &tunnels2, &transports2).unwrap(),
            );
        }

        /// An interface-name set reads back the same in any order, with
        /// any name repeated: nft lists a set as it likes.
        #[test]
        fn a_listed_name_set_reads_back_in_any_order(
            names in reordered(vec!["lo", "wg-a"]),
        ) {
            let fence = FENCE.replace(r#"["lo", "wg-a"]"#, &json!(names).to_string());
            let json = listing(&[META, &fence, LO, WG_A, PORT_V4, PORT_V6, DROP]);
            prop_assert_eq!(verify_listing(json).unwrap(), Verdict::Intact);
        }
    }
}
