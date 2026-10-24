use std::sync::Mutex;

use torrentd_engine::MockForwarder;
use torrentd_engine::MockVpn;

use super::*;

/// The transport [`FakeHost`] reports for a link listening on `port`: one
/// peer, at a documentation address.
fn fake_transport(port: u16) -> vpn::killswitch::Transport {
    vpn::killswitch::Transport::new(port, ["198.51.100.1:51820".parse().unwrap()])
}

/// A `CheckHost` with no host behind it: every answer is scripted, and the
/// tunnel manager and NAT-PMP client are the engine's recording doubles,
/// so what the checks *did* to them is assertable.
#[derive(Debug)]
struct FakeHost {
    existing: Vec<String>,
    /// Scripted answers for `interface_exists`, consumed in call order,
    /// for the case where the interface changes under the command — which
    /// is the whole of what `--bring-up` does. Empty means "answer from
    /// `existing`".
    exists_seq: Mutex<Vec<bool>>,
    addrs: Mutex<Vec<(String, Option<Ipv4Addr>)>>,
    /// Scripted `tunnel_ipv6` answers. An interface not listed has none.
    v6: Vec<(String, Vec<std::net::Ipv6Addr>)>,
    sysctls: Mutex<Vec<(String, String)>>,
    /// Every host interaction, in the order it happened, so *when* a
    /// sysctl was read relative to the raise is assertable. Shared with
    /// [`RecordingVpn`] so the raise lands in the same sequence.
    events: Arc<Mutex<Vec<String>>>,
    vpn: MockVpn,
    fwd: MockForwarder,
    /// Binaries `tool_available` should answer `false` for. Everything
    /// else is present, which is the ordinary host.
    missing_tools: Vec<String>,
    /// What `current_uid` answers.
    uid: Result<u32, String>,
    /// What `has_cap_net_admin` answers. `false` is the invocation
    /// `docs/running.md` recommends.
    privileged: bool,
    /// Scripted `nft --check` outcomes as `(exit code, stderr)`, consumed
    /// in call order. Empty means "accepted".
    nft: Mutex<Vec<(i32, String)>>,
    /// Scripted `wireguard_device` answers. An interface not listed reads
    /// as `None`, which is "neither read answered".
    wg_devices: Vec<(String, bool)>,
    /// What `handshake_age` answers for every interface. Defaults to a
    /// refusal, which is what an unprivileged `wg show` returns.
    handshake: Result<Option<Duration>, &'static str>,
    /// Scripted `listen_port` answers. An interface not listed has no
    /// port to read, which is a link that is not up.
    ports: Vec<(String, u16)>,
    /// What `route_probe` answers for every lookup. Defaults to a route by
    /// the tunnel, which is the healthy host.
    route: Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>,
    /// What `route_probe` answers for a lookup from one source, ahead of
    /// `route`.
    route_from: Vec<(
        IpAddr,
        Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>,
    )>,
}

impl FakeHost {
    fn new() -> Self {
        Self {
            existing: Vec::new(),
            exists_seq: Mutex::new(Vec::new()),
            addrs: Mutex::new(Vec::new()),
            v6: Vec::new(),
            sysctls: Mutex::new(Vec::new()),
            events: Arc::new(Mutex::new(Vec::new())),
            vpn: MockVpn::new(),
            fwd: MockForwarder::new(),
            missing_tools: Vec::new(),
            uid: Ok(2000),
            privileged: false,
            nft: Mutex::new(Vec::new()),
            wg_devices: Vec::new(),
            handshake: Err("refused"),
            ports: Vec::new(),
            route: Ok(vpn::route::RouteProbe::ViaTunnel),
            route_from: Vec::new(),
        }
    }

    /// Script what a route lookup from `src` answers.
    fn with_route_from(
        mut self,
        src: IpAddr,
        route: Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>,
    ) -> Self {
        self.route_from.push((src, route));
        self
    }

    /// Script the listen port `iface`'s link reports; its peer endpoint
    /// is [`fake_transport`]'s.
    fn with_listen_port(mut self, iface: &str, port: u16) -> Self {
        self.ports.push((iface.to_string(), port));
        self
    }

    /// Script what every route lookup answers.
    fn with_route(
        mut self,
        route: Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>,
    ) -> Self {
        self.route = route;
        self
    }

    /// Script what the `wg show <iface> latest-handshakes` probe answers.
    fn with_handshake(mut self, probe: Result<Option<Duration>, &'static str>) -> Self {
        self.handshake = probe;
        self
    }

    /// `bin` is not executable on this host.
    fn with_missing_tool(mut self, bin: &str) -> Self {
        self.missing_tools.push(bin.to_string());
        self
    }

    /// This process's effective uid, as `current_uid` reports it.
    fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Ok(uid);
        self
    }

    /// Script `nft --check`, call by call, as `(exit code, stderr)`.
    fn with_nft(self, seq: impl IntoIterator<Item = (i32, &'static str)>) -> Self {
        *self.nft.lock().unwrap() = seq.into_iter().map(|(c, e)| (c, e.to_string())).collect();
        self
    }

    /// Script what the capability-free link-type read says about `iface`.
    fn with_wireguard_device(mut self, iface: &str, is_wg: bool) -> Self {
        self.wg_devices.push((iface.to_string(), is_wg));
        self
    }

    /// `iface` is already present on the host before the command runs.
    fn with_existing(mut self, iface: &str) -> Self {
        self.existing.push(iface.to_string());
        self
    }

    /// Script `interface_exists` call by call.
    fn with_exists_seq(self, seq: impl IntoIterator<Item = bool>) -> Self {
        *self.exists_seq.lock().unwrap() = seq.into_iter().collect();
        self
    }

    /// Script a sysctl's contents. Anything not scripted reads as absent,
    /// which is what `/proc/sys/net/ipv4/conf/<iface>/rp_filter` does for
    /// an interface that is not there.
    fn with_sysctl(self, path: &str, value: &str) -> Self {
        self.sysctls
            .lock()
            .unwrap()
            .push((path.to_string(), value.to_string()));
        self
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn record(&self, what: String) {
        self.events.lock().unwrap().push(what);
    }

    /// Script what `first_ipv4(iface)` returns, call by call, so the
    /// address can change across the run the way a real bring-up or
    /// teardown changes it.
    fn with_addrs(self, seq: impl IntoIterator<Item = (&'static str, Option<Ipv4Addr>)>) -> Self {
        *self.addrs.lock().unwrap() = seq.into_iter().map(|(i, a)| (i.to_string(), a)).collect();
        self
    }

    /// Script the IPv6 addresses `iface`'s link holds.
    fn with_v6(mut self, iface: &str, addrs: &[std::net::Ipv6Addr]) -> Self {
        self.v6.push((iface.to_string(), addrs.to_vec()));
        self
    }
}

impl CheckHost for FakeHost {
    fn interface_exists(&self, iface: &str) -> bool {
        self.record(format!("interface_exists {iface}"));
        let mut g = self.exists_seq.lock().unwrap();
        if g.is_empty() {
            self.existing.iter().any(|i| i == iface)
        } else {
            g.remove(0)
        }
    }

    fn read_sysctl(&self, path: &str) -> Option<String> {
        self.record(format!("read_sysctl {path}"));
        self.sysctls
            .lock()
            .unwrap()
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, v)| v.clone())
    }

    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr> {
        let mut g = self.addrs.lock().unwrap();
        let next = if g.is_empty() {
            None
        } else {
            Some(g.remove(0))
        };
        match next {
            Some((_, Some(ip))) => Ok(ip),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no IPv4 address on {iface}"),
            )),
        }
    }

    fn tunnel_ipv6(&self, iface: &str) -> Vec<std::net::Ipv6Addr> {
        self.v6
            .iter()
            .find(|(i, _)| i == iface)
            .map(|(_, a)| a.clone())
            .unwrap_or_default()
    }

    fn manager(&self, _t: VpnType, _run_dir: &Path) -> Arc<dyn VpnManager> {
        Arc::new(RecordingVpn {
            inner: self.vpn.clone(),
            events: self.events.clone(),
        })
    }

    fn forwarder(&self) -> Arc<dyn PortForwarder> {
        Arc::new(self.fwd.clone())
    }

    fn tool_available(&self, bin: &str, probe_arg: &str) -> bool {
        self.record(format!("tool_available {bin} {probe_arg}"));
        !self.missing_tools.iter().any(|b| b == bin)
    }

    fn profile_metadata(&self, path: &Path) -> std::io::Result<()> {
        self.record(format!("profile_metadata {}", path.display()));
        Ok(())
    }

    fn handshake_age(&self, iface: &str) -> Result<Option<Duration>, &'static str> {
        self.record(format!("handshake_age {iface}"));
        self.handshake
    }

    fn current_uid(&self) -> Result<u32, String> {
        self.uid.clone()
    }

    fn has_cap_net_admin(&self) -> bool {
        self.privileged
    }

    fn nft_check(&self, ruleset: &str) -> std::io::Result<std::process::Output> {
        self.record(format!("nft_check {ruleset}"));
        let mut g = self.nft.lock().unwrap();
        if g.is_empty() {
            return Ok(nft_out(0, ""));
        }
        let (code, stderr) = g.remove(0);
        Ok(nft_out(code, &stderr))
    }

    fn wireguard_device(&self, iface: &str) -> Option<bool> {
        self.record(format!("wireguard_device {iface}"));
        self.wg_devices
            .iter()
            .find(|(i, _)| i == iface)
            .map(|(_, v)| *v)
    }

    fn transport(&self, iface: &str) -> std::io::Result<vpn::killswitch::Transport> {
        self.record(format!("transport {iface}"));
        self.ports
            .iter()
            .find(|(i, _)| i == iface)
            .map(|(_, p)| fake_transport(*p))
            .ok_or_else(|| std::io::Error::other(format!("{iface} is not up")))
    }

    fn route_probe(
        &self,
        iface: &str,
        src: IpAddr,
        dest: IpAddr,
    ) -> Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable> {
        self.record(format!("route_probe {iface} {src} {dest}"));
        self.route_from
            .iter()
            .find(|(from, _)| *from == src)
            .map_or_else(|| self.route.clone(), |(_, r)| r.clone())
    }
}

/// Build a finished `nft --check` `Output` with `code` and `stderr`.
fn nft_out(code: i32, stderr: &str) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

/// `MockVpn` with its calls recorded into `FakeHost`'s event log, so the
/// order of a raise against a host read is assertable. `MockVpn` keeps its
/// own `bring_up_calls`/`bring_down_calls` — those answer *whether*; this
/// answers *when*.
#[derive(Debug)]
struct RecordingVpn {
    inner: MockVpn,
    events: Arc<Mutex<Vec<String>>>,
}

impl VpnManager for RecordingVpn {
    fn bring_up(
        &self,
        tunnel: &torrentd_engine::VpnTunnel,
    ) -> Result<IpAddr, torrentd_engine::VpnError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("bring_up {}", tunnel.interface));
        self.inner.bring_up(tunnel)
    }

    fn current_ip(&self, iface: &str) -> Result<IpAddr, torrentd_engine::VpnError> {
        self.inner.current_ip(iface)
    }

    fn global_ipv6(
        &self,
        iface: &str,
    ) -> Result<Vec<std::net::Ipv6Addr>, torrentd_engine::VpnError> {
        self.inner.global_ipv6(iface)
    }

    fn bring_down(&self, iface: &str) {
        self.events
            .lock()
            .unwrap()
            .push(format!("bring_down {iface}"));
        self.inner.bring_down(iface);
    }
}

/// A config with one WireGuard `vpn` profile, built from TOML so a
/// required field added to `ProfileConfig` breaks this rather than letting
/// it exercise a shape the daemon never parses.
fn cfg_with_profile(extra: &str) -> Config {
    toml::from_str(&format!(
        r#"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_a"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_a"
{extra}
"#
    ))
    .expect("test config parses")
}

/// A config holding whatever `tables` spells out.
///
/// [`cfg_with_profile`] interpolates its argument *inside* the one
/// `[[profile]]` table it builds, so it can express neither a second
/// profile nor a host profile — which is why a 41-test suite was green
/// while the binary panicked on the shipped sample, and the sample ships
/// exactly one profile, `network = "host"`.
fn cfg_with_tables(tables: &str) -> Config {
    toml::from_str(&format!(
        r#"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"
{tables}
"#
    ))
    .expect("test config parses")
}

/// The shipped sample's shape: one profile, `network = "host"`.
const HOST_TABLE: &str = r#"
[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882,[::]:6882"
"#;

const VPN_TABLE: &str = r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
"#;

/// The same profile with a gateway-assigned port.
///
/// Written out rather than appended to [`cfg_with_profile`], which sets a
/// static `listen_port`: a `listen_port` under `port_forward = "natpmp"`
/// is refused now, because the gateway assigns the port at runtime and
/// nothing binds the configured one.
fn cfg_with_natpmp_profile(extra: &str) -> Config {
    cfg_with_tables(&format!(
        r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
port_forward         = "natpmp"
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_a"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_a"
{extra}
"#
    ))
}

/// `cfg_with_profile`'s config with a second vpn profile, so `--profile`
/// has something to exclude and the kill-switch table has more than one
/// interface in it.
fn cfg_with_two_profiles() -> Config {
    let mut cfg = cfg_with_profile("");
    cfg.network_kill_switch = true;
    let mut b = cfg_with_tables(
        r#"
[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-b.conf"
vpn_interface        = "wg-acct-b"
listen_port          = 6882
peer_fingerprint = "-BB1000-"
user_agent           = "Transmission/4.0.5"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_b"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_b"
"#,
    );
    cfg.profile.push(b.profile.remove(0));
    cfg
}

fn find<'a>(checks: &'a [Check], name: &str) -> Option<&'a Check> {
    checks.iter().find(|c| c.name == name)
}

#[test]
fn a_host_profile_is_skipped_rather_than_handed_to_profile_checks() {
    let cfg = cfg_with_tables(HOST_TABLE);
    let host = FakeHost::new();

    let reports = profile_reports(&cfg, None, false, None, &host)
        .expect("a host-only config is a legal config to check");

    assert_eq!(reports.len(), 1, "the profile is reported, not dropped");
    assert_eq!(reports[0].profile_id, "public");
    assert_eq!(reports[0].vpn_type, "none");
    let tunnel = find(&reports[0].checks, "tunnel")
        .expect("a host profile still gets a line, or the run reads as `checked, all clear`");
    assert_eq!(tunnel.verdict, Verdict::Skip, "detail: {}", tunnel.detail);
    assert!(
        tunnel.detail.contains("public") && tunnel.detail.contains("no tunnel"),
        "the operator has to be told why it was skipped: {}",
        tunnel.detail,
    );

    // A `skip` does not colour the status: the command exits 0 rather
    // than 101.
    let report = Report {
        host: Vec::new(),
        profiles: reports,
    };
    assert_eq!(report.exit_code(), EXIT_OK);
    assert!(!report.incomplete(), "a skip is not an unknown");
}

#[test]
fn scoping_to_a_host_profile_by_id_is_skipped_too() {
    // `--profile public` on a mixed config. The id filter is what used to
    // select the panicking profile on its own.
    let cfg = cfg_with_tables(&format!("{VPN_TABLE}{HOST_TABLE}"));
    let host = FakeHost::new();

    let reports = profile_reports(&cfg, Some("public"), false, None, &host)
        .expect("naming a host profile is not a usage error");

    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].profile_id, "public");
    assert_eq!(
        find(&reports[0].checks, "tunnel").unwrap().verdict,
        Verdict::Skip
    );
}

#[test]
fn a_mixed_config_checks_the_tunnel_and_skips_the_host() {
    // The bare invocation on a config that has both. Every profile is
    // reported, in configured order, and only the tunnelled one is
    // actually probed.
    let cfg = cfg_with_tables(&format!("{VPN_TABLE}{HOST_TABLE}"));
    let host = FakeHost::new()
        .with_existing("wg-acct-a")
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

    let reports = profile_reports(&cfg, None, false, None, &host)
        .expect("a mixed config is legal and --check-config calls it OK");

    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].profile_id, "acct_a");
    assert!(
        find(&reports[0].checks, "tunnel_ip").is_some(),
        "the vpn profile is still fully checked",
    );
    assert_eq!(reports[1].profile_id, "public");
    assert_eq!(reports[1].checks.len(), 1, "a host profile gets one line");
    assert_eq!(reports[1].checks[0].verdict, Verdict::Skip);
}

#[test]
fn bring_up_never_lowers_an_interface_it_did_not_raise() {
    // A running daemon's interface: checked, never lowered.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_existing("wg-acct-a")
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    assert!(
        host.vpn.bring_down_calls().is_empty(),
        "an adopted interface must never be brought down, got {:?}",
        host.vpn.bring_down_calls(),
    );
    assert!(
        host.vpn.bring_up_calls().is_empty(),
        "an existing interface must not be handed to bring_up either",
    );
    assert!(
        find(&r.checks, "bring_down").is_none(),
        "an adopted interface produces no bring_down line",
    );
    let bu = find(&r.checks, "bring_up").expect("a bring_up line is still reported");
    assert_eq!(bu.verdict, Verdict::Skip, "detail: {}", bu.detail);
    assert!(
        bu.detail.contains("wg-acct-a") && bu.detail.contains("already exists"),
        "the operator has to be told why it was skipped: {}",
        bu.detail,
    );
    // Adoption is not an early return: the rest of the profile is still
    // checked against the interface as it stands.
    assert!(find(&r.checks, "tunnel_ip").is_some());
}

#[test]
fn bring_up_raises_and_lowers_an_interface_that_was_not_there() {
    // Absent before the call and present after: raised here, so lowered.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
        ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
        ("wg-acct-a", None),
    ]);
    host.vpn
        .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    assert_eq!(host.vpn.bring_up_calls(), vec!["wg-acct-a"]);
    assert_eq!(host.vpn.bring_down_calls(), vec!["wg-acct-a"]);
    assert_eq!(
        find(&r.checks, "bring_up").map(|c| c.verdict),
        Some(Verdict::Pass),
    );
}

#[test]
fn without_bring_up_no_tunnel_is_touched_either_way() {
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_existing("wg-acct-a")
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

    assert!(host.vpn.bring_up_calls().is_empty());
    assert!(host.vpn.bring_down_calls().is_empty());
    assert!(find(&r.checks, "bring_up").is_none());
    assert!(find(&r.checks, "bring_down").is_none());
}

#[test]
fn a_bring_down_that_left_the_tunnel_up_is_reported_as_a_failure() {
    // The address is still there after the teardown: the host was left
    // changed, and the report must say so.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
        ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
        ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
    ]);
    host.vpn
        .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    assert_eq!(host.vpn.bring_down_calls(), vec!["wg-acct-a"]);
    let bd = find(&r.checks, "bring_down").expect("a bring_down line");
    assert_eq!(bd.verdict, Verdict::Fail, "detail: {}", bd.detail);
    assert!(
        bd.detail.contains("10.2.0.2"),
        "the address that is still there names the problem: {}",
        bd.detail,
    );
    assert!(r.failed(), "and it has to reach the exit status");
}

#[test]
fn a_bring_down_that_worked_is_reported_only_once_the_address_is_gone() {
    let cfg = cfg_with_profile("");
    let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
        ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
        ("wg-acct-a", None),
    ]);
    host.vpn
        .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    assert_eq!(
        find(&r.checks, "bring_down").map(|c| c.verdict),
        Some(Verdict::Pass),
    );
}

#[test]
fn the_default_path_leaves_its_mapping_to_expire_rather_than_deleting_it() {
    // Observe-only: the mapping is left to lapse, never deleted, since a
    // delete would remove the running daemon's forwards.
    let cfg = cfg_with_natpmp_profile("port_forward_gateway = \"10.2.0.1\"");
    let host = FakeHost::new().with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    host.fwd.push_ok(51413);

    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

    assert_eq!(
        host.fwd.call_count(),
        1,
        "exactly one negotiation, and nothing after it",
    );
    let req = host.fwd.calls()[0];
    assert_eq!(
        req.lifetime_secs,
        crate::port_forward_monitor::LEASE_SECS,
        "the pre-flight must ask for the daemon's lease, not a second copy of it",
    );
    assert_eq!(req.bind_ip, IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
    assert_eq!(
        req.internal_port,
        PortMapRequest::INTERNAL_PORT,
        "the pre-flight must send the daemon's internal port",
    );
    assert_eq!(
        req.suggested_port, 0,
        "the pre-flight holds no port, so it must suggest none",
    );

    let pf = find(&r.checks, "port_forward").expect("a port_forward line");
    assert_eq!(pf.verdict, Verdict::Pass, "detail: {}", pf.detail);
    assert!(
        pf.detail.contains("left to expire"),
        "the operator is told the mapping is left alone: {}",
        pf.detail,
    );
    assert!(
        !pf.detail.contains("released"),
        "a released mapping is the daemon's mapping: {}",
        pf.detail,
    );
}

#[test]
fn a_natpmp_profile_with_no_tunnel_address_negotiates_nothing() {
    // The gateway is only reachable through the tunnel, so with no tunnel
    // address there is nothing to negotiate from and nothing to report but
    // a skip. Checked here because it is the arm that keeps the mapping
    // call off a host that has no tunnel at all.
    let cfg = cfg_with_natpmp_profile("");
    let host = FakeHost::new();

    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

    assert_eq!(host.fwd.call_count(), 0);
    assert_eq!(
        find(&r.checks, "port_forward").map(|c| c.verdict),
        Some(Verdict::Skip),
    );
}

#[test]
fn a_report_fails_when_any_check_fails() {
    let r = Report {
        host: vec![Check::pass("a", "")],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "wireguard",
            checks: vec![Check::pass("b", ""), Check::fail("c", "")],
        }],
    };
    assert!(r.failed());
}

/// Answer one UDP datagram on loopback with `reply`, and hand back the
/// address to aim at. The same shape `vpn::natpmp`'s tests use for the
/// NAT-PMP gateway.
fn loopback_responder(reply: Vec<u8>) -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a responder");
    let addr = sock.local_addr().expect("responder address");
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        if let Ok((_, from)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&reply, from);
        }
    });
    addr
}

#[test]
fn an_egress_probe_passes_only_on_a_reply_to_its_own_query() {
    // The transaction id is the whole of what makes the reply ours. A
    // responder that echoes it is a round trip; one that does not is
    // something else on the wire, and the verdict says so rather than
    // claiming the tunnel works.
    let ours = loopback_responder(vec![0x7d, 0x0e, 0x81, 0x80]);
    let c = egress_probe(IpAddr::V4(Ipv4Addr::LOCALHOST), ours);
    assert_eq!(c.verdict, Verdict::Pass, "detail: {}", c.detail);

    let someone_else = loopback_responder(vec![0xff, 0xff, 0x81, 0x80]);
    let c = egress_probe(IpAddr::V4(Ipv4Addr::LOCALHOST), someone_else);
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(c.detail.contains("inconclusive"), "detail: {}", c.detail);
}

#[test]
fn an_egress_probe_that_cannot_bind_the_source_fails_with_the_address() {
    // Every socket in the profile is source-bound to the tunnel address, so
    // an address that cannot be bound is the whole profile failing, not just
    // this probe.
    let unbindable = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let c = egress_probe(unbindable, "127.0.0.1:53".parse().unwrap());
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(c.detail.contains("203.0.113.7"), "detail: {}", c.detail);
}

#[test]
fn an_egress_timeout_states_both_readings_and_names_the_port() {
    // No reply has two readings, and the failure names both.
    let closed = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let a = s.local_addr().unwrap();
        drop(s);
        a
    };
    let c = egress_probe(IpAddr::V4(Ipv4Addr::LOCALHOST), closed);
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(
        c.detail.contains("Two readings"),
        "the operator is handed both: {}",
        c.detail,
    );
    assert!(
        c.detail.contains(&closed.port().to_string()),
        "the port is named: {}",
        c.detail,
    );
    assert!(
        !c.detail
            .contains("has an address but is not carrying traffic"),
        "the single asserted cause is gone: {}",
        c.detail,
    );
}

#[test]
fn an_egress_check_that_was_asked_for_and_could_not_run_says_so() {
    // D7. `--egress` used to produce no line in the human report and no
    // key in the JSON when the profile had no tunnel address — a check the
    // operator explicitly asked for, silently absent.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new();

    let r = profile_checks(
        &cfg,
        &cfg.profile[0],
        false,
        Some("1.1.1.1:53".parse().unwrap()),
        &host,
    );

    let e = find(&r.checks, "egress").expect("an egress line even with no address");
    assert_eq!(e.verdict, Verdict::Skip, "detail: {}", e.detail);
    assert!(
        e.detail.contains("1.1.1.1:53") && e.detail.contains("wg-acct-a"),
        "detail: {}",
        e.detail,
    );
}

#[test]
fn no_egress_flag_means_no_egress_line() {
    let cfg = cfg_with_profile("");
    let host = FakeHost::new();
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
    assert!(find(&r.checks, "egress").is_none());
}

#[test]
fn rp_filter_is_judged_on_the_pair_the_kernel_actually_uses() {
    // The kernel takes max(conf/all, conf/<iface>): all = 0 with the
    // interface at 1 is strict.
    let c = judge_rp_filter("wg-acct-a", Some("0"), Some("1"));
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(c.detail.contains("effective 1"), "detail: {}", c.detail);
    assert!(
        c.detail.contains("wg-acct-a"),
        "the operator has to see which interface binds: {}",
        c.detail,
    );

    // The converse: all = 1 with the interface at 2 is loose and healthy,
    // and used to FAIL and take the exit code with it.
    let c = judge_rp_filter("wg-acct-a", Some("1"), Some("2"));
    assert_eq!(c.verdict, Verdict::Pass, "detail: {}", c.detail);
    assert!(c.detail.contains("effective 2"), "detail: {}", c.detail);

    // Both loose, the documented configuration.
    assert_eq!(
        judge_rp_filter("wg-acct-a", Some("2"), Some("2")).verdict,
        Verdict::Pass,
    );
    // Both strict.
    assert_eq!(
        judge_rp_filter("wg-acct-a", Some("1"), Some("1")).verdict,
        Verdict::Fail,
    );
}

#[test]
fn an_rp_filter_value_that_cannot_be_read_or_parsed_is_not_a_pass() {
    // The old `Some(v) => pass` arm passed anything that was not the
    // literal "1", nonsense included, and an interface whose sysctl is
    // absent says nothing about the interface either way.
    for (all, iface) in [
        (None, Some("2")),
        (Some("2"), None),
        (Some("banana"), Some("2")),
        (Some("2"), Some("")),
    ] {
        let c = judge_rp_filter("wg-acct-a", all, iface);
        assert_eq!(
            c.verdict,
            Verdict::Unknown,
            "all={all:?} iface={iface:?} gave {}",
            c.detail,
        );
    }
}

#[test]
fn the_kill_switch_uid_checks_do_not_pass_judgement_on_the_wrong_process() {
    // `sudo … --bring-up` is root; the daemon is not.
    let c = judge_kill_switch_uid(Some(998), Ok(0));
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(
        c.detail.contains("998") && c.detail.contains("uid 0"),
        "both uids are named: {}",
        c.detail,
    );
}

/// `--profile` scopes the kill-switch ruleset: an excluded profile's
/// interface is not dry-run, so it cannot fail a run about another.
#[test]
fn an_excluded_profile_s_interface_does_not_decide_a_scoped_run() {
    let cfg = cfg_with_two_profiles();
    let rejected = "/dev/stdin:5:39-39: Error: syntax error, unexpected string";

    let host = FakeHost::new()
        .with_nft([(0, "")])
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    host_checks(&cfg, Some(2000), Some("acct_a"), &host);
    let nft_calls: Vec<String> = host
        .events()
        .into_iter()
        .filter(|e| e.starts_with("nft_check"))
        .collect();
    assert_eq!(nft_calls.len(), 1, "{nft_calls:?}");
    assert!(
        nft_calls[0].contains("wg-acct-a") && !nft_calls[0].contains("wg-acct-b"),
        "the dry-run holds the selected profile's interface alone: {nft_calls:?}",
    );

    // A rejection of the scoped ruleset is the selected profile's.
    let host = FakeHost::new().with_nft([(1, rejected)]);
    let checks = host_checks(&cfg, Some(2000), Some("acct_a"), &host);
    let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);

    // An unscoped run dry-runs every vpn profile's interface.
    let host = FakeHost::new().with_nft([(1, rejected)]);
    let checks = host_checks(&cfg, Some(2000), None, &host);
    let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(
        c.detail.contains("wg-acct-a") && c.detail.contains("wg-acct-b"),
        "detail: {}",
        c.detail,
    );
}

#[test]
fn a_uid_mismatch_is_reported_without_colouring_the_exit_status() {
    // `--as-uid` names a uid the invoker is not, which no invocation can
    // settle, so it does not colour the status.
    let c = judge_kill_switch_uid(Some(998), Ok(2000));
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(
        c.needs_capability,
        "an unknown nothing can settle does not colour the status: {}",
        c.detail,
    );
    assert!(
        c.detail.contains("998") && c.detail.contains("2000"),
        "both uids are named: {}",
        c.detail,
    );

    // Through the report: this is the invocation `docs/running.md`
    // describes, and it has to be able to reach 0.
    let report = Report {
        host: vec![
            Check::pass("iproute2", "`ip` is available"),
            Check::pass("nftables", "`nft` is available"),
            judge_kill_switch_uid(Some(998), Ok(2000)),
        ],
        profiles: Vec::new(),
    };
    assert_eq!(
        report.exit_code(),
        EXIT_OK,
        "--as-uid from a uid that is not the subject is the expected case, not a fault",
    );

    // The uid check still answers where the answer does not depend on the
    // observer: uid 0 fails whoever asks.
    assert_eq!(
        judge_kill_switch_uid(Some(0), Ok(2000)).verdict,
        Verdict::Fail,
        "the non-colouring class does not swallow a decidable failure",
    );
}

#[test]
fn a_named_uid_of_zero_is_a_failure_whoever_is_asking() {
    // `killswitch::enable` refuses uid 0 whoever asks: a failure.
    let c = judge_kill_switch_uid(Some(0), Ok(1000));
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(
        c.detail.contains("refuses uid 0 whoever asks"),
        "the reason it is decidable without the invoker is stated: {}",
        c.detail,
    );
    assert!(
        c.detail.contains("--as-uid"),
        "and which of the two uids is being judged: {}",
        c.detail,
    );
    // It has to reach the exit status, not just the report.
    let r = Report {
        host: vec![c],
        profiles: vec![],
    };
    assert_eq!(r.exit_code(), EXIT_FAILED);

    // Every other route to subject 0 is the same failure.
    assert_eq!(judge_kill_switch_uid(Some(0), Ok(0)).verdict, Verdict::Fail);
    assert_eq!(judge_kill_switch_uid(None, Ok(0)).verdict, Verdict::Fail);
    assert_eq!(
        judge_kill_switch_uid(Some(0), Err("no Uid line".into())).verdict,
        Verdict::Fail,
    );
}

#[test]
fn an_unsettled_uid_check_no_longer_suppresses_the_ruleset_dry_run() {
    // The uid is unestablished, and the ruleset for it is still
    // dry-run: whether it parses does not depend on who asks.
    let uid = judge_kill_switch_uid(Some(998), Ok(2000));
    assert_eq!(uid.verdict, Verdict::Unknown, "detail: {}", uid.detail);
    assert_eq!(
        ruleset_subject(Some(998), Ok(2000)),
        Some(998),
        "the ruleset is rendered for the uid the operator named",
    );
    assert!(
        uid.detail.contains("still rendered and dry-run"),
        "and the operator is told the two are decoupled: {}",
        uid.detail,
    );

    // No uid named: this process's own, as before.
    assert_eq!(ruleset_subject(None, Ok(2000)), Some(2000));
    // Nothing to render for at all is the only `None`.
    assert_eq!(ruleset_subject(None, Err("no Uid line".into())), None);
    // And an unreadable invoker does not stop a named uid being judged.
    assert_eq!(
        ruleset_subject(Some(998), Err("no Uid line".into())),
        Some(998)
    );
}

#[test]
fn the_kill_switch_uid_check_still_judges_the_uid_it_is_actually_running_as() {
    assert_eq!(judge_kill_switch_uid(None, Ok(1000)).verdict, Verdict::Pass);
    assert_eq!(
        judge_kill_switch_uid(Some(1000), Ok(1000)).verdict,
        Verdict::Pass,
    );
    // uid 0 for real is still the outage `killswitch::enable` refuses.
    assert_eq!(judge_kill_switch_uid(None, Ok(0)).verdict, Verdict::Fail);
    assert_eq!(judge_kill_switch_uid(Some(0), Ok(0)).verdict, Verdict::Fail);
    // Nothing to judge at all.
    assert_eq!(
        judge_kill_switch_uid(None, Err("no Uid line".into())).verdict,
        Verdict::Unknown,
    );
}

#[test]
fn a_check_that_could_not_be_performed_does_not_exit_zero() {
    // An unknown is not a clean exit.
    let r = Report {
        host: vec![Check::pass("iproute2", ""), Check::unknown("rp_filter", "")],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "wireguard",
            checks: vec![
                Check::pass("tunnel_ip", ""),
                Check::unknown("handshake", ""),
            ],
        }],
    };
    assert!(!r.failed(), "nothing failed");
    assert!(r.incomplete());
    assert_eq!(r.exit_code(), EXIT_UNKNOWN);
}

#[test]
fn an_unknown_inside_a_profile_alone_is_enough_to_colour_the_status() {
    // The host half can be entirely clean and the profile half entirely
    // unestablished; `Report::failed` only ever looked at `Fail`, so the
    // profile half has to be reached explicitly.
    let r = Report {
        host: vec![Check::pass("iproute2", "")],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "wireguard",
            checks: vec![Check::unknown("handshake", "")],
        }],
    };
    assert_eq!(r.exit_code(), EXIT_UNKNOWN);
}

#[test]
fn a_failure_outranks_an_unknown_in_the_exit_status() {
    let r = Report {
        host: vec![Check::unknown("rp_filter", "")],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "wireguard",
            checks: vec![Check::fail("tunnel_ip", "")],
        }],
    };
    assert_eq!(r.exit_code(), EXIT_FAILED);
}

#[test]
fn a_skip_is_not_an_unknown_and_exits_clean() {
    // A NAT-PMP check on a static profile did not fail to happen; it
    // correctly did not apply. Colouring the status for it would make
    // every static deployment exit 2 forever.
    let r = Report {
        host: vec![Check::pass("iproute2", ""), Check::skip("kill_switch", "")],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "wireguard",
            checks: vec![
                Check::pass("tunnel_ip", ""),
                Check::skip("port_forward", ""),
            ],
        }],
    };
    assert!(!r.incomplete());
    assert_eq!(r.exit_code(), EXIT_OK);
}

#[test]
fn a_host_side_failure_alone_fails_the_report() {
    // The left side of `Report::failed`'s `||`, which nothing reached.
    let r = Report {
        host: vec![Check::fail("iproute2", "")],
        profiles: vec![],
    };
    assert!(r.failed());
    assert_eq!(r.exit_code(), EXIT_FAILED);
}

#[test]
fn unknown_and_skip_are_not_failures() {
    // An absent `wg` says nothing about whether the tunnel is healthy, and
    // reporting it as a failure would train an operator to ignore them.
    let r = Report {
        host: vec![Check::unknown("a", "")],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "openvpn",
            checks: vec![Check::skip("b", ""), Check::unknown("c", "")],
        }],
    };
    assert!(!r.failed());
}

#[test]
fn the_json_report_keeps_the_shape_its_consumers_parse() {
    // C7/C8. `--json` is a contract: the four verdicts are lowercase
    // strings, and the report is `host` plus `profiles`, each profile carrying
    // `profile_id`, `vpn_type` and `checks` of `name`/`verdict`/`detail`.
    // Nothing here is enforced by the type system — `#[serde(rename_all)]`
    // is one attribute away from renaming every verdict at once.
    let r = Report {
        host: vec![Check::pass("iproute2", "`ip` is available")],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "wireguard",
            checks: vec![
                Check::fail("tunnel_ip", "no address"),
                Check::skip("port_forward", "static"),
                Check::unknown("handshake", "probe unavailable"),
            ],
        }],
    };
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();

    assert_eq!(v["host"][0]["name"], "iproute2");
    assert_eq!(v["host"][0]["verdict"], "pass");
    assert_eq!(v["host"][0]["detail"], "`ip` is available");
    assert_eq!(v["profiles"][0]["profile_id"], "acct_a");
    assert_eq!(v["profiles"][0]["vpn_type"], "wireguard");
    assert_eq!(v["profiles"][0]["checks"][0]["verdict"], "fail");
    assert_eq!(v["profiles"][0]["checks"][1]["verdict"], "skip");
    assert_eq!(v["profiles"][0]["checks"][2]["verdict"], "unknown");
}

#[test]
fn every_verdict_serialises_to_its_documented_lowercase_name() {
    for (verdict, expected) in [
        (Verdict::Pass, "pass"),
        (Verdict::Fail, "fail"),
        (Verdict::Skip, "skip"),
        (Verdict::Unknown, "unknown"),
    ] {
        assert_eq!(serde_json::to_value(verdict).unwrap(), expected);
    }
}

#[test]
fn a_config_with_no_profiles_is_refused_with_an_explanation() {
    // C38. A config with no `[[profile]]` table has no tunnel to check, so
    // an empty report would read as a clean bill of health. Such a config
    // cannot start a daemon either, and the refusal says so.
    let cfg: Config = toml::from_str(
        r#"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"
"#,
    )
    .unwrap();

    let e = check(&cfg, None, false, false, None, None).unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("[[profile]]"), "got {msg}");
    assert!(msg.contains("cannot start"), "got {msg}");
}

#[test]
fn a_profile_filter_that_matches_nothing_is_refused_rather_than_reported_clean() {
    // C39. `--profile typo` used to be indistinguishable from "every profile
    // passed": no profiles selected, no failures, exit 0.
    let cfg = cfg_with_profile("");
    let e = check(&cfg, Some("acct_b"), false, false, None, None).unwrap_err();
    assert!(format!("{e:#}").contains("acct_b"), "got {e:#}");
}

#[test]
fn a_missing_tool_is_reported_rather_than_panicking() {
    assert!(!RealHost.tool_available("torrentd-definitely-not-a-binary", "--version"));
}

#[test]
fn the_client_the_check_negotiates_with_cannot_delete_on_any_branch() {
    // `NatpmpForwarder::map` can delete on one branch; the check must use
    // the probe client, which cannot (asserted in `natpmp.rs`).
    assert!(
        !RealHost::probe_forwarder().deletes_divergent_udp(),
        "the pre-flight must negotiate with a client that deletes nothing",
    );
    // And that it is still the one-shot budget, not the renewal one: the
    // check asks startup's question and deserves startup's retransmits.
    assert!(
        RealHost::probe_forwarder().deletes_divergent_udp()
            != vpn::NatpmpForwarder::for_startup().deletes_divergent_udp(),
        "the daemon's own client is unchanged and still tidies its orphan",
    );
}

#[test]
fn rp_filter_is_judged_for_the_profile_and_only_after_it_has_been_raised() {
    // `rp_filter` is per profile, and read only after `--bring-up` has
    // created the interface its sysctl belongs to.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_exists_seq([false, true])
        .with_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
        .with_sysctl("/proc/sys/net/ipv4/conf/wg-acct-a/rp_filter", "2")
        .with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", None),
        ]);
    host.vpn
        .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    let rp = find(&r.checks, "rp_filter").expect("the profile carries its own rp_filter line");
    assert_eq!(rp.verdict, Verdict::Pass, "detail: {}", rp.detail);
    assert!(
        rp.detail.contains("wg-acct-a") && rp.detail.contains("effective 2"),
        "the interface that binds is named: {}",
        rp.detail,
    );

    let events = host.events();
    let raised = events
        .iter()
        .position(|e| e == "bring_up wg-acct-a")
        .expect("the interface was raised");
    let read = events
        .iter()
        .position(|e| e == "read_sysctl /proc/sys/net/ipv4/conf/wg-acct-a/rp_filter")
        .expect("its rp_filter was read");
    assert!(
        raised < read,
        "the sysctl has to be read after the raise, or it reads as absent for the one \
             interface the run is about: {events:?}",
    );
}

#[test]
fn the_host_block_carries_no_per_profile_check_and_no_duplicate_name() {
    // The host block's check names are unique, as `--json` consumers key
    // by name.
    let cfg = cfg_with_profile("");
    let host = host_checks(&cfg, None, None, &FakeHost::new());
    assert!(
        find(&host, "rp_filter").is_none(),
        "rp_filter is per profile and belongs to the profile: {:?}",
        host.iter().map(|c| c.name).collect::<Vec<_>>(),
    );
    let mut names: Vec<&str> = host.iter().map(|c| c.name).collect();
    let before = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        before,
        "a consumer keying host[] by name has to get every check: {names:?}",
    );
}

#[test]
fn the_host_block_is_built_from_the_check_host_and_not_from_this_machine() {
    // Every host touch is scripted; the verdicts follow the script.
    let mut cfg = cfg_with_profile("");
    cfg.network_kill_switch = true;
    let host = FakeHost::new().with_uid(998).with_nft([(
        1,
        "netlink: Error: cache initialization failed: Operation not permitted",
    )]);

    let checks = host_checks(&cfg, None, None, &host);

    let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
    assert_eq!(
        names,
        vec![
            "iproute2",
            "nftables",
            "kill_switch_uid",
            "kill_switch_ruleset"
        ],
        "the host block's shape is the contract `host[]` publishes",
    );
    assert!(
        !names.contains(&"rp_filter"),
        "no per-profile check belongs in the unscoped host block: {names:?}",
    );

    // The scripted uid is the one judged, and the scripted `nft` outcome
    // is the one classified — neither came from this machine.
    let uid = find(&checks, "kill_switch_uid").expect("the uid check is reported");
    assert_eq!(uid.verdict, Verdict::Pass, "detail: {}", uid.detail);
    assert!(uid.detail.contains("998"), "detail: {}", uid.detail);
    let ruleset = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
    assert_eq!(
        ruleset.verdict,
        Verdict::Unknown,
        "detail: {}",
        ruleset.detail
    );
    assert!(ruleset.needs_capability, "detail: {}", ruleset.detail);

    // And the calls went through the seam rather than round it.
    let events = host.events();
    assert!(
        events.iter().any(|e| e.starts_with("tool_available ip"))
            && events.iter().any(|e| e.starts_with("nft_check")),
        "host_checks reaches the host only through CheckHost: {events:?}",
    );
}

/// #33: a name the renderer refuses is a `fail` naming it, reached before
/// any `nft` runs — not a ruleset handed to `nft` to reject with a line
/// number in stdin. Parsed without `Config::validate`, which would refuse
/// the name first, so this reaches the renderer's own guard.
#[test]
fn an_unrenderable_interface_fails_the_ruleset_check_without_nft() {
    let mut cfg = cfg_with_tables(
        r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg}x.conf"
vpn_interface        = "wg}x"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
"#,
    );
    cfg.network_kill_switch = true;
    let host = FakeHost::new().with_uid(998).with_nft([(0, "")]);

    let checks = host_checks(&cfg, None, None, &host);

    let ruleset = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
    assert_eq!(ruleset.verdict, Verdict::Fail, "detail: {}", ruleset.detail);
    assert!(
        ruleset.detail.contains("\"wg}x\""),
        "detail: {}",
        ruleset.detail
    );
    assert!(
        !host.events().iter().any(|e| e.starts_with("nft_check")),
        "nothing unparseable is handed to nft: {:?}",
        host.events(),
    );
}

/// #33 under `--profile`: the ruleset holds the selected profile's
/// interfaces alone, so a name the renderer refuses fails the run that
/// selects its profile and no other.
#[test]
fn a_render_refusal_fails_only_the_run_that_selects_its_profile() {
    let mut cfg = cfg_with_tables(
        r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"

[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg}x.conf"
vpn_interface        = "wg}x"
listen_port          = 6882
peer_fingerprint = "-BB1000-"
user_agent           = "Transmission/4.0.5"
"#,
    );
    cfg.network_kill_switch = true;

    // The selected profile owns the refused name: the scoped render is
    // refused as well, so the early return keeps the `fail`, and no
    // ruleset of any kind reaches nft.
    let host = FakeHost::new();
    let checks = host_checks(&cfg, Some(2000), Some("acct_b"), &host);
    let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(c.detail.contains("\"wg}x\""), "detail: {}", c.detail);
    assert!(
        !host.events().iter().any(|e| e.starts_with("nft_check")),
        "a refused scoped render hands nothing to nft: {:?}",
        host.events(),
    );
    let report = Report {
        host: checks,
        profiles: Vec::new(),
    };
    assert_ne!(
        report.exit_code(),
        EXIT_OK,
        "the selected profile's refusal decides the run"
    );

    // Only an excluded profile's name is refused: it is not in the scoped
    // ruleset at all.
    let host = FakeHost::new()
        .with_nft([(0, "")])
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    let checks = host_checks(&cfg, Some(2000), Some("acct_a"), &host);
    let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
    assert_ne!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    let nft_calls: Vec<String> = host
        .events()
        .into_iter()
        .filter(|e| e.starts_with("nft_check"))
        .collect();
    assert_eq!(
        nft_calls.len(),
        1,
        "only the scoped ruleset is dry-run: {nft_calls:?}"
    );
    assert!(
        nft_calls[0].contains("wg-acct-a") && !nft_calls[0].contains("wg}x"),
        "the dry-run ruleset holds the selected profile's interface alone: {nft_calls:?}",
    );
    let report = Report {
        host: checks,
        profiles: Vec::new(),
    };
    assert_eq!(
        report.exit_code(),
        EXIT_OK,
        "an excluded profile's refusal does not colour a scoped run"
    );
}

#[test]
fn a_bring_up_that_failed_after_raising_the_interface_lowers_it_again() {
    // A failed bring-up can leave an interface: absent before, present
    // after, so it is lowered whatever `bring_up` returned.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_exists_seq([false, true])
        .with_addrs([("wg-acct-a", None)]);
    // No `set_ip`, so MockVpn::bring_up returns BringUpTimeout — the exact
    // error both real managers produce after they have already started
    // something.

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    let bu = find(&r.checks, "bring_up").expect("a bring_up line");
    assert_eq!(bu.verdict, Verdict::Fail, "detail: {}", bu.detail);
    assert!(
        bu.detail.contains("lowering it again"),
        "the operator is told what is being done about it: {}",
        bu.detail,
    );
    assert_eq!(
        host.vpn.bring_down_calls(),
        vec!["wg-acct-a"],
        "an interface this command raised is lowered even when the raise reported failure",
    );
    assert!(
        find(&r.checks, "bring_down").is_some(),
        "and the teardown is reported, not assumed",
    );
}

#[test]
fn a_bring_up_that_failed_and_left_nothing_standing_says_what_it_cannot_see() {
    // Nothing appeared, so nothing is lowered; only OpenVPN's caveat
    // mentions a process it may have left.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new().with_exists_seq([false, false]);

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    assert!(host.vpn.bring_down_calls().is_empty());
    assert!(find(&r.checks, "bring_down").is_none());
    let bu = find(&r.checks, "bring_up").expect("a bring_up line");
    assert_eq!(bu.verdict, Verdict::Fail, "detail: {}", bu.detail);
    assert!(
        !bu.detail.contains("may have left a process running"),
        "wg-quick leaves no process, so the report must not suggest one: {}",
        bu.detail,
    );
    assert!(
        bu.detail.contains("leaves no process behind"),
        "the operator is told what was and was not left standing: {}",
        bu.detail,
    );

    // The openvpn profile, where the caveat is true and belongs.
    let mut cfg = cfg_with_profile("");
    match &mut cfg.profile[0].network {
        torrentd_engine::ProfileNetwork::Vpn { vpn_type, .. } => {
            *vpn_type = VpnType::Openvpn;
        }
        torrentd_engine::ProfileNetwork::Host { .. } => unreachable!("a vpn profile"),
    }
    let host = FakeHost::new().with_exists_seq([false, false]);

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    let bu = find(&r.checks, "bring_up").expect("a bring_up line");
    assert_eq!(bu.verdict, Verdict::Fail, "detail: {}", bu.detail);
    assert!(
        bu.detail.contains("may have left a process running")
            && bu.detail.contains("openvpn daemonises"),
        "the one thing it cannot observe is named, for the manager that can do it: {}",
        bu.detail,
    );
}

/// A tunnel whose traffic could not be routed through it did come up, and the
/// bring-up has already lowered it. For OpenVPN the report said "no tun
/// appeared … may have left a process running", which is wrong on both
/// counts; WireGuard reports the same `RoutingFailed`
/// (`vpn::wireguard`'s `raise_failed`), so it reads the same.
#[test]
fn a_tunnel_lowered_for_want_of_routing_is_reported_as_having_come_up() {
    for kind in [VpnType::Openvpn, VpnType::Wireguard] {
        let mut cfg = cfg_with_profile("");
        match &mut cfg.profile[0].network {
            torrentd_engine::ProfileNetwork::Vpn { vpn_type, .. } => {
                *vpn_type = kind;
            }
            torrentd_engine::ProfileNetwork::Host { .. } => unreachable!("a vpn profile"),
        }
        let host = FakeHost::new().with_exists_seq([false, false]);
        host.vpn.set_unroutable("wg-acct-a");

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        let bu = find(&r.checks, "bring_up").expect("a bring_up line");
        assert_eq!(bu.verdict, Verdict::Fail, "{kind:?} detail: {}", bu.detail);
        assert!(
            bu.detail.contains("came up") && bu.detail.contains("taken down again"),
            "{kind:?}: the tunnel appeared and is gone: {}",
            bu.detail,
        );
        assert!(
            !bu.detail.contains("no wg-acct-a appeared")
                && !bu.detail.contains("may have left a process running"),
            "{kind:?}: {}",
            bu.detail,
        );
        assert!(host.vpn.bring_down_calls().is_empty());
    }
}

#[test]
fn a_successful_bring_up_that_adopted_rather_than_created_is_not_lowered() {
    // `Ok` is not evidence of a raise: the re-probe decides.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_exists_seq([false, false])
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    host.vpn
        .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

    let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

    assert_eq!(
        find(&r.checks, "bring_up").map(|c| c.verdict),
        Some(Verdict::Pass),
    );
    assert!(
        host.vpn.bring_down_calls().is_empty(),
        "nothing was observed to appear, so nothing is torn down: {:?}",
        host.vpn.bring_down_calls(),
    );
}

#[test]
fn a_check_blocked_by_a_missing_capability_does_not_colour_the_exit_status() {
    // Run as the daemon's user, a healthy host exits 0.
    let r = Report {
        host: vec![
            Check::pass("iproute2", ""),
            Check::unknown_unsettleable("kill_switch_ruleset", ""),
        ],
        profiles: vec![ProfileReport {
            profile_id: "acct_a".into(),
            vpn_type: "wireguard",
            checks: vec![
                Check::pass("tunnel_ip", ""),
                Check::unknown_unsettleable("handshake", ""),
            ],
        }],
    };
    assert!(!r.failed());
    assert!(
        !r.incomplete(),
        "a capability this shell does not have is not something that could not be checked",
    );
    assert!(r.capability_bound(), "but it is still reported as such");
    assert_eq!(r.exit_code(), EXIT_OK);

    // A plain `Unknown` is untouched: an unreadable sysctl still means
    // nothing was established, and still exits 2.
    let r = Report {
        host: vec![
            Check::unknown_unsettleable("kill_switch_ruleset", ""),
            Check::unknown("rp_filter", ""),
        ],
        profiles: vec![],
    };
    assert_eq!(r.exit_code(), EXIT_UNKNOWN);

    // And a real failure still outranks both.
    let r = Report {
        host: vec![
            Check::unknown_unsettleable("handshake", ""),
            Check::fail("iproute2", ""),
        ],
        profiles: vec![],
    };
    assert_eq!(r.exit_code(), EXIT_FAILED);
}

#[test]
fn a_capability_bound_check_is_marked_in_both_renderings() {
    // It does not colour the status, so the renderings are the only place
    // an operator can learn it did not run. The JSON field is optional and
    // absent on every other check, so a consumer that does not know about
    // it sees exactly what it saw before.
    let blocked = Check::unknown_unsettleable("handshake", "no CAP_NET_ADMIN");
    assert_eq!(symbol(&blocked), "?cap");
    assert_eq!(symbol(&Check::unknown("rp_filter", "")), "?   ");
    assert_eq!(symbol(&Check::pass("iproute2", "")), "ok  ");

    let v = serde_json::to_value(&blocked).unwrap();
    assert_eq!(
        v["verdict"], "unknown",
        "the four verdict names do not change"
    );
    assert_eq!(v["needs_capability"], true);
    let ordinary = serde_json::to_value(Check::unknown("rp_filter", "")).unwrap();
    assert!(
        ordinary.get("needs_capability").is_none(),
        "the field is absent rather than false on every other check: {ordinary}",
    );
}

/// Build a `std::process::Output` for a finished `nft --check`.
fn nft_output(code: i32, stderr: &str) -> std::io::Result<std::process::Output> {
    use std::os::unix::process::ExitStatusExt;
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    })
}

#[test]
fn nft_check_is_classified_by_what_nft_reported_not_by_who_asked() {
    // nftables parses before it touches netlink, so what it reports, not
    // the capability mask, classifies the failure. Unprivileged, and nft
    // could not reach the kernel: capability-bound, the ruleset parsed.
    let c = judge_nft_check(
        nft_output(1, "netlink: konnte Cache nicht initialisieren"),
        false,
        998,
        "table inet torrentd {}",
    );
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(c.needs_capability, "detail: {}", c.detail);

    // Unprivileged, and nft rejected the ruleset: the parser's diagnostic
    // and the netlink one together.
    let c = judge_nft_check(
        nft_output(
            1,
            "/dev/stdin:5:39-39: Error: syntax error, unexpected string, expecting \
                 comma or '}'\n\t\tmeta skuid 2000 oifname { \"lo\", \"wg\"x\" } accept\n\t\t \
                 ^\nnetlink: Error: cache initialization failed: Operation not permitted",
        ),
        false,
        2000,
        "table inet torrentd {}",
    );
    assert_eq!(
        c.verdict,
        Verdict::Fail,
        "a ruleset nft will not parse is a rejection whoever asked: {}",
        c.detail,
    );
    assert!(
        !c.needs_capability,
        "a rejection is not an unknown, so it colours the status: {}",
        c.detail,
    );
    assert!(
        c.detail.contains("syntax error"),
        "nft's own words reach the operator: {}",
        c.detail,
    );

    // Privileged and rejected: a real failure, and it keeps the exit code.
    let c = judge_nft_check(
        nft_output(1, "Error: syntax error, unexpected newline"),
        true,
        998,
        "table inet torrentd {}",
    );
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(
        c.detail.contains("syntax error"),
        "nft's own words reach the operator: {}",
        c.detail,
    );

    // Privileged and nft still could not reach the kernel: the mask is
    // corroboration, not the discriminator, so what nft reported decides
    // this one too.
    let c = judge_nft_check(
        nft_output(
            1,
            "netlink: Error: cache initialization failed: Operation not permitted",
        ),
        true,
        998,
        "table inet torrentd {}",
    );
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(c.needs_capability);

    // Accepted.
    let c = judge_nft_check(nft_output(0, ""), true, 998, "table inet torrentd {}");
    assert_eq!(c.verdict, Verdict::Pass, "detail: {}", c.detail);
    assert!(
        c.detail.contains("998") && c.detail.contains("boot lists every"),
        "the uid judged and the interface-list caveat are both stated: {}",
        c.detail,
    );

    // `nft` could not be spawned at all: unknown, and *not* capability-
    // bound, because a missing binary is a real gap on a kill-switch host.
    let c = judge_nft_check(
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no nft")),
        false,
        998,
        "table inet torrentd {}",
    );
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(!c.needs_capability, "detail: {}", c.detail);
}

#[test]
fn the_capability_mask_is_read_from_the_kernel_not_guessed() {
    // CAP_NET_ADMIN is bit 12. The two masks below are a real `CapEff` for
    // a process that has it and one that does not.
    let has = "Name:\tnft\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n";
    let hasnt = "Name:\tnft\nUid:\t998\t998\t998\t998\nCapEff:\t0000000000000000\n";
    assert_eq!(cap_eff_has(has, CAP_NET_ADMIN_BIT), Some(true));
    assert_eq!(cap_eff_has(hasnt, CAP_NET_ADMIN_BIT), Some(false));
    // Exactly bit 12 and nothing adjacent.
    assert_eq!(cap_eff_has("CapEff:\t0000000000001000\n", 12), Some(true));
    assert_eq!(cap_eff_has("CapEff:\t0000000000000800\n", 12), Some(false));
    // No line, or one that cannot be parsed, classifies nothing.
    assert_eq!(cap_eff_has("Uid:\t0\t0\t0\t0\n", CAP_NET_ADMIN_BIT), None);
    assert_eq!(
        cap_eff_has("CapEff:\tnot-a-mask\n", CAP_NET_ADMIN_BIT),
        None
    );
}

#[test]
fn a_handshake_probe_refused_for_want_of_a_capability_is_told_apart_from_one_that_failed() {
    let max = Duration::from_secs(180);

    // Refused without CAP_NET_ADMIN on an interface the kernel confirms
    // *is* a WireGuard device: the capability the daemon has and this
    // shell does not. Reported, and not counted against the status.
    let c = judge_handshake("wg-acct-a", Err("refused"), max, false, Some(true));
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(c.needs_capability, "detail: {}", c.detail);
    assert!(
        c.detail.contains("CAP_NET_ADMIN"),
        "the operator is told what would settle it: {}",
        c.detail,
    );
    assert!(
        !c.detail.contains("would run this probe"),
        "the report does not predict what a process it never looked at would do: {}",
        c.detail,
    );

    // Refused *with* the capability is a real gap — `wg` cannot read it —
    // and still colours the status.
    let c = judge_handshake("wg-acct-a", Err("refused"), max, true, Some(true));
    assert_eq!(c.verdict, Verdict::Unknown);
    assert!(!c.needs_capability, "detail: {}", c.detail);

    // A missing `wg` is not a capability problem at any privilege.
    for privileged in [true, false] {
        let c = judge_handshake("wg-acct-a", Err("no_tool"), max, privileged, Some(true));
        assert_eq!(c.verdict, Verdict::Unknown);
        assert!(!c.needs_capability, "detail: {}", c.detail);
    }

    // And the verdicts that do not turn on privilege at all.
    assert_eq!(
        judge_handshake(
            "wg-acct-a",
            Ok(Some(Duration::from_secs(30))),
            max,
            false,
            Some(true),
        )
        .verdict,
        Verdict::Pass,
    );
    assert_eq!(
        judge_handshake(
            "wg-acct-a",
            Ok(Some(Duration::from_secs(300))),
            max,
            true,
            Some(true),
        )
        .verdict,
        Verdict::Fail,
    );
    let c = judge_handshake("wg-acct-a", Ok(None), max, true, Some(true));
    assert_eq!(c.verdict, Verdict::Unknown);
    assert!(
        !c.needs_capability,
        "a tunnel still coming up is not a permission problem"
    );

    // C30's missing arm. The link type could not be read at all, so the
    // refusal has two causes and the report says so rather than picking
    // one.
    let c = judge_handshake("wg-acct-a", Err("refused"), max, false, None);
    assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
    assert!(c.needs_capability, "detail: {}", c.detail);
    assert!(
        c.detail.contains("could not be read"),
        "an unread link type is disclosed, not assumed: {}",
        c.detail,
    );
}

#[test]
fn a_wireguard_profile_pointed_at_a_device_that_is_not_wireguard_fails() {
    // `wg show` refuses a non-WireGuard interface and a missing
    // permission alike; the link type, read without a capability,
    // settles which.
    let c = judge_handshake(
        "lo",
        Err("refused"),
        Duration::from_secs(180),
        false,
        Some(false),
    );
    assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    assert!(!c.needs_capability, "detail: {}", c.detail);
    assert!(
        c.detail.contains("lo"),
        "the offending interface is named: {}",
        c.detail,
    );

    // And through the whole profile: the verdict has to reach the report
    // and the exit status, not just the judge.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_existing("wg-acct-a")
        .with_wireguard_device("wg-acct-a", false)
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(127, 0, 0, 1)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
    let hs = find(&r.checks, "handshake").expect("the handshake line is still reported");
    assert_eq!(hs.verdict, Verdict::Fail, "detail: {}", hs.detail);
    let report = Report {
        host: Vec::new(),
        profiles: vec![r],
    };
    assert_eq!(
        report.exit_code(),
        EXIT_FAILED,
        "a profile whose handshake can never answer is not a clean run",
    );
}

#[test]
fn a_handshake_that_answered_outranks_the_link_type() {
    // A userspace WireGuard tunnel (`wireguard-go`, `wg-quick`'s fallback
    // without the kernel module) is a `tun` device: no DEVTYPE, and
    // `ip -d link` says `tun`. `wg show` still answers for it, and an
    // answer is `wg` itself reading WireGuard behind the interface.
    let max = Duration::from_secs(180);
    let fresh = judge_handshake(
        "wg-acct-a",
        Ok(Some(Duration::from_secs(30))),
        max,
        true,
        Some(false),
    );
    assert_eq!(fresh.verdict, Verdict::Pass, "detail: {}", fresh.detail);
    let stale = judge_handshake(
        "wg-acct-a",
        Ok(Some(Duration::from_secs(300))),
        max,
        true,
        Some(false),
    );
    assert_eq!(stale.verdict, Verdict::Fail, "detail: {}", stale.detail);
    assert!(
        !stale.detail.contains("not a WireGuard device"),
        "a stale handshake is not a misconfigured interface: {}",
        stale.detail,
    );
    let pending = judge_handshake("wg-acct-a", Ok(None), max, true, Some(false));
    assert_eq!(
        pending.verdict,
        Verdict::Unknown,
        "detail: {}",
        pending.detail
    );

    // And through the whole profile, to the exit status.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_existing("wg-acct-a")
        .with_wireguard_device("wg-acct-a", false)
        .with_handshake(Ok(Some(Duration::from_secs(30))))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(127, 0, 0, 1)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
    let hs = find(&r.checks, "handshake").expect("the handshake line is reported");
    assert_eq!(hs.verdict, Verdict::Pass, "detail: {}", hs.detail);
}

#[test]
fn a_tun_link_is_not_read_as_proof_that_the_interface_is_not_wireguard() {
    let kernel = "7: wg-acct-a: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420\n    \
                      link/none  promiscuity 0\n    wireguard addrgenmode none";
    assert_eq!(link_type_is_wireguard(kernel), Some(true));
    let userspace = "7: wg-acct-a: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420\n    \
                         link/none  promiscuity 0\n    tun type tun pi off vnet_hdr off";
    assert_eq!(link_type_is_wireguard(userspace), None);
    let loopback = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    \
                        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00";
    assert_eq!(link_type_is_wireguard(loopback), Some(false));
    // An interface merely *named* after either type answers nothing.
    assert_eq!(
        link_type_is_wireguard("4: tun: <UP> mtu 1500\n    link/ether 00:11:22:33:44:55"),
        Some(false),
    );
    assert_eq!(
        link_type_is_wireguard("4: wireguard: <UP> mtu 1500\n    link/ether 00:11:22:33:44:55"),
        Some(false),
    );
}

#[test]
fn a_profile_s_checks_reach_the_host_only_through_the_check_host() {
    // C1. Decision 32 put `host_checks` behind `CheckHost`; the per-tunnel
    // checks still stat'ed the tunnel config, ran the tool probes and the
    // handshake probe against this machine directly. Every one is scripted
    // here, and the verdicts follow the script.
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_missing_tool("wg")
        .with_handshake(Ok(Some(Duration::from_secs(10_000))))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(127, 0, 0, 1)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

    let config = find(&r.checks, "vpn_config").expect("the vpn_config line is reported");
    assert_eq!(config.verdict, Verdict::Pass, "detail: {}", config.detail);
    let wg = find(&r.checks, "wireguard_tools").expect("the wg line is reported");
    assert_eq!(wg.verdict, Verdict::Fail, "detail: {}", wg.detail);
    assert!(
        find(&r.checks, "wg_quick").is_none(),
        "the daemon never runs wg-quick, so its presence is not checked",
    );
    let hs = find(&r.checks, "handshake").expect("the handshake line is reported");
    assert_eq!(hs.verdict, Verdict::Fail, "detail: {}", hs.detail);
    assert!(hs.detail.contains("10000s"), "detail: {}", hs.detail);

    let events = host.events();
    for expected in [
        "profile_metadata /etc/wireguard/wg-acct-a.conf",
        "tool_available wg --version",
        "handshake_age wg-acct-a",
        "route_probe wg-acct-a 127.0.0.1 1.1.1.1",
    ] {
        assert!(
            events.iter().any(|e| e == expected),
            "{expected} went through the seam: {events:?}",
        );
    }
    assert!(
        !events.iter().any(|e| e.contains("wg-quick")),
        "nothing asks for wg-quick: {events:?}",
    );
}

/// The script `vpn check` dry-runs is byte-for-byte the one
/// `killswitch::enable` installs for the same uid, tunnels, addresses and
/// ports — each profile's address paired with its own interface.
#[test]
fn the_kill_switch_ruleset_renders_identically_in_vpn_check_and_at_boot() {
    let cfg = cfg_with_two_profiles();
    let addr_a = Ipv4Addr::new(10, 2, 0, 2);
    let addr_b = Ipv4Addr::new(10, 64, 0, 7);
    let addr_a6: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    let host = FakeHost::new()
        .with_addrs([("wg-acct-a", Some(addr_a)), ("wg-acct-b", Some(addr_b))])
        .with_v6("wg-acct-a", &[addr_a6])
        .with_listen_port("wg-acct-a", 51820)
        .with_listen_port("wg-acct-b", 40001);
    host_checks(&cfg, Some(998), None, &host);
    let dry_run: Vec<String> = host
        .events()
        .into_iter()
        .filter_map(|e| e.strip_prefix("nft_check ").map(str::to_string))
        .collect();
    assert_eq!(dry_run.len(), 1, "{dry_run:?}");

    let installed = std::cell::RefCell::new(String::new());
    let tunnels: Vec<String> = cfg
        .profile
        .iter()
        .filter_map(|p| p.vpn_interface().map(str::to_string))
        .collect();
    vpn::killswitch::enable_for_uid(
        998,
        &tunnels,
        |iface| {
            Ok(match iface {
                "wg-acct-a" => addr_a,
                _ => addr_b,
            })
        },
        |iface| {
            if iface == "wg-acct-a" {
                vec![addr_a6]
            } else {
                Vec::new()
            }
        },
        |iface| {
            Ok(fake_transport(match iface {
                "wg-acct-a" => 51820,
                _ => 40001,
            }))
        },
        |script| {
            *installed.borrow_mut() = script.to_string();
            Ok(())
        },
    )
    .expect("the boot path installs");
    assert_eq!(dry_run[0], *installed.borrow());
    assert!(
        dry_run[0].contains("ip saddr 10.2.0.2 oifname \"wg-acct-a\" accept")
            && dry_run[0].contains("ip6 saddr 2001:db8::2 oifname \"wg-acct-a\" accept")
            && dry_run[0].contains("ip saddr 10.64.0.7 oifname \"wg-acct-b\" accept"),
        "each profile is accepted on its own tunnel alone: {}",
        dry_run[0],
    );
}

/// A link with no address to read is left out of the dry-run, and the
/// check says so rather than accepting its interface for every address.
#[test]
fn a_tunnel_with_no_address_is_named_and_left_out_of_the_dry_run() {
    let cfg = cfg_with_two_profiles();
    let host = FakeHost::new()
        .with_nft([(0, "")])
        .with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-b", None),
        ])
        .with_listen_port("wg-acct-a", 51820)
        .with_listen_port("wg-acct-b", 40001);
    let checks = host_checks(&cfg, Some(998), None, &host);
    let dry_run: Vec<String> = host
        .events()
        .into_iter()
        .filter_map(|e| e.strip_prefix("nft_check ").map(str::to_string))
        .collect();
    assert_eq!(dry_run.len(), 1, "{dry_run:?}");
    assert!(
        dry_run[0].contains("oifname \"wg-acct-a\"") && !dry_run[0].contains("wg-acct-b"),
        "{}",
        dry_run[0]
    );
    let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
    assert!(
        c.detail
            .contains("no tunnel address could be read for wg-acct-b"),
        "detail: {}",
        c.detail
    );
}

/// The route the monitor probes is reported, and a route that leaves by
/// another device fails both the route line and the monitor's verdict.
#[test]
fn a_route_that_does_not_leave_by_the_tunnel_fails_the_route_and_the_health_verdict() {
    let cfg = cfg_with_profile("");
    let host = FakeHost::new()
        .with_handshake(Ok(Some(Duration::from_secs(5))))
        .with_route(Ok(vpn::route::RouteProbe::Elsewhere(
            "leaves by eth0".to_string(),
        )))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
    let route = find(&r.checks, "route").expect("the route line is reported");
    assert_eq!(route.verdict, Verdict::Fail, "detail: {}", route.detail);
    let health = find(&r.checks, "health").expect("the monitor's verdict is reported");
    assert_eq!(health.verdict, Verdict::Fail, "detail: {}", health.detail);
    assert!(
        health.detail.contains("route_mismatch"),
        "{}",
        health.detail
    );

    let healthy = FakeHost::new()
        .with_handshake(Ok(Some(Duration::from_secs(5))))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &healthy);
    let health = find(&r.checks, "health").expect("the monitor's verdict is reported");
    assert_eq!(health.verdict, Verdict::Pass, "detail: {}", health.detail);
}

/// #534: the route line asks what the monitor asks, from each global
/// IPv6 address too. With the IPv4 route by the tunnel and the IPv6 one
/// leaving by eth0, the monitor fences `route_mismatch`, so the route
/// and health lines fail, naming the IPv6 source. Ask from the IPv4
/// address alone and both lines pass, which is the first assertion
/// failing.
#[test]
fn an_ipv6_route_leaving_by_another_device_fails_the_route_and_the_health_verdict() {
    let cfg = cfg_with_profile("");
    let v6: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
    let leaking = FakeHost::new()
        .with_handshake(Ok(Some(Duration::from_secs(5))))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))])
        .with_v6("wg-acct-a", &[v6])
        .with_route_from(
            IpAddr::V6(v6),
            Ok(vpn::route::RouteProbe::Elsewhere(
                "leaves by eth0".to_string(),
            )),
        );
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &leaking);
    let route = find(&r.checks, "route").expect("the route line is reported");
    assert_eq!(route.verdict, Verdict::Fail, "detail: {}", route.detail);
    assert!(
        route
            .detail
            .contains("from fd00::2 to 2606:4700:4700::1111 does not leave"),
        "{}",
        route.detail
    );
    let health = find(&r.checks, "health").expect("the monitor's verdict is reported");
    assert_eq!(health.verdict, Verdict::Fail, "detail: {}", health.detail);
    assert!(
        health.detail.contains("route_mismatch"),
        "{}",
        health.detail
    );
    let probes: Vec<String> = leaking
        .events()
        .into_iter()
        .filter(|e| e.starts_with("route_probe "))
        .collect();
    assert_eq!(
        probes,
        [
            "route_probe wg-acct-a 10.2.0.2 1.1.1.1",
            "route_probe wg-acct-a fd00::2 2606:4700:4700::1111",
        ],
        "the IPv4 address first, each toward its own family's destination",
    );

    // Both by the tunnel: one passing line naming both questions.
    let healthy = FakeHost::new()
        .with_handshake(Ok(Some(Duration::from_secs(5))))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))])
        .with_v6("wg-acct-a", &[v6]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &healthy);
    let route = find(&r.checks, "route").expect("the route line is reported");
    assert_eq!(route.verdict, Verdict::Pass, "detail: {}", route.detail);
    assert_eq!(
        route.detail,
        "a packet from 10.2.0.2 to 1.1.1.1 and from fd00::2 to 2606:4700:4700::1111 \
             leaves by wg-acct-a"
    );
    let health = find(&r.checks, "health").expect("the monitor's verdict is reported");
    assert_eq!(health.verdict, Verdict::Pass, "detail: {}", health.detail);

    // An IPv4 route that already leaves is the answer; IPv6 is not asked.
    let v4_leaks = FakeHost::new()
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))])
        .with_v6("wg-acct-a", &[v6])
        .with_route(Ok(vpn::route::RouteProbe::Elsewhere(
            "leaves by eth0".to_string(),
        )));
    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &v4_leaks);
    let route = find(&r.checks, "route").expect("the route line is reported");
    assert!(
        route.detail.contains("from 10.2.0.2 to 1.1.1.1"),
        "{}",
        route.detail
    );
    assert!(
        !v4_leaks.events().iter().any(|e| e.contains("fd00::2")),
        "{:?}",
        v4_leaks.events()
    );
}

/// #534: an IPv4 route by the tunnel followed by an IPv6 probe that
/// could not run is the probe's answer, as it is for the monitor
/// (`vpn_monitor::route_probe` stops at the first answer not by the
/// tunnel). The route line is `unknown`, not a pass naming the IPv4 pair,
/// and the health observation carries no route, so the monitor's verdict
/// does not fence on it. Skip the unavailable answer and the route line
/// passes, which is the first assertion failing.
#[test]
fn an_ipv6_route_probe_that_cannot_run_leaves_the_route_unknown_and_the_health_unfenced() {
    let cfg = cfg_with_profile("");
    let v6: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
    let host = FakeHost::new()
        .with_handshake(Ok(Some(Duration::from_secs(5))))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))])
        .with_v6("wg-acct-a", &[v6])
        .with_route_from(
            IpAddr::V6(v6),
            Err(vpn::route::RouteProbeUnavailable::NoTool),
        );

    let (route, answer) = judge_routes(
        &host,
        "wg-acct-a",
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2))),
    );
    assert_eq!(route.verdict, Verdict::Unknown, "detail: {}", route.detail);
    assert_eq!(
        answer,
        Some(Err(vpn::route::RouteProbeUnavailable::NoTool)),
        "the unavailable IPv6 answer is the answer, not the IPv4 pass before it",
    );
    assert_eq!(
        answer.and_then(Result::ok),
        None,
        "the health observation gets no route, as the monitor's does",
    );

    let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
    let route = find(&r.checks, "route").expect("the route line is reported");
    assert_eq!(route.verdict, Verdict::Unknown, "detail: {}", route.detail);
    let health = find(&r.checks, "health").expect("the monitor's verdict is reported");
    assert_eq!(health.verdict, Verdict::Pass, "detail: {}", health.detail);
}

/// `--egress` asserts the route before it trusts a reply: a round trip
/// that went out of the physical interface is not evidence the tunnel
/// carries traffic, so it is not attempted.
#[test]
fn egress_asserts_the_route_to_its_destination_before_the_round_trip() {
    let cfg = cfg_with_profile("");
    let dest: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let host = FakeHost::new()
        .with_route(Ok(vpn::route::RouteProbe::Elsewhere(
            "leaves by eth0".to_string(),
        )))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, Some(dest), &host);
    let route = find(&r.checks, "egress_route").expect("the egress route is asserted");
    assert_eq!(route.verdict, Verdict::Fail, "detail: {}", route.detail);
    let egress = find(&r.checks, "egress").expect("the egress line is still reported");
    assert_eq!(egress.verdict, Verdict::Skip, "detail: {}", egress.detail);
    assert!(
        host.events()
            .iter()
            .any(|e| e == "route_probe wg-acct-a 10.2.0.2 192.0.2.53"),
        "the route is asked for the probe's own destination: {:?}",
        host.events(),
    );
}

/// A route probe that could not run says nothing about where the route
/// goes, and the skipped round trip says so instead of claiming the route
/// does not leave by the tunnel.
#[test]
fn an_egress_route_that_could_not_be_asked_is_not_called_a_wrong_route() {
    let cfg = cfg_with_profile("");
    let dest: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let host = FakeHost::new()
        .with_route(Err(vpn::route::RouteProbeUnavailable::NoTool))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, Some(dest), &host);
    let route = find(&r.checks, "egress_route").expect("the egress route line");
    assert_eq!(route.verdict, Verdict::Unknown, "detail: {}", route.detail);
    let egress = find(&r.checks, "egress").expect("the egress line");
    assert_eq!(egress.verdict, Verdict::Skip, "detail: {}", egress.detail);
    assert!(
        egress.detail.contains("could not be asked")
            && !egress.detail.contains("does not leave by"),
        "detail: {}",
        egress.detail,
    );
}

/// An IPv6 `--egress` destination from an IPv4 tunnel address is a family
/// mismatch, and is reported as one. `ip route get <v6> from <v4>` fails,
/// and that failure was reported as a missing or outranked tunnel rule.
#[test]
fn an_egress_destination_of_the_other_family_is_reported_as_such() {
    let cfg = cfg_with_profile("");
    let dest: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
    let host = FakeHost::new()
        .with_route(Ok(vpn::route::RouteProbe::Elsewhere(
            "RTNETLINK answers: Invalid argument".to_string(),
        )))
        .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
    let r = profile_checks(&cfg, &cfg.profile[0], false, Some(dest), &host);
    let route = find(&r.checks, "egress_route").expect("the egress route line");
    assert_eq!(route.verdict, Verdict::Fail, "detail: {}", route.detail);
    assert!(
        route.detail.contains("address family") && !route.detail.contains("outranked"),
        "detail: {}",
        route.detail,
    );
    assert!(
        !host.events().iter().any(|e| e.ends_with("2001:db8::53")),
        "no route is asked across families: {:?}",
        host.events(),
    );
    let egress = find(&r.checks, "egress").expect("the egress line");
    assert_eq!(egress.verdict, Verdict::Skip, "detail: {}", egress.detail);
}
