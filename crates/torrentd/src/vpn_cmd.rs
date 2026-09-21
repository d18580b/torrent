//! `torrentd vpn check` — verify a slot's VPN configuration against the real
//! host, with no libtorrent session, no torrents and no tracker contact.
//!
//! Every other way of exercising this code needs a fully configured daemon: a
//! pool, a torrent library, real payload, and an operator watching `/slots` for
//! thirty seconds to see whether the health monitor fences anything. That
//! conflates two independent things — "does my VPN configuration work" and
//! "does my seeding setup work" — and it is the first of those that has to be
//! true before the second is worth testing.
//!
//! The checks are ordered the way the daemon performs them at boot, so the
//! first failure here is the first failure the daemon would hit.
//!
//! Observe-only by default. Nothing in the default path mutates host state:
//! it reads interfaces, reads `wg` output, and — for a NAT-PMP slot — asks the
//! gateway for a mapping with a short lease and lets that lease lapse. That
//! changes no state the daemon depends on.
//!
//! `--bring-up` opts into raising tunnels, which is the one thing here that
//! changes the machine. It lowers again **only** what it raised: an interface
//! that already existed when the command started belongs to something else —
//! usually a running daemon — and is reported, checked, and left alone.
//!
//! The exit status carries three values, because a `mise` task or a systemd
//! `ExecStartPre` reads the status and never the report: `0` clean, `1` for any
//! failure, `2` for "nothing failed, but at least one check could not be
//! performed". See [`Report::exit_code`].

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use torrentd_engine::SlotConfig;
use torrentd_engine::VpnManager;
use torrentd_engine::VpnType;

use crate::config::Config;
use crate::vpn;

/// How long an egress probe waits before calling the tunnel unusable.
const EGRESS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Fail,
    /// Correctly configured to not apply — a NAT-PMP check on a static slot,
    /// a handshake check on OpenVPN. Distinct from `Pass` so a summary cannot
    /// read as "everything was verified" when most of it was skipped.
    Skip,
    /// The check could not be performed. Not the same as failing: an absent
    /// `wg` binary says nothing about whether the tunnel is healthy, and
    /// reporting it as a failure would train an operator to ignore failures.
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Pass,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Fail,
            detail: detail.into(),
        }
    }
    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Skip,
            detail: detail.into(),
        }
    }
    fn unknown(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Unknown,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SlotReport {
    pub slot_id: String,
    pub vpn_type: &'static str,
    pub checks: Vec<Check>,
}

impl SlotReport {
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Fail)
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub host: Vec<Check>,
    pub slots: Vec<SlotReport>,
}

/// Everything was established, and everything established was good.
pub const EXIT_OK: i32 = 0;
/// At least one check failed.
pub const EXIT_FAILED: i32 = 1;
/// Nothing failed, but at least one check could not be performed.
pub const EXIT_UNKNOWN: i32 = 2;

impl Report {
    pub fn failed(&self) -> bool {
        self.host.iter().any(|c| c.verdict == Verdict::Fail)
            || self.slots.iter().any(SlotReport::failed)
    }

    fn checks(&self) -> impl Iterator<Item = &Check> {
        self.host
            .iter()
            .chain(self.slots.iter().flat_map(|s| &s.checks))
    }

    /// Whether any check could not be performed at all.
    pub fn incomplete(&self) -> bool {
        self.checks().any(|c| c.verdict == Verdict::Unknown)
    }

    /// The exit status this report implies.
    ///
    /// The four-valued verdict exists so a green summary cannot quietly mean
    /// "mostly not checked" — but the exit status is the only part of this
    /// report a `mise` task or a systemd `ExecStartPre` ever sees, and
    /// collapsing `unknown` into success asserted in one byte exactly what the
    /// four values were introduced to avoid. A run where `rp_filter` is
    /// unreadable, `wg-quick --help` exits non-zero and `wg show` is refused
    /// for want of permission established nothing about the handshake half and
    /// exited 0.
    ///
    /// `Skip` is not `Unknown`: a NAT-PMP check on a static slot did not fail
    /// to happen, it correctly did not apply, and it does not colour the
    /// status.
    pub fn exit_code(&self) -> i32 {
        if self.failed() {
            EXIT_FAILED
        } else if self.incomplete() {
            EXIT_UNKNOWN
        } else {
            EXIT_OK
        }
    }
}

/// Whether `bin` can be executed at all.
fn tool_available(bin: &str, probe_arg: &str) -> bool {
    std::process::Command::new(bin)
        .arg(probe_arg)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The host-touching operations a slot's checks perform, behind a trait so the
/// branch structure around them is testable without a tunnel or a gateway.
///
/// Two of those branches are the reason this exists rather than being inlined:
/// whether `--bring-up` tears an interface down, and whether the NAT-PMP
/// negotiation releases what it mapped. Both are decisions about somebody
/// else's live daemon, and a decision that can only be exercised on a host
/// with a real tunnel is a decision nothing can hold in place.
pub trait CheckHost {
    /// Whether the kernel already has this interface.
    ///
    /// Deliberately not `first_ipv4`: an interface that exists with no address
    /// is still an interface this command did not create, and tearing it down
    /// is still somebody else's outage.
    fn interface_exists(&self, iface: &str) -> bool;

    /// The address the daemon would bind every socket in this slot to.
    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr>;

    /// The tunnel manager for a slot's VPN type.
    fn manager(&self, t: VpnType, run_dir: &Path) -> Arc<dyn VpnManager>;

    /// A NAT-PMP client configured the way startup configures its own.
    ///
    /// The return type is the whole port-forward surface these checks can
    /// reach, and `PortForwarder` carries `map` and nothing else. Releasing a
    /// mapping is therefore not expressible here — which is the point of the
    /// trait rather than an accident of it.
    fn forwarder(&self) -> Arc<dyn PortForwarder>;
}

/// `CheckHost` against the actual machine.
#[derive(Debug, Clone, Copy)]
pub struct RealHost;

impl CheckHost for RealHost {
    fn interface_exists(&self, iface: &str) -> bool {
        // The kernel's own list. `ip link show` would answer the same question
        // through a subprocess whose absence we already report separately.
        Path::new("/sys/class/net").join(iface).exists()
    }

    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr> {
        vpn::first_ipv4(iface)
    }

    fn manager(&self, t: VpnType, run_dir: &Path) -> Arc<dyn VpnManager> {
        vpn::for_type(t, run_dir)
    }

    fn forwarder(&self) -> Arc<dyn PortForwarder> {
        Arc::new(vpn::NatpmpForwarder::for_startup())
    }
}

/// Checks that are about the host, not any one slot.
fn host_checks(cfg: &Config) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(if tool_available("ip", "-V") {
        Check::pass("iproute2", "`ip` is available")
    } else {
        Check::fail(
            "iproute2",
            "`ip` is not executable; every tunnel IP lookup in the daemon shells out to it",
        )
    });

    // rp_filter in strict mode drops the replies to a source-bound socket, so
    // a multi-slot daemon looks like a tunnel that connects and carries no
    // traffic. docs/running.md calls for 2 (loose).
    let rp = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")
        .ok()
        .map(|s| s.trim().to_string());
    out.push(match rp.as_deref() {
        Some("1") => Check::fail(
            "rp_filter",
            "net.ipv4.conf.all.rp_filter = 1 (strict): replies to tunnel-bound sockets are \
             dropped by the kernel. Set it to 2.",
        ),
        Some(v) => Check::pass("rp_filter", format!("net.ipv4.conf.all.rp_filter = {v}")),
        None => Check::unknown(
            "rp_filter",
            "could not read /proc/sys/net/ipv4/conf/all/rp_filter",
        ),
    });

    if cfg.network_kill_switch {
        out.push(if vpn::killswitch::nft_available() {
            Check::pass("nftables", "`nft` is available")
        } else {
            Check::fail(
                "nftables",
                "network_kill_switch = true but `nft` is not executable",
            )
        });
        out.push(match vpn::killswitch::current_uid() {
            Ok(0) => Check::fail(
                "kill_switch_uid",
                "running as uid 0: the kill-switch ruleset confines the daemon's uid to \
                 loopback and its tunnels, which as root would drop every root-owned \
                 process's traffic on this host",
            ),
            Ok(uid) => Check::pass("kill_switch_uid", format!("running as uid {uid}")),
            Err(e) => Check::unknown(
                "kill_switch_uid",
                format!("could not read our own uid: {e}"),
            ),
        });
        if let Ok(uid) = vpn::killswitch::current_uid() {
            let tunnels: Vec<String> = cfg.slot.iter().map(|s| s.vpn_interface.clone()).collect();
            out.push(Check::pass(
                "kill_switch_ruleset",
                format!(
                    "would install:\n{}",
                    vpn::killswitch::render_ruleset(uid, &tunnels)
                ),
            ));
        }
    } else {
        out.push(Check::skip("kill_switch", "network_kill_switch = false"));
    }

    out
}

/// Prove that a socket **bound to the tunnel address** can send and receive.
///
/// This is the check that distinguishes a tunnel which exists from a tunnel
/// which works, and it is the same question the daemon asks implicitly of
/// every slot: `outgoing_interfaces` is pinned to the tunnel IP, so if traffic
/// cannot leave from that source address the slot connects to no peers and
/// announces to no tracker, while looking perfectly healthy to the IP-presence
/// check.
///
/// A source-bound UDP round trip is used rather than a TCP connect because
/// `std::net` offers no way to set the source address on an outbound TCP
/// connection — `TcpStream::connect` picks it from the routing table, which
/// would test the default route and not the tunnel at all. `UdpSocket::bind`
/// followed by `connect` does bind the source, which is exactly how
/// `vpn::natpmp` talks to the gateway.
///
/// The payload is a DNS query because every resolver answers one and the reply
/// is trivially identifiable, not because the daemon resolves anything this
/// way.
fn egress_probe(src: IpAddr, dest: SocketAddr) -> Check {
    let sock = match std::net::UdpSocket::bind(SocketAddr::new(src, 0)) {
        Ok(s) => s,
        Err(e) => {
            return Check::fail(
                "egress",
                format!(
                    "cannot bind a UDP socket to the tunnel address {src}: {e}. Every socket \
                     in this slot would fail the same way."
                ),
            )
        }
    };
    if let Err(e) = sock.set_read_timeout(Some(EGRESS_TIMEOUT)) {
        return Check::unknown("egress", format!("could not set a read timeout: {e}"));
    }
    if let Err(e) = sock.connect(dest) {
        return Check::fail("egress", format!("cannot reach {dest} from {src}: {e}"));
    }

    // Minimal DNS query: header + QNAME + QTYPE(A) + QCLASS(IN).
    const TXID: u16 = 0x7d0e;
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&TXID.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // 1 question
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answer/authority/additional
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    if let Err(e) = sock.send(&q) {
        return Check::fail("egress", format!("send from {src} to {dest} failed: {e}"));
    }
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        Ok(n) if n >= 2 && buf[0..2] == TXID.to_be_bytes() => Check::pass(
            "egress",
            format!("{src} -> {dest} round trip succeeded ({n} bytes)"),
        ),
        Ok(n) => Check::unknown(
            "egress",
            format!("{n} bytes came back from {dest} but not our query; treat as inconclusive"),
        ),
        Err(e) => Check::fail(
            "egress",
            format!(
                "no reply from {dest} within {}s on a socket bound to {src}: {e}. The tunnel \
                 has an address but is not carrying traffic.",
                EGRESS_TIMEOUT.as_secs()
            ),
        ),
    }
}

fn slot_checks(
    cfg: &Config,
    slot: &SlotConfig,
    bring_up: bool,
    egress: Option<SocketAddr>,
    host: &dyn CheckHost,
) -> SlotReport {
    let mut checks = Vec::new();
    let iface = slot.vpn_interface.as_str();

    // 1. The profile the daemon would hand to wg-quick / openvpn.
    checks.push(match std::fs::metadata(&slot.vpn_profile) {
        Ok(_) => Check::pass(
            "profile",
            format!("{} is readable", slot.vpn_profile.display()),
        ),
        Err(e) => Check::fail("profile", format!("{}: {e}", slot.vpn_profile.display())),
    });

    // 2. The tools that slot's type needs.
    match slot.vpn_type {
        VpnType::Wireguard => {
            checks.push(if tool_available("wg", "--version") {
                Check::pass("wireguard_tools", "`wg` is available")
            } else {
                Check::fail(
                    "wireguard_tools",
                    "`wg` is not executable: the handshake half of the health monitor \
                     cannot run, and the daemon would fall back to IP presence alone",
                )
            });
            checks.push(if tool_available("wg-quick", "--help") {
                Check::pass("wg_quick", "`wg-quick` is available")
            } else {
                Check::unknown("wg_quick", "`wg-quick --help` did not exit cleanly")
            });
        }
        VpnType::Openvpn => {
            checks.push(if tool_available("openvpn", "--version") {
                Check::pass("openvpn", "`openvpn` is available")
            } else {
                Check::fail("openvpn", "`openvpn` is not executable")
            });
        }
    }

    // 3. Optionally raise the tunnel, exactly as boot would — but only if it
    //    is not already there.
    //
    //    `wg-quick up` refuses an interface that already exists, and the
    //    adoption path in `vpn::wireguard` then matches the profile's public
    //    key and returns the address anyway. So a running daemon's tunnel used
    //    to be reported as "came up" having been created by nothing, and the
    //    unconditional teardown below then ran the same `wg-quick down` the
    //    daemon's own shutdown uses. The slot went down, `vpn_monitor` fenced
    //    it within 30s, and nothing re-raised it: a diagnostic command took a
    //    live seeding slot out until someone restarted the daemon.
    //
    //    An interface that was already there is adopted for every remaining
    //    check and never lowered. That also leaves the flag useful for the
    //    case it exists for — a crash-orphaned interface is still raised and
    //    still checked.
    let manager = host.manager(slot.vpn_type, &cfg.state_dir());
    let mut raised_here = false;
    if bring_up {
        if host.interface_exists(iface) {
            checks.push(Check::skip(
                "bring_up",
                format!(
                    "{iface} already exists — not raised by this command, and it will not be \
                     taken down. Every check below runs against it as it stands."
                ),
            ));
        } else {
            match manager.bring_up(&slot.vpn_profile()) {
                Ok(ip) => {
                    raised_here = true;
                    checks.push(Check::pass("bring_up", format!("tunnel came up on {ip}")));
                }
                Err(e) => {
                    checks.push(Check::fail("bring_up", format!("{e}")));
                    return SlotReport {
                        slot_id: slot.id.as_str().to_string(),
                        vpn_type: vpn_type_str(slot.vpn_type),
                        checks,
                    };
                }
            }
        }
    }

    // 4. The address the daemon would bind every socket in this slot to.
    let tunnel_ip = match host.first_ipv4(iface) {
        Ok(v4) => {
            checks.push(Check::pass("tunnel_ip", format!("{iface} has {v4}")));
            Some(IpAddr::V4(v4))
        }
        Err(e) => {
            checks.push(Check::fail(
                "tunnel_ip",
                format!(
                    "{iface} has no IPv4 address: {e}{}",
                    if bring_up {
                        ""
                    } else {
                        " (re-run with --bring-up to raise it)"
                    }
                ),
            ));
            None
        }
    };

    // 5. Handshake liveness — the same probe and the same threshold the health
    //    monitor applies every 30 seconds.
    match slot.vpn_type {
        VpnType::Wireguard => {
            let max = Duration::from_secs(cfg.vpn_handshake_max_age_secs);
            match vpn::wireguard_handshake_age(iface) {
                Ok(Some(age)) if age <= max => checks.push(Check::pass(
                    "handshake",
                    format!(
                        "last handshake {}s ago (threshold {}s)",
                        age.as_secs(),
                        max.as_secs()
                    ),
                )),
                Ok(Some(age)) => checks.push(Check::fail(
                    "handshake",
                    format!(
                        "last handshake {}s ago, over the {}s threshold: the daemon would \
                         fence this slot",
                        age.as_secs(),
                        max.as_secs()
                    ),
                )),
                Ok(None) => checks.push(Check::unknown(
                    "handshake",
                    "no peer has handshaked yet; the tunnel may still be coming up",
                )),
                Err(why) => checks.push(Check::unknown(
                    "handshake",
                    format!(
                        "probe unavailable ({}); the daemon would run on IP presence alone",
                        why.as_str()
                    ),
                )),
            }
        }
        VpnType::Openvpn => {
            checks.push(Check::skip(
                "handshake",
                "no cheap liveness probe for openvpn",
            ));
        }
    }

    // 6. Port forwarding, against the real gateway.
    //
    //    The mapping is left to expire rather than deleted. NAT-PMP's delete
    //    is the RFC 6886 §3.4 wildcard form — internal port 0, lifetime 0 —
    //    and it cannot be narrowed: it removes *every* mapping held by the
    //    requesting address, which over a tunnel the daemon is already using
    //    means that daemon's live TCP and UDP forwards. The daemon does not
    //    notice for up to a renewal interval, during which no new inbound peer
    //    can connect; if the gateway then hands back a different port the
    //    renewal churns the listen sockets and leaves a stale port advertised
    //    to trackers until the next reannounce.
    //
    //    Asking for the same short lease the daemon asks for costs nothing and
    //    is safe for the opposite reason: this is the same NAT-PMP client
    //    identity, so the gateway may legitimately answer with the port the
    //    daemon already holds, and that is a refreshed lease rather than a
    //    destroyed mapping.
    match slot.port_forward {
        PortForwardMode::Static => {
            checks.push(Check::skip(
                "port_forward",
                format!("static listen_port {:?}", slot.listen_port),
            ));
        }
        PortForwardMode::Natpmp => match (
            tunnel_ip,
            slot.port_forward_gateway_or_default().parse::<IpAddr>(),
        ) {
            (Some(bind_ip), Ok(gateway)) => {
                let lease = crate::port_forward_monitor::LEASE_SECS;
                let req = PortMapRequest {
                    gateway,
                    bind_ip,
                    internal_port: 0,
                    // The daemon's own lease. `LEASE_SECS` is public so both
                    // paths agree; re-deriving it here would silently move the
                    // pre-flight out of step with the daemon the first time
                    // anyone changed it.
                    lifetime_secs: lease,
                };
                match host.forwarder().map(&req) {
                    Ok(m) => {
                        checks.push(Check::pass(
                            "port_forward",
                            format!(
                                "gateway {gateway} offered port {}; its {lease}s lease is left \
                                 to expire, not deleted",
                                m.port,
                            ),
                        ));
                    }
                    Err(e) => checks.push(Check::fail(
                        "port_forward",
                        format!("NAT-PMP against {gateway} failed: {e}"),
                    )),
                }
            }
            (None, _) => checks.push(Check::skip(
                "port_forward",
                "skipped: no tunnel address to negotiate from",
            )),
            (_, Err(e)) => checks.push(Check::fail(
                "port_forward",
                format!("port_forward_gateway is not an IP address: {e}"),
            )),
        },
    }

    // 7. Optional reachability probe.
    if let (Some(src), Some(dest)) = (tunnel_ip, egress) {
        checks.push(egress_probe(src, dest));
    }

    // 8. Lower only what step 3 raised. An adopted interface is left exactly
    //    as it was found, and produces no `bring_down` line at all.
    //
    //    `VpnManager::bring_down` returns `()` and, per its own contract,
    //    swallows its errors to the log — so reporting a pass straight after
    //    calling it reported the one host mutation this command advertises
    //    without ever looking at it. `wg-quick down` can fail: the interface
    //    is busy, the profile moved, `wg-quick` is not on this uid's PATH.
    //    Look at the address instead.
    if raised_here {
        manager.bring_down(iface);
        checks.push(match host.first_ipv4(iface) {
            Err(_) => Check::pass(
                "bring_down",
                format!("{iface} no longer has an address; the host is as it was found"),
            ),
            Ok(ip) => Check::fail(
                "bring_down",
                format!(
                    "{iface} still has {ip} after bring_down: this command raised the tunnel \
                     and could not lower it again, so the host has been left changed"
                ),
            ),
        });
    }

    SlotReport {
        slot_id: slot.id.as_str().to_string(),
        vpn_type: vpn_type_str(slot.vpn_type),
        checks,
    }
}

fn vpn_type_str(t: VpnType) -> &'static str {
    match t {
        VpnType::Wireguard => "wireguard",
        VpnType::Openvpn => "openvpn",
    }
}

/// Run the checks, print them, and return the exit status they imply — `0`
/// clean, `1` for any failure, `2` for "nothing failed, but something could not
/// be checked". Usable as a pre-flight step in a unit or a CI job, which is why
/// `2` exists: those consumers read the status and not the report.
pub fn check(
    cfg: &Config,
    only: Option<&str>,
    json: bool,
    bring_up: bool,
    egress: Option<SocketAddr>,
) -> anyhow::Result<i32> {
    if cfg.slot.is_empty() {
        anyhow::bail!(
            "no [[slot]] entries are configured, so there is no VPN to check. \
             Single-session mode does not use a tunnel."
        );
    }
    let selected: Vec<&SlotConfig> = cfg
        .slot
        .iter()
        .filter(|s| only.is_none_or(|id| s.id.as_str() == id))
        .collect();
    if selected.is_empty() {
        anyhow::bail!("no slot matches {:?}", only.unwrap_or_default());
    }

    let host = RealHost;
    let report = Report {
        host: host_checks(cfg),
        slots: selected
            .into_iter()
            .map(|s| slot_checks(cfg, s, bring_up, egress, &host))
            .collect(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human(&report);
    }

    let code = report.exit_code();
    match code {
        EXIT_FAILED => eprintln!("one or more VPN checks failed"),
        EXIT_UNKNOWN => eprintln!(
            "nothing failed, but one or more checks could not be performed; \
             exiting {EXIT_UNKNOWN}"
        ),
        _ => {}
    }
    Ok(code)
}

fn symbol(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "ok  ",
        Verdict::Fail => "FAIL",
        Verdict::Skip => "skip",
        Verdict::Unknown => "?   ",
    }
}

fn print_human(report: &Report) {
    println!("host");
    for c in &report.host {
        println!("  [{}] {:<20} {}", symbol(c.verdict), c.name, c.detail);
    }
    for s in &report.slots {
        println!("\nslot {} ({})", s.slot_id, s.vpn_type);
        for c in &s.checks {
            println!("  [{}] {:<20} {}", symbol(c.verdict), c.name, c.detail);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use torrentd_engine::MockForwarder;
    use torrentd_engine::MockVpn;

    use super::*;

    /// A `CheckHost` with no host behind it: every answer is scripted, and the
    /// tunnel manager and NAT-PMP client are the engine's recording doubles,
    /// so what the checks *did* to them is assertable.
    #[derive(Debug)]
    struct FakeHost {
        existing: Vec<String>,
        addrs: Mutex<Vec<(String, Option<Ipv4Addr>)>>,
        vpn: MockVpn,
        fwd: MockForwarder,
    }

    impl FakeHost {
        fn new() -> Self {
            Self {
                existing: Vec::new(),
                addrs: Mutex::new(Vec::new()),
                vpn: MockVpn::new(),
                fwd: MockForwarder::new(),
            }
        }

        /// `iface` is already present on the host before the command runs.
        fn with_existing(mut self, iface: &str) -> Self {
            self.existing.push(iface.to_string());
            self
        }

        /// Script what `first_ipv4(iface)` returns, call by call, so the
        /// address can change across the run the way a real bring-up or
        /// teardown changes it.
        fn with_addrs(
            self,
            seq: impl IntoIterator<Item = (&'static str, Option<Ipv4Addr>)>,
        ) -> Self {
            *self.addrs.lock().unwrap() =
                seq.into_iter().map(|(i, a)| (i.to_string(), a)).collect();
            self
        }
    }

    impl CheckHost for FakeHost {
        fn interface_exists(&self, iface: &str) -> bool {
            self.existing.iter().any(|i| i == iface)
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

        fn manager(&self, _t: VpnType, _run_dir: &Path) -> Arc<dyn VpnManager> {
            Arc::new(self.vpn.clone())
        }

        fn forwarder(&self) -> Arc<dyn PortForwarder> {
            Arc::new(self.fwd.clone())
        }
    }

    /// A multi-slot config with one WireGuard slot, built from TOML so a
    /// required field added to `SlotConfig` breaks this rather than letting it
    /// exercise a shape the daemon never parses.
    fn cfg_with_slot(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"
listen_interfaces = "0.0.0.0:6881"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"

[[slot]]
id                   = "acct_a"
vpn_profile          = "/etc/wireguard/wg-acct-a.conf"
vpn_type             = "wireguard"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "qBittorrent/5.0.3"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_a"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_a"
{extra}
"#
        ))
        .expect("test config parses")
    }

    fn find<'a>(checks: &'a [Check], name: &str) -> Option<&'a Check> {
        checks.iter().find(|c| c.name == name)
    }

    #[test]
    fn bring_up_never_lowers_an_interface_it_did_not_raise() {
        // F1. The daemon is up and seeding on wg-acct-a. `--bring-up` finds
        // the interface already there, so it must adopt it: report the
        // bring-up as `skip`, run the remaining checks, and issue no teardown
        // at all. A `bring_down` recorded here is a live slot fenced until
        // someone restarts the daemon.
        let cfg = cfg_with_slot("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

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
        // Adoption is not an early return: the rest of the slot is still
        // checked against the interface as it stands.
        assert!(find(&r.checks, "tunnel_ip").is_some());
    }

    #[test]
    fn bring_up_raises_and_lowers_an_interface_that_was_not_there() {
        // The complement of the above, and the case the flag exists for: a
        // crash-orphaned or never-raised interface is raised, checked, and put
        // back the way it was found.
        let cfg = cfg_with_slot("");
        let host = FakeHost::new().with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", None),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

        assert_eq!(host.vpn.bring_up_calls(), vec!["wg-acct-a"]);
        assert_eq!(host.vpn.bring_down_calls(), vec!["wg-acct-a"]);
        assert_eq!(
            find(&r.checks, "bring_up").map(|c| c.verdict),
            Some(Verdict::Pass),
        );
    }

    #[test]
    fn without_bring_up_no_tunnel_is_touched_either_way() {
        let cfg = cfg_with_slot("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

        let r = slot_checks(&cfg, &cfg.slot[0], false, None, &host);

        assert!(host.vpn.bring_up_calls().is_empty());
        assert!(host.vpn.bring_down_calls().is_empty());
        assert!(find(&r.checks, "bring_up").is_none());
        assert!(find(&r.checks, "bring_down").is_none());
    }

    #[test]
    fn a_bring_down_that_left_the_tunnel_up_is_reported_as_a_failure() {
        // F7. `bring_down` returns `()` and logs its errors away, so "tunnel
        // taken back down" was printed whether or not the tunnel went down.
        // Here the address is still there on the second lookup — `wg-quick
        // down` failed — and the operator has to be told the host was left
        // changed, on the one mutation this command advertises.
        let cfg = cfg_with_slot("");
        let host = FakeHost::new().with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

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
        let cfg = cfg_with_slot("");
        let host = FakeHost::new().with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", None),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

        assert_eq!(
            find(&r.checks, "bring_down").map(|c| c.verdict),
            Some(Verdict::Pass),
        );
    }

    #[test]
    fn the_default_path_leaves_its_mapping_to_expire_rather_than_deleting_it() {
        // F2. The flagless path is the one documented as observe-only, and it
        // used to finish by issuing NAT-PMP's wildcard delete from the tunnel
        // address — which removes every mapping that address holds, i.e. the
        // running daemon's live TCP and UDP forwards.
        //
        // Two things hold that shut. `PortForwarder` is the whole surface the
        // call site can reach and it has no delete, so a release cannot be
        // reintroduced through this parameter at all. And the reported
        // contract, asserted below, is that the lease is left to lapse: the
        // previous wording said the mapping had been "released again", so this
        // assertion fails against the behaviour it replaced.
        let cfg = cfg_with_slot("port_forward = \"natpmp\"\nport_forward_gateway = \"10.2.0.1\"");
        let host = FakeHost::new().with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        host.fwd.push_ok(51413);

        let r = slot_checks(&cfg, &cfg.slot[0], false, None, &host);

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
    fn a_natpmp_slot_with_no_tunnel_address_negotiates_nothing() {
        // The gateway is only reachable through the tunnel, so with no tunnel
        // address there is nothing to negotiate from and nothing to report but
        // a skip. Checked here because it is the arm that keeps the mapping
        // call off a host that has no tunnel at all.
        let cfg = cfg_with_slot("port_forward = \"natpmp\"");
        let host = FakeHost::new();

        let r = slot_checks(&cfg, &cfg.slot[0], false, None, &host);

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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![Check::pass("b", ""), Check::fail("c", "")],
            }],
        };
        assert!(r.failed());
    }

    #[test]
    fn a_check_that_could_not_be_performed_does_not_exit_zero() {
        // F6. The report distinguishes four verdicts so a green cannot quietly
        // mean "mostly not checked", but the exit status is the only part of
        // it a mise task or a systemd ExecStartPre reads. A run that
        // established nothing about the handshake half used to exit 0.
        let r = Report {
            host: vec![Check::pass("iproute2", ""), Check::unknown("rp_filter", "")],
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
    fn an_unknown_inside_a_slot_alone_is_enough_to_colour_the_status() {
        // The host half can be entirely clean and the slot half entirely
        // unestablished; `Report::failed` only ever looked at `Fail`, so the
        // slot half has to be reached explicitly.
        let r = Report {
            host: vec![Check::pass("iproute2", "")],
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![Check::fail("tunnel_ip", "")],
            }],
        };
        assert_eq!(r.exit_code(), EXIT_FAILED);
    }

    #[test]
    fn a_skip_is_not_an_unknown_and_exits_clean() {
        // A NAT-PMP check on a static slot did not fail to happen; it
        // correctly did not apply. Colouring the status for it would make
        // every static deployment exit 2 forever.
        let r = Report {
            host: vec![Check::pass("iproute2", ""), Check::skip("kill_switch", "")],
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
            slots: vec![],
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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
                vpn_type: "openvpn",
                checks: vec![Check::skip("b", ""), Check::unknown("c", "")],
            }],
        };
        assert!(!r.failed());
    }

    #[test]
    fn a_missing_tool_is_reported_rather_than_panicking() {
        assert!(!tool_available(
            "torrentd-definitely-not-a-binary",
            "--version"
        ));
    }
}
