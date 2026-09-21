//! `torrentd vpn check` — verify a profile's VPN configuration against the real
//! host, with no libtorrent session, no torrents and no tracker contact.
//!
//! Every other way of exercising this code needs a fully configured daemon: a
//! pool, a torrent library, real payload, and an operator watching `/profiles` for
//! thirty seconds to see whether the health monitor fences anything. That
//! conflates two independent things — "does my VPN configuration work" and
//! "does my seeding setup work" — and it is the first of those that has to be
//! true before the second is worth testing.
//!
//! The checks are ordered the way the daemon performs them at boot, so the
//! first failure here is the first failure the daemon would hit.
//!
//! Observe-only by default. Nothing in the default path mutates host state:
//! it reads interfaces, reads `wg` output, and — for a NAT-PMP profile — asks the
//! gateway for a mapping and immediately releases it again. `--bring-up` opts
//! into raising and lowering tunnels, which is the one thing that changes the
//! machine.

use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

use serde::Serialize;
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use torrentd_engine::ProfileConfig;
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
    /// Correctly configured to not apply — a NAT-PMP check on a static profile,
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
pub struct ProfileReport {
    pub profile_id: String,
    pub vpn_type: &'static str,
    pub checks: Vec<Check>,
}

impl ProfileReport {
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Fail)
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub host: Vec<Check>,
    pub profiles: Vec<ProfileReport>,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.host.iter().any(|c| c.verdict == Verdict::Fail)
            || self.profiles.iter().any(ProfileReport::failed)
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

/// Checks that are about the host, not any one profile.
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
    // a multi-profile daemon looks like a tunnel that connects and carries no
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
            let tunnels: Vec<String> = cfg
                .profile
                .iter()
                .map(|s| s.vpn_interface.clone())
                .collect();
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
/// every profile: `outgoing_interfaces` is pinned to the tunnel IP, so if traffic
/// cannot leave from that source address the profile connects to no peers and
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
                     in this profile would fail the same way."
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

fn profile_checks(
    cfg: &Config,
    profile: &ProfileConfig,
    bring_up: bool,
    egress: Option<SocketAddr>,
) -> ProfileReport {
    let mut checks = Vec::new();
    let iface = profile.vpn_interface.as_str();

    // 1. The profile the daemon would hand to wg-quick / openvpn.
    checks.push(match std::fs::metadata(&profile.vpn_config) {
        Ok(_) => Check::pass(
            "profile",
            format!("{} is readable", profile.vpn_config.display()),
        ),
        Err(e) => Check::fail("profile", format!("{}: {e}", profile.vpn_config.display())),
    });

    // 2. The tools that profile's type needs.
    match profile.vpn_type {
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

    // 3. Optionally raise the tunnel, exactly as boot would.
    let manager = vpn::for_type(profile.vpn_type, &cfg.state_dir());
    if bring_up {
        match manager.bring_up(&profile.vpn_config()) {
            Ok(ip) => checks.push(Check::pass("bring_up", format!("tunnel came up on {ip}"))),
            Err(e) => {
                checks.push(Check::fail("bring_up", format!("{e}")));
                return ProfileReport {
                    profile_id: profile.id.as_str().to_string(),
                    vpn_type: vpn_type_str(profile.vpn_type),
                    checks,
                };
            }
        }
    }

    // 4. The address the daemon would bind every socket in this profile to.
    let tunnel_ip = match vpn::first_ipv4(iface) {
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
    match profile.vpn_type {
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
                         fence this profile",
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

    // 6. Port forwarding, against the real gateway. The mapping is released
    //    immediately; this is a negotiation, not a reservation.
    match profile.port_forward {
        PortForwardMode::Static => {
            checks.push(Check::skip(
                "port_forward",
                format!("static listen_port {:?}", profile.listen_port),
            ));
        }
        PortForwardMode::Natpmp => match (
            tunnel_ip,
            profile.port_forward_gateway_or_default().parse::<IpAddr>(),
        ) {
            (Some(bind_ip), Ok(gateway)) => {
                let req = PortMapRequest {
                    gateway,
                    bind_ip,
                    internal_port: 0,
                    lifetime_secs: 60,
                };
                let fwd = vpn::NatpmpForwarder::for_startup();
                match fwd.map(&req) {
                    Ok(m) => {
                        let _ = fwd.unmap(gateway, bind_ip);
                        checks.push(Check::pass(
                            "port_forward",
                            format!("gateway {gateway} offered port {} (released again)", m.port),
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

    if bring_up {
        manager.bring_down(iface);
        checks.push(Check::pass("bring_down", "tunnel taken back down"));
    }

    ProfileReport {
        profile_id: profile.id.as_str().to_string(),
        vpn_type: vpn_type_str(profile.vpn_type),
        checks,
    }
}

fn vpn_type_str(t: VpnType) -> &'static str {
    match t {
        VpnType::Wireguard => "wireguard",
        VpnType::Openvpn => "openvpn",
    }
}

/// Run the checks and print them. Exits non-zero if anything failed, so this
/// is usable as a pre-flight step in a unit or a CI job.
pub fn check(
    cfg: &Config,
    only: Option<&str>,
    json: bool,
    bring_up: bool,
    egress: Option<SocketAddr>,
) -> anyhow::Result<()> {
    if cfg.profile.is_empty() {
        anyhow::bail!(
            "no [[profile]] entries are configured, so there is no VPN to check. \
             Single-session mode does not use a tunnel."
        );
    }
    let selected: Vec<&ProfileConfig> = cfg
        .profile
        .iter()
        .filter(|s| only.is_none_or(|id| s.id.as_str() == id))
        .collect();
    if selected.is_empty() {
        anyhow::bail!("no profile matches {:?}", only.unwrap_or_default());
    }

    let report = Report {
        host: host_checks(cfg),
        profiles: selected
            .into_iter()
            .map(|s| profile_checks(cfg, s, bring_up, egress))
            .collect(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human(&report);
    }

    if report.failed() {
        anyhow::bail!("one or more VPN checks failed");
    }
    Ok(())
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
    for s in &report.profiles {
        println!("\nprofile {} ({})", s.profile_id, s.vpn_type);
        for c in &s.checks {
            println!("  [{}] {:<20} {}", symbol(c.verdict), c.name, c.detail);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_missing_tool_is_reported_rather_than_panicking() {
        assert!(!tool_available(
            "torrentd-definitely-not-a-binary",
            "--version"
        ));
    }
}
