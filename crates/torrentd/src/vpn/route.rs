//! Per-source routing for a tunnel, and the probe that checks it still holds.
//!
//! Every profile's sockets are bound to its tunnel address, and its outgoing
//! TCP connections — since the device is also named in `outgoing_interfaces`
//! — to the tunnel device. Its listen sockets, which also send its uTP and UDP
//! tracker traffic, are device-bound only as far as libtorrent's own best
//! effort goes (see `startup.rs`), so for them these rules are what keeps the
//! traffic in the tunnel. What a tunnel needs from the routing table is
//! narrow: traffic *from* its address goes to a table of its own, whose
//! routes all point at the tunnel.
//! Nothing else on the host is rerouted, and no tunnel's routes are visible to
//! another tunnel's traffic.
//!
//! Both tunnel types use this, as root or not:
//!
//! * WireGuard, raised by `vpn::wireguard`'s native path — `wg-quick`'s
//!   host-wide default route and fwmark rule are never installed;
//! * OpenVPN, run with `--route-noexec --pull-filter ignore redirect-gateway`
//!   so the server's pushed routes and default-gateway redirect are never
//!   applied, and the same table and rule are installed here instead.
//!
//! The table is `TABLE_BASE + ifindex`: unique per live link, derivable again
//! at teardown from the link alone, and clear of `wg-quick`'s 51820 and the
//! kernel's reserved 253-255.
//!
//! [`probe`] is the health monitor's half: each poll asks the kernel where a
//! packet from the tunnel address would go, and a route that no longer leaves
//! by the tunnel device fences the profile. A flushed `ip rule` list — a
//! firewall reload, another VPN client, an operator's `ip rule flush` — leaves
//! the address on the device and the handshake fresh, so neither of the other
//! two checks can see it, while every packet the profile sends falls through
//! to the main table's default route.

use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use super::exec;

/// Base of the per-link routing table numbers. See the module docs.
pub(crate) const TABLE_BASE: u32 = 0x7464_0000;

/// Upper bound on `ip rule del` per family at teardown. One rule is added per
/// address, so this is far above any real config; it only stops a loop on an
/// `ip` that reports success without deleting.
const MAX_RULES: usize = 64;

/// The destination the route probe asks about.
///
/// Any public address works: `ip route get` sends nothing, and the question
/// is "where would a packet to the internet from this source go", which is
/// the question every peer and tracker connection asks. A documentation or
/// private range would be the wrong choice — a host may blackhole or route
/// those specially, and the probe would fence a healthy profile.
pub(crate) const PROBE_DEST: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// The `-4`/`-6` family flag for an address or prefix.
pub(crate) fn family(addr: &str) -> &'static str {
    if addr.contains(':') {
        "-6"
    } else {
        "-4"
    }
}

/// The routing table this subsystem uses for the live link `iface`.
///
/// The ifindex is asked of `ip`, so the table is derived from the same view
/// of the links every other decision here is made from.
pub(crate) fn table_for(iface: &str) -> io::Result<u32> {
    Ok(TABLE_BASE.wrapping_add(super::ip_lookup::ifindex(iface)?))
}

/// Route each of `prefixes` via `iface` in the link's own table, and send
/// traffic from each of `addresses` to that table.
///
/// `addresses` may carry a prefix length (`10.2.0.2/32`); only the host part
/// is used for the rule. A prefix in a family none of `addresses` is in is
/// skipped: it could never be chosen — the rules are keyed on those
/// addresses — and on a host with IPv6 disabled it fails the whole bring-up.
///
/// Stops at the first failure and returns it; the caller removes what was
/// installed with [`remove`], which finds it by the table alone.
pub(crate) fn install(iface: &str, addresses: &[String], prefixes: &[String]) -> io::Result<()> {
    let dev = exec::iface(iface)?;
    let table = table_for(dev)?.to_string();
    for prefix in prefixes {
        if !addresses.iter().any(|a| family(a) == family(prefix)) {
            continue;
        }
        exec::run_ok(
            "ip",
            &[
                family(prefix),
                "route",
                "replace",
                prefix,
                "dev",
                dev,
                "table",
                &table,
            ],
            None,
            exec::CHANGE,
        )?;
    }
    for addr in addresses {
        let host = addr.split('/').next().unwrap_or(addr);
        exec::run_ok(
            "ip",
            &[family(addr), "rule", "add", "from", host, "table", &table],
            None,
            exec::CHANGE,
        )?;
    }
    Ok(())
}

/// Remove every rule pointing at `table`. Routes in the table go with the
/// link. Best effort: a rule that will not delete is left for the operator,
/// and the caller decides what a link still standing afterwards means.
///
/// Takes the table rather than the interface because the table has to be
/// read while the link is still up — for OpenVPN, before the process that
/// owns the link is signalled.
pub(crate) fn remove(table: u32) {
    remove_with(table, |args| {
        exec::run_ok("ip", &args[1..], None, exec::CHANGE)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
}

/// [`remove`] over a command runner, which is handed the whole command line
/// (`ip` first), so a caller can order it against its other commands and a
/// test can observe it.
pub(crate) fn remove_with(table: u32, mut run: impl FnMut(&[&str]) -> Result<(), String>) {
    let table = table.to_string();
    for fam in ["-4", "-6"] {
        for _ in 0..MAX_RULES {
            if run(&["ip", fam, "rule", "del", "table", &table]).is_err() {
                break;
            }
        }
    }
}

/// What the kernel says about a packet from the tunnel address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteProbe {
    /// It leaves by the tunnel device.
    ViaTunnel,
    /// It leaves by another device (named), or by none at all — an
    /// `unreachable`, `prohibit` or `blackhole` route, or a source address the
    /// kernel no longer holds.
    Elsewhere(String),
}

/// Why a route probe could not be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteProbeUnavailable {
    /// `ip` could not be run, or did not finish.
    NoTool,
}

impl RouteProbeUnavailable {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteProbeUnavailable::NoTool => "no_tool",
        }
    }
}

/// Ask the kernel where a packet from `src` to `dest` would go, and whether
/// that is `iface`.
///
/// `ip route get <dest> from <src>` performs the kernel's own output lookup —
/// rules, tables and all — and sends nothing. A lookup the kernel refuses (the
/// source address is not local any more) is [`RouteProbe::Elsewhere`], not
/// an unavailable probe: `ip` ran and answered, and the answer is that the
/// profile's traffic has nowhere tunnelled to go.
pub fn probe(iface: &str, src: IpAddr, dest: IpAddr) -> Result<RouteProbe, RouteProbeUnavailable> {
    let src = src.to_string();
    let dest = dest.to_string();
    let out = exec::run(
        "ip",
        &["route", "get", &dest, "from", &src],
        None,
        exec::QUICK,
    )
    .map_err(|_| RouteProbeUnavailable::NoTool)?;
    if !out.status.success() {
        return Ok(RouteProbe::Elsewhere(format!(
            "no route from {src}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(judge(iface, &String::from_utf8_lossy(&out.stdout)))
}

/// Read `ip route get`'s answer. Pure, so the rule is testable without a
/// tunnel.
///
/// The route is the tunnel's only when its first line names `dev <iface>` and
/// is not an `unreachable`/`prohibit`/`blackhole`/`throw` route. Matched on
/// whole tokens: an interface named `wg-a` is not `wg-ab`.
pub(crate) fn judge(iface: &str, answer: &str) -> RouteProbe {
    let first = answer.lines().next().unwrap_or_default();
    let tokens: Vec<&str> = first.split_whitespace().collect();
    if let Some(kind) = tokens
        .first()
        .filter(|t| ["unreachable", "prohibit", "blackhole", "throw"].contains(t))
    {
        return RouteProbe::Elsewhere(format!("{kind} route: {}", first.trim()));
    }
    let dev = tokens.windows(2).find(|w| w[0] == "dev").map(|w| w[1]);
    match dev {
        Some(d) if d == iface => RouteProbe::ViaTunnel,
        Some(d) => RouteProbe::Elsewhere(format!("leaves by {d}: {}", first.trim())),
        None => RouteProbe::Elsewhere(format!("names no device: {}", first.trim())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_by_the_tunnel_device_is_the_tunnels() {
        assert_eq!(
            judge(
                "wg-a",
                "1.1.1.1 from 10.2.0.2 dev wg-a table 1952710658 uid 998 \n    cache \n"
            ),
            RouteProbe::ViaTunnel,
        );
    }

    /// The drill: `ip rule flush` leaves the address and the handshake as
    /// they were, and the lookup falls through to the main table.
    #[test]
    fn a_route_by_the_physical_device_is_not() {
        let r = judge(
            "wg-a",
            "1.1.1.1 from 10.2.0.2 via 192.168.1.1 dev eth0 uid 998 \n    cache \n",
        );
        assert!(
            matches!(r, RouteProbe::Elsewhere(ref why) if why.contains("eth0")),
            "{r:?}"
        );
    }

    #[test]
    fn a_device_is_matched_as_a_whole_token_and_a_reject_route_is_not_a_route() {
        assert!(matches!(
            judge("wg-a", "1.1.1.1 from 10.2.0.2 dev wg-ab table 5"),
            RouteProbe::Elsewhere(_)
        ));
        assert!(matches!(
            judge("wg-a", "unreachable 1.1.1.1 from 10.2.0.2 dev wg-a table 5"),
            RouteProbe::Elsewhere(_)
        ));
        assert!(matches!(judge("wg-a", ""), RouteProbe::Elsewhere(_)));
    }

    #[test]
    fn a_source_the_host_does_not_hold_is_answered_not_unavailable() {
        // TEST-NET-3 is on no interface of any test host.
        let r = probe(
            "lo",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
            IpAddr::V4(PROBE_DEST),
        );
        assert!(matches!(r, Ok(RouteProbe::Elsewhere(_))), "{r:?}");
    }

    #[test]
    fn the_family_follows_the_address() {
        assert_eq!(family("10.2.0.2/32"), "-4");
        assert_eq!(family("fd00::2/128"), "-6");
    }
}
