//! Interface lookups: an interface's IPv4 address, whether a link exists, and
//! its ifindex.
//!
//! Shells out to `ip` (iproute2), found on the daemon's `PATH`, through
//! [`super::exec::run`]. We deliberately don't depend on the netlink crate
//! stack — it's another ~30 transitive deps for one small piece of
//! functionality, and the `ip` tool is universally present on every Linux
//! distro that runs WireGuard.
//!
//! **Every VPN tool is run by bare name, on purpose.** `ip` here, `wg`
//! (`vpn::wireguard`), `openvpn` and `kill` (`vpn::openvpn`), and `nft`
//! (`vpn::killswitch`) are all resolved through the daemon's inherited
//! `PATH`, and the daemon treats its own environment as trusted. Whoever can
//! set that `PATH` — the unit file, the container image, the invoking shell —
//! can equally replace `ExecStart=` or the binary itself, so an absolute path
//! would not narrow who can run code with the daemon's `CAP_NET_ADMIN`; it
//! would only break every host whose iproute2 or nftables lives somewhere
//! other than the one path chosen (`/sbin` versus `/usr/sbin`, NixOS's store).
//! The packaged unit sets no `PATH` and so gets systemd's fixed default for
//! system services, and the container image's is its own. A deployment that
//! puts an operator-writable directory on the daemon's `PATH` has made those
//! tools operator-controlled.
//!
//! **One view of the links.** Every question about a link is asked of `ip`,
//! which answers from this process's network namespace over netlink.
//! `/sys/class/net` shows the namespace sysfs was *mounted* in, which is not
//! necessarily this process's: a daemon started in a namespace of its own
//! with the host's sysfs saw one set of links there and another through `ip`,
//! and decided ownership from the first while tearing down through the
//! second.
//!
//! Output format we parse (`-o` makes it one address per line):
//!
//!     2: wg0    inet 10.0.0.5/24 brd 10.0.0.255 scope global wg0\       valid_lft forever preferred_lft forever
//!
//! The first whitespace-trimmed token after `inet ` up to `/` is the
//! address.

use std::io;
use std::net::Ipv4Addr;

use super::exec;

pub fn first_ipv4(iface: &str) -> io::Result<Ipv4Addr> {
    let out = exec::run(
        "ip",
        &["-4", "-o", "addr", "show", "dev", exec::iface(iface)?],
        None,
        exec::QUICK,
    )?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("ip addr show {iface}: {}", stderr.trim()),
        ));
    }
    parse_first_ipv4(iface, &String::from_utf8_lossy(&out.stdout))
}

/// Why [`probe_ipv4`] could not answer: `ip` could not be run, or did not
/// finish, so nothing is known about the interface's address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddrProbeUnavailable {
    /// The error, as `ip` failed to run (a spawn failure such as `EMFILE`,
    /// the [`exec::QUICK`] timeout, or a name that cannot be passed to `ip`).
    pub cause: String,
}

/// The interface's first IPv4 address, telling "no address" apart from "could
/// not ask".
///
/// * `Ok(Some(addr))` — `ip` ran and listed this address.
/// * `Ok(None)` — `ip` ran and the interface has no IPv4 address, or `ip`
///   exited nonzero (the link does not exist). `ip` answered, as a refused
///   `ip route get` is an answer to the route probe.
/// * `Err(_)` — `ip` could not be run or did not finish. This is a host fault,
///   not a fact about the tunnel, and a caller deciding whether the tunnel is
///   down leaves its verdict to the other checks rather than reading it as a
///   lost address.
///
/// [`first_ipv4`] keeps its single error for the callers that need an address
/// and treat every reason for not having one alike.
pub fn probe_ipv4(iface: &str) -> Result<Option<Ipv4Addr>, AddrProbeUnavailable> {
    let unavailable = |e: io::Error| AddrProbeUnavailable {
        cause: e.to_string(),
    };
    let out = exec::run(
        "ip",
        &[
            "-4",
            "-o",
            "addr",
            "show",
            "dev",
            exec::iface(iface).map_err(unavailable)?,
        ],
        None,
        exec::QUICK,
    )
    .map_err(unavailable)?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(parse_first_ipv4(iface, &String::from_utf8_lossy(&out.stdout)).ok())
}

fn parse_first_ipv4(iface: &str, text: &str) -> io::Result<Ipv4Addr> {
    for line in text.lines() {
        if let Some(rest) = line.split(" inet ").nth(1) {
            let cidr = rest.split_whitespace().next().unwrap_or("");
            if let Some(addr) = cidr.split('/').next() {
                if let Ok(ip) = addr.parse::<Ipv4Addr>() {
                    return Ok(ip);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no IPv4 address on {iface}"),
    ))
}

/// Whether a link of this name exists in this process's network namespace.
///
/// `Some(false)` only on `ip`'s own "does not exist" — read in the C locale,
/// which [`exec::run`] guarantees. `None` when the question could not be
/// answered (`ip` missing, timed out, or failing for another reason), so a
/// caller deciding whether it may remove something can take the conservative
/// side rather than read "could not ask" as "absent".
pub fn link_exists(iface: &str) -> Option<bool> {
    let name = exec::iface(iface).ok()?;
    let out = exec::run(
        "ip",
        &["-o", "link", "show", "dev", name],
        None,
        exec::QUICK,
    )
    .ok()?;
    if out.status.success() {
        return Some(true);
    }
    String::from_utf8_lossy(&out.stderr)
        .contains("does not exist")
        .then_some(false)
}

/// [`link_exists`], reading "could not ask" as "standing".
///
/// For the callers whose `false` licenses something — a teardown, dropping a
/// record that is what makes a later adoption possible. Reading an unanswered
/// probe as "absent" there is the destructive direction.
pub fn link_standing(iface: &str) -> bool {
    link_exists(iface).unwrap_or(true)
}

/// The ifindex of the live link `iface`, from `ip -o link show`.
pub fn ifindex(iface: &str) -> io::Result<u32> {
    let out = exec::run_ok(
        "ip",
        &["-o", "link", "show", "dev", exec::iface(iface)?],
        None,
        exec::QUICK,
    )?;
    String::from_utf8_lossy(&out.stdout)
        .split(':')
        .next()
        .and_then(|i| i.trim().parse::<u32>().ok())
        .ok_or_else(|| io::Error::other(format!("no ifindex for {iface}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_inet_address_is_read_off_a_one_line_listing() {
        let text = "2: wg0    inet 10.0.0.5/24 brd 10.0.0.255 scope global wg0\\       valid_lft forever preferred_lft forever\n";
        assert_eq!(
            parse_first_ipv4("wg0", text).unwrap(),
            Ipv4Addr::new(10, 0, 0, 5)
        );
        assert!(parse_first_ipv4("wg0", "").is_err());
    }

    /// Asked of `ip`, from this process's namespace, and the absent answer is
    /// told apart from the unanswered one.
    #[test]
    fn a_link_is_looked_up_through_ip_and_absence_is_positive() {
        assert_eq!(link_exists("lo"), Some(true));
        assert_eq!(link_exists("torrentd-nonexistent-iface"), Some(false));
        assert_eq!(
            link_exists("-x"),
            None,
            "a name that cannot be asked about is not an absent link"
        );
        assert!(link_standing("-x"), "and it is read as standing");
        assert_eq!(ifindex("lo").unwrap(), 1);
    }

    /// An address probe that ran tells "no address" (`Ok(None)`) apart from
    /// one that could not ask (`Err`).
    #[test]
    fn the_address_probe_tells_no_address_from_could_not_ask() {
        assert_eq!(probe_ipv4("lo"), Ok(Some(Ipv4Addr::LOCALHOST)));
        assert_eq!(
            probe_ipv4("torrentd-nonexistent-iface"),
            Ok(None),
            "a link that does not exist holds no address"
        );
        let err = probe_ipv4("-x").expect_err("a name that cannot be asked about");
        assert!(!err.cause.is_empty(), "the cause is kept: {err:?}");
    }
}
