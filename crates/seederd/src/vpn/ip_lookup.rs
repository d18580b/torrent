//! IPv4 lookup for a network interface.
//!
//! Shells out to `/usr/sbin/ip` (iproute2). We deliberately don't depend
//! on the netlink crate stack — it's another ~30 transitive deps for one
//! small piece of functionality, and the `ip` tool is universally
//! present on every Linux distro that runs WireGuard.
//!
//! Output format we parse (`-o` makes it one address per line):
//!
//!     2: wg0    inet 10.0.0.5/24 brd 10.0.0.255 scope global wg0\       valid_lft forever preferred_lft forever
//!
//! The first whitespace-trimmed token after `inet ` up to `/` is the
//! address.

use std::io;
use std::net::Ipv4Addr;
use std::process::Command;

pub fn first_ipv4(iface: &str) -> io::Result<Ipv4Addr> {
    let out = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("ip addr show {iface}: {}", stderr.trim()),
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
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
