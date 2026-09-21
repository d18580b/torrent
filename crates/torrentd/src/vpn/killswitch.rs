//! Network-layer VPN kill switch (nftables) — defence-in-depth backstop.
//!
//! Multi-slot isolation's primary guard is that every slot's libtorrent sockets
//! are source-bound to the tunnel IP (`startup.rs`), and [`crate::vpn_monitor`]
//! pauses a slot within ~30s of tunnel loss. Both live at the application layer:
//! the "no bare-IP leak" guarantee ultimately rests on libtorrent honouring the
//! bind and on the poll reacting in time.
//!
//! This module adds an independent, **fail-closed** nftables ruleset so the
//! daemon's own egress can only leave via loopback or a configured tunnel
//! interface. If a tunnel disappears its `oifname` is gone and the packets are
//! dropped by the kernel — no dependency on the source-bind or the 30s poll,
//! and it also forces tracker DNS through the tunnel.
//!
//! Opt-in (`network_kill_switch = true`); needs `CAP_NET_ADMIN` (the packaged
//! systemd unit already grants it). The daemon's traffic is matched by its
//! runtime uid, so torrentd must run as a dedicated user (the unit uses
//! `User=torrentd`).

use std::io;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use tracing::info;

/// nftables table this module owns. Torn down on graceful shutdown.
pub const TABLE: &str = "torrentd_ks";

/// Render the fail-closed nftables ruleset confining uid `uid`'s egress to
/// loopback + `tunnels`. Pure (no I/O) so it can be asserted byte-for-byte in
/// tests. Interface names are de-duplicated and sorted so the output is
/// deterministic regardless of slot ordering.
///
/// The chain policy stays `accept` (we must not touch other uids' traffic); we
/// only `drop` packets owned by `uid` that don't egress loopback or a tunnel.
pub fn render_ruleset(uid: u32, tunnels: &[String]) -> String {
    let mut ifaces: Vec<&str> = tunnels.iter().map(String::as_str).collect();
    ifaces.sort_unstable();
    ifaces.dedup();

    let mut chain = String::new();
    chain.push_str("\t\ttype filter hook output priority 0; policy accept;\n");
    chain.push_str(&format!("\t\tmeta skuid {uid} oifname \"lo\" accept\n"));
    if !ifaces.is_empty() {
        let set = ifaces
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        chain.push_str(&format!(
            "\t\tmeta skuid {uid} oifname {{ {set} }} accept\n"
        ));
    }
    chain.push_str(&format!("\t\tmeta skuid {uid} counter drop\n"));

    format!("table inet {TABLE} {{\n\tchain output {{\n{chain}\t}}\n}}\n")
}

/// Effective uid of this process, read from `/proc/self/status` (Linux-only,
/// which the daemon already requires) so no `libc` dependency is needed.
pub fn current_uid() -> io::Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Fields: real  effective  saved  fs. Match on the effective uid,
            // which owns sockets the process creates.
            if let Some(eff) = rest.split_whitespace().nth(1) {
                if let Ok(uid) = eff.parse::<u32>() {
                    return Ok(uid);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no Uid line in /proc/self/status",
    ))
}

/// Whether the `nft` binary is usable. Used by `--check-config` to fail early
/// when the kill switch is requested on a host without nftables.
pub fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Why `enable` must refuse to install a ruleset for `uid`, or `None` if it
/// may proceed.
///
/// Pure, and separate from `enable`, so the refusal is reachable by a test:
/// `enable` needs `nft` on the host and the process's own uid, so a test
/// cannot call it with 0. The guard was previously inline and covered only by
/// a test of `render_ruleset`, which the guard does not touch — deleting the
/// guard left the whole suite green while the change it prevents takes a host
/// off the network.
pub(crate) fn refusal_for_uid(uid: u32) -> Option<io::Error> {
    // The ruleset confines *this uid's* egress to loopback and the tunnels. As
    // root that is not a kill switch, it is an outage: every root-owned socket
    // on the host — the package manager, the NTP client, sshd's replies —
    // matches `meta skuid 0` and gets dropped. Refuse rather than install it.
    //
    // `wg-quick` is usually a root tool, so reaching here as root is an easy
    // mistake to make; the packaged unit's `User=torrentd` plus
    // `AmbientCapabilities=CAP_NET_ADMIN` is the supported shape.
    (uid == 0).then(|| {
        io::Error::other(
            "network_kill_switch = true requires a dedicated non-root user: the ruleset \
             confines the daemon's uid to loopback and its tunnels, and as uid 0 that \
             would drop every root-owned process's traffic on this host. Run torrentd as \
             its own user with CAP_NET_ADMIN (see deploy/torrentd.service).",
        )
    })
}

/// Install the kill switch for the current process's uid, confining egress to
/// loopback + `tunnels`. Returns the uid the ruleset was written for. Replaces
/// any stale table left by a previous unclean exit first.
///
/// Refuses uid 0 outright — see [`refusal_for_uid`].
pub fn enable(tunnels: &[String]) -> io::Result<u32> {
    let uid = current_uid()?;
    if let Some(refusal) = refusal_for_uid(uid) {
        return Err(refusal);
    }
    let ruleset = render_ruleset(uid, tunnels);
    // Clear a stale table before reloading. `nft -f -` merges into an existing
    // table rather than replacing it, so a delete that silently failed would
    // leave a previous run's rules in force alongside the new ones — with the
    // old run's tunnel interfaces still accepted.
    disable()?;
    apply(&ruleset)?;
    info!(
        target: "torrentd::vpn::killswitch",
        uid,
        tunnels = ?tunnels,
        "network kill switch installed (nftables, fail-closed)",
    );
    Ok(uid)
}

/// Remove the kill-switch table.
///
/// A missing table is success — shutdown must never fail on it, and the
/// startup pre-clear runs against a table that usually is not there. Any other
/// non-zero exit is reported: `nft` merges into an existing table rather than
/// replacing it, so a stale table that failed to delete would silently survive
/// alongside the new rules. Previously only a failure to *spawn* `nft` was
/// noticed, and a non-zero exit looked identical to success.
pub fn disable() -> io::Result<()> {
    let out = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("No such file or directory") || err.contains("does not exist") {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "nft delete table exited {}: {}",
        out.status,
        err.trim(),
    )))
}

/// Feed a ruleset to `nft -f -`.
fn apply(ruleset: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("nft stdin unavailable"))?;
    stdin.write_all(ruleset.as_bytes())?;
    drop(stdin); // close so nft sees EOF
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nft -f - exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_refuses_to_install_a_ruleset_as_root() {
        // The guard `enable` actually consults. Delete it and this fails,
        // which is the whole point: the test that used to carry this name
        // asserted on `render_ruleset`, a function the guard does not touch,
        // so removing the guard left the suite green while the change it
        // prevents takes a host off the network.
        let e = refusal_for_uid(0).expect("uid 0 must be refused");
        assert!(
            e.to_string().contains("non-root user"),
            "the refusal has to say what to do instead; got {e}",
        );
    }

    #[test]
    fn enable_proceeds_for_a_dedicated_uid() {
        assert!(
            refusal_for_uid(998).is_none(),
            "the supported shape — User=torrentd with CAP_NET_ADMIN — is not refused",
        );
    }

    #[test]
    fn render_ruleset_would_happily_confine_uid_0() {
        // `render_ruleset` is pure and has no guard of its own: it renders a
        // ruleset that drops every root-owned socket on the host. This pins
        // the shape `refusal_for_uid` exists to keep out of `nft`; on its own
        // it establishes nothing about whether anything checks.
        let rs = render_ruleset(0, &["wg0".to_string()]);
        assert!(
            rs.contains("meta skuid 0 counter drop"),
            "if this ever stops being catastrophic, revisit refusal_for_uid",
        );
    }

    #[test]
    fn ruleset_confines_uid_to_lo_and_tunnels() {
        let rs = render_ruleset(998, &["wg-b".to_string(), "wg-a".to_string()]);
        let expected = "\
table inet torrentd_ks {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 oifname { \"wg-a\", \"wg-b\" } accept
\t\tmeta skuid 998 counter drop
\t}
}
";
        assert_eq!(rs, expected);
    }

    #[test]
    fn ruleset_dedups_shared_interface() {
        let rs = render_ruleset(1000, &["wg0".to_string(), "wg0".to_string()]);
        assert_eq!(rs.matches("wg0").count(), 1);
        // Still fails closed: lo accept, one tunnel accept, then drop.
        assert!(rs.contains("meta skuid 1000 counter drop"));
    }

    #[test]
    fn ruleset_with_no_tunnels_allows_only_loopback() {
        let rs = render_ruleset(1000, &[]);
        assert!(!rs.contains("oifname {"));
        assert!(rs.contains("oifname \"lo\" accept"));
        assert!(rs.contains("counter drop"));
    }
}
