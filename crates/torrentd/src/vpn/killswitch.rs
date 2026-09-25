//! Network-layer VPN kill switch (nftables) — defence-in-depth backstop.
//!
//! Multi-profile isolation's primary guard is that every profile's libtorrent sockets
//! are source-bound to the tunnel IP (`startup.rs`), and [`crate::vpn_monitor`]
//! pauses a profile within ~30s of tunnel loss. Both live at the application layer:
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
//!
//! **What that leaves runnable.** Matching by uid confines every socket that
//! uid owns, and a WireGuard tunnel's encrypted traffic to its provider
//! leaves by the physical interface. WireGuard encrypts a packet in place, so
//! the encrypted UDP datagram still carries the socket that sent the
//! plaintext — the daemon's — and `meta skuid` matches it, whichever uid
//! raised the link. (Handshakes are built by the kernel with no socket
//! attached and match no uid rule, which is why a tunnel under the bare drop
//! handshakes and then carries nothing.) So the ruleset carries one
//! exemption per tunnel: its UDP **listen port**, read off the live link with
//! `wg show <iface> listen-port` when the ruleset is installed, is accepted
//! as a source port for the daemon's uid on any interface
//! ([`render_ruleset_with_transport`]). Nothing the daemon opens itself can
//! hold that port: the WireGuard socket binds it on the wildcard address
//! without address reuse, so a libtorrent bind to it fails with `EADDRINUSE`
//! rather than sharing it.
//!
//! - **OpenVPN: never.** The daemon spawns `openvpn` under its own uid, so the
//!   ruleset drops the client's connection to the provider. `Config::validate`
//!   refuses the kill switch beside an OpenVPN profile.
//! - **Any profile as uid 0: never.** `meta skuid 0 counter drop` drops every
//!   other root-owned socket on the host. [`refusal_for_uid`] refuses it.
//! - **WireGuard as a dedicated uid with `CAP_NET_ADMIN`: yes.** `wg-quick`
//!   re-execs itself through `sudo` unless its uid is 0, so a non-root daemon
//!   raises its links with `ip` and `wg` directly (see `vpn::wireguard`),
//!   which need only the capability. A link root raised before the daemon
//!   started, and which the daemon adopted, needs the same exemption and gets
//!   it: the packets are the daemon's either way.

use std::io;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use torrentd_engine::profile::ProfileConfig;
use tracing::info;

/// nftables table this module owns. Torn down on graceful shutdown.
pub const TABLE: &str = "torrentd_ks";

/// Render the fail-closed nftables ruleset confining uid `uid`'s egress to
/// loopback + `tunnels`. Pure (no I/O) so it can be asserted byte-for-byte in
/// tests. Interface names are de-duplicated and sorted so the output is
/// deterministic regardless of profile ordering.
///
/// The chain policy stays `accept` (we must not touch other uids' traffic); we
/// only `drop` packets owned by `uid` that don't egress loopback or a tunnel.
///
/// Refuses, with `InvalidInput` naming it, any interface name
/// [`ProfileConfig::is_valid_interface_name`] rejects. Each name is written
/// between literal quotes, and nftables has no escape for a `"` inside one, so
/// a name carrying a quote, brace or newline would produce a ruleset `nft`
/// rejects with a syntax error in a file the operator never wrote. Config
/// validation refuses such a name first; this keeps the renderer from emitting
/// an unparseable ruleset for any caller that did not.
pub fn render_ruleset(uid: u32, tunnels: &[String]) -> io::Result<String> {
    render_ruleset_with_transport(uid, tunnels, &[])
}

/// [`render_ruleset`], plus the tunnels' own transport: each port in
/// `transport_ports` is accepted as a UDP source port for `uid` on any
/// interface, ahead of the drop.
///
/// This is the ruleset `enable` installs. Without it no WireGuard link
/// carries the daemon's traffic: the encrypted UDP to the provider leaves by
/// the physical interface still attached to the daemon's sending socket, so
/// it matches `meta skuid <uid>` and the final `drop` takes it. Ports are de-duplicated and sorted, like the
/// interface names, so the output is deterministic.
pub fn render_ruleset_with_transport(
    uid: u32,
    tunnels: &[String],
    transport_ports: &[u16],
) -> io::Result<String> {
    if let Some(bad) = tunnels
        .iter()
        .find(|i| !ProfileConfig::is_valid_interface_name(i))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "vpn_interface {bad:?} cannot be written into the kill-switch ruleset: an \
                 interface name must be 1-15 characters of [A-Za-z0-9_=+.-]",
            ),
        ));
    }
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
    let mut ports = transport_ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    if !ports.is_empty() {
        let set = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        chain.push_str(&format!(
            "\t\tmeta skuid {uid} udp sport {{ {set} }} accept\n"
        ));
    }
    chain.push_str(&format!("\t\tmeta skuid {uid} counter drop\n"));

    Ok(format!(
        "table inet {TABLE} {{\n\tchain output {{\n{chain}\t}}\n}}\n"
    ))
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
    // mistake to make. A dedicated uid with `CAP_NET_ADMIN` raises its
    // WireGuard links itself with `ip` and `wg`, and the ruleset exempts
    // their transport — see this module's documentation.
    (uid == 0).then(|| {
        io::Error::other(
            "network_kill_switch = true requires a dedicated non-root user: the ruleset \
             confines the daemon's uid to loopback and its tunnels, and as uid 0 that \
             would drop every root-owned process's traffic on this host. Run the daemon \
             as its own user with CAP_NET_ADMIN, which raises WireGuard links with `ip` \
             and `wg` (see docs/running.md, \"Kill switch\"); otherwise unset \
             network_kill_switch.",
        )
    })
}

/// Install the kill switch for the current process's uid, confining egress to
/// loopback + `tunnels`, with each tunnel's own transport exempted (see
/// [`render_ruleset_with_transport`]). Returns the uid the ruleset was written
/// for. Replaces any stale table left by a previous unclean exit first.
///
/// Refuses uid 0 outright — see [`refusal_for_uid`].
pub fn enable(tunnels: &[String]) -> io::Result<u32> {
    enable_for_uid(current_uid()?, tunnels, listen_port, disable, apply)
}

/// The UDP port the WireGuard link `iface` listens on, from
/// `wg show <iface> listen-port`.
///
/// Read when the ruleset is installed, because a link with no `ListenPort`
/// is given a random one by the kernel when it comes up and no config holds
/// it. `0` — a link that is down and has no socket — is an error: there is
/// no transport to exempt, and the tunnel would not carry once it had one.
pub(crate) fn listen_port(iface: &str) -> io::Result<u16> {
    let out = Command::new("wg")
        .args(["show", iface, "listen-port"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "wg show {iface} listen-port exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        )));
    }
    parse_listen_port(iface, &String::from_utf8_lossy(&out.stdout))
}

/// `wg show <iface> listen-port`'s output, as a port the ruleset can exempt.
fn parse_listen_port(iface: &str, text: &str) -> io::Result<u16> {
    match text.trim().parse::<u16>() {
        Ok(0) => Err(io::Error::other(format!(
            "WireGuard link {iface} has no listen port (is it down?), so the kill \
             switch has no transport to exempt for it",
        ))),
        Ok(port) => Ok(port),
        Err(_) => Err(io::Error::other(format!(
            "wg show {iface} listen-port printed {:?}, not a port",
            text.trim(),
        ))),
    }
}

/// `enable`, with the uid and **both** `nft` calls handed in.
///
/// Making `refusal_for_uid` pure was half a fix: it left the guard *reachable*
/// by a test and the **call site** still unreachable by any of them, so
/// deleting `enable`'s `if let Some(refusal)` line left the whole suite green
/// while a host running the daemon as root installed `meta skuid 0 counter
/// drop` and lost every root-owned socket on the machine. `enable` itself
/// cannot be tested — it reads the process's real uid and shells out to `nft`
/// — so the control flow the guard sits in lives here, where a test can drive
/// uid 0 through it and watch `apply` not be called.
///
/// Injecting `apply` alone was half a seam, for the same reason one step on:
/// the refusal arm became reachable and the whole success path stayed
/// unreached, because `disable` still shelled out unconditionally and no test
/// could drive a non-zero uid past it. Deleting the `clear()?` line left the
/// suite green — and that line is what keeps a previous run's rules, and its
/// tunnel interfaces, from staying in force beside this run's. Both calls are
/// handed in, so the order and the ruleset are asserted rather than reasoned
/// about.
///
/// `transport_port` is the third host probe, handed in for the same reason:
/// the exemption it feeds is the difference between a WireGuard link the
/// daemon raised carrying traffic and carrying none.
pub(crate) fn enable_for_uid(
    uid: u32,
    tunnels: &[String],
    transport_port: impl Fn(&str) -> io::Result<u16>,
    clear: impl Fn() -> io::Result<()>,
    apply: impl Fn(&str) -> io::Result<()>,
) -> io::Result<u32> {
    if let Some(refusal) = refusal_for_uid(uid) {
        return Err(refusal);
    }
    // Every port is read before anything is cleared. A tunnel whose transport
    // cannot be exempted is a tunnel the ruleset would silence, so it fails
    // the install — and leaves a previous run's kill switch armed.
    let ports = tunnels
        .iter()
        .map(|iface| transport_port(iface))
        .collect::<io::Result<Vec<u16>>>()?;
    // Rendered before the clear, so a name the ruleset cannot carry leaves a
    // previous run's kill switch armed rather than disarming it and failing.
    let ruleset = render_ruleset_with_transport(uid, tunnels, &ports)?;
    // Clear a stale table before reloading. `nft -f -` merges into an existing
    // table rather than replacing it, so a delete that silently failed would
    // leave a previous run's rules in force alongside the new ones — with the
    // old run's tunnel interfaces still accepted.
    clear()?;
    apply(&ruleset)?;
    info!(
        target: "torrentd::vpn::killswitch",
        uid,
        tunnels = ?tunnels,
        transport_ports = ?ports,
        "network kill switch installed (nftables, fail-closed)",
    );
    Ok(uid)
}

/// Remove the kill-switch table.
///
/// A missing table is success — shutdown must never fail on it, and the
/// startup pre-clear runs against a table that usually is not there. Any other
/// failure is reported: `nft` merges into an existing table rather than
/// replacing it, so a stale table that failed to delete would silently survive
/// alongside the new rules.
///
/// Whether the table exists is asked directly, with `nft list tables`, rather
/// than inferred from the text of a failed delete. That text is `strerror`
/// output, which is localised: matching "No such file or directory" failed on
/// any host whose `LC_MESSAGES` is not C or English, so the first boot with the
/// kill switch on aborted on a delete of a table that was never there. The
/// listing is ruleset syntax, which no locale translates, and it still fails —
/// and so still reports — on the errors that matter, such as a missing
/// `CAP_NET_ADMIN`.
pub fn disable() -> io::Result<()> {
    disable_with(list_tables, delete_table)
}

/// `disable`, with both `nft` calls handed in so the decision between them is
/// reachable by a test on a host without `nft` or `CAP_NET_ADMIN`.
pub(crate) fn disable_with(
    list: impl Fn() -> io::Result<String>,
    delete: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    if !table_listed(&list()?) {
        return Ok(());
    }
    delete()
}

/// Whether `nft list tables` output names this module's table. Each line is
/// `table <family> <name>`; the table is matched on family and name exactly,
/// so a same-named table in another family, or one whose name merely starts
/// with [`TABLE`], is not taken for it.
fn table_listed(listing: &str) -> bool {
    listing
        .lines()
        .any(|line| line.split_whitespace().eq(["table", "inet", TABLE]))
}

/// `nft list tables`, returning its stdout.
fn list_tables() -> io::Result<String> {
    let out = Command::new("nft")
        .args(["list", "tables"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nft list tables exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `nft delete table inet TABLE`. Any non-zero exit is an error: it is only
/// called once the table has been listed, so there is no absent case to
/// excuse.
fn delete_table() -> io::Result<()> {
    let out = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nft delete table exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        )));
    }
    Ok(())
}

/// Feed a ruleset to `nft -f -`.
pub(crate) fn apply(ruleset: &str) -> io::Result<()> {
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
        // Driven through `enable`'s own control flow, not around it: delete
        // the `if let Some(refusal)` line and this fails, in any environment.
        // Asserting on `refusal_for_uid` alone -- which is what this test did
        // -- left the call site reachable by nothing, so the guard could be
        // deleted with the suite still green while a host running the daemon
        // as root lost every root-owned socket on it.
        let called = std::cell::Cell::new(false);
        let cleared = std::cell::Cell::new(false);
        let e = enable_for_uid(
            0,
            &["wg-a".to_string()],
            |_| Ok(51820),
            || {
                cleared.set(true);
                Ok(())
            },
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
            !called.get(),
            "the refusal comes before anything is handed to nft",
        );
        assert!(
            !cleared.get(),
            "and before the existing table is deleted — a refused enable must \
             not disarm a kill switch a previous run installed",
        );
    }

    #[test]
    fn the_refusal_is_the_predicate_the_guard_consults() {
        let e = refusal_for_uid(0).expect("uid 0 must be refused");
        assert!(e.to_string().contains("non-root user"), "got {e}");
    }

    /// The success path, driven through `enable_for_uid`'s real control flow.
    ///
    /// This test used to assert `refusal_for_uid(998).is_none()` — a function
    /// its name does not mention, and a duplicate of the test above it — so
    /// `render_ruleset`, the pre-clear and `apply` were reached by nothing at
    /// all. Deleting the `clear()?` line left the whole suite green, and that
    /// line is the one whose absence lets a previous run's rules stay in
    /// force beside this run's: `nft -f -` merges into an existing table
    /// rather than replacing it, so the old run's tunnel interfaces would
    /// still be accepted by a ruleset that does not own them.
    #[test]
    fn enable_clears_the_stale_table_before_it_installs_the_new_one() {
        // One log, so the order is asserted and not just the two calls.
        let calls = std::cell::RefCell::new(Vec::<String>::new());
        let uid = enable_for_uid(
            998,
            &["wg-b".to_string(), "wg-a".to_string()],
            |iface| Ok(if iface == "wg-a" { 51820 } else { 40001 }),
            || {
                calls.borrow_mut().push("clear".to_string());
                Ok(())
            },
            |rs| {
                calls.borrow_mut().push(format!("apply:{rs}"));
                Ok(())
            },
        )
        .expect("the supported shape — User=torrentd with CAP_NET_ADMIN — is not refused");

        assert_eq!(uid, 998, "the uid the ruleset was written for is returned");
        let calls = calls.borrow();
        assert_eq!(calls.len(), 2, "one clear and one apply; got {calls:?}");
        assert_eq!(
            calls[0], "clear",
            "the stale table goes before the new one is merged in",
        );
        assert_eq!(
            calls[1],
            format!(
                "apply:{}",
                render_ruleset_with_transport(
                    998,
                    &["wg-a".to_string(), "wg-b".to_string()],
                    &[40001, 51820],
                )
                .unwrap()
            ),
            "and the ruleset handed to nft is this uid's, over these tunnels, \
             with each tunnel's own listen port exempted",
        );
    }

    /// A tunnel whose listen port will not read stops the install before
    /// anything is cleared: installing without its exemption would silence
    /// that tunnel, and clearing first would disarm a previous run's switch.
    #[test]
    fn a_transport_port_that_will_not_read_stops_the_install_before_clearing() {
        let cleared = std::cell::Cell::new(false);
        let applied = std::cell::Cell::new(false);
        let e = enable_for_uid(
            998,
            &["wg-a".to_string()],
            |_| Err(io::Error::other("wg show wg-a listen-port exited 1")),
            || {
                cleared.set(true);
                Ok(())
            },
            |_| {
                applied.set(true);
                Ok(())
            },
        )
        .expect_err("a port that will not read is not an absent exemption");
        assert!(e.to_string().contains("listen-port"), "got {e}");
        assert!(!cleared.get(), "the existing table is left in force");
        assert!(!applied.get(), "nothing is handed to nft");
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
    /// drop, keyed on this uid **and** the source port, so it lets out the
    /// WireGuard socket's encrypted UDP and nothing else this uid owns.
    #[test]
    fn ruleset_exempts_each_tunnels_transport_ahead_of_the_drop() {
        let rs = render_ruleset_with_transport(
            998,
            &["wg-a".to_string(), "wg-b".to_string()],
            &[51820, 40001, 51820],
        )
        .unwrap();
        let expected = "\
table inet torrentd_ks {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 oifname { \"wg-a\", \"wg-b\" } accept
\t\tmeta skuid 998 udp sport { 40001, 51820 } accept
\t\tmeta skuid 998 counter drop
\t}
}
";
        assert_eq!(rs, expected);
    }

    /// A pre-clear that fails is fatal: an `nft delete` that reported a real
    /// error leaves a table whose rules this run would be merging into.
    #[test]
    fn a_failed_pre_clear_stops_the_install() {
        let applied = std::cell::Cell::new(false);
        let e = enable_for_uid(
            998,
            &[],
            |_| unreachable!("no tunnels, no ports"),
            || {
                Err(io::Error::other(
                    "nft delete table exited 1: something else",
                ))
            },
            |_| {
                applied.set(true);
                Ok(())
            },
        )
        .expect_err("a pre-clear failure is not swallowed");
        assert!(e.to_string().contains("nft delete table"), "got {e}");
        assert!(
            !applied.get(),
            "a ruleset is never merged into a table that would not clear",
        );
    }

    /// The first boot with the kill switch on: no table yet. `disable` must
    /// succeed without attempting the delete, whatever language `nft` would
    /// have failed it in — the absence is read from the listing, not from a
    /// localised error message.
    #[test]
    fn disable_succeeds_without_deleting_when_the_table_is_absent() {
        let deleted = std::cell::Cell::new(false);
        disable_with(
            || Ok("table ip filter\ntable inet other\n".to_string()),
            || {
                deleted.set(true);
                Err(io::Error::other(
                    "nft delete table exited 1: Fehler: Datei oder Verzeichnis nicht gefunden",
                ))
            },
        )
        .expect("an absent table is success");
        assert!(!deleted.get(), "nothing to delete, so no delete is run");

        disable_with(|| Ok(String::new()), || panic!("no tables at all"))
            .expect("an empty listing is an absent table");
    }

    #[test]
    fn disable_deletes_a_listed_table_and_reports_its_failure() {
        let deleted = std::cell::Cell::new(false);
        disable_with(
            || Ok(format!("table ip filter\ntable inet {TABLE}\n")),
            || {
                deleted.set(true);
                Ok(())
            },
        )
        .expect("a delete that succeeded");
        assert!(deleted.get(), "a listed table is deleted");

        let e = disable_with(
            || Ok(format!("table inet {TABLE}\n")),
            || Err(io::Error::other("nft delete table exited 1: busy")),
        )
        .expect_err("a table that exists and would not delete is not swallowed");
        assert!(e.to_string().contains("nft delete table"), "got {e}");
    }

    /// A listing that fails — no `CAP_NET_ADMIN`, say — is an error, not an
    /// absent table: otherwise a stale table this run cannot see would be
    /// left in force beneath the new rules.
    #[test]
    fn disable_reports_a_failed_listing_without_deleting() {
        let e = disable_with(
            || {
                Err(io::Error::other(
                    "nft list tables exited 1: Operation not permitted",
                ))
            },
            || panic!("nothing is deleted on a listing nobody could read"),
        )
        .expect_err("a failed listing is not an absent table");
        assert!(e.to_string().contains("nft list tables"), "got {e}");
    }

    /// `disable` against a real `nft`: absent, then present, then absent
    /// again. Needs `CAP_NET_ADMIN` in a network namespace of its own, so it
    /// is ignored by default; run it unprivileged, under a non-English locale,
    /// with
    ///
    /// ```text
    /// LC_ALL=de_DE.UTF-8 unshare -rn cargo test -p torrentd --bin torrentd \
    ///     disable_against_real_nft -- --ignored
    /// ```
    #[test]
    #[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
    fn disable_against_real_nft() {
        disable().expect("no table yet: success, in any locale");
        apply(&render_ruleset(998, &["wg0".to_string()]).unwrap()).expect("install");
        assert!(table_listed(&list_tables().expect("list")));
        disable().expect("an installed table is deleted");
        assert!(!table_listed(&list_tables().expect("list")));
        disable().expect("and deleting it again is still success");
    }

    #[test]
    fn only_this_family_and_name_count_as_the_table() {
        assert!(table_listed(&format!("table inet {TABLE}\n")));
        assert!(table_listed(&format!("table ip nat\ntable inet {TABLE}")));
        assert!(!table_listed(&format!("table ip {TABLE}\n")));
        assert!(!table_listed(&format!("table inet {TABLE}_old\n")));
        assert!(!table_listed(""));
    }

    #[test]
    fn render_ruleset_would_happily_confine_uid_0() {
        // `render_ruleset` is pure and has no guard of its own: it renders a
        // ruleset that drops every root-owned socket on the host. This pins
        // the shape `refusal_for_uid` exists to keep out of `nft`; on its own
        // it establishes nothing about whether anything checks.
        let rs = render_ruleset(0, &["wg0".to_string()]).unwrap();
        assert!(
            rs.contains("meta skuid 0 counter drop"),
            "if this ever stops being catastrophic, revisit refusal_for_uid",
        );
    }

    #[test]
    fn ruleset_confines_uid_to_lo_and_tunnels() {
        let rs = render_ruleset(998, &["wg-b".to_string(), "wg-a".to_string()]).unwrap();
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
        let rs = render_ruleset(1000, &["wg0".to_string(), "wg0".to_string()]).unwrap();
        assert_eq!(rs.matches("wg0").count(), 1);
        // Still fails closed: lo accept, one tunnel accept, then drop.
        assert!(rs.contains("meta skuid 1000 counter drop"));
    }

    #[test]
    fn ruleset_with_no_tunnels_allows_only_loopback() {
        let rs = render_ruleset(1000, &[]).unwrap();
        assert!(!rs.contains("oifname {"));
        assert!(rs.contains("oifname \"lo\" accept"));
        assert!(rs.contains("counter drop"));
    }

    /// The shape from #33: a quote closes the set's quoted token early and
    /// `nft` rejects the whole table. The renderer refuses it by name instead
    /// of emitting a ruleset it knows will not parse.
    #[test]
    fn ruleset_refuses_a_name_it_cannot_quote() {
        for bad in ["wg\"x", "wg}x", "wg\nx", ""] {
            let e = render_ruleset(2000, &["lo".to_string(), bad.to_string()])
                .expect_err("an unquotable name is refused, not rendered");
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            assert!(e.to_string().contains(&format!("{bad:?}")), "got {e}");
        }
    }

    /// And `enable` refuses it before the pre-clear, so a previous run's kill
    /// switch stays armed rather than being deleted and never replaced.
    #[test]
    fn enable_refuses_an_unquotable_name_before_clearing() {
        let cleared = std::cell::Cell::new(false);
        let applied = std::cell::Cell::new(false);
        enable_for_uid(
            998,
            &["wg\"x".to_string()],
            |_| Ok(51820),
            || {
                cleared.set(true);
                Ok(())
            },
            |_| {
                applied.set(true);
                Ok(())
            },
        )
        .expect_err("an unquotable name stops the install");
        assert!(!cleared.get(), "the existing table is left in force");
        assert!(!applied.get(), "nothing is handed to nft");
    }
}
