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
//! dropped by the kernel — no dependency on the source-bind or the 30s poll.
//!
//! **It does not put DNS through the tunnel.** The ruleset matches sockets the
//! daemon's uid owns. A tracker hostname is resolved by libc, and on a host
//! with a local stub resolver — `systemd-resolved` on `127.0.0.53`, `dnsmasq`,
//! `unbound` — the daemon's query goes to loopback, which the ruleset accepts,
//! and the resolver forwards it upstream from *its own* uid over whatever
//! interface its configuration picks, usually the physical one. Only a host
//! whose `/etc/resolv.conf` names a remote resolver directly has the daemon's
//! own socket send the query, and then the query is dropped unless it would
//! leave by a tunnel. Which tracker hostnames the daemon looks up is therefore
//! visible to the host's upstream resolver unless the resolver itself is
//! pointed through a tunnel; see `docs/running.md`, "Kill switch".
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
//! - **WireGuard as a dedicated uid with `CAP_NET_ADMIN`: yes.** The daemon
//!   raises its links with `ip` and `wg` directly (see `vpn::wireguard`),
//!   which need only the capability. A link root raised before the daemon
//!   started, and which the daemon adopted, needs the same exemption and gets
//!   it: the packets are the daemon's either way.
//!
//! **Installed in one transaction.** [`install_script`] declares the table,
//! deletes it, and defines it again, and the whole script is one `nft -f`,
//! which nftables commits atomically. The install used to be a delete and
//! then a load, two commands with a window between them in which no kill
//! switch was in force at all — and a load that failed after the delete
//! succeeded left none in force for the rest of the run.
//!
//! **What it cuts off besides leaks: the HTTP API off loopback.** The chain
//! hooks `output` and matches the socket's owner, and a reply on a connection
//! someone else opened is still sent from a socket the daemon's uid owns. So a
//! request to `http_listen` — the API, a Prometheus scrape of
//! `/metrics` — that arrives on a physical interface is accepted and its reply
//! dropped: the client sees a connection that opens and then hangs. Over
//! loopback, or through a tunnel interface, it works. That is the ruleset
//! doing what it is for, and it is kept: accepting replies by conntrack
//! direction would let any of the daemon's listening sockets that accepts a
//! connection on the bare interface talk over it, which makes the guarantee
//! rest on how each socket is bound — the application-layer property this
//! module exists not to depend on. Reach the API through a reverse proxy on the
//! same host (loopback), or scrape from inside the tunnel.

use std::io;

use torrentd_engine::profile::ProfileConfig;
use tracing::info;

use super::exec;

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
///
/// Test-only since the kill switch and `vpn check` both render through
/// [`install_script`]: without the transport exemption this is the negative
/// control the live tests install, not a ruleset anything ships.
#[cfg(test)]
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
                 interface name must be 1-15 characters of [A-Za-z0-9_=+.-], and not \".\", \
                 \"..\", \"all\" or \"interfaces\"",
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

/// The script `enable` hands to `nft -f`, and the one `torrentd vpn check`
/// dry-runs: [`render_ruleset_with_transport`], preceded by the two lines that
/// make it replace whatever table of this name is standing in the same
/// transaction.
///
/// `add table` creates the table if it is absent and is a no-op if it is not,
/// so the `delete table` after it always has something to delete; the
/// definition after that is then loaded into an empty table. `nft -f` commits
/// a script as one transaction, so the kernel goes from the old ruleset to the
/// new one with no instant in which neither is in force, and a script that
/// fails anywhere changes nothing — a previous run's kill switch stays armed.
///
/// A replace is needed at all because `nft -f` *merges* a table definition
/// into an existing table: loaded over a stale one, the old run's tunnel
/// interfaces would still be accepted.
pub fn install_script(uid: u32, tunnels: &[String], transport_ports: &[u16]) -> io::Result<String> {
    let table = render_ruleset_with_transport(uid, tunnels, transport_ports)?;
    Ok(format!(
        "add table inet {TABLE}\ndelete table inet {TABLE}\n{table}"
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
    exec::available("nft", "--version")
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
/// for. Replaces any stale table left by a previous unclean exit in the same
/// transaction ([`install_script`]).
///
/// Refuses uid 0 outright — see [`refusal_for_uid`].
pub fn enable(tunnels: &[String]) -> io::Result<u32> {
    enable_for_uid(current_uid()?, tunnels, listen_port, apply)
}

/// The UDP port the WireGuard link `iface` listens on, from
/// `wg show <iface> listen-port`.
///
/// Read when the ruleset is installed, because a link with no `ListenPort`
/// is given a random one by the kernel when it comes up and no config holds
/// it. `0` — a link that is down and has no socket — is an error: there is
/// no transport to exempt, and the tunnel would not carry once it had one.
pub(crate) fn listen_port(iface: &str) -> io::Result<u16> {
    let out = exec::run_ok(
        "wg",
        &["show", exec::iface(iface)?, "listen-port"],
        None,
        exec::QUICK,
    )?;
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

/// `enable`, with the uid and the host calls handed in.
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
/// `apply` is the one `nft` call: the install is a single transaction
/// ([`install_script`]) that replaces a stale table and loads the new one
/// together. It used to be a separate `disable` and then a load, and between
/// the two no kill switch was in force; a load that then failed left none for
/// the rest of the run.
///
/// `transport_port` is the other host probe, handed in for the same reason:
/// the exemption it feeds is the difference between a WireGuard link the
/// daemon raised carrying traffic and carrying none.
pub(crate) fn enable_for_uid(
    uid: u32,
    tunnels: &[String],
    transport_port: impl Fn(&str) -> io::Result<u16>,
    apply: impl Fn(&str) -> io::Result<()>,
) -> io::Result<u32> {
    if let Some(refusal) = refusal_for_uid(uid) {
        return Err(refusal);
    }
    // Every port is read before anything is handed to nft. A tunnel whose
    // transport cannot be exempted is a tunnel the ruleset would silence, so
    // it fails the install — and leaves a previous run's kill switch armed.
    let ports = tunnels
        .iter()
        .map(|iface| transport_port(iface))
        .collect::<io::Result<Vec<u16>>>()?;
    // A name the ruleset cannot carry fails here, before nft, so a previous
    // run's kill switch stays armed.
    let script = install_script(uid, tunnels, &ports)?;
    apply(&script)?;
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

/// How often [`watch`] checks the table is still installed.
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Check, for as long as the daemon runs, that the kill switch this boot
/// installed is still there.
///
/// Installation is verified once; nothing after it noticed a table removed
/// underneath the daemon — a firewall service reloading its ruleset with
/// `nft flush ruleset` does exactly that — and the backstop was gone while
/// `kill_switch_active` still read 1. Each check sets
/// `kill_switch_table_present`; a check that cannot list the tables counts in
/// `kill_switch_probe_errors_total` and leaves the gauge as it was, since not
/// knowing is not the same as absent.
///
/// Only spawned when the kill switch is active.
pub async fn watch(
    metrics: std::sync::Arc<crate::metrics_sink::PromSink>,
    mut shutdown: tokio::sync::broadcast::Receiver<torrentd_engine::ShutdownReason>,
) {
    use torrentd_engine::MetricsSink;
    // Installed moments ago by `enable`, which checked it.
    metrics.set_gauge("kill_switch_table_present", 1.0, &[]);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(WATCH_INTERVAL) => {}
            _ = shutdown.recv() => return,
        }
        let listed = tokio::task::spawn_blocking(list_tables).await;
        record_check(
            &*metrics,
            listed.unwrap_or_else(|e| Err(io::Error::other(e))),
        );
    }
}

/// Turn one `nft list tables` outcome into the watch's metrics and log.
fn record_check(metrics: &dyn torrentd_engine::MetricsSink, listed: io::Result<String>) {
    match listed {
        Ok(listing) if table_listed(&listing) => {
            metrics.set_gauge("kill_switch_table_present", 1.0, &[]);
        }
        Ok(_) => {
            metrics.set_gauge("kill_switch_table_present", 0.0, &[]);
            tracing::error!(
                target: "torrentd::vpn::killswitch",
                table = TABLE,
                "the network kill switch's nftables table is gone; the daemon's egress is no \
                 longer confined to the tunnels. Restart the daemon to reinstall it",
            );
        }
        Err(e) => {
            metrics.inc_counter("kill_switch_probe_errors_total", &[]);
            tracing::warn!(
                target: "torrentd::vpn::killswitch",
                table = TABLE,
                error.cause = %e,
                "could not check the network kill switch is still installed",
            );
        }
    }
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
    let out = exec::run_ok("nft", &["list", "tables"], None, exec::QUICK)?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `nft delete table inet TABLE`. Any non-zero exit is an error: it is only
/// called once the table has been listed, so there is no absent case to
/// excuse.
fn delete_table() -> io::Result<()> {
    exec::run_ok(
        "nft",
        &["delete", "table", "inet", TABLE],
        None,
        exec::CHANGE,
    )
    .map(|_| ())
}

/// Feed a script to `nft -f -`, which commits it as one transaction.
pub(crate) fn apply(script: &str) -> io::Result<()> {
    exec::run_ok("nft", &["-f", "-"], Some(script.as_bytes()), exec::CHANGE).map(|_| ())
}

/// Dry-run a script through `nft --check --file -`: nftables parses it and
/// validates it against the live kernel, and installs nothing. The output is
/// returned whatever the status, for the caller to classify.
pub(crate) fn check(script: &str) -> io::Result<std::process::Output> {
    exec::run(
        "nft",
        &["--check", "--file", "-"],
        Some(script.as_bytes()),
        exec::QUICK,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_refuses_to_install_a_ruleset_as_root() {
        let called = std::cell::Cell::new(false);
        let e = enable_for_uid(
            0,
            &["wg-a".to_string()],
            |_| Ok(51820),
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
            |iface| Ok(if iface == "wg-a" { 51820 } else { 40001 }),
            |script| {
                calls.borrow_mut().push(script.to_string());
                Ok(())
            },
        )
        .expect("the supported shape — User=torrentd with CAP_NET_ADMIN — is not refused");

        assert_eq!(uid, 998, "the uid the ruleset was written for is returned");
        let calls = calls.borrow();
        assert_eq!(calls.len(), 1, "one transaction; got {calls:?}");
        let expected = "\
add table inet torrentd_ks
delete table inet torrentd_ks
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

    /// A transaction nft refuses is reported, not swallowed. Because it is
    /// one transaction, nft has changed nothing: the previous table, if any,
    /// is still in force.
    #[test]
    fn a_refused_transaction_is_reported() {
        let e = enable_for_uid(
            998,
            &[],
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
        apply(&install_script(998, &["wg0".to_string()], &[]).unwrap())
            .expect("install onto no table");
        apply(&install_script(998, &["wg1".to_string()], &[51820]).unwrap())
            .expect("and replace a standing one in the same transaction");
        let listed = exec::run_ok("nft", &["list", "table", "inet", TABLE], None, exec::QUICK)
            .expect("list the table");
        let listed = String::from_utf8_lossy(&listed.stdout);
        assert!(
            listed.contains("wg1") && !listed.contains("wg0"),
            "the replace leaves only this install's rules: {listed}"
        );
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
    fn enable_refuses_an_unquotable_name_before_nft() {
        let applied = std::cell::Cell::new(false);
        enable_for_uid(
            998,
            &["wg\"x".to_string()],
            |_| Ok(51820),
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

    #[test]
    fn the_watch_reads_a_listed_table_as_present() {
        let metrics = torrentd_engine::RecordingSink::new();
        record_check(
            &metrics,
            Ok(format!("table inet filter\ntable inet {TABLE}\n")),
        );
        assert_eq!(gauge(&metrics), Some(1.0));
    }

    #[test]
    fn the_watch_reads_a_flushed_ruleset_as_absent() {
        let metrics = torrentd_engine::RecordingSink::new();
        record_check(&metrics, Ok("table inet filter\n".to_string()));
        assert_eq!(gauge(&metrics), Some(0.0));
    }

    #[test]
    fn a_failed_listing_is_counted_and_is_not_read_as_absent() {
        let metrics = torrentd_engine::RecordingSink::new();
        record_check(&metrics, Err(io::Error::other("nft: permission denied")));
        assert_eq!(gauge(&metrics), None, "not knowing is not absent");
        assert_eq!(metrics.count_for("kill_switch_probe_errors_total"), 1);
    }
}
