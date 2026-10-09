//! Network-layer VPN kill switch (nftables) — defence-in-depth backstop.
//!
//! Multi-profile isolation's primary guard is that every profile's libtorrent sockets
//! are source-bound to the tunnel IP (`startup.rs`), and [`crate::vpn_monitor`]
//! pauses a profile on its next 30s poll after its tunnel's address goes, or
//! once its WireGuard handshake is older than `vpn_handshake_max_age_secs`
//! (default 180s) — up to that age plus a poll after the tunnel stops
//! carrying. Both live at the application layer:
//! the "no bare-IP leak" guarantee ultimately rests on libtorrent honouring the
//! bind and on the poll reacting in time.
//!
//! This module adds an independent, **fail-closed** nftables ruleset so the
//! daemon's own egress can only leave via loopback or a configured tunnel
//! interface. If a tunnel disappears its `oifname` is gone and the packets are
//! dropped by the kernel — no dependency on the source-bind or the monitor's
//! poll, for as long as the ruleset stands. A ruleset flushed or replaced by
//! another tool is caught by `watch` on its next 30s check, which fences
//! every vpn profile until the table is intact again; until that check runs,
//! the source-bind is the only guard.
//!
//! **Each profile is held to its own tunnel.** A tunnel is accepted only for
//! the address its profile's sessions are bound to: one rule per profile,
//! `meta skuid <uid> ip saddr <tunnel address> oifname "<its interface>"
//! accept`, with the address read off the live link when the ruleset is
//! installed ([`Tunnel`]). A shared `oifname { every tunnel }` set let any
//! socket the daemon owns leave by any profile's tunnel, so a packet from
//! profile A's address that the routing table sent out of profile B's tunnel
//! — A's per-source `ip rule` lost or shadowed — was accepted, and A's
//! trackers saw B's exit address until the next health poll. Now it falls
//! through to the drop. Only IPv4 is paired: the tunnel address every session
//! binds to is the link's first IPv4 address, and the daemon's IPv6 egress by
//! a tunnel, which nothing binds to, is dropped.
//!
//! **It does not put DNS through the tunnel.** The ruleset matches sockets the
//! daemon's uid owns. A tracker hostname is resolved by libc, and on a host
//! with a local stub resolver — `systemd-resolved` on `127.0.0.53`, `dnsmasq`,
//! `unbound` — the daemon's query goes to loopback, which the ruleset accepts,
//! and the resolver forwards it upstream from *its own* uid over whatever
//! interface its configuration picks, usually the physical one. Only a host
//! whose `/etc/resolv.conf` names a remote resolver directly has the daemon's
//! own socket send the query, and then the query is dropped unless it would
//! leave by a tunnel from that tunnel's address. Which tracker hostnames the
//! daemon looks up is therefore visible to the host's upstream resolver unless the resolver itself is
//! pointed through a tunnel; see `docs/running.md`, "Kill switch".
//!
//! Opt-in (`network_kill_switch = true`); needs `CAP_NET_ADMIN`, which the
//! packaged systemd unit does not grant as shipped: uncomment its
//! `AmbientCapabilities=` and `CapabilityBoundingSet=` lines for
//! `CAP_NET_ADMIN`. The daemon's traffic is matched by its
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
//! loopback, or to a tunnel's own address through that tunnel, it works. That is the ruleset
//! doing what it is for, and it is kept: accepting replies by conntrack
//! direction would let any of the daemon's listening sockets that accepts a
//! connection on the bare interface talk over it, which makes the guarantee
//! rest on how each socket is bound — the application-layer property this
//! module exists not to depend on. Reach the API through a reverse proxy on the
//! same host (loopback), or scrape from inside the tunnel.

use std::io;
use std::net::Ipv4Addr;

use torrentd_engine::profile::ProfileConfig;
use tracing::info;

use super::exec;

/// nftables table this module owns. Torn down on graceful shutdown, by a boot
/// with the kill switch off, and by `torrentd net-cleanup` (the packaged unit's
/// `ExecStopPost=`).
pub const TABLE: &str = "torrentd_ks";

/// One profile's tunnel as the ruleset pairs it: the interface, and the
/// address on it that the profile's sessions are bound to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tunnel {
    pub iface: String,
    pub addr: Ipv4Addr,
}

impl Tunnel {
    pub fn new(iface: impl Into<String>, addr: Ipv4Addr) -> Self {
        Self {
            iface: iface.into(),
            addr,
        }
    }
}

/// Refuse, with `InvalidInput` naming it, the first interface name
/// [`ProfileConfig::is_valid_interface_name`] rejects.
///
/// Each name is written between literal quotes, and nftables has no escape
/// for a `"` inside one, so a name carrying a quote, brace or newline would
/// produce a ruleset `nft` rejects with a syntax error in a file the operator
/// never wrote. Config validation refuses such a name first; this keeps the
/// renderer from emitting an unparseable ruleset for any caller that did not.
/// Separate from the renderer so `vpn check` refuses a name whose link it
/// could not read an address off, and so leaves out of the ruleset.
pub(crate) fn check_interface_names<'a>(
    ifaces: impl IntoIterator<Item = &'a str>,
) -> io::Result<()> {
    match ifaces
        .into_iter()
        .find(|i| !ProfileConfig::is_valid_interface_name(i))
    {
        None => Ok(()),
        Some(bad) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "vpn_interface {bad:?} cannot be written into the kill-switch ruleset: an \
                 interface name must be 1-15 characters of [A-Za-z0-9_=+.-], and not \".\", \
                 \"..\", \"all\" or \"interfaces\"",
            ),
        )),
    }
}

/// Render the fail-closed nftables ruleset confining uid `uid`'s egress to
/// loopback, and to each of `tunnels`' interfaces from that tunnel's own
/// address. Pure (no I/O) so it can be asserted byte-for-byte in tests.
/// Tunnels are de-duplicated and sorted so the output is deterministic
/// regardless of profile ordering.
///
/// The chain policy stays `accept` (we must not touch other uids' traffic); we
/// only `drop` packets owned by `uid` that don't egress loopback, or a tunnel
/// from its own address. A packet from one tunnel's address leaving by
/// another tunnel's interface matches no accept and is dropped.
///
/// Refuses an interface name it cannot quote; see [`check_interface_names`].
///
/// Test-only since the kill switch and `vpn check` both render through
/// [`install_script`]: without the transport exemption this is the negative
/// control the live tests install, not a ruleset anything ships.
#[cfg(test)]
pub fn render_ruleset(uid: u32, tunnels: &[Tunnel]) -> io::Result<String> {
    render_ruleset_with_transport(uid, tunnels, &[])
}

/// [`render_ruleset`], plus the tunnels' own transport: each port in
/// `transport_ports` is accepted as a UDP source port for `uid` on any
/// interface, ahead of the drop.
///
/// This is the ruleset `enable` installs. Without it no WireGuard link
/// carries the daemon's traffic: the encrypted UDP to the provider leaves by
/// the physical interface still attached to the daemon's sending socket, so
/// it matches `meta skuid <uid>` and the final `drop` takes it. Ports are
/// de-duplicated and sorted, like the tunnels, so the output is deterministic.
pub fn render_ruleset_with_transport(
    uid: u32,
    tunnels: &[Tunnel],
    transport_ports: &[u16],
) -> io::Result<String> {
    check_interface_names(tunnels.iter().map(|t| t.iface.as_str()))?;
    let mut pairs: Vec<&Tunnel> = tunnels.iter().collect();
    pairs.sort_unstable();
    pairs.dedup();

    let mut chain = String::new();
    chain.push_str("\t\ttype filter hook output priority 0; policy accept;\n");
    chain.push_str(&format!("\t\tmeta skuid {uid} oifname \"lo\" accept\n"));
    for Tunnel { iface, addr } in pairs {
        chain.push_str(&format!(
            "\t\tmeta skuid {uid} ip saddr {addr} oifname \"{iface}\" accept\n"
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
pub fn install_script(uid: u32, tunnels: &[Tunnel], transport_ports: &[u16]) -> io::Result<String> {
    let table = render_ruleset_with_transport(uid, tunnels, transport_ports)?;
    Ok(replace_script(&table))
}

/// `table`, preceded by the two lines that make `nft -f` replace a standing
/// table of this name with it in one transaction; see [`install_script`].
fn replace_script(table: &str) -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n{table}")
}

/// The kill switch as `enable` installed it: the uid it confines, and the
/// table it rendered, which [`verify`] compares the live one with and
/// [`watch`] installs again when they differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub uid: u32,
    table: String,
}

impl Installed {
    /// The script that installs this table again, replacing whatever stands
    /// in its place, as one transaction.
    fn script(&self) -> String {
        replace_script(&self.table)
    }
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
/// loopback and to each of `tunnels` from the address its link holds, with
/// each tunnel's own transport exempted (see
/// [`render_ruleset_with_transport`]). Returns what was installed: the uid the
/// ruleset was written for, and the table, for [`verify`] and [`watch`].
/// Replaces any stale table left by a previous unclean exit in the same
/// transaction ([`install_script`]).
///
/// Refuses uid 0 outright — see [`refusal_for_uid`].
pub fn enable(tunnels: &[String]) -> io::Result<Installed> {
    enable_for_uid(
        current_uid()?,
        tunnels,
        super::ip_lookup::first_ipv4,
        listen_port,
        apply,
    )
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
/// `tunnel_addr` and `transport_port` are the other host probes, handed in
/// for the same reason: the pairing the first feeds is what keeps one
/// profile's traffic out of another's tunnel, and the exemption the second
/// feeds is the difference between a WireGuard link the daemon raised
/// carrying traffic and carrying none. `tunnel_addr` reads the address every
/// session of the profile is bound to — the link's first IPv4 address, which
/// is what bring-up hands the session.
pub(crate) fn enable_for_uid(
    uid: u32,
    tunnels: &[String],
    tunnel_addr: impl Fn(&str) -> io::Result<Ipv4Addr>,
    transport_port: impl Fn(&str) -> io::Result<u16>,
    apply: impl Fn(&str) -> io::Result<()>,
) -> io::Result<Installed> {
    if let Some(refusal) = refusal_for_uid(uid) {
        return Err(refusal);
    }
    // Every address and port is read before anything is handed to nft. A
    // tunnel with no address to pair it with, or whose transport cannot be
    // exempted, is a tunnel the ruleset would silence, so it fails the
    // install — and leaves a previous run's kill switch armed.
    let paired = tunnels
        .iter()
        .map(|iface| {
            tunnel_addr(iface)
                .map(|addr| Tunnel::new(iface.as_str(), addr))
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "the kill switch pairs {iface} with its tunnel address, and none \
                             could be read: {e}"
                        ),
                    )
                })
        })
        .collect::<io::Result<Vec<Tunnel>>>()?;
    let ports = tunnels
        .iter()
        .map(|iface| transport_port(iface))
        .collect::<io::Result<Vec<u16>>>()?;
    // A name the ruleset cannot carry fails here, before nft, so a previous
    // run's kill switch stays armed.
    let installed = Installed {
        uid,
        table: render_ruleset_with_transport(uid, &paired, &ports)?,
    };
    apply(&installed.script())?;
    info!(
        target: "torrentd::vpn::killswitch",
        uid,
        tunnels = ?paired,
        transport_ports = ?ports,
        "network kill switch installed (nftables, fail-closed)",
    );
    Ok(installed)
}

/// Remove the kill-switch table.
///
/// A missing table is success. Shutdown must never fail on it, and the other
/// callers usually find no table: the failed-boot guard, a boot with
/// `network_kill_switch = false` clearing what an unclean exit left
/// ([`remove_table`]), and `torrentd net-cleanup`. A boot with the kill switch
/// on does not call this: [`install_script`] replaces a stale table in the
/// same transaction as the install. Any other failure is reported, because a
/// table that failed to delete keeps confining the daemon's uid.
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
    remove_table().map(|_| ())
}

/// [`disable`], saying whether there was a table to remove: `true` when one
/// was listed and deleted, `false` when none was there.
///
/// For the callers to whom a table is news. A boot with the kill switch off
/// and `torrentd net-cleanup` find one only where an earlier run exited
/// without removing it, and say so.
pub fn remove_table() -> io::Result<bool> {
    disable_with(list_tables, delete_table)
}

/// [`remove_table`], with both `nft` calls handed in so the decision between
/// them is reachable by a test on a host without `nft` or `CAP_NET_ADMIN`.
pub(crate) fn disable_with(
    list: impl Fn() -> io::Result<String>,
    delete: impl Fn() -> io::Result<()>,
) -> io::Result<bool> {
    if !table_listed(&list()?) {
        return Ok(false);
    }
    delete().map(|()| true)
}

/// What [`verify`] found in place of the table `enable` installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The live table is the rendered one, rule for rule.
    Intact,
    /// No table of this name is listed.
    Absent,
    /// The table is listed and is not the one rendered: a chain or rule
    /// flushed, replaced or added. Says where it first differs.
    Drifted(String),
}

/// Compare the live kill-switch table with the one `installed` rendered.
///
/// The table's name being listed is not enough: `nft flush chain` or a
/// firewall manager replacing the table's contents leaves the name standing
/// with nothing in it. So the live table is listed as JSON
/// (`nft -j list table`), read back into the text [`render_ruleset_with_transport`]
/// writes, and compared with it. Whether the table exists at all is asked of
/// `nft list tables` first, as [`remove_table`] asks it: a listing of a
/// missing table fails with a localised message, and that failure is kept for
/// what it is — a check that could not run.
pub(crate) fn verify(installed: &Installed) -> io::Result<Verdict> {
    verify_with(installed, list_tables, list_table_json)
}

/// [`verify`], with both `nft` calls handed in.
pub(crate) fn verify_with(
    installed: &Installed,
    list: impl Fn() -> io::Result<String>,
    list_json: impl Fn() -> io::Result<String>,
) -> io::Result<Verdict> {
    if !table_listed(&list()?) {
        return Ok(Verdict::Absent);
    }
    let json: serde_json::Value = serde_json::from_str(&list_json()?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("nft -j list table printed something that is not JSON: {e}"),
        )
    })?;
    let live = match live_table(&json) {
        Ok(live) => live,
        Err(why) => return Ok(Verdict::Drifted(why)),
    };
    if live == installed.table {
        return Ok(Verdict::Intact);
    }
    let (want, got) = (installed.table.lines(), live.lines());
    let mut want = want.map(str::trim);
    let mut got = got.map(str::trim);
    let why = loop {
        match (want.next(), got.next()) {
            (Some(w), Some(g)) if w == g => continue,
            (w, g) => {
                break format!(
                    "installed {:?}, live {:?}",
                    w.unwrap_or("<nothing>"),
                    g.unwrap_or("<nothing>"),
                )
            }
        }
    };
    Ok(Verdict::Drifted(why))
}

/// `nft -j list table inet TABLE`, read back into the text
/// [`render_ruleset_with_transport`] writes, or why it cannot be: an object or
/// expression of a kind this module never installs is not this module's
/// table.
///
/// Counters are read without their values, and a one-port `udp sport` set,
/// which nft stores as a single value, is read as the set it was written as.
fn live_table(json: &serde_json::Value) -> Result<String, String> {
    use serde_json::Value;
    let items = json
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or("the listing has no nftables array")?;
    // Each chain's header line, if it is a base chain, and its rules.
    let mut chains: Vec<(String, Option<String>, Vec<String>)> = Vec::new();
    for item in items {
        let Some((kind, body)) = item
            .as_object()
            .filter(|o| o.len() == 1)
            .and_then(|o| o.iter().next())
        else {
            return Err(format!("an unread entry {item}"));
        };
        match kind.as_str() {
            "metainfo" | "table" => {}
            "chain" => {
                let name = body["name"].as_str().ok_or("a chain with no name")?;
                let header = match (
                    body["type"].as_str(),
                    body["hook"].as_str(),
                    scalar(&body["prio"]),
                    body["policy"].as_str(),
                ) {
                    (Some(t), Some(hook), Some(prio), Some(policy)) => Some(format!(
                        "type {t} hook {hook} priority {prio}; policy {policy};"
                    )),
                    _ => None,
                };
                chains.push((name.to_string(), header, Vec::new()));
            }
            "rule" => {
                let chain = body["chain"].as_str().ok_or("a rule with no chain")?;
                let line = rule_line(&body["expr"])?;
                chains
                    .iter_mut()
                    .find(|(name, ..)| name == chain)
                    .ok_or_else(|| format!("a rule in chain {chain:?}, which is not listed"))?
                    .2
                    .push(line);
            }
            other => {
                return Err(format!(
                    "the table holds a {other}, which the kill switch never installs"
                ))
            }
        }
    }
    let mut out = format!("table inet {TABLE} {{\n");
    for (name, header, rules) in chains {
        out.push_str(&format!("\tchain {name} {{\n"));
        for line in header.iter().chain(&rules) {
            out.push_str(&format!("\t\t{line}\n"));
        }
        out.push_str("\t}\n");
    }
    out.push_str("}\n");
    Ok(out)
}

/// A number or a string from the listing, as the ruleset text writes it.
fn scalar(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// One rule's `expr` array, as the line [`render_ruleset_with_transport`]
/// writes for it. Reads only the matches and verdicts that function renders.
fn rule_line(exprs: &serde_json::Value) -> Result<String, String> {
    let exprs = exprs.as_array().ok_or("a rule with no expressions")?;
    let unread =
        |e: &serde_json::Value| format!("an expression the kill switch never installs: {e}");
    let mut words = Vec::with_capacity(exprs.len());
    for e in exprs {
        if let Some(m) = e.get("match") {
            if m["op"] != "==" {
                return Err(unread(e));
            }
            let (left, right) = (&m["left"], &m["right"]);
            let key = match (
                left.pointer("/meta/key").and_then(|k| k.as_str()),
                left.pointer("/payload/protocol").and_then(|p| p.as_str()),
                left.pointer("/payload/field").and_then(|f| f.as_str()),
            ) {
                (Some("skuid"), ..) => "meta skuid",
                (Some("oifname"), ..) => "oifname",
                (None, Some("ip"), Some("saddr")) => "ip saddr",
                (None, Some("udp"), Some("sport")) => "udp sport",
                _ => return Err(unread(e)),
            };
            let value = match key {
                "oifname" => right.as_str().map(|s| format!("\"{s}\"")),
                "udp sport" => match right.pointer("/set").and_then(|s| s.as_array()) {
                    Some(set) => set
                        .iter()
                        .map(scalar)
                        .collect::<Option<Vec<_>>>()
                        .map(|ports| format!("{{ {} }}", ports.join(", "))),
                    None => scalar(right).map(|port| format!("{{ {port} }}")),
                },
                _ => scalar(right),
            }
            .ok_or_else(|| unread(e))?;
            words.push(format!("{key} {value}"));
        } else if e.get("counter").is_some() {
            words.push("counter".to_string());
        } else if e.get("accept").is_some() {
            words.push("accept".to_string());
        } else if e.get("drop").is_some() {
            words.push("drop".to_string());
        } else {
            return Err(unread(e));
        }
    }
    Ok(words.join(" "))
}

/// `nft -j list table inet TABLE`, returning its stdout.
fn list_table_json() -> io::Result<String> {
    let out = exec::run_ok(
        "nft",
        &["-j", "list", "table", "inet", TABLE],
        None,
        exec::QUICK,
    )?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// What [`watch`] does to the vpn profiles while the kill switch is not in
/// force as installed. Implemented over the profile registry by
/// `vpn_monitor::KillSwitchFence`; a trait so the watch's decisions are
/// reachable by a test with no sessions.
pub(crate) trait Fence: Send + Sync {
    /// Fence every vpn profile that is not fenced already, as the VPN monitor
    /// fences one whose tunnel is down.
    fn fence_all(&self);
    /// Lift what [`Fence::fence_all`] fenced: called only once the ruleset
    /// has been verified intact again.
    fn lift(&self);
}

/// How often [`watch`] checks the table is still installed.
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Where the watch stands between checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Watch {
    /// The last check found the table as installed.
    #[default]
    Intact,
    /// A check found it gone or changed: every vpn profile was fenced, and the
    /// one reinstall this loss gets was tried and did not check intact.
    Lost,
}

/// Check, for as long as the daemon runs, that the kill switch this boot
/// installed is still in force exactly as installed.
///
/// Installation is verified once, at boot. After that a firewall service
/// reloading its ruleset (`nft flush ruleset`), or an operator flushing the
/// chain while debugging, removes the backstop underneath the daemon. Only
/// the table's name used to be checked, so a flushed chain read as present,
/// and a removed table was only logged while every profile kept seeding.
///
/// Each check compares the live table with the rendered one ([`verify`]) and
/// sets `kill_switch_table_present` to whether it matched. A table gone or
/// changed fences every vpn profile, then the table is installed again once,
/// in one transaction, and checked again; only a reinstall that checks intact
/// lifts the fence. While it is not intact the check repeats each interval,
/// fencing again any profile set online meanwhile; a later check that finds it
/// intact — restored by the operator — lifts the fence then. A check that
/// cannot run counts in `kill_switch_probe_errors_total` and changes nothing,
/// since not knowing is not the same as absent.
///
/// Only spawned when the kill switch is active.
pub(crate) async fn watch(
    installed: Installed,
    fence: std::sync::Arc<dyn Fence>,
    metrics: std::sync::Arc<crate::metrics_sink::PromSink>,
    mut shutdown: tokio::sync::broadcast::Receiver<torrentd_engine::ShutdownReason>,
) {
    use torrentd_engine::MetricsSink;
    // Installed moments ago by `enable`, and verified by the boot.
    metrics.set_gauge("kill_switch_table_present", 1.0, &[]);
    let installed = std::sync::Arc::new(installed);
    let mut state = Watch::default();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(WATCH_INTERVAL) => {}
            _ = shutdown.recv() => return,
        }
        // Blocking throughout: the checks and the reinstall shell out to nft,
        // and fencing pauses torrents under each session's lock.
        let ticked = tokio::task::spawn_blocking({
            let (installed, fence, metrics) = (installed.clone(), fence.clone(), metrics.clone());
            move || {
                tick(
                    state,
                    || verify(&installed),
                    || apply(&installed.script()),
                    &*fence,
                    &*metrics,
                )
            }
        })
        .await;
        match ticked {
            Ok(next) => state = next,
            Err(e) => {
                metrics.inc_counter("kill_switch_probe_errors_total", &[]);
                tracing::warn!(
                    target: "torrentd::vpn::killswitch",
                    table = TABLE,
                    error.cause = %e,
                    "the network kill switch check failed to run",
                );
            }
        }
    }
}

/// One check of [`watch`]'s, from where the last one left it: verify, fence
/// and reinstall on a loss, lift on a verified recovery. Returns where it
/// leaves the watch.
fn tick(
    state: Watch,
    verify: impl Fn() -> io::Result<Verdict>,
    reinstall: impl Fn() -> io::Result<()>,
    fence: &dyn Fence,
    metrics: &dyn torrentd_engine::MetricsSink,
) -> Watch {
    let why = match verify() {
        Ok(Verdict::Intact) => {
            metrics.set_gauge("kill_switch_table_present", 1.0, &[]);
            if state != Watch::Intact {
                tracing::warn!(
                    target: "torrentd::vpn::killswitch",
                    table = TABLE,
                    "the network kill switch is in force as installed again; lifting the fence \
                     it put on the vpn profiles",
                );
                fence.lift();
            }
            return Watch::Intact;
        }
        Ok(Verdict::Absent) => "the table is gone".to_string(),
        Ok(Verdict::Drifted(why)) => why,
        Err(e) => {
            metrics.inc_counter("kill_switch_probe_errors_total", &[]);
            tracing::warn!(
                target: "torrentd::vpn::killswitch",
                table = TABLE,
                error.cause = %e,
                "could not check the network kill switch is still installed",
            );
            return state;
        }
    };
    metrics.set_gauge("kill_switch_table_present", 0.0, &[]);
    tracing::error!(
        target: "torrentd::vpn::killswitch",
        table = TABLE,
        drift = %why,
        "the network kill switch is not in force as installed, so the daemon's egress is no \
         longer confined to the tunnels; fencing every vpn profile",
    );
    fence.fence_all();
    if state == Watch::Lost {
        return Watch::Lost;
    }
    match reinstall().and_then(|()| verify()) {
        Ok(Verdict::Intact) => {
            metrics.set_gauge("kill_switch_table_present", 1.0, &[]);
            tracing::warn!(
                target: "torrentd::vpn::killswitch",
                table = TABLE,
                "reinstalled the network kill switch and verified it; lifting the fence",
            );
            fence.lift();
            Watch::Intact
        }
        Ok(verdict) => {
            tracing::error!(
                target: "torrentd::vpn::killswitch",
                table = TABLE,
                verdict = ?verdict,
                "reinstalled the network kill switch, and it still does not check as installed; \
                 the vpn profiles stay fenced. Restart the daemon to reinstall it",
            );
            Watch::Lost
        }
        Err(e) => {
            tracing::error!(
                target: "torrentd::vpn::killswitch",
                table = TABLE,
                error.cause = %e,
                "could not reinstall the network kill switch; the vpn profiles stay fenced. \
                 Restart the daemon to reinstall it",
            );
            Watch::Lost
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

    /// What the rendered chain does with one packet of `uid`'s, read the way
    /// nftables reads it: the first rule whose every match holds decides, and
    /// a packet no rule decides takes the chain's `accept` policy.
    ///
    /// Reads only the shapes this module renders — `meta skuid`, `ip saddr`,
    /// `oifname` (one name or a set), `udp sport` (a set) — and panics on
    /// anything else, so a new kind of match cannot be silently ignored here.
    ///
    /// `udp_sport` is `None` for a packet that is not UDP, which no
    /// `udp sport` match holds for.
    fn verdict(
        ruleset: &str,
        uid: u32,
        saddr: Ipv4Addr,
        oif: &str,
        udp_sport: Option<u16>,
    ) -> &'static str {
        const MATCHES: [&str; 4] = ["meta skuid ", "ip saddr ", "oifname ", "udp sport "];
        for line in ruleset.lines().map(str::trim) {
            if !line.starts_with("meta skuid ") {
                continue;
            }
            let (mut rest, verdict) = if let Some(m) = line.strip_suffix(" accept") {
                (m, "accept")
            } else if let Some(m) = line.strip_suffix(" counter drop") {
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
                let packet = match key {
                    "meta skuid " => Some(uid.to_string()),
                    "ip saddr " => Some(saddr.to_string()),
                    "oifname " => Some(oif.to_string()),
                    _ => udp_sport.map(|p| p.to_string()),
                };
                holds &= packet.is_some_and(|p| values.contains(&p.as_str()));
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
            addr_of,
            |iface| Ok(if iface == "wg-a" { 51820 } else { 40001 }),
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
add table inet torrentd_ks
delete table inet torrentd_ks
table inet torrentd_ks {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
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
            addr_of,
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
            |_| Ok(51820),
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
        let rs = render_ruleset_with_transport(998, &[tunnel("wg-a"), tunnel("wg-b")], &[51820])
            .unwrap();

        assert_eq!(verdict(&rs, 998, ADDR_A, "wg-a", None), "accept");
        assert_eq!(verdict(&rs, 998, ADDR_B, "wg-b", None), "accept");
        assert_eq!(
            verdict(&rs, 998, ADDR_A, "wg-b", None),
            "drop",
            "A's address on B's tunnel is dropped:\n{rs}"
        );
        assert_eq!(
            verdict(&rs, 998, ADDR_B, "wg-a", Some(6881)),
            "drop",
            "and B's on A's, UDP included:\n{rs}"
        );
        assert_eq!(
            verdict(&rs, 998, Ipv4Addr::new(192, 168, 1, 20), "wg-a", None),
            "drop",
            "an address no profile holds is dropped on every tunnel:\n{rs}"
        );
        assert_eq!(
            verdict(&rs, 1000, ADDR_A, "wg-b", None),
            "accept",
            "another uid's traffic is not this ruleset's to judge"
        );

        // The control: the shared accept this replaced let A out of B's tunnel.
        let shared = "\
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 oifname { \"wg-a\", \"wg-b\" } accept
\t\tmeta skuid 998 counter drop
";
        assert_eq!(verdict(shared, 998, ADDR_A, "wg-b", None), "accept");
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
            &[tunnel("wg-a"), tunnel("wg-b")],
            &[51820, 40001, 51820],
        )
        .unwrap();
        let expected = "\
table inet torrentd_ks {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
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
            |_| unreachable!("no tunnels, no addresses"),
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
        assert!(!removed, "and no table is reported removed");

        let removed = disable_with(|| Ok(String::new()), || panic!("no tables at all"))
            .expect("an empty listing is an absent table");
        assert!(!removed);
    }

    #[test]
    fn disable_deletes_a_listed_table_and_reports_its_failure() {
        let deleted = std::cell::Cell::new(false);
        let removed = disable_with(
            || Ok(format!("table ip filter\ntable inet {TABLE}\n")),
            || {
                deleted.set(true);
                Ok(())
            },
        )
        .expect("a delete that succeeded");
        assert!(deleted.get(), "a listed table is deleted");
        assert!(
            removed,
            "and reported removed, so a caller can say it found one"
        );

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
        apply(&install_script(998, &[tunnel("wg0")], &[]).unwrap()).expect("install onto no table");
        apply(&install_script(998, &[tunnel("wg1")], &[51820]).unwrap())
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
        let rs = render_ruleset(998, &[tunnel("wg-b"), tunnel("wg-a")]).unwrap();
        let expected = "\
table inet torrentd_ks {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
\t\tmeta skuid 998 counter drop
\t}
}
";
        assert_eq!(rs, expected);
    }

    #[test]
    fn ruleset_dedups_shared_interface() {
        let rs = render_ruleset(1000, &[tunnel("wg0"), tunnel("wg0")]).unwrap();
        assert_eq!(rs.matches("wg0").count(), 1);
        // Still fails closed: lo accept, one tunnel accept, then drop.
        assert!(rs.contains("meta skuid 1000 counter drop"));
    }

    #[test]
    fn ruleset_with_no_tunnels_allows_only_loopback() {
        let rs = render_ruleset(1000, &[]).unwrap();
        assert!(!rs.contains("saddr"));
        assert!(rs.contains("oifname \"lo\" accept"));
        assert!(rs.contains("counter drop"));
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

    /// What `enable` installs for uid 998 over `wg-a` with two transport
    /// ports: the table [`LIVE`] is nft's listing of.
    fn installed() -> Installed {
        Installed {
            uid: 998,
            table: render_ruleset_with_transport(998, &[tunnel("wg-a")], &[51820, 40001]).unwrap(),
        }
    }

    const META: &str = r#"{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "torrentd_ks", "handle": 1}}, {"chain": {"family": "inet", "table": "torrentd_ks", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}"#;
    const LO: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 2, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"accept": null}]}}"#;
    const WG_A: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 3, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.2.0.2"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg-a"}}, {"accept": null}]}}"#;
    const PORTS: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 5, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "sport"}}, "right": {"set": [40001, 51820]}}}, {"accept": null}]}}"#;
    const DROP: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 6, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"counter": {"packets": 12, "bytes": 960}}, {"drop": null}]}}"#;

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
            verify_listing(listing(&[META, LO, WG_A, PORTS, DROP])).unwrap(),
            Verdict::Intact,
            "counter values and rule handles are not drift",
        );
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
            why.starts_with("installed \"meta skuid 998 oifname \\\"lo\\\" accept\""),
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
        let accept_all = r#"{"rule": {"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 7, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"accept": null}]}}"#;
        let other_addr = WG_A.replace("10.2.0.2", "10.9.9.9");
        let drop_policy = META.replace(r#""policy": "accept""#, r#""policy": "drop""#);
        let set = r#"{"set": {"family": "inet", "name": "s", "table": "torrentd_ks", "type": "ipv4_addr", "handle": 4}}"#;
        let unread = DROP.replace(r#"{"drop": null}"#, r#"{"jump": {"target": "x"}}"#);
        for (label, json) in [
            (
                "an accept ahead of the drop",
                listing(&[META, LO, accept_all, WG_A, PORTS, DROP]),
            ),
            (
                "a tunnel address replaced",
                listing(&[META, LO, &other_addr, PORTS, DROP]),
            ),
            (
                "the policy changed",
                listing(&[&drop_policy, LO, WG_A, PORTS, DROP]),
            ),
            ("a set", listing(&[META, set, LO, WG_A, PORTS, DROP])),
            (
                "an unread verdict",
                listing(&[META, LO, WG_A, PORTS, &unread]),
            ),
        ] {
            assert!(
                matches!(verify_listing(json).unwrap(), Verdict::Drifted(_)),
                "{label} is drift",
            );
        }
    }

    /// nft stores a one-element set as the single value; it is read back as
    /// the set the renderer writes.
    #[test]
    fn a_one_port_set_reads_back_as_rendered() {
        let one = Installed {
            uid: 998,
            table: render_ruleset_with_transport(998, &[tunnel("wg-a")], &[51820]).unwrap(),
        };
        let port = PORTS.replace(r#"{"set": [40001, 51820]}"#, "51820");
        let json = listing(&[META, LO, WG_A, &port, DROP]);
        let verdict = verify_with(
            &one,
            || Ok(format!("table inet {TABLE}\n")),
            move || Ok(json.clone()),
        )
        .unwrap();
        assert_eq!(verdict, Verdict::Intact);
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
        fn fence_all(&self) {
            self.0.lock().unwrap().push("fence");
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

    /// Verdicts handed out in order, one per call.
    fn verdicts(v: Vec<io::Result<Verdict>>) -> impl Fn() -> io::Result<Verdict> {
        let v = std::cell::RefCell::new(std::collections::VecDeque::from(v));
        move || v.borrow_mut().pop_front().expect("no more checks scripted")
    }

    fn drifted() -> io::Result<Verdict> {
        Ok(Verdict::Drifted("installed x, live <nothing>".into()))
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
        }
    }

    #[test]
    fn a_check_that_cannot_run_is_counted_and_changes_nothing() {
        for state in [Watch::Intact, Watch::Lost] {
            let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
            let next = tick(
                state,
                verdicts(vec![Err(io::Error::other("nft: permission denied"))]),
                || panic!("nothing is reinstalled on a check that did not run"),
                &fence,
                &metrics,
            );
            assert_eq!(next, state);
            assert_eq!(gauge(&metrics), None, "not knowing is not absent");
            assert_eq!(fence.take(), Vec::<&str>::new());
            assert_eq!(metrics.count_for("kill_switch_probe_errors_total"), 1);
        }
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
        disable().expect("remove");
        assert_eq!(verify(&installed).unwrap(), Verdict::Absent);
    }
}
