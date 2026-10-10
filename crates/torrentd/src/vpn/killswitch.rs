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
//! through to the drop. Every address a session sends from is paired: the
//! link's first IPv4 address, and each global IPv6 address on it
//! ([`Tunnel::with_v6`]), since a session listens on its tunnel device and so
//! listens and announces on every address the device holds. The daemon's
//! IPv6 egress from any other address (a link-local one included) is dropped.
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
//! exemption per tunnel and provider endpoint: a UDP datagram of the daemon's
//! uid from the tunnel's **listen port** to the **peer endpoint**, each read
//! off the live link (`wg show <iface> listen-port` and `wg show <iface>
//! endpoints`) — `meta skuid <uid> ip daddr <endpoint> udp sport <listen
//! port> udp dport <endpoint port> accept` ([`render_ruleset_with_transport`]).
//! While the link is up nothing the daemon opens itself can hold that port:
//! the WireGuard socket binds it on the wildcard address without address
//! reuse, so a libtorrent bind to it fails with `EADDRINUSE`. Once the link
//! goes the port is free, and a socket that then holds it — bound to it, or
//! handed it as an ephemeral port — reaches only the provider's endpoint
//! through the exemption, never anywhere else.
//!
//! **The exemption follows the link.** A link taken down and raised again
//! without a `ListenPort` comes back on a port the kernel picks, and possibly
//! to another endpoint. Handshakes carry no socket and pass whatever the
//! ruleset says, so a tunnel whose exemption names the old port handshakes,
//! passes every health check, and carries nothing. [`watch`] re-reads each
//! tunnel's transport on every check and, when it changed, installs the
//! ruleset again with the live one ([`refresh`]); a reinstall that does not
//! take is the loss its check already handles, which fences every vpn
//! profile.
//!
//! **A tunnel's address leaves by that tunnel or not at all, whoever sent
//! it.** Ahead of every uid rule, `ip saddr <tunnel address> oifname != {
//! "lo", "<iface>" } drop` takes any packet carrying a tunnel's address out of
//! any other interface. The uid rules cannot: a TCP reset for a closed port
//! and an ICMP port-unreachable are built by the kernel with no socket of the
//! daemon's attached, so with a tunnel's `from <address>` routing rule lost,
//! the kernel's answer to a probe of the tunnel address arriving on the
//! physical link went back out of it from the tunnel address, tying that
//! address to the host. Tunnels sharing an address (providers that hand
//! every client the same one) share the rule, each of their interfaces
//! allowed.
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

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;

use torrentd_engine::profile::ProfileConfig;
use tracing::info;

use super::exec;

/// The name every table this module installs starts with, and the whole name
/// of the one table earlier releases installed for whichever uid ran them.
const TABLE_PREFIX: &str = "torrentd_ks";

/// The nftables table this module owns for `uid`: `torrentd_ks_<uid>`. Torn
/// down on graceful shutdown, by a boot with the kill switch off, and by
/// `torrentd net-cleanup` (the packaged unit's `ExecStopPost=`).
///
/// One table per uid, because the ruleset confines one uid and each of those
/// callers removes the table it finds. Under a single fixed name, a daemon
/// with the kill switch off — an OpenVPN or host-profile daemon beside a
/// WireGuard one, the layout docs/running.md prescribes — deleted the other
/// daemon's table each time it booted or stopped, and left that daemon's
/// egress unconfined until its watch noticed. Two daemons sharing a uid in one
/// network namespace still share a table; docs/running.md requires separate
/// uids.
pub fn table_name(uid: u32) -> String {
    format!("{TABLE_PREFIX}_{uid}")
}

/// The table for this process's uid, or the name's pattern where the uid
/// cannot be read: for messages that tell an operator what to delete.
pub fn own_table_name() -> String {
    current_uid().map_or_else(|_| format!("{TABLE_PREFIX}_<uid>"), table_name)
}

/// One profile's tunnel as the ruleset pairs it: the interface, and the
/// addresses on it the profile's sessions send from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tunnel {
    pub iface: String,
    /// The link's first IPv4 address, which the tunnel is routed by.
    pub addr: Ipv4Addr,
    /// The link's global IPv6 addresses, sorted. A session listening on the
    /// device listens and announces on each of them too.
    pub v6: Vec<Ipv6Addr>,
}

impl Tunnel {
    pub fn new(iface: impl Into<String>, addr: Ipv4Addr) -> Self {
        Self {
            iface: iface.into(),
            addr,
            v6: Vec::new(),
        }
    }

    /// Pair the link's IPv6 addresses with it as well.
    pub fn with_v6(mut self, v6: impl IntoIterator<Item = Ipv6Addr>) -> Self {
        self.v6 = v6.into_iter().collect();
        self.v6.sort_unstable();
        self.v6.dedup();
        self
    }

    /// Every address the ruleset pairs with this tunnel, IPv4 first.
    fn addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        std::iter::once(IpAddr::V4(self.addr)).chain(self.v6.iter().copied().map(IpAddr::V6))
    }
}

/// `ip` or `ip6`: the nftables payload protocol an address is matched in.
fn family(addr: &IpAddr) -> &'static str {
    if addr.is_ipv4() {
        "ip"
    } else {
        "ip6"
    }
}

/// One WireGuard link's own transport as the ruleset exempts it: the UDP port
/// the link listens on, and the endpoint of each peer that has one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Transport {
    pub listen_port: u16,
    pub endpoints: Vec<SocketAddr>,
}

impl Transport {
    pub fn new(listen_port: u16, endpoints: impl IntoIterator<Item = SocketAddr>) -> Self {
        let mut endpoints: Vec<SocketAddr> = endpoints.into_iter().collect();
        endpoints.sort_unstable();
        endpoints.dedup();
        Self {
            listen_port,
            endpoints,
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

/// [`render_ruleset`], plus the tunnels' own transport: for each of
/// `transports`, a UDP datagram of `uid`'s from its listen port to each of its
/// peer endpoints is accepted on any interface, ahead of the drop.
///
/// This is the ruleset `enable` installs. Without it no WireGuard link
/// carries the daemon's traffic: the encrypted UDP to the provider leaves by
/// the physical interface still attached to the daemon's sending socket, so
/// it matches `meta skuid <uid>` and the final `drop` takes it. It is scoped
/// to the endpoint, not the port alone, because the port outlives the link:
/// once the link is down any socket can hold it, and a port-only exemption
/// let that socket's traffic out to anywhere.
///
/// Every tunnel address is fenced to its own interfaces (and loopback) first,
/// for every uid: see the module documentation.
///
/// Tunnels, addresses and exemptions are de-duplicated and sorted, so the
/// output is deterministic regardless of profile ordering.
pub fn render_ruleset_with_transport(
    uid: u32,
    tunnels: &[Tunnel],
    transports: &[Transport],
) -> io::Result<String> {
    check_interface_names(tunnels.iter().map(|t| t.iface.as_str()))?;
    let mut pairs: Vec<&Tunnel> = tunnels.iter().collect();
    pairs.sort_unstable();
    pairs.dedup();

    let mut chain = String::new();
    chain.push_str("\t\ttype filter hook output priority 0; policy accept;\n");
    // Interfaces each address may leave by. Sorted as nft lists a set's
    // elements, so the table reads back as rendered.
    let mut fenced: BTreeMap<IpAddr, BTreeSet<&str>> = BTreeMap::new();
    for tunnel in &pairs {
        for addr in tunnel.addrs() {
            fenced
                .entry(addr)
                .or_insert_with(|| BTreeSet::from(["lo"]))
                .insert(tunnel.iface.as_str());
        }
    }
    for (addr, ifaces) in fenced {
        chain.push_str(&format!(
            "\t\t{} saddr {addr} oifname != {} drop\n",
            family(&addr),
            name_set(ifaces)
        ));
    }
    chain.push_str(&format!("\t\tmeta skuid {uid} oifname \"lo\" accept\n"));
    for tunnel in pairs {
        for addr in tunnel.addrs() {
            chain.push_str(&format!(
                "\t\tmeta skuid {uid} {} saddr {addr} oifname \"{}\" accept\n",
                family(&addr),
                tunnel.iface,
            ));
        }
    }
    let exempt: BTreeSet<(u16, SocketAddr)> = transports
        .iter()
        .flat_map(|t| t.endpoints.iter().map(|e| (t.listen_port, *e)))
        .collect();
    for (port, endpoint) in exempt {
        let family = if endpoint.is_ipv4() { "ip" } else { "ip6" };
        chain.push_str(&format!(
            "\t\tmeta skuid {uid} {family} daddr {} udp sport {port} udp dport {} accept\n",
            endpoint.ip(),
            endpoint.port(),
        ));
    }
    chain.push_str(&format!("\t\tmeta skuid {uid} counter drop\n"));

    Ok(format!(
        "table inet {} {{\n\tchain output {{\n{chain}\t}}\n}}\n",
        table_name(uid)
    ))
}

/// Interface names as an nft anonymous set, in the order given.
fn name_set<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let quoted: Vec<String> = names.into_iter().map(|n| format!("\"{n}\"")).collect();
    format!("{{ {} }}", quoted.join(", "))
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
pub fn install_script(
    uid: u32,
    tunnels: &[Tunnel],
    transports: &[Transport],
) -> io::Result<String> {
    let table = render_ruleset_with_transport(uid, tunnels, transports)?;
    Ok(replace_script(uid, &table))
}

/// `table`, preceded by the two lines that make `nft -f` replace `uid`'s
/// standing table with it in one transaction; see [`install_script`].
fn replace_script(uid: u32, table: &str) -> String {
    let name = table_name(uid);
    format!("add table inet {name}\ndelete table inet {name}\n{table}")
}

/// The kill switch as `enable` installed it: the uid it confines, the
/// tunnels and the transport of each it was rendered over, and the table it
/// rendered, which [`verify`] compares the live one with and [`watch`]
/// installs again when they differ. [`refresh`] replaces the transports and
/// the table when a link's transport changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub uid: u32,
    tunnels: Vec<Tunnel>,
    /// Each tunnel interface's transport, as last read.
    transports: Vec<(String, Transport)>,
    table: String,
}

impl Installed {
    /// Render the table for `uid` over `tunnels` and `transports`.
    fn render(
        uid: u32,
        tunnels: Vec<Tunnel>,
        transports: Vec<(String, Transport)>,
    ) -> io::Result<Self> {
        let table = render_ruleset_with_transport(
            uid,
            &tunnels,
            &transports
                .iter()
                .map(|(_, t)| t.clone())
                .collect::<Vec<_>>(),
        )?;
        Ok(Self {
            uid,
            tunnels,
            transports,
            table,
        })
    }

    /// The script that installs this table again, replacing whatever stands
    /// in its place, as one transaction.
    fn script(&self) -> String {
        replace_script(self.uid, &self.table)
    }

    /// The name of the table this install owns.
    pub(crate) fn table_name(&self) -> String {
        table_name(self.uid)
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
/// loopback and to each of `tunnels` from the addresses its link holds, with
/// each tunnel's own transport exempted (see
/// [`render_ruleset_with_transport`]). Returns what was installed: the uid the
/// ruleset was written for, and the table, for [`verify`] and [`watch`].
/// Replaces any stale table left by a previous unclean exit in the same
/// transaction ([`install_script`]).
///
/// Refuses uid 0 outright — see [`refusal_for_uid`].
///
/// A table an earlier release left under the single shared name
/// `torrentd_ks` is removed once this uid's table is in force, where it
/// confines this uid and no other ([`remove_legacy_with`]): it would otherwise
/// keep dropping whatever the old run's tunnels no longer cover. A failure
/// there is logged and does not fail the install.
pub fn enable(tunnels: &[String]) -> io::Result<Installed> {
    let installed = enable_for_uid(
        current_uid()?,
        tunnels,
        super::ip_lookup::first_ipv4,
        tunnel_ipv6,
        transport,
        apply,
    )?;
    let legacy = list_tables().and_then(|listing| {
        remove_legacy_with(installed.uid, &listing, list_table_json, delete_table)
    });
    match legacy {
        Ok(false) => {}
        Ok(true) => tracing::warn!(
            target: "torrentd::vpn::killswitch",
            table = TABLE_PREFIX,
            uid = installed.uid,
            "removed a kill-switch table an earlier release left under the shared name",
        ),
        Err(e) => warn_legacy_failure(&e),
    }
    Ok(installed)
}

/// The global IPv6 addresses the ruleset pairs with `iface`, or none where
/// they cannot be read. Pairing none is the closed side: the tunnel's IPv6
/// traffic is dropped, its IPv4 traffic unaffected, and the reason logged.
pub(crate) fn tunnel_ipv6(iface: &str) -> Vec<Ipv6Addr> {
    super::ip_lookup::global_ipv6(iface).unwrap_or_else(|e| {
        tracing::warn!(
            target: "torrentd::vpn::killswitch",
            iface,
            error.cause = %e,
            "could not read the tunnel's IPv6 addresses; the kill switch pairs none, so \
             its IPv6 traffic is dropped",
        );
        Vec::new()
    })
}

/// The WireGuard link `iface`'s own transport: its [`listen_port`] and the
/// endpoint of each of its peers, from `wg show <iface> endpoints`.
///
/// A link with no peer endpoint at all is an error, like a link with no
/// listen port: there is nowhere to exempt its transport to, and it could
/// not carry anyway.
pub(crate) fn transport(iface: &str) -> io::Result<Transport> {
    let port = listen_port(iface)?;
    let out = exec::run_ok(
        "wg",
        &["show", exec::iface(iface)?, "endpoints"],
        None,
        exec::QUICK,
    )?;
    let endpoints = parse_endpoints(iface, &String::from_utf8_lossy(&out.stdout))?;
    Ok(Transport::new(port, endpoints))
}

/// `wg show <iface> endpoints`'s output — a line per peer, its public key and
/// its endpoint or `(none)` — as the endpoints the ruleset can exempt.
fn parse_endpoints(iface: &str, text: &str) -> io::Result<Vec<SocketAddr>> {
    let mut endpoints = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some(endpoint) = line.split_whitespace().nth(1) else {
            return Err(io::Error::other(format!(
                "wg show {iface} endpoints printed {line:?}, not a peer and its endpoint",
            )));
        };
        if endpoint == "(none)" {
            continue;
        }
        endpoints.push(endpoint.parse::<SocketAddr>().map_err(|_| {
            io::Error::other(format!(
                "wg show {iface} endpoints printed {endpoint:?}, not an endpoint",
            ))
        })?);
    }
    if endpoints.is_empty() {
        return Err(io::Error::other(format!(
            "WireGuard link {iface} has no peer endpoint, so the kill switch has no \
             transport to exempt for it",
        )));
    }
    Ok(endpoints)
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
/// `tunnel_addr` and `transport` are the other host probes, handed in
/// for the same reason: the pairing the first feeds is what keeps one
/// profile's traffic out of another's tunnel, and the exemption the second
/// feeds is the difference between a WireGuard link the daemon raised
/// carrying traffic and carrying none. `tunnel_addr` reads the address the
/// tunnel is routed by — the link's first IPv4 address, which is what
/// bring-up hands the session. `tunnel_v6` reads the link's global IPv6
/// addresses, which a session listening on the device also sends from; a
/// link with none, or whose addresses could not be read, pairs none.
pub(crate) fn enable_for_uid(
    uid: u32,
    tunnels: &[String],
    tunnel_addr: impl Fn(&str) -> io::Result<Ipv4Addr>,
    tunnel_v6: impl Fn(&str) -> Vec<Ipv6Addr>,
    transport: impl Fn(&str) -> io::Result<Transport>,
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
                .map(|addr| Tunnel::new(iface.as_str(), addr).with_v6(tunnel_v6(iface)))
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
    let transports = tunnels
        .iter()
        .map(|iface| transport(iface).map(|t| (iface.clone(), t)))
        .collect::<io::Result<Vec<(String, Transport)>>>()?;
    // A name the ruleset cannot carry fails here, before nft, so a previous
    // run's kill switch stays armed.
    let installed = Installed::render(uid, paired, transports)?;
    apply(&installed.script())?;
    info!(
        target: "torrentd::vpn::killswitch",
        uid,
        tunnels = ?installed.tunnels,
        transports = ?installed.transports,
        "network kill switch installed (nftables, fail-closed)",
    );
    Ok(installed)
}

/// Remove this process's uid's kill-switch table ([`table_name`]), and a
/// table an earlier release left under the shared name where it confines
/// this uid alone. Another uid's table is never touched.
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
    remove_table_for(current_uid()?)
}

/// [`remove_table`] for `uid`'s table rather than this process's: for
/// `torrentd net-cleanup` run by root on a daemon's behalf.
pub fn remove_table_for(uid: u32) -> io::Result<bool> {
    disable_with(uid, list_tables, list_table_json, delete_table)
}

/// [`remove_table_for`], with every `nft` call handed in so the decision
/// between them is reachable by a test on a host without `nft` or
/// `CAP_NET_ADMIN`: `list` is `nft list tables`, `list_json` lists one table
/// as JSON, and `delete` deletes one table, each by name.
///
/// A failure on the legacy table is reported apart from this uid's own. Once
/// the own table is deleted it is a warning, and the call succeeds: the
/// caller's failure report says the uid stays confined by its own table,
/// which is gone. With no own table to delete, the legacy table is the only
/// one left that may confine this uid, so its failure is the call's error,
/// and the error names it.
pub(crate) fn disable_with(
    uid: u32,
    list: impl Fn() -> io::Result<String>,
    list_json: impl Fn(&str) -> io::Result<String>,
    delete: impl Fn(&str) -> io::Result<()>,
) -> io::Result<bool> {
    let listing = list()?;
    let own = table_name(uid);
    let mut removed = false;
    if table_listed(&listing, &own) {
        delete(&own)?;
        removed = true;
    }
    match remove_legacy_with(uid, &listing, list_json, delete) {
        Ok(legacy) => Ok(legacy || removed),
        Err(e) if removed => {
            warn_legacy_failure(&e);
            Ok(true)
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("the table an earlier release left under the shared name {TABLE_PREFIX}: {e}"),
        )),
    }
}

/// Log a failure to read or delete the table an earlier release left under
/// the shared name, after this uid's own table was dealt with.
fn warn_legacy_failure(e: &io::Error) {
    tracing::warn!(
        target: "torrentd::vpn::killswitch",
        table = TABLE_PREFIX,
        error.cause = %e,
        "could not check for, or remove, a kill-switch table an earlier release left under \
         the shared name. If it confines this daemon's uid, remove it with \
         `nft delete table inet {TABLE_PREFIX}`",
    );
}

/// Delete the table an earlier release installed under the single shared
/// name [`TABLE_PREFIX`], if `listing` names it and it confines `uid` and no
/// other uid. Whose it is is read off its rules' `meta skuid` matches: that
/// release rendered one uid into every rule but the fences, which match no
/// uid. A table naming another uid, or none, is another daemon's or not a
/// kill switch, and is left standing.
fn remove_legacy_with(
    uid: u32,
    listing: &str,
    list_json: impl Fn(&str) -> io::Result<String>,
    delete: impl Fn(&str) -> io::Result<()>,
) -> io::Result<bool> {
    if !table_listed(listing, TABLE_PREFIX) {
        return Ok(false);
    }
    let json: serde_json::Value = serde_json::from_str(&list_json(TABLE_PREFIX)?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("nft -j list table printed something that is not JSON: {e}"),
        )
    })?;
    if skuids(&json) != BTreeSet::from([u64::from(uid)]) {
        return Ok(false);
    }
    delete(TABLE_PREFIX).map(|()| true)
}

/// Every uid a `meta skuid` match in a `nft -j list table` listing names,
/// whatever its operator; a value that is not a number reads as `u64::MAX`,
/// which no uid is, so the table does not read as any one uid's.
fn skuids(json: &serde_json::Value) -> BTreeSet<u64> {
    json.get("nftables")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.pointer("/rule/expr")?.as_array())
        .flatten()
        .filter_map(|e| e.get("match"))
        .filter(|m| m.pointer("/left/meta/key").and_then(|k| k.as_str()) == Some("skuid"))
        .map(|m| m["right"].as_u64().unwrap_or(u64::MAX))
        .collect()
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
    let name = installed.table_name();
    verify_with(installed, list_tables, || list_table_json(&name))
}

/// [`verify`], with both `nft` calls handed in.
pub(crate) fn verify_with(
    installed: &Installed,
    list: impl Fn() -> io::Result<String>,
    list_json: impl Fn() -> io::Result<String>,
) -> io::Result<Verdict> {
    let name = installed.table_name();
    if !table_listed(&list()?, &name) {
        return Ok(Verdict::Absent);
    }
    let json: serde_json::Value = serde_json::from_str(&list_json()?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("nft -j list table printed something that is not JSON: {e}"),
        )
    })?;
    let live = match live_table(&json, &name) {
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

/// `nft -j list table inet <name>`, read back into the text
/// [`render_ruleset_with_transport`] writes, or why it cannot be: an object or
/// expression of a kind this module never installs is not this module's
/// table.
///
/// Counters are read without their values, and an interface-name set in the
/// order the renderer writes it.
fn live_table(json: &serde_json::Value, name: &str) -> Result<String, String> {
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
    let mut out = format!("table inet {name} {{\n");
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
            let (left, right) = (&m["left"], &m["right"]);
            let key = match (
                left.pointer("/meta/key").and_then(|k| k.as_str()),
                left.pointer("/payload/protocol").and_then(|p| p.as_str()),
                left.pointer("/payload/field").and_then(|f| f.as_str()),
            ) {
                (Some("skuid"), ..) => "meta skuid",
                (Some("oifname"), ..) => "oifname",
                (None, Some("ip"), Some("saddr")) => "ip saddr",
                (None, Some("ip"), Some("daddr")) => "ip daddr",
                (None, Some("ip6"), Some("saddr")) => "ip6 saddr",
                (None, Some("ip6"), Some("daddr")) => "ip6 daddr",
                (None, Some("udp"), Some("sport")) => "udp sport",
                (None, Some("udp"), Some("dport")) => "udp dport",
                _ => return Err(unread(e)),
            };
            // `!=` only where the renderer writes it: an interface-name set.
            let op = match (m["op"].as_str(), key) {
                (Some("=="), _) => "",
                (Some("!="), "oifname") if right.get("set").is_some() => "!= ",
                _ => return Err(unread(e)),
            };
            let value = match key {
                "oifname" => match right.pointer("/set").and_then(|s| s.as_array()) {
                    // Sorted as the renderer sorts them.
                    Some(set) => set
                        .iter()
                        .map(|n| n.as_str())
                        .collect::<Option<BTreeSet<&str>>>()
                        .map(name_set),
                    None => right.as_str().map(|s| format!("\"{s}\"")),
                },
                _ => scalar(right),
            }
            .ok_or_else(|| unread(e))?;
            words.push(format!("{key} {op}{value}"));
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

/// `nft -j list table inet <name>`, returning its stdout.
fn list_table_json(name: &str) -> io::Result<String> {
    let out = exec::run_ok(
        "nft",
        &["-j", "list", "table", "inet", name],
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
/// Before each check, each tunnel's transport is read off its link again
/// ([`refresh`]), and a change installs the ruleset again with the live one,
/// so a link re-raised on another port or to another endpoint carries again
/// at the next check rather than at the next restart. A reinstall that fails
/// leaves the live table differing from the one now rendered, which the
/// check reads as drift.
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
    // The uid, and so the table, is fixed for the run; every event a check
    // logs carries it through this span. At error level so that no level
    // filter that lets one of those events through disables the span.
    let table = installed.table_name();
    let installed = std::sync::Arc::new(std::sync::Mutex::new(installed));
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
            let span = tracing::error_span!("kill_switch_watch", table = %table);
            move || {
                let _span = span.entered();
                let mut installed = installed.lock().unwrap_or_else(|p| p.into_inner());
                refresh(&mut installed, transport, apply);
                let installed = &*installed;
                tick(
                    state,
                    || verify(installed),
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
                    table = %table,
                    error.cause = %e,
                    "the network kill switch check failed to run",
                );
            }
        }
    }
}

/// Read each tunnel's transport off its link, and where any changed since
/// `installed` was rendered, render it again with the live ones and install
/// that. Returns whether it changed.
///
/// A link that cannot be read — down, or gone while its provider's client
/// raises it again — keeps the transport last read: the exemption is scoped
/// to the provider's endpoint, so a stale one reaches nothing else, and
/// dropping it on a read that failed for any other reason would silence a
/// working tunnel until the next check. The VPN monitor reports and fences a
/// link that is down.
///
/// `installed` is replaced whether or not the install takes: a failed one
/// leaves the live table differing from the rendered one, and the check that
/// follows reads that as drift, fences every vpn profile, and installs it
/// again.
fn refresh(
    installed: &mut Installed,
    transport: impl Fn(&str) -> io::Result<Transport>,
    apply: impl Fn(&str) -> io::Result<()>,
) -> bool {
    let mut live = installed.transports.clone();
    for (iface, t) in &mut live {
        match transport(iface) {
            Ok(now) => *t = now,
            Err(e) => tracing::debug!(
                target: "torrentd::vpn::killswitch",
                iface = %iface,
                error.cause = %e,
                "could not read the tunnel's transport; keeping its exemption as last read",
            ),
        }
    }
    if live == installed.transports {
        return false;
    }
    let next = match Installed::render(installed.uid, installed.tunnels.clone(), live) {
        Ok(next) => next,
        // Not reached: the same names rendered at install.
        Err(e) => {
            tracing::error!(
                target: "torrentd::vpn::killswitch",
                uid = installed.uid,
                error.cause = %e,
                "could not render the kill switch over the tunnels' live transport",
            );
            return false;
        }
    };
    tracing::warn!(
        target: "torrentd::vpn::killswitch",
        was = ?installed.transports,
        now = ?next.transports,
        "a tunnel's transport changed since the kill switch was installed; installing it \
         again with the live one",
    );
    *installed = next;
    if let Err(e) = apply(&installed.script()) {
        tracing::error!(
            target: "torrentd::vpn::killswitch",
            uid = installed.uid,
            error.cause = %e,
            "could not install the kill switch with the tunnels' live transport",
        );
    }
    true
}

/// One check of [`watch`]'s, from where the last one left it: verify, fence
/// and reinstall on a loss, lift on a verified recovery. Returns where it
/// leaves the watch.
///
/// Each loss found from [`Watch::Intact`] counts once in
/// `kill_switch_lost_total`, by whether the one reinstall checked intact
/// (`reinstalled`) or not (`lost`). The whole loss, fence and reinstall
/// included, happens within this one call, so `kill_switch_table_present` is
/// back at 1 before any scrape can read the 0: the counter is the only trace a
/// loss the reinstall repaired leaves. The checks that repeat while the watch
/// is [`Watch::Lost`] are the same loss, and are not counted again.
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
                state = ?state,
                error.cause = %e,
                "could not check the network kill switch is still installed",
            );
            return state;
        }
    };
    metrics.set_gauge("kill_switch_table_present", 0.0, &[]);
    tracing::error!(
        target: "torrentd::vpn::killswitch",
        drift = %why,
        "the network kill switch is not in force as installed, so the daemon's egress is no \
         longer confined to the tunnels; fencing every vpn profile",
    );
    fence.fence_all();
    if state == Watch::Lost {
        return Watch::Lost;
    }
    let next = match reinstall().and_then(|()| verify()) {
        Ok(Verdict::Intact) => {
            metrics.set_gauge("kill_switch_table_present", 1.0, &[]);
            tracing::warn!(
                target: "torrentd::vpn::killswitch",
                "reinstalled the network kill switch and verified it; lifting the fence",
            );
            fence.lift();
            Watch::Intact
        }
        Ok(verdict) => {
            tracing::error!(
                target: "torrentd::vpn::killswitch",
                verdict = ?verdict,
                "reinstalled the network kill switch, and it still does not check as installed; \
                 the vpn profiles stay fenced. Restart the daemon to reinstall it",
            );
            Watch::Lost
        }
        Err(e) => {
            tracing::error!(
                target: "torrentd::vpn::killswitch",
                state = ?state,
                error.cause = %e,
                "could not reinstall the network kill switch; the vpn profiles stay fenced. \
                 Restart the daemon to reinstall it",
            );
            Watch::Lost
        }
    };
    let outcome = match next {
        Watch::Intact => "reinstalled",
        Watch::Lost => "lost",
    };
    metrics.inc_counter("kill_switch_lost_total", &[("outcome", outcome)]);
    next
}

/// Whether `nft list tables` output names the `inet` table `name`. Each line
/// is `table <family> <name>`; the table is matched on family and name
/// exactly, so a same-named table in another family, or one whose name merely
/// starts with `name` — another uid's, beside the shared legacy name — is not
/// taken for it.
fn table_listed(listing: &str, name: &str) -> bool {
    listing
        .lines()
        .any(|line| line.split_whitespace().eq(["table", "inet", name]))
}

/// `nft list tables`, returning its stdout.
fn list_tables() -> io::Result<String> {
    let out = exec::run_ok("nft", &["list", "tables"], None, exec::QUICK)?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `nft delete table inet <name>`. Any non-zero exit is an error: it is only
/// called once the table has been listed, so there is no absent case to
/// excuse.
fn delete_table(name: &str) -> io::Result<()> {
    exec::run_ok(
        "nft",
        &["delete", "table", "inet", name],
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

    /// The table every test install, for uid 998, owns.
    const TABLE: &str = "torrentd_ks_998";

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

    /// A link with no IPv6 address, which is most of them.
    fn no_v6(_: &str) -> Vec<Ipv6Addr> {
        Vec::new()
    }

    /// The IPv6 address scripted for `wg-a` where a test gives it one.
    const ADDR_A6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    /// The provider endpoint every test tunnel's peer has.
    const ENDPOINT: &str = "198.51.100.1:51820";

    /// A transport on `port` to [`ENDPOINT`].
    fn transport_on(port: u16) -> Transport {
        Transport::new(port, [ENDPOINT.parse().unwrap()])
    }

    /// One packet leaving the host, as the output hook sees it.
    #[derive(Clone, Copy)]
    struct Packet<'a> {
        /// The socket owner's uid, `None` for one the kernel built with no
        /// socket attached: a reset, an ICMP error.
        uid: Option<u32>,
        saddr: IpAddr,
        oif: &'a str,
        /// `(sport, daddr, dport)` for a UDP packet.
        udp: Option<(u16, std::net::IpAddr, u16)>,
    }

    fn pkt(uid: u32, saddr: impl Into<IpAddr>, oif: &str) -> Packet<'_> {
        Packet {
            uid: Some(uid),
            saddr: saddr.into(),
            oif,
            udp: None,
        }
    }

    impl<'a> Packet<'a> {
        fn udp(mut self, sport: u16, to: &str) -> Self {
            let to: SocketAddr = to.parse().unwrap();
            self.udp = Some((sport, to.ip(), to.port()));
            self
        }
        fn kernel(mut self) -> Self {
            self.uid = None;
            self
        }
    }

    /// What the rendered chain does with one packet, read the way nftables
    /// reads it: the first rule whose every match holds decides, and a packet
    /// no rule decides takes the chain's `accept` policy.
    ///
    /// Reads only the shapes this module renders — `meta skuid`,
    /// `ip saddr`/`ip6 saddr`, `ip daddr`/`ip6 daddr`, `oifname` (one name or
    /// a set, `!=` a set), `udp sport`/`udp dport` (a set or one value) — and
    /// panics on anything else, so a new kind of match cannot be silently
    /// ignored here. An `ip` match holds only for an IPv4 packet and an
    /// `ip6` one only for an IPv6 packet, as in an `inet` table.
    fn verdict(ruleset: &str, p: Packet<'_>) -> &'static str {
        const MATCHES: [&str; 8] = [
            "meta skuid ",
            "ip saddr ",
            "ip6 saddr ",
            "ip daddr ",
            "ip6 daddr ",
            "oifname ",
            "udp sport ",
            "udp dport ",
        ];
        for line in ruleset.lines().map(str::trim) {
            if !(line.starts_with("meta skuid ")
                || line.starts_with("ip saddr ")
                || line.starts_with("ip6 saddr "))
            {
                continue;
            }
            let (mut rest, verdict) = if let Some(m) = line.strip_suffix(" accept") {
                (m, "accept")
            } else if let Some(m) = line.strip_suffix(" counter drop") {
                (m, "drop")
            } else if let Some(m) = line.strip_suffix(" drop") {
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
                let (negated, r) = match r.strip_prefix("!= ") {
                    Some(r) => (true, r),
                    None => (false, r),
                };
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
                let field = match key {
                    "meta skuid " => p.uid.map(|u| u.to_string()),
                    "ip saddr " => Some(p.saddr).filter(IpAddr::is_ipv4).map(|a| a.to_string()),
                    "ip6 saddr " => Some(p.saddr).filter(IpAddr::is_ipv6).map(|a| a.to_string()),
                    "oifname " => Some(p.oif.to_string()),
                    "udp sport " => p.udp.map(|(s, ..)| s.to_string()),
                    "udp dport " => p.udp.map(|(.., d)| d.to_string()),
                    "ip daddr " => p
                        .udp
                        .filter(|(_, a, _)| a.is_ipv4())
                        .map(|(_, a, _)| a.to_string()),
                    _ => p
                        .udp
                        .filter(|(_, a, _)| a.is_ipv6())
                        .map(|(_, a, _)| a.to_string()),
                };
                holds &= field.is_some_and(|f| values.contains(&f.as_str()) != negated);
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
            no_v6,
            |_| Ok(transport_on(51820)),
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
            no_v6,
            |iface| {
                Ok(if iface == "wg-a" {
                    transport_on(51820)
                } else {
                    Transport::new(40001, ["[2001:db8::7]:4500".parse().unwrap()])
                })
            },
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
add table inet torrentd_ks_998
delete table inet torrentd_ks_998
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\" } drop
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg-b\" } drop
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
\t\tmeta skuid 998 ip6 daddr 2001:db8::7 udp sport 40001 udp dport 4500 accept
\t\tmeta skuid 998 ip daddr 198.51.100.1 udp sport 51820 udp dport 51820 accept
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
            no_v6,
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
            no_v6,
            |_| Ok(transport_on(51820)),
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
        let rs = render_ruleset_with_transport(
            998,
            &[tunnel("wg-a"), tunnel("wg-b")],
            &[transport_on(51820)],
        )
        .unwrap();

        assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a")), "accept");
        assert_eq!(verdict(&rs, pkt(998, ADDR_B, "wg-b")), "accept");
        assert_eq!(
            verdict(&rs, pkt(998, ADDR_A, "wg-b")),
            "drop",
            "A's address on B's tunnel is dropped:\n{rs}"
        );
        assert_eq!(
            verdict(&rs, pkt(998, ADDR_B, "wg-a").udp(6881, "203.0.113.9:6881")),
            "drop",
            "and B's on A's, UDP included:\n{rs}"
        );
        assert_eq!(
            verdict(&rs, pkt(998, Ipv4Addr::new(192, 168, 1, 20), "wg-a")),
            "drop",
            "an address no profile holds is dropped on every tunnel:\n{rs}"
        );
        assert_eq!(
            verdict(&rs, pkt(1000, Ipv4Addr::new(192, 168, 1, 20), "eth0")),
            "accept",
            "another uid's traffic from another address is not this ruleset's to judge"
        );

        // The control: the shared accept this replaced let A out of B's tunnel.
        let shared = "\
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 oifname { \"wg-a\", \"wg-b\" } accept
\t\tmeta skuid 998 counter drop
";
        assert_eq!(verdict(shared, pkt(998, ADDR_A, "wg-b")), "accept");
    }

    /// #136, the stale exemption: once a link is down its listen port is
    /// free, and a socket holding it — bound to it, or handed it as an
    /// ephemeral port by a resolver query — sent out of the physical
    /// interface through a port-only exemption. Scoped to the provider's
    /// endpoint, only the tunnel's own transport passes.
    #[test]
    fn the_transport_exemption_reaches_the_provider_endpoint_and_nowhere_else() {
        let rs =
            render_ruleset_with_transport(998, &[tunnel("wg-a")], &[transport_on(51820)]).unwrap();
        let phys = Ipv4Addr::new(192, 0, 2, 1);

        assert_eq!(
            verdict(&rs, pkt(998, phys, "eth0").udp(51820, ENDPOINT)),
            "accept",
            "the encrypted transport to the provider leaves:\n{rs}"
        );
        for (label, to) in [
            ("a datagram to another host", "192.0.2.2:7"),
            ("a resolver query", "192.0.2.53:53"),
            ("another port on the provider", "198.51.100.1:53"),
        ] {
            assert_eq!(
                verdict(&rs, pkt(998, phys, "eth0").udp(51820, to)),
                "drop",
                "{label} from the freed listen port is dropped:\n{rs}"
            );
        }
        assert_eq!(
            verdict(&rs, pkt(998, phys, "eth0").udp(40000, ENDPOINT)),
            "drop",
            "another source port to the provider is dropped:\n{rs}"
        );

        // The control: the port-only exemption this replaced let both out.
        let port_only = "\
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 udp sport { 51820 } accept
\t\tmeta skuid 998 counter drop
";
        assert_eq!(
            verdict(
                port_only,
                pkt(998, phys, "eth0").udp(51820, "192.0.2.53:53")
            ),
            "accept"
        );
    }

    /// #136, the kernel's replies: a reset or an ICMP error carries no socket
    /// of the daemon's, so no uid rule judges it. With the tunnel's source
    /// rule lost it left by the physical interface from the tunnel address.
    /// The address fence drops it whoever built it, and still lets the
    /// tunnel and loopback carry that address.
    #[test]
    fn a_tunnel_address_leaves_by_its_own_tunnel_or_loopback_whoever_sent_it() {
        let rs = render_ruleset_with_transport(
            998,
            &[tunnel("wg-a"), tunnel("wg-b")],
            &[transport_on(51820)],
        )
        .unwrap();
        for (label, p) in [
            ("a kernel reset", pkt(998, ADDR_A, "eth0").kernel()),
            ("another uid's socket", pkt(0, ADDR_A, "eth0")),
            ("into the other tunnel", pkt(0, ADDR_A, "wg-b")),
        ] {
            assert_eq!(verdict(&rs, p), "drop", "{label}:\n{rs}");
        }
        assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a").kernel()), "accept");
        assert_eq!(verdict(&rs, pkt(0, ADDR_A, "lo")), "accept");
        assert_eq!(
            verdict(&rs, pkt(0, Ipv4Addr::new(192, 0, 2, 1), "eth0").kernel()),
            "accept",
            "the host's own address is not the ruleset's to judge"
        );
    }

    /// Providers that hand every client the same address: two tunnels on it
    /// share one fence that allows both, or each would drop the other.
    #[test]
    fn tunnels_sharing_an_address_share_its_fence() {
        let rs = render_ruleset(
            998,
            &[Tunnel::new("wg-b", ADDR_A), Tunnel::new("wg-a", ADDR_A)],
        )
        .unwrap();
        assert_eq!(
            rs.matches("oifname != ").count(),
            1,
            "one fence for the address:\n{rs}"
        );
        assert!(
            rs.contains("ip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\", \"wg-b\" } drop"),
            "{rs}"
        );
        assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a")), "accept");
        assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-b")), "accept");
    }

    /// A session listening on its tunnel device listens and announces on the
    /// device's IPv6 addresses too. Each is paired with its own tunnel as the
    /// IPv4 address is: accepted there, dropped on another tunnel or off the
    /// tunnels whoever sent it, and an IPv6 address no tunnel holds is still
    /// dropped.
    #[test]
    fn a_tunnel_s_ipv6_addresses_are_paired_with_it_as_its_ipv4_address_is() {
        let rs = render_ruleset(998, &[tunnel("wg-a").with_v6([ADDR_A6]), tunnel("wg-b")]).unwrap();
        assert!(
            rs.contains("\t\tip6 saddr 2001:db8::2 oifname != { \"lo\", \"wg-a\" } drop\n")
                && rs
                    .contains("\t\tmeta skuid 998 ip6 saddr 2001:db8::2 oifname \"wg-a\" accept\n"),
            "{rs}"
        );
        assert_eq!(verdict(&rs, pkt(998, ADDR_A6, "wg-a")), "accept");
        assert_eq!(
            verdict(&rs, pkt(998, ADDR_A6, "wg-b")),
            "drop",
            "A's IPv6 address on B's tunnel is dropped:\n{rs}"
        );
        assert_eq!(
            verdict(&rs, pkt(998, ADDR_A6, "eth0").kernel()),
            "drop",
            "a kernel-built packet from it off the tunnel is dropped:\n{rs}"
        );
        assert_eq!(
            verdict(
                &rs,
                pkt(998, "2001:db8::99".parse::<Ipv6Addr>().unwrap(), "wg-a")
            ),
            "drop",
            "an IPv6 address no tunnel holds is dropped:\n{rs}"
        );
        assert_eq!(verdict(&rs, pkt(998, ADDR_A, "wg-a")), "accept");
        assert_eq!(verdict(&rs, pkt(998, ADDR_B, "wg-b")), "accept");
    }

    /// A link whose IPv6 addresses cannot be read is paired with none, which
    /// drops its IPv6 traffic, and the reason is logged. The name is one no
    /// tool may be handed, so the read fails before anything is run.
    #[test]
    fn a_failed_ipv6_read_pairs_no_address_and_says_why() {
        let log = crate::tracing_init::Buf::default();
        let (_handle, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        assert_eq!(tunnel_ipv6("-wg-a"), Vec::<Ipv6Addr>::new());

        let log = log.text();
        assert!(
            log.contains("\"level\":\"WARN\"")
                && log.contains("could not read the tunnel's IPv6 addresses")
                && log.contains("-wg-a")
                && log.contains("cannot be passed to a tool"),
            "{log}"
        );
    }

    /// `enable` pairs what the IPv6 probe reads for each link, and a link it
    /// reads none for gets no IPv6 rule.
    #[test]
    fn enable_pairs_each_link_s_ipv6_addresses() {
        let installed = enable_for_uid(
            998,
            &["wg-a".to_string(), "wg-b".to_string()],
            addr_of,
            |iface| {
                if iface == "wg-a" {
                    vec![ADDR_A6]
                } else {
                    Vec::new()
                }
            },
            |_| Ok(transport_on(51820)),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            installed.tunnels,
            vec![tunnel("wg-a").with_v6([ADDR_A6]), tunnel("wg-b")]
        );
        assert_eq!(
            installed.table.matches("ip6 saddr").count(),
            2,
            "{}",
            installed.table
        );
    }

    #[test]
    fn endpoints_are_read_and_a_link_with_none_is_refused() {
        let out = "a2V5MQ==\t198.51.100.1:51820\nb2V5Mg==\t(none)\nc2V5Mw==\t[2001:db8::7]:4500\n";
        assert_eq!(
            parse_endpoints("wg-a", out).unwrap(),
            vec![
                "198.51.100.1:51820".parse::<SocketAddr>().unwrap(),
                "[2001:db8::7]:4500".parse().unwrap(),
            ],
        );
        let e = parse_endpoints("wg-a", "a2V5MQ==\t(none)\n").expect_err("no endpoint");
        assert!(e.to_string().contains("no peer endpoint"), "got {e}");
        parse_endpoints("wg-a", "").expect_err("no peers at all");
        parse_endpoints("wg-a", "a2V5MQ==\tsomewhere\n").expect_err("not an endpoint");
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
    /// drop, keyed on this uid, the source port **and** the provider
    /// endpoint, so it lets out the WireGuard socket's encrypted UDP and
    /// nothing else this uid owns. One line per endpoint, de-duplicated.
    #[test]
    fn ruleset_exempts_each_tunnels_transport_ahead_of_the_drop() {
        let two_peers = Transport::new(
            40001,
            [
                "203.0.113.5:51820".parse().unwrap(),
                "198.51.100.1:51820".parse().unwrap(),
            ],
        );
        let rs = render_ruleset_with_transport(
            998,
            &[tunnel("wg-a"), tunnel("wg-b")],
            &[transport_on(51820), two_peers, transport_on(51820)],
        )
        .unwrap();
        let expected = "\
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\" } drop
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg-b\" } drop
\t\tmeta skuid 998 oifname \"lo\" accept
\t\tmeta skuid 998 ip saddr 10.2.0.2 oifname \"wg-a\" accept
\t\tmeta skuid 998 ip saddr 10.64.0.7 oifname \"wg-b\" accept
\t\tmeta skuid 998 ip daddr 198.51.100.1 udp sport 40001 udp dport 51820 accept
\t\tmeta skuid 998 ip daddr 203.0.113.5 udp sport 40001 udp dport 51820 accept
\t\tmeta skuid 998 ip daddr 198.51.100.1 udp sport 51820 udp dport 51820 accept
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
            |_| unreachable!("no tunnels, no IPv6 addresses"),
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
            998,
            || Ok("table ip filter\ntable inet other\n".to_string()),
            |_| panic!("no legacy table is listed, so none is read"),
            |_| {
                deleted.set(true);
                Err(io::Error::other(
                    "nft delete table exited 1: Fehler: Datei oder Verzeichnis nicht gefunden",
                ))
            },
        )
        .expect("an absent table is success");
        assert!(!deleted.get(), "nothing to delete, so no delete is run");
        assert!(!removed, "and no table is reported removed");

        let removed = disable_with(
            998,
            || Ok(String::new()),
            |_| panic!("no tables at all"),
            |_| panic!("no tables at all"),
        )
        .expect("an empty listing is an absent table");
        assert!(!removed);
    }

    #[test]
    fn disable_deletes_a_listed_table_and_reports_its_failure() {
        let deleted = std::cell::RefCell::new(Vec::new());
        let removed = disable_with(
            998,
            || Ok(format!("table ip filter\ntable inet {TABLE}\n")),
            |_| panic!("no legacy table is listed"),
            |name| {
                deleted.borrow_mut().push(name.to_string());
                Ok(())
            },
        )
        .expect("a delete that succeeded");
        assert_eq!(*deleted.borrow(), [TABLE], "the listed table is deleted");
        assert!(
            removed,
            "and reported removed, so a caller can say it found one"
        );

        let e = disable_with(
            998,
            || Ok(format!("table inet {TABLE}\n")),
            |_| panic!("no legacy table is listed"),
            |_| Err(io::Error::other("nft delete table exited 1: busy")),
        )
        .expect_err("a table that exists and would not delete is not swallowed");
        assert!(e.to_string().contains("nft delete table"), "got {e}");
    }

    /// #168: a daemon with the kill switch off — an OpenVPN daemon beside a
    /// WireGuard one, as docs/running.md prescribes — runs this at every boot
    /// and, through `net-cleanup`, at every stop. Another uid's table is the
    /// other daemon's kill switch in force, and is never deleted.
    #[test]
    fn disable_leaves_another_uids_table_standing() {
        let removed = disable_with(
            1000,
            || {
                Ok(format!(
                    "table inet {TABLE}\ntable inet torrentd_ks_10000\n"
                ))
            },
            |_| panic!("no legacy table is listed"),
            |name| panic!("{name} is another daemon's kill switch, and is not deleted"),
        )
        .expect("nothing of this uid's is listed: success");
        assert!(!removed);

        let deleted = std::cell::RefCell::new(Vec::new());
        disable_with(
            998,
            || Ok(format!("table inet torrentd_ks_1000\ntable inet {TABLE}\n")),
            |_| panic!("no legacy table is listed"),
            |name| {
                deleted.borrow_mut().push(name.to_string());
                Ok(())
            },
        )
        .expect("this uid's table deletes");
        assert_eq!(*deleted.borrow(), [TABLE], "and only this uid's");
    }

    /// `nft -j list table inet torrentd_ks` for a table an earlier release
    /// installed for `uid`: the fence, which names no uid, then the drop.
    fn legacy_listing(uid: u32) -> String {
        format!(
            r#"{{"nftables": [{{"metainfo": {{"json_schema_version": 1}}}}, {{"table": {{"family": "inet", "name": "torrentd_ks", "handle": 1}}}}, {{"rule": {{"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 2, "expr": [{{"match": {{"op": "==", "left": {{"payload": {{"protocol": "ip", "field": "saddr"}}}}, "right": "10.2.0.2"}}}}, {{"drop": null}}]}}}}, {{"rule": {{"family": "inet", "table": "torrentd_ks", "chain": "output", "handle": 3, "expr": [{{"match": {{"op": "==", "left": {{"meta": {{"key": "skuid"}}}}, "right": {uid}}}}}, {{"counter": {{"packets": 0, "bytes": 0}}}}, {{"drop": null}}]}}}}]}}"#
        )
    }

    /// A table an earlier release left under the shared name is removed by
    /// the uid it confines, and by no other.
    #[test]
    fn a_legacy_table_is_removed_only_by_the_uid_it_confines() {
        let deleted = std::cell::RefCell::new(Vec::new());
        let delete = |name: &str| {
            deleted.borrow_mut().push(name.to_string());
            Ok(())
        };
        let listing = || Ok(format!("table inet torrentd_ks\ntable inet {TABLE}\n"));

        let removed =
            disable_with(998, listing, |_| Ok(legacy_listing(998)), delete).expect("both delete");
        assert!(removed);
        assert_eq!(*deleted.borrow(), [TABLE, "torrentd_ks"]);

        deleted.borrow_mut().clear();
        let removed = disable_with(
            998,
            || Ok("table inet torrentd_ks\n".to_string()),
            |_| Ok(legacy_listing(1000)),
            delete,
        )
        .expect("another uid's legacy table is no failure");
        assert!(!removed, "it is left standing");
        assert!(deleted.borrow().is_empty(), "got {:?}", deleted.borrow());

        let no_uid =
            r#"{"nftables": [{"table": {"family": "inet", "name": "torrentd_ks", "handle": 1}}]}"#;
        let removed = disable_with(
            998,
            || Ok("table inet torrentd_ks\n".to_string()),
            |_| Ok(no_uid.to_string()),
            delete,
        )
        .expect("a table naming no uid is no failure");
        assert!(!removed, "and is nobody's to remove");
        assert!(deleted.borrow().is_empty());

        let e = disable_with(
            998,
            || Ok("table inet torrentd_ks\n".to_string()),
            |_| Err(io::Error::other("nft -j list table exited 1")),
            |_| panic!("nothing is deleted on a table nobody could read"),
        )
        .expect_err("a legacy table that could not be read is not taken for absent");
        assert!(e.to_string().contains("nft -j list table"), "got {e}");
        assert!(
            e.to_string().contains("shared name torrentd_ks:"),
            "the error names the legacy table, not this uid's: {e}"
        );
    }

    /// Once this uid's own table is deleted, a legacy table that cannot be
    /// read or deleted is a warning, not the call's failure: shutdown would
    /// otherwise report this uid's table as still confining it.
    #[test]
    fn a_legacy_failure_after_the_own_table_is_removed_is_a_warning() {
        let listing = || Ok(format!("table inet torrentd_ks\ntable inet {TABLE}\n"));

        let deleted = std::cell::RefCell::new(Vec::new());
        let removed = disable_with(
            998,
            listing,
            |_| Err(io::Error::other("nft -j list table exited 1")),
            |name| {
                deleted.borrow_mut().push(name.to_string());
                Ok(())
            },
        )
        .expect("the own table is gone, so the call succeeds");
        assert!(removed);
        assert_eq!(*deleted.borrow(), [TABLE], "only the own table is deleted");

        let deleted = std::cell::RefCell::new(Vec::new());
        let removed = disable_with(
            998,
            listing,
            |_| Ok(legacy_listing(998)),
            |name| {
                deleted.borrow_mut().push(name.to_string());
                if name == TABLE_PREFIX {
                    Err(io::Error::other("nft delete table exited 1: busy"))
                } else {
                    Ok(())
                }
            },
        )
        .expect("a legacy delete that failed does not fail the own table's removal");
        assert!(removed);
        assert_eq!(*deleted.borrow(), [TABLE, TABLE_PREFIX]);
    }

    #[test]
    fn a_table_naming_two_uids_is_nobodys() {
        let json: serde_json::Value =
            serde_json::from_str(&listing(&[LO, &DROP.replace("998", "1000")])).unwrap();
        assert_eq!(skuids(&json), BTreeSet::from([998, 1000]));
        assert_eq!(
            skuids(&serde_json::from_str(&legacy_listing(998)).unwrap()),
            BTreeSet::from([998])
        );
    }

    /// A listing that fails — no `CAP_NET_ADMIN`, say — is an error, not an
    /// absent table: otherwise a stale table this run cannot see would be
    /// left in force beneath the new rules.
    #[test]
    fn disable_reports_a_failed_listing_without_deleting() {
        let e = disable_with(
            998,
            || {
                Err(io::Error::other(
                    "nft list tables exited 1: Operation not permitted",
                ))
            },
            |_| panic!("nothing is read on a listing nobody could read"),
            |_| panic!("nothing is deleted on a listing nobody could read"),
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
        remove_table_for(998).expect("no table yet: success, in any locale");
        apply(&install_script(998, &[tunnel("wg0")], &[]).unwrap()).expect("install onto no table");
        apply(&install_script(998, &[tunnel("wg1")], &[transport_on(51820)]).unwrap())
            .expect("and replace a standing one in the same transaction");
        let listed = exec::run_ok("nft", &["list", "table", "inet", TABLE], None, exec::QUICK)
            .expect("list the table");
        let listed = String::from_utf8_lossy(&listed.stdout);
        assert!(
            listed.contains("wg1") && !listed.contains("wg0"),
            "the replace leaves only this install's rules: {listed}"
        );
        // #168: a second daemon's, under another uid, beside it.
        apply(&install_script(1000, &[tunnel("wg2")], &[]).unwrap()).expect("install uid 1000's");
        assert!(table_listed(&list_tables().expect("list"), TABLE));
        assert!(
            remove_table_for(998).expect("an installed table is deleted"),
            "and reported removed"
        );
        let listing = list_tables().expect("list");
        assert!(!table_listed(&listing, TABLE));
        assert!(
            table_listed(&listing, "torrentd_ks_1000"),
            "the other uid's table survives: {listing}"
        );
        assert!(!remove_table_for(998).expect("and deleting it again is still success"));
        assert!(remove_table_for(1000).expect("uid 1000's own removal takes it"));
    }

    /// A table an earlier release left under the shared name, against a real
    /// `nft`: another uid's removal leaves it, its own uid's removes it. Run
    /// it as [`disable_against_real_nft`] says.
    #[test]
    #[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
    fn a_legacy_table_against_real_nft() {
        let legacy = render_ruleset(998, &[tunnel("wg0")])
            .unwrap()
            .replace(TABLE, TABLE_PREFIX);
        apply(&legacy).expect("install a table under the shared name");
        assert!(!remove_table_for(1000).expect("another uid's removal"));
        assert!(table_listed(&list_tables().expect("list"), TABLE_PREFIX));
        assert!(remove_table_for(998).expect("its own uid's removal"));
        assert!(!table_listed(&list_tables().expect("list"), TABLE_PREFIX));
    }

    #[test]
    fn only_this_family_and_name_count_as_the_table() {
        assert!(table_listed(&format!("table inet {TABLE}\n"), TABLE));
        assert!(table_listed(
            &format!("table ip nat\ntable inet {TABLE}"),
            TABLE
        ));
        assert!(!table_listed(&format!("table ip {TABLE}\n"), TABLE));
        assert!(!table_listed(&format!("table inet {TABLE}_old\n"), TABLE));
        assert!(!table_listed("", TABLE));
        // The shared legacy name is not any uid's table, nor the reverse.
        assert!(!table_listed("table inet torrentd_ks\n", TABLE));
        assert!(!table_listed(
            &format!("table inet {TABLE}\n"),
            TABLE_PREFIX
        ));
    }

    #[test]
    fn each_uid_owns_its_own_table() {
        assert_eq!(table_name(998), TABLE);
        assert_ne!(table_name(998), table_name(1000));
        let rs = render_ruleset(1000, &[tunnel("wg-a")]).unwrap();
        assert!(rs.starts_with("table inet torrentd_ks_1000 {\n"), "{rs}");
        let script = install_script(1000, &[tunnel("wg-a")], &[]).unwrap();
        assert!(
            script.starts_with(
                "add table inet torrentd_ks_1000\ndelete table inet torrentd_ks_1000\n"
            ),
            "the replace touches only this uid's table: {script}"
        );
    }

    #[test]
    fn ruleset_confines_uid_to_lo_and_tunnels() {
        let rs = render_ruleset(998, &[tunnel("wg-b"), tunnel("wg-a")]).unwrap();
        let expected = "\
table inet torrentd_ks_998 {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tip saddr 10.2.0.2 oifname != { \"lo\", \"wg-a\" } drop
\t\tip saddr 10.64.0.7 oifname != { \"lo\", \"wg-b\" } drop
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
        assert_eq!(rs.matches("wg0").count(), 2, "one fence, one accept:\n{rs}");
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
            no_v6,
            |_| Ok(transport_on(51820)),
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

    /// The transport [`installed`] exempts: two peers, one on IPv6.
    fn two_peer_transport() -> Transport {
        Transport::new(
            51820,
            [
                ENDPOINT.parse().unwrap(),
                "[2001:db8::7]:4500".parse().unwrap(),
            ],
        )
    }

    /// What `enable` installs for uid 998 over `wg-a` with two peer
    /// endpoints: the table the listings below are nft's listing of.
    fn installed() -> Installed {
        Installed::render(
            998,
            vec![tunnel("wg-a")],
            vec![("wg-a".to_string(), two_peer_transport())],
        )
        .unwrap()
    }

    const META: &str = r#"{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "torrentd_ks_998", "handle": 1}}, {"chain": {"family": "inet", "table": "torrentd_ks_998", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}"#;
    const FENCE: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 2, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.2.0.2"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": {"set": ["lo", "wg-a"]}}}, {"drop": null}]}}"#;
    const LO: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 2, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"accept": null}]}}"#;
    const WG_A: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 3, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.2.0.2"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg-a"}}, {"accept": null}]}}"#;
    const PORT_V4: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 4, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "198.51.100.1"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "sport"}}, "right": 51820}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 51820}}, {"accept": null}]}}"#;
    const PORT_V6: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 5, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "daddr"}}, "right": "2001:db8::7"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "sport"}}, "right": 51820}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 4500}}, {"accept": null}]}}"#;
    const DROP: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 6, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"counter": {"packets": 12, "bytes": 960}}, {"drop": null}]}}"#;

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
            verify_listing(listing(&[META, FENCE, LO, WG_A, PORT_V4, PORT_V6, DROP])).unwrap(),
            Verdict::Intact,
            "counter values and rule handles are not drift",
        );
    }

    /// A tunnel with an IPv6 address reads back intact: the `ip6 saddr`
    /// matches its fence and its accept carry are read as rendered.
    #[test]
    fn a_table_pairing_an_ipv6_address_verifies_intact() {
        const FENCE_V6: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 7, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "2001:db8::2"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": {"set": ["lo", "wg-a"]}}}, {"drop": null}]}}"#;
        const WG_A_V6: &str = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 8, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "2001:db8::2"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg-a"}}, {"accept": null}]}}"#;
        let installed = Installed::render(
            998,
            vec![tunnel("wg-a").with_v6([ADDR_A6])],
            vec![("wg-a".to_string(), two_peer_transport())],
        )
        .unwrap();
        let json = listing(&[
            META, FENCE, FENCE_V6, LO, WG_A, WG_A_V6, PORT_V4, PORT_V6, DROP,
        ]);
        let verdict = verify_with(
            &installed,
            || Ok(format!("table inet {TABLE}\n")),
            move || Ok(json.clone()),
        )
        .unwrap();
        assert_eq!(verdict, Verdict::Intact);
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
            why.starts_with(
                "installed \"ip saddr 10.2.0.2 oifname != { \\\"lo\\\", \\\"wg-a\\\" } drop\""
            ),
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
        let accept_all = r#"{"rule": {"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": 7, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 998}}, {"accept": null}]}}"#;
        let other_addr = WG_A.replace("10.2.0.2", "10.9.9.9");
        let drop_policy = META.replace(r#""policy": "accept""#, r#""policy": "drop""#);
        let set = r#"{"set": {"family": "inet", "name": "s", "table": "torrentd_ks_998", "type": "ipv4_addr", "handle": 4}}"#;
        let unread = DROP.replace(r#"{"drop": null}"#, r#"{"jump": {"target": "x"}}"#);
        let fence_widened = FENCE.replace(r#"["lo", "wg-a"]"#, r#"["eth0", "lo", "wg-a"]"#);
        let fence_eq = FENCE.replace(r#""op": "!=""#, r#""op": "==""#);
        let other_endpoint = PORT_V4.replace("198.51.100.1", "192.0.2.53");
        let port_only = PORT_V4.replace(
            r#"{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "198.51.100.1"}}, "#,
            "",
        );
        let rest = [LO, WG_A, PORT_V4, PORT_V6, DROP];
        let with = |head: &[&str], tail: &[&str]| listing(&[head, tail].concat());
        for (label, json) in [
            (
                "an accept ahead of the drop",
                with(&[META, FENCE, LO, accept_all], &rest[1..]),
            ),
            (
                "a tunnel address replaced",
                listing(&[META, FENCE, LO, &other_addr, PORT_V4, PORT_V6, DROP]),
            ),
            ("the policy changed", with(&[&drop_policy, FENCE], &rest)),
            ("a set", with(&[META, set, FENCE], &rest)),
            (
                "an unread verdict",
                listing(&[META, FENCE, LO, WG_A, PORT_V4, PORT_V6, &unread]),
            ),
            ("the fence gone", with(&[META], &rest)),
            ("the fence widened", with(&[META, &fence_widened], &rest)),
            ("the fence inverted", with(&[META, &fence_eq], &rest)),
            (
                "an exemption to another endpoint",
                listing(&[META, FENCE, LO, WG_A, &other_endpoint, PORT_V6, DROP]),
            ),
            (
                "an exemption by port alone",
                listing(&[META, FENCE, LO, WG_A, &port_only, PORT_V6, DROP]),
            ),
        ] {
            assert!(
                matches!(verify_listing(json).unwrap(), Verdict::Drifted(_)),
                "{label} is drift",
            );
        }
    }

    /// A set's elements are compared in the order the renderer writes them,
    /// whatever order the listing gives them in.
    #[test]
    fn a_fence_set_listed_in_another_order_reads_back_as_rendered() {
        let reordered = FENCE.replace(r#"["lo", "wg-a"]"#, r#"["wg-a", "lo"]"#);
        assert_eq!(
            verify_listing(listing(&[
                META, &reordered, LO, WG_A, PORT_V4, PORT_V6, DROP
            ]))
            .unwrap(),
            Verdict::Intact,
        );
    }

    /// The transport read at the next check, scripted per interface.
    fn reads<'a>(
        answers: &'a [(&'static str, io::Result<Transport>)],
    ) -> impl Fn(&str) -> io::Result<Transport> + 'a {
        move |iface| match answers.iter().find(|(i, _)| *i == iface) {
            Some((_, Ok(t))) => Ok(t.clone()),
            Some((_, Err(e))) => Err(io::Error::new(e.kind(), e.to_string())),
            None => panic!("{iface} was not scripted"),
        }
    }

    /// #136, the re-raised link: back on a port the kernel picked, the
    /// exemption installed at boot named the old one, and the tunnel
    /// handshook and carried nothing until a restart. The next check reads
    /// the new port and installs the ruleset again with it.
    #[test]
    fn a_transport_that_changed_is_installed_again_with_the_live_one() {
        let mut installed = installed();
        let before = installed.clone();
        let applied = std::cell::RefCell::new(Vec::<String>::new());
        let moved = Transport::new(45136, [ENDPOINT.parse().unwrap()]);
        let changed = refresh(
            &mut installed,
            reads(&[("wg-a", Ok(moved.clone()))]),
            |script| {
                applied.borrow_mut().push(script.to_string());
                Ok(())
            },
        );
        assert!(changed);
        assert_eq!(installed.transports, vec![("wg-a".to_string(), moved)]);
        assert_eq!(installed.tunnels, before.tunnels, "the pairing is kept");
        let applied = applied.borrow();
        assert_eq!(applied.len(), 1, "one install: {applied:?}");
        assert_eq!(applied[0], installed.script());
        assert!(
            applied[0].contains("udp sport 45136 udp dport 51820 accept")
                && !applied[0].contains("udp sport 51820"),
            "the live port is exempted and the old one no longer is: {}",
            applied[0],
        );
    }

    #[test]
    fn an_unchanged_transport_installs_nothing() {
        let mut installed = installed();
        let before = installed.clone();
        let changed = refresh(
            &mut installed,
            reads(&[("wg-a", Ok(two_peer_transport()))]),
            |_| panic!("nothing changed, nothing to install"),
        );
        assert!(!changed);
        assert_eq!(installed, before);
    }

    /// A link that cannot be read keeps the exemption last read: scoped to
    /// the endpoint it reaches nothing else, and a read that failed for any
    /// other reason must not silence a working tunnel.
    #[test]
    fn a_transport_that_will_not_read_keeps_the_last_one() {
        let mut installed = installed();
        let before = installed.clone();
        let changed = refresh(
            &mut installed,
            reads(&[("wg-a", Err(io::Error::other("Unable to access interface")))]),
            |_| panic!("nothing read, nothing to install"),
        );
        assert!(!changed);
        assert_eq!(installed, before);
    }

    /// An install of the live transport that fails still replaces what the
    /// watch compares the live table with, so the check that follows reads
    /// the old table as drift and fences every vpn profile.
    #[test]
    fn a_failed_install_of_the_live_transport_is_drift_at_the_check() {
        let mut installed = installed();
        let changed = refresh(
            &mut installed,
            reads(&[("wg-a", Ok(transport_on(45136)))]),
            |_| Err(io::Error::other("nft -f - exited 1")),
        );
        assert!(changed);
        let live = listing(&[META, FENCE, LO, WG_A, PORT_V4, PORT_V6, DROP]);
        let verdict = verify_with(
            &installed,
            || Ok(format!("table inet {TABLE}\n")),
            move || Ok(live.clone()),
        )
        .unwrap();
        assert!(matches!(verdict, Verdict::Drifted(_)), "got {verdict:?}");
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

    /// What `kill_switch_lost_total{outcome}` was raised by.
    fn lost_for(metrics: &torrentd_engine::RecordingSink, outcome: &str) -> u64 {
        metrics
            .calls()
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    torrentd_engine::metrics::MetricCall::IncCounter { name, labels }
                        if name == "kill_switch_lost_total"
                            && labels[..] == [("outcome".to_string(), outcome.to_string())]
                )
            })
            .count() as u64
    }

    /// The loss a reinstall repairs is over within one check, so the gauge a
    /// scrape reads is back at 1; the counter is what keeps it.
    #[test]
    fn a_loss_the_reinstall_repairs_is_counted_once_and_reads_present() {
        let (fence, metrics) = (Recorded::default(), torrentd_engine::RecordingSink::new());
        let next = tick(
            Watch::Intact,
            verdicts(vec![Ok(Verdict::Absent), Ok(Verdict::Intact)]),
            || Ok(()),
            &fence,
            &metrics,
        );
        assert_eq!(next, Watch::Intact);
        assert_eq!(lost_for(&metrics, "reinstalled"), 1);
        assert_eq!(lost_for(&metrics, "lost"), 0);
        assert_eq!(metrics.count_for("kill_switch_lost_total"), 1);
        assert_eq!(gauge(&metrics), Some(1.0));

        let next = tick(
            next,
            verdicts(vec![Ok(Verdict::Intact)]),
            || panic!("nothing to reinstall"),
            &fence,
            &metrics,
        );
        assert_eq!(next, Watch::Intact);
        assert_eq!(
            metrics.count_for("kill_switch_lost_total"),
            1,
            "an intact check counts nothing"
        );
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
            assert_eq!(lost_for(&metrics, "reinstalled"), 1, "{label}");
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
            assert_eq!(
                lost_for(&metrics, "lost"),
                1,
                "{label}: one loss, counted once"
            );
            assert_eq!(lost_for(&metrics, "reinstalled"), 0, "{label}");
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
            assert_eq!(metrics.count_for("kill_switch_lost_total"), 0);
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
        remove_table_for(998).expect("remove");
        assert_eq!(verify(&installed).unwrap(), Verdict::Absent);
    }

    /// #178 against a real `nft`: a tunnel holding an IPv6 address installs
    /// its `ip6 saddr` fence, the live table verifies intact with it, and a
    /// table without it is drift. Run it as [`disable_against_real_nft`]
    /// says, with `--test-threads=1` beside the others.
    #[test]
    #[ignore = "needs nft and CAP_NET_ADMIN in a private network namespace"]
    fn an_ipv6_fence_against_real_nft() {
        let installed = Installed::render(
            998,
            vec![tunnel("wg-a").with_v6([ADDR_A6])],
            vec![("wg-a".to_string(), two_peer_transport())],
        )
        .unwrap();
        apply(&installed.script()).expect("install");
        let listed = exec::run_ok("nft", &["list", "table", "inet", TABLE], None, exec::QUICK)
            .expect("list the table");
        let listed = String::from_utf8_lossy(&listed.stdout);
        assert!(
            listed.contains("ip6 saddr 2001:db8::2 oifname != { \"lo\", \"wg-a\" } drop"),
            "the IPv6 fence is installed: {listed}"
        );
        assert_eq!(verify(&installed).unwrap(), Verdict::Intact);
        apply(&self::installed().script()).expect("install the table without it");
        assert!(matches!(verify(&installed).unwrap(), Verdict::Drifted(_)));
        remove_table_for(998).expect("remove");
    }
}
