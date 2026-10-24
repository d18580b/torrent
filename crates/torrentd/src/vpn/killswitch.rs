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
//! installed ([`Tunnel`]) and read again before each of [`watch`]'s checks
//! ([`refresh`]), so an address the link gains or changes after boot is
//! paired from the next check. A shared `oifname { every tunnel }` set let any
//! socket the daemon owns leave by any profile's tunnel, so a packet from
//! profile A's address that the routing table sent out of profile B's tunnel
//! — A's per-source `ip rule` lost or shadowed — was accepted, and A's
//! trackers saw B's exit address until the next health poll. Now it falls
//! through to the drop. Every address a session sends from is paired: the
//! link's first IPv4 address, and each global IPv6 address on it
//! ([`Tunnel::with_v6`]), since a session listens on its tunnel device and so
//! listens and announces on every address the device holds. The daemon's
//! IPv6 egress from any other address (a link-local one included) is dropped.
//! The VPN monitor's route probe asks from the same addresses, each toward a
//! destination of its own family ([`super::route`]), so a paired IPv6
//! address needs an IPv6 route through the tunnel as its IPv4 one does.
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
/// network namespace would still share a table; [`TableLock`] refuses the
/// second of them, and docs/running.md requires separate uids.
pub fn table_name(uid: u32) -> String {
    format!("{TABLE_PREFIX}_{uid}")
}

/// The table for this process's uid, or the name's pattern where the uid
/// cannot be read: for messages that tell an operator what to delete.
pub fn own_table_name() -> String {
    current_uid().map_or_else(|_| format!("{TABLE_PREFIX}_<uid>"), table_name)
}

/// The abstract unix socket `@torrentd_ks_<uid>`, bound for as long as this
/// is held: one holder per uid per network namespace, which is exactly the
/// scope of the uid's [`table_name`] table. A daemon holds it for its life
/// and `torrentd net-cleanup` for its run, so neither a second daemon of the
/// same uid on another state directory nor a cleanup acting for that uid can
/// replace or remove the table a running daemon's kill switch is.
///
/// The state directory's single-instance lock cannot do this: it is per
/// state directory, and the table is per uid. An abstract socket needs no
/// file, so nothing is left behind however the process ends, and it is
/// close-on-exec, so no child process (`openvpn`, `nft`) inherits it.
#[derive(Debug)]
pub struct TableLock {
    /// Never read. Holding the bound socket is the lock.
    _socket: std::os::unix::net::UnixDatagram,
}

impl TableLock {
    /// Take the lock on `uid`'s table, or refuse naming the process that
    /// holds it. The refusal's kind is [`io::ErrorKind::AddrInUse`], and no
    /// other failure's is.
    pub fn acquire(uid: u32) -> io::Result<Self> {
        Self::acquire_named(&table_name(uid))
    }

    /// [`TableLock::acquire`] on the abstract socket `@name`.
    pub(crate) fn acquire_named(name: &str) -> io::Result<Self> {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        use std::os::unix::net::UnixDatagram;

        let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
        match UnixDatagram::bind_addr(&addr) {
            Ok(socket) => Ok(Self { _socket: socket }),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                let who = match socket_holder(name) {
                    Some((pid, comm)) => format!("{comm} (pid {pid})"),
                    None => "another process".to_string(),
                };
                Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "{who} holds the abstract unix socket @{name}, which a torrentd holds for \
                         its life: the nftables table `inet {name}` is that daemon's kill switch \
                         and would be this one's too, since the table is per uid, not per state \
                         directory. Refusing before touching it. Stop that daemon first, or run \
                         this one under a user of its own (docs/running.md §11, \"Two daemons in \
                         one network namespace need separate uids\").",
                    ),
                ))
            }
            Err(e) => Err(io::Error::new(
                e.kind(),
                format!("bind the abstract unix socket @{name}: {e}"),
            )),
        }
    }
}

/// The pid and command name of a process holding the abstract unix socket
/// `@name`, as this process can see it: the socket's inode from
/// `/proc/net/unix` (this network namespace's), then the `/proc/<pid>/fd`
/// entry linking to it. Best effort, for the refusal's message only: a holder
/// in another pid namespace, or owned by another uid, is not found.
fn socket_holder(name: &str) -> Option<(u32, String)> {
    let table = std::fs::read_to_string("/proc/net/unix").ok()?;
    let inode = unix_socket_inode(&table, name)?;
    let target = std::ffi::OsString::from(format!("socket:[{inode}]"));
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let holds = fds
            .flatten()
            .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == target));
        if holds {
            let comm = std::fs::read_to_string(entry.path().join("comm"))
                .map_or_else(|_| "a process".to_string(), |c| c.trim().to_string());
            return Some((pid, comm));
        }
    }
    None
}

/// The inode `/proc/net/unix`'s `table` lists for the abstract socket
/// `@name`. Its columns are `Num RefCount Protocol Flags Type St Inode Path`.
fn unix_socket_inode(table: &str, name: &str) -> Option<u64> {
    let path = format!("@{name}");
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            [_, _, _, _, _, _, inode, p] if *p == path => inode.parse().ok(),
            _ => None,
        }
    })
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
/// installs again when they differ. [`refresh`] replaces the tunnels, the
/// transports and the table when a link's addresses or transport change.
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
    (uid == 0).then(|| io::Error::other(RootRefused))
}

/// The error [`refusal_for_uid`] carries, so a caller can tell the refusal —
/// which no restart changes — apart from an `nft` failure that one might
/// ([`is_uid_refusal`]).
#[derive(Debug)]
struct RootRefused;

impl std::fmt::Display for RootRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "network_kill_switch = true requires a dedicated non-root user: the ruleset \
             confines the daemon's uid to loopback and its tunnels, and as uid 0 that \
             would drop every root-owned process's traffic on this host. Run the daemon \
             as its own user with CAP_NET_ADMIN, which raises WireGuard links with `ip` \
             and `wg` (see docs/running.md, \"Kill switch\"); otherwise unset \
             network_kill_switch.",
        )
    }
}

impl std::error::Error for RootRefused {}

/// Whether `e` is [`refusal_for_uid`]'s refusal, as [`enable`] returns it.
pub(crate) fn is_uid_refusal(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.downcast_ref::<RootRefused>().is_some())
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
    /// fences one whose tunnel is down, because the table was found gone or
    /// changed ([`FenceCause::NotInForce`]).
    fn fence_all(&self) {
        self.fence_all_for(FenceCause::NotInForce);
    }
    /// [`Fence::fence_all`], for `cause`.
    fn fence_all_for(&self, cause: FenceCause);
    /// Lift what [`Fence::fence_all`] fenced: called only once the ruleset
    /// has been verified intact again.
    fn lift(&self);
}

/// Why [`watch`] fences every vpn profile: what the fence's
/// `profile_vpn_fenced_total` reason says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FenceCause {
    /// A check found the table gone, or not as installed.
    NotInForce,
    /// [`PROBE_FAILURES_TO_FENCE`](crate::vpn_monitor::PROBE_FAILURES_TO_FENCE)
    /// checks in a row could not run, so nothing has said for that long that
    /// the table is in force.
    Unverifiable,
}

/// How often [`watch`] checks the table is still installed.
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Where the watch stands between checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Watch {
    /// The last check found the table as installed.
    #[default]
    Intact,
    /// The last this many checks could not run, fewer than
    /// [`PROBE_FAILURES_TO_FENCE`](crate::vpn_monitor::PROBE_FAILURES_TO_FENCE),
    /// and nothing is fenced for them.
    Unchecked(u32),
    /// A check found it gone or changed: every vpn profile was fenced, and the
    /// one reinstall this loss gets was tried and did not check intact.
    Lost,
    /// [`PROBE_FAILURES_TO_FENCE`](crate::vpn_monitor::PROBE_FAILURES_TO_FENCE)
    /// checks in a row could not run: every vpn profile was fenced
    /// ([`FenceCause::Unverifiable`]), and stays so until a check finds the
    /// table intact.
    Unverified,
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
/// cannot run counts in `kill_switch_probe_errors_total` and, alone, changes
/// nothing, since not knowing is not the same as absent; but
/// [`PROBE_FAILURES_TO_FENCE`](crate::vpn_monitor::PROBE_FAILURES_TO_FENCE)
/// in a row fence every vpn profile (`probe_unavailable`), since an `nft` that
/// stays missing or stalled left every profile seeding with no check in force,
/// and the fence comes off at the first check that finds the table intact.
///
/// Before each check, each tunnel's addresses and transport are read off its
/// link again ([`refresh`]), and a change installs the ruleset again with the
/// live ones, so a link re-raised on another port or to another endpoint, or
/// holding an IPv6 address it did not hold at boot, carries again at the next
/// check rather than at the next restart. A reinstall that fails
/// leaves the live table differing from the one now rendered, which the
/// check reads as drift.
///
/// Only spawned when the kill switch is active. Runs until `stop`, which
/// the shutdown fires just before it closes the sessions and removes the
/// table, so the check holds through the shutdown's drain, while the
/// sessions still seed; past that point it would read the removal as a
/// flush and install the table again. A check already on the blocking pool
/// when the stop comes runs on, but its fences, lifts and installs pass the
/// stop's [`FencingGate`](crate::vpn_monitor::FencingGate), which the stop
/// closes before the teardown once any of them inside it has ended, so none
/// lands after the teardown unless that one outlasts the stop's bound.
pub(crate) async fn watch(
    installed: Installed,
    fence: std::sync::Arc<dyn Fence>,
    metrics: std::sync::Arc<crate::metrics_sink::PromSink>,
    mut stop: crate::vpn_monitor::FencingStopped,
) {
    use torrentd_engine::MetricsSink;
    // Installed moments ago by `enable`, and verified by the boot.
    metrics.set_gauge("kill_switch_table_present", 1.0, &[]);
    // The uid, and so the table, is fixed for the run; every event a check
    // logs carries it through this span. At error level so that no level
    // filter that lets one of those events through disables the span.
    let table = installed.table_name();
    let installed = std::sync::Arc::new(std::sync::Mutex::new(installed));
    let gate = stop.gate();
    let mut state = Watch::default();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(WATCH_INTERVAL) => {}
            () = stop.stopped() => {
                tracing::info!(target: "torrentd::vpn::killswitch", table = %table, "kill switch watch stopping");
                return;
            }
        }
        // Blocking throughout: the checks and the reinstall shell out to nft,
        // and fencing pauses torrents under each session's lock. Aborting
        // the watch cannot cancel this closure, so its fences and installs
        // pass the stop's gate.
        let ticked = tokio::task::spawn_blocking({
            let (installed, fence, metrics) = (installed.clone(), fence.clone(), metrics.clone());
            let gate = gate.clone();
            let span = tracing::error_span!("kill_switch_watch", table = %table);
            move || {
                let _span = span.entered();
                let apply = gated_apply(&gate, apply);
                let mut installed = installed.lock().unwrap_or_else(|p| p.into_inner());
                refresh(
                    &mut installed,
                    super::ip_lookup::first_ipv4,
                    super::ip_lookup::global_ipv6,
                    transport,
                    &apply,
                );
                let installed = &*installed;
                tick(
                    state,
                    || verify(installed),
                    || apply(&installed.script()),
                    &Gated {
                        fence: &*fence,
                        gate: &gate,
                    },
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

/// `apply`, refused once the shutdown's stop has closed `gate`: the teardown
/// is about to remove the table, or already has, and installing it then
/// would outlive the daemon.
fn gated_apply<'a>(
    gate: &'a crate::vpn_monitor::FencingGate,
    apply: impl Fn(&str) -> io::Result<()> + 'a,
) -> impl Fn(&str) -> io::Result<()> + 'a {
    move |script| {
        gate.run(|| apply(script)).unwrap_or_else(|| {
            Err(io::Error::other(
                "the shutdown stopped the kill switch watch; not installing the table again",
            ))
        })
    }
}

/// A [`Fence`] whose fences and lifts are dropped once the shutdown's stop
/// has closed `gate`: past it the sessions are closing.
struct Gated<'a> {
    fence: &'a dyn Fence,
    gate: &'a crate::vpn_monitor::FencingGate,
}

impl Fence for Gated<'_> {
    fn fence_all_for(&self, cause: FenceCause) {
        self.gate.run(|| self.fence.fence_all_for(cause));
    }
    fn lift(&self) {
        self.gate.run(|| self.fence.lift());
    }
}

/// Read each tunnel's addresses — its first IPv4 address (`tunnel_addr`) and
/// its global IPv6 ones (`tunnel_v6`) — and its transport off its link, and
/// where any changed since `installed` was rendered, render it again with the
/// live ones and install that. Returns whether it changed.
///
/// The addresses are read again for the same reason as the transport: they
/// were fixed at install, so an IPv6 address the link gained after boot (a
/// provider's client adding it once the link is up, an operator's `ip -6
/// addr add`) was never paired. A session listening on the device sends from
/// it, and the ruleset dropped every such packet for the rest of the run,
/// while the route probe judged its route healthy.
///
/// A link that cannot be read — down, or gone while its provider's client
/// raises it again — keeps what was last read of it: the exemption is scoped
/// to the provider's endpoint and each accept to the tunnel's own interface,
/// so a stale one reaches nothing else, and dropping it on a read that failed
/// for any other reason would silence a working tunnel until the next check.
/// The VPN monitor reports and fences a link that is down.
///
/// `installed` is replaced whether or not the install takes: a failed one
/// leaves the live table differing from the rendered one, and the check that
/// follows reads that as drift, fences every vpn profile, and installs it
/// again.
fn refresh(
    installed: &mut Installed,
    tunnel_addr: impl Fn(&str) -> io::Result<Ipv4Addr>,
    tunnel_v6: impl Fn(&str) -> io::Result<Vec<Ipv6Addr>>,
    transport: impl Fn(&str) -> io::Result<Transport>,
    apply: impl Fn(&str) -> io::Result<()>,
) -> bool {
    let kept = |iface: &str, what: &str, e: io::Error| {
        tracing::debug!(
            target: "torrentd::vpn::killswitch",
            iface = %iface,
            error.cause = %e,
            "could not read the tunnel's {what}; keeping its pairing as last read",
        );
    };
    let tunnels: Vec<Tunnel> = installed
        .tunnels
        .iter()
        .map(|t| {
            let addr = tunnel_addr(&t.iface).unwrap_or_else(|e| {
                kept(&t.iface, "IPv4 address", e);
                t.addr
            });
            let v6 = tunnel_v6(&t.iface).unwrap_or_else(|e| {
                kept(&t.iface, "IPv6 addresses", e);
                t.v6.clone()
            });
            Tunnel::new(t.iface.as_str(), addr).with_v6(v6)
        })
        .collect();
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
    if tunnels == installed.tunnels && live == installed.transports {
        return false;
    }
    let next = match Installed::render(installed.uid, tunnels, live) {
        Ok(next) => next,
        // Not reached: the same names rendered at install.
        Err(e) => {
            tracing::error!(
                target: "torrentd::vpn::killswitch",
                uid = installed.uid,
                error.cause = %e,
                "could not render the kill switch over the tunnels' live addresses and \
                 transport",
            );
            return false;
        }
    };
    tracing::warn!(
        target: "torrentd::vpn::killswitch",
        was_tunnels = ?installed.tunnels,
        now_tunnels = ?next.tunnels,
        was = ?installed.transports,
        now = ?next.transports,
        "a tunnel's addresses or transport changed since the kill switch was installed; \
         installing it again with the live ones",
    );
    *installed = next;
    if let Err(e) = apply(&installed.script()) {
        tracing::error!(
            target: "torrentd::vpn::killswitch",
            uid = installed.uid,
            error.cause = %e,
            "could not install the kill switch with the tunnels' live addresses and transport",
        );
    }
    true
}

/// One check of [`watch`]'s, from where the last one left it: verify, fence
/// and reinstall on a loss, lift on a verified recovery. Returns where it
/// leaves the watch.
///
/// Each loss found from any state but [`Watch::Lost`] counts once in
/// `kill_switch_lost_total`, by whether the one reinstall checked intact
/// (`reinstalled`) or not (`lost`). The whole loss, fence and reinstall
/// included, happens within this one call, so `kill_switch_table_present` is
/// back at 1 before any scrape can read the 0: the counter is the only trace a
/// loss the reinstall repaired leaves. The checks that repeat while the watch
/// is [`Watch::Lost`] are the same loss, and are not counted again.
///
/// A check that cannot run fences nothing until it is the
/// [`PROBE_FAILURES_TO_FENCE`](crate::vpn_monitor::PROBE_FAILURES_TO_FENCE)th
/// in a row, which fences every vpn profile
/// ([`FenceCause::Unverifiable`]); each later one fences again any profile set
/// online meanwhile. One that cannot run while the watch is [`Watch::Lost`]
/// leaves it so: every profile is fenced already, for the loss.
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
            if matches!(state, Watch::Lost | Watch::Unverified) {
                tracing::warn!(
                    target: "torrentd::vpn::killswitch",
                    state = ?state,
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
            return unchecked(state, fence);
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
    let outcome = if next == Watch::Intact {
        "reinstalled"
    } else {
        "lost"
    };
    metrics.inc_counter("kill_switch_lost_total", &[("outcome", outcome)]);
    next
}

/// Where a check that could not run leaves the watch, from `state`: see
/// [`tick`].
fn unchecked(state: Watch, fence: &dyn Fence) -> Watch {
    let failures = match state {
        Watch::Lost => return Watch::Lost,
        Watch::Intact => 1,
        Watch::Unchecked(n) => n.saturating_add(1),
        Watch::Unverified => crate::vpn_monitor::PROBE_FAILURES_TO_FENCE,
    };
    if failures < crate::vpn_monitor::PROBE_FAILURES_TO_FENCE {
        return Watch::Unchecked(failures);
    }
    if state != Watch::Unverified {
        tracing::error!(
            target: "torrentd::vpn::killswitch",
            failures,
            "the network kill switch could not be checked this many times in a row, so \
             nothing says the daemon's egress is still confined to the tunnels; fencing \
             every vpn profile until a check finds it in force",
        );
    }
    fence.fence_all_for(FenceCause::Unverifiable);
    Watch::Unverified
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
mod tests;
