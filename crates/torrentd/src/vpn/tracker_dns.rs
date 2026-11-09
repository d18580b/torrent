//! A vpn profile's tracker lookups, resolved through its own tunnel
//! (`tracker_dns = "tunnel"`).
//!
//! **Why a proxy.** libtorrent resolves a tracker's hostname with libc
//! (`getaddrinfo` on a resolver thread), and libc reads one
//! `/etc/resolv.conf` for the whole process. Whatever tunnel a session
//! sends from, the lookup goes to the host's resolver, and from a local stub
//! on to that stub's upstream over the physical link, telling it which
//! trackers this host uses. libtorrent 2.0 has no per-session resolver hook
//! (its `resolver_interface` is internal, built by `session_impl` and never
//! taken from `session_params`), so the only per-session way to keep a name
//! away from libc is the one libtorrent already has: a SOCKS5 proxy for
//! tracker connections with `proxy_hostnames`, which hands the proxy the
//! hostname instead of an address. Rewriting tracker URLs to addresses the
//! daemon resolved itself would break HTTPS (the certificate names the host),
//! the `Host` header, and the tracker guard, which matches hosts by name.
//!
//! **What runs.** [`TrackerProxy`] is a SOCKS5 server (RFC 1928, with RFC
//! 1929 username and password) listening on the tunnel's own address. Only
//! the profile's session can use it: a connection from any other source
//! address is closed unanswered, and the credentials are random per boot and
//! known only to that session. It resolves each name by asking the profile's
//! resolvers over UDP from the tunnel address, with the socket bound to the
//! tunnel device where the kernel allows, and connects to the tracker from
//! there too, so the lookup, like the announce, leaves by the tunnel or not
//! at all. The kill switch's per-profile rule (`ip saddr <tunnel address>
//! oifname "<its interface>"`) already accepts both; no carve-out is needed.
//!
//! **Why on the tunnel address.** libtorrent binds a tracker connection to
//! its listen socket's device. A socket bound to the tunnel device cannot
//! reach `127.0.0.1` (the loopback route is on `lo`), but it can reach an
//! address the tunnel device itself holds: the local route for it is on that
//! device, and the kernel then delivers the packet over loopback.
//!
//! **UDP trackers and uTP.** A UDP tracker is reached through a SOCKS5 UDP
//! association, relayed here. While one stands, libtorrent drops every
//! datagram on the listen socket that does not come from the proxy, uTP's
//! included, so a profile with tunnel DNS runs its peers over TCP alone
//! ([`TrackerProxy::configure`] turns uTP off rather than leave it broken).
//! Peer connections never go through the proxy.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;
use rand::RngCore;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpSocket;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tracing::debug;
use tracing::warn;

mod dns;

/// libtorrent's `settings_pack::socks5_pw`.
const SOCKS5_PW: u32 = 3;
/// How long one resolver is given to answer one question.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a tracker gets to accept the proxy's connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the client gets to finish the SOCKS5 handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounds on how long an answer is reused, whatever TTL it carried: a tracker
/// is asked again every few minutes per torrent, and a TTL of 0 would put a
/// query on the wire for each announce.
const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_secs(3600);
/// Most distinct names the answer cache holds before it is emptied.
const CACHE_CAP: usize = 1024;
/// Most destinations one UDP association answers for.
const UDP_PEERS_CAP: usize = 256;

/// Each name looked up, with when its answer expires and the answer.
type AnswerCache = HashMap<String, (Instant, Vec<IpAddr>)>;

/// Where a profile's tracker lookups are sent, and from where.
#[derive(Clone, Debug)]
pub struct TunnelResolver {
    /// The tunnel address every query and connection is sent from.
    bind: IpAddr,
    /// The tunnel device, bound with `SO_BINDTODEVICE` where permitted.
    device: Option<String>,
    servers: Vec<SocketAddr>,
    cache: Arc<Mutex<AnswerCache>>,
}

impl TunnelResolver {
    /// Resolvers on port 53, asked from `bind` over `device`.
    pub fn new(bind: IpAddr, device: Option<String>, servers: &[IpAddr]) -> Self {
        Self::with_servers(
            bind,
            device,
            servers.iter().map(|ip| SocketAddr::new(*ip, 53)).collect(),
        )
    }

    fn with_servers(bind: IpAddr, device: Option<String>, servers: Vec<SocketAddr>) -> Self {
        Self {
            bind,
            device,
            servers,
            cache: Arc::default(),
        }
    }

    /// The addresses `name` resolves to: its IPv4 addresses, or where it has
    /// none its IPv6 ones. Each resolver is asked in turn until one answers.
    pub async fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some((until, addrs)) = self.cache.lock().get(&key) {
            if Instant::now() < *until {
                return Ok(addrs.clone());
            }
        }
        let mut last = io::Error::other("no tunnel resolver configured");
        'servers: for server in &self.servers {
            for qtype in [dns::TYPE_A, dns::TYPE_AAAA] {
                match self.ask(*server, &key, qtype).await {
                    Ok(answer) if answer.addrs.is_empty() => continue,
                    Ok(answer) => {
                        let ttl = Duration::from_secs(answer.ttl.into()).clamp(MIN_TTL, MAX_TTL);
                        let mut cache = self.cache.lock();
                        if cache.len() >= CACHE_CAP {
                            cache.clear();
                        }
                        cache.insert(key, (Instant::now() + ttl, answer.addrs.clone()));
                        return Ok(answer.addrs);
                    }
                    Err(e) => {
                        debug!(dns_server = %server, error.cause = %e, "tunnel resolver did not answer");
                        last = e;
                        continue 'servers;
                    }
                }
            }
            // This resolver answered both questions, with no address.
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{key} has no address"),
            ));
        }
        Err(last)
    }

    async fn ask(&self, server: SocketAddr, name: &str, qtype: u16) -> io::Result<dns::Answer> {
        let local = match (self.bind, server) {
            (IpAddr::V4(_), SocketAddr::V4(_)) | (IpAddr::V6(_), SocketAddr::V6(_)) => {
                SocketAddr::new(self.bind, 0)
            }
            (_, SocketAddr::V4(_)) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            (_, SocketAddr::V6(_)) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        let sock = UdpSocket::bind(local).await?;
        bind_device(&sock, self.device.as_deref());
        let id = rand::thread_rng().next_u32() as u16;
        sock.send_to(&dns::query(id, name, qtype)?, server).await?;
        let mut buf = vec![0u8; 1500];
        tokio::time::timeout(DNS_TIMEOUT, async {
            loop {
                let (n, from) = sock.recv_from(&mut buf).await?;
                if from != server {
                    continue;
                }
                match dns::answer(&buf[..n], id, name, qtype) {
                    Err(dns::Error::NotOurs) => continue,
                    Err(e) => return Err(io::Error::other(format!("{server}: {e}"))),
                    Ok(answer) => return Ok(answer),
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{server} did not answer")))?
    }

    /// An outbound TCP connection to `name:port`, from the tunnel.
    async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        let addrs = match target {
            Target::Addr(sa) => vec![*sa],
            Target::Name(name, port) => self
                .resolve(name)
                .await?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, *port))
                .collect(),
        };
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address to connect to");
        for addr in addrs {
            let sock = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            bind_device(&sock, self.device.as_deref());
            if addr.is_ipv4() == self.bind.is_ipv4() {
                sock.bind(SocketAddr::new(self.bind, 0))?;
            }
            match tokio::time::timeout(CONNECT_TIMEOUT, sock.connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last = e,
                Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
            }
        }
        Err(last)
    }

    /// A UDP socket for relayed datagrams, sending from the tunnel.
    async fn udp_out(&self) -> io::Result<UdpSocket> {
        let sock = UdpSocket::bind(SocketAddr::new(self.bind, 0)).await?;
        bind_device(&sock, self.device.as_deref());
        Ok(sock)
    }
}

/// `SO_BINDTODEVICE`, best effort: before Linux 5.7 it needs `CAP_NET_RAW`,
/// which the daemon may not hold. The source address is bound either way,
/// and the profile's `from <address>` rule routes it by the tunnel, as it
/// does libtorrent's own sockets when their device bind is refused.
fn bind_device(sock: &impl std::os::fd::AsRawFd, device: Option<&str>) {
    let Some(device) = device else { return };
    let fd = sock.as_raw_fd();
    let name = device.as_bytes();
    // SAFETY: `fd` is an open socket owned by `sock` for the duration of the
    // call, and `name` is a live byte slice whose length is passed with it.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        debug!(
            vpn_iface = device,
            error.cause = %io::Error::last_os_error(),
            "SO_BINDTODEVICE refused; the tracker lookup is bound by source address alone",
        );
    }
}

/// A SOCKS5 destination.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    Addr(SocketAddr),
    Name(String, u16),
}

/// A running per-profile SOCKS5 proxy for tracker connections. Dropping it
/// stops it, unless [`TrackerProxy::keep`] was called.
#[derive(Debug)]
pub struct TrackerProxy {
    addr: SocketAddr,
    username: String,
    password: String,
    task: Option<tokio::task::AbortHandle>,
}

impl TrackerProxy {
    /// Listen on `resolver`'s tunnel address, on a port the kernel picks.
    pub async fn start(resolver: TunnelResolver) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(resolver.bind, 0)).await?;
        let addr = listener.local_addr()?;
        let username = random_token();
        let password = random_token();
        let auth = Arc::new((username.clone(), password.clone()));
        let resolver = Arc::new(resolver);
        let task = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error.cause = %e, "tracker proxy accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // Only the session on this tunnel, which connects from its
                // address. A packet arriving on the tunnel claiming that
                // source is a martian the kernel drops.
                if peer.ip() != resolver.bind {
                    debug!(peer = %peer, "tracker proxy refused a connection from another address");
                    continue;
                }
                let resolver = resolver.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, &resolver, &auth).await {
                        debug!(error.cause = %e, "tracker proxy connection ended");
                    }
                });
            }
        });
        Ok(Self {
            addr,
            username,
            password,
            task: Some(task.abort_handle()),
        })
    }

    /// Where the proxy listens.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Point a session's tracker connections at this proxy, hostnames and
    /// all, leave its peer connections direct, and turn uTP off (see the
    /// module documentation).
    pub fn configure(&self, s: &mut torrentd_engine::Settings) {
        s.proxy_type = Some(SOCKS5_PW);
        s.proxy_hostname = Some(self.addr.ip().to_string());
        s.proxy_port = Some(self.addr.port());
        s.proxy_username = Some(self.username.clone());
        s.proxy_password = Some(self.password.clone());
        s.proxy_hostnames = Some(true);
        s.proxy_peer_connections = Some(false);
        s.proxy_tracker_connections = Some(true);
        s.enable_outgoing_utp = Some(false);
        s.enable_incoming_utp = Some(false);
    }

    /// Leave the proxy running for the life of the process, as the session
    /// it serves is.
    pub fn keep(mut self) {
        self.task = None;
    }
}

impl Drop for TrackerProxy {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Equal-time comparison, so the reply's timing says nothing about how much
/// of a guess matched.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

const REP_OK: u8 = 0;
const REP_FAILURE: u8 = 1;
const REP_HOST_UNREACHABLE: u8 = 4;
const REP_REFUSED: u8 = 5;
const REP_COMMAND: u8 = 7;
const REP_ADDRESS_TYPE: u8 = 8;

async fn serve(
    mut stream: TcpStream,
    resolver: &TunnelResolver,
    auth: &(String, String),
) -> io::Result<()> {
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut stream, auth))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))??;
    let Some((cmd, target)) = request else {
        return Ok(());
    };
    match cmd {
        1 => {
            let upstream = match resolver.connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    let rep = match e.kind() {
                        io::ErrorKind::ConnectionRefused => REP_REFUSED,
                        io::ErrorKind::NotFound | io::ErrorKind::TimedOut => REP_HOST_UNREACHABLE,
                        _ => REP_FAILURE,
                    };
                    reply(&mut stream, rep, None).await?;
                    return Err(e);
                }
            };
            reply(&mut stream, REP_OK, Some(upstream.local_addr()?)).await?;
            let mut upstream = upstream;
            tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
            Ok(())
        }
        3 => associate(stream, resolver).await,
        _ => reply(&mut stream, REP_COMMAND, None).await,
    }
}

/// Method selection, authentication, and the request. `None` where the
/// client was answered with a refusal and the connection is done.
async fn handshake(
    stream: &mut TcpStream,
    auth: &(String, String),
) -> io::Result<Option<(u8, Target)>> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(io::Error::other("not SOCKS5"));
    }
    let mut methods = vec![0u8; head[1].into()];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        stream.write_all(&[5, 0xff]).await?;
        return Ok(None);
    }
    stream.write_all(&[5, 2]).await?;

    // RFC 1929.
    let mut ver = [0u8; 2];
    stream.read_exact(&mut ver).await?;
    let mut user = vec![0u8; ver[1].into()];
    stream.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; plen[0].into()];
    stream.read_exact(&mut pass).await?;
    let ok = same(&user, auth.0.as_bytes()) & same(&pass, auth.1.as_bytes());
    stream.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if ver[0] != 1 || !ok {
        return Ok(None);
    }

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(io::Error::other("not SOCKS5"));
    }
    let target = match read_target(stream, req[3]).await? {
        Some(t) => t,
        None => {
            reply(stream, REP_ADDRESS_TYPE, None).await?;
            return Ok(None);
        }
    };
    Ok(Some((req[1], target)))
}

async fn read_target(stream: &mut TcpStream, atyp: u8) -> io::Result<Option<Target>> {
    let target = match atyp {
        1 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Target::Addr(SocketAddr::new(ip.into(), u16::from_be_bytes([b[4], b[5]])))
        }
        4 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            Target::Addr(SocketAddr::new(
                Ipv6Addr::from(ip).into(),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut b = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut b).await?;
            let port = u16::from_be_bytes([b[b.len() - 2], b[b.len() - 1]]);
            b.truncate(b.len() - 2);
            let Ok(name) = String::from_utf8(b) else {
                return Ok(None);
            };
            Target::Name(name, port)
        }
        _ => return Ok(None),
    };
    Ok(Some(target))
}

/// `VER REP RSV ATYP BND.ADDR BND.PORT`.
async fn reply(stream: &mut TcpStream, rep: u8, bound: Option<SocketAddr>) -> io::Result<()> {
    let bound = bound.unwrap_or_else(|| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
    let mut out = vec![5, rep, 0];
    put_addr(&mut out, bound);
    stream.write_all(&out).await
}

fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// A UDP datagram's SOCKS5 header: `RSV RSV FRAG ATYP DST.ADDR DST.PORT`,
/// and where the payload starts. Fragments, which libtorrent never sends,
/// are refused.
fn parse_udp(datagram: &[u8]) -> Option<(Target, usize)> {
    if datagram.len() < 4 || datagram[2] != 0 {
        return None;
    }
    let rest = &datagram[4..];
    match datagram[3] {
        1 if rest.len() >= 6 => {
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Some((Target::Addr(SocketAddr::new(ip.into(), port)), 10))
        }
        4 if rest.len() >= 18 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&rest[..16]);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Some((
                Target::Addr(SocketAddr::new(Ipv6Addr::from(ip).into(), port)),
                22,
            ))
        }
        3 => {
            let len = usize::from(*rest.first()?);
            let name = std::str::from_utf8(rest.get(1..1 + len)?).ok()?;
            let port = rest.get(1 + len..3 + len)?;
            Some((
                Target::Name(name.to_string(), u16::from_be_bytes([port[0], port[1]])),
                4 + 3 + len,
            ))
        }
        _ => None,
    }
}

/// A UDP association: relay each datagram the client sends to the relay
/// socket on to its destination from the tunnel, and each answer from a
/// destination it was sent to back to the client, until the control
/// connection closes.
async fn associate(mut control: TcpStream, resolver: &TunnelResolver) -> io::Result<()> {
    let relay = match UdpSocket::bind(SocketAddr::new(resolver.bind, 0)).await {
        Ok(s) => s,
        Err(e) => {
            reply(&mut control, REP_FAILURE, None).await?;
            return Err(e);
        }
    };
    let out = match resolver.udp_out().await {
        Ok(s) => s,
        Err(e) => {
            reply(&mut control, REP_FAILURE, None).await?;
            return Err(e);
        }
    };
    reply(&mut control, REP_OK, Some(relay.local_addr()?)).await?;

    let mut client: Option<SocketAddr> = None;
    let mut sent_to: HashSet<SocketAddr> = HashSet::new();
    let mut from_client = vec![0u8; 65536];
    let mut from_out = vec![0u8; 65536];
    let mut eof = [0u8; 1];
    loop {
        tokio::select! {
            r = control.read(&mut eof) => {
                // The association lives as long as its control connection.
                if matches!(r, Ok(0) | Err(_)) {
                    return Ok(());
                }
            }
            r = relay.recv_from(&mut from_client) => {
                let (n, from) = r?;
                if from.ip() != resolver.bind || client.is_some_and(|c| c != from) {
                    continue;
                }
                client = Some(from);
                let Some((target, at)) = parse_udp(&from_client[..n]) else { continue };
                let dest = match target {
                    Target::Addr(sa) => sa,
                    Target::Name(name, port) => match resolver.resolve(&name).await {
                        Ok(addrs) => match addrs.iter().find(|a| a.is_ipv4() == resolver.bind.is_ipv4()) {
                            Some(ip) => SocketAddr::new(*ip, port),
                            None => continue,
                        },
                        Err(e) => {
                            debug!(error.cause = %e, "tracker proxy could not resolve a UDP destination");
                            continue;
                        }
                    },
                };
                if sent_to.len() >= UDP_PEERS_CAP {
                    sent_to.clear();
                }
                sent_to.insert(dest);
                if let Err(e) = out.send_to(&from_client[at..n], dest).await {
                    debug!(error.cause = %e, "tracker proxy could not relay a datagram");
                }
            }
            r = out.recv_from(&mut from_out) => {
                let (n, from) = r?;
                let Some(client) = client else { continue };
                if !sent_to.contains(&from) {
                    continue;
                }
                let mut wrapped = vec![0, 0, 0];
                put_addr(&mut wrapped, from);
                wrapped.extend_from_slice(&from_out[..n]);
                let _ = relay.send_to(&wrapped, client).await;
            }
        }
    }
}

#[cfg(test)]
mod tests;
