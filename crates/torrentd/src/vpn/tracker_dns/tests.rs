use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpSocket;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

use super::dns;
use super::parse_udp;
use super::Target;
use super::TrackerProxy;
use super::TunnelResolver;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// An answer to `query` holding `addrs` as A records, the first under the
/// question's own name by a compression pointer, after a CNAME.
fn reply_to(query: &[u8], addrs: &[Ipv4Addr], rcode: u8) -> Vec<u8> {
    let mut out = query[..2].to_vec();
    out.extend_from_slice(&[0x81, 0x80 | rcode]);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&(addrs.len() as u16 + 1).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..]);
    // A CNAME for the question's name to "x.cdn" (whose labels follow), the
    // resolver having followed it.
    out.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 7]);
    out.extend_from_slice(&[1, b'x', 3, b'c', b'd', b'n', 0]);
    for (i, a) in addrs.iter().enumerate() {
        out.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0]);
        out.push(if i == 0 { 120 } else { 90 });
        out.extend_from_slice(&[0, 4]);
        out.extend_from_slice(&a.octets());
    }
    out
}

#[test]
fn a_query_asks_one_recursive_question() {
    let q = dns::query(0xbeef, "Tracker.Example.", dns::TYPE_A).unwrap();
    assert_eq!(&q[..12], &[0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&q[12..], b"\x07Tracker\x07Example\x00\x00\x01\x00\x01");
    assert!(dns::query(1, "a..b", dns::TYPE_A).is_err());
    assert!(dns::query(1, "tracker.example/announce", dns::TYPE_A).is_err());
    assert!(dns::query(1, &"a".repeat(64), dns::TYPE_A).is_err());
}

#[test]
fn an_answer_gives_its_addresses_and_shortest_ttl_past_a_cname() {
    let q = dns::query(7, "t.example", dns::TYPE_A).unwrap();
    let a = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)];
    let answer = dns::answer(&reply_to(&q, &a, 0), 7, "T.EXAMPLE", dns::TYPE_A).unwrap();
    assert_eq!(answer.addrs, vec![IpAddr::from(a[0]), IpAddr::from(a[1])]);
    assert_eq!(answer.ttl, 90);
}

#[test]
fn an_answer_to_something_else_is_not_ours_and_a_failure_is_an_error() {
    let q = dns::query(7, "t.example", dns::TYPE_A).unwrap();
    let ok = reply_to(&q, &[Ipv4Addr::new(192, 0, 2, 1)], 0);
    assert_eq!(
        dns::answer(&ok, 8, "t.example", dns::TYPE_A),
        Err(dns::Error::NotOurs)
    );
    assert_eq!(
        dns::answer(&ok, 7, "u.example", dns::TYPE_A),
        Err(dns::Error::NotOurs)
    );
    assert_eq!(
        dns::answer(&ok, 7, "t.example", dns::TYPE_AAAA),
        Err(dns::Error::NotOurs)
    );
    // The query itself, echoed: not a response.
    assert_eq!(
        dns::answer(&q, 7, "t.example", dns::TYPE_A),
        Err(dns::Error::NotOurs)
    );

    let nx = reply_to(&q, &[], 3);
    let answer = dns::answer(&nx, 7, "t.example", dns::TYPE_A).unwrap();
    assert!(answer.addrs.is_empty());
    let servfail = reply_to(&q, &[], 2);
    assert_eq!(
        dns::answer(&servfail, 7, "t.example", dns::TYPE_A),
        Err(dns::Error::Rcode(2))
    );
    let mut truncated = ok.clone();
    truncated[2] |= 0x02;
    assert_eq!(
        dns::answer(&truncated, 7, "t.example", dns::TYPE_A),
        Err(dns::Error::Truncated)
    );
    assert_eq!(
        dns::answer(&ok[..ok.len() - 2], 7, "t.example", dns::TYPE_A),
        Err(dns::Error::Malformed)
    );
}

#[test]
fn a_pointer_loop_is_malformed() {
    let q = dns::query(7, "t.example", dns::TYPE_A).unwrap();
    let mut msg = q[..12].to_vec();
    msg[2] |= 0x80;
    msg.extend_from_slice(&[0xc0, 12]);
    assert_eq!(
        dns::answer(&msg, 7, "t.example", dns::TYPE_A),
        Err(dns::Error::Malformed)
    );
}

/// A resolver on loopback answering `name` with `addr` and anything else
/// with NXDOMAIN; the number of questions it was asked.
async fn fake_dns(name: &'static str, addr: Ipv4Addr) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let at = sock.local_addr().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let q = &buf[..n];
            let ours = dns::query(0, name, dns::TYPE_A).unwrap();
            let reply = if q[2..] == ours[2..] {
                reply_to(q, &[addr], 0)
            } else {
                reply_to(q, &[], 3)
            };
            sock.send_to(&reply, from).await.unwrap();
        }
    });
    (at, asked)
}

fn resolver(dns: SocketAddr) -> TunnelResolver {
    TunnelResolver::with_servers(LOOPBACK, None, vec![dns])
}

#[tokio::test]
async fn a_name_is_resolved_by_the_tunnel_resolver_and_its_answer_reused() {
    let (dns, asked) = fake_dns("tracker.test", Ipv4Addr::new(192, 0, 2, 9)).await;
    let r = resolver(dns);
    assert_eq!(
        r.resolve("tracker.test").await.unwrap(),
        vec![IpAddr::from([192, 0, 2, 9])]
    );
    assert_eq!(
        r.resolve("TRACKER.test.").await.unwrap(),
        vec![IpAddr::from([192, 0, 2, 9])]
    );
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "the second lookup came from the cache"
    );

    // A literal is never asked about.
    assert_eq!(
        r.resolve("192.0.2.7").await.unwrap(),
        vec![IpAddr::from([192, 0, 2, 7])]
    );
    assert_eq!(asked.load(Ordering::SeqCst), 1);

    // No A record and no AAAA record: both asked, and not found.
    let e = r.resolve("missing.test").await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    assert_eq!(asked.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_resolver_that_does_not_answer_is_passed_over_for_the_next() {
    // Bound and silent.
    let silent = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let (dns, _) = fake_dns("tracker.test", Ipv4Addr::new(192, 0, 2, 9)).await;
    let r = TunnelResolver::with_servers(LOOPBACK, None, vec![silent.local_addr().unwrap(), dns]);
    tokio::time::pause();
    let got = r.resolve("tracker.test").await.unwrap();
    assert_eq!(got, vec![IpAddr::from([192, 0, 2, 9])]);
}

/// Greet, authenticate and send `request` (`CMD RSV ATYP ADDR PORT`); the
/// reply's `REP` and bound address.
async fn socks(
    proxy: &TrackerProxy,
    from: IpAddr,
    password: &str,
    request: &[u8],
) -> std::io::Result<(TcpStream, u8, SocketAddr)> {
    let sock = TcpSocket::new_v4()?;
    sock.bind(SocketAddr::new(from, 0))?;
    let mut s = sock.connect(proxy.addr()).await?;
    s.write_all(&[5, 1, 2]).await?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await?;
    assert_eq!(m, [5, 2]);
    let mut auth = vec![1, proxy.username.len() as u8];
    auth.extend_from_slice(proxy.username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    s.write_all(&auth).await?;
    let mut a = [0u8; 2];
    s.read_exact(&mut a).await?;
    if a[1] != 0 {
        return Err(std::io::Error::other("authentication refused"));
    }
    let mut req = vec![5];
    req.extend_from_slice(request);
    s.write_all(&req).await?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await?;
    let bound = SocketAddr::new(
        Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]).into(),
        u16::from_be_bytes([rep[8], rep[9]]),
    );
    Ok((s, rep[1], bound))
}

fn by_name(cmd: u8, name: &str, port: u16) -> Vec<u8> {
    let mut r = vec![cmd, 0, 3, name.len() as u8];
    r.extend_from_slice(name.as_bytes());
    r.extend_from_slice(&port.to_be_bytes());
    r
}

#[tokio::test]
async fn a_tracker_named_to_the_proxy_is_resolved_in_the_tunnel_and_connected() {
    let (dns, asked) = fake_dns("tracker.test", Ipv4Addr::LOCALHOST).await;
    let tracker = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = tracker.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut c, _) = tracker.accept().await.unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).await.unwrap();
        c.write_all(&b).await.unwrap();
    });
    let proxy = TrackerProxy::start(resolver(dns)).await.unwrap();
    let password = proxy.password.clone();

    let (mut s, rep, _) = socks(
        &proxy,
        LOOPBACK,
        &password,
        &by_name(1, "tracker.test", port),
    )
    .await
    .unwrap();
    assert_eq!(rep, 0);
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    assert_eq!(asked.load(Ordering::SeqCst), 1);

    // A name the tunnel's resolver does not know is unreachable, and never
    // handed to the host's.
    let (_, rep, _) = socks(
        &proxy,
        LOOPBACK,
        &password,
        &by_name(1, "nowhere.test", port),
    )
    .await
    .unwrap();
    assert_eq!(rep, 4);
}

#[tokio::test]
async fn only_the_session_on_the_tunnel_address_may_use_the_proxy() {
    let (dns, _) = fake_dns("tracker.test", Ipv4Addr::LOCALHOST).await;
    let proxy = TrackerProxy::start(resolver(dns)).await.unwrap();
    let password = proxy.password.clone();
    let request = by_name(1, "tracker.test", 9);

    // A wrong password.
    let e = socks(&proxy, LOOPBACK, "guess", &request)
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), "authentication refused");

    // The right one, from another address: closed unanswered.
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    assert!(socks(&proxy, other, &password, &request).await.is_err());

    // A client offering no username and password method is told so.
    let mut s = TcpStream::connect(proxy.addr()).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0xff]);
}

#[tokio::test]
async fn a_udp_tracker_named_to_the_association_is_relayed_both_ways() {
    let (dns, _) = fake_dns("tracker.test", Ipv4Addr::LOCALHOST).await;
    let tracker = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let tracker_at = tracker.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 64];
        let (n, from) = tracker.recv_from(&mut b).await.unwrap();
        let mut answer = b"re:".to_vec();
        answer.extend_from_slice(&b[..n]);
        tracker.send_to(&answer, from).await.unwrap();
    });
    let proxy = TrackerProxy::start(resolver(dns)).await.unwrap();
    let password = proxy.password.clone();
    let (_control, rep, relay) = socks(&proxy, LOOPBACK, &password, &[3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    assert_eq!(rep, 0);
    assert_eq!(relay.ip(), LOOPBACK);

    let client = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let mut datagram = vec![0, 0, 0];
    datagram.extend_from_slice(&by_name(0, "tracker.test", tracker_at.port())[2..]);
    datagram.extend_from_slice(b"announce");
    client.send_to(&datagram, relay).await.unwrap();

    let mut b = [0u8; 128];
    let (n, from) =
        tokio::time::timeout(std::time::Duration::from_secs(5), client.recv_from(&mut b))
            .await
            .expect("an answer relayed back")
            .unwrap();
    assert_eq!(from, relay);
    let (source, at) = parse_udp(&b[..n]).unwrap();
    assert_eq!(source, Target::Addr(tracker_at));
    assert_eq!(&b[at..n], b"re:announce");
}

#[test]
fn a_udp_header_is_read_in_each_address_form_and_a_fragment_refused() {
    let v4 = [0, 0, 0, 1, 192, 0, 2, 1, 0, 80, b'x'];
    assert_eq!(
        parse_udp(&v4),
        Some((Target::Addr("192.0.2.1:80".parse().unwrap()), 10))
    );
    let mut v6 = vec![0, 0, 0, 4];
    v6.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    v6.extend_from_slice(&[0, 81]);
    assert_eq!(
        parse_udp(&v6),
        Some((Target::Addr("[2001:db8::1]:81".parse().unwrap()), 22))
    );
    let name = [0, 0, 0, 3, 1, b't', 0, 82, b'x'];
    assert_eq!(parse_udp(&name), Some((Target::Name("t".into(), 82), 8)));
    assert_eq!(
        parse_udp(&[0, 0, 1, 1, 192, 0, 2, 1, 0, 80]),
        None,
        "a fragment"
    );
    assert_eq!(parse_udp(&[0, 0, 0, 3, 5, b't']), None, "a short name");
}

#[tokio::test]
async fn configure_points_the_trackers_at_the_proxy_and_leaves_peers_direct() {
    let proxy = TrackerProxy::start(resolver("127.0.0.1:9".parse().unwrap()))
        .await
        .unwrap();
    let mut s = torrentd_engine::Settings::default();
    proxy.configure(&mut s);
    assert_eq!(s.proxy_type, Some(3));
    assert_eq!(s.proxy_hostname.as_deref(), Some("127.0.0.1"));
    assert_eq!(s.proxy_port, Some(proxy.addr().port()));
    assert_eq!(s.proxy_username.as_deref(), Some(proxy.username.as_str()));
    assert_eq!(s.proxy_password.as_deref(), Some(proxy.password.as_str()));
    assert_eq!(proxy.username.len(), 32);
    assert_eq!(s.proxy_hostnames, Some(true));
    assert_eq!(s.proxy_tracker_connections, Some(true));
    assert_eq!(s.proxy_peer_connections, Some(false));
    assert_eq!(s.enable_outgoing_utp, Some(false));
    assert_eq!(s.enable_incoming_utp, Some(false));
}

#[tokio::test]
async fn a_dropped_proxy_stops_listening_and_a_kept_one_does_not() {
    let dropped = TrackerProxy::start(resolver("127.0.0.1:9".parse().unwrap()))
        .await
        .unwrap();
    let at = dropped.addr();
    drop(dropped);
    tokio::task::yield_now().await;
    assert!(TcpStream::connect(at).await.is_err());

    let kept = TrackerProxy::start(resolver("127.0.0.1:9".parse().unwrap()))
        .await
        .unwrap();
    let at = kept.addr();
    kept.keep();
    tokio::task::yield_now().await;
    assert!(TcpStream::connect(at).await.is_ok());
}
