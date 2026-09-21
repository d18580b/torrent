//! Resolving the real client behind a reverse proxy.
//!
//! The daemon does not terminate TLS and is expected to sit behind a proxy, so
//! the socket's peer address is usually the proxy's. Two things need the real
//! client: the login throttle, and the log line that records a failed attempt.
//!
//! Neither could have it before. `axum::serve` was called without
//! `into_make_service_with_connect_info`, so no handler could see even the
//! socket address, and nothing parsed a forwarding header. The login throttle
//! is global as a direct consequence — its own comment says a per-IP bucket
//! "keyed on a spoofable header is worse than none", which was true while
//! every header was spoofable.
//!
//! What makes one not spoofable is knowing who is allowed to set it. A
//! forwarding header is read **only** when the immediate peer is in
//! `[http] trusted_proxies`; from anyone else it is ignored entirely, because
//! anyone else can write whatever they like in it. With no trusted proxies
//! configured — the default — no header is ever read and the behaviour is
//! exactly what it was.

use std::net::IpAddr;
use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::Request;

/// A CIDR block, matched against a peer address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `addr/prefix`, or a bare address as a single host.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_s
            .parse()
            .map_err(|_| format!("{addr_s:?} is not an IP address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_s {
            None => max,
            Some(p) => {
                let n: u8 = p
                    .parse()
                    .map_err(|_| format!("{p:?} is not a prefix length"))?;
                if n > max {
                    return Err(format!("prefix /{n} is too long for {addr}"));
                }
                n
            }
        };
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            // A v4-mapped v6 peer is the same host as its v4 form; a dual-stack
            // listener reports loopback as ::ffff:127.0.0.1, so not unmapping
            // here would silently stop trusting a proxy on the same machine.
            (IpAddr::V4(_), IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

fn prefix_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    a[full] & mask == b[full] & mask
}

/// The set of peers whose forwarding headers are believed.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        entries
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn trusts(&self, peer: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(peer))
    }
}

/// Where a request came from, and over what.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Client {
    pub ip: Option<IpAddr>,
    /// Whether the *original* request was over TLS. `false` when unknown,
    /// which is the safe direction: it only ever withholds the `Secure`
    /// cookie attribute, never adds it wrongly.
    pub secure: bool,
}

/// Resolve the client behind `req`.
///
/// `X-Forwarded-For` is a comma-separated chain appended to by each hop, so
/// the entry the *trusted* proxy added is the last one, not the first. Taking
/// the first — the usual mistake — takes whatever the original client sent,
/// which is attacker-controlled even through an honest proxy.
pub fn resolve<B>(req: &Request<B>, trusted: &TrustedProxies) -> Client {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let Some(peer) = peer else {
        return Client {
            ip: None,
            secure: false,
        };
    };
    if trusted.is_empty() || !trusted.trusts(peer) {
        // Not a proxy we know. Its headers are worth nothing, and its socket
        // address is the truth.
        return Client {
            ip: Some(peer),
            secure: false,
        };
    }

    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };

    let ip = header("x-forwarded-for")
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
        .or(Some(peer));

    let secure = header("x-forwarded-proto").is_some_and(|p| p.eq_ignore_ascii_case("https"))
        || header("forwarded").is_some_and(|f| {
            f.split(';')
                .any(|part| part.trim().eq_ignore_ascii_case("proto=https"))
        });

    Client { ip, secure }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn req(peer: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut r = Request::new(());
        r.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 12345)));
        for (k, v) in headers {
            r.headers_mut().insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        r
    }

    fn trusted(entries: &[&str]) -> TrustedProxies {
        TrustedProxies::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn with_no_trusted_proxies_no_header_is_ever_read() {
        // The default, and the behaviour that existed before any of this.
        let c = resolve(
            &req("203.0.113.9", &[("x-forwarded-for", "10.0.0.1")]),
            &TrustedProxies::default(),
        );
        assert_eq!(c.ip, Some("203.0.113.9".parse().unwrap()));
        assert!(!c.secure);
    }

    #[test]
    fn an_untrusted_peer_cannot_forge_its_address() {
        let c = resolve(
            &req("203.0.113.9", &[("x-forwarded-for", "127.0.0.1")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip,
            Some("203.0.113.9".parse().unwrap()),
            "the socket address is the only thing an untrusted peer can prove",
        );
    }

    #[test]
    fn a_trusted_proxy_is_believed() {
        let c = resolve(
            &req(
                "10.1.2.3",
                &[
                    ("x-forwarded-for", "198.51.100.7"),
                    ("x-forwarded-proto", "https"),
                ],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(c.ip, Some("198.51.100.7".parse().unwrap()));
        assert!(c.secure);
    }

    #[test]
    fn the_last_hop_wins_not_the_first() {
        // Each hop appends, so the entry the trusted proxy added is last. The
        // first is whatever the original client sent, which it chose.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[("x-forwarded-for", "127.0.0.1, 198.51.100.7")],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(c.ip, Some("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn rfc7239_forwarded_also_carries_the_scheme() {
        let c = resolve(
            &req("10.1.2.3", &[("forwarded", "for=198.51.100.7;proto=https")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(c.secure);
    }

    #[test]
    fn a_v4_mapped_peer_still_matches_a_v4_block() {
        // A dual-stack listener reports loopback as ::ffff:127.0.0.1; without
        // unmapping, a proxy on the same machine would silently stop being
        // trusted.
        assert!(Cidr::parse("127.0.0.1")
            .unwrap()
            .contains("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_boundaries() {
        let c = Cidr::parse("10.1.2.0/24").unwrap();
        assert!(c.contains("10.1.2.255".parse().unwrap()));
        assert!(!c.contains("10.1.3.0".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn a_bad_cidr_is_a_config_error() {
        assert!(Cidr::parse("not-an-ip").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn an_unknown_scheme_is_not_secure() {
        let c = resolve(
            &req("10.1.2.3", &[("x-forwarded-proto", "http")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(!c.secure, "only https sets Secure; unknown must not");
    }
}
