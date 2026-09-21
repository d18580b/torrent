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
//! `trusted_proxies` — a top-level key, beside `http_listen`, not a table of
//! its own; from anyone else it is ignored entirely, because anyone else can
//! write whatever they like in it.
//!
//! With no trusted proxies configured — the default — no header is ever read
//! and the socket's peer address is the client. That is not *quite* the
//! behaviour that existed before: the throttle was one shared bucket then,
//! and now it keys on whatever address this returns. Behind a proxy that is
//! the proxy's address for every request, so the effect is the shared bucket
//! again; on a directly exposed daemon it is the real client, so the throttle
//! keys per source IP. That is the better property — one attacker can no
//! longer lock every operator out — and it is the behaviour the daemon has,
//! so it is what is written down here.

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
///
/// A peer listed here can claim to be any client, so it has to be the address
/// the reverse proxy connects from and only that. The one thing required of
/// the proxy itself is that it **strips or overwrites** client-supplied
/// forwarding headers rather than passing them through: a value this daemon
/// believes must be one the proxy wrote. Whether the proxy appends by
/// extending the existing field line or by adding another one does not
/// matter — `last_element` reads both the same way.
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

/// The last element of `name`'s value, across every field line it arrived on.
///
/// Two rules, and they are the same rule at two levels.
///
/// A forwarding header is a chain appended to by each hop, so the entry the
/// *trusted* proxy added is the last one, not the first. Taking the first —
/// the usual mistake — takes whatever the original client sent, which is
/// attacker-controlled even through an honest proxy.
///
/// A proxy may append by adding a whole new field line rather than extending
/// the existing one; HAProxy's `option forwardfor` does exactly that. RFC 9110
/// §5.2-5.3 makes repeated field lines of one name semantically identical to a
/// single comma-joined value, so reading only `HeaderMap::get` — the *first*
/// line — hands the choice straight back to the client, which is the same
/// defect one level up. Joining every line in order and taking the last
/// element makes the proxy's field-line style stop mattering.
fn last_element<'a, B>(req: &'a Request<B>, name: &str) -> Option<&'a str> {
    req.headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .next_back()
}

/// The value of `key` in one RFC 7239 element, e.g. `proto` in
/// `for=203.0.113.9;proto=https`. Quotes are stripped; the name is
/// case-insensitive, as RFC 7239 §4 requires.
fn param<'a>(element: &'a str, key: &str) -> Option<&'a str> {
    element.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| v.trim().trim_matches('"'))
    })
}

/// The IP in an RFC 7239 node identifier: `1.2.3.4`, `1.2.3.4:567`,
/// `[2001:db8::1]:567`, or an obfuscated `_hidden`/`unknown` that is not an
/// address at all and yields `None`.
fn node_addr(node: &str) -> Option<IpAddr> {
    if let Some(rest) = node.strip_prefix('[') {
        return rest.split_once(']')?.0.parse().ok();
    }
    // Tried before splitting on a colon, because a bare IPv6 literal is full
    // of them.
    if let Ok(ip) = node.parse::<IpAddr>() {
        return Some(ip);
    }
    node.split_once(':')?.0.parse().ok()
}

/// Resolve the client behind `req`.
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

    // The last `Forwarded` element, whose parameters are its own; an earlier
    // element is another hop's, and through a proxy that appends rather than
    // strips, the earliest one is the client's.
    let forwarded = last_element(req, "forwarded");

    // RFC 7239 is the standardised form, so a proxy that emits only
    // `Forwarded` has to be able to supply the address too — otherwise its
    // client is silently discarded in favour of the proxy's socket address.
    // `X-Forwarded-For` is the near-universal one, so it decides wherever it
    // is present and `Forwarded` is read only where it is absent.
    //
    // Present-but-unreadable falls back to the socket peer, never to
    // `Forwarded`. The trusted proxy wrote `X-Forwarded-For`; it did not
    // write `Forwarded`, and treating a header it did not write as a second
    // opinion on one it did hands the client address to whoever sent it. A
    // proxy that *overwrites* `X-Forwarded-For` — the near-universal minimum
    // — while forwarding `Forwarded` verbatim is exactly the configuration
    // where that path is the only reachable one, and the address ends up in
    // the throttle key and in `client_ip` on the failed-login line.
    //
    // Both arms go through `node_addr`, so they parse one grammar: the bare
    // address, `host:port`, and a bracketed IPv6 literal are read the same on
    // either. Otherwise the *stricter* parser is the one that falls through
    // to the *less* trustworthy source, which is how the asymmetry bit.
    let ip = match last_element(req, "x-forwarded-for") {
        Some(xff) => node_addr(xff).or(Some(peer)),
        None => forwarded
            .and_then(|f| param(f, "for"))
            .and_then(node_addr)
            .or(Some(peer)),
    };

    let secure = last_element(req, "x-forwarded-proto")
        .is_some_and(|p| p.eq_ignore_ascii_case("https"))
        || forwarded
            .and_then(|f| param(f, "proto"))
            .is_some_and(|p| p.eq_ignore_ascii_case("https"));

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

    /// Like `req`, but appends each pair, so a repeated name becomes a second
    /// field line rather than replacing the first.
    fn req_appending(peer: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut r = Request::new(());
        r.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 12345)));
        for (k, v) in headers {
            r.headers_mut().append(
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
        // The default. No header is read — which is what the daemon did
        // before any of this — but the socket peer now *is* an address, so
        // the throttle keys on it rather than sharing one bucket.
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
    fn a_second_field_line_wins_over_the_first() {
        // HAProxy's `option forwardfor` appends a whole new `X-Forwarded-For:`
        // line instead of extending the one already there. RFC 9110 §5.2-5.3
        // makes the two lines one comma-joined value, so the trusted proxy's
        // entry is still last — reading only the first line would take the
        // value the *client* sent and let it choose its own identity.
        let c = resolve(
            &req_appending(
                "10.1.2.3",
                &[
                    ("x-forwarded-for", "198.51.100.7"),
                    ("x-forwarded-for", "203.0.113.4"),
                ],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip,
            Some("203.0.113.4".parse().unwrap()),
            "the last field line is the trusted proxy's; the first is the client's",
        );
    }

    #[test]
    fn a_second_proto_field_line_wins_over_the_first() {
        let c = resolve(
            &req_appending(
                "10.1.2.3",
                &[
                    ("x-forwarded-proto", "https"),
                    ("x-forwarded-proto", "http"),
                ],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            !c.secure,
            "the proxy's own line said http; the client's earlier https must not win",
        );
    }

    #[test]
    fn a_second_forwarded_field_line_wins_over_the_first() {
        let c = resolve(
            &req_appending(
                "10.1.2.3",
                &[
                    ("forwarded", "proto=https"),
                    ("forwarded", "for=203.0.113.4;proto=http"),
                ],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(!c.secure, "the last field line is the trusted proxy's");
    }

    #[test]
    fn an_earlier_forwarded_element_cannot_supply_the_scheme() {
        // The same last-hop rule as X-Forwarded-For, one level down: a proxy
        // that appends rather than strips leaves the client's element first.
        // Splitting the whole header on `;` accepted that element's
        // `proto=https` over a plain-HTTP request, which issues the session
        // cookie `Secure` and stops the browser returning it over http://.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[("forwarded", "proto=https ;x=1, for=203.0.113.9;proto=http")],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            !c.secure,
            "only the last element's proto counts; an earlier one is another hop's",
        );
    }

    #[test]
    fn rfc7239_forwarded_carries_the_scheme_and_the_client() {
        let c = resolve(
            &req("10.1.2.3", &[("forwarded", "for=198.51.100.7;proto=https")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(c.secure);
        assert_eq!(
            c.ip,
            Some("198.51.100.7".parse().unwrap()),
            "a proxy emitting only the standardised header must still be able \
             to name its client",
        );
    }

    #[test]
    fn a_forwarded_node_may_carry_a_port_or_be_obfuscated() {
        let case = |v: &str| {
            resolve(
                &req("10.1.2.3", &[("forwarded", v)]),
                &trusted(&["10.0.0.0/8"]),
            )
            .ip
        };
        assert_eq!(
            case("for=\"198.51.100.7:4711\""),
            Some("198.51.100.7".parse().unwrap()),
        );
        assert_eq!(
            case("for=\"[2001:db8::1]:4711\""),
            Some("2001:db8::1".parse().unwrap()),
        );
        assert_eq!(
            case("for=2001:db8::1"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            case("for=_hidden"),
            Some("10.1.2.3".parse().unwrap()),
            "an obfuscated node identifies nobody, so the peer stands",
        );
        assert_eq!(
            case("for=unknown"),
            Some("10.1.2.3".parse().unwrap()),
            "so does an explicitly unknown one",
        );
    }

    #[test]
    fn an_unreadable_x_forwarded_for_falls_back_to_the_peer_not_to_forwarded() {
        // The trusted proxy wrote `X-Forwarded-For` and did not write
        // `Forwarded`. Reading `Forwarded` when the header the proxy *did*
        // write fails to parse hands the client address to whoever sent it —
        // and a proxy that overwrites `X-Forwarded-For` while forwarding
        // `Forwarded` verbatim is the near-universal minimum, so that path is
        // the only one an attacker needs. The address reached here is the
        // throttle key and the `client_ip` on the failed-login line.
        let attacker = ("forwarded", "for=203.0.113.99");

        // A port-suffixed value is not unreadable. Both arms parse one
        // grammar, so the proxy's own value is read rather than discarded.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[("x-forwarded-for", "198.51.100.7:52014"), attacker],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip,
            Some("198.51.100.7".parse().unwrap()),
            "the stricter parser must not be the one that falls through: \
             host:port is an address on this arm too",
        );

        // Unreadable by any grammar: the socket peer stands, and the header
        // the proxy never wrote is not consulted at all.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[("x-forwarded-for", "not-an-address"), attacker],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip,
            Some("10.1.2.3".parse().unwrap()),
            "an unreadable X-Forwarded-For stands the peer up; `Forwarded` is \
             not a second opinion on a header the proxy did write",
        );
    }

    #[test]
    fn an_absent_x_forwarded_for_still_reads_forwarded() {
        // Only the *unreadable* case changed. Where the proxy sent no
        // `X-Forwarded-For` at all — the RFC 7239-only deployment — its
        // `for=` still names the client, and the scheme arm is independent
        // of the address arm.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[
                    ("x-forwarded-proto", "https"),
                    ("forwarded", "for=198.51.100.7"),
                ],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip,
            Some("198.51.100.7".parse().unwrap()),
            "a proxy emitting only the standardised header must still be able \
             to name its client",
        );
        assert!(c.secure);
    }

    #[test]
    fn x_forwarded_for_is_preferred_over_forwarded() {
        // Both name a client; the near-universal header is the one to trust
        // first, and the choice has to be fixed rather than incidental.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[
                    ("x-forwarded-for", "198.51.100.7"),
                    ("forwarded", "for=203.0.113.4"),
                ],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(c.ip, Some("198.51.100.7".parse().unwrap()));
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
