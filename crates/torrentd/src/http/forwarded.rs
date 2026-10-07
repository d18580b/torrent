//! Resolving the real client behind a reverse proxy.
//!
//! The daemon sits behind a proxy that terminates TLS, so the socket's peer
//! is usually the proxy. The login throttle and the `client_ip` log field
//! need the real client, and the `via_https` log field needs to know whether
//! it connected over TLS.
//!
//! A forwarding header is read **only** when the immediate peer is in
//! `trusted_proxies`; from anyone else it is ignored, because anyone else can
//! write whatever they like in it. With no trusted proxies — the default — no
//! header is ever read and the socket peer is the client.

use std::net::IpAddr;
use std::net::SocketAddr;

use kynos::http::HeaderMap;

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

    /// The parsed prefix length: `/0`, `/00` and `/+0` are all 0.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is inside this block.
    ///
    /// **Both sides** are folded to their v4 form first: a v4-mapped v6
    /// address is the same host as its v4 form, whether it is the peer a
    /// dual-stack listener reports or the entry an operator copied from a log.
    /// A mapped entry's prefix loses the mapped `/96`; one shorter than 96
    /// spans every v4 address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (net, prefix) = self.effective();
        match (net, unmap(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => prefix_match(&net.octets(), &ip.octets(), prefix),
            (IpAddr::V6(net), IpAddr::V6(ip)) => prefix_match(&net.octets(), &ip.octets(), prefix),
            // One side is a genuine v6 address and the other a v4 one. They
            // are different hosts in different families; neither fold above
            // can bring them together.
            _ => false,
        }
    }

    /// The block [`contains`](Self::contains) actually matches against: a
    /// v4-mapped entry folded to its v4 form with the mapped `/96` taken out
    /// of its prefix, anything else as written.
    fn effective(&self) -> (IpAddr, u8) {
        match self.addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => (IpAddr::V4(v4), self.prefix.saturating_sub(96)),
                None => (self.addr, self.prefix),
            },
            IpAddr::V4(_) => (self.addr, self.prefix),
        }
    }
}

/// The **effective** block, folded as [`Cidr::contains`] folds it and with
/// the host bits cleared: `::ffff:0:0/96` prints as `0.0.0.0/0`, which is what
/// the startup log has to show.
impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (net, prefix) = self.effective();
        let net = match net {
            IpAddr::V4(v4) => {
                let mut o = v4.octets();
                mask(&mut o, prefix);
                IpAddr::from(o)
            }
            IpAddr::V6(v6) => {
                let mut o = v6.octets();
                mask(&mut o, prefix);
                IpAddr::from(o)
            }
        };
        write!(f, "{net}/{prefix}")
    }
}

/// Clear every bit of `octets` past the first `prefix`.
fn mask(octets: &mut [u8], prefix: u8) {
    for (i, b) in octets.iter_mut().enumerate() {
        let kept = (prefix as usize).saturating_sub(i * 8).min(8);
        *b &= if kept == 0 { 0 } else { 0xffu8 << (8 - kept) };
    }
}

/// A v4-mapped v6 address as its v4 form; anything else unchanged. Every
/// address `resolve` returns goes through this, so one host is one throttle
/// key and one `client_ip`.
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
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
/// the reverse proxy connects from, and the proxy must strip or overwrite all
/// three client-supplied headers: `X-Forwarded-For`, `X-Forwarded-Proto` and
/// RFC 7239 `Forwarded` (`deploy/Caddyfile` shows how).
///
/// **One hop.** `resolve` takes the element the immediate peer contributed;
/// it does not walk past hops that are themselves listed. In a two-hop chain
/// the inner proxy's address is the client.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// Parse every entry, refusing one with a `/0` prefix: it trusts every
    /// peer there is, so every forwarding header becomes client-controlled.
    /// Decided on the parsed prefix, so `/00` and `/+0` are refused too.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        entries
            .iter()
            .map(|entry| {
                let cidr = Cidr::parse(entry)?;
                if cidr.prefix() == 0 {
                    return Err(format!(
                        "{entry:?} trusts every peer there is. Anything listed here can claim \
                         to be any client, so a /0 prefix makes every forwarding header \
                         client-controlled: the login throttle keys on a value the caller \
                         picks, and the client_ip on the failed-login line is whatever the \
                         caller wrote. List the address your reverse proxy connects from, and \
                         only that."
                    ));
                }
                Ok(cidr)
            })
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

/// Every block in its effective form (see [`Cidr`]'s `Display`), joined
/// with `", "`.
impl std::fmt::Display for TrustedProxies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, c) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// Where a request came from, and over what.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Client {
    pub ip: Option<IpAddr>,
    /// Whether the *original* request was over TLS: `https` anywhere in a
    /// readable chain, under either header name. It feeds the `via_https` log
    /// field and nothing else.
    ///
    /// Any element, not the last, because `https, http` is a TLS edge in front
    /// of a plain inner proxy. The cost is that a client's own forged `https`
    /// misreports its own login line where a proxy appends rather than
    /// overwrites; the two cases are the same bytes. `false` when unknown.
    pub secure: bool,
}

/// What reading a forwarding header yielded. *Was the name there at all*
/// decides which source `resolve` consults; *did it carry a readable element*
/// decides what that source says. A header the proxy wrote with nothing
/// readable and a header it never wrote have opposite safe answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeaderRead<'a> {
    /// Whether any field line carried this name, readable or not.
    present: bool,
    /// The **final** element across every field line — positionally, not the
    /// last one that happens to be readable — where it carries something.
    last: Option<&'a str>,
}

/// The last element of `name`'s value across every field line (RFC 9110
/// makes repeated lines one comma-joined value), and whether the name was
/// present at all.
///
/// The trusted proxy appends, so its element is the last; earlier ones are
/// the client's. *Last* is positional: an empty or non-UTF-8 final element
/// makes the header unreadable rather than licensing a read further left,
/// where the client's forged entries are.
fn last_element<'a>(headers: &'a HeaderMap, name: &str) -> HeaderRead<'a> {
    let values = headers.get_all(name);
    HeaderRead {
        present: values.iter().next().is_some(),
        last: values
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| split_elements(name, v, ',').last())
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    }
}

/// Whether `name`'s grammar makes a `"` a quoted-string delimiter. Only RFC
/// 7239 `Forwarded` does; in the `X-` headers a `"` is data, and honouring it
/// would let one planted quote swallow the proxy's own appended element.
fn has_quoted_strings(name: &str) -> bool {
    name.eq_ignore_ascii_case("forwarded")
}

/// Whether every `quoted-string` opened in `s` is closed. An unterminated
/// quote is data: honouring it would let a client's open quote swallow the
/// proxy's appended element.
fn quotes_terminated(s: &str) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            escaped = false;
        } else if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        }
    }
    !quoted
}

/// Split `s` on `sep`, ignoring separators inside a quoted string where the
/// grammar has them, so a quoted `host="a,for=6.6.6.6"` the proxy copied from
/// the client cannot reframe the element.
struct SplitList<'a> {
    rest: Option<&'a str>,
    sep: char,
    /// Whether a `"` opens a quoted string, or is ordinary data.
    quoted_strings: bool,
}

impl<'a> Iterator for SplitList<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let s = self.rest?;
        let mut quoted = false;
        let mut escaped = false;
        for (i, c) in s.char_indices() {
            if !self.quoted_strings {
                if c == self.sep {
                    self.rest = Some(&s[i + c.len_utf8()..]);
                    return Some(&s[..i]);
                }
            } else if escaped {
                escaped = false;
            } else if quoted && c == '\\' {
                // `quoted-pair`: the next character is data whatever it is,
                // including a closing quote.
                escaped = true;
            } else if c == '"' {
                quoted = !quoted;
            } else if c == self.sep && !quoted {
                self.rest = Some(&s[i + c.len_utf8()..]);
                return Some(&s[..i]);
            }
        }
        self.rest = None;
        Some(s)
    }
}

/// Split `name`'s value on `sep` under `name`'s own grammar: quote-aware for
/// `Forwarded` whose quoted strings are closed, a bare split otherwise.
fn split_elements<'a>(name: &str, s: &'a str, sep: char) -> SplitList<'a> {
    SplitList {
        rest: Some(s),
        sep,
        quoted_strings: has_quoted_strings(name) && quotes_terminated(s),
    }
}

/// Remove RFC 7239 §4 `quoted-string` quoting, `quoted-pair` escapes
/// included, from a parameter value; anything else is returned as it arrived.
fn unquote(v: &str) -> std::borrow::Cow<'_, str> {
    let Some(inner) = v.strip_prefix('"').and_then(|r| r.strip_suffix('"')) else {
        return std::borrow::Cow::Borrowed(v);
    };
    if !inner.contains('\\') {
        return std::borrow::Cow::Borrowed(inner);
    }
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Every element of `name`'s value, across every field line, in order: for
/// "did *any* hop say this". A non-UTF-8 line contributes nothing, so callers
/// ask [`last_element`] whether the header is readable first.
fn elements<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(move |v| split_elements(name, v, ','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// The value of `key` in one RFC 7239 element, e.g. `proto` in
/// `for=203.0.113.9;proto=https`: unquoted, and matched case-insensitively.
/// A name is a token, so the first `=` always separates it from the value.
fn param<'a>(element: &'a str, key: &str) -> Option<std::borrow::Cow<'a, str>> {
    split_elements("forwarded", element, ';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| unquote(v.trim()))
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

/// Resolve the client behind a request from `peer` carrying `headers`.
pub fn resolve(peer: Option<SocketAddr>, headers: &HeaderMap, trusted: &TrustedProxies) -> Client {
    // Unmapped before the trust test and either early return, so a dual-stack
    // listener's `::ffff:a.b.c.d` is one host on every path.
    let peer = peer.map(|addr| unmap(addr.ip()));

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

    let forwarded = last_element(headers, "forwarded");

    // `X-Forwarded-For` decides wherever it is present; `Forwarded` only where
    // it is absent. Present but unreadable — empty, unparseable, not UTF-8 —
    // falls back to the socket peer, never to `Forwarded`: the proxy wrote
    // the one and may be passing the other through from the client. Both
    // arms parse addresses with `node_addr`.
    let xff = last_element(headers, "x-forwarded-for");
    let ip = if xff.present {
        xff.last.and_then(node_addr).or(Some(peer))
    } else {
        forwarded
            .last
            .and_then(|f| param(f, "for"))
            .and_then(|node| node_addr(&node))
            .or(Some(peer))
    };

    // The same precedence and presence rule for the scheme; `last` decides
    // whether the header is readable, and any `https` in a readable chain
    // answers (see `Client::secure`).
    let xfp = last_element(headers, "x-forwarded-proto");
    let secure = if xfp.present {
        xfp.last.is_some()
            && elements(headers, "x-forwarded-proto").any(|p| p.eq_ignore_ascii_case("https"))
    } else {
        forwarded.last.is_some()
            && elements(headers, "forwarded")
                .filter_map(|e| param(e, "proto"))
                .any(|p| p.eq_ignore_ascii_case("https"))
    };

    // A header-supplied address can arrive mapped too.
    Client {
        ip: ip.map(unmap),
        secure,
    }
}

#[cfg(test)]
mod tests {
    use kynos::http::HeaderName;
    use kynos::http::HeaderValue;

    use super::*;

    /// A request as `resolve` sees it: the socket peer and the head.
    struct Request {
        peer: SocketAddr,
        headers: HeaderMap,
    }

    impl Request {
        fn new(peer: &str) -> Self {
            Self {
                peer: SocketAddr::new(peer.parse().unwrap(), 12345),
                headers: HeaderMap::new(),
            }
        }

        fn headers_mut(&mut self) -> &mut HeaderMap {
            &mut self.headers
        }
    }

    /// `super::resolve`, over the test's request shape.
    fn resolve(r: &Request, trusted: &TrustedProxies) -> Client {
        super::resolve(Some(r.peer), &r.headers, trusted)
    }

    fn req(peer: &str, headers: &[(&str, &str)]) -> Request {
        let mut r = Request::new(peer);
        for (k, v) in headers {
            r.headers_mut().insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        r
    }

    /// Like `req`, but appends each pair, so a repeated name becomes a second
    /// field line rather than replacing the first.
    fn req_appending(peer: &str, headers: &[(&str, &str)]) -> Request {
        let mut r = Request::new(peer);
        for (k, v) in headers {
            r.headers_mut().append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        r
    }

    /// A request whose last field line for `name` is raw bytes that are not
    /// UTF-8, preceded by whatever `before` lines the case needs.
    fn req_with_raw_last(peer: &str, name: &str, before: &[&str], raw: &[u8]) -> Request {
        let mut r = Request::new(peer);
        let header = HeaderName::from_bytes(name.as_bytes()).unwrap();
        for v in before {
            r.headers_mut()
                .append(header.clone(), HeaderValue::from_str(v).unwrap());
        }
        r.headers_mut()
            .append(header, HeaderValue::from_bytes(raw).unwrap());
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
    fn a_second_proto_field_line_is_read_at_all() {
        // Repeated field lines are one comma-joined value (RFC 9110
        // §5.2-5.3), so both lines have to be read. Reading only
        // `HeaderMap::get` — the first line — answers `false` here.
        //
        // This test previously asserted the opposite pairing: `https` then
        // `http` across two lines meant *not* secure, on the last-hop rule
        // the address uses. The scheme does not take its answer from the same
        // end of the chain — see `Client::secure` — so that expectation was
        // the defect, not the property. `a_tls_edge_in_front_of_a_plain_inner_proxy_is_still_secure`
        // pins the corrected direction; this pins that the second line is
        // read.
        let c = resolve(
            &req_appending(
                "10.1.2.3",
                &[
                    ("x-forwarded-proto", "http"),
                    ("x-forwarded-proto", "https"),
                ],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            c.secure,
            "the second field line names a TLS hop and must be read",
        );
    }

    #[test]
    fn a_second_forwarded_field_line_wins_over_the_first() {
        // The address takes the last field line — the trusted proxy's — and
        // the scheme reads every element of the joined chain, which is the
        // same pair of rules `X-Forwarded-For` and `X-Forwarded-Proto` follow.
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
        assert_eq!(
            c.ip,
            Some("203.0.113.4".parse().unwrap()),
            "the last field line is the trusted proxy's, and it names the client",
        );
        assert!(
            c.secure,
            "an earlier line naming a TLS hop is an outer hop, not a stale \
             claim the inner one corrects",
        );
    }

    #[test]
    fn an_earlier_forwarded_element_supplies_the_scheme_too() {
        // Inverted deliberately, and the property it used to pin — "a
        // client's earlier element cannot supply the scheme" — is given up
        // rather than moved; `Client::secure` records which property and why.
        //
        // `Forwarded` now answers the scheme the way `X-Forwarded-Proto`
        // does: `https` anywhere in a readable chain. The case that forced it
        // is the ordinary RFC 7239 one — a TLS edge that names the scheme and
        // an inner proxy that appends only `for=` because it terminated no
        // TLS — where the last element has no `proto=` at all and the
        // last-element rule reported a deployment that really was
        // TLS-fronted as plain HTTP.
        //
        // What is conceded is the other reading of the same bytes: a client
        // that plants `proto=https` in front of an appending proxy now has
        // its **own** login logged as over TLS, and nobody else's.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[("forwarded", "proto=https ;x=1, for=203.0.113.9;proto=http")],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            c.secure,
            "an element saying https is a hop that terminated TLS, whichever \
             end of the chain it sits at",
        );
        assert_eq!(
            c.ip,
            Some("203.0.113.9".parse().unwrap()),
            "and the address still comes from the last element only",
        );

        // The TLS edge whose inner hop appends no `proto=` at all. This is
        // the shape the last-element rule could not answer: it read the final
        // element, found no scheme, and said `false`.
        let c = resolve(
            &req("10.1.2.3", &[("forwarded", "proto=https, for=1.2.3.4")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            c.secure,
            "an inner proxy that terminated no TLS appends no proto=; that is \
             not the edge withdrawing its own https",
        );

        // The control: a chain with no TLS hop anywhere is not secure.
        let c = resolve(
            &req("10.1.2.3", &[("forwarded", "proto=http, proto=http")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(!c.secure, "no element names a TLS hop");

        // And readability still gates the chain, exactly as it does for
        // `X-Forwarded-Proto`: a final element the trusted proxy wrote and
        // that carries nothing makes the header unreadable, and unreadable is
        // `false` however much `https` sits to its left.
        let c = resolve(
            &req("10.1.2.3", &[("forwarded", "proto=https,")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            !c.secure,
            "the proxy's own final element carries nothing, so the header is \
             unreadable",
        );
    }

    #[test]
    fn the_scheme_rule_is_the_same_under_either_header_name() {
        // The property: a deployment gets the same answer whichever name its
        // proxies speak. Before this, the same two-hop TLS chain read as TLS
        // on `X-Forwarded-Proto` and as plain HTTP on `Forwarded`.
        let case = |headers: &[(&str, &str)]| {
            resolve(&req("10.1.2.3", headers), &trusted(&["10.0.0.0/8"])).secure
        };

        for (xfp, fwd) in [
            ("https, http", "proto=https, proto=http"),
            ("https", "proto=https"),
            ("http, https", "proto=http, proto=https"),
            ("http", "proto=http"),
            ("http, http", "proto=http, proto=http"),
            ("https,", "proto=https,"),
        ] {
            assert_eq!(
                case(&[("x-forwarded-proto", xfp)]),
                case(&[("forwarded", fwd)]),
                "X-Forwarded-Proto: {xfp:?} and Forwarded: {fwd:?} are the \
                 same chain and must give the same answer",
            );
        }
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
    fn a_quoted_forwarded_parameter_cannot_reframe_the_grammar() {
        // The property: RFC 7239 §4 separators inside a quoted string are
        // data, not structure. The parameter a proxy routinely quotes is
        // `host=`, because the client's `Host` may hold characters a token
        // may not — so a naive split hands the client the element boundary
        // and the parameter list, and the failure direction is toward a
        // client-controlled address and a client-controlled scheme.
        let case = |v: &str| {
            resolve(
                &req("10.1.2.3", &[("forwarded", v)]),
                &trusted(&["10.0.0.0/8"]),
            )
        };
        let proxy: Option<IpAddr> = Some("198.51.100.9".parse().unwrap());

        // A comma inside `host=` is not an element boundary.
        let c = case(r#"for=198.51.100.9;host="a,for=6.6.6.6""#);
        assert_eq!(
            c.ip, proxy,
            "the quoted comma does not start a second element, so the \
             proxy's own for= still decides",
        );

        // A semicolon inside `host=` is not a parameter boundary.
        let c = case(r#"host="a;for=6.6.6.6";for=198.51.100.9"#);
        assert_eq!(
            c.ip, proxy,
            "the quoted semicolon does not introduce a second parameter",
        );

        // The same, on the scheme: a quoted `proto=` is not a `proto=`.
        let c = case(r#"for=198.51.100.9;host="a,proto=https""#);
        assert!(
            !c.secure,
            "a quoted proto= is part of host=, and must not set secure (via_https)",
        );
        assert_eq!(
            c.ip, proxy,
            "and the element's own for= survives the quoted comma",
        );
        let c = case(r#"host="x;proto=https";proto=http"#);
        assert!(
            !c.secure,
            "the element's own proto=http decides, not the quoted text",
        );

        // `quoted-pair`: the escaped quote is data, so the string does not
        // end there and the value keeps the quote.
        assert_eq!(
            param(r#"host="a\"b";for=198.51.100.9"#, "host").as_deref(),
            Some(r#"a"b"#),
            "a backslash escape is unwrapped rather than left in the value",
        );
        assert_eq!(
            param(r#"host="a\"b";for=198.51.100.9"#, "for").as_deref(),
            Some("198.51.100.9"),
            "and the escaped quote does not swallow the rest of the element",
        );

        // Unquoting is not trimming quote characters off the ends.
        assert_eq!(param(r#"host="""#, "host").as_deref(), Some(""));
        assert_eq!(param("host=plain", "host").as_deref(), Some("plain"));
    }

    #[test]
    fn one_unbalanced_quote_cannot_swallow_the_proxys_own_element() {
        // The property: a `"` may re-frame a value only where the value's own
        // grammar says it is structure, and even there only where the quoted
        // string it opens is closed. Every value below is what the daemon
        // sees *after* an appending proxy has added its own contribution to
        // the client's text — `$proxy_add_x_forwarded_for` is raw
        // concatenation, so the client owns everything left of the comma.
        //
        // Applying RFC 7239 §4's quoting to all three names put the trusted
        // proxy's own appended element inside the client's quoted segment, so
        // the positional last element became the client's text. Demonstrated
        // end to end: eight failed logins each planting one quote returned
        // `401` eight times and were never throttled, while eight honest ones
        // locked out at the sixth and were still locked afterwards, and the
        // security log carried eight addresses the client chose.
        let proxy: Option<IpAddr> = Some("203.0.113.1".parse().unwrap());
        let case = |name: &str, v: &str| {
            resolve(&req("10.1.2.3", &[(name, v)]), &trusted(&["10.0.0.0/8"])).ip
        };

        // `X-Forwarded-For` has no quoted-string grammar, so a `"` is data.
        for v in [
            r#"[6.6.6.6]", 203.0.113.1"#,
            r#"6.6.6.6:80", 203.0.113.1"#,
            r#"[6.6.6.6]:80", 203.0.113.1"#,
            r#""6.6.6.6, 203.0.113.1"#,
            r#"6.6.6.6";q=", 203.0.113.1"#,
        ] {
            assert_eq!(
                case("x-forwarded-for", v),
                proxy,
                "X-Forwarded-For: {v:?} — a quote is ordinary data here, so \
                 the proxy's own trailing element is still the last one",
            );
        }

        // `Forwarded` does have the grammar, but an *unterminated* quoted
        // string is not a quoted string: RFC 7239 §4 requires the closing
        // DQUOTE, and honouring the opening one lets the client's element
        // swallow the proxy's.
        for v in [
            r#"for=6.6.6.6:80", for=203.0.113.1"#,
            r#"host="a, for=203.0.113.1"#,
            r#"for=6.6.6.6;host="a;x, for=203.0.113.1"#,
        ] {
            assert_eq!(
                case("forwarded", v),
                proxy,
                "Forwarded: {v:?} leaves a quote open, so it is not a quoted \
                 string and the proxy's own element still decides",
            );
        }

        // The control that must keep working: a *closed* quoted string on
        // `Forwarded` is still structure, which is the whole of the repair
        // that introduced this hole.
        assert_eq!(
            case("forwarded", r#"for=203.0.113.1;host="a,for=6.6.6.6""#),
            proxy,
            "a closed quoted string still hides its comma",
        );

        // And on the scheme, where the same byte runs the other way: merging
        // a TLS edge's own `https` into one unmatchable element reports a
        // deployment that really is TLS-fronted as plain HTTP.
        let secure = |v: &str| {
            resolve(
                &req("10.1.2.3", &[("x-forwarded-proto", v)]),
                &trusted(&["10.0.0.0/8"]),
            )
            .secure
        };
        assert!(
            secure(r#"", https"#),
            "the client's lone quote is data; the TLS edge's own https still \
             names a hop that terminated TLS",
        );
        assert!(
            !secure(r#"", http"#),
            "and the control still names no TLS hop",
        );

        // The per-name half of the rule, asserted where it lives. Once an
        // unterminated quote is data, no value an *appending* proxy can
        // produce separates the two splitters at `resolve`: for the final
        // comma to fall inside a terminated quoted string there must be a
        // quote to the right of it, and everything to the right of it is the
        // proxy's own contribution, which has none. So the rule that a
        // grammar belongs only to the header that defines it is pinned at the
        // splitter rather than through an outcome it cannot change.
        assert_eq!(
            split_elements("x-forwarded-for", r#""a,b", 1.2.3.4"#, ',').collect::<Vec<_>>(),
            vec![r#""a"#, r#"b""#, " 1.2.3.4"],
            "X-Forwarded-For has no quoted-string production, so every comma \
             is a separator",
        );
        assert_eq!(
            split_elements("x-forwarded-proto", r#""https,http", https"#, ',').collect::<Vec<_>>(),
            vec![r#""https"#, r#"http""#, " https"],
        );
        assert_eq!(
            split_elements("forwarded", r#"host="a,b", for=1.2.3.4"#, ',').collect::<Vec<_>>(),
            vec![r#"host="a,b""#, " for=1.2.3.4"],
            "Forwarded does have one, and a closed quoted string still hides \
             its comma",
        );
    }

    #[test]
    fn a_bracketed_ipv4_literal_is_read_as_an_address() {
        // Half of the primitive the quote spelling above needs: `node_addr`
        // takes everything between the brackets, and `[6.6.6.6]` parses as an
        // address even though the brackets exist for IPv6 literals. That is
        // what let `[6.6.6.6]", 203.0.113.1` — one element, once the quote
        // was honoured — yield `6.6.6.6` rather than nothing.
        //
        // It is pinned rather than changed: rejecting it would not have
        // closed the hole (`6.6.6.6:80"` needs no brackets and resolved the
        // same way), and a bracketed literal is how RFC 7239 §6 spells a node
        // whether or not the address inside is v6.
        assert_eq!(
            node_addr("[6.6.6.6]"),
            Some("6.6.6.6".parse().unwrap()),
            "the brackets are the node syntax, not a family declaration",
        );
        assert_eq!(node_addr("[6.6.6.6]:80"), Some("6.6.6.6".parse().unwrap()),);
        assert_eq!(
            node_addr("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().unwrap()),
        );
        assert_eq!(node_addr("[not-an-ip]"), None);
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
    fn a_present_but_empty_x_forwarded_for_stands_the_peer_up_too() {
        // "Unreadable" is decided on the header's *presence*, not on whether
        // an element survived parsing. Emptiness, separators-only and
        // non-UTF-8 bytes are all values the trusted proxy wrote, so each
        // stands the socket peer up exactly as an unparseable one does.
        //
        // Deciding on the surviving element instead splits the unreadable
        // case in two and sends half of it to `Forwarded` — the one header
        // the proxy did not write — which hands the client address, the
        // throttle key and the `client_ip` on the failed-login line to
        // whoever sent it.
        let attacker = ("forwarded", "for=203.0.113.98");
        let peer = Some("10.1.2.3".parse().unwrap());

        for empty in ["", "  ", ",", " ,  , "] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-for", empty), attacker]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert_eq!(
                c.ip, peer,
                "X-Forwarded-For: {empty:?} is present and carries nothing \
                 readable, so the peer stands rather than the client's \
                 `Forwarded`",
            );
        }

        // Non-UTF-8 is the same case. `to_str` fails, no element survives,
        // and the name was still present.
        let mut r = Request::new("10.1.2.3");
        r.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        r.headers_mut()
            .insert("forwarded", HeaderValue::from_static("for=203.0.113.98"));
        assert_eq!(
            resolve(&r, &trusted(&["10.0.0.0/8"])).ip,
            peer,
            "a non-UTF-8 X-Forwarded-For is unreadable, not absent",
        );
    }

    #[test]
    fn an_unreadable_last_x_forwarded_for_element_stands_the_peer_up() {
        // The property: emptiness is decided on the **final** element, not on
        // whichever element happens to be readable. The case above makes the
        // *whole* header yield nothing, which is why it never caught this.
        //
        // A trusted proxy that appends rather than overwrites can contribute
        // an element that evaluates empty — `option forwardfor` style
        // appending over an inner header that was not there. Searching
        // leftward for something readable then returns the element before it,
        // and the elements before the trusted proxy's are the client's. The
        // client's forged value becomes the resolved address: the throttle
        // key, and the `client_ip` on the failed-login line.
        let peer = Some("10.1.2.3".parse().unwrap());
        let forged = "6.6.6.6";

        for value in ["6.6.6.6,", "6.6.6.6, ", "6.6.6.6, ,", "6.6.6.6,,"] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-for", value)]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert_eq!(
                c.ip, peer,
                "X-Forwarded-For: {value:?} ends in an element the proxy \
                 wrote and that carries nothing, so the peer stands — \
                 {forged} is the client's own entry",
            );
        }

        // The same shape across field lines: the trusted proxy appended a
        // whole new line, and its line is the empty one.
        let c = resolve(
            &req_appending(
                "10.1.2.3",
                &[("x-forwarded-for", "6.6.6.6"), ("x-forwarded-for", "")],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip, peer,
            "the last field line is the trusted proxy's and it is empty, so \
             the client's earlier line is not the answer",
        );

        // And where the trusted proxy's own field line is not UTF-8. `to_str`
        // failing on the final line is the final element being unreadable,
        // not a reason to read the line before it.
        let c = resolve(
            &req_with_raw_last("10.1.2.3", "x-forwarded-for", &["6.6.6.6"], &[0xff, 0xfe]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip, peer,
            "a non-UTF-8 last field line is unreadable, and the readable line \
             before it is the client's",
        );

        // The control, which must keep working: two readable elements still
        // resolve to the last one.
        let c = resolve(
            &req("10.1.2.3", &[("x-forwarded-for", "6.6.6.6, 5.5.5.5")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip,
            Some("5.5.5.5".parse().unwrap()),
            "a readable final element is still the answer",
        );
    }

    #[test]
    fn a_v4_mapped_client_address_resolves_to_its_v4_form() {
        // The property: one host is one spelling. `Cidr::contains` unmaps a
        // v4-mapped peer before matching it, on the grounds that it is the
        // same host — so the *resolved* address has to be unmapped too, or
        // the two halves of the module disagree and one host becomes two
        // throttle buckets and two `client_ip` values in the security log.
        let v4: IpAddr = "198.51.100.88".parse().unwrap();

        for spelling in ["::ffff:198.51.100.88", "::ffff:c633:6458"] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-for", spelling)]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert_eq!(
                c.ip,
                Some(v4),
                "{spelling} is the same host as its v4 form, and has to be \
                 the same key",
            );
        }

        // Through `Forwarded` as well, which is a second route to the same
        // field.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[("forwarded", "for=\"[::ffff:198.51.100.88]\"")],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(c.ip, Some(v4));

        // And for the socket peer, which is what a dual-stack listener
        // reports for a v4 client.
        let c = resolve(&req("::ffff:10.1.2.3", &[]), &trusted(&["10.0.0.0/8"]));
        assert_eq!(
            c.ip,
            Some("10.1.2.3".parse::<IpAddr>().unwrap()),
            "a dual-stack listener's v4-mapped peer is one host too",
        );

        // A genuine v6 address is not touched.
        let c = resolve(
            &req("10.1.2.3", &[("x-forwarded-for", "2001:db8::1")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(c.ip, Some("2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn an_untrusted_v4_mapped_peer_resolves_to_its_v4_form_too() {
        // The property: one host is one spelling on **every** path out of
        // `resolve`, not only the one that reaches the fold at the bottom.
        // The untrusted branch returns before that fold, so on a dual-stack
        // `[::]` bind a client arriving directly kept its `::ffff:` spelling
        // while the same host named through the trusted proxy was folded —
        // two `client_ip` values and two `HashMap<IpAddr, _>` keys for one
        // host, in one daemon, under one configuration. Demonstrated: ten
        // failures before both buckets locked, where five against one
        // spelling locks, with the client choosing which route it takes.
        let v4: IpAddr = "198.51.100.9".parse().unwrap();

        // Untrusted: the header is ignored and the socket peer stands up —
        // in its v4 form.
        let c = resolve(
            &req("::ffff:198.51.100.9", &[("x-forwarded-for", "6.6.6.6")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(
            c.ip,
            Some(v4),
            "an untrusted v4-mapped peer is the same host as its v4 form, and \
             has to be the same throttle key",
        );

        // With no trust list at all — the default — the same.
        let c = resolve(
            &req("::ffff:198.51.100.9", &[]),
            &TrustedProxies::parse(&[]).unwrap(),
        );
        assert_eq!(c.ip, Some(v4));

        // And the trusted route names the same host by the same spelling, so
        // the two routes agree rather than merely each being consistent.
        let c = resolve(
            &req("10.1.2.3", &[("x-forwarded-for", "::ffff:198.51.100.9")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(c.ip, Some(v4));
    }

    #[test]
    fn a_tls_edge_in_front_of_a_plain_inner_proxy_is_still_secure() {
        // The property: `secure` is the **outermost** hop's answer. TLS is
        // terminated at the edge, so a chain written by a TLS edge in front
        // of a plain-HTTP inner proxy — each appending — reads `https, http`,
        // and the original request there was over TLS.
        //
        // Taking the last element instead returns `false` on a deployment
        // that really is TLS-fronted.
        for value in ["https, http", "https,http", "https, http, http"] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-proto", value)]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert!(
                c.secure,
                "X-Forwarded-Proto: {value:?} begins at a TLS edge, so the \
                 original request was over TLS",
            );
        }

        // The same across field lines, which is how an appending proxy that
        // adds its own line writes it.
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
            c.secure,
            "a second field line saying http is an inner hop, not a \
             correction of the edge",
        );

        // The control: a chain with no TLS hop anywhere is not secure.
        for value in ["http", "http, http"] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-proto", value)]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert!(!c.secure, "X-Forwarded-Proto: {value:?} names no TLS hop");
        }
    }

    #[test]
    fn an_unreadable_last_x_forwarded_proto_element_withholds_secure() {
        // The scheme arm of the same rule. `X-Forwarded-Proto` is present, so
        // it decides; its final element is the trusted proxy's, and where
        // that element carries nothing the header is unreadable and `secure`
        // is `false`. Reading leftward instead lets a client's own earlier
        // `https` report a plain-HTTP request as TLS.
        for value in ["https,", "https, ", "https, ,", "https,,"] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-proto", value)]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert!(
                !c.secure,
                "X-Forwarded-Proto: {value:?} ends in an element that carries \
                 nothing, so the header is unreadable and `secure` is \
                 false",
            );
        }

        let c = resolve(
            &req_appending(
                "10.1.2.3",
                &[("x-forwarded-proto", "https"), ("x-forwarded-proto", "")],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            !c.secure,
            "the trusted proxy's own field line is the empty one; the \
             client's earlier https is not the answer",
        );

        let c = resolve(
            &req_with_raw_last("10.1.2.3", "x-forwarded-proto", &["https"], &[0xff, 0xfe]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            !c.secure,
            "a non-UTF-8 last field line is unreadable, not absent",
        );
    }

    #[test]
    fn a_present_but_empty_x_forwarded_proto_does_not_let_forwarded_decide() {
        // The scheme arm, at the same spelling. `X-Forwarded-Proto` decides
        // wherever it is *present*; present and unreadable means `false`,
        // which never claims TLS it cannot show. Letting the client's
        // `Forwarded: proto=https` decide instead reports a plain-HTTP
        // request as TLS.
        let attacker = ("forwarded", "proto=https");

        for empty in ["", "  ", ",", " ,  , "] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-proto", empty), attacker]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert!(
                !c.secure,
                "X-Forwarded-Proto: {empty:?} is present, so it decides, and \
                 it does not say https",
            );
        }

        let mut r = Request::new("10.1.2.3");
        r.headers_mut().insert(
            "x-forwarded-proto",
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        r.headers_mut()
            .insert("forwarded", HeaderValue::from_static("proto=https"));
        assert!(
            !resolve(&r, &trusted(&["10.0.0.0/8"])).secure,
            "a non-UTF-8 X-Forwarded-Proto is unreadable, not absent",
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
    fn an_explicit_x_forwarded_proto_is_not_overridden_by_forwarded() {
        // The scheme follows the same precedence as the address. The trusted
        // proxy terminated plain HTTP and said so; a client whose `Forwarded`
        // the proxy passed through verbatim — nginx's default for a header it
        // does not know — must not turn that into https.
        let c = resolve(
            &req(
                "10.1.2.3",
                &[("x-forwarded-proto", "http"), ("forwarded", "proto=https")],
            ),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            !c.secure,
            "X-Forwarded-Proto decides where it is present; Forwarded is the \
             fallback, not a second opinion",
        );
    }

    #[test]
    fn a_single_forwarded_element_still_supplies_the_scheme() {
        // The other direction of the same rule, so precedence is pinned both
        // ways: with no `X-Forwarded-Proto` there is nothing to take
        // precedence over, and a proxy emitting only RFC 7239 still sets
        // `secure`. One element, so last-wins has nothing to discard either.
        let c = resolve(
            &req("10.1.2.3", &[("forwarded", "proto=https")]),
            &trusted(&["10.0.0.0/8"]),
        );
        assert!(
            c.secure,
            "Forwarded is the fallback where X-Forwarded-Proto is absent, and \
             a fallback that never fires is not a fallback",
        );
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
    fn a_v4_mapped_trust_entry_matches_the_v4_peer_it_names() {
        // The other side of the same fold. `docs/running.md` teaches
        // `::ffff:198.51.100.9` and `198.51.100.9` as one client and tells
        // the operator to name the address their proxy connects from, which
        // on a dual-stack host is the spelling they read out of a log — so
        // the trust list has to match it. Demonstrated: a daemon booted with
        // `trusted_proxies = ["::ffff:127.0.0.1"]` logged that trust set,
        // passed `--check-config`, and then ignored every forwarding header
        // from 127.0.0.1. It fails closed, but the logged set and the
        // effective set disagreed.
        assert!(Cidr::parse("::ffff:127.0.0.1")
            .unwrap()
            .contains("127.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("::ffff:127.0.0.1")
            .unwrap()
            .contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!Cidr::parse("::ffff:127.0.0.1")
            .unwrap()
            .contains("127.0.0.2".parse().unwrap()));

        // A prefix inside the mapped `/96` drops those 96 bits rather than
        // being read as a v4 prefix length: `/104` is `10.0.0.0/8` and
        // `/120` is `10.0.0.0/24`.
        let net = Cidr::parse("::ffff:10.0.0.0/104").unwrap();
        assert!(net.contains("10.1.0.1".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        let net = Cidr::parse("::ffff:10.0.0.0/120").unwrap();
        assert!(net.contains("10.0.0.1".parse().unwrap()));
        assert!(!net.contains("10.0.1.1".parse().unwrap()));

        // A genuine v6 block still does not match a v4 peer, and the
        // converse.
        assert!(!Cidr::parse("2001:db8::/32")
            .unwrap()
            .contains("10.0.0.1".parse().unwrap()));
        assert!(!Cidr::parse("10.0.0.0/8")
            .unwrap()
            .contains("2001:db8::1".parse().unwrap()));
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

    /// The startup log prints this form, so it has to be the block the
    /// matcher uses rather than the spelling the operator wrote.
    #[test]
    fn a_trust_set_displays_its_effective_blocks() {
        let set = TrustedProxies::parse(&[
            "::ffff:0:0/96".to_string(),
            "10.1.2.3/8".to_string(),
            "::ffff:127.0.0.1".to_string(),
            "2001:db8::1/64".to_string(),
            "172.28.0.2".to_string(),
        ])
        .unwrap();
        assert_eq!(
            set.to_string(),
            "0.0.0.0/0, 10.0.0.0/8, 127.0.0.1/32, 2001:db8::/64, 172.28.0.2/32"
        );
        // And what it prints is what it matches.
        let every_v4 = Cidr::parse("::ffff:0:0/96").unwrap();
        assert!(every_v4.contains("203.0.113.9".parse().unwrap()));
        assert_eq!(TrustedProxies::default().to_string(), "");
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
        assert!(
            !c.secure,
            "only https sets secure (via_https); unknown must not"
        );
    }
}
