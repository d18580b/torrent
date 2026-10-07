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

    /// Stands for a field line that is not UTF-8.
    const NON_UTF8: &str = "<non-utf8>";

    /// Resolve a request from `peer`, each header appended as its own field
    /// line, against `trust`.
    fn resolve_from(peer: &str, trust: &[&str], headers: &[(&str, &str)]) -> Client {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            let value = if *value == NON_UTF8 {
                HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap()
            } else {
                HeaderValue::from_str(value).unwrap()
            };
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), value);
        }
        let trust: Vec<String> = trust.iter().map(|s| s.to_string()).collect();
        let peer = SocketAddr::new(peer.parse().unwrap(), 12345);
        super::resolve(Some(peer), &map, &TrustedProxies::parse(&trust).unwrap())
    }

    const PEER: &str = "10.1.2.3";
    const PROXIES: &[&str] = &["10.0.0.0/8"];
    const XFF: &str = "x-forwarded-for";
    const XFP: &str = "x-forwarded-proto";
    const FWD: &str = "forwarded";

    /// Header sets from a trusted peer, and the client each must resolve to.
    #[rustfmt::skip]
    const CASES: &[(&[(&str, &str)], &str, bool)] = &[
        (&[(XFF, "198.51.100.7"), (XFP, "https")], "198.51.100.7", true),
        // The trusted proxy appends, so its element is the last; earlier ones
        // are the client's, on one field line or across several.
        (&[(XFF, "127.0.0.1, 198.51.100.7")], "198.51.100.7", false),
        (&[(XFF, "198.51.100.7"), (XFF, "203.0.113.4")], "203.0.113.4", false),
        (&[(XFF, "6.6.6.6, 5.5.5.5")], "5.5.5.5", false),
        // An empty final element is unreadable: the peer stands rather than
        // the client's earlier entry.
        (&[(XFF, "6.6.6.6,")], PEER, false),
        (&[(XFF, "6.6.6.6, ")], PEER, false),
        (&[(XFF, "6.6.6.6, ,")], PEER, false),
        (&[(XFF, "6.6.6.6,,")], PEER, false),
        (&[(XFF, "6.6.6.6"), (XFF, "")], PEER, false),
        (&[(XFF, "6.6.6.6"), (XFF, NON_UTF8)], PEER, false),
        // X-Forwarded-For decides wherever it is present; present but
        // unreadable stands the peer up rather than consulting Forwarded.
        (&[(XFF, "198.51.100.7"), (FWD, "for=203.0.113.4")], "198.51.100.7", false),
        (&[(XFF, "198.51.100.7:52014"), (FWD, "for=203.0.113.99")], "198.51.100.7", false),
        (&[(XFF, "not-an-address"), (FWD, "for=203.0.113.99")], PEER, false),
        (&[(XFF, ""), (FWD, "for=203.0.113.98")], PEER, false),
        (&[(XFF, "  "), (FWD, "for=203.0.113.98")], PEER, false),
        (&[(XFF, ","), (FWD, "for=203.0.113.98")], PEER, false),
        (&[(XFF, " ,  , "), (FWD, "for=203.0.113.98")], PEER, false),
        (&[(XFF, NON_UTF8), (FWD, "for=203.0.113.98")], PEER, false),
        // Forwarded alone names the client, with a port, bracketed, or not at
        // all when obfuscated.
        (&[(FWD, "for=198.51.100.7;proto=https")], "198.51.100.7", true),
        (&[(XFP, "https"), (FWD, "for=198.51.100.7")], "198.51.100.7", true),
        (&[(FWD, "for=\"198.51.100.7:4711\"")], "198.51.100.7", false),
        (&[(FWD, "for=\"[2001:db8::1]:4711\"")], "2001:db8::1", false),
        (&[(FWD, "for=2001:db8::1")], "2001:db8::1", false),
        (&[(FWD, "for=_hidden")], PEER, false),
        (&[(FWD, "for=unknown")], PEER, false),
        (&[(FWD, "proto=https"), (FWD, "for=203.0.113.4;proto=http")], "203.0.113.4", true),
        (&[(FWD, "proto=https ;x=1, for=203.0.113.9;proto=http")], "203.0.113.9", true),
        (&[(FWD, "proto=https, for=1.2.3.4")], "1.2.3.4", true),
        // A closed quoted string in Forwarded hides its separators.
        (&[(FWD, r#"for=198.51.100.9;host="a,for=6.6.6.6""#)], "198.51.100.9", false),
        (&[(FWD, r#"host="a;for=6.6.6.6";for=198.51.100.9"#)], "198.51.100.9", false),
        (&[(FWD, r#"for=198.51.100.9;host="a,proto=https""#)], "198.51.100.9", false),
        (&[(FWD, r#"host="x;proto=https";proto=http"#)], PEER, false),
        // An unbalanced quote is data, in X-Forwarded-For always and in
        // Forwarded when unterminated, so the proxy's element still decides.
        (&[(XFF, r#"[6.6.6.6]", 203.0.113.1"#)], "203.0.113.1", false),
        (&[(XFF, r#"6.6.6.6:80", 203.0.113.1"#)], "203.0.113.1", false),
        (&[(XFF, r#"[6.6.6.6]:80", 203.0.113.1"#)], "203.0.113.1", false),
        (&[(XFF, r#""6.6.6.6, 203.0.113.1"#)], "203.0.113.1", false),
        (&[(XFF, r#"6.6.6.6";q=", 203.0.113.1"#)], "203.0.113.1", false),
        (&[(FWD, r#"for=6.6.6.6:80", for=203.0.113.1"#)], "203.0.113.1", false),
        (&[(FWD, r#"host="a, for=203.0.113.1"#)], "203.0.113.1", false),
        (&[(FWD, r#"for=6.6.6.6;host="a;x, for=203.0.113.1"#)], "203.0.113.1", false),
        (&[(FWD, r#"for=203.0.113.1;host="a,for=6.6.6.6""#)], "203.0.113.1", false),
        // One host is one spelling.
        (&[(XFF, "::ffff:198.51.100.88")], "198.51.100.88", false),
        (&[(XFF, "::ffff:c633:6458")], "198.51.100.88", false),
        (&[(FWD, "for=\"[::ffff:198.51.100.88]\"")], "198.51.100.88", false),
        (&[(XFF, "2001:db8::1")], "2001:db8::1", false),
        // The scheme: https anywhere in a readable chain, under either name.
        (&[(XFP, "https, http")], PEER, true),
        (&[(XFP, "https,http")], PEER, true),
        (&[(XFP, "https, http, http")], PEER, true),
        (&[(XFP, "http, https")], PEER, true),
        (&[(XFP, "https"), (XFP, "http")], PEER, true),
        (&[(XFP, "http"), (XFP, "https")], PEER, true),
        (&[(XFP, r#"", https"#)], PEER, true),
        (&[(XFP, "http")], PEER, false),
        (&[(XFP, "http, http")], PEER, false),
        (&[(XFP, r#"", http"#)], PEER, false),
        (&[(FWD, "proto=https")], PEER, true),
        (&[(FWD, "proto=https, proto=http")], PEER, true),
        (&[(FWD, "proto=http, proto=https")], PEER, true),
        (&[(FWD, "proto=http")], PEER, false),
        (&[(FWD, "proto=http, proto=http")], PEER, false),
        // An unreadable final element withholds secure.
        (&[(XFP, "https,")], PEER, false),
        (&[(XFP, "https, ")], PEER, false),
        (&[(XFP, "https, ,")], PEER, false),
        (&[(XFP, "https,,")], PEER, false),
        (&[(XFP, "https"), (XFP, "")], PEER, false),
        (&[(XFP, "https"), (XFP, NON_UTF8)], PEER, false),
        (&[(FWD, "proto=https,")], PEER, false),
        // X-Forwarded-Proto decides wherever it is present.
        (&[(XFP, "http"), (FWD, "proto=https")], PEER, false),
        (&[(XFP, ""), (FWD, "proto=https")], PEER, false),
        (&[(XFP, "  "), (FWD, "proto=https")], PEER, false),
        (&[(XFP, ","), (FWD, "proto=https")], PEER, false),
        (&[(XFP, " ,  , "), (FWD, "proto=https")], PEER, false),
        (&[(XFP, NON_UTF8), (FWD, "proto=https")], PEER, false),
    ];

    #[test]
    fn a_trusted_proxy_s_headers_resolve_the_client() {
        for (headers, ip, secure) in CASES {
            let c = resolve_from(PEER, PROXIES, headers);
            assert_eq!(c.ip, Some(ip.parse().unwrap()), "{headers:?}");
            assert_eq!(c.secure, *secure, "{headers:?}");
        }
    }

    /// Whatever the headers say, an untrusted peer is itself and never
    /// secure, and no resolved address is v4-mapped.
    #[test]
    fn an_untrusted_peer_is_its_own_socket_address() {
        for (headers, _, _) in CASES {
            for trust in [&[][..], &["192.0.2.0/24"][..]] {
                let c = resolve_from(PEER, trust, headers);
                assert_eq!(c.ip, Some(PEER.parse().unwrap()), "{headers:?}");
                assert!(!c.secure, "{headers:?}");
            }
            let c = resolve_from("::ffff:198.51.100.9", PROXIES, headers);
            assert_eq!(c.ip, Some("198.51.100.9".parse().unwrap()), "{headers:?}");
            let c = resolve_from(PEER, PROXIES, headers);
            let mapped = matches!(c.ip, Some(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some());
            assert!(!mapped, "{headers:?} resolved to {:?}", c.ip);
        }
        // A dual-stack listener's mapped peer is trusted as its v4 form.
        let c = resolve_from("::ffff:10.1.2.3", PROXIES, &[]);
        assert_eq!(c.ip, Some(PEER.parse().unwrap()));
    }

    /// A quoted string is structure in `Forwarded` alone, and `param` and
    /// `node_addr` read RFC 7239's own spellings.
    #[test]
    fn forwarded_grammar_is_parsed_to_rfc_7239() {
        assert_eq!(
            split_elements(XFF, r#""a,b", 1.2.3.4"#, ',').collect::<Vec<_>>(),
            vec![r#""a"#, r#"b""#, " 1.2.3.4"],
        );
        assert_eq!(
            split_elements(XFP, r#""https,http", https"#, ',').collect::<Vec<_>>(),
            vec![r#""https"#, r#"http""#, " https"],
        );
        assert_eq!(
            split_elements(FWD, r#"host="a,b", for=1.2.3.4"#, ',').collect::<Vec<_>>(),
            vec![r#"host="a,b""#, " for=1.2.3.4"],
        );
        let element = r#"host="a\"b";for=198.51.100.9"#;
        assert_eq!(param(element, "host").as_deref(), Some(r#"a"b"#));
        assert_eq!(param(element, "FOR").as_deref(), Some("198.51.100.9"));
        assert_eq!(param(r#"host="""#, "host").as_deref(), Some(""));
        assert_eq!(param("host=plain", "host").as_deref(), Some("plain"));
        for (node, ip) in [
            ("[6.6.6.6]", Some("6.6.6.6")),
            ("[6.6.6.6]:80", Some("6.6.6.6")),
            ("[2001:db8::1]:443", Some("2001:db8::1")),
            ("[not-an-ip]", None),
        ] {
            assert_eq!(node_addr(node), ip.map(|ip| ip.parse().unwrap()), "{node}");
        }
    }

    #[test]
    fn cidr_matching_folds_v4_mapped_addresses_on_both_sides() {
        #[rustfmt::skip]
        let cases = [
            ("10.1.2.0/24", "10.1.2.255", true),
            ("10.1.2.0/24", "10.1.3.0", false),
            ("0.0.0.0/0", "1.2.3.4", true),
            ("127.0.0.1", "::ffff:127.0.0.1", true),
            ("::ffff:127.0.0.1", "127.0.0.1", true),
            ("::ffff:127.0.0.1", "::ffff:127.0.0.1", true),
            ("::ffff:127.0.0.1", "127.0.0.2", false),
            // A prefix inside the mapped /96 loses those 96 bits.
            ("::ffff:10.0.0.0/104", "10.1.0.1", true),
            ("::ffff:10.0.0.0/104", "11.0.0.1", false),
            ("::ffff:10.0.0.0/120", "10.0.0.1", true),
            ("::ffff:10.0.0.0/120", "10.0.1.1", false),
            ("::ffff:0:0/96", "203.0.113.9", true),
            ("2001:db8::/32", "10.0.0.1", false),
            ("10.0.0.0/8", "2001:db8::1", false),
        ];
        for (block, ip, inside) in cases {
            let c = Cidr::parse(block).unwrap();
            assert_eq!(c.contains(ip.parse().unwrap()), inside, "{block} ∋ {ip}");
        }
        assert!(Cidr::parse("not-an-ip").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
    }

    /// The startup log prints the effective blocks, not the spelling.
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
        assert_eq!(TrustedProxies::default().to_string(), "");
    }

    #[test]
    fn a_trust_set_refuses_a_zero_prefix_in_any_spelling() {
        for wide in ["0.0.0.0/0", "0.0.0.0/00", "0.0.0.0/+0", "::/0", "::/000"] {
            let err = TrustedProxies::parse(&[wide.to_string()]).expect_err(wide);
            assert!(err.contains(wide), "{err}");
        }
    }
}
