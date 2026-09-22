//! Resolving the real client behind a reverse proxy.
//!
//! The daemon does not terminate TLS and is expected to sit behind a proxy, so
//! the socket's peer address is usually the proxy's. Three things need the
//! real client: the login throttle, the `Secure` attribute on the session
//! cookie, and the `client_ip` field on the log line that records a failed
//! attempt.
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
//! keys per source IP. That is the better property — one attacker's failures
//! no longer share a bucket with the operator's, though a caller with enough
//! distinct addresses can still fill the tracked-client map and put everyone
//! back on the shared one — and it is the behaviour the daemon has, so it is
//! what is written down here.

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

    /// The parsed prefix length.
    ///
    /// Exposed because judging the *value* of a block is not the same
    /// question as matching against it, and the judgement has to be made on
    /// what `parse` produced. `u8::from_str` accepts a leading `+` and any
    /// number of leading zeros, so one prefix length has unboundedly many
    /// spellings and only this number identifies it.
    pub fn prefix(&self) -> u8 {
        self.prefix
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

/// A v4-mapped v6 address as its v4 form; anything else unchanged.
///
/// `Cidr::contains` already unmaps a peer before matching it, on the grounds
/// that `::ffff:a.b.c.d` "is the same host as its v4 form". The resolved
/// client address has to be spelled the same way or the repository holds both
/// positions at once: demonstrated, `X-Forwarded-For: ::ffff:198.51.100.88`
/// and `X-Forwarded-For: 198.51.100.88` were two `HashMap<IpAddr, _>` keys,
/// so eight failures alternating between the spellings never tripped a
/// lockout where five against one spelling did — and the security log carried
/// two `client_ip` spellings for one host.
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
/// the reverse proxy connects from and only that. The one thing required of
/// the proxy itself is that it **strips or overwrites** client-supplied
/// forwarding headers rather than passing them through: a value this daemon
/// believes must be one the proxy wrote.
///
/// There are **three** such headers and all three have to be covered, not
/// just the two an operator thinks of: `X-Forwarded-For`,
/// `X-Forwarded-Proto` and RFC 7239 `Forwarded`. `resolve` reads `Forwarded`
/// for both the address and the scheme, so a proxy that overwrites the two
/// `X-` names while forwarding `Forwarded` verbatim — nginx's default for a
/// header it does not know about — is handing a client-controlled value to a
/// peer this daemon believes. `deploy/Caddyfile` is the worked example of
/// covering all three: two `header_up` lines overwrite the `X-` pair and
/// `header_up -Forwarded` removes the third outright.
///
/// Whether the proxy appends by extending the existing field line or by
/// adding another one does not matter — `last_element` reads both the same
/// way.
///
/// **One hop.** `resolve` takes the element the immediate peer contributed
/// and stops; it does not walk right-to-left past hops that are themselves
/// listed here. A block wide enough to hold two of your own proxies —
/// `10.0.0.0/8` validates — therefore does not mean "believe the chain as far
/// as my own edge". In a two-hop chain the daemon resolves the **inner**
/// proxy's address as the client, which gives every client behind that edge
/// one shared throttle bucket and one `client_ip`.
///
/// That is a reason to list the one address your proxy connects from, which
/// is what everything else here asks for anyway. Walking the chain is a
/// larger design and is not what this does.
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
    /// Whether the *original* request was over TLS — the **outermost** hop's
    /// answer, not the nearest one's.
    ///
    /// The two are different questions and they read the chain from opposite
    /// ends. `ip` wants the hop the trusted proxy saw, which is the last
    /// element. TLS is terminated at the edge, so whether the request began
    /// over TLS is what the *first* element says, and `https` anywhere in a
    /// readable `X-Forwarded-Proto` chain means some hop terminated it:
    /// `https, http` is a TLS edge in front of a plain-HTTP inner proxy, and
    /// the original request there was TLS.
    ///
    /// `false` when unknown, which is the safe direction for the *unknown*
    /// case: it only ever withholds the `Secure` cookie attribute, never adds
    /// it wrongly. It is not the safe direction for a known TLS deployment —
    /// withholding `Secure` there sends the session cookie in clear to any
    /// plain-HTTP origin on the host — which is why "unknown" has to stay
    /// narrow.
    pub secure: bool,
}

/// What reading a forwarding header yielded.
///
/// The two questions are separate and must stay separate. *Was the name
/// there at all* decides which source `resolve` consults; *did it carry a
/// readable element* decides what that source says. Collapsing them into one
/// `Option` — the obvious shape — makes a header the proxy wrote but that
/// carries nothing readable indistinguishable from a header the proxy never
/// wrote, and those two have opposite safe answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeaderRead<'a> {
    /// Whether any field line carried this name, readable or not.
    present: bool,
    /// The **final** element across every field line — positionally, not the
    /// last one that happens to be readable — where it carries something.
    last: Option<&'a str>,
}

/// The last element of `name`'s value, across every field line it arrived on,
/// and whether the name was present at all.
///
/// Two rules for the element, and they are the same rule at two levels.
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
///
/// `present` is reported separately because an element that carries nothing
/// readable yields no `last`. A header that is present and yields nothing —
/// `X-Forwarded-For:`, `X-Forwarded-For: , `, or a value that is not UTF-8 —
/// is still a header the trusted proxy wrote, and `resolve` must not treat it
/// as one the proxy omitted.
///
/// Which element is *last* is decided **positionally**, at the same
/// granularity as `present`, and that is the whole of the second rule. Taking
/// the last element that happens to be readable — filtering emptiness out on
/// the way and letting `next_back` land wherever it lands — skips past an
/// unreadable final element and returns an **earlier** one, and the earlier
/// elements of a chain are the ones the client wrote. So a trusted proxy
/// whose own appended contribution evaluates empty, which is the ordinary
/// failure mode of appending a header field that was not there
/// (`add-header X-Forwarded-For %[hdr(...)]` over an absent inner header),
/// hands the client's forged first element straight back as the answer:
/// `X-Forwarded-For: 6.6.6.6,` resolved to `6.6.6.6` rather than to the
/// socket peer, and that value became the throttle key and the `client_ip`
/// on the failed-login line.
///
/// Deciding positionally makes the two rules one rule again: the final
/// element of the joined value is the trusted proxy's, whatever it contains,
/// and where it contains nothing usable the header is unreadable rather than
/// a licence to read further left.
fn last_element<'a, B>(req: &'a Request<B>, name: &str) -> HeaderRead<'a> {
    let values = req.headers().get_all(name);
    HeaderRead {
        present: values.iter().next().is_some(),
        // The last field line's last element. A non-UTF-8 *final* field line
        // makes the final element unreadable for the same reason an empty one
        // does — it is where the trusted proxy's contribution would be — so
        // `to_str` failing here is not a reason to consult the line before it.
        last: values
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| split_elements(name, v, ',').last())
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    }
}

/// Whether `name`'s grammar makes a `"` a quoted-string delimiter.
///
/// Only `Forwarded` does. RFC 7239 §4 makes a parameter value either a
/// `token` — which cannot contain a quote, a comma or a semicolon — or a
/// `quoted-string`, which can contain all three. `X-Forwarded-For` and
/// `X-Forwarded-Proto` are de-facto headers with no grammar beyond a
/// comma-separated list: nothing defines a quoted string in either, so a `"`
/// in one of their values is ordinary data the client happened to send.
///
/// Sharing one quote-aware splitter across all three names is not tidiness,
/// it is a hole. A client that plants **one unbalanced quote** makes the
/// trusted proxy's own appended element part of a single quoted segment, so
/// the positional last element is the client's text and `node_addr` reads the
/// client's address straight out of it. Demonstrated behind an appending
/// proxy — the `$proxy_add_x_forwarded_for` shape nginx documents, which is
/// raw concatenation of the client's header with the peer's address —
/// `[6.6.6.6]"`, `6.6.6.6:80"` and `[6.6.6.6]:80"` each resolved to
/// `6.6.6.6`. End to end on one daemon: eight failed logins each planting a
/// quote returned `401` eight times and were never throttled, while eight
/// honest ones locked out at the sixth and stayed locked, and the security
/// log recorded eight addresses the client chose. On `X-Forwarded-Proto` the
/// same byte runs the other way: a lone `"` merged a TLS edge's own `https`
/// into one unmatchable element and the session cookie shipped without
/// `Secure`.
///
/// A proxy that adds a *second field line* rather than extending the existing
/// one — HAProxy's `option forwardfor` — is unaffected either way, which is
/// what makes this precise rather than universal.
fn has_quoted_strings(name: &str) -> bool {
    name.eq_ignore_ascii_case("forwarded")
}

/// Whether every `quoted-string` opened in `s` is closed.
///
/// RFC 7239 §4's `quoted-string` production requires the closing `DQUOTE`, so
/// a value carrying an unterminated one is not a `Forwarded` value at all.
/// Honouring the opening quote anyway is the same hole one name over: a
/// client's `Forwarded: for=6.6.6.6:80"` leaves the quote open, the trusted
/// proxy's appended `, for=203.0.113.1` falls inside it, and the element that
/// answers is the client's — demonstrated live behind an appending proxy,
/// resolving to `6.6.6.6`.
///
/// So quoting is honoured only where the grammar it comes from is satisfied,
/// and an unterminated quote is data. The alternative — calling the whole
/// value unreadable — discards an element the trusted proxy wrote correctly
/// because the client sent a stray byte, and puts every client behind that
/// proxy in one throttle bucket on client-controlled input.
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

/// Split `s` on `sep`, ignoring separators inside a quoted string.
///
/// Splitting on the bare byte where the grammar *does* have a quoted string
/// re-frames that grammar around a value the *client* supplied: the one
/// parameter a proxy routinely copies from the request is `host=`, quoted
/// precisely because the client's `Host` may contain characters a token may
/// not.
///
/// Demonstrated against a daemon trusting loopback, before this:
/// `for=198.51.100.9;host="a,for=6.6.6.6"` read as two elements and resolved
/// to `6.6.6.6`; `host="a;for=6.6.6.6";for=198.51.100.9` read as two
/// parameters and did the same; `for=198.51.100.9;host="a,proto=https"`
/// destroyed the proxy's own `for=` *and* set `Secure`. The loss case needs
/// no attacker at all — a proxy legitimately quoting a separator silently
/// loses its own claim.
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

/// Split one `Forwarded` element's parameter list on `sep`.
///
/// The only caller is [`param`], which is reached from `Forwarded` and from
/// nowhere else, so the grammar is known without being passed.
fn split_outside_quotes(s: &str, sep: char) -> SplitList<'_> {
    SplitList {
        rest: Some(s),
        sep,
        quoted_strings: quotes_terminated(s),
    }
}

/// Split `name`'s value on `sep` under `name`'s own grammar.
///
/// Quote-aware for `Forwarded`, and then only for a value whose quoted
/// strings are closed; a bare split otherwise. [`has_quoted_strings`] and
/// [`quotes_terminated`] each say what their half is protecting against.
fn split_elements<'a>(name: &str, s: &'a str, sep: char) -> SplitList<'a> {
    SplitList {
        rest: Some(s),
        sep,
        quoted_strings: has_quoted_strings(name) && quotes_terminated(s),
    }
}

/// Remove RFC 7239 §4 `quoted-string` quoting from a parameter value.
///
/// `trim_matches('"')` is not this. It strips quote characters from either
/// end whether or not they are a matched pair, it leaves a `quoted-pair`
/// escape in the value, and on `""` it removes two quotes from one side. A
/// value that is not a quoted string at all is returned as it arrived.
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

/// Every element of `name`'s value, across every field line, in order.
///
/// For the question "did *any* hop say this", where [`last_element`]'s
/// question is "what did the hop that wrote the header say". A field line
/// that is not UTF-8 contributes nothing, which is why the caller still asks
/// `last_element` whether the header is readable at all before believing an
/// answer from here.
fn elements<'a, B>(req: &'a Request<B>, name: &'a str) -> impl Iterator<Item = &'a str> {
    req.headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(move |v| split_elements(name, v, ','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// The value of `key` in one RFC 7239 element, e.g. `proto` in
/// `for=203.0.113.9;proto=https`. Quoting is removed per RFC 7239 §4; the
/// name is case-insensitive, as the same section requires.
///
/// The parameter list is split outside quoted strings, for the reason
/// [`SplitOutsideQuotes`] gives. Splitting the *name* from the value on the
/// first `=` needs no such care: a name is a token, so the first `=` in a
/// parameter is always the one that separates them.
fn param<'a>(element: &'a str, key: &str) -> Option<std::borrow::Cow<'a, str>> {
    split_outside_quotes(element, ';').find_map(|p| {
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
    // Unreadable means *anything* the grammar cannot use, and which arm runs
    // is decided by `present` rather than by whether an element came back. A
    // value that does not parse, a value that is empty, a value that is only
    // separators, and a value that is not UTF-8 are one case: the proxy wrote
    // the header, so the peer stands. Deciding on the element instead splits
    // that case in two, and the half that reaches `Forwarded` takes the
    // client's word for the client's address.
    //
    // `last_element` decides emptiness at the same granularity, on the final
    // element and on no other. The two rules have to agree: a `present` that
    // asks about the header while `last` searches leftward for something
    // readable puts the client's own entry back in the answer without ever
    // reaching this arm.
    //
    // Both arms go through `node_addr`, so they parse one grammar: the bare
    // address, `host:port`, and a bracketed IPv6 literal are read the same on
    // either. Otherwise the *stricter* parser is the one that falls through
    // to the *less* trustworthy source, which is how the asymmetry bit.
    let xff = last_element(req, "x-forwarded-for");
    let ip = if xff.present {
        xff.last.and_then(node_addr).or(Some(peer))
    } else {
        forwarded
            .last
            .and_then(|f| param(f, "for"))
            .and_then(|node| node_addr(&node))
            .or(Some(peer))
    };

    // The same precedence, and the same presence rule, for the scheme. An
    // `||` across the two headers lets a client-supplied `proto=https`
    // override the trusted proxy's explicit `X-Forwarded-Proto: http`, which
    // issues the session cookie `Secure` over a plain-HTTP request: the
    // browser then neither stores nor returns it over http:// and the
    // operator cannot log in at all. One function must not carry two opposite
    // rules.
    //
    // Where `X-Forwarded-Proto` is present and unreadable the answer is
    // `false`, not `Forwarded`'s. `false` is the safe direction here — it
    // only ever withholds `Secure`, and the operator can still log in.
    //
    // *Which element* answers is the one thing that differs from the address,
    // and it differs because the question does. "Last" on the address chain
    // means the hop the trusted proxy saw, which is the client. The scheme
    // asks whether the **original** request was over TLS, and that is the
    // *outermost* hop's answer: a TLS-terminating edge in front of a
    // plain-HTTP inner proxy, each appending, writes `https, http`, and
    // taking the last element there returns `false` for a deployment whose
    // original request genuinely was TLS — so the session cookie ships
    // without `Secure` and the browser sends it in clear to any plain-HTTP
    // origin on that host. That is the harm this change exists to remove,
    // arriving from the rule meant to prevent it.
    //
    // So: `https` anywhere in a readable chain means the original request was
    // over TLS. Every element of the chain was written by a proxy — the one
    // requirement `TrustedProxies` places on the deployment is that
    // client-supplied values are stripped or overwritten — so there is no
    // element here whose `https` is the client's to forge. The two rules
    // compose: `last` still decides whether the header is *readable*, and the
    // chain decides what a readable one says.
    let xfp = last_element(req, "x-forwarded-proto");
    let secure = if xfp.present {
        xfp.last.is_some()
            && elements(req, "x-forwarded-proto").any(|p| p.eq_ignore_ascii_case("https"))
    } else {
        // `Forwarded` keeps the last-element rule, deliberately, and this is
        // the one place the two names differ. An `X-Forwarded-Proto` chain is
        // a chain of schemes and nothing else; a `Forwarded` element carries
        // `for=` and `proto=` together, so the element that answers "which
        // hop" for the address has to be the one that answers it for the
        // scheme, or one header yields two hops' answers to one request.
        // `an_earlier_forwarded_element_cannot_supply_the_scheme` pins that,
        // and a proxy that appends a `Forwarded` element without stripping
        // the client's leaves the client's element first.
        forwarded
            .last
            .and_then(|f| param(f, "proto"))
            .is_some_and(|p| p.eq_ignore_ascii_case("https"))
    };

    // Unmapped once, here, so every consumer gets one spelling per host. The
    // address reaches three things — the throttle key, the `client_ip` log
    // field, and nothing else that compares addresses — and two spellings of
    // one host is two throttle buckets and two log identities. Trust matching
    // already unmaps; this is the other half of that position.
    Client {
        ip: ip.map(unmap),
        secure,
    }
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

    /// A request whose last field line for `name` is raw bytes that are not
    /// UTF-8, preceded by whatever `before` lines the case needs.
    fn req_with_raw_last(peer: &str, name: &str, before: &[&str], raw: &[u8]) -> Request<()> {
        let mut r = Request::new(());
        r.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 12345)));
        let header = axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap();
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
            "a quoted proto= is part of host=, and must not set Secure",
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
        // a TLS edge's own `https` into one unmatchable element withholds
        // `Secure` from a deployment that really is TLS-fronted, and the
        // session cookie then travels in clear.
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
        let mut r = Request::new(());
        r.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "10.1.2.3".parse().unwrap(),
            12345,
        )));
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
    fn a_tls_edge_in_front_of_a_plain_inner_proxy_is_still_secure() {
        // The property: `secure` is the **outermost** hop's answer. TLS is
        // terminated at the edge, so a chain written by a TLS edge in front
        // of a plain-HTTP inner proxy — each appending — reads `https, http`,
        // and the original request there was over TLS.
        //
        // Taking the last element instead returns `false` and issues the
        // session cookie without `Secure` on a deployment that really is
        // TLS-fronted, so the browser sends it in clear to any plain-HTTP
        // origin on that host. That is the harm this change exists to remove.
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
        // `https` issue a `Secure` cookie over a plain-HTTP request, which
        // the browser will neither store nor return — so the caller cannot
        // log in.
        for value in ["https,", "https, ", "https, ,", "https,,"] {
            let c = resolve(
                &req("10.1.2.3", &[("x-forwarded-proto", value)]),
                &trusted(&["10.0.0.0/8"]),
            );
            assert!(
                !c.secure,
                "X-Forwarded-Proto: {value:?} ends in an element that carries \
                 nothing, so the header is unreadable and `Secure` is \
                 withheld",
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
        // which only ever withholds `Secure`. Letting the client's
        // `Forwarded: proto=https` decide instead issues a `Secure` cookie
        // over a plain-HTTP request, which the browser will neither store nor
        // return — so the operator cannot log in at all.
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

        let mut r = Request::new(());
        r.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "10.1.2.3".parse().unwrap(),
            12345,
        )));
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
        // does not know — must not turn that into https. It would issue the
        // session cookie `Secure` over a plain-HTTP request, and the browser
        // then neither stores nor returns it over http://, so the operator
        // cannot log in at all.
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
        // `Secure`. One element, so last-wins has nothing to discard either.
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
