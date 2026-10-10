//! Structured-logging bring-up.
//!
//! JSON lines on stdout, one object per event, keys in this order:
//! `timestamp` (RFC3339), `level`, the event's own fields (including
//! `message`) flat at the top (`flatten_event`), `target`, then `span`.
//! `span` is an object holding the current span's `name` and fields, e.g. the
//! `op`/`infohash` an `#[instrument]` attaches; those are nested there, not
//! flat at the top (`with_current_span`). `with_span_list(false)` suppresses
//! the separate `spans` array. Events outside any span have no `span` key.
//! Filter level seeded from config + overridden by RUST_LOG if set.
//!
//! The global filter is wrapped in a `reload::Layer` so SIGHUP can swap the
//! log level at runtime without restarting the daemon (//! Management: `log_level` is reloadable).
//!
//! # Credential redaction
//!
//! Every line passes through [`Redacting`] before it is written, so a URL
//! carrying a tracker credential never reaches the log, whichever field,
//! span, crate, or libtorrent log message it arrived in. A URL is
//! credential-carrying when it has userinfo (`user:pass@`), a query parameter
//! named in [`CREDENTIAL_KEYS`], or a path segment of 32 or more ASCII
//! alphanumerics (the shape of a passkey embedded in the path), or when a URL
//! nested unencoded after its host is itself credential-carrying, or when it
//! nests URLs more than [`MAX_URL_NESTING`] deep. Keys are compared after
//! percent-decoding, and a URL percent-encoded once or twice (`https%3A%2F%2F…`,
//! alone or nested in another URL) is judged by what it decodes to. Such a URL
//! is replaced by its scheme and host plus a marker holding a short hash of
//! the whole URL:
//!
//! ```text
//! https://tracker.example/announce?passkey=0123…  ->  https://tracker.example/[redacted:1a2b3c4d]
//! ```
//!
//! The hash is stable across runs, so two announce URLs on one host stay
//! distinguishable in a log without the secret. URLs that carry none of these
//! pass through unchanged — except under the targets in `HOST_ONLY_TARGETS`:
//! libtorrent's own log messages, and the tracker warning, scrape-failed and
//! announce-failed lines under `torrentd_engine::handler::tracker`, whose
//! messages libtorrent builds from the announce URL. These quote tracker URLs
//! in every shape a tracker invents, so there every URL is cut at its host
//! unless it is a bare `scheme://host[:port]/announce`-style URL, the same
//! fail-closed rule the API applies to announce URLs.
//! `CONTRIBUTING.md` § Reporting bugs promises this to bug reporters; change
//! the two together.

use std::borrow::Cow;
use std::fmt;

use sha2::Digest;
use sha2::Sha256;
use tracing::Event;
use tracing::Subscriber;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::reload;
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;

use crate::config::LogLevel;

/// Query parameter names whose value is an account credential. Compared
/// ASCII-case-insensitively, after percent-decoding. `key`, which libtorrent
/// adds to every announce, is a per-session random value and deliberately
/// absent. `pid` and `uid` are the Gazelle/Luminance account parameters, and
/// `rsskey` and `pass` the RSS and legacy passkey spellings trackers use.
const CREDENTIAL_KEYS: &[&str] = &[
    "passkey",
    "apikey",
    "api_key",
    "authkey",
    "torrent_pass",
    "token",
    "pid",
    "uid",
    "rsskey",
    "pass",
];

/// The targets whose lines quote tracker URLs verbatim, in whatever shape the
/// tracker uses: libtorrent's own log messages
/// (`torrentd_engine::handlers::log_msg`), and the tracker alert lines
/// (`torrentd_engine::handlers::warning`), whose `message()` libtorrent builds
/// from the announce URL. Every URL in them is held to the fail-closed rule
/// the API uses ([`display_announce_url`]) rather than to the credential
/// shapes [`redact_urls`] recognises, so a passkey of any shape (a UUID, a
/// short key, a base64url key) stays out of the log.
const HOST_ONLY_TARGETS: &[&str] = &[
    "torrentd_engine::handler::log",
    "torrentd_engine::handler::tracker",
];

/// Separators that start a URL's authority: `://` literally, and the same
/// percent-encoded once and twice, which is how a URL nested in another URL's
/// query (or a tracker's redirect) reaches a log line.
const SEPARATORS: &[&str] = &["://", "%3a%2f%2f", "%253a%252f%252f"];

/// A path segment at least this long and wholly ASCII-alphanumeric is treated
/// as an embedded passkey (`/<32 hex>/announce`, `/announce/<32 alnum>`).
const PATH_SECRET_MIN_LEN: usize = 32;

/// How many URLs deep, below the outermost, a nested URL is inspected for a
/// credential. A URL nesting more than this is redacted without inspecting
/// the rest, so a whitespace-free run of `://` in untrusted text costs at most
/// this many passes over the line, never a recursion as deep as the run.
const MAX_URL_NESTING: usize = 4;

/// Wraps an event formatter and redacts credential-carrying URLs from the
/// complete formatted line, so event fields and the span fields the JSON
/// formatter nests under `span` are covered alike.
struct Redacting<F>(F);

impl<S, N, F> FormatEvent<S, N> for Redacting<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut line = String::new();
        self.0.format_event(ctx, Writer::new(&mut line), event)?;
        let redacted = if HOST_ONLY_TARGETS.contains(&event.metadata().target()) {
            redact_urls_host_only(&line)
        } else {
            redact_urls(&line)
        };
        writer.write_str(&redacted)
    }
}

/// How much of a URL a line may keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Redact a URL carrying a credential shape [`redact_url`] recognises.
    Credentials,
    /// Keep a URL only where [`display_announce_url`] would show it whole;
    /// cut every other at the host. For text that quotes tracker URLs.
    HostOnly,
}

/// Replace every credential-carrying URL in `text` with its redacted form.
/// Borrows when `text` holds no URL at all, which is most lines.
pub(crate) fn redact_urls(text: &str) -> Cow<'_, str> {
    redact_urls_at(text, 0, Mode::Credentials)
}

/// Replace every URL in `text` that is not known to be safe with its scheme,
/// host and a marker: what a line quoting tracker URLs may keep.
fn redact_urls_host_only(text: &str) -> Cow<'_, str> {
    redact_urls_at(text, 0, Mode::HostOnly)
}

/// The first URL separator in `text`: its byte offset and length.
fn next_separator(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b':' | b'%' => {
                for sep in SEPARATORS {
                    let end = at + sep.len();
                    if end <= bytes.len() && bytes[at..end].eq_ignore_ascii_case(sep.as_bytes()) {
                        return Some((at, sep.len()));
                    }
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

/// `text` with every `%XX` escape decoded; borrowed when there is none.
/// Invalid escapes are kept as written, and bytes that do not decode to UTF-8
/// are replaced, which can only make a URL look less like a clean one.
fn percent_decode(text: &str) -> Cow<'_, str> {
    if !text.contains('%') {
        return Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    match String::from_utf8_lossy(&out) {
        Cow::Borrowed(s) if s == text => Cow::Borrowed(text),
        decoded => Cow::Owned(decoded.into_owned()),
    }
}

/// An announce URL as the API may show it, and the host it names.
pub(crate) struct DisplayedUrl {
    /// The host, with its port when the URL names one; empty when the URL
    /// could not be parsed.
    pub host: String,
    /// The URL, unchanged when every part of it is known to carry no
    /// credential, else `scheme://host/[redacted:<hash>]`, or the bare marker
    /// when it could not be parsed.
    pub url: String,
}

/// Path segments an announce URL may show: the conventional endpoints, which
/// name a protocol rather than an account.
const SAFE_ANNOUNCE_SEGMENTS: &[&str] = &["announce", "announce.php", "scrape", "scrape.php"];

/// One announce URL as the API may show it. Fails closed.
///
/// [`redact_urls`] reads free text for the log and redacts the credential
/// shapes it recognises. The API is held to more than that, because it
/// hands a tracker's URL to anyone holding `read`, and a passkey is an
/// account: this keeps a URL only when every part of it is known to be safe
/// — a scheme, a plain host and port, and a path made only of the
/// conventional endpoints — and replaces everything after the host
/// otherwise. A query, a fragment, userinfo, a path segment of any other
/// shape (a UUID, a short key, a base64url key), or anything that does not
/// parse as one well-formed URL is never echoed.
pub(crate) fn display_announce_url(url: &str) -> DisplayedUrl {
    let marker = || {
        let digest = Sha256::digest(url.as_bytes());
        format!("[redacted:{}]", hex::encode(&digest[..4]))
    };
    let opaque = || DisplayedUrl {
        host: String::new(),
        url: marker(),
    };
    let Some(sep) = url.find("://") else {
        return opaque();
    };
    let scheme = &url[..sep];
    let well_formed = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme.chars().all(is_scheme_char)
        && !url.contains(is_url_terminator);
    if !well_formed {
        return opaque();
    }
    let rest = &url[sep + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, host) = match authority.rsplit_once('@') {
        Some((_, host)) => (true, host),
        None => (false, authority),
    };
    if !is_plain_host(host) {
        return opaque();
    }
    let tail = &rest[authority_end..];
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let (path, extra) = tail.split_at(path_end);
    let path_safe = path.split('/').skip(1).all(|seg| {
        SAFE_ANNOUNCE_SEGMENTS
            .iter()
            .any(|safe| seg.eq_ignore_ascii_case(safe))
    });
    let url = if !userinfo && path_safe && extra.is_empty() {
        url.to_owned()
    } else {
        format!("{scheme}://{host}/{}", marker())
    };
    DisplayedUrl {
        host: host.to_owned(),
        url,
    }
}

/// Whether `host` is a bare hostname, IPv4 address or bracketed IPv6
/// address, with an optional numeric port — nothing a credential could hide
/// in.
fn is_plain_host(host: &str) -> bool {
    let (name_ok, port) = match host.strip_prefix('[') {
        Some(bracketed) => {
            let Some((addr, after)) = bracketed.split_once(']') else {
                return false;
            };
            let addr_ok = !addr.is_empty()
                && addr
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
            let port = match after {
                "" => None,
                _ => match after.strip_prefix(':') {
                    Some(port) => Some(port),
                    None => return false,
                },
            };
            (addr_ok, port)
        }
        None => {
            let (name, port) = match host.split_once(':') {
                Some((name, port)) => (name, Some(port)),
                None => (host, None),
            };
            let name_ok = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            (name_ok, port)
        }
    };
    let port_ok =
        port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()));
    name_ok && port_ok
}

/// [`redact_urls`] for text nested `depth` URLs deep inside another URL.
fn redact_urls_at(text: &str, depth: usize, mode: Mode) -> Cow<'_, str> {
    if next_separator(text).is_none() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((sep, sep_len)) = next_separator(rest) {
        let before = &rest[..sep];
        let mut start = before.trim_end_matches(is_scheme_char).len();
        // A scheme starts with a letter; skip digits or `+-.` glued before it.
        match before[start..].find(|c: char| c.is_ascii_alphabetic()) {
            Some(skip) => start += skip,
            None => {
                out.push_str(&rest[..sep + sep_len]);
                rest = &rest[sep + sep_len..];
                continue;
            }
        }
        let tail = &rest[sep + sep_len..];
        let end = sep + sep_len + tail.find(is_url_terminator).unwrap_or(tail.len());
        let end = start + trim_trailing_punctuation(&rest[start..end]).len();
        let url = &rest[start..end];
        out.push_str(&rest[..start]);
        let redacted = if sep_len == 3 {
            redact_url(url, sep - start, depth, mode)
        } else {
            // Percent-encoded: judge the URL it decodes to. A redaction is
            // made from the decoded form, so no escape of the secret survives.
            let decoded = percent_decode(url);
            if depth >= MAX_URL_NESTING {
                Some(marker_url(&decoded, sep - start))
            } else {
                redact_urls_at(&decoded, depth + 1, mode)
                    .ne(&decoded)
                    .then(|| marker_url(&decoded, sep - start))
            }
        };
        match redacted {
            Some(redacted) => out.push_str(&redacted),
            None => out.push_str(url),
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// `url` cut at its host: `scheme://host/[redacted:<hash>]`. `scheme_len` is
/// the byte length of the scheme; the separator after it may be literal or
/// encoded, and the host is whatever precedes the first `/`, `?` or `#` after
/// a literal `://`, or the bare marker where there is none.
fn marker_url(url: &str, scheme_len: usize) -> String {
    let digest = Sha256::digest(url.as_bytes());
    let marker = format!("[redacted:{}]", hex::encode(&digest[..4]));
    match url.get(scheme_len..).and_then(|r| r.strip_prefix("://")) {
        Some(after) => {
            let authority = &after[..after.find(['/', '?', '#']).unwrap_or(after.len())];
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            format!("{}://{host}/{marker}", &url[..scheme_len])
        }
        None => marker,
    }
}

pub(crate) fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

/// Where a URL embedded in a formatted line ends. `"` and `\` end it because
/// the line is JSON: a URL never spans a string boundary or an escape.
pub(crate) fn is_url_terminator(c: char) -> bool {
    c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\' | '<' | '>' | '\'' | '`')
}

/// Drop prose punctuation glued to the end of a URL (`… see http://x/a.`),
/// and a closing bracket the URL itself never opened (`(http://x/a)`).
pub(crate) fn trim_trailing_punctuation(url: &str) -> &str {
    let mut url = url;
    loop {
        let trimmed = match url.chars().last() {
            Some('.' | ',' | ';' | ':' | '!') => &url[..url.len() - 1],
            Some(')') if !url.contains('(') => &url[..url.len() - 1],
            Some(']') if !url.contains('[') => &url[..url.len() - 1],
            Some('}') if !url.contains('{') => &url[..url.len() - 1],
            _ => return url,
        };
        url = trimmed;
    }
}

/// The redacted form of `url` if it carries a credential, else `None`.
/// `scheme_len` is the byte length of the scheme before `://`; `depth` is how
/// many URLs enclose this one.
fn redact_url(url: &str, scheme_len: usize, depth: usize, mode: Mode) -> Option<String> {
    if mode == Mode::HostOnly {
        let shown = display_announce_url(url);
        return (shown.url != url).then_some(shown.url);
    }
    let scheme = &url[..scheme_len];
    let after = &url[scheme_len + 3..];
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..authority_end];
    let (userinfo, host) = match authority.rsplit_once('@') {
        Some((userinfo, host)) => (Some(userinfo), host),
        None => (None, authority),
    };
    let rest = &after[authority_end..];
    // A URL nested unencoded in this one (`/r?u=https://t/a?passkey=…`) is
    // swallowed whole by `redact_urls`, so check it here: a credential in it
    // makes this URL credential-carrying too. Past `MAX_URL_NESTING` the
    // nested URL is not inspected and this one is redacted, failing closed.
    //
    // The same holds for one nested percent-encoded (`?u=https%3A%2F%2Ft…`),
    // which is found by decoding the rest once and looking again; a
    // double-encoded one takes one more level, bounded by the same cap.
    let nested_secret_in = |r: &str| {
        next_separator(r).is_some()
            && (depth >= MAX_URL_NESTING || redact_urls_at(r, depth + 1, mode) != r)
    };
    let decoded_rest = percent_decode(rest);
    let secret_nested =
        nested_secret_in(rest) || (decoded_rest != rest && nested_secret_in(&decoded_rest));
    let rest = rest.split('#').next().unwrap_or_default();
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    };

    let secret_in_path = path.split('/').any(|seg| {
        seg.len() >= PATH_SECRET_MIN_LEN && seg.bytes().all(|b| b.is_ascii_alphanumeric())
    });
    // Keys are compared decoded (`pass%6Bey` is `passkey`), and the query is
    // also read decoded, so a key hidden behind an encoded `&` or `=` counts.
    let names_a_credential = |q: &str| {
        q.split(['&', ';']).any(|pair| {
            let key = percent_decode(pair.split('=').next().unwrap_or_default());
            CREDENTIAL_KEYS.iter().any(|k| key.eq_ignore_ascii_case(k))
        })
    };
    let decoded_query = percent_decode(query);
    let secret_in_query =
        names_a_credential(query) || (decoded_query != query && names_a_credential(&decoded_query));
    if userinfo.is_none() && !secret_in_path && !secret_in_query && !secret_nested {
        return None;
    }
    let digest = Sha256::digest(url.as_bytes());
    Some(format!(
        "{scheme}://{host}/[redacted:{}]",
        hex::encode(&digest[..4])
    ))
}

/// Handle that lets the SIGHUP pump swap the global log filter at runtime.
/// Cheap to clone (it wraps an `Arc<RwLock<…>>` internally).
#[derive(Clone)]
pub struct LogReloadHandle {
    inner: reload::Handle<EnvFilter, Registry>,
}

impl LogReloadHandle {
    /// Replace the global filter with one derived from `level`. This wins over
    /// any `RUST_LOG` that seeded the initial filter.
    pub fn set_level(&self, level: LogLevel) -> anyhow::Result<()> {
        self.inner
            .reload(level_filter(level))
            .map_err(|e| anyhow::anyhow!("reload log filter: {e}"))
    }
}

fn level_filter(level: LogLevel) -> EnvFilter {
    EnvFilter::new(format!(
        "info,torrentd={lvl},torrentd_engine={lvl},libtorrent_safe={lvl}",
        lvl = level.as_str()
    ))
}

pub fn init(level: LogLevel) -> LogReloadHandle {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| level_filter(level));
    let (filter_layer, handle) = reload::Layer::new(filter);

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer(std::io::stdout))
        .try_init();

    LogReloadHandle { inner: handle }
}

/// `init`'s subscriber, reloadable filter and daemon layer included, writing
/// to `writer` and installed nowhere, so a test can scope it with
/// `tracing::subscriber::set_default` and drive a real `LogReloadHandle`.
#[cfg(test)]
pub(crate) fn for_tests<W>(
    level: LogLevel,
    writer: W,
) -> (LogReloadHandle, impl Subscriber + Send + Sync)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let (filter_layer, handle) = reload::Layer::new(level_filter(level));
    let subscriber = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer(writer));
    (LogReloadHandle { inner: handle }, subscriber)
}

/// An in-memory log a test hands to `fmt_layer` and reads back.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl Buf {
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("buffer lock").clone()).expect("utf8")
    }
}

#[cfg(test)]
impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl<'w> MakeWriter<'w> for Buf {
    type Writer = Buf;
    fn make_writer(&'w self) -> Self::Writer {
        self.clone()
    }
}

/// The JSON formatting layer, redaction included, writing to `writer`.
fn fmt_layer<S, W>(writer: W) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let format = tracing_subscriber::fmt::format()
        .json()
        .with_timer(ChronoUtc::rfc_3339())
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .flatten_event(true);

    tracing_subscriber::fmt::layer()
        .fmt_fields(tracing_subscriber::fmt::format::JsonFields::new())
        .event_format(Redacting(format))
        .with_writer(writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSKEY: &str = "0123456789abcdef0123456789abcdef";

    fn redacted(s: &str) -> String {
        redact_urls(s).into_owned()
    }

    #[test]
    fn a_url_shown_by_the_api_never_carries_its_credential() {
        for clean in [
            "udp://tracker.example:6969/announce",
            "https://t.example/announce.php",
            "http://[2001:db8::1]:8080/announce",
            "http://10.0.0.1/scrape",
            "https://t.example",
        ] {
            let shown = display_announce_url(clean);
            assert_eq!(shown.url, clean);
        }
        assert_eq!(
            display_announce_url("udp://t.example:6969/announce").host,
            "t.example:6969"
        );

        // Every credential shape, including those the log's redactor does not
        // recognise, is cut at the host.
        for secret in [
            format!("https://t.example/announce?passkey={PASSKEY}"),
            format!("https://t.example/{PASSKEY}/announce"),
            "https://user:pw@t.example/announce".to_owned(),
            "https://t.example/announce/2f1c9a3e-6b1d-4c1e-9f0a-1234567890ab".to_owned(),
            "https://t.example/announce/Ab-_x9Qz".to_owned(),
            "https://t.example/announce?pk=abc123".to_owned(),
            "https://t.example/announce?uk=abc123".to_owned(),
            "https://t.example/announce?auth=abc123&rsskey=def".to_owned(),
            "https://t.example/announce#frag-secret".to_owned(),
            "https://t.example/a1b2c3".to_owned(),
        ] {
            let shown = display_announce_url(&secret);
            assert!(
                shown.url.starts_with("https://t.example/[redacted:"),
                "{}",
                shown.url
            );
            assert_eq!(shown.host, "t.example", "{secret}");
            for leak in [
                PASSKEY,
                "pw@",
                "2f1c9a3e",
                "Ab-_x9Qz",
                "abc123",
                "frag-secret",
                "a1b2c3",
            ] {
                assert!(!shown.url.contains(leak), "{}", shown.url);
            }
        }

        // Not one well-formed URL, or a host a credential could hide in:
        // replaced whole, and no host is claimed.
        for odd in [
            format!("t.example/announce?passkey={PASSKEY}"),
            format!("http://t.example/a ?passkey={PASSKEY}"),
            format!("http://t.example/a\"?passkey={PASSKEY}"),
            format!("1http://t.example/?passkey={PASSKEY}"),
            "http://u:p/q@h/announce".to_owned(),
            "http://t.example:port/announce".to_owned(),
            "http://[zz]/announce".to_owned(),
        ] {
            let shown = display_announce_url(&odd);
            assert!(shown.url.starts_with("[redacted:"), "{}", shown.url);
            assert!(shown.host.is_empty(), "{odd} -> {}", shown.host);
            assert!(!shown.url.contains(PASSKEY), "{}", shown.url);
        }
    }

    #[test]
    fn query_passkey_is_redacted_to_scheme_host_and_hash() {
        let out = redacted(&format!(
            "announce to https://t.example:8443/announce?passkey={PASSKEY}&key=ab ok"
        ));
        assert!(!out.contains(PASSKEY), "{out}");
        assert!(
            out.starts_with("announce to https://t.example:8443/[redacted:"),
            "{out}"
        );
        assert!(out.ends_with("] ok"), "{out}");
    }

    #[test]
    fn every_credential_key_is_redacted_case_insensitively() {
        for key in CREDENTIAL_KEYS {
            let upper = key.to_ascii_uppercase();
            for k in [key.to_string(), upper] {
                let out = redacted(&format!("http://t.example/a?x=1&{k}=SECRETVALUE"));
                assert!(!out.contains("SECRETVALUE"), "{k}: {out}");
            }
        }
    }

    #[test]
    fn passkey_path_segment_is_redacted() {
        for url in [
            format!("http://t.example/{PASSKEY}/announce"),
            format!("udp://t.example:6969/announce/{PASSKEY}"),
            "https://t.example/announce/AbCdEfGhIjKlMnOpQrStUvWxYz012345".to_string(),
        ] {
            let out = redacted(&url);
            assert!(out.contains("/[redacted:"), "{url} -> {out}");
            assert!(!out.contains("/announce"), "{url} -> {out}");
        }
    }

    #[test]
    fn userinfo_is_redacted() {
        let out = redacted("http://alice:hunter2@t.example/announce");
        assert!(!out.contains("hunter2") && !out.contains("alice"), "{out}");
        assert!(out.starts_with("http://t.example/[redacted:"), "{out}");
    }

    #[test]
    fn ordinary_urls_pass_through_borrowed_or_unchanged() {
        assert!(matches!(redact_urls("no url here"), Cow::Borrowed(_)));
        for s in [
            "udp://tracker.example:6969/announce?peer_id=x&key=ab12&port=1",
            "see https://example.com/docs/page.html.",
            "odd ://thing and 1://x",
        ] {
            assert_eq!(redacted(s), s);
        }
    }

    #[test]
    fn hash_is_stable_and_distinguishes_urls_on_one_host() {
        let a = redacted(&format!("http://t.example/announce?passkey={PASSKEY}"));
        let b = redacted("http://t.example/announce?passkey=ffffffffffffffffffffffffffffffff");
        assert_eq!(
            a,
            redacted(&format!("http://t.example/announce?passkey={PASSKEY}"))
        );
        assert_ne!(a, b);
        assert_eq!(a.len(), "http://t.example/[redacted:12345678]".len(), "{a}");
    }

    #[test]
    fn url_ends_at_json_string_and_trailing_punctuation() {
        let out = redacted(&format!(
            r#"{{"message":"(http://t.example/a?passkey={PASSKEY}).","next":"x"}}"#
        ));
        assert!(!out.contains(PASSKEY), "{out}");
        assert!(out.contains("(http://t.example/[redacted:"), "{out}");
        assert!(out.ends_with(r#"]).","next":"x"}"#), "{out}");
    }

    #[test]
    fn url_nested_in_another_urls_query_is_redacted() {
        let secret = "SECRETVALUE";
        for url in [
            format!("http://proxy/r?u=https://t.example/announce?passkey={secret}"),
            format!("http://proxy/r#u=https://t.example/announce?passkey={secret}"),
            format!("http://a/r?u=http://b/r?v=https://t.example/a?token={secret}"),
        ] {
            let out = redacted(&format!("fetch {url} done"));
            assert!(!out.contains(secret), "{url} -> {out}");
            assert!(out.starts_with("fetch http://"), "{out}");
            assert!(out.ends_with("] done"), "{out}");
        }
        let plain = "http://proxy/r?u=https://example.com/docs?page=2";
        assert_eq!(redacted(plain), plain);
    }

    /// A chain of `n` URLs, each nested unencoded in the query of the one before.
    fn url_chain(n: usize) -> String {
        (0..n)
            .map(|i| format!("http://h{i}/r"))
            .collect::<Vec<_>>()
            .join("?u=")
    }

    #[test]
    fn nesting_up_to_the_cap_is_inspected_and_deeper_fails_closed() {
        let within = url_chain(MAX_URL_NESTING + 1);
        assert_eq!(redacted(&within), within);
        let secret = format!("{within}?passkey=SECRETVALUE");
        assert!(!redacted(&secret).contains("SECRETVALUE"));
        let deeper = url_chain(MAX_URL_NESTING + 2);
        let out = redacted(&deeper);
        assert!(out.starts_with("http://h0/[redacted:"), "{out}");
        assert!(!out.contains("h1"), "{out}");
    }

    #[test]
    fn a_long_run_of_nested_schemes_is_bounded() {
        let line = format!("x {} y", "a://".repeat(16_000));
        let out = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || redacted(&line))
            .expect("spawn")
            .join()
            .expect("no stack overflow");
        assert!(out.starts_with("x a://a:/[redacted:"), "{}", &out[..40]);
        assert!(out.ends_with("] y"), "{out}");
    }

    #[test]
    fn account_keys_trackers_use_are_credentials() {
        for key in ["pid", "uid", "rsskey", "pass", "PASS", "RssKey"] {
            let out = redacted(&format!("http://t.example/announce?{key}=SECRETVALUE&x=1"));
            assert!(!out.contains("SECRETVALUE"), "{key}: {out}");
            assert!(out.starts_with("http://t.example/[redacted:"), "{out}");
        }
        // A key spelled with escapes is the same key.
        let out = redacted("http://t.example/announce?pass%6Bey=SECRETVALUE");
        assert!(!out.contains("SECRETVALUE"), "{out}");
        // Neither is a prefix match: `passage` and `pidgin` are not keys.
        for clean in [
            "http://t.example/a?passage=1",
            "http://t.example/a?pidgin=1",
        ] {
            assert_eq!(redacted(clean), clean);
        }
    }

    #[test]
    fn a_percent_encoded_url_is_judged_by_what_it_decodes_to() {
        let secret = "SECRETVALUE";
        for line in [
            // Alone in a line, encoded once and twice.
            format!("fetch https%3A%2F%2Ft.example%2Fannounce%3Fpasskey%3D{secret} done"),
            format!("fetch https%3a%2f%2ft.example%2fannounce%3fpasskey%3d{secret} done"),
            format!("fetch https%253A%252F%252Ft.example%252Fa%253Fpasskey%253D{secret} done"),
            // Nested in another URL's query, encoded once and twice.
            format!("fetch http://proxy/r?u=https%3A%2F%2Ft.example%2Fa%3Fpasskey%3D{secret} done"),
            format!(
                "fetch http://proxy/r?u=https%253A%252F%252Ft.example%252Fa%253Ftoken%253D{secret} \
                 done"
            ),
            // A credential key behind an encoded `&`.
            format!("fetch http://t.example/a?x=1%26passkey%3D{secret} done"),
        ] {
            let out = redacted(&line);
            assert!(!out.contains(secret), "{line} -> {out}");
            assert!(out.starts_with("fetch "), "{out}");
            assert!(out.ends_with("] done"), "{line} -> {out}");
        }
        // An encoded URL carrying nothing is left alone.
        let plain = "see https%3A%2F%2Fexample.com%2Fdocs and http://p/r?u=https%3A%2F%2Fe.com%2Fa";
        assert_eq!(redacted(plain), plain);
    }

    #[test]
    fn libtorrent_log_lines_keep_only_the_host_of_a_tracker_url() {
        // libtorrent quotes announce URLs in whatever shape the tracker uses;
        // a short key the credential rules do not recognise still stays out.
        let line = "==> TRACKER_REQUEST [ url: https://t.example/announce/Ab-_x9Qz?x=1 ]";
        let out = redact_urls_host_only(line);
        assert!(!out.contains("Ab-_x9Qz"), "{out}");
        assert!(
            out.starts_with("==> TRACKER_REQUEST [ url: https://t.example/[redacted:"),
            "{out}"
        );
        // A bare announce URL says nothing about the account.
        let bare = "==> TRACKER_REQUEST [ url: udp://t.example:6969/announce ]";
        assert_eq!(redact_urls_host_only(bare), bare);
        // And so does an encoded one.
        let encoded = "u=https%3A%2F%2Ft.example%2Fannounce%2FAb-_x9Qz";
        assert!(!redact_urls_host_only(encoded).contains("Ab-_x9Qz"));
    }

    #[test]
    fn the_daemon_layer_holds_libtorrent_messages_to_the_host_only_rule() {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::registry().with(fmt_layer(buf.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                target: "torrentd_engine::handler::log",
                "==> TRACKER_REQUEST [ url: https://t.example/announce?uk=abc123 ]"
            );
            tracing::info!(target: "torrentd::other", "see https://t.example/docs?page=2");
        });
        let out = String::from_utf8(buf.0.lock().expect("buffer lock").clone()).expect("utf8");
        assert!(!out.contains("abc123"), "{out}");
        assert!(out.contains("https://t.example/[redacted:"), "{out}");
        // Other targets keep the credential rules, and a clean URL whole.
        assert!(out.contains("https://t.example/docs?page=2"), "{out}");
    }

    #[test]
    fn the_daemon_layer_holds_tracker_warnings_to_the_host_only_rule() {
        // A UUID path passkey is no credential shape `redact_urls` knows, but
        // libtorrent quotes the announce URL in a tracker warning's and a
        // scrape failure's message, which `handlers::warning` logs as
        // `error.cause` under this target.
        const UUID: &str = "6f1c2a9e-0d4b-4c1e-9a77-3b2f5e8d1c40";
        let url = format!("https://t.example/{UUID}/announce");
        let buf = Buf::default();
        let subscriber = tracing_subscriber::registry().with(fmt_layer(buf.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                target: "torrentd_engine::handler::tracker",
                infohash = "aa",
                kind = "warning",
                error.code = 0,
                error.cause = %format!("{url} warning: slow down"),
                "tracker warning",
            );
            tracing::debug!(
                target: "torrentd_engine::handler::tracker",
                kind = "scrape_failed",
                error.cause = %format!("{url} scrape failed: timed out"),
                "tracker warning",
            );
        });
        let out = buf.text();
        assert!(!out.contains(UUID), "{out}");
        for line in out.lines() {
            let line: serde_json::Value = serde_json::from_str(line).expect("a JSON line");
            let cause = line["error.cause"].as_str().expect("error.cause");
            assert!(cause.starts_with("https://t.example/[redacted:"), "{cause}");
        }
        assert_eq!(out.lines().count(), 2, "{out}");
    }

    #[test]
    fn redacted_output_is_a_fixed_point() {
        let once = redacted(&format!("udp://t.example/{PASSKEY}/announce"));
        assert_eq!(redacted(&once), once);
    }

    #[test]
    fn the_daemon_layer_redacts_message_event_fields_and_span_fields() {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::registry().with(fmt_layer(buf.clone()));
        let url = format!("https://t.example/announce?passkey={PASSKEY}");
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("announce", tracker = %url);
            let _enter = span.enter();
            tracing::info!(tracker = %url, "==> TRACKER_REQUEST [ url: {url} ]");
        });
        let out = buf.text();
        assert!(!out.contains(PASSKEY), "{out}");
        let line: serde_json::Value = serde_json::from_str(out.trim()).expect("one JSON line");
        let redacted_url = redacted(&url);
        assert_eq!(line["tracker"], redacted_url.as_str());
        assert_eq!(line["span"]["tracker"], redacted_url.as_str());
        assert_eq!(
            line["message"],
            format!("==> TRACKER_REQUEST [ url: {redacted_url} ]").as_str()
        );
    }
}
