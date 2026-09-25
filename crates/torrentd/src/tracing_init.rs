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
//! alphanumerics (the shape of a passkey embedded in the path). Such a URL is
//! replaced by its scheme and host plus a marker holding a short hash of the
//! whole URL:
//!
//! ```text
//! https://tracker.example/announce?passkey=0123…  ->  https://tracker.example/[redacted:1a2b3c4d]
//! ```
//!
//! The hash is stable across runs, so two announce URLs on one host stay
//! distinguishable in a log without the secret. URLs that carry none of these
//! pass through unchanged. `CONTRIBUTING.md` § Reporting bugs promises this to
//! bug reporters; change the two together.

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
/// ASCII-case-insensitively. `key`, which libtorrent adds to every announce, is
/// a per-session random value and deliberately absent.
const CREDENTIAL_KEYS: &[&str] = &[
    "passkey",
    "apikey",
    "api_key",
    "authkey",
    "torrent_pass",
    "token",
];

/// A path segment at least this long and wholly ASCII-alphanumeric is treated
/// as an embedded passkey (`/<32 hex>/announce`, `/announce/<32 alnum>`).
const PATH_SECRET_MIN_LEN: usize = 32;

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
        writer.write_str(&redact_urls(&line))
    }
}

/// Replace every credential-carrying URL in `text` with its redacted form.
/// Borrows when `text` holds no URL at all, which is most lines.
fn redact_urls(text: &str) -> Cow<'_, str> {
    if !text.contains("://") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(sep) = rest.find("://") {
        let before = &rest[..sep];
        let mut start = before.trim_end_matches(is_scheme_char).len();
        // A scheme starts with a letter; skip digits or `+-.` glued before it.
        match before[start..].find(|c: char| c.is_ascii_alphabetic()) {
            Some(skip) => start += skip,
            None => {
                out.push_str(&rest[..sep + 3]);
                rest = &rest[sep + 3..];
                continue;
            }
        }
        let tail = &rest[sep + 3..];
        let end = sep + 3 + tail.find(is_url_terminator).unwrap_or(tail.len());
        let end = start + trim_trailing_punctuation(&rest[start..end]).len();
        let url = &rest[start..end];
        out.push_str(&rest[..start]);
        match redact_url(url, sep - start) {
            Some(redacted) => out.push_str(&redacted),
            None => out.push_str(url),
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    Cow::Owned(out)
}

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

/// Where a URL embedded in a formatted line ends. `"` and `\` end it because
/// the line is JSON: a URL never spans a string boundary or an escape.
fn is_url_terminator(c: char) -> bool {
    c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\' | '<' | '>' | '\'' | '`')
}

/// Drop prose punctuation glued to the end of a URL (`… see http://x/a.`),
/// and a closing bracket the URL itself never opened (`(http://x/a)`).
fn trim_trailing_punctuation(url: &str) -> &str {
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
/// `scheme_len` is the byte length of the scheme before `://`.
fn redact_url(url: &str, scheme_len: usize) -> Option<String> {
    let scheme = &url[..scheme_len];
    let after = &url[scheme_len + 3..];
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..authority_end];
    let (userinfo, host) = match authority.rsplit_once('@') {
        Some((userinfo, host)) => (Some(userinfo), host),
        None => (None, authority),
    };
    let rest = &after[authority_end..];
    let rest = rest.split('#').next().unwrap_or_default();
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    };

    let secret_in_path = path.split('/').any(|seg| {
        seg.len() >= PATH_SECRET_MIN_LEN && seg.bytes().all(|b| b.is_ascii_alphanumeric())
    });
    let secret_in_query = query.split(['&', ';']).any(|pair| {
        let key = pair.split('=').next().unwrap_or_default();
        CREDENTIAL_KEYS.iter().any(|k| key.eq_ignore_ascii_case(k))
    });
    if userinfo.is_none() && !secret_in_path && !secret_in_query {
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
    use std::io;
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;

    const PASSKEY: &str = "0123456789abcdef0123456789abcdef";

    fn redacted(s: &str) -> String {
        redact_urls(s).into_owned()
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
            "udp://tracker.example:6969/announce?info_hash=x&key=ab12&port=1",
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
    fn redacted_output_is_a_fixed_point() {
        let once = redacted(&format!("udp://t.example/{PASSKEY}/announce"));
        assert_eq!(redacted(&once), once);
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'w> MakeWriter<'w> for Buf {
        type Writer = Buf;
        fn make_writer(&'w self) -> Self::Writer {
            self.clone()
        }
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
        let out = String::from_utf8(buf.0.lock().expect("buffer lock").clone()).expect("utf8");
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
