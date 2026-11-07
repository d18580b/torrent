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
//! named in `redact::CREDENTIAL_KEYS`, or a path segment of 32 or more ASCII
//! alphanumerics (the shape of a passkey embedded in the path), or when a URL
//! nested unencoded after its host is itself credential-carrying, or when it
//! nests URLs more than `redact::MAX_URL_NESTING` deep. Keys are compared after
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
//! fail-closed rule the API applies to announce URLs. [`crate::redact`]
//! implements both rules, for this layer and for the API.
//! `CONTRIBUTING.md` § Reporting bugs promises this to bug reporters; change
//! the two together.
//!
//! # Before the subscriber exists
//!
//! The daemon refuses a config (exit 78), a usage error (exit 2) and a failed
//! subscriber install (exit 70) before [`init`] has installed anything, and
//! those are the lines that explain a crash loop. [`early_error`] writes each
//! as one JSON line on stdout with the subscriber's own keys, in its order:
//! `timestamp` (the same RFC3339 timer), `level`, `message`, `error.kind`,
//! then `target`, and the message passes through the same redaction. The
//! operator subcommands do not use it; they keep their human stderr.

use std::fmt;
use std::io::Write as _;

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
use crate::redact::redact_urls;
use crate::redact::redact_urls_host_only;

/// The targets whose lines quote tracker URLs verbatim, in whatever shape the
/// tracker uses: libtorrent's own log messages
/// (`torrentd_engine::handlers::log_msg`), and the tracker alert lines
/// (`torrentd_engine::handlers::warning`), whose `message()` libtorrent builds
/// from the announce URL. Every URL in them is held to the fail-closed rule
/// the API uses ([`display_announce_url`](crate::redact::display_announce_url))
/// rather than to the credential shapes [`redact_urls`] recognises, so a
/// passkey of any shape (a UUID, a short key, a base64url key) stays out of
/// the log.
const HOST_ONLY_TARGETS: &[&str] = &[
    "torrentd_engine::handler::log",
    "torrentd_engine::handler::tracker",
];

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

/// Install the global subscriber. An install that fails (a global subscriber
/// or `log` logger already set) is an error rather than ignored: ignoring it
/// lost every later log line without a word.
pub fn init(level: LogLevel) -> anyhow::Result<LogReloadHandle> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| level_filter(level));
    let (filter_layer, handle) = reload::Layer::new(filter);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer(std::io::stdout))
        .try_init()
        .map_err(|e| anyhow::anyhow!("install the tracing subscriber: {e}"))?;

    Ok(LogReloadHandle { inner: handle })
}

/// The `error.kind` of a line [`early_error`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyErrorKind {
    /// A configuration the daemon or `--check-config` refuses (exit 78).
    ConfigRefused,
    /// An invocation the daemon cannot run as given (exit 2).
    Usage,
    /// The subscriber [`init`] installs could not be installed (exit 70).
    TracingInitFailed,
}

impl EarlyErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConfigRefused => "config_refused",
            Self::Usage => "usage",
            Self::TracingInitFailed => "tracing_init_failed",
        }
    }
}

/// Write `message` to stdout as one ERROR line in the subscriber's JSON shape,
/// for an error raised before [`init`] installed it, or because it could not.
/// A failed write is ignored: the caller is about to exit with the status that
/// carries the outcome, and there is nowhere left to report it.
pub fn early_error(kind: EarlyErrorKind, message: &str) {
    let line = early_line(kind, message);
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// The line [`early_error`] writes, without the newline.
fn early_line(kind: EarlyErrorKind, message: &str) -> String {
    use tracing_subscriber::fmt::time::FormatTime as _;

    let mut timestamp = String::new();
    // `ChronoUtc` only fails where its writer does, and a `String` does not.
    let _ = ChronoUtc::rfc_3339().format_time(&mut Writer::new(&mut timestamp));
    let json = |s: &str| serde_json::Value::from(s).to_string();
    // Built by hand rather than from a `serde_json::Map`, which sorts its keys
    // without the `preserve_order` feature. The order is the subscriber's for
    // `error!(error.kind = .., "..")`: `flatten_event` writes the event's
    // fields, `message` first, before `target`.
    let line = format!(
        "{{\"timestamp\":{},\"level\":\"ERROR\",\"message\":{},\"error.kind\":{},\"target\":{}}}",
        json(&timestamp),
        json(message),
        json(kind.as_str()),
        json(env!("CARGO_CRATE_NAME")),
    );
    redact_urls(&line).into_owned()
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
    use crate::redact::test_support::redacted;
    use crate::redact::test_support::PASSKEY;

    #[test]
    fn an_early_error_has_the_subscribers_keys_in_its_order() {
        let msg = "failed to load config: \"x\"\nsecond line";
        let line = early_line(EarlyErrorKind::ConfigRefused, msg);
        assert!(!line.contains('\n'), "{line}");
        // The order the subscriber itself writes for the same event.
        let buf = Buf::default();
        let subscriber = tracing_subscriber::registry().with(fmt_layer(buf.clone()));
        torrentd_engine::testing::with_subscriber(subscriber, || {
            tracing::event!(
                target: "torrentd",
                tracing::Level::ERROR,
                error.kind = "config_refused",
                "x"
            );
        });
        let real = buf.text();
        let key_order = |l: &str, keys: &[&str]| -> Vec<String> {
            let mut found: Vec<(usize, String)> = keys
                .iter()
                .map(|k| (l.find(&format!("\"{k}\":")).expect(k), (*k).to_owned()))
                .collect();
            found.sort();
            found.into_iter().map(|(_, k)| k).collect()
        };
        let keys = ["timestamp", "level", "message", "target", "error.kind"];
        assert_eq!(
            key_order(&line, &keys),
            key_order(&real, &keys),
            "{line}\n{real}"
        );
        assert_eq!(
            key_order(&line, &keys),
            ["timestamp", "level", "message", "error.kind", "target"],
            "{line}"
        );
        let v: serde_json::Value = serde_json::from_str(&line).expect("one JSON object");
        assert_eq!(
            v.as_object().expect("an object").len(),
            keys.len(),
            "{line}"
        );
        assert_eq!(v["level"], "ERROR");
        assert_eq!(v["message"], msg);
        assert_eq!(v["target"], "torrentd");
        assert_eq!(v["error.kind"], "config_refused");
        // RFC3339 in UTC, `YYYY-MM-DDTHH:MM:SS[.frac]+00:00`, as the
        // subscriber's own timer writes it.
        let ts = v["timestamp"].as_str().expect("timestamp");
        let b = ts.as_bytes();
        assert!(
            b.len() >= 20
                && b[4] == b'-'
                && b[7] == b'-'
                && b[10] == b'T'
                && b[13] == b':'
                && b[16] == b':'
                && ts.ends_with("+00:00"),
            "{ts}"
        );
    }

    #[test]
    fn an_early_error_names_each_kind() {
        for (kind, name) in [
            (EarlyErrorKind::ConfigRefused, "config_refused"),
            (EarlyErrorKind::Usage, "usage"),
            (EarlyErrorKind::TracingInitFailed, "tracing_init_failed"),
        ] {
            let v: serde_json::Value =
                serde_json::from_str(&early_line(kind, "m")).expect("one JSON object");
            assert_eq!(v["error.kind"], name);
        }
    }

    #[test]
    fn an_early_error_is_redacted_like_every_other_line() {
        let url = format!("https://t.example/announce?passkey={PASSKEY}");
        let line = early_line(EarlyErrorKind::ConfigRefused, &format!("bad tracker {url}"));
        assert!(!line.contains(PASSKEY), "{line}");
        let v: serde_json::Value = serde_json::from_str(&line).expect("one JSON object");
        assert_eq!(
            v["message"],
            format!("bad tracker {}", redacted(&url)).as_str()
        );
    }

    #[test]
    fn the_daemon_layer_holds_libtorrent_messages_to_the_host_only_rule() {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::registry().with(fmt_layer(buf.clone()));
        torrentd_engine::testing::with_subscriber(subscriber, || {
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
        torrentd_engine::testing::with_subscriber(subscriber, || {
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
    fn the_daemon_layer_redacts_message_event_fields_and_span_fields() {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::registry().with(fmt_layer(buf.clone()));
        let url = format!("https://t.example/announce?passkey={PASSKEY}");
        torrentd_engine::testing::with_subscriber(subscriber, || {
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
