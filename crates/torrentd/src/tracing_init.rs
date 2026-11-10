//! Structured-logging bring-up.
//!
//! JSON lines on stdout, one object per event, keys in this order:
//! `timestamp` (RFC3339), `level`, the event's own fields (including
//! `message`) flat at the top (`flatten_event`), `target`, then `span`.
//! `span` is an object holding the current span's `name` and fields, e.g. the
//! `op`/`infohash` an `#[instrument]` attaches; those are nested there, not
//! flat at the top (`with_current_span`). `with_span_list(false)` suppresses
//! the separate `spans` array. Events outside any span have no `span` key.
//! A line inside a span ends with `trace_id` and `span_id`, the
//! OpenTelemetry ids of the innermost span at INFO or above, so it can be
//! joined to its trace; they are there whether or not `[telemetry]` exports
//! anything (`crate::telemetry`). Filter level seeded from config +
//! overridden by RUST_LOG if set.
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
//! # Counting WARN and ERROR events
//!
//! Beside the JSON layer, [`init`] installs a layer that counts every event
//! at `WARN` and `ERROR` into [`LogEventCounts`], a process-wide store the
//! metrics sink reads at scrape time as `torrentd_log_events_total{level,
//! target}`. The subscriber is installed before the sink exists, which is why
//! the counts live here rather than in it. The log filter is the JSON layer's
//! own (a per-layer filter), so an event is counted whatever `log_level` or
//! `RUST_LOG` lets through to the log. `target` is the event's target cut to
//! its first two `::` segments (the crate and its top-level module), and one
//! [`LOG_EVENT_TARGETS`] does not list is counted as `other`, so the series'
//! cardinality is fixed.
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

use std::borrow::Cow;
use std::fmt;
use std::io::Write as _;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

use opentelemetry::trace::SpanId;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry::trace::TraceId;
use opentelemetry_sdk::trace::SdkTracer;
use tracing::dispatcher::WeakDispatch;
use tracing::span;
use tracing::Dispatch;
use tracing::Event;
use tracing::Level;
use tracing::Subscriber;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::reload;
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;

use crate::config::LogLevel;
use crate::redact::redact_urls;
use crate::redact::redact_urls_host_only;
use crate::telemetry::Telemetry;

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
        let ids = ctx.event_scope().and_then(|scope| {
            scope
                .into_iter()
                .find_map(|span| span.extensions().get::<TraceIds>().copied())
        });
        if let Some(ids) = ids {
            ids.splice_into(&mut line);
        }
        writer.write_str(&redact_for_target(event.metadata().target(), &line))
    }
}

/// `text` held to the redaction rule for lines under `target`: the
/// fail-closed host-only rule for a [`HOST_ONLY_TARGETS`] target, the
/// credential shapes for every other. The span exporter holds spans to it
/// too (`crate::telemetry`).
pub(crate) fn redact_for_target<'a>(target: &str, text: &'a str) -> Cow<'a, str> {
    if HOST_ONLY_TARGETS.contains(&target) {
        redact_urls_host_only(text)
    } else {
        redact_urls(text)
    }
}

/// A span's OpenTelemetry trace and span id, kept in its extensions by
/// [`RecordTraceIds`] so the formatter reads them without a dispatcher.
#[derive(Clone, Copy, Debug)]
struct TraceIds {
    trace_id: TraceId,
    span_id: SpanId,
}

impl TraceIds {
    /// Add `trace_id` and `span_id` as the last two keys of `line`, one JSON
    /// object and its newline as the JSON formatter writes it.
    fn splice_into(self, line: &mut String) {
        if let Some(close) = line.rfind('}') {
            line.insert_str(
                close,
                &format!(
                    ",\"trace_id\":\"{}\",\"span_id\":\"{}\"",
                    self.trace_id, self.span_id
                ),
            );
        }
    }
}

/// Records each new span's OpenTelemetry ids into its extensions as
/// [`TraceIds`], once the OpenTelemetry layer beneath it has given the span
/// a context. That context is reachable only through the dispatcher, which
/// an event's formatter cannot reach: `tracing` lends no dispatcher out
/// while it dispatches the event.
#[derive(Default)]
struct RecordTraceIds {
    dispatch: OnceLock<WeakDispatch>,
}

impl<S> Layer<S> for RecordTraceIds
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_register_dispatch(&self, subscriber: &Dispatch) {
        let _ = self.dispatch.set(subscriber.downgrade());
    }

    fn on_new_span(&self, _attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let Some(dispatch) = self.dispatch.get().and_then(WeakDispatch::upgrade) else {
            return;
        };
        // Starts the OpenTelemetry span now rather than at its first use,
        // which is when its ids are drawn.
        let Some(cx) = tracing_opentelemetry::get_otel_context(id, &dispatch) else {
            return;
        };
        let span_context = cx.span().span_context().clone();
        if !span_context.is_valid() {
            return;
        }
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(TraceIds {
                trace_id: span_context.trace_id(),
                span_id: span_context.span_id(),
            });
        }
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

/// Install the global subscriber, its spans traced by `telemetry`'s tracer.
/// An install that fails (a global subscriber or `log` logger already set)
/// is an error rather than ignored: ignoring it lost every later log line
/// without a word.
pub fn init(level: LogLevel, telemetry: &Telemetry) -> anyhow::Result<LogReloadHandle> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| level_filter(level));
    let (handle, subscriber) = subscriber(filter, std::io::stdout, &LOG_EVENTS, telemetry.tracer());
    subscriber
        .try_init()
        .map_err(|e| anyhow::anyhow!("install the tracing subscriber: {e}"))?;
    Ok(handle)
}

/// The daemon's subscriber: the OpenTelemetry layer giving spans at INFO
/// and above their ids (and exporting them, where `tracer`'s provider
/// does), the JSON layer behind the reloadable `filter` writing those ids
/// into each line, and beside them the layer counting WARN and ERROR events
/// into `counts`, which `filter` does not hold back.
fn subscriber<W>(
    filter: EnvFilter,
    writer: W,
    counts: &'static LogEventCounts,
    tracer: SdkTracer,
) -> (LogReloadHandle, impl Subscriber + Send + Sync + 'static)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let (filter, handle) = reload::Layer::new(filter);
    // `RecordTraceIds` above the OpenTelemetry layer, whose `on_new_span`
    // runs first and gives the span the context it reads. The JSON layer
    // reads what it recorded only when an event is formatted.
    let subscriber = tracing_subscriber::registry()
        .with(fmt_layer(writer).with_filter(filter))
        .with(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_tracked_inactivity(false)
                .with_filter(LevelFilter::INFO),
        )
        .with(RecordTraceIds::default())
        .with(CountLogEvents(counts).with_filter(LevelFilter::WARN));
    (LogReloadHandle { inner: handle }, subscriber)
}

/// The `level` values of `torrentd_log_events_total`, in the order
/// [`LogEventCounts`] holds them.
pub const LOG_EVENT_LEVELS: &[&str] = &["warn", "error"];

/// The `target` values of `torrentd_log_events_total`: every crate and
/// top-level module of the daemon that logs at WARN or ERROR, by explicit
/// target or by its module path, then `other` for any target outside them
/// (a dependency's, or a module added since). A test in `metrics_sink` holds
/// this list equal to what the daemon's source logs under.
pub const LOG_EVENT_TARGETS: &[&str] = &[
    "torrentd",
    "torrentd::api_socket",
    "torrentd::auth",
    "torrentd::http",
    "torrentd::metrics",
    "torrentd::panic_hook",
    "torrentd::pool",
    "torrentd::port_forward_monitor",
    "torrentd::profile_registry",
    "torrentd::reload",
    "torrentd::sd_notify",
    "torrentd::signals",
    "torrentd::startup",
    "torrentd::telemetry",
    "torrentd::vpn",
    "torrentd::vpn_monitor",
    "torrentd_engine::alert_loop",
    "torrentd_engine::batch_writer",
    "torrentd_engine::handler",
    "torrentd_engine::registry",
    "torrentd_engine::store",
    "torrentd_pool::adopt",
    "torrentd_pool::drift",
    "torrentd_pool::plan",
    "torrentd_pool::scan",
    "torrentd_pool::store",
    "other",
];

const LOG_EVENT_TARGET_COUNT: usize = LOG_EVENT_TARGETS.len();

/// WARN and ERROR events counted since the process started, by level and
/// target. Process-wide because [`init`] installs the layer that writes it
/// before the metrics sink that reads it exists.
pub struct LogEventCounts([[AtomicU64; LOG_EVENT_TARGET_COUNT]; 2]);

static LOG_EVENTS: LogEventCounts = LogEventCounts::new();

/// The counts the subscriber [`init`] installs writes.
pub fn log_events() -> &'static LogEventCounts {
    &LOG_EVENTS
}

impl LogEventCounts {
    const fn new() -> Self {
        Self([const { [const { AtomicU64::new(0) }; LOG_EVENT_TARGET_COUNT] }; 2])
    }

    fn count(&self, level: &Level, target: &str) {
        let row = match *level {
            Level::WARN => 0,
            Level::ERROR => 1,
            _ => return,
        };
        self.0[row][log_event_target_index(target)].fetch_add(1, Ordering::Relaxed);
    }

    /// Every `(level, target, count)`, each level's targets in
    /// [`LOG_EVENT_TARGETS`]' order, levels in [`LOG_EVENT_LEVELS`]'.
    pub fn snapshot(&self) -> Vec<(&'static str, &'static str, u64)> {
        LOG_EVENT_LEVELS
            .iter()
            .zip(&self.0)
            .flat_map(|(level, row)| {
                LOG_EVENT_TARGETS
                    .iter()
                    .zip(row)
                    .map(move |(target, n)| (*level, *target, n.load(Ordering::Relaxed)))
            })
            .collect()
    }
}

/// `target` cut to its first two `::` segments.
pub(crate) fn log_event_module(target: &str) -> &str {
    match target.match_indices("::").nth(1) {
        Some((at, _)) => &target[..at],
        None => target,
    }
}

/// The index in [`LOG_EVENT_TARGETS`] `target` is counted under.
fn log_event_target_index(target: &str) -> usize {
    let module = log_event_module(target);
    LOG_EVENT_TARGETS
        .iter()
        .position(|t| *t == module)
        .unwrap_or(LOG_EVENT_TARGET_COUNT - 1)
}

/// Counts each event it sees into its [`LogEventCounts`].
struct CountLogEvents(&'static LogEventCounts);

impl<S: Subscriber> Layer<S> for CountLogEvents {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        self.0.count(meta.level(), meta.target());
    }
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
/// It counts into counts of its own, not the process-wide ones.
#[cfg(test)]
pub(crate) fn for_tests<W>(
    level: LogLevel,
    writer: W,
) -> (LogReloadHandle, impl Subscriber + Send + Sync)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    for_tests_traced(level, writer, &Telemetry::ids_only())
}

/// [`for_tests`], its spans traced by `telemetry`'s tracer.
#[cfg(test)]
pub(crate) fn for_tests_traced<W>(
    level: LogLevel,
    writer: W,
    telemetry: &Telemetry,
) -> (LogReloadHandle, impl Subscriber + Send + Sync)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let counts: &'static LogEventCounts = Box::leak(Box::new(LogEventCounts::new()));
    subscriber(level_filter(level), writer, counts, telemetry.tracer())
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
    fn warn_and_error_events_are_counted_by_module_whatever_the_log_level() {
        let counts: &'static LogEventCounts = Box::leak(Box::new(LogEventCounts::new()));
        let buf = Buf::default();
        let (_handle, subscriber) = subscriber(
            level_filter(LogLevel::Error),
            buf.clone(),
            counts,
            Telemetry::ids_only().tracer(),
        );
        torrentd_engine::testing::with_subscriber(subscriber, || {
            tracing::warn!(target: "torrentd::vpn::wireguard", "w1");
            tracing::warn!(target: "torrentd::vpn", "w2");
            tracing::error!(target: "torrentd_engine::handler::listen", "e1");
            tracing::warn!(target: "hyper::proto::h1", "w3");
            tracing::info!(target: "torrentd::vpn", "i1");
            tracing::debug!(target: "torrentd::vpn", "d1");
        });
        let n = |level: &str, target: &str| {
            counts
                .snapshot()
                .into_iter()
                .find(|(l, t, _)| *l == level && *t == target)
                .map(|(_, _, n)| n)
                .unwrap_or_else(|| panic!("no {level}/{target} in the snapshot"))
        };
        assert_eq!(n("warn", "torrentd::vpn"), 2);
        assert_eq!(n("error", "torrentd_engine::handler"), 1);
        assert_eq!(n("warn", "other"), 1);
        let total: u64 = counts.snapshot().iter().map(|(_, _, n)| n).sum();
        assert_eq!(total, 4, "INFO and DEBUG are not counted");
        // The log's own filter held the WARN lines back from the log, not
        // from the count.
        let out = buf.text();
        assert!(out.contains("e1"), "{out}");
        assert!(!out.contains("w1"), "{out}");
        assert_eq!(
            counts.snapshot().len(),
            LOG_EVENT_LEVELS.len() * LOG_EVENT_TARGETS.len()
        );
    }

    #[test]
    fn a_log_event_target_is_cut_to_its_crate_and_module() {
        assert_eq!(
            log_event_module("torrentd::vpn::wireguard"),
            "torrentd::vpn"
        );
        assert_eq!(log_event_module("torrentd::vpn"), "torrentd::vpn");
        assert_eq!(log_event_module("torrentd"), "torrentd");
        assert_eq!(LOG_EVENT_TARGETS.last(), Some(&"other"));
        assert_eq!(
            LOG_EVENT_TARGETS[log_event_target_index("not_ours::x")],
            "other"
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
