//! OpenTelemetry trace export over OTLP, off unless `[telemetry]` is
//! configured.
//!
//! The daemon's `tracing` spans become OpenTelemetry spans through
//! `tracing-opentelemetry`, which `tracing_init` installs whether or not
//! anything is exported: every span gets a trace id and a span id, and every
//! JSON log line inside one carries them. Without `[telemetry]` the tracer
//! provider samples nothing and has no exporter, so ids are generated and
//! nothing else is kept.
//!
//! With `[telemetry]`, spans at INFO and above are batched on a thread of the
//! SDK's own and exported to the collector `[telemetry]` names, with
//! `service.name` torrentd and `service.version` this build's. Each key the
//! section leaves out falls back to the standard environment variable, then
//! to the OpenTelemetry default, as [`Export::resolve`] says.
//!
//! # Redaction
//!
//! Every span passes through [`Redacting`] before it reaches the exporter:
//! its name, its attributes, its events' names and attributes, its links'
//! attributes and its status description are held to the rules the log is
//! (`crate::redact`, `HOST_ONLY_TARGETS` included), so a tracker credential
//! reaches the collector no more than it reaches the log.
//!
//! # Export failures
//!
//! An export that fails drops its batch, is counted in
//! `torrentd_telemetry_export_errors_total`, and is logged at WARN, target
//! `torrentd::telemetry`, at most once a minute (the line says how many it
//! held back). Nothing waits on the collector: spans queue in a bounded
//! buffer that drops when full, and each export is bounded by its client's
//! timeout. [`Telemetry::shutdown`] flushes what is queued at the end of the
//! shutdown drain, bounded by [`SHUTDOWN_FLUSH`].

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context as _;
use opentelemetry::trace::Status;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::Array;
use opentelemetry::KeyValue;
use opentelemetry::StringValue;
use opentelemetry::Value;
use opentelemetry_http::Bytes;
use opentelemetry_http::HttpError;
use opentelemetry_http::Request;
use opentelemetry_http::Response;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_otlp::WithHttpConfig as _;
use opentelemetry_otlp::WithTonicConfig as _;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::Sampler;
use opentelemetry_sdk::trace::SdkTracer;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::trace::SpanData;
use opentelemetry_sdk::trace::SpanExporter;
use opentelemetry_sdk::Resource;
// Logged under this module's path, `torrentd::telemetry`.
use tracing::warn;

use crate::config::OtlpProtocol;
use crate::config::TelemetryConfig;
use crate::tracing_init::redact_for_target;

/// The `service.name` every exported span carries.
pub const SERVICE_NAME: &str = "torrentd";

/// How long [`Telemetry::shutdown`] waits for queued spans to be exported.
pub const SHUTDOWN_FLUSH: Duration = Duration::from_secs(5);

/// The http/protobuf client's timeout for one export, request and response
/// together. The gRPC exporter has its own, `OTEL_EXPORTER_OTLP_TIMEOUT`
/// (10 seconds unless set).
const HTTP_EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of a collector's response the http/protobuf client reads.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// The least time between two WARN lines for failed exports.
const EXPORT_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// The OpenTelemetry defaults, used where neither `[telemetry]` nor the
/// environment names a collector.
const DEFAULT_GRPC_ENDPOINT: &str = "http://localhost:4317";
const DEFAULT_HTTP_ENDPOINT: &str = "http://localhost:4318";

/// What http/protobuf appends to a base endpoint, as the OpenTelemetry
/// specification has `OTEL_EXPORTER_OTLP_ENDPOINT` do.
const HTTP_TRACES_PATH: &str = "/v1/traces";

const ENV_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const ENV_TRACES_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const ENV_PROTOCOL: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";
const ENV_TRACES_PROTOCOL: &str = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL";
const ENV_HEADERS: &str = "OTEL_EXPORTER_OTLP_HEADERS";
const ENV_TRACES_HEADERS: &str = "OTEL_EXPORTER_OTLP_TRACES_HEADERS";

/// Resource attributes `[telemetry]` may not set: the daemon fixes them.
const FIXED_RESOURCE_ATTRIBUTES: &[&str] = &["service.name", "service.version"];

/// `[telemetry]` resolved against the environment: what the exporter is
/// built from.
#[derive(Debug, PartialEq)]
pub struct Export {
    pub protocol: OtlpProtocol,
    /// The URL handed to the exporter, `/v1/traces` included for
    /// http/protobuf.
    pub endpoint: String,
    /// From `headers_file`. Empty, the exporter reads
    /// `OTEL_EXPORTER_OTLP_(TRACES_)HEADERS` itself.
    pub headers: Vec<(String, String)>,
    pub sample_ratio: f64,
    pub resource_attributes: Vec<(String, String)>,
}

impl Export {
    /// Resolve `cfg`, reading the environment through `env`. Each key `cfg`
    /// leaves out falls back as the OpenTelemetry specification orders it:
    ///
    /// - `protocol`: `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`, then
    ///   `OTEL_EXPORTER_OTLP_PROTOCOL`, then `http/protobuf`;
    /// - `otlp_endpoint`: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, used as is,
    ///   then `OTEL_EXPORTER_OTLP_ENDPOINT`, then `localhost:4317` (gRPC) or
    ///   `localhost:4318` (http/protobuf); a base endpoint has `/v1/traces`
    ///   appended for http/protobuf, as `otlp_endpoint` does;
    /// - `headers_file`: `OTEL_EXPORTER_OTLP_TRACES_HEADERS`, then
    ///   `OTEL_EXPORTER_OTLP_HEADERS`, which the exporter reads itself. Both
    ///   a file and a variable are refused rather than merged;
    /// - `sample_ratio`: 1.0.
    pub fn resolve(
        cfg: &TelemetryConfig,
        env: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let env = |k: &str| env(k).filter(|v| !v.trim().is_empty());
        let protocol = match cfg.protocol {
            Some(p) => p,
            None => match env(ENV_TRACES_PROTOCOL)
                .map(|v| (ENV_TRACES_PROTOCOL, v))
                .or_else(|| env(ENV_PROTOCOL).map(|v| (ENV_PROTOCOL, v)))
            {
                Some((var, v)) => {
                    parse_protocol(v.trim()).with_context(|| format!("{var} = {v:?}"))?
                }
                None => OtlpProtocol::HttpProtobuf,
            },
        };

        let base = |url: &str| -> anyhow::Result<String> {
            check_url(url)?;
            Ok(match protocol {
                OtlpProtocol::Grpc => url.to_owned(),
                OtlpProtocol::HttpProtobuf => {
                    format!("{}{HTTP_TRACES_PATH}", url.trim_end_matches('/'))
                }
            })
        };
        let endpoint = if let Some(url) = &cfg.otlp_endpoint {
            base(url).context("otlp_endpoint")?
        } else if let Some(url) = env(ENV_TRACES_ENDPOINT) {
            check_url(&url).with_context(|| ENV_TRACES_ENDPOINT.to_owned())?;
            url
        } else if let Some(url) = env(ENV_ENDPOINT) {
            base(&url).with_context(|| ENV_ENDPOINT.to_owned())?
        } else {
            match protocol {
                OtlpProtocol::Grpc => DEFAULT_GRPC_ENDPOINT.to_owned(),
                OtlpProtocol::HttpProtobuf => format!("{DEFAULT_HTTP_ENDPOINT}{HTTP_TRACES_PATH}"),
            }
        };

        let headers = match &cfg.headers_file {
            Some(path) => {
                if let Some(var) = [ENV_TRACES_HEADERS, ENV_HEADERS]
                    .into_iter()
                    .find(|v| env(v).is_some())
                {
                    anyhow::bail!(
                        "headers_file and {var} are both set; set one, since the exporter would \
                         send both"
                    );
                }
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("headers_file: read {}", path.display()))?;
                parse_headers(&text).with_context(|| format!("headers_file {}", path.display()))?
            }
            None => Vec::new(),
        };

        let sample_ratio = cfg.sample_ratio.unwrap_or(1.0);
        if !(0.0..=1.0).contains(&sample_ratio) {
            anyhow::bail!("sample_ratio = {sample_ratio} is out of range (0.0..=1.0)");
        }

        for key in cfg.resource_attributes.keys() {
            if key.is_empty() {
                anyhow::bail!("resource_attributes: a key is empty");
            }
            if FIXED_RESOURCE_ATTRIBUTES.contains(&key.as_str()) {
                anyhow::bail!(
                    "resource_attributes: {key} is set by the daemon and cannot be overridden"
                );
            }
        }

        Ok(Self {
            protocol,
            endpoint,
            headers,
            sample_ratio,
            resource_attributes: cfg
                .resource_attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    /// The resource every exported span carries. `OTEL_RESOURCE_ATTRIBUTES`
    /// is read beneath `resource_attributes`, which wins a shared key, and
    /// `service.name` and `service.version` win over both.
    fn resource(&self) -> Resource {
        Resource::builder()
            .with_attributes(
                self.resource_attributes
                    .iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            )
            .with_service_name(SERVICE_NAME)
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build()
    }

    /// The OTLP exporter. For gRPC, built where a tokio runtime is entered:
    /// its channel's background task is spawned on it.
    fn exporter(&self) -> anyhow::Result<opentelemetry_otlp::SpanExporter> {
        let built = match self.protocol {
            OtlpProtocol::Grpc => {
                let mut builder = opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .with_endpoint(self.endpoint.clone());
                if self.endpoint.starts_with("https:") {
                    builder = builder.with_tls_config(
                        opentelemetry_otlp::tonic_types::transport::ClientTlsConfig::new()
                            .with_enabled_roots(),
                    );
                }
                if !self.headers.is_empty() {
                    let headers: HashMap<String, String> = self.headers.iter().cloned().collect();
                    let map =
                        reqwest::header::HeaderMap::try_from(&headers).context("export headers")?;
                    builder = builder.with_metadata(
                        opentelemetry_otlp::tonic_types::metadata::MetadataMap::from_headers(map),
                    );
                }
                builder.build()
            }
            OtlpProtocol::HttpProtobuf => {
                let mut builder = opentelemetry_otlp::SpanExporter::builder()
                    .with_http()
                    .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                    .with_endpoint(self.endpoint.clone())
                    .with_http_client(BlockingHttp::new()?);
                if !self.headers.is_empty() {
                    builder = builder.with_headers(self.headers.iter().cloned().collect());
                }
                builder.build()
            }
        };
        built.with_context(|| {
            format!(
                "build the {} OTLP exporter for {}",
                self.protocol.as_str(),
                redact_for_target("torrentd::telemetry", &self.endpoint)
            )
        })
    }
}

fn parse_protocol(v: &str) -> anyhow::Result<OtlpProtocol> {
    match v {
        "grpc" => Ok(OtlpProtocol::Grpc),
        "http/protobuf" => Ok(OtlpProtocol::HttpProtobuf),
        _ => anyhow::bail!("not a protocol the daemon exports with: use grpc or http/protobuf"),
    }
}

fn check_url(url: &str) -> anyhow::Result<()> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        anyhow::bail!(
            "{:?} is not an http:// or https:// URL",
            redact_for_target("torrentd::telemetry", url)
        );
    }
    Ok(())
}

/// Parse a headers file: `name=value` lines, blank lines and `#` comments
/// skipped. Names are lowercased, as gRPC metadata requires. An error names
/// the line, never its value, which is a credential.
fn parse_headers(text: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let n = i + 1;
        let Some((name, value)) = line.split_once('=') else {
            anyhow::bail!("line {n} is not name=value");
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            anyhow::bail!("line {n}: the header name is not a token of letters, digits, - _ .");
        }
        if !value
            .bytes()
            .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
        {
            anyhow::bail!("line {n}: the value of {name} holds a character a header cannot");
        }
        out.push((name, value.to_owned()));
    }
    Ok(out)
}

/// The tracer provider, and whether it exports.
pub struct Telemetry {
    provider: SdkTracerProvider,
    exporting: bool,
}

impl Telemetry {
    /// Export as `cfg` says, or generate ids alone where it is `None`. Where
    /// `cfg` exports over gRPC, call this inside an entered tokio runtime.
    pub fn new(cfg: Option<&TelemetryConfig>) -> anyhow::Result<Self> {
        let Some(cfg) = cfg else {
            return Ok(Self::ids_only());
        };
        let export = Export::resolve(cfg, |k| std::env::var(k).ok()).context("[telemetry]")?;
        let exporter = Redacting::new(export.exporter()?, &EXPORT_ERRORS);
        let provider = SdkTracerProvider::builder()
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                export.sample_ratio,
            ))))
            .with_resource(export.resource())
            .with_batch_exporter(exporter)
            .build();
        Ok(Self {
            provider,
            exporting: true,
        })
    }

    /// No exporter and no sampling: spans get ids, and nothing is recorded.
    pub fn ids_only() -> Self {
        Self {
            provider: SdkTracerProvider::builder()
                .with_sampler(Sampler::AlwaysOff)
                .build(),
            exporting: false,
        }
    }

    /// A provider exporting each span as it ends, through [`Redacting`], to
    /// `exporter`.
    #[cfg(test)]
    pub(crate) fn for_tests<E: SpanExporter + 'static>(
        exporter: E,
        errors: &'static ExportErrors,
    ) -> Self {
        Self {
            provider: SdkTracerProvider::builder()
                .with_simple_exporter(Redacting::new(exporter, errors))
                .build(),
            exporting: true,
        }
    }

    pub fn tracer(&self) -> SdkTracer {
        self.provider.tracer(SERVICE_NAME)
    }

    /// Whether spans are exported.
    pub fn is_exporting(&self) -> bool {
        self.exporting
    }

    /// Export what is queued and stop, waiting at most `timeout`. Blocks; on
    /// a runtime, call it from a blocking task, since the gRPC exporter
    /// needs the runtime's workers to send. A failure is logged at WARN.
    pub fn shutdown(&self, timeout: Duration) {
        if !self.exporting {
            return;
        }
        if let Err(e) = self.provider.shutdown_with_timeout(timeout) {
            warn!(
                error.kind = "span_flush_failed",
                error.cause = %e,
                "spans still queued at shutdown were not all exported",
            );
        }
    }
}

/// Failed exports: the count `torrentd_telemetry_export_errors_total`
/// exports, and the state that rate-limits their WARN.
pub struct ExportErrors {
    count: AtomicU64,
    last_warn: Mutex<Option<Instant>>,
    held_back: AtomicU64,
}

static EXPORT_ERRORS: ExportErrors = ExportErrors::new();

/// The failed exports the daemon's exporter counts into.
pub fn export_errors() -> &'static ExportErrors {
    &EXPORT_ERRORS
}

impl ExportErrors {
    pub(crate) const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            last_warn: Mutex::new(None),
            held_back: AtomicU64::new(0),
        }
    }

    /// Failed exports since the process started.
    pub fn total(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Count a failed export, and log it unless one was logged within
    /// [`EXPORT_WARN_INTERVAL`].
    fn record(&self, error: &dyn std::fmt::Display) {
        self.count.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        {
            let mut last = self.last_warn.lock().unwrap_or_else(|p| p.into_inner());
            if last.is_some_and(|t| now.duration_since(t) < EXPORT_WARN_INTERVAL) {
                self.held_back.fetch_add(1, Ordering::Relaxed);
                return;
            }
            *last = Some(now);
        }
        let held_back = self.held_back.swap(0, Ordering::Relaxed);
        warn!(
            error.kind = "span_export_failed",
            error.cause = %error,
            held_back,
            "span export failed; the batch is dropped (held_back counts failures since the last \
             line that were not logged)",
        );
    }
}

/// A span exporter that redacts every span before handing it to the one it
/// wraps, and counts the exports that fail.
#[derive(Debug)]
pub(crate) struct Redacting<E> {
    inner: E,
    errors: &'static ExportErrors,
}

impl std::fmt::Debug for ExportErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportErrors")
            .field("count", &self.total())
            .finish()
    }
}

impl<E> Redacting<E> {
    pub(crate) fn new(inner: E, errors: &'static ExportErrors) -> Self {
        Self { inner, errors }
    }
}

impl<E: SpanExporter> SpanExporter for Redacting<E> {
    async fn export(&self, mut batch: Vec<SpanData>) -> OTelSdkResult {
        for span in &mut batch {
            redact_span(span);
        }
        let result = self.inner.export(batch).await;
        if let Err(e) = &result {
            self.errors.record(e);
        }
        result
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

/// The `target` attribute `tracing-opentelemetry` puts on a span and on each
/// event: the `tracing` target it was emitted under.
fn target_of(attributes: &[KeyValue]) -> Option<&str> {
    attributes.iter().find_map(|kv| match &kv.value {
        Value::String(s) if kv.key.as_str() == "target" => Some(s.as_str()),
        _ => None,
    })
}

/// Hold every string `span` carries to the log's redaction rules for its
/// target, or for the event's own where an event names one.
fn redact_span(span: &mut SpanData) {
    let target = target_of(&span.attributes).unwrap_or_default().to_owned();
    redact_cow(&mut span.name, &target);
    redact_attributes(&mut span.attributes, &target);
    if let Status::Error { description } = &mut span.status {
        redact_cow(description, &target);
    }
    for event in &mut span.events.events {
        let target = target_of(&event.attributes)
            .map(str::to_owned)
            .unwrap_or_else(|| target.clone());
        redact_cow(&mut event.name, &target);
        redact_attributes(&mut event.attributes, &target);
    }
    for link in &mut span.links.links {
        redact_attributes(&mut link.attributes, &target);
    }
}

fn redact_cow(text: &mut Cow<'static, str>, target: &str) {
    if let Cow::Owned(redacted) = redact_for_target(target, text) {
        *text = Cow::Owned(redacted);
    }
}

fn redact_attributes(attributes: &mut [KeyValue], target: &str) {
    for kv in attributes {
        match &mut kv.value {
            Value::String(s) => redact_string_value(s, target),
            Value::Array(Array::String(items)) => {
                for s in items {
                    redact_string_value(s, target);
                }
            }
            _ => {}
        }
    }
}

fn redact_string_value(s: &mut StringValue, target: &str) {
    if let Cow::Owned(redacted) = redact_for_target(target, s.as_str()) {
        *s = StringValue::from(redacted);
    }
}

/// The http/protobuf exporter's client: the workspace's reqwest, blocking,
/// since the batch span processor exports from a thread of its own.
#[derive(Debug)]
struct BlockingHttp(reqwest::blocking::Client);

impl BlockingHttp {
    /// Built on a thread of its own: a blocking reqwest client refuses to be
    /// built where a tokio runtime is entered, and `main` enters one before
    /// the exporter is built.
    fn new() -> anyhow::Result<Self> {
        let client = std::thread::Builder::new()
            .name("torrentd-otlp-init".into())
            .spawn(|| {
                reqwest::blocking::Client::builder()
                    .timeout(HTTP_EXPORT_TIMEOUT)
                    .build()
            })
            .context("spawn the thread that builds the OTLP HTTP client")?
            .join()
            .map_err(|_| anyhow::anyhow!("building the OTLP HTTP client panicked"))?
            .context("build the OTLP HTTP client")?;
        Ok(Self(client))
    }

    fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        use std::io::Read as _;

        let request = reqwest::blocking::Request::try_from(request.map(|b| b.to_vec()))?;
        let mut response = self.0.execute(request)?;
        let status = response.status();
        let headers = std::mem::take(response.headers_mut());
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err("the collector's response is over 4 MiB".into());
        }
        let mut out = Response::new(Bytes::from(body));
        *out.status_mut() = status;
        *out.headers_mut() = headers;
        Ok(out)
    }
}

// `HttpClient` is an `async_trait` trait; this is the signature that macro
// writes, spelled out rather than taking the macro on as a dependency.
impl opentelemetry_http::HttpClient for BlockingHttp {
    fn send_bytes<'life0, 'async_trait>(
        &'life0 self,
        request: Request<Bytes>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Bytes>, HttpError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.send(request) })
    }
}

#[cfg(test)]
mod tests;
