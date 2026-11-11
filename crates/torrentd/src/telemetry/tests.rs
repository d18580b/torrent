use std::collections::BTreeMap;

use opentelemetry_sdk::error::OTelSdkError;
use opentelemetry_sdk::trace::InMemorySpanExporter;

use super::*;
use crate::config::LogLevel;
use crate::redact::test_support::PASSKEY;
use crate::tracing_init::for_tests_traced;
use crate::tracing_init::Buf;

fn cfg() -> TelemetryConfig {
    TelemetryConfig {
        otlp_endpoint: None,
        protocol: None,
        sample_ratio: None,
        resource_attributes: BTreeMap::new(),
        headers_file: None,
    }
}

fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |k| {
        vars.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| (*v).to_owned())
    }
}

fn lines(buf: &Buf) -> Vec<serde_json::Value> {
    buf.text()
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect()
}

fn is_hex(v: &serde_json::Value, len: usize) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit()) && s.bytes().any(|b| b != b'0')
    })
}

#[test]
fn a_line_inside_a_span_carries_its_trace_and_span_id_with_nothing_exported() {
    let buf = Buf::default();
    let (_handle, subscriber) = crate::tracing_init::for_tests(LogLevel::Info, buf.clone());
    torrentd_engine::testing::with_subscriber(subscriber, || {
        tracing::info!("outside");
        let outer = tracing::info_span!("outer", op = "x");
        let _outer = outer.enter();
        tracing::info!("in outer");
        let inner = tracing::info_span!("inner");
        let _inner = inner.enter();
        tracing::info!("in inner");
        // A span below the OpenTelemetry layer's INFO floor has no ids of
        // its own: its lines carry the nearest span's.
        let debug = tracing::debug_span!("debug");
        let _debug = debug.enter();
        tracing::info!("in debug");
    });
    let l = lines(&buf);
    assert_eq!(l.len(), 4, "{}", buf.text());
    assert!(l[0].get("trace_id").is_none(), "{}", l[0]);
    assert!(l[0].get("span_id").is_none(), "{}", l[0]);
    for line in &l[1..] {
        assert!(is_hex(&line["trace_id"], 32), "{line}");
        assert!(is_hex(&line["span_id"], 16), "{line}");
        assert_eq!(line["trace_id"], l[1]["trace_id"], "one trace");
    }
    assert_ne!(l[1]["span_id"], l[2]["span_id"]);
    assert_eq!(l[2]["span_id"], l[3]["span_id"]);
    // Still the JSON layer's shape: the ids are added at the top level,
    // after everything it writes.
    assert_eq!(l[1]["span"]["op"], "x");
    assert_eq!(l[1]["message"], "in outer");
}

#[test]
fn a_warn_line_carries_the_ids_of_spans_its_log_level_hides() {
    let buf = Buf::default();
    let (handle, subscriber) = crate::tracing_init::for_tests(LogLevel::Warn, buf.clone());
    torrentd_engine::testing::with_subscriber(subscriber, || {
        // `log_level` = warn keeps these INFO spans out of the JSON layer;
        // their ids must still reach the lines inside them.
        let outer = tracing::info_span!(target: "torrentd", "outer");
        let _outer = outer.enter();
        tracing::warn!(target: "torrentd", "warn in outer");
        let inner = tracing::info_span!(target: "torrentd", "inner");
        let _inner = inner.enter();
        tracing::error!(target: "torrentd", "error in inner");
        // As after a SIGHUP raising it from info.
        handle.set_filter(LogLevel::Error, None).expect("reload");
        tracing::warn!(target: "torrentd", "held back");
        tracing::error!(target: "torrentd", "error after reload");
    });
    let l = lines(&buf);
    assert_eq!(l.len(), 3, "{}", buf.text());
    for line in &l {
        assert!(is_hex(&line["trace_id"], 32), "{line}");
        assert!(is_hex(&line["span_id"], 16), "{line}");
        assert_eq!(line["trace_id"], l[0]["trace_id"], "one trace");
    }
    assert_ne!(l[0]["span_id"], l[1]["span_id"]);
    assert_eq!(l[1]["span_id"], l[2]["span_id"]);
    assert_eq!(l[2]["message"], "error after reload");
}

/// Every credential shape `crate::redact`'s tests hold the log to: the
/// shapes it recognises anywhere, and those it cuts only under a
/// `HOST_ONLY_TARGETS` target.
fn corpus() -> (Vec<String>, Vec<String>) {
    let anywhere = vec![
        format!("https://t.example/announce?passkey={PASSKEY}"),
        format!("http://t.example/{PASSKEY}/announce"),
        format!("udp://t.example:6969/announce/{PASSKEY}"),
        format!("https://user:{PASSKEY}@t.example/announce"),
        format!("https%3A%2F%2Ft.example%2Fannounce%3Fpasskey%3D{PASSKEY}"),
    ];
    let host_only = vec![
        "https://t.example/announce/2f1c9a3e-6b1d-4c1e-9f0a-1234567890ab".to_owned(),
        "https://t.example/announce?uk=Ab-_x9Qz".to_owned(),
        "https://t.example/a1b2c3d4e5/announce".to_owned(),
    ];
    (anywhere, host_only)
}

const HOST_ONLY_LEAKS: &[&str] = &["2f1c9a3e", "Ab-_x9Qz", "a1b2c3d4e5"];

#[test]
fn no_credential_reaches_an_exported_span() {
    static ERRORS: ExportErrors = ExportErrors::new();
    let exporter = InMemorySpanExporter::default();
    let telemetry = Telemetry::for_tests(exporter.clone(), &ERRORS);
    let buf = Buf::default();
    let (_handle, subscriber) = for_tests_traced(LogLevel::Info, buf.clone(), &telemetry);
    let (anywhere, host_only) = corpus();
    torrentd_engine::testing::with_subscriber(subscriber, || {
        for url in &anywhere {
            // The name, a field, a field recorded later, an event's message
            // and fields, and the error status.
            let span = tracing::info_span!(
                target: "torrentd::http",
                "announce",
                otel.name = %format!("announce {url}"),
                tracker = %url,
                late = tracing::field::Empty,
                otel.status_code = "error",
                otel.status_description = %format!("failed: {url}"),
            );
            span.record("late", url.as_str());
            let _e = span.enter();
            tracing::info!(target: "torrentd::http", tracker = %url, "==> {url}");
            tracing::event!(
                target: "torrentd::http",
                tracing::Level::ERROR,
                error.cause = %url,
                "announce failed",
            );
        }
        for url in &host_only {
            let span = tracing::info_span!(
                target: "torrentd_engine::handler::tracker",
                "tracker",
                tracker = %url,
            );
            let _e = span.enter();
            tracing::event!(
                target: "torrentd_engine::handler::tracker",
                tracing::Level::INFO,
                error.cause = %format!("{url} warning: slow down"),
                "tracker warning {url}",
            );
        }
        // An event under a host-only target inside a span under another.
        let span = tracing::info_span!(target: "torrentd::http", "outer");
        let _e = span.enter();
        tracing::info!(
            target: "torrentd_engine::handler::log",
            "==> TRACKER_REQUEST [ url: {} ]",
            host_only[1],
        );
    });
    let spans = exporter.get_finished_spans().expect("the exported spans");
    assert_eq!(spans.len(), anywhere.len() + host_only.len() + 1);
    let dump = format!("{spans:?}");
    assert!(!dump.contains(PASSKEY), "{dump}");
    for leak in HOST_ONLY_LEAKS {
        assert!(!dump.contains(leak), "{leak} in {dump}");
    }
    // Redacted, not dropped: the marker the log writes is there instead.
    assert!(dump.contains("https://t.example/[redacted:"), "{dump}");
    assert!(spans
        .iter()
        .any(|s| s.name.starts_with("announce https://t.example/[redacted:")));
    assert_eq!(ERRORS.total(), 0);

    // A log line inside a span names the trace that span was exported in.
    let exported: Vec<String> = spans
        .iter()
        .map(|s| s.span_context.trace_id().to_string())
        .collect();
    let logged = lines(&buf);
    assert!(!logged.is_empty());
    for line in &logged {
        let trace_id = line["trace_id"].as_str().expect("a trace_id");
        assert!(exported.iter().any(|t| t == trace_id), "{line}");
    }
}

/// An exporter whose every export fails.
#[derive(Debug)]
struct Refusing;

impl SpanExporter for Refusing {
    async fn export(&self, _batch: Vec<SpanData>) -> OTelSdkResult {
        Err(OTelSdkError::InternalFailure("collector refused".into()))
    }
}

#[test]
fn a_failed_export_is_counted_and_never_reaches_the_caller() {
    static ERRORS: ExportErrors = ExportErrors::new();
    let telemetry = Telemetry::for_tests(Refusing, &ERRORS);
    let (_handle, subscriber) = for_tests_traced(LogLevel::Info, Buf::default(), &telemetry);
    torrentd_engine::testing::with_subscriber(subscriber, || {
        for _ in 0..3 {
            let span = tracing::info_span!("work");
            let _e = span.enter();
            tracing::info!("done");
        }
    });
    assert_eq!(ERRORS.total(), 3);
}

#[test]
fn failed_exports_are_logged_at_most_once_a_minute() {
    let errors = ExportErrors::new();
    let buf = Buf::default();
    let (_handle, subscriber) = crate::tracing_init::for_tests(LogLevel::Info, buf.clone());
    torrentd_engine::testing::with_subscriber(subscriber, || {
        for _ in 0..4 {
            errors.record(&"connection refused");
        }
        // As if the interval had passed: the next failure is logged, with
        // the count of those held back.
        *errors.last_warn.lock().expect("lock") = Instant::now().checked_sub(EXPORT_WARN_INTERVAL);
        errors.record(&"connection refused");
    });
    assert_eq!(errors.total(), 5);
    let l = lines(&buf);
    assert_eq!(l.len(), 2, "{}", buf.text());
    for line in &l {
        assert_eq!(line["level"], "WARN");
        assert_eq!(line["target"], "torrentd::telemetry");
        assert_eq!(line["error.kind"], "span_export_failed");
    }
    assert_eq!(l[0]["held_back"], 0);
    assert_eq!(l[1]["held_back"], 3);
}

#[test]
fn an_unreachable_collector_is_counted_and_never_blocks_the_daemon() {
    // Port 1 on loopback: refused at once. Both transports, the gRPC one
    // built inside a runtime as `main` builds it.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    let before = export_errors().total();
    for protocol in [OtlpProtocol::HttpProtobuf, OtlpProtocol::Grpc] {
        let cfg = TelemetryConfig {
            otlp_endpoint: Some("http://127.0.0.1:1".to_owned()),
            protocol: Some(protocol),
            ..cfg()
        };
        let telemetry = {
            let _entered = runtime.enter();
            Telemetry::new(Some(&cfg)).expect("an exporter")
        };
        assert!(telemetry.is_exporting());
        let (_handle, subscriber) = for_tests_traced(LogLevel::Info, Buf::default(), &telemetry);
        let started = Instant::now();
        torrentd_engine::testing::with_subscriber(subscriber, || {
            let span = tracing::info_span!("work");
            let _e = span.enter();
            tracing::info!("done");
        });
        assert!(started.elapsed() < Duration::from_secs(1), "{protocol:?}");
        telemetry.shutdown(SHUTDOWN_FLUSH);
    }
    assert!(
        export_errors().total() >= before + 2,
        "{} -> {}",
        before,
        export_errors().total()
    );
}

#[test]
fn without_telemetry_nothing_is_exported() {
    let telemetry = Telemetry::new(None).expect("ids only");
    assert!(!telemetry.is_exporting());
}

#[test]
fn the_endpoint_falls_back_to_the_environment_then_the_default() {
    let resolve = |cfg: &TelemetryConfig, vars: &[(&str, &str)]| {
        Export::resolve(cfg, env(vars)).expect("resolves")
    };
    // Defaults: http/protobuf, the specification's.
    let e = resolve(&cfg(), &[]);
    assert_eq!(e.protocol, OtlpProtocol::HttpProtobuf);
    assert_eq!(e.endpoint, "http://localhost:4318/v1/traces");
    assert_eq!(e.sample_ratio, 1.0);
    let grpc = TelemetryConfig {
        protocol: Some(OtlpProtocol::Grpc),
        ..cfg()
    };
    assert_eq!(resolve(&grpc, &[]).endpoint, "http://localhost:4317");

    // A base endpoint gets the traces path for http/protobuf, and only a base
    // endpoint.
    let base = TelemetryConfig {
        otlp_endpoint: Some("http://alloy:4318/".to_owned()),
        ..cfg()
    };
    assert_eq!(resolve(&base, &[]).endpoint, "http://alloy:4318/v1/traces");
    assert_eq!(
        resolve(&cfg(), &[(ENV_ENDPOINT, "https://tempo:4318")]).endpoint,
        "https://tempo:4318/v1/traces"
    );
    assert_eq!(
        resolve(
            &cfg(),
            &[
                (ENV_TRACES_ENDPOINT, "http://a:9/custom"),
                (ENV_ENDPOINT, "http://b:4318")
            ]
        )
        .endpoint,
        "http://a:9/custom"
    );
    // The key wins over the environment.
    assert_eq!(
        resolve(&base, &[(ENV_TRACES_ENDPOINT, "http://a:9/custom")]).endpoint,
        "http://alloy:4318/v1/traces"
    );
    let grpc_base = TelemetryConfig {
        otlp_endpoint: Some("http://alloy:4317".to_owned()),
        ..grpc
    };
    assert_eq!(resolve(&grpc_base, &[]).endpoint, "http://alloy:4317");

    // The protocol, from the signal's variable before the general one.
    assert_eq!(
        resolve(
            &cfg(),
            &[
                (ENV_TRACES_PROTOCOL, "grpc"),
                (ENV_PROTOCOL, "http/protobuf")
            ]
        )
        .protocol,
        OtlpProtocol::Grpc
    );
    assert_eq!(
        resolve(&cfg(), &[(ENV_PROTOCOL, "grpc")]).protocol,
        OtlpProtocol::Grpc
    );
    let http = TelemetryConfig {
        protocol: Some(OtlpProtocol::HttpProtobuf),
        ..cfg()
    };
    assert_eq!(
        resolve(&http, &[(ENV_PROTOCOL, "grpc")]).protocol,
        OtlpProtocol::HttpProtobuf
    );
}

#[test]
fn what_cannot_be_exported_with_is_refused() {
    let refusal = |cfg: &TelemetryConfig, vars: &[(&str, &str)]| {
        format!(
            "{:#}",
            Export::resolve(cfg, env(vars)).expect_err("refused")
        )
    };
    assert!(refusal(&cfg(), &[(ENV_PROTOCOL, "http/json")]).contains(ENV_PROTOCOL));
    let not_http = TelemetryConfig {
        otlp_endpoint: Some("alloy:4317".to_owned()),
        ..cfg()
    };
    assert!(refusal(&not_http, &[]).contains("otlp_endpoint"));
    for ratio in [-0.1, 1.5, f64::NAN] {
        let c = TelemetryConfig {
            sample_ratio: Some(ratio),
            ..cfg()
        };
        assert!(refusal(&c, &[]).contains("sample_ratio"), "{ratio}");
    }
    for key in ["service.name", "service.version", ""] {
        let c = TelemetryConfig {
            resource_attributes: BTreeMap::from([(key.to_owned(), "x".to_owned())]),
            ..cfg()
        };
        assert!(refusal(&c, &[]).contains("resource_attributes"), "{key:?}");
    }
}

#[test]
fn an_endpoint_that_does_not_parse_is_refused_and_redacted() {
    let refusal = |cfg: &TelemetryConfig, vars: &[(&str, &str)]| {
        format!(
            "{:#}",
            Export::resolve(cfg, env(vars)).expect_err("refused")
        )
    };
    for bad in ["http://bad host", "http://", "https://[::1:4318/"] {
        let in_config = TelemetryConfig {
            otlp_endpoint: Some(bad.to_owned()),
            ..cfg()
        };
        let err = refusal(&in_config, &[]);
        assert!(
            err.contains("otlp_endpoint") && err.contains("not a valid URL"),
            "{err}"
        );
        let err = refusal(&cfg(), &[(ENV_ENDPOINT, bad)]);
        assert!(
            err.contains(ENV_ENDPOINT) && err.contains("not a valid URL"),
            "{err}"
        );
        let err = refusal(&cfg(), &[(ENV_TRACES_ENDPOINT, bad)]);
        assert!(
            err.contains(ENV_TRACES_ENDPOINT) && err.contains("not a valid URL"),
            "{err}"
        );
    }
    let leaky = TelemetryConfig {
        otlp_endpoint: Some(format!("https://user:{PASSKEY}@bad host/")),
        ..cfg()
    };
    let err = refusal(&leaky, &[]);
    assert!(err.contains("not a valid URL"), "{err}");
    assert!(!err.contains(PASSKEY), "{err}");
}

#[test]
fn a_headers_file_is_read_and_never_echoed() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("otlp-headers");
    std::fs::write(
        &path,
        "# for Grafana Cloud\n\nAuthorization = Basic dXNlcjpwYXNz==\nx-scope-orgid=tenant-1\n",
    )
    .expect("write");
    let with_file = TelemetryConfig {
        headers_file: Some(path.clone()),
        ..cfg()
    };
    let e = Export::resolve(&with_file, env(&[])).expect("resolves");
    assert_eq!(
        e.headers,
        [
            (
                "authorization".to_owned(),
                "Basic dXNlcjpwYXNz==".to_owned()
            ),
            ("x-scope-orgid".to_owned(), "tenant-1".to_owned()),
        ]
    );

    // Beside a headers variable: refused, not merged.
    let err = Export::resolve(&with_file, env(&[(ENV_HEADERS, "a=b")])).expect_err("refused");
    assert!(format!("{err:#}").contains(ENV_HEADERS), "{err:#}");

    // A malformed line is named by number; its value is never shown.
    std::fs::write(&path, "authorization=ok\nsecret-without-equals\n").expect("write");
    let err = format!(
        "{:#}",
        Export::resolve(&with_file, env(&[])).expect_err("refused")
    );
    assert!(err.contains("line 2"), "{err}");
    assert!(!err.contains("secret-without-equals"), "{err}");
    std::fs::write(&path, "authorization=bad\u{7}value\n").expect("write");
    let err = format!(
        "{:#}",
        Export::resolve(&with_file, env(&[])).expect_err("refused")
    );
    assert!(!err.contains("bad"), "{err}");

    let missing = TelemetryConfig {
        headers_file: Some(dir.path().join("absent")),
        ..cfg()
    };
    assert!(Export::resolve(&missing, env(&[])).is_err());
}

/// A minimal valid config, with `telemetry` as its `[telemetry]` body.
fn config_with(telemetry: &str) -> Result<crate::config::Config, toml::de::Error> {
    toml::from_str(&format!(
        r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
allow_unauthenticated = true

[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"

[telemetry]
{telemetry}
"#
    ))
}

#[test]
fn the_section_parses_validates_and_is_restart_only() {
    let parsed = config_with(
        "otlp_endpoint = \"http://alloy:4317\"\nprotocol = \"grpc\"\nsample_ratio = 0.25\n\
         resource_attributes = { \"deployment.environment\" = \"prod\" }\n",
    )
    .expect("parses");
    let t = parsed.telemetry.clone().expect("[telemetry]");
    assert_eq!(t.protocol, Some(OtlpProtocol::Grpc));
    assert_eq!(t.sample_ratio, Some(0.25));
    assert_eq!(t.resource_attributes["deployment.environment"], "prod");
    parsed.validate().expect("valid");

    let mut without = parsed.clone();
    without.telemetry = None;
    let d = crate::config::Config::diff(&without, &parsed);
    assert_eq!(d.non_reloadable_changes, ["telemetry"]);

    // An empty section exports, to the defaults.
    assert!(config_with("").expect("parses").telemetry.is_some());

    assert!(config_with("protocol = \"http/json\"").is_err());
    assert!(config_with("endpoint = \"http://alloy:4317\"").is_err());
    let refused = config_with("sample_ratio = 2.0")
        .expect("parses")
        .validate()
        .expect_err("refused");
    let refused = format!("{refused:#}");
    assert!(refused.contains("[telemetry]"), "{refused}");
    assert!(refused.contains("sample_ratio"), "{refused}");
}
