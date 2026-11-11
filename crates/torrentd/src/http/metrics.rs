//! `GET /metrics` — Prometheus text format — and [`HttpMetrics`], which
//! counts and times every response the API sends.

use std::sync::Arc;
use std::time::Duration;

use kynos::extract::body::binary::Binary;
use kynos::http::media::MediaType;
use kynos::middleware::Observer;
use kynos::openapi::Document;
use kynos::prelude::*;
use kynos::router::operation::Route;
use kynos::security::auth::Scoped;
use torrentd_engine::MetricsSink;

use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Metrics;
use crate::http::v1::Operations;
use crate::metrics_sink::PromSink;
use crate::metrics_sink::HTTP_STATUS_CLASSES;

const REQUESTS: &str = "http_requests_total";
const DURATION: &str = "http_request_duration_seconds";

/// The `route` and `method` of a request no operation matched: an unknown
/// path, a method the path does not take, or a trailing-slash spelling. Fixed,
/// so a scan of random paths cannot mint a series per path it tries.
pub const UNMATCHED: &str = "unmatched";

/// Counts every response in `http_requests_total` and times it in
/// `http_request_duration_seconds`, by the route template the request matched
/// rather than its path, and logs every 5xx at `ERROR` with its request id.
///
/// kynos' `Trace` writes the `response sent` line for every response at one
/// level, so a 500 is no louder there than a 200; the line written here is
/// the one an operator's log filter for errors finds. A 4xx is a client's
/// mistake, and stays at `Trace`'s `INFO`.
#[derive(Clone, Debug)]
pub struct HttpMetrics {
    sink: Arc<PromSink>,
}

impl HttpMetrics {
    pub fn new(sink: Arc<PromSink>) -> Self {
        Self { sink }
    }

    /// Write both series for every operation `doc` describes, and for
    /// [`UNMATCHED`], at zero: every status class of the counter, and an
    /// empty histogram. An alert reading `increase()` or a ratio over them
    /// then has a sample before the first request it should see.
    pub fn seed(&self, doc: &Document) {
        for (path, item) in &doc.paths.items {
            for (method, _) in item.operations() {
                self.seed_route(path, method.as_wire_str());
            }
        }
        self.seed_route(UNMATCHED, UNMATCHED);
    }

    fn seed_route(&self, route: &str, method: &str) {
        for class in HTTP_STATUS_CLASSES {
            self.sink.add_counter(
                REQUESTS,
                0,
                &[
                    ("route", route),
                    ("method", method),
                    ("status_class", class),
                ],
            );
        }
        self.sink
            .seed_histogram(DURATION, &[("route", route), ("method", method)]);
    }
}

/// `1xx` to `5xx`; anything past 599, which no handler answers with, is
/// counted as `5xx`.
fn status_class(status: kynos::http::StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        _ => "5xx",
    }
}

impl<C> Observer<C> for HttpMetrics {
    fn on_request(&self, _request: &kynos::http::Request, _route: Option<Route<'_>>, _: &C) {}

    fn on_response(
        &self,
        response: &kynos::http::Response,
        route: Option<Route<'_>>,
        elapsed: Duration,
    ) {
        // The matched operation's method, as `Trace`'s closing line names it:
        // `GET` for a `HEAD` a `GET` answers.
        let (path, method) = route.map_or((UNMATCHED, UNMATCHED), |route| {
            (route.path(), route.method().as_wire_str())
        });
        let status = response.status();
        self.sink.inc_counter(
            REQUESTS,
            &[
                ("route", path),
                ("method", method),
                ("status_class", status_class(status)),
            ],
        );
        self.sink.observe_histogram(
            DURATION,
            elapsed.as_secs_f64(),
            &[("route", path), ("method", method)],
        );
        if status.is_server_error() {
            // The id `RequestId` wrote on the response, which the client
            // holds and quotes.
            let request_id = response
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            tracing::error!(
                target: "torrentd::http",
                method,
                matched_path = path,
                status = status.as_u16(),
                latency = ?elapsed,
                request_id,
                "server error response",
            );
        }
    }
}

/// The Prometheus text exposition format, version 0.0.4.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrometheusText;

impl MediaType for PrometheusText {
    const MEDIA_TYPE: &'static str = "text/plain; version=0.0.4";
}

/// Why a scrape was not answered.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum MetricsError {
    /// The exposition could not be encoded; a partial one is never served.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// Scrape the daemon's metrics.
///
/// Prometheus text format. Needs the `metrics` scope, which no other
/// operation accepts and no session token carries, so a scrape credential can
/// never reach the control plane. `deploy/metrics.md` catalogues every
/// series. `500 internal` where the exposition cannot be encoded, rather
/// than a partial one that reads as series having vanished; the failure is
/// counted in `metrics_dropped_samples_total{reason="encode"}`.
#[kynos::get("/metrics", tag = Operations)]
pub async fn get_metrics(
    _caller: Scoped<Bearer, Metrics>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<Binary<PrometheusText>, MetricsError> {
    // Computed here rather than by a ticking task: a task could itself stall,
    // and the age read at scrape time is exactly the one `/healthz` would
    // report at that moment.
    s.metrics.set_gauge(
        "alert_loop_heartbeat_age_seconds",
        torrentd_engine::heartbeat_age(&s.alert_heartbeat).as_secs_f64(),
        &[],
    );
    s.metrics
        .try_render()
        .map(Binary::new)
        .map_err(|e| MetricsError::Internal {
            detail: crate::http::v1::common::internal("encoding the metrics", e),
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::http::tests::support::Coverage;
    use crate::http::tests::support::Harness;
    use crate::http::tests::support::PASSWORD;

    /// The scrape, as text.
    async fn scrape(h: &Harness) -> String {
        h.send("GET", "/metrics", Some(&h.tokens.metrics.clone()), None)
            .await
            .text()
            .to_owned()
    }

    /// The `torrentd_<name>{labels}` sample in `text`, where there is one.
    fn sample(text: &str, series: &str) -> Option<f64> {
        let prefix = format!("torrentd_{series} ");
        text.lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .map(|v| v.trim().parse().unwrap())
    }

    fn requests(route: &str, method: &str, class: &str) -> String {
        format!(
            "http_requests_total{{method=\"{method}\",route=\"{route}\",status_class=\"{class}\"}}"
        )
    }

    fn timed(route: &str, method: &str) -> String {
        format!("http_request_duration_seconds_count{{method=\"{method}\",route=\"{route}\"}}")
    }

    #[tokio::test]
    async fn every_route_and_unmatched_is_written_before_the_first_request() {
        let h = Harness::authed(&Coverage::new(), |_| {});
        // Read before the scrape below counts itself.
        let text = String::from_utf8(h.state.metrics.render()).unwrap();
        for (route, method) in [
            ("/v1/torrents/{infohash}", "DELETE"),
            ("/healthz", "GET"),
            ("/metrics", "GET"),
            (super::UNMATCHED, super::UNMATCHED),
        ] {
            for class in crate::metrics_sink::HTTP_STATUS_CLASSES {
                assert_eq!(
                    sample(&text, &requests(route, method, class)),
                    Some(0.0),
                    "{route} {method} {class}:\n{text}"
                );
            }
            assert_eq!(
                sample(&text, &timed(route, method)),
                Some(0.0),
                "{route} {method}:\n{text}"
            );
        }
        assert!(
            !text.contains("route=\"/v1/torrents/0"),
            "no concrete path is a route"
        );
    }

    #[tokio::test]
    async fn a_response_is_counted_and_timed_by_its_route_template() {
        let h = Harness::authed(&Coverage::new(), |_| {});
        let infohash = "0".repeat(40);
        h.read(&format!("/v1/torrents/{infohash}")).await;
        h.read("/v1/status").await;
        h.read("/v1/status").await;
        h.read("/v1/no-such-thing").await;
        h.send("PATCH", "/v1/status", None, None).await;
        let text = scrape(&h).await;
        assert_eq!(
            sample(&text, &requests("/v1/torrents/{infohash}", "GET", "4xx")),
            Some(1.0),
            "{text}"
        );
        assert_eq!(
            sample(&text, &requests("/v1/status", "GET", "2xx")),
            Some(2.0),
            "{text}"
        );
        assert_eq!(sample(&text, &timed("/v1/status", "GET")), Some(2.0));
        assert_eq!(
            sample(&text, &requests(super::UNMATCHED, super::UNMATCHED, "4xx")),
            Some(2.0),
            "an unknown path and a method the path does not take:\n{text}"
        );
        assert!(!text.contains(&infohash), "{text}");
        assert!(!text.contains("no-such-thing"), "{text}");
    }

    #[tokio::test]
    async fn a_5xx_is_counted_and_logged_at_error_with_its_request_id() {
        let log = crate::tracing_init::Buf::default();
        let (_reload, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let _guard = torrentd_engine::testing::set_subscriber(subscriber);
        // No reload task listening: the reload answers 503.
        let h = Harness::authed(&Coverage::new(), |_| {});
        let unavailable = h.write("POST", "/v1/config/reload").await;
        assert_eq!(unavailable.status().as_u16(), 503);
        let id = unavailable.header("x-request-id").unwrap().to_owned();
        let missing = h.read(&format!("/v1/torrents/{}", "0".repeat(40))).await;
        let missing_id = missing.header("x-request-id").unwrap().to_owned();

        let text = scrape(&h).await;
        assert_eq!(
            sample(&text, &requests("/v1/config/reload", "POST", "5xx")),
            Some(1.0),
            "{text}"
        );
        let log = log.text();
        let errors: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("\"level\":\"ERROR\""))
            .collect();
        assert_eq!(errors.len(), 1, "{log}");
        assert!(errors[0].contains("server error response"), "{log}");
        assert!(
            errors[0].contains(&format!("\"request_id\":\"{id}\"")),
            "{log}"
        );
        assert!(
            errors[0].contains("\"matched_path\":\"/v1/config/reload\""),
            "{log}"
        );
        assert!(errors[0].contains("\"status\":503"), "{log}");
        assert!(
            !log.lines()
                .any(|l| l.contains(&missing_id) && !l.contains("\"level\":\"INFO\"")),
            "a 4xx stays at INFO:\n{log}"
        );
    }

    #[tokio::test]
    async fn a_refused_token_is_counted_by_reason_and_logged_once_a_minute_per_client() {
        let log = crate::tracing_init::Buf::default();
        let (_reload, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let _guard = torrentd_engine::testing::set_subscriber(subscriber);
        let h = Harness::authed_with_session_ttl(&Coverage::new(), 0);

        // A rotated scrape token, three scrapes in a row.
        for _ in 0..3 {
            let resp = h
                .send("GET", "/metrics", Some("tdp_rotated_away"), None)
                .await;
            assert_eq!(resp.status().as_u16(), 401);
        }
        // Not a bearer credential at all.
        let resp = h
            .send_with(
                "GET",
                "/v1/status",
                None,
                None,
                &[("authorization", "Basic dXNlcjpwYXNz")],
            )
            .await;
        assert_eq!(resp.status().as_u16(), 401);
        // A session that lived no time at all, refused on a route whose body
        // the interceptor refuses before reading.
        let session = h
            .send(
                "POST",
                "/v1/sessions",
                None,
                Some(json!({"password": PASSWORD})),
            )
            .await;
        session.assert_status(kynos::http::StatusCode::CREATED);
        let token = session.json::<serde_json::Value>()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let resp = h
            .send("POST", "/v1/config/reload", Some(&token), None)
            .await;
        assert_eq!(resp.status().as_u16(), 401);
        // No credential is not a refused one.
        h.send("GET", "/v1/status", None, None).await;

        let rejections = |reason: &str| format!("auth_rejections_total{{reason=\"{reason}\"}}");
        let text = scrape(&h).await;
        assert_eq!(sample(&text, &rejections("unknown")), Some(3.0), "{text}");
        assert_eq!(sample(&text, &rejections("malformed")), Some(1.0), "{text}");
        assert_eq!(sample(&text, &rejections("expired")), Some(1.0), "{text}");

        // Every request above came from the harness's one peer, so one line
        // for the first refusal and none for the four within the minute.
        let log = log.text();
        let warned: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("refused a request's bearer token"))
            .collect();
        assert_eq!(warned.len(), 1, "{log}");
        assert!(warned[0].contains("\"level\":\"WARN\""), "{log}");
        assert!(warned[0].contains("\"reason\":\"unknown\""), "{log}");
        assert!(warned[0].contains("\"token_kind\":\"static\""), "{log}");
        assert!(warned[0].contains("192.0.2.10"), "{log}");
        assert!(!log.contains("tdp_rotated_away"), "{log}");
    }
}
