//! The span each request runs in, and the `traceparent` every response
//! carries from it.
//!
//! The other headers every response carries are kynos' own: the request id
//! from `kynos::middleware::request_id` and the security headers from
//! `kynos::middleware::security_headers`, both mounted in `http::router`.

use std::convert::Infallible;

use kynos::http;
use kynos::middleware::Continued;
use kynos::middleware::Interceptor;
use kynos::middleware::Next;
use kynos::HeaderParams;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::Instrument as _;

/// The header [`RequestSpan`] adds, declared so the document lists it.
#[derive(HeaderParams)]
pub struct TraceContextHeaders {
    /// The W3C trace context of the span this request ran in
    /// (`00-<trace id>-<span id>-<flags>`): the trace a log line or an
    /// exported span of this request is found under. Absent only where the
    /// daemon has no trace context to give.
    #[header(rename = "traceparent")]
    traceparent: Option<String>,
}

/// The span every request runs in, from the moment it is routed until its
/// response is formed: everything a handler logs, and everything it hands
/// off through `startup::tasks`, is inside it.
///
/// It carries `request_id` (the `X-Request-Id` the response does, so must be
/// mounted after [`kynos::middleware::request_id::RequestId`]), the `method`,
/// the `route` template (`<unmatched>` where none matched, as the request log
/// lines say), the `status`, recorded once the response is formed, and the
/// caller: `principal` (`session`, `token` or `anonymous`) and, for a static
/// token, its configured `token_name` — never the token.
///
/// A valid W3C `traceparent` (with its `tracestate`) on the request makes the
/// span a child of the caller's, so the request joins the caller's trace; an
/// invalid or absent one starts a trace of its own. Either way the response
/// carries the span's own `traceparent`.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestSpan;

/// What `route` holds where no operation matched.
const UNMATCHED: &str = "<unmatched>";

impl<C: Sync + 'static> Interceptor<C> for RequestSpan {
    type Reads = ();
    type Adds = TraceContextHeaders;
    type Short = Infallible;

    fn intercept(
        &self,
        request: http::Request,
        _reads: (),
        _context: &C,
        next: Next<'_, C>,
    ) -> impl std::future::Future<Output = Result<Continued<TraceContextHeaders>, Infallible>> + Send
    {
        let span = request_span(&request, next.route().map(|route| route.path()));
        let traceparent = traceparent_of(&span);
        // Started inside the span: kynos does part of the chain's work
        // before the future it returns is first polled.
        let run = span.in_scope(|| next.run(request));
        async move {
            let continued = run.instrument(span.clone()).await;
            span.record("status", continued.status().as_u16());
            Ok(continued.with_headers(TraceContextHeaders { traceparent }))
        }
    }
}

/// The span [`RequestSpan`] runs `request` in, `route` being its matched
/// template.
fn request_span(request: &http::Request, route: Option<&str>) -> tracing::Span {
    use opentelemetry::propagation::TextMapPropagator as _;
    use opentelemetry::trace::TraceContextExt as _;

    let parent = TraceContextPropagator::new()
        .extract(&opentelemetry_http::HeaderExtractor(request.headers()));
    // tracing-opentelemetry takes a new span's parent from the context
    // current when it is created, so the caller's is made current for just
    // that long.
    let _attached = parent
        .span()
        .span_context()
        .is_valid()
        .then(|| parent.clone().attach());
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|id| id.to_str().ok())
        .unwrap_or_default();
    // Who called over the unix socket, as the kernel reported it when the
    // connection was accepted; `None`, and so not written, over TCP.
    let peer = request
        .extensions()
        .get::<kynos::extract::connection::Connection>()
        .and_then(kynos::extract::connection::Connection::peer_credentials);
    tracing::info_span!(
        "request",
        request_id,
        peer.uid = peer.map(|p| p.uid()),
        peer.pid = peer.and_then(|p| p.pid()),
        method = %request.method(),
        route = route.unwrap_or(UNMATCHED),
        status = tracing::field::Empty,
        principal = tracing::field::Empty,
        token_name = tracing::field::Empty,
    )
}

/// `span`'s W3C `traceparent`, where it has a trace context.
fn traceparent_of(span: &tracing::Span) -> Option<String> {
    use opentelemetry::propagation::TextMapPropagator as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let mut fields = std::collections::HashMap::new();
    TraceContextPropagator::new().inject_context(&span.context(), &mut fields);
    fields.remove("traceparent")
}

#[cfg(test)]
mod tests {
    use kynos::extract::connection::Connection;
    use kynos::extract::connection::PeerCredentials;
    use kynos::http;

    use super::request_span;
    use crate::config::LogLevel;
    use crate::tracing_init::Buf;

    /// The line a request on `connection` logs inside its span.
    fn logged_on(connection: Connection) -> String {
        let mut request = http::Request::new(http::body::Body::empty());
        request.extensions_mut().insert(connection);
        let buf = Buf::default();
        let (_handle, subscriber) = crate::tracing_init::for_tests(LogLevel::Info, buf.clone());
        torrentd_engine::testing::with_subscriber(subscriber, || {
            let span = request_span(&request, Some("/v1/server"));
            let _entered = span.enter();
            tracing::info!("handled");
        });
        buf.text()
    }

    /// The property: who called over the unix socket is on every line its
    /// request logs, by the uid and pid the kernel reported, and a TCP
    /// request, which has no such caller, carries neither field.
    #[test]
    fn a_unix_socket_request_logs_its_callers_uid_and_pid() {
        let unix = std::os::unix::net::SocketAddr::from_pathname("/run/torrentd/api.sock").unwrap();
        let text = logged_on(
            Connection::from_peer(unix.clone(), unix)
                .with_peer_credentials(PeerCredentials::new(1000, 1000).with_pid(4242)),
        );
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert!(line.to_string().contains("\"peer.uid\":1000"), "{line}");
        assert!(line.to_string().contains("\"peer.pid\":4242"), "{line}");

        let tcp: std::net::SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let text = logged_on(Connection::from_peer(tcp, tcp));
        assert!(text.contains("handled"), "{text}");
        assert!(!text.contains("peer.uid"), "{text}");
        assert!(!text.contains("peer.pid"), "{text}");
    }
}
