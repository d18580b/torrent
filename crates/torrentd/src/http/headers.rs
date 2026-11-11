//! Headers every response carries, the request id they correlate by, and
//! the span each request runs in.

use std::convert::Infallible;

use kynos::http;
use kynos::middleware::Continued;
use kynos::middleware::Interceptor;
use kynos::middleware::Next;
use kynos::HeaderParams;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::Instrument as _;

/// The headers [`ApiHeaders`] adds, declared so the document lists them.
#[derive(HeaderParams)]
pub struct ApiResponseHeaders {
    /// `no-store`: every response describes live daemon state, and most of
    /// it is only readable with a credential.
    #[header(rename = "Cache-Control")]
    cache_control: String,
    /// Always `nosniff`.
    #[header(rename = "X-Content-Type-Options")]
    content_type_options: String,
}

/// Marks every response uncacheable and unsniffable.
#[derive(Clone, Copy, Debug, Default)]
pub struct ApiHeaders;

impl<C: Sync + 'static> Interceptor<C> for ApiHeaders {
    type Reads = ();
    type Adds = ApiResponseHeaders;
    type Short = Infallible;

    async fn intercept(
        &self,
        request: http::Request,
        _reads: (),
        _context: &C,
        next: Next<'_, C>,
    ) -> Result<Continued<ApiResponseHeaders>, Infallible> {
        Ok(next.run(request).await.with_headers(ApiResponseHeaders {
            cache_control: "no-store".to_owned(),
            content_type_options: "nosniff".to_owned(),
        }))
    }
}

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
    tracing::info_span!(
        "request",
        request_id,
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

/// Request ids: 128 random bits, as 32 hex digits.
///
/// Random rather than kynos' per-process counter, so an id quoted from a
/// response names one request across restarts too, and reveals nothing about
/// how many requests the daemon has served.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomRequestId;

impl kynos::middleware::request_id::RequestIdSource for RandomRequestId {
    fn next_id(&self) -> http::HeaderValue {
        use rand::RngCore as _;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        http::HeaderValue::from_str(&hex::encode(bytes)).expect("hex is a valid header value")
    }
}
