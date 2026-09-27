//! Headers every response carries, and the request id they correlate by.

use std::convert::Infallible;

use kynos::http;
use kynos::middleware::Continued;
use kynos::middleware::Interceptor;
use kynos::middleware::Next;
use kynos::HeaderParams;

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
