//! Serving the embedded web client.
//!
//! The bundle is compiled into the binary so a deployment is one artifact. It
//! is mounted last, under a catch-all, so it can never shadow an API route:
//! anything the router already matched wins, and only unmatched paths fall
//! through to here.
//!
//! This is an origin server sitting behind a caching reverse proxy, which is
//! what makes the response metadata matter. Without a validator, `no-cache`
//! on `index.html` means every single load re-ships the document — the proxy
//! has nothing to revalidate *with*, so it cannot answer 304 and neither
//! could this. Without `Content-Encoding` negotiation, a 226 KB bundle is
//! sent raw to every cold client. Both were the case.

use axum::body::Body;
use axum::http::header;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::Uri;
use axum::response::IntoResponse;
use axum::response::Response;

#[derive(rust_embed::Embed)]
#[folder = "../../web/dist"]
struct Assets;

/// Headers every response from this handler carries.
///
/// The web client holds a session cookie, so the origin serving it is worth
/// hardening even though the bundle itself contains no data:
///
/// * `nosniff` stops a browser content-type-guessing its way into executing
///   something that was not meant to be script;
/// * the CSP confines the app to its own origin — it fetches only same-origin
///   JSON and an SSE stream, so `self` is not a restriction it feels;
/// * `frame-ancestors 'none'` plus `X-Frame-Options` is the clickjacking
///   defence that `SameSite=Strict` does not provide;
/// * `Referrer-Policy` keeps info-hashes in the URL fragment out of any
///   outbound referrer.
fn security_headers(res: &mut HeaderMap) {
    for (k, v) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
             connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    ] {
        res.insert(k, HeaderValue::from_static(v));
    }
}

/// Whether the client said it would accept `encoding`.
fn accepts(headers: &HeaderMap, encoding: &str) -> bool {
    headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',').any(|part| {
                let name = part.split(';').next().unwrap_or("").trim();
                name.eq_ignore_ascii_case(encoding)
            })
        })
}

/// The best precompressed sibling of `path` the client will take.
///
/// Brotli first: it is both smaller and the one a modern browser prefers, and
/// the files are produced at build time so there is no runtime cost to either.
fn negotiated(path: &str, headers: &HeaderMap) -> Option<(rust_embed::EmbeddedFile, &'static str)> {
    for (suffix, encoding) in [(".br", "br"), (".gz", "gzip")] {
        if !accepts(headers, encoding) {
            continue;
        }
        if let Some(f) = Assets::get(&format!("{path}{suffix}")) {
            return Some((f, encoding));
        }
    }
    None
}

/// The strong validator for a file, from the hash rust-embed already computed.
fn etag(file: &rust_embed::EmbeddedFile) -> String {
    let h = file.metadata.sha256_hash();
    // 16 hex chars of a SHA-256 is ample to distinguish builds of one asset,
    // and keeps the header small enough not to matter.
    let mut s = String::with_capacity(20);
    s.push('"');
    for b in &h[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('"');
    s
}

/// Whether `If-None-Match` already holds this version.
///
/// `*` matches anything present, per RFC 9110; otherwise any member of the
/// comma-separated list matching the tag is a hit. Weak prefixes are stripped
/// because a weak comparison is the right one for a conditional GET.
fn matches_etag(headers: &HeaderMap, tag: &str) -> bool {
    let Some(inm) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    if inm.trim() == "*" {
        return true;
    }
    inm.split(',')
        .map(|c| c.trim().trim_start_matches("W/"))
        .any(|c| c == tag)
}

/// `Cache-Control` for a path.
///
/// Vite fingerprints filenames under `assets/`, so those are immutable for a
/// year. `index.html` must not be, or an upgraded daemon keeps serving the
/// previous app — but `no-cache` means *revalidate*, not *do not store*, and
/// with an ETag that revalidation is now a 304 instead of a full document.
fn cache_control(path: &str) -> &'static str {
    if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn respond(path: &str, req_headers: &HeaderMap) -> Option<Response> {
    let file = Assets::get(path)?;
    let tag = etag(&file);

    let mut headers = HeaderMap::new();
    security_headers(&mut headers);
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control(path)),
    );
    if let Ok(v) = HeaderValue::from_str(&tag) {
        headers.insert(header::ETAG, v);
    }
    // The response body varies by Accept-Encoding, so a shared cache must key
    // on it. Without this a proxy can hand a brotli body to a client that did
    // not ask for one.
    headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));

    if matches_etag(req_headers, &tag) {
        let mut res = StatusCode::NOT_MODIFIED.into_response();
        *res.headers_mut() = headers;
        return Some(res);
    }

    let mime = mime_guess::from_path(path).first_or_octet_stream();
    if let Ok(v) = HeaderValue::from_str(mime.as_ref()) {
        headers.insert(header::CONTENT_TYPE, v);
    }

    // Negotiation happens after the ETag, on purpose: the validator identifies
    // the *resource*, so a client holding a fresh copy gets its 304 whether or
    // not a precompressed sibling exists for it.
    let body = match negotiated(path, req_headers) {
        Some((compressed, encoding)) => {
            headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
            compressed.data
        }
        None => file.data,
    };

    let mut res = Response::new(Body::from(body.into_owned()));
    *res.headers_mut() = headers;
    Some(res)
}

pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    // A single-page app owns its own routing, so an unknown path is not a 404 —
    // it is a deep link the client will resolve. Only asset-looking requests
    // get a real 404, so a mistyped script URL fails loudly instead of being
    // answered with HTML.
    let candidate = if path.is_empty() { "index.html" } else { path };

    if let Some(res) = respond(candidate, &headers) {
        return res;
    }

    if candidate.contains('.') {
        let mut res = (StatusCode::NOT_FOUND, "not found").into_response();
        security_headers(res.headers_mut());
        return res;
    }

    match respond("index.html", &headers) {
        Some(res) => res,
        // Built with the feature on but no bundle present: say so plainly
        // rather than serving a blank page.
        None => {
            let mut res = (
                StatusCode::NOT_FOUND,
                "the web client was not embedded in this build",
            )
                .into_response();
            security_headers(res.headers_mut());
            res
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(k.clone(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn a_star_if_none_match_is_a_hit() {
        assert!(matches_etag(
            &headers(&[(header::IF_NONE_MATCH, "*")]),
            "\"abc\""
        ));
    }

    #[test]
    fn a_weak_validator_still_matches_for_a_conditional_get() {
        assert!(matches_etag(
            &headers(&[(header::IF_NONE_MATCH, "W/\"abc\"")]),
            "\"abc\""
        ));
    }

    #[test]
    fn any_member_of_the_list_matches() {
        assert!(matches_etag(
            &headers(&[(header::IF_NONE_MATCH, "\"x\", \"abc\", \"y\"")]),
            "\"abc\""
        ));
        assert!(!matches_etag(
            &headers(&[(header::IF_NONE_MATCH, "\"x\", \"y\"")]),
            "\"abc\""
        ));
    }

    #[test]
    fn a_missing_header_never_matches() {
        assert!(!matches_etag(&HeaderMap::new(), "\"abc\""));
    }

    #[test]
    fn encoding_negotiation_reads_a_q_list() {
        let h = headers(&[(header::ACCEPT_ENCODING, "gzip, deflate, br;q=1.0")]);
        assert!(accepts(&h, "br"));
        assert!(accepts(&h, "gzip"));
        assert!(!accepts(&h, "zstd"));
    }

    #[test]
    fn an_absent_accept_encoding_accepts_nothing() {
        // Sending a compressed body to a client that did not ask is a broken
        // response, not an optimisation.
        assert!(!accepts(&HeaderMap::new(), "br"));
        assert!(!accepts(&HeaderMap::new(), "gzip"));
    }

    #[test]
    fn fingerprinted_assets_are_immutable_and_the_document_is_not() {
        assert!(cache_control("assets/index-abc123.js").contains("immutable"));
        assert_eq!(cache_control("index.html"), "no-cache");
    }
}
