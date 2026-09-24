//! Serving the embedded web client.
//!
//! In a **release** build the bundle is compiled into the binary, so a
//! deployment is one artifact. In a debug build it is not: `rust-embed` gates
//! the embedded impl behind `#[cfg(not(debug_assertions))]` and the
//! `debug-embed` feature is not taken, so a debug binary holds the absolute
//! path to `web/dist` and reads each file from disk at request time. That is
//! a supported way to run this — `Cargo.toml` has `web-ui` on by default so
//! that a plain `cargo build` serves the UI, and a plain `cargo build` is
//! debug — and it is worth knowing that there the assets are whatever is on
//! disk, with `rust-embed`'s own documented symlink escape in play.
//!
//! Everything below is true of both: the dynamic path hashes file content the
//! same way, so the validators and the negotiation behave identically.
//!
//! It is mounted last, under a catch-all, so it can never shadow an API route:
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
///
/// `q=0` is a refusal, not an acceptance: RFC 9110 §12.5.3 defines a quality
/// of zero as "not acceptable". Ignoring it means answering
/// `Accept-Encoding: gzip, br;q=0` with brotli bytes the client has just said
/// it cannot decode, and the bundle then fails to load. Browsers do not send
/// it, but intermediaries and embedded clients do, and this is client input on
/// an unauthenticated route.
///
/// A bare `*` deliberately does **not** select a variant. It would be legal to
/// honour, but declining leaves the response in the identity encoding, which
/// every client can read — the safe direction when nothing named the encoding
/// explicitly.
///
/// Every field line is read, not just the first. `Accept-Encoding` is a
/// list-valued header, and RFC 9110 §5.2-5.3 makes repeated field lines of one
/// name semantically identical to a single comma-joined value — the same rule
/// `forwarded::last_element` cites. Reading `HeaderMap::get` sees only the
/// first line, so a client that sends `gzip` and `br` on two lines has the
/// second silently ignored. Browsers send one line; intermediaries and
/// embedded clients do not, and this is client input on an unauthenticated
/// route.
///
/// A `q=0` **refuses** the encoding wherever it appears, including after an
/// unqualified mention of the same name. Flattening the lines is necessary and
/// not sufficient: with a plain `any()`, `br, br;q=0` still accepts `br`, so
/// the function would read every line and still get the answer wrong. The cost
/// of honouring the refusal is the identity encoding, which every client can
/// read.
fn accepts(headers: &HeaderMap, encoding: &str) -> bool {
    let mut accepted = false;
    for part in headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
    {
        let mut fields = part.split(';');
        let name = fields.next().unwrap_or("").trim();
        if !name.eq_ignore_ascii_case(encoding) {
            continue;
        }
        // Any `q` parameter on this entry; absent means q=1. An unparseable
        // one is read as a refusal, which is the safe direction.
        let q = fields.find_map(|p| {
            let (k, val) = p.split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case("q")
                .then(|| val.trim().parse::<f32>().unwrap_or(0.0))
        });
        match q {
            // Written as the acceptance condition rather than as its
            // negation, and range-checked. A qvalue is a number in 0..=1
            // (RFC 9110 §12.4.2); `f32::parse` also accepts `nan`, `inf` and
            // `INFINITY`, and every comparison with NaN is false, so a
            // `q <= 0.0` refusal let `q=nan` fall through to the arm that
            // means "no `q` parameter at all" and serve a brotli body — as
            // did `q=INFINITY`. Stating what is accepted leaves nothing to
            // fall through: anything that is not a weight in range is
            // unreadable, and the line above says an unreadable one is a
            // refusal. The cost of a refusal is the identity encoding, which
            // every client can read.
            //
            // The range check is a behaviour change beyond the float
            // specials, and it is one: `br;q=2` is now a refusal where it was
            // an acceptance. RFC 9110 §12.4.2 bounds a qvalue to 0-1, so a
            // value outside that range is not a weight and refusing it is
            // right — but nothing else in the repository said so, and a
            // caller who sent it was being served brotli.
            Some(q) if q > 0.0 && q <= 1.0 => accepted = true,
            Some(_) => return false,
            None => accepted = true,
        }
    }
    accepted
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
///
/// That hash is over the embedded **bytes** and nothing else, so it is stable
/// across rebuilds of unchanged input — which is what the `immutable`
/// `Cache-Control` on a fingerprinted asset promises, and what makes a 304 on
/// an unchanged `index.html` correct. Established from rust-embed 8.12.0's own
/// source rather than assumed: `rust_embed_utils::read_file_from_fs` computes
/// `Sha256::digest(&data)`, and in a **release** build `rust_embed_impl::embed_file`
/// bakes that value into the binary at compile time. A debug build computes
/// the same digest over the same bytes at request time instead, so the
/// stability argument holds either way — it is content that is hashed, not a
/// build timestamp.
///
/// This is exactly why `Last-Modified` is not used instead. Its sibling field
/// there, `last_modified`, is `fs::metadata().modified()` — a filesystem
/// timestamp the build rewrites on every checkout and every rebuild, so it
/// would invalidate every client's cache for assets that had not changed.
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

/// The strong validator for the representation actually being sent.
///
/// A validator identifies a representation, not a resource: RFC 9110 §8.8.3
/// asks a strong one to change when the bytes on the wire change, and the
/// brotli bytes and the identity bytes of one path are different bytes.
/// `etag` hashes the identity file, so the encoding token has to be folded in
/// or the two representations ship the same validator and a shared cache
/// keyed on it can hand a `.br` body to a client that sent no
/// `Accept-Encoding`. `Vary: accept-encoding` is still sent; this is the half
/// that does not depend on the cache honouring it.
///
/// Kept strong rather than marked weak. Weakening gives up strong-validator
/// semantics on every request to cover a case the token covers exactly.
fn etag_for(file: &rust_embed::EmbeddedFile, encoding: Option<&str>) -> String {
    with_encoding(&etag(file), encoding)
}

/// Fold an encoding token into an entity-tag.
///
/// Split from [`etag_for`] because the rule is about the tag and not about
/// the file, and this is the half a test can reach: `Assets` is whatever the
/// build embedded, so a test cannot rely on a path with a precompressed
/// sibling existing.
fn with_encoding(tag: &str, encoding: Option<&str>) -> String {
    match encoding {
        // Inside the quotes: an entity-tag *is* the quoted string, so the
        // token has to be part of it to be compared by `matches_etag` at all.
        Some(e) => format!("{}-{e}\"", tag.trim_end_matches('"')),
        None => tag.to_string(),
    }
}

/// Whether `If-None-Match` already holds this version.
///
/// `*` matches anything present, per RFC 9110; otherwise any member of the
/// comma-separated list matching the tag is a hit. Weak prefixes are stripped
/// because a weak comparison is the right one for a conditional GET.
///
/// The list is read across **every** field line, as [`accepts`] reads
/// `Accept-Encoding`: RFC 9110 §5.3 makes a list-valued header split over
/// several lines equivalent to one line joined with commas, so a member on
/// the second line is as much a member as one on the first. A `*` member is
/// read as `*` wherever it appears; a line that is not visible ASCII is
/// skipped rather than voiding the others.
fn matches_etag(headers: &HeaderMap, tag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|c| c.trim().trim_start_matches("W/"))
        .any(|c| c == "*" || c == tag)
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

/// Serve `path`, honouring the request's conditional headers.
fn respond(path: &str, req_headers: &HeaderMap) -> Option<Response> {
    respond_inner(path, req_headers, true)
}

/// Serve `path` and ignore `If-None-Match`.
///
/// For the single-page-app fallback, where the path being served is not the
/// path the client asked for. A validator identifies a representation of the
/// *requested* URL, and the client has never fetched this one, so comparing
/// `index.html`'s tag against a conditional request for `/some/deep/link`
/// answers 304 — an empty body and no document — for a URL nothing was ever
/// stored under. `If-None-Match: *` reaches it with no stored validator at
/// all.
///
/// A conformant browser keys `If-None-Match` per URL and would not send one
/// here, but a shared cache revalidating on the operator's behalf is exactly
/// the deployment this change introduces, and `no-cache` on `index.html`
/// makes every deep-link load a revalidation.
fn respond_unconditionally(path: &str, req_headers: &HeaderMap) -> Option<Response> {
    respond_inner(path, req_headers, false)
}

fn respond_inner(path: &str, req_headers: &HeaderMap, conditional: bool) -> Option<Response> {
    let file = Assets::get(path)?;

    // Negotiation happens *before* the validator, because the validator is
    // per representation. `etag()` hashes the identity bytes, so computing it
    // first meant one strong validator covering both the identity body and
    // the `.br` body — which RFC 9110 §8.8.3 asks it not to do, and which lets
    // a shared cache keyed only on the validator hand brotli bytes to a client
    // that sent no `Accept-Encoding`. `Vary: accept-encoding` below makes that
    // tolerable rather than correct.
    let chosen = negotiated(path, req_headers);
    let tag = etag_for(&file, chosen.as_ref().map(|(_, encoding)| *encoding));

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

    if conditional && matches_etag(req_headers, &tag) {
        let mut res = StatusCode::NOT_MODIFIED.into_response();
        *res.headers_mut() = headers;
        return Some(res);
    }

    let mime = mime_guess::from_path(path).first_or_octet_stream();
    if let Ok(v) = HeaderValue::from_str(mime.as_ref()) {
        headers.insert(header::CONTENT_TYPE, v);
    }

    let body = match chosen {
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

/// Whether `path` is a precompressed sibling of an asset rather than an asset.
///
/// `precompress.mjs` writes `<asset>.br` and `<asset>.gz` beside each asset,
/// and `Assets` embeds the whole directory, so every sibling is also an
/// independently addressable URL. Served directly it is compressed bytes with
/// no `Content-Encoding`, under whatever `Content-Type` the `.br`/`.gz`
/// extension guesses, and under `assets/` with a year-long `immutable` —
/// demonstrated: `GET /index.html.br` returned 200,
/// `application/octet-stream`, raw brotli.
///
/// A sibling is a *representation* of the path it sits beside, reachable by
/// negotiating for that path. It is not a resource, so it does not have a URL.
fn is_precompressed_sibling(path: &str) -> bool {
    [".br", ".gz"]
        .iter()
        .filter_map(|suffix| path.strip_suffix(suffix))
        .any(|base| Assets::get(base).is_some())
}

/// A 404 that a shared cache cannot assign heuristic freshness to.
///
/// Neither 404 passes through `respond`, so neither inherited its
/// `Cache-Control` and both went out with none at all. RFC 9111 §4.2.2 lets a
/// cache invent freshness for a response that carries no explicit lifetime,
/// and a fingerprinted asset briefly 404s during a rolling upgrade — long
/// enough for a caching proxy to pin it.
fn not_found(message: &'static str) -> Response {
    let mut res = (StatusCode::NOT_FOUND, message).into_response();
    security_headers(res.headers_mut());
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    // A single-page app owns its own routing, so an unknown path is not a 404 —
    // it is a deep link the client will resolve. Only asset-looking requests
    // get a real 404, so a mistyped script URL fails loudly instead of being
    // answered with HTML.
    let candidate = if path.is_empty() { "index.html" } else { path };

    if is_precompressed_sibling(candidate) {
        return not_found("not found");
    }

    if let Some(res) = respond(candidate, &headers) {
        return res;
    }

    if candidate.contains('.') {
        return not_found("not found");
    }

    // The fallback, and the conditional request does not come with it: the
    // client asked for another URL, so its validator is about another URL.
    match respond_unconditionally("index.html", &headers) {
        Some(res) => res,
        // Built with the feature on but no bundle present: say so plainly
        // rather than serving a blank page.
        None => not_found("the web client was not embedded in this build"),
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
    fn a_member_on_a_later_field_line_matches() {
        let mut h = HeaderMap::new();
        h.append(header::IF_NONE_MATCH, HeaderValue::from_static("\"x\""));
        h.append(header::IF_NONE_MATCH, HeaderValue::from_static("\"abc\""));
        assert!(matches_etag(&h, "\"abc\""));

        let mut h = HeaderMap::new();
        h.append(header::IF_NONE_MATCH, HeaderValue::from_static("\"x\""));
        h.append(header::IF_NONE_MATCH, HeaderValue::from_static("\"y\""));
        assert!(!matches_etag(&h, "\"abc\""));

        // A non-UTF-8 line is skipped, not fatal to the lines around it.
        let mut h = HeaderMap::new();
        h.append(
            header::IF_NONE_MATCH,
            HeaderValue::from_bytes(b"\"\xff\"").unwrap(),
        );
        h.append(header::IF_NONE_MATCH, HeaderValue::from_static("\"abc\""));
        assert!(matches_etag(&h, "\"abc\""));
    }

    #[test]
    fn a_missing_header_never_matches() {
        assert!(!matches_etag(&HeaderMap::new(), "\"abc\""));
    }

    #[test]
    fn a_q_of_zero_is_a_refusal() {
        // RFC 9110 §12.5.3: q=0 means "not acceptable". Serving brotli to a
        // client that just said it cannot decode brotli breaks the bundle.
        let h = headers(&[(header::ACCEPT_ENCODING, "gzip, br;q=0")]);
        assert!(!accepts(&h, "br"), "q=0 is a refusal, not an acceptance");
        assert!(accepts(&h, "gzip"));

        let h = headers(&[(header::ACCEPT_ENCODING, "br;q=0.000")]);
        assert!(!accepts(&h, "br"), "any spelling of zero is still zero");

        let h = headers(&[(header::ACCEPT_ENCODING, "br;q=0.001")]);
        assert!(accepts(&h, "br"), "a low quality is still an acceptance");
    }

    #[test]
    fn a_q_that_is_not_a_weight_is_a_refusal() {
        // The property the doc on `accepts` claims: an unreadable `q` is a
        // refusal. `q=bogus` was refused, which proved the rule was
        // implemented — and `f32::parse` accepts the float specials, so
        // `q=nan` and `q=INFINITY` escaped it. Every comparison with NaN is
        // false, so a refusal written as `q <= 0.0` fell through to the arm
        // that means "no `q` parameter at all" and served a brotli body to a
        // client that never asked for one. Demonstrated live before the fix
        // for all four spellings below.
        for q in [
            "nan", "NaN", "inf", "-inf", "INFINITY", "infinity", "bogus", "", "2", "1.5",
        ] {
            let h = headers(&[(header::ACCEPT_ENCODING, format!("br;q={q}").as_str())]);
            assert!(
                !accepts(&h, "br"),
                "q={q:?} is not a weight in 0..=1, so it cannot be read as an \
                 acceptance",
            );
        }

        // The controls: real weights on either side of the boundary.
        for q in ["0.001", "0.5", "1", "1.0", "1.000"] {
            let h = headers(&[(header::ACCEPT_ENCODING, format!("br;q={q}").as_str())]);
            assert!(accepts(&h, "br"), "q={q:?} is a weight and an acceptance");
        }
    }

    #[test]
    fn a_404_forbids_a_cache_storing_it() {
        // Neither 404 branch passes through `respond`, so neither inherited
        // its `Cache-Control` and both went out with none at all — leaving a
        // shared cache free to invent freshness (RFC 9111 §4.2.2) for a
        // fingerprinted asset that 404s for a moment during a rolling
        // upgrade.
        let res = not_found("not found");
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            res.headers()
                .get(header::CACHE_CONTROL)
                .map(|v| v.to_str().unwrap()),
            Some("no-store"),
            "a 404 must say it is not to be stored",
        );
        assert_eq!(
            res.headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .map(|v| v.to_str().unwrap()),
            Some("nosniff"),
            "and it still carries the security headers it already had",
        );
    }

    #[tokio::test]
    async fn the_spa_fallback_ignores_a_conditional_request_for_another_url() {
        // `respond` evaluated `If-None-Match` against `index.html`'s
        // validator whatever URL was asked for, so a deep link the client has
        // never fetched answered **304 with an empty body** — no document,
        // for a URL nothing was ever stored under. `If-None-Match: *` reaches
        // it with no stored validator at all. A shared cache revalidating on
        // the operator's behalf is exactly the deployment this change
        // introduces.
        assert!(
            Assets::get("index.html").is_some(),
            "the bundle has to be present for this test to be testing \
             anything; `web-ui` is a default feature and the build produces it",
        );
        let tag = etag_for(&Assets::get("index.html").unwrap(), None);

        for inm in [tag.as_str(), "*"] {
            let res = serve(
                "/some/deep/link".parse::<Uri>().unwrap(),
                headers(&[(header::IF_NONE_MATCH, inm)]),
            )
            .await;
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "If-None-Match: {inm} belongs to /some/deep/link, which the \
                 client has never fetched, so the fallback owes it a document",
            );
        }

        // The control: on the URL the validator *is* about, a conditional
        // request still gets its 304.
        let res = serve(
            "/index.html".parse::<Uri>().unwrap(),
            headers(&[(header::IF_NONE_MATCH, &tag)]),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::NOT_MODIFIED,
            "a conditional request for the URL the tag identifies still 304s",
        );
    }

    #[tokio::test]
    async fn a_precompressed_sibling_is_not_a_url_of_its_own() {
        // Every sibling `precompress.mjs` writes is inside the embedded
        // directory, so each was independently addressable and served
        // compressed bytes with no `Content-Encoding`, under whatever
        // Content-Type the `.br` extension guesses, and under `assets/` with
        // a year-long `immutable`. A sibling is a representation of the path
        // it sits beside, reachable by negotiating for that path.
        //
        // This test and its neighbour are the first in the crate to require a
        // built `web/dist`, which is gitignored and which `build.rs` produces
        // by shelling out to npm under the default `web-ui` feature. That is
        // a new coupling between the Rust suite and the web build, and it is
        // deliberate: the assertion below states the precondition rather than
        // skipping, so a `web/dist` left over from before this change — the
        // "using the existing web/dist" fallback path — fails the suite
        // instead of quietly testing nothing.
        assert!(
            Assets::get("index.html.br").is_some(),
            "the precompressed siblings have to be present for this test to \
             be testing anything; the web build writes them",
        );

        for path in ["/index.html.br", "/index.html.gz"] {
            let res = serve(path.parse::<Uri>().unwrap(), HeaderMap::new()).await;
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "{path} is a representation of /index.html, not a resource",
            );
        }

        // The control: the path it is a sibling of is still served, and still
        // negotiates to the sibling's bytes.
        let res = serve(
            "/index.html".parse::<Uri>().unwrap(),
            headers(&[(header::ACCEPT_ENCODING, "br")]),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(header::CONTENT_ENCODING)
                .map(|v| v.to_str().unwrap()),
            Some("br"),
            "the brotli bytes are still reachable, by negotiating for them",
        );

        // And a `.br` path with nothing beside it is an ordinary miss rather
        // than a sibling.
        assert!(!is_precompressed_sibling("no-such-asset.js.br"));
    }

    #[test]
    fn a_wildcard_does_not_select_a_variant() {
        // Declining leaves the identity encoding, which every client reads.
        let h = headers(&[(header::ACCEPT_ENCODING, "*")]);
        assert!(!accepts(&h, "br"));
        assert!(!accepts(&h, "gzip"));
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

    /// A `HeaderMap` where a repeated name becomes a second field line rather
    /// than replacing the first, which is what an appending intermediary
    /// produces.
    fn appended(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(k.clone(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn accept_encoding_is_read_across_every_field_line() {
        // RFC 9110 §5.2-5.3: repeated field lines of one name are one
        // comma-joined value. `HeaderMap::get` returns only the first, so a
        // client that sends `gzip` and `br` on two lines has the second
        // ignored and the 226 KB bundle goes out gzip-compressed — or, with
        // the order reversed, raw.
        let h = appended(&[
            (header::ACCEPT_ENCODING, "gzip"),
            (header::ACCEPT_ENCODING, "br"),
        ]);
        assert!(
            accepts(&h, "br"),
            "the second field line is part of the value"
        );
        assert!(accepts(&h, "gzip"));
        assert!(!accepts(&h, "zstd"));

        // And in the other order, so this is not passing by reading only the
        // last line either.
        let h = appended(&[
            (header::ACCEPT_ENCODING, "br"),
            (header::ACCEPT_ENCODING, "gzip"),
        ]);
        assert!(accepts(&h, "br"));
        assert!(accepts(&h, "gzip"));
    }

    #[test]
    fn a_q_zero_refuses_an_encoding_wherever_it_appears() {
        // Flattening the field lines is necessary and not sufficient. A plain
        // `any()` over the flattened list accepts `br, br;q=0`, because the
        // first mention satisfies it and the refusal is never reached — so
        // the function would read every line and still answer wrongly. A
        // client that says q=0 has stated it cannot decode the encoding; the
        // cost of believing it is the identity encoding, which every client
        // can read.
        assert!(
            !accepts(&headers(&[(header::ACCEPT_ENCODING, "br, br;q=0")]), "br"),
            "a later q=0 refuses an encoding named earlier",
        );
        assert!(
            !accepts(&headers(&[(header::ACCEPT_ENCODING, "br;q=0, br")]), "br"),
            "and an earlier one refuses a later mention",
        );
        assert!(
            !accepts(
                &appended(&[
                    (header::ACCEPT_ENCODING, "gzip, br"),
                    (header::ACCEPT_ENCODING, "br;q=0"),
                ]),
                "br",
            ),
            "including across field lines, which is the case both halves of \
             this repair have to cover together",
        );
        // The refusal is specific to the encoding named.
        assert!(accepts(
            &headers(&[(header::ACCEPT_ENCODING, "gzip, br;q=0")]),
            "gzip",
        ));
    }

    #[test]
    fn a_precompressed_representation_gets_its_own_validator() {
        // A strong validator identifies a representation, not a resource
        // (RFC 9110 §8.8.3). `etag` hashes the identity bytes, so without the
        // encoding token the `.br` body and the raw body ship the same one,
        // and a shared cache keyed only on the validator can hand brotli
        // bytes to a client that sent no `Accept-Encoding`.
        let identity = "\"0123456789abcdef\"";
        let br = with_encoding(identity, Some("br"));
        let gzip = with_encoding(identity, Some("gzip"));

        assert_ne!(br, identity, "the brotli body is not the identity body");
        assert_ne!(gzip, identity);
        assert_ne!(br, gzip, "nor is it the gzip body");
        assert_eq!(
            with_encoding(identity, None),
            identity,
            "an unencoded response keeps the validator it always had",
        );

        // Still a syntactically valid entity-tag, so `matches_etag` — which
        // compares the quoted string — can hit on it.
        assert!(br.starts_with('"') && br.ends_with('"'));
        assert!(
            matches_etag(&headers(&[(header::IF_NONE_MATCH, &br)]), &br),
            "a client holding the brotli representation still gets its 304",
        );
        assert!(
            !matches_etag(&headers(&[(header::IF_NONE_MATCH, identity)]), &br),
            "and one holding the identity representation does not",
        );
    }
}
