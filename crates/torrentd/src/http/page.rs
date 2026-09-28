//! Cursor pagination, the one paging scheme `/v1` uses.
//!
//! A cursor is opaque to clients: base64url (unpadded) of
//! `v1:<listing>:<sort key>`. The version lets the sort key change without a
//! new API version. The listing names the collection *and* whatever scopes it
//! — a torrent's files carry its infohash, a directory listing its root and
//! path — so a cursor from one collection is invalid on another rather than
//! silently meaningful. Each listing also checks the key's shape, so a cursor
//! that decodes to nonsense is refused rather than answered with an empty
//! page. Either failure is a `400 invalid-cursor` — never a quiet restart from
//! the first page, which is what the previous API did and which made a client
//! loop forever on a corrupted cursor.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::http::validate::Invalid;

/// Items per page when the request names no `limit`.
pub const DEFAULT_LIMIT: u32 = 100;
/// The largest `limit` a request may name.
pub const MAX_LIMIT: u32 = 1000;

const VERSION: &str = "v1";

/// A validated page request: where to resume, and how many items to return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageRequest {
    /// The sort key of the last item the client already has, if any.
    pub after: Option<String>,
    pub limit: usize,
}

/// The cursor did not decode, or belongs to another listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCursor;

impl PageRequest {
    /// Validate `limit` into `invalid`, and decode `cursor` for `listing`.
    ///
    /// A bad `limit` is recorded as a violation, so it is reported alongside
    /// every other constraint the request broke; a bad cursor is its own
    /// failure, because nothing about the request is meaningful without it.
    pub fn parse(
        listing: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
        key_ok: impl Fn(&str) -> bool,
        invalid: &mut Invalid,
    ) -> Result<PageRequest, InvalidCursor> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT);
        invalid.check((1..=MAX_LIMIT).contains(&limit), "#/query/limit", || {
            format!("must be between 1 and {MAX_LIMIT}")
        });
        let after = cursor.map(|c| decode(listing, c)).transpose()?;
        if after.as_deref().is_some_and(|key| !key_ok(key)) {
            return Err(InvalidCursor);
        }
        Ok(PageRequest {
            after,
            limit: limit.clamp(1, MAX_LIMIT) as usize,
        })
    }
}

/// The cursor that resumes `listing` after `key`.
pub fn encode(listing: &str, key: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{VERSION}:{listing}:{key}"))
}

fn decode(listing: &str, cursor: &str) -> Result<String, InvalidCursor> {
    let raw = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| InvalidCursor)?;
    let raw = String::from_utf8(raw).map_err(|_| InvalidCursor)?;
    let rest = raw
        .strip_prefix(VERSION)
        .and_then(|r| r.strip_prefix(':'))
        .and_then(|r| r.strip_prefix(listing))
        .and_then(|r| r.strip_prefix(':'))
        .ok_or(InvalidCursor)?;
    Ok(rest.to_owned())
}

/// Whether `key` is a zero-padded decimal of `width` digits, the key shape of
/// a listing ordered by a number.
pub fn is_padded_decimal(key: &str, width: usize) -> bool {
    key.len() == width && key.bytes().all(|b| b.is_ascii_digit())
}

/// Take one page from `items`, already sorted ascending by `key`.
///
/// Returns the page and the cursor for the next one, which is `None` exactly
/// when nothing follows.
pub fn paginate<T>(
    listing: &str,
    items: impl IntoIterator<Item = T>,
    key: impl Fn(&T) -> String,
    page: &PageRequest,
) -> (Vec<T>, Option<String>) {
    let mut iter = items
        .into_iter()
        .skip_while(|item| {
            page.after
                .as_deref()
                .is_some_and(|after| key(item).as_str() <= after)
        })
        .peekable();
    let mut out = Vec::with_capacity(page.limit.min(64));
    while out.len() < page.limit {
        match iter.next() {
            Some(item) => out.push(item),
            None => break,
        }
    }
    let next = match (iter.peek(), out.last()) {
        (Some(_), Some(last)) => Some(encode(listing, &key(last))),
        _ => None,
    };
    (out, next)
}

/// A concrete, named page type.
///
/// kynos inlines generic instantiations rather than naming them, so a
/// `Page<T>` would reach every client as an anonymous schema. One named
/// struct per collection keeps the document's components meaningful.
macro_rules! page {
    ($(#[$meta:meta])* $name:ident, $item:ty) => {
        $(#[$meta])*
        #[derive(Debug, kynos::Schema, serde::Serialize)]
        pub struct $name {
            /// This page's items, in the collection's order.
            pub items: Vec<$item>,
            /// Pass as `cursor` to fetch the next page; `null` on the last one.
            pub next_cursor: Option<String>,
        }
    };
}
pub(crate) use page;

#[cfg(test)]
mod tests {
    use super::*;

    fn req(
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> (Result<PageRequest, InvalidCursor>, Invalid) {
        let mut invalid = Invalid::new();
        let r = PageRequest::parse(
            "things",
            cursor,
            limit,
            |k| k.starts_with('k'),
            &mut invalid,
        );
        (r, invalid)
    }

    #[test]
    fn a_page_resumes_strictly_after_its_cursor_and_the_last_page_has_none() {
        let keys: Vec<String> = (0..5).map(|i| format!("k{i}")).collect();
        let (first, invalid) = req(None, Some(2));
        assert!(invalid.violations.is_empty());
        let first = first.unwrap();
        let (items, next) = paginate("things", keys.clone(), |k| k.clone(), &first);
        assert_eq!(items, ["k0", "k1"]);
        let next = next.expect("more follow");

        let (second, _) = req(Some(&next), Some(2));
        let (items, next) = paginate("things", keys.clone(), |k| k.clone(), &second.unwrap());
        assert_eq!(items, ["k2", "k3"]);

        let (third, _) = req(next.as_deref(), Some(2));
        let (items, next) = paginate("things", keys, |k| k.clone(), &third.unwrap());
        assert_eq!(items, ["k4"]);
        assert_eq!(next, None);
    }

    #[test]
    fn an_exactly_full_last_page_has_no_cursor() {
        let keys = vec!["a".to_owned(), "b".to_owned()];
        let page = req(None, Some(2)).0.unwrap();
        let (items, next) = paginate("things", keys, |k| k.clone(), &page);
        assert_eq!(items.len(), 2);
        assert_eq!(next, None);
    }

    #[test]
    fn a_garbled_or_foreign_cursor_is_refused_rather_than_restarting() {
        assert_eq!(req(Some("!!!"), None).0, Err(InvalidCursor));
        let foreign = encode("other", "k1");
        assert_eq!(req(Some(&foreign), None).0, Err(InvalidCursor));
        let unversioned = URL_SAFE_NO_PAD.encode("things:k1");
        assert_eq!(req(Some(&unversioned), None).0, Err(InvalidCursor));
        // Decodes, belongs to this listing, and names no key it could hold.
        let nonsense = encode("things", "zzz");
        assert_eq!(req(Some(&nonsense), None).0, Err(InvalidCursor));
    }

    #[test]
    fn a_limit_out_of_range_is_a_violation_not_a_clamp() {
        for bad in [0, MAX_LIMIT + 1] {
            let (_, invalid) = req(None, Some(bad));
            assert_eq!(invalid.violations.len(), 1, "limit {bad}");
            assert_eq!(invalid.violations[0].pointer, "#/query/limit");
        }
        let (page, invalid) = req(None, None);
        assert!(invalid.violations.is_empty());
        assert_eq!(page.unwrap().limit, DEFAULT_LIMIT as usize);
    }
}
