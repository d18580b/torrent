//! Minimal reader for the hints in another client's `.fastresume`.
//!
//! A `.fastresume` is libtorrent resume data, so libtorrent could parse it —
//! but it deliberately ignores the `qBt-*` extension keys qBittorrent writes,
//! and those carry exactly the migration hints worth having: where the payload
//! actually lives, and how the operator had it organised.
//!
//! Scope is deliberately tiny: read string and integer values at the **top
//! level** of one bencoded dict, and give up on anything unexpected. This is
//! not a general bencode implementation and must never grow into one — in
//! particular it is never used to compute an info-hash, which stays in
//! libtorrent so the daemon cannot disagree with itself about a torrent's
//! identity. Every failure degrades to "no hint", never to a wrong hint.

use std::collections::HashMap;
use std::path::Path;

/// Hints recovered from a `.fastresume`. Every field is best-effort.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResumeHints {
    /// Where the previous client believed the payload lived.
    pub save_path: Option<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    /// qBittorrent records completion; a complete torrent whose files still
    /// match on disk can skip re-verification at adopt time.
    pub is_complete: bool,
}

pub fn read_hints(path: &Path) -> ResumeHints {
    match std::fs::read(path) {
        Ok(bytes) => parse_hints(&bytes),
        Err(_) => ResumeHints::default(),
    }
}

pub fn parse_hints(bytes: &[u8]) -> ResumeHints {
    let Some(top) = top_level_entries(bytes) else {
        return ResumeHints::default();
    };
    let get_str = |k: &str| -> Option<String> {
        top.get(k).and_then(|v| match v {
            Value::Str(s) => String::from_utf8(s.clone()).ok(),
            _ => None,
        })
    };
    let get_int = |k: &str| -> Option<i64> {
        top.get(k).and_then(|v| match v {
            Value::Int(i) => Some(*i),
            _ => None,
        })
    };

    // qBittorrent writes both; its own key is authoritative when they differ,
    // because `save_path` may still hold a pre-move location.
    let save_path = get_str("qBt-savePath").or_else(|| get_str("save_path"));

    let tags = get_str("qBt-tags")
        .map(|t| {
            t.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // Completion can be asserted two ways, and either is enough.
    //
    // `qBt-seedStatus` is qBittorrent's own flag. `seed_mode` is libtorrent's,
    // written by any client built on it once a torrent is a complete seed, so
    // honouring it means a migration from something other than qBittorrent
    // still gets the fast path instead of re-hashing the whole pool.
    //
    // Absent both, completion is unknown and adoption takes the verifying
    // path — never the other way round.
    let is_complete =
        get_int("qBt-seedStatus").unwrap_or(0) != 0 || get_int("seed_mode").unwrap_or(0) != 0;

    ResumeHints {
        save_path: save_path.filter(|s| !s.is_empty()),
        category: get_str("qBt-category").filter(|s| !s.is_empty()),
        tags,
        is_complete,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(Vec<u8>),
    Int(i64),
    /// Present but not a scalar we read; kept so key iteration stays aligned.
    Skipped,
}

/// Parse one top-level bencoded dict into its scalar entries, skipping over
/// nested structures without interpreting them.
fn top_level_entries(bytes: &[u8]) -> Option<HashMap<String, Value>> {
    let mut p = Parser { b: bytes, i: 0 };
    p.expect(b'd')?;
    let mut out = HashMap::new();
    while p.peek()? != b'e' {
        let key = p.read_bytes()?;
        let value = p.read_value()?;
        if let Ok(k) = String::from_utf8(key) {
            out.insert(k, value);
        }
    }
    Some(out)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn expect(&mut self, c: u8) -> Option<()> {
        if self.peek()? == c {
            self.i += 1;
            Some(())
        } else {
            None
        }
    }

    /// `<len>:<bytes>`
    fn read_bytes(&mut self) -> Option<Vec<u8>> {
        let start = self.i;
        while self.peek()?.is_ascii_digit() {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        let len: usize = std::str::from_utf8(&self.b[start..self.i])
            .ok()?
            .parse()
            .ok()?;
        self.expect(b':')?;
        // Guard against a length header that overruns the buffer, which is the
        // one way a malformed file could panic here.
        let end = self.i.checked_add(len)?;
        if end > self.b.len() {
            return None;
        }
        let out = self.b[self.i..end].to_vec();
        self.i = end;
        Some(out)
    }

    fn read_value(&mut self) -> Option<Value> {
        match self.peek()? {
            b'i' => {
                self.i += 1;
                let start = self.i;
                while self.peek()? != b'e' {
                    self.i += 1;
                }
                let n: i64 = std::str::from_utf8(&self.b[start..self.i])
                    .ok()?
                    .parse()
                    .ok()?;
                self.i += 1; // consume 'e'
                Some(Value::Int(n))
            }
            b'0'..=b'9' => self.read_bytes().map(Value::Str),
            b'l' | b'd' => {
                self.skip_container()?;
                Some(Value::Skipped)
            }
            _ => None,
        }
    }

    /// Skip a list or dict without interpreting its contents.
    fn skip_container(&mut self) -> Option<()> {
        let mut depth = 0usize;
        loop {
            match self.peek()? {
                b'l' | b'd' => {
                    depth += 1;
                    self.i += 1;
                }
                b'e' => {
                    self.i += 1;
                    depth -= 1;
                    if depth == 0 {
                        return Some(());
                    }
                }
                b'i' => {
                    self.i += 1;
                    while self.peek()? != b'e' {
                        self.i += 1;
                    }
                    self.i += 1;
                }
                b'0'..=b'9' => {
                    self.read_bytes()?;
                }
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build bencode with computed lengths. Hand-written fixtures get the
    /// length prefixes wrong and then fail for reasons unrelated to the code
    /// under test.
    fn bstr(s: &str) -> Vec<u8> {
        let mut v = format!("{}:", s.len()).into_bytes();
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn bint(n: i64) -> Vec<u8> {
        format!("i{n}e").into_bytes()
    }

    /// `entries` are (key, already-encoded value) pairs.
    fn bdict(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = b"d".to_vec();
        for (k, v) in entries {
            out.extend_from_slice(&bstr(k));
            out.extend_from_slice(v);
        }
        out.push(b'e');
        out
    }

    #[test]
    fn reads_qbittorrent_hints() {
        let b = bdict(&[
            ("qBt-category", bstr("movies")),
            ("qBt-savePath", bstr("/data/pool")),
            ("qBt-tags", bstr("hd,seeded")),
            ("qBt-seedStatus", bint(1)),
            ("save_path", bstr("/old/path")),
        ]);

        let h = parse_hints(&b);
        assert_eq!(h.save_path.as_deref(), Some("/data/pool"));
        assert_eq!(h.category.as_deref(), Some("movies"));
        assert_eq!(h.tags, vec!["hd", "seeded"]);
        assert!(h.is_complete);
    }

    #[test]
    fn qbt_save_path_wins_over_a_stale_plain_save_path() {
        // qBittorrent updates its own key on a move; `save_path` can lag.
        let b = bdict(&[
            ("save_path", bstr("/old/path")),
            ("qBt-savePath", bstr("/new/path")),
        ]);
        assert_eq!(parse_hints(&b).save_path.as_deref(), Some("/new/path"));
    }

    #[test]
    fn falls_back_to_plain_save_path() {
        let b = bdict(&[("save_path", bstr("/data/pool"))]);
        assert_eq!(parse_hints(&b).save_path.as_deref(), Some("/data/pool"));
    }

    #[test]
    fn skips_nested_structures_and_keeps_reading() {
        // A real .fastresume interleaves `pieces`, `file sizes`, `peers` and
        // friends between the keys we want; the reader has to step over them
        // without losing alignment.
        let mut nested_list = b"l".to_vec();
        nested_list.extend_from_slice(&bint(123));
        nested_list.extend_from_slice(&bint(456));
        nested_list.extend_from_slice(&bstr("a string in a list"));
        nested_list.push(b'e');

        let mut inner = b"d".to_vec();
        inner.extend_from_slice(&bstr("host"));
        inner.extend_from_slice(&nested_list.clone());
        inner.push(b'e');

        let b = bdict(&[
            ("file sizes", nested_list),
            ("peers", inner),
            ("qBt-savePath", bstr("/data/pool")),
        ]);
        assert_eq!(parse_hints(&b).save_path.as_deref(), Some("/data/pool"));
    }

    #[test]
    fn malformed_input_yields_no_hints_rather_than_panicking() {
        for bad in [
            &b""[..],
            &b"not bencode"[..],
            &b"d"[..],
            &b"d3:key"[..],
            // Length header that overruns the buffer.
            &b"d9:save_path999:/data"[..],
            &b"d12:qBt-savePathi"[..],
            // Unterminated nested container.
            &b"d10:file sizesli1e"[..],
        ] {
            assert_eq!(parse_hints(bad), ResumeHints::default(), "input {bad:?}");
        }
    }

    #[test]
    fn libtorrents_own_seed_mode_flag_also_means_complete() {
        // Resume data from any libtorrent-based client, not just qBittorrent.
        let b = bdict(&[("save_path", bstr("/data")), ("seed_mode", bint(1))]);
        assert!(parse_hints(&b).is_complete);
    }

    #[test]
    fn incomplete_torrents_are_not_reported_complete() {
        // No qBt-seedStatus at all: completion is unknown, so adoption must
        // take the verifying path rather than trusting the file.
        let b = bdict(&[("qBt-savePath", bstr("/data/pool"))]);
        assert!(!parse_hints(&b).is_complete);
        // An explicit zero on either key is still "not complete".
        let b = bdict(&[("seed_mode", bint(0)), ("qBt-seedStatus", bint(0))]);
        assert!(!parse_hints(&b).is_complete);
    }

    #[test]
    fn empty_strings_are_treated_as_absent() {
        let b = bdict(&[("qBt-savePath", bstr("")), ("qBt-category", bstr(""))]);
        let h = parse_hints(&b);
        assert_eq!(h.save_path, None);
        assert_eq!(h.category, None);
    }
}
