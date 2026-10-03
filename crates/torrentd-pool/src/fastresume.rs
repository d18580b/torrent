//! Minimal reader for the hints in another client's `.fastresume`.
//!
//! A `.fastresume` is libtorrent resume data, so libtorrent could parse it —
//! but it deliberately ignores the `qBt-*` extension keys qBittorrent writes,
//! and those carry exactly the migration hints worth having: where the payload
//! actually lives, and how the operator had it organised.
//!
//! Scope is deliberately tiny: read strings and flat lists of strings at the
//! **top level** of one bencoded dict, and give up on anything unexpected. This is
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
    /// Every piece is marked had in the resume data's `pieces` bitfield. A
    /// complete torrent whose files still match on disk can skip
    /// re-verification at adopt time.
    pub is_complete: bool,
    /// libtorrent's `mapped_files`: a file the previous client renamed, by
    /// index into the torrent's file list. `None` where it kept the name.
    pub mapped_files: Vec<Option<String>>,
    /// qBittorrent's `qBt-contentLayout`: `Original`, `Subfolder` or
    /// `NoSubfolder`.
    pub content_layout: Option<String>,
}

/// Where the previous client put a torrent's files, when not where the
/// `.torrent` says.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relayout {
    /// The on-disk relative path of every file, index-aligned.
    pub paths: Vec<String>,
    /// Whether libtorrent learns these paths from the resume data itself:
    /// true for `mapped_files`, false for a layout only qBittorrent's own key
    /// records. A torrent added without that resume data looks for its files
    /// at the `.torrent`'s paths.
    pub in_resume_data: bool,
}

impl ResumeHints {
    /// The on-disk paths for a torrent whose `.torrent` lists `paths` under
    /// `name`, or `None` when the previous client kept them as they are.
    ///
    /// `mapped_files` wins: it is what the client actually did. Failing it,
    /// `qBt-contentLayout` is applied the way qBittorrent applies it —
    /// `NoSubfolder` drops a multi-file torrent's top directory, `Subfolder`
    /// puts a single file inside a directory named after it without its
    /// extension.
    pub fn relayout(&self, paths: &[String], name: &str) -> Option<Relayout> {
        if self.mapped_files.iter().any(Option::is_some) {
            let mapped = paths
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    self.mapped_files
                        .get(i)
                        .cloned()
                        .flatten()
                        .map(|m| m.replace('\\', "/").trim_matches('/').to_owned())
                        .filter(|m| is_relative_and_contained(m))
                        .unwrap_or_else(|| p.clone())
                })
                .collect();
            return Some(Relayout {
                paths: mapped,
                in_resume_data: true,
            });
        }
        let in_name_dir = |p: &String| p.split_once('/').is_some_and(|(top, _)| top == name);
        match self.content_layout.as_deref() {
            Some("NoSubfolder") if paths.len() > 1 && paths.iter().all(in_name_dir) => {
                Some(Relayout {
                    paths: paths
                        .iter()
                        .map(|p| p.split_once('/').map_or(p.clone(), |(_, r)| r.to_owned()))
                        .collect(),
                    in_resume_data: false,
                })
            }
            Some("Subfolder") if paths.len() == 1 && !paths[0].contains('/') => {
                let stem = Path::new(&paths[0])
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&paths[0])
                    .to_owned();
                Some(Relayout {
                    paths: vec![format!("{stem}/{}", paths[0])],
                    in_resume_data: false,
                })
            }
            _ => None,
        }
    }
}

/// A mapped path is joined onto a base directory; one that is absolute or
/// walks out of it is not a layout, and is ignored.
fn is_relative_and_contained(p: &str) -> bool {
    !p.is_empty()
        && Path::new(p)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
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

    // Completion is read from the `pieces` bitfield — one byte per piece, the
    // low bit set for a piece the client had — and nothing else.
    //
    // `seed_mode` is not completion: libtorrent sets it for a torrent *added*
    // as a seed, whose pieces nobody has checked yet, which is the opposite of
    // the claim this flag would stand in for. `qBt-seedStatus` is
    // qBittorrent's own idea of what it was doing, not a statement about the
    // pieces. Absent a bitfield, or with any piece missing from it,
    // completion is unknown and adoption takes the verifying path.
    let is_complete = match top.get("pieces") {
        Some(Value::Str(bits)) => !bits.is_empty() && bits.iter().all(|b| b & 1 == 1),
        _ => false,
    };

    let mapped_files = match top.get("mapped_files") {
        Some(Value::List(items)) => items
            .iter()
            .map(|b| String::from_utf8(b.clone()).ok().filter(|s| !s.is_empty()))
            .collect(),
        _ => Vec::new(),
    };

    ResumeHints {
        save_path: save_path.filter(|s| !s.is_empty()),
        category: get_str("qBt-category").filter(|s| !s.is_empty()),
        tags,
        is_complete,
        mapped_files,
        content_layout: get_str("qBt-contentLayout").filter(|s| !s.is_empty()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(Vec<u8>),
    /// A list of strings — `mapped_files` is the one read.
    List(Vec<Vec<u8>>),
    /// Present but not a value we read; kept so key iteration stays aligned.
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
                // Validated, so a malformed integer still fails the parse;
                // no integer key is read any more.
                let _: i64 = std::str::from_utf8(&self.b[start..self.i])
                    .ok()?
                    .parse()
                    .ok()?;
                self.i += 1; // consume 'e'
                Some(Value::Skipped)
            }
            b'0'..=b'9' => self.read_bytes().map(Value::Str),
            b'l' => {
                // A flat list of strings is read; anything else in it means
                // it is not one, and the whole list is stepped over instead.
                let start = self.i;
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    match self.peek()? {
                        b'e' => {
                            self.i += 1;
                            return Some(Value::List(items));
                        }
                        b'0'..=b'9' => items.push(self.read_bytes()?),
                        _ => {
                            self.i = start;
                            self.skip_container()?;
                            return Some(Value::Skipped);
                        }
                    }
                }
            }
            b'd' => {
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
            ("pieces", bbytes(&[1, 1, 1])),
            ("save_path", bstr("/old/path")),
        ]);

        let h = parse_hints(&b);
        assert_eq!(h.save_path.as_deref(), Some("/data/pool"));
        assert_eq!(h.category.as_deref(), Some("movies"));
        assert_eq!(h.tags, vec!["hd", "seeded"]);
        assert!(h.is_complete);
    }

    fn bbytes(b: &[u8]) -> Vec<u8> {
        let mut v = format!("{}:", b.len()).into_bytes();
        v.extend_from_slice(b);
        v
    }

    fn blist(items: &[&str]) -> Vec<u8> {
        let mut v = b"l".to_vec();
        for i in items {
            v.extend_from_slice(&bstr(i));
        }
        v.push(b'e');
        v
    }

    #[test]
    fn completeness_is_the_pieces_bitfield_and_nothing_else() {
        // Every piece had: complete.
        let b = bdict(&[("pieces", bbytes(&[1, 1, 1, 1]))]);
        assert!(parse_hints(&b).is_complete);
        // One missing: not, whatever the flags say.
        let b = bdict(&[
            ("pieces", bbytes(&[1, 0, 1])),
            ("qBt-seedStatus", bint(1)),
            ("seed_mode", bint(1)),
        ]);
        assert!(!parse_hints(&b).is_complete);
        // `seed_mode` is a torrent *added* as a seed, unchecked: not a claim.
        let b = bdict(&[("save_path", bstr("/data")), ("seed_mode", bint(1))]);
        assert!(!parse_hints(&b).is_complete);
        // Neither is qBittorrent's own status flag.
        let b = bdict(&[("qBt-seedStatus", bint(1))]);
        assert!(!parse_hints(&b).is_complete);
        // An empty bitfield proves nothing.
        let b = bdict(&[("pieces", bbytes(&[]))]);
        assert!(!parse_hints(&b).is_complete);
    }

    #[test]
    fn mapped_files_rename_the_files_they_name() {
        let b = bdict(&[(
            "mapped_files",
            blist(&["", "Show/renamed.mkv", "../escape", ""]),
        )]);
        let h = parse_hints(&b);
        let paths: Vec<String> = ["Show/a.mkv", "Show/b.mkv", "Show/c.nfo", "Show/d.srt"]
            .map(String::from)
            .to_vec();
        let r = h.relayout(&paths, "Show").unwrap();
        assert!(r.in_resume_data);
        assert_eq!(
            r.paths,
            ["Show/a.mkv", "Show/renamed.mkv", "Show/c.nfo", "Show/d.srt"],
            "a traversal is not a layout and is ignored",
        );
        // A list holding anything but strings is skipped, not misread.
        let b = bdict(&[
            ("mapped_files", b"li1ee".to_vec()),
            ("qBt-savePath", bstr("/p")),
        ]);
        let h = parse_hints(&b);
        assert!(h.mapped_files.is_empty());
        assert_eq!(h.save_path.as_deref(), Some("/p"));
    }

    #[test]
    fn qbittorrents_content_layout_is_applied_without_mapped_files() {
        let multi: Vec<String> = ["Show/a.mkv", "Show/sub/b.mkv"].map(String::from).to_vec();
        let single = vec!["Film.2020.mkv".to_owned()];
        let layout = |l: &str| ResumeHints {
            content_layout: Some(l.to_owned()),
            ..ResumeHints::default()
        };

        let r = layout("NoSubfolder").relayout(&multi, "Show").unwrap();
        assert_eq!(r.paths, ["a.mkv", "sub/b.mkv"]);
        assert!(!r.in_resume_data);
        let r = layout("Subfolder")
            .relayout(&single, "Film.2020.mkv")
            .unwrap();
        assert_eq!(r.paths, ["Film.2020/Film.2020.mkv"]);
        assert_eq!(layout("Original").relayout(&multi, "Show"), None);
        assert_eq!(layout("NoSubfolder").relayout(&single, "Film"), None);
        assert_eq!(ResumeHints::default().relayout(&multi, "Show"), None);
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
    fn incomplete_torrents_are_not_reported_complete() {
        // No bitfield at all: completion is unknown, so adoption must take
        // the verifying path rather than trusting the file.
        let b = bdict(&[("qBt-savePath", bstr("/data/pool"))]);
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
