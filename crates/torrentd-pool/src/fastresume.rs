//! Minimal reader for the hints in another client's `.fastresume`.
//!
//! A `.fastresume` is libtorrent resume data, so libtorrent could parse it —
//! but it deliberately ignores the `qBt-*` extension keys qBittorrent writes,
//! and those carry exactly the migration hints worth having: where the payload
//! actually lives, and how the operator had it organised.
//!
//! Scope is deliberately tiny: read strings, flat lists of strings, and lists
//! of those (libtorrent's `trackers` tiers) at the **top level** of one
//! bencoded dict, and give up on anything unexpected. This is
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
    /// `mapped_files` entries that are not UTF-8, and so are not in
    /// `mapped_files` although libtorrent would still apply them.
    pub mapped_files_unreadable: usize,
    /// qBittorrent's `qBt-contentLayout`: `Original`, `Subfolder` or
    /// `NoSubfolder`.
    pub content_layout: Option<String>,
    /// libtorrent's `trackers`: the announce URLs by tier, as the previous
    /// client last had them. qBittorrent 4.4 and later keep a torrent's
    /// trackers here and may write its `.torrent` without any. Empty URLs,
    /// URLs that are not UTF-8 or hold a NUL, and tiers left empty are
    /// dropped.
    pub trackers: Vec<Vec<String>>,
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
    /// `mapped_files` entries refused — absolute, walking out of the base, or
    /// not UTF-8 — whose file `paths` therefore gives at the `.torrent`'s own
    /// path. libtorrent, handed the same resume data, still applies them, so
    /// the index and libtorrent disagree about where those files are.
    pub rejected: usize,
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
        if self.mapped_files.iter().any(Option::is_some) || self.mapped_files_unreadable > 0 {
            let mut rejected = self.mapped_files_unreadable;
            let mapped = paths
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let Some(m) = self.mapped_files.get(i).cloned().flatten() else {
                        return p.clone();
                    };
                    let m = m.replace('\\', "/");
                    if is_relative_and_contained(&m) {
                        m.trim_matches('/').to_owned()
                    } else {
                        rejected += 1;
                        p.clone()
                    }
                })
                .collect();
            return Some(Relayout {
                paths: mapped,
                in_resume_data: true,
                rejected,
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
                    rejected: 0,
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
                    rejected: 0,
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

    // An empty entry is a file the client did not rename. One that is not
    // UTF-8 is a rename this reader cannot follow, and is counted so the
    // layout built from these says so.
    let mut mapped_files_unreadable = 0;
    let mapped_files = match top.get("mapped_files") {
        Some(Value::List(items)) => items
            .iter()
            .map(|b| match String::from_utf8(b.clone()) {
                Ok(s) => Some(s).filter(|s| !s.is_empty()),
                Err(_) => {
                    mapped_files_unreadable += 1;
                    None
                }
            })
            .collect(),
        _ => Vec::new(),
    };

    // A list of tiers, each a list of URLs. A flat list, or one holding
    // anything else, is not libtorrent's format and reads as none.
    let trackers = match top.get("trackers") {
        Some(Value::Tiers(tiers)) => tiers
            .iter()
            .map(|tier| {
                tier.iter()
                    .filter_map(|u| String::from_utf8(u.clone()).ok())
                    // A NUL cannot cross to libtorrent as a C string.
                    .filter(|u| !u.is_empty() && !u.contains('\0'))
                    .collect::<Vec<_>>()
            })
            .filter(|tier| !tier.is_empty())
            .collect(),
        _ => Vec::new(),
    };

    ResumeHints {
        save_path: save_path.filter(|s| !s.is_empty()),
        category: get_str("qBt-category").filter(|s| !s.is_empty()),
        tags,
        is_complete,
        mapped_files,
        mapped_files_unreadable,
        content_layout: get_str("qBt-contentLayout").filter(|s| !s.is_empty()),
        trackers,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(Vec<u8>),
    /// A list of strings — `mapped_files` is the one read.
    List(Vec<Vec<u8>>),
    /// A list of lists of strings — `trackers`, by tier.
    Tiers(Vec<Vec<Vec<u8>>>),
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
                // A flat list of strings, or a list of flat lists of strings,
                // is read; anything else in it — a mix of the two included —
                // means it is neither, and the whole list is stepped over.
                let start = self.i;
                self.i += 1;
                let mut items = Vec::new();
                let mut tiers = Vec::new();
                loop {
                    match self.peek()? {
                        b'e' => {
                            self.i += 1;
                            return Some(if tiers.is_empty() {
                                Value::List(items)
                            } else {
                                Value::Tiers(tiers)
                            });
                        }
                        b'0'..=b'9' if tiers.is_empty() => items.push(self.read_bytes()?),
                        b'l' if items.is_empty() => match self.read_flat_list() {
                            Some(tier) => tiers.push(tier),
                            None => {
                                self.i = start;
                                self.skip_container()?;
                                return Some(Value::Skipped);
                            }
                        },
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

    /// `l<string>*e`, or `None` at anything else.
    fn read_flat_list(&mut self) -> Option<Vec<Vec<u8>>> {
        self.expect(b'l')?;
        let mut items = Vec::new();
        loop {
            match self.peek()? {
                b'e' => {
                    self.i += 1;
                    return Some(items);
                }
                b'0'..=b'9' => items.push(self.read_bytes()?),
                _ => return None,
            }
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
        assert_eq!(r.rejected, 1, "but it is counted");
        // An absolute mapping is refused before anything strips its slash.
        let b = bdict(&[("mapped_files", blist(&["/etc/passwd"]))]);
        let r = parse_hints(&b)
            .relayout(&["Show/a.mkv".to_owned()], "Show")
            .unwrap();
        assert_eq!((r.paths[0].as_str(), r.rejected), ("Show/a.mkv", 1));
        // A list holding anything but strings is skipped, not misread.
        let b = bdict(&[
            ("mapped_files", b"li1ee".to_vec()),
            ("qBt-savePath", bstr("/p")),
        ]);
        let h = parse_hints(&b);
        assert!(h.mapped_files.is_empty());
        assert_eq!(h.save_path.as_deref(), Some("/p"));
    }

    /// libtorrent's `trackers`: a list of tiers, each a list of URLs.
    fn btiers(tiers: &[&[&str]]) -> Vec<u8> {
        let mut v = b"l".to_vec();
        for t in tiers {
            v.extend_from_slice(&blist(t));
        }
        v.push(b'e');
        v
    }

    #[test]
    fn trackers_are_read_by_tier() {
        let b = bdict(&[
            (
                "trackers",
                btiers(&[
                    &["https://t.example/a", "udp://t.example:6969/a"],
                    &[],
                    &["", "http://backup.example/a"],
                ]),
            ),
            ("qBt-savePath", bstr("/p")),
        ]);
        let h = parse_hints(&b);
        assert_eq!(
            h.trackers,
            vec![
                vec!["https://t.example/a", "udp://t.example:6969/a"],
                vec!["http://backup.example/a"],
            ],
            "empty URLs and the tiers they leave empty are dropped",
        );
        assert_eq!(h.save_path.as_deref(), Some("/p"));

        // A URL that is not UTF-8, or holds a NUL, is dropped; its tier's
        // others stay.
        let mut tier = b"l".to_vec();
        tier.extend_from_slice(&bbytes(&[0xff, 0xfe]));
        tier.extend_from_slice(&bstr("https://t.example/\0a"));
        tier.extend_from_slice(&bstr("https://t.example/a"));
        tier.push(b'e');
        let mut list = b"l".to_vec();
        list.extend_from_slice(&tier);
        list.push(b'e');
        let h = parse_hints(&bdict(&[("trackers", list)]));
        assert_eq!(h.trackers, vec![vec!["https://t.example/a"]]);
    }

    #[test]
    fn trackers_not_in_libtorrents_shape_read_as_none() {
        for (shape, value) in [
            ("absent", None),
            ("empty", Some(b"le".to_vec())),
            ("flat", Some(blist(&["https://t.example/a"]))),
            ("a string", Some(bstr("https://t.example/a"))),
            ("an integer in a tier", Some(b"lli1eee".to_vec())),
            ("a dict in a tier", Some(b"lldeee".to_vec())),
            ("a tier beside a string", Some(b"l1:al1:bee".to_vec())),
            ("a string beside a tier", Some(b"ll1:ae1:be".to_vec())),
            ("nested too deep", Some(b"lll1:aeee".to_vec())),
        ] {
            let mut entries = vec![("qBt-savePath", bstr("/p"))];
            if let Some(v) = value {
                entries.push(("trackers", v));
            }
            let h = parse_hints(&bdict(&entries));
            assert!(h.trackers.is_empty(), "{shape}: {:?}", h.trackers);
            assert_eq!(h.save_path.as_deref(), Some("/p"), "{shape}");
        }
        // A truncated tier is a malformed file, not a skipped key.
        assert_eq!(parse_hints(b"d8:trackersll1:a"), ResumeHints::default());
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
