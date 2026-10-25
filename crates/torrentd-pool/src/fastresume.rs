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
//! identity. A hint that cannot be read is absent, never wrong; a sidecar that
//! cannot be read or parsed at all is an error the caller reports, so that
//! nothing mistakes it for a sidecar that holds no hints.

use std::collections::HashMap;
use std::path::Path;

/// Hints recovered from a `.fastresume`. Every field is best-effort.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResumeHints {
    /// Where the previous client believed the payload lived.
    pub save_path: Option<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    /// The resume data's `pieces` bitfield, where it has one. Whether it
    /// claims completion depends on the torrent's piece count, which only the
    /// `.torrent` holds: see [`ResumeHints::is_complete`].
    pub bitfield: Option<Bitfield>,
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

/// libtorrent's `pieces` bitfield, as read: one byte per piece, the low bit
/// set for a piece the client had.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bitfield {
    /// How many pieces it has an entry for.
    pub len: usize,
    /// Every entry has its low bit set.
    pub all_had: bool,
}

/// Why a `.fastresume` yielded no hints at all.
#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("the .fastresume could not be read: {0}")]
    Read(#[from] std::io::Error),
    #[error("the .fastresume is not a bencoded dictionary")]
    Parse,
}

impl SidecarError {
    /// The scan error kind this counts as: `read` or `parse`, the same kinds
    /// an unreadable or unparseable `.torrent` counts as.
    pub fn kind(&self) -> &'static str {
        match self {
            SidecarError::Read(_) => "read",
            SidecarError::Parse => "parse",
        }
    }
}

/// How many pieces a torrent of `total_size` bytes, padding included, has in
/// pieces of `piece_length`: libtorrent's own count, which a resume
/// bitfield's length has to equal. `0` for a piece length of `0`.
pub fn piece_count(total_size: u64, piece_length: u32) -> u64 {
    if piece_length == 0 {
        return 0;
    }
    total_size.div_ceil(u64::from(piece_length))
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
    /// Whether the resume data marks every one of the torrent's
    /// `num_pieces` pieces had. A complete torrent whose files still match on
    /// disk can skip re-verification at adopt time, so this holds only for a
    /// bitfield with exactly one entry per piece, every one of them set: a
    /// shorter one says nothing about the pieces it leaves out, and a longer
    /// one was written for some other torrent.
    pub fn is_complete(&self, num_pieces: u64) -> bool {
        self.bitfield
            .is_some_and(|b| num_pieces > 0 && b.len as u64 == num_pieces && b.all_had)
    }

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
                    match normalised_relative(&m.replace('\\', "/")) {
                        Some(n) => n,
                        None => {
                            rejected += 1;
                            p.clone()
                        }
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

/// A mapped path as the index stores it, or `None` for one that is not a
/// layout: a mapped path is joined onto a base directory, so one that is
/// empty, absolute or walks out of it is ignored.
///
/// A path that passes is rebuilt from its components, `/`-joined: `a/./b`,
/// `a//b` and `a/b/` all name `a/b`, and the index has to store that one
/// spelling, because every lookup against the scanned files compares it
/// literally.
fn normalised_relative(p: &str) -> Option<String> {
    let mut parts = Vec::new();
    for c in Path::new(p).components() {
        match c {
            std::path::Component::Normal(s) => parts.push(s.to_str()?),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// The hints in the `.fastresume` at `path`, or why there are none: a file
/// that cannot be read or is larger than
/// [`MAX_LIBRARY_FILE_BYTES`](crate::scan::MAX_LIBRARY_FILE_BYTES), or that is
/// not a bencoded dictionary. A caller holding hints from an earlier read
/// keeps them on an error, rather than taking it for a sidecar that holds
/// none.
pub fn read_hints(path: &Path) -> Result<ResumeHints, SidecarError> {
    let bytes = crate::scan::read_capped(path)?;
    parse_hints(&bytes).ok_or(SidecarError::Parse)
}

/// The hints in a `.fastresume`'s bytes, or `None` where they are not a
/// bencoded dictionary this reader can step through.
pub fn parse_hints(bytes: &[u8]) -> Option<ResumeHints> {
    let top = top_level_entries(bytes)?;
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
    // completion is unknown and adoption takes the verifying path. How many
    // entries the bitfield has is kept too: only the `.torrent` knows how
    // many it needs.
    let bitfield = match top.get("pieces") {
        Some(Value::Str(bits)) => Some(Bitfield {
            len: bits.len(),
            all_had: bits.iter().all(|b| b & 1 == 1),
        }),
        _ => None,
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

    Some(ResumeHints {
        save_path: save_path.filter(|s| !s.is_empty()),
        category: get_str("qBt-category").filter(|s| !s.is_empty()),
        tags,
        bitfield,
        mapped_files,
        mapped_files_unreadable,
        content_layout: get_str("qBt-contentLayout").filter(|s| !s.is_empty()),
        trackers,
    })
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

        let h = parse_hints(&b).unwrap();
        assert_eq!(h.save_path.as_deref(), Some("/data/pool"));
        assert_eq!(h.category.as_deref(), Some("movies"));
        assert_eq!(h.tags, vec!["hd", "seeded"]);
        assert!(h.is_complete(3));
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
        assert!(parse_hints(&b).unwrap().is_complete(4));
        // One missing: not, whatever the flags say.
        let b = bdict(&[
            ("pieces", bbytes(&[1, 0, 1])),
            ("qBt-seedStatus", bint(1)),
            ("seed_mode", bint(1)),
        ]);
        assert!(!parse_hints(&b).unwrap().is_complete(3));
        // `seed_mode` is a torrent *added* as a seed, unchecked: not a claim.
        let b = bdict(&[("save_path", bstr("/data")), ("seed_mode", bint(1))]);
        assert!(!parse_hints(&b).unwrap().is_complete(1));
        // Neither is qBittorrent's own status flag.
        let b = bdict(&[("qBt-seedStatus", bint(1))]);
        assert!(!parse_hints(&b).unwrap().is_complete(1));
        // An empty bitfield proves nothing, even of a torrent with no pieces.
        let b = bdict(&[("pieces", bbytes(&[]))]);
        assert!(!parse_hints(&b).unwrap().is_complete(0));
        assert!(!parse_hints(&b).unwrap().is_complete(1));
    }

    /// A one-byte `\x01` for a four-piece torrent says nothing about three of
    /// its pieces, and a bitfield longer than the torrent was written for
    /// another one: neither is complete.
    #[test]
    fn a_bitfield_of_any_length_but_the_piece_count_is_not_complete() {
        let h = parse_hints(&bdict(&[("pieces", bbytes(&[1]))])).unwrap();
        assert!(h.is_complete(1));
        assert!(!h.is_complete(4));
        let h = parse_hints(&bdict(&[("pieces", bbytes(&[1; 5]))])).unwrap();
        assert!(h.is_complete(5));
        assert!(!h.is_complete(4));
    }

    /// `is_complete(n)` implies a bitfield of exactly `n` entries, every one
    /// had: checked over every bitfield of up to six entries, each in every
    /// pattern of had and missing (with the high bits, which libtorrent uses
    /// for other flags, set), against every piece count up to eight.
    #[test]
    fn is_complete_implies_one_had_entry_per_piece() {
        for len in 0..=6usize {
            for pattern in 0u32..(1 << len) {
                let bits: Vec<u8> = (0..len)
                    .map(|i| 0xfe | u8::from(pattern & (1 << i) != 0))
                    .collect();
                let h = parse_hints(&bdict(&[("pieces", bbytes(&bits))])).unwrap();
                let all_had = pattern == (1 << len) - 1;
                for n in 0..=8u64 {
                    assert_eq!(
                        h.is_complete(n),
                        n > 0 && len as u64 == n && all_had,
                        "{bits:?} against {n} pieces",
                    );
                }
            }
        }
    }

    #[test]
    fn the_piece_count_rounds_a_short_last_piece_up() {
        assert_eq!(piece_count(4096, 1024), 4);
        assert_eq!(piece_count(4097, 1024), 5);
        assert_eq!(piece_count(1, 16384), 1);
        assert_eq!(piece_count(0, 16384), 0);
        assert_eq!(piece_count(4096, 0), 0);
        assert_eq!(piece_count(u64::MAX, 1), u64::MAX);
    }

    /// `a/./b`, `a//b` and `a/b/` name the file `a/b`, and are stored as that
    /// one spelling; what was refused before is refused still.
    #[test]
    fn mapped_paths_are_stored_normalised() {
        let b = bdict(&[(
            "mapped_files",
            blist(&[
                "Show/./a.mkv",
                "Show//b.mkv",
                "Show\\c.nfo",
                "Show/d.srt/",
                "./e",
            ]),
        )]);
        let paths: Vec<String> = ["S/a", "S/b", "S/c", "S/d", "S/e"]
            .map(String::from)
            .to_vec();
        let r = parse_hints(&b).unwrap().relayout(&paths, "S").unwrap();
        assert_eq!(
            r.paths,
            [
                "Show/a.mkv",
                "Show/b.mkv",
                "Show/c.nfo",
                "Show/d.srt",
                "S/e"
            ]
        );
        assert_eq!(r.rejected, 1, "a leading `.` is refused, as it was");
    }

    #[test]
    fn a_sidecar_that_cannot_be_read_or_parsed_is_an_error_of_its_kind() {
        let dir = tempfile::tempdir().unwrap();
        let missing = read_hints(&dir.path().join("gone.fastresume")).unwrap_err();
        assert_eq!(missing.kind(), "read");
        let truncated = dir.path().join("t.fastresume");
        std::fs::write(&truncated, b"d12:qBt-savePath5:/da").unwrap();
        assert_eq!(read_hints(&truncated).unwrap_err().kind(), "parse");
        // A dictionary with nothing this reader wants is no error: no hints.
        std::fs::write(&truncated, b"de").unwrap();
        assert_eq!(read_hints(&truncated).unwrap(), ResumeHints::default());
    }

    #[test]
    fn mapped_files_rename_the_files_they_name() {
        let b = bdict(&[(
            "mapped_files",
            blist(&["", "Show/renamed.mkv", "../escape", ""]),
        )]);
        let h = parse_hints(&b).unwrap();
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
            .unwrap()
            .relayout(&["Show/a.mkv".to_owned()], "Show")
            .unwrap();
        assert_eq!((r.paths[0].as_str(), r.rejected), ("Show/a.mkv", 1));
        // A list holding anything but strings is skipped, not misread.
        let b = bdict(&[
            ("mapped_files", b"li1ee".to_vec()),
            ("qBt-savePath", bstr("/p")),
        ]);
        let h = parse_hints(&b).unwrap();
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
        let h = parse_hints(&b).unwrap();
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
        let h = parse_hints(&bdict(&[("trackers", list)])).unwrap();
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
            let h = parse_hints(&bdict(&entries)).unwrap();
            assert!(h.trackers.is_empty(), "{shape}: {:?}", h.trackers);
            assert_eq!(h.save_path.as_deref(), Some("/p"), "{shape}");
        }
        // A truncated tier is a malformed file, not a skipped key.
        assert_eq!(parse_hints(b"d8:trackersll1:a"), None);
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
        // A torrent whose files already sit in a top directory gets no
        // second one: qBittorrent adds a subfolder only where there is none.
        assert_eq!(layout("Subfolder").relayout(&multi, "Show"), None);
        let one_in_dir = vec!["Show/a.mkv".to_owned()];
        assert_eq!(layout("Subfolder").relayout(&one_in_dir, "Show"), None);
    }

    #[test]
    fn qbt_save_path_wins_over_a_stale_plain_save_path() {
        // qBittorrent updates its own key on a move; `save_path` can lag.
        let b = bdict(&[
            ("save_path", bstr("/old/path")),
            ("qBt-savePath", bstr("/new/path")),
        ]);
        assert_eq!(
            parse_hints(&b).unwrap().save_path.as_deref(),
            Some("/new/path")
        );
    }

    #[test]
    fn falls_back_to_plain_save_path() {
        let b = bdict(&[("save_path", bstr("/data/pool"))]);
        assert_eq!(
            parse_hints(&b).unwrap().save_path.as_deref(),
            Some("/data/pool")
        );
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
        assert_eq!(
            parse_hints(&b).unwrap().save_path.as_deref(),
            Some("/data/pool")
        );
    }

    #[test]
    fn malformed_input_is_unparseable_rather_than_panicking() {
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
            assert_eq!(parse_hints(bad), None, "input {bad:?}");
        }
    }

    #[test]
    fn incomplete_torrents_are_not_reported_complete() {
        // No bitfield at all: completion is unknown, so adoption must take
        // the verifying path rather than trusting the file.
        let b = bdict(&[("qBt-savePath", bstr("/data/pool"))]);
        assert!(!parse_hints(&b).unwrap().is_complete(1));
    }

    #[test]
    fn empty_strings_are_treated_as_absent() {
        let b = bdict(&[("qBt-savePath", bstr("")), ("qBt-category", bstr(""))]);
        let h = parse_hints(&b).unwrap();
        assert_eq!(h.save_path, None);
        assert_eq!(h.category, None);
    }

    mod props {
        use std::path::Component;

        use proptest::prelude::*;

        use super::*;

        /// Bytes shaped like bencode: its tokens, lengths that may or may
        /// not fit, and anything else.
        fn bencode_soup() -> impl Strategy<Value = Vec<u8>> {
            let token = prop_oneof![
                prop::sample::select(vec![
                    &b"d"[..],
                    b"l",
                    b"e",
                    b"i",
                    b"0:",
                    b"1:",
                    b"4:",
                    b"999:",
                    b"18446744073709551616:",
                    b"i-1e",
                    b"6:pieces",
                    b"12:mapped_files",
                    b"8:trackers",
                    b"12:qBt-savePath",
                ])
                .prop_map(<[u8]>::to_vec),
                prop::collection::vec(any::<u8>(), 0..6),
            ];
            prop::collection::vec(token, 0..24).prop_map(|t| t.concat())
        }

        /// A string a hint keeps as written: not empty.
        fn text() -> impl Strategy<Value = String> {
            ".{1,16}"
        }

        prop_compose! {
            /// Hints in the shape a reading of them takes: nothing empty, no
            /// tag with a comma or surrounding space, no URL with a NUL.
            fn hints()(
                save_path in prop::option::of(text()),
                category in prop::option::of(text()),
                tags in prop::collection::vec("[a-zA-Z0-9_-]{1,8}", 0..4),
                pieces in prop::option::of(prop::collection::vec(any::<u8>(), 0..12)),
                mapped_files in prop::collection::vec(prop::option::of(text()), 0..5),
                content_layout in prop::option::of(text()),
                trackers in prop::collection::vec(
                    prop::collection::vec("[^\u{0}]{1,24}", 1..3),
                    0..3,
                ),
            ) -> (ResumeHints, Option<Vec<u8>>) {
                let bitfield = pieces.as_ref().map(|bits| Bitfield {
                    len: bits.len(),
                    all_had: bits.iter().all(|b| b & 1 == 1),
                });
                (
                    ResumeHints {
                        save_path,
                        category,
                        tags,
                        bitfield,
                        mapped_files,
                        mapped_files_unreadable: 0,
                        content_layout,
                        trackers,
                    },
                    pieces,
                )
            }
        }

        /// `hints` as a `.fastresume` writes them.
        fn encode(hints: &ResumeHints, pieces: &Option<Vec<u8>>) -> Vec<u8> {
            let mut entries: Vec<(&str, Vec<u8>)> = vec![("qBt-seedStatus", bint(1))];
            let mut opt = |key, v: &Option<String>| {
                if let Some(v) = v {
                    entries.push((key, bstr(v)));
                }
            };
            opt("qBt-savePath", &hints.save_path);
            opt("qBt-category", &hints.category);
            opt("qBt-contentLayout", &hints.content_layout);
            if !hints.tags.is_empty() {
                entries.push(("qBt-tags", bstr(&hints.tags.join(", "))));
            }
            if let Some(bits) = pieces {
                entries.push(("pieces", bbytes(bits)));
            }
            let mapped: Vec<&str> = hints
                .mapped_files
                .iter()
                .map(|m| m.as_deref().unwrap_or(""))
                .collect();
            entries.push(("mapped_files", blist(&mapped)));
            entries.push(("nested", bdict(&[("x", blist(&["y"]))])));
            let tiers: Vec<Vec<&str>> = hints
                .trackers
                .iter()
                .map(|t| t.iter().map(String::as_str).collect())
                .collect();
            let tiers: Vec<&[&str]> = tiers.iter().map(Vec::as_slice).collect();
            entries.push(("trackers", btiers(&tiers)));
            bdict(&entries)
        }

        /// A mapped path made of plain names, traversals, roots, empties and
        /// Windows separators.
        fn mapped_path() -> impl Strategy<Value = String> {
            prop::collection::vec(
                prop::sample::select(vec!["a", "b.mkv", "..", ".", "", "/", "\\", "C:"]),
                0..5,
            )
            .prop_map(|parts| parts.join("/"))
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            /// Whatever a sidecar holds, reading it answers.
            #[test]
            fn reading_any_bytes_never_panics(
                bytes in prop_oneof![bencode_soup(), prop::collection::vec(any::<u8>(), 0..64)],
            ) {
                let _ = parse_hints(&bytes);
            }

            /// Hints written as a `.fastresume` writes them read back as
            /// they were, beside keys and nested values the reader skips.
            #[test]
            fn hints_round_trip((hints, pieces) in hints()) {
                prop_assert_eq!(parse_hints(&encode(&hints, &pieces)), Some(hints));
            }

            /// Every path a relayout takes from `mapped_files` is relative
            /// and made of plain names only; a mapped path that is not is
            /// left at the `.torrent`'s path and counted as refused.
            #[test]
            fn a_relayout_takes_only_plain_relative_paths(
                paths in prop::collection::vec("[a-z]{1,4}(/[a-z]{1,4}){0,2}", 0..5),
                mapped in prop::collection::vec(prop::option::of(mapped_path()), 0..6),
                unreadable in 0usize..3,
                name in "[a-z]{1,4}",
            ) {
                let hints = ResumeHints {
                    mapped_files: mapped.clone(),
                    mapped_files_unreadable: unreadable,
                    ..ResumeHints::default()
                };
                let Some(out) = hints.relayout(&paths, &name) else {
                    prop_assert!(unreadable == 0 && mapped.iter().all(Option::is_none));
                    return Ok(());
                };
                prop_assert!(out.in_resume_data);
                prop_assert_eq!(out.paths.len(), paths.len());
                // The plain names a path holds, or `None` where it holds
                // anything else (a root, a `..`, a leading `.`) or nothing.
                let names = |p: &str| -> Option<Vec<String>> {
                    let parts: Option<Vec<String>> = Path::new(p)
                        .components()
                        .map(|c| match c {
                            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                            _ => None,
                        })
                        .collect();
                    parts.filter(|p| !p.is_empty())
                };
                let mut refused = 0;
                for (i, (got, was)) in out.paths.iter().zip(&paths).enumerate() {
                    match mapped.get(i).cloned().flatten() {
                        Some(m) => match names(&m.replace('\\', "/")) {
                            Some(want) => {
                                prop_assert_eq!(names(got), Some(want), "{:?} from {:?}", got, m);
                                prop_assert_eq!(got, &names(got).unwrap().join("/"));
                            }
                            None => {
                                refused += 1;
                                prop_assert_eq!(got, was, "{:?} from {:?}", got, m);
                            }
                        },
                        None => prop_assert_eq!(got, was),
                    }
                }
                prop_assert_eq!(out.rejected, unreadable + refused);
            }
        }
    }
}
