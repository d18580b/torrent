//! Torrent metadata extraction, with no session involved.
//!
//! The pool library scanner runs this over every `.torrent` it indexes. Parsing
//! goes through libtorrent rather than a Rust bencode crate because libtorrent
//! already handles v1, v2, and hybrid torrents plus hostile input, and because
//! a second implementation would have to agree with it byte-for-byte on
//! info-hash computation — a disagreement would silently split the registry.

use libtorrent_sys as ffi;

use crate::error::Error;
use crate::error::Result;
use crate::handle::InfoHash;

/// A BitTorrent v2 info-hash (SHA-256 of the info dict).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct InfoHashV2(pub [u8; 32]);

impl InfoHashV2 {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(Self(out))
    }

    /// The v1-shaped truncation libtorrent uses when a v2 torrent needs to be
    /// named by a 20-byte hash.
    pub fn truncated(self) -> InfoHash {
        let mut out = [0u8; 20];
        out.copy_from_slice(&self.0[..20]);
        InfoHash(out)
    }
}

impl std::fmt::Display for InfoHashV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for InfoHashV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InfoHashV2({})", self.to_hex())
    }
}

/// One file in a torrent's file list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorrentMetaFile {
    /// Torrent-relative, `/`-separated.
    pub path: String,
    pub size: u64,
    /// BitTorrent v2 per-file merkle root (SHA-256 over 16 KiB leaves).
    ///
    /// Recorded by the pool index; nothing places a file by it, since that
    /// would mean hashing the file on disk. `None` for v1-only torrents, where pieces span file
    /// boundaries and no per-file digest exists, and for v2 padding files.
    pub pieces_root: Option<[u8; 32]>,
    /// A BEP 47 padding file: it aligns the next file to a piece boundary,
    /// has a non-zero size, and is never written to disk.
    pub pad_file: bool,
}

/// Parsed `.torrent` metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorrentMeta {
    pub name: String,
    pub total_size: u64,
    pub piece_length: u32,
    pub infohash_v1: Option<InfoHash>,
    pub infohash_v2: Option<InfoHashV2>,
    pub files: Vec<TorrentMetaFile>,
}

impl TorrentMeta {
    /// The 20-byte hash this torrent is keyed by everywhere in the daemon.
    ///
    /// Mirrors libtorrent's `info_hash_t::get_best()`, which prefers the
    /// **truncated v2** hash when one exists and only falls back to v1. That
    /// ordering is easy to get backwards; `info_hash_from_torrent` and the
    /// assignment registry both depend on it, so a divergence here would key
    /// hybrid torrents under two different hashes.
    pub fn best_infohash(&self) -> Option<InfoHash> {
        match (self.infohash_v2, self.infohash_v1) {
            (Some(v2), _) => Some(v2.truncated()),
            (None, Some(v1)) => Some(v1),
            (None, None) => None,
        }
    }

    /// Whether this torrent carries v2 per-file merkle roots.
    pub fn has_v2(&self) -> bool {
        self.infohash_v2.is_some()
    }
}

/// Parse a `.torrent` buffer.
pub fn torrent_metadata(bytes: &[u8]) -> Result<TorrentMeta> {
    if bytes.is_empty() {
        return Err(Error::InvalidInput("empty .torrent buffer"));
    }
    let mut raw: ffi::lt_torrent_meta = unsafe { std::mem::zeroed() };
    let mut err = [0 as std::os::raw::c_char; 512];
    let rc = unsafe {
        ffi::lt_torrent_metadata(
            bytes.as_ptr(),
            bytes.len(),
            &mut raw,
            err.as_mut_ptr(),
            err.len() as i32,
        )
    };
    if rc != ffi::LT_OK as i32 {
        return Err(Error::Shim(err_to_string(&err)));
    }

    // From here every early return must still free `raw.files`, so build the
    // owned value first and free unconditionally at the end.
    let files = if raw.files.is_null() || raw.num_files == 0 {
        Vec::new()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(raw.files, raw.num_files) };
        slice
            .iter()
            .map(|f| TorrentMetaFile {
                path: fixed_c_str(&f.path),
                size: f.size,
                pieces_root: (f.has_pieces_root != 0).then_some(f.pieces_root),
                pad_file: f.pad_file != 0,
            })
            .collect()
    };

    let meta = TorrentMeta {
        name: fixed_c_str(&raw.name),
        total_size: raw.total_size,
        piece_length: raw.piece_length,
        infohash_v1: (raw.has_v1 != 0).then_some(InfoHash(raw.infohash_v1)),
        infohash_v2: (raw.has_v2 != 0).then_some(InfoHashV2(raw.infohash_v2)),
        files,
    };

    unsafe { ffi::lt_torrent_meta_free(&mut raw) };
    Ok(meta)
}

pub(crate) fn fixed_c_str(buf: &[std::os::raw::c_char]) -> String {
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let cstr = std::ffi::CStr::from_bytes_until_nul(bytes).unwrap_or(c"");
    String::from_utf8_lossy(cstr.to_bytes()).into_owned()
}

fn err_to_string(buf: &[std::os::raw::c_char]) -> String {
    let s = fixed_c_str(buf);
    if s.is_empty() {
        "unknown shim error".to_string()
    } else {
        s
    }
}
