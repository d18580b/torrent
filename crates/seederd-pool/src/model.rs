//! Shared pool types.

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoolError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("torrent parse: {0}")]
    Torrent(#[from] libtorrent_safe::Error),
    #[error("unknown managed root: {0}")]
    UnknownRoot(PathBuf),
    #[error("pool database schema is version {found}, this build understands {expected}")]
    SchemaVersion { found: i64, expected: i64 },
}

/// Where a torrent stands relative to the payload on disk.
///
/// Ordering matters for reporting: a torrent in a worse state should never be
/// summarised as a better one, and `Overlap` outranks everything because it is
/// the only state that makes a destructive operation unsafe.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionState {
    /// No file of this torrent was found under any managed root.
    Missing,
    /// Some files resolved, others did not. Adoption is refused: seeding a
    /// partial torrent advertises pieces the daemon cannot serve.
    Partial,
    /// Every file resolved at a consistent base, but the torrent is not yet
    /// loaded into a session.
    Matched,
    /// Loaded into a session and seeding.
    Adopted,
    /// Was matched or adopted, but a covering file's stats moved since the last
    /// verification. Needs a recheck before it can be trusted.
    Drifted,
    /// At least one file is claimed by another torrent too. Reported on every
    /// torrent involved, and blocks any mutation touching those files.
    Overlap,
}

impl AdoptionState {
    pub fn as_str(self) -> &'static str {
        match self {
            AdoptionState::Missing => "missing",
            AdoptionState::Partial => "partial",
            AdoptionState::Matched => "matched",
            AdoptionState::Adopted => "adopted",
            AdoptionState::Drifted => "drifted",
            AdoptionState::Overlap => "overlap",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "missing" => AdoptionState::Missing,
            "partial" => AdoptionState::Partial,
            "matched" => AdoptionState::Matched,
            "adopted" => AdoptionState::Adopted,
            "drifted" => AdoptionState::Drifted,
            "overlap" => AdoptionState::Overlap,
            _ => return None,
        })
    }

    /// Whether a torrent in this state may be handed to a session.
    pub fn is_adoptable(self) -> bool {
        matches!(self, AdoptionState::Matched)
    }
}

/// One file observed under a managed root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolFile {
    pub root_id: i64,
    /// Path relative to the root, `/`-separated.
    pub rel_path: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
    pub dev: u64,
    /// v2 merkle root, once known. Populated by matching against a v2 torrent
    /// rather than by hashing: computing it for an unmatched file would mean
    /// reading the whole pool.
    pub v2_root: Option<[u8; 32]>,
}

/// A `.torrent` in the library, plus whatever the sidecar `.fastresume` told us.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolTorrent {
    /// The 20-byte key the rest of the daemon uses, matching libtorrent's
    /// `info_hash_t::get_best()` (truncated v2 when present, else v1).
    pub infohash: String,
    pub infohash_v1: Option<String>,
    pub infohash_v2: Option<String>,
    pub name: String,
    pub total_size: u64,
    pub num_files: usize,
    /// The `.torrent` this was read from.
    pub source_path: PathBuf,
    /// A sibling `.fastresume`, when the library is another client's state dir.
    pub fastresume_path: Option<PathBuf>,
    /// Save path the previous client recorded, used as the first candidate base.
    pub declared_save_path: Option<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    /// Which slot owns it. Absorbs the old `slot_assignments.json`.
    pub slot: Option<String>,
}

impl PoolTorrent {
    pub fn has_v2(&self) -> bool {
        self.infohash_v2.is_some()
    }
}

/// One entry of a torrent's file list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorrentFileRow {
    pub infohash: String,
    pub idx: i64,
    /// Torrent-relative, `/`-separated.
    pub rel_path: String,
    pub size: u64,
    pub pieces_root: Option<[u8; 32]>,
}

/// Byte accounting for one directory subtree — what makes the pool legible at
/// petabyte scale, where a file listing is useless but "this subtree is 8 TB
/// and none of it is protected" is not.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirRollup {
    pub bytes_total: u64,
    pub bytes_adopted: u64,
    pub bytes_matched: u64,
    /// On disk and claimed by no torrent in the library.
    pub bytes_orphan: u64,
    pub files_total: u64,
    pub files_orphan: u64,
}
