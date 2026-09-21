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
    /// Guard for the one bug that could delete a pool: an empty claim table
    /// means every indexed file reads as unclaimed.
    #[error("refusing to clear claims outside a transaction")]
    ClaimsClearedOutsideTransaction,
    /// The pre-v3 copy-aside could not be written.
    ///
    /// Reported as itself rather than as a bare `Sqlite`: the copy is a step
    /// the operator did not ask for and has no reason to expect, so a raw
    /// SQLite code here named no backup, no path, and no reason the migration
    /// wanted one. `VACUUM INTO` writes a full second copy of an index that
    /// carries one row per file, so `database or disk is full` on a volume
    /// with less free space than the database is the ordinary way to reach it.
    #[error(
        "the pool index could not be copied aside to {path} before the one-way v3 schema \
         migration: {reason}. That copy is a full second copy of the index, so this needs free \
         space equal to the size of the database. The index has not been changed; free some \
         space and start again."
    )]
    BackupFailed { path: String, reason: String },
    /// Another process holds the pool database's write lock — almost always the
    /// running daemon, or a second `pool scan`.
    #[error(
        "the pool index is locked by another process (the running daemon, or another `pool scan`); \
         stop it or wait for it to finish"
    )]
    Busy,
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
    /// Which profile owns it. Absorbs the old `profile_assignments.json`.
    pub profile: Option<String>,
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

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

/// A mutation the operator has asked for but not yet applied.
///
/// Every change to the filesystem goes through one of these. Computing the
/// steps and executing them are separate calls so the operator always sees the
/// exact diff first, and so an interrupted apply can be resumed from the
/// journal rather than guessed at.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanRow {
    pub id: i64,
    pub kind: String,
    pub created_at: i64,
    pub applied_at: Option<i64>,
    /// `draft` | `applying` | `applied` | `failed` | `cancelled`
    pub status: String,
    /// JSON describing what was requested, kept so a resumed plan can be
    /// re-validated against the world as it is now.
    pub spec: String,
}

/// One filesystem operation, written to the journal before it is attempted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    /// `move_torrent` | `move_file` | `delete_file`
    pub op: String,
    pub src: String,
    pub dst: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanStepRow {
    pub seq: i64,
    pub op: String,
    pub src: String,
    pub dst: Option<String>,
    /// `pending` | `done` | `failed` | `skipped`
    pub status: String,
    pub error: Option<String>,
}

/// Operation names, kept in one place so the journal and the executor cannot
/// drift apart.
pub mod ops {
    /// Relocate an adopted torrent's payload. libtorrent performs the move so
    /// its storage state stays consistent with the session.
    pub const MOVE_TORRENT: &str = "move_torrent";
    /// Move a file no torrent claims. torrentd performs this one directly.
    pub const MOVE_FILE: &str = "move_file";
    /// Delete a file no torrent claims.
    pub const DELETE_FILE: &str = "delete_file";
}

pub mod plan_status {
    pub const DRAFT: &str = "draft";
    pub const APPLYING: &str = "applying";
    pub const APPLIED: &str = "applied";
    pub const FAILED: &str = "failed";
    pub const CANCELLED: &str = "cancelled";
}

pub mod step_status {
    pub const PENDING: &str = "pending";
    /// Written *before* the action is attempted, and cleared by its outcome.
    /// A crash leaves this behind, which is how a resumed apply tells "never
    /// started" from "started, verdict unknown" — the second needs a human.
    pub const IN_PROGRESS: &str = "in_progress";
    pub const DONE: &str = "done";
    pub const FAILED: &str = "failed";
    pub const SKIPPED: &str = "skipped";
}
