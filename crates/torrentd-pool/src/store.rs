//! SQLite-backed pool index.
//!
//! A managed root can hold millions of files, which is past what the daemon's
//! existing JSON-file conventions carry — and an API client needs to sort,
//! filter and paginate over that set without shipping all of it.
//! One transactional file serves the file index, the torrent library, adoption
//! state, and a copy of the torrent→profile mapping that lives in the
//! assignment registry, `registry.db` (once `profile_assignments.json`, and
//! before that `slot_assignments.json`).
//!
//! # `torrent.profile` is a cache, not the authority
//!
//! The assignment registry is the authority for which profile owns which
//! info-hash. It is what the daemon's resume scan writes, what every load is
//! gated on, and what the daemon refuses to boot against when it disagrees
//! with the configured profiles. This column is a copy of it, filled in by
//! `pool scan` and written by adoption and release, so it can be stale, and
//! nothing here may be read as overriding the file. Where the two disagree
//! the daemon's boot rewrites the column to the registry's profile, warning
//! with both values; a scan only fills a column that is empty.
//!
//! # Layout
//!
//! [`PoolStore`] is one type whose methods are split by what they touch:
//! `schema` holds the schema and its migrations, `conn` opening the index
//! and its transactions, `verify_queue` the persisted verify queue and the
//! index generation, `files` managed roots and the file index, `torrents`
//! the torrent library and its owner records, `claims` adoption state and
//! claims, `journal` the mutation plans and their steps, and `tree` the
//! materialised directory tree and the queries that read it.

use std::path::PathBuf;

use rusqlite::Connection;

use crate::model::AdoptionState;
use crate::model::PoolFile;
use crate::model::PoolTorrent;

mod claims;
mod conn;
mod files;
mod journal;
mod schema;
mod torrents;
mod tree;
mod verify_queue;

/// Rows the scan writes to the staging table per statement batch.
///
/// Bounds what a root walk holds in memory: a batch, not the root. Large
/// enough that the per-batch overhead vanishes next to the inserts.
pub const STAGE_BATCH: usize = 10_000;

/// An unclaimed file from [`PoolStore::orphan_files_sized`]: its root-relative
/// path, indexed size, and indexed `(dev, ino)`.
pub type SizedOrphan = (String, u64, (u64, u64));

/// What [`PoolStore::delete_plan`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum PlanDelete {
    /// The plan and its steps are gone.
    Deleted,
    /// No plan has this id.
    NotFound,
    /// The plan is mid-apply, and nothing was deleted.
    Applying,
}

pub struct PoolStore {
    conn: Connection,
    /// Nesting depth for [`PoolStore::in_transaction`]; 0 means autocommit.
    tx_depth: u32,
    /// This writer's advisory lock on the index's `.lock` file, held for the
    /// life of the store: shared from [`PoolStore::open`], exclusive from
    /// [`PoolStore::open_exclusive`]. `None` for an in-memory store or a
    /// read-only connection, which take no lock.
    _hold: Option<std::fs::File>,
}

impl std::fmt::Debug for PoolStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolStore").finish_non_exhaustive()
    }
}

/// One row of [`PoolStore::torrents_page`].
#[derive(Clone, Debug)]
pub struct TorrentListing {
    pub torrent: PoolTorrent,
    /// `None` until a match has placed the torrent.
    pub state: Option<AdoptionState>,
    /// The directory, relative to its root, the payload was matched at.
    pub base_rel: Option<String>,
    /// What the last match had to say about the torrent, for example how many
    /// of its files are present or that it has more than one complete copy.
    /// `None` when the verdict needs no explanation.
    pub note: Option<String>,
}

/// The directory a root-relative path sits in: `""` at the top of the root.
pub fn parent_of(rel_path: &str) -> &str {
    rel_path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// `rel` under the directory `base`, both root-relative: the path the index
/// keys that file by.
///
/// Both are already in the index's form, so the only normalisation is
/// trimming the `/` at either end, which leaves an empty `base` naming the
/// root itself. A backslash is kept: in an indexed path it is part of a file
/// name, and a torrent's own declared paths had theirs rewritten to `/` when
/// the library was scanned.
pub(crate) fn join_rel(base: &str, rel: &str) -> String {
    let (base, rel) = (base.trim_matches('/'), rel.trim_matches('/'));
    if base.is_empty() {
        rel.to_owned()
    } else {
        format!("{base}/{rel}")
    }
}

fn to_root32(v: Vec<u8>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

fn row_to_file(r: &rusqlite::Row<'_>) -> rusqlite::Result<PoolFile> {
    Ok(PoolFile {
        root_id: r.get(0)?,
        rel_path: r.get(1)?,
        size: r.get::<_, i64>(2)? as u64,
        mtime_ns: r.get(3)?,
        ino: r.get::<_, i64>(4)? as u64,
        dev: r.get::<_, i64>(5)? as u64,
        v2_root: r.get::<_, Option<Vec<u8>>>(6)?.and_then(to_root32),
    })
}

fn row_to_torrent(r: &rusqlite::Row<'_>) -> rusqlite::Result<PoolTorrent> {
    let tags: Option<String> = r.get(10)?;
    Ok(PoolTorrent {
        infohash: r.get(0)?,
        infohash_v1: r.get(1)?,
        infohash_v2: r.get(2)?,
        name: r.get(3)?,
        total_size: r.get::<_, i64>(4)? as u64,
        num_files: r.get::<_, i64>(5)? as usize,
        source_path: PathBuf::from(r.get::<_, String>(6)?),
        fastresume_path: r.get::<_, Option<String>>(7)?.map(PathBuf::from),
        declared_save_path: r.get(8)?,
        category: r.get(9)?,
        tags: tags
            .map(|t| {
                t.split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        profile: r.get(11)?,
    })
}

#[cfg(test)]
mod tests;
