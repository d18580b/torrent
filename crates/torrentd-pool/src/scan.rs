//! Filesystem and torrent-library scanning.
//!
//! Two independent passes feed the matcher: walking the managed roots to learn
//! what is on disk, and reading the torrent library to learn what is claimed.
//! Neither reads file contents — a managed root can be petabytes, so the scan
//! is metadata-only by construction.

use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use tracing::info;
use tracing::warn;

use crate::fastresume;
use crate::model::PoolError;
use crate::model::PoolFile;
use crate::model::PoolTorrent;
use crate::model::TorrentFileRow;
use crate::store::PoolStore;
use crate::store::STAGE_BATCH;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanStats {
    pub files_indexed: u64,
    pub bytes_indexed: u64,
    pub torrents_indexed: u64,
    /// Entries the walk could not stat, or `.torrent` files that failed to
    /// parse. Surfaced rather than swallowed: a permissions problem on a root
    /// otherwise looks exactly like an empty directory.
    pub errors: u64,
    /// `errors`, by kind: `walk` (the walk could not read an entry, or list a
    /// directory), `stat`,
    /// `path` (not UTF-8), `read` (a `.torrent` that could not be read) and
    /// `parse` (one that is not a torrent, or names no info-hash). A kind that
    /// never happened is absent. The daemon exports each as its own series, so
    /// an unreadable root and a library of corrupt files alert differently.
    pub errors_by_kind: std::collections::BTreeMap<&'static str, u64>,
}

impl ScanStats {
    /// Every value `errors_by_kind` can hold as a key.
    pub const ERROR_KINDS: &'static [&'static str] = &["walk", "stat", "path", "read", "parse"];

    fn note_error(&mut self, kind: &'static str) {
        debug_assert!(Self::ERROR_KINDS.contains(&kind), "{kind}");
        self.errors += 1;
        *self.errors_by_kind.entry(kind).or_default() += 1;
    }
}

/// Walk one managed root and replace its file index.
///
/// Symlinks are not followed. A pool assembled with symlinks into other roots
/// would otherwise index the same bytes under two paths and every torrent over
/// them would be reported as an overlap.
///
/// The walk streams into a staging table [`STAGE_BATCH`] rows at a time, and
/// the root's index is swapped for it only once the walk is done: memory is
/// one batch whatever the root's size, and the index never holds half a walk.
///
/// A root that cannot be read at all — missing, or present but not listable
/// — counts a `walk` error and keeps its previous index: swapping in the
/// empty walk would read every torrent over it as `missing`, though nothing
/// on disk is known to have changed.
pub fn scan_root(store: &mut PoolStore, root_path: &Path) -> Result<ScanStats, PoolError> {
    let root_id = store.upsert_root(root_path)?;
    let mut stats = ScanStats::default();
    store.begin_staging()?;
    let mut files = Vec::with_capacity(STAGE_BATCH);
    let mut root_unreadable = false;

    for entry in jwalk::WalkDir::new(root_path)
        .follow_links(false)
        .sort(false)
    {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(target: "torrentd_pool::scan", root = %root_path.display(), error.cause = %e, "walk error");
                stats.note_error("walk");
                root_unreadable |= e.depth() == 0;
                continue;
            }
        };
        if let Some(e) = &entry.read_children_error {
            note_unlistable(&mut stats, &entry.path(), e);
            root_unreadable |= entry.depth == 0;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                warn!(target: "torrentd_pool::scan", path = %path.display(), error.cause = %e, "stat failed");
                stats.note_error("stat");
                continue;
            }
        };
        let Ok(rel) = path.strip_prefix(root_path) else {
            continue;
        };
        // A non-UTF-8 path can't round-trip through the index or the JSON API.
        // Skipping loudly beats indexing a lossy name that would never match.
        let Some(rel_str) = rel.to_str() else {
            warn!(target: "torrentd_pool::scan", path = %path.display(), "skipping non-UTF-8 path");
            stats.note_error("path");
            continue;
        };
        // What a delete plan removed. Indexing it would offer it up as an
        // orphan again, or let a torrent match against it.
        if rel_str.starts_with(&format!("{}/", crate::plan::TRASH_DIR)) {
            continue;
        }

        stats.files_indexed += 1;
        stats.bytes_indexed += meta.len();
        files.push(PoolFile {
            root_id,
            rel_path: rel_str.replace('\\', "/"),
            size: meta.len(),
            mtime_ns: mtime_ns(&meta),
            ino: inode(&meta),
            dev: device(&meta),
            v2_root: None,
        });
        if files.len() >= STAGE_BATCH {
            store.stage_files(&files)?;
            files.clear();
        }
    }
    store.stage_files(&files)?;
    drop(files);

    if root_unreadable {
        // Empty the staging table rather than leave the failed walk in it.
        store.begin_staging()?;
        warn!(
            target: "torrentd_pool::scan",
            root = %root_path.display(),
            error_count = stats.errors,
            "root could not be read; its previous index is kept",
        );
        return Ok(stats);
    }
    store.swap_staged_root(root_id, now_secs())?;
    info!(
        target: "torrentd_pool::scan",
        root = %root_path.display(),
        file_count = stats.files_indexed,
        bytes = stats.bytes_indexed,
        error_count = stats.errors,
        "root scan complete",
    );
    Ok(stats)
}

/// Index a directory of `.torrent` files.
///
/// For a migration this is simply qBittorrent's `BT_backup`, which holds
/// `<hash>.torrent` alongside `<hash>.fastresume`; the sidecar is read for its
/// save-path, category and tag hints. Nothing here is qBittorrent-specific —
/// a plain directory of `.torrent` files works the same, minus the hints.
///
/// A torrent whose `.torrent` is gone leaves the index, except one in
/// `loaded` (hex info-hashes a session serves) — see
/// [`PoolStore::retain_torrents`].
pub fn scan_library(
    store: &mut PoolStore,
    library_dir: &Path,
    loaded: &std::collections::HashSet<String>,
) -> Result<ScanStats, PoolError> {
    let mut stats = ScanStats::default();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !library_dir.exists() {
        warn!(
            target: "torrentd_pool::scan",
            path = %library_dir.display(),
            "torrent library directory does not exist",
        );
        return Ok(stats);
    }

    for entry in jwalk::WalkDir::new(library_dir)
        .follow_links(false)
        .sort(false)
    {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Counted and previously not logged at all, so the count had
                // nothing in the journal to explain it.
                warn!(target: "torrentd_pool::scan", path = %library_dir.display(), error.cause = %e, "walk error");
                stats.note_error("walk");
                continue;
            }
        };
        let path = entry.path();
        if let Some(e) = &entry.read_children_error {
            note_unlistable(&mut stats, &path, e);
        }
        if !entry.file_type().is_file()
            || path.extension().and_then(|e| e.to_str()) != Some("torrent")
        {
            continue;
        }

        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!(target: "torrentd_pool::scan", path = %path.display(), error.cause = %e, "read failed");
                stats.note_error("read");
                continue;
            }
        };
        let meta = match libtorrent_safe::torrent_metadata(&bytes) {
            Ok(m) => m,
            Err(e) => {
                // One unparseable torrent must not abort indexing a library of
                // tens of thousands.
                warn!(target: "torrentd_pool::scan", path = %path.display(), error.cause = %e, "unparseable .torrent");
                stats.note_error("parse");
                continue;
            }
        };
        let Some(best) = meta.best_infohash() else {
            warn!(target: "torrentd_pool::scan", path = %path.display(), "torrent has no info-hash");
            stats.note_error("parse");
            continue;
        };

        let fr_path = path.with_extension("fastresume");
        let (fastresume_path, hints) = if fr_path.is_file() {
            (Some(fr_path.clone()), fastresume::read_hints(&fr_path))
        } else {
            (None, fastresume::ResumeHints::default())
        };

        let infohash = best.to_hex();
        let torrent = PoolTorrent {
            infohash: infohash.clone(),
            infohash_v1: meta.infohash_v1.map(|h| h.to_hex()),
            infohash_v2: meta.infohash_v2.map(|h| h.to_hex()),
            name: meta.name.clone(),
            total_size: meta.total_size,
            num_files: meta.files.len(),
            source_path: path.clone(),
            fastresume_path,
            declared_save_path: hints.save_path.clone(),
            category: hints.category.clone(),
            tags: hints.tags.clone(),
            // Never inferred here; profile assignment is the daemon's decision and
            // upsert_torrent preserves any existing value.
            profile: None,
        };
        store.upsert_torrent(&torrent, now_secs())?;

        // Where the previous client actually put each file: renamed through
        // libtorrent's `mapped_files`, or moved by qBittorrent's content
        // layout. Matching the `.torrent`'s own paths instead reads renamed
        // payload as missing — and offers it up as orphans to delete.
        let paths: Vec<String> = meta
            .files
            .iter()
            .map(|f| f.path.replace('\\', "/"))
            .collect();
        let paths = hints
            .relayout(&paths, &meta.name)
            .map_or(paths, |r| r.paths);
        let rows: Vec<TorrentFileRow> = meta
            .files
            .iter()
            .zip(paths)
            .enumerate()
            .map(|(i, (f, rel_path))| TorrentFileRow {
                infohash: infohash.clone(),
                idx: i as i64,
                rel_path,
                size: f.size,
                pieces_root: f.pieces_root,
                pad_file: f.pad_file,
            })
            .collect();
        store.replace_torrent_files(&infohash, &rows)?;
        stats.torrents_indexed += 1;
        seen.insert(infohash);
    }

    // A torrent whose `.torrent` is gone from the library leaves the index,
    // unless an error means the library was not fully seen: an unreadable
    // subdirectory would otherwise drop every torrent under it, and a
    // `.torrent` that is present but does not parse — truncated by a copy,
    // or corrupted — names no info-hash, so its torrent would be dropped
    // with its claims and its payload offered up as orphans.
    let unseen = ["walk", "read", "parse"]
        .iter()
        .map(|k| stats.errors_by_kind.get(k).copied().unwrap_or(0))
        .sum::<u64>();
    if unseen == 0 {
        let dropped = store.retain_torrents(&seen, loaded)?;
        if dropped > 0 {
            info!(
                target: "torrentd_pool::scan",
                torrent_count = dropped,
                "torrents no longer in the library dropped from the index",
            );
        }
    } else {
        warn!(
            target: "torrentd_pool::scan",
            error_count = unseen,
            "the library could not be read in full; torrents missing from it are kept",
        );
    }

    info!(
        target: "torrentd_pool::scan",
        path = %library_dir.display(),
        torrent_count = stats.torrents_indexed,
        error_count = stats.errors,
        "library scan complete",
    );
    Ok(stats)
}

/// Count a directory the walk could not list as a `walk` error.
///
/// jwalk does not yield such a directory as an `Err`: it yields the
/// directory's own `Ok` entry with the failure in `read_children_error`, and
/// simply has no children to yield after it. Read only as an `Err`, an
/// unreadable directory is indistinguishable from an empty one.
fn note_unlistable(stats: &mut ScanStats, dir: &Path, e: &jwalk::Error) {
    warn!(target: "torrentd_pool::scan", path = %dir.display(), error.cause = %e, "directory could not be read");
    stats.note_error("walk");
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The `(size, mtime, inode, device)` the index records for a file.
///
/// Public because anything comparing live metadata against the index — drift
/// detection, and the last-moment check before a delete — has to compute it
/// the same way the scanner did. Two copies of this encoding that disagree
/// would either miss a change or reject every unchanged file.
///
/// The device is part of it because an inode number is only unique within
/// one filesystem: a different volume mounted over a directory after the scan
/// can present a file with the same size, mtime and inode number that is not
/// the file the scan saw.
pub fn file_stamp(m: &std::fs::Metadata) -> (u64, i64, u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.len(), mtime_ns(m), m.ino(), m.dev())
}

fn mtime_ns(m: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    m.mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(i64::from(m.mtime_nsec() as i32))
}

fn inode(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}

fn device(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.dev()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unparseable_torrent_is_a_parse_error_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.torrent"), b"not bencode").unwrap();
        let mut store = PoolStore::open_in_memory().unwrap();

        let stats = scan_library(&mut store, dir.path(), &Default::default()).unwrap();

        assert_eq!(stats.errors, 1);
        assert_eq!(
            stats.errors_by_kind,
            std::collections::BTreeMap::from([("parse", 1)])
        );
    }

    #[test]
    fn the_kinds_sum_to_the_total() {
        let mut stats = ScanStats::default();
        for kind in ScanStats::ERROR_KINDS {
            stats.note_error(kind);
        }
        stats.note_error("parse");
        assert_eq!(stats.errors, stats.errors_by_kind.values().sum::<u64>());
        assert_eq!(stats.errors_by_kind["parse"], 2);
    }
}
