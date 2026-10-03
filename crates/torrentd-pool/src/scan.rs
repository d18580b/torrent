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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanStats {
    pub files_indexed: u64,
    pub bytes_indexed: u64,
    pub torrents_indexed: u64,
    /// Entries the walk could not stat, or `.torrent` files that failed to
    /// parse. Surfaced rather than swallowed: a permissions problem on a root
    /// otherwise looks exactly like an empty directory.
    pub errors: u64,
    /// `errors`, by kind: `walk` (the walk could not read an entry), `stat`,
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
pub fn scan_root(store: &mut PoolStore, root_path: &Path) -> Result<ScanStats, PoolError> {
    let root_id = store.upsert_root(root_path)?;
    let mut stats = ScanStats::default();
    let mut files = Vec::new();

    for entry in jwalk::WalkDir::new(root_path)
        .follow_links(false)
        .sort(false)
    {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(target: "torrentd_pool::scan", root = %root_path.display(), error.cause = %e, "walk error");
                stats.note_error("walk");
                continue;
            }
        };
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
    }

    store.replace_root_files(root_id, &files, now_secs())?;
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
pub fn scan_library(store: &mut PoolStore, library_dir: &Path) -> Result<ScanStats, PoolError> {
    let mut stats = ScanStats::default();
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
            declared_save_path: hints.save_path,
            category: hints.category,
            tags: hints.tags,
            // Never inferred here; profile assignment is the daemon's decision and
            // upsert_torrent preserves any existing value.
            profile: None,
        };
        store.upsert_torrent(&torrent, now_secs())?;

        let rows: Vec<TorrentFileRow> = meta
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| TorrentFileRow {
                infohash: infohash.clone(),
                idx: i as i64,
                rel_path: f.path.replace('\\', "/"),
                size: f.size,
                pieces_root: f.pieces_root,
                pad_file: f.pad_file,
            })
            .collect();
        store.replace_torrent_files(&infohash, &rows)?;
        stats.torrents_indexed += 1;
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

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The `(size, mtime, inode)` triple the index records for a file.
///
/// Public because anything comparing live metadata against the index — drift
/// detection, and the last-moment check before an irreversible delete — has to
/// compute it the same way the scanner did. Two copies of this encoding that
/// disagree would either miss a change or reject every unchanged file.
pub fn file_stamp(m: &std::fs::Metadata) -> (u64, i64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.len(), mtime_ns(m), m.ino())
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

        let stats = scan_library(&mut store, dir.path()).unwrap();

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
