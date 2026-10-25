//! Filesystem and torrent-library scanning.
//!
//! Two independent passes feed the matcher: walking the managed roots to learn
//! what is on disk, and reading the torrent library to learn what is claimed.
//! Neither reads file contents — a managed root can be petabytes, so the scan
//! is metadata-only by construction.

use std::path::Path;

use tracing::info;
use tracing::warn;

use crate::fastresume;
use crate::model::PoolError;
use crate::model::PoolFile;
use crate::model::PoolTorrent;
use crate::model::TorrentFileRow;
use crate::now_secs;
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
    /// `path` (not UTF-8), `read` (a `.torrent` that could not be read, or is
    /// larger than [`MAX_LIBRARY_FILE_BYTES`]),
    /// `parse` (one that is not a torrent, or names no info-hash) and
    /// `symlink` (a symlink under a managed root, which the walk does not
    /// follow, so nothing behind it is indexed). A kind that
    /// never happened is absent. The daemon exports each as its own series, so
    /// an unreadable root and a library of corrupt files alert differently.
    pub errors_by_kind: std::collections::BTreeMap<&'static str, u64>,
    /// `.torrent` files skipped because another one, earlier in path order,
    /// holds the same info-hash. Not an error: the torrent is indexed, from
    /// the first. Each is logged with the path that won.
    pub duplicate_infohashes: u64,
    /// `.fastresume` files in the library with no `.torrent` of the same name
    /// beside them, and so not imported: a qBittorrent entry added from a
    /// magnet link whose metadata never arrived has resume data and no
    /// `.torrent`, and nothing here names its files. Not an error, and not
    /// counted against the pruning: no torrent it could name is indexed.
    /// Each is logged at info with its path.
    pub unpaired_fastresume: u64,
}

/// Upper bound on a `.torrent` or `.fastresume` read from the library, by the
/// scan and by every later read of the same files through [`read_capped`]:
/// the daemon's own limit on a `.torrent` (`MAX_TORRENT_FILE_BYTES` in the
/// HTTP API), which a sidecar of the same torrent has no reason to exceed. A
/// file past it is not read, and the scan counts it a `read` error.
pub const MAX_LIBRARY_FILE_BYTES: u64 = 64 * 1024 * 1024;

impl ScanStats {
    /// Every value `errors_by_kind` can hold as a key.
    pub const ERROR_KINDS: &'static [&'static str] =
        &["walk", "stat", "path", "read", "parse", "symlink"];

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
/// them would be reported as an overlap. Each symlink below the root, to a
/// file or a directory, is logged with its path and counted a `symlink`
/// error: what it points at is absent from the index, so a torrent over it
/// reads `partial` or `missing`, and a count of 0 would hide why.
///
/// The walk streams into a staging table [`STAGE_BATCH`] rows at a time, and
/// the root's index is swapped for it only once the walk is done: memory is
/// one batch whatever the root's size, and the index never holds half a walk.
///
/// A root that cannot be read at all — missing, or present but not listable
/// — counts a `walk` error and keeps its previous index: swapping in the
/// empty walk would read every torrent over it as `missing`, though nothing
/// on disk is known to have changed. A subdirectory that cannot be listed,
/// or an entry below the root the walk could not read, counts a `walk` error
/// the same way and keeps that subtree's previous rows, and a file the walk
/// listed but could not stat counts a `stat` error and keeps its previous
/// row; the rest of the root is re-indexed as usual.
pub fn scan_root(store: &mut PoolStore, root_path: &Path) -> Result<ScanStats, PoolError> {
    let root_id = store.upsert_root(root_path)?;
    let mut stats = ScanStats::default();
    store.begin_staging()?;
    let mut files = Vec::with_capacity(STAGE_BATCH);
    let mut root_unreadable = false;
    // Paths below the root the walk could not read, each keeping its
    // previous rows through the swap.
    let mut unseen: Vec<String> = Vec::new();

    for entry in jwalk::WalkDir::new(root_path)
        .follow_links(false)
        .sort(false)
    {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(target: "torrentd_pool::scan", root = %root_path.display(), error.cause = %e, "walk error");
                stats.note_error("walk");
                // An error that names no path below the root says nothing
                // about which subtree went unseen, so it is the whole walk's.
                match e.path().filter(|_| e.depth() > 0) {
                    Some(p) => unseen.extend(rel_of(p, root_path)),
                    None => root_unreadable = true,
                }
                continue;
            }
        };
        if let Some(e) = &entry.read_children_error {
            note_unlistable(&mut stats, &entry.path(), e);
            if entry.depth == 0 {
                root_unreadable = true;
            } else {
                unseen.extend(rel_of(&entry.path(), root_path));
            }
        }
        // Not followed (see above), but not silent either. The root itself
        // is what the operator configured, so only entries below it count.
        if entry.depth > 0 && entry.file_type().is_symlink() {
            let path = entry.path();
            let in_trash = path
                .strip_prefix(root_path)
                .is_ok_and(|rel| rel.starts_with(crate::plan::TRASH_DIR));
            if !in_trash {
                warn!(target: "torrentd_pool::scan", path = %path.display(), "skipping symlink; nothing behind it is indexed");
                stats.note_error("symlink");
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                warn!(target: "torrentd_pool::scan", path = %path.display(), error.cause = %e, "stat failed; its previous index row is kept");
                stats.note_error("stat");
                // Unseen, not gone: dropping its row would read the torrent
                // over it as `missing` though nothing is known to have
                // changed.
                unseen.extend(rel_of(&path, root_path));
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
            // As it is on disk: a backslash is an ordinary character in a
            // Linux file name, and `a\b` rewritten to `a/b` names another
            // file. Only a torrent's own declared paths are normalised.
            rel_path: rel_str.to_owned(),
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
    let mut carried = 0u64;
    for rel in &unseen {
        carried += store.stage_previous_subtree(root_id, rel)?;
    }
    if !unseen.is_empty() {
        warn!(
            target: "torrentd_pool::scan",
            root = %root_path.display(),
            subtree_count = unseen.len(),
            file_count = carried,
            "subtrees could not be read; their previous index rows are kept",
        );
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
/// Of two `.torrent` files holding one info-hash, the first in path order is
/// indexed, with its own sidecar's hints, and the other is counted in
/// [`ScanStats::duplicate_infohashes`].
///
/// The walk is sorted and does not follow symlinks; only regular files named
/// `*.torrent` are read. A `*.fastresume` with no `.torrent` of the same name
/// beside it is logged and counted in [`ScanStats::unpaired_fastresume`], and
/// not imported. A `.torrent` that cannot be read, does not parse, or
/// names no info-hash is logged and counted in [`ScanStats::errors`] and
/// skipped, and the scan goes on. A missing `library_dir` is logged and
/// returns empty stats with the index untouched. A store failure ends the
/// scan with `Err`, keeping what it had already written.
///
/// A torrent whose `.torrent` is gone leaves the index, except one in
/// `loaded` (hex info-hashes a session serves) or one `adopted` or `drifted`
/// — see [`PoolStore::retain_torrents`]. That pruning runs only when the
/// library was read in full: a single walk, read or parse error (a sidecar's
/// excepted) keeps every torrent missing from this scan, because the
/// torrent behind the error cannot be told apart from one that is gone.
pub fn scan_library(
    store: &mut PoolStore,
    library_dir: &Path,
    loaded: &std::collections::HashSet<String>,
) -> Result<ScanStats, PoolError> {
    let mut stats = ScanStats::default();
    // Each info-hash indexed so far, and the `.torrent` it was indexed from.
    let mut seen: std::collections::HashMap<String, std::path::PathBuf> =
        std::collections::HashMap::new();
    // `read` and `parse` errors that were a sidecar's, whose torrent was
    // still seen.
    let mut sidecar_errors = 0u64;
    if !library_dir.exists() {
        warn!(
            target: "torrentd_pool::scan",
            path = %library_dir.display(),
            "torrent library directory does not exist",
        );
        return Ok(stats);
    }

    // Sorted, so that of two `.torrent` files holding one info-hash the
    // same one is met first, and indexed, on every scan. A library is
    // thousands of small files, so the sort costs nothing that matters.
    for entry in jwalk::WalkDir::new(library_dir)
        .follow_links(false)
        .sort(true)
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
        if !entry.file_type().is_file() {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("torrent") => {}
            Some("fastresume") => {
                // Read only as a `.torrent`'s sidecar, so one with no
                // `.torrent` beside it would otherwise vanish without a
                // trace, and the library would simply hold fewer torrents
                // than the client did.
                if !path.with_extension("torrent").is_file() {
                    info!(
                        target: "torrentd_pool::scan",
                        path = %path.display(),
                        "skipping .fastresume with no .torrent beside it (a magnet link whose metadata never arrived?); not imported",
                    );
                    stats.unpaired_fastresume += 1;
                }
                continue;
            }
            _ => continue,
        }

        let bytes = match read_capped(&path) {
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

        let infohash = best.to_hex();
        if let Some(winner) = seen.get(&infohash) {
            // Indexing this one too would overwrite the winner's row, its
            // source path and its sidecar's hints with this one's.
            warn!(
                target: "torrentd_pool::scan",
                infohash,
                path = %path.display(),
                winner = %winner.display(),
                "duplicate .torrent skipped; the info-hash is indexed from the first in path order",
            );
            stats.duplicate_infohashes += 1;
            continue;
        }
        let fr_path = path.with_extension("fastresume");
        let (fastresume_path, hints) = if fr_path.is_file() {
            match fastresume::read_hints(&fr_path) {
                Ok(hints) => (Some(fr_path), hints),
                Err(e) => {
                    warn!(target: "torrentd_pool::scan", path = %fr_path.display(), error.cause = %e, "unusable .fastresume");
                    stats.note_error(e.kind());
                    sidecar_errors += 1;
                    // The torrent itself was read, so it stays in the index,
                    // and what an earlier read of its sidecar recorded stands:
                    // its save path, category and tags, and the file paths
                    // `mapped_files` gave. Indexed without them, renamed
                    // payload would read as missing, and as orphans.
                    if let Some(mut known) = store.torrent(&infohash)? {
                        known.source_path = path.clone();
                        known.fastresume_path = Some(fr_path);
                        store.upsert_torrent(&known, now_secs())?;
                        stats.torrents_indexed += 1;
                        seen.insert(infohash, path);
                        continue;
                    }
                    // A torrent the index has never held has nothing to keep,
                    // and is indexed from its `.torrent` alone.
                    (Some(fr_path), fastresume::ResumeHints::default())
                }
            }
        } else {
            (None, fastresume::ResumeHints::default())
        };

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
        let paths = crate::adopt::torrent_paths(&meta);
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
        seen.insert(infohash, path);
    }

    // A torrent whose `.torrent` is gone from the library leaves the index,
    // unless an error means the library was not fully seen: an unreadable
    // subdirectory would otherwise drop every torrent under it, and a
    // `.torrent` that is present but does not parse — truncated by a copy,
    // or corrupted — names no info-hash, so its torrent would be dropped
    // with its claims and its payload offered up as orphans. A sidecar that
    // fails hides no torrent, so its error does not count here.
    let unseen = ["walk", "read", "parse"]
        .iter()
        .map(|k| stats.errors_by_kind.get(k).copied().unwrap_or(0))
        .sum::<u64>()
        - sidecar_errors;
    if unseen == 0 {
        let seen = seen.into_keys().collect();
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
        unpaired_fastresume_count = stats.unpaired_fastresume,
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

/// `path` relative to `root`, in the index's form, or `None` where it is not
/// under `root` or is not UTF-8 — a path the index cannot hold rows for.
fn rel_of(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?.to_str()?.to_owned();
    (!rel.is_empty()).then_some(rel)
}

/// The whole of the library file at `path`, or an error where it cannot be
/// read or is larger than [`MAX_LIBRARY_FILE_BYTES`]. One oversized file
/// would otherwise be read whole into memory however large it is.
///
/// The cap is checked against the file's size and again while reading, so a
/// file that grows between the two is cut off rather than read past it.
pub fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let too_large = || {
        std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("larger than the {MAX_LIBRARY_FILE_BYTES}-byte limit"),
        )
    };
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > MAX_LIBRARY_FILE_BYTES {
        return Err(too_large());
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_LIBRARY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LIBRARY_FILE_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
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

/// Run `f` with `dir` at mode `0o000`, restoring its mode afterwards. Where
/// permissions do not bind (running as root) and the directory still lists,
/// `f` is not run, through [`permissions_do_not_bind`].
#[cfg(test)]
pub(crate) fn with_unlistable(dir: &Path, f: impl FnOnce()) {
    use std::os::unix::fs::PermissionsExt;
    let original = std::fs::metadata(dir).unwrap().permissions();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let binds = std::fs::read_dir(dir).is_err();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if binds {
            f();
        } else {
            permissions_do_not_bind("an unlistable directory");
        }
    }));
    std::fs::set_permissions(dir, original).unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// A test of what a permission refusal does cannot build its case where
/// permissions do not bind (root, or `CAP_DAC_OVERRIDE`). Locally that skips
/// the test with a note on stderr. Where `CI` is set, as every CI runner sets
/// it, it fails the test instead: CI runs the suite as a non-root user, and a
/// runner that stopped doing so would otherwise pass every such test without
/// running it.
#[cfg(test)]
pub(crate) fn permissions_do_not_bind(case: &str) {
    assert!(
        std::env::var_os("CI").is_none(),
        "permissions do not bind for this user, so {case} cannot be built: \
         CI must run the tests as a user they bind for"
    );
    eprintln!("skipped: permissions do not bind for this user, so {case} cannot be built");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    fn indexed(store: &PoolStore, root: &Path, rel: &str) -> bool {
        let root_id = store.upsert_root(root).unwrap();
        store.file(root_id, rel).unwrap().is_some()
    }

    /// A walk that cannot list a subdirectory saw nothing in it; swapping
    /// the walk in dropped that subtree's rows, so every torrent over it
    /// read `missing`.
    #[test]
    fn an_unlistable_subdirectory_keeps_its_previous_rows() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "a.bin");
        write(root, "locked/b.bin");
        write(root, "locked/deep/c.bin");
        // Shares the prefix `locked` but is not under `locked/`.
        write(root, "locked2/d.bin");
        let mut store = PoolStore::open_in_memory().unwrap();
        scan_root(&mut store, root).unwrap();
        assert_eq!(store.file_count().unwrap(), 4);

        // Changed while readable, then locked: the rest is re-indexed.
        std::fs::remove_file(root.join("a.bin")).unwrap();
        std::fs::remove_file(root.join("locked2/d.bin")).unwrap();
        write(root, "new.bin");
        with_unlistable(&root.join("locked"), || {
            let stats = scan_root(&mut store, root).unwrap();
            assert!(stats.errors_by_kind.get("walk") >= Some(&1), "{stats:?}");
            assert!(indexed(&store, root, "locked/b.bin"), "kept");
            assert!(indexed(&store, root, "locked/deep/c.bin"), "kept");
            assert!(indexed(&store, root, "new.bin"), "the rest re-indexed");
            assert!(!indexed(&store, root, "a.bin"), "the rest re-indexed");
            assert!(!indexed(&store, root, "locked2/d.bin"), "not under locked/");
            assert_eq!(store.file_count().unwrap(), 3);
        });

        // Readable again, the subtree is re-indexed from disk.
        std::fs::remove_file(root.join("locked/b.bin")).unwrap();
        let stats = scan_root(&mut store, root).unwrap();
        assert_eq!(stats.errors, 0, "{stats:?}");
        assert!(!indexed(&store, root, "locked/b.bin"));
        assert!(indexed(&store, root, "locked/deep/c.bin"));
    }

    /// Issue #440: the unseen subtree is named as it is on disk. Rewritten
    /// to `x/y`, an unlistable `x\y` kept none of its rows and kept those of
    /// the real `x/y` instead, though that one was walked.
    #[test]
    fn an_unlistable_subdirectory_named_with_a_backslash_keeps_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "x\\y/b.bin");
        write(root, "x/y/c.bin");
        let mut store = PoolStore::open_in_memory().unwrap();
        scan_root(&mut store, root).unwrap();
        assert_eq!(store.file_count().unwrap(), 2);

        std::fs::remove_file(root.join("x/y/c.bin")).unwrap();
        with_unlistable(&root.join("x\\y"), || {
            let stats = scan_root(&mut store, root).unwrap();
            assert!(stats.errors_by_kind.get("walk") >= Some(&1), "{stats:?}");
            assert!(indexed(&store, root, "x\\y/b.bin"), "kept");
            assert!(!indexed(&store, root, "x/y/c.bin"), "walked, so dropped");
            assert_eq!(store.file_count().unwrap(), 1);
        });
    }

    /// A file the walk lists but cannot stat (EIO, or here a directory
    /// readable but not searchable) was counted and then dropped by the
    /// swap, so the torrent over it read `missing`.
    #[test]
    fn an_unstatable_file_keeps_its_previous_row() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "a.bin");
        write(root, "half/b.bin");
        let mut store = PoolStore::open_in_memory().unwrap();
        scan_root(&mut store, root).unwrap();
        assert_eq!(store.file_count().unwrap(), 2);

        let half = root.join("half");
        let original = std::fs::metadata(&half).unwrap().permissions();
        // Listable, not searchable: the name is seen, its stat fails.
        std::fs::set_permissions(&half, std::fs::Permissions::from_mode(0o444)).unwrap();
        let binds = std::fs::metadata(half.join("b.bin")).is_err();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if !binds {
                permissions_do_not_bind("an unsearchable directory");
                return;
            }
            let stats = scan_root(&mut store, root).unwrap();
            assert!(stats.errors_by_kind.get("stat") >= Some(&1), "{stats:?}");
            assert!(indexed(&store, root, "half/b.bin"), "kept");
            assert!(indexed(&store, root, "a.bin"));
            assert_eq!(store.file_count().unwrap(), 2);
        }));
        std::fs::set_permissions(&half, original).unwrap();
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

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
