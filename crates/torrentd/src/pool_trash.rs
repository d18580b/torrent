//! `DELETE /v1/torrents/{infohash}?delete_files=true`'s payload: proven
//! movable to the trash before anything is done to the torrent, then moved
//! there file by file the way a delete plan's step moves one.

use std::path::Path;

use tracing::info;

use crate::apply::index_location;
use crate::apply::move_into_trash;
use crate::apply::StepFailure;
use crate::live_torrent::LiveTorrent;
use crate::pool_service::PoolService;

/// A torrent's payload, proven movable to the trash before anything is
/// done to the torrent. Built by [`torrent_payload`], consumed by
/// [`trash_torrent_payload`].
#[derive(Debug)]
pub struct TorrentPayload {
    infohash: String,
    files: Vec<PayloadFile>,
}

#[derive(Debug)]
struct PayloadFile {
    path: std::path::PathBuf,
    /// `path` with every symlink resolved, when it resolves: what
    /// [`TorrentPayload::shared_with`] compares besides `path` itself.
    resolved: Option<std::path::PathBuf>,
    root: std::path::PathBuf,
    rel: String,
    /// Its indexed `(size, mtime)`, re-checked at the move.
    stamp: (u64, i64),
    /// Its `(dev, ino)` as stat'd when the payload was proven: what
    /// [`TorrentPayload::shared_with`] compares a file reached by another
    /// path against, since a bind mount or a hard link reaches the same file
    /// through a path neither spelling nor symlink resolution relates to this
    /// one. The live identity, not the indexed one: the other side is stat'd
    /// live too, and a reboot since the scan renumbers the index's.
    identity: (u64, u64),
}

/// `(dev, ino)` of whatever `path` names, following symlinks, or `None`
/// when it cannot be stat'd.
fn identity_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|md| (md.dev(), md.ino()))
}

/// Whether `path` or a directory above it is one of `dirs`, by `(dev, ino)`:
/// how a file is found under a directory that a bind mount aliases, where
/// no path comparison can see it. Each ancestor's identity is kept in
/// `seen`, so the files of one payload stat each directory once.
fn under_by_identity(
    path: &Path,
    dirs: &std::collections::HashSet<(u64, u64)>,
    seen: &mut std::collections::HashMap<std::path::PathBuf, Option<(u64, u64)>>,
) -> bool {
    path.ancestors().any(|dir| {
        let id = *seen
            .entry(dir.to_path_buf())
            .or_insert_with(|| identity_of(dir));
        id.is_some_and(|id| dirs.contains(&id))
    })
}

impl TorrentPayload {
    /// How many files the trash move covers. Files the torrent lists that
    /// were never created on disk are not among them.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// The first file of this payload that `other`, another torrent a
    /// session holds, has at the same path — or `None` when it has none.
    ///
    /// The pool index cannot answer this: claims come from the matcher
    /// alone, so a torrent added through `POST /v1/torrents` with a
    /// `save_path` over the same files claims nothing, and trashing them
    /// would leave it serving nothing. Each path is compared both as the
    /// sessions spell it and resolved, and each of `other`'s files is
    /// resolved on its own full path, so a `save_path` reaching the same
    /// directory through a symlink, a symlinked directory below it, and a
    /// file that is itself a symlink to the payload are all caught. Each is
    /// also compared by `(dev, ino)`, so a file reached through a bind mount
    /// aliasing a root, or a hard link, is caught where no path relates
    /// them. A torrent whose metadata has not arrived yet could write any
    /// file under its `save_path`, so every payload file under it counts as
    /// shared, its `save_path` compared by path and by the identity of each
    /// directory above the payload file.
    pub fn shared_with(&self, other: &LiveTorrent) -> Option<&std::path::Path> {
        let bases = other.bases();
        fn forms(f: &PayloadFile) -> impl Iterator<Item = &std::path::PathBuf> {
            std::iter::once(&f.path).chain(f.resolved.as_ref())
        }
        let hit = match &other.files {
            None => {
                let dirs: std::collections::HashSet<(u64, u64)> =
                    bases.iter().filter_map(|b| identity_of(b)).collect();
                let mut seen = std::collections::HashMap::new();
                self.files.iter().find(|f| {
                    forms(f).any(|p| bases.iter().any(|b| p.starts_with(b)))
                        || under_by_identity(&f.path, &dirs, &mut seen)
                })
            }
            Some(files) => {
                // Each of its files as spelled under either base, and with
                // every symlink on its own path resolved: a cross-seed whose
                // files are symlinks to the payload, or that reaches it
                // through a symlinked directory below its save path, is
                // caught by the resolved form only.
                let theirs: std::collections::HashSet<std::path::PathBuf> = files
                    .iter()
                    .flat_map(|rel| {
                        let joined = other.save_path.join(rel);
                        bases
                            .iter()
                            .map(move |b| b.join(rel))
                            .chain(std::fs::canonicalize(joined).ok())
                    })
                    .collect();
                // And each by identity: a bind mount of a root, or a hard
                // link, reaches the same file through an unrelated path.
                let ids: std::collections::HashSet<(u64, u64)> = files
                    .iter()
                    .filter_map(|rel| identity_of(&other.save_path.join(rel)))
                    .collect();
                self.files
                    .iter()
                    .find(|f| forms(f).any(|p| theirs.contains(p)) || ids.contains(&f.identity))
            }
        };
        hit.map(|f| f.path.as_path())
    }
}

/// What [`trash_torrent_payload`] did.
#[derive(Debug)]
pub struct TrashOutcome {
    /// Where the files went: `<root>/.torrentd-trash/<bucket>/` under each
    /// root the payload spans.
    pub trash: Vec<std::path::PathBuf>,
    /// How many files were moved.
    pub moved: usize,
    /// The file the move stopped at, and why: one that could not be moved,
    /// which is still in place, or one moved but whose move could not be
    /// fsynced, which `moved` counts. Every file after it is still in place.
    pub failed: Option<(std::path::PathBuf, String)>,
}

/// Why [`torrent_payload`] refused a payload.
#[derive(Debug)]
pub enum PayloadRefusal {
    /// Other torrents claim files of this one in the pool index: these,
    /// sorted. Moving its payload would move theirs.
    Shared(Vec<String>),
    /// A file could not be proven movable, or the index could not be read:
    /// why.
    Unproven(String),
}

impl std::fmt::Display for PayloadRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shared(others) => write!(
                f,
                "{} other torrent(s) claim files of this one in the pool index",
                others.len(),
            ),
            Self::Unproven(why) => f.write_str(why),
        }
    }
}

/// Prove that every file of the torrent `infohash` can go to the trash, and
/// say which.
///
/// `save_path` and `files` (torrent-relative, `/`-separated) are the
/// session's view of where the payload lies. Each file that exists must:
///
/// 1. lie inside a managed root, because the trash is a directory of a root
///    and a payload outside every root has no trash to go to;
/// 2. be in the index, and claimed there by this torrent — the index's
///    record is what the co-claimant check and the re-stat below rest on,
///    and a torrent the matcher has not placed contributes neither. A file
///    the torrent declares empty, and that is empty on disk and in the
///    index, needs no claim: the matcher claims no file without bytes;
/// 3. still hold what the index recorded: the same `(size, mtime)`, checked
///    here and again at the move. Device and inode are not compared, as the
///    drift check does not compare them: a reboot or a remount renumbers
///    them without touching a byte.
///
/// A listed file that is on neither the disk nor the index was never
/// written, and is skipped. Refused as [`PayloadRefusal::Shared`] when other
/// torrents claim any of this one's files, before any file is stat'd.
/// Nothing is changed on any outcome.
///
/// The claims, the co-claimants and every file's row are read on the read
/// connection, in one read transaction: they all come from the same
/// committed index, and the proof never waits out a scan holding the writer.
/// A scan still running then can commit a claim on these files after the
/// read; the delete is not refused for it, and the files go to the trash,
/// where they can be taken back from.
pub fn torrent_payload(
    pool: &PoolService,
    infohash: &str,
    save_path: &Path,
    files: &[String],
) -> Result<TorrentPayload, PayloadRefusal> {
    let outside = |path: &Path| {
        PayloadRefusal::Unproven(format!(
            "{} is outside every managed root, so there is no trash to move it to",
            path.display(),
        ))
    };
    let mut located = Vec::with_capacity(files.len());
    for file in files {
        let path = save_path.join(file);
        let Some((root_id, root, rel)) = index_location(pool, &path) else {
            return Err(outside(&path));
        };
        if !torrentd_pool::plan::contains(&root, &path) {
            return Err(outside(&path));
        }
        located.push((path, root_id, root, rel, file));
    }
    let (claims, empty, others, rows) = pool
        .with_reader(|s| {
            let claims: std::collections::HashSet<(i64, String)> =
                s.claims_of(infohash)?.into_iter().collect();
            let empty: std::collections::HashSet<String> = s
                .torrent_files(infohash)?
                .into_iter()
                .filter(|f| f.size == 0 && !f.pad_file)
                .map(|f| f.rel_path)
                .collect();
            let others = s.co_claimants(infohash)?;
            let rows = located
                .iter()
                .map(|(_, root_id, _, rel, _)| s.file(*root_id, rel))
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, torrentd_pool::PoolError>((claims, empty, others, rows))
        })
        .map_err(|e| PayloadRefusal::Unproven(e.to_string()))?;
    if !others.is_empty() {
        return Err(PayloadRefusal::Shared(others));
    }
    let mut out = Vec::with_capacity(located.len());
    for ((path, root_id, root, rel, file), row) in located.into_iter().zip(rows) {
        let unproven = |why: String| Err(PayloadRefusal::Unproven(why));
        let on_disk = match std::fs::symlink_metadata(&path) {
            Ok(md) => Some(md),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return unproven(format!("stat {}: {e}", path.display())),
        };
        let (md, row) = match (on_disk, row) {
            (None, None) => continue,
            (Some(md), Some(row)) => (md, row),
            (None, Some(_)) => {
                return unproven(format!(
                    "{} is in the index but not on disk; rescan before deleting",
                    path.display(),
                ))
            }
            (Some(_), None) => {
                return unproven(format!(
                    "{} is not in the index; rescan before deleting",
                    path.display(),
                ))
            }
        };
        // The matcher claims no file without bytes, so a file this torrent
        // declares empty has no claim row: it is this torrent's while it is
        // still empty, on disk and in the index.
        let own_empty = row.size == 0 && md.len() == 0 && empty.contains(file.as_str());
        if !own_empty && !claims.contains(&(root_id, rel.clone())) {
            return unproven(format!(
                "the index does not record this torrent claiming {}; rescan before deleting",
                path.display(),
            ));
        }
        if !md.is_file() {
            return unproven(format!("{} is not a regular file", path.display()));
        }
        let stamp = (row.size, row.mtime_ns);
        if torrentd_pool::scan::content_stamp(&md) != stamp {
            return unproven(format!(
                "{} changed since the scan that indexed it; rescan before deleting",
                path.display(),
            ));
        }
        out.push(PayloadFile {
            resolved: std::fs::canonicalize(&path).ok(),
            path,
            root,
            rel,
            stamp,
            identity: {
                use std::os::unix::fs::MetadataExt;
                (md.dev(), md.ino())
            },
        });
    }
    Ok(TorrentPayload {
        infohash: infohash.to_owned(),
        files: out,
    })
}

/// Move `payload` into `<root>/.torrentd-trash/<bucket>/`, each file
/// re-stat'd against the index at the moment it moves. Stops at the first
/// file whose move fails, and reports it as [`TrashOutcome::failed`]: a file
/// that could not be moved is left in place, a file that was moved but whose
/// move could not be fsynced is already in the trash and counted in `moved`,
/// and every file after it is left in place. Nothing is ever unlinked.
pub fn trash_torrent_payload(payload: &TorrentPayload, bucket: &str) -> TrashOutcome {
    let mut out = TrashOutcome {
        trash: Vec::new(),
        moved: 0,
        failed: None,
    };
    for f in &payload.files {
        let moved = move_into_trash(&f.root, &f.path, &f.rel, f.stamp, bucket);
        if let Err(StepFailure::Failed(e)) = moved {
            out.failed = Some((f.path.clone(), e));
            break;
        }
        let trash = f.root.join(torrentd_pool::plan::TRASH_DIR).join(bucket);
        if !out.trash.contains(&trash) {
            out.trash.push(trash);
        }
        out.moved += 1;
        // Moved, but not made durable: counted as moved, and the move stops.
        if let Err(StepFailure::Unknown(e)) = moved {
            out.failed = Some((f.path.clone(), e));
            break;
        }
        info!(
            target: "torrentd::pool::apply",
            infohash = %payload.infohash,
            path = %f.path.display(),
            "moved a deleted torrent's file to the trash",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::test_support::claimed;
    use crate::apply::test_support::long_rel_path;
    use crate::apply::test_support::renumber;
    use crate::apply::test_support::resize_keeping_mtime;
    use crate::apply::test_support::service;
    use crate::apply::test_support::touch_later;
    use crate::apply::test_support::write;
    use crate::apply::FAIL_FSYNC;

    #[test]
    fn a_torrents_payload_goes_to_the_trash_once_every_file_is_proven() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let f = write(&root, "T/a.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");

        // A listed file never written is skipped, not refused.
        let files = ["T/a.bin".to_owned(), "T/never.bin".to_owned()];
        let payload = torrent_payload(&pool, &ih, &root, &files).unwrap();
        assert_eq!(payload.file_count(), 1);
        let out = trash_torrent_payload(&payload, "torrent-x-1");
        assert!(out.failed.is_none(), "{:?}", out.failed);
        assert_eq!(out.moved, 1);
        assert_eq!(out.trash, vec![root.join(".torrentd-trash/torrent-x-1")]);
        assert!(!f.exists());
        assert_eq!(
            std::fs::read(root.join(".torrentd-trash/torrent-x-1/T/a.bin")).unwrap(),
            vec![7u8; 16]
        );
    }

    /// Issue #543: a payload file whose name holds a `\` is proven against
    /// the claim the index records for that name, and goes to the trash.
    #[test]
    fn a_torrents_payload_file_with_a_backslash_in_its_name_is_proven() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let f = write(&root, "T/a\\b.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a\\b.bin");

        let payload = torrent_payload(&pool, &ih, &root, &["T/a\\b.bin".to_owned()])
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(payload.file_count(), 1);
        let out = trash_torrent_payload(&payload, "torrent-x-1");
        assert!(out.failed.is_none(), "{:?}", out.failed);
        assert_eq!(out.moved, 1);
        assert!(!f.exists());
        assert!(root.join(".torrentd-trash/torrent-x-1/T/a\\b.bin").exists());
    }

    /// A file that reached the trash but could not be fsynced there is
    /// counted as moved, and the move stops at it.
    #[test]
    fn a_torrents_payload_file_whose_fsync_fails_is_counted_moved_and_stops_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let f = write(&root, "T/a.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        let payload = torrent_payload(&pool, &ih, &root, &["T/a.bin".to_owned()]).unwrap();

        FAIL_FSYNC.set(true);
        let out = trash_torrent_payload(&payload, "torrent-x-1");
        FAIL_FSYNC.set(false);
        assert_eq!(out.moved, 1);
        let (at, why) = out.failed.expect("the fsync failure is reported");
        assert_eq!(at, f);
        assert!(
            why.contains("outcome unknown") && why.contains("fsync"),
            "{why}"
        );
        assert!(!f.exists());
        assert!(root.join(".torrentd-trash/torrent-x-1/T/a.bin").exists());
    }

    #[test]
    fn a_torrents_payload_is_refused_unless_every_file_is_proven() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let claimed_file = write(&root, "T/a.bin", 16);
        let unclaimed = write(&root, "T/b.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        let refusal = |save: &Path, files: &[&str]| {
            let files: Vec<String> = files.iter().map(|f| (*f).to_owned()).collect();
            torrent_payload(&pool, &ih, save, &files)
                .unwrap_err()
                .to_string()
        };

        // Outside every root: there is no trash to go to.
        let outside = dir.path().join("data");
        write(&outside, "T/a.bin", 16);
        let e = refusal(&outside, &["T/a.bin"]);
        assert!(e.contains("outside every managed root"), "{e}");

        // Indexed, but the index does not say it is this torrent's.
        let e = refusal(&root, &["T/a.bin", "T/b.bin"]);
        assert!(e.contains("does not record this torrent claiming"), "{e}");

        // On disk, never scanned.
        write(&root, "T/new.bin", 16);
        let e = refusal(&root, &["T/new.bin"]);
        assert!(e.contains("not in the index"), "{e}");

        // Rewritten since the scan.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&claimed_file, vec![9u8; 48]).unwrap();
        let e = refusal(&root, &["T/a.bin"]);
        assert!(e.contains("changed since the scan"), "{e}");

        assert!(claimed_file.exists() && unclaimed.exists());
        assert!(!root.join(".torrentd-trash").exists());
    }

    #[test]
    fn a_torrents_payload_another_torrent_claims_is_refused_as_shared() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        write(&root, "T/a.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        let other = "cd".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        claimed(&pool, dir.path(), &other, "T/a.bin");

        match torrent_payload(&pool, &ih, &root, &["T/a.bin".to_owned()]) {
            Err(PayloadRefusal::Shared(others)) => assert_eq!(others, vec![other]),
            other => panic!("expected a shared refusal, got {other:?}"),
        }
        assert!(root.join("T/a.bin").exists());
    }

    #[test]
    fn a_payload_is_shared_with_a_live_torrent_holding_a_file_at_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let a = write(&root, "T/a.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        let payload = torrent_payload(&pool, &ih, &root, &["T/a.bin".to_owned()]).unwrap();
        let live = |save: &Path, files: Option<&[&str]>| LiveTorrent {
            save_path: save.to_path_buf(),
            files: files.map(|f| f.iter().map(|s| (*s).to_owned()).collect()),
        };

        // The same file through another torrent's save path and file list.
        assert_eq!(
            payload.shared_with(&live(&root.join("T"), Some(&["a.bin"]))),
            Some(a.as_path())
        );
        // The same directory reached through a symlink.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert_eq!(
            payload.shared_with(&live(&link, Some(&["T/a.bin"]))),
            Some(a.as_path())
        );
        // A cross-seed whose file is itself a symlink to the payload, in a
        // save path of its own that no symlink leads to.
        let xseed = dir.path().join("xseed");
        std::fs::create_dir_all(xseed.join("T")).unwrap();
        std::os::unix::fs::symlink(&a, xseed.join("T/a.bin")).unwrap();
        assert_eq!(
            payload.shared_with(&live(&xseed, Some(&["T/a.bin"]))),
            Some(a.as_path())
        );
        // A cross-seed reaching it through a symlinked directory below its
        // save path.
        let below = dir.path().join("below");
        std::fs::create_dir_all(&below).unwrap();
        std::os::unix::fs::symlink(root.join("T"), below.join("T")).unwrap();
        assert_eq!(
            payload.shared_with(&live(&below, Some(&["T/a.bin"]))),
            Some(a.as_path())
        );
        // No metadata yet: it could write anything under its save path.
        assert_eq!(payload.shared_with(&live(&root, None)), Some(a.as_path()));

        // A sibling file, another directory, or no metadata elsewhere.
        assert_eq!(payload.shared_with(&live(&root, Some(&["T/b.bin"]))), None);
        assert_eq!(
            payload.shared_with(&live(&dir.path().join("data"), Some(&["T/a.bin"]))),
            None
        );
        assert_eq!(
            payload.shared_with(&live(&dir.path().join("data"), None)),
            None
        );
    }

    /// Issue #657: the matcher claims no file without bytes, so a torrent's
    /// declared empty file has no claim row. It is proven this torrent's
    /// while it is empty, and goes to the trash with the rest; an empty
    /// file the torrent does not declare, or the declared one once it holds
    /// bytes, is still refused.
    #[test]
    fn a_torrents_declared_empty_file_goes_to_the_trash_with_its_payload() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let a = write(&root, "T/a.bin", 16);
        let empty = write(&root, "T/empty.txt", 0);
        write(&root, "T/stray.txt", 0);
        write(&root, "T/other.txt", 0);
        let filled = write(&root, "T/filled.txt", 5);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        let row = |idx: i64, rel: &str, size: u64, pad_file: bool| torrentd_pool::TorrentFileRow {
            infohash: ih.clone(),
            idx,
            rel_path: rel.to_owned(),
            size,
            pieces_root: None,
            pad_file,
        };
        pool.with_store_mut(|st| {
            st.replace_torrent_files(
                &ih,
                &[
                    row(0, "T/a.bin", 16, false),
                    row(1, "T/empty.txt", 0, false),
                    row(2, "T/stray.txt", 0, true),
                    row(3, "T/filled.txt", 0, false),
                ],
            )
        })
        .unwrap();
        let files =
            |names: &[&str]| -> Vec<String> { names.iter().map(|f| (*f).to_owned()).collect() };

        // A padding entry is never a file the torrent declares empty.
        let e = torrent_payload(&pool, &ih, &root, &files(&["T/a.bin", "T/stray.txt"]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not record this torrent claiming"), "{e}");

        // Nor is an empty file it does not declare at all.
        let e = torrent_payload(&pool, &ih, &root, &files(&["T/a.bin", "T/other.txt"]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not record this torrent claiming"), "{e}");
        // Bytes at a declared empty path are not the empty file it declares.
        let e = torrent_payload(&pool, &ih, &root, &files(&["T/a.bin", "T/filled.txt"]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not record this torrent claiming"), "{e}");
        assert!(filled.exists());

        let payload =
            torrent_payload(&pool, &ih, &root, &files(&["T/a.bin", "T/empty.txt"])).unwrap();
        let out = trash_torrent_payload(&payload, "torrent-x-1");
        assert!(out.failed.is_none(), "{:?}", out.failed);
        assert_eq!(out.moved, 2);
        assert!(!a.exists() && !empty.exists());
        let trash = root.join(".torrentd-trash/torrent-x-1/T");
        assert_eq!(std::fs::read(trash.join("empty.txt")).unwrap(), b"");
        assert_eq!(std::fs::read(trash.join("a.bin")).unwrap(), vec![7u8; 16]);
    }

    /// Issue #657: a live torrent reaching a payload file through a path no
    /// spelling or symlink relates to it — a bind mount aliasing a root, or
    /// a hard link — is caught by `(dev, ino)`.
    #[test]
    fn a_payload_is_shared_with_a_live_torrent_reaching_it_by_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let a = write(&root, "T/a.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        let payload = torrent_payload(&pool, &ih, &root, &["T/a.bin".to_owned()]).unwrap();

        // The same file under another save path, through a hard link: as a
        // bind mount does, it shares the inode and no path.
        let alias = dir.path().join("alias");
        std::fs::create_dir_all(alias.join("T")).unwrap();
        std::fs::hard_link(&a, alias.join("T/a.bin")).unwrap();
        let live = LiveTorrent {
            save_path: alias.clone(),
            files: Some(vec!["T/a.bin".to_owned()]),
        };
        assert_eq!(payload.shared_with(&live), Some(a.as_path()));
        // A different file at the same relative path is not shared.
        std::fs::remove_file(alias.join("T/a.bin")).unwrap();
        write(&alias, "T/a.bin", 16);
        assert_eq!(payload.shared_with(&live), None);

        // With no metadata, its save path is compared with each directory
        // above the payload file by identity, which is what catches a bind
        // mount of one: no path test sees it.
        let dirs: std::collections::HashSet<(u64, u64)> =
            identity_of(&root.join("T")).into_iter().collect();
        let mut seen = std::collections::HashMap::new();
        assert!(under_by_identity(&a, &dirs, &mut seen));
        let elsewhere: std::collections::HashSet<(u64, u64)> =
            identity_of(&alias).into_iter().collect();
        assert!(!under_by_identity(&a, &elsewhere, &mut seen));
    }

    /// Issue #669: a reboot or remount that renumbers device and inode does
    /// not stop the payload going to the trash, and the identity a live
    /// torrent is compared against is the file's as it reads now, so a hard
    /// link is still caught under the renumbered index. A changed size or
    /// mtime is still refused.
    #[test]
    fn a_renumbered_payload_goes_to_the_trash_unless_its_size_or_mtime_changed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let a = write(&root, "T/a.bin", 16);
        write(&root, "T/resized.bin", 16);
        write(&root, "T/touched.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        renumber(&pool, &["T/a.bin", "T/resized.bin", "T/touched.bin"]);
        resize_keeping_mtime(&root, "T/resized.bin", 48);
        touch_later(&root, "T/touched.bin");
        let a_only = ["T/a.bin".to_owned()];

        // `claimed` replaces the torrent's claims, so each file is claimed
        // alone before its payload is proven.
        for rel in ["T/resized.bin", "T/touched.bin"] {
            claimed(&pool, dir.path(), &ih, rel);
            let e = torrent_payload(&pool, &ih, &root, &[rel.to_owned()])
                .unwrap_err()
                .to_string();
            assert!(e.contains("changed since the scan"), "{rel}: {e}");
        }

        claimed(&pool, dir.path(), &ih, "T/a.bin");
        let payload = torrent_payload(&pool, &ih, &root, &a_only).unwrap();
        let alias = dir.path().join("alias");
        std::fs::create_dir_all(alias.join("T")).unwrap();
        std::fs::hard_link(&a, alias.join("T/a.bin")).unwrap();
        let live = LiveTorrent {
            save_path: alias.clone(),
            files: Some(a_only.to_vec()),
        };
        assert_eq!(payload.shared_with(&live), Some(a.as_path()));
        std::fs::remove_file(alias.join("T/a.bin")).unwrap();

        let out = trash_torrent_payload(&payload, "torrent-x-1");
        assert!(out.failed.is_none(), "{:?}", out.failed);
        assert_eq!(out.moved, 1);
        assert!(!a.exists());
        assert!(root.join(".torrentd-trash/torrent-x-1/T/a.bin").exists());
    }

    #[test]
    fn a_payload_with_a_long_file_path_goes_to_the_trash_whole() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let (_, rel) = long_rel_path();
        let long = write(&root, &rel, 16);
        let short = write(&root, "T/a.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        pool.with_store_mut(|st| {
            st.replace_claims(
                &ih,
                &[
                    (pool.roots()[0].0, "T/a.bin".to_owned()),
                    (pool.roots()[0].0, rel.clone()),
                ],
            )
        })
        .unwrap();

        // The session's file list holds the long path whole: the file is
        // proven and moved, not skipped as never written.
        let files = ["T/a.bin".to_owned(), rel.clone()];
        let payload = torrent_payload(&pool, &ih, &root, &files).unwrap();
        assert_eq!(payload.file_count(), 2);
        let out = trash_torrent_payload(&payload, "torrent-x-1");
        assert!(out.failed.is_none(), "{:?}", out.failed);
        assert_eq!(out.moved, 2);
        assert!(!long.exists() && !short.exists());
        assert_eq!(
            std::fs::read(root.join(".torrentd-trash/torrent-x-1").join(&rel)).unwrap(),
            vec![7u8; 16]
        );
    }

    #[test]
    fn a_payload_is_shared_with_a_live_torrent_through_its_long_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let (deep, rel) = long_rel_path();
        let leaf = write(&root, &rel, 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, &rel);
        // This torrent reaches the file through a deep save path and a short
        // relative one.
        let payload =
            torrent_payload(&pool, &ih, &root.join(&deep), &["leaf.bin".to_owned()]).unwrap();
        assert_eq!(payload.file_count(), 1);

        // Another reaches the same file through the root and the long
        // relative path, which the session reports whole.
        let other = LiveTorrent {
            save_path: root.clone(),
            files: Some(vec![rel.clone()]),
        };
        assert_eq!(payload.shared_with(&other), Some(leaf.as_path()));
        // A sibling at the same depth is not the same file.
        let sibling = LiveTorrent {
            save_path: root.clone(),
            files: Some(vec![format!("{deep}/other.bin")]),
        };
        assert_eq!(payload.shared_with(&sibling), None);
    }

    #[test]
    fn a_file_that_changes_after_the_proof_stops_the_move_there() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let a = write(&root, "T/a.bin", 16);
        let b = write(&root, "T/b.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        claimed(&pool, dir.path(), &ih, "T/a.bin");
        pool.with_store_mut(|st| {
            st.replace_claims(
                &ih,
                &[
                    (pool.roots()[0].0, "T/a.bin".to_owned()),
                    (pool.roots()[0].0, "T/b.bin".to_owned()),
                ],
            )
        })
        .unwrap();

        let files = ["T/a.bin".to_owned(), "T/b.bin".to_owned()];
        let payload = torrent_payload(&pool, &ih, &root, &files).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&b, vec![9u8; 48]).unwrap();

        let out = trash_torrent_payload(&payload, "torrent-x-1");
        assert_eq!(out.moved, 1);
        let (path, why) = out.failed.unwrap();
        assert_eq!(path, b);
        assert!(why.contains("changed since the scan"), "{why}");
        assert!(!a.exists());
        assert_eq!(std::fs::read(&b).unwrap(), vec![9u8; 48], "never unlinked");
    }
}
