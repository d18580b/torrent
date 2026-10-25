//! The delete step: a file re-proven unclaimed and unchanged, then moved
//! into its root's trash through directory descriptors, never unlinked.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use tracing::info;

use super::fsat;
use super::index_location;
use super::unknown_outcome_remedy;
use super::StepFailure;
use crate::pool_service::PoolService;

#[cfg(test)]
mod tests;

/// Delete a file, re-proving at the last moment that nothing is using it.
///
/// "Unclaimed" is a statement about the index, and the index is a snapshot.
/// Five things have to hold, because an irreversible operation should not
/// rest on any one of them:
///
/// 1. No torrent claims the file *now*, not when the plan was drafted.
/// 2. The index is a complete account of what is protected — checked once per
///    apply in [`apply`](super::apply), since it is a property of the whole plan rather than
///    of one file.
/// 3. The file on disk still holds what was indexed. A `(size, mtime)`
///    match is the same evidence `drift` trusts; anything else means the
///    bytes changed after the scan decided they were expendable. Device and
///    inode are not compared, as `drift` does not compare them: a reboot or
///    a remount renumbers them, and comparing them refused every delete
///    after one.
/// 4. No torrent the index *now* holds as partial, missing or overlapping
///    expects its payload where the file is, or is missing a file of its
///    size — the planner's guards ([`torrentd_pool::plan::DeleteGuard`]),
///    re-read whenever the index generation moves, since a rescan after the
///    plan was built can make a torrent partial over these very files.
/// 5. The file is not another path to a claimed file: its live
///    `(device, inode)` is not a claimed file's live one, under any root.
///    Claims are by path, so a hard link, or a root that aliases another
///    through a bind mount, reads as unclaimed while renaming it moves
///    claimed bytes. The index is not one snapshot of identities: a rescan
///    carries a row forward unchanged for a root it could not open, a
///    subtree it could not list, or a file it could not stat, so after a
///    reboot renumbers the disk the index can hold the old identity for one
///    file and the new one for another, and an old identity can equal an
///    unrelated file's new one, since inode numbers repeat across
///    filesystems. An indexed identity is therefore only a pointer to which
///    claimed files to look at: those whose indexed identity equals this
///    file's indexed or live one are stat'd, and the step is refused only
///    when one of them is this file now. That catches the alias whichever of
///    this file's identities is the stale one, when the claimed file's row
///    is current, and refuses no file for a stale row it merely collides
///    with. A claimed file that cannot be stat'd, for a reason other than
///    its being gone, cannot be told apart and refuses the step. It misses
///    an alias of a claimed file whose own row was carried from before a
///    renumbering, which no lookup through the index can find; check 3
///    missed it too when it still compared device and inode.
///
/// The path is walked from the root one directory at a time with
/// `O_NOFOLLOW`, so a directory swapped for a symlink after planning stops the
/// step instead of carrying it onto another volume, and the file is examined
/// and moved through that parent's descriptor rather than by name from `/`.
/// It is moved — `renameat2(RENAME_NOREPLACE)` — into
/// `<root>/.torrentd-trash/<bucket>/`, never unlinked, and both directories
/// are fsynced so the move survives a crash. `bucket` is the plan's
/// [`plan_trash_bucket`].
pub(super) fn delete_file(
    pool: &PoolService,
    path: &Path,
    plan_id: i64,
    bucket: &str,
    guards: &mut DeleteGuards,
) -> Result<(), StepFailure> {
    let (root, rel, stamp, indexed) = sanctioned_delete(pool, path, guards)?;
    let mut claimed_twin = |live| guards.claimed_twin(pool, indexed, live);
    move_into_trash(&root, path, &rel, stamp, Some(&mut claimed_twin), bucket).map_err(
        |e| match e {
            StepFailure::Unknown(e) => StepFailure::Unknown(format!(
                "{e} {}",
                unknown_outcome_remedy(&path.display().to_string(), None)
            )),
            failed => failed,
        },
    )?;
    info!(
        target: "torrentd::pool::apply",
        plan_id,
        bucket,
        path = %path.display(),
        "moved to the trash",
    );
    Ok(())
}

/// A file's indexed `(size, mtime)`, as [`torrentd_pool::scan::content_stamp`]
/// computes it.
type FileStamp = (u64, i64);

/// A file's `(dev, ino)`.
type Identity = (u64, u64);

/// Checks 1 and 4 of [`delete_file`] for `path`, whose root, path relative
/// to it, indexed `(size, mtime)` and indexed identity it returns, or why
/// the delete is refused. Checks 3 and 5 need the file's live metadata and
/// are made by [`move_into_trash`].
fn sanctioned_delete(
    pool: &PoolService,
    path: &Path,
    guards: &mut DeleteGuards,
) -> Result<(std::path::PathBuf, String, FileStamp, Identity), String> {
    let Some((root_id, root, rel)) = index_location(pool, path) else {
        return Err(format!("{} is outside every managed root", path.display(),));
    };
    // The planner's containment check, re-run now: the plan is a stored
    // record, and a traversal component or a symlinked ancestor added since
    // it was built must stop the step here.
    if !torrentd_pool::plan::contains(&root, path) {
        return Err(format!("{} is outside every managed root", path.display()));
    }

    let indexed = pool
        .with_store(|s| {
            let orphan = s.is_orphan(root_id, &rel)?;
            let row = s.file(root_id, &rel)?;
            Ok::<_, torrentd_pool::model::PoolError>((orphan, row))
        })
        .map_err(|e| e.to_string())?;
    let (still_orphan, Some(row)) = indexed else {
        return Err(format!(
            "{} is not in the index; deleting it was never sanctioned",
            path.display(),
        ));
    };
    if !still_orphan {
        return Err(format!("{} is now claimed by a torrent", path.display(),));
    }
    if let Some(why) = guards.refusal(pool, root_id, &root, &rel, row.size)? {
        return Err(format!("{}: {why}", path.display()));
    }

    Ok((root, rel, (row.size, row.mtime_ns), (row.dev, row.ino)))
}

/// The directory under `<root>/.torrentd-trash/` a delete plan's files go
/// to: `<plan id>-<created_at>`, the plan's id and the unix second it was
/// created.
///
/// The id alone is not enough. Since schema v7 a discarded plan's id is never
/// handed out again, but restoring an older `pool.db` takes the id sequence
/// back with it, so the next plan can repeat an id whose trash is still on
/// disk. The creation second ties the directory to one plan: a repeated id is
/// created later than the plan that first held it.
pub(super) fn plan_trash_bucket(plan_id: i64, created_at: i64) -> String {
    format!("{plan_id}-{created_at}")
}

/// Move the file at `rel` under `root` (`path` is the two joined, for
/// messages) into `<root>/.torrentd-trash/<bucket>/`, keeping its
/// root-relative directories, once its `(size, mtime)` is still `stamp` —
/// the scan's record of it. Device and inode are not compared: a reboot or
/// a remount renumbers them without touching a byte
/// ([`torrentd_pool::scan::content_stamp`]), and the walk below, not the
/// stamp, is what keeps the move on the file under `root`.
///
/// With `claimed_twin`, the file's live `(dev, ino)` is handed to it, and
/// the move is refused when it names the claimed file that is this file:
/// check 5 of [`delete_file`]. The `delete_files` proof passes `None`, since
/// it compares live identities itself.
///
/// The path is walked from the root one directory at a time with
/// `O_NOFOLLOW`, the file is examined and moved through its parent's
/// descriptor, the move is `renameat2(RENAME_NOREPLACE)`, and both
/// directories are fsynced so it survives a crash, along with every directory
/// on the trash walk's way, made here or found, so the path to it does too.
/// A failed fsync comes after the file moved, so it is
/// [`StepFailure::Unknown`]: `failed` would say the file is still where it
/// was.
pub(crate) fn move_into_trash(
    root: &Path,
    path: &Path,
    rel: &str,
    stamp: FileStamp,
    claimed_twin: Option<&mut ClaimedTwin<'_>>,
    bucket: &str,
) -> Result<(), StepFailure> {
    let (dirs, name) = match rel.rsplit_once('/') {
        Some((d, n)) => (d.split('/').collect::<Vec<_>>(), n),
        None => (Vec::new(), rel),
    };
    let root_dir =
        std::fs::File::open(root).map_err(|e| format!("open {}: {e}", root.display()))?;
    let parent = fsat::walk(&root_dir, &dirs, false)
        .map_err(|e| format!("{}: {e}; refusing to follow it", path.display()))?
        .dir;
    let parent = parent.as_ref().unwrap_or(&root_dir);

    let md =
        fsat::stat_nofollow(parent, name).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()).into());
    }
    if torrentd_pool::scan::content_stamp(&md) != stamp {
        return Err(format!(
            "{} changed since the scan that indexed it; rescan before deleting",
            path.display(),
        )
        .into());
    }
    if let Some(claimed_twin) = claimed_twin {
        let live = (md.dev(), md.ino());
        let twin = claimed_twin(live).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Some(twin) = twin {
            return Err(format!(
                "{} is the same file (device {}, inode {}) as {}, which a torrent claims: a \
                 hard link, or the claimed file seen through another root",
                path.display(),
                live.0,
                live.1,
                twin.display(),
            )
            .into());
        }
    }

    let mut trash_dirs = vec![torrentd_pool::plan::TRASH_DIR, bucket];
    trash_dirs.extend(dirs.iter().copied());
    let walked = fsat::walk(&root_dir, &trash_dirs, true)
        .map_err(|e| format!("trash for {}: {e}", path.display()))?;
    let trash = walked.dir.expect("a non-empty walk yields a directory");
    fsat::rename_noreplace(parent, name, &trash, name).map_err(|e| {
        format!(
            "move {} into {}/{bucket}: {e}",
            path.display(),
            torrentd_pool::plan::TRASH_DIR,
        )
    })?;
    // Both directory entries changed. Every directory on the way to the
    // trash is fsynced too, whether this walk made the entry in it or found
    // it there: a concurrent delete or apply may have just made it and not
    // fsynced it yet. Without these the rename, or the chain of directories
    // leading to it, can be lost to a crash and the file reappear where the
    // journal says it is gone, or be unreachable by path.
    let trash_path = root.join(torrentd_pool::plan::TRASH_DIR).join(bucket);
    let on_the_way = walked
        .crossed
        .iter()
        .map(|d| (d, "a directory on the way to the trash"));
    for (dir, what) in [(parent, "its directory"), (&trash, "the trash")]
        .into_iter()
        .chain(on_the_way)
    {
        fsat::fsync(dir).map_err(|e| {
            StepFailure::Unknown(format!(
                "outcome unknown: {} was moved into {}, but fsync of {what} failed ({e}), so \
                 the move may not survive a crash.",
                path.display(),
                trash_path.display(),
            ))
        })?;
    }
    Ok(())
}

/// Given a file's live `(dev, ino)`, the path of a claimed file that is the
/// same file now, if any, or why that cannot be told.
pub(crate) type ClaimedTwin<'a> =
    dyn FnMut(Identity) -> Result<Option<std::path::PathBuf>, String> + 'a;

/// The planner's unresolved-payload guards, per root, and the identities of
/// every claimed file, as of one index generation. Read on first use and
/// again whenever a rescan moves the generation, so a delete plan over many
/// files reads them once per root rather than once per file.
#[derive(Default)]
pub(super) struct DeleteGuards {
    generation: Option<i64>,
    by_root: std::collections::HashMap<i64, torrentd_pool::plan::DeleteGuard>,
    claimed: Option<std::collections::HashSet<(u64, u64)>>,
}

impl DeleteGuards {
    /// Drop everything read under an earlier index generation.
    fn refresh(&mut self, pool: &PoolService) -> Result<(), String> {
        let generation = pool
            .with_store(|s| s.index_generation())
            .map_err(|e| e.to_string())?;
        if self.generation != Some(generation) {
            self.by_root.clear();
            self.claimed = None;
            self.generation = Some(generation);
        }
        Ok(())
    }

    /// The claimed file, under any root, that a file indexed as `indexed`
    /// and stat'd now as `live` is: check 5 of [`delete_file`]. The file to
    /// delete is then another path to claimed bytes — a hard link, or the
    /// same file through an aliased root.
    ///
    /// Indexed identities only say which claimed files to look at: each
    /// claimed file whose indexed identity is `indexed` or `live` is stat'd,
    /// and only one whose live identity is `live` is returned, so a stale
    /// row that collides with this file's identity refuses nothing. One gone
    /// from its path is not this file; one that cannot be stat'd for another
    /// reason cannot be told apart from it, and is an error.
    fn claimed_twin(
        &mut self,
        pool: &PoolService,
        indexed: Identity,
        live: Identity,
    ) -> Result<Option<std::path::PathBuf>, String> {
        let claimed = self.claimed_identities(pool)?;
        let mut candidates = vec![live];
        if indexed != live {
            candidates.push(indexed);
        }
        candidates.retain(|id| claimed.contains(id));
        for (dev, ino) in candidates {
            let files = pool
                .with_store(|s| s.claimed_files_with_identity(dev, ino))
                .map_err(|e| e.to_string())?;
            for (root, rel) in files {
                let claimed_path = root.join(&rel);
                match std::fs::symlink_metadata(&claimed_path) {
                    Ok(md) if (md.dev(), md.ino()) == live => return Ok(Some(claimed_path)),
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) => {}
                    Err(e) => {
                        return Err(format!(
                            "cannot tell it apart from {}, which a torrent claims and the \
                             index gives the same device and inode: stat: {e}",
                            claimed_path.display(),
                        ))
                    }
                }
            }
        }
        Ok(None)
    }

    /// The indexed `(dev, ino)` of every claimed file, under any root, as of
    /// the current index generation: a filter that spares most files the
    /// lookup in [`DeleteGuards::claimed_twin`].
    fn claimed_identities(
        &mut self,
        pool: &PoolService,
    ) -> Result<&std::collections::HashSet<(u64, u64)>, String> {
        self.refresh(pool)?;
        let claimed = match self.claimed.take() {
            Some(claimed) => claimed,
            None => pool
                .with_store(|s| s.claimed_identities())
                .map_err(|e| e.to_string())?,
        };
        Ok(self.claimed.insert(claimed))
    }

    fn refusal(
        &mut self,
        pool: &PoolService,
        root_id: i64,
        root: &Path,
        rel: &str,
        size: u64,
    ) -> Result<Option<String>, String> {
        self.refresh(pool)?;
        if let std::collections::hash_map::Entry::Vacant(e) = self.by_root.entry(root_id) {
            let guard = pool
                .with_store(|s| torrentd_pool::plan::DeleteGuard::load(s, root_id, root))
                .map_err(|e| e.to_string())?;
            e.insert(guard);
        }
        Ok(self.by_root[&root_id].refusal(rel, size))
    }
}
