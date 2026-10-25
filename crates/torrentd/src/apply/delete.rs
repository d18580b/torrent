//! The delete step: a file re-proven unclaimed and unchanged, then moved
//! into its root's trash through directory descriptors, never unlinked.

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
/// 3. The file on disk is still the file that was indexed. A `(size, mtime,
///    inode, device)` match is the same evidence `drift` trusts; anything
///    else means the bytes changed after the scan decided they were
///    expendable.
/// 4. No torrent the index *now* holds as partial, missing or overlapping
///    expects its payload where the file is, or is missing a file of its
///    size — the planner's guards ([`torrentd_pool::plan::DeleteGuard`]),
///    re-read whenever the index generation moves, since a rescan after the
///    plan was built can make a torrent partial over these very files.
/// 5. The file is not another path to a claimed file: its indexed `(device,
///    inode)` is no claimed file's, under any root. Claims are by path, so a
///    hard link, or a root that aliases another through a bind mount, reads
///    as unclaimed while renaming it moves claimed bytes. The stamp check in
///    (3) ties that indexed identity to the file actually moved.
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
    let (root, rel, stamp) = sanctioned_delete(pool, path, guards)?;
    move_into_trash(&root, path, &rel, stamp, bucket).map_err(|e| match e {
        StepFailure::Unknown(e) => StepFailure::Unknown(format!(
            "{e} {}",
            unknown_outcome_remedy(&path.display().to_string(), None)
        )),
        failed => failed,
    })?;
    info!(
        target: "torrentd::pool::apply",
        plan_id,
        bucket,
        path = %path.display(),
        "moved to the trash",
    );
    Ok(())
}

/// A file's indexed `(size, mtime, inode, device)`.
type FileStamp = (u64, i64, u64, u64);

/// Checks 1 and 3 to 5 of [`delete_file`] for `path`, whose root, path
/// relative to it, and indexed `(size, mtime, inode, device)` it returns,
/// or why the delete is refused.
fn sanctioned_delete(
    pool: &PoolService,
    path: &Path,
    guards: &mut DeleteGuards,
) -> Result<(std::path::PathBuf, String, FileStamp), String> {
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
    if guards.shares_a_claimed_inode(pool, row.dev, row.ino)? {
        return Err(format!(
            "{} is the same file (device {}, inode {}) as one a torrent claims: a hard \
             link, or the claimed file seen through another root",
            path.display(),
            row.dev,
            row.ino,
        ));
    }

    Ok((root, rel, (row.size, row.mtime_ns, row.ino, row.dev)))
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
/// root-relative directories, once its `(size, mtime, inode, device)` is
/// still `stamp` — the scan's record of it.
///
/// The path is walked from the root one directory at a time with
/// `O_NOFOLLOW`, the file is examined and moved through its parent's
/// descriptor, the move is `renameat2(RENAME_NOREPLACE)`, and both
/// directories are fsynced so it survives a crash, along with every directory
/// the trash walk made a directory in, so the path to it does too. A failed
/// fsync comes after the file moved, so it is [`StepFailure::Unknown`]:
/// `failed` would say the file is still where it was.
pub(crate) fn move_into_trash(
    root: &Path,
    path: &Path,
    rel: &str,
    stamp: FileStamp,
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
    if torrentd_pool::file_stamp(&md) != stamp {
        return Err(format!(
            "{} changed since the scan that indexed it; rescan before deleting",
            path.display(),
        )
        .into());
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
    // Both directory entries changed, and so did every directory the walk
    // made a trash directory in; without these the rename, or the chain of
    // directories leading to it, can be lost to a crash and the file
    // reappear where the journal says it is gone, or be unreachable by path.
    let trash_path = root.join(torrentd_pool::plan::TRASH_DIR).join(bucket);
    let made_in = walked
        .grown
        .iter()
        .map(|d| (d, "a trash directory's parent"));
    for (dir, what) in [(parent, "its directory"), (&trash, "the trash")]
        .into_iter()
        .chain(made_in)
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

    /// Whether `(dev, ino)` is the indexed identity of a file some torrent
    /// claims, under any root: the file to delete is then another path to
    /// claimed bytes — a hard link, or the same file through an aliased root.
    fn shares_a_claimed_inode(
        &mut self,
        pool: &PoolService,
        dev: u64,
        ino: u64,
    ) -> Result<bool, String> {
        self.refresh(pool)?;
        if self.claimed.is_none() {
            let claimed = pool
                .with_store(|s| s.claimed_identities())
                .map_err(|e| e.to_string())?;
            self.claimed = Some(claimed);
        }
        Ok(self
            .claimed
            .as_ref()
            .is_some_and(|c| c.contains(&(dev, ino))))
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
