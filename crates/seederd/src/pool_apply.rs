//! Executing mutation plans.
//!
//! The planner decided *what*; this decides *how* and does it. Three rules
//! shape everything here:
//!
//! * **The journal is written before the action.** Every step is marked in the
//!   database, attempted, then marked again. A crash mid-apply leaves a plan in
//!   `applying` with a known last-completed step, which startup re-drives.
//! * **Adopted payload moves through libtorrent.** `move_storage` keeps the
//!   session's view of where the data lives consistent with reality; moving the
//!   files underneath a seeding torrent does not.
//! * **A cross-device move is a copy, a verify, and only then an unlink.** The
//!   source is never removed until the destination is known good, so an
//!   interruption at any point leaves the payload intact somewhere.

use std::path::Path;
use std::sync::Arc;

use seederd_engine::AlertSource;
use seederd_engine::MoveFlags;
use seederd_engine::StateMap;
use seederd_pool::model::ops;
use seederd_pool::model::plan_status;
use seederd_pool::model::step_status;
use seederd_pool::model::PlanStepRow;
use seederd_pool::AdoptionState;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::pool_service::PoolService;

#[derive(Debug, serde::Serialize)]
pub struct ApplyOutcome {
    pub plan_id: i64,
    pub done: usize,
    pub failed: usize,
    pub skipped: usize,
    pub status: String,
}

/// Apply every pending step of `plan_id`.
///
/// Already-`done` steps are skipped, which is what makes this safe to call
/// again on a plan a crash interrupted.
pub fn apply(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    plan_id: i64,
) -> Result<ApplyOutcome, String> {
    let Some(plan) = pool
        .with_store(|s| s.plan(plan_id))
        .map_err(|e| e.to_string())?
    else {
        return Err("no such plan".into());
    };
    if plan.status == plan_status::APPLIED {
        return Err("plan already applied".into());
    }
    if plan.status == plan_status::CANCELLED {
        return Err("plan was cancelled".into());
    }

    // Take the plan in one conditional UPDATE. Reading the status and then
    // setting it lets two concurrent apply requests both pass the checks above
    // and both execute the same steps over the same files.
    let claimed = pool
        .with_store(|s| s.claim_plan_for_apply(plan_id))
        .map_err(|e| e.to_string())?;
    if !claimed {
        return Err(format!(
            "plan is {} and cannot be applied right now",
            plan.status,
        ));
    }

    let steps: Vec<PlanStepRow> = pool
        .with_store(|s| s.plan_steps(plan_id))
        .map_err(|e| e.to_string())?;

    let mut out = ApplyOutcome {
        plan_id,
        done: 0,
        failed: 0,
        skipped: 0,
        status: plan_status::APPLIED.to_string(),
    };

    for step in steps {
        if step.status == step_status::DONE {
            out.skipped += 1;
            continue;
        }
        let result = match step.op.as_str() {
            ops::MOVE_TORRENT => move_torrent(pool, source, state, &step),
            ops::MOVE_FILE => move_file(
                Path::new(&step.src),
                Path::new(step.dst.as_deref().unwrap_or("")),
            ),
            ops::DELETE_FILE => delete_file(pool, Path::new(&step.src)),
            other => Err(format!("unknown plan operation {other:?}")),
        };

        match result {
            Ok(()) => {
                out.done += 1;
                let _ = pool
                    .with_store(|s| s.set_step_status(plan_id, step.seq, step_status::DONE, None));
            }
            Err(e) => {
                out.failed += 1;
                error!(
                    target: "seederd::pool::apply",
                    plan_id,
                    step = step.seq,
                    op = %step.op,
                    src = %step.src,
                    error.cause = %e,
                    "plan step failed",
                );
                let _ = pool.with_store(|s| {
                    s.set_step_status(plan_id, step.seq, step_status::FAILED, Some(&e))
                });
                // Stop at the first failure. Continuing would apply half a
                // reorganisation and leave the operator reconciling it by hand.
                out.status = plan_status::FAILED.to_string();
                break;
            }
        }
    }

    let now = now_secs();
    pool.with_store(|s| s.set_plan_status(plan_id, &out.status, Some(now)))
        .map_err(|e| e.to_string())?;
    info!(
        target: "seederd::pool::apply",
        plan_id,
        done = out.done,
        failed = out.failed,
        skipped = out.skipped,
        status = %out.status,
        "plan applied",
    );
    Ok(out)
}

/// Relocate an adopted torrent by asking libtorrent to move its storage.
fn move_torrent(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    step: &PlanStepRow,
) -> Result<(), String> {
    let dst = step
        .dst
        .as_deref()
        .ok_or("move_torrent step has no destination")?;
    // Containment is re-checked here for the same reason `delete_file` re-checks
    // its claim: a plan is a stored record that may be applied minutes or days
    // after it was built, by a process whose configured roots have since
    // changed. The planner refuses an escaping destination, so reaching this is
    // either a stale plan or a row edited underneath us — both worth refusing
    // rather than handing to `move_storage`.
    if !under_a_managed_root(pool, Path::new(dst)) {
        return Err(format!("destination {dst} is outside every managed root",));
    }
    // The infohash is recovered from the claim rather than carried in the step,
    // so a resumed apply re-resolves against the current index instead of a
    // stale copy.
    let infohash = torrent_at(pool, Path::new(&step.src))?;

    // Every refusal the planner made has to hold now, not when the plan was
    // drafted. A rescan or a `POST /api/pool/drift` between the two can turn a
    // relocatable torrent into an overlapping or drifted one, and the whole
    // point of those states is that moving the payload breaks something.
    recheck_relocatable(pool, &infohash, Path::new(&step.src))?;

    let hash = libtorrent_safe::InfoHash::from_hex(&infohash).ok_or("bad infohash")?;
    let Some(st) = state.get(&hash) else {
        // Not loaded: nothing is serving it, so seederd can move the files
        // itself. This is the `matched but not adopted` case.
        return move_directory(Path::new(&step.src), Path::new(dst));
    };
    let engine = source
        .engine_for(&st.slot_id)
        .ok_or("no engine for the torrent's slot")?;

    // DontReplace: if something is already at the destination, adopt it in
    // place rather than overwriting. The planner already refused on a
    // pre-existing destination, so this is a second line of defence against a
    // race between planning and applying.
    engine
        .move_storage(st.handle, dst, MoveFlags::DontReplace)
        .map_err(|e| e.to_string())?;

    info!(
        target: "seederd::pool::apply",
        infohash = %infohash,
        dst = %dst,
        "move_storage requested; libtorrent owns the move",
    );
    Ok(())
}

/// Move a directory tree seederd owns outright.
fn move_directory(src: &Path, dst: &Path) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if dst.exists() {
        return Err(format!("destination {} already exists", dst.display()));
    }
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc_exdev()) => Err(format!(
            "cross-device directory move is not attempted automatically \
                 ({} → {}); move the data and rescan",
            src.display(),
            dst.display(),
        )),
        Err(e) => Err(format!("rename {} → {}: {e}", src.display(), dst.display())),
    }
}

/// Move one file, falling back to copy-verify-unlink across filesystems.
fn move_file(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.as_os_str().is_empty() {
        return Err("move_file step has no destination".into());
    }
    if dst.exists() {
        return Err(format!("destination {} already exists", dst.display()));
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }

    match std::fs::rename(src, dst) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() != Some(libc_exdev()) => {
            return Err(format!("rename {} → {}: {e}", src.display(), dst.display()));
        }
        Err(_) => {}
    }

    // Different filesystem: copy, flush to disk, confirm the size, and only
    // then remove the source. `fs::copy` alone would leave the destination
    // unflushed, so a crash could unlink a good source against a truncated
    // destination.
    let src_len = std::fs::metadata(src)
        .map_err(|e| format!("stat {}: {e}", src.display()))?
        .len();
    std::fs::copy(src, dst)
        .map_err(|e| format!("copy {} → {}: {e}", src.display(), dst.display()))?;
    {
        use std::io::Write;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(dst)
            .map_err(|e| format!("reopen {}: {e}", dst.display()))?;
        let mut f = f;
        f.flush()
            .map_err(|e| format!("flush {}: {e}", dst.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", dst.display()))?;
    }
    let dst_len = std::fs::metadata(dst)
        .map_err(|e| format!("stat {}: {e}", dst.display()))?
        .len();
    if dst_len != src_len {
        // Leave both copies. Removing the source here is exactly the mistake
        // this whole path exists to avoid.
        return Err(format!(
            "copy verification failed: {} is {dst_len} bytes, source is {src_len}",
            dst.display(),
        ));
    }
    std::fs::remove_file(src).map_err(|e| format!("unlink {}: {e}", src.display()))?;
    Ok(())
}

/// Delete a file, re-proving at the last moment that nothing is using it.
///
/// "Unclaimed" is a statement about the index, and the index is a snapshot.
/// Three things have to hold, because an irreversible operation should not
/// rest on any one of them:
///
/// 1. No torrent claims the file *now*, not when the plan was drafted.
/// 2. The index is a complete account — no torrent has been loaded since the
///    last scan that the matcher has never placed. Claims are written only by
///    the matcher, so a torrent added through `POST /torrents` with a
///    `save_path` inside a managed root has none, and its actively-seeding
///    payload would enumerate as an orphan.
/// 3. The file on disk is still the file that was indexed. A `(size, mtime,
///    inode)` match is the same evidence `drift` trusts; anything else means
///    the bytes changed after the scan decided they were expendable.
fn delete_file(pool: &PoolService, path: &Path) -> Result<(), String> {
    let stale = pool.unindexed_adds();
    if stale > 0 {
        return Err(format!(
            "{stale} torrent(s) have been loaded since the last scan, so the index cannot \
             prove what is unclaimed; run `pool scan` (or POST /api/pool/scan) first",
        ));
    }

    let Some((root_id, rel)) = pool.roots().iter().find_map(|(id, root)| {
        path.strip_prefix(root)
            .ok()
            .map(|r| (*id, r.to_string_lossy().replace('\\', "/")))
    }) else {
        return Err(format!("{} is outside every managed root", path.display(),));
    };

    let indexed = pool
        .with_store(|s| {
            let orphan = s.is_orphan(root_id, &rel)?;
            let row = s.file(root_id, &rel)?;
            Ok::<_, seederd_pool::model::PoolError>((orphan, row))
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

    let md =
        std::fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if seederd_pool::file_stamp(&md) != (row.size, row.mtime_ns, row.ino) {
        return Err(format!(
            "{} changed since the scan that called it unclaimed; rescan before deleting",
            path.display(),
        ));
    }

    std::fs::remove_file(path).map_err(|e| format!("unlink {}: {e}", path.display()))?;
    Ok(())
}

/// Whether `path` lies inside one of the configured managed roots.
///
/// Purely lexical, matching the planner: `Path::starts_with` compares whole
/// components, so `/data/pool2` is correctly not inside `/data/pool`.
fn under_a_managed_root(pool: &PoolService, path: &Path) -> bool {
    pool.roots().iter().any(|(_, root)| path.starts_with(root))
}

/// Which torrent's payload sits at `dir`.
///
/// Resolved from the index at apply time rather than carried in the step, so a
/// plan resumed after a restart re-binds to the current state of the world
/// instead of a snapshot that may no longer hold.
///
/// Refuses when more than one torrent answers to the same base directory.
/// Returning the first match would bind the move to an arbitrary torrent — not
/// necessarily the one the plan was built for — and then move the directory
/// out from under all the others.
fn torrent_at(pool: &PoolService, dir: &Path) -> Result<String, String> {
    let mut found: Vec<String> = Vec::new();
    pool.with_store(|store| {
        let torrents = match store.torrents() {
            Ok(t) => t,
            Err(e) => return Err(e.to_string()),
        };
        for t in torrents {
            let Ok(Some((root_id, base))) = store.adoption_base(&t.infohash) else {
                continue;
            };
            let Some(root) = pool.root_path_of(root_id) else {
                continue;
            };
            let base = base.trim_matches('/');
            let full = if base.is_empty() {
                root
            } else {
                root.join(base)
            };
            if full == dir {
                found.push(t.infohash);
                if found.len() > 1 {
                    break;
                }
            }
        }
        Ok(())
    })?;
    match found.len() {
        0 => Err(format!(
            "no torrent in the library is based at {}",
            dir.display(),
        )),
        1 => Ok(found.remove(0)),
        _ => Err(format!(
            "more than one torrent is based at {}; refusing to guess which one this plan meant",
            dir.display(),
        )),
    }
}

/// Re-run the planner's relocate refusals against the index as it is now.
fn recheck_relocatable(pool: &PoolService, infohash: &str, src: &Path) -> Result<(), String> {
    pool.with_store(|store| {
        match store.adoption_state(infohash).map_err(|e| e.to_string())? {
            Some(AdoptionState::Adopted) | Some(AdoptionState::Matched) => {}
            Some(AdoptionState::Overlap) => {
                return Err(
                    "another torrent now claims these files; moving them would break it".into(),
                )
            }
            Some(AdoptionState::Drifted) => {
                return Err("payload changed since the plan was built; rescan and verify".into())
            }
            other => {
                return Err(format!(
                    "torrent is now {}, not relocatable",
                    other.map(|s| s.as_str()).unwrap_or("unknown"),
                ))
            }
        }

        // The source is a directory rename, so it still has to hold this
        // torrent's payload and nothing else.
        let Some((root_id, base)) = store.adoption_base(infohash).map_err(|e| e.to_string())? else {
            return Err("no source location recorded".into());
        };
        if base.trim_matches('/').is_empty() {
            return Err("torrent is matched at the root itself; refusing to move a whole root".into());
        }
        let foreign = store
            .foreign_files_under(root_id, &base, infohash, 3)
            .map_err(|e| e.to_string())?;
        if !foreign.is_empty() {
            return Err(format!(
                "{} now holds files this torrent does not claim ({}); moving it would take those too",
                src.display(),
                foreign.join(", "),
            ));
        }
        Ok(())
    })
}

/// `EXDEV`. Spelled out rather than pulled from a crate for one constant.
fn libc_exdev() -> i32 {
    18
}

/// Re-drive any plan a crash left mid-apply.
pub fn resume_unfinished(pool: &PoolService, source: &Arc<dyn AlertSource>, state: &StateMap) {
    if !pool.allow_mutations() {
        // Mutations were turned off between the interrupted apply and this
        // boot. Re-driving anyway would destroy data the operator has since
        // said they do not want the daemon touching; leave the plan `applying`
        // so it is still visible and can be resumed deliberately.
        warn!(
            target: "seederd::pool::apply",
            "pool mutations are disabled; not resuming interrupted plans",
        );
        return;
    }
    let unfinished = match pool.with_store(|s| s.unfinished_plans()) {
        Ok(p) => p,
        Err(e) => {
            warn!(target: "seederd::pool::apply", reason = %e, "cannot read unfinished plans");
            return;
        }
    };
    for plan in unfinished {
        warn!(
            target: "seederd::pool::apply",
            plan_id = plan.id,
            kind = %plan.kind,
            "resuming a plan interrupted mid-apply",
        );
        if let Err(e) = apply(pool, source, state, plan.id) {
            error!(target: "seederd::pool::apply", plan_id = plan.id, error.cause = %e, "resume failed");
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::Config;

    /// A `PoolService` over a real index in `dir`, with mutations allowed.
    fn service(dir: &Path, allow_mutations: bool) -> Arc<PoolService> {
        let cfg = Config::minimal_for_tests(dir, allow_mutations);
        PoolService::open(&cfg).unwrap().unwrap()
    }

    fn write(dir: &Path, rel: &str, len: usize) -> PathBuf {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![7u8; len]).unwrap();
        p
    }

    #[test]
    fn deleting_refuses_while_the_index_is_missing_a_loaded_torrent() {
        // The exact shape of the hazard: a torrent added through the API has
        // no claim rows until the matcher runs, so its payload reads as an
        // orphan. Deleting on that verdict erases data a session is serving.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let victim = write(&root, "movies/feature.bin", 64);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        // Unclaimed by anything the index knows: deletion is allowed.
        assert!(delete_file(&pool, &victim).is_ok());
        assert!(!victim.exists());

        let victim = write(&root, "movies/feature.bin", 64);
        pool.scan().unwrap();
        pool.note_torrent_loaded("ff00000000000000000000000000000000000000");
        let e = delete_file(&pool, &victim).unwrap_err();
        assert!(e.contains("since the last scan"), "got {e}");
        assert!(victim.exists(), "payload was deleted against a stale index");
    }

    #[test]
    fn deleting_refuses_a_file_that_changed_since_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let f = write(&root, "misc/notes.bin", 32);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();

        // Rewrite it: the scan's verdict was about bytes that no longer exist.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&f, vec![9u8; 48]).unwrap();

        let e = delete_file(&pool, &f).unwrap_err();
        assert!(e.contains("changed since the scan"), "got {e}");
        assert!(f.exists());
    }

    #[test]
    fn deleting_refuses_a_path_the_index_has_never_seen() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();

        let pool = service(dir.path(), true);
        pool.scan().unwrap();

        let sneaked = write(&root, "after/the/scan.bin", 8);
        let e = delete_file(&pool, &sneaked).unwrap_err();
        assert!(e.contains("never sanctioned"), "got {e}");
        assert!(sneaked.exists());

        let outside = dir.path().join("elsewhere.bin");
        std::fs::write(&outside, b"x").unwrap();
        let e = delete_file(&pool, &outside).unwrap_err();
        assert!(e.contains("outside every managed root"), "got {e}");
        assert!(outside.exists());
    }
}
