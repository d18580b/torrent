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

use torrentd_engine::AlertSource;
use torrentd_engine::MoveFlags;
use torrentd_engine::StateMap;
use torrentd_engine::StorageMove;
use torrentd_pool::model::ops;
use torrentd_pool::model::plan_status;
use torrentd_pool::model::step_status;
use torrentd_pool::model::PlanStepRow;
use torrentd_pool::AdoptionState;
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

/// Asked between steps: is the daemon shutting down? A plan stopped for it
/// is left `applying` with its remaining steps `pending`, which is exactly
/// what `resume_unfinished` re-drives on the next boot.
pub type StopCheck<'a> = &'a (dyn Fn() -> bool + Send + Sync);

/// Apply every pending step of `plan_id`, stopping between steps once `stop`
/// says so.
///
/// Already-`done` steps are skipped, which is what makes this safe to call
/// again on a plan a crash interrupted.
pub fn apply(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    plan_id: i64,
    stop: StopCheck<'_>,
) -> Result<ApplyOutcome, String> {
    apply_inner(pool, source, state, plan_id, false, stop)
}

/// Whether the index accounts for everything the daemon currently serves.
///
/// Claims are written by the matcher and by nothing else, so a loaded torrent
/// the matcher has never placed contributes none — and its payload reads as an
/// orphan.
fn check_index_accounts_for_live_state(pool: &PoolService, state: &StateMap) -> Result<(), String> {
    let loaded: Vec<String> = state.infohashes().iter().map(|ih| ih.to_hex()).collect();
    let unindexed = pool
        .with_store(|st| st.loaded_without_claims(&loaded))
        .map_err(|e| e.to_string())?;
    if !unindexed.is_empty() {
        return Err(format!(
            "{} loaded torrent(s) have no claims in the index, so it cannot prove what is \
             unclaimed — the first is {}. Run `pool scan` (or POST /v1/pool/scan) and \
             rebuild this plan.",
            unindexed.len(),
            unindexed[0],
        ));
    }
    Ok(())
}

/// What `apply_inner` answers when a shutdown stops it before the claim. The
/// boot re-drive tells a stop from a failure by it.
const SHUTTING_DOWN: &str = "the daemon is shutting down; apply the plan again once it is back";

fn apply_inner(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    plan_id: i64,
    resume: bool,
    stop: StopCheck<'_>,
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

    let steps: Vec<PlanStepRow> = pool
        .with_store(|s| s.plan_steps(plan_id))
        .map_err(|e| e.to_string())?;

    // ---- preconditions, all of them before the plan is claimed -------------
    //
    // Ordering matters. Claiming flips the status to `applying`, and an early
    // return after that would leave the plan in a state that `apply` refuses,
    // `resume_unfinished` refuses, and `delete_plan` refuses — permanently
    // stuck with no way out short of editing the database by hand.

    if let Some(stuck) = steps.iter().find(|s| s.status == step_status::IN_PROGRESS) {
        // Written before the attempt and cleared by the outcome, so finding
        // one here means a previous run died mid-step. Whether it happened is
        // unknown, and both re-running and skipping it can destroy data.
        //
        // Park it in `failed` rather than leaving it `applying`: a human has
        // to look either way, and `failed` is a state they can discard.
        let msg = format!(
            "step {} ({}) was interrupted and its outcome is unknown; inspect {} before \
             resuming this plan",
            stuck.seq, stuck.op, stuck.src,
        );
        if let Err(e) = pool.with_store(|s| s.set_plan_status(plan_id, plan_status::FAILED, None)) {
            pool.note_store_error("set_plan_status", &e);
        }
        pool.count("pool_plan_failures_total", &[("kind", "step_failed")]);
        return Err(msg);
    }

    // Deleting rests on "the index is a complete account of what is
    // protected". Derived from live session state, so it is correct on every
    // load path and across a restart.
    let deletes = steps.iter().any(|s| s.op == ops::DELETE_FILE);
    if deletes {
        check_index_accounts_for_live_state(pool, state)?;
    }

    // Not claimed during a shutdown: the claim would hand the plan to the next
    // boot to re-drive, which is not what a request made now asked for.
    if stop() {
        return Err(SHUTTING_DOWN.into());
    }

    // ---- claim -------------------------------------------------------------
    //
    // One conditional UPDATE. Reading the status and then setting it lets two
    // concurrent apply requests both pass the checks above and both execute
    // the same steps over the same files.
    let claimed = pool
        .with_store(|s| s.claim_plan_for_apply(plan_id, resume))
        .map_err(|e| e.to_string())?;
    if !claimed {
        return Err(format!(
            "plan is {} and cannot be applied right now",
            plan.status,
        ));
    }

    let mut out = ApplyOutcome {
        plan_id,
        done: 0,
        failed: 0,
        skipped: 0,
        status: plan_status::APPLIED.to_string(),
    };

    // A delete plan over a large subtree runs for minutes. A `POST /torrents`
    // landing in that window makes the index incomplete again, so the
    // precondition is re-established whenever the loaded set changes. `len()`
    // is O(1); the full check only runs when it has actually moved.
    let mut loaded_len = state.len();

    for step in steps {
        if step.status == step_status::DONE {
            out.skipped += 1;
            continue;
        }
        // Between steps, never inside one: a step is journalled
        // `in_progress` before it runs, and a process killed inside it leaves
        // a step whose outcome is unknown and a plan parked for a human. Stop
        // here instead and the plan stays `applying` with this step still
        // `pending`, which the next boot re-drives from exactly here.
        if stop() {
            warn!(
                target: "torrentd::pool::apply",
                plan_id,
                next_step = step.seq,
                done = out.done,
                "stopping between steps for shutdown; the plan resumes at the next boot",
            );
            out.status = plan_status::APPLYING.to_string();
            return Ok(out);
        }
        if deletes && step.op == ops::DELETE_FILE && state.len() != loaded_len {
            if let Err(e) = check_index_accounts_for_live_state(pool, state) {
                // Stop, but as a *failed* plan rather than an early return:
                // the plan is claimed at this point, and returning here would
                // strand it in `applying` where nothing can apply, resume or
                // discard it.
                out.failed += 1;
                out.status = plan_status::FAILED.to_string();
                if let Err(se) = pool.with_store(|s| {
                    s.set_step_status(plan_id, step.seq, step_status::FAILED, Some(&e))
                }) {
                    pool.note_store_error("set_step_status", &se);
                }
                error!(
                    target: "torrentd::pool::apply",
                    plan_id,
                    step = step.seq,
                    error.cause = %e,
                    "stopping: the index no longer accounts for what is loaded",
                );
                pool.count("pool_plan_failures_total", &[("kind", "index_diverged")]);
                break;
            }
            loaded_len = state.len();
        }
        // Written before the action, so a crash leaves `in_progress` behind.
        // Steps were inserted `pending` up front and only updated afterwards,
        // which made "never started" and "started, outcome unknown"
        // indistinguishable to the resume path.
        //
        // A journal write that fails here leaves the step `pending`, so a
        // crash during it re-runs the step instead of parking it for a human.
        // The step still runs — refusing would strand the claimed plan — but
        // the gap is reported.
        if let Err(e) = pool
            .with_store(|s| s.set_step_status(plan_id, step.seq, step_status::IN_PROGRESS, None))
        {
            pool.note_store_error("set_step_status", &e);
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
                if let Err(e) = pool
                    .with_store(|s| s.set_step_status(plan_id, step.seq, step_status::DONE, None))
                {
                    pool.note_store_error("set_step_status", &e);
                }
            }
            Err(e) => {
                out.failed += 1;
                error!(
                    target: "torrentd::pool::apply",
                    plan_id,
                    step = step.seq,
                    op = %step.op,
                    src = %step.src,
                    error.cause = %e,
                    "plan step failed",
                );
                pool.count("pool_plan_failures_total", &[("kind", "step_failed")]);
                if let Err(se) = pool.with_store(|s| {
                    s.set_step_status(plan_id, step.seq, step_status::FAILED, Some(&e))
                }) {
                    pool.note_store_error("set_step_status", &se);
                }
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
        target: "torrentd::pool::apply",
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
    // drafted. A rescan or a `POST /v1/pool/drift-check` between the two can turn a
    // relocatable torrent into an overlapping or drifted one, and the whole
    // point of those states is that moving the payload breaks something.
    recheck_relocatable(pool, &infohash, Path::new(&step.src))?;

    let hash = libtorrent_safe::InfoHash::from_hex(&infohash).ok_or("bad infohash")?;
    let Some(st) = state.get(&hash) else {
        // Not loaded: nothing is serving it, so torrentd can move the files
        // itself. This is the `matched but not adopted` case.
        return move_directory(Path::new(&step.src), Path::new(dst));
    };
    let engine = source
        .engine_for(&st.profile_id)
        .ok_or("no engine for the torrent's profile")?;

    // DontReplace: if something is already at the destination, adopt it in
    // place rather than overwriting. The planner already refused on a
    // pre-existing destination, so this is a second line of defence against a
    // race between planning and applying.
    state.update(&hash, |s| s.storage_move = Some(StorageMove::Pending));
    engine
        .move_storage(st.handle, dst, MoveFlags::DontReplace)
        .map_err(|e| e.to_string())?;

    info!(
        target: "torrentd::pool::apply",
        infohash = %infohash,
        dst = %dst,
        "move_storage requested; waiting for libtorrent's verdict",
    );

    // `move_storage` returns as soon as the move is queued. Treating that as
    // success reported a *failed* move as a completed plan step, and the
    // resume path then never retried it because the step said done.
    await_storage_move(state, &hash, dst)
}

/// How long to wait for `storage_moved_alert` before giving up on a verdict.
///
/// A move inside one filesystem is a rename and lands almost immediately;
/// across filesystems libtorrent copies, which is bounded by the payload size.
/// Timing out is not a failure — it means the verdict is still unknown, which
/// is reported as such rather than guessed either way.
const STORAGE_MOVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);
const STORAGE_MOVE_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Block until libtorrent reports the move done, failed, or the deadline runs
/// out.
fn await_storage_move(
    state: &StateMap,
    hash: &libtorrent_safe::InfoHash,
    dst: &str,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + STORAGE_MOVE_DEADLINE;
    loop {
        match state.get(hash).and_then(|s| s.storage_move) {
            Some(StorageMove::Moved { path }) => {
                info!(
                    target: "torrentd::pool::apply",
                    infohash = %hash,
                    save_path = %path,
                    "storage move confirmed",
                );
                return Ok(());
            }
            Some(StorageMove::Failed { message }) => {
                return Err(format!(
                    "libtorrent could not move the payload to {dst}: {message}"
                ));
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "libtorrent has not reported the move to {dst} after {}s; the torrent is \
                 still served from its old location and the step is left unfinished",
                STORAGE_MOVE_DEADLINE.as_secs(),
            ));
        }
        std::thread::sleep(STORAGE_MOVE_POLL);
    }
}

/// Move a directory tree torrentd owns outright.
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
    if let Err(e) = std::fs::copy(src, dst) {
        // A partial destination would make every retry fail on "destination
        // already exists", wedging the plan on its own debris. The source is
        // untouched, so removing the fragment is safe.
        let _ = std::fs::remove_file(dst);
        return Err(format!("copy {} → {}: {e}", src.display(), dst.display()));
    }
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
    // Fsync the destination *directory* too. Without it the file's data is on
    // disk but its directory entry may not be, so a crash after the unlink
    // below leaves neither copy reachable.
    if let Some(parent) = dst.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            d.sync_all()
                .map_err(|e| format!("fsync {}: {e}", parent.display()))?;
        }
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
/// 2. The index is a complete account of what is protected — checked once per
///    apply in [`apply`], since it is a property of the whole plan rather than
///    of one file.
/// 3. The file on disk is still the file that was indexed. A `(size, mtime,
///    inode)` match is the same evidence `drift` trusts; anything else means
///    the bytes changed after the scan decided they were expendable.
fn delete_file(pool: &PoolService, path: &Path) -> Result<(), String> {
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

    let md =
        std::fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if torrentd_pool::file_stamp(&md) != (row.size, row.mtime_ns, row.ino) {
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
/// Shares the planner's check, which follows the symlinks that exist rather
/// than comparing components lexically. The lexical form let a symlinked
/// directory inside a root carry a destination onto another volume while still
/// looking contained, and this is the last gate before `move_storage` or
/// `create_dir_all` acts on it.
fn under_a_managed_root(pool: &PoolService, path: &Path) -> bool {
    pool.roots()
        .iter()
        .any(|(_, root)| torrentd_pool::plan::contains(root, path))
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
            Some(AdoptionState::Overlap) | Some(AdoptionState::Shared) => {
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

        // `adopted` survives a rescan that finds another torrent over the
        // same files, so sharing is asked of the claim table directly.
        if store.shares_claims(infohash).map_err(|e| e.to_string())? {
            return Err(
                "another torrent now claims these files; moving them would break it".into(),
            );
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

/// [`resume_unfinished`] on the blocking pool, as boot runs it: `work` is
/// held by the blocking task for as long as the re-drive runs, so the
/// teardown waits for it, and its latch is the stop check between steps.
pub fn spawn_resume_unfinished(
    pool: Arc<PoolService>,
    source: Arc<dyn AlertSource>,
    state: Arc<StateMap>,
    work: Arc<crate::app_state::WorkGate>,
) -> tokio::task::JoinHandle<()> {
    let guard = work.enter();
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        resume_unfinished(&pool, &source, &state, &|| work.is_cancelled());
    })
}

/// Re-drive any plan a crash left mid-apply.
pub fn resume_unfinished(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    stop: StopCheck<'_>,
) {
    if !pool.allow_mutations() {
        // Mutations were turned off between the interrupted apply and this
        // boot. Re-driving anyway would destroy data the operator has since
        // said they do not want the daemon touching; leave the plan `applying`
        // so it is still visible and can be resumed deliberately.
        warn!(
            target: "torrentd::pool::apply",
            "pool mutations are disabled; not resuming interrupted plans",
        );
        return;
    }
    let unfinished = match pool.with_store(|s| s.unfinished_plans()) {
        Ok(p) => p,
        Err(e) => {
            warn!(target: "torrentd::pool::apply", reason = %e, "cannot read unfinished plans");
            pool.count("pool_plan_failures_total", &[("kind", "resume_failed")]);
            return;
        }
    };
    for plan in unfinished {
        warn!(
            target: "torrentd::pool::apply",
            plan_id = plan.id,
            kind = %plan.kind,
            "resuming a plan interrupted mid-apply",
        );
        // A plan that ran and stopped at a failed step has already counted
        // that; this counts the re-drive itself being refused or erroring.
        if stop() {
            return;
        }
        match apply_inner(pool, source, state, plan.id, true, stop) {
            Ok(_) => {}
            // A stop latched after the check above: the plan was stopped,
            // not failed, and stays `applying` for the next boot.
            Err(e) if e == SHUTTING_DOWN => {
                warn!(
                    target: "torrentd::pool::apply",
                    plan_id = plan.id,
                    "not resuming for shutdown; the plan resumes at the next boot",
                );
                return;
            }
            Err(e) => {
                error!(target: "torrentd::pool::apply", plan_id = plan.id, error.cause = %e, "resume failed");
                pool.count("pool_plan_failures_total", &[("kind", "resume_failed")]);
            }
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

    /// Build a `delete_orphans` plan over the whole root.
    fn delete_plan(pool: &PoolService) -> i64 {
        let root_id = pool.roots()[0].0;
        let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans {
            root_id,
            prefix: String::new(),
        };
        let steps = pool
            .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
            .unwrap()
            .expect("plan builds");
        let id = pool
            .with_store(|st| st.create_plan("delete_orphans", "{}", 0))
            .unwrap();
        pool.with_store_mut(|st| st.add_plan_steps(id, &steps))
            .unwrap();
        id
    }

    fn engine_and_state() -> (Arc<dyn AlertSource>, StateMap) {
        let engine: Arc<dyn torrentd_engine::TorrentEngine> =
            Arc::new(torrentd_engine::MockEngine::new());
        (
            Arc::new(torrentd_engine::ProfileSource::new(vec![(
                torrentd_engine::ProfileId::new("p"),
                engine,
            )])),
            StateMap::new(),
        )
    }

    #[test]
    fn applying_refuses_while_a_loaded_torrent_is_absent_from_the_index() {
        // The end-to-end shape of the hazard: a torrent the daemon serves that
        // the matcher has never placed contributes no claims, so its payload
        // enumerates as an orphan. Driven through `apply` so that deleting the
        // precondition from the executor fails this test.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let victim = write(&root, "movies/feature.bin", 64);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);

        let (source, state) = engine_and_state();
        // A torrent is loaded that the index has never seen.
        state.insert(
            libtorrent_safe::InfoHash([0xff; 20]),
            torrentd_engine::TorrentState::newly_added(
                torrentd_engine::TorrentHandle {
                    id: 1,
                    infohash: libtorrent_safe::InfoHash([0xff; 20]),
                },
                torrentd_engine::ProfileId::new("p"),
                std::time::Instant::now(),
            ),
        );

        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(e.contains("no claims in the index"), "got {e}");
        assert!(victim.exists(), "payload was deleted against a stale index");

        // And the refusal must not have bricked the plan: it was never
        // claimed, so it is still applicable once the index catches up.
        let status = pool
            .with_store(|st| st.plan(plan_id))
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, torrentd_pool::model::plan_status::DRAFT);
    }

    #[test]
    fn a_plan_interrupted_mid_step_can_still_be_resumed_and_discarded() {
        // A crash leaves a step `in_progress` and the plan `applying`. The
        // startup re-drive has to be able to claim it — with the claim
        // restricted to draft/failed it could not, and the plan was
        // unapplyable, unresumable and undeletable at the same time.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "movies/feature.bin", 64);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);

        // Simulate the crash: claimed, one step mid-flight.
        assert!(pool
            .with_store(|st| st.claim_plan_for_apply(plan_id, false))
            .unwrap());
        pool.with_store(|st| {
            st.set_step_status(
                plan_id,
                0,
                torrentd_pool::model::step_status::IN_PROGRESS,
                None,
            )
        })
        .unwrap();

        let (source, state) = engine_and_state();
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(
            e.contains("interrupted and its outcome is unknown"),
            "got {e}"
        );

        // Parked in `failed`, not stranded in `applying`: an operator can now
        // discard it, which `delete_plan` refuses for `applying`.
        let status = pool
            .with_store(|st| st.plan(plan_id))
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, torrentd_pool::model::plan_status::FAILED);
        pool.with_store_mut(|st| st.delete_plan(plan_id)).unwrap();
        assert!(pool.with_store(|st| st.plan(plan_id)).unwrap().is_none());
    }

    /// Status and per-step statuses of `plan_id`.
    fn plan_state(pool: &PoolService, plan_id: i64) -> (String, Vec<String>) {
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        (plan.status, steps.into_iter().map(|s| s.status).collect())
    }

    #[test]
    fn a_shutdown_during_an_apply_stops_between_steps_and_the_next_boot_finishes_it() {
        // SIGTERM mid-apply: the teardown used to run alongside the blocking
        // apply until `process::exit` killed it — inside a step as often as
        // not, which parks the plan `failed` for a human. Stopping between
        // steps leaves it `applying`, the state the next boot re-drives.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let a = write(&root, "a/one.bin", 16);
        let b = write(&root, "b/two.bin", 16);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let (_, steps) = plan_state(&pool, plan_id);
        assert_eq!(steps.len(), 2, "one delete per orphan");

        // The shutdown lands once the first step is done: asked before the
        // claim, before step 0, then before step 1.
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 2;
        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
        assert_eq!(out.done, 1);
        assert_eq!(out.status, plan_status::APPLYING);

        let (status, steps) = plan_state(&pool, plan_id);
        assert_eq!(status, plan_status::APPLYING, "left for the next boot");
        assert_eq!(steps, vec![step_status::DONE, step_status::PENDING]);
        assert_eq!(
            [a.exists(), b.exists()].iter().filter(|e| **e).count(),
            1,
            "exactly one step ran",
        );

        // Next boot.
        resume_unfinished(&pool, &source, &state, &|| false);
        let (status, steps) = plan_state(&pool, plan_id);
        assert_eq!(status, plan_status::APPLIED);
        assert_eq!(steps, vec![step_status::DONE, step_status::DONE]);
        assert!(!a.exists() && !b.exists());
    }

    #[test]
    fn an_apply_asked_for_during_a_shutdown_is_refused_unclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let a = write(&root, "a/one.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let (source, state) = engine_and_state();
        let e = apply(&pool, &source, &state, plan_id, &|| true).unwrap_err();
        assert!(e.contains("shutting down"), "got {e}");
        assert_eq!(plan_state(&pool, plan_id).0, plan_status::DRAFT);
        assert!(a.exists());
    }

    /// Hold the pool store's lock on another thread until the returned sender
    /// is sent to (or dropped), so work that needs the store blocks there.
    fn hold_the_store(
        pool: &Arc<PoolService>,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let held = Arc::clone(pool);
        let holder = std::thread::spawn(move || {
            held.with_store(|_| {
                locked_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
        });
        locked_rx.recv().unwrap();
        (release_tx, holder)
    }

    #[tokio::test]
    async fn the_boot_redrive_holds_the_work_gate_until_it_finishes() {
        // The teardown waits on the gate before it stops the alert loop and
        // closes the sessions a re-driven move goes through. A re-drive that
        // did not hold it would be torn down around mid-step.
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "a/one.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let (source, state) = engine_and_state();
        let work: Arc<crate::app_state::WorkGate> = Arc::default();

        // The re-drive's first act is reading the store, so it blocks here.
        let (release, holder) = hold_the_store(&pool);
        let task = spawn_resume_unfinished(
            Arc::clone(&pool),
            source,
            Arc::new(state),
            Arc::clone(&work),
        );
        assert!(
            !work.wait_idle(Duration::from_millis(200)).await,
            "the teardown saw no work while the re-drive was running",
        );
        assert_eq!(work.in_flight(), 1);

        release.send(()).unwrap();
        holder.join().unwrap();
        task.await.unwrap();
        assert_eq!(work.in_flight(), 0, "released once the re-drive is done");
    }

    #[tokio::test]
    async fn the_boot_redrive_stops_on_the_work_gates_latch() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "a/one.bin", 16);
        write(&root, "b/two.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let (source, state) = engine_and_state();

        // Left `applying` with nothing done, as a shutdown right after the
        // claim leaves it.
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1;
        apply(&pool, &source, &state, plan_id, &stop).unwrap();
        let state = Arc::new(state);

        let work: Arc<crate::app_state::WorkGate> = Arc::default();
        work.cancel();
        spawn_resume_unfinished(
            Arc::clone(&pool),
            Arc::clone(&source),
            Arc::clone(&state),
            Arc::clone(&work),
        )
        .await
        .unwrap();
        let (status, steps) = plan_state(&pool, plan_id);
        assert_eq!(status, plan_status::APPLYING, "a latched gate stops it");
        assert_eq!(steps, vec![step_status::PENDING, step_status::PENDING]);

        spawn_resume_unfinished(Arc::clone(&pool), source, state, Arc::default())
            .await
            .unwrap();
        assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLIED);
    }

    #[test]
    fn a_stop_latched_inside_the_redrive_is_not_counted_as_a_failure() {
        // The re-drive checks the stop, then `apply_inner` checks it again
        // before its claim. A shutdown landing between the two used to come
        // back as an error and count as `resume_failed`.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "a/one.bin", 16);
        write(&root, "b/two.bin", 16);
        let pool = service(dir.path(), true);
        let metrics = Arc::new(crate::metrics_sink::PromSink::new());
        pool.set_metrics(metrics.clone());
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let (source, state) = engine_and_state();
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1;
        apply(&pool, &source, &state, plan_id, &stop).unwrap();
        assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);

        // Clear for the re-drive's own check, latched for `apply_inner`'s.
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let stop = || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1;
        resume_unfinished(&pool, &source, &state, &stop);

        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 2);
        let (status, steps) = plan_state(&pool, plan_id);
        assert_eq!(
            status,
            plan_status::APPLYING,
            "a stopped plan is left for the next boot"
        );
        assert_eq!(steps, vec![step_status::PENDING, step_status::PENDING]);
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(!text.contains("kind=\"resume_failed\"} 1"), "{text}");
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
