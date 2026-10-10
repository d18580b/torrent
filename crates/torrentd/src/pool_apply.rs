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
//!   files underneath a seeding torrent does not. The step succeeds only once
//!   libtorrent reports the move done and none of the torrent's files is left
//!   at the source; across devices that move is libtorrent's own copy, which
//!   torrentd does not verify.
//! * **torrentd never moves a directory across devices itself.** An
//!   unadopted directory is moved with a `rename`, and an `EXDEV` refuses the
//!   step rather than copying, so the payload is never half in two places
//!   because of a move torrentd made.

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
    let mut guards = DeleteGuards::default();

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
            ops::DELETE_FILE => delete_file(pool, Path::new(&step.src), plan_id, &mut guards)
                .map_err(StepFailure::Failed),
            other => Err(StepFailure::Failed(format!(
                "unknown plan operation {other:?}"
            ))),
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
            Err(StepFailure::Unknown(e)) => {
                // Not `failed`: the move may yet land. The step stays
                // `in_progress` — the journal's own word for "started, verdict
                // unknown" — so neither a resume nor a retry re-runs it, and
                // the plan is parked for a human, who can see where the
                // payload is before deciding.
                out.failed += 1;
                error!(
                    target: "torrentd::pool::apply",
                    plan_id,
                    step = step.seq,
                    op = %step.op,
                    src = %step.src,
                    error.cause = %e,
                    "plan step outcome unknown",
                );
                pool.count("pool_plan_failures_total", &[("kind", "step_failed")]);
                if let Err(se) = pool.with_store(|s| {
                    s.set_step_status(plan_id, step.seq, step_status::IN_PROGRESS, Some(&e))
                }) {
                    pool.note_store_error("set_step_status", &se);
                }
                out.status = plan_status::FAILED.to_string();
                break;
            }
            Err(StepFailure::Failed(e)) => {
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

/// How a step did not succeed.
enum StepFailure {
    /// It did not happen, or was undone; the journal says `failed`.
    Failed(String),
    /// It was started and its verdict is not known — a storage move libtorrent
    /// has not reported on by the deadline. Recording that as `failed` invited
    /// a retry of a move that may still land.
    Unknown(String),
}

impl From<String> for StepFailure {
    fn from(e: String) -> Self {
        StepFailure::Failed(e)
    }
}

impl From<&str> for StepFailure {
    fn from(e: &str) -> Self {
        StepFailure::Failed(e.to_owned())
    }
}

/// Relocate an adopted torrent by asking libtorrent to move its storage.
fn move_torrent(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    step: &PlanStepRow,
) -> Result<(), StepFailure> {
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
        return Err(format!("destination {dst} is outside every managed root").into());
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
        move_directory(Path::new(&step.src), Path::new(dst))?;
        record_new_base(pool, &infohash, Path::new(dst));
        return Ok(());
    };
    let engine = source
        .engine_for(&st.profile_id)
        .ok_or("no engine for the torrent's profile")?;

    // The planner's destination check, re-run now. A file of this torrent
    // that landed at the destination after the plan was built is one
    // `DontReplace` would skip without a word: libtorrent leaves the source
    // copy behind, reports the move done, and rechecks against the file it
    // found, so the payload ends up split between the two places.
    if let Some(rel) = pool
        .with_store(|s| {
            torrentd_pool::plan::existing_destination_file(s, &infohash, Path::new(dst))
        })
        .map_err(|e| e.to_string())?
    {
        return Err(format!(
            "destination {dst} now already contains {rel}; refusing to move onto it"
        )
        .into());
    }

    // DontReplace stays as the last line against a file that lands between
    // the check above and libtorrent's own; a skip it makes is caught after
    // the move by `left_behind`.
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
    let moved_to = await_storage_move(state, &hash, dst)?;
    record_new_base(pool, &infohash, Path::new(&moved_to));
    // The save path recorded beside the `.torrent` is where the boot scan
    // re-adds a torrent whose resume file is lost; it follows the payload.
    pool.record_save_path(&st.profile_id, &infohash, &moved_to);
    // libtorrent serves from the new path either way, so the base and save
    // path above follow it; but a file it skipped is still at the source and
    // the step is not the move the plan asked for.
    left_behind(pool, &infohash, Path::new(&step.src), dst)
}

/// Whether a storage move libtorrent reported done left any of the torrent's
/// files at the source.
///
/// `storage_moved_alert` is posted for a `need_full_check` outcome exactly as
/// for a clean one, and under `DontReplace` that outcome means a destination
/// file already existed: libtorrent skipped it, left the source copy where it
/// was, and started a recheck against the file it found. The only trace is
/// the source file still being there. That is recorded as an unknown outcome,
/// not done and not failed: the step must not be retried over a payload now
/// split between two places, and a human has to decide which copy is right.
fn left_behind(
    pool: &PoolService,
    infohash: &str,
    src: &Path,
    dst: &str,
) -> Result<(), StepFailure> {
    // The move has happened by now, so not being able to look is not a
    // failure either: `failed` would invite a retry of a move that landed.
    let files = pool
        .with_store(|s| s.torrent_files(infohash))
        .map_err(|e| {
            StepFailure::Unknown(format!(
                "outcome unknown: libtorrent moved the torrent to {dst}, but its file list \
                 could not be read to confirm nothing was left at {}: {e}",
                src.display(),
            ))
        })?;
    let Some(rel) = files.into_iter().find_map(|f| {
        let still = f.is_on_disk() && src.join(&f.rel_path).symlink_metadata().is_ok();
        still.then_some(f.rel_path)
    }) else {
        return Ok(());
    };
    Err(StepFailure::Unknown(format!(
        "outcome unknown: libtorrent moved the torrent to {dst} but left {rel} at {}, \
         most likely because a file of that name was already at the destination. The \
         payload is split between the two places and libtorrent is rechecking against \
         the destination; reconcile them before resuming or discarding this plan",
        src.display(),
    )))
}

/// Point the torrent's adoption at where its payload now is.
///
/// The adoption base is what `save_path_of`, a later relocate, drift and
/// `torrent_at` all resolve against, and left at the old directory every one
/// of them looked where the payload no longer is until the next rescan. The
/// claims and the file index still describe the old paths; the rescan that
/// follows a relocate rebuilds both.
fn record_new_base(pool: &PoolService, infohash: &str, dir: &Path) {
    let Some((root_id, rel)) = pool.roots().iter().find_map(|(id, root)| {
        dir.strip_prefix(root)
            .ok()
            .map(|r| (*id, r.to_string_lossy().replace('\\', "/")))
    }) else {
        warn!(
            target: "torrentd::pool::apply",
            infohash,
            dir = %dir.display(),
            "the payload moved outside every managed root; its adoption base is unchanged",
        );
        return;
    };
    let written = pool.with_store(|s| {
        let Some(state) = s.adoption_state(infohash)? else {
            return Ok(());
        };
        let drift_at = s.drift_at(infohash)?;
        s.set_adoption(
            infohash,
            state,
            Some(root_id),
            Some(rel.trim_matches('/')),
            None,
            drift_at,
            None,
        )
    });
    if let Err(e) = written {
        pool.note_store_error("set_adoption", &e);
    }
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
/// out. `Ok` carries the save path libtorrent reported.
fn await_storage_move(
    state: &StateMap,
    hash: &libtorrent_safe::InfoHash,
    dst: &str,
) -> Result<String, StepFailure> {
    await_storage_move_within(state, hash, dst, STORAGE_MOVE_DEADLINE)
}

fn await_storage_move_within(
    state: &StateMap,
    hash: &libtorrent_safe::InfoHash,
    dst: &str,
    within: std::time::Duration,
) -> Result<String, StepFailure> {
    let deadline = std::time::Instant::now() + within;
    loop {
        match state.get(hash).and_then(|s| s.storage_move) {
            Some(StorageMove::Moved { path }) => {
                info!(
                    target: "torrentd::pool::apply",
                    infohash = %hash,
                    save_path = %path,
                    "storage move confirmed",
                );
                return Ok(path);
            }
            Some(StorageMove::Failed { message }) => {
                return Err(StepFailure::Failed(format!(
                    "libtorrent could not move the payload to {dst}: {message}"
                )));
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(StepFailure::Unknown(format!(
                "outcome unknown: libtorrent has not reported the move to {dst} after {}s. \
                 It may still be copying; check where the payload is before resuming or \
                 discarding this plan",
                within.as_secs(),
            )));
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
        Ok(()) => sync_parents(&[src, dst]),
        Err(e) if e.raw_os_error() == Some(libc_exdev()) => Err(format!(
            "cross-device directory move is not attempted automatically \
                 ({} → {}); move the data and rescan",
            src.display(),
            dst.display(),
        )),
        Err(e) => Err(format!("rename {} → {}: {e}", src.display(), dst.display())),
    }
}

/// Fsync the directory holding each path, so a rename or unlink in it
/// survives a crash rather than leaving the journal describing a directory
/// entry the disk never recorded.
fn sync_parents(paths: &[&Path]) -> Result<(), String> {
    let mut done: Vec<&Path> = Vec::new();
    for p in paths {
        let Some(parent) = p.parent() else { continue };
        if done.contains(&parent) {
            continue;
        }
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("fsync {}: {e}", parent.display()))?;
        done.push(parent);
    }
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
///    inode, device)` match is the same evidence `drift` trusts; anything
///    else means the bytes changed after the scan decided they were
///    expendable.
/// 4. No torrent the index *now* holds as partial, missing or overlapping
///    expects its payload where the file is, or is missing a file of its
///    size — the planner's guards ([`torrentd_pool::plan::DeleteGuard`]),
///    re-read whenever the index generation moves, since a rescan after the
///    plan was built can make a torrent partial over these very files.
///
/// The path is walked from the root one directory at a time with
/// `O_NOFOLLOW`, so a directory swapped for a symlink after planning stops the
/// step instead of carrying it onto another volume, and the file is examined
/// and moved through that parent's descriptor rather than by name from `/`.
/// It is moved — `renameat2(RENAME_NOREPLACE)` — into
/// `<root>/.torrentd-trash/<plan id>/`, never unlinked, and both directories
/// are fsynced so the move survives a crash.
fn delete_file(
    pool: &PoolService,
    path: &Path,
    plan_id: i64,
    guards: &mut DeleteGuards,
) -> Result<(), String> {
    let Some((root_id, root, rel)) = pool.roots().iter().find_map(|(id, root)| {
        path.strip_prefix(root)
            .ok()
            .map(|r| (*id, root.clone(), r.to_string_lossy().replace('\\', "/")))
    }) else {
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

    let stamp = (row.size, row.mtime_ns, row.ino, row.dev);
    move_into_trash(&root, path, &rel, stamp, &plan_id.to_string())?;
    info!(
        target: "torrentd::pool::apply",
        plan_id,
        path = %path.display(),
        "moved to the trash",
    );
    Ok(())
}

/// Move the file at `rel` under `root` (`path` is the two joined, for
/// messages) into `<root>/.torrentd-trash/<bucket>/`, keeping its
/// root-relative directories, once its `(size, mtime, inode, device)` is
/// still `stamp` — the scan's record of it.
///
/// The path is walked from the root one directory at a time with
/// `O_NOFOLLOW`, the file is examined and moved through its parent's
/// descriptor, the move is `renameat2(RENAME_NOREPLACE)`, and both
/// directories are fsynced so it survives a crash.
fn move_into_trash(
    root: &Path,
    path: &Path,
    rel: &str,
    stamp: (u64, i64, u64, u64),
    bucket: &str,
) -> Result<(), String> {
    let (dirs, name) = match rel.rsplit_once('/') {
        Some((d, n)) => (d.split('/').collect::<Vec<_>>(), n),
        None => (Vec::new(), rel),
    };
    let root_dir =
        std::fs::File::open(root).map_err(|e| format!("open {}: {e}", root.display()))?;
    let parent = fsat::walk(&root_dir, &dirs, false)
        .map_err(|e| format!("{}: {e}; refusing to follow it", path.display()))?;
    let parent = parent.as_ref().unwrap_or(&root_dir);

    let md =
        fsat::stat_nofollow(parent, name).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if torrentd_pool::file_stamp(&md) != stamp {
        return Err(format!(
            "{} changed since the scan that indexed it; rescan before deleting",
            path.display(),
        ));
    }

    let mut trash_dirs = vec![torrentd_pool::plan::TRASH_DIR, bucket];
    trash_dirs.extend(dirs.iter().copied());
    let trash = fsat::walk(&root_dir, &trash_dirs, true)
        .map_err(|e| format!("trash for {}: {e}", path.display()))?
        .expect("a non-empty walk yields a directory");
    fsat::rename_noreplace(parent, name, &trash, name).map_err(|e| {
        format!(
            "move {} into {}/{bucket}: {e}",
            path.display(),
            torrentd_pool::plan::TRASH_DIR,
        )
    })?;
    // Both directory entries changed; without these the rename can be lost
    // to a crash and the file reappear where the journal says it is gone.
    fsat::fsync(parent).map_err(|e| format!("fsync {}: {e}", path.display()))?;
    fsat::fsync(&trash).map_err(|e| format!("fsync trash: {e}"))?;
    Ok(())
}

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
    stamp: (u64, i64, u64, u64),
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
    /// sessions spell it and resolved, so a `save_path` reaching the same
    /// directory through a symlink is still caught. A torrent whose metadata
    /// has not arrived yet could write any file under its `save_path`, so
    /// every payload file under it counts as shared.
    pub fn shared_with(&self, other: &LiveTorrent) -> Option<&std::path::Path> {
        let bases: Vec<std::path::PathBuf> = std::iter::once(other.save_path.clone())
            .chain(std::fs::canonicalize(&other.save_path).ok())
            .collect();
        fn forms(f: &PayloadFile) -> impl Iterator<Item = &std::path::PathBuf> {
            std::iter::once(&f.path).chain(f.resolved.as_ref())
        }
        let hit: Box<dyn Fn(&PayloadFile) -> bool> = match &other.files {
            None => Box::new(|f| forms(f).any(|p| bases.iter().any(|b| p.starts_with(b)))),
            Some(files) => {
                let theirs: std::collections::HashSet<std::path::PathBuf> = files
                    .iter()
                    .flat_map(|rel| bases.iter().map(move |b| b.join(rel)))
                    .collect();
                Box::new(move |f| forms(f).any(|p| theirs.contains(p)))
            }
        };
        self.files.iter().find(|f| hit(f)).map(|f| f.path.as_path())
    }
}

/// Another torrent a session holds, as [`TorrentPayload::shared_with`]
/// compares it: where its session says its payload lies.
#[derive(Debug)]
pub struct LiveTorrent {
    /// The session's save path for it.
    pub save_path: std::path::PathBuf,
    /// Its files, torrent-relative and `/`-separated, or `None` while its
    /// metadata has not arrived.
    pub files: Option<Vec<String>>,
}

/// What [`trash_torrent_payload`] did.
#[derive(Debug)]
pub struct TrashOutcome {
    /// Where the files went: `<root>/.torrentd-trash/<bucket>/` under each
    /// root the payload spans.
    pub trash: Vec<std::path::PathBuf>,
    /// How many files were moved.
    pub moved: usize,
    /// The first file that could not be moved, and why. The move stops
    /// there, so it and every file after it are still in place.
    pub failed: Option<(std::path::PathBuf, String)>,
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
///    and a torrent the matcher has not placed contributes neither;
/// 3. still be the file the index recorded: the same `(size, mtime, inode,
///    device)`, checked here and again at the move.
///
/// A listed file that is on neither the disk nor the index was never
/// written, and is skipped. Nothing is changed on any outcome.
pub fn torrent_payload(
    pool: &PoolService,
    infohash: &str,
    save_path: &Path,
    files: &[String],
) -> Result<TorrentPayload, String> {
    let claims: std::collections::HashSet<(i64, String)> = pool
        .with_store(|s| s.claims_of(infohash))
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect();
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        let path = save_path.join(file);
        let Some((root_id, root, rel)) = pool.roots().iter().find_map(|(id, root)| {
            path.strip_prefix(root)
                .ok()
                .map(|r| (*id, root.clone(), r.to_string_lossy().replace('\\', "/")))
        }) else {
            return Err(format!(
                "{} is outside every managed root, so there is no trash to move it to",
                path.display(),
            ));
        };
        if !torrentd_pool::plan::contains(&root, &path) {
            return Err(format!(
                "{} is outside every managed root, so there is no trash to move it to",
                path.display(),
            ));
        }
        let on_disk = match std::fs::symlink_metadata(&path) {
            Ok(md) => Some(md),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("stat {}: {e}", path.display())),
        };
        let row = pool
            .with_store(|s| s.file(root_id, &rel))
            .map_err(|e| e.to_string())?;
        let (md, row) = match (on_disk, row) {
            (None, None) => continue,
            (Some(md), Some(row)) => (md, row),
            (None, Some(_)) => {
                return Err(format!(
                    "{} is in the index but not on disk; rescan before deleting",
                    path.display(),
                ))
            }
            (Some(_), None) => {
                return Err(format!(
                    "{} is not in the index; rescan before deleting",
                    path.display(),
                ))
            }
        };
        if !claims.contains(&(root_id, rel.clone())) {
            return Err(format!(
                "the index does not record this torrent claiming {}; rescan before deleting",
                path.display(),
            ));
        }
        if !md.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let stamp = (row.size, row.mtime_ns, row.ino, row.dev);
        if torrentd_pool::file_stamp(&md) != stamp {
            return Err(format!(
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
        });
    }
    Ok(TorrentPayload {
        infohash: infohash.to_owned(),
        files: out,
    })
}

/// Move `payload` into `<root>/.torrentd-trash/<bucket>/`, each file
/// re-stat'd against the index at the moment it moves. Stops at the first
/// file that cannot be moved, and leaves it and the rest in place: nothing
/// is ever unlinked.
pub fn trash_torrent_payload(payload: &TorrentPayload, bucket: &str) -> TrashOutcome {
    let mut out = TrashOutcome {
        trash: Vec::new(),
        moved: 0,
        failed: None,
    };
    for f in &payload.files {
        if let Err(e) = move_into_trash(&f.root, &f.path, &f.rel, f.stamp, bucket) {
            out.failed = Some((f.path.clone(), e));
            break;
        }
        let trash = f.root.join(torrentd_pool::plan::TRASH_DIR).join(bucket);
        if !out.trash.contains(&trash) {
            out.trash.push(trash);
        }
        out.moved += 1;
        info!(
            target: "torrentd::pool::apply",
            infohash = %payload.infohash,
            path = %f.path.display(),
            "moved a deleted torrent's file to the trash",
        );
    }
    out
}

/// The planner's unresolved-payload guards, per root, as of one index
/// generation. Read on first use and again whenever a rescan moves the
/// generation, so a delete plan over many files reads them once per root
/// rather than once per file.
#[derive(Default)]
struct DeleteGuards {
    generation: Option<i64>,
    by_root: std::collections::HashMap<i64, torrentd_pool::plan::DeleteGuard>,
}

impl DeleteGuards {
    fn refusal(
        &mut self,
        pool: &PoolService,
        root_id: i64,
        root: &Path,
        rel: &str,
        size: u64,
    ) -> Result<Option<String>, String> {
        let generation = pool
            .with_store(|s| s.index_generation())
            .map_err(|e| e.to_string())?;
        if self.generation != Some(generation) {
            self.by_root.clear();
            self.generation = Some(generation);
        }
        if let std::collections::hash_map::Entry::Vacant(e) = self.by_root.entry(root_id) {
            let guard = pool
                .with_store(|s| torrentd_pool::plan::DeleteGuard::load(s, root_id, root))
                .map_err(|e| e.to_string())?;
            e.insert(guard);
        }
        Ok(self.by_root[&root_id].refusal(rel, size))
    }
}

/// Directory-relative filesystem calls the delete step is made of.
mod fsat {
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;

    fn cname(name: &str) -> io::Result<CString> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name:?} is not a single path component"),
            ));
        }
        CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    /// Open `components` one directory at a time beneath `start`, each with
    /// `O_NOFOLLOW`: a symlink anywhere on the way is `ELOOP`, never followed.
    /// With `create`, a missing directory is made (`0700`) first. `None` for
    /// an empty walk, which is `start` itself.
    pub fn walk(start: &File, components: &[&str], create: bool) -> io::Result<Option<File>> {
        let mut cur: Option<File> = None;
        for c in components {
            let name = cname(c)?;
            let dirfd = cur.as_ref().unwrap_or(start).as_raw_fd();
            if create {
                // SAFETY: a valid directory fd and a NUL-terminated name.
                let rc = unsafe { libc::mkdirat(dirfd, name.as_ptr(), 0o700) };
                if rc != 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::EEXIST) {
                        return Err(e);
                    }
                }
            }
            // SAFETY: as above; the returned fd is owned by the `File`.
            let fd = unsafe {
                libc::openat(
                    dirfd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            cur = Some(unsafe { File::from_raw_fd(fd) });
        }
        Ok(cur)
    }

    /// The metadata of `name` in `dir`, without following a symlink there.
    pub fn stat_nofollow(dir: &File, name: &str) -> io::Result<std::fs::Metadata> {
        let name = cname(name)?;
        // SAFETY: `O_PATH | O_NOFOLLOW` opens the entry itself, symlink or
        // not, for `fstat` only; the fd is owned by the `File`.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe { File::from_raw_fd(fd) }.metadata()
    }

    /// `renameat2(RENAME_NOREPLACE)`: refuses rather than overwrites.
    pub fn rename_noreplace(from: &File, a: &str, to: &File, b: &str) -> io::Result<()> {
        let (a, b) = (cname(a)?, cname(b)?);
        // SAFETY: valid directory fds and NUL-terminated names.
        let rc = unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                a.as_ptr(),
                to.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn fsync(dir: &File) -> io::Result<()> {
        dir.sync_all()
    }
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
///
/// `loaded` is every info-hash the boot handed to a session. The re-drive
/// waits until each is in the state map: a session holds a torrent from the
/// moment it is added, but the state map learns of it only when its
/// `add_torrent_alert` is processed, and until then the re-drive would read
/// a loaded torrent as unloaded — a delete would find the index accounting
/// for everything "loaded", and a relocate would rename the directory a
/// session is serving instead of asking libtorrent to move it.
pub fn spawn_resume_unfinished(
    pool: Arc<PoolService>,
    source: Arc<dyn AlertSource>,
    state: Arc<StateMap>,
    work: Arc<crate::app_state::WorkGate>,
    loaded: Vec<libtorrent_safe::InfoHash>,
) -> tokio::task::JoinHandle<()> {
    let guard = work.enter();
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let stop = || work.is_cancelled();
        let unfinished = pool
            .with_store(|s| s.unfinished_plans())
            .map(|p| !p.is_empty())
            .unwrap_or(true);
        if unfinished && !await_loaded(&state, &loaded, REDRIVE_SETTLE_DEADLINE, &stop) {
            if !stop() {
                warn!(
                    target: "torrentd::pool::apply",
                    "not every torrent the boot loaded reached the state map in time; \
                     interrupted plans are left applying for the next boot",
                );
            }
            return;
        }
        resume_unfinished(&pool, &source, &state, &stop);
    })
}

/// How long the boot re-drive waits for the loaded torrents to appear.
const REDRIVE_SETTLE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);

/// Wait until every one of `loaded` is in `state`. `false` on the deadline
/// or a stop.
fn await_loaded(
    state: &StateMap,
    loaded: &[libtorrent_safe::InfoHash],
    within: std::time::Duration,
    stop: StopCheck<'_>,
) -> bool {
    let deadline = std::time::Instant::now() + within;
    let mut pending: Vec<_> = loaded.to_vec();
    loop {
        pending.retain(|ih| !state.contains(ih));
        if pending.is_empty() {
            return true;
        }
        if stop() || std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
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

    /// Index a torrent straight into the pool and re-match, as a rescan that
    /// found a new `.torrent` in the library would.
    fn add_and_rematch(
        pool: &PoolService,
        ih: &str,
        name: &str,
        save_path: Option<&Path>,
        files: &[(&str, u64)],
    ) {
        pool.with_store_mut(|st| {
            st.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: ih.to_owned(),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: name.to_owned(),
                    total_size: files.iter().map(|(_, s)| s).sum(),
                    num_files: files.len(),
                    source_path: format!("/library/{ih}.torrent").into(),
                    fastresume_path: None,
                    declared_save_path: save_path.map(|p| p.to_string_lossy().into_owned()),
                    category: None,
                    tags: vec![],
                    profile: None,
                },
                0,
            )
            .unwrap();
            let rows: Vec<_> = files
                .iter()
                .enumerate()
                .map(|(i, (p, s))| torrentd_pool::model::TorrentFileRow {
                    infohash: ih.to_owned(),
                    idx: i as i64,
                    rel_path: (*p).to_owned(),
                    size: *s,
                    pieces_root: None,
                    pad_file: false,
                })
                .collect();
            st.replace_torrent_files(ih, &rows).unwrap();
            torrentd_pool::match_all(st).unwrap();
        });
    }

    /// The planner's unresolved-payload guards hold at apply time too. A
    /// rescan between building and applying that leaves a torrent partial
    /// over the plan's files, or missing a file of one's size, stops those
    /// steps: an operator re-reading the changed confirm token still applies
    /// the same steps.
    #[test]
    fn applying_re_runs_the_unresolved_payload_guards() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        // Ordered first under `junk`, so it is the step the guard meets.
        let near = write(&root, "junk/T/0.nfo", 7);
        write(&root, "junk/T/a.bin", 100);
        let lookalike = write(&root, "loose/maybe.mkv", 4321);
        write(&root, "loose/really-junk.txt", 9);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let under_junk = delete_plan_under(&pool, "junk");
        let under_loose = delete_plan_under(&pool, "loose");

        // T is placed under `junk/` with `b.bin` not found: partial, and
        // expecting its payload under `junk/T`. M is missing a 4321-byte file.
        add_and_rematch(
            &pool,
            "aa",
            "T",
            Some(&root.join("junk")),
            &[("T/a.bin", 100), ("T/b.bin", 300)],
        );
        add_and_rematch(&pool, "bb", "M", None, &[("M/film.mkv", 4321)]);
        assert_eq!(
            pool.with_store(|st| st.adoption_state("aa")).unwrap(),
            Some(AdoptionState::Partial),
        );

        let (source, state) = engine_and_state();
        for (plan_id, file, expect) in [
            (under_junk, &near, "torrent aa"),
            (under_loose, &lookalike, "size"),
        ] {
            let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
            assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
            assert!(file.exists());
            let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
            assert_eq!(Path::new(&steps[0].src), file.as_path());
            let why = steps[0].error.clone().unwrap_or_default();
            assert!(why.contains(expect), "{why}");
        }
    }

    /// Build a `delete_orphans` plan under `prefix`.
    fn delete_plan_under(pool: &PoolService, prefix: &str) -> i64 {
        let root_id = pool.roots()[0].0;
        let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans {
            root_id,
            prefix: prefix.to_owned(),
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
            Vec::new(),
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
            Vec::new(),
        )
        .await
        .unwrap();
        let (status, steps) = plan_state(&pool, plan_id);
        assert_eq!(status, plan_status::APPLYING, "a latched gate stops it");
        assert_eq!(steps, vec![step_status::PENDING, step_status::PENDING]);

        spawn_resume_unfinished(Arc::clone(&pool), source, state, Arc::default(), Vec::new())
            .await
            .unwrap();
        assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLIED);
    }

    #[tokio::test]
    async fn the_boot_redrive_waits_for_every_loaded_torrent_to_reach_the_state_map() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "a/one.bin", 16);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let (source, state) = engine_and_state();
        // Claimed and left applying, as a crash right after the claim leaves it.
        pool.with_store(|s| s.claim_plan_for_apply(plan_id, false))
            .unwrap();
        let state = Arc::new(state);

        // A torrent the boot handed to a session whose add alert is not in.
        let pending = libtorrent_safe::InfoHash([9; 20]);
        let work: Arc<crate::app_state::WorkGate> = Arc::default();
        let task = spawn_resume_unfinished(
            Arc::clone(&pool),
            Arc::clone(&source),
            Arc::clone(&state),
            Arc::clone(&work),
            vec![pending],
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            plan_state(&pool, plan_id).0,
            plan_status::APPLYING,
            "nothing is re-driven while a loaded torrent is missing from the state map",
        );
        // Shut down: it gives up without touching the plan.
        work.cancel();
        task.await.unwrap();
        assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);

        assert!(await_loaded(
            &state,
            &[],
            std::time::Duration::ZERO,
            &|| false
        ));
        assert!(!await_loaded(
            &state,
            &[pending],
            std::time::Duration::ZERO,
            &|| false
        ));
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

        let e = delete_file(&pool, &f, 1, &mut Default::default()).unwrap_err();
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
        let e = delete_file(&pool, &sneaked, 1, &mut Default::default()).unwrap_err();
        assert!(e.contains("never sanctioned"), "got {e}");
        assert!(sneaked.exists());

        let outside = dir.path().join("elsewhere.bin");
        std::fs::write(&outside, b"x").unwrap();
        let e = delete_file(&pool, &outside, 1, &mut Default::default()).unwrap_err();
        assert!(e.contains("outside every managed root"), "got {e}");
        assert!(outside.exists());

        // A traversal component walks back out of the root once resolved.
        let escaping = root.join("misc/../../elsewhere.bin");
        let e = delete_file(&pool, &escaping, 1, &mut Default::default()).unwrap_err();
        assert!(e.contains("outside every managed root"), "got {e}");
        assert!(outside.exists());
    }

    /// A file of the torrent that lands at the destination between planning
    /// and applying refuses the step before libtorrent is asked to move
    /// anything: `DontReplace` would skip it silently and split the payload.
    #[test]
    fn a_destination_file_that_appears_after_planning_refuses_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let src_file = write(&root, "old/T/a.bin", 100);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        add_and_rematch(
            &pool,
            &ih,
            "T",
            Some(&root.join("old")),
            &[("T/a.bin", 100)],
        );
        let root_id = pool.roots()[0].0;
        let spec = torrentd_pool::plan::PlanSpec::Relocate {
            infohash: ih.clone(),
            dest_root_id: root_id,
            dest_rel: "new".into(),
        };
        let steps = pool
            .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
            .unwrap()
            .expect("plan builds");
        let plan_id = pool
            .with_store(|st| st.create_plan("relocate", "{}", 0))
            .unwrap();
        pool.with_store_mut(|st| st.add_plan_steps(plan_id, &steps))
            .unwrap();

        // Someone else's copy arrives at the destination after the plan.
        let foreign = write(&root, "new/T/a.bin", 100);

        let mock = Arc::new(torrentd_engine::MockEngine::new());
        // Without the re-check, the step reaches `move_storage`; failing it
        // there makes that a quick wrong answer rather than a ten-minute wait
        // for an alert the mock never delivers.
        mock.inject_error("move_storage", torrentd_engine::EngineError::Shutdown);
        let engine: Arc<dyn torrentd_engine::TorrentEngine> = mock.clone();
        let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            torrentd_engine::ProfileId::new("p"),
            engine,
        )]));
        let state = StateMap::new();
        let hash = libtorrent_safe::InfoHash::from_hex(&ih).unwrap();
        state.insert(
            hash,
            torrentd_engine::TorrentState::newly_added(
                torrentd_engine::TorrentHandle {
                    id: 1,
                    infohash: hash,
                },
                torrentd_engine::ProfileId::new("p"),
                std::time::Instant::now(),
            ),
        );

        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(steps[0].status, step_status::FAILED);
        let why = steps[0].error.clone().unwrap_or_default();
        assert!(why.contains("already contains T/a.bin"), "{why}");
        assert!(
            !mock
                .calls()
                .iter()
                .any(|c| matches!(c, torrentd_engine::RecordedCall::MoveStorage { .. })),
            "move_storage was called: {:?}",
            mock.calls(),
        );
        assert!(src_file.exists() && foreign.exists());
    }

    /// A move libtorrent reported done that left a file at the source is the
    /// trace of a `DontReplace` skip, and is recorded unknown rather than done.
    #[test]
    fn a_file_left_at_the_source_after_a_move_is_an_unknown_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let pool = service(dir.path(), true);
        let ih = "cd".repeat(20);
        add_and_rematch(&pool, &ih, "T", None, &[("T/a.bin", 100), ("T/b.bin", 5)]);
        let src = root.join("old");

        left_behind(&pool, &ih, &src, "/dst").unwrap_or_else(|_| panic!("nothing was left"));

        let stray = write(&src, "T/b.bin", 5);
        match left_behind(&pool, &ih, &src, "/dst") {
            Err(StepFailure::Unknown(e)) => assert!(e.contains("left T/b.bin"), "{e}"),
            Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
            Ok(()) => panic!("a skipped file was recorded as moved"),
        }
        assert!(stray.exists());
    }

    /// The move has already happened when `left_behind` looks, so a file list
    /// it cannot read is an unknown outcome too, never `failed`: a retry would
    /// move a payload that already moved.
    #[test]
    fn an_unreadable_file_list_after_a_move_is_an_unknown_outcome() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("pool")).unwrap();
        let pool = service(dir.path(), true);
        let ih = "ef".repeat(20);
        add_and_rematch(&pool, &ih, "T", None, &[("T/a.bin", 100)]);
        // A size that does not read back as a number, as a corrupt index
        // would hold: `torrent_files` fails on the row.
        rusqlite::Connection::open(Config::minimal_for_tests(dir.path(), true).pool_db_path())
            .unwrap()
            .execute(
                "UPDATE torrent_file SET size = 'corrupt' WHERE infohash = ?1",
                [&ih],
            )
            .unwrap();

        match left_behind(&pool, &ih, &dir.path().join("pool/old"), "/dst") {
            Err(StepFailure::Unknown(e)) => {
                assert!(e.contains("file list could not be read"), "{e}")
            }
            Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
            Ok(()) => panic!("an unread file list was taken as nothing left behind"),
        }
    }

    #[test]
    fn a_storage_move_libtorrent_never_reports_on_is_unknown_not_failed() {
        let state = StateMap::new();
        let hash = libtorrent_safe::InfoHash([3; 20]);
        match await_storage_move_within(&state, &hash, "/x", std::time::Duration::ZERO) {
            Err(StepFailure::Unknown(e)) => assert!(e.contains("outcome unknown"), "{e}"),
            Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
            Ok(p) => panic!("reported moved to {p}"),
        }
    }

    #[test]
    fn a_relocated_torrent_is_based_where_its_payload_now_is() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let root_id = pool.roots()[0].0;
        let t = torrentd_pool::PoolTorrent {
            infohash: "ab".repeat(20),
            infohash_v1: None,
            infohash_v2: None,
            name: "T".into(),
            total_size: 1,
            num_files: 1,
            source_path: dir.path().join("t.torrent"),
            fastresume_path: None,
            declared_save_path: None,
            category: None,
            tags: vec![],
            profile: None,
        };
        pool.with_store(|s| {
            s.upsert_torrent(&t, 0)?;
            s.set_adoption(
                &t.infohash,
                AdoptionState::Adopted,
                Some(root_id),
                Some("old"),
                Some(1),
                None,
                None,
            )
        })
        .unwrap();

        record_new_base(&pool, &t.infohash, &root.join("new/place"));

        let base = pool.with_store(|s| s.adoption_base(&t.infohash)).unwrap();
        assert_eq!(base, Some((root_id, "new/place".to_owned())));
    }

    #[test]
    fn deleting_moves_the_file_into_the_trash_and_a_rescan_ignores_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let f = write(&root, "misc/old.bin", 32);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        delete_file(&pool, &f, 42, &mut Default::default()).unwrap();

        assert!(!f.exists());
        let trashed = root.join(".torrentd-trash/42/misc/old.bin");
        assert_eq!(std::fs::read(&trashed).unwrap(), vec![7u8; 32]);

        pool.scan().unwrap();
        let root_id = pool.roots()[0].0;
        let orphans = pool.with_store(|st| st.orphan_files(root_id, "")).unwrap();
        assert!(
            orphans.is_empty(),
            "the trash is never indexed: {orphans:?}"
        );
    }

    /// Index `rel` under the root and record `infohash` claiming it.
    fn claimed(pool: &PoolService, dir: &Path, infohash: &str, rel: &str) {
        pool.with_store_mut(|st| {
            st.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: infohash.to_owned(),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: "T".into(),
                    total_size: 1,
                    num_files: 1,
                    source_path: dir.join("t.torrent"),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: None,
                },
                0,
            )?;
            st.replace_claims(infohash, &[(pool.roots()[0].0, rel.to_owned())])
        })
        .unwrap();
    }

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
            torrent_payload(&pool, &ih, save, &files).unwrap_err()
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

    #[test]
    fn deleting_refuses_to_follow_a_directory_swapped_for_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let f = write(&root, "misc/victim.bin", 32);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();

        // After the scan, `misc` becomes a link to a directory outside the
        // root holding a file with the same name.
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("victim.bin"), vec![7u8; 32]).unwrap();
        std::fs::rename(root.join("misc"), dir.path().join("moved-away")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("misc")).unwrap();

        assert!(delete_file(&pool, &f, 1, &mut Default::default()).is_err());
        assert!(outside.join("victim.bin").exists());
    }
}
