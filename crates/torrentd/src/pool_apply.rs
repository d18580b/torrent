//! Executing mutation plans.
//!
//! The planner decided *what*; this decides *how* and does it. Three rules
//! shape everything here:
//!
//! * **The journal is written before the action.** Every step is marked in the
//!   database, attempted, then marked again, a batch of up to
//!   [`JOURNAL_BATCH`] delete steps per commit. A stop between batches leaves
//!   a plan in `applying` with a known last-completed step, which startup
//!   re-drives; a crash inside a batch leaves its steps `in_progress`.
//! * **Adopted payload moves through libtorrent.** `move_storage` keeps the
//!   session's view of where the data lives consistent with reality; moving the
//!   files underneath a seeding torrent does not. The step is attempted only
//!   when the session holds the torrent at the plan's source, and succeeds
//!   only once libtorrent reports the move done, none of the torrent's files
//!   is left at the source, and every one that was there is at the
//!   destination; across devices that move is libtorrent's own copy, whose
//!   contents torrentd does not verify.
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
use torrentd_pool::model::PlanRow;
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
/// Only a `draft` or `failed` plan is claimed. Already-`done` steps are
/// skipped, which is what makes applying a `failed` plan again a retry from
/// the step that stopped it. A plan a crash left `applying` is not this
/// function's to take: [`resume_unfinished`] re-drives it at boot.
pub fn apply(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    plan_id: i64,
    stop: StopCheck<'_>,
) -> Result<ApplyOutcome, String> {
    apply_inner(pool, source, state, plan_id, false, stop)
}

/// Whether the index accounts for everything the daemon owns.
///
/// Claims are written by the matcher and by nothing else, so a torrent the
/// matcher has never placed contributes none — and its payload reads as an
/// orphan. Owned means loaded, assigned in the registry, or queued for
/// verification: a torrent whose profile failed at boot is in no session, and
/// its payload is still its own.
///
/// Only an unclaimed torrent that may hold a file in `scope`, the roots the
/// plan deletes from, refuses. One a session holds whose payload lies outside
/// them - added through `POST /v1/torrents` with a `save_path` elsewhere, or a
/// library torrent whose payload is outside every root - can have no file
/// among the plan's orphans, and no scan would ever give it claims, so it
/// does not block the plan. One no session can report on still refuses:
/// where its files are is unknown.
fn check_index_accounts_for_live_state(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    scope: &DeleteScope,
) -> Result<(), String> {
    let owned = pool.owned_infohashes(state)?;
    let unindexed = pool
        .with_store(|st| st.loaded_without_claims(&owned))
        .map_err(|e| e.to_string())?;
    if unindexed.is_empty() {
        return Ok(());
    }
    // Each unclaimed torrent costs a session read and a resolve and a stat
    // per listed file, where a fully claimed index costs one query: logged,
    // so a slow plan start or a slow step names what it spent its time on.
    let started = std::time::Instant::now();
    let mut files_read = 0usize;
    let blocking: Vec<(&String, String)> = unindexed
        .iter()
        .filter_map(|ih| {
            unclaimed_payload_may_reach(source, state, ih, scope, &mut files_read)
                .map(|why| (ih, why))
        })
        .collect();
    info!(
        target: "torrentd::pool::apply",
        unclaimed = unindexed.len(),
        files = files_read,
        blocking = blocking.len(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "compared the unclaimed torrents the daemon owns with the plan's deletes",
    );
    if let Some((first, why)) = blocking.first() {
        return Err(format!(
            "{} torrent(s) the daemon owns (loaded, assigned to a profile, or queued for \
             verification) have no claims in the index and may hold files under this \
             plan's root, so it cannot prove what is unclaimed — the first is {first}, \
             which {why}. A torrent whose library `.torrent` the matcher has not placed \
             yet: run `pool scan` (or POST /v1/pool/scan) and rebuild this plan. A torrent \
             added through POST /v1/torrents, which a scan never claims: copy its \
             `.torrent` into the library and rescan, move its payload out of this root, or \
             remove it. A torrent no session holds keeps refusing until its profile loads \
             it or it is removed. A torrent none of whose files lies under this plan's \
             root, as spelled, through a symlink, or as a hard link, never blocks it.",
            blocking.len(),
        ));
    }
    Ok(())
}

/// Why the unclaimed torrent `infohash` may hold a file in `scope`, or
/// `None` where its session shows it holds none. Adds the number of files
/// its session lists to `files_read`.
fn unclaimed_payload_may_reach(
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    infohash: &str,
    scope: &DeleteScope,
    files_read: &mut usize,
) -> Option<String> {
    let Some(st) = libtorrent_safe::InfoHash::from_hex(infohash).and_then(|ih| state.get(&ih))
    else {
        return Some("no session holds, so where its files lie is unknown".into());
    };
    match read_live_torrent(source, &st) {
        Err(LiveReadError::NoSession) => Some(format!(
            "is held by profile {}, which has no session to say where its files lie",
            st.profile_id,
        )),
        Err(LiveReadError::Engine(e)) => Some(format!(
            "could not be read from its session ({e}), so where its files lie is unknown"
        )),
        Ok(live) => {
            *files_read += live.files.as_ref().map_or(0, Vec::len);
            scope.reached_by(&live)
        }
    }
}

/// Why [`read_live_torrent`] could not read a torrent from its session.
#[derive(Debug)]
pub enum LiveReadError {
    /// The profile holding it has no session.
    NoSession,
    /// Its session could not report it.
    Engine(torrentd_engine::EngineError),
}

/// Where the session of the profile holding `st` says its payload lies:
/// its save path and, once its metadata has arrived, its files.
pub fn read_live_torrent(
    source: &Arc<dyn AlertSource>,
    st: &torrentd_engine::TorrentState,
) -> Result<LiveTorrent, LiveReadError> {
    let engine = source
        .engine_for(&st.profile_id)
        .ok_or(LiveReadError::NoSession)?;
    let details = engine
        .torrent_details(st.handle)
        .map_err(LiveReadError::Engine)?;
    let files = engine
        .torrent_files(st.handle)
        .map_err(LiveReadError::Engine)?
        .map(|fs| fs.into_iter().map(|f| f.path).collect());
    Ok(LiveTorrent {
        save_path: details.save_path.into(),
        files,
    })
}

/// What a delete plan may remove, as an unclaimed torrent is compared with
/// it: the roots its steps delete from, and the files they delete.
struct DeleteScope {
    /// Each root as configured and, where it resolves, with its symlinks
    /// resolved.
    roots: Vec<std::path::PathBuf>,
    targets: Vec<std::path::PathBuf>,
    /// `(device, inode)` of each target on disk, and the target, read on
    /// first use: only a plan an unclaimed torrent sits beside pays for the
    /// stats.
    identities: std::cell::OnceCell<std::collections::HashMap<(u64, u64), std::path::PathBuf>>,
}

impl DeleteScope {
    /// The scope of `steps`' deletes. Every root where no step lies under
    /// one, which no plan the planner builds does.
    fn of(pool: &PoolService, steps: &[PlanStepRow]) -> Self {
        let targets: Vec<std::path::PathBuf> = steps
            .iter()
            .filter(|s| s.op == ops::DELETE_FILE)
            .map(|s| std::path::PathBuf::from(&s.src))
            .collect();
        let mut roots: Vec<std::path::PathBuf> = Vec::new();
        for target in &targets {
            if let Some((_, root)) = pool.roots().iter().find(|(_, r)| target.starts_with(r)) {
                if !roots.contains(root) {
                    roots.push(root.clone());
                }
            }
        }
        if roots.is_empty() {
            roots = pool.roots().iter().map(|(_, r)| r.clone()).collect();
        }
        let resolved: Vec<std::path::PathBuf> = roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .collect();
        roots.extend(resolved);
        Self {
            roots,
            targets,
            identities: std::cell::OnceCell::new(),
        }
    }

    fn identities(&self) -> &std::collections::HashMap<(u64, u64), std::path::PathBuf> {
        use std::os::unix::fs::MetadataExt;
        self.identities.get_or_init(|| {
            self.targets
                .iter()
                .filter_map(|t| {
                    let md = std::fs::symlink_metadata(t).ok()?;
                    Some(((md.dev(), md.ino()), t.clone()))
                })
                .collect()
        })
    }

    /// The root of this plan's that `p` lies under, if any.
    fn root_over(&self, p: &Path) -> Option<&Path> {
        self.roots
            .iter()
            .find(|r| p.starts_with(r))
            .map(std::path::PathBuf::as_path)
    }

    /// Why `live`, a torrent its session holds, may have a file this plan
    /// deletes, naming the rule and the path that matched; `None` where it
    /// has none.
    ///
    /// Every path is compared both as spelled and with its symlinks resolved,
    /// so a save path reaching a root through a symlink, or a symlinked
    /// directory below it, still reaches it; and each of its files on disk is
    /// compared by `(device, inode)` with the plan's, so a hard link or a bind
    /// mount of a root reaches it too. A torrent with no metadata yet could
    /// write anything under its save path, so it reaches a root its save path
    /// is under or above.
    fn reached_by(&self, live: &LiveTorrent) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let save_path = live.save_path.as_path();
        let bases = live.bases();
        let Some(files) = &live.files else {
            return bases.iter().find_map(|b| {
                if let Some(r) = self.root_over(b) {
                    return Some(format!(
                        "has no metadata yet and is saved at {}, under this plan's root {}, \
                         so it could write any file there",
                        b.display(),
                        r.display(),
                    ));
                }
                self.roots.iter().find(|r| r.starts_with(b)).map(|r| {
                    format!(
                        "has no metadata yet and is saved at {}, above this plan's root {}, \
                         so it could write any file there",
                        b.display(),
                        r.display(),
                    )
                })
            });
        };
        files.iter().find_map(|rel| {
            let joined = save_path.join(rel);
            for b in &bases {
                let p = b.join(rel);
                if let Some(r) = self.root_over(&p) {
                    return Some(format!(
                        "lists {rel}, at {}, under this plan's root {}",
                        p.display(),
                        r.display(),
                    ));
                }
            }
            if let Some(p) = live.resolved(rel) {
                if let Some(r) = self.root_over(&p) {
                    return Some(format!(
                        "lists {rel}, at {}, which a symlink leads to {}, under this plan's \
                         root {}",
                        joined.display(),
                        p.display(),
                        r.display(),
                    ));
                }
            }
            let md = std::fs::metadata(&joined).ok()?;
            self.identities().get(&(md.dev(), md.ino())).map(|target| {
                format!(
                    "lists {rel}, at {}, which is the same file on disk (device and inode) as \
                     {}, which this plan deletes: a hard link or a bind mount of its root",
                    joined.display(),
                    target.display(),
                )
            })
        })
    }
}

/// What the between-steps re-check of [`check_index_accounts_for_live_state`]
/// watches: the change counters of the loaded set and of the registry.
///
/// Not their sizes: one torrent removed and another added leaves both sizes
/// as they were, and the added torrent's files would then read as orphans.
fn ownership_generation(pool: &PoolService, state: &StateMap) -> (u64, u64) {
    (state.generation(), pool.registry_generation())
}

/// What `apply_inner` answers when a shutdown stops it before the claim. The
/// boot re-drive tells a stop from a failure by it.
const SHUTTING_DOWN: &str = "the daemon is shutting down; apply the plan again once it is back";

/// The refusal for a plan another caller holds: its status as it is now,
/// which is what moved since `read` was taken.
fn not_claimable(pool: &PoolService, plan_id: i64, read: &str) -> String {
    let now = pool
        .with_store(|s| s.plan(plan_id))
        .ok()
        .flatten()
        .map_or_else(|| read.to_owned(), |p| p.status);
    format!("plan is {now} and cannot be applied right now")
}

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
        // one here means a previous run died mid-batch. Whether each step
        // happened is unknown, and both re-running and skipping one can
        // destroy data.
        //
        // Park it in `failed` rather than leaving it `applying`: a human has
        // to look either way, and `failed` is a state they can discard.
        //
        // Nothing marks the step resolved, so this refusal repeats on every
        // apply and every re-drive; the message says so, and names the only
        // way forward, rather than inviting a resume that cannot happen.
        let more = steps
            .iter()
            .filter(|s| s.status == step_status::IN_PROGRESS)
            .count()
            - 1;
        let others = if more == 0 {
            String::new()
        } else {
            format!(
                ", and so are {more} more of its steps, journalled in the same batch \
                 (GET /v1/pool/plans/{plan_id}/steps lists each one)"
            )
        };
        let msg = format!(
            "step {} ({}) was interrupted and its outcome is unknown{others}. {}",
            stuck.seq,
            stuck.op,
            unknown_outcome_remedy(&stuck.src, stuck.dst.as_deref()),
        );
        //
        // Only a plan this caller could have claimed is parked. An API apply
        // also finds `in_progress` steps when another apply is running them
        // right now, and failing that plan would make it claimable by a third
        // apply that ran the same steps alongside the first.
        match pool.with_store(|s| s.fail_unclaimed_plan(plan_id, resume)) {
            Ok(true) => {}
            Ok(false) => return Err(not_claimable(pool, plan_id, &plan.status)),
            Err(e) => pool.note_store_error("fail_unclaimed_plan", &e),
        }
        pool.count("pool_plan_failures_total", &[("kind", "step_failed")]);
        return Err(msg);
    }

    // Deleting rests on "the index is a complete account of what is
    // protected". Derived from live session state, so it is correct on every
    // load path and across a restart.
    let deletes = steps.iter().any(|s| s.op == ops::DELETE_FILE);
    let scope = DeleteScope::of(pool, &steps);
    // A delete plan over a large subtree runs for minutes. A `POST /torrents`
    // landing in that window makes the index incomplete again, so the
    // precondition is re-established whenever the loaded set or the registry
    // changes. Read before the check, so a change landing while it runs is
    // one the first step's comparison sees. Both counters are O(1); the full
    // check only runs when one has actually moved.
    let mut owned_generation = ownership_generation(pool, state);
    if deletes {
        if let Err(msg) = check_index_accounts_for_live_state(pool, source, state, &scope) {
            // The boot re-drive refusing leaves a plan in `applying`, which
            // the API can neither apply nor discard; `failed` it can do both
            // with, once a rescan lets the index account for the torrent. An
            // API refusal leaves the plan as it was.
            if resume {
                if let Err(e) = pool.with_store(|s| s.fail_unclaimed_plan(plan_id, true)) {
                    pool.note_store_error("fail_unclaimed_plan", &e);
                }
            }
            return Err(msg);
        }
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
        return Err(not_claimable(pool, plan_id, &plan.status));
    }

    let mut out = ApplyOutcome {
        plan_id,
        done: 0,
        failed: 0,
        skipped: 0,
        status: plan_status::APPLIED.to_string(),
    };

    let mut guards = DeleteGuards::default();
    let bucket = plan_trash_bucket(plan.id, plan.created_at);

    let mut todo: Vec<PlanStepRow> = Vec::with_capacity(steps.len());
    for step in steps {
        if step.status == step_status::DONE {
            out.skipped += 1;
        } else {
            todo.push(step);
        }
    }
    let mut rest = todo.as_slice();
    while let Some(first) = rest.first() {
        let (batch, after) = rest.split_at(journal_batch_len(rest));
        rest = after;
        // Between batches and between the steps of one, never inside a step.
        // Stop here and the plan stays `applying` with this step still
        // `pending`, which the next boot re-drives from exactly here.
        if stop() {
            warn!(
                target: "torrentd::pool::apply",
                plan_id,
                next_step = first.seq,
                done = out.done,
                "stopping between steps for shutdown; the plan resumes at the next boot",
            );
            out.status = plan_status::APPLYING.to_string();
            return Ok(out);
        }
        // Written before the action, so a crash leaves `in_progress` behind.
        // Steps were inserted `pending` up front and only updated afterwards,
        // which made "never started" and "started, outcome unknown"
        // indistinguishable to the resume path. The whole batch is marked in
        // one commit, so a crash inside it leaves every step of the batch
        // `in_progress`, those done and those not yet started alike: each is
        // a step whose outcome is unknown, as one interrupted step always
        // was, and the remedy is the same rescan and rebuild.
        //
        // A batch whose start the journal cannot record is not run. Running
        // it anyway moved files the journal still called `pending`, and the
        // `done` and plan-status writes that followed failed the same way,
        // so nothing recorded which files the plan had moved. Stop as a
        // failed plan, so the claimed plan is not stranded in `applying`:
        // nothing in the batch ran, so applying the plan again starts it
        // afresh. Where even that cannot be written, the plan stays
        // `applying` with the batch `pending`, which the next boot re-drives
        // from exactly here.
        let started: Vec<(i64, &str, Option<&str>)> = batch
            .iter()
            .map(|s| (s.seq, step_status::IN_PROGRESS, None))
            .collect();
        if let Err(e) = pool.with_store_mut(|s| s.set_steps_status(plan_id, &started)) {
            pool.note_store_error("set_steps_status", &e);
            let msg = format!("not started: the plan journal could not record the step: {e}");
            out.failed += 1;
            out.status = plan_status::FAILED.to_string();
            if let Err(se) = pool.with_store(|s| {
                s.set_step_status(plan_id, first.seq, step_status::FAILED, Some(&msg))
            }) {
                pool.note_store_error("set_step_status", &se);
            }
            error!(
                target: "torrentd::pool::apply",
                plan_id,
                step = first.seq,
                op = %first.op,
                src = %first.src,
                error.cause = %e,
                "stopping: the plan journal could not record a step as started",
            );
            pool.count("pool_plan_failures_total", &[("kind", "step_failed")]);
            break;
        }

        // Each step's outcome, recorded for the whole batch in one commit
        // once it ends. A step the batch did not reach goes back to
        // `pending`: it never ran, so a resume or a retry runs it.
        let mut outcomes: Vec<(i64, &str, Option<String>)> = Vec::with_capacity(batch.len());
        let mut halted = false;
        let mut stopping = false;
        for (i, step) in batch.iter().enumerate() {
            if i > 0 && stop() {
                warn!(
                    target: "torrentd::pool::apply",
                    plan_id,
                    next_step = step.seq,
                    done = out.done,
                    "stopping between steps for shutdown; the plan resumes at the next boot",
                );
                out.status = plan_status::APPLYING.to_string();
                stopping = true;
            } else if deletes
                && step.op == ops::DELETE_FILE
                && ownership_generation(pool, state) != owned_generation
            {
                // Read before the check, not after it: a change landing while
                // the check runs is then one the next step's comparison sees.
                let seen = ownership_generation(pool, state);
                match check_index_accounts_for_live_state(pool, source, state, &scope) {
                    Ok(()) => owned_generation = seen,
                    Err(e) => {
                        // Stop, but as a *failed* plan rather than an early
                        // return: the plan is claimed at this point, and
                        // returning here would strand it in `applying` where
                        // nothing can apply, resume or discard it.
                        out.failed += 1;
                        out.status = plan_status::FAILED.to_string();
                        error!(
                            target: "torrentd::pool::apply",
                            plan_id,
                            step = step.seq,
                            error.cause = %e,
                            "stopping: the index no longer accounts for what is loaded",
                        );
                        pool.count("pool_plan_failures_total", &[("kind", "index_diverged")]);
                        outcomes.push((step.seq, step_status::FAILED, Some(e)));
                        halted = true;
                    }
                }
            }
            if stopping || halted {
                let unrun = &batch[outcomes.len()..];
                outcomes.extend(unrun.iter().map(|s| (s.seq, step_status::PENDING, None)));
                break;
            }
            let result = match step.op.as_str() {
                ops::MOVE_TORRENT => move_torrent(pool, source, state, step, stop),
                ops::DELETE_FILE => {
                    delete_file(pool, Path::new(&step.src), plan_id, &bucket, &mut guards)
                }
                other => Err(StepFailure::Failed(format!(
                    "unknown plan operation {other:?}"
                ))),
            };
            match result {
                Ok(()) => {
                    out.done += 1;
                    outcomes.push((step.seq, step_status::DONE, None));
                }
                Err(StepFailure::Unknown(e)) => {
                    // Not `failed`: the move may yet land. The step stays
                    // `in_progress` — the journal's own word for "started,
                    // verdict unknown" — so neither a resume nor a retry
                    // re-runs it, and the plan is parked for a human, who can
                    // see where the payload is before deciding.
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
                    outcomes.push((step.seq, step_status::IN_PROGRESS, Some(e)));
                    out.status = plan_status::FAILED.to_string();
                    halted = true;
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
                    outcomes.push((step.seq, step_status::FAILED, Some(e)));
                    // Stop at the first failure. Continuing would apply half a
                    // reorganisation and leave the operator reconciling it by
                    // hand.
                    out.status = plan_status::FAILED.to_string();
                    halted = true;
                }
            }
            if halted {
                let unrun = &batch[outcomes.len()..];
                outcomes.extend(unrun.iter().map(|s| (s.seq, step_status::PENDING, None)));
                break;
            }
        }
        let recorded: Vec<(i64, &str, Option<&str>)> = outcomes
            .iter()
            .map(|(seq, status, error)| (*seq, *status, error.as_deref()))
            .collect();
        if let Err(e) = pool.with_store_mut(|s| s.set_steps_status(plan_id, &recorded)) {
            pool.note_store_error("set_steps_status", &e);
        }
        if stopping {
            return Ok(out);
        }
        if halted {
            break;
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

/// The most delete steps one journal batch holds.
///
/// Every journal write is a commit of the index's writer, which runs
/// `synchronous=FULL`: a WAL fsync each. Two per step made a 200,000-file
/// delete plan spend 400,000 fsyncs on its journal alone. A batch is marked
/// `in_progress` in one commit and its outcomes recorded in one more, so a
/// plan costs two commits per batch. The bound is what a crash inside a batch
/// leaves `in_progress` for a human to look at.
pub(crate) const JOURNAL_BATCH: usize = 64;

/// How many of `rest`'s leading steps the next journal batch holds: a run of
/// up to [`JOURNAL_BATCH`] deletes, or one step of any other operation.
///
/// A move stays alone. Its outcome can be unknown with its payload in
/// flight, and a crash beside it must not leave other steps' outcomes
/// unknown too; a relocate plan has one step anyway.
fn journal_batch_len(rest: &[PlanStepRow]) -> usize {
    rest.iter()
        .take(JOURNAL_BATCH)
        .take_while(|s| s.op == ops::DELETE_FILE)
        .count()
        .max(1)
        .min(rest.len())
}

/// How a step did not succeed.
#[derive(Debug)]
enum StepFailure {
    /// It did not happen, or was undone; the journal says `failed`.
    Failed(String),
    /// It was started and its verdict is not known — a storage move libtorrent
    /// has not reported on by the deadline, or a rename that happened but
    /// whose fsync failed. Recording that as `failed` invited a retry of a
    /// move that may still land, or already has.
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

/// What an operator can do about a step whose outcome is unknown, for a step
/// from `src` to `dst` (`None` for a delete).
///
/// Such a step stays `in_progress`, and no request marks it resolved, so
/// every later apply and boot re-drive refuses the plan. The only way on is
/// to look, rescan, discard and rebuild, and this says exactly that, so no
/// message invites a resume the daemon then refuses.
fn unknown_outcome_remedy(src: &str, dst: Option<&str>) -> String {
    let look = match dst {
        Some(dst) => format!(
            "Look at {src} and {dst} and find which of them holds the complete payload \
             before removing anything: a move whose wait was cut off can still finish and \
             delete {src}, or stop with a partial copy at {dst}. A new plan refuses to \
             move onto a file already at the destination, so once you know which copy is \
             complete, remove only the other."
        ),
        None => format!("Look at {src} to find what happened to it."),
    };
    format!(
        "This plan cannot be applied or resumed again: its step stays in_progress, and \
         nothing marks it resolved. {look} Then rescan (POST /v1/pool/scan), discard this \
         plan (DELETE /v1/pool/plans/{{plan_id}}), and build a new one"
    )
}

/// Relocate an adopted torrent by asking libtorrent to move its storage,
/// waiting for libtorrent's verdict until `stop` says to give up on it.
fn move_torrent(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    step: &PlanStepRow,
    stop: StopCheck<'_>,
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
        // Not loaded. Only a torrent nothing owns - the `matched but not
        // adopted` case - may have its files moved by torrentd itself. One a
        // profile owns but did not load (its VPN failed at boot, say) still
        // has its resume data, recorded save path and any queued adoption
        // naming the source; renaming under them strands the payload when
        // the profile comes back.
        if let Some(why) = pool.unloaded_owner(&infohash)? {
            return Err(format!(
                "torrent {infohash} is not loaded, but {why}; it can be relocated only \
                 while its session serves it, so bring its profile up and apply again"
            )
            .into());
        }
        refuse_live_files_under(source, state, Path::new(&step.src))?;
        let moved = move_directory(Path::new(&step.src), Path::new(dst));
        // An unknown outcome is one whose rename happened: the payload is at
        // `dst` now, so the base follows it as it does a move that is done.
        if !matches!(moved, Err(StepFailure::Failed(_))) {
            record_new_base(pool, &infohash, Path::new(dst));
        }
        return moved;
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

    // `move_storage` moves from wherever the session holds the torrent, not
    // from `step.src`, and libtorrent skips every source file that does not
    // exist and still reports the move done. A session that disagrees with the
    // index - a crash before the resume save after an earlier relocate, a
    // rescan that re-placed the torrent - would move nothing, and the base and
    // save path below would then point at an empty destination while the
    // payload sat unclaimed at the source.
    let src = Path::new(&step.src);
    let held_at = engine
        .torrent_details(st.handle)
        .map_err(|e| format!("could not read where the session holds torrent {infohash}: {e}"))?
        .save_path;
    if !same_directory(Path::new(&held_at), src) {
        return Err(format!(
            "the session serves torrent {infohash} from {held_at}, but the plan moves it \
             from {}; refusing, since libtorrent would move nothing from there. Reconcile \
             the two (rescan, or move the torrent back), then build a new plan",
            step.src,
        )
        .into());
    }
    // What the move has to carry. Checked again at the destination once
    // libtorrent reports the move done, since that report alone does not
    // prove a single file travelled.
    let present = files_present_under(pool, &infohash, src)?;
    if present.is_empty() {
        return Err(format!(
            "none of torrent {infohash}'s files is at {}; refusing to record a move of a \
             payload that is not there",
            step.src,
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
    let moved_to = await_storage_move(state, &hash, &step.src, dst, stop)?;
    record_new_base(pool, &infohash, Path::new(&moved_to));
    // The save path recorded beside the `.torrent` is where the boot scan
    // re-adds a torrent whose resume file is lost; it follows the payload.
    pool.record_save_path(&st.profile_id, &infohash, &moved_to);
    // libtorrent serves from the new path either way, so the base and save
    // path above follow it; but a file it skipped is still at the source and
    // the step is not the move the plan asked for.
    left_behind(pool, &infohash, src, dst)?;
    arrived(&present, src, dst)
}

/// Whether two spellings name the same directory: component-wise equal, or
/// resolving to the same place once symlinks are followed.
fn same_directory(a: &Path, b: &Path) -> bool {
    a == b
        || matches!(
            (std::fs::canonicalize(a), std::fs::canonicalize(b)),
            (Ok(x), Ok(y)) if x == y
        )
}

/// The torrent's files, torrent-relative, that have an entry under `dir`.
fn files_present_under(
    pool: &PoolService,
    infohash: &str,
    dir: &Path,
) -> Result<Vec<String>, String> {
    let files = pool
        .with_store(|s| s.torrent_files(infohash))
        .map_err(|e| format!("could not read torrent {infohash}'s file list: {e}"))?;
    Ok(files
        .into_iter()
        .filter(|f| f.is_on_disk() && dir.join(&f.rel_path).symlink_metadata().is_ok())
        .map(|f| f.rel_path)
        .collect())
}

/// Whether every file that was at the source before the move is now at the
/// destination.
///
/// `storage_moved_alert` is posted even when libtorrent found nothing to move,
/// so the report alone is not the move. A file missing here is an unknown
/// outcome rather than a failure: libtorrent has already re-pointed the
/// session, and a retry would move from a place the payload may have left.
fn arrived(present: &[String], src: &Path, dst: &str) -> Result<(), StepFailure> {
    let Some(rel) = present
        .iter()
        .find(|rel| Path::new(dst).join(rel).symlink_metadata().is_err())
    else {
        return Ok(());
    };
    Err(StepFailure::Unknown(format!(
        "outcome unknown: libtorrent reported the torrent moved to {dst}, but {rel}, which \
         was at {} before the move, is not there. {}",
        src.display(),
        unknown_outcome_remedy(&src.display().to_string(), Some(dst)),
    )))
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
                 could not be read to confirm nothing was left at {}: {e}. {}",
                src.display(),
                unknown_outcome_remedy(&src.display().to_string(), Some(dst)),
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
         the destination. {}",
        src.display(),
        unknown_outcome_remedy(&src.display().to_string(), Some(dst)),
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

/// How much longer a move is waited for once a shutdown is latched.
///
/// The latch is set as the server sees the stop, and teardown gives pool work
/// the HTTP drain and then `POOL_WORK_DRAIN` (20 s) before closing the
/// sessions under it. A move that lands in this window is recorded done; one
/// still copying at its end is cut off, recorded as such, and its step
/// released before the teardown gives up on it.
const STORAGE_MOVE_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// Block until libtorrent reports the move from `src` done or failed, the
/// deadline runs out, or a shutdown latched in `stop` outlasts
/// [`STORAGE_MOVE_STOP_GRACE`]. `Ok` carries the save path libtorrent
/// reported.
fn await_storage_move(
    state: &StateMap,
    hash: &libtorrent_safe::InfoHash,
    src: &str,
    dst: &str,
    stop: StopCheck<'_>,
) -> Result<String, StepFailure> {
    await_storage_move_within(
        state,
        hash,
        src,
        dst,
        STORAGE_MOVE_DEADLINE,
        STORAGE_MOVE_STOP_GRACE,
        stop,
    )
}

fn await_storage_move_within(
    state: &StateMap,
    hash: &libtorrent_safe::InfoHash,
    src: &str,
    dst: &str,
    within: std::time::Duration,
    stop_grace: std::time::Duration,
    stop: StopCheck<'_>,
) -> Result<String, StepFailure> {
    let deadline = std::time::Instant::now() + within;
    // When the grace a latched shutdown gives the move runs out; `None`
    // until the latch is seen.
    let mut cut_off_at: Option<std::time::Instant> = None;
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
        // The shutdown does not wait out a cross-device copy: teardown gives
        // pool work a bounded drain and then closes the session under it.
        // Waiting on regardless only meant the cut-off went unrecorded, the
        // step left `in_progress` with nothing saying why. Give the move a
        // short grace, then stop, say so, and park the step with the reason.
        if cut_off_at.is_none() && stop() {
            cut_off_at = Some(std::time::Instant::now() + stop_grace);
            info!(
                target: "torrentd::pool::apply",
                infohash = %hash,
                dst,
                grace_secs = stop_grace.as_secs(),
                "shutting down while libtorrent is still moving the payload; waiting \
                 briefly for it to land",
            );
        }
        if cut_off_at.is_some_and(|at| std::time::Instant::now() >= at) {
            warn!(
                target: "torrentd::pool::apply",
                infohash = %hash,
                src,
                dst,
                "shutting down while libtorrent is still moving the payload; the move \
                 is cut off and its step's outcome is unknown",
            );
            return Err(StepFailure::Unknown(format!(
                "outcome unknown: the daemon shut down while libtorrent was still moving the \
                 payload from {src} to {dst}, so the wait for it was cut off. {}",
                unknown_outcome_remedy(src, Some(dst)),
            )));
        }
        if std::time::Instant::now() >= deadline {
            return Err(StepFailure::Unknown(format!(
                "outcome unknown: libtorrent has not reported the move to {dst} after {}s, \
                 and may still be copying. {}",
                within.as_secs(),
                unknown_outcome_remedy(src, Some(dst)),
            )));
        }
        std::thread::sleep(STORAGE_MOVE_POLL);
    }
}

/// Refuse renaming `src`, an unloaded torrent's directory, while any torrent
/// a session holds serves a file from under it.
///
/// The pool index cannot answer this: claims come from the matcher alone, so
/// a cross-seed added through `POST /v1/torrents` with a `save_path` over the
/// same files claims nothing, and `recheck_relocatable` sees neither a
/// co-claimant nor a foreign file. This reads every loaded torrent from its
/// session instead, as `DELETE ?delete_files=true` does. One whose session
/// cannot be read cannot be shown not to serve from `src`, so it refuses too.
fn refuse_live_files_under(
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    src: &Path,
) -> Result<(), String> {
    let mut loaded = state.infohashes();
    loaded.sort_unstable_by_key(libtorrent_safe::InfoHash::to_hex);
    for ih in &loaded {
        // Removed since the list was taken: it serves nothing any more.
        let Some(st) = state.get(ih) else { continue };
        let unprovable = |why: String| {
            format!(
                "torrent {ih} {why}, so whether it serves files from under {} cannot be \
                 ruled out; nothing was moved. Apply again once its session can be read, \
                 or once it is removed",
                src.display(),
            )
        };
        let live = read_live_torrent(source, &st).map_err(|e| match e {
            LiveReadError::NoSession => unprovable(format!(
                "is held by profile {}, which has no session",
                st.profile_id,
            )),
            LiveReadError::Engine(e) => {
                unprovable(format!("could not be read from its session ({e})"))
            }
        })?;
        if let Some(path) = live.file_under(src) {
            return Err(format!(
                "torrent {ih}, loaded in profile {}, serves {} from under {}, so renaming \
                 that directory would move its files away from it; nothing was moved. Remove \
                 that torrent or move it through its session first, then apply again",
                st.profile_id,
                path.display(),
                src.display(),
            ));
        }
    }
    Ok(())
}

/// Move a directory tree torrentd owns outright.
///
/// The move is `renameat2(RENAME_NOREPLACE)` between the two parents, so an
/// entry already at `dst` refuses it, an empty directory included, and one
/// that appears there after a check cannot be replaced either. Both parents
/// are then fsynced, so the rename survives a crash; a failure there comes
/// after the rename happened, and is [`StepFailure::Unknown`] rather than
/// `failed`, which would say the payload is still at `src`.
fn move_directory(src: &Path, dst: &Path) -> Result<(), StepFailure> {
    fn named(p: &Path) -> Result<(&Path, &str), String> {
        let name = p.file_name().and_then(|n| n.to_str());
        p.parent()
            .zip(name)
            .ok_or_else(|| format!("{} is not a directory that can be renamed", p.display()))
    }
    let ((src_parent, src_name), (dst_parent, dst_name)) = (named(src)?, named(dst)?);
    std::fs::create_dir_all(dst_parent)
        .map_err(|e| format!("create {}: {e}", dst_parent.display()))?;
    let open = |p: &Path| std::fs::File::open(p).map_err(|e| format!("open {}: {e}", p.display()));
    let (from, to) = (open(src_parent)?, open(dst_parent)?);
    match fsat::rename_noreplace(&from, src_name, &to, dst_name) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            return Err(format!("destination {} already exists", dst.display()).into())
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            return Err(format!(
                "cross-device directory move is not attempted automatically \
                 ({} → {}); move the data and rescan",
                src.display(),
                dst.display(),
            )
            .into())
        }
        Err(e) => return Err(format!("rename {} → {}: {e}", src.display(), dst.display()).into()),
    }
    for (dir, path) in [(&from, src_parent), (&to, dst_parent)] {
        fsat::fsync(dir).map_err(|e| {
            StepFailure::Unknown(format!(
                "outcome unknown: {} was renamed to {}, but fsync {} failed ({e}), so the \
                 rename may not survive a crash. {}",
                src.display(),
                dst.display(),
                path.display(),
                unknown_outcome_remedy(
                    &src.display().to_string(),
                    Some(&dst.display().to_string()),
                ),
            ))
        })?;
    }
    Ok(())
}

/// Delete a file, re-proving at the last moment that nothing is using it.
///
/// "Unclaimed" is a statement about the index, and the index is a snapshot.
/// Five things have to hold, because an irreversible operation should not
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
fn delete_file(
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
fn plan_trash_bucket(plan_id: i64, created_at: i64) -> String {
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
/// directories are fsynced so it survives a crash. A failed fsync comes after
/// the file moved, so it is [`StepFailure::Unknown`]: `failed` would say the
/// file is still where it was.
fn move_into_trash(
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
        .map_err(|e| format!("{}: {e}; refusing to follow it", path.display()))?;
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
    let trash_path = root.join(torrentd_pool::plan::TRASH_DIR).join(bucket);
    for (dir, what) in [(parent, "its directory"), (&trash, "the trash")] {
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
    /// sessions spell it and resolved, and each of `other`'s files is
    /// resolved on its own full path, so a `save_path` reaching the same
    /// directory through a symlink, a symlinked directory below it, and a
    /// file that is itself a symlink to the payload are all caught. A
    /// torrent whose metadata
    /// has not arrived yet could write any file under its `save_path`, so
    /// every payload file under it counts as shared.
    pub fn shared_with(&self, other: &LiveTorrent) -> Option<&std::path::Path> {
        let bases = other.bases();
        fn forms(f: &PayloadFile) -> impl Iterator<Item = &std::path::PathBuf> {
            std::iter::once(&f.path).chain(f.resolved.as_ref())
        }
        let hit: Box<dyn Fn(&PayloadFile) -> bool> = match &other.files {
            None => Box::new(|f| forms(f).any(|p| bases.iter().any(|b| p.starts_with(b)))),
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

impl LiveTorrent {
    /// The first path at which this torrent serves a file from under `dir`,
    /// or `None` when it serves none from there: the directory-level
    /// counterpart of [`TorrentPayload::shared_with`], for a move that
    /// renames `dir` whole.
    ///
    /// Paths are compared as the session spells them and with their
    /// symlinks resolved, on both sides, so a save path reaching `dir`
    /// through a symlink, a symlinked directory below it, and a file that
    /// is itself a symlink into `dir` are all caught. A file not written
    /// yet resolves through its parent. A torrent whose metadata has not
    /// arrived could write any file under its save path, so it serves from
    /// `dir` when its save path is `dir`, above it, or below it; the path
    /// returned is then its save path.
    pub fn file_under(&self, dir: &Path) -> Option<std::path::PathBuf> {
        let dirs: Vec<std::path::PathBuf> = std::iter::once(dir.to_path_buf())
            .chain(std::fs::canonicalize(dir).ok())
            .collect();
        let bases = self.bases();
        let under = |p: &Path| dirs.iter().any(|d| p.starts_with(d));
        let Some(files) = &self.files else {
            return bases
                .iter()
                .any(|b| under(b) || dirs.iter().any(|d| d.starts_with(b)))
                .then(|| self.save_path.clone());
        };
        files.iter().find_map(|rel| {
            let hit = bases.iter().any(|b| under(&b.join(rel)))
                || self.resolved(rel).as_deref().is_some_and(under);
            hit.then(|| self.save_path.join(rel))
        })
    }

    /// Its save path as the session spells it, then with its symlinks
    /// resolved where it resolves: the two bases every comparison of its
    /// files joins them to.
    fn bases(&self) -> Vec<std::path::PathBuf> {
        std::iter::once(self.save_path.clone())
            .chain(std::fs::canonicalize(&self.save_path).ok())
            .collect()
    }

    /// Where its file `rel` lies with every symlink on its full path
    /// resolved. A file not written yet resolves through its parent, so a
    /// symlinked directory below the save path leads there all the same.
    fn resolved(&self, rel: &str) -> Option<std::path::PathBuf> {
        let joined = self.save_path.join(rel);
        std::fs::canonicalize(&joined).ok().or_else(|| {
            let parent = std::fs::canonicalize(joined.parent()?).ok()?;
            Some(parent.join(joined.file_name()?))
        })
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
///    and a torrent the matcher has not placed contributes neither;
/// 3. still be the file the index recorded: the same `(size, mtime, inode,
///    device)`, checked here and again at the move.
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
        let Some((root_id, root, rel)) = pool.roots().iter().find_map(|(id, root)| {
            path.strip_prefix(root)
                .ok()
                .map(|r| (*id, root.clone(), r.to_string_lossy().replace('\\', "/")))
        }) else {
            return Err(outside(&path));
        };
        if !torrentd_pool::plan::contains(&root, &path) {
            return Err(outside(&path));
        }
        located.push((path, root_id, root, rel));
    }
    let (claims, others, rows) = pool
        .with_reader(|s| {
            let claims: std::collections::HashSet<(i64, String)> =
                s.claims_of(infohash)?.into_iter().collect();
            let others = s.co_claimants(infohash)?;
            let rows = located
                .iter()
                .map(|(_, root_id, _, rel)| s.file(*root_id, rel))
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, torrentd_pool::PoolError>((claims, others, rows))
        })
        .map_err(|e| PayloadRefusal::Unproven(e.to_string()))?;
    if !others.is_empty() {
        return Err(PayloadRefusal::Shared(others));
    }
    let mut out = Vec::with_capacity(located.len());
    for ((path, root_id, root, rel), row) in located.into_iter().zip(rows) {
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
        if !claims.contains(&(root_id, rel.clone())) {
            return unproven(format!(
                "the index does not record this torrent claiming {}; rescan before deleting",
                path.display(),
            ));
        }
        if !md.is_file() {
            return unproven(format!("{} is not a regular file", path.display()));
        }
        let stamp = (row.size, row.mtime_ns, row.ino, row.dev);
        if torrentd_pool::file_stamp(&md) != stamp {
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

/// The planner's unresolved-payload guards, per root, and the identities of
/// every claimed file, as of one index generation. Read on first use and
/// again whenever a rescan moves the generation, so a delete plan over many
/// files reads them once per root rather than once per file.
#[derive(Default)]
struct DeleteGuards {
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
        #[cfg(test)]
        if FAIL_FSYNC.get() {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        dir.sync_all()
    }

    #[cfg(test)]
    thread_local! {
        /// Fails every [`fsync`] on this thread with `EIO`, for the tests of
        /// a rename that happened but could not be made durable.
        pub static FAIL_FSYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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

        // A held `adopted` torrent survives a rescan that finds its payload
        // partial or gone, so completeness is asked of the claim table too.
        if torrentd_pool::plan::has_unplaced_files(store, infohash).map_err(|e| e.to_string())? {
            return Err(
                "its payload is no longer all present as of the last rescan; rescan once it is \
                 back and rebuild the plan"
                    .into(),
            );
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
        let claimed = torrentd_pool::plan::claimed_under(store, infohash, root_id)
            .map_err(|e| e.to_string())?;
        Ok((base, claimed))
    })
    .and_then(|(base, claimed)| {
        // The disk, asked again: anything that landed under the source since
        // the plan was built would travel with the rename unseen. `src` is
        // this base under its root, as `torrent_at` resolved it. Walked
        // outside the store, which a large directory would otherwise hold.
        match torrentd_pool::plan::unlisted_entry(src, &base, &claimed) {
            Some(entry) => Err(format!(
                "{} now holds {entry}; moving it would take that too",
                src.display(),
            )),
            None => Ok(()),
        }
    })
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
///
/// `plans` is [`unfinished_at_boot`], read before the API serves. Only those
/// plans are re-driven: one an API apply claims while the re-drive waits is
/// `applying` because that apply is running it, and re-driving it would run
/// its steps alongside it, or park it `failed` where a third apply could
/// claim it.
pub fn spawn_resume_unfinished(
    pool: Arc<PoolService>,
    source: Arc<dyn AlertSource>,
    state: Arc<StateMap>,
    work: Arc<crate::app_state::WorkGate>,
    loaded: Vec<libtorrent_safe::InfoHash>,
    plans: Vec<PlanRow>,
) -> tokio::task::JoinHandle<()> {
    let guard = work.enter();
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let stop = || work.is_cancelled();
        redrive_once_loaded(
            &pool,
            &source,
            &state,
            &loaded,
            &plans,
            REDRIVE_SETTLE_DEADLINE,
            &stop,
        );
    })
}

/// The plans a crash or a kill left mid-apply, as the boot finds them before
/// the API serves: only the boot re-drive may resume a plan, and every plan
/// `applying` after that may be an API apply's own. A store error is logged
/// and counted (`pool_plan_failures_total{kind="resume_failed"}`), and leaves
/// nothing to re-drive this boot.
pub fn unfinished_at_boot(pool: &PoolService) -> Vec<PlanRow> {
    match pool.with_store(|s| s.unfinished_plans()) {
        Ok(plans) => plans,
        Err(e) => {
            warn!(target: "torrentd::pool::apply", reason = %e, "cannot read unfinished plans");
            pool.count("pool_plan_failures_total", &[("kind", "resume_failed")]);
            Vec::new()
        }
    }
}

/// How long the boot re-drive waits for the loaded torrents to appear.
const REDRIVE_SETTLE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);

/// How many of the info-hashes that never reached the state map the
/// give-up names in its log line; the rest are only counted.
const REDRIVE_MISSING_LOGGED: usize = 16;

/// The body of [`spawn_resume_unfinished`], with the settle deadline a
/// parameter so a test can reach the give-up without waiting it out.
///
/// A give-up on the deadline counts
/// `pool_plan_failures_total{kind="redrive_timed_out"}` and names the
/// torrents still missing: the interrupted plans stay `applying`, and
/// without the count nothing but a log line would say so. A stop is a
/// shutdown, not a failure, and is not counted.
fn redrive_once_loaded(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    loaded: &[libtorrent_safe::InfoHash],
    plans: &[PlanRow],
    within: std::time::Duration,
    stop: StopCheck<'_>,
) {
    if !plans.is_empty() {
        match await_loaded(state, loaded, within, stop) {
            Settled::Loaded => {}
            Settled::Stopped => return,
            Settled::TimedOut(missing) => {
                let named: Vec<String> = missing
                    .iter()
                    .take(REDRIVE_MISSING_LOGGED)
                    .map(|ih| ih.to_hex())
                    .collect();
                warn!(
                    target: "torrentd::pool::apply",
                    missing = missing.len(),
                    infohashes = %named.join(","),
                    "not every torrent the boot loaded reached the state map in time; \
                     interrupted plans are left applying for the next boot",
                );
                pool.count("pool_plan_failures_total", &[("kind", "redrive_timed_out")]);
                return;
            }
        }
    }
    resume_unfinished(pool, source, state, plans, stop);
}

/// How [`await_loaded`] ended.
#[derive(Debug, PartialEq, Eq)]
enum Settled {
    /// Every loaded torrent is in the state map.
    Loaded,
    /// The stop latched first.
    Stopped,
    /// The deadline passed with these still missing from the state map.
    TimedOut(Vec<libtorrent_safe::InfoHash>),
}

/// Wait until every one of `loaded` is in `state`, the stop latches, or
/// `within` passes. A stop is checked before the deadline, so a shutdown
/// that lands as the deadline passes is a stop.
fn await_loaded(
    state: &StateMap,
    loaded: &[libtorrent_safe::InfoHash],
    within: std::time::Duration,
    stop: StopCheck<'_>,
) -> Settled {
    let deadline = std::time::Instant::now() + within;
    let mut pending: Vec<_> = loaded.to_vec();
    loop {
        pending.retain(|ih| !state.contains(ih));
        if pending.is_empty() {
            return Settled::Loaded;
        }
        if stop() {
            return Settled::Stopped;
        }
        if std::time::Instant::now() >= deadline {
            return Settled::TimedOut(pending);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Re-drive `plans`, the ones a crash left mid-apply ([`unfinished_at_boot`]).
///
/// A plan the re-drive refuses before claiming it — a step whose outcome is
/// unknown, or a torrent the index cannot account for — is parked `failed`,
/// where the API can apply it again or discard it. One stopped by a shutdown
/// stays `applying` for the next boot, and with `[pool] allow_mutations` off
/// none is re-driven and each stays `applying`.
pub fn resume_unfinished(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    plans: &[PlanRow],
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
    for plan in plans {
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

    /// A torrent loaded in profile `p`'s mock session, with no claims in the
    /// index, held at `save_path` with `files` (`None`: no metadata yet).
    fn unclaimed_loaded(
        save_path: &Path,
        files: Option<&[&str]>,
    ) -> (Arc<dyn AlertSource>, StateMap) {
        unclaimed_loaded_on(
            Arc::new(torrentd_engine::MockEngine::new()),
            save_path,
            files,
        )
    }

    /// [`unclaimed_loaded`], in `mock`'s session.
    fn unclaimed_loaded_on(
        mock: Arc<torrentd_engine::MockEngine>,
        save_path: &Path,
        files: Option<&[&str]>,
    ) -> (Arc<dyn AlertSource>, StateMap) {
        let hash = libtorrent_safe::InfoHash([0xee; 20]);
        let handle = mock.register_handle(hash);
        mock.set_torrent_details(
            handle,
            libtorrent_safe::TorrentDetails {
                save_path: save_path.to_string_lossy().into_owned(),
                ..torrentd_engine::MockEngine::default_details()
            },
        );
        mock.set_torrent_files(
            handle,
            files.map(|fs| {
                fs.iter()
                    .enumerate()
                    .map(|(i, f)| libtorrent_safe::TorrentFile {
                        index: i as u32,
                        path: (*f).to_owned(),
                        size: 64,
                        downloaded: 64,
                        priority: 4,
                    })
                    .collect()
            }),
        );
        let engine: Arc<dyn torrentd_engine::TorrentEngine> = mock;
        let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            torrentd_engine::ProfileId::new("p"),
            engine,
        )]));
        let state = StateMap::new();
        state.insert(
            hash,
            torrentd_engine::TorrentState::newly_added(
                handle,
                torrentd_engine::ProfileId::new("p"),
                std::time::Instant::now(),
            ),
        );
        (source, state)
    }

    /// A torrent added through the API and seeding from outside every root
    /// never gets claims, and no scan changes that. It has no file among a
    /// root's orphans, so a delete plan over that root applies.
    #[test]
    fn an_unclaimed_torrent_outside_every_root_does_not_block_a_delete_plan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let orphan = write(&root, "junk/old.bin", 64);
        let elsewhere = dir.path().join("other");
        let seeding = write(&elsewhere, "T/a.bin", 64);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);

        let scope = scope_of(&pool, plan_id);
        for files in [Some(&["T/a.bin"][..]), None] {
            let (source, state) = unclaimed_loaded(&elsewhere, files);
            check_index_accounts_for_live_state(&pool, &source, &state, &scope)
                .unwrap_or_else(|e| panic!("refused with files {files:?}: {e}"));
        }

        let (source, state) = unclaimed_loaded(&elsewhere, Some(&["T/a.bin"]));
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
        assert!(!orphan.exists(), "the orphan was not trashed");
        assert!(
            seeding.exists(),
            "the outside torrent's payload was touched"
        );
    }

    fn scope_of(pool: &PoolService, plan_id: i64) -> DeleteScope {
        DeleteScope::of(pool, &pool.with_store(|st| st.plan_steps(plan_id)).unwrap())
    }

    /// An unclaimed torrent that may hold a file under the plan's root still
    /// refuses: saved under it, saved above it with no metadata yet, holding a
    /// file there, reaching it through a symlink, or holding the same file
    /// through a hard link (as a bind mount of the root would).
    #[test]
    fn an_unclaimed_torrent_that_may_reach_the_root_still_blocks_a_delete_plan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let orphan = write(&root, "junk/old.bin", 64);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        let below = dir.path().join("below");
        std::fs::create_dir_all(&below).unwrap();
        std::os::unix::fs::symlink(root.join("junk"), below.join("junk")).unwrap();
        let aliased = dir.path().join("aliased");
        std::fs::create_dir_all(&aliased).unwrap();
        std::fs::hard_link(&orphan, aliased.join("old.bin")).unwrap();

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);

        // Each refusal names the rule that matched and the file it matched on.
        let cases: [(&Path, Option<&[&str]>, &str); 6] = [
            (&root, Some(&["T/a.bin"]), "lists T/a.bin, at "),
            (dir.path(), None, "has no metadata yet and is saved at "),
            (
                dir.path(),
                Some(&["pool/junk/old.bin"]),
                "lists pool/junk/old.bin, at ",
            ),
            (&link, Some(&["junk/old.bin"]), "lists junk/old.bin, at "),
            (&below, Some(&["junk/old.bin"]), "which a symlink leads to "),
            (
                &aliased,
                Some(&["old.bin"]),
                "the same file on disk (device and inode) as ",
            ),
        ];
        for (save_path, files, rule) in cases {
            let (source, state) = unclaimed_loaded(save_path, files);
            let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
            assert!(
                e.contains("no claims in the index")
                    && e.contains(&"ee".repeat(20))
                    && e.contains(rule),
                "{save_path:?} {files:?}: {e}"
            );
        }
        let (source, state) = unclaimed_loaded(&aliased, Some(&["old.bin"]));
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(e.contains(&orphan.display().to_string()), "{e}");
        // Above the root, but every file it lists is elsewhere.
        let (source, state) = unclaimed_loaded(dir.path(), Some(&["other/T/a.bin"]));
        check_index_accounts_for_live_state(&pool, &source, &state, &scope_of(&pool, plan_id))
            .unwrap();

        assert!(orphan.exists(), "payload was deleted against a stale index");
        let status = pool
            .with_store(|st| st.plan(plan_id))
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, torrentd_pool::model::plan_status::DRAFT);
    }

    /// A plan's scope is the roots its deletes lie under, not every root: an
    /// unclaimed torrent seeding from under another root has no file among
    /// this plan's orphans, so it does not block it.
    #[test]
    fn an_unclaimed_torrent_under_another_root_does_not_block_a_delete_plan() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("pool");
        let second = dir.path().join("second");
        let orphan = write(&first, "junk/old.bin", 64);
        let seeding = write(&second, "T/a.bin", 64);

        let mut cfg = Config::minimal_for_tests(dir.path(), true);
        cfg.pool.as_mut().unwrap().roots.push(second.clone());
        let pool = PoolService::open(&cfg).unwrap().unwrap();
        pool.scan().unwrap();
        assert_eq!(
            pool.roots()[0].1,
            first,
            "`delete_plan` plans the first root"
        );
        let plan_id = delete_plan(&pool);

        for files in [Some(&["T/a.bin"][..]), None] {
            let (source, state) = unclaimed_loaded(&second, files);
            check_index_accounts_for_live_state(&pool, &source, &state, &scope_of(&pool, plan_id))
                .unwrap_or_else(|e| panic!("refused with files {files:?}: {e}"));
        }
        let (source, state) = unclaimed_loaded(&second, Some(&["T/a.bin"]));
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
        assert!(!orphan.exists(), "the orphan was not trashed");
        assert!(seeding.exists(), "the other root's payload was touched");
    }

    /// An unclaimed torrent whose session cannot say where its files lie
    /// refuses: its profile has no session, or its session read fails.
    #[test]
    fn an_unclaimed_torrent_no_session_can_report_blocks_a_delete_plan() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, orphan, _other) = one_orphan_delete_plan(dir.path());
        let elsewhere = dir.path().join("other");

        // Held by profile `q`, which the source has no session for.
        let (source, _) = engine_and_state();
        let state = StateMap::new();
        let hash = libtorrent_safe::InfoHash([0xee; 20]);
        state.insert(
            hash,
            torrentd_engine::TorrentState::newly_added(
                torrentd_engine::TorrentHandle {
                    id: 1,
                    infohash: hash,
                },
                torrentd_engine::ProfileId::new("q"),
                std::time::Instant::now(),
            ),
        );
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(
            e.contains("no claims in the index") && e.contains("profile q, which has no session"),
            "{e}"
        );

        for op in ["torrent_details", "torrent_files"] {
            let mock = Arc::new(torrentd_engine::MockEngine::new());
            let (source, state) = unclaimed_loaded_on(mock.clone(), &elsewhere, Some(&["T/a.bin"]));
            mock.inject_error(op, torrentd_engine::EngineError::Shutdown);
            let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
            assert!(
                e.contains("no claims in the index")
                    && e.contains("could not be read from its session"),
                "{op}: {e}"
            );
        }

        assert!(orphan.exists(), "payload was deleted against a stale index");
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::DRAFT);
    }

    /// The between-steps re-check uses the plan's scope too: a torrent loaded
    /// under the root mid-plan with no claims stops the plan as failed, with
    /// the step it stopped at failed and its file untouched.
    #[test]
    fn an_unclaimed_torrent_loaded_under_the_root_mid_plan_fails_the_plan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [
            write(&root, "junk/a.bin", 64),
            write(&root, "junk/b.bin", 64),
        ];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        assert_eq!(scope_of(&pool, plan_id).targets.len(), 2);

        // The torrent's session, and its state, held back until the second step.
        let (source, held) = unclaimed_loaded(&root, Some(&["T/a.bin"]));
        let hash = libtorrent_safe::InfoHash([0xee; 20]);
        let late = held.get(&hash).unwrap();
        let state = StateMap::new();
        // Polled between steps: loads the torrent once the first step ran.
        let stop = || {
            if state.is_empty() && orphans.iter().any(|o| !o.exists()) {
                state.insert(hash, late.clone());
            }
            false
        };
        let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (1, 1, "failed"),
            "{out:?}"
        );
        assert_eq!(
            orphans.iter().filter(|o| o.exists()).count(),
            1,
            "the step after the torrent loaded still ran"
        );
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        let failed = steps
            .iter()
            .find(|s| s.status == step_status::FAILED)
            .expect("a failed step");
        assert!(
            failed.error.as_deref().is_some_and(
                |e| e.contains("no claims in the index") && e.contains("lists T/a.bin")
            ),
            "{failed:?}"
        );
    }

    /// The between-steps re-check watches change, not size: one torrent
    /// removed and another loaded under the root in the same window leaves
    /// the loaded set the size it was, and the new torrent's file must still
    /// stop the plan rather than be trashed as an orphan.
    #[test]
    fn a_torrent_swapped_in_mid_plan_aborts_the_delete() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [
            write(&root, "junk/a.bin", 64),
            write(&root, "junk/b.bin", 64),
        ];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        assert_eq!(scope_of(&pool, plan_id).targets.len(), 2);

        // `late` lists a file under the root; `leaving` lists one elsewhere,
        // so it never blocks the plan. Both are in the same session.
        let mock = Arc::new(torrentd_engine::MockEngine::new());
        let (source, held) = unclaimed_loaded_on(mock.clone(), &root, Some(&["T/a.bin"]));
        let late_hash = libtorrent_safe::InfoHash([0xee; 20]);
        let late = held.get(&late_hash).unwrap();
        let leaving_hash = libtorrent_safe::InfoHash([0xdd; 20]);
        let leaving = mock.register_handle(leaving_hash);
        mock.set_torrent_details(
            leaving,
            libtorrent_safe::TorrentDetails {
                save_path: dir.path().join("other").to_string_lossy().into_owned(),
                ..torrentd_engine::MockEngine::default_details()
            },
        );
        mock.set_torrent_files(
            leaving,
            Some(vec![libtorrent_safe::TorrentFile {
                index: 0,
                path: "T/b.bin".to_owned(),
                size: 64,
                downloaded: 64,
                priority: 4,
            }]),
        );
        let profile = torrentd_engine::ProfileId::new("p");
        let state = StateMap::new();
        state.insert(
            leaving_hash,
            torrentd_engine::TorrentState::newly_added(
                leaving,
                profile.clone(),
                std::time::Instant::now(),
            ),
        );
        // Polled between steps: once the first step ran, swaps `leaving` out
        // and `late` in, so the loaded set is one torrent before and after.
        let stop = || {
            if state.contains(&leaving_hash) && orphans.iter().any(|o| !o.exists()) {
                state
                    .remove(&leaving_hash, &profile, Some(leaving))
                    .unwrap();
                state.insert(late_hash, late.clone());
                assert_eq!(state.len(), 1);
            }
            false
        };
        let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (1, 1, "failed"),
            "{out:?}"
        );
        assert_eq!(
            orphans.iter().filter(|o| o.exists()).count(),
            1,
            "the step after the swap still ran"
        );
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        let failed = steps
            .iter()
            .find(|s| s.status == step_status::FAILED)
            .expect("a failed step");
        assert!(
            failed.error.as_deref().is_some_and(
                |e| e.contains("no claims in the index") && e.contains("lists T/a.bin")
            ),
            "{failed:?}"
        );
    }

    /// One session holding two unclaimed torrents: `late`, `0xee`, listing
    /// `T/a.bin` under `root`, and `leaving`, `0xdd`, listing a file outside
    /// it, so `leaving` alone never blocks a plan over `root`. Returns the
    /// session, `late`'s state, and `leaving`'s hash and state.
    fn late_and_leaving(
        mock: Arc<torrentd_engine::MockEngine>,
        dir: &Path,
        root: &Path,
    ) -> (
        Arc<dyn AlertSource>,
        torrentd_engine::TorrentState,
        libtorrent_safe::InfoHash,
        torrentd_engine::TorrentState,
    ) {
        let (source, held) = unclaimed_loaded_on(mock.clone(), root, Some(&["T/a.bin"]));
        let late = held.get(&libtorrent_safe::InfoHash([0xee; 20])).unwrap();
        let leaving_hash = libtorrent_safe::InfoHash([0xdd; 20]);
        let leaving = mock.register_handle(leaving_hash);
        mock.set_torrent_details(
            leaving,
            libtorrent_safe::TorrentDetails {
                save_path: dir.join("other").to_string_lossy().into_owned(),
                ..torrentd_engine::MockEngine::default_details()
            },
        );
        mock.set_torrent_files(
            leaving,
            Some(vec![libtorrent_safe::TorrentFile {
                index: 0,
                path: "T/b.bin".to_owned(),
                size: 64,
                downloaded: 64,
                priority: 4,
            }]),
        );
        let leaving_state = torrentd_engine::TorrentState::newly_added(
            leaving,
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        );
        (source, late, leaving_hash, leaving_state)
    }

    /// Swaps `leaving` out and `late` in once `held`, a session read the
    /// ownership check makes, is reached, then lets the read go on.
    fn swap_during(
        held: torrentd_engine::HeldCall,
        state: &StateMap,
        leaving: (libtorrent_safe::InfoHash, &torrentd_engine::TorrentState),
        late: &torrentd_engine::TorrentState,
    ) {
        held.wait_entered();
        state
            .remove(&leaving.0, &leaving.1.profile_id, Some(leaving.1.handle))
            .unwrap();
        state.insert(libtorrent_safe::InfoHash([0xee; 20]), late.clone());
        held.release();
    }

    /// The change counter is read before the initial ownership check, not
    /// after it: a torrent swapped in while that check reads a session is
    /// one it never saw, so the first delete step must re-check and fail
    /// rather than trash anything.
    #[test]
    fn a_torrent_swapped_in_during_the_initial_check_fails_the_first_delete() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [
            write(&root, "junk/a.bin", 64),
            write(&root, "junk/b.bin", 64),
        ];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);

        let mock = Arc::new(torrentd_engine::MockEngine::new());
        let (source, late, leaving_hash, leaving) =
            late_and_leaving(mock.clone(), dir.path(), &root);
        let state = StateMap::new();
        state.insert(leaving_hash, leaving.clone());
        // The initial check's read of `leaving`'s session is the first.
        let held = mock.hold_next("torrent_details");
        let out = std::thread::scope(|s| {
            let (st, lv, lt) = (&state, &leaving, &late);
            s.spawn(move || swap_during(held, st, (leaving_hash, lv), lt));
            apply(&pool, &source, &state, plan_id, &|| false).unwrap()
        });
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (0, 1, "failed"),
            "{out:?}"
        );
        assert!(
            orphans.iter().all(|o| o.exists()),
            "a delete ran against an ownership check the swap overtook"
        );
    }

    /// The change counter is read before each between-steps re-check, not
    /// after it: a torrent swapped in while that re-check reads a session is
    /// one it never saw, so the next delete step must re-check and fail.
    #[test]
    fn a_torrent_swapped_in_during_a_re_check_fails_the_next_delete() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [
            write(&root, "junk/a.bin", 64),
            write(&root, "junk/b.bin", 64),
            write(&root, "junk/c.bin", 64),
        ];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        assert_eq!(scope_of(&pool, plan_id).targets.len(), 3);

        let mock = Arc::new(torrentd_engine::MockEngine::new());
        let (source, late, leaving_hash, leaving) =
            late_and_leaving(mock.clone(), dir.path(), &root);
        let state = StateMap::new();
        // Polled between steps: loads `leaving` once the first step ran, so
        // the second step re-checks and reads its session, the first read.
        let stop = || {
            if state.is_empty() && orphans.iter().any(|o| !o.exists()) {
                state.insert(leaving_hash, leaving.clone());
            }
            false
        };
        let held = mock.hold_next("torrent_details");
        let out = std::thread::scope(|s| {
            let (st, lv, lt) = (&state, &leaving, &late);
            s.spawn(move || swap_during(held, st, (leaving_hash, lv), lt));
            apply(&pool, &source, &state, plan_id, &stop).unwrap()
        });
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (2, 1, "failed"),
            "{out:?}"
        );
        assert_eq!(
            orphans.iter().filter(|o| o.exists()).count(),
            1,
            "the step after the swap still ran"
        );
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        let failed = steps
            .iter()
            .find(|s| s.status == step_status::FAILED)
            .expect("a failed step");
        assert!(
            failed.error.as_deref().is_some_and(
                |e| e.contains("no claims in the index") && e.contains("lists T/a.bin")
            ),
            "{failed:?}"
        );
    }

    /// A delete plan over one orphan, `pool/junk/old.bin`, in an index at
    /// `dir`, and a raw connection to that index for a test to hold or rig.
    fn one_orphan_delete_plan(
        dir: &Path,
    ) -> (Arc<PoolService>, i64, PathBuf, rusqlite::Connection) {
        let root = dir.join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let orphan = write(&root, "junk/old.bin", 64);
        let pool = service(dir, true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(steps.len(), 1, "{steps:?}");
        let other = rusqlite::Connection::open(Config::minimal_for_tests(dir, true).pool_db_path())
            .unwrap();
        (pool, plan_id, orphan, other)
    }

    /// Another process holding the index's write lock, as a CLI `pool scan`
    /// beside the daemon did for its whole run, made every journal write fail
    /// while the steps still ran. The plan must be refused before its claim,
    /// with nothing moved, and apply once the lock is gone.
    #[test]
    fn a_delete_plan_applied_while_another_writer_holds_the_index_moves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, orphan, other) = one_orphan_delete_plan(dir.path());
        other.execute_batch("BEGIN IMMEDIATE").unwrap();

        let (source, state) = engine_and_state();
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(
            orphan.exists(),
            "a file moved while the journal was locked: {e}"
        );
        other.execute_batch("ROLLBACK").unwrap();
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::DRAFT, "claimed under the lock");

        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
        assert!(!orphan.exists());
    }

    /// A step whose `in_progress` write fails is not run: running it moved a
    /// file the journal still called `pending`. The plan ends `failed` with
    /// the step `failed`, so applying it again runs the step afresh.
    #[test]
    fn a_step_the_journal_cannot_record_as_started_is_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, orphan, other) = one_orphan_delete_plan(dir.path());
        // After the claim, so only the step's own journal write fails.
        other
            .execute_batch(
                "CREATE TRIGGER journal_refuses BEFORE UPDATE OF status ON plan_step
                 WHEN NEW.status = 'in_progress'
                 BEGIN SELECT RAISE(ABORT, 'journal unavailable'); END;",
            )
            .unwrap();

        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (0, 1, "failed"),
            "{out:?}"
        );
        assert!(orphan.exists(), "the step ran unjournalled");
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(steps[0].status, step_status::FAILED);
        let why = steps[0].error.clone().unwrap_or_default();
        assert!(
            why.contains("not started") && why.contains("journal unavailable"),
            "{why}"
        );
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::FAILED);

        other.execute_batch("DROP TRIGGER journal_refuses").unwrap();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
        assert!(!orphan.exists());
    }

    /// The statuses of `plan_id`'s steps, in order.
    fn statuses(pool: &PoolService, plan_id: i64) -> Vec<String> {
        pool.with_store(|st| st.plan_steps(plan_id))
            .unwrap()
            .into_iter()
            .map(|s| s.status)
            .collect()
    }

    /// A delete plan over 2,000 files journals in batches: the writer commits
    /// O(steps / batch) times, not twice per step (4,000), and every step ends
    /// `done`. Not 10,000: each step's own trash move fsyncs two directories,
    /// so that many cost most of a minute on a disk, for the same proof.
    #[test]
    fn a_large_delete_plan_journals_a_batch_of_steps_per_commit() {
        const FILES: usize = 2_000;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        for i in 0..FILES {
            write(&root, &format!("junk/d{:02}/f{i:05}.bin", i % 20), 1);
        }
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        assert_eq!(statuses(&pool, plan_id).len(), FILES);

        let commits = pool.with_store(|st| st.count_commits());
        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (FILES, 0, "applied"),
            "{out:?}"
        );
        let commits = commits.load(std::sync::atomic::Ordering::Relaxed);
        // Two per batch, the claim, and the plan's final status.
        let bound = 2 * FILES.div_ceil(JOURNAL_BATCH) as u64 + 2;
        assert!(
            commits <= bound && commits < FILES as u64 / 10,
            "{commits} commits for {FILES} steps; at most {bound} expected"
        );
        assert!(statuses(&pool, plan_id)
            .iter()
            .all(|s| s == step_status::DONE));
        assert!(!root.join("junk/d00/f00000.bin").exists());
    }

    /// A shutdown inside a batch stops between two of its steps: the steps it
    /// ran are `done`, the ones it did not reach go back to `pending` rather
    /// than staying `in_progress`, and the boot re-drive finishes the plan.
    #[test]
    fn a_shutdown_inside_a_batch_leaves_the_steps_it_did_not_reach_pending() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [
            write(&root, "junk/a.bin", 8),
            write(&root, "junk/b.bin", 8),
            write(&root, "junk/c.bin", 8),
        ];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);

        let (source, state) = engine_and_state();
        // Asked before each step: says stop once the first file is gone.
        let stop = || orphans.iter().any(|o| !o.exists());
        let out = apply(&pool, &source, &state, plan_id, &stop).unwrap();
        assert_eq!((out.done, out.status.as_str()), (1, "applying"), "{out:?}");
        assert_eq!(statuses(&pool, plan_id), ["done", "pending", "pending"]);
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::APPLYING);

        let out = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap();
        assert_eq!(
            (out.done, out.skipped, out.status.as_str()),
            (2, 1, "applied"),
            "{out:?}"
        );
        assert!(orphans.iter().all(|o| !o.exists()));
    }

    /// A step failing inside a batch stops the plan there: the steps before
    /// it are `done`, it is `failed`, and the ones after go back to `pending`
    /// with their files untouched.
    #[test]
    fn a_step_failing_inside_a_batch_leaves_the_steps_after_it_pending() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [
            write(&root, "junk/a.bin", 8),
            write(&root, "junk/b.bin", 8),
            write(&root, "junk/c.bin", 8),
        ];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert!(steps[1].src.ends_with("junk/b.bin"), "{steps:?}");
        // Changed after the scan, so its delete is refused.
        std::fs::write(&orphans[1], vec![1u8; 16]).unwrap();

        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (1, 1, "failed"),
            "{out:?}"
        );
        assert_eq!(statuses(&pool, plan_id), ["done", "failed", "pending"]);
        assert!(!orphans[0].exists());
        assert!(orphans[1].exists() && orphans[2].exists());
    }

    /// A crash inside a batch leaves every step of it `in_progress`, and the
    /// re-drive refuses the plan with a message counting all of them.
    #[test]
    fn a_crash_inside_a_batch_refuses_the_plan_counting_every_unknown_step() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        for name in ["a", "b", "c"] {
            write(&root, &format!("junk/{name}.bin"), 8);
        }
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        pool.with_store_mut(|st| {
            st.set_plan_status(plan_id, plan_status::APPLYING, None)?;
            st.set_steps_status(
                plan_id,
                &[
                    (0, step_status::IN_PROGRESS, None),
                    (1, step_status::IN_PROGRESS, None),
                    (2, step_status::IN_PROGRESS, None),
                ],
            )
        })
        .unwrap();

        let (source, state) = engine_and_state();
        let e = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap_err();
        assert!(
            e.contains("step 0 (delete_file) was interrupted")
                && e.contains("2 more of its steps")
                && e.contains(&format!("/v1/pool/plans/{plan_id}/steps")),
            "{e}"
        );
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::FAILED);
    }

    /// A second apply while the first is mid-batch sees the first's own
    /// `in_progress` steps. It is refused without touching the plan: marking
    /// it `failed` would make it claimable, and a third apply would run the
    /// same steps alongside the first.
    #[test]
    fn a_racing_apply_leaves_a_running_plan_applying() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [write(&root, "junk/a.bin", 8), write(&root, "junk/b.bin", 8)];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        // The first apply: claimed, and its batch journalled.
        assert!(pool
            .with_store(|st| st.claim_plan_for_apply(plan_id, false))
            .unwrap());
        pool.with_store_mut(|st| {
            st.set_steps_status(
                plan_id,
                &[
                    (0, step_status::IN_PROGRESS, None),
                    (1, step_status::IN_PROGRESS, None),
                ],
            )
        })
        .unwrap();

        let (source, state) = engine_and_state();
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert_eq!(e, "plan is applying and cannot be applied right now");
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::APPLYING);
        assert!(
            !pool
                .with_store(|st| st.claim_plan_for_apply(plan_id, false))
                .unwrap(),
            "a third apply claimed the running plan"
        );
        assert_eq!(statuses(&pool, plan_id), ["in_progress", "in_progress"]);
        assert!(orphans.iter().all(|o| o.exists()));
    }

    /// The boot re-drive runs alongside the API. A plan an API apply claims
    /// after the boot read its unfinished plans is that apply's: re-driving
    /// it would park it `failed` on the apply's own `in_progress` steps,
    /// where a third apply could claim it and run them again.
    #[test]
    fn the_boot_redrive_leaves_a_plan_the_api_claimed_after_boot_alone() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [write(&root, "junk/a.bin", 8), write(&root, "junk/b.bin", 8)];
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        // Nothing was mid-apply at boot.
        let plans = unfinished_at_boot(&pool);
        assert!(plans.is_empty(), "{plans:?}");

        // While the re-drive waits, an API apply claims the plan and
        // journals its batch.
        assert!(pool
            .with_store(|st| st.claim_plan_for_apply(plan_id, false))
            .unwrap());
        pool.with_store_mut(|st| {
            st.set_steps_status(
                plan_id,
                &[
                    (0, step_status::IN_PROGRESS, None),
                    (1, step_status::IN_PROGRESS, None),
                ],
            )
        })
        .unwrap();

        let (source, state) = engine_and_state();
        redrive_once_loaded(
            &pool,
            &source,
            &state,
            &[],
            &plans,
            std::time::Duration::ZERO,
            &|| false,
        );

        assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);
        assert!(
            !pool
                .with_store(|st| st.claim_plan_for_apply(plan_id, false))
                .unwrap(),
            "a third apply claimed the running plan"
        );
        assert_eq!(statuses(&pool, plan_id), ["in_progress", "in_progress"]);
        assert!(orphans.iter().all(|o| o.exists()));
    }

    /// The boot re-drive refusing a plan before claiming it — here because a
    /// loaded torrent the index has never claimed may hold files under the
    /// root — parks it `failed`, where the API can apply or discard it. Left
    /// `applying`, the API could do neither, and every boot refused it again.
    #[test]
    fn a_re_drive_refused_before_its_claim_parks_the_plan_failed() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, orphan, _other) = one_orphan_delete_plan(dir.path());
        pool.with_store(|st| st.set_plan_status(plan_id, plan_status::APPLYING, None))
            .unwrap();

        // Held by profile `q`, which the source has no session for.
        let (source, _) = engine_and_state();
        let state = StateMap::new();
        let hash = libtorrent_safe::InfoHash([0xee; 20]);
        state.insert(
            hash,
            torrentd_engine::TorrentState::newly_added(
                torrentd_engine::TorrentHandle {
                    id: 1,
                    infohash: hash,
                },
                torrentd_engine::ProfileId::new("q"),
                std::time::Instant::now(),
            ),
        );
        resume_unfinished(&pool, &source, &state, &unfinished_at_boot(&pool), &|| {
            false
        });

        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::FAILED);
        assert!(orphan.exists(), "the refused re-drive ran nothing");
        assert_eq!(statuses(&pool, plan_id), ["pending"]);
        assert_eq!(
            pool.with_store_mut(|st| st.delete_plan(plan_id)).unwrap(),
            torrentd_pool::store::PlanDelete::Deleted,
            "the API can now discard it"
        );
    }

    /// The child half of
    /// [`a_kill_9_inside_a_delete_batch_leaves_its_steps_in_progress`]: applies
    /// the plan, and once the batch's first step has moved its file, says so
    /// and waits there, between two steps of one batch, to be killed.
    #[test]
    #[ignore = "run only as the crash test's child process"]
    fn delete_batch_crash_child() {
        use std::io::Write as _;
        let Some(dir) = std::env::var_os("TORRENTD_POOL_CRASH_DIR") else {
            return;
        };
        let plan_id: i64 = std::env::var("TORRENTD_POOL_CRASH_PLAN")
            .unwrap()
            .parse()
            .unwrap();
        let first = PathBuf::from(std::env::var_os("TORRENTD_POOL_CRASH_FIRST").unwrap());
        let pool = service(Path::new(&dir), true);
        let (source, state) = engine_and_state();
        let stop = || {
            if !first.exists() {
                let mut out = std::io::stdout().lock();
                writeln!(out, "inside the batch").unwrap();
                out.flush().unwrap();
                // The parent never writes; this returns only if it is gone.
                let _ = std::io::stdin().read_line(&mut String::new());
                std::process::exit(3);
            }
            false
        };
        let _ = apply(&pool, &source, &state, plan_id, &stop);
        panic!("the batch ran to its end without being killed");
    }

    /// `kill -9` between two steps of one journal batch, then a fresh open of
    /// the same index: every step of the batch is `in_progress`, the one that
    /// ran and the ones that had not alike, the plan is still `applying`, and
    /// the re-drive refuses it rather than re-running or skipping any of
    /// them. [`a_crash_inside_a_batch_refuses_the_plan_counting_every_unknown_step`]
    /// writes that journal by hand; this one has a real process die into it.
    #[test]
    fn a_kill_9_inside_a_delete_batch_leaves_its_steps_in_progress() {
        use std::io::BufRead as _;
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Command;
        use std::process::Stdio;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let orphans = [
            write(&root, "junk/a.bin", 8),
            write(&root, "junk/b.bin", 8),
            write(&root, "junk/c.bin", 8),
        ];
        let (plan_id, first) = {
            let pool = service(dir.path(), true);
            pool.scan().unwrap();
            let plan_id = delete_plan(&pool);
            let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
            assert_eq!(steps.len(), 3, "{steps:?}");
            (plan_id, PathBuf::from(&steps[0].src))
        };
        assert_eq!(first, orphans[0]);

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pool_apply::tests::delete_batch_crash_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TORRENTD_POOL_CRASH_DIR", dir.path())
            .env("TORRENTD_POOL_CRASH_PLAN", plan_id.to_string())
            .env("TORRENTD_POOL_CRASH_FIRST", &first)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Read on a thread of its own, so a child that never gets there fails
        // the test within a bound rather than hanging it.
        let (tx, rx) = std::sync::mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                // libtest's `test NAME ... ` precedes it on the same line.
                if line.is_ok_and(|l| l.ends_with("inside the batch")) {
                    let _ = tx.send(());
                    return;
                }
            }
        });
        let reached = rx.recv_timeout(std::time::Duration::from_secs(60));
        if reached.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the child never reached the inside of the batch: {reached:?}");
        }
        child.kill().unwrap(); // SIGKILL
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");

        let pool = service(dir.path(), true);
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::APPLYING);
        assert_eq!(
            statuses(&pool, plan_id),
            ["in_progress", "in_progress", "in_progress"],
            "the batch's start was journalled in one commit before its first step",
        );
        assert!(!orphans[0].exists(), "the first step ran before the kill");
        assert!(orphans[1].exists() && orphans[2].exists());

        let (source, state) = engine_and_state();
        let e = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap_err();
        assert!(
            e.contains("step 0 (delete_file) was interrupted") && e.contains("2 more of its steps"),
            "{e}"
        );
        let plan = pool.with_store(|st| st.plan(plan_id)).unwrap().unwrap();
        assert_eq!(plan.status, plan_status::FAILED);
        assert!(
            orphans[1].exists() && orphans[2].exists(),
            "the refused re-drive ran nothing"
        );
    }

    /// A registry over `dir` assigning `ih` to profile `p`, handed to `pool`
    /// as the daemon hands it the boot's.
    fn assign(pool: &PoolService, dir: &Path, ih: &str) {
        let registry = Arc::new(torrentd_engine::AssignmentRegistry::new_empty(
            dir.join("registry.db"),
        ));
        registry
            .assign(
                libtorrent_safe::InfoHash::from_hex(ih).unwrap(),
                torrentd_engine::ProfileId::new("p"),
            )
            .unwrap();
        pool.set_registry(registry);
    }

    /// A torrent added through the API, with its payload under a root and its
    /// `.torrent` outside the library, whose profile failed at boot: the
    /// registry assigns it, no session holds it, and the index has never
    /// placed it. Its payload reads as orphans, and the plan must refuse.
    #[test]
    fn applying_refuses_while_a_registered_unloaded_torrent_is_absent_from_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let victim = write(&root, "api/feature.bin", 64);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        assign(&pool, dir.path(), &"cd".repeat(20));

        // Nothing is loaded: the profile that owns the torrent is down.
        let (source, state) = engine_and_state();
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(e.contains("no claims in the index"), "got {e}");
        assert!(e.contains(&"cd".repeat(20)), "got {e}");
        assert!(victim.exists(), "an owned torrent's payload was trashed");
        let status = pool
            .with_store(|st| st.plan(plan_id))
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, torrentd_pool::model::plan_status::DRAFT);
    }

    /// A queued adoption is owned too, before any session holds it.
    #[test]
    fn applying_refuses_while_a_queued_adoption_is_absent_from_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let victim = write(&root, "queued/feature.bin", 64);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let ih = "ef".repeat(20);
        pool.with_store(|st| {
            st.enqueue_verify(&torrentd_pool::VerifyQueueRow {
                infohash: ih.clone(),
                profile: "p".into(),
                torrent_path: dir.path().join("t.torrent"),
                save_path: root.join("queued"),
                owner_recorded: false,
                trackers: vec![],
            })
        })
        .unwrap();

        let (source, state) = engine_and_state();
        let e = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert!(e.contains(&ih), "got {e}");
        assert!(victim.exists(), "a queued adoption's payload was trashed");
    }

    /// A one-step relocate plan moving `ih`'s payload to `new` under the root.
    fn relocate_plan(pool: &PoolService, ih: &str) -> i64 {
        let spec = torrentd_pool::plan::PlanSpec::Relocate {
            infohash: ih.to_owned(),
            dest_root_id: pool.roots()[0].0,
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
        plan_id
    }

    /// Index `T` with its payload at `old/T/a.bin`, matched, and mark it
    /// adopted as an adoption into a profile would.
    fn adopted_at_old(pool: &PoolService, root: &Path, ih: &str) {
        add_and_rematch(pool, ih, "T", Some(&root.join("old")), &[("T/a.bin", 100)]);
        pool.with_store(|s| {
            let (root_id, base) = s.adoption_base(ih)?.expect("matched with a base");
            s.set_adoption(
                ih,
                AdoptionState::Adopted,
                Some(root_id),
                Some(&base),
                None,
                None,
                None,
            )
        })
        .unwrap();
    }

    /// An adopted torrent whose profile is down is still that profile's: its
    /// resume data and recorded save path name the source, so torrentd must
    /// not rename the directory under them.
    #[test]
    fn relocating_refuses_an_adopted_torrent_its_profile_did_not_load() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let src_file = write(&root, "old/T/a.bin", 100);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        adopted_at_old(&pool, &root, &ih);
        let plan_id = relocate_plan(&pool, &ih);
        assign(&pool, dir.path(), &ih);

        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(steps[0].status, step_status::FAILED);
        let why = steps[0].error.clone().unwrap_or_default();
        assert!(
            why.contains("the registry assigns it to profile p"),
            "{why}"
        );
        assert!(src_file.exists(), "the payload was renamed");
        assert!(!root.join("new").exists());
        let base = pool.with_store(|s| s.adoption_base(&ih)).unwrap();
        assert_eq!(base.map(|(_, b)| b), Some("old".to_owned()));
    }

    /// The verify queue's persisted row names the source as the save path it
    /// adds the torrent at, so a queued adoption is refused the same way.
    #[test]
    fn relocating_refuses_a_queued_adoption() {
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
        let plan_id = relocate_plan(&pool, &ih);
        pool.with_store(|st| {
            st.enqueue_verify(&torrentd_pool::VerifyQueueRow {
                infohash: ih.clone(),
                profile: "p".into(),
                torrent_path: dir.path().join("t.torrent"),
                save_path: root.join("old"),
                owner_recorded: false,
                trackers: vec![],
            })
        })
        .unwrap();

        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!(out.status, "failed", "{out:?}");
        let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
            .error
            .clone()
            .unwrap_or_default();
        assert!(why.contains("verify queue"), "{why}");
        assert!(src_file.exists(), "the payload was renamed");
    }

    /// A `matched` torrent nothing owns is still moved by torrentd itself.
    #[test]
    fn relocating_moves_an_unowned_matched_torrent() {
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
        let plan_id = relocate_plan(&pool, &ih);
        // A registry that assigns some other torrent is no owner of this one.
        assign(&pool, dir.path(), &"cd".repeat(20));

        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (1, "applied"), "{out:?}");
        assert!(!src_file.exists());
        assert!(root.join("new/T/a.bin").exists());
    }

    /// A matched torrent nothing owns at `root/old/T/a.bin`, and a one-step
    /// relocate plan moving it to `root/new`. Returns the plan and the file.
    fn unowned_relocate(dir: &Path) -> (Arc<PoolService>, i64, PathBuf) {
        let root = dir.join("pool");
        let src_file = write(&root, "old/T/a.bin", 100);
        let pool = service(dir, true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        add_and_rematch(
            &pool,
            &ih,
            "T",
            Some(&root.join("old")),
            &[("T/a.bin", 100)],
        );
        let plan_id = relocate_plan(&pool, &ih);
        (pool, plan_id, src_file)
    }

    /// Build [`unowned_relocate`] in a fresh directory, load what `load`
    /// returns for that directory, and apply the plan, expecting its one
    /// step to fail with an error containing each of `needles` and the
    /// source to be left in place.
    fn assert_relocate_refused(
        load: impl FnOnce(&Path) -> (Arc<dyn AlertSource>, StateMap),
        needles: &[&str],
    ) {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, src_file) = unowned_relocate(dir.path());
        let (source, state) = load(dir.path());
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
            .error
            .clone()
            .unwrap_or_default();
        for needle in needles {
            assert!(why.contains(needle), "{needle:?} not in {why}");
        }
        assert!(src_file.exists(), "the payload was renamed: {why}");
        assert!(!dir.path().join("pool/new").exists(), "{why}");
    }

    /// The refusal a step that failed outright carries; panics on success or
    /// on an unknown outcome.
    fn failed(r: Result<(), StepFailure>) -> String {
        match r {
            Err(StepFailure::Failed(e)) => e,
            other => panic!("expected a failed step, got {other:?}"),
        }
    }

    /// The planner walks the source directory: a file the scan never saw
    /// would travel with the rename without appearing in the plan.
    #[test]
    fn planning_a_relocate_refuses_a_file_the_index_does_not_list() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        write(&root, "old/T/a.bin", 100);
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
        write(&root, "old/T/since-the-scan.bin", 5);

        let spec = torrentd_pool::plan::PlanSpec::Relocate {
            infohash: ih,
            dest_root_id: pool.roots()[0].0,
            dest_rel: "new".into(),
        };
        let built = pool
            .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
            .unwrap();
        let why = built
            .expect_err("the plan was built over an unlisted file")
            .0;
        assert!(
            why.contains("old/T/since-the-scan.bin") && why.contains("does not list"),
            "{why}"
        );
    }

    /// The executor walks it again: whatever appears under the source after
    /// the plan was built refuses the rename, which moves nothing.
    #[test]
    fn relocating_refuses_a_file_that_appeared_since_planning() {
        assert_relocate_refused(
            |dir| {
                write(&dir.join("pool"), "old/T/late.bin", 5);
                engine_and_state()
            },
            &["old/T/late.bin", "does not list", "would take that too"],
        );
    }

    #[test]
    fn relocating_refuses_a_symlink_under_the_source() {
        assert_relocate_refused(
            |dir| {
                std::os::unix::fs::symlink(dir, dir.join("pool/old/T/link")).unwrap();
                engine_and_state()
            },
            &["old/T/link, a symlink"],
        );
    }

    #[test]
    fn relocating_refuses_a_name_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt as _;
        assert_relocate_refused(
            |dir| {
                let name = std::ffi::OsStr::from_bytes(b"\xff.bin");
                std::fs::write(dir.join("pool/old/T").join(name), b"x").unwrap();
                engine_and_state()
            },
            &["is not UTF-8"],
        );
    }

    /// A subdirectory that cannot be listed may hold anything. Root lists
    /// it regardless, so there the case cannot be built and is not asserted.
    #[test]
    fn relocating_refuses_a_subdirectory_that_cannot_be_listed() {
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, src_file) = unowned_relocate(dir.path());
        let sealed = dir.path().join("pool/old/T/sealed");
        std::fs::create_dir(&sealed).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let (source, state) = engine_and_state();
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
            .error
            .clone()
            .unwrap_or_default();
        assert!(why.contains("cannot be listed"), "{why}");
        assert!(src_file.exists(), "the payload was renamed: {why}");
    }

    /// The rename itself refuses to replace what is at the destination, an
    /// empty directory included, and leaves the source where it was.
    #[test]
    fn moving_a_directory_never_replaces_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let src_file = write(dir.path(), "src/a.bin", 3);
        std::fs::create_dir(dir.path().join("dst")).unwrap();
        let e = failed(move_directory(
            &dir.path().join("src"),
            &dir.path().join("dst"),
        ));
        assert!(e.contains("already exists"), "{e}");
        assert!(src_file.exists());
        assert_eq!(
            std::fs::read_dir(dir.path().join("dst")).unwrap().count(),
            0
        );
    }

    /// An fsync that fails after the rename is not a step that did not
    /// happen: the payload is at the destination, so the step stays
    /// `in_progress` for a human and the adoption base follows the payload.
    #[test]
    fn a_relocate_whose_fsync_fails_after_the_rename_is_an_unknown_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, src_file) = unowned_relocate(dir.path());
        let (source, state) = engine_and_state();
        fsat::FAIL_FSYNC.set(true);
        let out = apply(&pool, &source, &state, plan_id, &|| false);
        fsat::FAIL_FSYNC.set(false);
        let out = out.unwrap();
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (0, 1, "failed"),
            "{out:?}"
        );
        let step = &pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0];
        assert_eq!(step.status, step_status::IN_PROGRESS);
        let why = step.error.clone().unwrap_or_default();
        assert!(
            why.contains("outcome unknown") && why.contains("fsync"),
            "{why}"
        );
        assert!(!src_file.exists());
        assert!(dir.path().join("pool/new/T/a.bin").exists());
        let base = pool
            .with_store(|s| s.adoption_base(&"ab".repeat(20)))
            .unwrap();
        assert_eq!(base.map(|(_, b)| b), Some("new".to_owned()));
    }

    /// Likewise a delete step: the file is in the trash, not where it was.
    #[test]
    fn a_delete_whose_fsync_fails_after_the_move_is_an_unknown_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, orphan, _other) = one_orphan_delete_plan(dir.path());
        let (source, state) = engine_and_state();
        fsat::FAIL_FSYNC.set(true);
        let out = apply(&pool, &source, &state, plan_id, &|| false);
        fsat::FAIL_FSYNC.set(false);
        let out = out.unwrap();
        assert_eq!(
            (out.done, out.failed, out.status.as_str()),
            (0, 1, "failed"),
            "{out:?}"
        );
        let step = &pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0];
        assert_eq!(step.status, step_status::IN_PROGRESS);
        let why = step.error.clone().unwrap_or_default();
        assert!(
            why.contains("outcome unknown") && why.contains("fsync"),
            "{why}"
        );
        assert!(!orphan.exists());
        let trash = dir.path().join("pool").join(torrentd_pool::plan::TRASH_DIR);
        let buckets: Vec<_> = std::fs::read_dir(&trash).unwrap().collect();
        assert_eq!(buckets.len(), 1);
        assert!(buckets[0]
            .as_ref()
            .unwrap()
            .path()
            .join("junk/old.bin")
            .exists());
    }

    /// A torrent added through the API over the unloaded torrent's files has
    /// no claims, so only its session shows it serves them: renaming the
    /// directory would pull them from under it.
    #[test]
    fn relocating_refuses_an_unloaded_torrent_a_loaded_one_serves_files_from() {
        assert_relocate_refused(
            |dir| unclaimed_loaded(&dir.join("pool/old"), Some(&["T/a.bin"])),
            &[&"ee".repeat(20), "serves", "T/a.bin", "nothing was moved"],
        );
    }

    /// The same, reached through a symlink: a save path that is a symlink to
    /// the source's parent, and one whose directory below it is a symlink
    /// into the source.
    #[test]
    fn relocating_refuses_an_unloaded_torrent_a_loaded_one_serves_through_a_symlink() {
        assert_relocate_refused(
            |dir| {
                let link = dir.join("link");
                std::os::unix::fs::symlink(dir.join("pool/old"), &link).unwrap();
                unclaimed_loaded(&link, Some(&["T/a.bin"]))
            },
            &[&"ee".repeat(20), "link/T/a.bin"],
        );
        assert_relocate_refused(
            |dir| {
                let below = dir.join("below");
                std::fs::create_dir_all(&below).unwrap();
                std::os::unix::fs::symlink(dir.join("pool/old/T"), below.join("X")).unwrap();
                unclaimed_loaded(&below, Some(&["X/a.bin"]))
            },
            &[&"ee".repeat(20), "below/X/a.bin"],
        );
        // A file it lists but has not written yet resolves through its
        // parent, the symlinked directory into the source.
        assert_relocate_refused(
            |dir| {
                let below = dir.join("below");
                std::fs::create_dir_all(&below).unwrap();
                std::os::unix::fs::symlink(dir.join("pool/old/T"), below.join("X")).unwrap();
                unclaimed_loaded(&below, Some(&["X/unwritten.bin"]))
            },
            &[&"ee".repeat(20), "below/X/unwritten.bin"],
        );
    }

    /// A loaded torrent with no metadata yet could write any file under its
    /// save path, so one saved above the source refuses the move, and so
    /// does one saved below it; so does one whose session cannot be read.
    #[test]
    fn relocating_refuses_an_unloaded_torrent_a_loaded_one_may_serve_from() {
        assert_relocate_refused(
            |dir| unclaimed_loaded(&dir.join("pool"), None),
            &[&"ee".repeat(20), "serves"],
        );
        assert_relocate_refused(
            |dir| unclaimed_loaded(&dir.join("pool/old/T"), None),
            &[&"ee".repeat(20), "serves", "pool/old/T from under"],
        );
        for op in ["torrent_details", "torrent_files"] {
            assert_relocate_refused(
                |dir| {
                    let mock = Arc::new(torrentd_engine::MockEngine::new());
                    let loaded =
                        unclaimed_loaded_on(mock.clone(), &dir.join("other"), Some(&["a.bin"]));
                    mock.inject_error(op, torrentd_engine::EngineError::Shutdown);
                    loaded
                },
                &["could not be read from its session", "cannot be ruled out"],
            );
        }
        assert_relocate_refused(
            |_| {
                let (source, _) = engine_and_state();
                let state = StateMap::new();
                let hash = libtorrent_safe::InfoHash([0xee; 20]);
                state.insert(
                    hash,
                    torrentd_engine::TorrentState::newly_added(
                        torrentd_engine::TorrentHandle {
                            id: 1,
                            infohash: hash,
                        },
                        torrentd_engine::ProfileId::new("q"),
                        std::time::Instant::now(),
                    ),
                );
                (source, state)
            },
            &["profile q, which has no session", "cannot be ruled out"],
        );
    }

    /// A loaded torrent serving from elsewhere does not block the move, with
    /// or without its metadata, nor does one in a sibling directory whose
    /// name merely starts with the source's.
    #[test]
    fn relocating_moves_an_unloaded_torrent_beside_a_loaded_one_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, plan_id, src_file) = unowned_relocate(dir.path());
        // The step renames the torrent's base directory, `pool/old`.
        let src = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
            .src
            .clone();
        assert_eq!(Path::new(&src), dir.path().join("pool/old"));
        let elsewhere = dir.path().join("other");
        write(&elsewhere, "U/b.bin", 64);
        let sibling = dir.path().join("pool/older");
        write(&sibling, "T/a.bin", 64);
        for save_path in [&elsewhere, &sibling] {
            for files in [Some(&["U/b.bin", "T/a.bin"][..]), None] {
                let (source, state) = unclaimed_loaded(save_path, files);
                refuse_live_files_under(&source, &state, Path::new(&src))
                    .unwrap_or_else(|e| panic!("refused {save_path:?} with {files:?}: {e}"));
            }
        }
        let (source, state) = unclaimed_loaded(&elsewhere, Some(&["U/b.bin"]));
        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(
            (out.done, out.status.as_str()),
            (1, "applied"),
            "{out:?} {:?}",
            steps[0].error,
        );
        assert!(!src_file.exists());
        assert!(dir.path().join("pool/new/T/a.bin").exists());
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

        // The boot re-drive is what owns a plan a crash left `applying`; an
        // API apply cannot tell it from one running now, and leaves it be.
        let (source, state) = engine_and_state();
        let e = apply_inner(&pool, &source, &state, plan_id, true, &|| false).unwrap_err();
        assert!(
            e.contains("interrupted and its outcome is unknown"),
            "got {e}"
        );
        // The remedy the message gives is the one the docs give, and it is
        // the only one there is: applying again refuses the same way.
        assert_names_the_unknown_outcome_remedy(&e);
        let again = apply(&pool, &source, &state, plan_id, &|| false).unwrap_err();
        assert_eq!(again, e);

        // Parked in `failed`, not stranded in `applying`: an operator can now
        // discard it, which `delete_plan` refuses for `applying`.
        let status = pool
            .with_store(|st| st.plan(plan_id))
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, torrentd_pool::model::plan_status::FAILED);
        assert_eq!(
            pool.with_store_mut(|st| st.delete_plan(plan_id)).unwrap(),
            torrentd_pool::store::PlanDelete::Deleted
        );
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
        resume_unfinished(&pool, &source, &state, &unfinished_at_boot(&pool), &|| {
            false
        });
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
        let plan_id = delete_plan(&pool);
        pool.with_store(|s| s.claim_plan_for_apply(plan_id, false))
            .unwrap();
        let plans = unfinished_at_boot(&pool);
        let (source, state) = engine_and_state();
        let work: Arc<crate::app_state::WorkGate> = Arc::default();

        // The re-drive's first act is reading the plan, so it blocks here.
        let (release, holder) = hold_the_store(&pool);
        let task = spawn_resume_unfinished(
            Arc::clone(&pool),
            source,
            Arc::new(state),
            Arc::clone(&work),
            Vec::new(),
            plans,
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
            unfinished_at_boot(&pool),
        )
        .await
        .unwrap();
        let (status, steps) = plan_state(&pool, plan_id);
        assert_eq!(status, plan_status::APPLYING, "a latched gate stops it");
        assert_eq!(steps, vec![step_status::PENDING, step_status::PENDING]);

        spawn_resume_unfinished(
            Arc::clone(&pool),
            source,
            state,
            Arc::default(),
            Vec::new(),
            unfinished_at_boot(&pool),
        )
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
            unfinished_at_boot(&pool),
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

        assert_eq!(
            await_loaded(&state, &[], std::time::Duration::ZERO, &|| false),
            Settled::Loaded,
        );
        assert_eq!(
            await_loaded(&state, &[pending], std::time::Duration::ZERO, &|| false),
            Settled::TimedOut(vec![pending]),
        );
        assert_eq!(
            await_loaded(&state, &[pending], std::time::Duration::ZERO, &|| true),
            Settled::Stopped,
            "a stop as the deadline passes is a stop",
        );
    }

    #[test]
    fn a_redrive_that_times_out_waiting_for_the_state_map_is_counted() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "a/one.bin", 16);
        let pool = service(dir.path(), true);
        let metrics = Arc::new(crate::metrics_sink::PromSink::new());
        pool.set_metrics(metrics.clone());
        pool.scan().unwrap();
        let plan_id = delete_plan(&pool);
        let (source, state) = engine_and_state();
        pool.with_store(|s| s.claim_plan_for_apply(plan_id, false))
            .unwrap();
        let pending = libtorrent_safe::InfoHash([9; 20]);
        let timed_out = "pool_plan_failures_total{kind=\"redrive_timed_out\"} 1";

        // A shutdown during the wait gives up uncounted.
        redrive_once_loaded(
            &pool,
            &source,
            &state,
            &[pending],
            &unfinished_at_boot(&pool),
            std::time::Duration::from_secs(600),
            &|| true,
        );
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(!text.contains(timed_out), "{text}");
        assert_eq!(plan_state(&pool, plan_id).0, plan_status::APPLYING);

        // The deadline passing with a loaded torrent still missing counts.
        redrive_once_loaded(
            &pool,
            &source,
            &state,
            &[pending],
            &unfinished_at_boot(&pool),
            std::time::Duration::ZERO,
            &|| false,
        );
        let text = String::from_utf8(metrics.render()).unwrap();
        assert!(text.contains(timed_out), "{text}");
        assert!(!text.contains("kind=\"resume_failed\"} 1"), "{text}");
        assert_eq!(
            plan_state(&pool, plan_id).0,
            plan_status::APPLYING,
            "the plan is left for the next boot",
        );
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
        resume_unfinished(&pool, &source, &state, &unfinished_at_boot(&pool), &stop);

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

        let e = failed(delete_file(&pool, &f, 1, "1-0", &mut Default::default()));
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
        let e = failed(delete_file(
            &pool,
            &sneaked,
            1,
            "1-0",
            &mut Default::default(),
        ));
        assert!(e.contains("never sanctioned"), "got {e}");
        assert!(sneaked.exists());

        let outside = dir.path().join("elsewhere.bin");
        std::fs::write(&outside, b"x").unwrap();
        let e = failed(delete_file(
            &pool,
            &outside,
            1,
            "1-0",
            &mut Default::default(),
        ));
        assert!(e.contains("outside every managed root"), "got {e}");
        assert!(outside.exists());

        // A traversal component walks back out of the root once resolved.
        let escaping = root.join("misc/../../elsewhere.bin");
        let e = failed(delete_file(
            &pool,
            &escaping,
            1,
            "1-0",
            &mut Default::default(),
        ));
        assert!(e.contains("outside every managed root"), "got {e}");
        assert!(outside.exists());
    }

    /// A second root that reaches claimed bytes by another path — a hard link
    /// here, standing in for a bind mount of the first root — indexes them as
    /// an orphan there, since claims are by path. The delete planner leaves
    /// it out, and the delete step compares the file's identity with every
    /// claimed file's and refuses; an ordinary orphan beside it still goes to
    /// the trash.
    #[test]
    fn deleting_refuses_a_file_that_is_a_claimed_file_under_another_root() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("pool");
        let second = dir.path().join("alias");
        let claimed_file = write(&first, "T/a.bin", 16);
        std::fs::create_dir_all(second.join("T")).unwrap();
        let alias = second.join("T/a.bin");
        std::fs::hard_link(&claimed_file, &alias).unwrap();
        let orphan = write(&second, "T/extra.bin", 8);

        let mut cfg = Config::minimal_for_tests(dir.path(), true);
        cfg.pool.as_mut().unwrap().roots.push(second.clone());
        let pool = PoolService::open(&cfg).unwrap().unwrap();
        pool.scan().unwrap();
        let root_id = |p: &Path| pool.roots().iter().find(|(_, r)| r == p).unwrap().0;
        let (first_id, second_id) = (root_id(&first), root_id(&second));
        claimed(&pool, dir.path(), &"ab".repeat(20), "T/a.bin");
        assert_eq!(
            pool.roots()[0].0,
            first_id,
            "`claimed` claims under the first root"
        );
        let unclaimed = pool
            .with_store(|s| s.is_orphan(second_id, "T/a.bin"))
            .unwrap();
        assert!(unclaimed, "by path, the alias reads as an orphan");

        // The planner leaves the alias out, so a plan never holds a step the
        // executor would refuse halfway through.
        let spec = torrentd_pool::plan::PlanSpec::DeleteOrphans {
            root_id: second_id,
            prefix: String::new(),
        };
        let steps = pool
            .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
            .unwrap()
            .expect("plan builds");
        let srcs: Vec<_> = steps.iter().map(|s| PathBuf::from(&s.src)).collect();
        assert_eq!(srcs, vec![orphan.clone()], "only the unrelated orphan");

        // The executor still refuses it, for a plan built before the claim.
        let mut guards = DeleteGuards::default();
        let e = failed(delete_file(&pool, &alias, 1, "1-0", &mut guards));
        assert!(
            e.contains("same file") && e.contains("a torrent claims"),
            "got {e}"
        );
        assert!(alias.exists() && claimed_file.exists());

        delete_file(&pool, &orphan, 1, "1-0", &mut guards).expect("an unrelated orphan is deleted");
        assert!(!orphan.exists());
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

    /// A relocate of `T` from `old` to `new`, with `T` loaded in profile
    /// `p`'s mock session at `held_at`. `move_storage` fails fast, so a step
    /// that reaches it ends with the engine's error rather than a ten-minute
    /// wait for an alert the mock never delivers.
    fn loaded_relocate(
        pool: &PoolService,
        root: &Path,
        ih: &str,
        held_at: &Path,
    ) -> (
        i64,
        Arc<torrentd_engine::MockEngine>,
        Arc<dyn AlertSource>,
        StateMap,
    ) {
        add_and_rematch(pool, ih, "T", Some(&root.join("old")), &[("T/a.bin", 100)]);
        let plan_id = relocate_plan(pool, ih);
        let mock = Arc::new(torrentd_engine::MockEngine::new());
        mock.inject_error("move_storage", torrentd_engine::EngineError::Shutdown);
        let hash = libtorrent_safe::InfoHash::from_hex(ih).unwrap();
        let handle = mock.register_handle(hash);
        mock.set_torrent_details(
            handle,
            libtorrent_safe::TorrentDetails {
                save_path: held_at.to_string_lossy().into_owned(),
                ..torrentd_engine::MockEngine::default_details()
            },
        );
        let engine: Arc<dyn torrentd_engine::TorrentEngine> = mock.clone();
        let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            torrentd_engine::ProfileId::new("p"),
            engine,
        )]));
        let state = StateMap::new();
        state.insert(
            hash,
            torrentd_engine::TorrentState::newly_added(
                handle,
                torrentd_engine::ProfileId::new("p"),
                std::time::Instant::now(),
            ),
        );
        (plan_id, mock, source, state)
    }

    fn moved_storage(mock: &torrentd_engine::MockEngine) -> bool {
        mock.calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::MoveStorage { .. }))
    }

    /// `move_storage` moves from where the session holds the torrent, and
    /// reports done even when nothing was there. A session holding it away
    /// from the plan's source refuses the step before the move, naming both,
    /// and leaves the index where the payload is.
    #[test]
    fn a_session_holding_the_torrent_elsewhere_refuses_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let src_file = write(&root, "old/T/a.bin", 100);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        let elsewhere = root.join("elsewhere");
        let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &elsewhere);

        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(steps[0].status, step_status::FAILED);
        let why = steps[0].error.clone().unwrap_or_default();
        assert!(
            why.contains(&*elsewhere.to_string_lossy())
                && why.contains(&*root.join("old").to_string_lossy()),
            "{why}"
        );
        assert!(
            !moved_storage(&mock),
            "move_storage was called: {:?}",
            mock.calls()
        );
        assert!(src_file.exists());
        let base = pool.with_store(|s| s.adoption_base(&ih)).unwrap();
        assert_eq!(base.map(|(_, b)| b), Some("old".to_owned()));
    }

    /// A session that cannot say where it holds the torrent cannot be shown to
    /// hold it at the source, so the step is refused before the move rather
    /// than trusting `move_storage` to start from the right place.
    #[test]
    fn a_session_that_cannot_report_its_save_path_refuses_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let src_file = write(&root, "old/T/a.bin", 100);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &root.join("old"));
        mock.inject_error("torrent_details", torrentd_engine::EngineError::Shutdown);

        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        let steps = pool.with_store(|st| st.plan_steps(plan_id)).unwrap();
        assert_eq!(steps[0].status, step_status::FAILED);
        let why = steps[0].error.clone().unwrap_or_default();
        assert!(
            why.contains("could not read where the session holds torrent"),
            "{why}"
        );
        assert!(
            !moved_storage(&mock),
            "move_storage was called: {:?}",
            mock.calls()
        );
        assert!(src_file.exists());
        let base = pool.with_store(|s| s.adoption_base(&ih)).unwrap();
        assert_eq!(base.map(|(_, b)| b), Some("old".to_owned()));
    }

    /// The same directory spelled with a trailing separator is the source, and
    /// the step goes on to the move.
    #[test]
    fn a_session_holding_the_torrent_at_the_source_reaches_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        write(&root, "old/T/a.bin", 100);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        let held_at = PathBuf::from(format!("{}/", root.join("old").display()));
        let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &held_at);

        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!(out.status, "failed", "{out:?}");
        assert!(
            moved_storage(&mock),
            "move_storage was not called: {:?}",
            mock.calls()
        );
    }

    /// A session at the source with none of the payload there has nothing to
    /// move, and libtorrent would report that nothing as done.
    #[test]
    fn a_source_holding_none_of_the_payload_refuses_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let src_file = write(&root, "old/T/a.bin", 100);
        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        let ih = "ab".repeat(20);
        let (plan_id, mock, source, state) = loaded_relocate(&pool, &root, &ih, &root.join("old"));
        std::fs::remove_file(&src_file).unwrap();

        let out = apply(&pool, &source, &state, plan_id, &|| false).unwrap();
        assert_eq!((out.done, out.status.as_str()), (0, "failed"), "{out:?}");
        let why = pool.with_store(|st| st.plan_steps(plan_id)).unwrap()[0]
            .error
            .clone()
            .unwrap_or_default();
        assert!(why.contains("none of torrent"), "{why}");
        assert!(
            !moved_storage(&mock),
            "move_storage was called: {:?}",
            mock.calls()
        );
    }

    /// A move libtorrent reported done is confirmed at the destination: a file
    /// that was at the source and is not there is an unknown outcome.
    #[test]
    fn a_file_missing_at_the_destination_after_a_move_is_an_unknown_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("old");
        let dst = dir.path().join("new");
        let dst_str = dst.to_string_lossy();
        let present = vec!["T/a.bin".to_owned()];

        match arrived(&present, &src, &dst_str) {
            Err(StepFailure::Unknown(e)) => assert!(e.contains("T/a.bin"), "{e}"),
            Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
            Ok(()) => panic!("a file missing at the destination was recorded as moved"),
        }

        write(&dst, "T/a.bin", 100);
        arrived(&present, &src, &dst_str).unwrap_or_else(|_| panic!("the file arrived"));
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
        match await_storage_move_within(
            &state,
            &hash,
            "/w",
            "/x",
            std::time::Duration::ZERO,
            STORAGE_MOVE_STOP_GRACE,
            &|| false,
        ) {
            Err(StepFailure::Unknown(e)) => {
                assert!(e.contains("outcome unknown"), "{e}");
                assert_names_the_unknown_outcome_remedy(&e);
            }
            Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
            Ok(p) => panic!("reported moved to {p}"),
        }
    }

    /// A message for a step left `in_progress` names what an operator can
    /// actually do, which is what `docs/operations.md`'s After a crash
    /// documents: look, rescan, discard and rebuild. Never a resume, which
    /// every later apply and re-drive refuses.
    fn assert_names_the_unknown_outcome_remedy(e: &str) {
        for needle in [
            "cannot be applied or resumed again",
            "POST /v1/pool/scan",
            "DELETE /v1/pool/plans/{plan_id}",
            "build a new one",
        ] {
            assert!(e.contains(needle), "{needle:?} missing from: {e}");
        }
        assert!(!e.contains("before resuming"), "invites a resume: {e}");
    }

    /// A state map holding one torrent, at `hash`, with no move reported.
    fn state_with(hash: libtorrent_safe::InfoHash) -> StateMap {
        let state = StateMap::new();
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
        state.update(&hash, |s| s.storage_move = Some(StorageMove::Pending));
        state
    }

    #[test]
    fn a_shutdown_cuts_off_a_storage_move_still_copying_as_unknown() {
        // A cross-device copy outlasts the shutdown's pool drain. Waiting on
        // regardless left the step `in_progress` with nothing saying why;
        // the latch now cuts the wait off, long before the 600 s deadline,
        // with the reason recorded.
        let hash = libtorrent_safe::InfoHash([4; 20]);
        let state = state_with(hash);
        let started = std::time::Instant::now();
        match await_storage_move_within(
            &state,
            &hash,
            "/pool/old/T",
            "/pool/new/T",
            STORAGE_MOVE_DEADLINE,
            std::time::Duration::ZERO,
            &|| true,
        ) {
            Err(StepFailure::Unknown(e)) => {
                assert!(
                    e.contains("shut down while libtorrent was still moving"),
                    "{e}"
                );
                assert!(
                    e.contains("/pool/old/T") && e.contains("/pool/new/T"),
                    "{e}"
                );
                // The move may still finish after the cut-off and delete the
                // source, so the remedy never presumes which copy is whole.
                assert!(
                    e.contains("holds the complete payload before removing anything"),
                    "{e}"
                );
                assert!(!e.contains("remove what does not belong"), "{e}");
                assert_names_the_unknown_outcome_remedy(&e);
            }
            Err(StepFailure::Failed(e)) => panic!("recorded as failed: {e}"),
            Ok(p) => panic!("reported moved to {p}"),
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_storage_move_that_landed_is_recorded_done_even_under_a_shutdown() {
        // The verdict is read before the latch: a move libtorrent finished is
        // done, and cutting it off would park a plan whose step happened.
        let hash = libtorrent_safe::InfoHash([5; 20]);
        let state = state_with(hash);
        state.update(&hash, |s| {
            s.storage_move = Some(StorageMove::Moved {
                path: "/pool/new/T".into(),
            })
        });
        let moved = await_storage_move_within(
            &state,
            &hash,
            "/pool/old/T",
            "/pool/new/T",
            STORAGE_MOVE_DEADLINE,
            std::time::Duration::ZERO,
            &|| true,
        );
        assert!(matches!(moved, Ok(ref p) if p == "/pool/new/T"));
    }

    #[test]
    fn a_shutdown_gives_a_storage_move_its_grace_before_cutting_it_off() {
        // The latch is set as the server sees the stop, well before teardown
        // closes the session: a move that lands inside the grace is done.
        let hash = libtorrent_safe::InfoHash([6; 20]);
        let state = std::sync::Arc::new(state_with(hash));
        let landing = {
            let state = state.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(300));
                state.update(&hash, |s| {
                    s.storage_move = Some(StorageMove::Moved {
                        path: "/pool/new/T".into(),
                    })
                });
            })
        };
        let moved = await_storage_move_within(
            &state,
            &hash,
            "/pool/old/T",
            "/pool/new/T",
            STORAGE_MOVE_DEADLINE,
            std::time::Duration::from_secs(30),
            &|| true,
        );
        landing.join().unwrap();
        assert!(matches!(moved, Ok(ref p) if p == "/pool/new/T"));
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

        // A destination past the 1 023 bytes the shim once cut a moved-to
        // path at is recorded whole, not as a prefix naming another
        // directory.
        let (deep, _) = long_rel_path();
        record_new_base(&pool, &t.infohash, &root.join(&deep));
        let base = pool.with_store(|s| s.adoption_base(&t.infohash)).unwrap();
        assert_eq!(base, Some((root_id, deep)));
    }

    #[test]
    fn deleting_moves_the_file_into_the_trash_and_a_rescan_ignores_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        std::fs::create_dir_all(&root).unwrap();
        let f = write(&root, "misc/old.bin", 32);

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        delete_file(&pool, &f, 42, "42-1700000000", &mut Default::default()).unwrap();

        assert!(!f.exists());
        let trashed = root.join(".torrentd-trash/42-1700000000/misc/old.bin");
        assert_eq!(std::fs::read(&trashed).unwrap(), vec![7u8; 32]);

        pool.scan().unwrap();
        let root_id = pool.roots()[0].0;
        let orphans = pool.with_store(|st| st.orphan_files(root_id, "")).unwrap();
        assert!(
            orphans.is_empty(),
            "the trash is never indexed: {orphans:?}"
        );
    }

    /// A delete plan over the whole root, created at `created_at`.
    fn delete_plan_at(pool: &PoolService, created_at: i64) -> i64 {
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
            .with_store(|st| st.create_plan("delete_orphans", "{}", created_at))
            .unwrap();
        pool.with_store_mut(|st| st.add_plan_steps(id, &steps))
            .unwrap();
        id
    }

    /// Every file under `dir`, relative to it.
    fn files_under(dir: &Path) -> Vec<String> {
        fn walk(base: &Path, at: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(at).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else {
                    out.push(p.strip_prefix(base).unwrap().display().to_string());
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    /// Discard a delete plan once it has applied, then build another: the
    /// second plan gets an id of its own, so its files go to a trash
    /// directory of their own and emptying either never touches the other.
    #[test]
    fn a_plan_built_after_a_discarded_one_trashes_into_its_own_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        write(&root, "a/one.bin", 16);
        let pool = service(dir.path(), true);
        let (source, state) = engine_and_state();
        pool.scan().unwrap();

        let first = delete_plan_at(&pool, 0);
        let out = apply(&pool, &source, &state, first, &|| false).unwrap();
        assert_eq!(out.status, "applied", "{out:?}");
        assert_eq!(
            pool.with_store_mut(|st| st.delete_plan(first)).unwrap(),
            torrentd_pool::store::PlanDelete::Deleted
        );

        write(&root, "a/two.bin", 16);
        pool.scan().unwrap();
        let second = delete_plan_at(&pool, 0);
        assert_ne!(
            first, second,
            "the discarded plan's id was handed out again"
        );
        let out = apply(&pool, &source, &state, second, &|| false).unwrap();
        assert_eq!(out.status, "applied", "{out:?}");

        let trash = root.join(torrentd_pool::plan::TRASH_DIR);
        assert_eq!(
            files_under(&trash.join(plan_trash_bucket(first, 0))),
            ["a/one.bin"]
        );
        assert_eq!(
            files_under(&trash.join(plan_trash_bucket(second, 0))),
            ["a/two.bin"]
        );
    }

    /// Restoring an older `pool.db` takes the plan id sequence back with it,
    /// so the next plan repeats the id of one whose trash is still on disk.
    /// Its trash directory is still its own.
    #[test]
    fn a_plan_that_repeats_an_id_after_a_restore_trashes_into_its_own_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pool");
        let db = dir.path().join("pool.db");
        let backup = dir.path().join("pool.db.backup");
        write(&root, "a/one.bin", 16);
        let (source, state) = engine_and_state();

        let pool = service(dir.path(), true);
        pool.scan().unwrap();
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
            .unwrap();
        let first = delete_plan_at(&pool, 1_700_000_000);
        let out = apply(&pool, &source, &state, first, &|| false).unwrap();
        assert_eq!(out.status, "applied", "{out:?}");
        drop(pool);

        // The restore: the backup, taken before the first plan existed,
        // replaces the index and its write-ahead log.
        for side in ["pool.db-wal", "pool.db-shm"] {
            let _ = std::fs::remove_file(dir.path().join(side));
        }
        std::fs::rename(&backup, &db).unwrap();

        let pool = service(dir.path(), true);
        write(&root, "a/two.bin", 16);
        pool.scan().unwrap();
        let second = delete_plan_at(&pool, 1_700_000_500);
        assert_eq!(second, first, "the restore took the id sequence back");
        let out = apply(&pool, &source, &state, second, &|| false).unwrap();
        assert_eq!(out.status, "applied", "{out:?}");

        let trash = root.join(torrentd_pool::plan::TRASH_DIR);
        assert_eq!(
            files_under(&trash.join(plan_trash_bucket(first, 1_700_000_000))),
            ["a/one.bin"]
        );
        assert_eq!(
            files_under(&trash.join(plan_trash_bucket(second, 1_700_000_500))),
            ["a/two.bin"]
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

        fsat::FAIL_FSYNC.set(true);
        let out = trash_torrent_payload(&payload, "torrent-x-1");
        fsat::FAIL_FSYNC.set(false);
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

    /// A torrent-relative path past the 1 023 bytes the shim once cut file
    /// paths at, and the directory it lies in: six 200-byte directories
    /// under `T`, each within the 255-byte file-name limit.
    fn long_rel_path() -> (String, String) {
        let dirs: Vec<String> = (0..6).map(|i| format!("{i}{}", "d".repeat(199))).collect();
        let dir = format!("T/{}", dirs.join("/"));
        let rel = format!("{dir}/leaf.bin");
        assert!(rel.len() > 1_023, "{}", rel.len());
        (dir, rel)
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

        assert!(delete_file(&pool, &f, 1, "1-0", &mut Default::default()).is_err());
        assert!(outside.join("victim.bin").exists());
    }
}
