//! Claiming a plan and running its steps, journalled before each action.

use std::path::Path;
use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::StateMap;
use torrentd_pool::model::ops;
use torrentd_pool::model::plan_status;
use torrentd_pool::model::step_status;
use torrentd_pool::model::PlanStepRow;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::delete::delete_file;
use super::delete::plan_trash_bucket;
use super::delete::DeleteGuards;
use super::ownership_guard::check_index_accounts_for_live_state;
use super::ownership_guard::ownership_generation;
use super::ownership_guard::DeleteScope;
use super::relocate::move_torrent;
use super::unknown_outcome_remedy;
use super::ApplyOutcome;
use super::StepFailure;
use super::StopCheck;
use super::SHUTTING_DOWN;
use crate::pool_service::PoolService;

#[cfg(test)]
mod tests;

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

pub(super) fn apply_inner(
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

    let now = crate::pool_service::now_secs();
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
