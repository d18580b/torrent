//! The boot re-drive of the plans a crash or a kill left mid-apply.

use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::StateMap;
use torrentd_pool::model::PlanRow;
use tracing::error;
use tracing::warn;

use super::apply_inner;
use super::StopCheck;
use super::SHUTTING_DOWN;
use crate::pool_service::PoolService;

#[cfg(test)]
mod tests;

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
