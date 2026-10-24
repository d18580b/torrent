//! Executing mutation plans.
//!
//! The planner decided *what*; this decides *how* and does it. Three rules
//! shape everything here:
//!
//! * **The journal is written before the action.** Every step is marked in the
//!   database, attempted, then marked again, a batch of up to
//!   [`JOURNAL_BATCH`](executor::JOURNAL_BATCH) delete steps per commit. A stop between batches leaves
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
//!
//! The executor ([`executor`]) claims a plan and journals its steps; the
//! ownership guard ([`ownership_guard`]) is the precondition a delete plan
//! rests on; [`relocate`] and [`delete`] are the two step kinds, made of the
//! directory-relative calls in [`fsat`]; [`recovery`] re-drives at boot what
//! a crash left mid-apply.

use std::path::Path;
use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::StateMap;

use crate::pool_service::PoolService;

mod delete;
mod executor;
mod fsat;
mod ownership_guard;
mod recovery;
mod relocate;

pub(crate) use delete::move_into_trash;
use executor::apply_inner;
#[cfg(test)]
pub(crate) use fsat::FAIL_FSYNC;
pub use recovery::spawn_resume_unfinished;
pub use recovery::unfinished_at_boot;
#[cfg(test)]
pub(crate) mod test_support;

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
/// function's to take: [`recovery::resume_unfinished`] re-drives it at boot.
pub fn apply(
    pool: &PoolService,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    plan_id: i64,
    stop: StopCheck<'_>,
) -> Result<ApplyOutcome, String> {
    apply_inner(pool, source, state, plan_id, false, stop)
}

/// What `apply_inner` answers when a shutdown stops it before the claim. The
/// boot re-drive tells a stop from a failure by it.
const SHUTTING_DOWN: &str = "the daemon is shutting down; apply the plan again once it is back";

/// How a step did not succeed.
#[derive(Debug)]
pub(crate) enum StepFailure {
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

/// The managed root `path` is under, its id, and `path` relative to it in
/// the index's form: as the scan indexes it, `/`-separated with a `\` in a
/// name kept literally, since a Unix file name may hold one. Turned into a
/// `/`, a name holding one would look up a path the index has no row for.
pub(crate) fn index_location(
    pool: &PoolService,
    path: &Path,
) -> Option<(i64, std::path::PathBuf, String)> {
    pool.roots().iter().find_map(|(id, root)| {
        path.strip_prefix(root)
            .ok()
            .map(|r| (*id, root.clone(), r.to_string_lossy().into_owned()))
    })
}
