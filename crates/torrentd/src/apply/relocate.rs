//! The relocate step: an adopted torrent's payload moved through
//! libtorrent, an unadopted directory renamed, each re-checked against the
//! index and the disk as they are when the step runs.

use std::path::Path;
use std::sync::Arc;

use torrentd_engine::AlertSource;
use torrentd_engine::MoveFlags;
use torrentd_engine::StateMap;
use torrentd_engine::StorageMove;
use torrentd_pool::model::PlanStepRow;
use torrentd_pool::AdoptionState;
use tracing::info;
use tracing::warn;

use super::fsat;
use super::index_location;
use super::unknown_outcome_remedy;
use super::StepFailure;
use super::StopCheck;
use crate::live_torrent::read_live_torrent;
use crate::live_torrent::LiveReadError;
use crate::pool_service::PoolService;

#[cfg(test)]
mod tests;

/// Relocate an adopted torrent by asking libtorrent to move its storage,
/// waiting for libtorrent's verdict until `stop` says to give up on it.
pub(super) fn move_torrent(
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
pub(super) fn same_directory(a: &Path, b: &Path) -> bool {
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
    let Some((root_id, _, rel)) = index_location(pool, dir) else {
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
        let listed = torrentd_pool::plan::listed_under(store, infohash, root_id, &base)
            .map_err(|e| e.to_string())?;
        Ok((base, listed))
    })
    .and_then(|(base, listed)| {
        // The disk, asked again: anything that landed under the source since
        // the plan was built would travel with the rename unseen. `src` is
        // this base under its root, as `torrent_at` resolved it. Walked
        // outside the store, which a large directory would otherwise hold.
        match torrentd_pool::plan::unlisted_entry(src, &base, &listed) {
            Some(entry) => Err(format!(
                "{} now holds {entry}; moving it would take that too",
                src.display(),
            )),
            None => Ok(()),
        }
    })
}
