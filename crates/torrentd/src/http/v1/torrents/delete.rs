//! Removing: `DELETE /v1/torrents/{infohash}`, and the payload with it when
//! asked.

use std::fmt;
use std::path::Path as FsPath;
use std::sync::Arc;

use kynos::prelude::*;
use kynos::security::auth::Scoped;
use libtorrent_safe::InfoHash;
use torrentd_engine::removal::delete_removed_files;
use torrentd_engine::removal::Tombstone;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentHandle;
use tracing::warn;

use super::model::TorrentPath;
use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Write;
use crate::http::v1::common::blocking;
use crate::http::v1::common::internal;
use crate::http::v1::Torrents;

/// How to remove a torrent.
#[derive(Schema, QueryParams)]
pub struct DeleteTorrentQuery {
    /// Also move the payload into the trash of the managed root it lies in
    /// (`<root>/.torrentd-trash/torrent-<infohash>-<unix seconds>/`). Needs
    /// `[pool] allow_mutations` and `confirm`; `false` when absent.
    pub delete_files: Option<bool>,
    /// With `delete_files=true`: this torrent's infohash, repeated, to confirm
    /// that its payload is the one to delete. Ignored otherwise.
    pub confirm: Option<String>,
}

torrent_error! {
    /// Why a torrent was not removed.
    pub enum DeleteTorrentError {
        /// `delete_files=true` without `[pool] allow_mutations`.
        #[error("deleting payload requires a [pool] section with `allow_mutations = true`")]
        #[problem(status = 403, title = "Mutations are disabled")]
        MutationsDisabled,
        /// `delete_files=true` without `confirm` repeating the infohash.
        #[error(
            "deleting payload needs `confirm` set to this torrent's infohash; re-send with \
             `confirm={infohash}` once it is the torrent whose payload should go"
        )]
        #[problem(status = 422, title = "The delete is not confirmed")]
        DeleteUnconfirmed { infohash: String },
        /// No torrent with this infohash is assigned to any profile.
        #[error("no torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The torrent is still being added to its session.
        #[error(
            "this torrent is still being added to its session; retry the delete once its phase \
             is no longer \"unknown\""
        )]
        #[problem(status = 409, title = "The torrent is still being added")]
        TorrentAdding,
        /// `delete_files=true` for a torrent whose files the pool index has
        /// another torrent claiming too — a cross-seed, or a conflict — or
        /// one of whose files another torrent a session holds lists at the
        /// same path, however it was added. Deleting them would take the
        /// other torrent's payload with them.
        #[error("{detail}")]
        #[problem(status = 409, title = "The payload is shared")]
        PayloadShared { detail: String },
        /// `delete_files=true` for a torrent whose payload cannot be proven
        /// safe to move to the trash: a file outside every managed root, one
        /// the index does not record this torrent claiming, one that changed
        /// since the scan, or another assigned torrent whose files no session
        /// can report to compare against; or the torrent itself is one no
        /// session holds: the boot left it unloaded, or a delete that did not
        /// move its payload removed it from its session and could not clear
        /// its assignment. Nothing was changed.
        #[error("{detail}")]
        #[problem(status = 409, title = "The payload cannot be trashed")]
        PayloadUntrashable { detail: String },
        /// A plain delete of a torrent the boot left unloaded while its
        /// profile's stores still hold its resume file or `.torrent`: they
        /// are what the next boot loads it from. `detail` names them.
        /// Nothing was changed.
        #[error("{detail}")]
        #[problem(status = 409, title = "The torrent did not load")]
        TorrentUnloaded { detail: String },
        /// `delete_files=true` for a torrent whose profile has no running
        /// session: its payload is reachable only through one.
        #[error("{detail}")]
        #[problem(status = 409, title = "The profile is unavailable")]
        ProfileUnavailable {
            detail: String,
            #[problem(extension)]
            profile_status: &'static str,
        },
        /// The session or a store could not complete the removal; `detail`
        /// says which half and whether to retry.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}

/// Remove a torrent.
///
/// Removes it from its session and clears its assignment, so the infohash can
/// be added again. Its resume file, `.torrent` and recorded save path are
/// deleted before the answer, so a restart after a `204` does not load it
/// again. `delete_files=true` also moves the payload into the trash
/// of the managed root it lies in, never unlinking it, and needs `[pool]
/// allow_mutations` and `confirm` repeating the infohash. It is refused,
/// changing nothing, unless every file is under a managed root, claimed by
/// this torrent alone in the pool index, listed at the same path by no other
/// torrent any session holds, and unchanged since the scan that indexed it;
/// while another assigned torrent is held by no session, its files cannot be
/// compared, and that refuses too. A torrent whose profile has no running
/// session, or that the boot left unloaded, is cleared from the daemon's
/// records alone (`delete_files` is refused there: nothing can reach the
/// payload). One the boot left unloaded whose resume file or `.torrent` its
/// profile's stores still hold is `409 torrent-unloaded`, changing nothing:
/// those files are what the next boot loads it from. A torrent still being
/// added is `409 torrent-adding`; retry once it lists a phase other than
/// `unknown`.
#[kynos::delete("/torrents/{infohash}", tag = Torrents)]
pub async fn delete_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
    Query(q): Query<DeleteTorrentQuery>,
) -> Result<NoContent, DeleteTorrentError> {
    let ih = p.infohash.get();
    let delete_files = q.delete_files.unwrap_or(false);
    // Erasing payload is a pool mutation wherever it is spelled. This used to
    // reach `delete_files` with no plan, no confirmation and no overlap check
    // — a single request with a larger blast radius than everything the
    // planner guards.
    //
    // Refused when `[pool]` is absent too. Without a pool there is no index to
    // reason about what the payload is, which makes an unreviewable delete
    // less defensible rather than more; allowing it there would leave the
    // operation wide open on exactly the deployments with the least context.
    if delete_files && s.pool.as_ref().is_none_or(|p| !p.allow_mutations()) {
        return Err(DeleteTorrentError::MutationsDisabled);
    }
    // One flag is too little to stand between a request and a payload: the
    // infohash has to be said twice, so a client that sets `delete_files` on
    // the wrong call, or a script that templates it in, is refused.
    if delete_files
        && !q
            .confirm
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case(&ih.to_hex()))
    {
        return Err(DeleteTorrentError::DeleteUnconfirmed {
            infohash: ih.to_hex(),
        });
    }
    // The planner refuses to delete a file two torrents claim, and this is the
    // same deletion spelled differently: libtorrent removes every file in this
    // torrent's list, including the ones a cross-seeded torrent is serving.
    if delete_files {
        if let Some(pool) = s.pool.as_ref() {
            let hex = ih.to_hex();
            // Off the reader: the claims are the last committed index's, and
            // the writer would make a refusal wait out a whole running scan.
            // A scan can commit a new co-claimant after this, so
            // `payload_to_trash` asks again, in the read its proof makes,
            // before anything is moved; this one only answers the common
            // refusal early.
            refuse_co_claimants(pool.with_reader(|st| st.co_claimants(&hex)))?;
        }
    }
    let profile = s
        .registry
        .lookup(&ih)
        .ok_or(DeleteTorrentError::TorrentNotFound)?;
    let Some(engine) = s.source.engine_for(&profile) else {
        return clear_sessionless(&s, &ih, &profile, delete_files);
    };
    // An earlier delete removed the torrent from its session and then could
    // not clear the assignment, and answered asking for this retry. The
    // session's removal alert drops the state-map entry, so the match below
    // would answer `409 torrent-adding` for a torrent no add is in flight
    // for; and before the alert lands, removing the handle a second time is
    // not the work left. The assignment, and the index owner the failed
    // attempt never reached, are all there is to clear.
    let removed = s.removed_unassigned.lock().get(&ih).copied();
    if let Some(payload_deleted) = removed {
        if delete_files && !payload_deleted {
            // A 204 would say files went to the trash that the delete which
            // removed the torrent did not move, and no session holds it now
            // to reach them.
            return Err(DeleteTorrentError::PayloadUntrashable {
                detail: format!(
                    "torrent {ih} was already removed from its session by a delete that did not \
                     move its payload to the trash, and no session holds it now to reach it. \
                     Nothing was changed; retry without `delete_files` to clear its assignment \
                     and leave the files where they are."
                ),
            });
        }
        clear_assignment(&s, &ih, &profile, payload_deleted)?;
        return Ok(NoContent);
    }
    // A missing state-map entry means one of two things, and only one of them
    // may be cleared.
    //
    // An entry the startup scans left unloaded — its resume add failed, or a
    // delete whose registry write failed left it in the registry for the next
    // boot — is held by no session, so the assignment is all there is to
    // clear. Answering 404 there would leave it uncleared by any means but
    // hand-editing `registry.db`.
    //
    // Any other entry was assigned in this process, by the add or adopt
    // path, and handed to a session whose `AddTorrent` alert has not been
    // processed yet: the session holds the torrent and the state map does not
    // know it. Clearing the assignment there would answer 204 without
    // removing anything, and the torrent would go on seeding unassigned, free
    // to be added to a second profile. There is no handle to remove it by
    // until the alert lands, so the delete is refused as a conflict to retry.
    match s.state.get(&ih) {
        Some(st) => {
            // The await is a cancellation point: a client that disconnects
            // drops this handler while the blocking task runs on. A removal
            // whose assignment clear ran after the await would leave the
            // infohash assigned to a torrent no session holds, and every later
            // delete a `409 torrent-adding`, so the clear runs in the task.
            let settler = Arc::clone(&s);
            blocking(move || {
                // Proven before the torrent leaves its session, so a refusal
                // changes nothing and the torrent goes on seeding.
                let payload = if delete_files {
                    Some(payload_to_trash(&settler, &engine, &ih, st.handle)?)
                } else {
                    None
                };
                // Written before the torrent leaves its session, so the
                // delete is durable from the moment it is acted on: a crash,
                // or a file below that will not delete, leaves a tombstone
                // the next boot honours by deleting the files rather than
                // loading the torrent. Until the assignment is cleared the
                // boot reads it as a delete that never answered, and keeps
                // the torrent.
                let tombstoned = settler.resume.write_tombstone(&profile, &ih);
                if let Err(e) = &tombstoned {
                    count_cleanup_error(&settler, &ih, &profile, "tombstone", e);
                }
                // Recorded before the session is asked, so the alert that
                // settles it finds the record: the assignment is cleared below
                // as soon as the session accepts, and an add of the same
                // info-hash can land before that alert, whose handler must
                // then leave the new torrent's files and entry alone.
                settler.state.begin_removal(&profile, st.handle);
                // libtorrent never deletes the files itself: they go to the
                // trash below, where an operator can take them back.
                //
                // A tombstone left by a refusal is not cleared: a second
                // `DELETE` running alongside may have written it, and its
                // removal still needs it. One left standing is harmless, as
                // the assignment is kept, and the boot spends it.
                engine.remove_torrent(st.handle, false).map_err(|e| {
                    settler.state.abandon_removal(&profile, st.handle);
                    DeleteTorrentError::Internal {
                        detail: internal("removing the torrent from its session", e),
                    }
                })?;
                // Deleted before the assignment is cleared, which is the
                // first moment an add of the same info-hash can write files
                // of its own, and before the answer, so neither a restart nor
                // a power loss after a 204 finds them to load. The tombstone
                // stays: a resume save libtorrent queued before the removal
                // can still be written, and the removal alert's handler, the
                // last of this torrent's, deletes that and settles it.
                let left = delete_removed_files(
                    &*settler.resume,
                    &*settler.torrents,
                    &*settler.metrics,
                    &profile,
                    &ih,
                    false,
                    Tombstone::Keep,
                );
                let resurrects = tombstoned.is_err() && left.files_left();
                let Some(payload) = payload else {
                    clear_assignment(&settler, &ih, &profile, false)?;
                    return report_unfinished_cleanup(&ih, resurrects);
                };
                let bucket = format!("torrent-{}-{}", ih.to_hex(), unix_now());
                let outcome = crate::pool_trash::trash_torrent_payload(&payload, &bucket);
                // The session no longer holds it, so the assignment is
                // cleared whatever the move did: left in place it would answer
                // every later delete `409 torrent-adding`.
                clear_assignment(&settler, &ih, &profile, outcome.failed.is_none())?;
                if let Some((path, why)) = outcome.failed {
                    return Err(DeleteTorrentError::Internal {
                        detail: format!(
                            "{} The torrent was removed from its session and its assignment \
                             cleared; {} of {} file(s) were moved to the trash before the \
                             move stopped at {}, and every file after it is where it was. \
                             Nothing was unlinked.",
                            internal("moving the payload to the trash", why),
                            outcome.moved,
                            payload.file_count(),
                            path.display(),
                        ),
                    });
                }
                report_unfinished_cleanup(&ih, resurrects)
            })
            .await?;
        }
        None if s.unloaded_at_boot.lock().contains(&ih) => {
            if delete_files {
                // Refused before anything changes, as `clear_sessionless`
                // refuses it: no session holds the torrent, so nothing can
                // reach its payload, and a 204 would tell the client files
                // went to the trash that were never touched.
                return Err(DeleteTorrentError::PayloadUntrashable {
                    detail: format!(
                        "no session holds torrent {ih}: the startup scans left it unloaded, so \
                         its payload cannot be reached to move to the trash. Nothing was \
                         changed; retry without `delete_files` to clear it from the daemon's \
                         records and leave the files where they are."
                    ),
                });
            }
            // The boot leaves a torrent unloaded mostly because its add
            // failed: a save path on a disk not mounted yet, or a resume file
            // libtorrent refused. Its resume file and `.torrent` are then the
            // only copy of its metadata and what the next boot loads it from,
            // so a plain delete refuses rather than deleting them. A claim
            // with nothing behind it, which a crash between an add's claim
            // and its first record leaves, has neither and is cleared.
            refuse_unloaded_with_store_files(&s, &ih, &profile)?;
            clear_unheld(&s, &ih, &profile)?;
            warn!(
                target: "torrentd::http",
                infohash = %ih,
                profile_id = %profile,
                "cleared an assignment the startup scans left unloaded, which had no resume or \
                 .torrent file behind it",
            );
        }
        None => return Err(DeleteTorrentError::TorrentAdding),
    }
    Ok(NoContent)
}

/// The files `delete_files` would move to the trash for the torrent `h`,
/// each proven to lie under a managed root, to be claimed by this torrent in
/// the pool index, and to be unchanged since the scan — or why not.
fn payload_to_trash(
    s: &AppState,
    engine: &Arc<dyn TorrentEngine>,
    ih: &InfoHash,
    h: TorrentHandle,
) -> Result<crate::pool_trash::TorrentPayload, DeleteTorrentError> {
    let Some(pool) = s.pool.as_ref() else {
        // Checked by the handler already; a pool is what holds the trash.
        return Err(DeleteTorrentError::MutationsDisabled);
    };
    let session_err = |e| DeleteTorrentError::Internal {
        detail: internal("reading the torrent's files from its session", e),
    };
    let details = engine.torrent_details(h).map_err(session_err)?;
    let files: Vec<String> = engine
        .torrent_files(h)
        .map_err(session_err)?
        .unwrap_or_default()
        .into_iter()
        .map(|f| f.path)
        .collect();
    // The handler's co-claimant check ran before the session was asked for
    // the files, and a scan may have committed since: the proof asks again,
    // in the same read of the committed index as the claims and rows it
    // rests on. It reads the read connection, so it never waits out a scan
    // still holding the writer.
    let payload = match crate::pool_trash::torrent_payload(
        pool,
        &ih.to_hex(),
        FsPath::new(&details.save_path),
        &files,
    ) {
        Ok(payload) => payload,
        Err(crate::pool_trash::PayloadRefusal::Shared(others)) => {
            return Err(payload_shared(&others));
        }
        Err(crate::pool_trash::PayloadRefusal::Unproven(why)) => {
            return Err(DeleteTorrentError::PayloadUntrashable {
                detail: format!(
                    "{why}. Nothing was changed; the torrent is still in its session. Retry \
                     without `delete_files` to remove the torrent alone."
                ),
            });
        }
    };
    refuse_live_overlap(s, ih, &payload)?;
    Ok(payload)
}

/// Refuse `delete_files` when the pool index has other torrents claiming
/// files of this one: deleting its payload would delete theirs.
fn refuse_co_claimants(
    others: Result<Vec<String>, torrentd_pool::PoolError>,
) -> Result<(), DeleteTorrentError> {
    let others = others.map_err(|e| DeleteTorrentError::Internal {
        detail: internal("reading the pool index", e),
    })?;
    if others.is_empty() {
        return Ok(());
    }
    Err(payload_shared(&others))
}

/// `409 payload-shared`, naming the first of `others`: the torrents the pool
/// index has claiming files of the one being deleted.
fn payload_shared(others: &[String]) -> DeleteTorrentError {
    DeleteTorrentError::PayloadShared {
        detail: format!(
            "{} other torrent(s) claim files of this one in the pool index — the first is {} — \
             so deleting its payload would delete theirs; retry without `delete_files`",
            others.len(),
            others.first().map_or("unknown", String::as_str),
        ),
    }
}

/// Refuse `payload` when any other torrent the daemon holds has a file at
/// one of its paths.
///
/// The co-claimant check reads the pool index, where only the matcher writes
/// claims, so a cross-seed added through `POST /v1/torrents` with a
/// `save_path` over the same files is invisible to it. This reads every other
/// torrent from its session instead: each one assigned in the registry and
/// each one in the state map, whichever profile holds it. One whose files no
/// session can report — assigned but not loaded, or loaded where its session
/// cannot be asked — cannot be shown not to overlap, so it refuses too.
fn refuse_live_overlap(
    s: &AppState,
    ih: &InfoHash,
    payload: &crate::pool_trash::TorrentPayload,
) -> Result<(), DeleteTorrentError> {
    let mut others: Vec<InfoHash> = s
        .registry
        .entries()
        .into_iter()
        .map(|(other, _)| other)
        .chain(s.state.infohashes())
        .filter(|other| other != ih)
        .collect();
    others.sort_unstable_by_key(InfoHash::to_hex);
    others.dedup();
    let unprovable = |other: &InfoHash, why: String| DeleteTorrentError::PayloadUntrashable {
        detail: format!(
            "torrent {other} {why}, so its files cannot be compared with this one's. Nothing \
             was changed; retry once it is loaded or removed, or retry without `delete_files` \
             to remove this torrent alone."
        ),
    };
    for other in &others {
        let Some(st) = s.state.get(other) else {
            return Err(unprovable(
                other,
                "is assigned to a profile but no session holds it".to_owned(),
            ));
        };
        let live = crate::live_torrent::read_live_torrent(&s.source, &st).map_err(|e| match e {
            crate::live_torrent::LiveReadError::NoSession => unprovable(
                other,
                format!("is held by profile {}, which has no session", st.profile_id),
            ),
            crate::live_torrent::LiveReadError::Engine(e) => {
                unprovable(other, format!("could not be read from its session ({e})"))
            }
        })?;
        if let Some(path) = payload.shared_with(&live) {
            return Err(DeleteTorrentError::PayloadShared {
                detail: format!(
                    "torrent {other}, in profile {}, has a file at {}, so deleting this \
                     torrent's payload would delete its files too; retry without \
                     `delete_files`",
                    st.profile_id,
                    path.display(),
                ),
            });
        }
    }
    Ok(())
}

/// Seconds since the epoch, naming a deleted torrent's trash directory.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Log and count a failure to write or clear `(profile, ih)`'s tombstone, as
/// `delete_removed_files` counts the deletes it makes.
fn count_cleanup_error(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
    store: &str,
    e: &dyn fmt::Display,
) {
    warn!(
        target: "torrentd::http",
        infohash = %ih,
        profile_id = %profile,
        store,
        error.cause = %e,
        "failed to write or clear a removed torrent's tombstone",
    );
    s.metrics.inc_counter(
        torrentd_engine::metrics::REMOVE_CLEANUP_ERRORS,
        &[("profile_id", profile.as_str()), ("store", store)],
    );
}

/// Answer a delete that removed the torrent but left a file the next boot
/// would load it from, with no tombstone to stop that, as the failure it is.
///
/// The torrent is out of its session and its assignment is cleared by now,
/// so a retry answers `404`; the removal alert's handler deletes the files
/// again, and writes the tombstone where they still will not go. The detail
/// says so, rather than a 204 claiming a delete the next restart undoes.
fn report_unfinished_cleanup(ih: &InfoHash, resurrects: bool) -> Result<(), DeleteTorrentError> {
    if !resurrects {
        return Ok(());
    }
    Err(DeleteTorrentError::Internal {
        detail: format!(
            "torrent {ih} was removed from its session and its assignment cleared, but its \
             resume file or .torrent could not be deleted and no tombstone could be written to \
             stop the next start loading it again; see \
             torrentd_torrent_remove_cleanup_errors_total and the daemon log. The daemon \
             retries the delete as the session confirms the removal. If the torrent is listed \
             after a restart, delete it again."
        ),
    })
}

/// Clear `ih`'s assignment to `profile` once no session holds it.
/// `payload_deleted` says its session deleted its files as it removed it.
fn clear_assignment(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
    payload_deleted: bool,
) -> Result<(), DeleteTorrentError> {
    // Report a persist failure rather than discarding it. On a full or
    // read-only state directory the payload is gone and the assignment write
    // fails, and a 204 here would say the delete succeeded — so the claim
    // comes back from the file at the next restart, over a torrent that no
    // longer exists, and clearing it then is the hard case. The removal from
    // the session has already happened, which the detail says, so a retry is
    // about the assignment alone. The info-hash is recorded for that retry:
    // once the removal alert drops its state-map entry nothing else tells it
    // from an add whose alert has not landed, which a delete refuses.
    if let Err(e) = s.registry.remove(ih) {
        s.removed_unassigned.lock().insert(*ih, payload_deleted);
        return Err(DeleteTorrentError::Internal {
            detail: format!(
                "{} The torrent was removed from its session; retry the delete to clear the \
                 assignment.",
                internal("clearing the torrent's assignment", e)
            ),
        });
    }
    // Cleared, so a later add of the same info-hash is this process's own
    // and must not be mistaken for one the boot left unloaded, or for one an
    // earlier delete removed.
    s.unloaded_at_boot.lock().remove(ih);
    s.removed_unassigned.lock().remove(ih);
    release_index_owner(s, ih, profile, payload_deleted);
    Ok(())
}

/// Forget the pool index's record that `profile` owns `ih`, once the torrent
/// is gone from it.
///
/// Adoption refuses a torrent the index says another profile owns, and one
/// it records as `adopted`, so either left behind after a delete would refuse
/// every later adoption of it into any other profile, with nothing but the
/// database to clear it from. Only a record naming `profile` is cleared, and
/// its `adopted` verdict with it (`missing` where `payload_deleted`, as the
/// files are gone); one naming anything else was never this delete's. A
/// failed write is logged and counted by the pool, and leaves adoption
/// refusing rather than allowing.
///
/// The response does not wait for the write: while a scan holds the writer
/// the release is queued until it lets go (see
/// [`crate::pool_service::PoolService::release_owner_soon`]). The torrent is
/// gone from the registry by then, so a client that timed out on the wait and
/// retried got `404` for a delete that had succeeded.
fn release_index_owner(s: &AppState, ih: &InfoHash, profile: &ProfileId, payload_deleted: bool) {
    let Some(pool) = s.pool.as_ref() else {
        return;
    };
    pool.release_owner_soon(ih.to_hex(), profile.as_str().to_owned(), payload_deleted);
}

/// Remove a torrent whose profile has no live session.
///
/// The profile the registry names failed to come up, and Safety Rule 1 left
/// the rest of the daemon running. No session holds this torrent, so there is
/// nothing to remove from one; what is left is the registry entry, and that
/// entry is what makes `POST /v1/torrents` answer `torrent-exists` for this
/// infohash. Clearing it is the whole of the work; refusing would leave an
/// operator no way to clear it but hand-editing `registry.db`.
fn clear_sessionless(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
    delete_files: bool,
) -> Result<NoContent, DeleteTorrentError> {
    if delete_files {
        // Refuse rather than report success for a deletion that cannot
        // happen: the payload is reachable only through the session.
        return Err(DeleteTorrentError::ProfileUnavailable {
            detail: format!(
                "profile {profile} has no running session, so its payload cannot be deleted; \
                 retry without `delete_files` to clear the assignment alone"
            ),
            profile_status: crate::http::v1::common::ProfileUnavailableReason::Failed.as_str(),
        });
    }
    clear_unheld(s, ih, profile)?;
    warn!(
        target: "torrentd::http",
        infohash = %ih,
        profile_id = %profile,
        "cleared an assignment whose profile has no running session, and deleted its resume \
         and .torrent files so the startup scan does not re-assign it",
    );
    Ok(NoContent)
}

/// Refuse, changing nothing, the plain delete of a torrent the boot left
/// unloaded while `profile`'s stores still hold its resume file or `.torrent`.
///
/// Those files are what the next boot loads it from once the reason its add
/// failed is fixed, and for a torrent not adopted from the pool the only copy
/// of its metadata, so deleting them would turn a load failure into a lost
/// torrent. A store that cannot say whether it holds the file refuses too.
fn refuse_unloaded_with_store_files(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
) -> Result<(), DeleteTorrentError> {
    let resume = s
        .resume
        .exists(profile, ih)
        .map_err(|e| DeleteTorrentError::Internal {
            detail: format!(
                "{} Nothing was changed; retry the delete.",
                internal("checking for the torrent's resume file", e)
            ),
        })?;
    // A `.torrent` with no resume file that the pool index records `drifted`
    // is one the boot held back on purpose: its verification failed, no boot
    // loads it, and deleting it and adopting it again is how it is verified
    // again. Where the index cannot be read it is kept.
    let torrent = s.torrents.exists(profile, ih) && (resume || !recorded_drifted(s, ih));
    let held: Vec<String> = [(resume, "resume"), (torrent, "torrent")]
        .into_iter()
        .filter(|(present, _)| *present)
        .map(|(_, suffix)| format!("`{}.{suffix}`", ih.to_hex()))
        .collect();
    if held.is_empty() {
        return Ok(());
    }
    Err(DeleteTorrentError::TorrentUnloaded {
        detail: format!(
            "the boot left torrent {ih} unloaded, and profile {profile}'s stores still hold {}, \
             which the next boot loads it from. Nothing was changed. Fix why it did not load \
             (the boot logged a warning naming it, such as `resume add failed`, `torrent-dir \
             add failed` or a tracker `allowed_tracker_urls` refuses, and \
             `torrentd_boot_torrent_load_failures` counts failed adds) and restart the daemon. \
             To retire it anyway, move those files out of the profile's resume and torrent \
             directories and retry the delete.",
            held.join(" and "),
        ),
    })
}

/// Whether the pool index records `ih`'s adoption `drifted`; `false` with no
/// pool, or where the index cannot be read.
fn recorded_drifted(s: &AppState, ih: &InfoHash) -> bool {
    s.pool.as_ref().is_some_and(|pool| {
        matches!(
            pool.with_reader(|st| st.adoption_state(&ih.to_hex())),
            Ok(Some(torrentd_pool::AdoptionState::Drifted))
        )
    })
}

/// Clear the assignment of `ih` to `profile`, which no session holds, with
/// the resume file and `.torrent` that would re-assign it at the next start.
fn clear_unheld(
    s: &AppState,
    ih: &InfoHash,
    profile: &ProfileId,
) -> Result<(), DeleteTorrentError> {
    // The two stores first, then the registry entry.
    //
    // Clearing the registry entry alone does not hold: `startup::scan` re-scans
    // `<resume_dir>/<id>` and `<torrent_dir>/<id>` at the next start and
    // re-`assign`s every info-hash it finds, so the operator's clear would be
    // silently undone the first time the daemon restarts. The engine-backed
    // path deletes them in the request too, under a tombstone, and again in
    // `TorrentRemoved` -> the engine's `handlers/add.rs`; with no session
    // there is no removal to race and no alert, so the deletes alone are
    // done here.
    //
    // The order is what makes the advice below true. Clearing the registry
    // first and deleting after would mean a failed delete tells the operator
    // to retry — and the retry would find no assignment, answer
    // `torrent-not-found`, and never reach the files. The resume file and the
    // `.torrent` would stay on disk and the next start re-`assign` the
    // info-hash, the resurrection this branch exists to prevent. Deleting
    // first leaves the lookup resolving, so the retry re-enters and finishes
    // the work.
    //
    // Reported rather than warned: a clear that will resurrect is not a
    // clear. Both deletes are no-ops on a missing file, so an error here means
    // the filesystem, not a race.
    let store_err = |what: &str, e: String| DeleteTorrentError::Internal {
        detail: format!(
            "{} The assignment has been left in place so this can be retried; until the file is \
             gone the startup scan will re-assign this infohash. Retry the delete.",
            internal(&format!("deleting the {what}"), e)
        ),
    };
    s.resume
        .delete(profile, ih)
        .map_err(|e| store_err("resume file", e.to_string()))?;
    s.torrents
        .delete(profile, ih)
        .map_err(|e| store_err(".torrent file", e.to_string()))?;
    s.registry
        .remove(ih)
        .map_err(|e| DeleteTorrentError::Internal {
            detail: format!(
                "{} The resume and .torrent files were deleted but the assignment could not be \
                 cleared. Retry the delete; the two deletes are no-ops on a file that is already \
                 gone.",
                internal("clearing the torrent's assignment", e)
            ),
        })?;
    s.unloaded_at_boot.lock().remove(ih);
    s.removed_unassigned.lock().remove(ih);
    release_index_owner(s, ih, profile, false);
    Ok(())
}
