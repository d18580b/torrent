//! `AddTorrent` and `TorrentRemoved` alert handlers.

use std::sync::atomic::fence;
use std::sync::atomic::Ordering;

use libtorrent_safe::Alert;
use libtorrent_safe::InfoHash;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::TorrentHandle;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::handlers::HandlerCtx;
use crate::removal::delete_removed_files;
use crate::removal::Tombstone;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::AddTorrent {
            hdr,
            error_code,
            message,
        } => {
            let _enter = ctx.span.enter();
            if *error_code != 0 {
                error!(
                    target: "torrentd_engine::handler::add",
                    alert_type = "add_torrent",
                    error.code = *error_code,
                    error.cause = %message.as_deref().unwrap_or(""),
                    "add_torrent failed",
                );
                ctx.metrics.inc_counter(
                    "torrent_add_errors_total",
                    &[("profile_id", ctx.profile_id.as_str())],
                );
                return;
            }
            let Some(handle) = hdr.handle else {
                error!(
                    target: "torrentd_engine::handler::add",
                    "add_torrent_alert missing handle",
                );
                return;
            };
            let fresh = track(handle, ctx);
            info!(
                target: "torrentd_engine::handler::add",
                infohash = %handle.infohash,
                already_tracked = !fresh,
                "torrent added",
            );
            ctx.metrics.inc_counter(
                "torrents_added_total",
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
        Alert::TorrentRemoved { hdr } => {
            let _enter = ctx.span.enter();
            if let Some(ih) = hdr.infohash {
                // Delete persisted state so a removed torrent doesn't
                // resurrect from disk on the next startup scan. This fires
                // after libtorrent has fully removed the torrent, so it can't
                // race a still-pending save_resume_data write.
                //
                // The `.torrent` and save path are kept where this profile
                // added the info-hash again in the meantime: `DELETE` clears
                // the assignment as soon as the session accepts the removal,
                // so an add can be accepted and write both before this alert
                // is handled, and they are the new torrent's. Its resume file
                // is not yet: the save its own `AddTorrent` queues writes it,
                // and that alert follows this one, so the resume file here is
                // still the removed torrent's, recording where that one was.
                // The entry is dropped only if it is this profile's, and the
                // removed torrent's where the removal was recorded: another
                // profile may hold the info-hash by now.
                //
                // A resume file the delete leaves behind is marked stale, so
                // the next add of the info-hash in this profile still gets
                // its first save rather than leaving the removed torrent's
                // save path and state for the next boot to load.
                //
                // `DELETE` already deleted these files before it answered,
                // and left the tombstone it wrote standing: this is the
                // fallback that deletes whatever a resume save landing after
                // that wrote, and the point where the tombstone is settled,
                // since no alert of this torrent's follows this one. A delete
                // that fails here keeps the tombstone, so the next boot
                // deletes the file rather than loading the torrent again.
                let settled = ctx.state.settle_removal(&ctx.profile_id, &ih, |readded| {
                    settle_removed_files(ctx, &ih, readded, Tombstone::Settle);
                });
                // Settle a save that was in flight when the torrent went: its
                // answer arrives with no info-hash (the shim skips an invalid
                // handle), so `resume::handle` cannot settle it, and the drain
                // would wait out its deadline on it while it held a cap slot.
                // A queued one is dropped at dispatch, which finds no state.
                // Not where the map holds a torrent added since: a save in
                // flight is that torrent's, and its answer settles it.
                if settled.entry_released {
                    ctx.state.note_resume_settled(&ih);
                }
                info!(
                    target: "torrentd_engine::handler::add",
                    infohash = %ih,
                    readded = settled.readded,
                    "torrent removed",
                );
                ctx.metrics.inc_counter(
                    "torrents_removed_total",
                    &[("profile_id", ctx.profile_id.as_str())],
                );
            }
        }
        _ => unreachable!("add::handle called with non-add alert"),
    }
}

/// Delete what a settled removal of the profile's `ih` leaves to delete: its
/// resume file, and its `.torrent` and save path unless `readded`, doing with
/// its tombstone what `tombstone` says. A resume file the delete leaves behind
/// is marked stale.
///
/// For `torrent_removed_alert`, which settles the tombstone, and for a removal
/// an overflow may have dropped that alert of (`handlers::dropped`), which
/// keeps it: that alert may be only late, and a resume save can still land
/// before it.
pub(crate) fn settle_removed_files(
    ctx: &HandlerCtx<'_>,
    ih: &InfoHash,
    readded: bool,
    tombstone: Tombstone,
) {
    let left = delete_removed_files(
        ctx.resume,
        ctx.torrents,
        ctx.metrics,
        &ctx.profile_id,
        ih,
        readded,
        tombstone,
    );
    ctx.state
        .set_stale_resume_file(&ctx.profile_id, ih, left.resume_failed);
}

/// Take a torrent the session added into the state map, hold it if its
/// profile is fenced, and queue its first resume save. Returns whether the map
/// had no entry for it yet.
///
/// For its `add_torrent_alert`. Idempotent: where the boot
/// scan already put the torrent in the map from the handle `add_torrent`
/// returned, the entry is kept rather than reset. The hold and the save are
/// asked again either way; a pause is idempotent, and a save already queued
/// or in flight is not asked for twice.
///
/// A fresh entry starts in the phase the add implies, from whether the
/// session holds the torrent's metadata: a magnet reads `AwaitingMetadata`
/// and any other torrent `Checking` until its first state update. The
/// session is asked only for a torrent the map lacks, so the boot's add
/// alerts, whose torrents the scans already tracked, cost no query each.
pub fn track(handle: TorrentHandle, ctx: &HandlerCtx<'_>) -> bool {
    // For a torrent already tracked the answer is unused: its entry is kept.
    let has_metadata =
        ctx.state.tracks(handle, &ctx.profile_id) || session_has_metadata(handle, ctx);
    track_known(handle, has_metadata, ctx)
}

/// [`track`], with whether the session holds `handle`'s metadata already
/// known. For the reconciliation of dropped add alerts
/// (`handlers::dropped`), which learns it for every missing torrent from one
/// `torrent_statuses` listing rather than a `torrent_details` query each, on
/// an alert loop already behind.
pub fn track_known(handle: TorrentHandle, has_metadata: bool, ctx: &HandlerCtx<'_>) -> bool {
    let fresh = ctx
        .state
        .track_added(handle, &ctx.profile_id, has_metadata, ctx.clock.now());
    hold_if_fenced(handle, ctx);
    queue_first_resume_save(handle, ctx);
    fresh
}

/// Whether `handle`'s session holds its metadata. A torrent the session
/// cannot describe is taken to have it: libtorrent starts every torrent in
/// `checking_resume_data`, and only one the session says lacks metadata is
/// known to be fetching it.
fn session_has_metadata(handle: TorrentHandle, ctx: &HandlerCtx<'_>) -> bool {
    match ctx.engine.torrent_details(handle) {
        Ok(details) => details.has_metadata,
        Err(e) => {
            warn!(
                target: "torrentd_engine::handler::add",
                infohash = %handle.infohash,
                op = "torrent_details",
                error.cause = %e,
                "could not read an added torrent's details; it reads checking until its first \
                 state update",
            );
            true
        }
    }
}

/// Make an add durable now rather than at the next 30-minute sweep or the
/// shutdown drain, where the torrent has no resume file yet: until one exists,
/// a crash leaves the registry claiming a torrent no session reloads. That is
/// an API add, an adoption, or a torrent-dir scan's load.
///
/// Unconditional, because an `ONLY_IF_MODIFIED` save depends on libtorrent's
/// modified bit, which says nothing about whether this torrent has a file on
/// disk yet.
///
/// Skipped where the profile already holds a resume file for it: that is the
/// boot's resume scan loading the file it just read. Saving each of those
/// again would rewrite every file at every boot, and the saves would hold the
/// queue's place against the shutdown drain's `ONLY_IF_MODIFIED` requests, so
/// a stop soon after a boot would spend its deadline on them. A re-add after
/// a removal is not skipped: the removal's alert, handled first, deleted the
/// old torrent's file. Where that delete failed, the file left behind is the
/// removed torrent's, marked stale, and the re-add is saved over it. A store
/// that cannot answer gets the save.
fn queue_first_resume_save(handle: TorrentHandle, ctx: &HandlerCtx<'_>) {
    let ih = handle.infohash;
    let stale = ctx.state.take_stale_resume_file(&ctx.profile_id, &ih);
    match ctx.resume.exists(&ctx.profile_id, &ih) {
        Ok(true) if !stale => return,
        Ok(_) => {}
        Err(e) => warn!(
            target: "torrentd_engine::handler::add",
            infohash = %ih,
            error.cause = %e,
            "could not tell whether the torrent has a resume file; saving it",
        ),
    }
    ctx.state.queue_resume_save(ih, ResumeFlags::empty());
}

/// Pause a torrent just inserted into the state map if its profile is fenced.
///
/// The VPN monitor fences a profile by pausing the torrents the state map
/// holds, and outside the boot scans a torrent enters the map only through
/// [`track`]: when its `add_torrent_alert` is handled, or when an overflow
/// that dropped it is reconciled. One the session added before the fence and
/// whose alert lands after it was not in the map the fence walked, so without
/// this it would seed on in a profile whose tunnel is down.
///
/// The fence marks the profile before it walks the map, and this inserts
/// before it asks. The `SeqCst` fence here pairs with the one in the VPN
/// monitor between those two steps, so at least one side sees the other: the
/// fence finds the torrent in the map, or this finds the profile fenced.
///
/// A torrent paused here is not added to the profile's `paused_for_vpn`
/// count: the fence's walk and the daemon's own post-add re-check can pause
/// the same torrent, so counting each pause would overcount.
///
/// Run through [`HandlerCtx::fence_hold`] where the daemon gave one, so the
/// kill-switch fence records what this pauses and its lift resumes it: that
/// fence resumes only what it recorded, and its walk did not find this one.
fn hold_if_fenced(handle: TorrentHandle, ctx: &HandlerCtx<'_>) {
    let mut hold = || pause_if_fenced(handle, ctx);
    match ctx.fence_hold {
        Some(f) => f(&ctx.profile_id, handle, &mut hold),
        None => {
            hold();
        }
    }
}

/// [`hold_if_fenced`]'s check and pause. Returns whether the profile was
/// fenced, whether or not the pause took: one that failed leaves the torrent
/// running, and a lift that resumes it changes nothing.
fn pause_if_fenced(handle: TorrentHandle, ctx: &HandlerCtx<'_>) -> bool {
    fence(Ordering::SeqCst);
    if !ctx.profile_fenced.is_some_and(|f| f(&ctx.profile_id)) {
        return false;
    }
    match ctx.engine.pause_torrent(handle) {
        Ok(()) => info!(
            target: "torrentd_engine::handler::add",
            infohash = %handle.infohash,
            "torrent added into a fenced profile; paused",
        ),
        Err(e) => {
            error!(
                target: "torrentd_engine::handler::add",
                infohash = %handle.infohash,
                error.cause = %e,
                "could not pause a torrent added into a fenced profile",
            );
            ctx.metrics.inc_counter(
                "profile_fence_pause_errors_total",
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
    }
    true
}

#[cfg(test)]
mod tests;
