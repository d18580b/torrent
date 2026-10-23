//! Deleting what a removed torrent leaves on disk, and settling its tombstone.
//!
//! One routine for every path that removes a torrent: `DELETE` before it
//! answers, the `torrent_removed_alert` handler (`handlers::add`), a removal
//! whose alert an overflow dropped (`handlers::dropped`), and the boot
//! honouring a tombstone.

use libtorrent_safe::InfoHash;
use tracing::warn;

use crate::metrics::MetricsSink;
use crate::metrics::REMOVE_CLEANUP_ERRORS;
use crate::profile::ProfileId;
use crate::resume_store::ResumeStore;
use crate::torrent_store::TorrentStore;

/// What [`delete_removed_files`] could not delete.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemovalCleanup {
    /// The resume file is still there.
    pub resume_failed: bool,
    /// The `.torrent` or its save path is still there.
    pub torrent_failed: bool,
    /// The tombstone could not be written or cleared, as asked.
    pub tombstone_failed: bool,
}

impl RemovalCleanup {
    /// Whether a file the next boot would load the torrent from is left.
    pub fn files_left(&self) -> bool {
        self.resume_failed || self.torrent_failed
    }
}

/// What [`delete_removed_files`] does with the tombstone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tombstone {
    /// Leave it as it is.
    Keep,
    /// Clear it once every file asked for is gone. Where one is left, write
    /// it (it may never have been written, or its write failed), so the next
    /// boot deletes what is left rather than loading it.
    Settle,
}

/// Delete what would bring `(profile, ih)` back at the next boot: its resume
/// file, and its `.torrent` and save path unless `keep_torrent` (they are a
/// re-add's). Each delete that fails is logged and counted under
/// [`REMOVE_CLEANUP_ERRORS`].
///
/// For `DELETE`, which runs this before it answers and keeps the tombstone it
/// wrote: a resume save libtorrent queued before the removal can still be
/// written after it, and only this torrent's `torrent_removed_alert`, the
/// last alert it posts, settles that. For that alert's handler, and for the
/// boot honouring a tombstone, both of which settle it: cleared once the
/// files are gone, written where one is left.
pub fn delete_removed_files(
    resume: &dyn ResumeStore,
    torrents: &dyn TorrentStore,
    metrics: &dyn MetricsSink,
    profile: &ProfileId,
    ih: &InfoHash,
    keep_torrent: bool,
    tombstone: Tombstone,
) -> RemovalCleanup {
    let failed = |store: &str, e: &dyn std::fmt::Display| {
        warn!(
            target: "torrentd_engine::handler::add",
            profile_id = %profile,
            infohash = %ih,
            store,
            error.cause = %e,
            "failed to delete a removed torrent's file, or to settle its tombstone",
        );
        metrics.inc_counter(
            REMOVE_CLEANUP_ERRORS,
            &[("profile_id", profile.as_str()), ("store", store)],
        );
    };
    let mut out = RemovalCleanup::default();
    if let Err(e) = resume.delete(profile, ih) {
        failed("resume", &e);
        out.resume_failed = true;
    }
    if !keep_torrent {
        if let Err(e) = torrents.delete(profile, ih) {
            failed("torrent", &e);
            out.torrent_failed = true;
        }
    }
    if tombstone == Tombstone::Settle {
        let settled = if out.files_left() {
            resume.write_tombstone(profile, ih)
        } else {
            resume.clear_tombstone(profile, ih)
        };
        if let Err(e) = settled {
            failed("tombstone", &e);
            out.tombstone_failed = true;
        }
    }
    out
}
