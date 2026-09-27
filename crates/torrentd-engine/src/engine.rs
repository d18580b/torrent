//! `TorrentEngine` — the trait every business-logic component is written
//! against.
//!
//! Concrete implementations:
//!   - `crate::mock::MockEngine` — pre-loaded alert queue, call recorder,
//!     per-method error injection. Drives every Layer 1 unit test.
//!   - `RealEngine` (in `crate::real`) — delegates to a
//!     `libtorrent_safe::Session`.

use std::sync::Arc;

pub use libtorrent_safe::AddParams;
pub use libtorrent_safe::Alert;
pub use libtorrent_safe::InfoHash;
pub use libtorrent_safe::MoveFlags;
pub use libtorrent_safe::ResumeData;
pub use libtorrent_safe::ResumeFlags;
pub use libtorrent_safe::Settings;
pub use libtorrent_safe::TorrentDetails;
pub use libtorrent_safe::TorrentFile;
pub use libtorrent_safe::TorrentHandle;
pub use libtorrent_safe::TrackerEntry;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Safe(#[from] libtorrent_safe::Error),

    /// Caller asked for a torrent that is not in the engine's handle map.
    /// Distinct from `Safe(TorrentNotFound)` — this is the engine layer's
    /// view of registry/handle bookkeeping.
    #[error("torrent not registered with engine: {}", .0)]
    UnknownHandle(InfoHash),

    /// The engine has been shut down; further calls are rejected.
    #[error("engine shut down")]
    Shutdown,

    /// MockEngine: a method was called that the test injected an error for.
    #[error("mock injected error on `{op}`: {message}")]
    MockInjected { op: &'static str, message: String },
}

/// All operations the daemon's business logic performs against libtorrent.
///
/// Conventions:
///   - `add_torrent` returns the canonical handle the caller should keep;
///     duplicate adds resolve to the same handle (libtorrent and the shim
///     handle map enforce this).
///   - `save_resume_data` is asynchronous — the result lands as a
///     `Alert::SaveResumeData{Failed}` event. Callers that need to wait
///     should track an outstanding-save counter and watch the alert
///     stream.
///   - `pop_alerts` is non-blocking; an empty `Vec` means the queue is
///     drained.
///   - `post_updates` and `post_stats` trigger libtorrent to emit a
///     `state_update_alert` and `session_stats_alert` respectively.
pub trait TorrentEngine: Send + Sync + std::fmt::Debug {
    fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle, EngineError>;
    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError>;
    fn pause_torrent(&self, h: TorrentHandle) -> Result<(), EngineError>;
    fn resume_torrent(&self, h: TorrentHandle) -> Result<(), EngineError>;
    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError>;
    fn pop_alerts(&self) -> Vec<Alert>;
    fn post_updates(&self);
    fn post_stats(&self);
    fn set_upload_limit(&self, h: TorrentHandle, bytes_per_sec: i32) -> Result<(), EngineError>;
    fn set_file_priority(
        &self,
        h: TorrentHandle,
        file_idx: i32,
        priority: u8,
    ) -> Result<(), EngineError>;
    /// Re-hash the payload against the torrent's piece hashes. Asynchronous:
    /// completion lands as `Alert::TorrentChecked`. This is the daemon's only
    /// verification path — piece hashing is never reimplemented.
    fn force_recheck(&self, h: TorrentHandle) -> Result<(), EngineError>;
    /// Announce to every tracker now rather than at the next scheduled
    /// interval. Fire-and-forget: the outcome arrives as tracker alerts.
    fn force_reannounce(&self, h: TorrentHandle) -> Result<(), EngineError>;
    /// Relocate a torrent's payload via libtorrent, so its storage state stays
    /// consistent. Asynchronous: `Alert::StorageMoved{,Failed}`.
    fn move_storage(
        &self,
        h: TorrentHandle,
        new_path: &str,
        flags: MoveFlags,
    ) -> Result<(), EngineError>;
    fn apply_settings(&self, settings: &Settings) -> Result<(), EngineError>;
    fn session_state(&self) -> Result<Vec<u8>, EngineError>;
    /// Name, size, save path, upload limit and added time of one torrent.
    /// Synchronous query; an unknown handle is `Safe(TorrentNotFound)`.
    fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails, EngineError>;
    /// The torrent's files in index order, or `None` while its metadata has
    /// not arrived yet.
    fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>, EngineError>;
    /// The torrent's trackers, tier by tier, with their announce state.
    fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>, EngineError>;
}

// Convenience: any Arc<dyn TorrentEngine> is itself a TorrentEngine.
impl<T: TorrentEngine + ?Sized> TorrentEngine for Arc<T> {
    fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle, EngineError> {
        (**self).add_torrent(params)
    }
    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError> {
        (**self).remove_torrent(h, delete_files)
    }
    fn pause_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        (**self).pause_torrent(h)
    }
    fn resume_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        (**self).resume_torrent(h)
    }
    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError> {
        (**self).save_resume_data(h, flags)
    }
    fn set_upload_limit(&self, h: TorrentHandle, bps: i32) -> Result<(), EngineError> {
        (**self).set_upload_limit(h, bps)
    }
    fn set_file_priority(&self, h: TorrentHandle, idx: i32, prio: u8) -> Result<(), EngineError> {
        (**self).set_file_priority(h, idx, prio)
    }
    fn pop_alerts(&self) -> Vec<Alert> {
        (**self).pop_alerts()
    }
    fn post_updates(&self) {
        (**self).post_updates()
    }
    fn post_stats(&self) {
        (**self).post_stats()
    }
    fn force_recheck(&self, h: TorrentHandle) -> Result<(), EngineError> {
        (**self).force_recheck(h)
    }
    fn force_reannounce(&self, h: TorrentHandle) -> Result<(), EngineError> {
        (**self).force_reannounce(h)
    }
    fn move_storage(
        &self,
        h: TorrentHandle,
        new_path: &str,
        flags: MoveFlags,
    ) -> Result<(), EngineError> {
        (**self).move_storage(h, new_path, flags)
    }
    fn apply_settings(&self, s: &Settings) -> Result<(), EngineError> {
        (**self).apply_settings(s)
    }
    fn session_state(&self) -> Result<Vec<u8>, EngineError> {
        (**self).session_state()
    }
    fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails, EngineError> {
        (**self).torrent_details(h)
    }
    fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>, EngineError> {
        (**self).torrent_files(h)
    }
    fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>, EngineError> {
        (**self).torrent_trackers(h)
    }
}
