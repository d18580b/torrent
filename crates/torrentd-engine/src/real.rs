//! `RealEngine` — delegates to a `libtorrent_safe::Session` 1:1.
//!
//! No business logic here; that lives in the alert loop and handlers.
//! `RealEngine` exists only to satisfy `TorrentEngine` so production code
//! can swap in `MockEngine` for tests.
//!
//! Concurrency: `libtorrent_safe::Session` is `!Send + !Sync`. We park it
//! behind a `parking_lot::Mutex` and route every call through that lock.
//! libtorrent's session is internally thread-safe but the C shim's per-
//! session handle map is mutex-guarded already, so the contention overhead
//! is small for the shape of work torrentd does (one engine call per
//! second per torrent, max).

use libtorrent_safe::AddParams;
use libtorrent_safe::Alert;
use libtorrent_safe::MoveFlags;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::Session;
use libtorrent_safe::Settings;
use libtorrent_safe::TorrentDetails;
use libtorrent_safe::TorrentFile;
use libtorrent_safe::TorrentHandle;
use libtorrent_safe::TrackerEntry;
use parking_lot::Mutex;
use tracing::instrument;

use crate::engine::EngineError;
use crate::engine::TorrentEngine;

pub struct RealEngine {
    session: Mutex<Session>,
}

impl std::fmt::Debug for RealEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealEngine").finish_non_exhaustive()
    }
}

impl RealEngine {
    /// Construct a new engine with the given settings layered on top of
    /// libtorrent's `high_performance_seed()` preset.
    pub fn new(settings: &Settings) -> Result<Self, EngineError> {
        let session = Session::new(settings)?;
        Ok(Self {
            session: Mutex::new(session),
        })
    }

    /// Build from an existing `Session`. Useful when the caller wants to
    /// `load_state` first.
    pub fn from_session(session: Session) -> Self {
        Self {
            session: Mutex::new(session),
        }
    }
}

impl TorrentEngine for RealEngine {
    #[instrument(skip_all, fields(op = "add_torrent"))]
    fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle, EngineError> {
        Ok(self.session.lock().add_torrent(params)?)
    }

    #[instrument(skip_all, fields(op = "remove_torrent", infohash = %h.infohash, delete_files))]
    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError> {
        Ok(self.session.lock().remove_torrent(h, delete_files)?)
    }

    #[instrument(skip_all, fields(op = "pause_torrent", infohash = %h.infohash))]
    fn pause_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session.lock().pause_torrent(h)?)
    }

    #[instrument(skip_all, fields(op = "resume_torrent", infohash = %h.infohash))]
    fn resume_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session.lock().resume_torrent(h)?)
    }

    #[instrument(skip_all, fields(op = "save_resume_data", infohash = %h.infohash))]
    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError> {
        Ok(self.session.lock().save_resume_data(h, flags)?)
    }

    #[instrument(skip_all, fields(op = "set_upload_limit", infohash = %h.infohash))]
    fn set_upload_limit(&self, h: TorrentHandle, bytes_per_sec: i32) -> Result<(), EngineError> {
        Ok(self.session.lock().set_upload_limit(h, bytes_per_sec)?)
    }

    #[instrument(skip_all, fields(op = "set_file_priority", infohash = %h.infohash))]
    fn set_file_priority(
        &self,
        h: TorrentHandle,
        file_idx: i32,
        priority: u8,
    ) -> Result<(), EngineError> {
        Ok(self
            .session
            .lock()
            .set_file_priority(h, file_idx, priority)?)
    }

    #[instrument(skip_all, fields(op = "force_recheck", infohash = %h.infohash))]
    fn force_recheck(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session.lock().force_recheck(h)?)
    }

    #[instrument(skip_all, fields(op = "force_reannounce", infohash = %h.infohash))]
    fn force_reannounce(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session.lock().force_reannounce(h)?)
    }

    #[instrument(skip_all, fields(op = "move_storage", infohash = %h.infohash, new_path))]
    fn move_storage(
        &self,
        h: TorrentHandle,
        new_path: &str,
        flags: MoveFlags,
    ) -> Result<(), EngineError> {
        Ok(self.session.lock().move_storage(h, new_path, flags)?)
    }

    fn pop_alerts(&self) -> Vec<Alert> {
        self.session.lock().drain_alerts()
    }

    fn post_updates(&self) {
        self.session.lock().post_torrent_updates()
    }
    fn post_stats(&self) {
        self.session.lock().post_session_stats()
    }

    #[instrument(skip_all, fields(op = "apply_settings"))]
    fn apply_settings(&self, settings: &Settings) -> Result<(), EngineError> {
        Ok(self.session.lock().apply_settings(settings)?)
    }

    fn session_state(&self) -> Result<Vec<u8>, EngineError> {
        Ok(self.session.lock().save_state()?)
    }

    #[instrument(skip_all, fields(op = "torrent_details", infohash = %h.infohash))]
    fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails, EngineError> {
        Ok(self.session.lock().torrent_details(h)?)
    }

    #[instrument(skip_all, fields(op = "torrent_files", infohash = %h.infohash))]
    fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>, EngineError> {
        Ok(self.session.lock().torrent_files(h)?)
    }

    #[instrument(skip_all, fields(op = "torrent_trackers", infohash = %h.infohash))]
    fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>, EngineError> {
        Ok(self.session.lock().torrent_trackers(h)?)
    }
}
