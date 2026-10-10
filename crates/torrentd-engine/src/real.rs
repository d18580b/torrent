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
use libtorrent_safe::FilePage;
use libtorrent_safe::MoveFlags;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::Session;
use libtorrent_safe::Settings;
use libtorrent_safe::TorrentDetails;
use libtorrent_safe::TorrentFile;
use libtorrent_safe::TorrentHandle;
use libtorrent_safe::TrackerEntry;
use parking_lot::MappedMutexGuard;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use tracing::instrument;

use crate::engine::EngineError;
use crate::engine::TorrentEngine;

/// The most alerts one `pop_alerts` converts while holding the session lock.
///
/// Every engine call takes that lock, the HTTP handlers' included, so an
/// uncapped drain — up to the whole `alert_queue_size` of 10000, each alert a
/// ~3 KiB union to convert — stalls every one of them behind it. The alert
/// loop drains again at once while a pop comes back non-empty, so a cap costs
/// no throughput; it only lets other callers in between batches.
pub const MAX_ALERTS_PER_POP: usize = 512;

pub struct RealEngine {
    /// `None` once [`TorrentEngine::close`] has destroyed the session; every
    /// call after that answers [`EngineError::Shutdown`].
    session: Mutex<Option<Session>>,
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
            session: Mutex::new(Some(session)),
        })
    }

    /// Build from an existing `Session`, such as one restored with
    /// `Session::with_state`.
    pub fn from_session(session: Session) -> Self {
        Self {
            session: Mutex::new(Some(session)),
        }
    }

    /// The live session, locked, or `Shutdown` once it has been closed.
    fn session(&self) -> Result<MappedMutexGuard<'_, Session>, EngineError> {
        MutexGuard::try_map(self.session.lock(), Option::as_mut).map_err(|_| EngineError::Shutdown)
    }
}

impl TorrentEngine for RealEngine {
    #[instrument(skip_all, fields(op = "add_torrent"))]
    fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle, EngineError> {
        Ok(self.session()?.add_torrent(params)?)
    }

    #[instrument(skip_all, fields(op = "remove_torrent", infohash = %h.infohash, delete_files))]
    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError> {
        Ok(self.session()?.remove_torrent(h, delete_files)?)
    }

    #[instrument(skip_all, fields(op = "pause_torrent", infohash = %h.infohash))]
    fn pause_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.pause_torrent(h)?)
    }

    #[instrument(skip_all, fields(op = "resume_torrent", infohash = %h.infohash))]
    fn resume_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.resume_torrent(h)?)
    }

    #[instrument(skip_all, fields(op = "save_resume_data", infohash = %h.infohash))]
    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError> {
        Ok(self.session()?.save_resume_data(h, flags)?)
    }

    #[instrument(skip_all, fields(op = "set_upload_limit", infohash = %h.infohash))]
    fn set_upload_limit(&self, h: TorrentHandle, bytes_per_sec: i32) -> Result<(), EngineError> {
        Ok(self.session()?.set_upload_limit(h, bytes_per_sec)?)
    }

    #[instrument(skip_all, fields(op = "set_file_priority", infohash = %h.infohash))]
    fn set_file_priority(
        &self,
        h: TorrentHandle,
        file_idx: i32,
        priority: u8,
    ) -> Result<(), EngineError> {
        Ok(self.session()?.set_file_priority(h, file_idx, priority)?)
    }

    #[instrument(skip_all, fields(op = "force_recheck", infohash = %h.infohash))]
    fn force_recheck(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.force_recheck(h)?)
    }

    #[instrument(skip_all, fields(op = "force_reannounce", infohash = %h.infohash))]
    fn force_reannounce(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.force_reannounce(h)?)
    }

    #[instrument(skip_all, fields(op = "move_storage", infohash = %h.infohash, new_path))]
    fn move_storage(
        &self,
        h: TorrentHandle,
        new_path: &str,
        flags: MoveFlags,
    ) -> Result<(), EngineError> {
        Ok(self.session()?.move_storage(h, new_path, flags)?)
    }

    fn pop_alerts(&self) -> Vec<Alert> {
        self.session()
            .map(|s| s.drain_alerts_up_to(MAX_ALERTS_PER_POP))
            .unwrap_or_default()
    }

    fn post_updates(&self) {
        if let Ok(s) = self.session() {
            s.post_torrent_updates()
        }
    }
    fn post_stats(&self) {
        if let Ok(s) = self.session() {
            s.post_session_stats()
        }
    }

    fn close(&self) {
        // Taken out of the lock before it is dropped: the destructor blocks
        // until libtorrent has closed every socket and flushed its disk
        // threads, and nothing else should queue behind the lock meanwhile
        // only to be told the session is gone.
        let session = self.session.lock().take();
        drop(session);
    }

    #[instrument(skip_all, fields(op = "apply_settings"))]
    fn apply_settings(&self, settings: &Settings) -> Result<(), EngineError> {
        Ok(self.session()?.apply_settings(settings)?)
    }

    fn session_state(&self) -> Result<Vec<u8>, EngineError> {
        Ok(self.session()?.save_state()?)
    }

    #[instrument(skip_all, fields(op = "pause_session"))]
    fn pause_session(&self) -> Result<(), EngineError> {
        Ok(self.session()?.pause()?)
    }

    #[instrument(skip_all, fields(op = "resume_session"))]
    fn resume_session(&self) -> Result<(), EngineError> {
        Ok(self.session()?.resume()?)
    }

    fn session_paused(&self) -> Result<bool, EngineError> {
        Ok(self.session()?.is_paused()?)
    }

    #[instrument(skip_all, fields(op = "torrent_details", infohash = %h.infohash))]
    fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails, EngineError> {
        Ok(self.session()?.torrent_details(h)?)
    }

    #[instrument(skip_all, fields(op = "torrent_files", infohash = %h.infohash))]
    fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>, EngineError> {
        // The session lock covers the shim call only. Converting the list
        // copies every path, up to 250k of them, and needs no session.
        let raw = self.session()?.torrent_files_raw(h, 0, usize::MAX)?;
        Ok(raw.into_files())
    }

    #[instrument(skip_all, fields(op = "torrent_files_page", infohash = %h.infohash, start, limit))]
    fn torrent_files_page(
        &self,
        h: TorrentHandle,
        start: u32,
        limit: u32,
    ) -> Result<Option<FilePage>, EngineError> {
        // As above, but the shim copies only the page under the lock.
        let raw = self
            .session()?
            .torrent_files_raw(h, start as usize, limit as usize)?;
        Ok(raw.into_page())
    }

    #[instrument(skip_all, fields(op = "torrent_trackers", infohash = %h.infohash))]
    fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>, EngineError> {
        Ok(self.session()?.torrent_trackers(h)?)
    }
}
