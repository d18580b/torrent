//! `MockEngine` — drives every Layer 1 unit test that needs a
//! `TorrentEngine` without touching libtorrent.
//!
//! Capabilities (matching ):
//!   - Pre-loaded alert queue: `push_alert(...)`.
//!   - Call recorder: every trait method records a `RecordedCall` so
//!     tests assert "this op was called with these args".
//!   - Per-method error injection: `inject_error("save_resume_data",
//!     EngineError::...)` makes the next call to that op fail.
//!   - Synthetic handle issuance: `register_handle(infohash)` returns a
//!     `TorrentHandle` the test can hold and pass back through the trait.
//!   - Per-handle query data: `set_torrent_details` / `set_torrent_files` /
//!     `set_torrent_trackers` preload what the matching query returns; an
//!     unset handle gets a metadata-less default.
//!   - Fault injection beyond errors: `inject_panic(op)` makes the next call
//!     to that op panic, and `stall_next_pop(d)` makes the next `pop_alerts`
//!     block for `d`, which wedges whatever loop is draining it.
//!
//! The daemon's `fault-injection` build layers one of these over each real
//! session so an alert drill can queue libtorrent alerts, stall the alert
//! loop, or panic a task. A long-running process calls `pop_alerts` many
//! times a second, so that build turns the call recorder off with
//! `without_recording`.

use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dashmap::DashMap;
use libtorrent_safe::alert::AlertHeader;
use libtorrent_safe::AddParams;
use libtorrent_safe::Alert;
use libtorrent_safe::AlertKind;
use libtorrent_safe::InfoHash;
use libtorrent_safe::MoveFlags;
use libtorrent_safe::ResumeData;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::Settings;
use libtorrent_safe::TorrentDetails;
use libtorrent_safe::TorrentFile;
use libtorrent_safe::TorrentFlags;
use libtorrent_safe::TorrentHandle;
use libtorrent_safe::TrackerEntry;
use parking_lot::Mutex;

use crate::engine::EngineError;
use crate::engine::TorrentEngine;

/// Trait-method invocation captured by `MockEngine`.
#[derive(Debug, Clone)]
pub enum RecordedCall {
    AddTorrent(AddParamsSummary),
    RemoveTorrent {
        handle: TorrentHandle,
        delete_files: bool,
    },
    PauseTorrent(TorrentHandle),
    ResumeTorrent(TorrentHandle),
    SetUploadLimit {
        handle: TorrentHandle,
        bytes_per_sec: i32,
    },
    SetFilePriority {
        handle: TorrentHandle,
        file_idx: i32,
        priority: u8,
    },
    SaveResumeData {
        handle: TorrentHandle,
        flags: ResumeFlags,
    },
    PopAlerts,
    PostUpdates,
    PostStats,
    ForceRecheck(TorrentHandle),
    ForceReannounce(TorrentHandle),
    MoveStorage {
        handle: TorrentHandle,
        new_path: String,
        flags: MoveFlags,
    },
    ApplySettings(Settings),
    SessionState,
    TorrentDetails(TorrentHandle),
    TorrentFiles(TorrentHandle),
    TorrentTrackers(TorrentHandle),
}

/// Stripped-down view of `AddParams` so we can derive Clone/Debug
/// without dragging the byte buffers into every test assertion.
#[derive(Debug, Clone)]
pub enum AddParamsSummary {
    File {
        save_path: String,
        byte_len: usize,
        flags_bits: u32,
    },
    Magnet {
        uri: String,
        save_path: String,
        flags_bits: u32,
    },
    Resume {
        byte_len: usize,
        /// Whether `.torrent` bytes were supplied to repair missing metadata.
        has_torrent: bool,
        save_path: Option<String>,
        /// Set on top of the resume data's own flags.
        flags_set: u32,
        /// Cleared from them, after `flags_set`.
        flags_clear: u32,
    },
}

impl AddParamsSummary {
    /// The flags the add asserts: `flags` for a `.torrent` or magnet add,
    /// `flags_set` for a resume add.
    pub fn flags_set(&self) -> TorrentFlags {
        TorrentFlags::from_bits_retain(match self {
            Self::File { flags_bits, .. } | Self::Magnet { flags_bits, .. } => *flags_bits,
            Self::Resume { flags_set, .. } => *flags_set,
        })
    }

    /// The flags the add clears from what it starts from: nothing for a
    /// `.torrent` or magnet add, which starts from no flags at all.
    pub fn flags_clear(&self) -> TorrentFlags {
        match self {
            Self::File { .. } | Self::Magnet { .. } => TorrentFlags::empty(),
            Self::Resume { flags_clear, .. } => TorrentFlags::from_bits_retain(*flags_clear),
        }
    }

    /// Whether the add, as the caller asked for it, leaves the torrent in
    /// upload mode with no [`crate::policy::forbidden`] flag in force whatever
    /// its resume data carried.
    pub fn forbids_downloading(&self) -> bool {
        let forbidden = crate::policy::forbidden();
        self.flags_set().contains(TorrentFlags::UPLOAD_MODE)
            && !self.flags_set().intersects(forbidden)
            && match self {
                Self::Resume { .. } => self.flags_clear().contains(forbidden),
                Self::File { .. } | Self::Magnet { .. } => true,
            }
    }
}

impl From<&AddParams> for AddParamsSummary {
    fn from(p: &AddParams) -> Self {
        match p {
            AddParams::File {
                save_path,
                bytes,
                flags,
            } => AddParamsSummary::File {
                save_path: save_path.clone(),
                byte_len: bytes.len(),
                flags_bits: flags.bits(),
            },
            AddParams::Magnet {
                uri,
                save_path,
                flags,
            } => AddParamsSummary::Magnet {
                uri: uri.clone(),
                save_path: save_path.clone(),
                flags_bits: flags.bits(),
            },
            AddParams::Resume {
                bytes,
                torrent,
                save_path,
                flags_set,
                flags_clear,
            } => AddParamsSummary::Resume {
                byte_len: bytes.len(),
                has_torrent: torrent.as_ref().is_some_and(|t| !t.is_empty()),
                save_path: save_path.clone(),
                flags_set: flags_set.bits(),
                flags_clear: flags_clear.bits(),
            },
        }
    }
}

#[derive(Debug)]
pub struct MockEngine {
    alerts: Mutex<VecDeque<Alert>>,
    calls: Mutex<Vec<RecordedCall>>,
    next_handle_id: AtomicU64,
    /// `op_name` → fixed error to return on the next call to that op.
    error_inject: DashMap<&'static str, EngineError>,
    /// Ops whose next call panics.
    panic_inject: DashMap<&'static str, ()>,
    /// How long the next `pop_alerts` blocks before draining.
    stall: Mutex<Option<Duration>>,
    /// When clear, `calls()` stays empty. On by default.
    recording: AtomicBool,
    /// infohash → handle, so add/remove are consistent across calls.
    handles: DashMap<InfoHash, TorrentHandle>,
    /// When set, every successful `save_resume_data(h, _)` immediately
    /// pushes a synthetic `Alert::SaveResumeData` for `h` so callers can
    /// drive the alert loop's shutdown coordinator without orchestrating
    /// alerts manually. Defaults to off — tests that want full control
    /// keep their own alert script.
    auto_save_resume: AtomicBool,
    /// When set, `force_recheck` / `move_storage` synthesize their completion
    /// alert immediately, mirroring libtorrent's async behaviour.
    auto_check: AtomicBool,
    /// infohash → what `torrent_details` returns. Unset: `default_details`.
    details: DashMap<InfoHash, TorrentDetails>,
    /// infohash → what `torrent_files` returns. Unset: `None` (no metadata).
    files: DashMap<InfoHash, Option<Vec<TorrentFile>>>,
    /// infohash → what `torrent_trackers` returns. Unset: empty.
    trackers: DashMap<InfoHash, Vec<TrackerEntry>>,
}

impl Default for MockEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEngine {
    pub fn new() -> Self {
        Self {
            alerts: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            next_handle_id: AtomicU64::new(1),
            error_inject: DashMap::new(),
            panic_inject: DashMap::new(),
            stall: Mutex::new(None),
            recording: AtomicBool::new(true),
            handles: DashMap::new(),
            auto_save_resume: AtomicBool::new(false),
            auto_check: AtomicBool::new(false),
            details: DashMap::new(),
            files: DashMap::new(),
            trackers: DashMap::new(),
        }
    }

    /// Record no calls. For a mock that lives as long as a process, where the
    /// recorder would otherwise grow with every `pop_alerts`.
    pub fn without_recording(self) -> Self {
        self.recording.store(false, Ordering::SeqCst);
        self
    }

    /// Make every successful save_resume_data call enqueue a synthetic
    /// SaveResumeData alert for the same handle. Mirrors what libtorrent
    /// does asynchronously; useful for shutdown-coordinator tests.
    pub fn with_auto_save_resume(self, on: bool) -> Self {
        self.auto_save_resume.store(on, Ordering::SeqCst);
        self
    }
    pub fn set_auto_save_resume(&self, on: bool) {
        self.auto_save_resume.store(on, Ordering::SeqCst);
    }

    /// Synthesize `TorrentChecked` / `StorageMoved` completions.
    pub fn with_auto_check(self, on: bool) -> Self {
        self.auto_check.store(on, Ordering::SeqCst);
        self
    }
    pub fn set_auto_check(&self, on: bool) {
        self.auto_check.store(on, Ordering::SeqCst);
    }

    // --- test fixture helpers -----------------------------------------------

    /// Queue an alert that the next `pop_alerts` call will surface.
    pub fn push_alert(&self, a: Alert) {
        self.alerts.lock().push_back(a);
    }

    pub fn push_alerts(&self, alerts: impl IntoIterator<Item = Alert>) {
        let mut g = self.alerts.lock();
        for a in alerts {
            g.push_back(a);
        }
    }

    /// Inject a one-shot error for a specific trait method (by name).
    /// Recognized op names: `add_torrent`, `remove_torrent`, `pause_torrent`,
    /// `resume_torrent`, `save_resume_data`, `apply_settings`, `session_state`,
    /// `torrent_details`, `torrent_files`, `torrent_trackers` — in fact any
    /// trait method's name except `pop_alerts` / `post_updates` / `post_stats`.
    pub fn inject_error(&self, op: &'static str, err: EngineError) {
        self.error_inject.insert(op, err);
    }

    /// Make the next call to `op` panic, with a message naming it. Takes the
    /// same op names as `inject_error`, and is checked before them.
    pub fn inject_panic(&self, op: &'static str) {
        self.panic_inject.insert(op, ());
    }

    /// Make the next `pop_alerts` block for `d` before it drains the queue.
    /// A later call replaces an armed stall that has not been taken yet.
    pub fn stall_next_pop(&self, d: Duration) {
        *self.stall.lock() = Some(d);
    }

    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().clone()
    }

    /// Pre-register a handle so `add_torrent`/lookups behave consistently.
    pub fn register_handle(&self, ih: InfoHash) -> TorrentHandle {
        if let Some(h) = self.handles.get(&ih) {
            return *h;
        }
        let id = self.next_handle_id.fetch_add(1, Ordering::SeqCst);
        let h = TorrentHandle { id, infohash: ih };
        self.handles.insert(ih, h);
        h
    }

    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// What `torrent_details(h)` returns from now on.
    pub fn set_torrent_details(&self, h: TorrentHandle, details: TorrentDetails) {
        self.details.insert(h.infohash, details);
    }

    /// What `torrent_files(h)` returns from now on; `None` models a torrent
    /// whose metadata has not arrived.
    pub fn set_torrent_files(&self, h: TorrentHandle, files: Option<Vec<TorrentFile>>) {
        self.files.insert(h.infohash, files);
    }

    /// What `torrent_trackers(h)` returns from now on.
    pub fn set_torrent_trackers(&self, h: TorrentHandle, trackers: Vec<TrackerEntry>) {
        self.trackers.insert(h.infohash, trackers);
    }

    /// What `torrent_details` returns for a handle nothing was preloaded for:
    /// a torrent that has no metadata yet, saved at `/`.
    pub fn default_details() -> TorrentDetails {
        TorrentDetails {
            name: None,
            has_metadata: false,
            total_size: None,
            save_path: "/".to_string(),
            upload_limit: None,
            added_at: None,
        }
    }

    // --- internal -----------------------------------------------------------

    fn record(&self, c: RecordedCall) {
        if self.recording.load(Ordering::SeqCst) {
            self.calls.lock().push(c);
        }
    }

    fn check_error(&self, op: &'static str) -> Result<(), EngineError> {
        if self.panic_inject.remove(op).is_some() {
            panic!("mock injected panic on `{op}`");
        }
        if let Some((_, err)) = self.error_inject.remove(op) {
            return Err(err);
        }
        Ok(())
    }
}

impl TorrentEngine for MockEngine {
    fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle, EngineError> {
        self.record(RecordedCall::AddTorrent((&params).into()));
        self.check_error("add_torrent")?;
        // Synthesize an infohash from the params if none is implicit.
        // Tests that need a specific infohash should pre-register via
        // `register_handle` and then push their own AddTorrent alert.
        let ih = match &params {
            AddParams::Resume { bytes, .. } | AddParams::File { bytes, .. } => {
                let mut buf = [0u8; 20];
                for (i, b) in bytes.iter().take(20).enumerate() {
                    buf[i] = *b;
                }
                InfoHash(buf)
            }
            AddParams::Magnet { uri, .. } => {
                let mut buf = [0u8; 20];
                for (i, b) in uri.as_bytes().iter().take(20).enumerate() {
                    buf[i] = *b;
                }
                InfoHash(buf)
            }
        };
        Ok(self.register_handle(ih))
    }

    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError> {
        self.record(RecordedCall::RemoveTorrent {
            handle: h,
            delete_files,
        });
        self.check_error("remove_torrent")?;
        self.handles.remove(&h.infohash);
        Ok(())
    }

    fn pause_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.record(RecordedCall::PauseTorrent(h));
        self.check_error("pause_torrent")
    }

    fn resume_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.record(RecordedCall::ResumeTorrent(h));
        self.check_error("resume_torrent")
    }

    fn set_upload_limit(&self, h: TorrentHandle, bytes_per_sec: i32) -> Result<(), EngineError> {
        self.record(RecordedCall::SetUploadLimit {
            handle: h,
            bytes_per_sec,
        });
        self.check_error("set_upload_limit")
    }

    fn set_file_priority(
        &self,
        h: TorrentHandle,
        file_idx: i32,
        priority: u8,
    ) -> Result<(), EngineError> {
        self.record(RecordedCall::SetFilePriority {
            handle: h,
            file_idx,
            priority,
        });
        self.check_error("set_file_priority")
    }

    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError> {
        self.record(RecordedCall::SaveResumeData { handle: h, flags });
        self.check_error("save_resume_data")?;
        if self.auto_save_resume.load(Ordering::SeqCst) {
            self.push_alert(Alert::SaveResumeData {
                hdr: AlertHeader {
                    kind: AlertKind::SaveResumeData,
                    infohash: Some(h.infohash),
                    handle: Some(h),
                    timestamp_us: 0,
                },
                data: ResumeData::new(Vec::new()),
            });
        }
        Ok(())
    }

    fn force_recheck(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.record(RecordedCall::ForceRecheck(h));
        self.check_error("force_recheck")?;
        if self.auto_check.load(Ordering::SeqCst) {
            self.push_alert(Alert::TorrentChecked {
                hdr: AlertHeader {
                    kind: AlertKind::TorrentChecked,
                    infohash: Some(h.infohash),
                    handle: Some(h),
                    timestamp_us: 0,
                },
            });
        }
        Ok(())
    }

    fn force_reannounce(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.record(RecordedCall::ForceReannounce(h));
        self.check_error("force_reannounce")
    }

    fn move_storage(
        &self,
        h: TorrentHandle,
        new_path: &str,
        flags: MoveFlags,
    ) -> Result<(), EngineError> {
        self.record(RecordedCall::MoveStorage {
            handle: h,
            new_path: new_path.to_string(),
            flags,
        });
        self.check_error("move_storage")?;
        if self.auto_check.load(Ordering::SeqCst) {
            self.push_alert(Alert::StorageMoved {
                hdr: AlertHeader {
                    kind: AlertKind::StorageMoved,
                    infohash: Some(h.infohash),
                    handle: Some(h),
                    timestamp_us: 0,
                },
                path: new_path.to_string(),
            });
        }
        Ok(())
    }

    fn pop_alerts(&self) -> Vec<Alert> {
        self.record(RecordedCall::PopAlerts);
        // Taken out of the lock before sleeping, so arming another stall or
        // queueing an alert does not wait out this one.
        let stall = self.stall.lock().take();
        if let Some(d) = stall {
            std::thread::sleep(d);
        }
        self.alerts.lock().drain(..).collect()
    }

    fn post_updates(&self) {
        self.record(RecordedCall::PostUpdates);
    }
    fn post_stats(&self) {
        self.record(RecordedCall::PostStats);
    }

    fn apply_settings(&self, settings: &Settings) -> Result<(), EngineError> {
        self.record(RecordedCall::ApplySettings(settings.clone()));
        self.check_error("apply_settings")
    }

    fn session_state(&self) -> Result<Vec<u8>, EngineError> {
        self.record(RecordedCall::SessionState);
        self.check_error("session_state")?;
        Ok(Vec::new())
    }

    fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails, EngineError> {
        self.record(RecordedCall::TorrentDetails(h));
        self.check_error("torrent_details")?;
        Ok(self
            .details
            .get(&h.infohash)
            .map(|d| d.clone())
            .unwrap_or_else(Self::default_details))
    }

    fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>, EngineError> {
        self.record(RecordedCall::TorrentFiles(h));
        self.check_error("torrent_files")?;
        Ok(self.files.get(&h.infohash).and_then(|f| f.clone()))
    }

    fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>, EngineError> {
        self.record(RecordedCall::TorrentTrackers(h));
        self.check_error("torrent_trackers")?;
        Ok(self
            .trackers
            .get(&h.infohash)
            .map(|t| t.clone())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pop_alerts_returns_pushed_alerts_in_order() {
        let m = MockEngine::new();
        let hdr = libtorrent_safe::alert::AlertHeader {
            kind: libtorrent_safe::AlertKind::TorrentFinished,
            infohash: Some(InfoHash([0u8; 20])),
            handle: None,
            timestamp_us: 0,
        };
        m.push_alert(Alert::TorrentFinished { hdr: hdr.clone() });
        m.push_alert(Alert::TorrentFinished { hdr });
        let drained = m.pop_alerts();
        assert_eq!(drained.len(), 2);
        assert!(m.pop_alerts().is_empty());
    }

    #[test]
    fn inject_error_fires_once() {
        let m = MockEngine::new();
        let h = m.register_handle(InfoHash([1u8; 20]));
        m.inject_error("save_resume_data", EngineError::Shutdown);
        assert!(m
            .save_resume_data(h, ResumeFlags::ONLY_IF_MODIFIED)
            .is_err());
        // Second call: error consumed, succeeds.
        assert!(m.save_resume_data(h, ResumeFlags::ONLY_IF_MODIFIED).is_ok());
    }

    #[test]
    fn calls_recorder_captures_in_order() {
        let m = MockEngine::new();
        let h = m.register_handle(InfoHash([2u8; 20]));
        m.pause_torrent(h).unwrap();
        m.resume_torrent(h).unwrap();
        m.post_updates();
        let calls = m.calls();
        assert!(matches!(calls[0], RecordedCall::PauseTorrent(_)));
        assert!(matches!(calls[1], RecordedCall::ResumeTorrent(_)));
        assert!(matches!(calls[2], RecordedCall::PostUpdates));
    }

    #[test]
    fn inject_panic_panics_once_naming_the_op() {
        let m = MockEngine::new();
        m.inject_panic("apply_settings");
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            m.apply_settings(&Settings::default())
        }))
        .expect_err("the armed call panics");
        let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(msg.contains("apply_settings"), "{msg}");
        assert!(m.apply_settings(&Settings::default()).is_ok());
    }

    #[test]
    fn a_stall_blocks_one_pop_then_drains_what_was_queued() {
        let m = MockEngine::new();
        m.push_alert(Alert::TorrentFinished {
            hdr: AlertHeader {
                kind: AlertKind::TorrentFinished,
                infohash: Some(InfoHash([3u8; 20])),
                handle: None,
                timestamp_us: 0,
            },
        });
        m.stall_next_pop(Duration::from_millis(150));
        let started = std::time::Instant::now();
        assert_eq!(m.pop_alerts().len(), 1);
        assert!(started.elapsed() >= Duration::from_millis(150));
        let started = std::time::Instant::now();
        assert!(m.pop_alerts().is_empty());
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn torrent_queries_default_to_a_metadata_less_torrent() {
        let m = MockEngine::new();
        let h = m.register_handle(InfoHash([4u8; 20]));
        assert_eq!(m.torrent_details(h).unwrap(), MockEngine::default_details());
        assert_eq!(m.torrent_details(h).unwrap().save_path, "/");
        assert_eq!(m.torrent_files(h).unwrap(), None);
        assert!(m.torrent_trackers(h).unwrap().is_empty());
        let calls = m.calls();
        assert!(matches!(calls[0], RecordedCall::TorrentDetails(c) if c == h));
        assert!(matches!(calls[2], RecordedCall::TorrentFiles(c) if c == h));
        assert!(matches!(calls[3], RecordedCall::TorrentTrackers(c) if c == h));
    }

    #[test]
    fn torrent_queries_return_preloaded_data_per_handle() {
        let m = MockEngine::new();
        let a = m.register_handle(InfoHash([5u8; 20]));
        let b = m.register_handle(InfoHash([6u8; 20]));
        let details = TorrentDetails {
            name: Some("a".into()),
            has_metadata: true,
            total_size: Some(10),
            save_path: "/srv/a".into(),
            upload_limit: Some(1000),
            added_at: Some(1_700_000_000),
        };
        let files = vec![TorrentFile {
            index: 0,
            path: "a/x".into(),
            size: 10,
            downloaded: 10,
            priority: 4,
        }];
        let trackers = vec![TrackerEntry {
            url: "http://t/announce".into(),
            tier: 0,
            verified: true,
            updating: false,
            fails: 0,
            message: None,
            last_error: None,
            next_announce: Some(1_700_000_900),
            scrape_complete: Some(3),
            scrape_incomplete: None,
        }];
        m.set_torrent_details(a, details.clone());
        m.set_torrent_files(a, Some(files.clone()));
        m.set_torrent_trackers(a, trackers.clone());

        assert_eq!(m.torrent_details(a).unwrap(), details);
        assert_eq!(m.torrent_files(a).unwrap(), Some(files));
        assert_eq!(m.torrent_trackers(a).unwrap(), trackers);
        // Another handle still gets the defaults.
        assert_eq!(m.torrent_details(b).unwrap(), MockEngine::default_details());
        assert_eq!(m.torrent_files(b).unwrap(), None);
        assert!(m.torrent_trackers(b).unwrap().is_empty());

        // Preloading `None` models metadata that has not arrived.
        m.set_torrent_files(a, None);
        assert_eq!(m.torrent_files(a).unwrap(), None);
    }

    #[test]
    fn torrent_query_errors_inject_once_per_op() {
        let m = MockEngine::new();
        let h = m.register_handle(InfoHash([7u8; 20]));
        m.inject_error("torrent_details", EngineError::Shutdown);
        m.inject_error("torrent_files", EngineError::UnknownHandle(h.infohash));
        m.inject_error(
            "torrent_trackers",
            EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(h.infohash)),
        );
        assert!(matches!(m.torrent_details(h), Err(EngineError::Shutdown)));
        assert!(matches!(
            m.torrent_files(h),
            Err(EngineError::UnknownHandle(_))
        ));
        assert!(matches!(
            m.torrent_trackers(h),
            Err(EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(
                _
            )))
        ));
        assert!(m.torrent_details(h).is_ok());
        assert!(m.torrent_files(h).is_ok());
        assert!(m.torrent_trackers(h).is_ok());
    }

    #[test]
    fn without_recording_keeps_no_calls() {
        let m = MockEngine::new().without_recording();
        m.pop_alerts();
        m.post_updates();
        assert!(m.calls().is_empty());
    }
}
