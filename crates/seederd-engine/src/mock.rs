//! `MockEngine` — drives every Layer 1 unit test that needs a
//! `TorrentEngine` without touching libtorrent.
//!
//! Capabilities (matching PRD §3.3):
//!   - Pre-loaded alert queue: `push_alert(...)`.
//!   - Call recorder: every trait method records a `RecordedCall` so
//!     tests assert "this op was called with these args".
//!   - Per-method error injection: `inject_error("save_resume_data",
//!     EngineError::...)` makes the next call to that op fail.
//!   - Synthetic handle issuance: `register_handle(infohash)` returns a
//!     `TorrentHandle` the test can hold and pass back through the trait.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::engine::{EngineError, TorrentEngine};
use libtorrent_safe::{AddParams, Alert, InfoHash, ResumeFlags, Settings, TorrentHandle};

/// Trait-method invocation captured by `MockEngine`.
#[derive(Debug, Clone)]
pub enum RecordedCall {
    AddTorrent(AddParamsSummary),
    RemoveTorrent { handle: TorrentHandle, delete_files: bool },
    PauseTorrent(TorrentHandle),
    ResumeTorrent(TorrentHandle),
    SaveResumeData { handle: TorrentHandle, flags: ResumeFlags },
    PopAlerts,
    PostUpdates,
    PostStats,
    ApplySettings(Settings),
    SessionState,
}

/// Stripped-down view of `AddParams` so we can derive Clone/Debug
/// without dragging the byte buffers into every test assertion.
#[derive(Debug, Clone)]
pub enum AddParamsSummary {
    File { save_path: String, byte_len: usize, flags_bits: u32 },
    Magnet { uri: String, save_path: String, flags_bits: u32 },
    Resume { byte_len: usize },
}

impl From<&AddParams> for AddParamsSummary {
    fn from(p: &AddParams) -> Self {
        match p {
            AddParams::File { save_path, bytes, flags } =>
                AddParamsSummary::File {
                    save_path: save_path.clone(),
                    byte_len: bytes.len(),
                    flags_bits: flags.bits(),
                },
            AddParams::Magnet { uri, save_path, flags } =>
                AddParamsSummary::Magnet {
                    uri: uri.clone(),
                    save_path: save_path.clone(),
                    flags_bits: flags.bits(),
                },
            AddParams::Resume { bytes } =>
                AddParamsSummary::Resume { byte_len: bytes.len() },
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
    /// infohash → handle, so add/remove are consistent across calls.
    handles: DashMap<InfoHash, TorrentHandle>,
}

impl Default for MockEngine {
    fn default() -> Self { Self::new() }
}

impl MockEngine {
    pub fn new() -> Self {
        Self {
            alerts: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            next_handle_id: AtomicU64::new(1),
            error_inject: DashMap::new(),
            handles: DashMap::new(),
        }
    }

    // --- test fixture helpers -----------------------------------------------

    /// Queue an alert that the next `pop_alerts` call will surface.
    pub fn push_alert(&self, a: Alert) {
        self.alerts.lock().push_back(a);
    }

    pub fn push_alerts(&self, alerts: impl IntoIterator<Item = Alert>) {
        let mut g = self.alerts.lock();
        for a in alerts { g.push_back(a); }
    }

    /// Inject a one-shot error for a specific trait method (by name).
    /// Recognized op names: `add_torrent`, `remove_torrent`, `pause_torrent`,
    /// `resume_torrent`, `save_resume_data`, `apply_settings`, `session_state`.
    pub fn inject_error(&self, op: &'static str, err: EngineError) {
        self.error_inject.insert(op, err);
    }

    pub fn calls(&self) -> Vec<RecordedCall> { self.calls.lock().clone() }

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

    pub fn handle_count(&self) -> usize { self.handles.len() }

    // --- internal -----------------------------------------------------------

    fn record(&self, c: RecordedCall) {
        self.calls.lock().push(c);
    }

    fn check_error(&self, op: &'static str) -> Result<(), EngineError> {
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
            AddParams::Resume { bytes } | AddParams::File { bytes, .. } => {
                let mut buf = [0u8; 20];
                for (i, b) in bytes.iter().take(20).enumerate() { buf[i] = *b; }
                InfoHash(buf)
            }
            AddParams::Magnet { uri, .. } => {
                let mut buf = [0u8; 20];
                for (i, b) in uri.as_bytes().iter().take(20).enumerate() { buf[i] = *b; }
                InfoHash(buf)
            }
        };
        Ok(self.register_handle(ih))
    }

    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError> {
        self.record(RecordedCall::RemoveTorrent { handle: h, delete_files });
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

    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError> {
        self.record(RecordedCall::SaveResumeData { handle: h, flags });
        self.check_error("save_resume_data")
    }

    fn pop_alerts(&self) -> Vec<Alert> {
        self.record(RecordedCall::PopAlerts);
        self.alerts.lock().drain(..).collect()
    }

    fn post_updates(&self) { self.record(RecordedCall::PostUpdates); }
    fn post_stats(&self)   { self.record(RecordedCall::PostStats);   }

    fn apply_settings(&self, settings: &Settings) -> Result<(), EngineError> {
        self.record(RecordedCall::ApplySettings(settings.clone()));
        self.check_error("apply_settings")
    }

    fn session_state(&self) -> Result<Vec<u8>, EngineError> {
        self.record(RecordedCall::SessionState);
        self.check_error("session_state")?;
        Ok(Vec::new())
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
        assert!(m.save_resume_data(h, ResumeFlags::ONLY_IF_MODIFIED).is_err());
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
}
