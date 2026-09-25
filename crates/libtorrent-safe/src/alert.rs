//! Strongly-typed alert enum.
//!
//! `Alert` is the Rust-side mirror of `lt_alert_union`. Conversion happens in
//! `Session::pop_alert` via `Alert::from_raw_owned`, which copies all heap
//! payloads out of the C union into owned Rust values and then calls
//! `lt_alert_payload_free` so the C side never leaks.

use std::ffi::CStr;

use libtorrent_sys as ffi;

use crate::handle::InfoHash;
use crate::handle::TorrentHandle;
use crate::resume::ResumeData;

/// Compact tag enum mirroring `lt_alert_kind`. Useful for routing /
/// metrics keying without matching the full payload.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum AlertKind {
    AddTorrent,
    TorrentRemoved,
    StateUpdate,
    TorrentFinished,
    TorrentError,
    FileError,
    HashFailed,
    MetadataReceived,
    SaveResumeData,
    SaveResumeDataFailed,
    ListenFailed,
    ListenSucceeded,
    SessionStats,
    AlertsDropped,
    TrackerError,
    PeerDisconnected,
    TorrentLog,
    Log,
    TorrentChecked,
    StorageMoved,
    StorageMovedFailed,
}

impl AlertKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertKind::AddTorrent => "add_torrent",
            AlertKind::TorrentRemoved => "torrent_removed",
            AlertKind::StateUpdate => "state_update",
            AlertKind::TorrentFinished => "torrent_finished",
            AlertKind::TorrentError => "torrent_error",
            AlertKind::FileError => "file_error",
            AlertKind::HashFailed => "hash_failed",
            AlertKind::MetadataReceived => "metadata_received",
            AlertKind::SaveResumeData => "save_resume_data",
            AlertKind::SaveResumeDataFailed => "save_resume_data_failed",
            AlertKind::TorrentChecked => "torrent_checked",
            AlertKind::StorageMoved => "storage_moved",
            AlertKind::StorageMovedFailed => "storage_moved_failed",
            AlertKind::ListenFailed => "listen_failed",
            AlertKind::ListenSucceeded => "listen_succeeded",
            AlertKind::SessionStats => "session_stats",
            AlertKind::AlertsDropped => "alerts_dropped",
            AlertKind::TrackerError => "tracker_error",
            AlertKind::PeerDisconnected => "peer_disconnected",
            AlertKind::TorrentLog => "torrent_log",
            AlertKind::Log => "log",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AlertHeader {
    pub kind: AlertKind,
    pub infohash: Option<InfoHash>,
    pub handle: Option<TorrentHandle>,
    /// Microseconds since session start (libtorrent's clock).
    pub timestamp_us: i64,
}

#[derive(Clone, Debug)]
pub struct TorrentStatusView {
    pub handle: TorrentHandle,
    pub state: u32,
    pub flags: u32,
    pub total_uploaded: u64,
    pub total_payload_uploaded: u64,
    pub upload_rate: i64,
    pub download_rate: i64,
    pub num_peers: i32,
    pub num_seeds: i32,
    pub num_connections: i32,
    pub progress: f32,
    pub has_metadata: bool,
    pub needs_save_resume: bool,
    pub is_finished: bool,
    pub is_seeding: bool,
    /// libtorrent holds an error on this torrent (`torrent_status::errc`).
    /// A disk error that is not routed to upload mode sets one and pauses
    /// the torrent; `resume()` clears it.
    pub has_error: bool,
}

#[derive(Clone, Debug)]
pub enum Alert {
    AddTorrent {
        hdr: AlertHeader,
        error_code: i32,
        message: Option<String>,
    },
    TorrentRemoved {
        hdr: AlertHeader,
    },
    StateUpdate {
        hdr: AlertHeader,
        statuses: Vec<TorrentStatusView>,
    },
    TorrentFinished {
        hdr: AlertHeader,
    },
    TorrentError {
        hdr: AlertHeader,
        error_code: i32,
        filename: String,
        message: String,
    },
    FileError {
        hdr: AlertHeader,
        error_code: i32,
        filename: String,
        operation: String,
        message: String,
    },
    HashFailed {
        hdr: AlertHeader,
        piece_index: i32,
    },
    MetadataReceived {
        hdr: AlertHeader,
        info_section: Vec<u8>,
    },
    SaveResumeData {
        hdr: AlertHeader,
        data: ResumeData,
    },
    SaveResumeDataFailed {
        hdr: AlertHeader,
        error_code: i32,
        not_modified: bool,
        message: String,
    },
    ListenFailed {
        hdr: AlertHeader,
        error_code: i32,
        operation: String,
        endpoint: String,
        iface: String,
        message: String,
    },
    ListenSucceeded {
        hdr: AlertHeader,
        endpoint: String,
    },
    /// A `force_recheck` finished hashing the payload. The result is read from
    /// the following `StateUpdate` (progress / is_seeding), not from here.
    TorrentChecked {
        hdr: AlertHeader,
    },
    /// `move_storage` completed; `path` is the new save path.
    StorageMoved {
        hdr: AlertHeader,
        path: String,
    },
    StorageMovedFailed {
        hdr: AlertHeader,
        error_code: i32,
        operation: String,
        path: String,
        message: String,
    },
    SessionStats {
        hdr: AlertHeader,
        counters: Vec<i64>,
        timestamp_ns: i64,
    },
    AlertsDropped {
        hdr: AlertHeader,
        bits: [u64; 2],
    },
    TrackerError {
        hdr: AlertHeader,
        error_code: i32,
        times_in_row: i32,
        tracker_url: String,
        message: String,
    },
    PeerDisconnected {
        hdr: AlertHeader,
        peer_address: String,
        error_code: i32,
        message: String,
    },
    TorrentLog {
        hdr: AlertHeader,
        message: String,
    },
    Log {
        hdr: AlertHeader,
        message: String,
    },
}

impl Alert {
    pub fn header(&self) -> &AlertHeader {
        match self {
            Alert::AddTorrent { hdr, .. }
            | Alert::TorrentRemoved { hdr, .. }
            | Alert::StateUpdate { hdr, .. }
            | Alert::TorrentFinished { hdr, .. }
            | Alert::TorrentError { hdr, .. }
            | Alert::FileError { hdr, .. }
            | Alert::HashFailed { hdr, .. }
            | Alert::MetadataReceived { hdr, .. }
            | Alert::SaveResumeData { hdr, .. }
            | Alert::SaveResumeDataFailed { hdr, .. }
            | Alert::ListenFailed { hdr, .. }
            | Alert::ListenSucceeded { hdr, .. }
            | Alert::TorrentChecked { hdr, .. }
            | Alert::StorageMoved { hdr, .. }
            | Alert::StorageMovedFailed { hdr, .. }
            | Alert::SessionStats { hdr, .. }
            | Alert::AlertsDropped { hdr, .. }
            | Alert::TrackerError { hdr, .. }
            | Alert::PeerDisconnected { hdr, .. }
            | Alert::TorrentLog { hdr, .. }
            | Alert::Log { hdr, .. } => hdr,
        }
    }

    pub fn kind(&self) -> AlertKind {
        self.header().kind
    }
    pub fn infohash(&self) -> Option<InfoHash> {
        self.header().infohash
    }

    /// Convert from a popped `lt_alert_union`, taking ownership of heap
    /// payloads. Callers MUST NOT call `lt_alert_payload_free` separately —
    /// this function does it.
    ///
    /// Returns `None` if the union's `kind` is not recognized (e.g. if the
    /// shim is updated to emit a kind older safe-wrapper code does not yet
    /// know about).
    ///
    /// # Safety
    /// `raw` must be a value previously written by `lt_pop_alert`. After
    /// this call returns, the union's heap fields are zeroed; passing the
    /// same `raw` to `lt_alert_payload_free` is a no-op.
    pub(crate) unsafe fn from_raw_owned(raw: &mut ffi::lt_alert_union) -> Option<Self> {
        let kind = match raw.kind {
            ffi::lt_alert_kind_LT_ALERT_ADD_TORRENT => AlertKind::AddTorrent,
            ffi::lt_alert_kind_LT_ALERT_TORRENT_REMOVED => AlertKind::TorrentRemoved,
            ffi::lt_alert_kind_LT_ALERT_STATE_UPDATE => AlertKind::StateUpdate,
            ffi::lt_alert_kind_LT_ALERT_TORRENT_FINISHED => AlertKind::TorrentFinished,
            ffi::lt_alert_kind_LT_ALERT_TORRENT_ERROR => AlertKind::TorrentError,
            ffi::lt_alert_kind_LT_ALERT_FILE_ERROR => AlertKind::FileError,
            ffi::lt_alert_kind_LT_ALERT_HASH_FAILED => AlertKind::HashFailed,
            ffi::lt_alert_kind_LT_ALERT_METADATA_RECEIVED => AlertKind::MetadataReceived,
            ffi::lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA => AlertKind::SaveResumeData,
            ffi::lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA_FAILED => AlertKind::SaveResumeDataFailed,
            ffi::lt_alert_kind_LT_ALERT_LISTEN_FAILED => AlertKind::ListenFailed,
            ffi::lt_alert_kind_LT_ALERT_LISTEN_SUCCEEDED => AlertKind::ListenSucceeded,
            ffi::lt_alert_kind_LT_ALERT_SESSION_STATS => AlertKind::SessionStats,
            ffi::lt_alert_kind_LT_ALERT_ALERTS_DROPPED => AlertKind::AlertsDropped,
            ffi::lt_alert_kind_LT_ALERT_TRACKER_ERROR => AlertKind::TrackerError,
            ffi::lt_alert_kind_LT_ALERT_PEER_DISCONNECTED => AlertKind::PeerDisconnected,
            ffi::lt_alert_kind_LT_ALERT_TORRENT_LOG => AlertKind::TorrentLog,
            ffi::lt_alert_kind_LT_ALERT_LOG => AlertKind::Log,
            ffi::lt_alert_kind_LT_ALERT_TORRENT_CHECKED => AlertKind::TorrentChecked,
            ffi::lt_alert_kind_LT_ALERT_STORAGE_MOVED => AlertKind::StorageMoved,
            ffi::lt_alert_kind_LT_ALERT_STORAGE_MOVED_FAILED => AlertKind::StorageMovedFailed,
            _ => {
                // Unknown — still free any payload to avoid leaks.
                unsafe { ffi::lt_alert_payload_free(raw as *mut _) };
                return None;
            }
        };

        let infohash = if raw.infohash == [0u8; 20] {
            None
        } else {
            Some(InfoHash(raw.infohash))
        };
        let handle = TorrentHandle::from_raw(raw.handle as u64, raw.infohash);
        let hdr = AlertHeader {
            kind,
            infohash,
            handle,
            timestamp_us: raw.timestamp_us,
        };

        let alert = match kind {
            AlertKind::AddTorrent => {
                let p = unsafe { &raw.payload.add_torrent };
                let msg = c_str_to_owned(&p.message);
                Alert::AddTorrent {
                    hdr,
                    error_code: p.error_code,
                    message: if p.error_code == 0 { None } else { Some(msg) },
                }
            }
            AlertKind::TorrentRemoved => Alert::TorrentRemoved { hdr },
            AlertKind::StateUpdate => {
                let p = unsafe { &raw.payload.state_update };
                let count = p.count;
                let mut statuses = Vec::with_capacity(count);
                if !p.statuses.is_null() {
                    let slice = unsafe { std::slice::from_raw_parts(p.statuses, count) };
                    for s in slice {
                        if let Some(handle) = TorrentHandle::from_raw(s.handle as u64, s.infohash) {
                            statuses.push(TorrentStatusView {
                                handle,
                                state: s.state,
                                flags: s.flags,
                                total_uploaded: s.total_uploaded,
                                total_payload_uploaded: s.total_payload_uploaded,
                                upload_rate: s.upload_rate,
                                download_rate: s.download_rate,
                                num_peers: s.num_peers,
                                num_seeds: s.num_seeds,
                                num_connections: s.num_connections,
                                progress: s.progress,
                                has_metadata: s.has_metadata != 0,
                                needs_save_resume: s.needs_save_resume != 0,
                                is_finished: s.is_finished != 0,
                                is_seeding: s.is_seeding != 0,
                                has_error: s.has_error != 0,
                            });
                        }
                    }
                }
                Alert::StateUpdate { hdr, statuses }
            }
            AlertKind::TorrentFinished => Alert::TorrentFinished { hdr },
            AlertKind::TorrentError => {
                let p = unsafe { &raw.payload.torrent_error };
                Alert::TorrentError {
                    hdr,
                    error_code: p.error_code,
                    filename: c_str_to_owned(&p.filename),
                    message: c_str_to_owned(&p.message),
                }
            }
            AlertKind::FileError => {
                let p = unsafe { &raw.payload.file_error };
                Alert::FileError {
                    hdr,
                    error_code: p.error_code,
                    filename: c_str_to_owned(&p.filename),
                    operation: c_str_to_owned(&p.operation),
                    message: c_str_to_owned(&p.message),
                }
            }
            AlertKind::HashFailed => {
                let p = unsafe { &raw.payload.hash_failed };
                Alert::HashFailed {
                    hdr,
                    piece_index: p.piece_index,
                }
            }
            AlertKind::MetadataReceived => {
                let p = unsafe { &raw.payload.metadata_received };
                let bytes = if p.buf.is_null() {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.buf, p.len).to_vec() }
                };
                Alert::MetadataReceived {
                    hdr,
                    info_section: bytes,
                }
            }
            AlertKind::SaveResumeData => {
                let p = unsafe { &raw.payload.save_resume };
                let bytes = if p.buf.is_null() {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.buf, p.len).to_vec() }
                };
                Alert::SaveResumeData {
                    hdr,
                    data: ResumeData(bytes),
                }
            }
            AlertKind::SaveResumeDataFailed => {
                let p = unsafe { &raw.payload.resume_failed };
                Alert::SaveResumeDataFailed {
                    hdr,
                    error_code: p.error_code,
                    not_modified: p.not_modified != 0,
                    message: c_str_to_owned(&p.message),
                }
            }
            AlertKind::ListenFailed => {
                let p = unsafe { &raw.payload.listen_failed };
                Alert::ListenFailed {
                    hdr,
                    error_code: p.error_code,
                    operation: c_str_to_owned(&p.operation),
                    endpoint: c_str_to_owned(&p.endpoint),
                    iface: c_str_to_owned(&p.iface),
                    message: c_str_to_owned(&p.message),
                }
            }
            AlertKind::ListenSucceeded => {
                let p = unsafe { &raw.payload.listen_succeeded };
                Alert::ListenSucceeded {
                    hdr,
                    endpoint: c_str_to_owned(&p.endpoint),
                }
            }
            AlertKind::TorrentChecked => Alert::TorrentChecked { hdr },
            AlertKind::StorageMoved => {
                let p = unsafe { &raw.payload.storage_moved };
                Alert::StorageMoved {
                    hdr,
                    path: c_str_to_owned(&p.path),
                }
            }
            AlertKind::StorageMovedFailed => {
                let p = unsafe { &raw.payload.storage_moved_failed };
                Alert::StorageMovedFailed {
                    hdr,
                    error_code: p.error_code,
                    operation: c_str_to_owned(&p.operation),
                    path: c_str_to_owned(&p.path),
                    message: c_str_to_owned(&p.message),
                }
            }
            AlertKind::SessionStats => {
                let p = unsafe { &raw.payload.session_stats };
                let counters = if p.counters.is_null() {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.counters, p.count).to_vec() }
                };
                Alert::SessionStats {
                    hdr,
                    counters,
                    timestamp_ns: p.timestamp_ns,
                }
            }
            AlertKind::AlertsDropped => {
                let p = unsafe { &raw.payload.alerts_dropped };
                Alert::AlertsDropped { hdr, bits: p.bits }
            }
            AlertKind::TrackerError => {
                let p = unsafe { &raw.payload.tracker_error };
                Alert::TrackerError {
                    hdr,
                    error_code: p.error_code,
                    times_in_row: p.times_in_row,
                    tracker_url: c_str_to_owned(&p.tracker_url),
                    message: c_str_to_owned(&p.message),
                }
            }
            AlertKind::PeerDisconnected => {
                let p = unsafe { &raw.payload.peer_disconnected };
                Alert::PeerDisconnected {
                    hdr,
                    peer_address: c_str_to_owned(&p.peer_address),
                    error_code: p.error_code,
                    message: c_str_to_owned(&p.message),
                }
            }
            AlertKind::TorrentLog | AlertKind::Log => {
                let p = unsafe { &raw.payload.log_msg };
                let msg = c_str_to_owned(&p.message);
                if matches!(kind, AlertKind::TorrentLog) {
                    Alert::TorrentLog { hdr, message: msg }
                } else {
                    Alert::Log { hdr, message: msg }
                }
            }
        };

        // We've copied all heap payloads; release the C-side allocations.
        unsafe { ffi::lt_alert_payload_free(raw as *mut _) };
        let _ = infohash; // keep the variable alive for the unused-warning lint
        Some(alert)
    }
}

/// Read a fixed-size NUL-terminated C buffer (e.g. `[c_char; LT_MSG_MAX]`)
/// into an owned UTF-8 String. Invalid UTF-8 is replaced with U+FFFD; we
/// never want a stray byte from libtorrent to crash the daemon.
fn c_str_to_owned(buf: &[std::os::raw::c_char]) -> String {
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    // No NUL found — fall back to an empty string rather than read past the
    // buffer. `c""` is a `&'static CStr`; no `unsafe` needed.
    let cstr = CStr::from_bytes_until_nul(bytes).unwrap_or(c"");
    String::from_utf8_lossy(cstr.to_bytes()).into_owned()
}
