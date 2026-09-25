//! `Session` — RAII handle around a libtorrent session.
//!
//! The struct is `!Send + !Sync` by construction (raw pointer field). The
//! engine layer wraps a `Session` in an `Arc<Mutex<…>>` or owns it from a
//! single thread; concurrent access is the caller's responsibility.
//!
//! Methods return `Result<…, Error>`, never panic on shim failures, and
//! never expose raw pointers.

use std::ffi::CString;
use std::marker::PhantomData;
use std::path::Path;

use libtorrent_sys as ffi;
use tracing::debug;

use crate::alert::Alert;
use crate::error::Error;
use crate::error::Result;
use crate::handle::InfoHash;
use crate::handle::TorrentHandle;
use crate::settings::MoveFlags;
use crate::settings::ResumeFlags;
use crate::settings::Settings;
use crate::settings::TorrentFlags;

/// Caller-friendly enum for `Session::add_torrent`.
#[derive(Clone, Debug)]
pub enum AddParams {
    File {
        bytes: Vec<u8>,
        save_path: String,
        flags: TorrentFlags,
    },
    Magnet {
        uri: String,
        save_path: String,
        flags: TorrentFlags,
    },
    /// Re-add from previously saved resume data.
    ///
    /// libtorrent only embeds the info dict in resume data when
    /// `save_resume_data` was called with `SAVE_INFO_DICT`, so resume data
    /// alone often carries no metadata and the torrent would re-enter
    /// `downloading_metadata` on restart. `torrent` supplies the `.torrent`
    /// bytes the daemon already keeps on disk to repair that, rather than
    /// bloating every resume file with a full piece-hash table.
    Resume {
        bytes: Vec<u8>,
        /// `.torrent` bytes, used only when the resume data has no info dict.
        torrent: Option<Vec<u8>>,
        /// Relocate the torrent's payload (adoption / relocation).
        save_path: Option<String>,
        /// Applied to the resume data's own flags, set before clear.
        flags_set: TorrentFlags,
        flags_clear: TorrentFlags,
    },
}

impl AddParams {
    /// Re-add from resume data with no overrides — the common restart path.
    pub fn resume(bytes: Vec<u8>) -> Self {
        Self::Resume {
            bytes,
            torrent: None,
            save_path: None,
            flags_set: TorrentFlags::empty(),
            flags_clear: TorrentFlags::empty(),
        }
    }
}

const ERR_BUF_LEN: usize = 512;

pub struct Session {
    ptr: *mut ffi::lt_session,
    _marker: PhantomData<()>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("ptr", &self.ptr).finish()
    }
}

// Safety: the C shim's `lt_session` is internally thread-safe — every shim
// function takes the per-session handle mutex before touching state. The
// underlying `lt::session` from libtorrent is documented thread-safe.
// `Session` is thus Send (ownership can move across threads). We deliberately
// do NOT implement Sync; engine layers that share a `Session` between threads
// place it behind a `Mutex` so calls are ordered, which keeps the FFI surface
// linearizable even though libtorrent would technically tolerate concurrent
// calls.
unsafe impl Send for Session {}

impl Session {
    /// Construct a new session with the given settings layered on top of
    /// libtorrent's `high_performance_seed()` preset.
    pub fn new(settings: &Settings) -> Result<Self> {
        let json = settings.to_shim_json()?;
        let json_c = CString::new(json).map_err(|_| Error::InteriorNul("settings_json".into()))?;
        let mut err = ErrBuf::new();
        let ptr = unsafe { ffi::lt_session_create(json_c.as_ptr(), err.ptr(), err.len() as i32) };
        if ptr.is_null() {
            return Err(Error::Shim(err.into_string()));
        }
        debug!(target: "libtorrent_safe", "session created");
        Ok(Self {
            ptr,
            _marker: PhantomData,
        })
    }

    /// Like [`Session::new`], but restores the DHT routing table + session
    /// state from a blob previously produced by [`Session::save_state`]. Used
    /// at startup for single-session (DHT-enabled) mode.
    pub fn with_state(settings: &Settings, state: &[u8]) -> Result<Self> {
        let json = settings.to_shim_json()?;
        let json_c = CString::new(json).map_err(|_| Error::InteriorNul("settings_json".into()))?;
        let mut err = ErrBuf::new();
        let ptr = unsafe {
            ffi::lt_session_create_with_state(
                json_c.as_ptr(),
                state.as_ptr(),
                state.len(),
                err.ptr(),
                err.len() as i32,
            )
        };
        if ptr.is_null() {
            return Err(Error::Shim(err.into_string()));
        }
        debug!(target: "libtorrent_safe", "session created from saved state");
        Ok(Self {
            ptr,
            _marker: PhantomData,
        })
    }

    /// Apply settings on a running session. Used by SIGHUP reload and per-profile
    /// startup overrides.
    pub fn apply_settings(&self, settings: &Settings) -> Result<()> {
        let json = settings.to_shim_json()?;
        let json_c = CString::new(json).map_err(|_| Error::InteriorNul("settings_json".into()))?;
        let mut err = ErrBuf::new();
        let rc = unsafe {
            ffi::lt_session_apply_settings(self.ptr, json_c.as_ptr(), err.ptr(), err.len() as i32)
        };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::Shim(err.into_string()))
        }
    }

    /// Save serialized session state (DHT routing table, settings) for
    /// restoration.
    pub fn save_state(&self) -> Result<Vec<u8>> {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let mut err = ErrBuf::new();
        let rc = unsafe {
            ffi::lt_session_save_state(self.ptr, &mut buf, &mut len, err.ptr(), err.len() as i32)
        };
        if rc != ffi::LT_OK as i32 {
            return Err(Error::Shim(err.into_string()));
        }
        if buf.is_null() || len == 0 {
            return Ok(Vec::new());
        }
        let v = unsafe { std::slice::from_raw_parts(buf, len).to_vec() };
        unsafe { ffi::lt_buf_free(buf) };
        Ok(v)
    }

    pub fn load_state(&self, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Err(Error::InvalidInput("empty session-state buffer"));
        }
        let mut err = ErrBuf::new();
        let rc = unsafe {
            ffi::lt_session_load_state(
                self.ptr,
                buf.as_ptr(),
                buf.len(),
                err.ptr(),
                err.len() as i32,
            )
        };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::Shim(err.into_string()))
        }
    }

    /// Add a torrent. Returns the stable `TorrentHandle` (or an error).
    pub fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle> {
        let mut err = ErrBuf::new();
        let mut infohash = [0u8; 20];

        let raw_handle = match params {
            AddParams::File {
                bytes,
                save_path,
                flags,
            } => {
                if bytes.is_empty() {
                    return Err(Error::InvalidInput("empty .torrent buffer"));
                }
                let save_c =
                    CString::new(save_path).map_err(|_| Error::InteriorNul("save_path".into()))?;
                unsafe {
                    ffi::lt_add_torrent_file(
                        self.ptr,
                        bytes.as_ptr(),
                        bytes.len(),
                        save_c.as_ptr(),
                        flags.bits(),
                        infohash.as_mut_ptr(),
                        err.ptr(),
                        err.len() as i32,
                    )
                }
            }
            AddParams::Magnet {
                uri,
                save_path,
                flags,
            } => {
                let uri_c =
                    CString::new(uri).map_err(|_| Error::InteriorNul("magnet uri".into()))?;
                let save_c =
                    CString::new(save_path).map_err(|_| Error::InteriorNul("save_path".into()))?;
                unsafe {
                    ffi::lt_add_torrent_magnet(
                        self.ptr,
                        uri_c.as_ptr(),
                        save_c.as_ptr(),
                        flags.bits(),
                        infohash.as_mut_ptr(),
                        err.ptr(),
                        err.len() as i32,
                    )
                }
            }
            AddParams::Resume {
                bytes,
                torrent,
                save_path,
                flags_set,
                flags_clear,
            } => {
                if bytes.is_empty() {
                    return Err(Error::InvalidInput("empty resume buffer"));
                }
                let save_c = save_path
                    .map(|p| CString::new(p).map_err(|_| Error::InteriorNul("save_path".into())))
                    .transpose()?;
                let (t_ptr, t_len) = match torrent.as_ref() {
                    Some(t) if !t.is_empty() => (t.as_ptr(), t.len()),
                    _ => (std::ptr::null(), 0),
                };
                unsafe {
                    ffi::lt_add_torrent_resume_ex(
                        self.ptr,
                        bytes.as_ptr(),
                        bytes.len(),
                        t_ptr,
                        t_len,
                        save_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                        flags_set.bits(),
                        flags_clear.bits(),
                        infohash.as_mut_ptr(),
                        err.ptr(),
                        err.len() as i32,
                    )
                }
            }
        };

        if raw_handle == 0 {
            return Err(Error::Shim(err.into_string()));
        }
        Ok(TorrentHandle {
            id: raw_handle as u64,
            infohash: InfoHash(infohash),
        })
    }

    pub fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<()> {
        let rc = unsafe {
            ffi::lt_remove_torrent(self.ptr, h.id as ffi::lt_handle, delete_files as i32)
        };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    pub fn pause_torrent(&self, h: TorrentHandle) -> Result<()> {
        let rc = unsafe { ffi::lt_torrent_pause(self.ptr, h.id as ffi::lt_handle) };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    pub fn resume_torrent(&self, h: TorrentHandle) -> Result<()> {
        let rc = unsafe { ffi::lt_torrent_resume(self.ptr, h.id as ffi::lt_handle) };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    pub fn set_upload_limit(&self, h: TorrentHandle, bytes_per_sec: i32) -> Result<()> {
        let rc = unsafe {
            ffi::lt_torrent_set_upload_limit(self.ptr, h.id as ffi::lt_handle, bytes_per_sec)
        };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    pub fn set_file_priority(&self, h: TorrentHandle, file_idx: i32, priority: u8) -> Result<()> {
        let rc = unsafe {
            ffi::lt_torrent_set_file_priority(self.ptr, h.id as ffi::lt_handle, file_idx, priority)
        };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    /// Re-hash the payload against the torrent's piece hashes (v1 SHA-1 / v2
    /// SHA-256 merkle). Asynchronous — completion arrives as
    /// `Alert::TorrentChecked`.
    pub fn force_recheck(&self, h: TorrentHandle) -> Result<()> {
        let rc = unsafe { ffi::lt_torrent_force_recheck(self.ptr, h.id as ffi::lt_handle) };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    /// Announce to every tracker now instead of at the next scheduled
    /// interval. Fire-and-forget — the outcome arrives as tracker alerts.
    pub fn force_reannounce(&self, h: TorrentHandle) -> Result<()> {
        let rc = unsafe { ffi::lt_torrent_force_reannounce(self.ptr, h.id as ffi::lt_handle) };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    /// Relocate the torrent's payload, letting libtorrent perform the move so
    /// its storage state stays consistent. Asynchronous — completion arrives
    /// as `Alert::StorageMoved` or `Alert::StorageMovedFailed`.
    pub fn move_storage(&self, h: TorrentHandle, new_path: &str, flags: MoveFlags) -> Result<()> {
        let path = CString::new(new_path).map_err(|_| Error::InteriorNul("new_path".into()))?;
        let rc = unsafe {
            ffi::lt_torrent_move_storage(
                self.ptr,
                h.id as ffi::lt_handle,
                path.as_ptr(),
                flags as u32,
            )
        };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    pub fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<()> {
        let rc =
            unsafe { ffi::lt_save_resume_data(self.ptr, h.id as ffi::lt_handle, flags.bits()) };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    /// Triggers a `state_update_alert` covering all subscribed torrents.
    pub fn post_torrent_updates(&self) {
        unsafe { ffi::lt_post_torrent_updates(self.ptr) }
    }

    /// Triggers a `session_stats_alert` with the current counters.
    pub fn post_session_stats(&self) {
        unsafe { ffi::lt_post_session_stats(self.ptr) }
    }

    /// Drain one alert from the queue. Returns `None` if empty (after one
    /// pop_alerts inside the shim has already drained the libtorrent side).
    pub fn pop_alert(&self) -> Option<Alert> {
        loop {
            let mut raw: ffi::lt_alert_union = unsafe { std::mem::zeroed() };
            let got = unsafe { ffi::lt_pop_alert(self.ptr, &mut raw) };
            if got == 0 {
                return None;
            }
            // SAFETY: raw is uninitialized only outside this branch; here it
            // was filled by lt_pop_alert.
            match unsafe { Alert::from_raw_owned(&mut raw) } {
                Some(alert) => return Some(alert),
                None => {
                    // Unknown alert kind. Skip and try the next one.
                    continue;
                }
            }
        }
    }

    /// Drain *all* alerts currently queued (after a single shim drain).
    ///
    /// Convenience for the engine's poll thread; equivalent to calling
    /// `pop_alert` in a loop until it returns None.
    pub fn drain_alerts(&self) -> Vec<Alert> {
        let mut out = Vec::new();
        while let Some(a) = self.pop_alert() {
            out.push(a);
        }
        out
    }
}

/// Compute the info-hash of a `.torrent` buffer without adding it to a
/// session — used to enforce registry uniqueness before any session sees the
/// torrent.
pub fn info_hash_from_torrent(bytes: &[u8]) -> Result<InfoHash> {
    if bytes.is_empty() {
        return Err(Error::InvalidInput("empty .torrent buffer"));
    }
    let mut out = [0u8; 20];
    let mut err = ErrBuf::new();
    let rc = unsafe {
        ffi::lt_torrent_info_hash(
            bytes.as_ptr(),
            bytes.len(),
            out.as_mut_ptr(),
            err.ptr(),
            err.len() as i32,
        )
    };
    if rc == ffi::LT_OK as i32 {
        Ok(InfoHash(out))
    } else {
        Err(Error::Shim(err.into_string()))
    }
}

/// Compute the info-hash encoded in a magnet URI without adding it.
pub fn info_hash_from_magnet(uri: &str) -> Result<InfoHash> {
    let uri_c = CString::new(uri).map_err(|_| Error::InteriorNul("magnet uri".into()))?;
    let mut out = [0u8; 20];
    let mut err = ErrBuf::new();
    let rc = unsafe {
        ffi::lt_magnet_info_hash(
            uri_c.as_ptr(),
            out.as_mut_ptr(),
            err.ptr(),
            err.len() as i32,
        )
    };
    if rc == ffi::LT_OK as i32 {
        Ok(InfoHash(out))
    } else {
        Err(Error::Shim(err.into_string()))
    }
}

/// Check whether any tracker host in a `.torrent` buffer matches one of
/// `domains` (exact or subdomain). Misconfiguration guard for profile assignment
///. Returns `Ok(false)` for an empty buffer
/// or empty domain list.
pub fn torrent_tracker_host_matches(bytes: &[u8], domains: &[String]) -> Result<bool> {
    if bytes.is_empty() || domains.is_empty() {
        return Ok(false);
    }
    let csv = domains.join(",");
    let csv_c = CString::new(csv).map_err(|_| Error::InteriorNul("domains".into()))?;
    let mut err = ErrBuf::new();
    let rc = unsafe {
        ffi::lt_torrent_tracker_host_matches(
            bytes.as_ptr(),
            bytes.len(),
            csv_c.as_ptr(),
            err.ptr(),
            err.len() as i32,
        )
    };
    match rc {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(Error::Shim(err.into_string())),
    }
}

/// Resolve a libtorrent session-stats counter name (e.g. `"net.sent_bytes"`)
/// to its index in the `session_stats_alert` counter array, or `None` if the
/// name is unknown to this libtorrent build. The mapping is a build-time
/// constant — resolve once and cache.
pub fn session_stats_metric_index(name: &str) -> Option<usize> {
    let c = CString::new(name).ok()?;
    let idx = unsafe { ffi::lt_session_stats_metric_index(c.as_ptr()) };
    if idx < 0 {
        None
    } else {
        Some(idx as usize)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::lt_session_destroy(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct ErrBuf {
    buf: [std::os::raw::c_char; ERR_BUF_LEN],
}

impl ErrBuf {
    fn new() -> Self {
        Self {
            buf: [0; ERR_BUF_LEN],
        }
    }
    fn ptr(&mut self) -> *mut std::os::raw::c_char {
        self.buf.as_mut_ptr()
    }
    fn len(&self) -> usize {
        ERR_BUF_LEN
    }

    fn into_string(self) -> String {
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(self.buf.as_ptr() as *const u8, ERR_BUF_LEN) };
        let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..nul]).into_owned()
    }
}

// `Path`-only helper for downstream callers. Not public; the AddParams
// variants already accept `String`.
#[allow(dead_code)]
fn path_to_string(p: &Path) -> Result<String> {
    p.to_str()
        .map(|s| s.to_string())
        .ok_or(Error::InvalidInput("non-UTF8 save_path"))
}

#[cfg(test)]
mod tests {
    // Real session tests require the C++ build to succeed; covered by the
    // integration tests in `crates/torrentd/tests`. Pure unit tests live in
    // settings.rs and handle.rs where they don't need libtorrent.
}
