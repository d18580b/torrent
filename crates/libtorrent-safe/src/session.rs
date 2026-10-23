//! `Session` — RAII handle around a libtorrent session.
//!
//! The struct is `Send` but not `Sync`: its raw pointer field would make it
//! neither, and `Send` is asserted below on the shim's own locking. The
//! engine layer owns it behind a `Mutex` (`torrentd-engine`'s `RealEngine`),
//! so calls from several threads are ordered.
//!
//! Methods return `Result<…, Error>`, never panic on shim failures, and
//! never expose raw pointers.

use std::cell::Cell;
use std::ffi::CString;
use std::marker::PhantomData;

use libtorrent_sys as ffi;
use tracing::debug;

use crate::alert::Alert;
use crate::alert::TorrentStatusView;
use crate::error::Error;
use crate::error::Result;
use crate::handle::InfoHash;
use crate::handle::TorrentHandle;
use crate::metadata::InfoHashes;
use crate::settings::MoveFlags;
use crate::settings::ResumeFlags;
use crate::settings::Settings;
use crate::settings::TorrentFlags;
use crate::torrent_info::DetailsGuard;
use crate::torrent_info::FileListGuard;
use crate::torrent_info::FilePage;
use crate::torrent_info::TorrentDetails;
use crate::torrent_info::TorrentFile;
use crate::torrent_info::TrackerEntry;
use crate::torrent_info::TrackerListGuard;

/// Caller-friendly enum for `Session::add_torrent`.
#[derive(Clone, Debug)]
pub enum AddParams {
    File {
        bytes: Vec<u8>,
        save_path: String,
        flags: TorrentFlags,
        /// Announce URLs by tier that replace the `.torrent`'s own, the way a
        /// resume file's `trackers` list does. Empty keeps the `.torrent`'s.
        trackers: Vec<Vec<String>>,
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
    /// Re-add from resume data with no relocation and no `.torrent` — the
    /// plain restart path. Asserts `UPLOAD_MODE` and clears every flag that
    /// could lift it, as the shim does on every add anyway: a constructor that
    /// reads as "no overrides" must not be the one path that says otherwise.
    pub fn resume(bytes: Vec<u8>) -> Self {
        Self::Resume {
            bytes,
            torrent: None,
            save_path: None,
            flags_set: TorrentFlags::UPLOAD_MODE,
            flags_clear: FORBIDDEN_TORRENT_FLAGS,
        }
    }
}

/// Flags no torrent the daemon adds may carry, because each can take it out
/// of upload mode (`AUTO_MANAGED`), requests pieces by design (`SHARE_MODE`),
/// or is a downloading client's knob with no meaning for a torrent that never
/// leaves upload mode.
///
/// The one Rust copy of the set: [`AddParams::resume`] clears it and the
/// engine's add-time policy states it from here. The shim keeps the same set
/// as libtorrent flags (`forbidden_torrent_flags` in `libtorrent_shim.cpp`)
/// and clears it on every add whatever the caller passes, so a change here is
/// a change there too.
pub const FORBIDDEN_TORRENT_FLAGS: TorrentFlags = TorrentFlags::AUTO_MANAGED
    .union(TorrentFlags::SHARE_MODE)
    .union(TorrentFlags::SUPER_SEEDING)
    .union(TorrentFlags::SEQUENTIAL_DOWNLOAD)
    .union(TorrentFlags::STOP_WHEN_READY);

const ERR_BUF_LEN: usize = 512;

pub struct Session {
    ptr: *mut ffi::lt_session,
    /// Alerts [`Session::pop_alert`] popped and skipped because their kind is
    /// none this crate translates. Counted into
    /// [`Session::alert_translate_errors`].
    unknown_alerts: Cell<u64>,
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
        let json_c = c_string(json, "settings_json")?;
        let mut err = ErrBuf::new();
        let ptr = unsafe { ffi::lt_session_create(json_c.as_ptr(), err.ptr(), err.len() as i32) };
        if ptr.is_null() {
            return Err(Error::Shim(err.into_string()));
        }
        debug!(target: "libtorrent_safe", "session created");
        Ok(Self {
            ptr,
            unknown_alerts: Cell::new(0),
            _marker: PhantomData,
        })
    }

    /// Like [`Session::new`], but restores the DHT routing table + session
    /// state from a blob previously produced by [`Session::save_state`]. Used
    /// at startup for single-session (DHT-enabled) mode.
    pub fn with_state(settings: &Settings, state: &[u8]) -> Result<Self> {
        let json = settings.to_shim_json()?;
        let json_c = c_string(json, "settings_json")?;
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
            unknown_alerts: Cell::new(0),
            _marker: PhantomData,
        })
    }

    /// Apply settings on a running session. Used by SIGHUP reload and per-profile
    /// startup overrides.
    pub fn apply_settings(&self, settings: &Settings) -> Result<()> {
        let json = settings.to_shim_json()?;
        let json_c = c_string(json, "settings_json")?;
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

    /// Pause the whole session: no announce, no peer, no incoming connection,
    /// for every torrent it holds and every torrent added while it stays
    /// paused. Each torrent's own paused flag is untouched, so
    /// [`Session::resume`] puts back exactly what was running. Queued in
    /// order with every other call, so a pause before an add covers it.
    pub fn pause(&self) -> Result<()> {
        let rc = unsafe { ffi::lt_session_pause(self.ptr) };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::Shim("session pause failed".to_owned()))
        }
    }

    /// Undo [`Session::pause`].
    pub fn resume(&self) -> Result<()> {
        let rc = unsafe { ffi::lt_session_resume(self.ptr) };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::Shim("session resume failed".to_owned()))
        }
    }

    /// Whether the session is paused, as of every pause or resume issued
    /// before this call.
    pub fn is_paused(&self) -> Result<bool> {
        match unsafe { ffi::lt_session_is_paused(self.ptr) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Shim("session pause state unreadable".to_owned())),
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
                trackers,
            } => {
                if bytes.is_empty() {
                    return Err(Error::InvalidInput("empty .torrent buffer"));
                }
                let save_c = c_string(save_path, "save_path")?;
                let trackers = TrackerOverride::new(&trackers)?;
                unsafe {
                    ffi::lt_add_torrent_file(
                        self.ptr,
                        bytes.as_ptr(),
                        bytes.len(),
                        save_c.as_ptr(),
                        flags.bits(),
                        trackers.urls_ptr(),
                        trackers.tiers.as_ptr(),
                        trackers.len(),
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
                let uri_c = c_string(uri, "magnet uri")?;
                let save_c = c_string(save_path, "save_path")?;
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
                let save_c = save_path.map(|p| c_string(p, "save_path")).transpose()?;
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

    /// Clear `flags` on one torrent; bits it does not carry stay as they are.
    ///
    /// Only the discovery guards — [`TorrentFlags::DISABLE_PEX`],
    /// [`TorrentFlags::DISABLE_DHT`] and [`TorrentFlags::DISABLE_LSD`] — may
    /// be cleared: anything else is [`Error::InvalidInput`] and reaches no
    /// torrent, so this can never lift upload mode. libtorrent writes the
    /// three bits into resume data, so the change survives a restart only
    /// once a resume save follows it.
    pub fn unset_flags(&self, h: TorrentHandle, flags: TorrentFlags) -> Result<()> {
        let clearable =
            TorrentFlags::DISABLE_PEX | TorrentFlags::DISABLE_DHT | TorrentFlags::DISABLE_LSD;
        if !clearable.contains(flags) {
            return Err(Error::InvalidInput(
                "only DISABLE_PEX, DISABLE_DHT and DISABLE_LSD can be cleared",
            ));
        }
        let rc =
            unsafe { ffi::lt_torrent_unset_flags(self.ptr, h.id as ffi::lt_handle, flags.bits()) };
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
        let path = c_string(new_path, "new_path")?;
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

    /// Name, size, save path, upload limit and added time of one torrent.
    /// Synchronous: libtorrent answers from its network thread.
    pub fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails> {
        let mut raw = DetailsGuard::new();
        let mut err = ErrBuf::new();
        let rc = unsafe {
            ffi::lt_torrent_details(
                self.ptr,
                h.id as ffi::lt_handle,
                &mut raw.0,
                err.ptr(),
                err.len() as i32,
            )
        };
        if rc != ffi::LT_OK as i32 {
            return Err(query_error(h, err));
        }
        Ok(raw.details())
    }

    /// The torrent's files in index order, or `None` while its metadata has
    /// not arrived yet (a magnet still fetching it).
    pub fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>> {
        self.torrent_files_raw(h, 0, usize::MAX)
            .map(RawFileList::into_files)
    }

    /// At most `limit` of the torrent's files, from index `start` on, and
    /// how many it has in all; `None` while its metadata has not arrived.
    ///
    /// Only the page is copied out of the session, so listing a large
    /// torrent page by page costs each page its own size, not the whole list.
    pub fn torrent_files_page(
        &self,
        h: TorrentHandle,
        start: u32,
        limit: u32,
    ) -> Result<Option<FilePage>> {
        self.torrent_files_raw(h, start as usize, limit as usize)
            .map(RawFileList::into_page)
    }

    /// At most `limit` of the torrent's files from index `start` on, as the
    /// shim returned them, unconverted. `limit` `usize::MAX` is the whole list.
    ///
    /// Converting is a copy of every path in the page, and needs nothing from
    /// the session. A caller that serialises session access behind a lock
    /// takes this under the lock and calls [`RawFileList::into_page`] or
    /// [`RawFileList::into_files`] after releasing it.
    pub fn torrent_files_raw(
        &self,
        h: TorrentHandle,
        start: usize,
        limit: usize,
    ) -> Result<RawFileList> {
        let mut list = FileListGuard::new();
        let mut err = ErrBuf::new();
        let rc = unsafe {
            ffi::lt_torrent_files(
                self.ptr,
                h.id as ffi::lt_handle,
                start,
                limit,
                &mut list.0,
                err.ptr(),
                err.len() as i32,
            )
        };
        if rc != ffi::LT_OK as i32 {
            return Err(query_error(h, err));
        }
        Ok(RawFileList(list))
    }

    /// The torrent's trackers, tier by tier, with their announce state.
    pub fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>> {
        let mut list = TrackerListGuard::new();
        let mut err = ErrBuf::new();
        let rc = unsafe {
            ffi::lt_torrent_trackers(
                self.ptr,
                h.id as ffi::lt_handle,
                &mut list.0,
                err.ptr(),
                err.len() as i32,
            )
        };
        if rc != ffi::LT_OK as i32 {
            return Err(query_error(h, err));
        }
        Ok(list.entries().iter().map(TrackerEntry::from_raw).collect())
    }

    /// Triggers a `state_update_alert` covering all subscribed torrents.
    pub fn post_torrent_updates(&self) {
        unsafe { ffi::lt_post_torrent_updates(self.ptr) }
    }

    /// Every torrent's status, read from the session now, in the shape a
    /// `state_update_alert` carries, whether or not it changed since the last
    /// [`Session::post_torrent_updates`]. libtorrent posts a torrent again
    /// only once its status changes again, so this is the only way to learn
    /// the status of a paused or idle torrent whose update was dropped.
    pub fn torrent_statuses(&self) -> Result<Vec<TorrentStatusView>> {
        let mut list = StatusListGuard::new();
        let mut err = ErrBuf::new();
        let rc =
            unsafe { ffi::lt_torrent_statuses(self.ptr, &mut list.0, err.ptr(), err.len() as i32) };
        if rc != ffi::LT_OK as i32 {
            return Err(Error::Shim(err.into_string()));
        }
        Ok(list
            .statuses()
            .iter()
            .filter_map(TorrentStatusView::from_raw)
            .collect())
    }

    /// Triggers a `session_stats_alert` with the current counters.
    pub fn post_session_stats(&self) {
        unsafe { ffi::lt_post_session_stats(self.ptr) }
    }

    /// Drain one alert from the queue. Returns `None` if empty (after one
    /// pop_alerts inside the shim has already drained the libtorrent side).
    pub fn pop_alert(&self) -> Option<Alert> {
        skip_unknown(&self.unknown_alerts, || {
            let mut raw: ffi::lt_alert_union = unsafe { std::mem::zeroed() };
            let got = unsafe { ffi::lt_pop_alert(self.ptr, &mut raw) };
            if got == 0 {
                return None;
            }
            // SAFETY: raw is uninitialized only outside this branch; here it
            // was filled by lt_pop_alert.
            Some(unsafe { Alert::from_raw_owned(&mut raw) })
        })
    }

    /// How many alerts this session popped from libtorrent and then dropped
    /// because translating them failed: the shim's own count, of alerts it
    /// could not copy out, plus every alert [`Session::pop_alert`] skipped
    /// because its kind is none this crate translates. Either is an alert the
    /// daemon never saw, and each is dropped on its own while the rest of the
    /// queue is still delivered, so a nonzero count is alerts lost one at a
    /// time, not a stalled queue. Monotonic for the session's lifetime.
    pub fn alert_translate_errors(&self) -> u64 {
        let shim = unsafe { ffi::lt_alert_translate_errors(self.ptr) };
        shim.saturating_add(self.unknown_alerts.get())
    }

    /// Test-only: hand torrent `h` the peer at `peer` to connect to.
    /// Asynchronous; the session dials it once the torrent wants peers, and
    /// calling again for a peer it already knows is harmless.
    ///
    /// The daemon never dials a peer by address. This exists so a test can put
    /// a seeder next to a torrent and show the torrent takes nothing from it.
    #[cfg(feature = "test-api")]
    pub fn connect_peer(&self, h: TorrentHandle, peer: std::net::SocketAddr) -> Result<()> {
        let ip = c_string(peer.ip().to_string(), "peer ip")?;
        let rc = unsafe {
            ffi::lt_test_connect_peer(self.ptr, h.id as ffi::lt_handle, ip.as_ptr(), peer.port())
        };
        if rc == ffi::LT_OK as i32 {
            Ok(())
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    /// Test-only: the payload bytes torrent `h` has received from peers since
    /// it was added to this session (libtorrent's `total_payload_download`).
    ///
    /// Not in [`TorrentStatusView`]: no torrent the daemon adds downloads, and
    /// this is how a test shows that.
    #[cfg(feature = "test-api")]
    pub fn total_payload_download(&self, h: TorrentHandle) -> Result<u64> {
        let mut out = 0u64;
        let rc = unsafe {
            ffi::lt_test_total_payload_download(self.ptr, h.id as ffi::lt_handle, &mut out)
        };
        if rc == ffi::LT_OK as i32 {
            Ok(out)
        } else {
            Err(Error::TorrentNotFound(h.infohash))
        }
    }

    /// Drain *all* alerts currently queued (after a single shim drain).
    ///
    /// Convenience for the engine's poll thread; equivalent to calling
    /// `pop_alert` in a loop until it returns None.
    pub fn drain_alerts(&self) -> Vec<Alert> {
        self.drain_alerts_up_to(usize::MAX)
    }

    /// Drain at most `max` queued alerts. Whatever is left stays queued for
    /// the next call, so a caller holding a lock across this bounds how long
    /// it holds it.
    pub fn drain_alerts_up_to(&self, max: usize) -> Vec<Alert> {
        let mut out = Vec::new();
        while out.len() < max {
            match self.pop_alert() {
                Some(a) => out.push(a),
                None => break,
            }
        }
        out
    }
}

/// A torrent's file list as the shim filled it, owned until dropped.
///
/// Not `Send`: it owns a buffer the shim allocated, and nothing here needs to
/// move it across threads.
pub struct RawFileList(FileListGuard);

impl std::fmt::Debug for RawFileList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawFileList")
            .field("has_metadata", &(self.0 .0.has_metadata != 0))
            .field("num_files", &self.0.entries().len())
            .field("total_files", &self.0 .0.total_files)
            .field("first_index", &self.0 .0.first_index)
            .finish()
    }
}

impl RawFileList {
    /// The page's files in index order, or `None` while the torrent's
    /// metadata has not arrived.
    pub fn into_files(self) -> Option<Vec<TorrentFile>> {
        self.into_page().map(|p| p.files)
    }

    /// The page with the torrent's file count, or `None` while the torrent's
    /// metadata has not arrived.
    pub fn into_page(self) -> Option<FilePage> {
        let raw = &self.0 .0;
        if raw.has_metadata == 0 {
            return None;
        }
        // Both fit: libtorrent indexes files with an int.
        let total = u32::try_from(raw.total_files).unwrap_or(u32::MAX);
        let first = u32::try_from(raw.first_index).unwrap_or(u32::MAX);
        Some(FilePage {
            total,
            files: (first..)
                .zip(self.0.entries())
                // SAFETY: the shim filled these entries, and their paths
                // live in the list until the guard drops, after this copy.
                .map(|(i, f)| unsafe { TorrentFile::from_raw(i, f) })
                .collect(),
        })
    }
}

/// The info-hashes of a `.torrent` buffer, without adding it to a session —
/// used to enforce registry uniqueness before any session sees the torrent.
pub fn info_hashes_from_torrent(bytes: &[u8]) -> Result<InfoHashes> {
    if bytes.is_empty() {
        return Err(Error::InvalidInput("empty .torrent buffer"));
    }
    let mut out: ffi::lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = ErrBuf::new();
    let rc = unsafe {
        ffi::lt_torrent_info_hashes(
            bytes.as_ptr(),
            bytes.len(),
            &mut out,
            err.ptr(),
            err.len() as i32,
        )
    };
    if rc == ffi::LT_OK as i32 {
        Ok(InfoHashes::from_raw(&out))
    } else {
        Err(Error::Shim(err.into_string()))
    }
}

/// The info-hashes a magnet URI names (`btih`, `btmh`), without adding it.
pub fn info_hashes_from_magnet(uri: &str) -> Result<InfoHashes> {
    let uri_c = c_string(uri, "magnet uri")?;
    let mut out: ffi::lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = ErrBuf::new();
    let rc = unsafe {
        ffi::lt_magnet_info_hashes(uri_c.as_ptr(), &mut out, err.ptr(), err.len() as i32)
    };
    if rc == ffi::LT_OK as i32 {
        Ok(InfoHashes::from_raw(&out))
    } else {
        Err(Error::Shim(err.into_string()))
    }
}

/// The key ([`InfoHashes::key`]) of a `.torrent` buffer: the hash the session
/// will report for it once added.
pub fn info_hash_from_torrent(bytes: &[u8]) -> Result<InfoHash> {
    key_of(info_hashes_from_torrent(bytes)?)
}

/// The key ([`InfoHashes::key`]) of the torrent a magnet URI names.
pub fn info_hash_from_magnet(uri: &str) -> Result<InfoHash> {
    key_of(info_hashes_from_magnet(uri)?)
}

fn key_of(hashes: InfoHashes) -> Result<InfoHash> {
    hashes
        .key()
        .ok_or_else(|| Error::Shim("torrent names no info-hash".to_owned()))
}

/// What [`add_info_hashes`] read: the info-hashes a session would give the
/// torrent, and whether the add would carry its metadata.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AddInfoHashes {
    pub hashes: InfoHashes,
    /// The add carries the torrent's metadata: a `.torrent`, or resume data
    /// with an info dict of its own or the `.torrent` attached to it.
    pub has_metadata: bool,
}

impl AddInfoHashes {
    /// The key ([`InfoHashes::key`]) the session reports for the torrent once
    /// added and keeps for its life, or `None` where none can be read before
    /// the add.
    ///
    /// `None` for a torrent with no v1 hash and no metadata: the session keys
    /// it by its truncated v2 hash until the metadata arrives, and hybrid
    /// metadata then gives it a v1 hash, which the shim keys it by from then
    /// on.
    pub fn stable_key(&self) -> Option<InfoHash> {
        if self.hashes.v1.is_none() && !self.has_metadata {
            return None;
        }
        self.hashes.key()
    }
}

/// The first alert `pop` yields that translated, counting into `unknown` each
/// one it skips. `pop` answers `None` once the queue is empty, and
/// `Some(None)` for an alert whose kind is none this crate translates.
fn skip_unknown(
    unknown: &Cell<u64>,
    mut pop: impl FnMut() -> Option<Option<Alert>>,
) -> Option<Alert> {
    loop {
        match pop()? {
            Some(alert) => return Some(alert),
            None => unknown.set(unknown.get().saturating_add(1)),
        }
    }
}

/// The info-hashes the session would give a torrent added from `params`,
/// without adding it.
///
/// `params` is read the way [`Session::add_torrent`] hands it to libtorrent:
/// for resume data, the `.torrent` is attached only where the resume data
/// carries no info dict of its own, and the metadata's hashes are the ones the
/// session keys the torrent by. An `Err` is a source the add would refuse on
/// its own: one the shim cannot parse, or a `.torrent` that names another
/// torrent than the resume data it is attached to.
pub fn add_info_hashes(params: &AddParams) -> Result<AddInfoHashes> {
    let buf = |b: Option<&Vec<u8>>| match b {
        Some(b) if !b.is_empty() => (b.as_ptr(), b.len()),
        _ => (std::ptr::null(), 0),
    };
    let (magnet, torrent, resume) = match params {
        AddParams::File { bytes, .. } => {
            if bytes.is_empty() {
                return Err(Error::InvalidInput("empty .torrent buffer"));
            }
            (None, buf(Some(bytes)), buf(None))
        }
        AddParams::Magnet { uri, .. } => (
            Some(c_string(uri.as_str(), "magnet uri")?),
            buf(None),
            buf(None),
        ),
        AddParams::Resume { bytes, torrent, .. } => {
            if bytes.is_empty() {
                return Err(Error::InvalidInput("empty resume buffer"));
            }
            (None, buf(torrent.as_ref()), buf(Some(bytes)))
        }
    };
    let mut out: ffi::lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut has_metadata: std::os::raw::c_int = 0;
    let mut err = ErrBuf::new();
    let rc = unsafe {
        ffi::lt_add_info_hashes(
            magnet.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            torrent.0,
            torrent.1,
            resume.0,
            resume.1,
            &mut out,
            &mut has_metadata,
            err.ptr(),
            err.len() as i32,
        )
    };
    if rc == ffi::LT_OK as i32 {
        Ok(AddInfoHashes {
            hashes: InfoHashes::from_raw(&out),
            has_metadata: has_metadata != 0,
        })
    } else {
        Err(Error::Shim(err.into_string()))
    }
}

/// Whether every tracker `params` would announce to is on `domains`: its host
/// is a domain or a subdomain of one, compared case-insensitively.
///
/// `params` is read the way [`Session::add_torrent`] hands it to libtorrent,
/// so the trackers checked are the ones the session would announce to: a
/// `.torrent`'s announce list, or the `trackers` given with it in its place,
/// a magnet's `tr=` parameters, or — for resume data — its own `trackers`
/// list, which replaces the attached `.torrent`'s.
///
/// `url_prefixes`, when not empty, is the account binding: every tracker must
/// also be announced under one of these announce-URL prefixes, as
/// [`announce_url_has_prefix`] reads one.
///
/// [`TrackerVerdict::NotAllowed`] when any tracker is outside `domains` or has
/// no host libtorrent can read, and when `domains` is empty;
/// [`TrackerVerdict::AccountMismatch`] when every host is on `domains` but a
/// tracker is under none of `url_prefixes`;
/// [`TrackerVerdict::NoTrackers`] when there is no tracker at all. An `Err` is
/// a source the shim cannot parse, which the add would refuse too.
pub fn add_trackers_allowed(
    params: &AddParams,
    domains: &[String],
    url_prefixes: &[String],
) -> Result<TrackerVerdict> {
    if domains.is_empty() {
        return Ok(TrackerVerdict::NotAllowed);
    }
    let csv_c = c_string(domains.join(","), "allowed_tracker_domains")?;
    let prefixes_c = url_prefixes
        .iter()
        .map(|p| c_string(p.as_str(), "allowed_tracker_urls"))
        .collect::<Result<Vec<_>>>()?;
    let prefix_ptrs: Vec<*const std::os::raw::c_char> =
        prefixes_c.iter().map(|c| c.as_ptr()).collect();
    let buf = |b: Option<&Vec<u8>>| match b {
        Some(b) if !b.is_empty() => (b.as_ptr(), b.len()),
        _ => (std::ptr::null(), 0),
    };
    let no_override = TrackerOverride::new(&[])?;
    let (magnet, torrent, trackers, resume) = match params {
        AddParams::File {
            bytes, trackers, ..
        } => {
            if bytes.is_empty() {
                return Err(Error::InvalidInput("empty .torrent buffer"));
            }
            (
                None,
                buf(Some(bytes)),
                TrackerOverride::new(trackers)?,
                buf(None),
            )
        }
        AddParams::Magnet { uri, .. } => (
            Some(c_string(uri.as_str(), "magnet uri")?),
            buf(None),
            no_override,
            buf(None),
        ),
        AddParams::Resume { bytes, torrent, .. } => {
            if bytes.is_empty() {
                return Err(Error::InvalidInput("empty resume buffer"));
            }
            (None, buf(torrent.as_ref()), no_override, buf(Some(bytes)))
        }
    };
    let mut err = ErrBuf::new();
    let rc = unsafe {
        ffi::lt_add_trackers_allowed(
            magnet.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            torrent.0,
            torrent.1,
            trackers.urls_ptr(),
            trackers.tiers.as_ptr(),
            trackers.len(),
            resume.0,
            resume.1,
            csv_c.as_ptr(),
            if prefix_ptrs.is_empty() {
                std::ptr::null()
            } else {
                prefix_ptrs.as_ptr()
            },
            prefix_ptrs.len(),
            err.ptr(),
            err.len() as i32,
        )
    };
    match rc {
        1 => Ok(TrackerVerdict::Allowed),
        0 => Ok(TrackerVerdict::NotAllowed),
        rc if rc == ffi::LT_NO_TRACKERS as i32 => Ok(TrackerVerdict::NoTrackers),
        rc if rc == ffi::LT_TRACKER_ACCOUNT_MISMATCH as i32 => Ok(TrackerVerdict::AccountMismatch),
        _ => Err(Error::Shim(err.into_string())),
    }
}

/// Whether announce URL `url` falls under the announce-URL prefix `prefix`,
/// the rule [`add_trackers_allowed`] applies to its `url_prefixes`.
///
/// `prefix` is `scheme://authority/...`. Its scheme and authority must equal
/// the URL's, compared case-insensitively; the rest must be a byte-exact
/// prefix of the URL's that ends at a boundary — the prefix ends in `/`, `?`
/// or `&`, or the URL ends there or goes on with one of `/?&#;` — so
/// `?passkey=a` does not admit `?passkey=ab`. A prefix of any other shape, or
/// either argument holding a NUL, matches nothing.
pub fn announce_url_has_prefix(url: &str, prefix: &str) -> bool {
    let (Ok(url), Ok(prefix)) = (CString::new(url), CString::new(prefix)) else {
        return false;
    };
    unsafe { ffi::lt_announce_url_has_prefix(url.as_ptr(), prefix.as_ptr()) == 1 }
}

/// What [`add_trackers_allowed`] found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackerVerdict {
    /// There is at least one tracker, and every one is allowed.
    Allowed,
    /// A tracker is outside the domains, or has no host libtorrent can read.
    NotAllowed,
    /// Every tracker's host is on the domains, but one is announced under
    /// none of the account's URL prefixes: another account on the same
    /// tracker.
    AccountMismatch,
    /// The add would announce to no tracker at all.
    NoTrackers,
}

/// [`AddParams::File`]'s `trackers` in the shape the shim takes them: one
/// C string per URL, and each URL's tier alongside it.
struct TrackerOverride {
    _urls: Vec<CString>,
    ptrs: Vec<*const std::os::raw::c_char>,
    tiers: Vec<i32>,
}

impl TrackerOverride {
    fn new(trackers: &[Vec<String>]) -> Result<Self> {
        let mut urls = Vec::new();
        let mut tiers = Vec::new();
        for (tier, tier_urls) in trackers.iter().enumerate() {
            for url in tier_urls {
                urls.push(c_string(url.as_str(), "tracker url")?);
                tiers.push(i32::try_from(tier).unwrap_or(i32::MAX));
            }
        }
        let ptrs = urls.iter().map(|c| c.as_ptr()).collect();
        Ok(Self {
            _urls: urls,
            ptrs,
            tiers,
        })
    }

    /// Null when there are none, which the shim reads as "keep the
    /// `.torrent`'s".
    fn urls_ptr(&self) -> *const *const std::os::raw::c_char {
        if self.ptrs.is_empty() {
            std::ptr::null()
        } else {
            self.ptrs.as_ptr()
        }
    }

    fn len(&self) -> usize {
        self.ptrs.len()
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

/// Owns an `lt_status_list` the shim filled and frees it on drop.
struct StatusListGuard(ffi::lt_status_list);

impl StatusListGuard {
    fn new() -> Self {
        // SAFETY: a zeroed lt_status_list is the empty list the free
        // function accepts.
        Self(unsafe { std::mem::zeroed() })
    }

    fn statuses(&self) -> &[ffi::lt_torrent_status_view] {
        if self.0.statuses.is_null() || self.0.count == 0 {
            return &[];
        }
        // SAFETY: the shim allocated `count` initialised views at
        // `statuses`, which live until the guard drops.
        unsafe { std::slice::from_raw_parts(self.0.statuses, self.0.count) }
    }
}

impl Drop for StatusListGuard {
    fn drop(&mut self) {
        // SAFETY: idempotent; safe on a zeroed or already-freed struct.
        unsafe { ffi::lt_status_list_free(&mut self.0) };
    }
}

/// Map a failed per-torrent query to an error: the shim's unknown-handle
/// marker (an id it never issued, or a torrent libtorrent already removed)
/// becomes `TorrentNotFound`, anything else is a libtorrent failure.
fn query_error(h: TorrentHandle, err: ErrBuf) -> Error {
    let msg = err.into_string();
    let marker = &ffi::LT_ERR_UNKNOWN_HANDLE_MSG[..ffi::LT_ERR_UNKNOWN_HANDLE_MSG.len() - 1];
    if msg.as_bytes() == marker {
        Error::TorrentNotFound(h.infohash)
    } else if msg.is_empty() {
        Error::Shim("unknown shim error".into())
    } else {
        Error::Shim(msg)
    }
}

/// `s` as a C string, or [`Error::InteriorNul`] naming the argument `what`.
fn c_string(s: impl Into<Vec<u8>>, what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::InteriorNul(what.into()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;
    use crate::alert::AlertKind;
    use crate::metadata::InfoHashV2;

    #[test]
    fn an_alert_of_an_unknown_kind_is_skipped_and_counted() {
        let dropped = |bits| {
            Some(Alert::AlertsDropped {
                hdr: crate::alert::AlertHeader {
                    kind: AlertKind::AlertsDropped,
                    infohash: None,
                    handle: None,
                    timestamp_us: 0,
                },
                bits,
            })
        };
        let mut queue = vec![None, None, dropped([1, 0]), None, dropped([2, 0])].into_iter();
        let unknown = Cell::new(0);
        let mut pop = || skip_unknown(&unknown, || queue.next());
        assert!(matches!(
            pop(),
            Some(Alert::AlertsDropped { bits: [1, 0], .. })
        ));
        assert_eq!(unknown.get(), 2);
        assert!(matches!(
            pop(),
            Some(Alert::AlertsDropped { bits: [2, 0], .. })
        ));
        assert_eq!(unknown.get(), 3);
        assert!(pop().is_none(), "an empty queue is the end");
        assert_eq!(unknown.get(), 3);
    }

    #[test]
    fn the_resume_constructor_clears_exactly_the_forbidden_flags() {
        let AddParams::Resume {
            flags_set,
            flags_clear,
            ..
        } = AddParams::resume(vec![])
        else {
            unreachable!()
        };
        assert_eq!(flags_set, TorrentFlags::UPLOAD_MODE);
        assert_eq!(flags_clear, FORBIDDEN_TORRENT_FLAGS);
        assert!(!FORBIDDEN_TORRENT_FLAGS.contains(TorrentFlags::UPLOAD_MODE));
    }

    /// Two real sessions on loopback, with nothing to discover peers but the
    /// magnet's own `x.pe`.
    fn loopback_settings() -> Settings {
        let mut s = Settings::server_seed_overrides();
        s.enable_dht = Some(false);
        s.enable_lsd = Some(false);
        s.enable_upnp = Some(false);
        s.enable_natpmp = Some(false);
        s.listen_interfaces = Some("127.0.0.1:0".into());
        s
    }

    /// A single-file `.torrent` whose piece hashes are filler: serving its
    /// metadata over `ut_metadata` never reads a piece, so nothing verifies
    /// them.
    fn single_file_torrent(name: &str, len: usize, piece_len: usize) -> Vec<u8> {
        let pieces = vec![0xab_u8; len.div_ceil(piece_len) * 20];
        let mut out = Vec::new();
        out.extend_from_slice(b"d4:infod");
        out.extend_from_slice(format!("6:lengthi{len}e").as_bytes());
        out.extend_from_slice(format!("4:name{}:{name}", name.len()).as_bytes());
        out.extend_from_slice(format!("12:piece lengthi{piece_len}e").as_bytes());
        out.extend_from_slice(format!("6:pieces{}:", pieces.len()).as_bytes());
        out.extend_from_slice(&pieces);
        out.extend_from_slice(b"ee");
        out
    }

    /// A scratch directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let p = std::env::temp_dir().join(format!(
                "libtorrent-safe-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).expect("create scratch dir");
            Self(p)
        }

        fn path(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Poll `f` until it returns `Some` or `timeout` passes.
    fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(v) = f() {
                return Some(v);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// Add `torrent` to `seed` and return the session's listen port, once the
    /// torrent's check has finished: a peer that connects while the torrent is
    /// still checking is turned away, and the fetching side would not retry it
    /// within a test's deadline.
    fn serve(seed: &Session, torrent: Vec<u8>, dir: &Scratch) -> u16 {
        seed.add_torrent(AddParams::File {
            bytes: torrent,
            save_path: dir.path(),
            flags: TorrentFlags::empty(),
            trackers: Vec::new(),
        })
        .expect("seed add");

        let (mut port, mut checked) = (None, false);
        wait_for(Duration::from_secs(10), || {
            for a in seed.drain_alerts() {
                match a {
                    Alert::ListenSucceeded { endpoint, .. } => {
                        port = endpoint
                            .rsplit_once(':')
                            .and_then(|(_, p)| p.parse::<u16>().ok())
                            .filter(|p| *p != 0)
                            .or(port);
                    }
                    Alert::TorrentChecked { .. } => checked = true,
                    _ => {}
                }
            }
            (port.is_some() && checked).then_some(())
        })
        .expect("the seed session reports its listen port and finishes its check");
        port.expect("listen port")
    }

    /// A v1+v2 hybrid test torrent kept in the repository. Not one from the
    /// `vendor/libtorrent` corpus: `cargo test` runs without the submodules.
    fn hybrid_torrent() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent");
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// A hybrid torrent added from a btih-only magnet holds only its v1 hash
    /// until the metadata arrives, and libtorrent then gives it the v2 hash
    /// too. Every alert must go on naming it by the v1 hash it was added
    /// under: the daemon keys its state, its resume saves and its removal by
    /// that hash, and an alert under the truncated v2 one reaches none of them.
    #[test]
    fn a_hybrid_torrent_added_by_a_v1_magnet_keeps_its_v1_key_after_its_metadata() {
        let seed_dir = Scratch::new("hybrid-seed");
        let fetch_dir = Scratch::new("hybrid-fetch");
        let seed = Session::new(&loopback_settings()).expect("seed session");
        let fetch = Session::new(&loopback_settings()).expect("fetch session");

        let torrent = hybrid_torrent();
        let hashes = info_hashes_from_torrent(&torrent).expect("info hashes");
        let (v1, v2) = (
            hashes.v1.expect("hybrid has v1"),
            hashes.v2.expect("hybrid has v2"),
        );
        assert_eq!(hashes.key(), Some(v1), "a hybrid is keyed by v1");
        assert_eq!(info_hash_from_torrent(&torrent).expect("key"), v1);
        let port = serve(&seed, torrent, &seed_dir);

        drop(fetch.drain_alerts());
        let uri = format!("magnet:?xt=urn:btih:{}&x.pe=127.0.0.1:{port}", v1.to_hex());
        assert_eq!(info_hash_from_magnet(&uri).expect("magnet key"), v1);
        let h = fetch
            .add_torrent(AddParams::Magnet {
                uri,
                save_path: fetch_dir.path(),
                flags: TorrentFlags::empty(),
            })
            .expect("magnet add");
        assert_eq!(h.infohash, v1);

        let mut alerts = Vec::new();
        wait_for(Duration::from_secs(30), || {
            seed.drain_alerts();
            alerts.extend(fetch.drain_alerts());
            alerts
                .iter()
                .any(|a| matches!(a, Alert::MetadataReceived { .. }))
                .then_some(())
        })
        .expect("the metadata arrives from the seed session");

        // The scenario is the one under test only if the metadata made the
        // torrent hybrid.
        let info_section = alerts
            .iter()
            .find_map(|a| match a {
                Alert::MetadataReceived { info_section, .. } => Some(info_section.clone()),
                _ => None,
            })
            .expect("metadata alert");
        let mut received = b"d4:info".to_vec();
        received.extend_from_slice(&info_section);
        received.push(b'e');
        assert_eq!(
            info_hashes_from_torrent(&received).expect("received metadata parses"),
            InfoHashes {
                v1: Some(v1),
                v2: Some(v2)
            },
        );

        // A status update and a resume save after the metadata.
        fetch.post_torrent_updates();
        fetch
            .save_resume_data(h, ResumeFlags::empty())
            .expect("save resume data");
        let (mut saved, mut updated) = (false, false);
        wait_for(Duration::from_secs(10), || {
            for a in fetch.drain_alerts() {
                match &a {
                    Alert::SaveResumeData { .. } => saved = true,
                    Alert::StateUpdate { statuses, .. } => {
                        updated |= statuses.iter().any(|s| s.handle.id == h.id);
                    }
                    _ => {}
                }
                alerts.push(a);
            }
            (saved && updated).then_some(())
        })
        .expect("a resume save and a state update for the torrent");

        fetch.remove_torrent(h, false).expect("remove");
        wait_for(Duration::from_secs(10), || {
            alerts.extend(fetch.drain_alerts());
            alerts
                .iter()
                .any(|a| matches!(a, Alert::TorrentRemoved { .. }))
                .then_some(())
        })
        .expect("the removal is reported");

        let mut checked = Vec::new();
        for a in &alerts {
            if let Alert::StateUpdate { statuses, .. } = a {
                for s in statuses.iter().filter(|s| s.handle.id == h.id) {
                    assert_eq!(s.handle.infohash, v1, "a status view names the v1 key");
                }
            }
            let hdr = a.header();
            if hdr.handle.as_ref().is_some_and(|x| x.id == h.id)
                || matches!(a, Alert::TorrentRemoved { .. })
            {
                assert_eq!(
                    hdr.infohash,
                    Some(v1),
                    "{:?} names the torrent by its v1 key",
                    hdr.kind
                );
                checked.push(hdr.kind);
            }
        }
        for kind in [
            AlertKind::AddTorrent,
            AlertKind::MetadataReceived,
            AlertKind::SaveResumeData,
            AlertKind::TorrentRemoved,
        ] {
            assert!(checked.contains(&kind), "no {kind:?} alert was checked");
        }
    }

    /// A magnet whose torrent is removed after its metadata arrived but before
    /// the `metadata_received_alert` is popped. Translating that alert used to
    /// throw (the torrent it names no longer exists), which took every alert
    /// in the same pop with it: `add_torrent`, `torrent_removed`, and any other
    /// torrent's alerts in the batch.
    #[test]
    fn a_torrent_removed_before_its_metadata_alert_is_popped_loses_no_alerts() {
        let seed_dir = Scratch::new("seed");
        let fetch_dir = Scratch::new("fetch");
        let seed = Session::new(&loopback_settings()).expect("seed session");
        let fetch = Session::new(&loopback_settings()).expect("fetch session");

        let torrent = single_file_torrent("payload.bin", 64 * 1024, 16 * 1024);
        let ih = info_hash_from_torrent(&torrent).expect("info hash");
        let port = serve(&seed, torrent, &seed_dir);

        // Anything the fetching session posted before the magnet is not what
        // this test is about.
        drop(fetch.drain_alerts());
        let h = fetch
            .add_torrent(AddParams::Magnet {
                uri: format!("magnet:?xt=urn:btih:{}&x.pe=127.0.0.1:{port}", ih.to_hex()),
                save_path: fetch_dir.path(),
                flags: TorrentFlags::empty(),
            })
            .expect("magnet add");

        // Watch for the metadata without popping the fetching session's
        // alerts, so its metadata_received_alert is still queued.
        wait_for(Duration::from_secs(30), || {
            seed.drain_alerts();
            fetch.torrent_details(h).ok().filter(|d| d.has_metadata)
        })
        .expect("the metadata arrives from the seed session");

        fetch.remove_torrent(h, false).expect("remove");
        // A synchronous session call runs on libtorrent's network thread after
        // the removal it queued. The torrent object itself is freed a little
        // later, once its peer connection and disk jobs let go of it, and
        // nothing observable without a pop says when; only then does the
        // alert's handle stop resolving. A pause well past that (20 ms already
        // reproduced the loss) puts the pop after it.
        fetch.is_paused().expect("session barrier");
        std::thread::sleep(Duration::from_millis(500));

        let mut kinds = Vec::new();
        wait_for(Duration::from_secs(10), || {
            kinds.extend(fetch.drain_alerts().iter().map(|a| a.header().kind));
            kinds.contains(&AlertKind::TorrentRemoved).then_some(())
        });

        for kind in [
            AlertKind::AddTorrent,
            AlertKind::MetadataReceived,
            AlertKind::TorrentRemoved,
        ] {
            assert!(
                kinds.contains(&kind),
                "{kind:?} was not delivered; delivered: {kinds:?}"
            );
        }
        assert_eq!(
            fetch.alert_translate_errors(),
            0,
            "no alert failed to translate"
        );
    }

    /// Resume data as libtorrent writes it: the hashes it names, an info dict
    /// where `info` is given, and a save path.
    fn resume_data(v1: Option<InfoHash>, v2: Option<InfoHashV2>, info: Option<&[u8]>) -> Vec<u8> {
        let mut out = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
        if let Some(info) = info {
            out.extend_from_slice(b"4:info");
            out.extend_from_slice(info);
        }
        if let Some(v1) = v1 {
            out.extend_from_slice(b"9:info-hash20:");
            out.extend_from_slice(&v1.0);
        }
        if let Some(v2) = v2 {
            out.extend_from_slice(b"10:info-hash232:");
            out.extend_from_slice(&v2.0);
        }
        out.extend_from_slice(b"9:save_path4:/tmpe");
        out
    }

    fn resume_params(bytes: Vec<u8>, torrent: Option<Vec<u8>>) -> AddParams {
        AddParams::Resume {
            bytes,
            torrent,
            save_path: None,
            flags_set: TorrentFlags::empty(),
            flags_clear: TorrentFlags::empty(),
        }
    }

    /// Issue #412: resume data with no metadata is keyed by the hashes it
    /// names, and the key is stable only where one of them is a v1 hash.
    #[test]
    fn add_info_hashes_reads_resume_data_without_metadata() {
        let hashes = info_hashes_from_torrent(&hybrid_torrent()).unwrap();
        let (v1, v2) = (hashes.v1.unwrap(), hashes.v2.unwrap());

        let both = add_info_hashes(&resume_params(resume_data(Some(v1), Some(v2), None), None))
            .expect("hybrid resume data reads");
        assert_eq!(both.hashes, hashes);
        assert!(!both.has_metadata);
        assert_eq!(both.stable_key(), Some(v1));

        // A btmh-only magnet another client never fetched the metadata of:
        // keyed by the truncated v2 hash until hybrid metadata gives it a v1.
        let v2_only = add_info_hashes(&resume_params(resume_data(None, Some(v2), None), None))
            .expect("v2-only resume data reads");
        assert_eq!(v2_only.hashes.v1, None);
        assert_eq!(v2_only.hashes.key(), Some(v2.truncated()));
        assert!(!v2_only.has_metadata);
        assert_eq!(v2_only.stable_key(), None);
    }

    /// The attached `.torrent` supplies the metadata, and with it the hashes
    /// the session keys the torrent by; one naming another torrent is refused,
    /// as the add refuses it.
    #[test]
    fn add_info_hashes_reads_the_attached_torrent() {
        let torrent = hybrid_torrent();
        let hashes = info_hashes_from_torrent(&torrent).unwrap();
        let (v1, v2) = (hashes.v1.unwrap(), hashes.v2.unwrap());

        let attached = add_info_hashes(&resume_params(
            resume_data(None, Some(v2), None),
            Some(torrent.clone()),
        ))
        .expect("v2-only resume data with its .torrent reads");
        assert!(attached.has_metadata);
        assert_eq!(attached.hashes, hashes);
        assert_eq!(attached.stable_key(), Some(v1));

        let other = single_file_torrent("other", 1 << 16, 1 << 14);
        let other_v1 = info_hash_from_torrent(&other).unwrap();
        assert!(
            add_info_hashes(&resume_params(
                resume_data(Some(other_v1), None, None),
                Some(torrent)
            ))
            .is_err(),
            "a .torrent naming another torrent than the resume data is refused"
        );
    }

    /// Resume data carrying its own info dict is keyed by it, and the
    /// `.torrent` attached to it is ignored, as the add ignores it.
    #[test]
    fn add_info_hashes_prefers_the_resume_datas_own_metadata() {
        let own = single_file_torrent("own", 1 << 16, 1 << 14);
        let own_v1 = info_hash_from_torrent(&own).unwrap();
        // `d4:info` ... `e`: the info dict alone.
        let info = &own[7..own.len() - 1];
        let read = add_info_hashes(&resume_params(
            resume_data(Some(own_v1), None, Some(info)),
            Some(hybrid_torrent()),
        ))
        .expect("resume data with its own info dict reads");
        assert!(read.has_metadata);
        assert_eq!(read.hashes.v1, Some(own_v1));
        assert_eq!(read.hashes.v2, None);
        assert_eq!(read.stable_key(), Some(own_v1));
    }

    /// The `.torrent` and magnet sources read as their adds do.
    #[test]
    fn add_info_hashes_reads_a_torrent_and_a_magnet() {
        let torrent = hybrid_torrent();
        let hashes = info_hashes_from_torrent(&torrent).unwrap();
        let file = add_info_hashes(&AddParams::File {
            bytes: torrent,
            save_path: "/tmp".into(),
            flags: TorrentFlags::empty(),
            trackers: Vec::new(),
        })
        .unwrap();
        assert!(file.has_metadata);
        assert_eq!(file.stable_key(), hashes.v1);

        let btmh = format!("magnet:?xt=urn:btmh:1220{}", hashes.v2.unwrap().to_hex());
        let magnet = add_info_hashes(&AddParams::Magnet {
            uri: btmh,
            save_path: "/tmp".into(),
            flags: TorrentFlags::empty(),
        })
        .unwrap();
        assert!(!magnet.has_metadata);
        assert_eq!(magnet.stable_key(), None);

        assert!(add_info_hashes(&resume_params(b"not bencode".to_vec(), None)).is_err());
    }
}
