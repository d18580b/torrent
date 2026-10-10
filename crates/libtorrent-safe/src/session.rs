//! `Session` — RAII handle around a libtorrent session.
//!
//! The struct is `Send` but not `Sync`: its raw pointer field would make it
//! neither, and `Send` is asserted below on the shim's own locking. The
//! engine layer owns it behind a `Mutex` (`torrentd-engine`'s `RealEngine`),
//! so calls from several threads are ordered.
//!
//! Methods return `Result<…, Error>`, never panic on shim failures, and
//! never expose raw pointers.

use std::ffi::CString;
use std::marker::PhantomData;

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
            flags_clear: TorrentFlags::AUTO_MANAGED
                | TorrentFlags::SHARE_MODE
                | TorrentFlags::SUPER_SEEDING
                | TorrentFlags::SEQUENTIAL_DOWNLOAD
                | TorrentFlags::STOP_WHEN_READY,
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
        let json_c = c_string(json, "settings_json")?;
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
        // SAFETY: all-zero is a valid lt_torrent_details (plain data).
        let mut raw: ffi::lt_torrent_details = unsafe { std::mem::zeroed() };
        let mut err = ErrBuf::new();
        let rc = unsafe {
            ffi::lt_torrent_details(
                self.ptr,
                h.id as ffi::lt_handle,
                &mut raw,
                err.ptr(),
                err.len() as i32,
            )
        };
        if rc != ffi::LT_OK as i32 {
            return Err(query_error(h, err));
        }
        Ok(TorrentDetails::from_raw(&raw))
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

    /// How many alerts this session popped from libtorrent and then dropped
    /// because translating them failed. The shim drops such an alert on its
    /// own and still delivers the rest of its batch, so a nonzero count is
    /// alerts lost one at a time, not a stalled queue. Monotonic for the
    /// session's lifetime.
    pub fn alert_translate_errors(&self) -> u64 {
        unsafe { ffi::lt_alert_translate_errors(self.ptr) }
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
                .map(|(i, f)| TorrentFile::from_raw(i, f))
                .collect(),
        })
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
    let uri_c = c_string(uri, "magnet uri")?;
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

/// Whether every tracker `params` would announce to is on `domains`: its host
/// is a domain or a subdomain of one, compared case-insensitively.
///
/// `params` is read the way [`Session::add_torrent`] hands it to libtorrent,
/// so the trackers checked are the ones the session would announce to: a
/// `.torrent`'s announce list, or the `trackers` given with it in its place,
/// a magnet's `tr=` parameters, or — for resume data — its own `trackers`
/// list, which replaces the attached `.torrent`'s.
///
/// [`TrackerVerdict::NotAllowed`] when any tracker is outside `domains` or has
/// no host libtorrent can read, and when `domains` is empty;
/// [`TrackerVerdict::NoTrackers`] when there is no tracker at all. An `Err` is
/// a source the shim cannot parse, which the add would refuse too.
pub fn add_trackers_allowed(params: &AddParams, domains: &[String]) -> Result<TrackerVerdict> {
    if domains.is_empty() {
        return Ok(TrackerVerdict::NotAllowed);
    }
    let csv_c = c_string(domains.join(","), "allowed_tracker_domains")?;
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
            err.ptr(),
            err.len() as i32,
        )
    };
    match rc {
        1 => Ok(TrackerVerdict::Allowed),
        0 => Ok(TrackerVerdict::NotAllowed),
        rc if rc == ffi::LT_NO_TRACKERS as i32 => Ok(TrackerVerdict::NoTrackers),
        _ => Err(Error::Shim(err.into_string())),
    }
}

/// What [`add_trackers_allowed`] found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackerVerdict {
    /// There is at least one tracker, and every one is allowed.
    Allowed,
    /// A tracker is outside the domains, or has no host libtorrent can read.
    NotAllowed,
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
        seed.add_torrent(AddParams::File {
            bytes: torrent,
            save_path: seed_dir.path(),
            flags: TorrentFlags::empty(),
            trackers: Vec::new(),
        })
        .expect("seed add");

        // The listen port, and the seed's check finished: a peer that connects
        // while the torrent is still checking is turned away, and the fetching
        // side would not retry it within the test's deadline.
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
        let port = port.expect("listen port");

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
}
