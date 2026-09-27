//! Point-in-time views of one torrent in a session: details, file list and
//! tracker list.
//!
//! These are plain data, copied out of the shim's C structs by the
//! `Session::torrent_details` / `torrent_files` / `torrent_trackers` wrappers.
//! The shim's sentinels (`0` for "unlimited" / "unknown", `-1` for an unknown
//! scrape count, empty strings for "none") become `Option`s here so no caller
//! has to know the C conventions.

use libtorrent_sys as ffi;

use crate::metadata::fixed_c_str;

/// Details of one torrent in a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorrentDetails {
    /// `None` while libtorrent has no name yet (a magnet without `dn=` whose
    /// metadata has not arrived).
    pub name: Option<String>,
    pub has_metadata: bool,
    /// Total payload bytes. `None` without metadata.
    pub total_size: Option<u64>,
    pub save_path: String,
    /// Bytes per second. `None` = unlimited.
    pub upload_limit: Option<u32>,
    /// When the torrent was first added, in unix seconds. `None` if unknown.
    pub added_at: Option<i64>,
}

/// One file of a torrent in a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorrentFile {
    /// libtorrent file index, the one `Session::set_file_priority` takes.
    pub index: u32,
    /// Torrent-relative, `/`-separated. For a multi-file torrent this starts
    /// with the torrent's root directory name.
    pub path: String,
    pub size: u64,
    /// Bytes of this file covered by pieces the torrent has. Piece
    /// granularity, so a partially downloaded piece does not count yet.
    pub downloaded: u64,
    /// libtorrent download priority, 0 (skip) to 7 (top); 4 is the default.
    pub priority: u8,
}

/// One tracker of a torrent in a session.
///
/// libtorrent keeps announce state per (listen endpoint x protocol version);
/// the shim folds those into this one row. `updating` and `fails` aggregate
/// over all of them (any / max). `message`, `last_error`, `next_announce` and
/// the scrape counts come from the endpoint with the most recent announce
/// activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackerEntry {
    pub url: String,
    pub tier: u8,
    /// Whether the tracker has responded to an announce with a valid reply.
    pub verified: bool,
    /// An announce is in flight.
    pub updating: bool,
    /// Consecutive failed announces.
    pub fails: u32,
    /// The tracker's last `warning message` / status text.
    pub message: Option<String>,
    /// The error of the last failed announce.
    pub last_error: Option<String>,
    /// When the next announce is due, in unix seconds. `None` if unscheduled.
    pub next_announce: Option<i64>,
    /// Seeds, from the last scrape / announce reply.
    pub scrape_complete: Option<u32>,
    /// Leechers, from the last scrape / announce reply.
    pub scrape_incomplete: Option<u32>,
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

impl TorrentDetails {
    pub(crate) fn from_raw(raw: &ffi::lt_torrent_details) -> Self {
        let has_metadata = raw.has_metadata != 0;
        Self {
            name: non_empty(fixed_c_str(&raw.name)),
            has_metadata,
            total_size: has_metadata.then_some(raw.total_size),
            save_path: fixed_c_str(&raw.save_path),
            upload_limit: (raw.upload_limit != 0).then_some(raw.upload_limit),
            added_at: (raw.added_time != 0).then_some(raw.added_time),
        }
    }
}

impl TorrentFile {
    pub(crate) fn from_raw(index: u32, raw: &ffi::lt_torrent_file_entry) -> Self {
        Self {
            index,
            path: fixed_c_str(&raw.path),
            size: raw.size,
            downloaded: raw.downloaded,
            priority: raw.priority,
        }
    }
}

impl TrackerEntry {
    pub(crate) fn from_raw(raw: &ffi::lt_tracker_entry) -> Self {
        Self {
            url: fixed_c_str(&raw.url),
            tier: raw.tier,
            verified: raw.verified != 0,
            updating: raw.updating != 0,
            fails: raw.fails,
            message: non_empty(fixed_c_str(&raw.message)),
            last_error: non_empty(fixed_c_str(&raw.last_error)),
            next_announce: (raw.next_announce != 0).then_some(raw.next_announce),
            scrape_complete: u32::try_from(raw.scrape_complete).ok(),
            scrape_incomplete: u32::try_from(raw.scrape_incomplete).ok(),
        }
    }
}

/// Owns an `lt_torrent_file_list` the shim filled and frees it on drop, so
/// every return path (including a panic while copying) releases the array.
pub(crate) struct FileListGuard(pub(crate) ffi::lt_torrent_file_list);

impl FileListGuard {
    pub(crate) fn new() -> Self {
        // SAFETY: all-zero is the shim's documented empty state (null pointer,
        // zero counts), which lt_torrent_file_list_free accepts.
        Self(unsafe { std::mem::zeroed() })
    }

    pub(crate) fn entries(&self) -> &[ffi::lt_torrent_file_entry] {
        if self.0.files.is_null() || self.0.num_files == 0 {
            return &[];
        }
        // SAFETY: on LT_OK the shim hands over `num_files` initialized entries
        // at `files`, valid until lt_torrent_file_list_free.
        unsafe { std::slice::from_raw_parts(self.0.files, self.0.num_files) }
    }
}

impl Drop for FileListGuard {
    fn drop(&mut self) {
        // SAFETY: idempotent; safe on a zeroed or already-freed struct.
        unsafe { ffi::lt_torrent_file_list_free(&mut self.0) };
    }
}

/// Owns an `lt_tracker_list` the shim filled and frees it on drop.
pub(crate) struct TrackerListGuard(pub(crate) ffi::lt_tracker_list);

impl TrackerListGuard {
    pub(crate) fn new() -> Self {
        // SAFETY: as for FileListGuard::new.
        Self(unsafe { std::mem::zeroed() })
    }

    pub(crate) fn entries(&self) -> &[ffi::lt_tracker_entry] {
        if self.0.entries.is_null() || self.0.num_entries == 0 {
            return &[];
        }
        // SAFETY: as for FileListGuard::entries.
        unsafe { std::slice::from_raw_parts(self.0.entries, self.0.num_entries) }
    }
}

impl Drop for TrackerListGuard {
    fn drop(&mut self) {
        // SAFETY: idempotent; safe on a zeroed or already-freed struct.
        unsafe { ffi::lt_tracker_list_free(&mut self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(buf: &mut [std::os::raw::c_char], s: &str) {
        for (d, b) in buf.iter_mut().zip(s.bytes()) {
            *d = b as std::os::raw::c_char;
        }
    }

    #[test]
    fn details_sentinels_become_none() {
        let mut raw: ffi::lt_torrent_details = unsafe { std::mem::zeroed() };
        put(&mut raw.save_path, "/srv");
        let d = TorrentDetails::from_raw(&raw);
        assert_eq!(
            d,
            TorrentDetails {
                name: None,
                has_metadata: false,
                total_size: None,
                save_path: "/srv".into(),
                upload_limit: None,
                added_at: None,
            }
        );

        put(&mut raw.name, "n");
        raw.has_metadata = 1;
        raw.total_size = 0;
        raw.upload_limit = 1024;
        raw.added_time = 1_700_000_000;
        let d = TorrentDetails::from_raw(&raw);
        assert_eq!(d.name.as_deref(), Some("n"));
        assert_eq!(
            d.total_size,
            Some(0),
            "an empty torrent with metadata is 0, not None"
        );
        assert_eq!(d.upload_limit, Some(1024));
        assert_eq!(d.added_at, Some(1_700_000_000));
    }

    #[test]
    fn tracker_sentinels_become_none() {
        let mut raw: ffi::lt_tracker_entry = unsafe { std::mem::zeroed() };
        put(&mut raw.url, "http://t/a");
        raw.scrape_complete = -1;
        raw.scrape_incomplete = -1;
        let t = TrackerEntry::from_raw(&raw);
        assert_eq!(t.url, "http://t/a");
        assert_eq!(t.message, None);
        assert_eq!(t.last_error, None);
        assert_eq!(t.next_announce, None);
        assert_eq!(t.scrape_complete, None);
        assert_eq!(t.scrape_incomplete, None);

        put(&mut raw.message, "hi");
        put(&mut raw.last_error, "refused");
        raw.next_announce = 42;
        raw.scrape_complete = 0;
        raw.scrape_incomplete = 7;
        raw.tier = 2;
        raw.verified = 1;
        raw.updating = 1;
        raw.fails = 3;
        let t = TrackerEntry::from_raw(&raw);
        assert_eq!(t.message.as_deref(), Some("hi"));
        assert_eq!(t.last_error.as_deref(), Some("refused"));
        assert_eq!(t.next_announce, Some(42));
        assert_eq!(t.scrape_complete, Some(0));
        assert_eq!(t.scrape_incomplete, Some(7));
        assert_eq!(
            (t.tier, t.verified, t.updating, t.fails),
            (2, true, true, 3)
        );
    }

    #[test]
    fn empty_guards_free_cleanly() {
        let f = FileListGuard::new();
        assert!(f.entries().is_empty());
        let t = TrackerListGuard::new();
        assert!(t.entries().is_empty());
    }
}
