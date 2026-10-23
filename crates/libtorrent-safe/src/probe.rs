//! What an add would do, read without a session: the info-hashes a torrent
//! source names and the session would key it by, whether its trackers pass a
//! profile's tracker guard, and libtorrent's session-stats counter indices.
//!
//! Each reads its source the way [`Session::add_torrent`] hands it to
//! libtorrent, so a refusal here is one the add would make too.

use std::ffi::CString;

use libtorrent_sys as ffi;

use crate::error::Error;
use crate::error::Result;
use crate::ffi_util::c_string;
use crate::ffi_util::ErrBuf;
use crate::handle::InfoHash;
use crate::metadata::InfoHashes;
use crate::session::AddParams;
#[cfg(doc)]
use crate::session::Session;
use crate::session::TrackerOverride;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::InfoHashV2;
    use crate::session::tests::hybrid_torrent;
    use crate::session::tests::single_file_torrent;
    use crate::settings::TorrentFlags;

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
