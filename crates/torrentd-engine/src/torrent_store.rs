//! `.torrent` file persistence.
//!
//! Mirrors [`crate::resume_store`] but for the raw `.torrent` metadata. The
//! daemon writes `<base>/<profile_id>/<infohash_hex>.torrent` whenever a torrent
//! is added from a buffer / file so the startup
//! inventory scan can re-add it if its resume file is ever lost, and the
//! `metadata_received` handler writes the fetched metadata for magnet adds.
//! A magnet add records its URI beside where that `.torrent` will go, so a
//! magnet whose daemon stops before its first resume save and before its
//! metadata arrives is re-added from it rather than lost. An adoption records
//! the trackers the previous client's resume data announced to beside the
//! `.torrent`, so a re-add from the `.torrent` alone announces to them too.

use std::fs;
use std::path::PathBuf;

#[cfg(any(test, feature = "test-support"))]
use dashmap::DashMap;
use libtorrent_safe::InfoHash;
use thiserror::Error;

use crate::batch_writer::WriteErrorHook;
use crate::profile::ProfileId;
use crate::resume_store::Listing;
use crate::resume_store::PartitionedDir;
use crate::resume_store::Scan;

pub trait TorrentStore: Send + Sync + std::fmt::Debug {
    /// Scan every `.torrent` file owned by `profile`, as
    /// `(infohash-from-filename, raw bytes)`. Files whose name isn't a
    /// 40-char hex info-hash are skipped with a warning; files that are
    /// named as one and cannot be read are skipped, logged and counted.
    fn scan(&self, profile: &ProfileId) -> Result<Scan<Vec<u8>>, TorrentStoreError>;

    /// [`TorrentStore::scan`]'s entries alone.
    fn load_all(&self, profile: &ProfileId) -> Result<Vec<(InfoHash, Vec<u8>)>, TorrentStoreError> {
        self.scan(profile).map(|s| s.entries)
    }

    /// The info-hash of every `.torrent` file owned by `profile`, by name,
    /// with the housekeeping [`TorrentStore::scan`] does first and no file
    /// read: the boot's torrent-dir scan, which reads with
    /// [`TorrentStore::read`] only what it has not already loaded.
    ///
    /// The default reads every file through `scan`; a store that can list
    /// without reading overrides it.
    fn list(&self, profile: &ProfileId) -> Result<Listing, TorrentStoreError> {
        self.scan(profile).map(Listing::from)
    }

    /// Atomically replace the `.torrent` file for `(profile, ih)` with `data`,
    /// durably before returning in the sense
    /// [`crate::resume_store`]'s Durability section gives: the data always,
    /// the new name as far as a directory `fsync` can make it.
    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError>;

    /// Replace the `.torrent` file for `(profile, ih)` with `data`, possibly
    /// later, from another thread; what the alert loop calls. A store with no
    /// writer of its own writes at once. [`TorrentStore::read`] and
    /// [`TorrentStore::exists`] see the bytes from the moment this returns.
    fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError> {
        self.write(profile, ih, data)
    }

    /// Return once every batched write accepted so far is durable.
    fn flush(&self) {}

    /// Delete the `.torrent` file for `(profile, ih)`, and the magnet URI,
    /// trackers and save path recorded beside it, before returning, then `fsync` the directory: a
    /// crash after this returns does not bring them back, and a power loss
    /// can only where that `fsync` failed ([`crate::resume_store`]'s
    /// Durability section). Missing files are not an error.
    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), TorrentStoreError>;

    /// Atomically record, durably before returning (as
    /// [`crate::resume_store`]'s Durability section defines it), the save path
    /// `(profile, ih)` was added at, beside its `.torrent`.
    ///
    /// The torrent-dir scan re-adds a `.torrent` whose resume file is gone;
    /// without this it can only guess the payload is at `default_save_path`.
    fn write_save_path(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        save_path: &str,
    ) -> Result<(), TorrentStoreError>;

    /// The save path recorded for `(profile, ih)` by
    /// [`TorrentStore::write_save_path`], or `None` if none was.
    fn read_save_path(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<String>, TorrentStoreError>;

    /// Atomically record, durably before returning (as
    /// [`crate::resume_store`]'s Durability section defines it), the magnet
    /// URI `(profile, ih)` was added from, beside where its `.torrent` goes.
    ///
    /// A magnet has no `.torrent` until its metadata arrives and no resume
    /// file until its first save lands; a daemon stopped before both would
    /// otherwise leave nothing the boot can re-add it from.
    fn write_magnet(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        uri: &str,
    ) -> Result<(), TorrentStoreError>;

    /// The magnet URI recorded for `(profile, ih)` by
    /// [`TorrentStore::write_magnet`], or `None` if none was.
    fn read_magnet(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<String>, TorrentStoreError>;

    /// Atomically record, durably before returning (as
    /// [`crate::resume_store`]'s Durability section defines it), the announce
    /// URLs by tier that `(profile, ih)` was added with in place of its
    /// `.torrent`'s own, beside its `.torrent`. An empty list removes the
    /// record, so the `.torrent`'s own trackers apply again.
    ///
    /// An adoption from a client that keeps a torrent's trackers only in its
    /// resume data (qBittorrent 4.4 and later) adds a `.torrent` that may
    /// carry none. Once the session saves resume data of its own, that holds
    /// them; a daemon stopped before then would otherwise re-add the torrent
    /// from its `.torrent` announcing to nothing.
    fn write_trackers(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        trackers: &[Vec<String>],
    ) -> Result<(), TorrentStoreError>;

    /// The trackers recorded for `(profile, ih)` by
    /// [`TorrentStore::write_trackers`], or an empty list if none were.
    fn read_trackers(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Vec<Vec<String>>, TorrentStoreError>;

    /// The info-hash of every magnet URI recorded for `profile`, by name and
    /// with no file read, after removing the temp files an interrupted
    /// [`TorrentStore::write_magnet`] left.
    fn list_magnets(&self, profile: &ProfileId) -> Result<Listing, TorrentStoreError>;

    /// Whether a `.torrent` file already exists for `(profile, ih)`.
    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> bool;

    /// Read one `.torrent`, or `None` if it isn't stored.
    ///
    /// The resume-add path uses this to re-attach metadata: libtorrent omits
    /// the info dict from resume data unless `SAVE_INFO_DICT` was set, so the
    /// `.torrent` kept here is what keeps a restarted torrent out of
    /// `downloading_metadata`.
    fn read(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<Vec<u8>>, TorrentStoreError>;
}

#[derive(Debug, Error)]
pub enum TorrentStoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// FsTorrentStore
// ---------------------------------------------------------------------------

/// `<infohash>.torrent` files, each with an optional `<infohash>.save_path`
/// sidecar in the same directory holding the UTF-8 save path it was added at,
/// and, for a magnet add, an `<infohash>.magnet` sidecar holding its URI,
/// and, for an adoption that announces to its previous client's trackers, an
/// `<infohash>.trackers` sidecar holding them. The `.torrent` scan reads only its own suffix, so the sidecars never show
/// up as entries.
#[derive(Debug)]
pub struct FsTorrentStore {
    torrents: PartitionedDir,
    save_paths: PartitionedDir,
    magnets: PartitionedDir,
    trackers: PartitionedDir,
}

impl FsTorrentStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            torrents: PartitionedDir::new(base.clone(), ".torrent", "torrent"),
            save_paths: PartitionedDir::new(base.clone(), SAVE_PATH_SUFFIX, "save path"),
            magnets: PartitionedDir::new(base.clone(), MAGNET_SUFFIX, "magnet"),
            trackers: PartitionedDir::new(base, TRACKERS_SUFFIX, "trackers"),
        }
    }

    /// Queue `write_batched` onto a writer thread of the store's own, which
    /// reports each failure to `on_error`.
    pub fn with_batched_writes(mut self, on_error: Option<WriteErrorHook>) -> Self {
        self.torrents
            .batch_writes("torrentd-torrent-writer", on_error);
        self
    }

    /// Pin `profile` to an explicit directory rather than the derived one.
    pub fn with_profile_dir(mut self, profile: ProfileId, dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        self.torrents.pin(profile.clone(), dir.clone());
        self.save_paths.pin(profile.clone(), dir.clone());
        self.magnets.pin(profile.clone(), dir.clone());
        self.trackers.pin(profile, dir);
        self
    }

    pub fn path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.torrents.path_for(profile, ih)
    }

    /// Where the save-path sidecar for `(profile, ih)` lives.
    pub fn save_path_path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.save_paths.path_for(profile, ih)
    }

    /// Where the magnet sidecar for `(profile, ih)` lives.
    pub fn magnet_path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.magnets.path_for(profile, ih)
    }

    /// Where the trackers sidecar for `(profile, ih)` lives.
    pub fn trackers_path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.trackers.path_for(profile, ih)
    }
}

/// The save-path sidecar's suffix, beside `<infohash>.torrent`.
const SAVE_PATH_SUFFIX: &str = ".save_path";

/// The magnet sidecar's suffix, beside `<infohash>.torrent`.
const MAGNET_SUFFIX: &str = ".magnet";

/// The trackers sidecar's suffix, beside `<infohash>.torrent`.
const TRACKERS_SUFFIX: &str = ".trackers";

/// The trackers sidecar's text: one announce URL per line, a blank line
/// between tiers. A URL holding a line break, which no tracker's does, could
/// not be read back as itself, so it is left out, and so is a tier left empty.
fn encode_trackers(trackers: &[Vec<String>]) -> String {
    trackers
        .iter()
        .map(|tier| {
            tier.iter()
                .filter(|url| !url.is_empty() && !url.contains(['\n', '\r']))
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|tier| !tier.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// [`encode_trackers`]' inverse.
fn decode_trackers(text: &str) -> Vec<Vec<String>> {
    text.split("\n\n")
        .map(|tier| {
            tier.lines()
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|tier| !tier.is_empty())
        .collect()
}

/// A UTF-8 sidecar's text, or `None` where there is none.
fn read_text(path: &std::path::Path) -> Result<Option<String>, TorrentStoreError> {
    match fs::read(path) {
        Ok(b) => String::from_utf8(b).map(Some).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error()).into()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

impl TorrentStore for FsTorrentStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<Vec<u8>>, TorrentStoreError> {
        // The sidecars are written through a temp file too.
        self.save_paths.remove_stale_temps(profile)?;
        self.magnets.remove_stale_temps(profile)?;
        self.trackers.remove_stale_temps(profile)?;
        Ok(self.torrents.scan(profile)?)
    }

    fn list(&self, profile: &ProfileId) -> Result<Listing, TorrentStoreError> {
        self.save_paths.remove_stale_temps(profile)?;
        self.magnets.remove_stale_temps(profile)?;
        self.trackers.remove_stale_temps(profile)?;
        Ok(self.torrents.list(profile)?)
    }

    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError> {
        Ok(self.torrents.write(profile, ih, data)?)
    }

    fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError> {
        Ok(self.torrents.write_batched(profile, ih, data)?)
    }

    fn flush(&self) {
        self.torrents.flush();
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), TorrentStoreError> {
        // The `.torrent` and the magnet first, the two the boot re-adds a
        // torrent from: trackers or a save path left behind by a failure
        // after them are never read, since nothing is left to re-add.
        self.torrents.delete(profile, ih)?;
        self.magnets.delete(profile, ih)?;
        self.trackers.delete(profile, ih)?;
        Ok(self.save_paths.delete(profile, ih)?)
    }

    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> bool {
        let path = self.path_for(profile, ih);
        self.torrents.pending(&path).is_some() || path.exists()
    }

    fn write_save_path(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        save_path: &str,
    ) -> Result<(), TorrentStoreError> {
        Ok(self.save_paths.write(profile, ih, save_path.as_bytes())?)
    }

    fn read_save_path(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<String>, TorrentStoreError> {
        read_text(&self.save_path_path_for(profile, ih))
    }

    fn write_magnet(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        uri: &str,
    ) -> Result<(), TorrentStoreError> {
        Ok(self.magnets.write(profile, ih, uri.as_bytes())?)
    }

    fn read_magnet(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<String>, TorrentStoreError> {
        read_text(&self.magnet_path_for(profile, ih))
    }

    fn write_trackers(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        trackers: &[Vec<String>],
    ) -> Result<(), TorrentStoreError> {
        let text = encode_trackers(trackers);
        if text.is_empty() {
            return Ok(self.trackers.delete(profile, ih)?);
        }
        Ok(self.trackers.write(profile, ih, text.as_bytes())?)
    }

    fn read_trackers(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Vec<Vec<String>>, TorrentStoreError> {
        Ok(read_text(&self.trackers_path_for(profile, ih))?
            .as_deref()
            .map(decode_trackers)
            .unwrap_or_default())
    }

    fn list_magnets(&self, profile: &ProfileId) -> Result<Listing, TorrentStoreError> {
        Ok(self.magnets.list(profile)?)
    }

    fn read(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<Vec<u8>>, TorrentStoreError> {
        Ok(self.torrents.read(profile, ih)?)
    }
}

// ---------------------------------------------------------------------------
// MemoryTorrentStore (test fixture)
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct MemoryTorrentStore {
    inner: DashMap<(ProfileId, InfoHash), Vec<u8>>,
    save_paths: DashMap<(ProfileId, InfoHash), String>,
    magnets: DashMap<(ProfileId, InfoHash), String>,
    trackers: DashMap<(ProfileId, InfoHash), Vec<Vec<String>>>,
}

#[cfg(any(test, feature = "test-support"))]
impl MemoryTorrentStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl TorrentStore for MemoryTorrentStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<Vec<u8>>, TorrentStoreError> {
        Ok(Scan {
            entries: self
                .inner
                .iter()
                .filter(|e| e.key().0 == *profile)
                .map(|e| (e.key().1, e.value().clone()))
                .collect(),
            unreadable: 0,
        })
    }

    fn list(&self, profile: &ProfileId) -> Result<Listing, TorrentStoreError> {
        Ok(Listing {
            names: self
                .inner
                .iter()
                .filter(|e| e.key().0 == *profile)
                .map(|e| e.key().1)
                .collect(),
            unreadable: 0,
        })
    }

    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError> {
        self.inner.insert((profile.clone(), *ih), data.to_vec());
        Ok(())
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), TorrentStoreError> {
        self.inner.remove(&(profile.clone(), *ih));
        self.save_paths.remove(&(profile.clone(), *ih));
        self.magnets.remove(&(profile.clone(), *ih));
        self.trackers.remove(&(profile.clone(), *ih));
        Ok(())
    }

    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> bool {
        self.inner.contains_key(&(profile.clone(), *ih))
    }

    fn read(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<Vec<u8>>, TorrentStoreError> {
        Ok(self
            .inner
            .get(&(profile.clone(), *ih))
            .map(|e| e.value().clone()))
    }

    fn write_save_path(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        save_path: &str,
    ) -> Result<(), TorrentStoreError> {
        self.save_paths
            .insert((profile.clone(), *ih), save_path.to_owned());
        Ok(())
    }

    fn read_save_path(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<String>, TorrentStoreError> {
        Ok(self
            .save_paths
            .get(&(profile.clone(), *ih))
            .map(|e| e.value().clone()))
    }

    fn write_magnet(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        uri: &str,
    ) -> Result<(), TorrentStoreError> {
        self.magnets.insert((profile.clone(), *ih), uri.to_owned());
        Ok(())
    }

    fn read_magnet(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<String>, TorrentStoreError> {
        Ok(self
            .magnets
            .get(&(profile.clone(), *ih))
            .map(|e| e.value().clone()))
    }

    fn write_trackers(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        trackers: &[Vec<String>],
    ) -> Result<(), TorrentStoreError> {
        // Through the file's own encoding, so the fixture reads back exactly
        // what the file store would.
        let kept = decode_trackers(&encode_trackers(trackers));
        if kept.is_empty() {
            self.trackers.remove(&(profile.clone(), *ih));
        } else {
            self.trackers.insert((profile.clone(), *ih), kept);
        }
        Ok(())
    }

    fn read_trackers(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Vec<Vec<String>>, TorrentStoreError> {
        Ok(self
            .trackers
            .get(&(profile.clone(), *ih))
            .map(|e| e.value().clone())
            .unwrap_or_default())
    }

    fn list_magnets(&self, profile: &ProfileId) -> Result<Listing, TorrentStoreError> {
        Ok(Listing {
            names: self
                .magnets
                .iter()
                .filter(|e| e.key().0 == *profile)
                .map(|e| e.key().1)
                .collect(),
            unreadable: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn fs_store_atomic_roundtrip() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x42u8; 20]);
        assert!(!store.exists(&profile, &ih));
        store.write(&profile, &ih, b"d4:infod...e").unwrap();
        assert!(store.exists(&profile, &ih));
        let loaded = store.load_all(&profile).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, ih);
        assert_eq!(loaded[0].1, b"d4:infod...e");
        store.delete(&profile, &ih).unwrap();
        assert!(store.load_all(&profile).unwrap().is_empty());
        // Deleting a missing file is fine.
        store.delete(&profile, &ih).unwrap();
    }

    #[test]
    fn the_save_path_sidecar_round_trips_and_is_not_a_scan_entry() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x5au8; 20]);
        assert_eq!(store.read_save_path(&profile, &ih).unwrap(), None);
        store.write(&profile, &ih, b"t").unwrap();
        store
            .write_save_path(&profile, &ih, "/data/torrents/movies/X")
            .unwrap();
        assert_eq!(
            store.save_path_path_for(&profile, &ih),
            dir.path()
                .join("p")
                .join(format!("{}.save_path", ih.to_hex())),
        );
        assert_eq!(
            store.read_save_path(&profile, &ih).unwrap().as_deref(),
            Some("/data/torrents/movies/X"),
        );
        // The sidecar sits in the scanned directory but is not a `.torrent`.
        let scan = store.scan(&profile).unwrap();
        assert_eq!(scan.entries, vec![(ih, b"t".to_vec())]);
        assert_eq!(scan.unreadable, 0);
        // Deleting the torrent deletes its sidecar too.
        store.delete(&profile, &ih).unwrap();
        assert!(!store.save_path_path_for(&profile, &ih).exists());
        assert_eq!(store.read_save_path(&profile, &ih).unwrap(), None);
    }

    /// Issue #627: a magnet's URI is kept beside where its `.torrent` goes,
    /// listed by name, kept out of the `.torrent` scan, and deleted with it.
    #[test]
    fn the_magnet_sidecar_round_trips_lists_and_goes_with_the_torrent() {
        let dir = tempdir().unwrap();
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x5du8; 20]);
        let uri = "magnet:?xt=urn:btih:5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d";
        let fs_store = FsTorrentStore::new(dir.path());
        let memory = MemoryTorrentStore::new();
        for store in [&fs_store as &dyn TorrentStore, &memory] {
            assert_eq!(store.read_magnet(&profile, &ih).unwrap(), None);
            store.write_magnet(&profile, &ih, uri).unwrap();
            assert_eq!(
                store.read_magnet(&profile, &ih).unwrap().as_deref(),
                Some(uri)
            );
            assert_eq!(store.list_magnets(&profile).unwrap().names, vec![ih]);
            assert!(store
                .list_magnets(&ProfileId::new("q"))
                .unwrap()
                .names
                .is_empty());
            assert!(store.scan(&profile).unwrap().entries.is_empty());
            store.delete(&profile, &ih).unwrap();
            assert_eq!(store.read_magnet(&profile, &ih).unwrap(), None);
            assert!(store.list_magnets(&profile).unwrap().names.is_empty());
        }
        assert_eq!(
            fs_store.magnet_path_for(&profile, &ih),
            dir.path().join("p").join(format!("{}.magnet", ih.to_hex())),
        );
    }

    #[test]
    fn the_trackers_sidecar_round_trips_by_tier_and_goes_with_the_torrent() {
        let dir = tempdir().unwrap();
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x5eu8; 20]);
        let tiers = vec![
            vec![
                "https://a.example/announce?passkey=1".to_owned(),
                "udp://b.example:80".to_owned(),
            ],
            // Left out whole: a tier with nothing that can be read back.
            vec!["".to_owned(), "https://x.example/\nannounce".to_owned()],
            vec!["https://c.example/announce".to_owned()],
        ];
        let kept = vec![tiers[0].clone(), tiers[2].clone()];
        let fs_store = FsTorrentStore::new(dir.path());
        let memory = MemoryTorrentStore::new();
        for store in [&fs_store as &dyn TorrentStore, &memory] {
            assert!(store.read_trackers(&profile, &ih).unwrap().is_empty());
            store.write_trackers(&profile, &ih, &tiers).unwrap();
            assert_eq!(store.read_trackers(&profile, &ih).unwrap(), kept);
            assert!(store.scan(&profile).unwrap().entries.is_empty());
            // An empty list clears the record rather than writing one.
            store.write_trackers(&profile, &ih, &[]).unwrap();
            assert!(store.read_trackers(&profile, &ih).unwrap().is_empty());
            store.write_trackers(&profile, &ih, &tiers).unwrap();
            store.delete(&profile, &ih).unwrap();
            assert!(store.read_trackers(&profile, &ih).unwrap().is_empty());
        }
        let path = fs_store.trackers_path_for(&profile, &ih);
        assert_eq!(
            path,
            dir.path()
                .join("p")
                .join(format!("{}.trackers", ih.to_hex())),
        );
        assert!(!path.exists());
    }

    #[test]
    fn a_pinned_profile_keeps_its_sidecar_beside_its_torrent() {
        let dir = tempdir().unwrap();
        let pinned = dir.path().join("elsewhere");
        let profile = ProfileId::new("p");
        let store = FsTorrentStore::new(dir.path()).with_profile_dir(profile.clone(), &pinned);
        let ih = InfoHash([0x5bu8; 20]);
        store.write_save_path(&profile, &ih, "/srv/x").unwrap();
        assert_eq!(
            store.save_path_path_for(&profile, &ih).parent(),
            Some(pinned.as_path())
        );
        assert_eq!(
            store.read_save_path(&profile, &ih).unwrap().as_deref(),
            Some("/srv/x")
        );
    }

    #[test]
    fn a_sidecar_that_is_not_utf8_reads_as_an_error() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x5cu8; 20]);
        let path = store.save_path_path_for(&profile, &ih);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(store.read_save_path(&profile, &ih).is_err());
    }

    #[test]
    fn read_returns_none_for_a_missing_torrent() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x9au8; 20]);
        assert_eq!(store.read(&profile, &ih).unwrap(), None);
        store.write(&profile, &ih, b"payload").unwrap();
        assert_eq!(
            store.read(&profile, &ih).unwrap().as_deref(),
            Some(&b"payload"[..])
        );
    }

    #[test]
    fn one_unreadable_torrent_file_is_skipped_and_counted_not_fatal() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let profile = ProfileId::new("p");
        let good = InfoHash([0x01u8; 20]);
        store.write(&profile, &good, b"t").unwrap();
        std::fs::create_dir(store.path_for(&profile, &InfoHash([0x02u8; 20]))).unwrap();
        let scan = store.scan(&profile).unwrap();
        assert_eq!(scan.unreadable, 1);
        assert_eq!(scan.entries, vec![(good, b"t".to_vec())]);
    }

    /// The torrent-dir scan lists by name and reads only what no resume file
    /// loaded, so the listing reads nothing: a file that cannot be read is
    /// listed, and fails its own read alone. It removes the temp files the
    /// scan removes, the sidecar's included.
    #[test]
    fn a_listing_reads_no_file_and_removes_the_scans_temp_files() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path()).with_batched_writes(None);
        let profile = ProfileId::new("p");
        let good = InfoHash([0x01u8; 20]);
        let bad = InfoHash([0x02u8; 20]);
        store.write(&profile, &good, b"t").unwrap();
        std::fs::create_dir(store.path_for(&profile, &bad)).unwrap();
        let mut tmp = store.save_path_path_for(&profile, &good).into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, b"torn").unwrap();

        let listing = store.list(&profile).unwrap();
        let mut names = listing.names.clone();
        names.sort_by_key(|ih| ih.0);
        assert_eq!(names, vec![good, bad]);
        assert_eq!(listing.unreadable, 0);
        assert!(!tmp.exists(), "the listing left {}", tmp.display());
        assert_eq!(
            store.read(&profile, &good).unwrap().as_deref(),
            Some(&b"t"[..])
        );
        assert!(store.read(&profile, &bad).is_err());

        let memory = MemoryTorrentStore::new();
        memory.write(&profile, &good, b"t").unwrap();
        assert_eq!(memory.list(&profile).unwrap().names, vec![good]);
        assert!(memory.list(&ProfileId::new("q")).unwrap().names.is_empty());
    }

    /// A write killed between its temp file and its rename leaves the temp
    /// file behind, and a torrent never written again keeps it forever. The
    /// boot scan removes the `.torrent`'s and the sidecar's.
    #[test]
    fn the_scan_removes_temp_files_left_by_interrupted_writes() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path()).with_batched_writes(None);
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x5bu8; 20]);
        let torrent = store.path_for(&profile, &ih);
        std::fs::create_dir_all(torrent.parent().unwrap()).unwrap();
        let sidecar = store.save_path_path_for(&profile, &ih);
        let leftovers: Vec<PathBuf> = [".tmp", ".now.tmp"]
            .iter()
            .flat_map(|ext| {
                [&torrent, &sidecar].map(|p| {
                    let mut s = p.as_os_str().to_owned();
                    s.push(ext);
                    PathBuf::from(s)
                })
            })
            .collect();
        for tmp in &leftovers {
            std::fs::write(tmp, b"torn").unwrap();
        }
        let scan = store.scan(&profile).unwrap();
        assert!(scan.entries.is_empty());
        assert_eq!(scan.unreadable, 0);
        for tmp in &leftovers {
            assert!(!tmp.exists(), "the boot scan left {}", tmp.display());
        }
    }

    /// `delete` removes the lower-case name only, so an upper-case `.torrent`
    /// the scan loaded would bring the torrent back at every boot.
    #[test]
    fn an_upper_case_torrent_file_is_not_loaded() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let profile = ProfileId::new("p");
        let ih = InfoHash([0xcdu8; 20]);
        let path = store.path_for(&profile, &ih);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let upper = path.with_file_name(format!("{}.torrent", ih.to_hex().to_uppercase()));
        std::fs::write(&upper, b"t").unwrap();
        let scan = store.scan(&profile).unwrap();
        assert!(scan.entries.is_empty(), "{:?}", scan.entries);
        assert_eq!(scan.unreadable, 0);
    }

    #[test]
    fn a_batched_torrent_is_readable_before_it_lands() {
        // The resume-add path reads the `.torrent` back to re-attach
        // metadata; a write still in the queue must not read as missing.
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path()).with_batched_writes(None);
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x03u8; 20]);
        store.write_batched(&profile, &ih, b"meta").unwrap();
        assert!(store.exists(&profile, &ih));
        assert_eq!(
            store.read(&profile, &ih).unwrap().as_deref(),
            Some(&b"meta"[..])
        );
        store.flush();
        assert_eq!(
            std::fs::read(store.path_for(&profile, &ih)).unwrap(),
            b"meta"
        );
    }

    #[test]
    fn multi_profile_partitions_by_subdir() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let a = ProfileId::new("acct_a");
        let ih = InfoHash([0x01u8; 20]);
        store.write(&a, &ih, b"x").unwrap();
        assert!(dir
            .path()
            .join("acct_a")
            .join(format!("{}.torrent", ih.to_hex()))
            .exists());
        assert!(store.load_all(&ProfileId::new("p")).unwrap().is_empty());
        assert_eq!(store.load_all(&a).unwrap().len(), 1);
    }
}
