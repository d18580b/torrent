//! `.torrent` file persistence.
//!
//! Mirrors [`crate::resume_store`] but for the raw `.torrent` metadata. The
//! daemon writes `<base>/<profile_id>/<infohash_hex>.torrent` whenever a torrent
//! is added from a buffer / file so the startup
//! inventory scan can re-add it if its resume file is ever lost, and the
//! `metadata_received` handler writes the fetched metadata for magnet adds.

use std::fs;
use std::path::PathBuf;

use dashmap::DashMap;
use libtorrent_safe::InfoHash;
use thiserror::Error;

use crate::batch_writer::WriteErrorHook;
use crate::profile::ProfileId;
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

    /// Atomically replace the `.torrent` file for `(profile, ih)` with `data`,
    /// durably, before returning.
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

    /// Delete the `.torrent` file for `(profile, ih)`, and the save path
    /// recorded beside it. Missing files are not an error.
    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), TorrentStoreError>;

    /// Atomically record, durably before returning, the save path
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
/// sidecar in the same directory holding the UTF-8 save path it was added at.
/// The `.torrent` scan reads only its own suffix, so the sidecars never show
/// up as entries.
#[derive(Debug)]
pub struct FsTorrentStore {
    torrents: PartitionedDir,
    save_paths: PartitionedDir,
}

impl FsTorrentStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            torrents: PartitionedDir::new(base.clone(), ".torrent", "torrent"),
            save_paths: PartitionedDir::new(base, SAVE_PATH_SUFFIX, "save path"),
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
        self.save_paths.pin(profile, dir);
        self
    }

    pub fn path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.torrents.path_for(profile, ih)
    }

    /// Where the save-path sidecar for `(profile, ih)` lives.
    pub fn save_path_path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.save_paths.path_for(profile, ih)
    }
}

/// The sidecar's suffix, beside `<infohash>.torrent`.
const SAVE_PATH_SUFFIX: &str = ".save_path";

impl TorrentStore for FsTorrentStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<Vec<u8>>, TorrentStoreError> {
        Ok(self.torrents.scan(profile)?)
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
        // The `.torrent` first: a sidecar left behind by a failure between
        // the two is never read, since the scan only finds `.torrent` files.
        self.torrents.delete(profile, ih)?;
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
        match fs::read(self.save_path_path_for(profile, ih)) {
            Ok(b) => String::from_utf8(b).map(Some).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error()).into()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn read(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<Vec<u8>>, TorrentStoreError> {
        let path = self.path_for(profile, ih);
        if let Some(queued) = self.torrents.pending(&path) {
            return Ok(Some(queued.to_vec()));
        }
        match fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryTorrentStore (test fixture)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryTorrentStore {
    inner: DashMap<(ProfileId, InfoHash), Vec<u8>>,
    save_paths: DashMap<(ProfileId, InfoHash), String>,
}

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
