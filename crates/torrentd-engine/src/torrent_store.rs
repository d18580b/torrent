//! `.torrent` file persistence.
//!
//! Mirrors [`crate::resume_store`] but for the raw `.torrent` metadata. The
//! daemon writes `<base>/<profile_id>/<infohash_hex>.torrent` whenever a torrent
//! is added from a buffer / file so the startup
//! inventory scan can re-add it if its resume file is ever lost, and the
//! `metadata_received` handler writes the fetched metadata for magnet adds.
//!
//! Like the resume store, this always partitions by profile id — there is no
//! count of profiles at which files go directly under `base`, because a
//! deployment with one profile is a deployment with n = 1, not a mode of its
//! own. Two profiles' torrents are therefore never co-mingled.

use std::fs;
use std::path::PathBuf;

use dashmap::DashMap;
use libtorrent_safe::InfoHash;
use thiserror::Error;
use tracing::debug;

use crate::batch_writer::remove_if_present;
use crate::batch_writer::write_atomic;
use crate::batch_writer::BatchWriter;
use crate::batch_writer::WriteErrorHook;
use crate::profile::ProfileId;
use crate::resume_store::scan_dir;
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

    /// Delete the `.torrent` file for `(profile, ih)`. Missing files are not an
    /// error.
    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), TorrentStoreError>;

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

#[derive(Debug)]
pub struct FsTorrentStore {
    base: PathBuf,
    /// Explicit directory for a profile, from its `[[profile]]` config.
    ///
    /// Without this the layout is always `<base>/<profile_id>`, and a profile that
    /// configured a directory elsewhere had it validated for uniqueness and
    /// then silently ignored — the files landed somewhere the operator had not
    /// asked for, and matched only by coincidence when the configured path
    /// happened to equal the derived one.
    overrides: std::collections::HashMap<ProfileId, PathBuf>,
    /// Where `write_batched` queues, when set; otherwise it writes at once.
    writer: Option<BatchWriter>,
}

impl FsTorrentStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            overrides: std::collections::HashMap::new(),
            writer: None,
        }
    }

    /// Queue `write_batched` onto a writer thread of the store's own, which
    /// reports each failure to `on_error`.
    pub fn with_batched_writes(mut self, on_error: Option<WriteErrorHook>) -> Self {
        self.writer = Some(BatchWriter::spawn("torrentd-torrent-writer", on_error));
        self
    }

    /// Pin `profile` to an explicit directory rather than the derived one.
    pub fn with_profile_dir(mut self, profile: ProfileId, dir: impl Into<PathBuf>) -> Self {
        self.overrides.insert(profile, dir.into());
        self
    }

    fn dir_for(&self, profile: &ProfileId) -> PathBuf {
        if let Some(dir) = self.overrides.get(profile) {
            return dir.clone();
        }
        // Always partitioned by profile id. There is no profile that owns
        // the base directory: that was the single-session special case, and
        // with it went the last place two profiles could co-mingle files.
        self.base.join(profile.as_str())
    }

    pub fn path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.dir_for(profile)
            .join(format!("{}.torrent", ih.to_hex()))
    }
}

impl TorrentStore for FsTorrentStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<Vec<u8>>, TorrentStoreError> {
        // Whatever is still queued lands first, so the scan reads the newest.
        self.flush();
        Ok(scan_dir(
            &self.dir_for(profile),
            ".torrent",
            profile,
            "torrent",
        )?)
    }

    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError> {
        // Atomic write: temp file → fsync(file) → rename → fsync(dir), same
        // as the resume store.
        let path = self.path_for(profile, ih);
        match &self.writer {
            Some(w) => w.write_now(&path, data)?,
            None => write_atomic(&path, data)?,
        }
        debug!(
            target: "torrentd_engine::torrent_store",
            profile_id = %profile,
            infohash = %ih,
            bytes = data.len(),
            "wrote torrent file",
        );
        Ok(())
    }

    fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError> {
        match &self.writer {
            Some(w) => {
                w.enqueue(self.path_for(profile, ih), profile, ih, data);
                Ok(())
            }
            None => self.write(profile, ih, data),
        }
    }

    fn flush(&self) {
        if let Some(w) = &self.writer {
            w.flush();
        }
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), TorrentStoreError> {
        let path = self.path_for(profile, ih);
        match &self.writer {
            Some(w) => w.delete_now(&path)?,
            None => remove_if_present(&path)?,
        }
        Ok(())
    }

    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> bool {
        let path = self.path_for(profile, ih);
        self.writer
            .as_ref()
            .is_some_and(|w| w.pending(&path).is_some())
            || path.exists()
    }

    fn read(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<Vec<u8>>, TorrentStoreError> {
        let path = self.path_for(profile, ih);
        if let Some(queued) = self.writer.as_ref().and_then(|w| w.pending(&path)) {
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
