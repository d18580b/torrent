//! Resume data persistence.
//!
//! `FsResumeStore` writes one bencoded file per info-hash under
//! `<base_dir>/<profile_id>/<infohash_hex>.resume`. Writes go via temp file +
//! `fsync` + `rename` for atomicity: a partial write must leave the
//! previous resume file intact. With
//! [`FsResumeStore::with_batched_writes`], `write_batched` queues onto a
//! [`BatchWriter`] instead, which pays those flushes per batch on its own
//! thread rather than per file on the alert loop's.
//!
//! `MemoryResumeStore` keeps everything in a `DashMap` keyed by
//! `(profile, infohash)`. Used by Layer 1 unit tests so we don't hit the
//! filesystem.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use dashmap::DashMap;
use libtorrent_safe::InfoHash;
use libtorrent_safe::ResumeData;
use thiserror::Error;
use tracing::debug;
use tracing::warn;

use crate::batch_writer::remove_if_present;
use crate::batch_writer::write_atomic;
use crate::batch_writer::BatchWriter;
use crate::batch_writer::WriteErrorHook;
use crate::profile::ProfileId;

/// What a store's scan of one profile's directory found.
#[derive(Debug, Default)]
pub struct Scan<T> {
    /// Every file that read, keyed by the info-hash its name carries.
    pub entries: Vec<(InfoHash, T)>,
    /// Files with a well-formed name that could not be read. Each is skipped
    /// and logged rather than failing the scan: one bad file used to abort
    /// the whole profile's load, and a profile that loads nothing is a far
    /// larger outage than one torrent missing.
    pub unreadable: u64,
}

pub trait ResumeStore: Send + Sync + std::fmt::Debug {
    /// Scan every resume file owned by `profile`. Implementations skip
    /// files that don't parse as a 40-char hex info-hash filename, and count
    /// the ones that do but cannot be read.
    fn scan(&self, profile: &ProfileId) -> Result<Scan<ResumeData>, ResumeStoreError>;

    /// [`ResumeStore::scan`]'s entries alone.
    fn load_all(
        &self,
        profile: &ProfileId,
    ) -> Result<Vec<(InfoHash, ResumeData)>, ResumeStoreError> {
        self.scan(profile).map(|s| s.entries)
    }

    /// Atomically replace the resume file for `(profile, ih)` with `data`,
    /// durably, before returning.
    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError>;

    /// Replace the resume file for `(profile, ih)` with `data`, possibly
    /// later, from another thread. What the alert loop calls: it must not
    /// wait on the disk. A store with no writer of its own writes at once.
    /// A failure after this returns is the writer's to report.
    fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError> {
        self.write(profile, ih, data)
    }

    /// Return once every batched write accepted so far is durable.
    fn flush(&self) {}

    /// Delete the resume file for `(profile, ih)`. Missing files are not an
    /// error.
    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError>;

    /// Whether `(profile, ih)` has a resume file, on disk or queued for one.
    ///
    /// The add handler asks this to skip the save a torrent loaded from its
    /// own resume file does not need. A store that cannot tell answers
    /// `false`, which costs a save rather than leaving a torrent with no file.
    fn exists(&self, _profile: &ProfileId, _ih: &InfoHash) -> Result<bool, ResumeStoreError> {
        Ok(false)
    }
}

/// Read every `<infohash><suffix>` file in `dir`, skipping — with a warning
/// — names that are not an info-hash and files that cannot be read. `what`
/// names the store in the log.
pub(crate) fn scan_dir(
    dir: &Path,
    suffix: &str,
    profile: &ProfileId,
    what: &str,
) -> std::io::Result<Scan<Vec<u8>>> {
    let mut out = Scan::default();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    target: "torrentd_engine::store",
                    profile_id = %profile,
                    dir = %dir.display(),
                    error.cause = %e,
                    "skipping a {what} directory entry that could not be read",
                );
                out.unreadable += 1;
                continue;
            }
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(suffix) else {
            continue;
        };
        let Some(ih) = InfoHash::from_hex(stem) else {
            warn!(
                target: "torrentd_engine::store",
                profile_id = %profile,
                file = %path.display(),
                "skipping {what} file with invalid name",
            );
            continue;
        };
        match fs::read(&path) {
            Ok(bytes) => out.entries.push((ih, bytes)),
            Err(e) => {
                warn!(
                    target: "torrentd_engine::store",
                    profile_id = %profile,
                    infohash = %ih,
                    file = %path.display(),
                    error.cause = %e,
                    "skipping {what} file that could not be read",
                );
                out.unreadable += 1;
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Error)]
pub enum ResumeStoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid resume filename: {0}")]
    InvalidName(String),
}

/// One `<infohash><suffix>` file per torrent under a directory per profile:
/// `<base>/<profile_id>/`, or the directory the profile's config pins. The
/// filesystem half of both [`FsResumeStore`] and
/// [`crate::torrent_store::FsTorrentStore`].
#[derive(Debug)]
pub(crate) struct PartitionedDir {
    base: PathBuf,
    /// Explicit directory for a profile, from its `[[profile]]` config.
    overrides: HashMap<ProfileId, PathBuf>,
    /// Where `write_batched` queues, when set; otherwise it writes at once.
    writer: Option<BatchWriter>,
    /// `".resume"` or `".torrent"`.
    suffix: &'static str,
    /// The store's name in the log.
    what: &'static str,
}

impl PartitionedDir {
    pub(crate) fn new(base: PathBuf, suffix: &'static str, what: &'static str) -> Self {
        Self {
            base,
            overrides: HashMap::new(),
            writer: None,
            suffix,
            what,
        }
    }

    pub(crate) fn batch_writes(&mut self, thread: &str, on_error: Option<WriteErrorHook>) {
        self.writer = Some(BatchWriter::spawn(thread, on_error));
    }

    pub(crate) fn pin(&mut self, profile: ProfileId, dir: PathBuf) {
        self.overrides.insert(profile, dir);
    }

    fn dir_for(&self, profile: &ProfileId) -> PathBuf {
        match self.overrides.get(profile) {
            Some(dir) => dir.clone(),
            None => self.base.join(profile.as_str()),
        }
    }

    pub(crate) fn path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.dir_for(profile)
            .join(format!("{}{}", ih.to_hex(), self.suffix))
    }

    pub(crate) fn scan(&self, profile: &ProfileId) -> std::io::Result<Scan<Vec<u8>>> {
        // Whatever is still queued lands first, so the scan reads the newest.
        self.flush();
        scan_dir(&self.dir_for(profile), self.suffix, profile, self.what)
    }

    /// Replace the file durably before returning: temp file, `fsync`,
    /// `rename`, `fsync` of the directory.
    pub(crate) fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> std::io::Result<()> {
        let path = self.path_for(profile, ih);
        match &self.writer {
            Some(w) => w.write_now(&path, data)?,
            None => write_atomic(&path, data)?,
        }
        debug!(
            target: "torrentd_engine::store",
            profile_id = %profile,
            infohash = %ih,
            bytes = data.len(),
            "wrote {} file",
            self.what,
        );
        Ok(())
    }

    pub(crate) fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> std::io::Result<()> {
        match &self.writer {
            Some(w) => {
                w.enqueue(self.path_for(profile, ih), profile, ih, data);
                Ok(())
            }
            None => self.write(profile, ih, data),
        }
    }

    pub(crate) fn flush(&self) {
        if let Some(w) = &self.writer {
            w.flush();
        }
    }

    pub(crate) fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> std::io::Result<()> {
        let path = self.path_for(profile, ih);
        match &self.writer {
            Some(w) => w.delete_now(&path),
            None => remove_if_present(&path),
        }
    }

    /// Whether `(profile, ih)` has a file on disk or a write queued for one.
    /// The queue is read first: a batch drops its entry once the rename has
    /// landed, so a file between the two is seen in one or the other.
    pub(crate) fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> std::io::Result<bool> {
        let path = self.path_for(profile, ih);
        if self.pending(&path).is_some() {
            return Ok(true);
        }
        path.try_exists()
    }

    /// The bytes queued for `path` and not yet on disk, if any.
    pub(crate) fn pending(&self, path: &Path) -> Option<std::sync::Arc<[u8]>> {
        self.writer.as_ref().and_then(|w| w.pending(path))
    }
}

// ---------------------------------------------------------------------------
// FsResumeStore
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct FsResumeStore(PartitionedDir);

impl FsResumeStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self(PartitionedDir::new(base.into(), ".resume", "resume"))
    }

    /// Queue `write_batched` onto a writer thread of the store's own, which
    /// reports each failure to `on_error`.
    pub fn with_batched_writes(mut self, on_error: Option<WriteErrorHook>) -> Self {
        self.0.batch_writes("torrentd-resume-writer", on_error);
        self
    }

    /// Pin `profile` to an explicit directory rather than the derived one.
    pub fn with_profile_dir(mut self, profile: ProfileId, dir: impl Into<PathBuf>) -> Self {
        self.0.pin(profile, dir.into());
        self
    }
}

impl ResumeStore for FsResumeStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<ResumeData>, ResumeStoreError> {
        let raw = self.0.scan(profile)?;
        Ok(Scan {
            entries: raw
                .entries
                .into_iter()
                .map(|(ih, b)| (ih, ResumeData::new(b)))
                .collect(),
            unreadable: raw.unreadable,
        })
    }

    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError> {
        Ok(self.0.write(profile, ih, data)?)
    }

    fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError> {
        Ok(self.0.write_batched(profile, ih, data)?)
    }

    fn flush(&self) {
        self.0.flush();
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        Ok(self.0.delete(profile, ih)?)
    }

    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> Result<bool, ResumeStoreError> {
        Ok(self.0.exists(profile, ih)?)
    }
}

// ---------------------------------------------------------------------------
// MemoryResumeStore (test fixture)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryResumeStore {
    inner: DashMap<(ProfileId, InfoHash), Vec<u8>>,
}

impl MemoryResumeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Test helper: contents for a profile.
    pub fn snapshot(&self, profile: &ProfileId) -> Vec<(InfoHash, Vec<u8>)> {
        self.inner
            .iter()
            .filter(|e| e.key().0 == *profile)
            .map(|e| (e.key().1, e.value().clone()))
            .collect()
    }
}

impl ResumeStore for MemoryResumeStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<ResumeData>, ResumeStoreError> {
        Ok(Scan {
            entries: self
                .inner
                .iter()
                .filter(|e| e.key().0 == *profile)
                .map(|e| (e.key().1, ResumeData::new(e.value().clone())))
                .collect(),
            unreadable: 0,
        })
    }

    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError> {
        self.inner.insert((profile.clone(), *ih), data.to_vec());
        Ok(())
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.inner.remove(&(profile.clone(), *ih));
        Ok(())
    }

    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> Result<bool, ResumeStoreError> {
        Ok(self.inner.contains_key(&(profile.clone(), *ih)))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn fs_store_atomic_roundtrip() {
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path());
        let profile = ProfileId::new("p");
        let ih = InfoHash([0x42u8; 20]);
        store.write(&profile, &ih, b"hello").unwrap();

        let expected = dir.path().join("p").join(format!("{}.resume", ih.to_hex()));
        assert!(
            expected.exists(),
            "resume data must land under <base>/<profile_id>/, got a store rooted at {}",
            dir.path().display(),
        );

        let loaded = store.load_all(&profile).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, ih);
        assert_eq!(loaded[0].1.as_bytes(), b"hello");
        store.delete(&profile, &ih).unwrap();
        assert_eq!(store.load_all(&profile).unwrap().len(), 0);
    }

    #[test]
    fn one_unreadable_resume_file_is_skipped_and_counted_not_fatal() {
        // `load_all` used to `?` on the first read failure, which aborted the
        // whole profile's load at boot: one bad file, zero torrents.
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path());
        let profile = ProfileId::new("p");
        let good = InfoHash([0x01u8; 20]);
        store.write(&profile, &good, b"ok").unwrap();
        // A directory where a resume file should be reads as EISDIR.
        std::fs::create_dir(
            dir.path()
                .join("p")
                .join(format!("{}.resume", InfoHash([0x02u8; 20]).to_hex())),
        )
        .unwrap();
        let scan = store.scan(&profile).unwrap();
        assert_eq!(scan.unreadable, 1);
        assert_eq!(scan.entries.len(), 1);
        assert_eq!(scan.entries[0].0, good);
    }

    #[test]
    fn batched_writes_land_and_a_delete_after_one_sticks() {
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path()).with_batched_writes(None);
        let profile = ProfileId::new("p");
        let kept = InfoHash([0x01u8; 20]);
        let removed = InfoHash([0x02u8; 20]);
        store.write_batched(&profile, &kept, b"kept").unwrap();
        store.write_batched(&profile, &removed, b"gone").unwrap();
        store.delete(&profile, &removed).unwrap();
        store.flush();
        let loaded = store.load_all(&profile).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, kept);
        assert_eq!(loaded[0].1.as_bytes(), b"kept");
    }

    #[test]
    fn exists_sees_a_queued_write_a_landed_one_and_not_a_deleted_one() {
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path()).with_batched_writes(None);
        let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
        let ih = InfoHash([0x03u8; 20]);
        assert!(!store.exists(&p, &ih).unwrap(), "nothing written yet");
        // Queued or already renamed by the writer thread: either way it is
        // the torrent's file.
        store.write_batched(&p, &ih, b"queued").unwrap();
        assert!(store.exists(&p, &ih).unwrap());
        store.flush();
        assert!(store.exists(&p, &ih).unwrap());
        assert!(!store.exists(&q, &ih).unwrap(), "another profile's file");
        store.delete(&p, &ih).unwrap();
        assert!(!store.exists(&p, &ih).unwrap());
    }

    #[test]
    fn memory_store_partitions_by_profile() {
        let store = MemoryResumeStore::new();
        let a = ProfileId::new("a");
        let b = ProfileId::new("b");
        let ih = InfoHash([0x01u8; 20]);
        store.write(&a, &ih, b"profile-a").unwrap();
        store.write(&b, &ih, b"profile-b").unwrap();
        assert_eq!(store.snapshot(&a)[0].1, b"profile-a");
        assert_eq!(store.snapshot(&b)[0].1, b"profile-b");
    }
}
