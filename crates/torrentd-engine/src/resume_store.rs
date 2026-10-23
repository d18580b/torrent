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
use crate::batch_writer::sync_dir;
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

    /// Delete the resume file for `(profile, ih)`, and any write queued for
    /// it, durably before returning. Missing files are not an error.
    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError>;

    /// Whether `(profile, ih)` has a resume file, on disk or queued for one.
    ///
    /// The add handler asks this to skip the save a torrent loaded from its
    /// own resume file does not need. A store that cannot tell answers
    /// `false`, which costs a save rather than leaving a torrent with no file.
    fn exists(&self, _profile: &ProfileId, _ih: &InfoHash) -> Result<bool, ResumeStoreError> {
        Ok(false)
    }

    /// Record, durably before returning, that `(profile, ih)` was removed.
    ///
    /// `DELETE` writes one before it removes the torrent from its session,
    /// and it stands until every file that would bring the torrent back is
    /// gone: the resume file, the `.torrent` and its save path. The boot
    /// honours one before its scans: it deletes those files and loads
    /// nothing for `(profile, ih)`, unless the registry assigns `ih` to
    /// `profile` again, which means it was added again since. So a delete
    /// that fails, or one a crash cuts short, is retried at the next boot
    /// rather than the torrent loading and announcing again.
    ///
    /// A store that keeps nothing across a restart has nothing for a boot to
    /// resurrect, and keeps no tombstone: the default does nothing.
    fn write_tombstone(
        &self,
        _profile: &ProfileId,
        _ih: &InfoHash,
    ) -> Result<(), ResumeStoreError> {
        Ok(())
    }

    /// Remove `(profile, ih)`'s tombstone, durably before returning. Missing
    /// is not an error.
    fn clear_tombstone(
        &self,
        _profile: &ProfileId,
        _ih: &InfoHash,
    ) -> Result<(), ResumeStoreError> {
        Ok(())
    }

    /// Every info-hash `profile` holds a tombstone for.
    fn tombstones(&self, _profile: &ProfileId) -> Result<Vec<InfoHash>, ResumeStoreError> {
        Ok(Vec::new())
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

    /// The info-hash of every file in `profile`'s directory, by name alone:
    /// unlike [`PartitionedDir::scan`], a file that cannot be read is still
    /// listed.
    pub(crate) fn names(&self, profile: &ProfileId) -> std::io::Result<Vec<InfoHash>> {
        let dir = self.dir_for(profile);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let name = entry?.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(self.suffix)) else {
                continue;
            };
            if let Some(ih) = InfoHash::from_hex(stem) {
                out.push(ih);
            }
        }
        Ok(out)
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

    /// Remove the file and any write queued for it, then `fsync` the
    /// directory, so a crash or power loss after this returns cannot bring
    /// the file back for the next boot's scan to load.
    pub(crate) fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> std::io::Result<()> {
        let path = self.path_for(profile, ih);
        match &self.writer {
            Some(w) => w.delete_now(&path)?,
            None => remove_if_present(&path)?,
        }
        // Best effort, as after a rename, and counted the same way. A
        // directory never created holds nothing to make durable.
        let dir = self.dir_for(profile);
        if dir.is_dir() {
            sync_dir(&dir);
        }
        Ok(())
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

/// `<infohash>.resume` files, each with an `<infohash>.removed` tombstone in
/// the same directory while a removal is unfinished (see
/// [`ResumeStore::write_tombstone`]). The resume scan reads only its own
/// suffix, so the tombstones never show up as entries.
#[derive(Debug)]
pub struct FsResumeStore {
    resume: PartitionedDir,
    tombstones: PartitionedDir,
}

/// The tombstone's suffix, beside `<infohash>.resume`.
const TOMBSTONE_SUFFIX: &str = ".removed";

impl FsResumeStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            resume: PartitionedDir::new(base.clone(), ".resume", "resume"),
            tombstones: PartitionedDir::new(base, TOMBSTONE_SUFFIX, "tombstone"),
        }
    }

    /// Queue `write_batched` onto a writer thread of the store's own, which
    /// reports each failure to `on_error`.
    pub fn with_batched_writes(mut self, on_error: Option<WriteErrorHook>) -> Self {
        self.resume.batch_writes("torrentd-resume-writer", on_error);
        self
    }

    /// Pin `profile` to an explicit directory rather than the derived one.
    pub fn with_profile_dir(mut self, profile: ProfileId, dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        self.resume.pin(profile.clone(), dir.clone());
        self.tombstones.pin(profile, dir);
        self
    }

    /// Where the tombstone for `(profile, ih)` lives.
    pub fn tombstone_path_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.tombstones.path_for(profile, ih)
    }
}

impl ResumeStore for FsResumeStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<ResumeData>, ResumeStoreError> {
        let raw = self.resume.scan(profile)?;
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
        Ok(self.resume.write(profile, ih, data)?)
    }

    fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError> {
        Ok(self.resume.write_batched(profile, ih, data)?)
    }

    fn flush(&self) {
        self.resume.flush();
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        Ok(self.resume.delete(profile, ih)?)
    }

    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> Result<bool, ResumeStoreError> {
        Ok(self.resume.exists(profile, ih)?)
    }

    fn write_tombstone(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        Ok(self.tombstones.write(profile, ih, b"")?)
    }

    fn clear_tombstone(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        Ok(self.tombstones.delete(profile, ih)?)
    }

    fn tombstones(&self, profile: &ProfileId) -> Result<Vec<InfoHash>, ResumeStoreError> {
        Ok(self.tombstones.names(profile)?)
    }
}

// ---------------------------------------------------------------------------
// MemoryResumeStore (test fixture)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryResumeStore {
    inner: DashMap<(ProfileId, InfoHash), Vec<u8>>,
    tombstones: DashMap<(ProfileId, InfoHash), ()>,
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

    fn write_tombstone(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.tombstones.insert((profile.clone(), *ih), ());
        Ok(())
    }

    fn clear_tombstone(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.tombstones.remove(&(profile.clone(), *ih));
        Ok(())
    }

    fn tombstones(&self, profile: &ProfileId) -> Result<Vec<InfoHash>, ResumeStoreError> {
        Ok(self
            .tombstones
            .iter()
            .filter(|e| e.key().0 == *profile)
            .map(|e| e.key().1)
            .collect())
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

    /// A delete is durable only once the directory that held the name is
    /// flushed after the unlink: before that, a power loss can bring the
    /// file back for the next boot's scan to load.
    #[test]
    fn a_delete_unlinks_and_then_syncs_the_directory() {
        use crate::batch_writer::steps_under;
        use crate::batch_writer::Step;
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path()).with_batched_writes(None);
        let p = ProfileId::new("p");
        let ih = InfoHash([0x08u8; 20]);
        store.write(&p, &ih, b"x").unwrap();
        let before = steps_under(dir.path()).len();
        store.delete(&p, &ih).unwrap();
        let steps = steps_under(dir.path()).split_off(before);
        let profile_dir = dir.path().join("p");
        assert_eq!(
            steps,
            vec![
                Step::Unlink(profile_dir.join(format!("{}.resume", ih.to_hex()))),
                Step::SyncDir(profile_dir),
            ],
        );
    }

    /// A crash between a write's temp file and its rename leaves
    /// `<infohash>.resume.tmp` (a batch's) or `<infohash>.resume.now.tmp`
    /// (`write`'s) beside the resume files. The next boot's scan must neither
    /// load one as a torrent nor count it unreadable, and the next write for
    /// that torrent must replace it.
    #[test]
    fn a_leftover_tmp_file_is_neither_scanned_nor_fatal() {
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path()).with_batched_writes(None);
        let p = ProfileId::new("p");
        let (batched, now) = (InfoHash([0x09u8; 20]), InfoHash([0x0au8; 20]));
        let profile_dir = dir.path().join("p");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let batch_tmp = profile_dir.join(format!("{}.resume.tmp", batched.to_hex()));
        let now_tmp = profile_dir.join(format!("{}.resume.now.tmp", now.to_hex()));
        std::fs::write(&batch_tmp, b"torn half of a resume file").unwrap();
        std::fs::write(&now_tmp, b"torn").unwrap();

        let scan = store.scan(&p).unwrap();
        assert!(scan.entries.is_empty(), "a temp file was loaded");
        assert_eq!(scan.unreadable, 0, "a temp file was counted unreadable");
        assert!(store.tombstones(&p).unwrap().is_empty());
        assert!(!store.exists(&p, &batched).unwrap());

        store.write_batched(&p, &batched, b"whole").unwrap();
        store.flush();
        store.write(&p, &now, b"whole too").unwrap();
        let mut loaded: Vec<(InfoHash, Vec<u8>)> = store
            .load_all(&p)
            .unwrap()
            .into_iter()
            .map(|(ih, d)| (ih, d.as_bytes().to_vec()))
            .collect();
        loaded.sort_by_key(|(ih, _)| ih.0);
        assert_eq!(
            loaded,
            vec![(batched, b"whole".to_vec()), (now, b"whole too".to_vec())],
        );
        assert!(
            !batch_tmp.exists() && !now_tmp.exists(),
            "the writes reused them"
        );
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
    fn a_tombstone_is_listed_until_cleared_and_never_scanned_as_resume_data() {
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path());
        let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
        let (gone, kept) = (InfoHash([0x05u8; 20]), InfoHash([0x06u8; 20]));
        assert!(store.tombstones(&p).unwrap().is_empty(), "no directory yet");
        store.write(&p, &kept, b"kept").unwrap();
        store.write_tombstone(&p, &gone).unwrap();
        assert!(store.tombstone_path_for(&p, &gone).exists());
        assert_eq!(store.tombstones(&p).unwrap(), vec![gone]);
        assert!(
            store.tombstones(&q).unwrap().is_empty(),
            "another profile's"
        );
        let loaded = store.load_all(&p).unwrap();
        assert_eq!(loaded.len(), 1, "the tombstone is not a resume file");
        assert_eq!(loaded[0].0, kept);
        store.clear_tombstone(&p, &gone).unwrap();
        store.clear_tombstone(&p, &gone).unwrap();
        assert!(store.tombstones(&p).unwrap().is_empty());
    }

    #[test]
    fn a_tombstone_that_cannot_be_read_is_still_listed() {
        let dir = tempdir().unwrap();
        let store = FsResumeStore::new(dir.path());
        let p = ProfileId::new("p");
        let ih = InfoHash([0x07u8; 20]);
        // A directory reads as EISDIR, as an unreadable file would fail.
        std::fs::create_dir_all(store.tombstone_path_for(&p, &ih)).unwrap();
        assert_eq!(store.tombstones(&p).unwrap(), vec![ih]);
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
