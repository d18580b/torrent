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

// ---------------------------------------------------------------------------
// FsResumeStore
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct FsResumeStore {
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

impl FsResumeStore {
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
        self.writer = Some(BatchWriter::spawn("torrentd-resume-writer", on_error));
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
        // Always partitioned by profile id. There is no profile that
        // owns the base directory: that was the single-session special
        // case, and with it went the last place two profiles could
        // co-mingle files by accident.
        self.base.join(profile.as_str())
    }

    fn file_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.dir_for(profile)
            .join(format!("{}.resume", ih.to_hex()))
    }
}

impl ResumeStore for FsResumeStore {
    fn scan(&self, profile: &ProfileId) -> Result<Scan<ResumeData>, ResumeStoreError> {
        // Whatever is still queued lands first, so the scan reads the newest.
        self.flush();
        let raw = scan_dir(&self.dir_for(profile), ".resume", profile, "resume")?;
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
        // Atomic write: temp file → fsync(file) → rename → fsync(dir). The
        // temp file is in the same directory so the rename is
        // same-filesystem.
        let path = self.file_for(profile, ih);
        match &self.writer {
            Some(w) => w.write_now(&path, data)?,
            None => write_atomic(&path, data)?,
        }
        debug!(
            target: "torrentd_engine::resume_store",
            profile_id = %profile,
            infohash = %ih,
            bytes = data.len(),
            "wrote resume file",
        );
        Ok(())
    }

    fn write_batched(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError> {
        match &self.writer {
            Some(w) => {
                w.enqueue(self.file_for(profile, ih), profile, ih, data);
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

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        let path = self.file_for(profile, ih);
        match &self.writer {
            Some(w) => w.delete_now(&path)?,
            None => remove_if_present(&path)?,
        }
        Ok(())
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

        // Pinned to the literal path, not just to the round trip. Reading
        // back what this same store wrote passes whether or not `dir_for`
        // partitions at all — and partitioning is the property: with it went
        // the last place two profiles could co-mingle files by accident.
        // `FsTorrentStore`'s equivalent asserts the path; this one did not.
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
