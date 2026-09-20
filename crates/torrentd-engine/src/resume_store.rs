//! Resume data persistence.
//!
//! `FsResumeStore` writes one bencoded file per info-hash under
//! `<base_dir>/<slot_id>/<infohash_hex>.resume`. Writes go via temp file +
//! `fsync` + `rename` for atomicity (PRD §6 — a partial write must leave
//! the previous resume file intact).
//!
//! `MemoryResumeStore` keeps everything in a `DashMap` keyed by
//! `(slot, infohash)`. Used by Layer 1 unit tests so we don't hit the
//! filesystem.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use dashmap::DashMap;
use libtorrent_safe::InfoHash;
use libtorrent_safe::ResumeData;
use thiserror::Error;
use tracing::debug;
use tracing::warn;

use crate::slot::SlotId;

pub trait ResumeStore: Send + Sync + std::fmt::Debug {
    /// Load every resume file owned by `slot`. Implementations skip
    /// files that don't parse as a 40-char hex info-hash filename.
    fn load_all(&self, slot: &SlotId) -> Result<Vec<(InfoHash, ResumeData)>, ResumeStoreError>;

    /// Atomically replace the resume file for `(slot, ih)` with `data`.
    fn write(&self, slot: &SlotId, ih: &InfoHash, data: &[u8]) -> Result<(), ResumeStoreError>;

    /// Delete the resume file for `(slot, ih)`. Missing files are not an
    /// error.
    fn delete(&self, slot: &SlotId, ih: &InfoHash) -> Result<(), ResumeStoreError>;
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
    /// Explicit directory for a slot, from its `[[slot]]` config.
    ///
    /// Without this the layout is always `<base>/<slot_id>`, and a slot that
    /// configured a directory elsewhere had it validated for uniqueness and
    /// then silently ignored — the files landed somewhere the operator had not
    /// asked for, and matched only by coincidence when the configured path
    /// happened to equal the derived one.
    overrides: std::collections::HashMap<SlotId, PathBuf>,
}

impl FsResumeStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            overrides: std::collections::HashMap::new(),
        }
    }

    /// Pin `slot` to an explicit directory rather than the derived one.
    pub fn with_slot_dir(mut self, slot: SlotId, dir: impl Into<PathBuf>) -> Self {
        self.overrides.insert(slot, dir.into());
        self
    }

    fn dir_for(&self, slot: &SlotId) -> PathBuf {
        if let Some(dir) = self.overrides.get(slot) {
            return dir.clone();
        }
        // SlotId::DEFAULT lives directly under base for single-session mode;
        // otherwise we partition by slot id so multi-slot mode never
        // co-mingles resume files (PRD Multi-Account Resume Data Isolation).
        if slot.is_default() {
            self.base.clone()
        } else {
            self.base.join(slot.as_str())
        }
    }

    fn file_for(&self, slot: &SlotId, ih: &InfoHash) -> PathBuf {
        self.dir_for(slot).join(format!("{}.resume", ih.to_hex()))
    }
}

impl ResumeStore for FsResumeStore {
    fn load_all(&self, slot: &SlotId) -> Result<Vec<(InfoHash, ResumeData)>, ResumeStoreError> {
        let dir = self.dir_for(slot);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".resume") else {
                continue;
            };
            match InfoHash::from_hex(stem) {
                Some(ih) => {
                    let bytes = fs::read(&path)?;
                    out.push((ih, ResumeData::new(bytes)));
                }
                None => {
                    warn!(
                        target: "torrentd_engine::resume_store",
                        slot_id = %slot,
                        file = %path.display(),
                        "skipping resume file with invalid name",
                    );
                }
            }
        }
        Ok(out)
    }

    fn write(&self, slot: &SlotId, ih: &InfoHash, data: &[u8]) -> Result<(), ResumeStoreError> {
        let dir = self.dir_for(slot);
        fs::create_dir_all(&dir)?;
        let final_path = self.file_for(slot, ih);
        let tmp_path = dir.join(format!("{}.resume.tmp", ih.to_hex()));

        // Atomic write: temp file → fsync(file) → rename. The temp file is
        // in the same directory so the rename is same-filesystem.
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        // fsync the parent directory so the rename hits disk too. Best-effort
        // — on filesystems that don't support fsync of dirs (rare on Linux),
        // ignore the failure.
        if let Ok(d) = fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        debug!(
            target: "torrentd_engine::resume_store",
            slot_id = %slot,
            infohash = %ih,
            bytes = data.len(),
            "wrote resume file",
        );
        Ok(())
    }

    fn delete(&self, slot: &SlotId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        let path = self.file_for(slot, ih);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryResumeStore (test fixture)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryResumeStore {
    inner: DashMap<(SlotId, InfoHash), Vec<u8>>,
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

    /// Test helper: contents for a slot.
    pub fn snapshot(&self, slot: &SlotId) -> Vec<(InfoHash, Vec<u8>)> {
        self.inner
            .iter()
            .filter(|e| e.key().0 == *slot)
            .map(|e| (e.key().1, e.value().clone()))
            .collect()
    }
}

impl ResumeStore for MemoryResumeStore {
    fn load_all(&self, slot: &SlotId) -> Result<Vec<(InfoHash, ResumeData)>, ResumeStoreError> {
        Ok(self
            .inner
            .iter()
            .filter(|e| e.key().0 == *slot)
            .map(|e| (e.key().1, ResumeData::new(e.value().clone())))
            .collect())
    }

    fn write(&self, slot: &SlotId, ih: &InfoHash, data: &[u8]) -> Result<(), ResumeStoreError> {
        self.inner.insert((slot.clone(), *ih), data.to_vec());
        Ok(())
    }

    fn delete(&self, slot: &SlotId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        self.inner.remove(&(slot.clone(), *ih));
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
        let slot = SlotId::default_single();
        let ih = InfoHash([0x42u8; 20]);
        store.write(&slot, &ih, b"hello").unwrap();
        let loaded = store.load_all(&slot).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, ih);
        assert_eq!(loaded[0].1.as_bytes(), b"hello");
        store.delete(&slot, &ih).unwrap();
        assert_eq!(store.load_all(&slot).unwrap().len(), 0);
    }

    #[test]
    fn memory_store_partitions_by_slot() {
        let store = MemoryResumeStore::new();
        let a = SlotId::new("a");
        let b = SlotId::new("b");
        let ih = InfoHash([0x01u8; 20]);
        store.write(&a, &ih, b"slot-a").unwrap();
        store.write(&b, &ih, b"slot-b").unwrap();
        assert_eq!(store.snapshot(&a)[0].1, b"slot-a");
        assert_eq!(store.snapshot(&b)[0].1, b"slot-b");
    }
}
