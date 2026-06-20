//! `.torrent` file persistence.
//!
//! Mirrors [`crate::resume_store`] but for the raw `.torrent` metadata. The
//! daemon writes `<base>/<slot_id>/<infohash_hex>.torrent` whenever a torrent
//! is added from a buffer / file (PRD §Session Management) so the startup
//! inventory scan can re-add it if its resume file is ever lost, and the
//! `metadata_received` handler writes the fetched metadata for magnet adds.
//!
//! Like the resume store, single-session mode (`SlotId::DEFAULT`) keeps files
//! directly under `base`; multi-slot mode partitions by slot id so torrents
//! are never co-mingled (PRD §Multi-Account).

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use dashmap::DashMap;
use thiserror::Error;
use tracing::{debug, warn};

use crate::slot::SlotId;
use libtorrent_safe::InfoHash;

pub trait TorrentStore: Send + Sync + std::fmt::Debug {
    /// Load every `.torrent` file owned by `slot`, returning
    /// `(infohash-from-filename, raw bytes)`. Files whose name isn't a
    /// 40-char hex info-hash are skipped with a warning.
    fn load_all(&self, slot: &SlotId) -> Result<Vec<(InfoHash, Vec<u8>)>, TorrentStoreError>;

    /// Atomically replace the `.torrent` file for `(slot, ih)` with `data`.
    fn write(&self, slot: &SlotId, ih: &InfoHash, data: &[u8]) -> Result<(), TorrentStoreError>;

    /// Delete the `.torrent` file for `(slot, ih)`. Missing files are not an
    /// error.
    fn delete(&self, slot: &SlotId, ih: &InfoHash) -> Result<(), TorrentStoreError>;

    /// Whether a `.torrent` file already exists for `(slot, ih)`.
    fn exists(&self, slot: &SlotId, ih: &InfoHash) -> bool;
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
}

impl FsTorrentStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn dir_for(&self, slot: &SlotId) -> PathBuf {
        if slot.is_default() {
            self.base.clone()
        } else {
            self.base.join(slot.as_str())
        }
    }

    pub fn path_for(&self, slot: &SlotId, ih: &InfoHash) -> PathBuf {
        self.dir_for(slot).join(format!("{}.torrent", ih.to_hex()))
    }
}

impl TorrentStore for FsTorrentStore {
    fn load_all(&self, slot: &SlotId) -> Result<Vec<(InfoHash, Vec<u8>)>, TorrentStoreError> {
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
            let Some(stem) = name.strip_suffix(".torrent") else { continue };
            match InfoHash::from_hex(stem) {
                Some(ih) => out.push((ih, fs::read(&path)?)),
                None => warn!(
                    target: "seederd_engine::torrent_store",
                    slot_id = %slot,
                    file = %path.display(),
                    "skipping torrent file with invalid name",
                ),
            }
        }
        Ok(out)
    }

    fn write(&self, slot: &SlotId, ih: &InfoHash, data: &[u8]) -> Result<(), TorrentStoreError> {
        let dir = self.dir_for(slot);
        fs::create_dir_all(&dir)?;
        let final_path = self.path_for(slot, ih);
        let tmp_path = dir.join(format!("{}.torrent.tmp", ih.to_hex()));

        // Atomic write: temp file → fsync(file) → rename, same as the resume
        // store (PRD §6 — a partial write must leave the previous file intact).
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
        if let Ok(d) = fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        debug!(
            target: "seederd_engine::torrent_store",
            slot_id = %slot,
            infohash = %ih,
            bytes = data.len(),
            "wrote torrent file",
        );
        Ok(())
    }

    fn delete(&self, slot: &SlotId, ih: &InfoHash) -> Result<(), TorrentStoreError> {
        match fs::remove_file(self.path_for(slot, ih)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, slot: &SlotId, ih: &InfoHash) -> bool {
        self.path_for(slot, ih).exists()
    }
}

// ---------------------------------------------------------------------------
// MemoryTorrentStore (test fixture)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryTorrentStore {
    inner: DashMap<(SlotId, InfoHash), Vec<u8>>,
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
    fn load_all(&self, slot: &SlotId) -> Result<Vec<(InfoHash, Vec<u8>)>, TorrentStoreError> {
        Ok(self
            .inner
            .iter()
            .filter(|e| e.key().0 == *slot)
            .map(|e| (e.key().1, e.value().clone()))
            .collect())
    }

    fn write(&self, slot: &SlotId, ih: &InfoHash, data: &[u8]) -> Result<(), TorrentStoreError> {
        self.inner.insert((slot.clone(), *ih), data.to_vec());
        Ok(())
    }

    fn delete(&self, slot: &SlotId, ih: &InfoHash) -> Result<(), TorrentStoreError> {
        self.inner.remove(&(slot.clone(), *ih));
        Ok(())
    }

    fn exists(&self, slot: &SlotId, ih: &InfoHash) -> bool {
        self.inner.contains_key(&(slot.clone(), *ih))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fs_store_atomic_roundtrip() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let slot = SlotId::default_single();
        let ih = InfoHash([0x42u8; 20]);
        assert!(!store.exists(&slot, &ih));
        store.write(&slot, &ih, b"d4:infod...e").unwrap();
        assert!(store.exists(&slot, &ih));
        let loaded = store.load_all(&slot).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, ih);
        assert_eq!(loaded[0].1, b"d4:infod...e");
        store.delete(&slot, &ih).unwrap();
        assert!(store.load_all(&slot).unwrap().is_empty());
        // Deleting a missing file is fine.
        store.delete(&slot, &ih).unwrap();
    }

    #[test]
    fn multi_slot_partitions_by_subdir() {
        let dir = tempdir().unwrap();
        let store = FsTorrentStore::new(dir.path());
        let a = SlotId::new("acct_a");
        let ih = InfoHash([0x01u8; 20]);
        store.write(&a, &ih, b"x").unwrap();
        assert!(dir.path().join("acct_a").join(format!("{}.torrent", ih.to_hex())).exists());
        assert!(store.load_all(&SlotId::default_single()).unwrap().is_empty());
        assert_eq!(store.load_all(&a).unwrap().len(), 1);
    }
}
