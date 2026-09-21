//! Resume data persistence.
//!
//! `FsResumeStore` writes one bencoded file per info-hash under
//! `<base_dir>/<profile_id>/<infohash_hex>.resume`. Writes go via temp file +
//! `fsync` + `rename` for atomicity: a partial write must leave the
//! previous resume file intact.
//!
//! `MemoryResumeStore` keeps everything in a `DashMap` keyed by
//! `(profile, infohash)`. Used by Layer 1 unit tests so we don't hit the
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

use crate::profile::ProfileId;

pub trait ResumeStore: Send + Sync + std::fmt::Debug {
    /// Load every resume file owned by `profile`. Implementations skip
    /// files that don't parse as a 40-char hex info-hash filename.
    fn load_all(
        &self,
        profile: &ProfileId,
    ) -> Result<Vec<(InfoHash, ResumeData)>, ResumeStoreError>;

    /// Atomically replace the resume file for `(profile, ih)` with `data`.
    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError>;

    /// Delete the resume file for `(profile, ih)`. Missing files are not an
    /// error.
    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError>;
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
}

impl FsResumeStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            overrides: std::collections::HashMap::new(),
        }
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
        // ProfileId::DEFAULT lives directly under base for single-session mode;
        // otherwise we partition by profile id so multi-profile mode never
        // co-mingles resume files.
        if profile.is_default() {
            self.base.clone()
        } else {
            self.base.join(profile.as_str())
        }
    }

    fn file_for(&self, profile: &ProfileId, ih: &InfoHash) -> PathBuf {
        self.dir_for(profile)
            .join(format!("{}.resume", ih.to_hex()))
    }
}

impl ResumeStore for FsResumeStore {
    fn load_all(
        &self,
        profile: &ProfileId,
    ) -> Result<Vec<(InfoHash, ResumeData)>, ResumeStoreError> {
        let dir = self.dir_for(profile);
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
                        profile_id = %profile,
                        file = %path.display(),
                        "skipping resume file with invalid name",
                    );
                }
            }
        }
        Ok(out)
    }

    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), ResumeStoreError> {
        let dir = self.dir_for(profile);
        fs::create_dir_all(&dir)?;
        let final_path = self.file_for(profile, ih);
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
            profile_id = %profile,
            infohash = %ih,
            bytes = data.len(),
            "wrote resume file",
        );
        Ok(())
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
        let path = self.file_for(profile, ih);
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
    fn load_all(
        &self,
        profile: &ProfileId,
    ) -> Result<Vec<(InfoHash, ResumeData)>, ResumeStoreError> {
        Ok(self
            .inner
            .iter()
            .filter(|e| e.key().0 == *profile)
            .map(|e| (e.key().1, ResumeData::new(e.value().clone())))
            .collect())
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
        let profile = ProfileId::default_single();
        let ih = InfoHash([0x42u8; 20]);
        store.write(&profile, &ih, b"hello").unwrap();
        let loaded = store.load_all(&profile).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, ih);
        assert_eq!(loaded[0].1.as_bytes(), b"hello");
        store.delete(&profile, &ih).unwrap();
        assert_eq!(store.load_all(&profile).unwrap().len(), 0);
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
