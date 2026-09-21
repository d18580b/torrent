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
use std::io::Write;
use std::path::PathBuf;

use dashmap::DashMap;
use libtorrent_safe::InfoHash;
use thiserror::Error;
use tracing::debug;
use tracing::warn;

use crate::profile::ProfileId;

pub trait TorrentStore: Send + Sync + std::fmt::Debug {
    /// Load every `.torrent` file owned by `profile`, returning
    /// `(infohash-from-filename, raw bytes)`. Files whose name isn't a
    /// 40-char hex info-hash are skipped with a warning.
    fn load_all(&self, profile: &ProfileId) -> Result<Vec<(InfoHash, Vec<u8>)>, TorrentStoreError>;

    /// Atomically replace the `.torrent` file for `(profile, ih)` with `data`.
    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError>;

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
}

impl FsTorrentStore {
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
    fn load_all(&self, profile: &ProfileId) -> Result<Vec<(InfoHash, Vec<u8>)>, TorrentStoreError> {
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
            let Some(stem) = name.strip_suffix(".torrent") else {
                continue;
            };
            match InfoHash::from_hex(stem) {
                Some(ih) => out.push((ih, fs::read(&path)?)),
                None => warn!(
                    target: "torrentd_engine::torrent_store",
                    profile_id = %profile,
                    file = %path.display(),
                    "skipping torrent file with invalid name",
                ),
            }
        }
        Ok(out)
    }

    fn write(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
        data: &[u8],
    ) -> Result<(), TorrentStoreError> {
        let dir = self.dir_for(profile);
        fs::create_dir_all(&dir)?;
        let final_path = self.path_for(profile, ih);
        let tmp_path = dir.join(format!("{}.torrent.tmp", ih.to_hex()));

        // Atomic write: temp file → fsync(file) → rename, same as the resume
        // store.
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
            target: "torrentd_engine::torrent_store",
            profile_id = %profile,
            infohash = %ih,
            bytes = data.len(),
            "wrote torrent file",
        );
        Ok(())
    }

    fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), TorrentStoreError> {
        match fs::remove_file(self.path_for(profile, ih)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, profile: &ProfileId, ih: &InfoHash) -> bool {
        self.path_for(profile, ih).exists()
    }

    fn read(
        &self,
        profile: &ProfileId,
        ih: &InfoHash,
    ) -> Result<Option<Vec<u8>>, TorrentStoreError> {
        match fs::read(self.path_for(profile, ih)) {
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
    fn load_all(&self, profile: &ProfileId) -> Result<Vec<(InfoHash, Vec<u8>)>, TorrentStoreError> {
        Ok(self
            .inner
            .iter()
            .filter(|e| e.key().0 == *profile)
            .map(|e| (e.key().1, e.value().clone()))
            .collect())
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
