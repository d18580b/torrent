//! Torrent → profile assignment registry.
//!
//! Safety Rule 3 — global info-hash uniqueness — lives here. Every
//! torrent the daemon loads (via API add, startup resume scan, or
//! startup torrent dir scan) is first looked up here. Two outcomes:
//!
//!   - The infohash is already mapped to *any* profile → reject (409).
//!   - The infohash is unmapped → assign to the requested profile, persist
//!     the file, return Ok.
//!
//! Persistence is `<data_dir>/profile_assignments.json`, a flat JSON object
//! `{ "<infohash_hex>": "<profile_id>" }`. Writes are atomic (temp file +
//! fsync + rename) — a partial write must leave the previous registry
//! file intact.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use libtorrent_safe::InfoHash;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::debug;
use tracing::info;

use crate::profile::ProfileId;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Parse(#[from] serde_json::Error),

    #[error("infohash {infohash} already assigned to profile {existing}")]
    Conflict {
        infohash: InfoHash,
        existing: ProfileId,
    },
}

#[derive(Debug)]
pub struct AssignmentRegistry {
    path: PathBuf,
    inner: RwLock<HashMap<InfoHash, ProfileId>>,
}

impl AssignmentRegistry {
    /// Construct empty (in memory + on disk).
    pub fn new_empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Load from disk; missing file is not an error (empty registry).
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        Self::load_from(path, None)
    }

    /// Load `path`, falling back to `legacy` when `path` does not exist.
    ///
    /// The fallback is read-only: the first `assign` or `remove` persists under
    /// `path`, so the old file is left alone rather than deleted or moved. An
    /// operator who rolls back gets their original file intact.
    pub fn load_from(
        path: impl Into<PathBuf>,
        legacy: Option<PathBuf>,
    ) -> Result<Self, RegistryError> {
        let path = path.into();
        let source = match legacy {
            Some(l) if !path.exists() && l.exists() => {
                info!(
                    target: "torrentd_engine::registry",
                    from = %l.display(),
                    to = %path.display(),
                    "reading the pre-profiles assignment registry; \
                     it will be rewritten under the new name on the next change",
                );
                l
            }
            _ => path.clone(),
        };
        Self::load_inner(path, source)
    }

    fn load_inner(path: PathBuf, source: PathBuf) -> Result<Self, RegistryError> {
        let map: HashMap<InfoHash, ProfileId> = match fs::read(&source) {
            Ok(bytes) if !bytes.is_empty() => {
                let raw: HashMap<String, String> = serde_json::from_slice(&bytes)?;
                let mut out = HashMap::with_capacity(raw.len());
                for (k, v) in raw {
                    let Some(ih) = InfoHash::from_hex(&k) else {
                        tracing::warn!(
                            target: "torrentd_engine::registry",
                            key = %k,
                            "skipping registry entry with invalid infohash hex",
                        );
                        continue;
                    };
                    out.insert(ih, ProfileId::new(v));
                }
                out
            }
            Ok(_) | Err(_) if !source.exists() => HashMap::new(),
            Ok(_) => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        info!(
            target: "torrentd_engine::registry",
            path = %path.display(),
            entries = map.len(),
            "registry loaded",
        );
        Ok(Self {
            path,
            inner: RwLock::new(map),
        })
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    pub fn lookup(&self, ih: &InfoHash) -> Option<ProfileId> {
        self.inner.read().get(ih).cloned()
    }

    /// Atomically assign an infohash to a profile. Conflict iff the infohash
    /// is already mapped to *any* profile.
    pub fn assign(&self, ih: InfoHash, profile: ProfileId) -> Result<(), RegistryError> {
        {
            let mut g = self.inner.write();
            if let Some(existing) = g.get(&ih) {
                if *existing == profile {
                    debug!(
                        target: "torrentd_engine::registry",
                        infohash = %ih,
                        profile_id = %profile,
                        "assign no-op (already assigned to same profile)",
                    );
                    return Ok(());
                }
                return Err(RegistryError::Conflict {
                    infohash: ih,
                    existing: existing.clone(),
                });
            }
            g.insert(ih, profile.clone());
        }
        self.persist()?;
        info!(
            target: "torrentd_engine::registry",
            infohash = %ih,
            profile_id = %profile,
            "assigned",
        );
        Ok(())
    }

    /// Remove an assignment. No-op if the infohash isn't present.
    pub fn remove(&self, ih: &InfoHash) -> Result<Option<ProfileId>, RegistryError> {
        let prev = self.inner.write().remove(ih);
        if prev.is_some() {
            self.persist()?;
            debug!(
                target: "torrentd_engine::registry",
                infohash = %ih,
                "removed",
            );
        }
        Ok(prev)
    }

    /// Snapshot of every (infohash, profile) pair, sorted by profile for
    /// deterministic iteration in tests and startup logs.
    pub fn entries(&self) -> Vec<(InfoHash, ProfileId)> {
        let mut v: Vec<(InfoHash, ProfileId)> = self
            .inner
            .read()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        v.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()).then(a.0 .0.cmp(&b.0 .0)));
        v
    }

    /// All infohashes currently assigned to `profile`.
    pub fn for_profile(&self, profile: &ProfileId) -> Vec<InfoHash> {
        self.inner
            .read()
            .iter()
            .filter(|(_, s)| *s == profile)
            .map(|(ih, _)| *ih)
            .collect()
    }

    /// Iterate over every (infohash, profile) and execute `visit`. Used by
    /// the startup cross-check that compares the registry against
    /// resume files on disk per profile.
    pub fn for_each<F: FnMut(&InfoHash, &ProfileId)>(&self, mut visit: F) {
        for (ih, profile) in self.inner.read().iter() {
            visit(ih, profile);
        }
    }

    fn persist(&self) -> Result<(), RegistryError> {
        let snapshot: HashMap<String, String> = self
            .inner
            .read()
            .iter()
            .map(|(k, v)| (k.to_hex(), v.as_str().to_string()))
            .collect();
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        atomic_write(&self.path, &bytes)?;
        Ok(())
    }
}

/// Atomic write: temp file → fsync → rename. Same-fs guaranteed because
/// the temp lives in the target's parent directory.
fn atomic_write(target: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "registry path has no parent",
        )
    })?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(match target.file_name() {
        Some(n) => format!(".{}.tmp", n.to_string_lossy()),
        None => ".registry.tmp".to_string(),
    });
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, target)?;
    if let Ok(d) = fs::File::open(parent) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn assign_then_lookup() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([1u8; 20]);
        r.assign(ih, ProfileId::new("a")).unwrap();
        assert_eq!(r.lookup(&ih).unwrap().as_str(), "a");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn conflict_is_rejected() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([2u8; 20]);
        r.assign(ih, ProfileId::new("a")).unwrap();
        let err = r.assign(ih, ProfileId::new("b")).unwrap_err();
        assert!(
            matches!(err, RegistryError::Conflict { existing, .. } if existing.as_str() == "a")
        );
    }

    #[test]
    fn assign_same_profile_is_idempotent() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([3u8; 20]);
        let profile = ProfileId::new("x");
        r.assign(ih, profile.clone()).unwrap();
        r.assign(ih, profile).unwrap(); // OK, same profile
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn the_pre_profiles_registry_is_read_once_and_rewritten_under_the_new_name() {
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        let current = dir.path().join("profile_assignments.json");
        {
            let r = AssignmentRegistry::new_empty(&legacy);
            r.assign(InfoHash([0xAA; 20]), ProfileId::new("acct_a"))
                .unwrap();
        }

        let r = AssignmentRegistry::load_from(&current, Some(legacy.clone())).unwrap();
        assert_eq!(
            r.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(),
            "acct_a",
            "without this the daemon starts with no record of who owns what, and the \
             cross-profile uniqueness rule has nothing to enforce against",
        );

        // Writing goes to the new name; the old file is left intact so a
        // rollback still has it.
        r.assign(InfoHash([0xBB; 20]), ProfileId::new("acct_b"))
            .unwrap();
        assert!(current.exists());
        assert_eq!(AssignmentRegistry::load(&current).unwrap().len(), 2);
        assert_eq!(AssignmentRegistry::load(&legacy).unwrap().len(), 1);
    }

    #[test]
    fn a_current_registry_wins_over_a_legacy_one() {
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        let current = dir.path().join("profile_assignments.json");
        AssignmentRegistry::new_empty(&legacy)
            .assign(InfoHash([0xAA; 20]), ProfileId::new("stale"))
            .unwrap();
        AssignmentRegistry::new_empty(&current)
            .assign(InfoHash([0xBB; 20]), ProfileId::new("live"))
            .unwrap();

        let r = AssignmentRegistry::load_from(&current, Some(legacy)).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.lookup(&InfoHash([0xAA; 20])).is_none());
    }

    #[test]
    fn persist_and_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reg.json");

        {
            let r = AssignmentRegistry::new_empty(&path);
            r.assign(InfoHash([0xAA; 20]), ProfileId::new("acct_a"))
                .unwrap();
            r.assign(InfoHash([0xBB; 20]), ProfileId::new("acct_b"))
                .unwrap();
            assert_eq!(r.len(), 2);
        }

        let reloaded = AssignmentRegistry::load(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(
            reloaded.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(),
            "acct_a"
        );
    }

    #[test]
    fn for_profile_returns_only_matching() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        r.assign(InfoHash([1u8; 20]), ProfileId::new("a")).unwrap();
        r.assign(InfoHash([2u8; 20]), ProfileId::new("a")).unwrap();
        r.assign(InfoHash([3u8; 20]), ProfileId::new("b")).unwrap();

        let mut as_a = r.for_profile(&ProfileId::new("a"));
        as_a.sort_by_key(|ih| ih.0);
        assert_eq!(as_a.len(), 2);
        assert_eq!(r.for_profile(&ProfileId::new("b")).len(), 1);
    }
}
