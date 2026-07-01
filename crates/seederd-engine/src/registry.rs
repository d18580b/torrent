//! Torrent → slot assignment registry.
//!
//! PRD Safety Rule 3 — global info-hash uniqueness — lives here. Every
//! torrent the daemon loads (via API add, startup resume scan, or
//! startup torrent dir scan) is first looked up here. Two outcomes:
//!
//!   - The infohash is already mapped to *any* slot → reject (409).
//!   - The infohash is unmapped → assign to the requested slot, persist
//!     the file, return Ok.
//!
//! Persistence is `<data_dir>/slot_assignments.json`, a flat JSON object
//! `{ "<infohash_hex>": "<slot_id>" }`. Writes are atomic (temp file +
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

use crate::slot::SlotId;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Parse(#[from] serde_json::Error),

    #[error("infohash {infohash} already assigned to slot {existing}")]
    Conflict {
        infohash: InfoHash,
        existing: SlotId,
    },
}

#[derive(Debug)]
pub struct AssignmentRegistry {
    path: PathBuf,
    inner: RwLock<HashMap<InfoHash, SlotId>>,
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
        let path = path.into();
        let map: HashMap<InfoHash, SlotId> = match fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => {
                let raw: HashMap<String, String> = serde_json::from_slice(&bytes)?;
                let mut out = HashMap::with_capacity(raw.len());
                for (k, v) in raw {
                    let Some(ih) = InfoHash::from_hex(&k) else {
                        tracing::warn!(
                            target: "seederd_engine::registry",
                            key = %k,
                            "skipping registry entry with invalid infohash hex",
                        );
                        continue;
                    };
                    out.insert(ih, SlotId::new(v));
                }
                out
            }
            Ok(_) | Err(_) if !path.exists() => HashMap::new(),
            Ok(_) => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        info!(
            target: "seederd_engine::registry",
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

    pub fn lookup(&self, ih: &InfoHash) -> Option<SlotId> {
        self.inner.read().get(ih).cloned()
    }

    /// Atomically assign an infohash to a slot. Conflict iff the infohash
    /// is already mapped to *any* slot (PRD Safety Rule 3).
    pub fn assign(&self, ih: InfoHash, slot: SlotId) -> Result<(), RegistryError> {
        {
            let mut g = self.inner.write();
            if let Some(existing) = g.get(&ih) {
                if *existing == slot {
                    debug!(
                        target: "seederd_engine::registry",
                        infohash = %ih,
                        slot_id = %slot,
                        "assign no-op (already assigned to same slot)",
                    );
                    return Ok(());
                }
                return Err(RegistryError::Conflict {
                    infohash: ih,
                    existing: existing.clone(),
                });
            }
            g.insert(ih, slot.clone());
        }
        self.persist()?;
        info!(
            target: "seederd_engine::registry",
            infohash = %ih,
            slot_id = %slot,
            "assigned",
        );
        Ok(())
    }

    /// Remove an assignment. No-op if the infohash isn't present.
    pub fn remove(&self, ih: &InfoHash) -> Result<Option<SlotId>, RegistryError> {
        let prev = self.inner.write().remove(ih);
        if prev.is_some() {
            self.persist()?;
            debug!(
                target: "seederd_engine::registry",
                infohash = %ih,
                "removed",
            );
        }
        Ok(prev)
    }

    /// Snapshot of every (infohash, slot) pair, sorted by slot for
    /// deterministic iteration in tests and startup logs.
    pub fn entries(&self) -> Vec<(InfoHash, SlotId)> {
        let mut v: Vec<(InfoHash, SlotId)> = self
            .inner
            .read()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        v.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()).then(a.0 .0.cmp(&b.0 .0)));
        v
    }

    /// All infohashes currently assigned to `slot`.
    pub fn for_slot(&self, slot: &SlotId) -> Vec<InfoHash> {
        self.inner
            .read()
            .iter()
            .filter(|(_, s)| *s == slot)
            .map(|(ih, _)| *ih)
            .collect()
    }

    /// Iterate over every (infohash, slot) and execute `visit`. Used by
    /// the startup cross-check that compares the registry against
    /// resume files on disk per slot.
    pub fn for_each<F: FnMut(&InfoHash, &SlotId)>(&self, mut visit: F) {
        for (ih, slot) in self.inner.read().iter() {
            visit(ih, slot);
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
        r.assign(ih, SlotId::new("a")).unwrap();
        assert_eq!(r.lookup(&ih).unwrap().as_str(), "a");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn conflict_is_rejected() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([2u8; 20]);
        r.assign(ih, SlotId::new("a")).unwrap();
        let err = r.assign(ih, SlotId::new("b")).unwrap_err();
        assert!(
            matches!(err, RegistryError::Conflict { existing, .. } if existing.as_str() == "a")
        );
    }

    #[test]
    fn assign_same_slot_is_idempotent() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        let ih = InfoHash([3u8; 20]);
        let slot = SlotId::new("x");
        r.assign(ih, slot.clone()).unwrap();
        r.assign(ih, slot).unwrap(); // OK, same slot
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn persist_and_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reg.json");

        {
            let r = AssignmentRegistry::new_empty(&path);
            r.assign(InfoHash([0xAA; 20]), SlotId::new("acct_a"))
                .unwrap();
            r.assign(InfoHash([0xBB; 20]), SlotId::new("acct_b"))
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
    fn for_slot_returns_only_matching() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        r.assign(InfoHash([1u8; 20]), SlotId::new("a")).unwrap();
        r.assign(InfoHash([2u8; 20]), SlotId::new("a")).unwrap();
        r.assign(InfoHash([3u8; 20]), SlotId::new("b")).unwrap();

        let mut as_a = r.for_slot(&SlotId::new("a"));
        as_a.sort_by_key(|ih| ih.0);
        assert_eq!(as_a.len(), 2);
        assert_eq!(r.for_slot(&SlotId::new("b")).len(), 1);
    }
}
