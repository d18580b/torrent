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
//!
//! # This file is the authority
//!
//! Two artefacts persist a torrent→profile mapping: this one, and the pool
//! index's `torrent.profile` column. **This one wins.** It is what the resume
//! scan writes and what the daemon refuses to boot against when it disagrees
//! with the configured profiles; the index's column is a cache of it, written
//! by `pool scan`, which an operator may never run. Where they disagree the
//! scan warns naming both values rather than silently preferring one.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
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

    /// A pre-profiles registry names an id the charset rule refuses.
    ///
    /// The slot era imposed no charset or length rule — `SlotConfig`'s
    /// validation checked `is_default`, duplicates, ports and interfaces only,
    /// and `SlotId`'s `Deserialize` was infallible — so `id = "acct.a"` was a
    /// legal deployment and its `slot_assignments.json` holds that value.
    /// Deserializing that file straight into `ProfileId` fails it as a serde
    /// error, on the one boot that reads it, before the reconciliation refusal
    /// built for exactly this class of mismatch can say anything. The operator
    /// got a truncated context and no id, no file and no remedy, under
    /// `Restart=on-failure`.
    ///
    /// This carries the same three things that refusal carries: the file, what
    /// is wrong with it, and both ways out.
    // `read_from`, not `source`: thiserror reads a field called `source` as
    // the error's cause and tries to make a `PathBuf` into one.
    #[error(
        "the pre-profiles assignment registry at {} assigns {count} torrent(s) to the profile \
         id {id:?}, which this release cannot use: {reason} The registry is migrated verbatim, \
         so the ids in it are the ones that deployment used. Either rename that id in {} to one \
         a [[profile]] table declares — nothing has been written yet, and {} is created from it \
         once it loads — or remove those entries from {} and re-add the torrents.",
        read_from.display(),
        read_from.display(),
        written_to.display(),
        read_from.display(),
    )]
    LegacyProfileId {
        /// The pre-rename file the entries were read from.
        read_from: PathBuf,
        /// The post-rename file the daemon would have written.
        written_to: PathBuf,
        id: String,
        count: usize,
        reason: String,
    },
}

#[derive(Debug)]
pub struct AssignmentRegistry {
    path: PathBuf,
    /// The file the entries were actually read from.
    ///
    /// Equal to `path` except on the one boot that reads a pre-rename file.
    /// `startup.rs` quotes it in the refusal that tells an operator which
    /// entries to remove, and quoting `path` there named a file that, before
    /// the unconditional persist below, was by construction not on disk on
    /// exactly the path that refusal fires on.
    source: PathBuf,
    inner: RwLock<HashMap<InfoHash, ProfileId>>,
}

impl AssignmentRegistry {
    /// Construct empty (in memory + on disk).
    pub fn new_empty(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            path,
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Load from disk; missing file is not an error (empty registry).
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        Self::load_from(path, None)
    }

    /// Load `path`, falling back to `legacy` when `path` does not exist.
    ///
    /// The old file is never deleted or moved: an operator who rolls back gets
    /// it intact. The new one is written **once, unconditionally**, as soon as
    /// the fallback is taken.
    ///
    /// Waiting for the first `assign` or `remove` to write it was not enough.
    /// `assign` returns `Ok(())` without persisting when the info-hash is
    /// already mapped to the same profile, and on a migrated deployment in
    /// steady state the resume scan takes exactly that path for every entry —
    /// so the new file appeared only at the first genuinely new assignment,
    /// which might be never. Meanwhile `startup.rs`'s refusal and
    /// `docs/running.md` both told the operator to edit it.
    pub fn load_from(
        path: impl Into<PathBuf>,
        legacy: Option<PathBuf>,
    ) -> Result<Self, RegistryError> {
        let path = path.into();
        let mut migrated = false;
        let source = match legacy {
            Some(l) if !path.exists() && l.exists() => {
                info!(
                    target: "torrentd_engine::registry",
                    from = %l.display(),
                    to = %path.display(),
                    "reading the pre-profiles assignment registry; \
                     rewriting it under the new name now",
                );
                migrated = true;
                l
            }
            _ => path.clone(),
        };
        let loaded = Self::load_inner(path, source, migrated)?;
        if migrated {
            loaded.persist()?;
            info!(
                target: "torrentd_engine::registry",
                path = %loaded.path.display(),
                entries = loaded.len(),
                "assignment registry written under its current name",
            );
        }
        Ok(loaded)
    }

    fn load_inner(
        path: PathBuf,
        source: PathBuf,
        // True on the one boot that reads a pre-profiles `slot_assignments.json`.
        // That file predates the charset rule entirely, so a value in it that
        // the rule refuses is an upgrade to diagnose rather than a corrupt
        // file — and it gets a refusal that says so instead of a serde error.
        migrated: bool,
    ) -> Result<Self, RegistryError> {
        let map: HashMap<InfoHash, ProfileId> = match fs::read(&source) {
            Ok(bytes) if !bytes.is_empty() => {
                // Deserialize the value as a `ProfileId`, not as a `String`
                // converted afterwards. This file is the other door untrusted
                // text comes through, and `ProfileId`'s `Deserialize` is what
                // enforces the charset rule — a hand-edited id like `../..`
                // otherwise reached `dir_for` and was joined onto a path with
                // nothing in between. A bad id fails the load rather than
                // being skipped: the map cannot be reconstructed, so dropping
                // an entry quietly loses which torrent belonged to which
                // account.
                //
                // Except on the migration path, where the same failure means
                // something else. Below, the values are converted one at a
                // time so the refusal can name the file, the id and the
                // remedy; here, `Deserialize` rejects the whole document and
                // the operator is told only that a load failed.
                let raw: HashMap<String, ProfileId> = if migrated {
                    Self::convert_legacy(&bytes, &source, &path)?
                } else {
                    serde_json::from_slice(&bytes)?
                };
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
                    out.insert(ih, v);
                }
                out
            }
            Ok(_) | Err(_) if !source.exists() => HashMap::new(),
            Ok(_) => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        info!(
            target: "torrentd_engine::registry",
            path = %source.display(),
            entries = map.len(),
            "registry loaded",
        );
        Ok(Self {
            path,
            source,
            inner: RwLock::new(map),
        })
    }

    /// Convert a pre-profiles registry's values one at a time.
    ///
    /// The slot era imposed no charset rule on a slot id, so this file can
    /// legally hold one this release refuses. Deserializing the document
    /// straight into `ProfileId` turns that into a serde error raised on the
    /// migration path, before the reconciliation refusal — which exists for
    /// exactly this class of mismatch — reads anything. Converting per entry
    /// keeps the same rule and the same door, and lets the failure carry the
    /// file, the id, how many entries name it, and what to do.
    ///
    /// All the offending entries are counted before returning, so an operator
    /// learns the size of the edit rather than discovering it one boot at a
    /// time. The first offending id in sort order is the one named, so the
    /// message does not change between two runs over one file.
    fn convert_legacy(
        bytes: &[u8],
        source: &Path,
        target: &Path,
    ) -> Result<HashMap<String, ProfileId>, RegistryError> {
        let raw: HashMap<String, String> = serde_json::from_slice(bytes)?;
        let mut bad: BTreeMap<&str, usize> = BTreeMap::new();
        for id in raw.values() {
            if !crate::profile::ProfileConfig::is_valid_id(id) {
                *bad.entry(id.as_str()).or_insert(0) += 1;
            }
        }
        if let Some((id, count)) = bad.into_iter().next() {
            return Err(RegistryError::LegacyProfileId {
                read_from: source.to_path_buf(),
                written_to: target.to_path_buf(),
                id: id.to_string(),
                count,
                reason: crate::profile::ID_CHARSET_RULE.to_string(),
            });
        }
        Ok(raw
            .into_iter()
            .map(|(k, v)| (k, ProfileId::new(v)))
            .collect())
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Where the entries in memory were read from.
    ///
    /// The current path except on the one boot that reads a pre-rename file.
    /// A message telling an operator to edit "those entries" has to name this
    /// one.
    pub fn source_path(&self) -> &Path {
        &self.source
    }

    /// Where changes are written.
    pub fn path(&self) -> &Path {
        &self.path
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

    /// Profile ids this registry names that `configured` does not contain,
    /// each with how many info-hashes it holds. Sorted, so a caller can put
    /// them in a message without the order changing between runs.
    ///
    /// A registry carried over from the pre-profiles layout names the ids that
    /// deployment used — `default` for every entry, on a single-session one —
    /// and no `[[profile]]` table need declare any of them. Every consumer of
    /// an entry treats a mapped info-hash as already owned and refuses to load
    /// it again, and nothing prunes: `assign` conflicts, the API add path
    /// answers 409, the pool's claim refuses the same way, and the startup
    /// cross-check only ever compares against profiles that have files. An
    /// entry naming a profile that does not exist is therefore a torrent that
    /// nothing can load and nothing can clear.
    pub fn unknown_profiles(&self, configured: &HashSet<ProfileId>) -> BTreeMap<String, usize> {
        let mut out: BTreeMap<String, usize> = BTreeMap::new();
        for profile in self.inner.read().values() {
            if !configured.contains(profile) {
                *out.entry(profile.as_str().to_string()).or_default() += 1;
            }
        }
        out
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
    fn a_legacy_read_writes_the_new_file_before_anything_else_looks_for_it() {
        // `assign` returns `Ok(())` without persisting when the info-hash is
        // already mapped to the same profile, and on a migrated deployment in
        // steady state the resume scan takes exactly that path for every
        // entry — so waiting for the first change to write the new file meant
        // it appeared at the first genuinely new assignment, which might be
        // never. Meanwhile `startup.rs`'s refusal fires before any scan and
        // tells the operator to edit that very file, and `docs/running.md`
        // says the same.
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        let current = dir.path().join("profile_assignments.json");
        {
            let r = AssignmentRegistry::new_empty(&legacy);
            r.assign(InfoHash([0xAA; 20]), ProfileId::new("default"))
                .unwrap();
        }

        let r = AssignmentRegistry::load_from(&current, Some(legacy.clone())).unwrap();

        assert!(
            current.exists(),
            "the file the refusal message quotes has to be on disk by the time it fires",
        );
        assert_eq!(AssignmentRegistry::load(&current).unwrap().len(), 1);
        assert_eq!(
            AssignmentRegistry::load(&legacy).unwrap().len(),
            1,
            "and the old file is still intact for a rollback",
        );

        // The entries came from the old file, and a message telling the
        // operator which ones to look at has to be able to say so.
        assert_eq!(r.source_path(), legacy);
        assert_eq!(r.path(), current);
    }

    #[test]
    fn a_legacy_id_the_charset_rule_refuses_is_named_rather_than_serde_failed() {
        // C46. The slot era imposed no charset rule: its validation checked
        // `is_default`, duplicates, ports and interfaces only, and `SlotId`'s
        // `Deserialize` was infallible — so `id = "acct.a"` was a legal
        // deployment and this is what its registry holds.
        //
        // Deserializing the document straight into `ProfileId` failed it as a
        // serde error on the migration path, before the reconciliation
        // refusal built for this class of mismatch could say anything. With
        // `startup.rs`'s `.context("load assignment registry")` on top, the
        // operator got four words under `Restart=on-failure`.
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        let current = dir.path().join("profile_assignments.json");
        std::fs::write(
            &legacy,
            r#"{"aa00000000000000000000000000000000000000":"acct.a",
                "bb00000000000000000000000000000000000000":"acct.a"}"#,
        )
        .unwrap();

        let err = AssignmentRegistry::load_from(&current, Some(legacy.clone()))
            .expect_err("an id outside [A-Za-z0-9_-] cannot be used as a path component");
        let msg = err.to_string();

        // The three things the refusal at `startup.rs` carries, which this
        // path preempts: the offending id, the file it is in, and the remedy.
        assert!(msg.contains("acct.a"), "names the offending id, got: {msg}");
        assert!(
            msg.contains(&legacy.display().to_string()),
            "names the file the entries were read from, got: {msg}",
        );
        assert!(
            msg.contains("[A-Za-z0-9_-]"),
            "says what an id may contain, got: {msg}",
        );
        assert!(
            msg.contains("re-add the torrents") && msg.contains("rename"),
            "states both ways out, got: {msg}",
        );
        assert!(
            msg.contains('2'),
            "says how many entries name it, so the operator knows the size of the edit, \
             got: {msg}",
        );

        // It is a refusal, not a partial load: the map cannot be
        // reconstructed, so dropping the entry quietly loses which torrent
        // belonged to which account.
        assert!(
            matches!(err, RegistryError::LegacyProfileId { .. }),
            "a dedicated variant, not a serde error, got: {err:?}",
        );
        assert!(
            !current.exists(),
            "nothing is written under the new name until the old one loads",
        );
    }

    #[test]
    fn a_legacy_registry_whose_ids_are_all_legal_still_migrates() {
        // The rule cannot pass by refusing every legacy file: the ordinary
        // upgrade — every entry saying `default` — is the case the migration
        // exists for.
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        let current = dir.path().join("profile_assignments.json");
        std::fs::write(
            &legacy,
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"default"}"#,
        )
        .unwrap();

        let r = AssignmentRegistry::load_from(&current, Some(legacy)).unwrap();
        assert_eq!(r.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(), "default");
        assert!(current.exists());
    }

    #[test]
    fn a_registry_that_needed_no_migration_reads_and_writes_one_file() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("profile_assignments.json");
        let r = AssignmentRegistry::load_from(&current, None).unwrap();
        assert_eq!(r.source_path(), current);
        assert_eq!(r.path(), current);
        assert!(
            !current.exists(),
            "nothing was migrated, so nothing is written until something changes",
        );
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

    #[test]
    fn unknown_profiles_reports_every_id_no_configured_profile_declares() {
        // What a registry migrated from the pre-profiles layout looks like:
        // every entry names `default`, and the operator's new config declares
        // `public`. Nothing downstream reconciles the two, so this is the only
        // place the mismatch can be seen before it strands the library.
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("reg.json"));
        r.assign(InfoHash([1u8; 20]), ProfileId::new("default"))
            .unwrap();
        r.assign(InfoHash([2u8; 20]), ProfileId::new("default"))
            .unwrap();
        r.assign(InfoHash([3u8; 20]), ProfileId::new("public"))
            .unwrap();

        let configured: HashSet<ProfileId> = [ProfileId::new("public")].into_iter().collect();
        let unknown = r.unknown_profiles(&configured);
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown.get("default"), Some(&2));

        // Declare it and nothing is unknown — the way out the refusal offers.
        let configured: HashSet<ProfileId> = [ProfileId::new("public"), ProfileId::new("default")]
            .into_iter()
            .collect();
        assert!(r.unknown_profiles(&configured).is_empty());
    }

    #[test]
    fn a_legacy_registry_read_under_the_new_name_still_names_the_old_profile_ids() {
        // The migration is verbatim by design, so the ids it carries over are
        // the pre-profiles deployment's — which is exactly why the caller has
        // to reconcile them rather than assume the rewrite fixed them.
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        fs::write(
            &legacy,
            br#"{"0101010101010101010101010101010101010101":"default"}"#,
        )
        .unwrap();

        let r = AssignmentRegistry::load_from(
            dir.path().join("profile_assignments.json"),
            Some(legacy),
        )
        .unwrap();

        let configured: HashSet<ProfileId> = [ProfileId::new("public")].into_iter().collect();
        assert_eq!(r.unknown_profiles(&configured).get("default"), Some(&1));
    }
}
