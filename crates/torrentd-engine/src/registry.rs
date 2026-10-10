//! Torrent → profile assignment registry.
//!
//! Safety Rule 3 — global info-hash uniqueness — lives here. Every
//! torrent the daemon loads (via API add, startup resume scan, or
//! startup torrent dir scan) is first looked up here. Two outcomes:
//!
//!   - The infohash is already mapped to *any* profile → reject (409).
//!   - The infohash is unmapped → assign to the requested profile, persist
//!     it, return Ok.
//!
//! # Persistence
//!
//! A SQLite database, `<state_dir>/registry.db`, holding one row per
//! assignment in `assignment(infohash TEXT PRIMARY KEY, profile_id TEXT)`.
//! Every change is one row inside one transaction, written through a single
//! serialized writer, and the in-memory map is updated only after that
//! transaction commits — so a failed write leaves memory and disk agreeing
//! that nothing changed.
//!
//! It replaced a flat JSON file, `profile_assignments.json`, that was
//! rewritten whole and fsynced on every change. That cost O(N) per add — O(N²)
//! to build a library — and two writers racing on its one temp path could
//! corrupt it or drop an assignment, and a write that failed left the change
//! in memory anyway. A JSON file found next to the database is imported into
//! it once and renamed to `<name>.imported`; see [`JsonImport`].
//!
//! # This registry is the authority
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
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use libtorrent_safe::InfoHash;
use parking_lot::Mutex;
use parking_lot::RwLock;
use rusqlite::params;
use rusqlite::Connection;
use thiserror::Error;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::profile::ProfileId;

/// The schema this release writes, in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 1;

/// How long a write waits for another process's write lock — `torrentd pool
/// scan` opening the registry while the daemon runs — before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// What a successful [`AssignmentRegistry::assign`] did.
///
/// A caller that goes on to load the torrent must tell the two apart: only a
/// claim this call inserted is the caller's to release when the load fails.
/// Releasing an [`Claim::AlreadyOurs`] claim deletes one a concurrent load of
/// the same info-hash into the same profile made, and leaves that torrent
/// seeding with no owner the uniqueness rule can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// This call inserted the assignment.
    New,
    /// The info-hash was already assigned to this same profile; nothing was
    /// written.
    AlreadyOurs,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Parse(#[from] serde_json::Error),

    /// The database could not be opened, read or written.
    #[error("assignment registry database {}: {source}", path.display())]
    Db {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    /// The database was written by a newer release.
    #[error(
        "assignment registry database {} has schema version {found}; this release \
         understands up to {SCHEMA_VERSION}. It was written by a newer torrentd — run that, \
         or restore the database from before the upgrade.",
        path.display()
    )]
    Schema { path: PathBuf, found: i64 },

    /// A row names a profile id the charset rule refuses.
    ///
    /// Only a hand edit puts one there: every write goes through `ProfileId`.
    /// Skipping the row would quietly lose which torrent belonged to which
    /// account, so the load fails instead and names the row.
    #[error(
        "assignment registry database {} assigns {infohash} to the profile id {id:?}, which \
         is not a usable id: {reason} Correct or delete that row.",
        path.display()
    )]
    BadRow {
        path: PathBuf,
        infohash: String,
        id: String,
        reason: String,
    },

    /// A JSON registry being imported disagrees with the database.
    #[error(
        "{} assigns {infohash} to profile {in_file}, but the assignment registry database {} \
         already assigns it to {in_db}. Nothing was imported and {} was left where it is. \
         Remove that entry from one of the two and start again.",
        file.display(),
        db.display(),
        file.display()
    )]
    ImportConflict {
        file: PathBuf,
        db: PathBuf,
        infohash: InfoHash,
        in_file: ProfileId,
        in_db: ProfileId,
    },

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
         a [[profile]] table declares — nothing has been written yet, and it is imported into {} \
         once it loads — or remove those entries from {} and re-add the torrents.",
        read_from.display(),
        read_from.display(),
        written_to.display(),
        read_from.display(),
    )]
    LegacyProfileId {
        /// The pre-rename file the entries were read from.
        read_from: PathBuf,
        /// The database the entries would have been imported into.
        written_to: PathBuf,
        id: String,
        count: usize,
        reason: String,
    },
}

/// A JSON assignment file to fold into the database when it is opened.
///
/// Which file, if any, is the caller's decision — `Config::registry_import`
/// in the daemon. Opening imports every entry in one transaction, then renames
/// the file to `<name>.imported` so it is not read again; an entry the
/// database already holds for the same profile is skipped, so a boot that
/// died between that commit and the rename imports nothing twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonImport {
    pub path: PathBuf,
    /// A pre-profiles `slot_assignments.json`.
    ///
    /// That file predates the charset rule entirely, so a value in it that the
    /// rule refuses is an upgrade to diagnose rather than a corrupt file — and
    /// it gets a refusal that says so ([`RegistryError::LegacyProfileId`])
    /// instead of a serde error.
    pub pre_profiles: bool,
}

#[derive(Debug)]
pub struct AssignmentRegistry {
    path: PathBuf,
    /// Where the entries were read from.
    ///
    /// Equal to `path` except on the boot that imports a JSON file, where it
    /// is that file under the `.imported` name it was moved to. `startup.rs`
    /// quotes it in the refusal that tells an operator which entries to
    /// remove.
    source: PathBuf,
    /// The read path. Holds exactly what the database holds: every change
    /// lands here only after its transaction commits.
    inner: RwLock<HashMap<InfoHash, ProfileId>>,
    /// The one writer. Holding it across check-and-write is what makes an
    /// `assign` atomic against every other `assign` and `remove`; the lock
    /// order is always this, then `inner`.
    writer: Mutex<Connection>,
}

impl AssignmentRegistry {
    /// Open the database at `path` with nothing to import.
    ///
    /// For tests and tools that start from a path of their own.
    ///
    /// # Panics
    ///
    /// If the database cannot be opened.
    #[track_caller]
    pub fn new_empty(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self::open(&path, None)
            .unwrap_or_else(|e| panic!("open assignment registry {}: {e}", path.display()))
    }

    /// Open (creating if absent) the database at `path`, first importing
    /// `import` when it is given.
    ///
    /// The JSON file is read and validated before the database is touched, so
    /// a file that fails to parse or names an unusable id leaves nothing
    /// created and nothing renamed.
    pub fn open(
        path: impl Into<PathBuf>,
        import: Option<JsonImport>,
    ) -> Result<Self, RegistryError> {
        let path = path.into();
        let parsed = match &import {
            Some(i) => Some(Self::read_json(i, &path)?),
            None => None,
        };

        let mut conn = open_db(&path)?;
        let mut map = read_all(&conn, &path)?;
        let mut source = path.clone();

        if let (Some(import), Some(entries)) = (import, parsed) {
            let added = import_into(&mut conn, &path, &import.path, &mut map, entries)?;
            let moved = move_aside(&import.path)?;
            info!(
                target: "torrentd_engine::registry",
                from = %import.path.display(),
                moved_to = %moved.display(),
                to = %path.display(),
                imported = added,
                "JSON assignment registry imported into the database and moved aside",
            );
            source = moved;
        }

        info!(
            target: "torrentd_engine::registry",
            path = %path.display(),
            entries = map.len(),
            "registry loaded",
        );
        Ok(Self {
            path,
            source,
            inner: RwLock::new(map),
            writer: Mutex::new(conn),
        })
    }

    /// Parse a JSON registry into validated entries.
    fn read_json(
        import: &JsonImport,
        db: &Path,
    ) -> Result<HashMap<InfoHash, ProfileId>, RegistryError> {
        let bytes = fs::read(&import.path)?;
        if bytes.is_empty() {
            return Ok(HashMap::new());
        }
        // Deserialize the value as a `ProfileId`, not as a `String` converted
        // afterwards. This file is the other door untrusted text comes
        // through, and `ProfileId`'s `Deserialize` is what enforces the
        // charset rule — a hand-edited id like `../..` otherwise reached
        // `dir_for` and was joined onto a path with nothing in between. A bad
        // id fails the load rather than being skipped: the map cannot be
        // reconstructed, so dropping an entry quietly loses which torrent
        // belonged to which account.
        //
        // Except for a pre-profiles file, where the same failure means
        // something else. There the values are converted one at a time so the
        // refusal can name the file, the id and the remedy; here,
        // `Deserialize` rejects the whole document and the operator is told
        // only that a load failed.
        let raw: HashMap<String, ProfileId> = if import.pre_profiles {
            Self::convert_legacy(&bytes, &import.path, db)?
        } else {
            serde_json::from_slice(&bytes)?
        };
        let mut out = HashMap::with_capacity(raw.len());
        for (k, v) in raw {
            let Some(ih) = InfoHash::from_hex(&k) else {
                warn!(
                    target: "torrentd_engine::registry",
                    key = %k,
                    "skipping registry entry with invalid infohash hex",
                );
                continue;
            };
            out.insert(ih, v);
        }
        Ok(out)
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
    /// The database except on the boot that imports a JSON file, where it is
    /// that file under its `.imported` name. It says where the entries an
    /// operator is being told about *came from*; it does not say where to edit
    /// them — that is always [`Self::path`], because the moved file is kept
    /// for a rollback and is not read again.
    ///
    /// A message about those entries therefore names **both**, as the startup
    /// refusal does.
    pub fn source_path(&self) -> &Path {
        &self.source
    }

    /// The database changes are written to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn db_err(&self, source: rusqlite::Error) -> RegistryError {
        RegistryError::Db {
            path: self.path.clone(),
            source,
        }
    }

    pub fn lookup(&self, ih: &InfoHash) -> Option<ProfileId> {
        self.inner.read().get(ih).cloned()
    }

    /// Atomically assign an infohash to a profile. Conflict iff the infohash
    /// is already mapped to *another* profile; [`Claim::AlreadyOurs`] when it
    /// is already mapped to this one, so a caller can tell a claim it made from
    /// one somebody else in the same profile holds.
    ///
    /// Persisted before it is visible: a write that fails leaves the infohash
    /// unassigned in memory as on disk, so a caller that sees `Err` holds no
    /// claim to release.
    pub fn assign(&self, ih: InfoHash, profile: ProfileId) -> Result<Claim, RegistryError> {
        let mut conn = self.writer.lock();
        if let Some(existing) = self.inner.read().get(&ih) {
            if *existing == profile {
                debug!(
                    target: "torrentd_engine::registry",
                    infohash = %ih,
                    profile_id = %profile,
                    "assign no-op (already assigned to same profile)",
                );
                return Ok(Claim::AlreadyOurs);
            }
            return Err(RegistryError::Conflict {
                infohash: ih,
                existing: existing.clone(),
            });
        }
        // The primary key is the last word, not the map: another process with
        // the database open (`torrentd pool scan`) may have written a row this
        // one has not seen. Whatever the table holds for this infohash after
        // the statement is the answer.
        let hex = ih.to_hex();
        let tx = conn.transaction().map_err(|e| self.db_err(e))?;
        let inserted = tx
            .execute(
                "INSERT INTO assignment (infohash, profile_id) VALUES (?1, ?2) \
                 ON CONFLICT (infohash) DO NOTHING",
                params![hex, profile.as_str()],
            )
            .map_err(|e| self.db_err(e))?;
        if inserted == 0 {
            let existing: String = tx
                .query_row(
                    "SELECT profile_id FROM assignment WHERE infohash = ?1",
                    params![hex],
                    |r| r.get(0),
                )
                .map_err(|e| self.db_err(e))?;
            drop(tx);
            // A row this process did not write gets the check `read_all`
            // applies at load; only then may it enter the map.
            if !crate::profile::ProfileConfig::is_valid_id(&existing) {
                return Err(RegistryError::BadRow {
                    path: self.path.clone(),
                    infohash: hex,
                    id: existing,
                    reason: crate::profile::ID_CHARSET_RULE.to_string(),
                });
            }
            let existing = ProfileId::new(existing);
            self.inner.write().insert(ih, existing.clone());
            if existing == profile {
                return Ok(Claim::AlreadyOurs);
            }
            return Err(RegistryError::Conflict {
                infohash: ih,
                existing,
            });
        }
        tx.commit().map_err(|e| self.db_err(e))?;
        self.inner.write().insert(ih, profile.clone());
        drop(conn);
        info!(
            target: "torrentd_engine::registry",
            infohash = %ih,
            profile_id = %profile,
            "assigned",
        );
        Ok(Claim::New)
    }

    /// Remove an assignment. No-op if the infohash isn't present.
    ///
    /// Like [`Self::assign`], persisted before it is visible: a write that
    /// fails leaves the assignment in place, so retrying the remove retries
    /// the write.
    pub fn remove(&self, ih: &InfoHash) -> Result<Option<ProfileId>, RegistryError> {
        let mut conn = self.writer.lock();
        let Some(prev) = self.inner.read().get(ih).cloned() else {
            return Ok(None);
        };
        let tx = conn.transaction().map_err(|e| self.db_err(e))?;
        tx.execute(
            "DELETE FROM assignment WHERE infohash = ?1",
            params![ih.to_hex()],
        )
        .map_err(|e| self.db_err(e))?;
        tx.commit().map_err(|e| self.db_err(e))?;
        self.inner.write().remove(ih);
        drop(conn);
        debug!(
            target: "torrentd_engine::registry",
            infohash = %ih,
            "removed",
        );
        Ok(Some(prev))
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
}

/// Open the database, creating it and its schema where absent.
fn open_db(path: &Path) -> Result<Connection, RegistryError> {
    let db = |source| RegistryError::Db {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).map_err(db)?;
    // WAL: a commit appends to the log rather than rewriting pages in place,
    // so a process killed mid-write leaves the last committed state intact and
    // readable, and the next open replays or discards the tail.
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(db)?;
    // NORMAL, not FULL. Under WAL a commit that has returned survives the
    // process being killed at any instant — the log is in the OS page cache
    // and the next open replays it — which is the failure a daemon under
    // `Restart=on-failure` actually meets. Only an OS crash or power loss can
    // lose the newest commits, and even then the database is consistent, not
    // corrupt. FULL fsyncs every commit: measured at ~5 ms each on a busy
    // disk, that made 100K assigns take 505 s, where NORMAL takes seconds. An
    // assignment lost that way is re-claimed by the next boot's resume and
    // torrent-dir scans, which run before the HTTP API accepts an add.
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(db)?;
    conn.busy_timeout(BUSY_TIMEOUT).map_err(db)?;

    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(db)?;
    if version > SCHEMA_VERSION {
        return Err(RegistryError::Schema {
            path: path.to_path_buf(),
            found: version,
        });
    }
    // Hex, not a blob, so an operator following a refusal's advice can read
    // and edit it with the `sqlite3` shell.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS assignment (
             infohash   TEXT PRIMARY KEY NOT NULL,
             profile_id TEXT NOT NULL
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS assignment_profile ON assignment (profile_id);",
    )
    .map_err(db)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(db)?;
    Ok(conn)
}

/// Every row, validated the way the JSON import validates its entries.
fn read_all(conn: &Connection, path: &Path) -> Result<HashMap<InfoHash, ProfileId>, RegistryError> {
    let db = |source| RegistryError::Db {
        path: path.to_path_buf(),
        source,
    };
    let mut stmt = conn
        .prepare("SELECT infohash, profile_id FROM assignment")
        .map_err(db)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(db)?;
    let mut out = HashMap::new();
    for row in rows {
        let (hex, id) = row.map_err(db)?;
        let Some(ih) = InfoHash::from_hex(&hex) else {
            warn!(
                target: "torrentd_engine::registry",
                key = %hex,
                "skipping registry row with invalid infohash hex",
            );
            continue;
        };
        if !crate::profile::ProfileConfig::is_valid_id(&id) {
            return Err(RegistryError::BadRow {
                path: path.to_path_buf(),
                infohash: hex,
                id,
                reason: crate::profile::ID_CHARSET_RULE.to_string(),
            });
        }
        out.insert(ih, ProfileId::new(id));
    }
    Ok(out)
}

/// Insert `entries` into the database in one transaction, and into `map`
/// once it commits. Returns how many were new.
///
/// An entry the database already holds for the same profile is skipped; one
/// it holds for a different profile refuses the whole import, which rolls
/// back.
fn import_into(
    conn: &mut Connection,
    db: &Path,
    file: &Path,
    map: &mut HashMap<InfoHash, ProfileId>,
    entries: HashMap<InfoHash, ProfileId>,
) -> Result<usize, RegistryError> {
    let err = |source| RegistryError::Db {
        path: db.to_path_buf(),
        source,
    };
    // Sorted, so a refusal names the same entry on every run over one file.
    let mut entries: Vec<(InfoHash, ProfileId)> = entries.into_iter().collect();
    entries.sort_by_key(|a| a.0 .0);
    let mut fresh = Vec::new();
    for (ih, profile) in entries {
        match map.get(&ih) {
            Some(existing) if *existing == profile => {}
            Some(existing) => {
                return Err(RegistryError::ImportConflict {
                    file: file.to_path_buf(),
                    db: db.to_path_buf(),
                    infohash: ih,
                    in_file: profile,
                    in_db: existing.clone(),
                });
            }
            None => fresh.push((ih, profile)),
        }
    }
    let tx = conn.transaction().map_err(err)?;
    {
        let mut ins = tx
            .prepare("INSERT INTO assignment (infohash, profile_id) VALUES (?1, ?2)")
            .map_err(err)?;
        for (ih, profile) in &fresh {
            ins.execute(params![ih.to_hex(), profile.as_str()])
                .map_err(err)?;
        }
    }
    tx.commit().map_err(err)?;
    let n = fresh.len();
    map.extend(fresh);
    Ok(n)
}

/// Rename an imported JSON file to `<name>.imported`, or `<name>.imported.N`
/// where that is taken, so an earlier copy is never overwritten. Returns where
/// it went.
fn move_aside(file: &Path) -> Result<PathBuf, RegistryError> {
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "assignments.json".to_string());
    let mut to = file.with_file_name(format!("{name}.imported"));
    let mut n = 1u32;
    while to.exists() {
        to = file.with_file_name(format!("{name}.imported.{n}"));
        n += 1;
    }
    fs::rename(file, &to)?;
    if let Some(parent) = to.parent() {
        if let Ok(d) = fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(to)
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
        assert_eq!(r.assign(ih, profile.clone()).unwrap(), Claim::New);
        // Same profile: not an error, but not this call's claim either.
        assert_eq!(r.assign(ih, profile).unwrap(), Claim::AlreadyOurs);
        assert_eq!(r.len(), 1);
    }

    fn json(path: &Path, pre_profiles: bool) -> Option<JsonImport> {
        Some(JsonImport {
            path: path.to_path_buf(),
            pre_profiles,
        })
    }

    fn imported(path: &Path) -> PathBuf {
        path.with_file_name(format!(
            "{}.imported",
            path.file_name().unwrap().to_string_lossy()
        ))
    }

    /// Acceptance: the first open on a JSON registry imports it losslessly.
    #[test]
    fn a_json_registry_is_imported_losslessly_and_moved_aside() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("profile_assignments.json");
        let db = dir.path().join("registry.db");
        let expected: HashMap<String, String> = (0..2000u32)
            .map(|i| {
                let mut b = [0u8; 20];
                b[..4].copy_from_slice(&i.to_be_bytes());
                (hex::encode(b), format!("acct_{}", i % 7))
            })
            .collect();
        fs::write(&file, serde_json::to_vec(&expected).unwrap()).unwrap();

        let r = AssignmentRegistry::open(&db, json(&file, false)).unwrap();
        assert_eq!(r.len(), expected.len());
        assert!(!file.exists(), "imported once, so not read again");
        assert!(imported(&file).exists(), "kept, renamed, for a rollback");
        assert_eq!(r.source_path(), imported(&file));
        assert_eq!(r.path(), db);
        drop(r);

        // What a later boot reads: the database alone, holding every entry.
        let r = AssignmentRegistry::open(&db, None).unwrap();
        let got: HashMap<String, String> = r
            .entries()
            .into_iter()
            .map(|(ih, p)| (ih.to_hex(), p.as_str().to_string()))
            .collect();
        assert_eq!(got, expected);
        assert_eq!(r.source_path(), db);
    }

    #[test]
    fn the_pre_profiles_registry_is_imported_the_same_way() {
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        let db = dir.path().join("registry.db");
        fs::write(
            &legacy,
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"acct_a"}"#,
        )
        .unwrap();

        let r = AssignmentRegistry::open(&db, json(&legacy, true)).unwrap();
        assert_eq!(
            r.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(),
            "acct_a",
            "without this the daemon starts with no record of who owns what, and the \
             cross-profile uniqueness rule has nothing to enforce against",
        );
        r.assign(InfoHash([0xBB; 20]), ProfileId::new("acct_b"))
            .unwrap();
        drop(r);
        assert_eq!(AssignmentRegistry::open(&db, None).unwrap().len(), 2);
        assert!(imported(&legacy).exists());
    }

    #[test]
    fn an_import_whose_rename_never_happened_is_not_doubled_on_the_next_open() {
        // The commit and the rename are two steps; a process killed between
        // them leaves the file in place and its entries in the database. The
        // next open must import it again as a no-op, not refuse or duplicate.
        let dir = tempdir().unwrap();
        let file = dir.path().join("profile_assignments.json");
        let db = dir.path().join("registry.db");
        let body = r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"acct_a"}"#;
        fs::write(&file, body).unwrap();
        drop(AssignmentRegistry::open(&db, json(&file, false)).unwrap());
        fs::write(&file, body).unwrap();

        let r = AssignmentRegistry::open(&db, json(&file, false)).unwrap();
        assert_eq!(r.len(), 1);
        assert!(!file.exists());
        assert!(
            imported(&file).exists()
                && dir
                    .path()
                    .join("profile_assignments.json.imported.1")
                    .exists(),
            "the earlier copy is not overwritten",
        );
    }

    #[test]
    fn an_import_that_contradicts_the_database_is_refused_whole() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("profile_assignments.json");
        let db = dir.path().join("registry.db");
        AssignmentRegistry::new_empty(&db)
            .assign(InfoHash([0xAA; 20]), ProfileId::new("live"))
            .unwrap();
        fs::write(
            &file,
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"stale",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":"stale"}"#,
        )
        .unwrap();

        let err = AssignmentRegistry::open(&db, json(&file, false)).unwrap_err();
        assert!(
            matches!(&err, RegistryError::ImportConflict { in_db, in_file, .. }
                if in_db.as_str() == "live" && in_file.as_str() == "stale"),
            "{err:?}",
        );
        assert!(
            file.exists(),
            "a refused import leaves the file where it was"
        );
        let r = AssignmentRegistry::open(&db, None).unwrap();
        assert_eq!(r.len(), 1, "and imports none of it");
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
        let current = dir.path().join("registry.db");
        std::fs::write(
            &legacy,
            r#"{"aa00000000000000000000000000000000000000":"acct.a",
                "bb00000000000000000000000000000000000000":"acct.a"}"#,
        )
        .unwrap();

        let err = AssignmentRegistry::open(&current, json(&legacy, true))
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
            "nothing is created until the old file loads",
        );
        assert!(
            legacy.exists(),
            "and the file to edit is still where it was"
        );
    }

    #[test]
    fn a_legacy_registry_whose_ids_are_all_legal_still_migrates() {
        // The rule cannot pass by refusing every legacy file: the ordinary
        // upgrade — every entry saying `default` — is the case the migration
        // exists for.
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("slot_assignments.json");
        let current = dir.path().join("registry.db");
        std::fs::write(
            &legacy,
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"default"}"#,
        )
        .unwrap();

        let r = AssignmentRegistry::open(&current, json(&legacy, true)).unwrap();
        assert_eq!(r.lookup(&InfoHash([0xAA; 20])).unwrap().as_str(), "default");
        assert!(current.exists());
    }

    #[test]
    fn a_registry_with_nothing_to_import_reads_and_writes_one_database() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("registry.db");
        let r = AssignmentRegistry::open(&current, None).unwrap();
        assert_eq!(r.source_path(), current);
        assert_eq!(r.path(), current);
        assert!(r.is_empty());
    }

    #[test]
    fn a_hand_edited_row_naming_an_escaping_profile_id_does_not_load() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        drop(AssignmentRegistry::new_empty(&db));
        Connection::open(&db)
            .unwrap()
            .execute(
                "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', '../..')",
                [],
            )
            .unwrap();
        let err = AssignmentRegistry::open(&db, None).unwrap_err();
        assert!(
            matches!(&err, RegistryError::BadRow { id, .. } if id == "../.."),
            "{err:?}"
        );
    }

    #[test]
    fn a_row_another_process_wrote_after_load_answers_assign_as_a_conflict() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        let r = AssignmentRegistry::open(&db, None).unwrap();
        Connection::open(&db)
            .unwrap()
            .execute(
                "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', 'other')",
                [],
            )
            .unwrap();
        let ih = InfoHash([1u8; 20]);
        let err = r.assign(ih, ProfileId::new("mine")).unwrap_err();
        assert!(
            matches!(&err, RegistryError::Conflict { existing, .. } if existing.as_str() == "other"),
            "{err:?}"
        );
        assert_eq!(r.lookup(&ih), Some(ProfileId::new("other")));
    }

    /// The same row naming the caller's own profile is not a claim this call
    /// made: the caller must not release it if its load then fails.
    #[test]
    fn a_row_another_process_wrote_for_the_same_profile_is_not_a_new_claim() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        let r = AssignmentRegistry::open(&db, None).unwrap();
        Connection::open(&db)
            .unwrap()
            .execute(
                "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', 'mine')",
                [],
            )
            .unwrap();
        let ih = InfoHash([1u8; 20]);
        assert_eq!(
            r.assign(ih, ProfileId::new("mine")).unwrap(),
            Claim::AlreadyOurs
        );
        assert_eq!(r.lookup(&ih), Some(ProfileId::new("mine")));
    }

    #[test]
    fn a_row_another_process_wrote_with_an_escaping_profile_id_is_refused_by_assign() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        let r = AssignmentRegistry::open(&db, None).unwrap();
        Connection::open(&db)
            .unwrap()
            .execute(
                "INSERT INTO assignment VALUES ('0101010101010101010101010101010101010101', '../..')",
                [],
            )
            .unwrap();
        let ih = InfoHash([1u8; 20]);
        let err = r.assign(ih, ProfileId::new("mine")).unwrap_err();
        assert!(
            matches!(&err, RegistryError::BadRow { id, .. } if id == "../.."),
            "{err:?}"
        );
        assert_eq!(r.lookup(&ih), None);
    }

    #[test]
    fn a_database_from_a_newer_schema_is_refused() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        drop(AssignmentRegistry::new_empty(&db));
        Connection::open(&db)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            AssignmentRegistry::open(&db, None),
            Err(RegistryError::Schema { .. })
        ));
    }

    /// Make every write to `db` fail from here on, as on a full or read-only
    /// state directory, without touching the registry that has it open.
    fn fail_writes(db: &Path) {
        Connection::open(db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_insert BEFORE INSERT ON assignment \
                   BEGIN SELECT RAISE(ABORT, 'disk full'); END;
                 CREATE TRIGGER no_delete BEFORE DELETE ON assignment \
                   BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
    }

    #[test]
    fn a_write_that_fails_changes_nothing_in_memory_either() {
        // Before, `assign` inserted into the map and then persisted, and
        // `remove` removed and then persisted — so a failed write left memory
        // saying one thing and the file another until the next restart
        // silently undid it.
        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        let r = AssignmentRegistry::new_empty(&db);
        let kept = InfoHash([0x01; 20]);
        r.assign(kept, ProfileId::new("a")).unwrap();
        fail_writes(&db);

        let fresh = InfoHash([0x02; 20]);
        assert!(r.assign(fresh, ProfileId::new("a")).is_err());
        assert_eq!(
            r.lookup(&fresh),
            None,
            "an assign that failed claims nothing"
        );

        assert!(r.remove(&kept).is_err());
        assert_eq!(
            r.lookup(&kept),
            Some(ProfileId::new("a")),
            "a remove that failed releases nothing, so retrying it retries the write",
        );
    }

    /// Acceptance: concurrent assigns lose nothing, and exactly one of several
    /// racing claims on one infohash wins.
    #[test]
    fn concurrent_assigns_lose_nothing() {
        const THREADS: u32 = 8;
        const PER: u32 = 250;
        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        let r = std::sync::Arc::new(AssignmentRegistry::new_empty(&db));
        let contested = InfoHash([0xFF; 20]);

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let r = std::sync::Arc::clone(&r);
                std::thread::spawn(move || {
                    let profile = ProfileId::new(format!("p{t}"));
                    let won = r.assign(contested, profile.clone()).is_ok();
                    for i in 0..PER {
                        let mut b = [0u8; 20];
                        b[..4].copy_from_slice(&t.to_be_bytes());
                        b[4..8].copy_from_slice(&i.to_be_bytes());
                        r.assign(InfoHash(b), profile.clone())
                            .unwrap_or_else(|e| panic!("assign {t}/{i}: {e}"));
                    }
                    won
                })
            })
            .collect();
        let winners = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(
            winners, 1,
            "one claim on an infohash wins, the rest conflict"
        );
        let total = (THREADS * PER) as usize + 1;
        assert_eq!(r.len(), total);
        drop(r);

        let reopened = AssignmentRegistry::open(&db, None).unwrap();
        assert_eq!(reopened.len(), total, "and every one of them is on disk");
    }

    /// The child half of [`a_kill_9_mid_write_loses_no_acknowledged_assignment`]:
    /// assigns until killed, printing each infohash once `assign` returned.
    #[test]
    #[ignore = "run only as the crash test's child process"]
    fn crash_child() {
        use std::io::Write as _;
        let Some(db) = std::env::var_os("TORRENTD_REGISTRY_CRASH_DB") else {
            return;
        };
        let r = AssignmentRegistry::new_empty(PathBuf::from(db));
        let mut out = std::io::stdout().lock();
        for i in 0u64..=u64::MAX {
            let mut b = [0u8; 20];
            b[..8].copy_from_slice(&i.to_be_bytes());
            let ih = InfoHash(b);
            r.assign(ih, ProfileId::new("p")).unwrap();
            writeln!(out, "ok {}", ih.to_hex()).unwrap();
            out.flush().unwrap();
        }
    }

    /// Acceptance: `kill -9` mid-write, reopen — the database is intact and
    /// every assignment the writer was told had succeeded is in it.
    #[test]
    fn a_kill_9_mid_write_loses_no_acknowledged_assignment() {
        use std::io::BufRead as _;
        use std::process::Command;
        use std::process::Stdio;

        let dir = tempdir().unwrap();
        let db = dir.path().join("registry.db");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "registry::tests::crash_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TORRENTD_REGISTRY_CRASH_DB", &db)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut acked = Vec::new();
        // Mid-stream: well past the first commit, with writes still going.
        while acked.len() < 200 {
            let line = lines
                .next()
                .expect("the child stopped before it was killed")
                .unwrap();
            if let Some(hex) = line.strip_prefix("ok ") {
                acked.push(hex.to_string());
            }
        }
        child.kill().unwrap(); // SIGKILL
        child.wait().unwrap();
        // Whatever it acknowledged before the signal landed is still in the
        // pipe; every one of those counts too.
        for line in lines {
            if let Some(hex) = line.unwrap().strip_prefix("ok ") {
                acked.push(hex.to_string());
            }
        }

        let r = AssignmentRegistry::open(&db, None).expect("the database opens after a kill -9");
        for hex in &acked {
            let ih = InfoHash::from_hex(hex).unwrap();
            assert_eq!(
                r.lookup(&ih),
                Some(ProfileId::new("p")),
                "{hex} was acknowledged before the kill and is gone"
            );
        }
        let ok: String = Connection::open(&db)
            .unwrap()
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(ok, "ok");
    }

    /// Acceptance: 100K assigns take seconds, not hours. The JSON file this
    /// replaced rewrote every entry on every add, so the 100_000th add wrote
    /// 100_000 entries. About 7 s in a debug build; the bound is loose so a
    /// loaded CI runner does not fail it, and still minutes short of the old
    /// file's quadratic cost.
    #[test]
    fn a_hundred_thousand_assigns_take_seconds() {
        let dir = tempdir().unwrap();
        let r = AssignmentRegistry::new_empty(dir.path().join("registry.db"));
        let start = std::time::Instant::now();
        for i in 0..100_000u32 {
            let mut b = [0u8; 20];
            b[..4].copy_from_slice(&i.to_be_bytes());
            r.assign(InfoHash(b), ProfileId::new("p")).unwrap();
        }
        let took = start.elapsed();
        eprintln!("100000 assigns took {took:?}");
        assert!(took < Duration::from_secs(120), "took {took:?}");
    }

    #[test]
    fn persist_and_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.db");

        {
            let r = AssignmentRegistry::new_empty(&path);
            r.assign(InfoHash([0xAA; 20]), ProfileId::new("acct_a"))
                .unwrap();
            r.assign(InfoHash([0xBB; 20]), ProfileId::new("acct_b"))
                .unwrap();
            assert_eq!(r.len(), 2);
        }

        let reloaded = AssignmentRegistry::open(&path, None).unwrap();
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

        let r =
            AssignmentRegistry::open(dir.path().join("registry.db"), json(&legacy, true)).unwrap();

        let configured: HashSet<ProfileId> = [ProfileId::new("public")].into_iter().collect();
        assert_eq!(r.unknown_profiles(&configured).get("default"), Some(&1));
    }
}
