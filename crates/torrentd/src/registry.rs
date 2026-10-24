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
//! with the configured profiles; the index's column is a cache of it, filled
//! in by `pool scan` and written by adoption and release. Where they disagree
//! the daemon's boot rewrites the column to this registry's profile, warning
//! with both values.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libtorrent_safe::InfoHash;
use parking_lot::Mutex;
use parking_lot::RwLock;
use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use thiserror::Error;
use torrentd_engine::profile::ProfileId;
use tracing::debug;
use tracing::info;
use tracing::warn;

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
    /// Bumped, under `inner`'s write lock, after every entry `inner` gains
    /// or loses. See [`Self::generation`].
    generation: AtomicU64,
    /// The one writer. Holding it across check-and-write is what makes an
    /// `assign` atomic against every other `assign` and `remove`; the lock
    /// order is always this, then `inner`.
    writer: Mutex<Connection>,
}

impl AssignmentRegistry {
    /// Open the database at `path` with nothing to import.
    ///
    /// For tests that start from a path of their own.
    ///
    /// # Panics
    ///
    /// If the database cannot be opened.
    #[cfg(test)]
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
            generation: AtomicU64::new(0),
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
            if !torrentd_engine::profile::ProfileConfig::is_valid_id(id) {
                *bad.entry(id.as_str()).or_insert(0) += 1;
            }
        }
        if let Some((id, count)) = bad.into_iter().next() {
            return Err(RegistryError::LegacyProfileId {
                read_from: source.to_path_buf(),
                written_to: target.to_path_buf(),
                id: id.to_string(),
                count,
                reason: torrentd_engine::profile::ID_CHARSET_RULE.to_string(),
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

    /// A counter that moves on every assignment added to or removed from the
    /// map, and never moves back. O(1).
    ///
    /// Two equal readings mean no assignment came or went in between, which
    /// [`Self::len`] cannot say: one remove and one assign leave the length
    /// as it was. The bump lands under the same write lock as the change, so
    /// a caller that reads the counter and then reads the map sees at least
    /// every change that counter reading counts.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Insert into the map and bump [`Self::generation`] under one lock.
    fn insert_entry(&self, ih: InfoHash, profile: ProfileId) {
        let mut map = self.inner.write();
        map.insert(ih, profile);
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Remove from the map, bumping [`Self::generation`] under the same lock
    /// where there was an entry to remove.
    fn remove_entry(&self, ih: &InfoHash) -> Option<ProfileId> {
        let mut map = self.inner.write();
        let prev = map.remove(ih);
        if prev.is_some() {
            self.generation.fetch_add(1, Ordering::Release);
        }
        prev
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
            if !torrentd_engine::profile::ProfileConfig::is_valid_id(&existing) {
                return Err(RegistryError::BadRow {
                    path: self.path.clone(),
                    infohash: hex,
                    id: existing,
                    reason: torrentd_engine::profile::ID_CHARSET_RULE.to_string(),
                });
            }
            let existing = ProfileId::new(existing);
            self.insert_entry(ih, existing.clone());
            if existing == profile {
                return Ok(Claim::AlreadyOurs);
            }
            return Err(RegistryError::Conflict {
                infohash: ih,
                existing,
            });
        }
        tx.commit().map_err(|e| self.db_err(e))?;
        self.insert_entry(ih, profile.clone());
        drop(conn);
        info!(
            target: "torrentd_engine::registry",
            infohash = %ih,
            profile_id = %profile,
            "assigned",
        );
        Ok(Claim::New)
    }

    /// Remove an assignment, returning the profile it named. No-op, returning
    /// `None`, if neither this process nor the database holds one.
    ///
    /// The database's row is deleted whether or not this process had loaded
    /// it: a row another process wrote after this one loaded the registry is
    /// still the assignment [`Self::assign`] answers with, so leaving it would
    /// keep the info-hash claimed after the remove said it was not. Such a
    /// row's profile is returned only if it is one `read_all` would have
    /// loaded.
    ///
    /// Like [`Self::assign`], persisted before it is visible: a write that
    /// fails leaves the assignment in place, so retrying the remove retries
    /// the write.
    pub fn remove(&self, ih: &InfoHash) -> Result<Option<ProfileId>, RegistryError> {
        let mut conn = self.writer.lock();
        let tx = conn.transaction().map_err(|e| self.db_err(e))?;
        let deleted: Option<String> = tx
            .query_row(
                "DELETE FROM assignment WHERE infohash = ?1 RETURNING profile_id",
                params![ih.to_hex()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| self.db_err(e))?;
        tx.commit().map_err(|e| self.db_err(e))?;
        let prev = self.remove_entry(ih).or_else(|| {
            deleted
                .filter(|id| torrentd_engine::profile::ProfileConfig::is_valid_id(id))
                .map(ProfileId::new)
        });
        let Some(prev) = prev else {
            return Ok(None);
        };
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
        // Lower-case only: `remove` deletes the row by `to_hex()`, so a row
        // spelled any other way would load at every boot and never go.
        let Some(ih) = torrentd_engine::resume_store::canonical_infohash(&hex) else {
            warn!(
                target: "torrentd_engine::registry",
                key = %hex,
                "skipping registry row whose infohash is not lower-case hex",
            );
            continue;
        };
        if !torrentd_engine::profile::ProfileConfig::is_valid_id(&id) {
            return Err(RegistryError::BadRow {
                path: path.to_path_buf(),
                infohash: hex,
                id,
                reason: torrentd_engine::profile::ID_CHARSET_RULE.to_string(),
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
mod tests;

#[cfg(test)]
mod props {
    use proptest::prelude::*;

    use super::*;

    #[derive(Clone, Debug)]
    enum Op {
        Assign(u8, u8),
        Remove(u8),
        Reopen,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0u8..5, 0u8..3).prop_map(|(t, p)| Op::Assign(t, p)),
            2 => (0u8..5).prop_map(Op::Remove),
            1 => Just(Op::Reopen),
        ]
    }

    fn profile(p: u8) -> ProfileId {
        ProfileId::new(["a", "b", "c"][usize::from(p)])
    }

    proptest! {
        // Each step is a durable database write; 64 runs of up to 40 keep
        // this within a few seconds.
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The registry is a map from info-hash to profile in which the
        /// first assignment wins: assigning a free info-hash claims it,
        /// assigning it to its own profile again changes nothing, and
        /// assigning it to another is refused naming the holder; a remove
        /// returns what it held. Every read (lookup, len, entries,
        /// for_profile) agrees with that map after every step, the
        /// generation moves exactly when an entry comes or goes, and
        /// reopening the database reads the same map back.
        #[test]
        fn the_registry_behaves_like_a_first_writer_wins_map(ops in prop::collection::vec(op(), 0..40)) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("assignments.db");
            let mut reg = AssignmentRegistry::new_empty(&path);
            let mut model: BTreeMap<u8, ProfileId> = BTreeMap::new();
            for op in ops {
                let before = reg.generation();
                let changed = match op {
                    Op::Assign(t, p) => {
                        let got = reg.assign(InfoHash([t; 20]), profile(p));
                        match model.get(&t) {
                            None => {
                                prop_assert!(matches!(got, Ok(Claim::New)), "{:?}: {:?}", op, got);
                                model.insert(t, profile(p));
                                true
                            }
                            Some(held) if *held == profile(p) => {
                                prop_assert!(matches!(got, Ok(Claim::AlreadyOurs)), "{:?}: {:?}", op, got);
                                false
                            }
                            Some(held) => {
                                let refused = matches!(&got, Err(RegistryError::Conflict { existing, .. }) if existing == held);
                                prop_assert!(refused, "{:?}: {:?}", op, got);
                                false
                            }
                        }
                    }
                    Op::Remove(t) => {
                        let got = reg.remove(&InfoHash([t; 20])).unwrap();
                        let held = model.remove(&t);
                        prop_assert_eq!(&got, &held, "{:?}", op);
                        held.is_some()
                    }
                    Op::Reopen => {
                        drop(reg);
                        reg = AssignmentRegistry::new_empty(&path);
                        false
                    }
                };
                if !matches!(op, Op::Reopen) {
                    prop_assert_eq!(reg.generation() > before, changed, "{:?}", op);
                }
                prop_assert_eq!(reg.len(), model.len());
                for t in 0u8..5 {
                    prop_assert_eq!(reg.lookup(&InfoHash([t; 20])), model.get(&t).cloned());
                }
                let mut expect: Vec<(InfoHash, ProfileId)> =
                    model.iter().map(|(t, p)| (InfoHash([*t; 20]), p.clone())).collect();
                expect.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()).then(a.0 .0.cmp(&b.0 .0)));
                prop_assert_eq!(reg.entries(), expect);
                for p in 0u8..3 {
                    let mut got: Vec<u8> = reg.for_profile(&profile(p)).iter().map(|ih| ih.0[0]).collect();
                    got.sort_unstable();
                    let want: Vec<u8> = model.iter().filter(|(_, q)| **q == profile(p)).map(|(t, _)| *t).collect();
                    prop_assert_eq!(got, want);
                }
            }
        }
    }
}
