//! SQLite-backed pool index.
//!
//! A managed root can hold millions of files, which is past what the daemon's
//! existing JSON-file conventions carry — and an API client needs to sort,
//! filter and paginate over that set without shipping all of it.
//! One transactional file serves the file index, the torrent library, adoption
//! state, and a copy of the torrent→profile mapping that lives in the
//! assignment registry, `registry.db` (once `profile_assignments.json`, and
//! before that `slot_assignments.json`).
//!
//! # `torrent.profile` is a cache, not the authority
//!
//! The assignment registry is the authority for which profile owns which
//! info-hash. It is what the daemon's resume scan writes, what every load is
//! gated on, and what the daemon refuses to boot against when it disagrees
//! with the configured profiles. This column is a copy of it, written by
//! `pool scan` — which an operator may never run — so it can be stale, and
//! nothing here may be read as overriding the file. Where the two disagree
//! the resume scan warns naming both values rather than silently preferring
//! one.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use tracing::info;
use tracing::warn;

use crate::model::AdoptionState;
use crate::model::DirRollup;
use crate::model::PlanRow;
use crate::model::PlanStep;
use crate::model::PlanStepRow;
use crate::model::PoolError;
use crate::model::PoolFile;
use crate::model::PoolTorrent;
use crate::model::TorrentFileRow;
use crate::model::VerifyQueueRow;

/// Bumped whenever the schema changes; `migrate` walks forward from whatever
/// the file reports. A file from the future is refused rather than guessed at.
const SCHEMA_VERSION: i64 = 7;

/// The version [`PoolStore::migrate_v6`] brings a file to.
const V6: i64 = 6;

/// v7 makes plan ids non-reusable: `plan.id` becomes `AUTOINCREMENT`.
///
/// Declared `INTEGER PRIMARY KEY` alone, SQLite hands out `max(id) + 1`, so
/// discarding the newest plan gave its id to the next one, and a delete
/// plan's trash directory is named after its id. SQLite cannot add
/// `AUTOINCREMENT` to a column in place, so the table is rebuilt and its rows
/// copied with their ids; `sqlite_sequence` starts at the highest id copied.
/// `plan_step` refers to `plan` by name, so it follows the rebuilt table.
/// Run with foreign keys off: dropping the old table with them on would
/// cascade-delete every step.
const SCHEMA_V7: &str = r#"
CREATE TABLE plan_v7 (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    applied_at INTEGER,
    -- draft | applying | applied | failed | cancelled
    status     TEXT    NOT NULL,
    spec       TEXT    NOT NULL
);
INSERT INTO plan_v7 (id, kind, created_at, applied_at, status, spec)
    SELECT id, kind, created_at, applied_at, status, spec FROM plan;
DROP TABLE plan;
ALTER TABLE plan_v7 RENAME TO plan;
CREATE INDEX plan_by_status ON plan(status);
"#;

/// The version [`PoolStore::migrate_v4`] brings a file to.
const V4: i64 = 4;

/// The version [`PoolStore::migrate_v5`] brings a file to.
const V5: i64 = 5;

/// v6 keeps the daemon's verify queue, so a restart re-drives it.
///
/// An adoption claims its info-hash in the assignment registry before it
/// queues the torrent, and the queue admits a bounded number at a time. Held
/// only in memory, a crash with items still waiting left each one's claim
/// with nothing behind it: no scan loaded the torrent, and adopting it again
/// was refused. A row is written when an item is queued and removed when the
/// queue adds it to a session or drops it.
///
/// `seq` is the queue order. The paths are the bytes of the `OsStr`, so a
/// path that is not UTF-8 comes back as it went in. `trackers` is a JSON
/// array of tiers. There is no foreign key to `torrent`: a rescan that drops
/// the library row must not take the queued item, and the claim behind it,
/// with it.
const SCHEMA_V6: &str = r#"
CREATE TABLE IF NOT EXISTS verify_queue (
    seq            INTEGER PRIMARY KEY,
    infohash       TEXT    NOT NULL UNIQUE,
    profile        TEXT    NOT NULL,
    torrent_path   BLOB    NOT NULL,
    save_path      BLOB    NOT NULL,
    owner_recorded INTEGER NOT NULL,
    trackers       TEXT    NOT NULL,
    enqueued_at    INTEGER NOT NULL
);
"#;

/// Rows the scan writes to the staging table per statement batch.
///
/// Bounds what a root walk holds in memory: a batch, not the root. Large
/// enough that the per-batch overhead vanishes next to the inserts.
pub const STAGE_BATCH: usize = 10_000;

/// v5 materialises the directory tree, so a listing reads one directory's
/// rows instead of every path under it.
///
/// - `file.parent` is the directory a file sits in (`""` at the top of the
///   root), indexed so a directory's files are one range.
/// - `dir` holds every directory that holds an indexed file, with the byte
///   accounting that depends only on the file index and the claim table.
/// - `dir_claim` holds, per directory, the bytes under it each torrent
///   claims. The adopted and matched figures are those rows joined to the
///   live `adoption` state, so adopting or verifying a torrent moves them
///   without rebuilding anything.
/// - `adoption(state, infohash)` lets `/v1/pool/torrents?state=` page in
///   infohash order without sorting.
///
/// `dir` and `dir_claim` are derived: [`PoolStore::rebuild_rollups`]
/// recomputes them from `file` and `claim`, which every scan and every match
/// does.
const SCHEMA_V5: &str = r#"
ALTER TABLE file ADD COLUMN parent TEXT NOT NULL DEFAULT '';
UPDATE file SET parent = rtrim(rtrim(rel_path, replace(rel_path, '/', '')), '/');
CREATE INDEX IF NOT EXISTS file_by_parent ON file(root_id, parent, rel_path);
CREATE INDEX IF NOT EXISTS adoption_by_state_infohash ON adoption(state, infohash);
"#;

/// The derived tables of v5.
const SCHEMA_V5_DERIVED: &str = r#"
CREATE TABLE IF NOT EXISTS dir (
    root_id      INTEGER NOT NULL REFERENCES root(id) ON DELETE CASCADE,
    path         TEXT    NOT NULL,
    -- NULL for the root directory itself, whose path is ''.
    parent       TEXT,
    bytes_total  INTEGER NOT NULL,
    files_total  INTEGER NOT NULL,
    bytes_orphan INTEGER NOT NULL,
    files_orphan INTEGER NOT NULL,
    PRIMARY KEY (root_id, path)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS dir_by_parent ON dir(root_id, parent, path);

CREATE TABLE IF NOT EXISTS dir_claim (
    root_id  INTEGER NOT NULL REFERENCES root(id) ON DELETE CASCADE,
    path     TEXT    NOT NULL,
    infohash TEXT    NOT NULL,
    bytes    INTEGER NOT NULL,
    PRIMARY KEY (root_id, path, infohash)
) WITHOUT ROWID;
"#;

/// The version [`PoolStore::migrate`] brings a file to; v4 and v5 are steps
/// on top of it.
const V3: i64 = 3;

/// v4 marks padding files and adds the index generation.
///
/// `pad_file` defaults to 0, so a torrent indexed before this step keeps
/// reading its padding entries as payload until the library is scanned again,
/// which rewrites every torrent's file rows. `pool_meta` holds the index
/// generation a destructive plan's confirm token is bound to.
const SCHEMA_V4: &str = r#"
ALTER TABLE torrent_file ADD COLUMN pad_file INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS pool_meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) WITHOUT ROWID;
"#;

/// The v3 index, less the journal: what a new file is created with.
const SCHEMA_V3: &str = r#"
CREATE TABLE root (
    id       INTEGER PRIMARY KEY,
    path     TEXT NOT NULL UNIQUE,
    enabled  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE file (
    root_id    INTEGER NOT NULL REFERENCES root(id) ON DELETE CASCADE,
    rel_path   TEXT    NOT NULL,
    size       INTEGER NOT NULL,
    mtime_ns   INTEGER NOT NULL,
    ino        INTEGER NOT NULL,
    dev        INTEGER NOT NULL,
    v2_root    BLOB,
    scanned_at INTEGER NOT NULL,
    PRIMARY KEY (root_id, rel_path)
) WITHOUT ROWID;

-- Matching anchors on file size before it ever touches a path, so this index
-- carries the candidate lookup for large libraries.
CREATE INDEX file_by_size ON file(size);
CREATE INDEX file_by_v2root ON file(v2_root) WHERE v2_root IS NOT NULL;

CREATE TABLE torrent (
    infohash      TEXT PRIMARY KEY,
    infohash_v1   TEXT,
    infohash_v2   TEXT,
    name          TEXT    NOT NULL,
    total_size    INTEGER NOT NULL,
    num_files     INTEGER NOT NULL,
    source_path   TEXT    NOT NULL,
    fastresume_path TEXT,
    declared_save_path TEXT,
    category      TEXT,
    tags          TEXT,
    profile       TEXT,
    added_at      INTEGER NOT NULL
);

CREATE INDEX torrent_by_profile ON torrent(profile) WHERE profile IS NOT NULL;

CREATE TABLE torrent_file (
    infohash    TEXT    NOT NULL REFERENCES torrent(infohash) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,
    rel_path    TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    pieces_root BLOB,
    PRIMARY KEY (infohash, idx)
) WITHOUT ROWID;

CREATE INDEX torrent_file_by_size ON torrent_file(size);

CREATE TABLE adoption (
    infohash    TEXT PRIMARY KEY REFERENCES torrent(infohash) ON DELETE CASCADE,
    state       TEXT    NOT NULL,
    root_id     INTEGER REFERENCES root(id) ON DELETE SET NULL,
    -- Directory under `root_id` that the torrent's relative paths hang off.
    base_rel    TEXT,
    verified_at INTEGER,
    drift_at    INTEGER,
    last_error  TEXT
);

CREATE INDEX adoption_by_state ON adoption(state);

-- Which file each torrent claims. Written by the matcher; read to detect
-- overlap and to compute directory rollups.
CREATE TABLE claim (
    root_id  INTEGER NOT NULL,
    rel_path TEXT    NOT NULL,
    infohash TEXT    NOT NULL REFERENCES torrent(infohash) ON DELETE CASCADE,
    PRIMARY KEY (root_id, rel_path, infohash)
) WITHOUT ROWID;

CREATE INDEX claim_by_torrent ON claim(infohash);
"#;

/// The mutation journal, which v2 added: part of a new file, and the step a
/// v1 file takes. v7 rebuilds `plan` with an `AUTOINCREMENT` id
/// ([`SCHEMA_V7`]); a new file takes that step like any other.
const SCHEMA_JOURNAL: &str = r#"
CREATE TABLE plan (
    id         INTEGER PRIMARY KEY,
    kind       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    applied_at INTEGER,
    -- draft | applying | applied | failed | cancelled
    status     TEXT    NOT NULL,
    spec       TEXT    NOT NULL
);

CREATE INDEX plan_by_status ON plan(status);

-- Written before each step is attempted. A crash mid-apply leaves the plan
-- `applying` with a known last-completed step, which startup re-drives.
CREATE TABLE plan_step (
    plan_id INTEGER NOT NULL REFERENCES plan(id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    op      TEXT    NOT NULL,
    src     TEXT    NOT NULL,
    dst     TEXT,
    -- pending | done | failed | skipped
    status  TEXT    NOT NULL,
    error   TEXT,
    PRIMARY KEY (plan_id, seq)
) WITHOUT ROWID;
"#;

/// The v2 → v3 step: v1 and v2 named the torrent→account column `slot`.
/// SQLite would carry `torrent_by_slot` over to the renamed column under its
/// old name, so it is dropped and recreated.
const SCHEMA_V2_TO_V3: &str = r#"
ALTER TABLE torrent RENAME COLUMN slot TO profile;

DROP INDEX torrent_by_slot;

CREATE INDEX torrent_by_profile ON torrent(profile) WHERE profile IS NOT NULL;
"#;

/// An unclaimed file from [`PoolStore::orphan_files_sized`]: its root-relative
/// path, indexed size, and indexed `(dev, ino)`.
pub type SizedOrphan = (String, u64, (u64, u64));

pub struct PoolStore {
    conn: Connection,
    /// Nesting depth for [`PoolStore::in_transaction`]; 0 means autocommit.
    tx_depth: u32,
    /// This writer's advisory lock on the index's `.lock` file, held for the
    /// life of the store: shared from [`PoolStore::open`], exclusive from
    /// [`PoolStore::open_exclusive`]. `None` for an in-memory store or a
    /// read-only connection, which take no lock.
    _hold: Option<std::fs::File>,
}

/// The advisory lock file beside the index at `db`: `pool.db.lock` for
/// `pool.db`.
///
/// Not the database file itself. SQLite takes its own byte-range locks on
/// that, and where `flock` is emulated over `fcntl` (NFS) a whole-file lock
/// there would collide with them.
fn lock_path(db: &Path) -> PathBuf {
    let mut name = db.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    db.with_file_name(name)
}

/// Take the advisory lock that says which processes hold the index at `db`
/// for writing, without waiting: [`PoolError::Busy`] when it is held in a
/// mode that excludes this one.
///
/// `None` where the lock file neither exists nor can be created, in a
/// directory this process may not write: no process of the same user can
/// hold a lock there either, so there is nothing to exclude. `None` too, with
/// a warning, where it exists but this process may not even read it: a file
/// another user left unreadable must not keep the daemon from booting.
fn hold_index(db: &Path, exclusive: bool) -> Result<Option<std::fs::File>, PoolError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;
    let path = lock_path(db);
    // The lock needs an open file, not a writable one. A `.lock` file another
    // user created (a CLI run as root before the daemon's user) is still
    // lockable read-only.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => {
            // Readable by every user whatever the umask, so a root CLI run
            // under umask 077 leaves a file the daemon's user can still
            // open read-only and lock. Best effort: only the owner may
            // chmod, and an owner who can open it for writing already can.
            if let Ok(meta) = file.metadata() {
                let mode = meta.permissions().mode();
                if mode & 0o044 != 0o044 {
                    let _ = file
                        .set_permissions(std::fs::Permissions::from_mode((mode | 0o044) & 0o7777));
                }
            }
            file
        }
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            match std::fs::File::open(&path) {
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "cannot open the pool index lock file even read-only; \
                         opening the index without the lock that keeps a CLI \
                         `pool scan` off it",
                    );
                    return Ok(None);
                }
                other => other?,
            }
        }
        Err(e) => return Err(e.into()),
    };
    let taken = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    match taken {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(PoolError::Busy),
        Err(std::fs::TryLockError::Error(e)) => Err(PoolError::Io(e)),
    }
}

impl std::fmt::Debug for PoolStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolStore").finish_non_exhaustive()
    }
}

impl PoolStore {
    /// Open (creating if needed) the pool database at `path` as one of any
    /// number of concurrent writers: the daemon, or a short CLI command such
    /// as `pool check`.
    ///
    /// Holds a shared lock on `pool.db.lock` for the life of the store, which
    /// is what makes [`PoolStore::open_exclusive`] refuse while the daemon
    /// runs. [`PoolError::Busy`] while an exclusive holder has it.
    pub fn open(path: &Path) -> Result<Self, PoolError> {
        Self::open_held(path, false)
    }

    /// Open the pool database at `path` as its only writer, for a CLI
    /// `pool scan`.
    ///
    /// That scan is one write transaction for its whole duration, an hour on
    /// a large pool, and SQLite refuses every other writer at once for all of
    /// it. Beside a running daemon that is every daemon write: a plan's step
    /// journal, a verification's verdict, a released owner. So it refuses to
    /// start, with [`PoolError::Busy`], while any other [`PoolStore::open`]
    /// holds the index, and while it runs no other one can open it.
    pub fn open_exclusive(path: &Path) -> Result<Self, PoolError> {
        Self::open_held(path, true)
    }

    fn open_held(path: &Path, exclusive: bool) -> Result<Self, PoolError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Before the connection, so an exclusive holder also keeps a second
        // process from migrating the schema under it.
        let hold = hold_index(path, exclusive)?;
        let conn = Connection::open(path)?;
        let mut store = Self::from_conn(conn)?;
        store._hold = hold;
        Ok(store)
    }

    /// In-memory store, for tests.
    pub fn open_in_memory() -> Result<Self, PoolError> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> Result<Self, PoolError> {
        // WAL keeps the scanner's long write transactions from blocking the
        // HTTP layer's reads: a reader sees the pre-transaction snapshot for
        // the whole duration of a rescan rather than a half-rebuilt index.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // FULL, not NORMAL. The file index really is reconstructible by
        // rescanning — but the `plan` / `plan_step` mutation journal lives in
        // this same database and is not. Under NORMAL a power loss can lose the
        // last commits, which would resurrect a completed destructive step as
        // `pending` and re-drive it at startup. An fsync per commit is cheap
        // next to that.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // A scan takes the database's write lock for its whole duration (see
        // `in_transaction`). A second writer that meets it — a `pool check`
        // beside the daemon's scan — must fail fast with SQLITE_BUSY so the
        // caller can say so, not block for hours. The CLI `pool scan` cannot
        // be that scan beside the daemon: `open_exclusive` refuses it first.
        conn.busy_timeout(std::time::Duration::from_millis(0))?;
        let mut store = Self {
            conn,
            tx_depth: 0,
            _hold: None,
        };
        store.migrate()?;
        store.migrate_v4()?;
        store.migrate_v5()?;
        store.migrate_v6()?;
        store.migrate_v7()?;
        Ok(store)
    }

    /// Open a second, read-only connection to an index another
    /// [`PoolStore::open`] has already created and migrated.
    ///
    /// The daemon's writer connection is held for the whole of a scan, which
    /// on a large pool is an hour. Under WAL a reader on its own connection
    /// sees the last committed index throughout — the previous one in full,
    /// never a half-rebuilt one — so every read the API serves goes through
    /// this connection and none of them waits for the scan. It never
    /// migrates and cannot write: `query_only` refuses any statement that
    /// would.
    pub fn open_read_only(path: &Path) -> Result<Self, PoolError> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            path,
            // Read-write at the file level: SQLite needs to write the WAL index
            // (`-shm`) to read a WAL database. `query_only` is what forbids
            // writes to the index itself.
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.pragma_update(None, "query_only", "ON")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // A reader under WAL is blocked only briefly — a checkpoint, or WAL
        // recovery after a crash — and waiting those out is the right answer
        // where the writer's zero is not.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let found: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found != SCHEMA_VERSION {
            return Err(PoolError::SchemaVersion {
                found,
                expected: SCHEMA_VERSION,
            });
        }
        Ok(Self {
            conn,
            tx_depth: 0,
            _hold: None,
        })
    }

    /// Run `f` inside one read transaction, so every query it makes sees the
    /// same committed index: a listing that reads a page and then each row's
    /// accounting must not straddle a scan's commit.
    ///
    /// `BEGIN DEFERRED` takes no lock and reads nothing, so it fails only on
    /// a connection that is already unusable; `f` then runs without the
    /// snapshot and its own statements report the failure.
    pub fn read_snapshot<T>(&self, f: impl FnOnce(&Self) -> T) -> T {
        if self.tx_depth > 0
            || !self.conn.is_autocommit()
            || self.conn.execute_batch("BEGIN DEFERRED").is_err()
        {
            // Inside a transaction already, which is a snapshot already.
            return f(self);
        }
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        // A read transaction has nothing to keep; ending it releases the
        // snapshot so the WAL can be checkpointed past it.
        let _ = self.conn.execute_batch("ROLLBACK");
        match out {
            Ok(v) => v,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// Run `f` with the whole store inside one write transaction.
    ///
    /// Every multi-statement rebuild must go through this. The claim table is
    /// what proves a file is protected, and a rebuild that clears it outside a
    /// transaction makes every file in every root read as an orphan until the
    /// rebuild finishes — which is long enough for a concurrent delete plan to
    /// enumerate the entire pool. `BEGIN IMMEDIATE` also takes SQLite's own
    /// cross-process write lock, so a second scanner (the CLI racing the
    /// daemon) is refused rather than interleaved.
    ///
    /// Re-entrant: a nested call becomes a savepoint, so callers can compose
    /// without knowing whether they are already inside one.
    pub fn in_transaction<T, E>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<PoolError>,
    {
        let depth = self.tx_depth;
        let (begin, commit, rollback) = if depth == 0 {
            (
                "BEGIN IMMEDIATE".to_string(),
                "COMMIT".to_string(),
                "ROLLBACK".to_string(),
            )
        } else {
            let name = format!("pool_tx_{depth}");
            (
                format!("SAVEPOINT {name}"),
                format!("RELEASE {name}"),
                format!("ROLLBACK TO {name}; RELEASE {name}"),
            )
        };
        self.conn.execute_batch(&begin).map_err(|e| {
            E::from({
                if matches!(
                    e.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) {
                    PoolError::Busy
                } else {
                    PoolError::Sqlite(e)
                }
            })
        })?;
        self.tx_depth = depth + 1;
        // Catch an unwind from `f`. Without this a panic anywhere inside a
        // transaction leaves the connection mid-transaction with `tx_depth`
        // one too high: the rollback never runs, every later `in_transaction`
        // takes the savepoint branch believing it is nested, and the open
        // write transaction keeps SQLite's write lock for the life of the
        // process. No torrentd HTTP operation opts into kynos's
        // `catch_panics` boundary, so an HTTP handler is enough to get there. Roll back, restore the depth, then re-raise.
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        let out = match out {
            Ok(v) => v,
            Err(panic) => {
                let _ = self.conn.execute_batch(&rollback);
                self.tx_depth = depth;
                std::panic::resume_unwind(panic);
            }
        };
        match out {
            Ok(v) => match self.conn.execute_batch(&commit) {
                Ok(()) => {
                    self.tx_depth = depth;
                    Ok(v)
                }
                Err(e) => {
                    // A COMMIT can fail — SQLITE_FULL, SQLITE_IOERR, a WAL
                    // snapshot conflict — and SQLite leaves the transaction
                    // *open* when it does. Restoring the depth before this
                    // point would have left the counter saying 0 while a
                    // transaction was still live, after which every later
                    // `BEGIN IMMEDIATE` fails with "cannot start a
                    // transaction within a transaction" for the life of the
                    // process. Roll back explicitly, then restore.
                    let _ = self.conn.execute_batch(&rollback);
                    self.tx_depth = depth;
                    Err(E::from(PoolError::Sqlite(e)))
                }
            },
            Err(e) => {
                // Report the original failure; a rollback that itself fails
                // means the connection is already unusable either way.
                let _ = self.conn.execute_batch(&rollback);
                self.tx_depth = depth;
                Err(e)
            }
        }
    }

    /// Suffix of the copy [`PoolStore::migrate`] leaves before the v2 → v3
    /// rename. Named in `docs/running.md`'s rollback note.
    pub const PRE_V3_BACKUP_SUFFIX: &'static str = ".pre-v3.bak";

    /// Copy an existing index aside before the v2 → v3 rename, which nothing
    /// can undo, in a file that also holds the journal a rescan cannot
    /// rebuild. `VACUUM INTO`, because under WAL the main file alone is not a
    /// complete database.
    ///
    /// Whatever is already at the backup path (by `symlink_metadata`, so a
    /// dangling symlink counts and is never written through) must be a copy
    /// of a pool index, or the migration stops: see
    /// [`PoolStore::rollback_copy_of_an_index`]. A real copy is kept until
    /// the migration commits, because if it fails that copy is the one that
    /// predates the run. A fresh copy is taken beside it as `<backup>.new`,
    /// and that `(fresh, existing)` pair is returned for
    /// [`PoolStore::promote_fresh_backup`] to settle.
    fn backup_before_v3(&self) -> Result<Option<(String, String)>, PoolError> {
        // No path: an in-memory store, which has nothing to roll back to.
        let Some(path) = self.conn.path().filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        let backup = format!("{path}{}", Self::PRE_V3_BACKUP_SUFFIX);
        let vacuum_into = |to: &str| {
            self.conn
                .execute("VACUUM INTO ?1", params![to])
                .map_err(|e| PoolError::BackupFailed {
                    path: to.to_string(),
                    reason: e.to_string(),
                })
        };
        if Path::new(&backup).symlink_metadata().is_ok() {
            if let Err(reason) = Self::rollback_copy_of_an_index(&backup, path) {
                return Err(PoolError::BackupNotARollbackCopy {
                    path: backup,
                    reason,
                });
            }
            let fresh = format!("{backup}.new");
            // A leftover from a run that died before settling it.
            // `remove_file` removes a symlink itself, never its target.
            if Path::new(&fresh).symlink_metadata().is_ok() {
                std::fs::remove_file(&fresh).map_err(|e| PoolError::BackupFailed {
                    path: fresh.clone(),
                    reason: e.to_string(),
                })?;
            }
            vacuum_into(&fresh)?;
            info!(
                target: "torrentd_pool::store",
                backup = %backup,
                fresh = %fresh,
                "pool schema v3 backup already exists; took a fresh copy beside it, which \
                 replaces it once the migration commits",
            );
            return Ok(Some((fresh, backup)));
        }
        vacuum_into(&backup)?;
        info!(
            target: "torrentd_pool::store",
            backup = %backup,
            "pool database copied aside before the v3 schema migration",
        );
        Ok(None)
    }

    /// Settle a fresh copy [`PoolStore::backup_before_v3`] took beside an
    /// existing one: after a commit it replaces the older copy; after a
    /// failure it is discarded, being a copy of the index that failed.
    /// Neither outcome fails the open; a copy that cannot be settled is
    /// reported for the operator to settle by hand.
    fn promote_fresh_backup(pair: Option<(String, String)>, committed: bool) {
        let Some((fresh, backup)) = pair else {
            return;
        };
        if committed {
            match std::fs::rename(&fresh, &backup) {
                Ok(()) => info!(
                    target: "torrentd_pool::store",
                    backup = %backup,
                    "replaced the earlier pre-v3 backup with the copy taken before this migration",
                ),
                Err(e) => warn!(
                    target: "torrentd_pool::store",
                    backup = %backup,
                    fresh = %fresh,
                    error.cause = %e,
                    "the migration committed but its fresh pre-v3 copy could not replace the \
                     earlier one; the fresh copy is the rollback for this migration — move it \
                     over the earlier one by hand",
                ),
            }
        } else if let Err(e) = std::fs::remove_file(&fresh) {
            warn!(
                target: "torrentd_pool::store",
                fresh = %fresh,
                error.cause = %e,
                "could not discard the fresh pre-v3 copy of an index whose migration failed; \
                 it is a copy of that same index and not a rollback — delete it by hand",
            );
        }
    }

    /// Whether what is at `path` can be a rollback copy of the index at
    /// `index`, or the reason it cannot: it must not resolve to the index
    /// itself, must report a pool schema version this build understands, and
    /// must carry the `root` and `torrent` tables every version has. Opened
    /// read-only, so a dangling symlink fails to open rather than being
    /// created.
    fn rollback_copy_of_an_index(path: &str, index: &str) -> Result<(), String> {
        use rusqlite::OpenFlags;
        if let (Ok(a), Ok(b)) = (std::fs::canonicalize(path), std::fs::canonicalize(index)) {
            if a == b {
                return Err("it resolves to the pool index itself".to_string());
            }
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if !(1..=SCHEMA_VERSION).contains(&version) {
            return Err(format!(
                "it reports pool schema version {version}, and a copy of this index reports \
                 1 to {SCHEMA_VERSION}"
            ));
        }
        for table in ["root", "torrent"] {
            let present: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            if present == 0 {
                return Err(format!(
                    "it has no {table} table, so it is not a copy of a pool index"
                ));
            }
        }
        Ok(())
    }

    /// Run one schema step and the `user_version` write it ends at in one
    /// transaction, so the version and the schema never disagree: without
    /// one, `execute_batch` commits statement by statement.
    ///
    /// A failure is reported as [`PoolError::MigrationFailed`], naming the
    /// file and the step: `startup.rs` opens the pool under
    /// `Restart=on-failure`, so this is all the operator sees.
    fn step(
        &mut self,
        from: i64,
        to: i64,
        f: impl FnOnce(&mut Self) -> Result<(), PoolError>,
    ) -> Result<(), PoolError> {
        let stepped = self.in_transaction(|st| -> Result<(), PoolError> {
            f(st)?;
            st.conn.pragma_update(None, "user_version", to)?;
            Ok(())
        });
        match stepped {
            Ok(()) => {
                info!(
                    target: "torrentd_pool::store",
                    from_version = from,
                    to_version = to,
                    "pool schema migrated",
                );
                Ok(())
            }
            Err(PoolError::Busy) => Err(PoolError::Busy),
            Err(e) => Err(PoolError::MigrationFailed {
                path: self
                    .conn
                    .path()
                    .filter(|p| !p.is_empty())
                    .unwrap_or("<in-memory>")
                    .to_string(),
                from,
                to,
                reason: e.to_string(),
            }),
        }
    }

    /// Bring the file to v3: a new file is created there, and a v1 or v2 file
    /// takes the journal and the rename.
    fn migrate(&mut self) -> Result<(), PoolError> {
        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found > SCHEMA_VERSION {
            return Err(PoolError::SchemaVersion {
                found,
                expected: SCHEMA_VERSION,
            });
        }
        if found >= V3 {
            return Ok(());
        }
        // Outside the transaction, which VACUUM cannot run in; and only for a
        // file that already exists.
        let fresh_backup = if found >= 1 {
            self.backup_before_v3()?
        } else {
            None
        };
        let stepped = self.step(found, V3, |st| {
            if found == 0 {
                st.conn.execute_batch(SCHEMA_V3)?;
            }
            if found <= 1 {
                st.conn.execute_batch(SCHEMA_JOURNAL)?;
            }
            if found >= 1 {
                st.conn.execute_batch(SCHEMA_V2_TO_V3)?;
            }
            Ok(())
        });
        Self::promote_fresh_backup(fresh_backup, stepped.is_ok());
        stepped
    }

    /// Step a v3 file to v4.
    fn migrate_v4(&mut self) -> Result<(), PoolError> {
        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found >= V4 {
            return Ok(());
        }
        self.step(found, V4, |st| Ok(st.conn.execute_batch(SCHEMA_V4)?))
    }

    /// Step a v4 file to v5: the materialised tree, built from the file and
    /// claim tables the file already holds.
    fn migrate_v5(&mut self) -> Result<(), PoolError> {
        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found >= V5 {
            return Ok(());
        }
        self.step(found, V5, |st| {
            st.conn.execute_batch(SCHEMA_V5)?;
            st.conn.execute_batch(SCHEMA_V5_DERIVED)?;
            st.rebuild_all_rollups()
        })
    }

    /// Step a v5 file to v6: the persisted verify queue, empty.
    fn migrate_v6(&mut self) -> Result<(), PoolError> {
        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found >= V6 {
            return Ok(());
        }
        self.step(found, V6, |st| Ok(st.conn.execute_batch(SCHEMA_V6)?))
    }

    /// Step a v6 file to v7: `plan.id` becomes `AUTOINCREMENT`, so a
    /// discarded plan's id is never handed out again.
    ///
    /// `PRAGMA foreign_keys` is a no-op inside a transaction, so it is turned
    /// off around the step rather than in it, and turned back on whatever the
    /// step's outcome. `foreign_key_check` runs before the commit, so a
    /// rebuild that left a step without its plan rolls back instead.
    fn migrate_v7(&mut self) -> Result<(), PoolError> {
        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found >= SCHEMA_VERSION {
            return Ok(());
        }
        self.conn.pragma_update(None, "foreign_keys", "OFF")?;
        let stepped = self.step(found, SCHEMA_VERSION, |st| {
            st.conn.execute_batch(SCHEMA_V7)?;
            let dangling: i64 = st.conn.query_row(
                "SELECT count(*) FROM pragma_foreign_key_check('plan_step')",
                [],
                |r| r.get(0),
            )?;
            if dangling != 0 {
                return Err(PoolError::Io(std::io::Error::other(format!(
                    "{dangling} plan steps would be left without their plan by rebuilding the \
                     plan table"
                ))));
            }
            Ok(())
        });
        let restored = self.conn.pragma_update(None, "foreign_keys", "ON");
        stepped?;
        Ok(restored?)
    }

    // -- verify queue ------------------------------------------------------

    /// Record an adoption the verify queue now holds, at the back of the
    /// queue. An info-hash already recorded keeps its place and takes the new
    /// row's values.
    pub fn enqueue_verify(&self, row: &VerifyQueueRow) -> Result<(), PoolError> {
        use std::os::unix::ffi::OsStrExt;
        let trackers = serde_json::to_string(&row.trackers)
            .map_err(|e| PoolError::Io(std::io::Error::other(e)))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn.execute(
            "INSERT INTO verify_queue
                 (infohash, profile, torrent_path, save_path, owner_recorded, trackers, enqueued_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(infohash) DO UPDATE SET
                 profile = excluded.profile,
                 torrent_path = excluded.torrent_path,
                 save_path = excluded.save_path,
                 owner_recorded = excluded.owner_recorded,
                 trackers = excluded.trackers",
            params![
                row.infohash,
                row.profile,
                row.torrent_path.as_os_str().as_bytes(),
                row.save_path.as_os_str().as_bytes(),
                row.owner_recorded,
                trackers,
                now,
            ],
        )?;
        Ok(())
    }

    /// Forget a queued adoption: the queue added it to a session or dropped
    /// it. Forgetting one that is not recorded is not an error.
    pub fn dequeue_verify(&self, infohash: &str) -> Result<(), PoolError> {
        self.conn.execute(
            "DELETE FROM verify_queue WHERE infohash = ?1",
            params![infohash],
        )?;
        Ok(())
    }

    /// Every queued adoption, in queue order.
    pub fn verify_queue(&self) -> Result<Vec<VerifyQueueRow>, PoolError> {
        use std::os::unix::ffi::OsStrExt;
        let mut st = self.conn.prepare(
            "SELECT infohash, profile, torrent_path, save_path, owner_recorded, trackers
             FROM verify_queue ORDER BY seq",
        )?;
        let rows = st.query_map([], |r| {
            let torrent_path: Vec<u8> = r.get(2)?;
            let save_path: Vec<u8> = r.get(3)?;
            let trackers: String = r.get(5)?;
            let trackers = serde_json::from_str(&trackers).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, e.into())
            })?;
            Ok(VerifyQueueRow {
                infohash: r.get(0)?,
                profile: r.get(1)?,
                torrent_path: PathBuf::from(std::ffi::OsStr::from_bytes(&torrent_path)),
                save_path: PathBuf::from(std::ffi::OsStr::from_bytes(&save_path)),
                owner_recorded: r.get(4)?,
                trackers,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The index generation: bumped by every match, so anything bound to it
    /// — a destructive plan's confirm token — stops matching once the index
    /// it was computed from has been rebuilt.
    pub fn index_generation(&self) -> Result<i64, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM pool_meta WHERE key = 'index_generation'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    pub(crate) fn bump_index_generation(&self) -> Result<(), PoolError> {
        self.conn.execute(
            "INSERT INTO pool_meta(key, value) VALUES ('index_generation', 1)
             ON CONFLICT(key) DO UPDATE SET value = value + 1",
            [],
        )?;
        Ok(())
    }

    // -- roots -------------------------------------------------------------

    /// Register a managed root, returning its id. Idempotent.
    pub fn upsert_root(&self, path: &Path) -> Result<i64, PoolError> {
        let p = path.to_string_lossy();
        self.conn.execute(
            "INSERT INTO root(path, enabled) VALUES (?1, 1)
             ON CONFLICT(path) DO UPDATE SET enabled = 1",
            params![p],
        )?;
        let id: i64 =
            self.conn
                .query_row("SELECT id FROM root WHERE path = ?1", params![p], |r| {
                    r.get(0)
                })?;
        Ok(id)
    }

    /// Forget every root not in `keep`: its row, its file index (by cascade)
    /// and the claims made against it. Returns how many were dropped.
    ///
    /// A root removed from the config otherwise stayed in the index for good —
    /// its files still listed, its claims still "protecting" bytes the daemon
    /// no longer manages, and every torrent once matched there still placed
    /// on a root nothing resolves.
    pub fn retain_roots(&mut self, keep: &[PathBuf]) -> Result<usize, PoolError> {
        let keep: std::collections::HashSet<String> = keep
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let gone: Vec<(i64, String)> = {
            let mut st = self.conn.prepare("SELECT id, path FROM root")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<Vec<(i64, String)>, _>>()?
                .into_iter()
                .filter(|(_, p)| !keep.contains(p))
                .collect()
        };
        if gone.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.savepoint()?;
        for (id, path) in &gone {
            tx.execute("DELETE FROM claim WHERE root_id = ?1", params![id])?;
            tx.execute("DELETE FROM root WHERE id = ?1", params![id])?;
            info!(
                target: "torrentd_pool::store",
                root = %path,
                "root is no longer configured; dropped from the index",
            );
        }
        tx.commit()?;
        Ok(gone.len())
    }

    /// Drop every library torrent not in `seen`, unless it is `adopted` or
    /// `drifted`, or in `loaded`. Returns how many went.
    ///
    /// A `.torrent` deleted from the library otherwise stayed in the index
    /// for good, and its claims kept protecting bytes no torrent wants. A
    /// torrent a session serves is kept whatever its state: its claims are
    /// what keep a delete plan off its payload, and a loaded torrent with no
    /// claims makes every delete plan refuse to apply. `adopted` and
    /// `drifted` are kept even where the caller cannot say what is loaded,
    /// because only a torrent that was adopted reaches either. `loaded` is
    /// hex info-hashes, as the index keys them.
    pub fn retain_torrents(
        &mut self,
        seen: &std::collections::HashSet<String>,
        loaded: &std::collections::HashSet<String>,
    ) -> Result<usize, PoolError> {
        let gone: Vec<String> = self
            .torrents()?
            .into_iter()
            .map(|t| t.infohash)
            .filter(|ih| !seen.contains(ih) && !loaded.contains(ih))
            .collect();
        let mut dropped = 0;
        let tx = self.conn.savepoint()?;
        for ih in gone {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM adoption WHERE infohash = ?1",
                    params![ih],
                    |r| r.get(0),
                )
                .optional()?;
            if matches!(
                state.as_deref().and_then(AdoptionState::parse),
                Some(AdoptionState::Adopted | AdoptionState::Drifted)
            ) {
                warn!(
                    target: "torrentd_pool::store",
                    infohash = %ih,
                    "an adopted torrent's .torrent left the library; keeping it in the index",
                );
                continue;
            }
            tx.execute("DELETE FROM torrent WHERE infohash = ?1", params![ih])?;
            dropped += 1;
        }
        tx.commit()?;
        Ok(dropped)
    }

    pub fn roots(&self) -> Result<Vec<(i64, PathBuf)>, PoolError> {
        let mut st = self
            .conn
            .prepare("SELECT id, path FROM root WHERE enabled = 1 ORDER BY path")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, PathBuf::from(r.get::<_, String>(1)?)))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn root_id(&self, path: &Path) -> Result<i64, PoolError> {
        self.conn
            .query_row(
                "SELECT id FROM root WHERE path = ?1",
                params![path.to_string_lossy()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| PoolError::UnknownRoot(path.to_path_buf()))
    }

    // -- files -------------------------------------------------------------

    /// Replace the file index for one root, inside a single transaction.
    ///
    /// Taken whole rather than incrementally because a partial index is worse
    /// than a stale one: the matcher would read absent files as deleted and
    /// mark healthy torrents `Missing`.
    pub fn replace_root_files(
        &mut self,
        root_id: i64,
        files: &[PoolFile],
        scanned_at: i64,
    ) -> Result<(), PoolError> {
        self.begin_staging()?;
        for batch in files.chunks(STAGE_BATCH) {
            self.stage_files(batch)?;
        }
        self.swap_staged_root(root_id, scanned_at)
    }

    /// Empty the staging table a root walk writes into, creating it on first
    /// use.
    ///
    /// The table is `TEMP`: private to this connection, never in the index
    /// file, and gone with the connection, so a walk that dies half way
    /// leaves nothing a reader or the next open could mistake for the index.
    pub fn begin_staging(&self) -> Result<(), PoolError> {
        self.conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS file_staging (
                 rel_path TEXT    PRIMARY KEY,
                 parent   TEXT    NOT NULL,
                 size     INTEGER NOT NULL,
                 mtime_ns INTEGER NOT NULL,
                 ino      INTEGER NOT NULL,
                 dev      INTEGER NOT NULL,
                 v2_root  BLOB
             ) WITHOUT ROWID;
             DELETE FROM temp.file_staging;",
        )?;
        Ok(())
    }

    /// Append one batch of a root walk to the staging table.
    ///
    /// Each batch is one savepoint, so its inserts share a journal commit
    /// rather than paying one each outside a transaction.
    pub fn stage_files(&mut self, files: &[PoolFile]) -> Result<(), PoolError> {
        let tx = self.conn.savepoint()?;
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO temp.file_staging(rel_path, parent, size, mtime_ns, ino, dev, v2_root)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for f in files {
                ins.execute(params![
                    f.rel_path,
                    parent_of(&f.rel_path),
                    f.size as i64,
                    f.mtime_ns,
                    f.ino as i64,
                    f.dev as i64,
                    f.v2_root.map(|r| r.to_vec()),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Replace `root_id`'s file index with what is staged, and rebuild its
    /// rollups, as one savepoint.
    ///
    /// Taken whole rather than incrementally because a partial index is worse
    /// than a stale one: the matcher would read absent files as deleted and
    /// mark healthy torrents `Missing`.
    pub fn swap_staged_root(&mut self, root_id: i64, scanned_at: i64) -> Result<(), PoolError> {
        self.in_transaction(|st| -> Result<(), PoolError> {
            st.conn
                .execute("DELETE FROM file WHERE root_id = ?1", params![root_id])?;
            st.conn.execute(
                "INSERT INTO file(root_id, rel_path, size, mtime_ns, ino, dev, v2_root, scanned_at, parent)
                 SELECT ?1, rel_path, size, mtime_ns, ino, dev, v2_root, ?2, parent
                 FROM temp.file_staging ORDER BY rel_path",
                params![root_id, scanned_at],
            )?;
            st.conn.execute_batch("DELETE FROM temp.file_staging")?;
            st.rebuild_rollups(root_id)
        })
    }

    pub fn file(&self, root_id: i64, rel_path: &str) -> Result<Option<PoolFile>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT root_id, rel_path, size, mtime_ns, ino, dev, v2_root
                 FROM file WHERE root_id = ?1 AND rel_path = ?2",
                params![root_id, rel_path],
                row_to_file,
            )
            .optional()?)
    }

    /// Files indexed across every root, from each root's materialised total
    /// rather than a count of the file table.
    pub fn file_count(&self) -> Result<u64, PoolError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(SUM(d.files_total), 0)
             FROM root r JOIN dir d ON d.root_id = r.id AND d.path = ''",
            [],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    /// Every file in a root whose size matches, used as the matcher's anchor
    /// lookup. Returns `(rel_path, size)`.
    pub fn files_with_size(&self, root_id: i64, size: u64) -> Result<Vec<String>, PoolError> {
        let mut st = self
            .conn
            .prepare("SELECT rel_path FROM file WHERE root_id = ?1 AND size = ?2")?;
        let rows = st.query_map(params![root_id, size as i64], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    // -- torrents ----------------------------------------------------------

    pub fn upsert_torrent(&self, t: &PoolTorrent, added_at: i64) -> Result<(), PoolError> {
        self.conn.execute(
            "INSERT INTO torrent(infohash, infohash_v1, infohash_v2, name, total_size,
                                 num_files, source_path, fastresume_path, declared_save_path,
                                 category, tags, profile, added_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(infohash) DO UPDATE SET
                infohash_v1        = excluded.infohash_v1,
                infohash_v2        = excluded.infohash_v2,
                name               = excluded.name,
                total_size         = excluded.total_size,
                num_files          = excluded.num_files,
                source_path        = excluded.source_path,
                fastresume_path    = excluded.fastresume_path,
                declared_save_path = excluded.declared_save_path,
                category           = excluded.category,
                tags               = excluded.tags,
                -- A rescan must never clear an assignment the daemon made.
                profile               = COALESCE(excluded.profile, torrent.profile)",
            params![
                t.infohash,
                t.infohash_v1,
                t.infohash_v2,
                t.name,
                t.total_size as i64,
                t.num_files as i64,
                t.source_path.to_string_lossy(),
                t.fastresume_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned()),
                t.declared_save_path,
                t.category,
                if t.tags.is_empty() {
                    None
                } else {
                    Some(t.tags.join(","))
                },
                t.profile,
                added_at,
            ],
        )?;
        Ok(())
    }

    pub fn replace_torrent_files(
        &mut self,
        infohash: &str,
        files: &[TorrentFileRow],
    ) -> Result<(), PoolError> {
        let tx = self.conn.savepoint()?;
        Self::replace_torrent_files_tx(&tx, infohash, files)?;
        tx.commit()?;
        Ok(())
    }

    fn replace_torrent_files_tx(
        tx: &Connection,
        infohash: &str,
        files: &[TorrentFileRow],
    ) -> Result<(), PoolError> {
        tx.execute(
            "DELETE FROM torrent_file WHERE infohash = ?1",
            params![infohash],
        )?;
        let mut ins = tx.prepare(
            "INSERT INTO torrent_file(infohash, idx, rel_path, size, pieces_root, pad_file)
             VALUES (?1,?2,?3,?4,?5,?6)",
        )?;
        for f in files {
            ins.execute(params![
                infohash,
                f.idx,
                f.rel_path,
                f.size as i64,
                f.pieces_root.map(|r| r.to_vec()),
                f.pad_file,
            ])?;
        }
        Ok(())
    }

    pub fn torrent(&self, infohash: &str) -> Result<Option<PoolTorrent>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT infohash, infohash_v1, infohash_v2, name, total_size, num_files,
                        source_path, fastresume_path, declared_save_path, category, tags, profile
                 FROM torrent WHERE infohash = ?1",
                params![infohash],
                row_to_torrent,
            )
            .optional()?)
    }

    pub fn torrents(&self) -> Result<Vec<PoolTorrent>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT infohash, infohash_v1, infohash_v2, name, total_size, num_files,
                    source_path, fastresume_path, declared_save_path, category, tags, profile
             FROM torrent ORDER BY infohash",
        )?;
        let rows = st.query_map([], row_to_torrent)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn torrent_files(&self, infohash: &str) -> Result<Vec<TorrentFileRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT infohash, idx, rel_path, size, pieces_root, pad_file
             FROM torrent_file WHERE infohash = ?1 ORDER BY idx",
        )?;
        let rows = st.query_map(params![infohash], |r| {
            Ok(TorrentFileRow {
                infohash: r.get(0)?,
                idx: r.get(1)?,
                rel_path: r.get(2)?,
                size: r.get::<_, i64>(3)? as u64,
                pieces_root: r.get::<_, Option<Vec<u8>>>(4)?.and_then(to_root32),
                pad_file: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn torrent_count(&self) -> Result<u64, PoolError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM torrent", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    // -- profile assignment (absorbs profile_assignments.json) --------------------

    pub fn profile_of(&self, infohash: &str) -> Result<Option<String>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT profile FROM torrent WHERE infohash = ?1",
                params![infohash],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn set_profile(&self, infohash: &str, profile: Option<&str>) -> Result<(), PoolError> {
        self.conn.execute(
            "UPDATE torrent SET profile = ?2 WHERE infohash = ?1",
            params![infohash, profile],
        )?;
        Ok(())
    }

    /// Forget that `profile` owns `infohash`, now that no session holds it.
    ///
    /// Only a record naming `profile` is cleared. With it, an `adopted`
    /// verdict goes too: nothing serves the torrent, and adoption refuses
    /// `adopted` outright, so left behind it would refuse every later
    /// adoption, into any profile. `payload_deleted` says its files were
    /// deleted with it. Returns whether the record named `profile`.
    pub fn release_owner(
        &mut self,
        infohash: &str,
        profile: &str,
        payload_deleted: bool,
    ) -> Result<bool, PoolError> {
        self.in_transaction(|st| {
            if st.profile_of(infohash)?.as_deref() != Some(profile) {
                return Ok(false);
            }
            st.set_profile(infohash, None)?;
            crate::matcher::settle_released(st, infohash, payload_deleted)?;
            Ok(true)
        })
    }

    /// Fold a legacy `profile_assignments.json` in. Existing assignments win, so
    /// re-running is safe and the JSON can stay on disk as a backup.
    pub fn import_legacy_registry(
        &mut self,
        assignments: &HashMap<String, String>,
    ) -> Result<usize, PoolError> {
        let tx = self.conn.savepoint()?;
        let mut n = 0usize;
        {
            let mut up = tx.prepare(
                "UPDATE torrent SET profile = ?2 WHERE infohash = ?1 AND profile IS NULL",
            )?;
            for (ih, profile) in assignments {
                n += up.execute(params![ih, profile])?;
            }
        }
        tx.commit()?;
        if n > 0 {
            info!(
                target: "torrentd_pool::store",
                torrent_count = n,
                "imported legacy profile assignments",
            );
        }
        let unknown = assignments.len().saturating_sub(n);
        if unknown > 0 {
            // Torrents assigned to a profile but absent from the library: the
            // operator's `.torrent` files and their registry disagree.
            warn!(
                target: "torrentd_pool::store",
                torrent_count = unknown,
                "legacy assignments with no matching torrent in the library",
            );
        }
        Ok(n)
    }

    // -- adoption + claims -------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn set_adoption(
        &self,
        infohash: &str,
        state: AdoptionState,
        root_id: Option<i64>,
        base_rel: Option<&str>,
        verified_at: Option<i64>,
        drift_at: Option<i64>,
        last_error: Option<&str>,
    ) -> Result<(), PoolError> {
        self.conn.execute(
            "INSERT INTO adoption(infohash, state, root_id, base_rel, verified_at, drift_at, last_error)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(infohash) DO UPDATE SET
                state = excluded.state, root_id = excluded.root_id,
                base_rel = excluded.base_rel, verified_at = excluded.verified_at,
                drift_at = excluded.drift_at, last_error = excluded.last_error",
            params![infohash, state.as_str(), root_id, base_rel, verified_at, drift_at, last_error],
        )?;
        Ok(())
    }

    pub fn adoption_state(&self, infohash: &str) -> Result<Option<AdoptionState>, PoolError> {
        let s: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM adoption WHERE infohash = ?1",
                params![infohash],
                |r| r.get(0),
            )
            .optional()?;
        Ok(s.and_then(|s| AdoptionState::parse(&s)))
    }

    /// `(base_rel, root_id)` recorded for a matched/adopted torrent.
    pub fn adoption_base(&self, infohash: &str) -> Result<Option<(i64, String)>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT root_id, base_rel FROM adoption
                 WHERE infohash = ?1 AND root_id IS NOT NULL AND base_rel IS NOT NULL",
                params![infohash],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?)
    }

    pub fn counts_by_state(&self) -> Result<HashMap<AdoptionState, u64>, PoolError> {
        let mut st = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM adoption GROUP BY state")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        let mut out = HashMap::new();
        for row in rows {
            let (s, n) = row?;
            if let Some(state) = AdoptionState::parse(&s) {
                out.insert(state, n);
            }
        }
        Ok(out)
    }

    /// Record exactly which files a torrent claims, replacing any prior set.
    pub fn replace_claims(
        &mut self,
        infohash: &str,
        claims: &[(i64, String)],
    ) -> Result<(), PoolError> {
        let tx = self.conn.savepoint()?;
        tx.execute("DELETE FROM claim WHERE infohash = ?1", params![infohash])?;
        {
            let mut ins = tx.prepare(
                "INSERT OR IGNORE INTO claim(root_id, rel_path, infohash) VALUES (?1,?2,?3)",
            )?;
            for (root_id, rel) in claims {
                ins.execute(params![root_id, rel, infohash])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Drop every claim row.
    ///
    /// Only meaningful inside [`PoolStore::in_transaction`] — on its own it
    /// publishes an empty claim table, under which every indexed file reads as
    /// an orphan. Refuses rather than trusting the caller.
    pub fn clear_all_claims(&self) -> Result<(), PoolError> {
        if self.tx_depth == 0 {
            return Err(PoolError::ClaimsClearedOutsideTransaction);
        }
        self.conn.execute("DELETE FROM claim", [])?;
        Ok(())
    }

    /// Every torrent that shares at least one file with another torrent.
    ///
    /// This is the check that gates destructive operations: two torrents over
    /// the same bytes means moving or deleting for one silently breaks the
    /// other.
    pub fn overlapping_torrents(&self) -> Result<Vec<String>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT c.infohash FROM claim c
             WHERE EXISTS (
                SELECT 1 FROM claim o
                WHERE o.root_id = c.root_id AND o.rel_path = c.rel_path
                  AND o.infohash <> c.infohash
             )",
        )?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Every file `infohash` claims, sorted, so two claim sets compare equal
    /// exactly when they name the same files.
    pub fn claims_of(&self, infohash: &str) -> Result<Vec<(i64, String)>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT root_id, rel_path FROM claim WHERE infohash = ?1 ORDER BY root_id, rel_path",
        )?;
        let rows = st.query_map(params![infohash], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The other torrents that claim at least one file `infohash` claims.
    pub fn co_claimants(&self, infohash: &str) -> Result<Vec<String>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT o.infohash FROM claim c
             JOIN claim o ON o.root_id = c.root_id AND o.rel_path = c.rel_path
             WHERE c.infohash = ?1 AND o.infohash <> ?1
             ORDER BY o.infohash",
        )?;
        let rows = st.query_map(params![infohash], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Whether any file `infohash` claims is claimed by another torrent too —
    /// shared payload or a conflict, either of which makes moving or deleting
    /// those bytes for one torrent break the other.
    ///
    /// Asked directly rather than read off the adoption state, because an
    /// adopted torrent keeps `adopted` across a rescan that finds it sharing.
    pub fn shares_claims(&self, infohash: &str) -> Result<bool, PoolError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM claim c JOIN claim o
                  ON o.root_id = c.root_id AND o.rel_path = c.rel_path
                WHERE c.infohash = ?1 AND o.infohash <> ?1)",
            params![infohash],
            |r| r.get(0),
        )?)
    }

    /// When drift was last recorded for `infohash` and not since cleared by a
    /// verification. Only a verify clears it.
    pub fn drift_at(&self, infohash: &str) -> Result<Option<i64>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT drift_at FROM adoption WHERE infohash = ?1",
                params![infohash],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }

    // -- plans ---------------------------------------------------------------

    pub fn create_plan(&self, kind: &str, spec: &str, created_at: i64) -> Result<i64, PoolError> {
        self.conn.execute(
            "INSERT INTO plan(kind, created_at, status, spec) VALUES (?1,?2,'draft',?3)",
            params![kind, created_at, spec],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn add_plan_steps(&mut self, plan_id: i64, steps: &[PlanStep]) -> Result<(), PoolError> {
        let tx = self.conn.savepoint()?;
        {
            let mut ins = tx.prepare(
                "INSERT INTO plan_step(plan_id, seq, op, src, dst, status, error)
                 VALUES (?1,?2,?3,?4,?5,'pending',NULL)",
            )?;
            for (i, st) in steps.iter().enumerate() {
                ins.execute(params![plan_id, i as i64, st.op, st.src, st.dst])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn plan(&self, id: i64) -> Result<Option<PlanRow>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, kind, created_at, applied_at, status, spec FROM plan WHERE id = ?1",
                params![id],
                |r| {
                    Ok(PlanRow {
                        id: r.get(0)?,
                        kind: r.get(1)?,
                        created_at: r.get(2)?,
                        applied_at: r.get(3)?,
                        status: r.get(4)?,
                        spec: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn plans(&self) -> Result<Vec<PlanRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, created_at, applied_at, status, spec FROM plan ORDER BY id DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok(PlanRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                created_at: r.get(2)?,
                applied_at: r.get(3)?,
                status: r.get(4)?,
                spec: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Plans left mid-apply by a crash or a kill, in id order so the oldest is
    /// resumed first.
    pub fn unfinished_plans(&self) -> Result<Vec<PlanRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, created_at, applied_at, status, spec
             FROM plan WHERE status = 'applying' ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(PlanRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                created_at: r.get(2)?,
                applied_at: r.get(3)?,
                status: r.get(4)?,
                spec: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn set_plan_status(
        &self,
        id: i64,
        status: &str,
        applied_at: Option<i64>,
    ) -> Result<(), PoolError> {
        self.conn.execute(
            "UPDATE plan SET status = ?2, applied_at = COALESCE(?3, applied_at) WHERE id = ?1",
            params![id, status, applied_at],
        )?;
        Ok(())
    }

    /// Atomically take ownership of a plan for applying.
    ///
    /// Returns `true` if this caller now owns it. Two concurrent
    /// `POST /v1/pool/plans/{plan_id}/apply` requests otherwise both read the steps
    /// as `pending` and both execute them — the second racing the first over
    /// the same files. A conditional `UPDATE` in one statement makes exactly
    /// one of them win.
    ///
    /// `resume` additionally admits a plan already in `applying`, which is
    /// what a crash leaves behind. Only the startup re-drive passes it: for an
    /// API request `applying` means another caller is mid-apply right now, and
    /// admitting it would be the very race this exists to prevent.
    pub fn claim_plan_for_apply(&self, id: i64, resume: bool) -> Result<bool, PoolError> {
        use crate::model::plan_status as ps;
        let changed = if resume {
            self.conn.execute(
                "UPDATE plan SET status = ?2 WHERE id = ?1 AND status IN (?3, ?4, ?5)",
                params![id, ps::APPLYING, ps::DRAFT, ps::FAILED, ps::APPLYING],
            )?
        } else {
            self.conn.execute(
                "UPDATE plan SET status = ?2 WHERE id = ?1 AND status IN (?3, ?4)",
                params![id, ps::APPLYING, ps::DRAFT, ps::FAILED],
            )?
        };
        Ok(changed == 1)
    }

    /// Discard a plan and its steps.
    ///
    /// One transaction: two bare `DELETE`s leave orphaned `plan_step` rows if
    /// the process dies between them.
    pub fn delete_plan(&mut self, id: i64) -> Result<(), PoolError> {
        let tx = self.conn.savepoint()?;
        tx.execute("DELETE FROM plan_step WHERE plan_id = ?1", params![id])?;
        tx.execute("DELETE FROM plan WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn plan_steps(&self, plan_id: i64) -> Result<Vec<PlanStepRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT seq, op, src, dst, status, error FROM plan_step
             WHERE plan_id = ?1 ORDER BY seq",
        )?;
        let rows = st.query_map(params![plan_id], |r| {
            Ok(PlanStepRow {
                seq: r.get(0)?,
                op: r.get(1)?,
                src: r.get(2)?,
                dst: r.get(3)?,
                status: r.get(4)?,
                error: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn set_step_status(
        &self,
        plan_id: i64,
        seq: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), PoolError> {
        self.conn.execute(
            "UPDATE plan_step SET status = ?3, error = ?4 WHERE plan_id = ?1 AND seq = ?2",
            params![plan_id, seq, status, error],
        )?;
        Ok(())
    }

    // -- rollups -----------------------------------------------------------

    /// Byte accounting for everything under `prefix` in `root_id`.
    ///
    /// Adopted/matched bytes are attributed via `claim`, so a file counts as
    /// protected only if some torrent actually references it.
    ///
    /// Read from the materialised tree, so the cost is one row plus one per
    /// torrent claiming anything under `prefix`, never one per file. A
    /// `prefix` that names no directory — a file, or nothing — rolls up to
    /// zero, as a directory with nothing under it would.
    pub fn rollup(&self, root_id: i64, prefix: &str) -> Result<DirRollup, PoolError> {
        let path = prefix.trim_matches('/');
        let Some((bytes_total, files_total, bytes_orphan, files_orphan)) = self
            .conn
            .query_row(
                "SELECT bytes_total, files_total, bytes_orphan, files_orphan
                 FROM dir WHERE root_id = ?1 AND path = ?2",
                params![root_id, path],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(DirRollup::default());
        };

        // A file claimed by two torrents counts once per claimant, as a
        // claim-by-claim sum over the files does.
        let (bytes_adopted, bytes_matched): (i64, i64) = self.conn.query_row(
            "SELECT
               COALESCE(SUM(CASE WHEN a.state = 'adopted' THEN dc.bytes ELSE 0 END),0),
               COALESCE(SUM(CASE WHEN a.state = 'matched' THEN dc.bytes ELSE 0 END),0)
             FROM dir_claim dc
             JOIN adoption a ON a.infohash = dc.infohash
             WHERE dc.root_id = ?1 AND dc.path = ?2",
            params![root_id, path],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        Ok(DirRollup {
            bytes_total: bytes_total as u64,
            bytes_adopted: bytes_adopted as u64,
            bytes_matched: bytes_matched as u64,
            bytes_orphan: bytes_orphan as u64,
            files_total: files_total as u64,
            files_orphan: files_orphan as u64,
        })
    }

    /// Recompute `root_id`'s materialised tree — `dir` and `dir_claim` —
    /// from its file index and the claim table.
    ///
    /// Streams both tables once, so it holds one aggregate per directory and
    /// one per (directory, claimant), never the file list. Every writer of
    /// `file` or `claim` that the daemon runs ends with this: a root swap
    /// rebuilds its root, and a match rebuilds every root.
    pub fn rebuild_rollups(&mut self, root_id: i64) -> Result<(), PoolError> {
        #[derive(Default)]
        struct Agg {
            bytes_total: u64,
            files_total: u64,
            bytes_orphan: u64,
            files_orphan: u64,
        }
        self.in_transaction(|st| -> Result<(), PoolError> {
            st.conn
                .execute("DELETE FROM dir WHERE root_id = ?1", params![root_id])?;
            st.conn
                .execute("DELETE FROM dir_claim WHERE root_id = ?1", params![root_id])?;

            let mut dirs: HashMap<String, Agg> = HashMap::new();
            {
                let mut q = st.conn.prepare(
                    "SELECT f.rel_path, f.size, EXISTS(
                         SELECT 1 FROM claim c
                         WHERE c.root_id = f.root_id AND c.rel_path = f.rel_path)
                     FROM file f WHERE f.root_id = ?1",
                )?;
                let mut rows = q.query(params![root_id])?;
                while let Some(r) = rows.next()? {
                    let rel: String = r.get(0)?;
                    let size = r.get::<_, i64>(1)? as u64;
                    let claimed: bool = r.get(2)?;
                    for dir in ancestors(&rel) {
                        // Only directories new to this walk allocate a key.
                        if !dirs.contains_key(dir) {
                            dirs.insert(dir.to_owned(), Agg::default());
                        }
                        let Some(agg) = dirs.get_mut(dir) else {
                            continue;
                        };
                        agg.bytes_total = agg.bytes_total.saturating_add(size);
                        agg.files_total += 1;
                        if !claimed {
                            agg.bytes_orphan = agg.bytes_orphan.saturating_add(size);
                            agg.files_orphan += 1;
                        }
                    }
                }
            }
            {
                let mut ins = st.conn.prepare(
                    "INSERT INTO dir(root_id, path, parent, bytes_total, files_total,
                                     bytes_orphan, files_orphan)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )?;
                for (path, a) in &dirs {
                    let parent = (!path.is_empty()).then(|| parent_of(path));
                    ins.execute(params![
                        root_id,
                        path,
                        parent,
                        clamp_i64(a.bytes_total),
                        clamp_i64(a.files_total),
                        clamp_i64(a.bytes_orphan),
                        clamp_i64(a.files_orphan),
                    ])?;
                }
            }
            drop(dirs);

            let mut claimed: HashMap<(String, String), u64> = HashMap::new();
            {
                let mut q = st.conn.prepare(
                    "SELECT c.rel_path, c.infohash, f.size
                     FROM claim c
                     JOIN file f ON f.root_id = c.root_id AND f.rel_path = c.rel_path
                     WHERE c.root_id = ?1",
                )?;
                let mut rows = q.query(params![root_id])?;
                while let Some(r) = rows.next()? {
                    let rel: String = r.get(0)?;
                    let infohash: String = r.get(1)?;
                    let size = r.get::<_, i64>(2)? as u64;
                    for dir in ancestors(&rel) {
                        let bytes = claimed
                            .entry((dir.to_owned(), infohash.clone()))
                            .or_default();
                        *bytes = bytes.saturating_add(size);
                    }
                }
            }
            let mut ins = st.conn.prepare(
                "INSERT INTO dir_claim(root_id, path, infohash, bytes) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for ((path, infohash), bytes) in &claimed {
                ins.execute(params![root_id, path, infohash, clamp_i64(*bytes)])?;
            }
            Ok(())
        })
    }

    /// [`PoolStore::rebuild_rollups`] for every root the index holds.
    pub fn rebuild_all_rollups(&mut self) -> Result<(), PoolError> {
        let ids: Vec<i64> = {
            let mut st = self.conn.prepare("SELECT id FROM root ORDER BY id")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        self.in_transaction(|st| {
            for id in ids {
                st.rebuild_rollups(id)?;
            }
            Ok(())
        })
    }

    /// Every file under `prefix` that no torrent claims.
    ///
    /// This is the only query a delete plan is allowed to build from: a file is
    /// a deletion candidate solely because nothing in the library references
    /// it, never because it merely looks unused.
    pub fn orphan_files(&self, root_id: i64, prefix: &str) -> Result<Vec<String>, PoolError> {
        Ok(self
            .orphan_files_sized(root_id, prefix)?
            .into_iter()
            .map(|(p, ..)| p)
            .collect())
    }

    /// [`PoolStore::orphan_files`], with each file's indexed size and
    /// `(dev, ino)` identity.
    ///
    /// The identity lets the delete planner drop an orphan that is a claimed
    /// file reached by another path (see [`PoolStore::claimed_identities`]).
    pub fn orphan_files_sized(
        &self,
        root_id: i64,
        prefix: &str,
    ) -> Result<Vec<SizedOrphan>, PoolError> {
        let like = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let upper = prefix_upper_bound(&like);
        let mut st = self.conn.prepare(
            "SELECT f.rel_path, f.size, f.dev, f.ino FROM file f
             WHERE f.root_id = ?1 AND f.rel_path >= ?2 AND f.rel_path < ?3
               AND NOT EXISTS (
                 SELECT 1 FROM claim c
                 WHERE c.root_id = f.root_id AND c.rel_path = f.rel_path
               )
             ORDER BY f.rel_path",
        )?;
        let rows = st.query_map(params![root_id, like, upper], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                (r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64),
            ))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Files under `(root_id, prefix)` that `infohash` does **not** claim.
    ///
    /// A relocate moves a whole directory, so the only way that is safe is if
    /// the directory holds nothing but this torrent's payload. Anything else
    /// under there — another torrent's files, or unclaimed bytes — would be
    /// dragged along by the rename without appearing anywhere in the plan.
    ///
    /// Returns at most `limit` paths; the caller only needs enough to name one
    /// in the refusal.
    pub fn foreign_files_under(
        &self,
        root_id: i64,
        prefix: &str,
        infohash: &str,
        limit: usize,
    ) -> Result<Vec<String>, PoolError> {
        let like = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let upper = prefix_upper_bound(&like);
        let mut st = self.conn.prepare(
            "SELECT f.rel_path FROM file f
             WHERE f.root_id = ?1 AND f.rel_path >= ?2 AND f.rel_path < ?3
               AND NOT EXISTS (
                 SELECT 1 FROM claim c
                 WHERE c.root_id = f.root_id AND c.rel_path = f.rel_path
                   AND c.infohash = ?4
               )
             ORDER BY f.rel_path
             LIMIT ?5",
        )?;
        let rows = st.query_map(params![root_id, like, upper, infohash, limit as i64], |r| {
            r.get::<_, String>(0)
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Of `loaded`, the info-hashes for which this index holds no claim rows.
    ///
    /// Claims are written by the matcher and by nothing else, so a torrent the
    /// daemon is serving that the matcher has never placed contributes no
    /// claims — and its payload therefore reads as unclaimed. Any non-empty
    /// result means the claim table is an incomplete account of what is
    /// protected, which is the one precondition a delete cannot do without.
    ///
    /// Derived from live state rather than counted as torrents are added, so
    /// it is correct across a restart and cannot drift from reality.
    pub fn loaded_without_claims(&self, loaded: &[String]) -> Result<Vec<String>, PoolError> {
        if loaded.is_empty() {
            return Ok(Vec::new());
        }
        let mut st = self
            .conn
            .prepare("SELECT EXISTS(SELECT 1 FROM claim WHERE infohash = ?1)")?;
        let mut out = Vec::new();
        for ih in loaded {
            let claimed: i64 = st.query_row(params![ih], |r| r.get(0))?;
            if claimed == 0 {
                out.push(ih.clone());
            }
        }
        Ok(out)
    }

    /// Whether one specific file is claimed by no torrent.
    ///
    /// The single-file form of [`PoolStore::orphan_files`], for the last-moment
    /// re-check before an irreversible delete. Listing every orphan in the root
    /// and scanning it would be O(pool) per file.
    pub fn is_orphan(&self, root_id: i64, rel_path: &str) -> Result<bool, PoolError> {
        let claimed: i64 = self.conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM claim WHERE root_id = ?1 AND rel_path = ?2
             )",
            params![root_id, rel_path],
            |r| r.get(0),
        )?;
        if claimed != 0 {
            return Ok(false);
        }
        // A path the index has never seen is not an orphan either — it is
        // outside the pool's knowledge, and deleting it was never sanctioned.
        let known: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM file WHERE root_id = ?1 AND rel_path = ?2)",
            params![root_id, rel_path],
            |r| r.get(0),
        )?;
        Ok(known != 0)
    }

    /// The indexed `(dev, ino)` of every claimed file, under every root.
    ///
    /// A path is not the only way to reach a file: a hard link, or the same
    /// directory listed twice through a bind mount, is a second path to the
    /// claimed bytes that [`PoolStore::is_orphan`] reads as unclaimed. The
    /// delete step refuses any file whose identity is in this set.
    pub fn claimed_identities(&self) -> Result<HashSet<(u64, u64)>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT f.dev, f.ino FROM claim c
             JOIN file f ON f.root_id = c.root_id AND f.rel_path = c.rel_path",
        )?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.collect::<Result<HashSet<_>, _>>()?)
    }

    /// Distinct adoption states of every torrent claiming a file under
    /// `prefix`.
    ///
    /// Lets the tree view colour a directory in one query instead of one per
    /// row, which matters when a page has 500 entries.
    pub fn states_under(
        &self,
        root_id: i64,
        prefix: &str,
    ) -> Result<Vec<AdoptionState>, PoolError> {
        let path = prefix.trim_matches('/');
        // A directory reads its claimants from the materialised tree; a path
        // that is not one may name a file, whose claimants are its own claim
        // rows. Both are index lookups, never a walk of the subtree.
        let is_dir: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM dir WHERE root_id = ?1 AND path = ?2)",
            params![root_id, path],
            |r| r.get(0),
        )?;
        let sql = if is_dir {
            "SELECT DISTINCT a.state
             FROM dir_claim dc
             JOIN adoption a ON a.infohash = dc.infohash
             WHERE dc.root_id = ?1 AND dc.path = ?2"
        } else {
            "SELECT DISTINCT a.state
             FROM claim c
             JOIN adoption a ON a.infohash = c.infohash
             WHERE c.root_id = ?1 AND c.rel_path = ?2"
        };
        let mut st = self.conn.prepare_cached(sql)?;
        let rows = st.query_map(params![root_id, path], |r| r.get::<_, String>(0))?;
        let mut out: Vec<AdoptionState> = rows
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|s| AdoptionState::parse(&s))
            .collect();
        out.sort_by_key(|s| s.as_str());
        out.dedup();
        Ok(out)
    }

    /// Immediate children of `prefix` — directories and files — for the tree
    /// browser: directories first, then files, each in byte order of path.
    ///
    /// Every child at once; [`PoolStore::children_page`] is the paged form.
    /// Both read one directory's rows of the materialised tree, never the
    /// paths under its subdirectories.
    pub fn children(&self, root_id: i64, prefix: &str) -> Result<Vec<(String, bool)>, PoolError> {
        self.children_page(root_id, prefix, None, usize::MAX, false)
    }

    /// Up to `limit` immediate children of `prefix`, in [`PoolStore::children`]'s
    /// order, starting after `after` — `(is_dir, path)` of the last child
    /// the caller already has.
    ///
    /// With `orphans_only`, only children holding bytes no torrent claims: a
    /// directory whose materialised orphan bytes are non-zero, or an
    /// unclaimed file that is not empty.
    pub fn children_page(
        &self,
        root_id: i64,
        prefix: &str,
        after: Option<(bool, &str)>,
        limit: usize,
        orphans_only: bool,
    ) -> Result<Vec<(String, bool)>, PoolError> {
        let parent = prefix.trim_matches('/');
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut out = Vec::new();
        // Directories sort before files, so a cursor on a file is past every
        // directory.
        let (dir_after, file_after) = match after {
            None => (Some(""), ""),
            Some((true, p)) => (Some(p), ""),
            Some((false, p)) => (None, p),
        };
        if let Some(dir_after) = dir_after {
            let mut st = self.conn.prepare_cached(
                "SELECT path FROM dir
                 WHERE root_id = ?1 AND parent = ?2 AND path > ?3
                   AND (?4 = 0 OR bytes_orphan > 0)
                 ORDER BY path LIMIT ?5",
            )?;
            let rows = st.query_map(
                params![root_id, parent, dir_after, orphans_only, limit],
                |r| r.get::<_, String>(0),
            )?;
            for row in rows {
                out.push((row?, true));
            }
        }
        let room = limit.saturating_sub(out.len() as i64);
        if room > 0 {
            let mut st = self.conn.prepare_cached(
                "SELECT f.rel_path FROM file f
                 WHERE f.root_id = ?1 AND f.parent = ?2 AND f.rel_path > ?3
                   AND (?4 = 0 OR f.size > 0 AND NOT EXISTS (
                     SELECT 1 FROM claim c
                     WHERE c.root_id = f.root_id AND c.rel_path = f.rel_path))
                 ORDER BY f.rel_path LIMIT ?5",
            )?;
            let rows = st.query_map(
                params![root_id, parent, file_after, orphans_only, room],
                |r| r.get::<_, String>(0),
            )?;
            for row in rows {
                out.push((row?, false));
            }
        }
        Ok(out)
    }

    /// Up to `limit` library torrents in infohash order after `after`, each
    /// with its adoption state and the base it was matched at, optionally
    /// only those in `state`.
    ///
    /// Keyset pagination in SQL: a page costs `limit` index steps whatever
    /// the library's size, where loading every torrent and cutting a page
    /// from it cost the whole library on every request.
    pub fn torrents_page(
        &self,
        after: Option<&str>,
        state: Option<AdoptionState>,
        limit: usize,
    ) -> Result<Vec<TorrentListing>, PoolError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let after = after.unwrap_or("");
        let map = |r: &rusqlite::Row<'_>| -> rusqlite::Result<TorrentListing> {
            let state: Option<String> = r.get(12)?;
            Ok(TorrentListing {
                torrent: row_to_torrent(r)?,
                state: state.as_deref().and_then(AdoptionState::parse),
                base_rel: r.get(13)?,
            })
        };
        let rows = match state {
            None => {
                let mut st = self.conn.prepare_cached(
                    "SELECT t.infohash, t.infohash_v1, t.infohash_v2, t.name, t.total_size,
                            t.num_files, t.source_path, t.fastresume_path, t.declared_save_path,
                            t.category, t.tags, t.profile, a.state,
                            CASE WHEN a.root_id IS NOT NULL THEN a.base_rel END
                     FROM torrent t
                     LEFT JOIN adoption a ON a.infohash = t.infohash
                     WHERE t.infohash > ?1
                     ORDER BY t.infohash LIMIT ?2",
                )?;
                let rows = st.query_map(params![after, limit], map)?;
                rows.collect::<Result<Vec<_>, _>>()?
            }
            Some(state) => {
                let mut st = self.conn.prepare_cached(
                    "SELECT t.infohash, t.infohash_v1, t.infohash_v2, t.name, t.total_size,
                            t.num_files, t.source_path, t.fastresume_path, t.declared_save_path,
                            t.category, t.tags, t.profile, a.state,
                            CASE WHEN a.root_id IS NOT NULL THEN a.base_rel END
                     FROM adoption a
                     JOIN torrent t ON t.infohash = a.infohash
                     WHERE a.state = ?1 AND a.infohash > ?2
                     ORDER BY a.infohash LIMIT ?3",
                )?;
                let rows = st.query_map(params![state.as_str(), after, limit], map)?;
                rows.collect::<Result<Vec<_>, _>>()?
            }
        };
        Ok(rows)
    }
}

/// One row of [`PoolStore::torrents_page`].
#[derive(Clone, Debug)]
pub struct TorrentListing {
    pub torrent: PoolTorrent,
    /// `None` until a match has placed the torrent.
    pub state: Option<AdoptionState>,
    /// The directory, relative to its root, the payload was matched at.
    pub base_rel: Option<String>,
}

/// The directory a root-relative path sits in: `""` at the top of the root.
pub fn parent_of(rel_path: &str) -> &str {
    rel_path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// Every directory `rel_path` (a file) sits under, from the root (`""`) down
/// to its parent.
fn ancestors(rel_path: &str) -> impl Iterator<Item = &str> {
    std::iter::once("").chain(
        rel_path
            .match_indices('/')
            .map(move |(i, _)| &rel_path[..i])
            .filter(|d| !d.is_empty()),
    )
}

/// A `u64` count or byte total as SQLite's `INTEGER` stores it, saturating
/// rather than wrapping past `i64::MAX`.
fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Exclusive upper bound for a `>= prefix AND < upper` range scan.
///
/// Incrementing the last byte is what turns a prefix match into an index range
/// scan; `LIKE 'prefix%'` would not use the primary key on a multi-million-row
/// table. An all-`0xff` tail has no successor, so fall back to an open range.
fn prefix_upper_bound(prefix: &str) -> String {
    if prefix.is_empty() {
        // Sorts after any realistic path; `< upper` then matches everything.
        return "\u{10FFFF}".to_string();
    }
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.pop() {
        if last < 0xff {
            bytes.push(last + 1);
            return String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    "\u{10FFFF}".to_string()
}

fn to_root32(v: Vec<u8>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

fn row_to_file(r: &rusqlite::Row<'_>) -> rusqlite::Result<PoolFile> {
    Ok(PoolFile {
        root_id: r.get(0)?,
        rel_path: r.get(1)?,
        size: r.get::<_, i64>(2)? as u64,
        mtime_ns: r.get(3)?,
        ino: r.get::<_, i64>(4)? as u64,
        dev: r.get::<_, i64>(5)? as u64,
        v2_root: r.get::<_, Option<Vec<u8>>>(6)?.and_then(to_root32),
    })
}

fn row_to_torrent(r: &rusqlite::Row<'_>) -> rusqlite::Result<PoolTorrent> {
    let tags: Option<String> = r.get(10)?;
    Ok(PoolTorrent {
        infohash: r.get(0)?,
        infohash_v1: r.get(1)?,
        infohash_v2: r.get(2)?,
        name: r.get(3)?,
        total_size: r.get::<_, i64>(4)? as u64,
        num_files: r.get::<_, i64>(5)? as usize,
        source_path: PathBuf::from(r.get::<_, String>(6)?),
        fastresume_path: r.get::<_, Option<String>>(7)?.map(PathBuf::from),
        declared_save_path: r.get(8)?,
        category: r.get(9)?,
        tags: tags
            .map(|t| {
                t.split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        profile: r.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon and a CLI `pool check` may write side by side; a CLI
    /// `pool scan` may not run beside either, and nothing opens beside it.
    #[test]
    fn an_exclusive_writer_and_any_other_writer_exclude_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pool.db");

        let daemon = PoolStore::open(&db).unwrap();
        let check = PoolStore::open(&db).expect("shared writers coexist");
        assert!(matches!(
            PoolStore::open_exclusive(&db),
            Err(PoolError::Busy)
        ));
        drop(check);
        assert!(
            matches!(PoolStore::open_exclusive(&db), Err(PoolError::Busy)),
            "refused while any one writer remains",
        );
        // A reader takes no lock: the API reads through one during a scan.
        drop(PoolStore::open_read_only(&db).unwrap());
        drop(daemon);

        let scan = PoolStore::open_exclusive(&db).expect("alone, the scan opens");
        assert!(matches!(PoolStore::open(&db), Err(PoolError::Busy)));
        assert!(matches!(
            PoolStore::open_exclusive(&db),
            Err(PoolError::Busy)
        ));
        drop(PoolStore::open_read_only(&db).unwrap());
        drop(scan);
        PoolStore::open(&db).expect("released when the scan's store drops");
        assert!(dir.path().join("pool.db.lock").exists());
    }

    /// Whether this process can open `path` for writing despite its mode: a
    /// root or CAP_DAC_OVERRIDE test run, where the permission tests below
    /// cannot set up the situation they check.
    fn bypasses_permissions(path: &Path) -> bool {
        std::fs::OpenOptions::new().write(true).open(path).is_ok()
    }

    /// A lock file this process may not write (another user's, here 0444) is
    /// opened read-only and still locks: the scan and any other writer still
    /// exclude each other through it.
    #[test]
    fn a_lock_file_that_cannot_be_written_still_locks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pool.db");
        let lock = dir.path().join("pool.db.lock");
        drop(PoolStore::open(&db).unwrap());
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
        if bypasses_permissions(&lock) {
            return;
        }

        let daemon = PoolStore::open(&db).expect("a read-only lock file opens");
        assert!(daemon._hold.is_some(), "and is locked");
        assert!(matches!(
            PoolStore::open_exclusive(&db),
            Err(PoolError::Busy)
        ));
        drop(daemon);

        let scan = PoolStore::open_exclusive(&db).expect("alone, the scan opens");
        assert!(scan._hold.is_some());
        assert!(matches!(PoolStore::open(&db), Err(PoolError::Busy)));
        drop(scan);
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o444,
            "a file this process cannot write is not chmodded",
        );
    }

    /// A lock file created under a restrictive umask is made readable by
    /// every user, so another user's process can still open it to lock; one
    /// this process cannot read at all opens the index without the lock,
    /// rather than refusing it.
    #[test]
    fn the_lock_file_is_left_readable_and_an_unreadable_one_is_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pool.db");
        let lock = dir.path().join("pool.db.lock");
        std::fs::File::create(&lock).unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();

        drop(PoolStore::open(&db).unwrap());
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o644,
        );

        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
        if bypasses_permissions(&lock) {
            return;
        }
        let store = PoolStore::open(&db).expect("an unreadable lock file does not refuse the open");
        assert!(store._hold.is_none());
    }
}
