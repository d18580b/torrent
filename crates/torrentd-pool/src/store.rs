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

/// Bumped whenever the schema changes; `migrate` walks forward from whatever
/// the file reports. A file from the future is refused rather than guessed at.
const SCHEMA_VERSION: i64 = 4;

/// The version [`PoolStore::migrate`] brings a file to. Everything that
/// machinery stamps, recognises and repairs is the v3 schema; v4 is one
/// additive step on top of it, in [`PoolStore::migrate_v4`], so the v3
/// recognition arms keep describing exactly the files they were written for.
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

const SCHEMA_V1: &str = r#"
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
    -- Historical text. v1 named this column `slot`; v3 renames it to
    -- `profile`. Do not substitute the new name here: an index created by an
    -- earlier build really does carry a `slot` column, and a v1 statement that
    -- claims otherwise is a migration that never runs.
    slot          TEXT,
    added_at      INTEGER NOT NULL
);

CREATE INDEX torrent_by_slot ON torrent(slot) WHERE slot IS NOT NULL;

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

/// v2 adds the mutation journal. Applied on top of v1 rather than folded into
/// it so an index created by an earlier build migrates forward in place.
const SCHEMA_V2: &str = r#"
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

/// v3 renames the torrent→account column from `slot` to `profile`, following
/// the same convention as v2: applied on top of v1 rather than folded into it,
/// so an index created by an earlier build migrates forward in place. Folding
/// the new name into v1 instead leaves a `user_version = 2` file untouched —
/// `open` succeeds, the daemon boots clean, and the first pool query fails with
/// `no such column: profile`, with no recovery but deleting the index and the
/// `plan`/`plan_step` journal that `from_conn` documents as not reconstructible.
///
/// SQLite rewrites the surviving index's definition to follow the rename, so
/// `torrent_by_slot` would keep its old name over the new column; it is dropped
/// and recreated rather than left mislabelled.
const SCHEMA_V3: &str = r#"
ALTER TABLE torrent RENAME COLUMN slot TO profile;

DROP INDEX torrent_by_slot;

CREATE INDEX torrent_by_profile ON torrent(profile) WHERE profile IS NOT NULL;
"#;

/// [`SCHEMA_V3`]'s two index statements, in the form that may be applied to a
/// file where either of them has already run.
///
/// A build that applied `SCHEMA_V3` with one implicit transaction per statement
/// could commit the rename and lose an index statement, leaving v3's columns
/// under `user_version = 2` with either no index on `profile` or the old
/// `torrent_by_slot` mislabelled over it. [`PoolStore::migrate`]'s recognition
/// arm brings such a file the rest of the way with these two statements and no
/// rename, so both have to tolerate the work already being done.
///
/// Deliberately **not** `SCHEMA_V3`'s own text. The version-keyed step's
/// `CREATE INDEX` is bare on purpose: `a_v3_step_that_fails_leaves_the_version
/// _and_the_schema_agreeing` forces that statement to fail by pre-creating an
/// index of the name, which is how the one-transaction property is pinned, and
/// an `IF NOT EXISTS` there would disarm it. The two texts describe the same
/// two indexes; a change to either index belongs in both.
const SCHEMA_V3_INDEXES: &str = r#"
DROP INDEX IF EXISTS torrent_by_slot;

CREATE INDEX IF NOT EXISTS torrent_by_profile ON torrent(profile) WHERE profile IS NOT NULL;
"#;

pub struct PoolStore {
    conn: Connection,
    /// Nesting depth for [`PoolStore::in_transaction`]; 0 means autocommit.
    tx_depth: u32,
}

impl std::fmt::Debug for PoolStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolStore").finish_non_exhaustive()
    }
}

impl PoolStore {
    /// Open (creating if needed) the pool database at `path`.
    pub fn open(path: &Path) -> Result<Self, PoolError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        Self::from_conn(conn)
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
        // `in_transaction`). A second writer — the CLI `pool scan` racing the
        // daemon — must fail fast with SQLITE_BUSY so the caller can say so,
        // not block for hours.
        conn.busy_timeout(std::time::Duration::from_millis(0))?;
        let store = Self { conn, tx_depth: 0 };
        store.migrate()?;
        store.migrate_v4()?;
        Ok(store)
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
        // process. Axum installs no panic layer, so an HTTP handler is enough
        // to get there. Roll back, restore the depth, then re-raise.
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

    /// Suffix of the copy [`PoolStore::migrate`] leaves before the first
    /// destructive schema step. Named in `docs/running.md`'s rollback note.
    pub const PRE_V3_BACKUP_SUFFIX: &'static str = ".pre-v3.bak";

    /// Take a consistent copy of an existing database aside, once, before v3
    /// touches it.
    ///
    /// v3 is the first schema step that destroys information: `ALTER TABLE
    /// torrent RENAME COLUMN slot TO profile` cannot be undone by re-running
    /// anything, and the file also holds the `plan` / `plan_step` journal that
    /// [`PoolStore::from_conn`] documents as not reconstructible by rescanning.
    /// The sibling artefact takes the same posture for the same reason — the
    /// assignment registry keeps its pre-migration file "intact for a
    /// rollback" — and nothing argued the index should behave differently.
    ///
    /// `VACUUM INTO` rather than a file copy: the database runs in WAL mode,
    /// so the bytes at `path` are not by themselves a complete database.
    ///
    /// An existing backup does not describe the state this run is about to
    /// change. It can be from an earlier attempt that rolled back, but it can
    /// equally be from an earlier **successful** migration that the operator
    /// rolled back by copying it over the index, leaving it in place — and
    /// every change made since then is in the index and not in the copy.
    /// Keeping it and taking no new one meant a second rollback after the
    /// re-upgrade silently discarded those changes. So a fresh copy is taken
    /// beside it, as `<backup>.new`, and replaces it only once the migration
    /// commits: until then the older file stays, because if the migration
    /// fails the fresh copy is of the index that just failed, and the older
    /// one is the copy that predates the run — the one the failure message
    /// tells the operator they may restore. The caller does the replacing, in
    /// [`PoolStore::promote_fresh_backup`].
    ///
    /// "Exists" is `symlink_metadata`, not `Path::exists`: the latter follows
    /// symlinks, so a `.pre-v3.bak` that is a symlink to nothing read as
    /// absent, and `VACUUM INTO` then wrote the only rollback copy of the
    /// index *through* it, wherever it pointed. Whatever an operator put at
    /// this path, the answer to "is something already here" is yes.
    ///
    /// But keeping it through a failed run is only the right answer for
    /// something that is a copy of the index. A dangling symlink, a directory
    /// or an unrelated file is not one, and keeping it meant the irreversible
    /// v3 rename then ran with **no** rollback copy at all, while `docs/running.md` tells the operator that
    /// restoring that file is how they go back. A promise of a rollback that
    /// does not exist is worse than a refusal naming why, so the migration
    /// stops instead. [`PoolStore::rollback_copy_of_an_index`] is that test,
    /// and it asks what the sentence above claims rather than the weaker
    /// question of whether SQLite can open the bytes.
    ///
    /// Returns the `(fresh, existing)` pair when a fresh copy was taken beside
    /// an existing one, for the caller to promote after the commit or discard
    /// after a failure.
    fn backup_before_v3(&self) -> Result<Option<(String, String)>, PoolError> {
        // No path: an in-memory store, which has nothing to roll back to.
        let Some(path) = self.conn.path().filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        let backup = format!("{path}{}", Self::PRE_V3_BACKUP_SUFFIX);
        if Path::new(&backup).symlink_metadata().is_ok() {
            if let Err(reason) = Self::rollback_copy_of_an_index(&backup, path) {
                return Err(PoolError::BackupNotARollbackCopy {
                    path: backup,
                    reason,
                });
            }
            let fresh = format!("{backup}.new");
            // A leftover from a run that died before promoting or discarding
            // it. `remove_file` removes a symlink itself, never its target.
            if Path::new(&fresh).symlink_metadata().is_ok() {
                std::fs::remove_file(&fresh).map_err(|e| PoolError::BackupFailed {
                    path: fresh.clone(),
                    reason: e.to_string(),
                })?;
            }
            self.conn
                .execute("VACUUM INTO ?1", params![fresh])
                .map_err(|e| PoolError::BackupFailed {
                    path: fresh.clone(),
                    reason: e.to_string(),
                })?;
            info!(
                target: "torrentd_pool::store",
                backup = %backup,
                fresh = %fresh,
                "pool schema v3 backup already exists; took a fresh copy beside it, which \
                 replaces it once the migration commits",
            );
            return Ok(Some((fresh, backup)));
        }
        // Wrapped, not propagated. A bare `PoolError::Sqlite` here aborted an
        // otherwise-valid migration with a SQLite code and no mention of a
        // backup, a path, or why the migration needed one — and `startup.rs`
        // opens the pool with `?`, so that code was the whole of what the
        // operator got.
        self.conn
            .execute("VACUUM INTO ?1", params![backup])
            .map_err(|e| PoolError::BackupFailed {
                path: backup.clone(),
                reason: e.to_string(),
            })?;
        info!(
            target: "torrentd_pool::store",
            backup = %backup,
            "pool database copied aside before the v3 schema migration",
        );
        Ok(None)
    }

    /// Settle a fresh copy [`PoolStore::backup_before_v3`] took beside an
    /// existing one: after a commit it replaces the older copy, because it is
    /// the state the migration just changed; after a failure it is discarded,
    /// because it is a copy of the index that failed and the older one is the
    /// rollback that predates the run.
    ///
    /// Neither outcome fails the open. The migration has already committed or
    /// already failed; a copy that cannot be settled is reported with both
    /// paths so the operator can settle it by hand.
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
    /// `index`, or the reason it cannot.
    ///
    /// Read-only so nothing is created: a path that does not resolve — which
    /// is what a dangling symlink is — fails to open rather than being made.
    ///
    /// Three questions, because the one this used to ask — can SQLite open it
    /// and answer `PRAGMA schema_version` — is true of things that are not a
    /// copy of anything, and the caller's doc promises the stronger claim:
    ///
    /// 1. **It is not this index.** `.pre-v3.bak` as a symlink to `pool.db`
    ///    passed every other test there is, the migration proceeded, and the
    ///    file `docs/running.md` tells the operator to restore was the
    ///    *migrated v3 database*. Compared after `canonicalize`, because the
    ///    two paths are equal only after the links on both are resolved.
    /// 2. **It reports a pool schema version this build understands.** A
    ///    zero-byte file is a valid empty database to SQLite: it opens, it
    ///    answers a `PRAGMA`, and it reports `user_version = 0`. Nothing this
    ///    project ever wrote reports 0 with data in it, and a copy from a
    ///    *newer* build is not a rollback for this one either.
    /// 3. **It carries this index's tables.** `root` and `torrent` are in
    ///    `SCHEMA_V1` and in every version since, so any genuine copy has
    ///    both, and an unrelated SQLite database an operator left at that path
    ///    has neither.
    ///
    /// What this still cannot decide is whether a file that passes all three
    /// is a copy of *this* index rather than of another deployment's — two
    /// pool indexes are the same shape. Refusing every symlink would close
    /// that, at the cost of refusing a copy an operator deliberately parked on
    /// another volume, which is a posture nothing in this repository states.
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

    /// Whether this file carries v3's `torrent` columns: a `profile` column and
    /// **no** `slot` column.
    ///
    /// Not one commit's file. Any superseded build of this change that reached
    /// v3's columns without recording the version writes this shape, and there
    /// is more than one way it happened: a build that folded the rename into
    /// `SCHEMA_V1` at `SCHEMA_VERSION = 2` wrote it with both indexes correct,
    /// and a build that applied `SCHEMA_V3` with one implicit transaction per
    /// statement wrote it with the rename committed and an index statement
    /// lost. Naming a commit here claimed a boundary this predicate does not
    /// have: the column test is true of every one of them, so the arm below
    /// checks the indexes too and repairs them rather than stamping a version
    /// over a schema that is not yet v3's.
    ///
    /// **This does not reopen the decision that the migration is keyed on
    /// `user_version`.** That decision rejected keying the *migration* on
    /// `PRAGMA table_info` — probing for the old column and renaming where it
    /// is present — because a schema that inspects itself has two sources of
    /// truth about its own shape. Nothing here keys a migration on anything:
    /// the steps below are unchanged and still run off `found`. This is a
    /// one-shot repair of files that superseded builds of this very branch
    /// wrote with a version their schema does not match, and the transaction
    /// around `migrate` means no build after it can produce another.
    ///
    /// What cannot match: a file with both columns, or with neither, goes down
    /// the ordinary path, and a genuine v2 file has `slot` and no `profile`.
    ///
    /// Not tied to a version either. It was `carries_v3_columns_at_v2` while
    /// the arm below was guarded on `found == 2`; the arm now runs the index
    /// half for any version this build can open, because a build in this
    /// change's own `e391b72 … 1195546^` window stamped `user_version = 3` and
    /// ran no index DDL at all — so the same incomplete schema exists at 3, and
    /// at 3 nothing was even looking.
    ///
    /// The alternative was to tell the operator this file cannot be migrated
    /// and must be deleted. That is honest and it destroys the `plan` /
    /// `plan_step` journal `from_conn` documents as not reconstructible by
    /// rescanning — the one thing in the file worth protecting. The copy-aside
    /// does not help either: it is a `VACUUM INTO` of the already-broken
    /// database, so the rollback the upgrade note describes restores the same
    /// unopenable file.
    fn carries_v3_columns(&self) -> Result<bool, PoolError> {
        let mut has_profile = false;
        let mut has_slot = false;
        let mut stmt = self.conn.prepare("PRAGMA table_info(torrent)")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            match r.get::<_, String>(1)?.as_str() {
                "profile" => has_profile = true,
                "slot" => has_slot = true,
                _ => {}
            }
        }
        Ok(has_profile && !has_slot)
    }

    /// Whether both tables `SCHEMA_V2` creates exist in this file.
    ///
    /// The columns and indexes say v1's half of the schema is v3's; this says
    /// v2's half was ever applied. A build that folded the rename into
    /// `SCHEMA_V1` and wrote the version after its steps, interrupted between
    /// `SCHEMA_V1` and `SCHEMA_V2`, left v3's `torrent` columns and indexes at
    /// version 0 with no `plan` or `plan_step` at all. Stamping that file
    /// opened it cleanly and failed later with `no such table: plan`.
    fn has_v2_tables(&self) -> Result<bool, PoolError> {
        let found: i64 = self.conn.query_row(
            "SELECT count(*) FROM sqlite_master \
             WHERE type = 'table' AND name IN ('plan', 'plan_step')",
            [],
            |r| r.get(0),
        )?;
        Ok(found == 2)
    }

    /// Whether an index called `name` exists on `torrent` in this file.
    ///
    /// The other half of the recognition: the columns say the rename ran, and
    /// this says whether the index statements that follow it ran with it.
    fn has_torrent_index(&self, name: &str) -> Result<bool, PoolError> {
        let found: i64 = self.conn.query_row(
            "SELECT count(*) FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = 'torrent' AND name = ?1",
            params![name],
            |r| r.get(0),
        )?;
        Ok(found > 0)
    }

    /// Walk the schema forward from whatever the file reports.
    ///
    /// Every step and the `user_version` write go inside **one**
    /// `BEGIN IMMEDIATE … COMMIT`. `execute_batch` without an explicit
    /// transaction gives one implicit transaction *per statement*, so a
    /// `RENAME COLUMN` that commits before a failing `DROP INDEX` or
    /// `CREATE INDEX` — `SQLITE_FULL`, `SQLITE_IOERR`, or the process dying —
    /// left `user_version` at 2 over a schema that had already moved to 3.
    /// Every later open then re-ran v3 and failed on its own completed work,
    /// permanently, on a database `startup.rs` opens with `?` under
    /// `Restart=on-failure`. `PRAGMA user_version` is journaled and
    /// participates in the transaction.
    ///
    /// A file those steps cannot reach — v3's columns already, under a version
    /// that does not describe them — is recognised rather than stepped: see
    /// [`PoolStore::carries_v3_columns`].
    fn migrate(&self) -> Result<(), PoolError> {
        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found > SCHEMA_VERSION {
            return Err(PoolError::SchemaVersion {
                found,
                expected: SCHEMA_VERSION,
            });
        }
        // Past v3 already: everything below describes files at or before it,
        // and its recognition arm would otherwise stamp a v4 file back to 3.
        if found > V3 {
            return Ok(());
        }
        // The files no version-keyed step can reach: v3's columns already, so
        // there is no `slot` to rename, under a version that does not describe
        // them. Stamped rather than stepped — and where the indexes did not
        // come with the columns, brought the rest of the way first.
        //
        // Checked **before** the `found == V3` return below, and
        // for any version this build can open, not only for 2. That return was
        // what made an incomplete v3 permanent, and this change's own builds
        // produced one: in the `e391b72 … 1195546^` window the arm stamped the
        // version and ran no index DDL, so a `pool.db` any of them opened is at
        // `user_version = 3` carrying either no index on `profile` or the old
        // `torrent_by_slot` still sitting over the renamed column. Returning at
        // the version meant nothing ever looked, nothing ever repaired it, and
        // nothing ever said so — while both operator-facing texts promise the
        // file ends with `torrent_by_profile` and nothing called
        // `torrent_by_slot`.
        //
        // Any version this build can open, including 0 and 1. The guard was
        // `found >= 2`, on the stated reason that "below that there is no
        // `torrent` table to index yet" — which is false for the population
        // this arm exists for. A build predating the one-transaction migration
        // ran the schema steps as separate `execute_batch` calls with the
        // `PRAGMA` after them, so an interruption between the last DDL commit
        // and the version write leaves 0 or 1 over a **complete, correct v3
        // schema**. Both were demonstrated: exit 1, the migration wedged
        // permanently under `Restart=on-failure`, and the only remedy the
        // message offered that works destroys the `plan`/`plan_step` journal.
        //
        // Those files are a strictly easier case than the ones this arm
        // already repairs, not a harder one: `carries_v3_columns` and
        // `has_torrent_index("torrent_by_profile")` both answer true, so the
        // file's schema is already exactly what this arm would produce, and
        // nothing is being guessed at. A file at 0 or 1 that is *not* already
        // v3 still fails the column test — a genuine v1 or v2 index has `slot`
        // and no `profile`, and an empty file has no `torrent` table for
        // `PRAGMA table_info` to report — so every one of them goes down the
        // stepped path exactly as before.
        //
        // Before the backup, and without one: the rename is v3's only
        // irreversible statement and it has already run here, so what is left
        // destroys nothing — an index is derivable from the table it indexes.
        // A stray `.pre-v3.bak` beside a healthy index reads as a failed
        // migration, which the fresh-database test states as a property.
        //
        // Below v3 the file must also carry v2's tables, or it is not the
        // complete v3 schema this arm stamps: a build interrupted between
        // `SCHEMA_V1` and `SCHEMA_V2` left v3's columns and indexes with no
        // `plan` / `plan_step`. That file goes down the stepped path, which
        // fails on `SCHEMA_V1` and says to rebuild with `pool scan` — which
        // costs nothing here, because the journal it would lose was never
        // created.
        if found >= 0 && self.carries_v3_columns()? && (found == V3 || self.has_v2_tables()?) {
            let indexed = self.has_torrent_index("torrent_by_profile")?;
            // `torrent_by_slot` surviving is a defect in its own right, not
            // merely a symptom of `torrent_by_profile` being absent. Keying
            // the repair on the *new* index being missing meant a file
            // carrying both came out of here still carrying both: at version 2
            // it was stamped to 3 with the stale name intact, and at version 3
            // it returned below having had nothing done and nothing said — no
            // log line at all — while `docs/running.md` promises,
            // unconditionally, that "after this open the file has
            // `torrent_by_profile` and nothing called `torrent_by_slot`".
            // Both demonstrated.
            //
            // `SCHEMA_V3_INDEXES` is written to tolerate the work already
            // being done (`DROP … IF EXISTS`, `CREATE … IF NOT EXISTS`), so
            // running it for a stale name is the same statement pair either
            // way.
            let stale = self.has_torrent_index("torrent_by_slot")?;
            if found == V3 && indexed && !stale {
                // An ordinary v3 open: the version and the schema agree.
                return Ok(());
            }
            // One transaction over the index statements and the stamp, for
            // the reason the stepped path has one: a stamp that commits
            // without them is the state this arm exists to end.
            self.conn.execute_batch("BEGIN IMMEDIATE")?;
            let repaired = (|| -> Result<(), PoolError> {
                if !indexed || stale {
                    self.conn.execute_batch(SCHEMA_V3_INDEXES)?;
                }
                self.conn.pragma_update(None, "user_version", V3)?;
                Ok(())
            })();
            if let Err(e) = repaired {
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e);
            }
            self.conn.execute_batch("COMMIT")?;
            match (found == V3, indexed && !stale) {
                (false, true) => warn!(
                    target: "torrentd_pool::store",
                    from_version = found,
                    to_version = V3,
                    indexes_repaired = false,
                    "pool index already carries the v3 schema under a user_version that does not \
                     describe it; stamping the version to match. A superseded build of this \
                     change wrote this file with v3's schema and an earlier version — either \
                     stamping 2 deliberately, or dying between the last schema statement and the \
                     version write, which can leave 0 or 1. No schema change was made and no \
                     data moved",
                ),
                (false, false) => warn!(
                    target: "torrentd_pool::store",
                    from_version = found,
                    to_version = V3,
                    indexes_repaired = true,
                    "pool index carries the v3 schema under a user_version that does not describe \
                     it, but not v3's indexes; creating torrent_by_profile, dropping \
                     torrent_by_slot if it survived the rename, and stamping the version to \
                     match. A superseded build of this change wrote this file with the column \
                     rename committed and an index statement lost. No data moved",
                ),
                (true, false) => warn!(
                    target: "torrentd_pool::store",
                    from_version = found,
                    to_version = V3,
                    indexes_repaired = true,
                    "pool index reports user_version = 3 but its indexes are not the set v3 \
                     describes; creating torrent_by_profile if it is missing and dropping \
                     torrent_by_slot if it survived the rename. A superseded build of this change \
                     stamped the version over a schema whose index statements had been lost — or \
                     left the old index name beside the new one — and the version being correct \
                     is why nothing repaired it until now. No data moved",
                ),
                // Returned above: the version and the schema already agree.
                (true, true) => unreachable!("an ordinary v3 open returns before the repair"),
            }
            return Ok(());
        }
        if found == V3 {
            return Ok(());
        }
        // Outside the transaction: VACUUM cannot run inside one. Only for a
        // database that already exists — `found >= 1` — because there is
        // nothing to preserve in a file this call is about to create.
        let fresh_backup = if found >= 1 {
            self.backup_before_v3()?
        } else {
            None
        };

        if let Err(e) = self.conn.execute_batch("BEGIN IMMEDIATE") {
            Self::promote_fresh_backup(fresh_backup, false);
            return Err(e.into());
        }
        let stepped = (|| -> Result<(), PoolError> {
            if found < 1 {
                self.conn.execute_batch(SCHEMA_V1)?;
            }
            if found < 2 {
                self.conn.execute_batch(SCHEMA_V2)?;
            }
            if found < 3 {
                self.conn.execute_batch(SCHEMA_V3)?;
            }
            self.conn.pragma_update(None, "user_version", V3)?;
            Ok(())
        })();
        // Settled whichever way the transaction ends, before any `?` below
        // can return past it.
        let stepped =
            stepped.and_then(|()| self.conn.execute_batch("COMMIT").map_err(PoolError::from));
        Self::promote_fresh_backup(fresh_backup, stepped.is_ok());
        match stepped {
            Ok(()) => {
                info!(
                    target: "torrentd_pool::store",
                    from_version = found,
                    to_version = V3,
                    "pool schema migrated",
                );
                Ok(())
            }
            Err(e) => {
                // Roll back first; a rollback that itself fails means the
                // connection is unusable either way, and `open` returns the
                // error that says what went wrong.
                let _ = self.conn.execute_batch("ROLLBACK");
                // Wrapped, not propagated, for the reason `BackupFailed` is:
                // `startup.rs` opens the pool with `?` under
                // `Restart=on-failure`, so whatever comes out of here is the
                // whole of what the operator sees, on a loop. A bare SQLite
                // code named no file, no step, and no way out — and the
                // reachable shape is not a corrupt database but a file a build
                // predating the one-transaction migration left with its schema
                // ahead of its `user_version`, where the code that surfaces is
                // `table root already exists` followed by the schema text.
                // Not repaired here: nothing in this file can tell which of
                // those steps ran, and guessing is how an index gets stamped
                // over a schema that is not the one it claims.
                //
                // The remedy naming `.pre-v3.bak` is qualified for a reason
                // this site is where you can see: `backup_before_v3` ran a few
                // lines above, immediately before the steps that just failed.
                // So on this path the copy beside the index is normally one
                // *this run* took, of the index exactly as it stands, and
                // restoring it walks the operator back into the same failure.
                Err(PoolError::MigrationFailed {
                    path: self
                        .conn
                        .path()
                        .filter(|p| !p.is_empty())
                        .unwrap_or("<in-memory>")
                        .to_string(),
                    from: found,
                    to: V3,
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Step a v3 file to v4: one transaction over the additive DDL and the
    /// version write, for the reason [`PoolStore::migrate`] gives.
    ///
    /// The column is added only where it is absent, so a file that carries it
    /// under a version that does not say so is stamped rather than failed.
    fn migrate_v4(&self) -> Result<(), PoolError> {
        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found >= SCHEMA_VERSION {
            return Ok(());
        }
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let stepped = (|| -> Result<(), PoolError> {
            let has_pad: i64 = self.conn.query_row(
                "SELECT count(*) FROM pragma_table_info('torrent_file') WHERE name = 'pad_file'",
                [],
                |r| r.get(0),
            )?;
            if has_pad == 0 {
                self.conn.execute_batch(SCHEMA_V4)?;
            } else {
                self.conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS pool_meta (
                         key TEXT PRIMARY KEY, value INTEGER NOT NULL) WITHOUT ROWID;",
                )?;
            }
            self.conn
                .pragma_update(None, "user_version", SCHEMA_VERSION)?;
            Ok(())
        })();
        let stepped =
            stepped.and_then(|()| self.conn.execute_batch("COMMIT").map_err(PoolError::from));
        match stepped {
            Ok(()) => {
                info!(
                    target: "torrentd_pool::store",
                    from_version = found,
                    to_version = SCHEMA_VERSION,
                    "pool schema migrated",
                );
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(PoolError::MigrationFailed {
                    path: self
                        .conn
                        .path()
                        .filter(|p| !p.is_empty())
                        .unwrap_or("<in-memory>")
                        .to_string(),
                    from: found,
                    to: SCHEMA_VERSION,
                    reason: e.to_string(),
                })
            }
        }
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
        let tx = self.conn.savepoint()?;
        tx.execute("DELETE FROM file WHERE root_id = ?1", params![root_id])?;
        {
            let mut ins = tx.prepare(
                "INSERT INTO file(root_id, rel_path, size, mtime_ns, ino, dev, v2_root, scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for f in files {
                ins.execute(params![
                    root_id,
                    f.rel_path,
                    f.size as i64,
                    f.mtime_ns,
                    f.ino as i64,
                    f.dev as i64,
                    f.v2_root.map(|r| r.to_vec()),
                    scanned_at,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
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

    pub fn file_count(&self) -> Result<u64, PoolError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM file", [], |r| r.get::<_, i64>(0))? as u64)
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
    pub fn rollup(&self, root_id: i64, prefix: &str) -> Result<DirRollup, PoolError> {
        // `prefix` is a directory path; "" means the whole root. GLOB-free
        // prefix match via range comparison keeps the index usable.
        let like = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let upper = prefix_upper_bound(&like);

        let (bytes_total, files_total): (i64, i64) = self.conn.query_row(
            "SELECT COALESCE(SUM(size),0), COUNT(*) FROM file
             WHERE root_id = ?1 AND rel_path >= ?2 AND rel_path < ?3",
            params![root_id, like, upper],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let (bytes_adopted, bytes_matched): (i64, i64) = self.conn.query_row(
            "SELECT
               COALESCE(SUM(CASE WHEN a.state = 'adopted' THEN f.size ELSE 0 END),0),
               COALESCE(SUM(CASE WHEN a.state = 'matched' THEN f.size ELSE 0 END),0)
             FROM file f
             JOIN claim c ON c.root_id = f.root_id AND c.rel_path = f.rel_path
             JOIN adoption a ON a.infohash = c.infohash
             WHERE f.root_id = ?1 AND f.rel_path >= ?2 AND f.rel_path < ?3",
            params![root_id, like, upper],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let (bytes_orphan, files_orphan): (i64, i64) = self.conn.query_row(
            "SELECT COALESCE(SUM(f.size),0), COUNT(*) FROM file f
             WHERE f.root_id = ?1 AND f.rel_path >= ?2 AND f.rel_path < ?3
               AND NOT EXISTS (
                 SELECT 1 FROM claim c
                 WHERE c.root_id = f.root_id AND c.rel_path = f.rel_path
               )",
            params![root_id, like, upper],
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

    /// Every file under `prefix` that no torrent claims.
    ///
    /// This is the only query a delete plan is allowed to build from: a file is
    /// a deletion candidate solely because nothing in the library references
    /// it, never because it merely looks unused.
    pub fn orphan_files(&self, root_id: i64, prefix: &str) -> Result<Vec<String>, PoolError> {
        Ok(self
            .orphan_files_sized(root_id, prefix)?
            .into_iter()
            .map(|(p, _)| p)
            .collect())
    }

    /// [`PoolStore::orphan_files`], with each file's indexed size.
    pub fn orphan_files_sized(
        &self,
        root_id: i64,
        prefix: &str,
    ) -> Result<Vec<(String, u64)>, PoolError> {
        let like = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let upper = prefix_upper_bound(&like);
        let mut st = self.conn.prepare(
            "SELECT f.rel_path, f.size FROM file f
             WHERE f.root_id = ?1 AND f.rel_path >= ?2 AND f.rel_path < ?3
               AND NOT EXISTS (
                 SELECT 1 FROM claim c
                 WHERE c.root_id = f.root_id AND c.rel_path = f.rel_path
               )
             ORDER BY f.rel_path",
        )?;
        let rows = st.query_map(params![root_id, like, upper], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
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
        let like = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let upper = prefix_upper_bound(&like);
        let mut st = self.conn.prepare(
            "SELECT DISTINCT a.state
             FROM claim c
             JOIN adoption a ON a.infohash = c.infohash
             WHERE c.root_id = ?1
               AND ((?2 = '' ) OR (c.rel_path >= ?2 AND c.rel_path < ?3) OR c.rel_path = ?4)",
        )?;
        // The trailing `= ?4` clause catches the case where `prefix` names a
        // file rather than a directory, which has no '/'-terminated children.
        let rows = st.query_map(
            params![root_id, like, upper, prefix.trim_matches('/')],
            |r| r.get::<_, String>(0),
        )?;
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
    /// browser. Directories are inferred from paths, not stored.
    pub fn children(&self, root_id: i64, prefix: &str) -> Result<Vec<(String, bool)>, PoolError> {
        let like = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let upper = prefix_upper_bound(&like);
        let mut st = self.conn.prepare(
            "SELECT rel_path FROM file
             WHERE root_id = ?1 AND rel_path >= ?2 AND rel_path < ?3",
        )?;
        let rows = st.query_map(params![root_id, like, upper], |r| r.get::<_, String>(0))?;

        let mut seen: HashMap<String, bool> = HashMap::new();
        for row in rows {
            let full = row?;
            let rest = &full[like.len()..];
            match rest.split_once('/') {
                Some((dir, _)) => {
                    seen.insert(format!("{like}{dir}"), true);
                }
                None => {
                    seen.insert(full, false);
                }
            }
        }
        let mut out: Vec<(String, bool)> = seen.into_iter().collect();
        // Directories first, then lexicographic — the order a file browser
        // wants, computed here so the client doesn't re-sort a large page.
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(out)
    }
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
