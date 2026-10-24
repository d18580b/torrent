//! The index's schema, version by version, and the migrations that walk a
//! file forward to the current one.

use std::path::Path;

use rusqlite::params;
use rusqlite::Connection;
use tracing::info;
use tracing::warn;

use super::PoolStore;
use crate::model::PoolError;

/// Bumped whenever the schema changes; `migrate` walks forward from whatever
/// the file reports. A file from the future is refused rather than guessed at.
pub(super) const SCHEMA_VERSION: i64 = 7;

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

impl PoolStore {
    /// Suffix of the copy [`PoolStore::migrate`] leaves before the v2 → v3
    /// rename; restoring it is the way back to a build that predates v3.
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
    pub(super) fn migrate(&mut self) -> Result<(), PoolError> {
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
    pub(super) fn migrate_v4(&mut self) -> Result<(), PoolError> {
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
    pub(super) fn migrate_v5(&mut self) -> Result<(), PoolError> {
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
    pub(super) fn migrate_v6(&mut self) -> Result<(), PoolError> {
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
    pub(super) fn migrate_v7(&mut self) -> Result<(), PoolError> {
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
}
