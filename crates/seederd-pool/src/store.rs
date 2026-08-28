//! SQLite-backed pool index.
//!
//! A managed root can hold millions of files, which is past what the daemon's
//! existing JSON-file conventions carry — and the web client needs to sort,
//! filter and paginate over that set without shipping it all to the browser.
//! One transactional file serves the file index, the torrent library, adoption
//! state, and the torrent→slot registry that used to live in
//! `slot_assignments.json`.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::Transaction;
use tracing::info;
use tracing::warn;

use crate::model::AdoptionState;
use crate::model::DirRollup;
use crate::model::PoolError;
use crate::model::PoolFile;
use crate::model::PoolTorrent;
use crate::model::TorrentFileRow;

/// Bumped whenever the schema changes; `migrate` walks forward from whatever
/// the file reports. A file from the future is refused rather than guessed at.
const SCHEMA_VERSION: i64 = 1;

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

pub struct PoolStore {
    conn: Connection,
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
        // HTTP layer's reads. NORMAL is the right durability trade here: every
        // row is reconstructible by rescanning, so trading an fsync per commit
        // for throughput over millions of rows is worth it.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

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
        if found < 1 {
            self.conn.execute_batch(SCHEMA_V1)?;
        }
        if found != SCHEMA_VERSION {
            self.conn
                .pragma_update(None, "user_version", SCHEMA_VERSION)?;
            info!(
                target: "seederd_pool::store",
                from_version = found,
                to_version = SCHEMA_VERSION,
                "pool schema migrated",
            );
        }
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
        let tx = self.conn.transaction()?;
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

    /// Look a file up by its v2 merkle root — content-addressed, so it finds
    /// the file wherever it now lives.
    pub fn file_by_v2_root(
        &self,
        root_id: i64,
        v2_root: &[u8; 32],
    ) -> Result<Option<String>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT rel_path FROM file WHERE root_id = ?1 AND v2_root = ?2",
                params![root_id, v2_root.to_vec()],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn set_file_v2_root(
        &self,
        root_id: i64,
        rel_path: &str,
        v2_root: &[u8; 32],
    ) -> Result<(), PoolError> {
        self.conn.execute(
            "UPDATE file SET v2_root = ?3 WHERE root_id = ?1 AND rel_path = ?2",
            params![root_id, rel_path, v2_root.to_vec()],
        )?;
        Ok(())
    }

    // -- torrents ----------------------------------------------------------

    pub fn upsert_torrent(&self, t: &PoolTorrent, added_at: i64) -> Result<(), PoolError> {
        self.conn.execute(
            "INSERT INTO torrent(infohash, infohash_v1, infohash_v2, name, total_size,
                                 num_files, source_path, fastresume_path, declared_save_path,
                                 category, tags, slot, added_at)
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
                slot               = COALESCE(excluded.slot, torrent.slot)",
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
                t.slot,
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
        let tx = self.conn.transaction()?;
        Self::replace_torrent_files_tx(&tx, infohash, files)?;
        tx.commit()?;
        Ok(())
    }

    fn replace_torrent_files_tx(
        tx: &Transaction<'_>,
        infohash: &str,
        files: &[TorrentFileRow],
    ) -> Result<(), PoolError> {
        tx.execute(
            "DELETE FROM torrent_file WHERE infohash = ?1",
            params![infohash],
        )?;
        let mut ins = tx.prepare(
            "INSERT INTO torrent_file(infohash, idx, rel_path, size, pieces_root)
             VALUES (?1,?2,?3,?4,?5)",
        )?;
        for f in files {
            ins.execute(params![
                infohash,
                f.idx,
                f.rel_path,
                f.size as i64,
                f.pieces_root.map(|r| r.to_vec()),
            ])?;
        }
        Ok(())
    }

    pub fn torrent(&self, infohash: &str) -> Result<Option<PoolTorrent>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT infohash, infohash_v1, infohash_v2, name, total_size, num_files,
                        source_path, fastresume_path, declared_save_path, category, tags, slot
                 FROM torrent WHERE infohash = ?1",
                params![infohash],
                row_to_torrent,
            )
            .optional()?)
    }

    pub fn torrents(&self) -> Result<Vec<PoolTorrent>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT infohash, infohash_v1, infohash_v2, name, total_size, num_files,
                    source_path, fastresume_path, declared_save_path, category, tags, slot
             FROM torrent ORDER BY infohash",
        )?;
        let rows = st.query_map([], row_to_torrent)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn torrent_files(&self, infohash: &str) -> Result<Vec<TorrentFileRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT infohash, idx, rel_path, size, pieces_root
             FROM torrent_file WHERE infohash = ?1 ORDER BY idx",
        )?;
        let rows = st.query_map(params![infohash], |r| {
            Ok(TorrentFileRow {
                infohash: r.get(0)?,
                idx: r.get(1)?,
                rel_path: r.get(2)?,
                size: r.get::<_, i64>(3)? as u64,
                pieces_root: r.get::<_, Option<Vec<u8>>>(4)?.and_then(to_root32),
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

    // -- slot assignment (absorbs slot_assignments.json) --------------------

    pub fn slot_of(&self, infohash: &str) -> Result<Option<String>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT slot FROM torrent WHERE infohash = ?1",
                params![infohash],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn set_slot(&self, infohash: &str, slot: Option<&str>) -> Result<(), PoolError> {
        self.conn.execute(
            "UPDATE torrent SET slot = ?2 WHERE infohash = ?1",
            params![infohash, slot],
        )?;
        Ok(())
    }

    /// Fold a legacy `slot_assignments.json` in. Existing assignments win, so
    /// re-running is safe and the JSON can stay on disk as a backup.
    pub fn import_legacy_registry(
        &mut self,
        assignments: &HashMap<String, String>,
    ) -> Result<usize, PoolError> {
        let tx = self.conn.transaction()?;
        let mut n = 0usize;
        {
            let mut up =
                tx.prepare("UPDATE torrent SET slot = ?2 WHERE infohash = ?1 AND slot IS NULL")?;
            for (ih, slot) in assignments {
                n += up.execute(params![ih, slot])?;
            }
        }
        tx.commit()?;
        if n > 0 {
            info!(
                target: "seederd_pool::store",
                torrent_count = n,
                "imported legacy slot assignments",
            );
        }
        let unknown = assignments.len().saturating_sub(n);
        if unknown > 0 {
            // Torrents assigned to a slot but absent from the library: the
            // operator's `.torrent` files and their registry disagree.
            warn!(
                target: "seederd_pool::store",
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
        let tx = self.conn.transaction()?;
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

    pub fn clear_all_claims(&self) -> Result<(), PoolError> {
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
        slot: r.get(11)?,
    })
}
