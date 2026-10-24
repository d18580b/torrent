//! Managed roots and the file index under them: registering and retiring
//! roots, and staging a root walk into the index whole.

use std::path::Path;
use std::path::PathBuf;

use rusqlite::params;
use rusqlite::OptionalExtension;
use tracing::info;
use tracing::warn;

use super::parent_of;
use super::row_to_file;
use super::PoolStore;
use super::STAGE_BATCH;
use crate::model::AdoptionState;
use crate::model::PoolError;
use crate::model::PoolFile;

impl PoolStore {
    // -- roots -------------------------------------------------------------

    /// Register a managed root, returning its id. Idempotent.
    ///
    /// `root.enabled` is left at its default of 1 and never read: a root is
    /// in the index exactly while it is configured, and
    /// [`PoolStore::retain_roots`] drops the rest. The column stays so the
    /// schema does not change for it.
    pub fn upsert_root(&self, path: &Path) -> Result<i64, PoolError> {
        let p = path.to_string_lossy();
        self.conn.execute(
            "INSERT INTO root(path) VALUES (?1) ON CONFLICT(path) DO NOTHING",
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
            .prepare("SELECT id, path FROM root ORDER BY path")?;
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

    /// Stage `root_id`'s current index rows at `rel_path` and under it, as
    /// they stand, for a subtree the walk could not read. Returns how many
    /// rows were carried.
    ///
    /// A walk that could not list a directory saw none of what is in it, so
    /// the swap would otherwise drop that subtree's rows: the matcher would
    /// read every torrent over it as `missing`, though nothing on disk is
    /// known to have changed. A row the walk did stage is left as staged.
    pub fn stage_previous_subtree(
        &mut self,
        root_id: i64,
        rel_path: &str,
    ) -> Result<u64, PoolError> {
        let rel_path = rel_path.trim_matches('/');
        // `/` sorts immediately before `0`, so the half-open range is exactly
        // the paths below `rel_path/`, and it reads the primary key's order.
        let carried = self.conn.execute(
            "INSERT OR IGNORE INTO temp.file_staging(rel_path, parent, size, mtime_ns, ino, dev, v2_root)
             SELECT rel_path, parent, size, mtime_ns, ino, dev, v2_root
             FROM file
             WHERE root_id = ?1
               AND (rel_path = ?2 OR (rel_path >= ?2 || '/' AND rel_path < ?2 || '0'))",
            params![root_id, rel_path],
        )?;
        Ok(carried as u64)
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
}
