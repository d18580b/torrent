//! The torrent library — each `.torrent` and its file list — and the owner
//! record each torrent's `profile` column caches.

use std::collections::HashMap;

use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use tracing::info;
use tracing::warn;

use super::row_to_torrent;
use super::to_root32;
use super::PoolStore;
use crate::model::PoolError;
use crate::model::PoolTorrent;
use crate::model::TorrentFileRow;

impl PoolStore {
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

    /// Move `infohash`'s owner record from `from` to `to`, where it still
    /// names `from`. Returns whether it did.
    ///
    /// For an owner the assignment registry, the authority, gives another
    /// profile than the record does. Conditional, so a record that changed
    /// since `from` was read is left as it now stands.
    pub fn rewrite_owner(&self, infohash: &str, from: &str, to: &str) -> Result<bool, PoolError> {
        Ok(self.conn.execute(
            "UPDATE torrent SET profile = ?3 WHERE infohash = ?1 AND profile = ?2",
            params![infohash, from, to],
        )? > 0)
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
}
