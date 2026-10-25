//! Each torrent's adoption state, and the claim rows that say which files
//! it protects.

use std::collections::HashMap;

use rusqlite::params;
use rusqlite::OptionalExtension;

use super::PoolStore;
use crate::model::AdoptionState;
use crate::model::PoolError;

impl PoolStore {
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

    /// `(root_id, base_rel)` recorded for a torrent, in that order: the root
    /// its payload was matched in and the payload's base directory relative
    /// to it. `None` when the torrent has no adoption row, or its row records
    /// no root or no base (a torrent never matched, or one whose root has
    /// since left the index, which nulls `root_id`), whatever its state.
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
}
