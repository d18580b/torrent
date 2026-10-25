//! The persisted verify queue, and the index generation a destructive plan's
//! confirm token is bound to.

use std::path::PathBuf;

use rusqlite::params;
use rusqlite::OptionalExtension;

use super::PoolStore;
use crate::model::PoolError;
use crate::model::VerifyQueueRow;

impl PoolStore {
    /// Record an adoption the verify queue now holds, at the back of the
    /// queue. An info-hash already recorded keeps its place and takes the new
    /// row's values.
    pub fn enqueue_verify(&self, row: &VerifyQueueRow) -> Result<(), PoolError> {
        use std::os::unix::ffi::OsStrExt;
        let trackers = serde_json::to_string(&row.trackers)
            .map_err(|e| PoolError::Io(std::io::Error::other(e)))?;
        let now = crate::now_secs();
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
}
