//! The materialised directory tree — byte rollups per directory — and the
//! queries that read it: orphans, foreign files, children and listing pages.

use std::collections::HashMap;
use std::collections::HashSet;

use rusqlite::params;
use rusqlite::OptionalExtension;

use super::parent_of;
use super::row_to_torrent;
use super::PoolStore;
use super::SizedOrphan;
use super::TorrentListing;
use crate::model::AdoptionState;
use crate::model::DirRollup;
use crate::model::PoolError;

impl PoolStore {
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
    ///
    /// An empty file at a declared empty path of a torrent placed in the
    /// root is not counted as an orphan, as in [`PoolStore::orphan_files`].
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

            let declared = st.declared_empty_paths(root_id)?;
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
                    let orphan = !claimed && (size > 0 || !declared.contains(&rel));
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
                        if orphan {
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
    ///
    /// An empty file at the path of a declared empty file of a torrent placed
    /// in this root is that torrent's, and is not listed: the matcher claims
    /// no file without bytes, so it has no claim row (see
    /// [`PoolStore::declared_empty_paths`]).
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
        let rows = rows.collect::<Result<Vec<SizedOrphan>, _>>()?;
        if !rows.iter().any(|(_, size, _)| *size == 0) {
            return Ok(rows);
        }
        let declared = self.declared_empty_paths(root_id)?;
        Ok(rows
            .into_iter()
            .filter(|(rel, size, _)| *size > 0 || !declared.contains(rel))
            .collect())
    }

    /// The root-relative path of every declared empty file of every torrent
    /// placed in `root_id`: its torrent-relative path under the torrent's
    /// recorded base. Padding entries are never written, so none is listed.
    ///
    /// The matcher claims no file without bytes, so an empty file at one of
    /// these paths has no claim row, yet it is that torrent's payload: a
    /// delete that took it would take a file the torrent declares.
    pub fn declared_empty_paths(&self, root_id: i64) -> Result<HashSet<String>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT a.base_rel, t.rel_path FROM torrent_file t
             JOIN adoption a ON a.infohash = t.infohash
             WHERE t.size = 0 AND t.pad_file = 0
               AND a.root_id = ?1 AND a.base_rel IS NOT NULL",
        )?;
        let rows = st.query_map(params![root_id], |r| {
            Ok(super::join_rel(
                &r.get::<_, String>(0)?,
                &r.get::<_, String>(1)?,
            ))
        })?;
        Ok(rows.collect::<Result<HashSet<_>, _>>()?)
    }

    /// Whether `rel_path` is a declared empty file of a torrent placed in
    /// `root_id`: the single-path form of [`PoolStore::declared_empty_paths`].
    ///
    /// Driven from the root's adoptions, and only a torrent whose recorded
    /// base is an ancestor of `rel_path` has its file rows read, so the cost
    /// never grows with the number of declared empty files in the root. The
    /// path comparison is [`super::join_rel`]'s, written in SQL.
    fn is_declared_empty(&self, root_id: i64, rel_path: &str) -> Result<bool, PoolError> {
        let declared: i64 = self.conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM adoption a CROSS JOIN torrent_file t
                WHERE a.root_id = ?1 AND a.base_rel IS NOT NULL
                  AND (trim(a.base_rel, '/') = ''
                       OR substr(?2, 1, length(trim(a.base_rel, '/')) + 1)
                          = trim(a.base_rel, '/') || '/')
                  AND t.infohash = a.infohash
                  AND t.size = 0 AND t.pad_file = 0
                  AND trim(t.rel_path, '/') = CASE
                        WHEN trim(a.base_rel, '/') = '' THEN ?2
                        ELSE substr(?2, length(trim(a.base_rel, '/')) + 2)
                      END
             )",
            params![root_id, rel_path],
            |r| r.get(0),
        )?;
        Ok(declared != 0)
    }

    /// Files under `(root_id, prefix)` that `infohash` does **not** claim.
    ///
    /// A relocate moves a whole directory, so the only way that is safe is if
    /// the directory holds nothing but this torrent's payload. Anything else
    /// under there — another torrent's files, or unclaimed bytes — would be
    /// dragged along by the rename without appearing anywhere in the plan.
    ///
    /// An empty file at the path of one of this torrent's declared empty
    /// files is its own: the matcher claims no file without bytes, so it has
    /// no claim row, yet it is part of the payload the rename carries.
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
               AND NOT (f.size = 0 AND EXISTS (
                 SELECT 1 FROM torrent_file t
                 WHERE t.infohash = ?4 AND t.size = 0 AND t.pad_file = 0
                   AND ?2 || t.rel_path = f.rel_path
               ))
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
    /// and scanning it would be O(pool) per file. An empty file that is a
    /// placed torrent's declared empty file is not an orphan, as there.
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
        let size: Option<i64> = self
            .conn
            .query_row(
                "SELECT size FROM file WHERE root_id = ?1 AND rel_path = ?2",
                params![root_id, rel_path],
                |r| r.get(0),
            )
            .optional()?;
        match size {
            None => Ok(false),
            Some(0) => Ok(!self.is_declared_empty(root_id, rel_path)?),
            Some(_) => Ok(true),
        }
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
    /// with its adoption state, the base it was matched at and the note the
    /// match left, optionally only those in `state`.
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
                note: r.get(14)?,
            })
        };
        let rows = match state {
            None => {
                let mut st = self.conn.prepare_cached(
                    "SELECT t.infohash, t.infohash_v1, t.infohash_v2, t.name, t.total_size,
                            t.num_files, t.source_path, t.fastresume_path, t.declared_save_path,
                            t.category, t.tags, t.profile, a.state,
                            CASE WHEN a.root_id IS NOT NULL THEN a.base_rel END, a.last_error
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
                            CASE WHEN a.root_id IS NOT NULL THEN a.base_rel END, a.last_error
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
