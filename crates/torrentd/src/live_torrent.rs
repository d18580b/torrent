//! Where a session says a torrent it holds keeps its payload, as the delete
//! plan's ownership guard, the relocate step and `DELETE
//! /v1/torrents/{infohash}?delete_files=true` compare it with the files they
//! act on.

use std::path::Path;
use std::sync::Arc;

use torrentd_engine::AlertSource;

/// Why [`read_live_torrent`] could not read a torrent from its session.
#[derive(Debug)]
pub enum LiveReadError {
    /// The profile holding it has no session.
    NoSession,
    /// Its session could not report it.
    Engine(torrentd_engine::EngineError),
}

/// Where the session of the profile holding `st` says its payload lies:
/// its save path and, once its metadata has arrived, its files.
pub fn read_live_torrent(
    source: &Arc<dyn AlertSource>,
    st: &torrentd_engine::TorrentState,
) -> Result<LiveTorrent, LiveReadError> {
    let engine = source
        .engine_for(&st.profile_id)
        .ok_or(LiveReadError::NoSession)?;
    let details = engine
        .torrent_details(st.handle)
        .map_err(LiveReadError::Engine)?;
    let files = engine
        .torrent_files(st.handle)
        .map_err(LiveReadError::Engine)?
        .map(|fs| fs.into_iter().map(|f| f.path).collect());
    Ok(LiveTorrent {
        save_path: details.save_path.into(),
        files,
    })
}

/// Another torrent a session holds, as [`TorrentPayload::shared_with`]
/// compares it: where its session says its payload lies.
#[derive(Debug)]
pub struct LiveTorrent {
    /// The session's save path for it.
    pub save_path: std::path::PathBuf,
    /// Its files, torrent-relative and `/`-separated, or `None` while its
    /// metadata has not arrived.
    pub files: Option<Vec<String>>,
}

impl LiveTorrent {
    /// The first path at which this torrent serves a file from under `dir`,
    /// or `None` when it serves none from there: the directory-level
    /// counterpart of [`TorrentPayload::shared_with`], for a move that
    /// renames `dir` whole.
    ///
    /// Paths are compared as the session spells them and with their
    /// symlinks resolved, on both sides, so a save path reaching `dir`
    /// through a symlink, a symlinked directory below it, and a file that
    /// is itself a symlink into `dir` are all caught. A file not written
    /// yet resolves through its parent. A torrent whose metadata has not
    /// arrived could write any file under its save path, so it serves from
    /// `dir` when its save path is `dir`, above it, or below it; the path
    /// returned is then its save path.
    pub fn file_under(&self, dir: &Path) -> Option<std::path::PathBuf> {
        let dirs: Vec<std::path::PathBuf> = std::iter::once(dir.to_path_buf())
            .chain(std::fs::canonicalize(dir).ok())
            .collect();
        let bases = self.bases();
        let under = |p: &Path| dirs.iter().any(|d| p.starts_with(d));
        let Some(files) = &self.files else {
            return bases
                .iter()
                .any(|b| under(b) || dirs.iter().any(|d| d.starts_with(b)))
                .then(|| self.save_path.clone());
        };
        files.iter().find_map(|rel| {
            let hit = bases.iter().any(|b| under(&b.join(rel)))
                || self.resolved(rel).as_deref().is_some_and(under);
            hit.then(|| self.save_path.join(rel))
        })
    }

    /// Its save path as the session spells it, then with its symlinks
    /// resolved where it resolves: the two bases every comparison of its
    /// files joins them to.
    pub(crate) fn bases(&self) -> Vec<std::path::PathBuf> {
        std::iter::once(self.save_path.clone())
            .chain(std::fs::canonicalize(&self.save_path).ok())
            .collect()
    }

    /// Where its file `rel` lies with every symlink on its full path
    /// resolved. A file not written yet resolves through its parent, so a
    /// symlinked directory below the save path leads there all the same.
    pub(crate) fn resolved(&self, rel: &str) -> Option<std::path::PathBuf> {
        let joined = self.save_path.join(rel);
        std::fs::canonicalize(&joined).ok().or_else(|| {
            let parent = std::fs::canonicalize(joined.parent()?).ok()?;
            Some(parent.join(joined.file_name()?))
        })
    }
}
