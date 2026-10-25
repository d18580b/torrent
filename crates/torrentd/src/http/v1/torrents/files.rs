//! Files: `GET /v1/torrents/{infohash}/files` and a file's priority.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::security::auth::Scoped;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::TorrentEngine;

use super::is_gone;
use super::loaded;
use super::model::TorrentFilePath;
use super::model::TorrentPath;
use super::Lookup;
use crate::app_state::AppState;
use crate::http::page::page;
use crate::http::page::PageLimit;
use crate::http::page::PageRequest;
use crate::http::security::Bearer;
use crate::http::security::Read;
use crate::http::security::Write;
use crate::http::v1::common::blocking;
use crate::http::v1::common::internal;
use crate::http::v1::Torrents;
use crate::http::validate::from_invalid;
use crate::http::validate::Invalid;
use crate::http::validate::Unenforced;
use crate::http::validate::Validate;

/// The listing name file cursors are bound to.
const FILES_LISTING: &str = "files";

/// One file of a torrent.
#[derive(Debug, Schema, Serialize)]
pub struct TorrentFile {
    /// The file's index, which `PUT …/files/{index}/priority` takes.
    pub index: u32,
    /// Torrent-relative, `/`-separated; for a multi-file torrent it starts
    /// with the torrent's directory name.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Bytes of this file covered by complete, verified pieces.
    pub downloaded: u64,
    /// Download priority, 0 (skip) to 7 (top); 4 is the default.
    pub priority: u8,
}

impl From<torrentd_engine::TorrentFile> for TorrentFile {
    fn from(f: torrentd_engine::TorrentFile) -> Self {
        Self {
            index: f.index,
            path: f.path,
            size: f.size,
            downloaded: f.downloaded,
            priority: f.priority,
        }
    }
}

page!(
    /// One page of a torrent's files, in index order.
    TorrentFilePage,
    TorrentFile
);

/// Which page of files.
#[derive(Schema, QueryParams)]
pub struct ListFilesQuery {
    /// Resume after the page this cursor ended.
    pub cursor: Option<String>,
    /// Files per page, 1 to 1000; 100 when absent.
    pub limit: Option<PageLimit>,
}

/// The cursor key of file `index`: zero-padded, so the keys sort as the
/// indices do.
fn file_key(index: u32) -> String {
    format!("{index:0FILE_KEY_WIDTH$}")
}

/// Digits in a file cursor key: enough for every `u32`.
const FILE_KEY_WIDTH: usize = 10;

torrent_error! {
    /// Why a torrent's files could not be listed.
    pub enum ListFilesError {
        /// The cursor is not one this listing issued.
        #[error("the cursor is not one this listing issued; start again without it")]
        #[problem(status = 400, title = "Invalid cursor")]
        InvalidCursor,
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The torrent was added from a magnet and has no metadata yet.
        #[error("the torrent has no metadata yet; retry once it has a name")]
        #[problem(status = 409, title = "Metadata pending")]
        MetadataPending,
        /// A query parameter is out of range.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
        /// The session could not be asked.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(ListFilesError);
from_invalid!(ListFilesError);

/// List a torrent's files.
///
/// In index order, with size, bytes present and download priority, paged
/// with `cursor`. A magnet without metadata has no file list yet:
/// `409 metadata-pending`.
#[kynos::get("/torrents/{infohash}/files", tag = Torrents)]
pub async fn list_torrent_files(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
    Query(q): Query<ListFilesQuery>,
) -> Result<Json<TorrentFilePage>, ListFilesError> {
    let mut invalid = Invalid::new();
    // Scoped to the torrent, so one torrent's cursor is refused on another's
    // files rather than silently skipping into them.
    let listing = format!("{FILES_LISTING}:{}", p.infohash);
    let page = PageRequest::parse(
        &listing,
        q.cursor.as_deref(),
        q.limit.map(PageLimit::get),
        |key| crate::http::page::is_padded_decimal(key, FILE_KEY_WIDTH),
        &mut invalid,
    )
    .map_err(|_| ListFilesError::InvalidCursor)?;
    invalid.finish()?;
    let (st, engine) = loaded(&s, p.infohash.get())?;
    // The page starts strictly after the cursor's index. A key is a checked
    // ten-digit decimal, which can name an index past any torrent's last
    // file: that is an empty last page, as it was when the whole list was
    // read and skipped through.
    let start = page
        .after
        .as_deref()
        .and_then(|key| key.parse::<u64>().ok())
        .map_or(0, |after| u32::try_from(after + 1).unwrap_or(u32::MAX));
    let limit = u32::try_from(page.limit).unwrap_or(u32::MAX);
    // Only this page is copied out of the session, under its lock: every
    // engine call and the alert loop's drain wait on that lock, so a page of
    // a 250,000-file torrent must not copy the whole list. Still blocking
    // work, kept off the async workers.
    let files = match blocking_files(&engine, st.handle, start, limit).await {
        Ok(Some(files)) => files,
        Ok(None) => return Err(ListFilesError::MetadataPending),
        Err(e) if e.is_gone() => return Err(ListFilesError::TorrentNotFound),
        Err(e) => {
            return Err(ListFilesError::Internal {
                detail: internal("listing the torrent's files", e),
            })
        }
    };
    let next_cursor = files
        .files
        .last()
        .filter(|last| u64::from(last.index) + 1 < u64::from(files.total))
        .map(|last| crate::http::page::encode(&listing, &file_key(last.index)));
    Ok(Json(TorrentFilePage {
        items: files.files.into_iter().map(TorrentFile::from).collect(),
        next_cursor,
    }))
}

/// A file's download priority.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct FilePriority {
    /// libtorrent's download priority: 0 skips the file, 1 is low, 4 normal,
    /// 7 top.
    #[schema(minimum = 0, maximum = 7)]
    pub priority: u8,
}

impl Validate for FilePriority {
    fn validate(&self) -> Result<(), Invalid> {
        let mut invalid = Invalid::new();
        // Checked before it crosses the FFI boundary: libtorrent would read an
        // arbitrary byte however it happens to.
        invalid.check(self.priority <= 7, "/priority", || {
            "must be 0..=7 (0 = skip, 1 = low, 4 = normal, 7 = top)".to_owned()
        });
        invalid.finish()
    }
}

torrent_error! {
    /// Why a file's priority was not set.
    pub enum SetFilePriorityError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The torrent has no file at this index.
        #[error("the torrent has no file at this index")]
        #[problem(status = 404, title = "File not found")]
        FileNotFound,
        /// The torrent was added from a magnet and has no metadata yet.
        #[error("the torrent has no metadata yet; retry once it has a name")]
        #[problem(status = 409, title = "Metadata pending")]
        MetadataPending,
        /// A constraint the schema declares is broken.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(SetFilePriorityError);
from_invalid!(SetFilePriorityError);

/// Set a file's download priority.
///
/// Priority 0 skips the file. The torrent stays in upload mode whatever the
/// priority, so this decides what a later recheck or relocation expects, not
/// what is fetched. A magnet without metadata has no files yet:
/// `409 metadata-pending`.
#[kynos::put("/torrents/{infohash}/files/{index}/priority", tag = Torrents)]
pub async fn set_file_priority(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentFilePath>,
    Json(Unenforced(body)): Json<Unenforced<FilePriority>>,
) -> Result<NoContent, SetFilePriorityError> {
    body.validate()?;
    let (st, engine) = loaded(&s, p.infohash.get())?;
    // libtorrent ignores an index past the end without saying so; the file
    // list's length is what tells a missing file from a set priority. An
    // empty page reads it without copying a file.
    let count = match blocking_files(&engine, st.handle, 0, 0).await {
        Ok(Some(files)) => files.total as usize,
        Ok(None) => return Err(SetFilePriorityError::MetadataPending),
        Err(e) if e.is_gone() => return Err(SetFilePriorityError::TorrentNotFound),
        Err(e) => {
            return Err(SetFilePriorityError::Internal {
                detail: internal("listing the torrent's files", e),
            })
        }
    };
    let index = i32::try_from(p.index)
        .ok()
        .filter(|_| (p.index as usize) < count)
        .ok_or(SetFilePriorityError::FileNotFound)?;
    let priority = body.priority;
    match blocking(move || engine.set_file_priority(st.handle, index, priority)).await {
        Ok(()) => Ok(NoContent),
        // Removed between the count and the set.
        Err(e) if is_gone(&e) => Err(SetFilePriorityError::TorrentNotFound),
        Err(e) => Err(SetFilePriorityError::Internal {
            detail: internal("setting the file's priority", e),
        }),
    }
}

/// `engine.torrent_files_page(handle, start, limit)`, on the blocking pool.
///
/// A task that panicked is reported as the engine error it stands in for: the
/// listing was not produced, and the caller's `500` says so.
async fn blocking_files(
    engine: &Arc<dyn TorrentEngine>,
    handle: torrentd_engine::TorrentHandle,
    start: u32,
    limit: u32,
) -> Result<Option<torrentd_engine::FilePage>, FilesFailure> {
    let engine = Arc::clone(engine);
    match tokio::task::spawn_blocking(move || engine.torrent_files_page(handle, start, limit)).await
    {
        Ok(Ok(files)) => Ok(files),
        Ok(Err(e)) => Err(FilesFailure::Engine(e)),
        Err(join) => Err(FilesFailure::Task(join)),
    }
}

/// Why [`blocking_files`] produced no listing.
#[derive(Debug, thiserror::Error)]
enum FilesFailure {
    #[error(transparent)]
    Engine(torrentd_engine::EngineError),
    #[error("the file listing task failed: {0}")]
    Task(tokio::task::JoinError),
}

impl FilesFailure {
    /// The torrent left its session while it was being listed.
    fn is_gone(&self) -> bool {
        matches!(self, Self::Engine(e) if is_gone(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_cursor_keys_sort_as_the_indices_do() {
        let mut keys: Vec<String> = [10, 2, 1, 100, u32::MAX].map(file_key).to_vec();
        keys.sort();
        assert_eq!(keys, [1, 2, 10, 100, u32::MAX].map(file_key));
    }
}
