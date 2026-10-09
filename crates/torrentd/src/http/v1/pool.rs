//! The managed pool: the index of payload on disk, adoption of existing
//! payload, verification, and mutation plans.
//!
//! The tree listing is the primary read: it answers "what is under this path,
//! and how much of it is protected" without shipping a file listing to the
//! client, which is the only way this stays usable at petabyte scale.
//!
//! Every operation is mounted whatever the config, so the document is the same
//! on every daemon; without `[pool]` each answers `404 pool-not-configured`,
//! and `GET /v1/server` says so up front.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use kynos::prelude::*;
use kynos::schema::ParamValue;
use kynos::security::auth::Scoped;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use tracing::info;

use crate::app_state::AppState;
use crate::http::page::page;
use crate::http::page::paginate;
use crate::http::page::InvalidCursor;
use crate::http::page::PageLimit;
use crate::http::page::PageRequest;
use crate::http::security::Bearer;
use crate::http::security::Read;
use crate::http::security::Write;
use crate::http::v1::common::blocking;
use crate::http::v1::common::from_profile_problem;
use crate::http::v1::common::internal;
use crate::http::v1::common::unfenced_engine;
use crate::http::v1::common::InfoHashHex;
use crate::http::v1::server::count;
use crate::http::v1::Pool;
use crate::http::validate::from_invalid;
use crate::http::validate::Invalid;
use crate::http::validate::Validate;
use crate::pool_service::execute_adopt;
use crate::pool_service::PoolService;

/// The most infohashes one adoption or verification request may name.
pub const MAX_INFOHASHES: usize = 1000;

const NO_POOL: &str = "no [pool] section is configured on this daemon";

// ---------------------------------------------------------------------------
// Shared wire types
// ---------------------------------------------------------------------------

/// Where a torrent in the library stands relative to the payload on disk.
#[derive(Clone, Copy, Debug, Schema, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionState {
    /// No file of this torrent was found under any managed root.
    Missing,
    /// Some files resolved, others did not. Adoption is refused: seeding a
    /// partial torrent advertises pieces the daemon cannot serve.
    Partial,
    /// Every file resolved at a consistent base, but the torrent is not yet
    /// loaded into a session. Adoptable.
    Matched,
    /// Loaded into a session and seeding.
    Adopted,
    /// Was matched or adopted, but a covering file's stats moved since the
    /// last verification. Stays so across rescans until a verification
    /// clears it; adopting one always re-hashes it.
    Drifted,
    /// At least one file is claimed by another torrent too, and the two do
    /// not claim the same set. Blocks adoption and any mutation touching
    /// those files.
    Overlap,
    /// Complete, and every other torrent claiming any of these files claims
    /// exactly the same set — one payload under several info-hashes, as
    /// cross-seeding produces. Adoptable, each torrent into the profile the
    /// request names; never moved or deleted for one of them.
    Shared,
}

impl From<torrentd_pool::AdoptionState> for AdoptionState {
    fn from(s: torrentd_pool::AdoptionState) -> Self {
        use torrentd_pool::AdoptionState as D;
        match s {
            D::Missing => Self::Missing,
            D::Partial => Self::Partial,
            D::Matched => Self::Matched,
            D::Adopted => Self::Adopted,
            D::Drifted => Self::Drifted,
            D::Overlap => Self::Overlap,
            D::Shared => Self::Shared,
        }
    }
}

impl From<AdoptionState> for torrentd_pool::AdoptionState {
    fn from(s: AdoptionState) -> Self {
        use torrentd_pool::AdoptionState as D;
        match s {
            AdoptionState::Missing => D::Missing,
            AdoptionState::Partial => D::Partial,
            AdoptionState::Matched => D::Matched,
            AdoptionState::Adopted => D::Adopted,
            AdoptionState::Drifted => D::Drifted,
            AdoptionState::Overlap => D::Overlap,
            AdoptionState::Shared => D::Shared,
        }
    }
}

impl FromStr for AdoptionState {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        torrentd_pool::AdoptionState::parse(s)
            .map(Self::from)
            .ok_or("not an adoption state")
    }
}

impl fmt::Display for AdoptionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(torrentd_pool::AdoptionState::from(*self).as_str())
    }
}

impl ParamValue for AdoptionState {}

/// Byte accounting for one directory subtree — what makes the pool legible at
/// petabyte scale, where a file listing is useless but "this subtree is 8 TB
/// and none of it is protected" is not.
#[derive(Clone, Debug, Default, Schema, Serialize)]
pub struct DirRollup {
    /// Bytes indexed under this path.
    pub bytes_total: u64,
    /// Bytes claimed by a torrent that is adopted (loaded and seeding).
    pub bytes_adopted: u64,
    /// Bytes claimed by a torrent that is matched but not yet adopted.
    pub bytes_matched: u64,
    /// Bytes on disk that no torrent in the library claims.
    pub bytes_orphan: u64,
    /// Files indexed under this path.
    pub files_total: u64,
    /// Files no torrent in the library claims.
    pub files_orphan: u64,
}

impl From<torrentd_pool::DirRollup> for DirRollup {
    fn from(r: torrentd_pool::DirRollup) -> Self {
        Self {
            bytes_total: r.bytes_total,
            bytes_adopted: r.bytes_adopted,
            bytes_matched: r.bytes_matched,
            bytes_orphan: r.bytes_orphan,
            files_total: r.files_total,
            files_orphan: r.files_orphan,
        }
    }
}

/// A torrent an adoption or verification did not act on, and why.
#[derive(Debug, Schema, Serialize)]
pub struct RefusedTorrent {
    /// The torrent.
    pub infohash: InfoHashHex,
    /// Why it was not acted on, in prose for an operator.
    pub reason: String,
}

/// The id path of a managed root.
#[derive(Schema, PathParams)]
pub struct RootPath {
    /// The managed root, as `GET /v1/pool` lists it.
    pub root_id: i64,
}

/// The id path of a mutation plan.
#[derive(Schema, PathParams)]
pub struct PlanPath {
    /// The plan's id.
    pub plan_id: i64,
}

/// A pool index infohash as the API spells it.
///
/// The index only ever stores what libtorrent hashed, so a string that does
/// not parse means the index is corrupt: `Err` is the `detail` of a
/// `500 internal`. Leaving the row out instead would hide a torrent from the
/// operator with no trace; a rescan rebuilds the library rows.
fn hex(infohash: &str) -> Result<InfoHashHex, String> {
    infohash.parse().map_err(|_| {
        internal(
            "reading the pool index",
            format!("the index holds {infohash:?}, which is not an infohash"),
        )
    })
}

fn hexes(infohashes: impl IntoIterator<Item = String>) -> Result<Vec<InfoHashHex>, String> {
    infohashes.into_iter().map(|ih| hex(&ih)).collect()
}

/// Validate `infohashes` as a list of 1..=1000 into `invalid`.
fn check_infohashes(invalid: &mut Invalid, pointer: &str, infohashes: &[InfoHashHex]) {
    invalid.check(
        (1..=MAX_INFOHASHES).contains(&infohashes.len()),
        pointer,
        || format!("must name between 1 and {MAX_INFOHASHES} infohashes"),
    );
}

// ---------------------------------------------------------------------------
// GET /v1/pool, POST /v1/pool/scan, POST /v1/pool/drift-check
// ---------------------------------------------------------------------------

/// Why an operation on the whole pool failed.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum PoolFailure {
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// One managed root and what is under it.
#[derive(Debug, Schema, Serialize)]
pub struct RootSummary {
    /// The root's id, which every per-root operation takes.
    pub root_id: i64,
    /// The root's absolute path on the daemon's host.
    pub path: String,
    /// Byte accounting for the whole root.
    #[serde(flatten)]
    pub rollup: DirRollup,
}

/// How many library torrents are in each adoption state.
#[derive(Debug, Default, Schema, Serialize)]
pub struct AdoptionCounts {
    /// Torrents with no payload under any managed root.
    pub missing: u64,
    /// Torrents with some of their payload present.
    pub partial: u64,
    /// Torrents whose payload is complete and not yet adopted.
    pub matched: u64,
    /// Torrents loaded into a session.
    pub adopted: u64,
    /// Torrents whose payload changed since it was last verified.
    pub drifted: u64,
    /// Torrents sharing some files with another torrent that claims a
    /// different set.
    pub overlap: u64,
    /// Torrents whose files another torrent claims as exactly the same set.
    pub shared: u64,
}

impl AdoptionCounts {
    fn slot(&mut self, state: AdoptionState) -> &mut u64 {
        match state {
            AdoptionState::Missing => &mut self.missing,
            AdoptionState::Partial => &mut self.partial,
            AdoptionState::Matched => &mut self.matched,
            AdoptionState::Adopted => &mut self.adopted,
            AdoptionState::Drifted => &mut self.drifted,
            AdoptionState::Overlap => &mut self.overlap,
            AdoptionState::Shared => &mut self.shared,
        }
    }
}

/// The pool at a glance.
#[derive(Debug, Schema, Serialize)]
pub struct PoolOverview {
    /// Every managed root, with its byte accounting.
    pub roots: Vec<RootSummary>,
    /// The directory the library of `.torrent` files is read from.
    pub library_dir: String,
    /// Torrents in the library.
    pub torrents: u64,
    /// Files indexed across every root.
    pub files: u64,
    /// Library torrents by adoption state. A torrent never matched has no
    /// state and is in none of these.
    pub states: AdoptionCounts,
    /// Adopted torrents waiting for a verification slot.
    pub verify_queue_depth: u32,
    /// Adopted torrents libtorrent is hashing now.
    pub verify_in_flight: u32,
}

/// Summarise the pool.
///
/// Every managed root with its byte accounting, the library's size, how many
/// torrents are in each adoption state, and the verification queue.
#[kynos::get("/pool", tag = Pool)]
pub async fn get_pool(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<Json<PoolOverview>, PoolFailure> {
    let pool = s.pool.clone().ok_or(PoolFailure::PoolNotConfigured)?;
    let fail = |e: torrentd_pool::PoolError| PoolFailure::Internal {
        detail: internal("reading the pool index", e),
    };
    let reader = Arc::clone(&pool);
    let (roots, torrents, files, by_state) = blocking(move || {
        reader.with_reader(|st| {
            let roots = reader
                .roots()
                .iter()
                .map(|(id, path)| {
                    st.rollup(*id, "").map(|rollup| RootSummary {
                        root_id: *id,
                        path: path.to_string_lossy().into_owned(),
                        rollup: rollup.into(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((
                roots,
                st.torrent_count()?,
                st.file_count()?,
                st.counts_by_state()?,
            ))
        })
    })
    .await
    .map_err(fail)?;
    let mut states = AdoptionCounts::default();
    for (state, n) in by_state {
        *states.slot(state.into()) += n;
    }
    Ok(Json(PoolOverview {
        roots,
        library_dir: pool.library_dir().to_string_lossy().into_owned(),
        torrents,
        files,
        states,
        verify_queue_depth: count(pool.verify_queue().depth()),
        verify_in_flight: count(pool.verify_queue().in_flight()),
    }))
}

/// What a full re-index found.
#[derive(Debug, Schema, Serialize)]
pub struct ScanSummary {
    /// Files indexed across every root.
    pub files: u64,
    /// Bytes indexed across every root.
    pub bytes: u64,
    /// Torrents read from the library.
    pub torrents: u64,
    /// Torrents whose payload is complete.
    pub matched: u64,
    /// Torrents with some of their payload present.
    pub partial: u64,
    /// Torrents with none of their payload present.
    pub missing: u64,
    /// Torrents sharing some files with another torrent that claims a
    /// different set.
    pub overlap: u64,
    /// Torrents whose files another torrent claims as exactly the same set.
    pub shared: u64,
    /// Complete torrents still carrying drift no verification has cleared.
    pub drifted: u64,
    /// Entries skipped because they could not be read; the daemon's log names
    /// each, and `pool_scan_errors_total` counts them by kind.
    pub errors: u64,
}

impl From<crate::pool_service::ScanSummary> for ScanSummary {
    fn from(s: crate::pool_service::ScanSummary) -> Self {
        Self {
            files: s.files,
            bytes: s.bytes,
            torrents: s.torrents,
            matched: s.matched,
            partial: s.partial,
            missing: s.missing,
            overlap: s.overlap,
            shared: s.shared,
            drifted: s.drifted,
            errors: s.errors,
        }
    }
}

/// Re-index the pool.
///
/// Walks every managed root, re-reads the library and re-matches every
/// torrent against the payload, in one transaction: a concurrent reader sees
/// the previous index in full rather than a partial rebuild. On a large pool
/// this takes minutes, and the request waits for it.
#[kynos::post("/pool/scan", tag = Pool)]
pub async fn scan_pool(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<Json<ScanSummary>, PoolFailure> {
    let pool = s.pool.clone().ok_or(PoolFailure::PoolNotConfigured)?;
    // Walking millions of paths is blocking work; keeping it off the async
    // runtime is what stops a scan from stalling every other request. The
    // guard moves into the task, so the teardown waits for the scan itself
    // and not merely for this request: one transaction, which a kill would
    // roll back whole, but whose rollback is minutes of work thrown away.
    let guard = s.work.enter();
    let summary = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        pool.scan()
    })
    .await
    .map_err(|e| PoolFailure::Internal {
        detail: internal("the pool scan", e),
    })?
    .map_err(|e| PoolFailure::Internal {
        detail: internal("the pool scan", format!("{e:#}")),
    })?;
    info!(
        target: "torrentd::http::pool",
        files = summary.files,
        torrents = summary.torrents,
        matched = summary.matched,
        "pool scan complete",
    );
    Ok(Json(summary.into()))
}

/// What a drift check found.
#[derive(Debug, Schema, Serialize)]
pub struct DriftReport {
    /// Torrents now marked `drifted`: a claimed file changed or vanished.
    pub drifted: Vec<InfoHashHex>,
    /// Claimed files whose size or modification time changed.
    pub files_changed: u64,
    /// Claimed files that are gone.
    pub files_vanished: u64,
}

/// Check adopted and matched payload for drift.
///
/// Stats every file a matched or adopted torrent claims and compares it with
/// the index. A torrent with a changed or vanished file is marked `drifted`,
/// which refuses it for adoption and relocation until it is rescanned and
/// verified. A `POST` because it writes those states into the index. Unclaimed
/// files are not stated.
#[kynos::post("/pool/drift-check", tag = Pool)]
pub async fn check_pool_drift(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<Json<DriftReport>, PoolFailure> {
    let pool = s.pool.clone().ok_or(PoolFailure::PoolNotConfigured)?;
    // Held by the task, as for a scan: the teardown waits for it.
    let guard = s.work.enter();
    let report = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let roots: std::collections::HashMap<i64, std::path::PathBuf> =
            pool.roots().iter().cloned().collect();
        pool.with_store_mut(|st| torrentd_pool::drift::detect(st, |id| roots.get(&id).cloned()))
    })
    .await
    .map_err(|e| PoolFailure::Internal {
        detail: internal("the drift check", e),
    })?
    .map_err(|e| PoolFailure::Internal {
        detail: internal("the drift check", e),
    })?;
    Ok(Json(DriftReport {
        drifted: hexes(report.drifted).map_err(|detail| PoolFailure::Internal { detail })?,
        files_changed: report.files_changed,
        files_vanished: report.files_vanished,
    }))
}

// ---------------------------------------------------------------------------
// GET /v1/pool/roots/{root_id}/tree, …/orphans
// ---------------------------------------------------------------------------

/// Why a directory listing failed.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum TreeError {
    /// The cursor is not one this listing issued.
    #[error("the cursor is not one this listing issued; start again without one")]
    #[problem(status = 400, title = "Invalid cursor")]
    InvalidCursor,
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// No managed root has this id.
    #[error("unknown root_id")]
    #[problem(status = 404, title = "Root not found")]
    RootNotFound,
    /// A query parameter breaks a documented constraint.
    #[error("{summary}")]
    #[problem(status = 422, title = "The request is invalid")]
    ValidationFailed {
        summary: String,
        /// Every violated constraint.
        #[problem(extension)]
        errors: serde_json::Value,
    },
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}
from_invalid!(TreeError);

impl From<InvalidCursor> for TreeError {
    fn from(_: InvalidCursor) -> Self {
        Self::InvalidCursor
    }
}

/// Where in a root to list, and which page.
#[derive(Schema, QueryParams)]
pub struct TreeQuery {
    /// The directory to list, relative to the root and `/`-separated. Empty
    /// or absent lists the root itself; leading and trailing `/` are ignored.
    pub path: Option<String>,
    /// Resume after the last entry of the previous page.
    pub cursor: Option<String>,
    /// Entries per page; 100 when absent.
    #[schema(minimum = 1, maximum = 1000)]
    pub limit: Option<PageLimit>,
}

/// One entry of a directory listing.
#[derive(Debug, Schema, Serialize)]
pub struct TreeEntry {
    /// The last path segment.
    pub name: String,
    /// The path relative to the root; pass it as `path` to list inside a
    /// directory.
    pub path: String,
    /// Whether this is a directory. Directories are inferred from indexed file
    /// paths, so an empty directory never appears.
    pub is_dir: bool,
    /// Byte accounting for everything under this entry.
    #[serde(flatten)]
    pub rollup: DirRollup,
    /// Adoption states of the torrents claiming anything under this entry, so
    /// a client can colour a row without a request per row. Always empty in
    /// an orphan listing.
    pub states: Vec<AdoptionState>,
}

page!(
    /// One page of a directory listing: directories first, then files, each
    /// in byte order of their path.
    TreePage,
    TreeEntry
);

/// Whether `key` could be a [`tree_key`] of an immediate child of `prefix`:
/// `d` or `f`, then a path directly under the listed directory.
///
/// A key of that shape that names no entry is still a position — the next
/// page starts after where it would sort — which is what a cursor is.
fn is_child_key(key: &str, prefix: &str) -> bool {
    let Some(path) = key.strip_prefix(['d', 'f']) else {
        return false;
    };
    let name = if prefix.is_empty() {
        Some(path)
    } else {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('/'))
    };
    name.is_some_and(|n| !n.is_empty() && !n.contains('/'))
}

/// The cursor key of a listing entry, ascending in the order the store lists
/// children: directories first, then files, each by path.
fn tree_key(path: &str, is_dir: bool) -> String {
    format!("{}{path}", if is_dir { 'd' } else { 'f' })
}

/// One page of the immediate children of `path` in `root_id` after the
/// cursor — with `orphans_only`, only those holding bytes no torrent claims —
/// each with its accounting and, for the tree, the states claiming it.
///
/// The page is read from the materialised tree on the read connection, on
/// the blocking pool: `limit + 1` rows of one directory, whatever the size of
/// the subtree under it, and never waiting for a scan.
async fn list_children(
    s: &AppState,
    listing: &'static str,
    root_id: i64,
    q: TreeQuery,
    orphans_only: bool,
) -> Result<TreePage, TreeError> {
    let pool = s.pool.clone().ok_or(TreeError::PoolNotConfigured)?;
    let prefix = q.path.as_deref().unwrap_or("").trim_matches('/').to_owned();
    // Scoped to the directory listed, so a cursor from another root or path
    // is refused rather than read as "nothing follows".
    // The path's length goes in first, so no path — `:` and all — can make
    // one directory's listing name a prefix of another's.
    let listing = format!("{listing}:{root_id}:{}:{prefix}", prefix.len());
    let mut invalid = Invalid::new();
    let page = PageRequest::parse(
        &listing,
        q.cursor.as_deref(),
        q.limit.map(PageLimit::get),
        |key| is_child_key(key, &prefix),
        &mut invalid,
    )?;
    invalid.finish()?;
    if pool.root_path_of(root_id).is_none() {
        return Err(TreeError::RootNotFound);
    }
    let fail = |e: torrentd_pool::PoolError| TreeError::Internal {
        detail: internal("listing the pool index", e),
    };
    blocking(move || {
        pool.with_reader(|st| {
            // `is_child_key` admitted the cursor, so it is `d` or `f` and a
            // path.
            let after = page
                .after
                .as_deref()
                .and_then(|k| Some((k.starts_with('d'), k.get(1..)?)));
            // One more than the page, so `paginate` can tell whether a next
            // page exists.
            let children = st
                .children_page(
                    root_id,
                    &prefix,
                    after,
                    page.limit.saturating_add(1),
                    orphans_only,
                )
                .map_err(fail)?;
            let entries = children
                .into_iter()
                .map(|(path, is_dir)| {
                    let rollup = entry_rollup(st, root_id, &path, is_dir)?;
                    let states = if orphans_only {
                        Vec::new()
                    } else {
                        st.states_under(root_id, &path)?
                            .into_iter()
                            .map(AdoptionState::from)
                            .collect()
                    };
                    Ok(TreeEntry {
                        name: name_of(&path),
                        path,
                        is_dir,
                        rollup: rollup.into(),
                        states,
                    })
                })
                .collect::<Result<Vec<_>, torrentd_pool::PoolError>>()
                .map_err(fail)?;
            let (items, next_cursor) = paginate(
                &listing,
                entries,
                |e: &TreeEntry| tree_key(&e.path, e.is_dir),
                &page,
            );
            Ok(TreePage { items, next_cursor })
        })
    })
    .await
}

fn name_of(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

/// Byte accounting for one listing entry.
///
/// The store's rollup covers everything *under* a directory path, so a file's
/// own path rolls up to nothing; a file's accounting is its own row instead.
/// This is what makes a file row render like a directory row, and what lets
/// an unclaimed file appear among the orphans at all.
fn entry_rollup(
    st: &torrentd_pool::PoolStore,
    root_id: i64,
    path: &str,
    is_dir: bool,
) -> Result<torrentd_pool::DirRollup, torrentd_pool::PoolError> {
    if is_dir {
        return st.rollup(root_id, path);
    }
    let Some(file) = st.file(root_id, path)? else {
        return Ok(torrentd_pool::DirRollup::default());
    };
    let orphan = st.is_orphan(root_id, path)?;
    let states = st.states_under(root_id, path)?;
    let if_claimed_as = |state| {
        if states.contains(&state) {
            file.size
        } else {
            0
        }
    };
    Ok(torrentd_pool::DirRollup {
        bytes_total: file.size,
        bytes_adopted: if_claimed_as(torrentd_pool::AdoptionState::Adopted),
        bytes_matched: if_claimed_as(torrentd_pool::AdoptionState::Matched),
        bytes_orphan: if orphan { file.size } else { 0 },
        files_total: 1,
        files_orphan: u64::from(orphan),
    })
}

/// List a directory of a managed root.
///
/// The immediate children of `path` — directories first, then files — each
/// with its byte accounting and the adoption states of the torrents claiming
/// anything under it. Answers "what is under here, and how much of it is
/// protected" without a file listing of the whole subtree. A `path` that names
/// nothing lists nothing.
#[kynos::get("/pool/roots/{root_id}/tree", tag = Pool)]
pub async fn get_pool_tree(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<RootPath>,
    Query(q): Query<TreeQuery>,
) -> Result<Json<TreePage>, TreeError> {
    list_children(&s, "pool-tree", p.root_id, q, false)
        .await
        .map(Json)
}

/// List a directory's unclaimed payload.
///
/// As the tree listing, keeping only the children holding bytes no torrent in
/// the library claims — the candidates a `delete_orphans` plan would act on.
/// `states` is always empty here.
#[kynos::get("/pool/roots/{root_id}/orphans", tag = Pool)]
pub async fn list_pool_orphans(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<RootPath>,
    Query(q): Query<TreeQuery>,
) -> Result<Json<TreePage>, TreeError> {
    list_children(&s, "pool-orphans", p.root_id, q, true)
        .await
        .map(Json)
}

// ---------------------------------------------------------------------------
// GET /v1/pool/torrents, GET /v1/pool/plans
// ---------------------------------------------------------------------------

/// Why a paged pool listing failed.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum ListError {
    /// The cursor is not one this listing issued.
    #[error("the cursor is not one this listing issued; start again without one")]
    #[problem(status = 400, title = "Invalid cursor")]
    InvalidCursor,
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// A query parameter breaks a documented constraint.
    #[error("{summary}")]
    #[problem(status = 422, title = "The request is invalid")]
    ValidationFailed {
        summary: String,
        /// Every violated constraint.
        #[problem(extension)]
        errors: serde_json::Value,
    },
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}
from_invalid!(ListError);

impl From<InvalidCursor> for ListError {
    fn from(_: InvalidCursor) -> Self {
        Self::InvalidCursor
    }
}

/// Which library torrents to list, and which page.
#[derive(Schema, QueryParams)]
pub struct PoolTorrentQuery {
    /// Only torrents in this adoption state. A torrent never matched has no
    /// state and is listed only without this filter.
    pub state: Option<AdoptionState>,
    /// Resume after the last torrent of the previous page.
    pub cursor: Option<String>,
    /// Torrents per page; 100 when absent.
    #[schema(minimum = 1, maximum = 1000)]
    pub limit: Option<PageLimit>,
}

/// A torrent in the pool's library.
#[derive(Debug, Schema, Serialize)]
pub struct PoolTorrent {
    /// The torrent.
    pub infohash: InfoHashHex,
    /// The torrent's name from its metainfo.
    pub name: String,
    /// Payload size, in bytes.
    pub total_size: u64,
    /// Files in the torrent.
    pub num_files: u32,
    /// Where it stands against the payload on disk; `null` until a scan has
    /// matched it.
    pub state: Option<AdoptionState>,
    /// The directory, relative to its root, the payload was matched at;
    /// `null` when unmatched.
    pub base_rel: Option<String>,
    /// The profile that owns it, as the library or an adoption recorded;
    /// `null` when none has.
    pub profile_id: Option<String>,
    /// The category the previous client recorded, if any.
    pub category: Option<String>,
    /// The tags the previous client recorded.
    pub tags: Vec<String>,
    /// Whether the previous client left resume data beside it, which lets an
    /// adoption skip re-hashing.
    pub has_fastresume: bool,
}

page!(
    /// One page of library torrents, in infohash order.
    PoolTorrentPage,
    PoolTorrent
);

/// List the library's torrents.
///
/// Every `.torrent` the pool read from its library, with where it stands
/// against the payload on disk, in infohash order. Filter by `state` to find,
/// for example, what is `matched` and ready to adopt.
#[kynos::get("/pool/torrents", tag = Pool)]
pub async fn list_pool_torrents(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Query(q): Query<PoolTorrentQuery>,
) -> Result<Json<PoolTorrentPage>, ListError> {
    const LISTING: &str = "pool-torrents";
    let pool = s.pool.clone().ok_or(ListError::PoolNotConfigured)?;
    let mut invalid = Invalid::new();
    let page = PageRequest::parse(
        LISTING,
        q.cursor.as_deref(),
        q.limit.map(PageLimit::get),
        crate::http::validate::is_infohash_hex,
        &mut invalid,
    )?;
    invalid.finish()?;
    let want = q.state.map(torrentd_pool::AdoptionState::from);
    // One page of the index in SQL, keyed on infohash, on the read
    // connection: `limit + 1` rows whatever the library's size, and never
    // waiting for a scan.
    let (after, limit) = (page.after.clone(), page.limit);
    let rows = blocking(move || {
        pool.with_reader(|st| st.torrents_page(after.as_deref(), want, limit.saturating_add(1)))
    })
    .await
    .map_err(|e| ListError::Internal {
        detail: internal("listing the pool index", e),
    })?;
    let items = rows
        .into_iter()
        .map(|r| {
            let t = r.torrent;
            Ok(PoolTorrent {
                infohash: hex(&t.infohash)?,
                base_rel: r.base_rel,
                state: r.state.map(AdoptionState::from),
                name: t.name,
                total_size: t.total_size,
                num_files: count(t.num_files),
                profile_id: t.profile,
                category: t.category,
                tags: t.tags,
                has_fastresume: t.fastresume_path.is_some(),
            })
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|detail| ListError::Internal { detail })?;
    let (items, next_cursor) = paginate(
        LISTING,
        items,
        |t: &PoolTorrent| t.infohash.to_string(),
        &page,
    );
    Ok(Json(PoolTorrentPage { items, next_cursor }))
}

// ---------------------------------------------------------------------------
// POST /v1/pool/adoptions
// ---------------------------------------------------------------------------

/// Which torrents to adopt.
#[derive(Debug, Deserialize, Schema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdoptSelector {
    /// These torrents.
    Infohashes {
        /// Between 1 and 1000 torrents from the library.
        #[schema(min_items = 1, max_items = 1000)]
        infohashes: Vec<InfoHashHex>,
    },
    /// Every library torrent whose payload was matched under a directory.
    Subtree {
        /// The managed root.
        root_id: i64,
        /// The directory, relative to the root; empty for the whole root.
        path: String,
    },
}

/// A request to adopt existing payload into a profile.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct AdoptRequest {
    /// The profile whose session receives every adopted torrent. Always
    /// required: a profile is an account identity, and there is no count of
    /// profiles at which the daemon may pick one for the caller.
    pub profile_id: String,
    /// Report what would happen and adopt nothing. The drift check every
    /// adoption runs first still marks changed payload `drifted`.
    #[serde(default)]
    pub dry_run: bool,
    /// Which torrents to adopt.
    pub selector: AdoptSelector,
}

impl Validate for AdoptRequest {
    fn validate(&self) -> Result<(), Invalid> {
        let mut invalid = Invalid::new();
        if let AdoptSelector::Infohashes { infohashes } = &self.selector {
            check_infohashes(&mut invalid, "/selector/infohashes", infohashes);
        }
        invalid.finish()
    }
}

/// What an adoption did, or would do.
#[derive(Debug, Schema, Serialize)]
pub struct AdoptionResult {
    /// Whether this was a dry run, which changed nothing.
    pub dry_run: bool,
    /// Adopted in seed mode on the strength of the previous client's resume
    /// data; these seed without re-hashing.
    pub fast_path: Vec<InfoHashHex>,
    /// Adopted without seed mode: libtorrent hashes each before it seeds, a
    /// bounded number at a time.
    pub queued_for_verification: Vec<InfoHashHex>,
    /// Not adopted, each with the reason.
    pub refused: Vec<RefusedTorrent>,
    /// Bytes libtorrent must read to verify the queued set — the number that
    /// decides whether an adoption takes minutes or days.
    pub verify_bytes: u64,
}

/// Why an adoption could not start.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum AdoptError {
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// No profile with this id is configured.
    #[error("unknown profile_id")]
    #[problem(status = 404, title = "Profile not found")]
    ProfileNotFound,
    /// The subtree selector names no managed root.
    #[error("unknown root_id")]
    #[problem(status = 404, title = "Root not found")]
    RootNotFound,
    /// The profile failed to start, is fenced, or is set offline, so it
    /// cannot receive torrents.
    #[error("{detail}")]
    #[problem(status = 409, title = "The profile is unavailable")]
    ProfileUnavailable {
        detail: String,
        /// `failed`, `vpn_down` or `offline`.
        #[problem(extension)]
        profile_status: &'static str,
    },
    /// The body breaks a documented constraint.
    #[error("{summary}")]
    #[problem(status = 422, title = "The request is invalid")]
    ValidationFailed {
        summary: String,
        /// Every violated constraint.
        #[problem(extension)]
        errors: serde_json::Value,
    },
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}
from_invalid!(AdoptError);
from_profile_problem!(AdoptError);

/// Adopt existing payload.
///
/// Hands library torrents whose payload the pool matched to one profile's
/// session. Each is claimed in the daemon's assignment registry first, so a
/// torrent another profile already holds is refused rather than announced from
/// a second account. A torrent whose previous client left trustworthy resume
/// data seeds at once (`fast_path`); any other is hashed by libtorrent before
/// it seeds (`queued_for_verification`). Torrents that are not `matched` are
/// refused, each with the reason. `dry_run` reports all of this and adopts
/// nothing.
///
/// Every adoption, dry run included, first runs the drift check over the
/// selected `matched` and `shared` torrents: any whose files changed since the
/// last scan is marked `drifted` in the index, as `POST /v1/pool/drift-check`
/// would mark it, and is queued for verification rather than trusted on its
/// resume data.
///
/// Not gated on `[pool] allow_mutations`: adoption records an existing file's
/// ownership and moves nothing on disk.
#[kynos::post("/pool/adoptions", tag = Pool)]
pub async fn adopt_pool_torrents(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Json(req): Json<AdoptRequest>,
) -> Result<Json<AdoptionResult>, AdoptError> {
    // `allow_mutations` is deliberately not consulted. It gates the plan
    // surface — creating a plan as well as applying one — because a plan
    // moves or deletes payload. Adoption is not part of that surface: it
    // records an existing file's ownership in the index, so it is outside the
    // switch; `write` scope is what it needs.
    let pool = s.pool.clone().ok_or(AdoptError::PoolNotConfigured)?;
    req.validate()?;
    let profile = ProfileId::new(req.profile_id.as_str());
    // Configured-and-failed is not the same as unknown, and telling an
    // operator their id does not exist sends them to the config file for a
    // tunnel problem. Adopting into a fenced profile would land every torrent
    // paused and make the profile look healthy; same guard as adding one.
    unfenced_engine(&s, &profile)?;

    // On the blocking pool: every target reads and writes the index on the
    // writer, which a running scan holds, and adds go through a session's
    // lock. Waiting there holds a blocking thread, not a runtime worker.
    blocking(move || adopt_each(&s, &pool, &req, &profile).map(Json)).await
}

/// [`adopt_pool_torrents`] past its up-front checks: resolve the targets and
/// adopt, or refuse, each in turn.
fn adopt_each(
    s: &AppState,
    pool: &PoolService,
    req: &AdoptRequest,
    profile: &ProfileId,
) -> Result<AdoptionResult, AdoptError> {
    let fail = |e: torrentd_pool::PoolError| AdoptError::Internal {
        detail: internal("reading the pool index", e),
    };
    let targets: Vec<String> = match &req.selector {
        AdoptSelector::Infohashes { infohashes } => {
            infohashes.iter().map(InfoHashHex::to_string).collect()
        }
        AdoptSelector::Subtree { root_id, path } => {
            if pool.root_path_of(*root_id).is_none() {
                return Err(AdoptError::RootNotFound);
            }
            let pv = pool
                .with_store(|st| {
                    torrentd_pool::adopt::preview(st, *root_id, path, |id| pool.root_path_of(id))
                })
                .map_err(fail)?;
            pv.fast_path
                .into_iter()
                .chain(pv.verify)
                .chain(pv.refused.into_iter().map(|(ih, _)| ih))
                .collect()
        }
    };

    // Every target is converted before any is acted on: a corrupt index row
    // refuses the request up front, rather than failing it half way through
    // with earlier torrents already claimed and added and nothing saying
    // which.
    let targets = targets
        .into_iter()
        .map(|ih| hex(&ih).map(|infohash| (ih, infohash)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|detail| AdoptError::Internal { detail })?;

    // The fast path trusts the previous client's "complete" only as far as
    // the index is fresh, and the scan may be weeks old: payload rewritten in
    // place at the same size since then would seed as complete and serve bad
    // pieces. Stat the selection first, so anything that changed is marked
    // `drifted` and planned through verification instead. Before any target
    // is acted on, so a failure here is a whole-request error, not a refusal.
    let selected: Vec<String> = targets.iter().map(|(ih, _)| ih.clone()).collect();
    let drift = pool
        .check_drift_before_adopt(&selected)
        .map_err(|e| AdoptError::Internal {
            detail: internal("the drift check before adopting", e),
        })?;

    let mut resp = AdoptionResult {
        dry_run: req.dry_run,
        fast_path: Vec::new(),
        queued_for_verification: Vec::new(),
        refused: Vec::new(),
        verify_bytes: 0,
    };

    for (ih, infohash) in targets {
        let refuse = |resp: &mut AdoptionResult, reason: String| {
            resp.refused.push(RefusedTorrent { infohash, reason });
        };
        // Refused, not a 500: by now earlier targets may already be claimed
        // and loaded, and a failure here must leave the response saying
        // exactly which. The cause is logged; the reason says only that the
        // index could not be read for this torrent.
        let plan = match pool
            .with_store(|st| torrentd_pool::adopt::plan(st, &ih, |id| pool.root_path_of(id)))
        {
            Ok(plan) => plan,
            Err(e) => {
                refuse(
                    &mut resp,
                    internal("reading the pool index for this torrent", e),
                );
                continue;
            }
        };

        // The two adoptable outcomes differ only in which bucket they land in
        // and whether their bytes are counted, so collapse them: everything
        // after this point — the registry claim above all — must hold for both,
        // and holding it in two branches is how it came to hold in neither.
        let verifies = match plan {
            torrentd_pool::AdoptPlan::Refuse { reason } => {
                refuse(&mut resp, reason.to_owned());
                continue;
            }
            torrentd_pool::AdoptPlan::FastPath { .. } => false,
            torrentd_pool::AdoptPlan::Verify { .. } => true,
        };

        // Counted only once it is taken, so a refused torrent's bytes are not.
        let accept = |resp: &mut AdoptionResult| {
            if verifies {
                resp.verify_bytes += pool
                    .with_store(|st| st.torrent(&ih).ok().flatten().map(|t| t.total_size))
                    .unwrap_or(0);
            }
            bucket(resp, verifies).push(infohash);
        };
        // Refusals that keep one account's torrent out of another are counted
        // where every add path counts them — by the adoption, not its dry run,
        // which changes nothing.
        let isolation_refused = || {
            if !req.dry_run {
                s.metrics.inc_counter(
                    "profile_assignment_registry_errors_total",
                    &[("profile_id", profile.as_str())],
                );
            }
        };
        if let Err(reason) = check_index_owner(pool, &ih, profile) {
            isolation_refused();
            refuse(&mut resp, reason);
            continue;
        }
        if req.dry_run {
            // Everything up to the add, the account-isolation guard included,
            // so a dry run refuses what the adoption would.
            match execute_adopt(pool, &s.source, &s.profiles, &ih, profile.clone(), true) {
                Ok(_) => accept(&mut resp),
                Err(r) => refuse(&mut resp, r.reason),
            }
            continue;
        }

        // Safety Rules 3 and 4, in the order they are written: the registry is
        // the authority on which profile owns an info-hash, and it is consulted
        // *before* any session receives the torrent.
        //
        // Claiming afterwards could not enforce anything. libtorrent refuses a
        // duplicate within one session, but a profile is a whole separate
        // session by construction, so an info-hash already seeding in profile A
        // was free to be adopted into profile B and start announcing from a
        // second account — the permanent-ban case Rule 3 exists for — while the
        // conflict was recorded as a warning after the fact.
        if let Err(reason) = claim_in_registry(s, infohash, profile) {
            refuse(&mut resp, reason);
            continue;
        }
        match execute_adopt(pool, &s.source, &s.profiles, &ih, profile.clone(), false) {
            Ok(_) => accept(&mut resp),
            Err(r) => {
                release_claim(s, infohash);
                if r.isolation {
                    isolation_refused();
                }
                refuse(&mut resp, r.reason);
            }
        }
    }

    info!(
        target: "torrentd::http::pool",
        dry_run = req.dry_run,
        fast_path = resp.fast_path.len(),
        queued = resp.queued_for_verification.len(),
        refused = resp.refused.len(),
        drifted = drift.drifted.len(),
        "adopt",
    );
    Ok(resp)
}

/// Which result bucket an adopted torrent belongs in.
fn bucket(resp: &mut AdoptionResult, verifies: bool) -> &mut Vec<InfoHashHex> {
    if verifies {
        &mut resp.queued_for_verification
    } else {
        &mut resp.fast_path
    }
}

/// Claim `infohash` for `profile` before any session sees it.
///
/// Deliberately the same shape as the claim in `POST /v1/torrents`: an
/// info-hash already mapped to *any* profile is a refusal rather than a
/// warning, because the registry is the only thing that can see across
/// profiles. `assign` re-checks uniqueness under its own lock, which closes the
/// gap between the lookup and the insert.
fn claim_in_registry(
    s: &AppState,
    infohash: InfoHashHex,
    profile: &ProfileId,
) -> Result<(), String> {
    let ih = infohash.get();
    if let Some(existing) = s.registry.lookup(&ih) {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile.as_str())],
        );
        return Err(format!("info-hash already loaded in profile {existing}"));
    }
    s.registry.assign(ih, profile.clone()).map_err(|e| {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile.as_str())],
        );
        format!("{e}")
    })
}

/// Refuse a torrent the pool index says another profile owns.
///
/// The index keeps an owner of its own (`torrent.profile`, which also
/// absorbed the pre-registry `profile_assignments.json`), and it outlives the
/// torrent being loaded, so the registry claim alone does not see it: a
/// torrent no session holds now can still be another account's.
/// `DELETE /v1/torrents/{infohash}` clears the record, so it never outlasts
/// the torrent it describes.
fn check_index_owner(pool: &PoolService, ih: &str, profile: &ProfileId) -> Result<(), String> {
    match pool.with_store(|st| st.profile_of(ih)) {
        Ok(Some(owner)) if owner != profile.as_str() => Err(format!(
            "the pool index assigns this torrent to profile {owner}"
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(internal(
            "reading the pool index's owner of this torrent",
            e,
        )),
    }
}

/// Release a claim whose add then failed, so the info-hash can be retried.
fn release_claim(s: &AppState, infohash: InfoHashHex) {
    if let Err(e) = s.registry.remove(&infohash.get()) {
        tracing::warn!(
            target: "torrentd::http::pool",
            infohash = %infohash,
            error.cause = %e,
            "could not release the registry claim of a failed adopt",
        );
    }
}

// ---------------------------------------------------------------------------
// POST /v1/pool/verifications
// ---------------------------------------------------------------------------

/// Torrents to re-hash.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// Between 1 and 1000 loaded torrents.
    #[schema(min_items = 1, max_items = 1000)]
    pub infohashes: Vec<InfoHashHex>,
}

impl Validate for VerifyRequest {
    fn validate(&self) -> Result<(), Invalid> {
        let mut invalid = Invalid::new();
        check_infohashes(&mut invalid, "/infohashes", &self.infohashes);
        invalid.finish()
    }
}

/// Which re-hashes started.
#[derive(Debug, Schema, Serialize)]
pub struct VerifyResult {
    /// How many infohashes the request named.
    pub requested: u32,
    /// Torrents libtorrent is now re-hashing.
    pub started: Vec<InfoHashHex>,
    /// Torrents not re-hashed, each with the reason.
    pub skipped: Vec<RefusedTorrent>,
}

/// Why a verification could not start.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum VerifyError {
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// The body breaks a documented constraint.
    #[error("{summary}")]
    #[problem(status = 422, title = "The request is invalid")]
    ValidationFailed {
        summary: String,
        /// Every violated constraint.
        #[problem(extension)]
        errors: serde_json::Value,
    },
}
from_invalid!(VerifyError);

/// Re-hash loaded torrents.
///
/// Asks libtorrent to check each torrent's payload against its piece hashes
/// (v1 SHA-1, v2 SHA-256 merkle) — the daemon's only authoritative check.
/// `202` means the checks started; each torrent reports `checking` until it
/// finishes. A torrent not loaded in any session, or paused (libtorrent does
/// not hash a paused torrent), is skipped with the reason. Only a torrent in
/// the pool index has its outcome recorded: a pass marks it `adopted`, a
/// failure marks it `drifted` and pauses it.
#[kynos::post("/pool/verifications", tag = Pool)]
pub async fn verify_pool_torrents(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Accepted<Json<VerifyResult>>, VerifyError> {
    s.pool.as_ref().ok_or(VerifyError::PoolNotConfigured)?;
    req.validate()?;
    // On the blocking pool: each recheck takes its session's lock, and a
    // request may name thousands of torrents.
    let resp = crate::http::v1::common::blocking(move || {
        let mut resp = VerifyResult {
            requested: count(req.infohashes.len()),
            started: Vec::new(),
            skipped: Vec::new(),
        };
        for infohash in req.infohashes {
            let skip = |resp: &mut VerifyResult, reason: String| {
                resp.skipped.push(RefusedTorrent { infohash, reason });
            };
            let Some(st) = s.state.get(&infohash.get()) else {
                skip(&mut resp, "not loaded in any session".to_owned());
                continue;
            };
            // A recheck resumes the torrent's network activity once it ends,
            // so a fenced or offline profile is skipped as resume-all skips
            // it: its torrents wait for the operator to set it online.
            let engine = match unfenced_engine(&s, &st.profile_id) {
                Ok(engine) => engine,
                Err(crate::http::v1::common::ProfileProblem::Unavailable { detail, .. }) => {
                    skip(&mut resp, detail);
                    continue;
                }
                Err(crate::http::v1::common::ProfileProblem::NotFound) => {
                    skip(&mut resp, "engine missing".to_owned());
                    continue;
                }
            };
            // libtorrent does not hash a paused torrent: the check waits for a
            // resume that nothing here issues, so reporting it started would
            // be false. A torrent paused by a failed verification is the
            // common case; resuming it is the operator's call, since it puts
            // the rejected payload back on the network until the check ends.
            if st.phase == torrentd_engine::TorrentPhase::Paused {
                skip(
                    &mut resp,
                    "paused, and libtorrent does not hash a paused torrent; resume it, then \
                     verify again"
                        .to_owned(),
                );
                continue;
            }
            // Tracked before it is asked for, so the check it starts finishes
            // after the mark; the verify queue then records its outcome, which
            // is what clears a drifted torrent or pauses one that failed.
            // Only a torrent the pool index holds has an adoption to record:
            // anything else is re-hashed and left alone, neither paused on a
            // failure nor written into the index.
            if let Some(pool) = s.pool.as_ref() {
                let ih = infohash.to_string();
                let indexed = pool.with_reader(|st| st.torrent(&ih).map(|t| t.is_some()));
                match indexed {
                    Ok(true) => pool.verify_queue().track_recheck(ih),
                    Ok(false) => {}
                    Err(e) => {
                        skip(&mut resp, format!("pool index unreadable: {e}"));
                        continue;
                    }
                }
            }
            match engine.force_recheck(st.handle) {
                Ok(()) => resp.started.push(infohash),
                Err(e) => skip(&mut resp, e.to_string()),
            }
        }
        resp
    })
    .await;
    Ok(Accepted::new(Json(resp)))
}

// ---------------------------------------------------------------------------
// Mutation plans
// ---------------------------------------------------------------------------

/// What a plan does.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanKind {
    /// Move one torrent's payload to another directory under a managed root.
    Relocate,
    /// Delete every file under a subtree that no torrent claims, by moving it
    /// into `<root>/.torrentd-trash/<plan id>/`. Refused where a torrent the
    /// matcher could not fully place expects its files, and a file the size
    /// of one the library is still missing is left out. Destructive: applying
    /// it needs the plan's `confirm_token`, which changes whenever the pool is
    /// rescanned.
    DeleteOrphans,
}

/// Where a plan stands.
#[derive(Clone, Copy, Debug, Schema, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    /// Computed and not applied; nothing on disk has changed.
    Draft,
    /// Being applied now, or interrupted mid-apply; startup resumes it.
    Applying,
    /// Every step is done.
    Applied,
    /// Applying stopped at a failed step. Applying it again retries from the
    /// first step not done.
    Failed,
    /// Discarded without being applied.
    Cancelled,
}

/// One filesystem operation of a plan.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepOp {
    /// Relocate an adopted torrent's payload; libtorrent performs the move so
    /// its session stays consistent.
    MoveTorrent,
    /// Delete a file no torrent claims.
    DeleteFile,
}

/// Where one step stands.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Not attempted.
    Pending,
    /// Attempted and not finished. Found on a plan nothing is applying, it
    /// means a run died mid-step and a human must inspect `src`.
    InProgress,
    /// Done.
    Done,
    /// Failed; `error` says why.
    Failed,
    /// Not attempted, deliberately.
    Skipped,
}

macro_rules! wire_enum_from_str {
    ($ty:ty { $($s:literal => $v:ident),+ $(,)? }) => {
        impl $ty {
            /// The value the pool index stores, as the API spells it.
            fn parse(s: &str) -> Option<Self> {
                match s {
                    $($s => Some(Self::$v),)+
                    _ => None,
                }
            }

            #[cfg_attr(not(test), allow(dead_code))]
            fn as_str(self) -> &'static str {
                match self {
                    $(Self::$v => $s,)+
                }
            }
        }
    };
}

wire_enum_from_str!(PlanKind { "relocate" => Relocate, "delete_orphans" => DeleteOrphans });
wire_enum_from_str!(PlanStatus {
    "draft" => Draft,
    "applying" => Applying,
    "applied" => Applied,
    "failed" => Failed,
    "cancelled" => Cancelled,
});
wire_enum_from_str!(StepOp {
    "move_torrent" => MoveTorrent,
    "delete_file" => DeleteFile,
});
wire_enum_from_str!(StepStatus {
    "pending" => Pending,
    "in_progress" => InProgress,
    "done" => Done,
    "failed" => Failed,
    "skipped" => Skipped,
});

impl FromStr for PlanStatus {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or("not a plan status")
    }
}

impl fmt::Display for PlanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ParamValue for PlanStatus {}

/// A string the pool index holds that this build has no name for.
fn unknown(what: &str, value: &str) -> String {
    internal(
        "reading a plan",
        format!("the pool index holds {what} {value:?}, which this build does not know"),
    )
}

/// One step of a plan.
#[derive(Debug, Schema, Serialize)]
pub struct PlanStep {
    /// The step's position; steps run in this order.
    pub seq: i64,
    /// What the step does.
    pub op: StepOp,
    /// The path acted on.
    pub src: String,
    /// Where a move puts it; `null` for a delete.
    pub dst: Option<String>,
    /// Where the step stands.
    pub status: StepStatus,
    /// Why the step failed; `null` unless it did.
    pub error: Option<String>,
}

/// A mutation plan: the exact diff an apply would make.
#[derive(Debug, Schema, Serialize)]
pub struct Plan {
    /// The plan's id.
    pub id: i64,
    /// What the plan does.
    pub kind: PlanKind,
    /// Where it stands.
    pub status: PlanStatus,
    /// When it was computed.
    pub created_at: jiff::Timestamp,
    /// When an apply last finished, successfully or not; `null` before.
    pub applied_at: Option<jiff::Timestamp>,
    /// Every step, in the order an apply runs them.
    pub steps: Vec<PlanStep>,
    /// For a plan that deletes data, the token `POST …/apply` must repeat;
    /// `null` for any other. Derived from the steps, so it names this plan and
    /// no other.
    pub confirm_token: Option<String>,
}

/// A plan without its steps, as a listing carries it.
#[derive(Debug, Schema, Serialize)]
pub struct PlanSummary {
    /// The plan's id.
    pub id: i64,
    /// What the plan does.
    pub kind: PlanKind,
    /// Where it stands.
    pub status: PlanStatus,
    /// When it was computed.
    pub created_at: jiff::Timestamp,
    /// When an apply last finished, successfully or not; `null` before.
    pub applied_at: Option<jiff::Timestamp>,
}

page!(
    /// One page of plans, oldest first.
    PlanPage,
    PlanSummary
);

fn unix(secs: i64) -> jiff::Timestamp {
    jiff::Timestamp::from_second(secs).unwrap_or(jiff::Timestamp::UNIX_EPOCH)
}

fn summary_of(p: &torrentd_pool::model::PlanRow) -> Result<PlanSummary, String> {
    Ok(PlanSummary {
        id: p.id,
        kind: PlanKind::parse(&p.kind).ok_or_else(|| unknown("plan kind", &p.kind))?,
        status: PlanStatus::parse(&p.status).ok_or_else(|| unknown("plan status", &p.status))?,
        created_at: unix(p.created_at),
        applied_at: p.applied_at.map(unix),
    })
}

/// A plan as the API shows it, or `None` when there is no such plan.
///
/// `Err` is the `detail` of a `500 internal`.
///
/// Read on the read connection, in one snapshot, so the steps and the
/// generation its confirm token binds are the same commit's; a plan written
/// on the writer is visible once it commits. Blocking: call it on the
/// blocking pool.
fn load_plan(pool: &PoolService, id: i64) -> Result<Option<Plan>, String> {
    let fail = |e: torrentd_pool::PoolError| internal("reading a plan", e);
    let read = pool
        .with_reader(|st| -> Result<_, torrentd_pool::PoolError> {
            let Some(row) = st.plan(id)? else {
                return Ok(None);
            };
            Ok(Some((row, st.plan_steps(id)?, st.index_generation()?)))
        })
        .map_err(fail)?;
    let Some((row, steps, generation)) = read else {
        return Ok(None);
    };
    let confirm_token = torrentd_pool::plan::is_destructive(&row.kind)
        .then(|| torrentd_pool::plan::confirm_token(id, generation, &steps));
    let summary = summary_of(&row)?;
    let steps = steps
        .into_iter()
        .map(|s| {
            Ok(PlanStep {
                op: StepOp::parse(&s.op).ok_or_else(|| unknown("step op", &s.op))?,
                status: StepStatus::parse(&s.status)
                    .ok_or_else(|| unknown("step status", &s.status))?,
                seq: s.seq,
                src: s.src,
                dst: s.dst,
                error: s.error,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Some(Plan {
        id: summary.id,
        kind: summary.kind,
        status: summary.status,
        created_at: summary.created_at,
        applied_at: summary.applied_at,
        steps,
        confirm_token,
    }))
}

/// Which plans to list, and which page.
#[derive(Schema, QueryParams)]
pub struct PlanQuery {
    /// Only plans with this status.
    pub status: Option<PlanStatus>,
    /// Resume after the last plan of the previous page.
    pub cursor: Option<String>,
    /// Plans per page; 100 when absent.
    #[schema(minimum = 1, maximum = 1000)]
    pub limit: Option<PageLimit>,
}

/// List mutation plans.
///
/// Every plan the pool holds, oldest first, without their steps; fetch one
/// plan for its steps and confirm token.
#[kynos::get("/pool/plans", tag = Pool)]
pub async fn list_plans(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Query(q): Query<PlanQuery>,
) -> Result<Json<PlanPage>, ListError> {
    const LISTING: &str = "pool-plans";
    let pool = s.pool.clone().ok_or(ListError::PoolNotConfigured)?;
    let mut invalid = Invalid::new();
    let page = PageRequest::parse(
        LISTING,
        q.cursor.as_deref(),
        q.limit.map(PageLimit::get),
        |key| crate::http::page::is_padded_decimal(key, PLAN_KEY_WIDTH),
        &mut invalid,
    )?;
    invalid.finish()?;
    let mut rows = blocking(move || pool.with_reader(|st| st.plans()))
        .await
        .map_err(|e| ListError::Internal {
            detail: internal("listing plans", e),
        })?;
    rows.sort_by_key(|p| p.id);
    let items = rows
        .iter()
        .filter(|p| q.status.is_none_or(|want| p.status == want.as_str()))
        .map(summary_of)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|detail| ListError::Internal { detail })?;
    let (items, next_cursor) = paginate(LISTING, items, |p| plan_key(p.id), &page);
    Ok(Json(PlanPage { items, next_cursor }))
}

/// A plan id as a cursor key: zero-padded, so byte order is numeric order.
fn plan_key(id: i64) -> String {
    format!("{id:0PLAN_KEY_WIDTH$}")
}

/// Digits in a plan cursor key: enough for every non-negative `i64`.
const PLAN_KEY_WIDTH: usize = 20;

/// What to plan.
#[derive(Debug, Deserialize, Schema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CreatePlanRequest {
    /// Move one torrent's payload to a new directory under a managed root.
    Relocate {
        /// The torrent; it must be `matched` or `adopted`.
        infohash: InfoHashHex,
        /// The managed root to move it to.
        dest_root_id: i64,
        /// The destination directory, relative to that root.
        dest_rel: String,
    },
    /// Delete every file under a subtree that no torrent claims.
    DeleteOrphans {
        /// The managed root.
        root_id: i64,
        /// The directory, relative to the root; empty for the whole root.
        prefix: String,
    },
}

impl From<CreatePlanRequest> for torrentd_pool::PlanSpec {
    fn from(r: CreatePlanRequest) -> Self {
        match r {
            CreatePlanRequest::Relocate {
                infohash,
                dest_root_id,
                dest_rel,
            } => Self::Relocate {
                infohash: infohash.to_string(),
                dest_root_id,
                dest_rel,
            },
            CreatePlanRequest::DeleteOrphans { root_id, prefix } => {
                Self::DeleteOrphans { root_id, prefix }
            }
        }
    }
}

const MUTATIONS_DISABLED: &str = "pool mutations are disabled; set `allow_mutations = true` in \
                                  the [pool] section of the config to move, relocate or delete \
                                  inside a managed root";

/// Why a plan was not created.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum CreatePlanError {
    /// `[pool] allow_mutations` is off.
    #[error("{MUTATIONS_DISABLED}")]
    #[problem(status = 403, title = "Pool mutations are disabled")]
    MutationsDisabled,
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// The planner refused; `detail` says why.
    #[error("{0}")]
    #[problem(status = 409, title = "The plan was refused")]
    PlanRefused(String),
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// Compute a mutation plan.
///
/// Works out every step the change would take and stores them as a `draft`,
/// touching nothing on disk; `POST …/apply` performs it. The planner refuses
/// with `409 plan-refused` when the change is unsafe as the index stands — an
/// overlap, drift, an occupied destination, a torrent not in the index.
///
/// Refused with `403 mutations-disabled` unless `[pool] allow_mutations` is
/// set. Creating a plan touches nothing, but a plan that can never be applied
/// is a trap, and refusing where the operator asks is the clearer signal.
#[kynos::post("/pool/plans", tag = Pool)]
pub async fn create_plan(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Json(req): Json<CreatePlanRequest>,
) -> Result<Created<Json<Plan>>, CreatePlanError> {
    let pool = s.pool.clone().ok_or(CreatePlanError::PoolNotConfigured)?;
    if !pool.allow_mutations() {
        return Err(CreatePlanError::MutationsDisabled);
    }
    // On the blocking pool: the plan is built and written on the writer,
    // which a running scan holds.
    blocking(move || create_plan_blocking(&pool, torrentd_pool::PlanSpec::from(req))).await
}

/// [`create_plan`] past its up-front checks.
fn create_plan_blocking(
    pool: &PoolService,
    spec: torrentd_pool::PlanSpec,
) -> Result<Created<Json<Plan>>, CreatePlanError> {
    let kind = spec.kind();
    let fail = |e: &dyn fmt::Display| CreatePlanError::Internal {
        detail: internal("creating a plan", e),
    };

    let built = pool
        .with_store(|st| torrentd_pool::plan::build(st, &spec, |id| pool.root_path_of(id)))
        .map_err(|e| fail(&e))?;
    let steps = match built {
        Ok(steps) => steps,
        // A refusal is the expected outcome for overlap, drift, or an occupied
        // destination — a 409 with the reason, not a 500.
        Err(refused) => return Err(CreatePlanError::PlanRefused(refused.to_string())),
    };

    let spec_json = serde_json::to_string(&spec).map_err(|e| fail(&e))?;
    let id = pool
        .with_store(|st| st.create_plan(kind, &spec_json, now_secs()))
        .map_err(|e| fail(&e))?;
    pool.with_store_mut(|st| st.add_plan_steps(id, &steps))
        .map_err(|e| fail(&e))?;

    let plan = load_plan(pool, id)
        .map_err(|detail| CreatePlanError::Internal { detail })?
        .ok_or_else(|| fail(&"the plan vanished as it was created"))?;
    info!(
        target: "torrentd::http::pool",
        plan_id = id,
        kind = %kind,
        step_count = plan.steps.len(),
        "plan created (nothing applied)",
    );
    Ok(Created::at(
        // `relative_uri` knows the route, not the group it is mounted under.
        format!(
            "{}{}",
            crate::http::v1::PREFIX,
            get_plan::relative_uri(PlanPath { plan_id: id })
        ),
        Json(plan),
    ))
}

/// Why a plan could not be read.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum GetPlanError {
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// No plan has this id.
    #[error("no such plan")]
    #[problem(status = 404, title = "Plan not found")]
    PlanNotFound,
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// Describe a mutation plan.
///
/// Its status, every step with where it stands, and — for a plan that deletes
/// data — the confirm token applying it needs.
#[kynos::get("/pool/plans/{plan_id}", tag = Pool)]
pub async fn get_plan(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<PlanPath>,
) -> Result<Json<Plan>, GetPlanError> {
    let pool = s.pool.clone().ok_or(GetPlanError::PoolNotConfigured)?;
    blocking(move || load_plan(&pool, p.plan_id))
        .await
        .map_err(|detail| GetPlanError::Internal { detail })?
        .map(Json)
        .ok_or(GetPlanError::PlanNotFound)
}

/// Why a plan was not discarded.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum DeletePlanError {
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// No plan has this id.
    #[error("no such plan")]
    #[problem(status = 404, title = "Plan not found")]
    PlanNotFound,
    /// The plan is mid-apply.
    #[error("plan is mid-apply; it will be resumed rather than discarded")]
    #[problem(status = 409, title = "The plan is being applied")]
    PlanApplying,
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// Discard a mutation plan.
///
/// Removes the plan and its steps, whatever it did. Nothing on disk changes:
/// discarding an applied plan does not undo it. A plan mid-apply is refused —
/// startup resumes it rather than losing track of half a change.
#[kynos::delete("/pool/plans/{plan_id}", tag = Pool)]
pub async fn delete_plan(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<PlanPath>,
) -> Result<NoContent, DeletePlanError> {
    let pool = s.pool.clone().ok_or(DeletePlanError::PoolNotConfigured)?;
    let fail = |e: torrentd_pool::PoolError| DeletePlanError::Internal {
        detail: internal("discarding a plan", e),
    };
    // On the blocking pool, and on the writer for the read as well as the
    // delete: the status that refuses a plan mid-apply must be the one the
    // delete acts on.
    blocking(move || {
        let Some(plan) = pool.with_store(|st| st.plan(p.plan_id)).map_err(fail)? else {
            return Err(DeletePlanError::PlanNotFound);
        };
        if plan.status == torrentd_pool::model::plan_status::APPLYING {
            return Err(DeletePlanError::PlanApplying);
        }
        pool.with_store_mut(|st| st.delete_plan(p.plan_id))
            .map_err(fail)?;
        Ok(NoContent)
    })
    .await
}

/// Consent to apply a plan.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    /// The plan's `confirm_token`, for a plan that deletes data; `null` or
    /// absent for any other.
    pub confirm_token: Option<String>,
}

/// What applying a plan did.
#[derive(Debug, Schema, Serialize)]
pub struct ApplyOutcome {
    /// The plan.
    pub plan_id: i64,
    /// Steps performed by this apply.
    pub done: u32,
    /// Steps that failed; an apply stops at the first.
    pub failed: u32,
    /// Steps already done by an earlier apply, and not repeated.
    pub skipped: u32,
    /// Where the plan stands now: `applied`, or `failed` when a step failed —
    /// the plan's steps then show which, and why.
    pub status: PlanStatus,
}

/// Why a plan was not applied.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum ApplyPlanError {
    /// `[pool] allow_mutations` is off.
    #[error("{MUTATIONS_DISABLED}")]
    #[problem(status = 403, title = "Pool mutations are disabled")]
    MutationsDisabled,
    /// The daemon has no `[pool]` section.
    #[error("{NO_POOL}")]
    #[problem(status = 404, title = "The pool is not configured")]
    PoolNotConfigured,
    /// No plan has this id.
    #[error("no such plan")]
    #[problem(status = 404, title = "Plan not found")]
    PlanNotFound,
    /// The plan is applying, applied or cancelled.
    #[error("{0}")]
    #[problem(status = 409, title = "The plan cannot be applied")]
    PlanNotDraft(String),
    /// Applying refused to start, or stopped, on an error.
    #[error("{0}")]
    #[problem(status = 409, title = "Applying the plan failed")]
    ApplyFailed(String),
    /// The plan deletes data and the request carries no confirm token.
    #[error("this plan deletes data; re-send with the plan's confirm_token")]
    #[problem(status = 422, title = "A confirm token is required")]
    ConfirmTokenRequired,
    /// The confirm token is not this plan's.
    #[error("confirm_token is not this plan's; fetch the plan and re-send its token")]
    #[problem(status = 422, title = "The confirm token does not match")]
    ConfirmTokenMismatch,
    /// The pool index failed; the daemon's log has the cause.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// Whether a plan in `status` can be claimed for an apply.
///
/// `failed` can: applying again retries from the first step not done, which is
/// how an operator continues after fixing what stopped it.
fn applicable(status: PlanStatus) -> bool {
    matches!(status, PlanStatus::Draft | PlanStatus::Failed)
}

/// Apply a mutation plan.
///
/// Performs every step not yet done, in order, and waits for the last: a
/// large delete or a cross-device move can run for minutes. Each step is
/// journalled before it is attempted, and applying stops at the first failure
/// — answering `200` with `status: failed` and the plan's steps saying which
/// and why. A `failed` plan can be applied again to retry.
///
/// A plan that deletes data applies only with its `confirm_token`: not a
/// security control, but a guard against applying the wrong plan id. Refused
/// with `403 mutations-disabled` unless `[pool] allow_mutations` is set.
#[kynos::post("/pool/plans/{plan_id}/apply", tag = Pool)]
pub async fn apply_plan(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<PlanPath>,
    Json(req): Json<ApplyRequest>,
) -> Result<Json<ApplyOutcome>, ApplyPlanError> {
    let pool = s.pool.clone().ok_or(ApplyPlanError::PoolNotConfigured)?;
    if !pool.allow_mutations() {
        return Err(ApplyPlanError::MutationsDisabled);
    }
    let id = p.plan_id;
    let reader = Arc::clone(&pool);
    let plan = blocking(move || load_plan(&reader, id))
        .await
        .map_err(|detail| ApplyPlanError::Internal { detail })?
        .ok_or(ApplyPlanError::PlanNotFound)?;
    if !applicable(plan.status) {
        return Err(ApplyPlanError::PlanNotDraft(format!(
            "plan is {}; only a draft or failed plan can be applied",
            plan.status
        )));
    }

    // Deleting data takes a second, deliberate call carrying a value only the
    // plan could have produced. Not a security control — a guard against
    // applying the wrong plan id.
    //
    // Checked against the writer, not the snapshot `load_plan` read: during
    // a scan the reader still shows the previous index generation, so a token
    // read before the rescan would match there and the plan would then run on
    // the rescanned index. The writer waits for the scan to commit and
    // answers with the generation the executor will see.
    if plan.confirm_token.is_some() {
        let Some(got) = req.confirm_token else {
            return Err(ApplyPlanError::ConfirmTokenRequired);
        };
        let writer = Arc::clone(&pool);
        let expected = blocking(move || {
            writer
                .with_store(|st| -> Result<_, torrentd_pool::PoolError> {
                    Ok((st.plan_steps(id)?, st.index_generation()?))
                })
                .map(|(steps, generation)| {
                    torrentd_pool::plan::confirm_token(id, generation, &steps)
                })
                .map_err(|e| internal("reading a plan", e))
        })
        .await
        .map_err(|detail| ApplyPlanError::Internal { detail })?;
        if got != expected {
            return Err(ApplyPlanError::ConfirmTokenMismatch);
        }
    }

    let source = s.source.clone();
    let state = s.state.clone();
    let worker = Arc::clone(&pool);
    // Moving payload is blocking work and can run long; keep it off the async
    // runtime so the rest of the API stays responsive. The apply checks the
    // shutdown latch between steps, and the guard it holds is what the
    // teardown waits on before it closes the sessions a move goes through.
    let work = Arc::clone(&s.work);
    let guard = work.enter();
    let outcome = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        crate::pool_apply::apply(&worker, &source, &state, id, &|| work.is_cancelled())
    })
    .await
    .map_err(|e| ApplyPlanError::Internal {
        detail: internal("applying a plan", e),
    })?;

    match outcome {
        Ok(o) => Ok(Json(ApplyOutcome {
            plan_id: o.plan_id,
            done: count(o.done),
            failed: count(o.failed),
            skipped: count(o.skipped),
            status: PlanStatus::parse(&o.status).ok_or_else(|| ApplyPlanError::Internal {
                detail: unknown("plan status", &o.status),
            })?,
        })),
        // The executor reports every refusal as prose. Another request
        // claiming the plan between the check above and the executor's own
        // claim is told apart by the plan's status now; anything else is the
        // executor refusing or stopping.
        Err(reason) => match blocking(move || load_plan(&pool, id)).await {
            Ok(None) => Err(ApplyPlanError::PlanNotFound),
            Ok(Some(now)) if !applicable(now.status) => Err(ApplyPlanError::PlanNotDraft(reason)),
            _ => Err(ApplyPlanError::ApplyFailed(reason)),
        },
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Operations that take no request body.
macro_rules! bodyless_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![
            crate::http::v1::pool::get_pool,
            crate::http::v1::pool::get_pool_tree,
            crate::http::v1::pool::list_pool_orphans,
            crate::http::v1::pool::list_pool_torrents,
            crate::http::v1::pool::scan_pool,
            crate::http::v1::pool::check_pool_drift,
            crate::http::v1::pool::list_plans,
            crate::http::v1::pool::get_plan,
            crate::http::v1::pool::delete_plan,
        ])
    };
}
pub(crate) use bodyless_routes;

/// Operations whose body is bounded by `MAX_BODY_BYTES` and whose request is
/// bounded by `REQUEST_DEADLINE`.
macro_rules! body_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![
            crate::http::v1::pool::adopt_pool_torrents,
            crate::http::v1::pool::verify_pool_torrents,
            crate::http::v1::pool::create_plan,
        ])
    };
}
pub(crate) use body_routes;

/// Operations whose body is bounded by `MAX_BODY_BYTES` and that may run for
/// minutes, so carry no deadline: applying a plan waits for every step.
macro_rules! long_body_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![crate::http::v1::pool::apply_plan])
    };
}
pub(crate) use long_body_routes;

#[cfg(test)]
mod tests {
    use torrentd_engine::InfoHash;

    use super::*;
    use crate::app_state::build_test_state;

    const IH: &str = "0101010101010101010101010101010101010101";

    fn ih() -> InfoHashHex {
        IH.parse().unwrap()
    }

    #[test]
    fn adopting_an_infohash_another_profile_holds_is_refused() {
        // Safety Rule 3. libtorrent cannot see this: a profile is a separate
        // session, so the add into profile B would have succeeded and the same
        // info-hash would have started announcing from a second account. The
        // registry is the only thing with a cross-profile view, which is why
        // the claim has to happen before the session ever sees the torrent.
        let s = build_test_state(None);
        let hash = InfoHash::from_hex(IH).unwrap();
        s.registry.assign(hash, ProfileId::new("acct_a")).unwrap();

        let err = claim_in_registry(&s, ih(), &ProfileId::new("acct_b")).unwrap_err();
        assert!(
            err.contains("already loaded in profile acct_a"),
            "got {err}"
        );
    }

    #[test]
    fn a_free_infohash_is_claimed_before_the_add() {
        let s = build_test_state(None);
        let profile = ProfileId::new("acct_a");
        assert!(claim_in_registry(&s, ih(), &profile).is_ok());
        let hash = InfoHash::from_hex(IH).unwrap();
        assert_eq!(s.registry.lookup(&hash), Some(profile));
    }

    #[test]
    fn re_adopting_a_torrent_this_profile_already_holds_is_refused() {
        // Not a no-op: the session already has it, and `duplicate_is_error`
        // would reject the add anyway. Refusing here keeps the message honest
        // and means a failed add can always release its own claim safely.
        let s = build_test_state(None);
        let profile = ProfileId::new("acct_a");
        claim_in_registry(&s, ih(), &profile).unwrap();
        let err = claim_in_registry(&s, ih(), &profile).unwrap_err();
        assert!(
            err.contains("already loaded in profile acct_a"),
            "got {err}"
        );
    }

    #[test]
    fn a_released_claim_can_be_retried() {
        let s = build_test_state(None);
        let profile = ProfileId::new("acct_a");
        claim_in_registry(&s, ih(), &profile).unwrap();
        release_claim(&s, ih());
        assert!(claim_in_registry(&s, ih(), &profile).is_ok());
    }

    #[test]
    fn tree_keys_sort_in_the_order_the_store_lists_children() {
        // Directories first, then files, each by path: the cursor compares
        // keys, so the key order has to be the listing order.
        let listed = [("b", true), ("z", true), ("a.bin", false), ("c.bin", false)];
        let keys: Vec<String> = listed.iter().map(|(p, d)| tree_key(p, *d)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn plan_keys_sort_numerically() {
        assert!(plan_key(9) < plan_key(10));
        assert!(plan_key(99) < plan_key(100_000));
    }

    #[test]
    fn every_stored_plan_and_step_string_has_a_wire_name() {
        use torrentd_pool::model::ops;
        use torrentd_pool::model::plan_status as ps;
        use torrentd_pool::model::step_status as ss;
        for s in [
            ps::DRAFT,
            ps::APPLYING,
            ps::APPLIED,
            ps::FAILED,
            ps::CANCELLED,
        ] {
            assert_eq!(PlanStatus::parse(s).unwrap().as_str(), s);
        }
        for s in [
            ss::PENDING,
            ss::IN_PROGRESS,
            ss::DONE,
            ss::FAILED,
            ss::SKIPPED,
        ] {
            assert_eq!(StepStatus::parse(s).unwrap().as_str(), s);
        }
        for s in [ops::MOVE_TORRENT, ops::DELETE_FILE] {
            assert_eq!(StepOp::parse(s).unwrap().as_str(), s);
        }
        for spec in [
            torrentd_pool::PlanSpec::Relocate {
                infohash: IH.to_owned(),
                dest_root_id: 1,
                dest_rel: String::new(),
            },
            torrentd_pool::PlanSpec::DeleteOrphans {
                root_id: 1,
                prefix: String::new(),
            },
        ] {
            assert_eq!(PlanKind::parse(spec.kind()).unwrap().as_str(), spec.kind());
        }
    }
}
