//! `/torrents` and `/torrents/:infohash` endpoints.

use std::path::Path as FsPath;
use std::path::PathBuf;

use axum::extract::FromRequest;
use axum::extract::Multipart;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::Request;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use libtorrent_safe::info_hash_from_magnet;
use libtorrent_safe::info_hash_from_torrent;
use libtorrent_safe::AddParams;
use libtorrent_safe::InfoHash;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;

use crate::app_state::AppState;

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;

/// Upper bound on a `POST /torrents` body (JSON or a multipart `.torrent`
/// upload). Also installed as the router's `DefaultBodyLimit`.
pub(crate) const MAX_BODY_BYTES: usize = 50 * 1024 * 1024;

/// Upper bound on a `.torrent` read from the daemon's own filesystem.
///
/// A torrent file is metadata: even a multi-terabyte v1 torrent with 16 KiB
/// pieces is a few hundred MiB of piece hashes, and anything past this is not
/// a torrent worth parsing.
const MAX_TORRENT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Resolved add source, carrying the bytes/uri needed to (a) compute the
/// info-hash up front and (b) build the engine params after the registry
/// reservation succeeds.
enum AddSource {
    Magnet(String),
    File(Vec<u8>),
}

#[derive(Deserialize)]
pub struct ListQuery {
    after: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
pub struct TorrentSummary {
    infohash: String,
    profile_id: String,
    phase: String,
    upload_rate: i64,
    download_rate: i64,
    total_uploaded: u64,
    total_payload_uploaded: u64,
    num_peers: i32,
    progress: f32,
    is_finished: bool,
    is_seeding: bool,
}

#[derive(Serialize)]
pub struct ListResponse {
    items: Vec<TorrentSummary>,
    next_cursor: Option<String>,
}

/// Build the wire summary for one torrent (registry profile + live state).
pub(crate) fn summarize(s: &AppState, ih: &InfoHash, profile: &ProfileId) -> TorrentSummary {
    let st = s.state.get(ih);
    TorrentSummary {
        infohash: ih.to_hex(),
        profile_id: profile.as_str().to_string(),
        phase: st
            .as_ref()
            .map(|s| s.phase.as_str().to_string())
            .unwrap_or_else(|| "unknown".into()),
        upload_rate: st.as_ref().map(|s| s.upload_rate).unwrap_or(0),
        download_rate: st.as_ref().map(|s| s.download_rate).unwrap_or(0),
        total_uploaded: st.as_ref().map(|s| s.total_uploaded).unwrap_or(0),
        total_payload_uploaded: st.as_ref().map(|s| s.total_payload_uploaded).unwrap_or(0),
        num_peers: st.as_ref().map(|s| s.num_peers).unwrap_or(0),
        progress: st.as_ref().map(|s| s.progress).unwrap_or(0.0),
        is_finished: st.as_ref().map(|s| s.is_finished).unwrap_or(false),
        is_seeding: st.as_ref().map(|s| s.is_seeding).unwrap_or(false),
    }
}

pub async fn list(State(s): State<AppState>, Query(q): Query<ListQuery>) -> Json<ListResponse> {
    let limit = q.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let after = q.after.as_deref().and_then(InfoHash::from_hex);

    let mut all = s.registry.entries();
    all.sort_by_key(|(ih, _)| ih.0);
    let start = match after {
        Some(a) => all
            .iter()
            .position(|(ih, _)| ih.0 > a.0)
            .unwrap_or(all.len()),
        None => 0,
    };
    let end = (start + limit).min(all.len());
    let next_cursor = if end < all.len() {
        Some(all[end - 1].0.to_hex())
    } else {
        None
    };

    let items = all[start..end]
        .iter()
        .map(|(ih, profile)| summarize(&s, ih, profile))
        .collect();

    Json(ListResponse { items, next_cursor })
}

pub async fn get(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<Json<TorrentSummary>, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let profile = s.registry.lookup(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    Ok(Json(summarize(&s, &ih, &profile)))
}

#[derive(Deserialize)]
pub struct AddRequest {
    /// Either `magnet` or `torrent_path` is required.
    pub magnet: Option<String>,
    pub torrent_path: Option<String>,
    pub save_path: Option<String>,
    pub profile_id: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct AddResponse {
    infohash: String,
    profile_id: String,
}

type AddParse = (Option<String>, Option<String>, AddSource);
type AddError = (StatusCode, Json<serde_json::Value>);

/// `POST /torrents` accepts either a JSON body (`{magnet}` / `{torrent_path}`)
/// or a multipart upload carrying the `.torrent` file. Dispatch
/// on Content-Type, normalize to `(profile_id, save_path, AddSource)`, then run
/// one shared add path.
pub async fn add(
    State(s): State<AppState>,
    req: Request,
) -> Result<(StatusCode, Json<AddResponse>), AddError> {
    let is_multipart = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("multipart/form-data"));
    let (profile_id_opt, save_path_opt, source) = if is_multipart {
        parse_multipart(req, &s).await?
    } else {
        parse_json(req, &s).await?
    };
    do_add(&s, profile_id_opt, save_path_opt, source).await
}

async fn parse_json(req: Request, state: &AppState) -> Result<AddParse, AddError> {
    let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("read body: {e}")})),
            )
        })?;
    let r: AddRequest = serde_json::from_slice(&bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid JSON: {e}")})),
        )
    })?;
    let source = if let Some(uri) = r.magnet {
        AddSource::Magnet(uri)
    } else if let Some(path) = r.torrent_path {
        AddSource::File(read_local_torrent(state, FsPath::new(&path))?)
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "magnet or torrent_path required"})),
        ));
    };
    Ok((r.profile_id, r.save_path, source))
}

/// Read a `.torrent` the caller named by path on the daemon's own filesystem.
///
/// `torrent_path` used to be handed straight to `std::fs::read` with the OS
/// error echoed back, which made it an existence-and-permission oracle for
/// every path the daemon can reach, and an unbounded read — `/dev/zero` or a
/// large sparse file would allocate until the OOM killer arrived. The 50 MiB
/// body limit does not apply, because the bytes never cross the HTTP boundary.
///
/// It is confined to the directories the daemon already owns: the torrent
/// store, the pool's torrent library, and the managed roots. That covers what
/// the feature is for — pointing at a file the daemon put there, or at a
/// library being migrated — without turning the route into a file reader.
fn read_local_torrent(state: &AppState, path: &FsPath) -> Result<Vec<u8>, AddError> {
    let refused = |msg: &str| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
    };

    let allowed: Vec<PathBuf> = state.local_torrent_dirs();
    if !allowed
        .iter()
        .any(|d| torrentd_pool::plan::contains(d, path))
    {
        // Deliberately does not say whether the file exists.
        return Err(refused(
            "torrent_path must be inside the daemon's torrent directory, the pool library, \
             or a managed root",
        ));
    }

    let md = std::fs::symlink_metadata(path).map_err(|_| refused("no such .torrent"))?;
    if !md.is_file() {
        return Err(refused("torrent_path is not a regular file"));
    }
    if md.len() > MAX_TORRENT_FILE_BYTES {
        return Err(refused("`.torrent` file is implausibly large"));
    }
    std::fs::read(path).map_err(|_| refused("could not read that .torrent"))
}

async fn parse_multipart(req: Request, state: &AppState) -> Result<AddParse, AddError> {
    let mut mp = Multipart::from_request(req, state).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid multipart: {e}")})),
        )
    })?;
    let mut torrent: Option<Vec<u8>> = None;
    let mut profile_id: Option<String> = None;
    let mut save_path: Option<String> = None;
    while let Some(field) = mp.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("multipart field: {e}")})),
        )
    })? {
        match field.name().map(|n| n.to_string()).as_deref() {
            Some("torrent") => {
                let b = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("read torrent field: {e}")})),
                    )
                })?;
                torrent = Some(b.to_vec());
            }
            Some("profile_id") => profile_id = field.text().await.ok(),
            Some("save_path") => save_path = field.text().await.ok(),
            _ => {}
        }
    }
    let torrent = torrent.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "multipart: missing 'torrent' file field"})),
        )
    })?;
    Ok((profile_id, save_path, AddSource::File(torrent)))
}

async fn do_add(
    s: &AppState,
    profile_id_opt: Option<String>,
    save_path_opt: Option<String>,
    source: AddSource,
) -> Result<(StatusCode, Json<AddResponse>), AddError> {
    // Always required. There is no default profile to fall back to — that is
    // the point of the model: a client that does not say where a torrent goes
    // is a client that does not know, and guessing meant guessing which
    // account announces it.
    let Some(profile_id) = profile_id_opt.as_deref().map(ProfileId::new) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "profile_id is required"})),
        ));
    };

    let engine = s.source.engine_for(&profile_id).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unknown profile_id"})),
        )
    })?;

    // Don't accept new torrents into a fenced (VpnDown) profile — they would land
    // paused and mislead the operator into thinking the profile is healthy.
    if s.profile_vpn_down(&profile_id) {
        return Err(vpn_down());
    }

    // An unconstrained save_path points libtorrent at any directory the daemon
    // can write, including inside a managed root — where the payload would
    // have no claim rows until the next scan and would read as an orphan.
    let save_path = match save_path_opt {
        None => s.default_save_path.to_string_lossy().into_owned(),
        Some(p) => {
            let candidate = FsPath::new(&p);
            let permitted = std::iter::once(s.default_save_path.clone())
                .chain(s.pool.iter().flat_map(|pool| {
                    pool.roots()
                        .iter()
                        .map(|(_, r)| r.clone())
                        .collect::<Vec<_>>()
                }))
                .any(|d| torrentd_pool::plan::contains(&d, candidate));
            if !permitted {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "save_path must be inside default_save_path or a managed root"
                    })),
                ));
            }
            p
        }
    };
    let Some(profile_cfg) = s.profile_config(&profile_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unknown profile_id"})),
        ));
    };
    let flags = torrentd_engine::seed_flags(profile_cfg);

    // Compute the info-hash WITHOUT touching any session: Safety Rule 4
    // (the session never receives an unverified torrent) and Rule 3 (global
    // info-hash uniqueness across profiles).
    let infohash = match &source {
        AddSource::Magnet(uri) => info_hash_from_magnet(uri),
        AddSource::File(bytes) => info_hash_from_torrent(bytes),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid torrent: {e}")})),
        )
    })?;

    // Misconfiguration guard (multi-profile): a .torrent must announce to one of
    // the profile's allowed tracker domains. Catches uploading the wrong profile's
    // .torrent into another profile. Only checked for file adds against a
    // configured, non-empty allow-list.
    if let AddSource::File(bytes) = &source {
        let domains = s
            .profiles
            .get(&profile_id)
            .map(|e| e.config.allowed_tracker_domains.clone())
            .unwrap_or_default();
        if !domains.is_empty() {
            match libtorrent_safe::torrent_tracker_host_matches(bytes, &domains) {
                Ok(true) => {}
                Ok(false) => {
                    s.metrics.inc_counter(
                        "profile_assignment_registry_errors_total",
                        &[("profile_id", profile_id.as_str())],
                    );
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(
                            serde_json::json!({"error": "torrent does not announce to the profile's allowed_tracker_domains"}),
                        ),
                    ));
                }
                Err(e) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("tracker check: {e}")})),
                    ));
                }
            }
        }
    }

    // Reject duplicates before the session sees the torrent: 409 if the
    // info-hash is already loaded in any profile.
    if s.registry.lookup(&infohash).is_some() {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile_id.as_str())],
        );
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "info-hash already loaded"})),
        ));
    }
    // Reserve the assignment; assign() re-checks uniqueness to close any race.
    if let Err(e) = s.registry.assign(infohash, profile_id.clone()) {
        s.metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile_id.as_str())],
        );
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": format!("{e}")})),
        ));
    }

    // Now build params and hand the torrent to the session. Release the
    // reservation if the add fails so the info-hash can be retried.
    let (params, torrent_bytes) = match source {
        AddSource::Magnet(uri) => (
            AddParams::Magnet {
                uri,
                save_path,
                flags,
            },
            None,
        ),
        AddSource::File(bytes) => (
            AddParams::File {
                bytes: bytes.clone(),
                save_path,
                flags,
            },
            Some(bytes),
        ),
    };
    if let Err(e) = engine.add_torrent(params) {
        let _ = s.registry.remove(&infohash);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ));
    }

    // Persist the .torrent so the startup inventory scan can recover it if
    // resume data is ever lost.
    if let Some(bytes) = torrent_bytes {
        if let Err(e) = s.torrents.write(&profile_id, &infohash, &bytes) {
            tracing::warn!(
                infohash = %infohash,
                error.cause = %e,
                "failed to persist .torrent file",
            );
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(AddResponse {
            infohash: infohash.to_hex(),
            profile_id: profile_id.as_str().to_string(),
        }),
    ))
}

#[derive(Deserialize, Default)]
pub struct DeleteQuery {
    #[serde(default)]
    delete_files: bool,
}

pub async fn remove(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    // Erasing payload is a pool mutation wherever it is spelled. This route
    // predates the plan/apply machinery and used to reach `delete_files` with
    // no plan, no confirmation and no overlap check — a single request with a
    // larger blast radius than everything the planner guards.
    //
    // Refused when `[pool]` is absent too. Without a pool there is no index to
    // reason about what the payload is, which makes an unreviewable delete
    // less defensible rather than more; and `is_some_and` here would have left
    // the route wide open on exactly the deployments with the least context.
    if q.delete_files && s.pool.as_ref().is_none_or(|p| !p.allow_mutations()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "deleting payload requires a [pool] section with \
                          `allow_mutations = true`"
            })),
        ));
    }
    let profile = s.registry.lookup(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    let Some(engine) = s.source.engine_for(&profile) else {
        // The profile the registry names has no live session — it failed to
        // come up, and Safety Rule 1 left the rest of the daemon running. No
        // session holds this torrent, so there is nothing to remove from one;
        // what is left is the registry entry, and that entry is what makes
        // `POST /api/torrents` answer 409 for this info-hash. Clearing it is
        // the whole of the work. Answering 500 "engine missing" instead —
        // before ever reaching the `remove` below — left an operator no way
        // to clear it but hand-editing `profile_assignments.json`.
        if q.delete_files {
            // Refuse rather than report success for a deletion that cannot
            // happen: the payload is reachable only through the session.
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!(
                        "profile {profile} has no running session, so its payload cannot be \
                         deleted; retry without `delete_files` to clear the assignment alone"
                    )
                })),
            ));
        }
        s.registry.remove(&ih).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
        })?;
        tracing::warn!(
            target: "torrentd::http",
            infohash = %ih,
            profile_id = %profile,
            "cleared an assignment whose profile has no running session",
        );
        return Ok(StatusCode::NO_CONTENT);
    };
    let st = s.state.get(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_in_state_map"})),
        )
    })?;
    engine
        .remove_torrent(st.handle, q.delete_files)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
        })?;
    let _ = s.registry.remove(&ih);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn pause(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    let engine = s.source.engine_for(&st.profile_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "engine missing"})),
        )
    })?;
    engine.pause_torrent(st.handle).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn resume(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    // Refuse to un-quarantine a torrent whose profile the VPN monitor fenced.
    if s.profile_vpn_down(&st.profile_id) {
        return Err(vpn_down());
    }
    let engine = s.source.engine_for(&st.profile_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "engine missing"})),
        )
    })?;
    engine.resume_torrent(st.handle).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct UploadLimitBody {
    /// Bytes per second; 0 = unlimited.
    bytes_per_sec: i32,
}

pub async fn set_upload_limit(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
    Json(body): Json<UploadLimitBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // The adjacent file-priority route validates its argument before it
    // crosses the FFI boundary and this one did not, so a negative rate
    // reached libtorrent unchecked. 0 is "unlimited"; anything below it is not
    // a rate.
    if body.bytes_per_sec < 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "bytes_per_sec must be >= 0 (0 = unlimited)"
            })),
        ));
    }
    let (st, engine) = lookup_engine(&s, &infohash)?;
    engine
        .set_upload_limit(st.handle, body.bytes_per_sec)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct FilePriorityBody {
    file_idx: i32,
    /// libtorrent download_priority: 0=skip, 1=low, 4=normal, 7=high.
    priority: u8,
}

pub async fn set_file_priority(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
    Json(body): Json<FilePriorityBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // libtorrent's download_priority is 0..=7; anything else reached the shim
    // unvalidated. Reject here rather than letting an arbitrary byte cross the
    // FFI boundary and be interpreted however libtorrent happens to.
    if body.priority > 7 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "priority must be 0..=7 (0 = skip, 1 = low, 4 = normal, 7 = high)"
            })),
        ));
    }
    if body.file_idx < 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "file_idx must not be negative"})),
        ));
    }
    let (st, engine) = lookup_engine(&s, &infohash)?;
    engine
        .set_file_priority(st.handle, body.file_idx, body.priority)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

type EngineRef = std::sync::Arc<dyn torrentd_engine::TorrentEngine>;

/// Resolve `(state, engine)` for a torrent by hex infohash, or an HTTP error.
fn lookup_engine(
    s: &AppState,
    infohash: &str,
) -> Result<(torrentd_engine::TorrentState, EngineRef), AddError> {
    let ih = InfoHash::from_hex(infohash).ok_or_else(bad_infohash)?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
    })?;
    let engine = s.source.engine_for(&st.profile_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "engine missing"})),
        )
    })?;
    Ok((st, engine))
}

fn bad_infohash() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid infohash hex"})),
    )
}

fn vpn_down() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "profile vpn_down; restart daemon to resume"})),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrentd_engine::AssignmentRegistry;

    use super::*;

    /// The shared helper, with the two paths this module's tests care about
    /// pointed at a temp dir.
    fn test_state(dir: &std::path::Path) -> AppState {
        let mut app = crate::app_state::build_test_state(None);
        app.registry = Arc::new(AssignmentRegistry::new_empty(dir.join("reg.json")));
        app.default_save_path = dir.to_path_buf();
        app.torrent_dir = dir.to_path_buf();
        app
    }

    const MAGNET: &str = "magnet:?xt=urn:btih:0101010101010101010101010101010101010101";
    const MAGNET_HEX: &str = "0101010101010101010101010101010101010101";

    /// The state a profile that failed to come up leaves behind: the registry
    /// names it, `source` has no engine for it.
    fn state_with_a_stale_assignment(dir: &std::path::Path, ih: InfoHash) -> AppState {
        let app = test_state(dir);
        app.registry
            .assign(ih, ProfileId::new("gone"))
            .expect("assign");
        assert!(
            app.source.engine_for(&ProfileId::new("gone")).is_none(),
            "fixture is wrong: `gone` must have no engine",
        );
        app
    }

    #[tokio::test]
    async fn deleting_a_torrent_whose_profile_has_no_session_clears_the_assignment() {
        // Without this, `remove` answers 500 "engine missing" and never
        // reaches the `registry.remove` below it, so the entry stays. That
        // entry is what makes a re-add answer 409, which leaves the operator
        // with an info-hash that cannot be loaded, cannot be re-added and
        // cannot be deleted — clearable only by hand-editing
        // `profile_assignments.json`.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let app = state_with_a_stale_assignment(dir.path(), ih);

        let code = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery {
                delete_files: false,
            }),
        )
        .await
        .expect("delete must succeed");

        assert_eq!(code, StatusCode::NO_CONTENT);
        assert!(
            app.registry.lookup(&ih).is_none(),
            "the assignment survived the delete",
        );
    }

    #[tokio::test]
    async fn clearing_a_stale_assignment_refuses_to_pretend_it_deleted_the_payload() {
        // The payload is reachable only through the session, and there is no
        // session. Reporting 204 for a `delete_files` request would claim a
        // deletion that did not happen.
        let dir = tempfile::tempdir().unwrap();
        let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
        let mut app = state_with_a_stale_assignment(dir.path(), ih);
        // A pool that permits mutations, so the guard above this branch lets
        // the request through and it is *this* branch under test.
        app.pool = crate::pool_service::PoolService::open(
            &crate::config::Config::minimal_for_tests(dir.path(), true),
        )
        .unwrap();
        assert!(
            app.pool.as_ref().is_some_and(|p| p.allow_mutations()),
            "fixture is wrong: the mutation guard must not be what refuses",
        );

        let err = remove(
            State(app.clone()),
            Path(MAGNET_HEX.to_string()),
            Query(DeleteQuery { delete_files: true }),
        )
        .await
        .expect_err("must not report a deletion it cannot perform");

        assert_eq!(err.0, StatusCode::CONFLICT);
        let msg = err.1 .0["error"].as_str().unwrap().to_string();
        assert!(msg.contains("no running session"), "got {msg}");
        assert!(msg.contains("delete_files"), "got {msg}");
        // And the entry is still there to clear with a plain delete.
        assert!(
            app.registry.lookup(&ih).is_some(),
            "entry was cleared anyway"
        );
    }

    #[test]
    fn add_request_parses_magnet_and_profile() {
        let r: AddRequest =
            serde_json::from_str(r#"{"magnet":"magnet:?x","profile_id":"acct_a"}"#).unwrap();
        assert_eq!(r.magnet.as_deref(), Some("magnet:?x"));
        assert_eq!(r.profile_id.as_deref(), Some("acct_a"));
        assert!(r.torrent_path.is_none());
    }

    #[test]
    fn a_torrent_path_outside_the_daemons_directories_is_refused() {
        // Unconstrained, this route was an existence-and-permission oracle for
        // the whole filesystem and an unbounded read into the bencode parser.
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());

        let outside = dir.path().join("..").join("etc-shadow-ish");
        let err = read_local_torrent(&app, &outside).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let msg = err.1 .0["error"].as_str().unwrap().to_string();
        assert!(msg.contains("must be inside"), "got {msg}");
        // The refusal must not disclose whether the path exists.
        assert!(!msg.contains("No such file"), "got {msg}");
    }

    #[test]
    fn an_oversized_local_torrent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        // `test_state` points torrent_dir at `dir`, so this is inside it.
        let big = dir.path().join("huge.torrent");
        let f = std::fs::File::create(&big).unwrap();
        f.set_len(MAX_TORRENT_FILE_BYTES + 1).unwrap();

        let err = read_local_torrent(&app, &big).unwrap_err();
        let msg = err.1 .0["error"].as_str().unwrap().to_string();
        assert!(msg.contains("implausibly large"), "got {msg}");
    }

    #[test]
    fn torrent_summary_serializes_expected_schema() {
        let ts = TorrentSummary {
            infohash: "aa".into(),
            profile_id: "default".into(),
            phase: "seeding".into(),
            upload_rate: 10,
            download_rate: 0,
            total_uploaded: 4096,
            total_payload_uploaded: 4000,
            num_peers: 2,
            progress: 0.5,
            is_finished: false,
            is_seeding: true,
        };
        let v = serde_json::to_value(&ts).unwrap();
        assert_eq!(v["phase"], "seeding");
        assert_eq!(v["upload_rate"], 10);
        assert_eq!(v["total_uploaded"], 4096);
        assert_eq!(v["is_seeding"], true);
    }

    #[tokio::test]
    async fn do_add_magnet_assigns_and_calls_engine() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let (code, resp) = do_add(
            &app,
            Some("p".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap();
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(resp.0.infohash, MAGNET_HEX);
        assert_eq!(app.registry.len(), 1);
        assert_eq!(
            app.registry
                .lookup(&InfoHash::from_hex(MAGNET_HEX).unwrap())
                .unwrap()
                .as_str(),
            "p"
        );
    }

    #[tokio::test]
    async fn an_add_without_a_profile_id_is_refused() {
        // There is no default profile to fall back to. A client that does not
        // say where a torrent goes is a client that does not know, and
        // guessing meant guessing which account announces it.
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let err = do_add(&app, None, None, AddSource::Magnet(MAGNET.into()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0["error"]
            .as_str()
            .unwrap()
            .contains("profile_id is required"));
    }

    #[tokio::test]
    async fn an_add_to_an_unknown_profile_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let err = do_add(
            &app,
            Some("nope".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn do_add_duplicate_is_409() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_state(dir.path());
        let _ = do_add(
            &app,
            Some("p".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap();
        let err = do_add(
            &app,
            Some("p".into()),
            None,
            AddSource::Magnet(MAGNET.into()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
    }
}
