//! `/torrents` and `/torrents/:infohash` endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use libtorrent_safe::{
    info_hash_from_magnet, info_hash_from_torrent, AddParams, InfoHash, TorrentFlags,
};
use seederd_engine::{MetricsSink, SlotId};

use crate::app_state::{AppState, Mode};

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;

/// Resolved add source, carrying the bytes/uri needed to (a) compute the
/// info-hash up front and (b) build the engine params after the registry
/// reservation succeeds (PRD Safety Rule 4).
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
    slot_id: String,
    phase: String,
    upload_rate: i64,
    download_rate: i64,
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

/// Build the wire summary for one torrent (registry slot + live state).
pub(crate) fn summarize(s: &AppState, ih: &InfoHash, slot: &SlotId) -> TorrentSummary {
    let st = s.state.get(ih);
    TorrentSummary {
        infohash: ih.to_hex(),
        slot_id: slot.as_str().to_string(),
        phase: st.as_ref().map(|s| s.phase.as_str().to_string()).unwrap_or_else(|| "unknown".into()),
        upload_rate: st.as_ref().map(|s| s.upload_rate).unwrap_or(0),
        download_rate: st.as_ref().map(|s| s.download_rate).unwrap_or(0),
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
        Some(a) => all.iter().position(|(ih, _)| ih.0 > a.0).unwrap_or(all.len()),
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
        .map(|(ih, slot)| summarize(&s, ih, slot))
        .collect();

    Json(ListResponse { items, next_cursor })
}

pub async fn get(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<Json<TorrentSummary>, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let slot = s.registry.lookup(&ih).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not_found"})))
    })?;
    Ok(Json(summarize(&s, &ih, &slot)))
}

#[derive(Deserialize)]
pub struct AddRequest {
    /// Either `magnet` or `torrent_path` is required.
    pub magnet: Option<String>,
    pub torrent_path: Option<String>,
    pub save_path: Option<String>,
    pub slot_id: Option<String>,
}

#[derive(Serialize)]
pub struct AddResponse {
    infohash: String,
    slot_id: String,
}

pub async fn add(
    State(s): State<AppState>,
    Json(req): Json<AddRequest>,
) -> Result<(StatusCode, Json<AddResponse>), (StatusCode, Json<serde_json::Value>)> {
    let slot_id = match (s.mode, req.slot_id.as_deref()) {
        (Mode::Single, _) => SlotId::default_single(),
        (Mode::MultiSlot, Some(id)) => SlotId::new(id),
        (Mode::MultiSlot, None) => return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "slot_id required in multi-slot mode"})),
        )),
    };

    let engine = s.source.engine_for(&slot_id).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unknown slot_id"})))
    })?;

    let save_path = req
        .save_path
        .unwrap_or_else(|| s.default_save_path.to_string_lossy().into_owned());
    let flags = TorrentFlags::SEED_MODE
        | if !slot_id.is_default() {
            TorrentFlags::DISABLE_PEX | TorrentFlags::DISABLE_DHT | TorrentFlags::DISABLE_LSD
        } else {
            TorrentFlags::empty()
        };

    // Resolve the source and compute its info-hash WITHOUT touching any
    // session: PRD Safety Rule 4 (the session never receives an unverified
    // torrent) and Safety Rule 3 (global info-hash uniqueness across slots).
    let source = if let Some(uri) = req.magnet {
        AddSource::Magnet(uri)
    } else if let Some(path) = req.torrent_path {
        let bytes = std::fs::read(&path).map_err(|e| {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("read torrent file: {e}")})))
        })?;
        AddSource::File(bytes)
    } else {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "magnet or torrent_path required"}))));
    };
    let infohash = match &source {
        AddSource::Magnet(uri) => info_hash_from_magnet(uri),
        AddSource::File(bytes) => info_hash_from_torrent(bytes),
    }
    .map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid torrent: {e}")})))
    })?;

    // Reject duplicates before the session sees the torrent (PRD: 409 if the
    // info-hash is already loaded in any slot).
    if s.registry.lookup(&infohash).is_some() {
        s.metrics
            .inc_counter("slot_assignment_registry_errors_total", &[("slot_id", slot_id.as_str())]);
        return Err((StatusCode::CONFLICT, Json(serde_json::json!({"error": "info-hash already loaded"}))));
    }
    // Reserve the assignment; assign() re-checks uniqueness to close any race.
    if let Err(e) = s.registry.assign(infohash, slot_id.clone()) {
        s.metrics
            .inc_counter("slot_assignment_registry_errors_total", &[("slot_id", slot_id.as_str())]);
        return Err((StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("{e}")}))));
    }

    // Now build params and hand the torrent to the session. Release the
    // reservation if the add fails so the info-hash can be retried.
    let (params, torrent_bytes) = match source {
        AddSource::Magnet(uri) => (AddParams::Magnet { uri, save_path, flags }, None),
        AddSource::File(bytes) => {
            (AddParams::File { bytes: bytes.clone(), save_path, flags }, Some(bytes))
        }
    };
    if let Err(e) = engine.add_torrent(params) {
        let _ = s.registry.remove(&infohash);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{e}")}))));
    }

    // Persist the .torrent so the startup inventory scan can recover it if
    // resume data is ever lost (PRD §Session Management).
    if let Some(bytes) = torrent_bytes {
        if let Err(e) = s.torrents.write(&slot_id, &infohash, &bytes) {
            tracing::warn!(
                infohash = %infohash,
                error.cause = %e,
                "failed to persist .torrent file",
            );
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(AddResponse { infohash: infohash.to_hex(), slot_id: slot_id.as_str().to_string() }),
    ))
}

#[derive(Deserialize, Default)]
pub struct DeleteQuery { #[serde(default)] delete_files: bool }

pub async fn remove(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let slot = s.registry.lookup(&ih).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not_found"})))
    })?;
    let engine = s.source.engine_for(&slot).ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "engine missing"})))
    })?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not_in_state_map"})))
    })?;
    engine.remove_torrent(st.handle, q.delete_files).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{e}")})))
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
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not_found"})))
    })?;
    let engine = s.source.engine_for(&st.slot_id).ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "engine missing"})))
    })?;
    engine.pause_torrent(st.handle).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{e}")})))
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn resume(
    State(s): State<AppState>,
    Path(infohash): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let ih = InfoHash::from_hex(&infohash).ok_or_else(bad_infohash)?;
    let st = s.state.get(&ih).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not_found"})))
    })?;
    let engine = s.source.engine_for(&st.slot_id).ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "engine missing"})))
    })?;
    engine.resume_torrent(st.handle).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{e}")})))
    })?;
    Ok(StatusCode::NO_CONTENT)
}

fn bad_infohash() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid infohash hex"})))
}
