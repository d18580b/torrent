//! `/slots` endpoints (multi-slot mode only; mounted conditionally).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use tracing::info;

use seederd_engine::SlotId;

use crate::app_state::AppState;
use crate::http::torrents::{summarize, TorrentSummary};
use crate::slot_registry::SlotEntry;

#[derive(Serialize)]
pub struct SlotSummary {
    slot_id: String,
    status: String,
    tunnel_ip: Option<String>,
    torrent_count: usize,
    listen_port: u16,
    user_agent: String,
}

#[derive(Serialize)]
pub struct SlotDetail {
    #[serde(flatten)]
    summary: SlotSummary,
    vpn_interface: String,
    allowed_tracker_domains: Vec<String>,
    /// Torrents currently paused because the tunnel went down.
    paused_for_vpn: u64,
}

fn summary_of(s: &AppState, e: &SlotEntry) -> SlotSummary {
    let h = e.health();
    SlotSummary {
        slot_id: e.config.id.as_str().to_string(),
        status: h.status.as_str().to_string(),
        tunnel_ip: h.tunnel_ip.map(|ip| ip.to_string()),
        torrent_count: s.registry.for_slot(&e.config.id).len(),
        listen_port: e.config.listen_port,
        user_agent: e.config.user_agent.clone(),
    }
}

fn not_configured() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "slots not configured"})))
}
fn no_such_slot() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown slot_id"})))
}

pub async fn list(
    State(s): State<AppState>,
) -> Result<Json<Vec<SlotSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let slots = s.slots.as_ref().ok_or_else(not_configured)?;
    let out = slots.iter().map(|e| summary_of(&s, e)).collect();
    Ok(Json(out))
}

pub async fn get(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SlotDetail>, (StatusCode, Json<serde_json::Value>)> {
    let slots = s.slots.as_ref().ok_or_else(not_configured)?;
    let slot_id = SlotId::new(id);
    let e = slots.get(&slot_id).ok_or_else(no_such_slot)?;
    let h = e.health();
    Ok(Json(SlotDetail {
        summary: summary_of(&s, e),
        vpn_interface: e.config.vpn_interface.clone(),
        allowed_tracker_domains: e.config.allowed_tracker_domains.clone(),
        paused_for_vpn: h.paused_for_vpn,
    }))
}

pub async fn torrents(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<TorrentSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let slots = s.slots.as_ref().ok_or_else(not_configured)?;
    let slot_id = SlotId::new(id);
    if slots.get(&slot_id).is_none() {
        return Err(no_such_slot());
    }
    let items = s
        .registry
        .for_slot(&slot_id)
        .iter()
        .map(|ih| summarize(&s, ih, &slot_id))
        .collect();
    Ok(Json(items))
}

pub async fn pause_all(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let slots = s.slots.as_ref().ok_or_else(not_configured)?;
    let slot_id = SlotId::new(id);
    let entry = slots.get(&slot_id).ok_or_else(no_such_slot)?;
    let mut count = 0usize;
    for h in s.state.handles_for_slot(&slot_id) {
        if entry.engine.pause_torrent(h).is_ok() {
            count += 1;
        }
    }
    info!(slot_id = %slot_id, torrent_count = count, "paused all torrents in slot");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn resume_all(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let slots = s.slots.as_ref().ok_or_else(not_configured)?;
    let slot_id = SlotId::new(id);
    let entry = slots.get(&slot_id).ok_or_else(no_such_slot)?;
    let mut count = 0usize;
    for h in s.state.handles_for_slot(&slot_id) {
        if entry.engine.resume_torrent(h).is_ok() {
            count += 1;
        }
    }
    info!(slot_id = %slot_id, torrent_count = count, "resumed all torrents in slot");
    Ok(StatusCode::NO_CONTENT)
}
