//! `/slots` endpoints (multi-slot mode only; mounted conditionally).

use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use seederd_engine::SlotId;
use seederd_engine::SlotStatus;
use serde::Serialize;
use tracing::info;

use crate::app_state::AppState;
use crate::http::torrents::summarize;
use crate::http::torrents::TorrentSummary;
use crate::slot_registry::SlotEntry;

#[derive(Serialize)]
pub struct SlotSummary {
    slot_id: String,
    status: String,
    tunnel_ip: Option<String>,
    torrent_count: usize,
    /// Configured static listen port (`null` for natpmp slots).
    listen_port: Option<u16>,
    /// How the listen port is chosen: `"static"` or `"natpmp"`.
    port_forward: String,
    /// Current effective listen port: the NAT-PMP-negotiated port for natpmp
    /// slots, else the configured static port.
    forwarded_port: Option<u16>,
    user_agent: String,
    /// Why the slot has no session. Only set when `status` is `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<String>,
}

#[derive(Serialize)]
pub struct SlotDetail {
    #[serde(flatten)]
    summary: SlotSummary,
    vpn_interface: String,
    allowed_tracker_domains: Vec<String>,
    /// Torrents currently paused because the tunnel went down.
    paused_for_vpn: u64,
    /// Whether the last NAT-PMP renewal succeeded (always `true` for static
    /// slots, which have nothing to renew).
    port_forward_ok: bool,
}

fn summary_of(s: &AppState, e: &SlotEntry) -> SlotSummary {
    let h = e.health();
    // For natpmp slots the effective port is the negotiated one; for static
    // slots it's the configured listen_port.
    let forwarded_port = h.forwarded_port.or(e.config.listen_port);
    SlotSummary {
        slot_id: e.config.id.as_str().to_string(),
        status: h.status.as_str().to_string(),
        tunnel_ip: h.tunnel_ip.map(|ip| ip.to_string()),
        torrent_count: s.registry.for_slot(&e.config.id).len(),
        listen_port: e.config.listen_port,
        port_forward: e.config.port_forward.as_str().to_string(),
        forwarded_port,
        user_agent: e.config.user_agent.clone(),
        failure_reason: None,
    }
}

fn not_configured() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "slots not configured"})),
    )
}
fn no_such_slot() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "unknown slot_id"})),
    )
}
fn slot_vpn_down() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "slot vpn_down; restart daemon to resume"})),
    )
}

/// Summarise a slot that never got a session.
///
/// Reported rather than omitted: a slot whose tunnel failed used to vanish
/// from this list entirely, so the operator saw a short list with no
/// indication that an account was missing.
fn summary_of_failed(f: &crate::slot_registry::FailedSlot) -> SlotSummary {
    SlotSummary {
        slot_id: f.config.id.as_str().to_string(),
        status: SlotStatus::Failed.as_str().to_string(),
        tunnel_ip: None,
        torrent_count: 0,
        listen_port: f.config.listen_port,
        port_forward: f.config.port_forward.as_str().to_string(),
        forwarded_port: None,
        user_agent: f.config.user_agent.clone(),
        failure_reason: Some(f.reason.clone()),
    }
}

pub async fn list(
    State(s): State<AppState>,
) -> Result<Json<Vec<SlotSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let slots = s.slots.as_ref().ok_or_else(not_configured)?;
    let mut out: Vec<SlotSummary> = slots.iter().map(|e| summary_of(&s, e)).collect();
    out.extend(slots.failed().iter().map(summary_of_failed));
    Ok(Json(out))
}

pub async fn get(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SlotDetail>, (StatusCode, Json<serde_json::Value>)> {
    let slots = s.slots.as_ref().ok_or_else(not_configured)?;
    let slot_id = SlotId::new(id);
    let Some(e) = slots.get(&slot_id) else {
        // A configured slot that failed to come up is still a slot; answering
        // 404 would be indistinguishable from a typo in the id.
        if let Some(f) = slots.failed_slot(&slot_id) {
            return Ok(Json(SlotDetail {
                summary: summary_of_failed(f),
                vpn_interface: f.config.vpn_interface.clone(),
                allowed_tracker_domains: f.config.allowed_tracker_domains.clone(),
                paused_for_vpn: 0,
                port_forward_ok: false,
            }));
        }
        return Err(no_such_slot());
    };
    let h = e.health();
    Ok(Json(SlotDetail {
        summary: summary_of(&s, e),
        vpn_interface: e.config.vpn_interface.clone(),
        allowed_tracker_domains: e.config.allowed_tracker_domains.clone(),
        paused_for_vpn: h.paused_for_vpn,
        port_forward_ok: h.port_forward_ok,
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
    // A VpnDown slot is fenced: its torrents were paused because the tunnel is
    // gone. Refuse to resume until the operator restarts (PRD: no auto-restart).
    if entry.health().status == SlotStatus::VpnDown {
        return Err(slot_vpn_down());
    }
    let mut count = 0usize;
    for h in s.state.handles_for_slot(&slot_id) {
        if entry.engine.resume_torrent(h).is_ok() {
            count += 1;
        }
    }
    info!(slot_id = %slot_id, torrent_count = count, "resumed all torrents in slot");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::Path;
    use axum::extract::State;

    use super::*;
    use crate::app_state::build_test_state;
    use crate::slot_registry::test_entry;
    use crate::slot_registry::SlotRegistry;

    #[tokio::test]
    async fn resume_all_on_vpndown_slot_is_409() {
        let reg = Arc::new(SlotRegistry::new(vec![test_entry(
            "acct_a",
            SlotStatus::VpnDown,
        )]));
        let s = build_test_state(Some(reg));
        let err = resume_all(State(s), Path("acct_a".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn resume_all_on_active_slot_is_204() {
        let reg = Arc::new(SlotRegistry::new(vec![test_entry(
            "acct_a",
            SlotStatus::Active,
        )]));
        let s = build_test_state(Some(reg));
        let code = resume_all(State(s), Path("acct_a".to_string()))
            .await
            .unwrap();
        assert_eq!(code, StatusCode::NO_CONTENT);
    }
}
