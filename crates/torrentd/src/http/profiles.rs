//! `/profiles` endpoints (multi-profile mode only; mounted conditionally).

use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use tracing::info;

use crate::app_state::AppState;
use crate::http::torrents::summarize;
use crate::http::torrents::TorrentSummary;
use crate::profile_registry::ProfileEntry;

#[derive(Serialize)]
pub struct ProfileSummary {
    profile_id: String,
    status: String,
    tunnel_ip: Option<String>,
    torrent_count: usize,
    /// Configured static listen port (`null` for natpmp profiles).
    listen_port: Option<u16>,
    /// How the listen port is chosen: `"static"` or `"natpmp"`.
    port_forward: String,
    /// Current effective listen port: the NAT-PMP-negotiated port for natpmp
    /// profiles, else the configured static port.
    forwarded_port: Option<u16>,
    user_agent: String,
    /// Why the profile has no session. Only set when `status` is `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileDetail {
    #[serde(flatten)]
    summary: ProfileSummary,
    vpn_interface: String,
    allowed_tracker_domains: Vec<String>,
    /// Torrents currently paused because the tunnel went down.
    paused_for_vpn: u64,
    /// Whether the last NAT-PMP renewal succeeded (always `true` for static
    /// profiles, which have nothing to renew).
    port_forward_ok: bool,
}

fn summary_of(s: &AppState, e: &ProfileEntry) -> ProfileSummary {
    let h = e.health();
    // For natpmp profiles the effective port is the negotiated one; for static
    // profiles it's the configured listen_port.
    let forwarded_port = h.forwarded_port.or(e.config.listen_port);
    ProfileSummary {
        profile_id: e.config.id.as_str().to_string(),
        status: h.status.as_str().to_string(),
        tunnel_ip: h.tunnel_ip.map(|ip| ip.to_string()),
        torrent_count: s.registry.for_profile(&e.config.id).len(),
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
        Json(serde_json::json!({"error": "profiles not configured"})),
    )
}
fn no_such_profile() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "unknown profile_id"})),
    )
}
fn profile_vpn_down() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "profile vpn_down; restart daemon to resume"})),
    )
}

/// Summarise a profile that never got a session.
///
/// Reported rather than omitted: a profile whose tunnel failed used to vanish
/// from this list entirely, so the operator saw a short list with no
/// indication that an account was missing.
fn summary_of_failed(f: &crate::profile_registry::FailedProfile) -> ProfileSummary {
    ProfileSummary {
        profile_id: f.config.id.as_str().to_string(),
        status: ProfileStatus::Failed.as_str().to_string(),
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
) -> Result<Json<Vec<ProfileSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let profiles = s.profiles.as_ref().ok_or_else(not_configured)?;
    let mut out: Vec<ProfileSummary> = profiles.iter().map(|e| summary_of(&s, e)).collect();
    out.extend(profiles.failed().iter().map(summary_of_failed));
    Ok(Json(out))
}

pub async fn get(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ProfileDetail>, (StatusCode, Json<serde_json::Value>)> {
    let profiles = s.profiles.as_ref().ok_or_else(not_configured)?;
    let profile_id = ProfileId::new(id);
    let Some(e) = profiles.get(&profile_id) else {
        // A configured profile that failed to come up is still a profile; answering
        // 404 would be indistinguishable from a typo in the id.
        if let Some(f) = profiles.failed_profile(&profile_id) {
            return Ok(Json(ProfileDetail {
                summary: summary_of_failed(f),
                vpn_interface: f.config.vpn_interface.clone(),
                allowed_tracker_domains: f.config.allowed_tracker_domains.clone(),
                paused_for_vpn: 0,
                port_forward_ok: false,
            }));
        }
        return Err(no_such_profile());
    };
    let h = e.health();
    Ok(Json(ProfileDetail {
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
    let profiles = s.profiles.as_ref().ok_or_else(not_configured)?;
    let profile_id = ProfileId::new(id);
    if profiles.get(&profile_id).is_none() {
        return Err(no_such_profile());
    }
    let items = s
        .registry
        .for_profile(&profile_id)
        .iter()
        .map(|ih| summarize(&s, ih, &profile_id))
        .collect();
    Ok(Json(items))
}

pub async fn pause_all(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let profiles = s.profiles.as_ref().ok_or_else(not_configured)?;
    let profile_id = ProfileId::new(id);
    let entry = profiles.get(&profile_id).ok_or_else(no_such_profile)?;
    let mut count = 0usize;
    for h in s.state.handles_for_profile(&profile_id) {
        if entry.engine.pause_torrent(h).is_ok() {
            count += 1;
        }
    }
    info!(profile_id = %profile_id, torrent_count = count, "paused all torrents in profile");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn resume_all(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let profiles = s.profiles.as_ref().ok_or_else(not_configured)?;
    let profile_id = ProfileId::new(id);
    let entry = profiles.get(&profile_id).ok_or_else(no_such_profile)?;
    // A VpnDown profile is fenced: its torrents were paused because the tunnel is
    // gone. Refuse to resume until the operator restarts.
    if entry.health().status == ProfileStatus::VpnDown {
        return Err(profile_vpn_down());
    }
    let mut count = 0usize;
    for h in s.state.handles_for_profile(&profile_id) {
        if entry.engine.resume_torrent(h).is_ok() {
            count += 1;
        }
    }
    info!(profile_id = %profile_id, torrent_count = count, "resumed all torrents in profile");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::Path;
    use axum::extract::State;

    use super::*;
    use crate::app_state::build_test_state;
    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    #[tokio::test]
    async fn resume_all_on_vpndown_profile_is_409() {
        let reg = Arc::new(ProfileRegistry::new(vec![test_entry(
            "acct_a",
            ProfileStatus::VpnDown,
        )]));
        let s = build_test_state(Some(reg));
        let err = resume_all(State(s), Path("acct_a".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn resume_all_on_active_profile_is_204() {
        let reg = Arc::new(ProfileRegistry::new(vec![test_entry(
            "acct_a",
            ProfileStatus::Active,
        )]));
        let s = build_test_state(Some(reg));
        let code = resume_all(State(s), Path("acct_a".to_string()))
            .await
            .unwrap();
        assert_eq!(code, StatusCode::NO_CONTENT);
    }
}
