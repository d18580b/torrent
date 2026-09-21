//! `/profiles` endpoints. Always mounted: a daemon always has at least one
//! profile.

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
    /// `None` for a host profile that did not override it.
    user_agent: Option<String>,
    /// Why the profile has no session. Only set when `status` is `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileDetail {
    #[serde(flatten)]
    summary: ProfileSummary,
    /// `None` for a host profile.
    vpn_interface: Option<String>,
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
    let forwarded_port = h.forwarded_port.or(e.config.listen_port());
    ProfileSummary {
        profile_id: e.config.id.as_str().to_string(),
        status: h.status.as_str().to_string(),
        tunnel_ip: h.tunnel_ip.map(|ip| ip.to_string()),
        torrent_count: s.registry.for_profile(&e.config.id).len(),
        listen_port: e.config.listen_port(),
        port_forward: e.config.port_forward().as_str().to_string(),
        forwarded_port,
        user_agent: e.config.user_agent.clone(),
        failure_reason: None,
    }
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

/// A configured profile that never got a session cannot act on its torrents.
///
/// 409 with the bring-up failure, not 404: the id is in the config file, so
/// "unknown profile_id" sends the operator to look for a typo that is not
/// there. The reason is the one thing that tells them what to fix.
fn profile_failed(reason: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": format!(
                "profile has no session: {reason}. Its torrents are not loaded; fix the \
                 profile and restart the daemon."
            )
        })),
    )
}

/// Summarise a profile that never got a session.
///
/// Reported rather than omitted: a profile whose tunnel failed used to vanish
/// from this list entirely, so the operator saw a short list with no
/// indication that an account was missing.
fn summary_of_failed(s: &AppState, f: &crate::profile_registry::FailedProfile) -> ProfileSummary {
    ProfileSummary {
        profile_id: f.config.id.as_str().to_string(),
        status: ProfileStatus::Failed.as_str().to_string(),
        tunnel_ip: None,
        // From the registry, like every other profile's. Hardcoding 0 here
        // reported no stranded torrents for the profile whose stranded
        // torrents are exactly what the operator is hunting: the registry
        // typically still holds its assignments, and none of them are loaded.
        torrent_count: s.registry.for_profile(&f.config.id).len(),
        listen_port: f.config.listen_port(),
        port_forward: f.config.port_forward().as_str().to_string(),
        forwarded_port: None,
        user_agent: f.config.user_agent.clone(),
        failure_reason: Some(f.reason.clone()),
    }
}

/// `GET /api/profiles`.
///
/// **Order is part of the contract**: live profiles first, in the order their
/// `[[profile]]` tables appear in the config file, then the profiles that
/// failed to come up, in config order among themselves. Configured order is
/// what `ProfileSource`'s `Vec` already gives every other consumer and what
/// the operator wrote; sorting by id would throw it away.
///
/// It is stated because something depends on it. It is not, however, a
/// substitute for a client checking `status`: the first entry is only an
/// `active` profile when at least one came up, so a client picking a default
/// target filters on `status == "active"` rather than taking `[0]`.
pub async fn list(
    State(s): State<AppState>,
) -> Result<Json<Vec<ProfileSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let profiles = &s.profiles;
    let mut out: Vec<ProfileSummary> = profiles.iter().map(|e| summary_of(&s, e)).collect();
    out.extend(profiles.failed().iter().map(|f| summary_of_failed(&s, f)));
    Ok(Json(out))
}

pub async fn get(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ProfileDetail>, (StatusCode, Json<serde_json::Value>)> {
    let profiles = &s.profiles;
    let profile_id = ProfileId::new(id);
    let Some(e) = profiles.get(&profile_id) else {
        // A configured profile that failed to come up is still a profile; answering
        // 404 would be indistinguishable from a typo in the id.
        if let Some(f) = profiles.failed_profile(&profile_id) {
            return Ok(Json(ProfileDetail {
                summary: summary_of_failed(&s, f),
                vpn_interface: f.config.vpn_interface().map(str::to_string),
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
        vpn_interface: e.config.vpn_interface().map(str::to_string),
        allowed_tracker_domains: e.config.allowed_tracker_domains.clone(),
        paused_for_vpn: h.paused_for_vpn,
        port_forward_ok: h.port_forward_ok,
    }))
}

/// `GET /api/profiles/:profile_id/torrents`.
///
/// Serves a **failed** profile's entries too. This route reads
/// `s.registry.for_profile` and needs no engine, so there is nothing for a
/// failed profile to be missing — and `GET /api/profiles` now reports that
/// profile a non-zero `torrent_count` computed from the same registry,
/// precisely so an operator can find the torrents stranded by a tunnel that
/// did not come up. Answering 404 here made the one question that count raises
/// unanswerable, thirty lines below `get`'s own comment arguing the opposite.
pub async fn torrents(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<TorrentSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let profiles = &s.profiles;
    let profile_id = ProfileId::new(id);
    if !profiles.is_configured(&profile_id) {
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
    let profiles = &s.profiles;
    let profile_id = ProfileId::new(id);
    let Some(entry) = profiles.get(&profile_id) else {
        // Configured but never brought up: refuse with the reason rather than
        // deny the id exists.
        if let Some(f) = profiles.failed_profile(&profile_id) {
            return Err(profile_failed(&f.reason));
        }
        return Err(no_such_profile());
    };
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
    let profiles = &s.profiles;
    let profile_id = ProfileId::new(id);
    let Some(entry) = profiles.get(&profile_id) else {
        if let Some(f) = profiles.failed_profile(&profile_id) {
            return Err(profile_failed(&f.reason));
        }
        return Err(no_such_profile());
    };
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

    // -----------------------------------------------------------------
    // C30 — the three routes that resolve a caller-supplied id against a
    // profile that is configured but never came up.
    //
    // All three used to answer 404 "unknown profile_id", which is what a typo
    // gets: it sends the operator to the config file to look for an id that is
    // already in it. `/profiles` lists that profile with a non-zero
    // `torrent_count` read from the assignment registry, so the drill-down is
    // exactly the question the list invites.
    // -----------------------------------------------------------------

    /// One configured profile, failed at bring-up, with no live session.
    fn failed_only(id: &str, reason: &str) -> AppState {
        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_failed_profile;

        let reg = Arc::new(
            ProfileRegistry::new(vec![]).with_failed(vec![test_failed_profile(id, reason)]),
        );
        build_test_state_with_sessions(Some(reg), &[])
    }

    #[tokio::test]
    async fn torrents_of_a_failed_profile_are_served_not_404() {
        // This route reads the assignment registry and needs no engine, so
        // there is nothing a failed profile is missing. Refusing it withholds
        // the one list the `torrent_count` on `/profiles` invites the operator
        // to ask for.
        let s = failed_only("acct_b", "wg-acct_b: no handshake");
        let out = torrents(State(s), Path("acct_b".to_string()))
            .await
            .expect("a configured profile's registry entries are readable without a session");
        assert!(
            out.0.is_empty(),
            "no assignments in this fixture, but the route answered rather than refusing",
        );
    }

    #[tokio::test]
    async fn an_id_no_profile_declares_is_still_404_on_torrents() {
        // The pairing must not turn every typo into a 200.
        let s = failed_only("acct_b", "wg-acct_b: no handshake");
        // `TorrentSummary` is not `Debug`, so match rather than `unwrap_err`.
        match torrents(State(s), Path("typo".to_string())).await {
            Err(e) => assert_eq!(e.0, StatusCode::NOT_FOUND),
            Ok(_) => panic!("an id no [[profile]] declares must still be 404"),
        }
    }

    #[tokio::test]
    async fn pause_all_on_a_failed_profile_is_409_with_the_reason() {
        let s = failed_only("acct_b", "wg-acct_b: no handshake");
        let err = pause_all(State(s), Path("acct_b".to_string()))
            .await
            .unwrap_err();
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "the id is configured, so 404 would send the operator to hunt a typo",
        );
        let body = err.1 .0.to_string();
        assert!(
            body.contains("wg-acct_b: no handshake"),
            "the bring-up reason is the only thing that says what to fix, got: {body}",
        );
    }

    #[tokio::test]
    async fn resume_all_on_a_failed_profile_is_409_with_the_reason() {
        let s = failed_only("acct_b", "wg-acct_b: no handshake");
        let err = resume_all(State(s), Path("acct_b".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        let body = err.1 .0.to_string();
        assert!(body.contains("wg-acct_b: no handshake"), "got: {body}");
    }

    #[tokio::test]
    async fn pause_all_on_an_unknown_id_is_still_404() {
        let s = failed_only("acct_b", "wg-acct_b: no handshake");
        let err = pause_all(State(s), Path("typo".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
