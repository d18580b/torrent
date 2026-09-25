//! `/profiles` endpoints. Always mounted: a daemon always has at least one
//! profile.

use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::http::torrents::paginate;
use crate::http::torrents::ListResponse;
use crate::http::torrents::PageQuery;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::Resolution;

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
    // A configured profile that failed to come up is still a profile; answering
    // 404 would be indistinguishable from a typo in the id.
    let e = match profiles.resolve(&profile_id) {
        Resolution::Active(e) => e,
        Resolution::Failed(f) => {
            return Ok(Json(ProfileDetail {
                summary: summary_of_failed(&s, f),
                vpn_interface: f.config.vpn_interface().map(str::to_string),
                allowed_tracker_domains: f.config.allowed_tracker_domains.clone(),
                paused_for_vpn: 0,
                port_forward_ok: false,
            }))
        }
        Resolution::Unknown => return Err(no_such_profile()),
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
///
/// Paginated like `GET /api/torrents` — `?after=<infohash>&limit=<n>` →
/// `{"items":[…],"next_cursor":…}` — because a profile can hold as many
/// torrents as the daemon does, and this answered every one of them at once.
pub async fn torrents(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
) -> Result<Json<ListResponse>, (StatusCode, Json<serde_json::Value>)> {
    let profiles = &s.profiles;
    let profile_id = ProfileId::new(id);
    // Active or failed alike: this route reads the registry, not an engine.
    if matches!(profiles.resolve(&profile_id), Resolution::Unknown) {
        return Err(no_such_profile());
    }
    let all = s
        .registry
        .for_profile(&profile_id)
        .into_iter()
        .map(|ih| (ih, profile_id.clone()))
        .collect();
    Ok(Json(paginate(&s, all, &q)))
}

pub async fn pause_all(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let profiles = &s.profiles;
    let profile_id = ProfileId::new(id);
    let entry = match profiles.resolve(&profile_id) {
        Resolution::Active(e) => e,
        // Configured but never brought up: refuse with the reason rather than
        // deny the id exists.
        Resolution::Failed(f) => return Err(profile_failed(&f.reason)),
        Resolution::Unknown => return Err(no_such_profile()),
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
    let entry = match profiles.resolve(&profile_id) {
        Resolution::Active(e) => e,
        Resolution::Failed(f) => return Err(profile_failed(&f.reason)),
        Resolution::Unknown => return Err(no_such_profile()),
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

/// What a daemon-wide pause or resume did, profile by profile.
///
/// 200 with a body rather than the per-profile routes' bare 204: this one
/// spans profiles that can be in different states, and an operator stopping
/// everything during an incident has to see what was not reached.
#[derive(Serialize)]
pub struct BulkOutcome {
    /// Torrents the engine accepted the pause or resume for.
    pub(crate) torrent_count: usize,
    /// Torrents whose engine call failed. Nonzero means "not everything".
    pub(crate) failed_count: usize,
    /// Profiles this request did not act on, each with why.
    pub(crate) skipped_profiles: Vec<SkippedProfile>,
}

#[derive(Serialize)]
pub struct SkippedProfile {
    pub(crate) profile_id: String,
    pub(crate) reason: String,
}

/// Apply `op` to every torrent a live profile holds; `(accepted, failed)`.
fn for_each_torrent(
    s: &AppState,
    entry: &ProfileEntry,
    op: impl Fn(&ProfileEntry, torrentd_engine::TorrentHandle) -> bool,
) -> (usize, usize) {
    let mut ok = 0usize;
    let mut failed = 0usize;
    for h in s.state.handles_for_profile(entry.id()) {
        if op(entry, h) {
            ok += 1;
        } else {
            failed += 1;
        }
    }
    (ok, failed)
}

/// The profiles that never got a session: nothing of theirs is loaded, so a
/// bulk route reports them rather than claiming to have reached them.
fn skipped_failed(s: &AppState) -> Vec<SkippedProfile> {
    s.profiles
        .failed()
        .iter()
        .map(|f| SkippedProfile {
            profile_id: f.config.id.as_str().to_string(),
            reason: format!("profile has no session: {}", f.reason),
        })
        .collect()
}

/// `POST /api/pause-all` — pause every torrent in every live profile.
///
/// Fenced profiles are paused too: their torrents are already paused, and
/// pausing again is harmless.
pub async fn pause_everything(State(s): State<AppState>) -> Json<BulkOutcome> {
    let mut out = BulkOutcome {
        torrent_count: 0,
        failed_count: 0,
        skipped_profiles: skipped_failed(&s),
    };
    for entry in s.profiles.iter() {
        let (ok, failed) = for_each_torrent(&s, entry, |e, h| e.engine.pause_torrent(h).is_ok());
        out.torrent_count += ok;
        out.failed_count += failed;
    }
    if out.failed_count > 0 {
        warn!(
            torrent_count = out.torrent_count,
            failed_count = out.failed_count,
            "daemon-wide pause did not reach every torrent"
        );
    }
    info!(
        torrent_count = out.torrent_count,
        "paused all torrents in every profile"
    );
    Json(out)
}

/// `POST /api/resume-all` — resume every torrent in every live profile that is
/// not fenced.
///
/// A fenced profile is skipped and reported, not refused wholesale: one
/// account's dead tunnel must not stop the others resuming, and resuming it
/// is exactly what `resume-all` on that profile already refuses.
pub async fn resume_everything(State(s): State<AppState>) -> Json<BulkOutcome> {
    let mut out = BulkOutcome {
        torrent_count: 0,
        failed_count: 0,
        skipped_profiles: skipped_failed(&s),
    };
    for entry in s.profiles.iter() {
        if entry.health().status == ProfileStatus::VpnDown {
            out.skipped_profiles.push(SkippedProfile {
                profile_id: entry.id().as_str().to_string(),
                reason: "profile vpn_down; restart daemon to resume".to_string(),
            });
            continue;
        }
        let (ok, failed) = for_each_torrent(&s, entry, |e, h| e.engine.resume_torrent(h).is_ok());
        out.torrent_count += ok;
        out.failed_count += failed;
    }
    if out.failed_count > 0 {
        warn!(
            torrent_count = out.torrent_count,
            failed_count = out.failed_count,
            "daemon-wide resume did not reach every torrent"
        );
    }
    info!(
        torrent_count = out.torrent_count,
        "resumed all torrents in every unfenced profile"
    );
    Json(out)
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
        let out = torrents(
            State(s),
            Path("acct_b".to_string()),
            Query(PageQuery::default()),
        )
        .await
        .expect("a configured profile's registry entries are readable without a session");
        assert!(
            out.0.items.is_empty(),
            "no assignments in this fixture, but the route answered rather than refusing",
        );
    }

    #[tokio::test]
    async fn an_id_no_profile_declares_is_still_404_on_torrents() {
        // The pairing must not turn every typo into a 200.
        let s = failed_only("acct_b", "wg-acct_b: no handshake");
        // `TorrentSummary` is not `Debug`, so match rather than `unwrap_err`.
        match torrents(
            State(s),
            Path("typo".to_string()),
            Query(PageQuery::default()),
        )
        .await
        {
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

    // -----------------------------------------------------------------
    // #23 — daemon-wide pause/resume, and pagination on a profile's torrents.
    // -----------------------------------------------------------------

    use torrentd_engine::InfoHash;
    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::TorrentHandle;
    use torrentd_engine::TorrentState;

    /// A live profile whose engine the test keeps a handle on.
    fn live(id: &str, status: ProfileStatus) -> (ProfileEntry, Arc<MockEngine>) {
        let engine = Arc::new(MockEngine::new());
        let entry = ProfileEntry::new(
            crate::profile_registry::test_entry(id, ProfileStatus::Active).config,
            engine.clone(),
            None,
            None,
            0,
        );
        entry.update_health(|h| h.status = status);
        (entry, engine)
    }

    /// Put one loaded torrent into `profile`'s slice of the state map.
    fn load(s: &AppState, byte: u8, profile: &str) -> TorrentHandle {
        let ih = InfoHash([byte; 20]);
        let h = TorrentHandle {
            id: u64::from(byte),
            infohash: ih,
        };
        s.state.insert(
            ih,
            TorrentState::newly_added(h, ProfileId::new(profile), std::time::Instant::now()),
        );
        h
    }

    fn calls_matching(engine: &MockEngine, f: impl Fn(&RecordedCall) -> bool) -> usize {
        engine.calls().iter().filter(|c| f(c)).count()
    }

    #[tokio::test]
    async fn pause_everything_reaches_every_live_profile_and_reports_the_failed_one() {
        let (a, eng_a) = live("acct_a", ProfileStatus::Active);
        // Fenced profiles are paused too; pausing a paused torrent is harmless.
        let (b, eng_b) = live("acct_b", ProfileStatus::VpnDown);
        let reg = Arc::new(ProfileRegistry::new(vec![a, b]).with_failed(vec![
            crate::profile_registry::test_failed_profile("acct_c", "wg-acct_c: no handshake"),
        ]));
        let s = build_test_state(Some(reg));
        let ha = load(&s, 1, "acct_a");
        let hb = load(&s, 2, "acct_b");

        let out = pause_everything(State(s)).await.0;

        assert_eq!(out.torrent_count, 2);
        assert_eq!(out.failed_count, 0);
        assert_eq!(
            calls_matching(
                &eng_a,
                |c| matches!(c, RecordedCall::PauseTorrent(h) if *h == ha)
            ),
            1
        );
        assert_eq!(
            calls_matching(
                &eng_b,
                |c| matches!(c, RecordedCall::PauseTorrent(h) if *h == hb)
            ),
            1
        );
        assert_eq!(out.skipped_profiles.len(), 1);
        assert_eq!(out.skipped_profiles[0].profile_id, "acct_c");
        assert!(out.skipped_profiles[0].reason.contains("no handshake"));
    }

    #[tokio::test]
    async fn pause_everything_counts_what_the_engine_refused() {
        let (a, eng_a) = live("acct_a", ProfileStatus::Active);
        let s = build_test_state(Some(Arc::new(ProfileRegistry::new(vec![a]))));
        load(&s, 1, "acct_a");
        eng_a.inject_error(
            "pause_torrent",
            torrentd_engine::EngineError::MockInjected {
                op: "pause_torrent",
                message: "boom".into(),
            },
        );

        let out = pause_everything(State(s)).await.0;

        assert_eq!(out.torrent_count, 0);
        assert_eq!(
            out.failed_count, 1,
            "a torrent left seeding must not read as paused"
        );
    }

    #[tokio::test]
    async fn resume_everything_skips_a_fenced_profile_and_resumes_the_rest() {
        let (a, eng_a) = live("acct_a", ProfileStatus::Active);
        let (b, eng_b) = live("acct_b", ProfileStatus::VpnDown);
        let reg = Arc::new(ProfileRegistry::new(vec![a, b]));
        let s = build_test_state(Some(reg));
        let ha = load(&s, 1, "acct_a");
        load(&s, 2, "acct_b");

        let out = resume_everything(State(s)).await.0;

        assert_eq!(out.torrent_count, 1);
        assert_eq!(
            calls_matching(
                &eng_a,
                |c| matches!(c, RecordedCall::ResumeTorrent(h) if *h == ha)
            ),
            1
        );
        assert_eq!(
            calls_matching(&eng_b, |c| matches!(c, RecordedCall::ResumeTorrent(_))),
            0,
            "a fenced profile must never be un-quarantined by a bulk resume",
        );
        assert_eq!(out.skipped_profiles.len(), 1);
        assert_eq!(out.skipped_profiles[0].profile_id, "acct_b");
        assert!(out.skipped_profiles[0].reason.contains("vpn_down"));
    }

    #[tokio::test]
    async fn a_profiles_torrents_are_paginated() {
        let (a, _) = live("acct_a", ProfileStatus::Active);
        let s = build_test_state(Some(Arc::new(ProfileRegistry::new(vec![a]))));
        for byte in 1..=3u8 {
            s.registry
                .assign(InfoHash([byte; 20]), ProfileId::new("acct_a"))
                .unwrap();
        }
        // Another profile's assignment must not appear on this one's list.
        s.registry
            .assign(InfoHash([9; 20]), ProfileId::new("acct_z"))
            .unwrap();

        let first = torrents(
            State(s.clone()),
            Path("acct_a".to_string()),
            Query(PageQuery {
                after: None,
                limit: Some(2),
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("a live profile's list is served"))
        .0;
        assert_eq!(first.items.len(), 2);
        let cursor = first.next_cursor.clone().expect("a third entry remains");
        assert_eq!(cursor, InfoHash([2; 20]).to_hex());

        let second = torrents(
            State(s),
            Path("acct_a".to_string()),
            Query(PageQuery {
                after: Some(cursor),
                limit: Some(2),
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("a live profile's list is served"))
        .0;
        assert_eq!(second.items.len(), 1);
        assert!(second.next_cursor.is_none());
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
