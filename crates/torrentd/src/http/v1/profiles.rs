//! Profiles: listing them, describing one, and pausing or resuming every
//! torrent in one profile or in all of them.
//!
//! A daemon always has at least one profile, so these are always mounted.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::security::auth::Scoped;
use serde::Serialize;
use torrentd_engine::PortForwardMode as EnginePortForwardMode;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileStatus as EngineProfileStatus;
use torrentd_engine::TorrentEngine;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Read;
use crate::http::security::Write;
use crate::http::v1::common::blocking;
use crate::http::v1::common::engine_for;
use crate::http::v1::common::from_profile_problem;
use crate::http::v1::common::unfenced_engine;
use crate::http::v1::common::InfoHashHex;
use crate::http::v1::common::ProfileProblem;
use crate::http::v1::common::ProfileUnavailableReason;
use crate::http::v1::server::count;
use crate::http::v1::Profiles;
use crate::http::v1::Torrents;
use crate::profile_registry::FailedProfile;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::Resolution;

/// Operations that take no request body.
macro_rules! bodyless_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![
            crate::http::v1::profiles::list_profiles,
            crate::http::v1::profiles::get_profile,
            crate::http::v1::profiles::pause_profile,
            crate::http::v1::profiles::resume_profile,
            crate::http::v1::profiles::pause_all_torrents,
            crate::http::v1::profiles::resume_all_torrents,
        ])
    };
}
pub(crate) use bodyless_routes;

/// Operations whose body is bounded by `MAX_BODY_BYTES`. None here.
macro_rules! body_routes {
    ($group:expr) => {
        $group
    };
}
pub(crate) use body_routes;

/// Whether a profile has a session, and whether its tunnel is up.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    /// The profile has a live session and, for a tunnelled profile, its
    /// tunnel is up.
    Active,
    /// The profile never came up at boot. It has no session and its torrents
    /// are not loaded; `failure_reason` says why.
    Failed,
    /// The VPN monitor fenced the profile after its tunnel failed: its
    /// torrents are paused and stay paused until the daemon restarts.
    VpnDown,
}

impl From<&EngineProfileStatus> for ProfileStatus {
    fn from(s: &EngineProfileStatus) -> Self {
        match s {
            EngineProfileStatus::Active => Self::Active,
            EngineProfileStatus::Failed => Self::Failed,
            EngineProfileStatus::VpnDown => Self::VpnDown,
        }
    }
}

/// How a profile's listen port is chosen.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortForwardMode {
    /// The configured `listen_port`, forwarded by the operator.
    Static,
    /// A port negotiated with the VPN gateway over NAT-PMP and renewed
    /// continuously.
    Natpmp,
}

impl From<EnginePortForwardMode> for PortForwardMode {
    fn from(m: EnginePortForwardMode) -> Self {
        match m {
            EnginePortForwardMode::Static => Self::Static,
            EnginePortForwardMode::Natpmp => Self::Natpmp,
        }
    }
}

/// One profile: one libtorrent session, usually one tracker account behind
/// one VPN tunnel.
#[derive(Debug, Schema, Serialize)]
pub struct Profile {
    /// The profile's id, as its `[[profile]]` table names it.
    pub profile_id: String,
    /// Whether the profile has a session, and whether its tunnel is up.
    pub status: ProfileStatus,
    /// The tunnel's address; `null` for a host profile, a failed one, or
    /// before the tunnel reported one.
    pub tunnel_ip: Option<String>,
    /// Torrents assigned to this profile, loaded or not. For a `failed`
    /// profile these are the torrents stranded by its missing session.
    pub torrent_count: u32,
    /// The configured static listen port; `null` for a `natpmp` profile.
    pub listen_port: Option<u16>,
    /// How the listen port is chosen.
    pub port_forward: PortForwardMode,
    /// The effective listen port now: the NAT-PMP-negotiated port for a
    /// `natpmp` profile, else the configured static port. `null` while a
    /// `natpmp` profile has none, and for a `failed` profile.
    pub forwarded_port: Option<u16>,
    /// The user agent the session announces with; `null` for a host profile
    /// that did not override libtorrent's.
    pub user_agent: Option<String>,
    /// Why the profile has no session. Set only when `status` is `failed`.
    pub failure_reason: Option<String>,
}

/// Every configured profile.
#[derive(Debug, Schema, Serialize)]
pub struct ProfileList {
    /// Live profiles in the order their `[[profile]]` tables appear in the
    /// config file, then the profiles that failed to come up, in config order
    /// among themselves. The first entry is only `active` when at least one
    /// profile came up: pick a default by filtering on `status`, not by
    /// taking the first.
    pub items: Vec<Profile>,
}

/// One profile, with its tunnel and tracker configuration.
#[derive(Debug, Schema, Serialize)]
pub struct ProfileDetail {
    /// Every member of `Profile`.
    #[serde(flatten)]
    pub profile: Profile,
    /// The VPN interface the session binds to; `null` for a host profile.
    pub vpn_interface: Option<String>,
    /// Tracker domains this profile's torrents may announce to. Empty admits
    /// any.
    pub allowed_tracker_domains: Vec<String>,
    /// Torrents currently paused because the tunnel went down.
    pub paused_for_vpn: u64,
    /// Whether the last NAT-PMP renewal succeeded. Always `true` for a
    /// `static` profile, which has nothing to renew, and `false` for a
    /// `failed` one.
    pub port_forward_ok: bool,
}

/// What a pause or resume of many torrents did.
///
/// A body rather than a bare `204`: a daemon-wide pause spans profiles that
/// can be in different states, and an operator stopping everything during an
/// incident has to see what was not reached.
#[derive(Debug, Default, Schema, Serialize)]
pub struct BulkOutcome {
    /// Torrents the engine accepted the pause or resume for.
    pub torrent_count: u32,
    /// Torrents whose engine call failed. Nonzero means not everything was
    /// reached.
    pub failed_count: u32,
    /// Which torrents those were: the 100 smallest infohashes among them, in
    /// infohash order. Retry each with its own
    /// `POST /v1/torrents/{infohash}/pause` or `/resume`; when
    /// `failed_count` is larger, repeat the bulk operation after those.
    pub failed_infohashes: Vec<InfoHashHex>,
    /// Profiles this request did not act on, each with why. Always empty for
    /// a single profile's operation, which refuses instead.
    pub skipped_profiles: Vec<SkippedProfile>,
}

/// How many failed infohashes a bulk operation names. A daemon-wide pause
/// against a session that refuses everything would otherwise answer with a
/// hundred thousand of them.
pub const MAX_REPORTED_FAILURES: usize = 100;

/// A profile a bulk operation did not act on.
#[derive(Debug, Schema, Serialize)]
pub struct SkippedProfile {
    /// The profile's id.
    pub profile_id: String,
    /// Why it was skipped.
    pub reason: ProfileUnavailableReason,
    /// The same, for a person: for a `failed` profile, its bring-up failure.
    pub detail: String,
}

/// The profile's id, as its `[[profile]]` table names it.
#[derive(Schema, PathParams)]
pub struct ProfilePath {
    /// The profile's id, as its `[[profile]]` table names it.
    pub profile_id: String,
}

fn profile_of(s: &AppState, e: &ProfileEntry) -> Profile {
    let h = e.health();
    let listen_port = e.config.listen_port();
    Profile {
        profile_id: e.config.id.as_str().to_owned(),
        status: ProfileStatus::from(&h.status),
        tunnel_ip: h.tunnel_ip.map(|ip| ip.to_string()),
        torrent_count: count(s.registry.for_profile(&e.config.id).len()),
        listen_port,
        port_forward: e.config.port_forward().into(),
        // For a natpmp profile the effective port is the negotiated one; for
        // a static one it is the configured listen_port.
        forwarded_port: h.forwarded_port.or(listen_port),
        user_agent: e.config.user_agent.clone(),
        failure_reason: None,
    }
}

/// A profile that never got a session.
///
/// Reported rather than omitted: a profile whose tunnel failed used to vanish
/// from the list entirely, so the operator saw a short list with no
/// indication that an account was missing.
fn profile_of_failed(s: &AppState, f: &FailedProfile) -> Profile {
    Profile {
        profile_id: f.config.id.as_str().to_owned(),
        status: ProfileStatus::Failed,
        tunnel_ip: None,
        // From the registry, like every other profile's. Hardcoding 0 here
        // reported no stranded torrents for the profile whose stranded
        // torrents are exactly what the operator is hunting: the registry
        // typically still holds its assignments, and none of them are loaded.
        torrent_count: count(s.registry.for_profile(&f.config.id).len()),
        listen_port: f.config.listen_port(),
        port_forward: f.config.port_forward().into(),
        forwarded_port: None,
        user_agent: f.config.user_agent.clone(),
        failure_reason: Some(f.reason.clone()),
    }
}

/// List every profile.
///
/// Live profiles first, in the order their `[[profile]]` tables appear in the
/// config file, then the profiles that failed to come up, in config order
/// among themselves. The order is part of the contract; it is not a
/// substitute for checking `status`, since the first entry is `active` only
/// when at least one profile came up.
#[kynos::get("/profiles", tag = Profiles)]
pub async fn list_profiles(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
) -> Json<ProfileList> {
    // Configured order is what the registry's `Vec` gives every other
    // consumer and what the operator wrote; sorting by id would throw it away.
    let mut items: Vec<Profile> = s.profiles.iter().map(|e| profile_of(&s, e)).collect();
    items.extend(s.profiles.failed().iter().map(|f| profile_of_failed(&s, f)));
    Json(ProfileList { items })
}

/// Why a profile could not be described.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum GetProfileError {
    /// No profile with this id is configured.
    #[error("unknown profile_id")]
    #[problem(status = 404, title = "Profile not found")]
    ProfileNotFound,
}

/// Describe one profile.
///
/// Everything `GET /v1/profiles` reports for it, plus its tunnel interface,
/// tracker allow-list, and port-forward health. A profile that failed to come
/// up is still described, with `status` `failed` and its `failure_reason`:
/// answering `404` would be indistinguishable from a typo in the id.
#[kynos::get("/profiles/{profile_id}", tag = Profiles)]
pub async fn get_profile(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(path): Path<ProfilePath>,
) -> Result<Json<ProfileDetail>, GetProfileError> {
    let profile_id = ProfileId::new(path.profile_id);
    match s.profiles.resolve(&profile_id) {
        Resolution::Active(e) => {
            let h = e.health();
            Ok(Json(ProfileDetail {
                profile: profile_of(&s, e),
                vpn_interface: e.config.vpn_interface().map(str::to_owned),
                allowed_tracker_domains: e.config.allowed_tracker_domains.clone(),
                paused_for_vpn: h.paused_for_vpn,
                port_forward_ok: h.port_forward_ok,
            }))
        }
        Resolution::Failed(f) => Ok(Json(ProfileDetail {
            profile: profile_of_failed(&s, f),
            vpn_interface: f.config.vpn_interface().map(str::to_owned),
            allowed_tracker_domains: f.config.allowed_tracker_domains.clone(),
            paused_for_vpn: 0,
            port_forward_ok: false,
        })),
        Resolution::Unknown => Err(GetProfileError::ProfileNotFound),
    }
}

/// Why a profile's torrents could not all be paused or resumed.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum ProfileBulkError {
    /// No profile with this id is configured.
    #[error("unknown profile_id")]
    #[problem(status = 404, title = "Profile not found")]
    ProfileNotFound,
    /// The profile is configured but has no session, or (for a resume) the
    /// VPN monitor fenced it.
    #[error("{detail}")]
    #[problem(status = 409, title = "The profile is unavailable")]
    ProfileUnavailable {
        detail: String,
        /// `failed` or `vpn_down`.
        #[problem(extension)]
        profile_status: &'static str,
    },
}
from_profile_problem!(ProfileBulkError);

/// What a bulk operation says of a profile that never got a session.
fn no_session_detail(reason: &str) -> String {
    format!(
        "profile has no session: {reason}. Its torrents are not loaded; fix the profile and \
         restart the daemon."
    )
}

/// `problem`, with a failed profile's detail saying what to do about it.
///
/// 409 with the bring-up failure, not 404: the id is in the config file, so
/// "unknown profile_id" sends the operator to look for a typo that is not
/// there. The reason is the one thing that tells them what to fix.
fn explain(s: &AppState, profile_id: &ProfileId, problem: ProfileProblem) -> ProfileProblem {
    match (problem, s.profiles.resolve(profile_id)) {
        (
            ProfileProblem::Unavailable {
                reason: ProfileUnavailableReason::Failed,
                ..
            },
            Resolution::Failed(f),
        ) => ProfileProblem::Unavailable {
            reason: ProfileUnavailableReason::Failed,
            detail: no_session_detail(&f.reason),
        },
        (problem, _) => problem,
    }
}

/// What one profile's share of a bulk operation reached.
struct Reached {
    /// Torrents the engine accepted the call for.
    ok: u32,
    /// Torrents it refused, all of them.
    failed_count: u32,
    /// The refused handles with the smallest infohashes: after
    /// [`Reached::keep_smallest`], at most [`MAX_REPORTED_FAILURES`] of them in
    /// infohash order. Only those can be named, so a profile whose session
    /// refuses tens of thousands of torrents hands back a bounded list rather
    /// than every one of them to sort on an async worker.
    failed: Vec<torrentd_engine::TorrentHandle>,
}

impl Reached {
    /// Count a refused handle, keeping it only while it could be named.
    ///
    /// Trims once the list reaches twice the cap, so each trim sorts a
    /// bounded list and the work stays linear in the failures.
    fn fail(&mut self, h: torrentd_engine::TorrentHandle) {
        self.failed_count = self.failed_count.saturating_add(1);
        self.failed.push(h);
        if self.failed.len() >= 2 * MAX_REPORTED_FAILURES {
            self.keep_smallest();
        }
    }

    /// Cut `failed` to the [`MAX_REPORTED_FAILURES`] smallest infohashes, in
    /// infohash order.
    fn keep_smallest(&mut self) {
        self.failed.sort_unstable_by_key(|h| h.infohash.0);
        self.failed.truncate(MAX_REPORTED_FAILURES);
    }
}

/// Apply `op` to every torrent `profile_id` holds.
///
/// On the blocking pool: each call takes the session's lock, and a profile can
/// hold tens of thousands of torrents.
async fn for_each_torrent(
    s: &AppState,
    profile_id: &ProfileId,
    engine: Arc<dyn TorrentEngine>,
    op: fn(&dyn TorrentEngine, torrentd_engine::TorrentHandle) -> bool,
) -> Reached {
    let handles = s.state.handles_for_profile(profile_id);
    blocking(move || {
        let mut reached = Reached {
            ok: 0,
            failed_count: 0,
            failed: Vec::new(),
        };
        for h in handles {
            if op(engine.as_ref(), h) {
                reached.ok = reached.ok.saturating_add(1);
            } else {
                reached.fail(h);
            }
        }
        reached.keep_smallest();
        reached
    })
    .await
}

/// Add one profile's share to `out`, naming its failures while there is room.
///
/// Across profiles the named ones are the smallest infohashes that failed,
/// so the list is the same whichever order the profiles were visited in.
/// Each profile's list is already bounded, so this merges at most twice the
/// cap.
fn tally(out: &mut BulkOutcome, reached: Reached) {
    out.torrent_count = out.torrent_count.saturating_add(reached.ok);
    out.failed_count = out.failed_count.saturating_add(reached.failed_count);
    out.failed_infohashes
        .extend(reached.failed.iter().map(|h| InfoHashHex::new(h.infohash)));
    out.failed_infohashes.sort_by_key(|ih| ih.get().0);
    out.failed_infohashes.truncate(MAX_REPORTED_FAILURES);
}

/// Pause every torrent in one profile.
///
/// A fenced (`vpn_down`) profile is paused too: its torrents are already
/// paused, and pausing again is harmless. A profile that never came up has
/// nothing loaded to pause and answers `409 profile-unavailable` with its
/// bring-up failure. `failed_count` counts torrents the engine refused.
#[kynos::post("/profiles/{profile_id}/pause-all", tag = Profiles)]
pub async fn pause_profile(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(path): Path<ProfilePath>,
) -> Result<Json<BulkOutcome>, ProfileBulkError> {
    let profile_id = ProfileId::new(path.profile_id);
    let engine = engine_for(&s, &profile_id).map_err(|p| explain(&s, &profile_id, p))?;
    let mut out = BulkOutcome::default();
    tally(
        &mut out,
        for_each_torrent(&s, &profile_id, engine, |e, h| e.pause_torrent(h).is_ok()).await,
    );
    if out.failed_count > 0 {
        warn!(
            profile_id = %profile_id,
            torrent_count = out.torrent_count,
            failed_count = out.failed_count,
            "pause of a profile did not reach every torrent"
        );
    }
    info!(
        profile_id = %profile_id,
        torrent_count = out.torrent_count,
        "paused all torrents in profile"
    );
    Ok(Json(out))
}

/// Resume every torrent in one profile.
///
/// Refused with `409 profile-unavailable` for a profile that never came up
/// (nothing of it is loaded) and for a fenced (`vpn_down`) one: its torrents
/// were paused because the tunnel is gone, and they stay paused until the
/// operator restarts the daemon. `failed_count` counts torrents the engine
/// refused.
#[kynos::post("/profiles/{profile_id}/resume-all", tag = Profiles)]
pub async fn resume_profile(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(path): Path<ProfilePath>,
) -> Result<Json<BulkOutcome>, ProfileBulkError> {
    let profile_id = ProfileId::new(path.profile_id);
    let engine = unfenced_engine(&s, &profile_id).map_err(|p| explain(&s, &profile_id, p))?;
    let mut out = BulkOutcome::default();
    tally(
        &mut out,
        for_each_torrent(&s, &profile_id, engine, |e, h| e.resume_torrent(h).is_ok()).await,
    );
    if out.failed_count > 0 {
        warn!(
            profile_id = %profile_id,
            torrent_count = out.torrent_count,
            failed_count = out.failed_count,
            "resume of a profile did not reach every torrent"
        );
    }
    info!(
        profile_id = %profile_id,
        torrent_count = out.torrent_count,
        "resumed all torrents in profile"
    );
    Ok(Json(out))
}

/// The profiles that never got a session: nothing of theirs is loaded, so a
/// bulk operation reports them rather than claiming to have reached them.
fn skipped_failed(s: &AppState) -> Vec<SkippedProfile> {
    s.profiles
        .failed()
        .iter()
        .map(|f| SkippedProfile {
            profile_id: f.config.id.as_str().to_owned(),
            reason: ProfileUnavailableReason::Failed,
            detail: no_session_detail(&f.reason),
        })
        .collect()
}

/// Pause every torrent in every profile.
///
/// Every live profile is reached, fenced ones included: their torrents are
/// already paused, and pausing again is harmless. Profiles that never came up
/// are listed in `skipped_profiles`, since nothing of theirs is loaded. A
/// nonzero `failed_count` means some torrents are still running.
#[kynos::post("/torrents/pause-all", tag = Torrents)]
pub async fn pause_all_torrents(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
) -> Json<BulkOutcome> {
    let mut out = BulkOutcome {
        skipped_profiles: skipped_failed(&s),
        ..BulkOutcome::default()
    };
    for entry in s.profiles.iter() {
        let reached = for_each_torrent(&s, entry.id(), Arc::clone(&entry.engine), |e, h| {
            e.pause_torrent(h).is_ok()
        })
        .await;
        tally(&mut out, reached);
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

/// Resume every torrent in every profile that is not fenced.
///
/// A fenced (`vpn_down`) profile is skipped and listed in `skipped_profiles`,
/// not refused wholesale: one account's dead tunnel must not stop the others
/// resuming, and resuming it is exactly what the profile's own resume-all
/// refuses. Profiles that never came up are listed too.
#[kynos::post("/torrents/resume-all", tag = Torrents)]
pub async fn resume_all_torrents(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
) -> Json<BulkOutcome> {
    let mut out = BulkOutcome {
        skipped_profiles: skipped_failed(&s),
        ..BulkOutcome::default()
    };
    for entry in s.profiles.iter() {
        if entry.health().status == EngineProfileStatus::VpnDown {
            let ProfileProblem::Unavailable { reason, detail } = ProfileProblem::vpn_down() else {
                unreachable!("vpn_down is an unavailable profile");
            };
            out.skipped_profiles.push(SkippedProfile {
                profile_id: entry.id().as_str().to_owned(),
                reason,
                detail,
            });
            continue;
        }
        let reached = for_each_torrent(&s, entry.id(), Arc::clone(&entry.engine), |e, h| {
            e.resume_torrent(h).is_ok()
        })
        .await;
        tally(&mut out, reached);
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
    use super::*;

    #[test]
    fn a_failed_profiles_detail_carries_its_reason_and_what_to_do() {
        let d = no_session_detail("wg-acct_b: no handshake");
        assert!(d.starts_with("profile has no session: wg-acct_b: no handshake."));
        assert!(d.contains("restart the daemon"));
    }

    #[test]
    fn failures_are_counted_exactly_and_named_up_to_the_cap_smallest_first() {
        use torrentd_engine::InfoHash;
        use torrentd_engine::TorrentHandle;
        let handle = |b: u8| TorrentHandle {
            id: u64::from(b),
            infohash: InfoHash([b; 20]),
        };
        let mut out = BulkOutcome::default();
        // Two profiles, visited largest-first, together over the cap.
        tally(
            &mut out,
            Reached {
                ok: 3,
                failed_count: 51,
                failed: (150..=200).rev().map(handle).collect(),
            },
        );
        tally(
            &mut out,
            Reached {
                ok: 2,
                failed_count: 60,
                failed: (1..=60).map(handle).collect(),
            },
        );
        assert_eq!(out.torrent_count, 5);
        assert_eq!(out.failed_count, 51 + 60);
        let named: Vec<u8> = out.failed_infohashes.iter().map(|h| h.get().0[0]).collect();
        let want: Vec<u8> = (1..=60).chain(150..=189).collect();
        assert_eq!(named.len(), MAX_REPORTED_FAILURES);
        assert_eq!(named, want);
    }

    #[test]
    fn a_profile_keeps_only_the_failures_it_could_name_and_counts_them_all() {
        use torrentd_engine::InfoHash;
        use torrentd_engine::TorrentHandle;
        let handle = |n: u16| {
            let mut ih = [0u8; 20];
            ih[..2].copy_from_slice(&n.to_be_bytes());
            TorrentHandle {
                id: u64::from(n) + 1,
                infohash: InfoHash(ih),
            }
        };
        let mut reached = Reached {
            ok: 0,
            failed_count: 0,
            failed: Vec::new(),
        };
        // Largest first, so every trim has something smaller to keep.
        for n in (0..1000u16).rev() {
            reached.fail(handle(n));
            assert!(reached.failed.len() < 2 * MAX_REPORTED_FAILURES);
        }
        reached.keep_smallest();
        assert_eq!(reached.failed_count, 1000);
        let kept: Vec<u16> = reached
            .failed
            .iter()
            .map(|h| u16::from_be_bytes([h.infohash.0[0], h.infohash.0[1]]))
            .collect();
        let want: Vec<u16> = (0..100).collect();
        assert_eq!(kept, want);
    }
}
