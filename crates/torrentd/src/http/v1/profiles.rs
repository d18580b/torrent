//! Profiles: listing them, describing one, setting one or all of them online
//! or offline, and pausing or resuming every torrent in one profile or in all
//! of them.
//!
//! A daemon always has at least one profile, so these are always mounted.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::security::auth::Scoped;
use serde::Deserialize;
use serde::Serialize;
use torrentd_engine::port_forward::REANNOUNCE_PACE;
use torrentd_engine::DesiredState;
use torrentd_engine::MetricsSink;
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
use crate::http::v1::common::internal;
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
            crate::http::v1::profiles::set_offline_all,
            crate::http::v1::profiles::set_online_all,
            crate::http::v1::profiles::pause_profile,
            crate::http::v1::profiles::resume_profile,
            crate::http::v1::profiles::pause_all_torrents,
            crate::http::v1::profiles::resume_all_torrents,
        ])
    };
}
pub(crate) use bodyless_routes;

/// Operations whose body is bounded by `MAX_BODY_BYTES`.
macro_rules! body_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![crate::http::v1::profiles::set_profile_state])
    };
}
pub(crate) use body_routes;

/// Whether a profile is on the network.
#[derive(Clone, Copy, Debug, Schema, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileState {
    /// On the network.
    Online,
    /// Held off it: no announce, no peer, no incoming connection, and no DHT
    /// node.
    Offline,
}

impl From<DesiredState> for ProfileState {
    fn from(d: DesiredState) -> Self {
        match d {
            DesiredState::Online => Self::Online,
            DesiredState::Offline => Self::Offline,
        }
    }
}

impl From<ProfileState> for DesiredState {
    fn from(s: ProfileState) -> Self {
        match s {
            ProfileState::Online => Self::Online,
            ProfileState::Offline => Self::Offline,
        }
    }
}

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
    /// torrents are paused and stay paused until the operator sets the
    /// profile online and its tunnel checks healthy.
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
    /// The profile's own online/offline setting, persisted across restarts.
    /// `offline_all` holds every profile offline without changing it.
    pub desired_state: ProfileState,
    /// Whether the profile is on the network now: `online` only when it has
    /// a session, its `status` is `active`, and its session is not paused.
    /// Read from the session, so it differs from what `desired_state` and
    /// `offline_all` ask for only when a session refused the pause or resume
    /// that applies them (the change that hit it answered `500`).
    pub effective_state: ProfileState,
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
    /// Whether `POST /v1/profiles/offline-all` holds every profile offline.
    /// Each profile's own `desired_state` stands beneath it, and is what
    /// `online-all` restores.
    pub offline_all: bool,
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
    /// Torrents the fence paused when the tunnel went down. A torrent added
    /// while the profile is fenced is paused as well, but not counted here.
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
    #[schema(max_items = 100)]
    pub failed_infohashes: Vec<InfoHashHex>,
    /// Profiles this request did not act on, or not on all of, each with why.
    /// A single profile's operation refuses a profile it cannot act on, so
    /// lists one here only when a resume was cut short by a fence.
    pub skipped_profiles: Vec<SkippedProfile>,
}

/// How many failed infohashes a bulk operation names. A daemon-wide pause
/// against a session that refuses everything would otherwise answer with a
/// hundred thousand of them. Published as `failed_infohashes`' `maxItems`,
/// which the derive takes only as a literal: the spec tests hold the two
/// equal.
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
    let states = s.profiles.states();
    // Read from the session, not the record: a session that refused the
    // pause or resume applying a change keeps running (or stays paused)
    // while the record says otherwise, and this field reports which. Only
    // a session whose pause state cannot be read falls back to the record.
    let session_running = match e.engine.session_paused() {
        Ok(paused) => !paused,
        Err(_) => !states.holds_offline(e.id()),
    };
    let on_network = h.status == EngineProfileStatus::Active && session_running;
    Profile {
        profile_id: e.config.id.as_str().to_owned(),
        status: ProfileStatus::from(&h.status),
        desired_state: states.desired(e.id()).into(),
        effective_state: if on_network {
            ProfileState::Online
        } else {
            ProfileState::Offline
        },
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
        // Kept for a failed profile too: it is what the profile starts in
        // once a restart brings it up.
        desired_state: s.profiles.states().desired(&f.config.id).into(),
        effective_state: ProfileState::Offline,
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
    Json(profile_list(&s))
}

/// Every profile, in the order [`list_profiles`] documents.
fn profile_list(s: &AppState) -> ProfileList {
    // Configured order is what the registry's `Vec` gives every other
    // consumer and what the operator wrote; sorting by id would throw it away.
    let mut items: Vec<Profile> = s.profiles.iter().map(|e| profile_of(s, e)).collect();
    items.extend(s.profiles.failed().iter().map(|f| profile_of_failed(s, f)));
    ProfileList {
        items,
        offline_all: s.profiles.states().offline_all,
    }
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
    detail_of(&s, &profile_id)
        .map(Json)
        .ok_or(GetProfileError::ProfileNotFound)
}

/// What [`get_profile`] reports for `profile_id`, or `None` for an id no
/// profile declares.
fn detail_of(s: &AppState, profile_id: &ProfileId) -> Option<ProfileDetail> {
    match s.profiles.resolve(profile_id) {
        Resolution::Active(e) => {
            let h = e.health();
            Some(ProfileDetail {
                profile: profile_of(s, e),
                vpn_interface: e.config.vpn_interface().map(str::to_owned),
                allowed_tracker_domains: e.config.allowed_tracker_domains.clone(),
                paused_for_vpn: h.paused_for_vpn,
                port_forward_ok: h.port_forward_ok,
            })
        }
        Resolution::Failed(f) => Some(ProfileDetail {
            profile: profile_of_failed(s, f),
            vpn_interface: f.config.vpn_interface().map(str::to_owned),
            allowed_tracker_domains: f.config.allowed_tracker_domains.clone(),
            paused_for_vpn: 0,
            port_forward_ok: false,
        }),
        Resolution::Unknown => None,
    }
}

/// The state to set a profile to.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct SetProfileState {
    /// `offline` holds the profile off the network; `online` puts it back.
    pub state: ProfileState,
}

/// Why a profile's state was not set.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum SetProfileStateError {
    /// No profile with this id is configured.
    #[error("unknown profile_id")]
    #[problem(status = 404, title = "Profile not found")]
    ProfileNotFound,
    /// The profile is fenced (`vpn_down`) and its tunnel still fails the
    /// health check, so it stays fenced and its state is unchanged.
    #[error("{detail}")]
    #[problem(status = 409, title = "The profile is unavailable")]
    ProfileUnavailable {
        detail: String,
        /// `vpn_down`.
        #[problem(extension)]
        profile_status: &'static str,
    },
    /// The state could not be recorded, or a session refused it.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// Set one profile online or offline.
///
/// `offline` pauses the profile's whole session: no announce, no peer, no
/// incoming connection, for every torrent in it and every torrent that
/// reaches it later; a host profile with `dht` also has its DHT node stopped.
/// Adds, adoptions, and resumes into it are refused with
/// `409 profile-unavailable` (`offline`) until it is set online. `online`
/// resumes the session (and its DHT), and every torrent goes back to what
/// its own paused flag says. The setting is written to the state directory
/// before it takes effect, so it survives a crash and a restart; a profile left offline
/// starts with its session paused, before any torrent is loaded into it.
///
/// Setting a fenced (`vpn_down`) profile online is how the fence is lifted
/// without a restart. The tunnel is checked first: its interface must hold
/// the address the session is bound to, and a packet from that address must
/// route by the tunnel. If it passes, the VPN monitor watches the profile
/// again, handshake included, and the fence's pauses are undone 100 torrents
/// a second, going on after the response, since each torrent resumed
/// announces to its trackers; if it fails, `409` and nothing changes. A profile that never came up keeps the setting
/// for its next boot. `offline_all`, while on, keeps every profile offline
/// whatever this sets.
#[kynos::patch("/profiles/{profile_id}", tag = Profiles)]
pub async fn set_profile_state(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(path): Path<ProfilePath>,
    Json(body): Json<SetProfileState>,
) -> Result<Json<ProfileDetail>, SetProfileStateError> {
    let profile_id = ProfileId::new(path.profile_id);
    if matches!(s.profiles.resolve(&profile_id), Resolution::Unknown) {
        return Err(SetProfileStateError::ProfileNotFound);
    }
    let desired = DesiredState::from(body.state);
    // On the blocking pool: the tunnel probe shells out, the record is
    // fsynced, and each session call takes its session's lock.
    let state = Arc::clone(&s);
    let id = profile_id.clone();
    blocking(move || set_state(&state, &id, desired)).await?;
    detail_of(&s, &profile_id)
        .map(Json)
        .ok_or(SetProfileStateError::ProfileNotFound)
}

/// [`set_profile_state`]'s work, on the blocking pool.
fn set_state(
    s: &AppState,
    profile_id: &ProfileId,
    desired: DesiredState,
) -> Result<(), SetProfileStateError> {
    let fenced = s
        .profiles
        .resolve(profile_id)
        .active()
        .filter(|e| e.health().status == EngineProfileStatus::VpnDown);
    let lift = match (desired, fenced) {
        (DesiredState::Online, Some(entry)) => {
            if let Err(reason) = crate::vpn_monitor::recovery_check(entry, &s.tunnel_probe) {
                warn!(
                    profile_id = %profile_id,
                    reason = reason.as_str(),
                    "profile set online while fenced; its tunnel still fails the check, so it \
                     stays fenced",
                );
                return Err(SetProfileStateError::ProfileUnavailable {
                    detail: format!(
                        "profile vpn_down: its tunnel still fails the health check \
                         ({}), so it stays fenced and its state is unchanged. Bring the \
                         tunnel back on the address the session is bound to, then retry.",
                        reason.as_str()
                    ),
                    profile_status: ProfileUnavailableReason::VpnDown.as_str(),
                });
            }
            Some(entry)
        }
        _ => None,
    };
    s.profiles
        .change_states(|r| r.set(profile_id, desired), &*s.metrics)
        .map_err(|e| SetProfileStateError::Internal {
            detail: internal("setting the profile's state", e),
        })?;
    if let Some(entry) = lift {
        lift_fence(s, entry);
    }
    info!(profile_id = %profile_id, state = desired.as_str(), "profile state set");
    Ok(())
}

/// Undo a fence whose tunnel has just passed [`crate::vpn_monitor::recovery_check`]:
/// mark the profile active, so the VPN monitor watches it again, and resume
/// the torrents the fence paused.
///
/// The fence paused every torrent in the profile and recorded none of them,
/// so every one is resumed, including one the operator had paused on its own
/// before the fence. Pause it again after.
///
/// The resumes are paced, a batch a second, by a task that goes on after the
/// request is answered ([`crate::vpn_monitor::spawn_lift`]).
fn lift_fence(s: &AppState, entry: &ProfileEntry) {
    let profile_id = entry.id();
    entry.update_health(|h| {
        h.status = EngineProfileStatus::Active;
        h.tunnel_ip = entry.session_ip;
        h.paused_for_vpn = 0;
    });
    let labels = [("profile_id", profile_id.as_str())];
    s.metrics.set_gauge("profile_vpn_tunnel_up", 1.0, &labels);
    s.metrics
        .set_gauge("profile_torrents_paused_vpn_down", 0.0, &labels);
    let handles = s.state.handles_for_profile(profile_id);
    info!(
        profile_id = %profile_id,
        torrent_count = handles.len(),
        "fence lifted: the tunnel checked healthy and the profile was set online; resuming \
         its torrents a batch at a time",
    );
    crate::vpn_monitor::spawn_lift(
        &s.profiles,
        &s.metrics,
        entry,
        handles,
        crate::vpn_monitor::Lift::SetOnline,
    );
}

/// Why offline-all or online-all did not fully apply.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum StateSwitchError {
    /// The switch could not be recorded, or a session refused it.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

/// [`set_offline_all`] and [`set_online_all`]: set the daemon-wide switch and
/// apply it.
async fn switch_all(
    s: Arc<AppState>,
    offline: bool,
) -> Result<Json<ProfileList>, StateSwitchError> {
    let state = Arc::clone(&s);
    blocking(move || {
        state
            .profiles
            .change_states(|r| r.offline_all = offline, &*state.metrics)
    })
    .await
    .map_err(|e| StateSwitchError::Internal {
        detail: internal(
            if offline {
                "taking every profile offline"
            } else {
                "clearing offline-all"
            },
            e,
        ),
    })?;
    info!(offline_all = offline, "daemon-wide profile state set");
    Ok(Json(profile_list(&s)))
}

/// Take every profile offline.
///
/// The same session pause a single profile's `offline` uses, applied to every
/// profile, and recorded as its own switch: each profile's `desired_state` is
/// left as it was, so `online-all` restores exactly the states that stood
/// before. Persisted like them, and in force from boot while set. Adds,
/// adoptions and resumes into any profile are refused until it is cleared.
#[kynos::post("/profiles/offline-all", tag = Profiles)]
pub async fn set_offline_all(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<Json<ProfileList>, StateSwitchError> {
    switch_all(s, true).await
}

/// Clear offline-all.
///
/// Each profile returns to its own `desired_state`: one set offline on its
/// own stays offline. A fenced (`vpn_down`) profile stays fenced; setting it
/// online with `PATCH /v1/profiles/{profile_id}` is what checks its tunnel
/// and lifts the fence.
#[kynos::post("/profiles/online-all", tag = Profiles)]
pub async fn set_online_all(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
) -> Result<Json<ProfileList>, StateSwitchError> {
    switch_all(s, false).await
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
    /// VPN monitor fenced it or the operator set it offline.
    #[error("{detail}")]
    #[problem(status = 409, title = "The profile is unavailable")]
    ProfileUnavailable {
        detail: String,
        /// `failed`, `vpn_down` or `offline`.
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

/// Resume every torrent `profile_id` holds, through the shared pacer
/// ([`crate::vpn_monitor::resume_paced`]), and add what it reached to `out`.
/// A profile fenced before the last batch is added to `skipped_profiles` with
/// how many it did not reach.
///
/// On a task of its own, which the request only awaits, so a client that
/// stops waiting does not leave the profile half resumed.
///
/// A pause of the profile while it runs stops it, and a torrent paused on its
/// own is left out ([`crate::profile_registry::ResumeGate`]): the response
/// then counts only what was resumed, and lists nothing in
/// `skipped_profiles`, since the later pause is what the operator asked for.
async fn resume_each(s: &AppState, profile_id: &ProfileId, out: &mut BulkOutcome) {
    let Some(gate) = s
        .profiles
        .resolve(profile_id)
        .active()
        .map(|e| e.open_gate())
    else {
        return;
    };
    let handles = s.state.handles_for_profile(profile_id);
    let (profiles, metrics, id) = (
        Arc::clone(&s.profiles),
        Arc::clone(&s.metrics),
        profile_id.clone(),
    );
    let task = tokio::spawn(async move {
        let mut reached = Reached {
            ok: 0,
            failed_count: 0,
            failed: Vec::new(),
        };
        let resumed = crate::vpn_monitor::resume_paced(
            profiles,
            id,
            &handles,
            REANNOUNCE_PACE,
            || false,
            gate,
            metrics,
            |h, _| reached.fail(h),
        )
        .await;
        reached.ok = u32::try_from(resumed.resumed).unwrap_or(u32::MAX);
        reached.keep_smallest();
        (reached, resumed)
    });
    let (reached, resumed) = match task.await {
        Ok(v) => v,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Only a runtime shutting down cancels the task, and then the request
        // that awaited it is being torn down with it.
        Err(e) => panic!("resume task did not run: {e}"),
    };
    tally(out, reached);
    if resumed.halted || resumed.excluded > 0 {
        info!(
            profile_id = %profile_id,
            torrent_count = resumed.not_reached,
            excluded_count = resumed.excluded,
            halted = resumed.halted,
            "torrents paused while a resume-all ran were left paused",
        );
        if resumed.halted {
            return;
        }
    }
    let not_reached = resumed.not_reached;
    if not_reached > 0 {
        warn!(
            profile_id = %profile_id,
            torrent_count = not_reached,
            "profile fenced while its torrents were being resumed; the rest stay paused",
        );
        out.skipped_profiles.push(SkippedProfile {
            profile_id: profile_id.as_str().to_owned(),
            reason: ProfileUnavailableReason::VpnDown,
            detail: format!(
                "profile fenced (vpn_down) while its torrents were being resumed: {not_reached} \
                 were not resumed and stay paused until the profile is set online."
            ),
        });
    }
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
///
/// A paced resume still running in the profile, a lifted fence's or a
/// resume-all's, is stopped first, so it does not resume torrents after this
/// paused them.
#[kynos::post("/profiles/{profile_id}/pause-all", tag = Profiles)]
pub async fn pause_profile(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(path): Path<ProfilePath>,
) -> Result<Json<BulkOutcome>, ProfileBulkError> {
    let profile_id = ProfileId::new(path.profile_id);
    let engine = engine_for(&s, &profile_id).map_err(|p| explain(&s, &profile_id, p))?;
    if let Some(entry) = s.profiles.resolve(&profile_id).active() {
        entry.halt_resumes();
    }
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
/// Each torrent resumed announces to its trackers, so they are resumed 100 a
/// second, and the response comes once the last is: about a second per 100
/// torrents in the profile. The resume goes on if the client stops waiting.
/// A profile fenced while it runs stops it there: the profile is then listed
/// in `skipped_profiles` (`vpn_down`), with how many torrents stayed paused.
///
/// Refused with `409 profile-unavailable` for a profile that never came up
/// (nothing of it is loaded), for a fenced (`vpn_down`) one, whose torrents
/// were paused because the tunnel is gone and stay paused until the profile
/// is set online and its tunnel checks healthy, and for an `offline` one.
/// `failed_count` counts torrents the engine refused.
#[kynos::post("/profiles/{profile_id}/resume-all", tag = Profiles)]
pub async fn resume_profile(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(path): Path<ProfilePath>,
) -> Result<Json<BulkOutcome>, ProfileBulkError> {
    let profile_id = ProfileId::new(path.profile_id);
    unfenced_engine(&s, &profile_id).map_err(|p| explain(&s, &profile_id, p))?;
    let mut out = BulkOutcome::default();
    resume_each(&s, &profile_id, &mut out).await;
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
///
/// A paced resume still running in a profile, a lifted fence's or a
/// resume-all's, is stopped first, so it does not resume torrents after this
/// paused them.
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
        entry.halt_resumes();
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

/// Resume every torrent in every profile that is not fenced or offline.
///
/// A fenced (`vpn_down`) or `offline` profile is skipped and listed in
/// `skipped_profiles`, not refused wholesale: one account's dead tunnel must
/// not stop the others resuming, and resuming it is exactly what the
/// profile's own resume-all refuses. Profiles that never came up are listed
/// too.
///
/// Each torrent resumed announces to its trackers, so each profile's are
/// resumed 100 a second, one profile after another, and the response comes
/// once the last is: about a second per 100 torrents in the daemon. The
/// resume goes on if the client stops waiting. A profile fenced while its
/// torrents are being resumed is listed in `skipped_profiles` (`vpn_down`)
/// with how many stayed paused.
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
        let held = if entry.health().status == EngineProfileStatus::VpnDown {
            Some(ProfileProblem::vpn_down())
        } else if s.profile_offline(entry.id()) {
            Some(ProfileProblem::offline())
        } else {
            None
        };
        if let Some(problem) = held {
            let ProfileProblem::Unavailable { reason, detail } = problem else {
                unreachable!("vpn_down and offline are unavailable profiles");
            };
            out.skipped_profiles.push(SkippedProfile {
                profile_id: entry.id().as_str().to_owned(),
                reason,
                detail,
            });
            continue;
        }
        resume_each(&s, entry.id(), &mut out).await;
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
        // Two profiles, visited largest-first, together over the cap. The
        // first refused more than it could name, so its count is not its
        // list's length.
        tally(
            &mut out,
            Reached {
                ok: 3,
                failed_count: 1000,
                failed: (101..=200).rev().map(handle).collect(),
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
        assert_eq!(out.failed_count, 1000 + 60);
        let named: Vec<u8> = out.failed_infohashes.iter().map(|h| h.get().0[0]).collect();
        let want: Vec<u8> = (1..=60).chain(101..=140).collect();
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
