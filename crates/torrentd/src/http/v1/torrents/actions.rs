//! Per-torrent controls: pause, resume, recheck, reannounce, and the upload
//! limit.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::response::status::Accepted;
use kynos::security::auth::Scoped;
use serde::Deserialize;
use torrentd_engine::TorrentEngine;

use super::loaded;
use super::loaded_unfenced;
use super::model::TorrentPath;
use super::Lookup;
use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Write;
use crate::http::v1::common::blocking;
use crate::http::v1::common::internal;
use crate::http::v1::common::ProfileProblem;
use crate::http::v1::Torrents;
use crate::http::validate::from_invalid;
use crate::http::validate::Invalid;
use crate::http::validate::Unenforced;
use crate::http::validate::Validate;

torrent_error! {
    /// Why a torrent's upload limit was not set.
    pub enum SetUploadLimitError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// A constraint the schema declares is broken.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(SetUploadLimitError);
from_invalid!(SetUploadLimitError);

torrent_error! {
    /// Why a torrent was not paused.
    pub enum PauseTorrentError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(PauseTorrentError);

/// Pause a torrent.
///
/// Stops it announcing and serving peers until resumed. Allowed on a fenced
/// profile: pausing puts nothing back on the network. A paced resume still
/// running in the profile, a lifted fence's or a resume-all's, leaves it out.
#[kynos::post("/torrents/{infohash}/pause", tag = Torrents)]
pub async fn pause_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<NoContent, PauseTorrentError> {
    let (st, engine) = loaded(&s, p.infohash.get())?;
    let entry = s.profiles.resolve(&st.profile_id).active();
    let before = entry.map(|e| e.prepare_pause(st.handle));
    let paused = blocking(move || engine.pause_torrent(st.handle)).await;
    if let (Err(_), Some(e), Some(before)) = (&paused, entry, before) {
        e.restore_noted(st.handle, before);
    }
    paused.map_err(|e| PauseTorrentError::Internal {
        detail: internal("pausing the torrent", e),
    })?;
    // A `.torrent` held paused for its first check is the operator's to
    // resume from here on: the check queue no longer resumes it, and the
    // next boot keeps it paused.
    s.checks.forget_add(st.handle.infohash);
    // Saved now rather than at the next 30-minute sweep: a crash before it
    // would bring the torrent back running.
    s.state.queue_resume_save_now(st.handle.infohash);
    Ok(NoContent)
}

torrent_error! {
    /// Why a torrent was not resumed, rechecked or reannounced.
    pub enum UnfencedControlError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The VPN monitor fenced the torrent's profile, or the operator set
        /// it offline; nothing may put its torrents back on the network until
        /// the profile is set online.
        #[error("{detail}")]
        #[problem(status = 409, title = "The profile is unavailable")]
        ProfileUnavailable {
            detail: String,
            #[problem(extension)]
            profile_status: &'static str,
        },
        /// The session refused the request.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(UnfencedControlError, fenced);

/// Resume a torrent.
///
/// Refused with `409 profile-unavailable` while the torrent's profile is
/// fenced: un-quarantining a torrent whose tunnel is down would announce it
/// from the wrong address. A profile fenced while the resume goes out is
/// refused the same way, and the torrent is paused again. A torrent a paced
/// set-online still held is no longer held once resumed.
#[kynos::post("/torrents/{infohash}/resume", tag = Torrents)]
pub async fn resume_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<NoContent, UnfencedControlError> {
    let (st, engine) = loaded_unfenced(&s, p.infohash.get())?;
    let state = Arc::clone(&s);
    let resumed = blocking(move || {
        let resume = || {
            crate::fence::resume_unless_fenced(
                &state.profiles,
                &st.profile_id,
                engine.as_ref(),
                st.handle,
                &*state.metrics,
            )
        };
        // Running now by the operator's hand: a paced set-online that still
        // held it (one whose paced resume was refused, say) no longer pauses
        // it, so the hold is released, and a re-hash the hold kept queued
        // starts ([`crate::profile_state::PacedHolds`]). Released after the
        // resume, so a failed one leaves the torrent held, and serialised
        // with a set-online's hold-and-pause, so the hold and the torrent's
        // pause cannot part.
        let resumed = match state.profiles.resolve(&st.profile_id).active() {
            Some(entry) => entry.resume_by_hand(st.handle, resume, |r| {
                *r == crate::fence::SingleResume::Resumed
            }),
            None => resume(),
        };
        // A `.torrent` still waiting for a check slot starts its first check
        // now, by the operator's hand: it takes its slot at once, over the
        // limit if it must, so the queue counts it and admits nothing beside
        // it until it ends.
        if matches!(resumed, Ok(crate::fence::SingleResume::Resumed)) {
            state.checks.start_held_add_now(st.handle.infohash);
        }
        resumed
    })
    .await
    .map_err(|e| UnfencedControlError::Internal {
        detail: internal("resuming the torrent", e),
    })?;
    if resumed == crate::fence::SingleResume::Resumed {
        return Ok(NoContent);
    }
    let ProfileProblem::Unavailable { reason, detail } = ProfileProblem::vpn_down() else {
        unreachable!("vpn_down is an unavailable profile");
    };
    Err(UnfencedControlError::ProfileUnavailable {
        detail,
        profile_status: reason.as_str(),
    })
}

/// Re-verify a torrent's payload.
///
/// Re-hashes the payload against the piece hashes. `202`: libtorrent checks
/// asynchronously, and the torrent's `phase` reports `checking` from the
/// moment the check starts until it is done. Needs no `[pool]`. The check is
/// queued rather than started, and a queued check leaves the torrent in its
/// old `phase` until the daemon's check queue starts it: the queue starts it
/// once a slot is free, at most `[pool] max_concurrent_verify` checks at once
/// (its default of 4 without `[pool]`) together with adoptions'
/// verifications, `POST /v1/pool/verifications`' re-hashes, the first checks
/// of `.torrent`s added and the disk-error retry's checks. `GET /v1/pool`
/// counts it in `verify_queue_depth` while it waits and `verify_in_flight`
/// while it hashes. Asking again for a torrent already waiting or checking
/// queues nothing more. For a paused torrent or one still without metadata
/// (which libtorrent does not hash until it is resumed or its metadata
/// arrives), libtorrent is asked at once. A recheck drops seed mode, which is
/// safe because the no-download invariant rests on upload mode, and that
/// survives it. Refused while the profile is fenced, as resuming is.
#[kynos::post("/torrents/{infohash}/recheck", tag = Torrents)]
pub async fn recheck_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Accepted<()>, UnfencedControlError> {
    let (st, engine) = loaded_unfenced(&s, p.infohash.get())?;
    // Every check started at once used to run beside every other: libtorrent
    // bounds checking only for auto-managed torrents, and none is one here.
    // A scripted recheck of a whole library hashed it all at once, and each
    // check disconnects its torrent's peers until it ends. The verify queue
    // is that bound, and its admission checks again everything this request
    // checked (still loaded, profile on the network), holding the check
    // while the profile is fenced or a paced resume has yet to reach it.
    //
    // Its verdict is not recorded in the pool index: this endpoint never
    // paused a torrent that failed, or cleared one `drifted`, and
    // `POST /v1/pool/verifications` is the request that does.
    //
    // A paused torrent, or one with no metadata, starts no disk work now:
    // libtorrent marks it to check once it can. The queue drops such a
    // re-hash rather than hold a slot for it, so it is asked for directly,
    // as it always was.
    let hashes_now = !matches!(
        st.phase,
        torrentd_engine::TorrentPhase::Paused | torrentd_engine::TorrentPhase::AwaitingMetadata
    );
    if hashes_now {
        s.checks.enqueue_recheck(st.handle.infohash.to_hex(), false);
        return Ok(Accepted::new(()));
    }
    let state = Arc::clone(&s);
    blocking(move || {
        crate::check_queue::force_recheck_marking_checking(engine.as_ref(), &state.state, st.handle)
    })
    .await
    .map_err(|e| UnfencedControlError::Internal {
        detail: internal("rechecking the torrent", e),
    })?;
    Ok(Accepted::new(()))
}

/// Announce a torrent to its trackers now.
///
/// For after a passkey rotation or a tracker's "not registered", which would
/// otherwise wait for the next interval. `202`: the outcome shows in
/// `GET /v1/torrents/{infohash}/trackers`. Refused while the profile is
/// fenced: an announce with the tunnel down has nowhere safe to go.
#[kynos::post("/torrents/{infohash}/reannounce", tag = Torrents)]
pub async fn reannounce_torrent(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Accepted<()>, UnfencedControlError> {
    let (st, engine) = loaded_unfenced(&s, p.infohash.get())?;
    blocking(move || engine.force_reannounce(st.handle))
        .await
        .map_err(|e| UnfencedControlError::Internal {
            detail: internal("reannouncing the torrent", e),
        })?;
    Ok(Accepted::new(()))
}

/// A torrent's own upload limit.
#[derive(Debug, Deserialize, Schema)]
#[serde(deny_unknown_fields)]
pub struct UploadLimit {
    /// Bytes per second, at least 1. `null` (or absent) removes the limit;
    /// the profile's and the daemon's limits still apply.
    #[schema(minimum = 1, maximum = 2147483647)]
    pub bytes_per_sec: Option<u32>,
}

impl Validate for UploadLimit {
    fn validate(&self) -> Result<(), Invalid> {
        let mut invalid = Invalid::new();
        if let Some(rate) = self.bytes_per_sec {
            // libtorrent reads 0 as "unlimited", which `null` already says;
            // and it takes an `int`, so anything past `i32::MAX` would wrap.
            invalid.check(
                (1..=i32::MAX as u32).contains(&rate),
                "/bytes_per_sec",
                || "must be between 1 and 2147483647, or null for no limit".to_owned(),
            );
        }
        invalid.finish()
    }
}

/// Set a torrent's upload limit.
///
/// Its own limit, under the profile's and the daemon's. `null` removes it.
/// Allowed on a fenced profile: a limit puts nothing on the network.
#[kynos::put("/torrents/{infohash}/upload-limit", tag = Torrents)]
pub async fn set_upload_limit(
    _caller: Scoped<Bearer, Write>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
    Json(Unenforced(body)): Json<Unenforced<UploadLimit>>,
) -> Result<NoContent, SetUploadLimitError> {
    body.validate()?;
    let (st, engine) = loaded(&s, p.infohash.get())?;
    // Validated into `1..=i32::MAX` above; libtorrent's 0 is "unlimited".
    let rate = body.bytes_per_sec.map_or(0, |r| r as i32);
    blocking(move || engine.set_upload_limit(st.handle, rate))
        .await
        .map_err(|e| SetUploadLimitError::Internal {
            detail: internal("setting the torrent's upload limit", e),
        })?;
    Ok(NoContent)
}
