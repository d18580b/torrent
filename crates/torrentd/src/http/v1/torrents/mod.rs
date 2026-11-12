//! Torrents: listing, adding, removing, and per-torrent controls.
//!
//! Where a torrent lives is the assignment registry's answer (which profile
//! owns an infohash); what it is doing is the state map's, fed by the alert
//! loop. Neither is an engine call, so listing a hundred thousand torrents
//! costs no round-trip into libtorrent. Everything else here names one torrent
//! and asks its session.

use std::sync::Arc;

use kynos::prelude::*;
use libtorrent_safe::InfoHash;
use torrentd_engine::EngineError;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentState;

use crate::app_state::AppState;
use crate::http::v1::common::engine_for;
use crate::http::v1::common::internal;
use crate::http::v1::common::unfenced_engine;
use crate::http::v1::common::ProfileProblem;
use crate::http::v1::common::ProfileUnavailableReason;

/// A loaded torrent's state and its session, or why there is none.
///
/// Keyed on the state map: these act through a handle, and a torrent with no
/// state entry has none.
fn loaded(s: &AppState, ih: InfoHash) -> Result<(TorrentState, Arc<dyn TorrentEngine>), Lookup> {
    let st = s.state.get(&ih).ok_or(Lookup::TorrentNotFound)?;
    let engine = engine_for(s, &st.profile_id).map_err(|_| Lookup::no_session())?;
    Ok((st, engine))
}

/// As [`loaded`], also refusing a torrent whose profile the VPN monitor
/// fenced or the operator set offline.
///
/// For resume, recheck and reannounce, which each act on a torrent the fence
/// paused: an announce with the tunnel down has nowhere safe to go, and a
/// recheck is a step towards resuming, which must wait for the operator to
/// set the profile online.
fn loaded_unfenced(
    s: &AppState,
    ih: InfoHash,
) -> Result<(TorrentState, Arc<dyn TorrentEngine>), UnfencedLookup> {
    let st = s.state.get(&ih).ok_or(Lookup::TorrentNotFound)?;
    let engine = unfenced_engine(s, &st.profile_id).map_err(|p| match p {
        ProfileProblem::ProfileNotFound => UnfencedLookup::Lookup(Lookup::no_session()),
        ProfileProblem::ProfileUnavailable {
            detail,
            profile_status,
        } => UnfencedLookup::ProfileUnavailable {
            detail,
            profile_status,
        },
    })?;
    Ok((st, engine))
}

/// Why [`loaded`] found no torrent to act on.
///
/// An operation's error enum holds it as
/// `#[problem(transparent)] Lookup(#[from] Lookup)`.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = crate::http::security::PROBLEM_BASE)]
pub enum Lookup {
    /// No loaded torrent has this infohash.
    #[error("no loaded torrent with this infohash")]
    #[problem(status = 404, title = "Torrent not found")]
    TorrentNotFound,
    /// A state entry whose profile has no engine: a bug, not a request error.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}

impl Lookup {
    fn no_session() -> Self {
        Self::Internal {
            detail: internal("finding the torrent's session", "no engine for its profile"),
        }
    }
}

/// Why [`loaded_unfenced`] found no torrent to act on.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = crate::http::security::PROBLEM_BASE)]
pub enum UnfencedLookup {
    #[error(transparent)]
    #[problem(transparent)]
    Lookup(#[from] Lookup),
    /// The VPN monitor fenced the torrent's profile, or the operator set
    /// it offline; nothing may put its torrents back on the network until
    /// the profile is set online.
    #[error("{detail}")]
    #[problem(status = 409, title = "The profile is unavailable")]
    ProfileUnavailable {
        detail: String,
        #[problem(extension)]
        profile_status: ProfileUnavailableReason,
    },
}

/// Whether `e` says the session no longer knows the handle.
fn is_gone(e: &EngineError) -> bool {
    matches!(
        e,
        EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(_))
            | EngineError::UnknownHandle(_)
    )
}

mod actions;
mod add;
mod delete;
mod files;
mod list;
mod model;
mod trackers;

pub use actions::*;
pub use add::*;
pub use delete::*;
pub use files::*;
pub use list::*;
pub use trackers::*;

// ---------------------------------------------------------------------------
// Mounting
// ---------------------------------------------------------------------------

/// Operations that take no request body.
macro_rules! bodyless_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![
            crate::http::v1::torrents::list_torrents,
            crate::http::v1::torrents::get_torrent,
            crate::http::v1::torrents::delete_torrent,
            crate::http::v1::torrents::pause_torrent,
            crate::http::v1::torrents::resume_torrent,
            crate::http::v1::torrents::recheck_torrent,
            crate::http::v1::torrents::reannounce_torrent,
            crate::http::v1::torrents::list_torrent_files,
            crate::http::v1::torrents::list_torrent_trackers,
        ])
    };
}
pub(crate) use bodyless_routes;

/// Operations whose body is bounded by `MAX_BODY_BYTES`.
macro_rules! body_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![
            crate::http::v1::torrents::set_upload_limit,
            crate::http::v1::torrents::set_file_priority,
        ])
    };
}
pub(crate) use body_routes;

/// `POST /v1/torrents`, whose body may carry a whole `.torrent`.
macro_rules! add_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![crate::http::v1::torrents::add_torrent])
    };
}
pub(crate) use add_routes;
