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
use crate::http::v1::common::unfenced_engine;
use crate::http::v1::common::ProfileProblem;

/// The problem base every error here shares.
macro_rules! torrent_error {
    ($(#[$meta:meta])* pub enum $name:ident { $($body:tt)* }) => {
        $(#[$meta])*
        #[derive(Debug, thiserror::Error, ApiError)]
        #[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
        pub enum $name { $($body)* }
    };
}

/// A loaded torrent's state and its session, or why there is none.
///
/// Keyed on the state map: these act through a handle, and a torrent with no
/// state entry has none.
fn loaded(s: &AppState, ih: InfoHash) -> Result<(TorrentState, Arc<dyn TorrentEngine>), Lookup> {
    let st = s.state.get(&ih).ok_or(Lookup::NotFound)?;
    let engine = engine_for(s, &st.profile_id).map_err(|_| Lookup::NoSession)?;
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
) -> Result<(TorrentState, Arc<dyn TorrentEngine>), Lookup> {
    let st = s.state.get(&ih).ok_or(Lookup::NotFound)?;
    let engine = unfenced_engine(s, &st.profile_id).map_err(|p| match p {
        ProfileProblem::NotFound => Lookup::NoSession,
        ProfileProblem::Unavailable { reason, detail } => Lookup::Fenced {
            detail,
            profile_status: reason.as_str(),
        },
    })?;
    Ok((st, engine))
}

/// Why [`loaded`] found no session to act through.
enum Lookup {
    NotFound,
    /// A state entry whose profile has no engine: a bug, not a request error.
    NoSession,
    Fenced {
        detail: String,
        profile_status: &'static str,
    },
}

/// `From<Lookup>` for an error enum with `TorrentNotFound` and `Internal`,
/// and `ProfileUnavailable` where named.
macro_rules! from_lookup {
    ($error:ty) => {
        impl From<Lookup> for $error {
            fn from(l: Lookup) -> Self {
                match l {
                    Lookup::NotFound => Self::TorrentNotFound,
                    Lookup::NoSession | Lookup::Fenced { .. } => Self::Internal {
                        detail: internal(
                            "finding the torrent's session",
                            "no engine for its profile",
                        ),
                    },
                }
            }
        }
    };
    ($error:ty, fenced) => {
        impl From<Lookup> for $error {
            fn from(l: Lookup) -> Self {
                match l {
                    Lookup::NotFound => Self::TorrentNotFound,
                    Lookup::NoSession => Self::Internal {
                        detail: internal(
                            "finding the torrent's session",
                            "no engine for its profile",
                        ),
                    },
                    Lookup::Fenced {
                        detail,
                        profile_status,
                    } => Self::ProfileUnavailable {
                        detail,
                        profile_status,
                    },
                }
            }
        }
    };
}

/// Whether `e` says the session no longer knows the handle.
fn is_gone(e: &EngineError) -> bool {
    matches!(
        e,
        EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(_))
            | EngineError::UnknownHandle(_)
    )
}

// Declared after the macros above, which they use.
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
