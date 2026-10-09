//! Building blocks more than one `/v1` module shares.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use kynos::prelude::*;
use kynos::schema::ParamValue;
use libtorrent_safe::InfoHash;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentEngine;
use tracing::error;

use crate::app_state::AppState;

/// A torrent's v1 infohash as the API spells it: 40 hex digits.
///
/// Emitted lowercase; accepted in either case, in a path and in a body alike.
/// Anything else is refused where it is parsed — a `400` in a path, a `422`
/// in a body — before a handler sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Schema)]
pub struct InfoHashHex(
    #[schema(pattern = "^[0-9a-fA-F]{40}$", min_length = 40, max_length = 40)] HexString,
);

/// The string form [`InfoHashHex`] is described as. Never constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HexString(InfoHash);

impl kynos::schema::Schema for HexString {
    fn schema(registry: &mut kynos::schema::registry::Registry) -> kynos::openapi::Schema {
        String::schema(registry)
    }
}

impl InfoHashHex {
    pub fn new(ih: InfoHash) -> Self {
        Self(HexString(ih))
    }

    pub fn get(self) -> InfoHash {
        self.0 .0
    }
}

impl From<InfoHash> for InfoHashHex {
    fn from(ih: InfoHash) -> Self {
        Self::new(ih)
    }
}

impl FromStr for InfoHashHex {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !crate::http::validate::is_infohash_hex(s) {
            return Err("an infohash is 40 hex digits");
        }
        InfoHash::from_hex(s)
            .map(Self::new)
            .ok_or("an infohash is 40 hex digits")
    }
}

impl fmt::Display for InfoHashHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.get().to_hex())
    }
}

impl ParamValue for InfoHashHex {}

impl Serialize for InfoHashHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.get().to_hex())
    }
}

impl<'de> Deserialize<'de> for InfoHashHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A profile's state, as far as a request needing it is concerned.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileUnavailableReason {
    /// The profile never came up at boot; its torrents are not loaded.
    Failed,
    /// The VPN monitor fenced the profile after its tunnel failed. It stays
    /// fenced until the operator sets it online and its tunnel checks
    /// healthy.
    VpnDown,
    /// The operator set the profile offline, or every profile offline with
    /// offline-all.
    Offline,
}

impl ProfileUnavailableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::VpnDown => "vpn_down",
            Self::Offline => "offline",
        }
    }
}

/// Why a request naming a profile cannot proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileProblem {
    /// No profile with this id is configured.
    NotFound,
    /// The profile is configured and cannot take the request.
    Unavailable {
        reason: ProfileUnavailableReason,
        detail: String,
    },
}

impl ProfileProblem {
    fn failed(reason: &str) -> Self {
        Self::Unavailable {
            reason: ProfileUnavailableReason::Failed,
            detail: format!("profile failed to start: {reason}"),
        }
    }

    pub fn vpn_down() -> Self {
        Self::Unavailable {
            reason: ProfileUnavailableReason::VpnDown,
            detail: "profile vpn_down: the VPN monitor fenced it after its tunnel failed. Once \
                     the tunnel is back, set the profile online to lift the fence."
                .to_owned(),
        }
    }

    pub fn offline() -> Self {
        Self::Unavailable {
            reason: ProfileUnavailableReason::Offline,
            detail: "profile offline: it is held off the network by its own state or by \
                     offline-all. Set it online first."
                .to_owned(),
        }
    }
}

/// Run synchronous engine work on tokio's blocking pool.
///
/// Every call into a real session takes that session's lock, and the alert
/// loop holds it while it drains a batch, so an engine call made on an async
/// worker parks the worker — and every request queued on it — until the drain
/// ends. A panic in `f` resumes in the caller, exactly as it would have run
/// inline.
pub async fn blocking<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Only a runtime shutting down cancels a blocking task, and then the
        // request that awaited it is being torn down with it.
        Err(e) => panic!("engine task did not run: {e}"),
    }
}

/// The engine of a live profile, or why there is none.
///
/// A failed profile is `Unavailable`, never `NotFound`: telling an operator
/// whose tunnel failed that their profile does not exist is the trace-less
/// answer the failed list exists to end. Fencing is *not* checked here, since
/// not every caller refuses a fenced profile; see [`unfenced_engine`].
pub fn engine_for(
    s: &AppState,
    profile_id: &ProfileId,
) -> Result<Arc<dyn TorrentEngine>, ProfileProblem> {
    if let Some(engine) = s.source.engine_for(profile_id) {
        return Ok(engine);
    }
    Err(match s.profiles.resolve(profile_id) {
        crate::profile_registry::Resolution::Failed(f) => ProfileProblem::failed(&f.reason),
        // `Active` does not reach here: a live profile has an engine.
        _ => ProfileProblem::NotFound,
    })
}

/// As [`engine_for`], also refusing a profile the VPN monitor fenced or the
/// operator set offline.
///
/// For every request that would put a profile's torrents on the network —
/// resume, recheck, reannounce, add, adopt — which must wait for the operator
/// to set it online. An add is refused rather than held paused: the session
/// pause would hold it, but an add that answers `201` into a profile that
/// cannot seed it reads as success. A fence is named before offline, since
/// setting a fenced profile online is what lifts it.
pub fn unfenced_engine(
    s: &AppState,
    profile_id: &ProfileId,
) -> Result<Arc<dyn TorrentEngine>, ProfileProblem> {
    let engine = engine_for(s, profile_id)?;
    if s.profile_vpn_down(profile_id) {
        return Err(ProfileProblem::vpn_down());
    }
    if s.profile_offline(profile_id) {
        return Err(ProfileProblem::offline());
    }
    Ok(engine)
}

/// Adds `From<ProfileProblem>` to an error enum declaring
///
/// ```ignore
/// #[error("unknown profile_id")]
/// #[problem(status = 404, title = "Profile not found")]
/// ProfileNotFound,
/// #[error("{detail}")]
/// #[problem(status = 409, title = "The profile is unavailable")]
/// ProfileUnavailable { detail: String, #[problem(extension)] profile_status: &'static str },
/// ```
macro_rules! from_profile_problem {
    ($($error:ty),+ $(,)?) => {$(
        impl From<$crate::http::v1::common::ProfileProblem> for $error {
            fn from(p: $crate::http::v1::common::ProfileProblem) -> Self {
                match p {
                    $crate::http::v1::common::ProfileProblem::NotFound => Self::ProfileNotFound,
                    $crate::http::v1::common::ProfileProblem::Unavailable { reason, detail } => {
                        Self::ProfileUnavailable {
                            detail,
                            profile_status: reason.as_str(),
                        }
                    }
                }
            }
        }
    )+};
}
pub(crate) use from_profile_problem;

/// Log an internal failure with what was being attempted, and return the
/// `detail` a `500 internal` carries: the attempt, never the cause.
///
/// The cause can name paths and engine state an API caller has no business
/// reading; the log has it.
pub fn internal(attempt: &str, cause: impl fmt::Display) -> String {
    error!(target: "torrentd::http", attempt, error.cause = %cause, "internal failure");
    format!("{attempt} failed; the daemon's log has the cause")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_infohash_round_trips_lowercase_and_accepts_either_case() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let ih: InfoHashHex = upper.parse().unwrap();
        assert_eq!(ih.to_string(), upper.to_lowercase());
        let json = serde_json::to_string(&ih).unwrap();
        assert_eq!(json, format!("\"{}\"", upper.to_lowercase()));
        let back: InfoHashHex = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ih);
        for bad in ["", "abc", &"g".repeat(40), &"a".repeat(41)] {
            assert!(bad.parse::<InfoHashHex>().is_err(), "{bad}");
        }
    }
}
