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

use crate::app_state::AppState;

/// A torrent's infohash as the API spells it: 40 hex digits.
///
/// A torrent is named by its v1 infohash, a hybrid (v1+v2) torrent's
/// included; only a v2-only torrent, which has none, is named by its v2
/// infohash truncated to its first 20 bytes.
///
/// Emitted lowercase; accepted in either case, in a path and in a body alike.
/// Anything else is refused where it is parsed — a `400` in a path, a `422`
/// in a body — before a handler sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Schema)]
pub struct InfoHashHex(
    #[schema(
        as = String,
        via = InfoHash::to_hex,
        pattern = "^[0-9a-fA-F]{40}$",
        min_length = 40,
        max_length = 40
    )]
    InfoHash,
);

impl InfoHashHex {
    pub fn new(ih: InfoHash) -> Self {
        Self(ih)
    }

    pub fn get(self) -> InfoHash {
        self.0
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

/// Why a request naming a profile cannot proceed.
///
/// An operation's error enum holds it as
/// `#[problem(transparent)] Profile(#[from] ProfileProblem)`, so both
/// failures are declared here once.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, ApiError)]
#[problem(base = crate::http::security::PROBLEM_BASE)]
pub enum ProfileProblem {
    /// No profile with this id is configured.
    #[error("unknown profile_id")]
    #[problem(status = 404, title = "Profile not found")]
    ProfileNotFound,
    /// The profile is configured and cannot take the request.
    #[error("{detail}")]
    #[problem(status = 409, title = "The profile is unavailable")]
    ProfileUnavailable {
        detail: String,
        /// `failed`, `vpn_down` or `offline`.
        #[problem(extension)]
        profile_status: ProfileUnavailableReason,
    },
}

impl ProfileProblem {
    fn failed(reason: &str) -> Self {
        Self::ProfileUnavailable {
            profile_status: ProfileUnavailableReason::Failed,
            detail: format!("profile failed to start: {reason}"),
        }
    }

    pub fn vpn_down() -> Self {
        Self::ProfileUnavailable {
            profile_status: ProfileUnavailableReason::VpnDown,
            detail: "profile vpn_down: the VPN monitor fenced it after its tunnel failed. Once \
                     the tunnel is back, set the profile online to lift the fence."
                .to_owned(),
        }
    }

    pub fn offline() -> Self {
        Self::ProfileUnavailable {
            profile_status: ProfileUnavailableReason::Offline,
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
    match crate::startup::tasks::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Only a runtime shutting down cancels a blocking task, and then the
        // request that awaited it is being torn down with it.
        Err(e) => panic!("engine task did not run: {e}"),
    }
}

/// The engine of a live profile, or why there is none.
///
/// A failed profile is `ProfileUnavailable`, never `ProfileNotFound`: telling an operator
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
        _ => ProfileProblem::ProfileNotFound,
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

/// The `detail` a `500 internal` carries for a failure of `attempt`: the
/// attempt, never the cause.
///
/// The cause can name paths and engine state an API caller has no business
/// reading; the log has it. A `500` is built with [`Internal::new`], which
/// holds the cause as its `#[source]`: kynos' own `ERROR` line for a 5xx
/// (target `kynos::error`) writes the detail as `error` and the cause as
/// `error.sources`. A refusal reported inside a successful answer is no 5xx
/// and gets no such line, so its caller logs the cause itself and calls this
/// for the reason.
pub fn internal(attempt: &str) -> String {
    format!("{attempt} failed; the daemon's log has the cause")
}

/// What a `500 internal` was caused by: an error, or a message where the
/// failure is not one.
type Cause = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A failure inside the daemon: `500 internal`.
///
/// Every operation that can fail this way holds it as
/// `#[problem(transparent)] Internal(#[from] Internal)`, so the `500` is
/// declared here once. The variant goes before any other transparent one:
/// kynos describes a transparent variant's statuses after every declared
/// variant's, in the order the variants are written, and that is where the
/// `500` stood when each enum declared it itself.
///
/// The other failures several operations share (`PoolNotConfigured`,
/// `PlanNotFound`, `InvalidCursor`, `ProfileNotFound`, `ProfileUnavailable`,
/// `TorrentNotFound`) stay declared in each enum. By the same rule, holding
/// one transparently would move its status, or its title, behind the
/// operation's own variants on several operations, and changing that order
/// changes the published document. Some also differ in their detail from one
/// operation to the next.
///
/// The cause is the `#[source]`, never part of the detail: it reaches the
/// daemon's log on kynos' line for the 5xx, and nothing the caller reads.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = crate::http::security::PROBLEM_BASE)]
#[problem(status = 500, title = "Internal error")]
#[error("{detail}")]
pub struct Internal {
    detail: String,
    #[source]
    cause: Option<Cause>,
}

impl Internal {
    /// The failure of `attempt`, its cause held as the source and kept out of
    /// the detail (see [`internal`]).
    pub fn new(attempt: &str, cause: impl Into<Cause>) -> Self {
        Self {
            detail: internal(attempt),
            cause: Some(cause.into()),
        }
    }

    /// A failure whose detail is written for the caller in full, its causes
    /// already logged or counted where they happened.
    pub fn detailed(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            cause: None,
        }
    }

    /// This failure, its detail followed by `more`: what the request did
    /// before it failed, and what to do about it. The cause stays the
    /// source.
    pub fn then(self, more: impl fmt::Display) -> Self {
        Self {
            detail: format!("{} {more}", self.detail),
            ..self
        }
    }
}

/// Hold `log`, the daemon's log captured while `resp`'s request ran, to
/// where a `500 internal`'s cause goes: kynos' line for the 5xx carries it,
/// and the answer does not.
///
/// kynos' line (target `kynos::error`) records the failure as an error
/// field: the daemon's JSON log writes its message, the detail, as `error`
/// and its `source()` chain, the cause nearest, as `error.sources`.
#[cfg(test)]
pub(crate) fn assert_cause_only_logged(resp: &kynos::test::TestResponse, log: &str) {
    let detail = resp.problem().detail.unwrap();
    let kynos = log
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|l| l["level"] == "ERROR" && l["target"] == "kynos::error")
        .unwrap_or_else(|| panic!("kynos logged no line for the 5xx:\n{log}"));
    assert_eq!(kynos["error"], detail.as_str(), "{log}");
    let cause = kynos["error.sources"][0]
        .as_str()
        .unwrap_or_else(|| panic!("kynos' line carries no cause:\n{log}"));
    assert!(!cause.is_empty() && !detail.contains(cause), "{log}");
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
