//! The wire types a torrent is reported in, and the paths that name one.

use std::fmt;
use std::str::FromStr;

use kynos::prelude::*;
use kynos::schema::ParamValue;
use libtorrent_safe::InfoHash;
use serde::Serialize;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentDetails;
use torrentd_engine::TorrentState;

use crate::app_state::AppState;
use crate::http::page::page;
use crate::http::v1::common::InfoHashHex;

/// What a torrent is doing, as of the last state update libtorrent posted.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TorrentPhase {
    /// libtorrent is hashing pieces; the torrent is not seeding yet.
    Checking,
    /// A magnet whose metadata has not arrived yet.
    AwaitingMetadata,
    /// Pieces are missing from the payload, and the torrent never downloads
    /// them: its check failed, or the payload was never there. Supply the
    /// payload and recheck.
    Incomplete,
    /// Has metadata but no peers yet; rare for a seeder.
    Idle,
    /// Seeding.
    Seeding,
    /// Paused, by an operator or by the VPN fence.
    Paused,
    /// libtorrent's last word was a file error; the disk-error retry is
    /// working on it.
    DiskError,
    /// libtorrent set an error on the torrent.
    Errored,
    /// Removed from its session; about to disappear from the listing.
    Removed,
    /// No state update has arrived for it: it is still being added, or its
    /// profile's session did not load it at boot.
    Unknown,
}

impl TorrentPhase {
    const ALL: [Self; 10] = [
        Self::Checking,
        Self::AwaitingMetadata,
        Self::Incomplete,
        Self::Idle,
        Self::Seeding,
        Self::Paused,
        Self::DiskError,
        Self::Errored,
        Self::Removed,
        Self::Unknown,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Checking => "checking",
            Self::AwaitingMetadata => "awaiting_metadata",
            Self::Incomplete => "incomplete",
            Self::Idle => "idle",
            Self::Seeding => "seeding",
            Self::Paused => "paused",
            Self::DiskError => "disk_error",
            Self::Errored => "errored",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }

    pub(super) fn of(state: Option<&TorrentState>) -> Self {
        use torrentd_engine::TorrentPhase as P;
        match state.map(|s| s.phase) {
            Some(P::Checking) => Self::Checking,
            Some(P::AwaitingMetadata) => Self::AwaitingMetadata,
            Some(P::Incomplete) => Self::Incomplete,
            Some(P::Idle) => Self::Idle,
            Some(P::Seeding) => Self::Seeding,
            Some(P::Paused) => Self::Paused,
            Some(P::DiskError) => Self::DiskError,
            Some(P::Errored) => Self::Errored,
            Some(P::Removed) => Self::Removed,
            None => Self::Unknown,
        }
    }
}

impl fmt::Display for TorrentPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TorrentPhase {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| format!("unknown phase {s:?}"))
    }
}

impl ParamValue for TorrentPhase {}

#[derive(Debug, Schema, Serialize)]
/// One torrent, as a listing reports it: what the daemon's own state map
/// knows, read without asking any session.
///
/// `GET /v1/torrents/{infohash}` returns the fuller [`Torrent`], which adds
/// what only the torrent's session can say.
pub struct TorrentSummary {
    /// The torrent's v1 infohash, or for a v2-only torrent its v2 infohash
    /// truncated to 20 bytes.
    pub infohash: InfoHashHex,
    /// The profile the torrent is assigned to. An infohash belongs to exactly
    /// one profile.
    pub profile_id: String,
    /// What the torrent is doing. `unknown` when no state update has arrived
    /// for it — it is still being added, or no session holds it.
    pub phase: TorrentPhase,
    /// Fraction of the payload present and verified, 0 to 1.
    pub progress: f32,
    /// Upload rate, in bytes per second.
    pub upload_rate: u64,
    /// Download rate, in bytes per second. A seeding daemon keeps this near
    /// zero.
    pub download_rate: u64,
    /// Bytes uploaded this session, including protocol overhead.
    pub total_uploaded: u64,
    /// Payload bytes uploaded this session, the figure ratios are judged on.
    pub total_payload_uploaded: u64,
    /// Peers connected.
    pub num_peers: u32,
    /// Whether every wanted piece is present.
    pub is_finished: bool,
    /// Whether the torrent is seeding.
    pub is_seeding: bool,
}

impl TorrentSummary {
    /// The torrent `ih`, assigned to `profile`, from the state map.
    pub(super) fn build(s: &AppState, ih: &InfoHash, profile: &ProfileId) -> Self {
        let st = s.state.get(ih);
        let st = st.as_ref();
        Self {
            infohash: InfoHashHex::new(*ih),
            profile_id: profile.as_str().to_owned(),
            phase: TorrentPhase::of(st),
            progress: st.map_or(0.0, |s| s.progress),
            upload_rate: st.map_or(0, |s| s.upload_rate.max(0) as u64),
            download_rate: st.map_or(0, |s| s.download_rate.max(0) as u64),
            total_uploaded: st.map_or(0, |s| s.total_uploaded),
            total_payload_uploaded: st.map_or(0, |s| s.total_payload_uploaded),
            num_peers: st.map_or(0, |s| s.num_peers.max(0) as u32),
            is_finished: st.is_some_and(|s| s.is_finished),
            is_seeding: st.is_some_and(|s| s.is_seeding),
        }
    }
}

#[derive(Debug, Schema, Serialize)]
/// One torrent: its summary, and what its session reports.
pub struct Torrent {
    #[serde(flatten)]
    pub summary: TorrentSummary,
    /// What the torrent's session reports. `null` exactly when no session
    /// holds the torrent: it is still being added, its profile never came up,
    /// or the session could not be asked (the daemon logs why).
    pub session: Option<TorrentSession>,
}

#[derive(Debug, Schema, Serialize)]
/// What a torrent's session reports about it.
pub struct TorrentSession {
    /// The torrent's name. `null` while a magnet has no metadata.
    pub name: Option<String>,
    /// Total payload size in bytes. `null` while a magnet has no metadata.
    pub total_size: Option<u64>,
    /// Where the payload is stored.
    pub save_path: String,
    /// This torrent's own upload limit in bytes per second; `null` when it
    /// has none (the profile's and the daemon's limits still apply).
    pub upload_limit_bytes_per_sec: Option<u32>,
    /// When the torrent was first added; `null` when libtorrent does not know.
    pub added_at: Option<jiff::Timestamp>,
}

impl Torrent {
    /// The torrent `ih`, assigned to `profile`, with `details` from its
    /// session when there are any.
    pub(super) fn build(
        s: &AppState,
        ih: &InfoHash,
        profile: &ProfileId,
        details: Option<TorrentDetails>,
    ) -> Self {
        Self {
            summary: TorrentSummary::build(s, ih, profile),
            session: details.map(|d| TorrentSession {
                name: d.name,
                total_size: d.total_size,
                save_path: d.save_path,
                upload_limit_bytes_per_sec: d.upload_limit,
                added_at: d
                    .added_at
                    .and_then(|secs| jiff::Timestamp::from_second(secs).ok()),
            }),
        }
    }
}

page!(
    /// One page of torrents, ordered by infohash.
    TorrentPage,
    TorrentSummary
);

/// The torrent `/{infohash}` names.
#[derive(Schema, PathParams)]
pub struct TorrentPath {
    /// The torrent's v1 infohash (truncated v2 for a v2-only torrent), 40 hex
    /// digits in either case.
    pub infohash: InfoHashHex,
}

/// One file of a torrent, `/{infohash}/files/{index}`.
#[derive(Schema, PathParams)]
pub struct TorrentFilePath {
    /// The torrent's v1 infohash (truncated v2 for a v2-only torrent), 40 hex
    /// digits in either case.
    pub infohash: InfoHashHex,
    /// The file's index, as `GET /v1/torrents/{infohash}/files` reports it.
    pub index: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_phase_round_trips_through_its_query_form() {
        for phase in TorrentPhase::ALL {
            assert_eq!(phase.to_string().parse::<TorrentPhase>(), Ok(phase));
            let json = serde_json::to_value(phase).unwrap();
            assert_eq!(json, phase.as_str());
        }
        assert!("Seeding".parse::<TorrentPhase>().is_err());
    }
}
