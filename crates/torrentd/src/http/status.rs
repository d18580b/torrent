//! `GET /status` — overview of session counts + aggregate rates.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::app_state::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    torrents_total: usize,
    seeding: usize,
    paused: usize,
    /// Torrents libtorrent is hashing. One of the four states the spec names,
    /// and the one that explains why a freshly adopted pool is not seeding yet.
    checking: usize,
    /// Torrents in `TorrentPhase::DiskError`: a `file_error_alert` arrived
    /// and no state update has superseded it. This was `upload_mode`, which
    /// said nothing, since every torrent is in libtorrent's upload mode.
    disk_error: usize,
    errored: usize,
    /// Peers connected across every torrent. Not derivable from the per-torrent
    /// endpoints without listing every torrent, which is the thing the status
    /// overview exists to avoid at 100k rows.
    peers_total: i64,
    upload_rate_total: i64,
    download_rate_total: i64,
    pending_resume_count: u64,
    profile_count: usize,
}

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let mut seeding = 0usize;
    let mut paused = 0usize;
    let mut checking = 0usize;
    let mut disk_error = 0usize;
    let mut errored = 0usize;
    let mut peers = 0i64;
    let mut up = 0i64;
    let mut down = 0i64;

    let mut total = 0usize;
    s.registry.for_each(|ih, _| {
        total += 1;
        if let Some(st) = s.state.get(ih) {
            up += st.upload_rate;
            down += st.download_rate;
            peers += i64::from(st.num_peers);
            use torrentd_engine::TorrentPhase::*;
            match st.phase {
                Seeding => seeding += 1,
                Paused => paused += 1,
                Checking => checking += 1,
                DiskError => disk_error += 1,
                Errored => errored += 1,
                // Not counted: neither is a state an operator acts on here.
                Idle | Removed => {}
            }
        }
    });

    Json(StatusResponse {
        torrents_total: total,
        seeding,
        paused,
        checking,
        disk_error,
        errored,
        peers_total: peers,
        upload_rate_total: up,
        download_rate_total: down,
        pending_resume_count: s.state.pending_resume_count(),
        profile_count: s.source.profiles().len(),
    })
}
