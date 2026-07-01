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
    upload_mode: usize,
    errored: usize,
    upload_rate_total: i64,
    download_rate_total: i64,
    pending_resume_count: u64,
    slot_count: usize,
}

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let mut seeding = 0usize;
    let mut paused = 0usize;
    let mut upload_mode = 0usize;
    let mut errored = 0usize;
    let mut up = 0i64;
    let mut down = 0i64;

    let mut total = 0usize;
    s.registry.for_each(|ih, _| {
        total += 1;
        if let Some(st) = s.state.get(ih) {
            up += st.upload_rate;
            down += st.download_rate;
            use seederd_engine::TorrentPhase::*;
            match st.phase {
                Seeding => seeding += 1,
                Paused => paused += 1,
                UploadMode => upload_mode += 1,
                Errored => errored += 1,
                _ => {}
            }
        }
    });

    Json(StatusResponse {
        torrents_total: total,
        seeding,
        paused,
        upload_mode,
        errored,
        upload_rate_total: up,
        download_rate_total: down,
        pending_resume_count: s.state.pending_resume_count(),
        slot_count: s.source.slots().len(),
    })
}
