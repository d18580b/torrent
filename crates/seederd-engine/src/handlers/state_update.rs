//! `StateUpdate` and `TorrentFinished` handlers.

use tracing::info;

use crate::handlers::HandlerCtx;
use crate::state::TorrentPhase;
use libtorrent_safe::Alert;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::StateUpdate { statuses, .. } => {
            for s in statuses {
                let now = ctx.clock.now();
                ctx.state.update(&s.handle.infohash, |st| {
                    st.last_alert = now;
                    st.upload_rate = s.upload_rate;
                    st.download_rate = s.download_rate;
                    st.num_peers = s.num_peers;
                    st.progress = s.progress;
                    st.is_finished = s.is_finished;
                    st.is_seeding = s.is_seeding;
                    st.needs_save_resume = s.needs_save_resume;
                    // Map libtorrent's state enum onto our TorrentPhase.
                    // libtorrent state_t values:
                    //   0=queued_for_checking (deprecated), 1=checking_files,
                    //   2=downloading_metadata, 3=downloading, 4=finished,
                    //   5=seeding, 6=allocating, 7=checking_resume_data
                    let phase = match s.state {
                        1 | 7 => TorrentPhase::Checking,
                        4 | 5 => if s.is_seeding { TorrentPhase::Seeding } else { TorrentPhase::Idle },
                        _     => st.phase,    // preserve current; other states aren't seeder-relevant
                    };
                    if st.phase != phase {
                        st.phase = phase;
                    }
                });
            }
        }
        Alert::TorrentFinished { hdr } => {
            let _enter = ctx.span.enter();
            if let Some(ih) = hdr.infohash {
                ctx.state.update(&ih, |st| {
                    st.is_finished = true;
                    st.phase = TorrentPhase::Seeding;
                });
                info!(
                    target: "seederd_engine::handler::state_update",
                    infohash = %ih,
                    "torrent finished",
                );
                ctx.metrics.inc_counter(
                    "torrents_finished_total",
                    &[("slot_id", ctx.slot_id.as_str())],
                );
            }
        }
        _ => unreachable!("state_update::handle called with non-state_update alert"),
    }
}
