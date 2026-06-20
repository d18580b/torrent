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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::{MetricCall, RecordingSink};
    use crate::mock::MockEngine;
    use crate::resume_store::MemoryResumeStore;
    use crate::slot::SlotId;
    use crate::state::{StateMap, TorrentState};
    use crate::torrent_store::MemoryTorrentStore;
    use libtorrent_safe::alert::{AlertHeader, TorrentStatusView};
    use libtorrent_safe::{AlertKind, InfoHash, TorrentHandle};

    fn ih(b: u8) -> InfoHash {
        InfoHash([b; 20])
    }

    fn seed_state(state: &StateMap, h: TorrentHandle) {
        state.insert(h.infohash, TorrentState::newly_added(h, SlotId::default_single(), Instant::now()));
    }

    fn dispatch(alert: &Alert, state: &StateMap, metrics: &RecordingSink) {
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut ctx = HandlerCtx {
            state,
            resume: &resume,
            torrents: &torrents,
            metrics,
            clock: &clock,
            engine: &engine,
            slot_id: SlotId::default_single(),
            span: tracing::info_span!("test"),
        };
        handle(alert, &mut ctx);
    }

    #[test]
    fn state_update_sets_seeding_phase_and_rates() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle { id: 1, infohash: ih(0x44) };
        seed_state(&state, h);
        let view = TorrentStatusView {
            handle: h,
            state: 5, // libtorrent seeding
            flags: 0,
            total_uploaded: 100,
            total_payload_uploaded: 90,
            upload_rate: 4242,
            download_rate: 0,
            num_peers: 3,
            num_seeds: 1,
            num_connections: 3,
            progress: 1.0,
            has_metadata: true,
            needs_save_resume: true,
            is_finished: true,
            is_seeding: true,
        };
        dispatch(
            &Alert::StateUpdate {
                hdr: AlertHeader { kind: AlertKind::StateUpdate, infohash: None, handle: None, timestamp_us: 0 },
                statuses: vec![view],
            },
            &state,
            &metrics,
        );
        let st = state.get(&ih(0x44)).unwrap();
        assert_eq!(st.phase, TorrentPhase::Seeding);
        assert_eq!(st.upload_rate, 4242);
        assert_eq!(st.num_peers, 3);
        assert!(st.is_seeding && st.needs_save_resume);
    }

    #[test]
    fn torrent_finished_marks_finished_seeding() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle { id: 2, infohash: ih(0x55) };
        seed_state(&state, h);
        dispatch(
            &Alert::TorrentFinished {
                hdr: AlertHeader { kind: AlertKind::TorrentFinished, infohash: Some(ih(0x55)), handle: None, timestamp_us: 0 },
            },
            &state,
            &metrics,
        );
        let st = state.get(&ih(0x55)).unwrap();
        assert!(st.is_finished);
        assert_eq!(st.phase, TorrentPhase::Seeding);
        assert!(metrics
            .calls()
            .iter()
            .any(|c| matches!(c, MetricCall::IncCounter { name, .. } if name == "torrents_finished_total")));
    }
}
