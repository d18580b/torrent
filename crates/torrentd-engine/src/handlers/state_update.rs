//! `StateUpdate` and `TorrentFinished` handlers.

use libtorrent_safe::Alert;
use libtorrent_safe::TorrentFlags;
use tracing::info;

use crate::handlers::HandlerCtx;
use crate::state::TorrentPhase;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::StateUpdate { statuses, .. } => {
            for s in statuses {
                let now = ctx.clock.now();
                ctx.state.update(&s.handle.infohash, |st| {
                    st.last_alert = now;
                    st.upload_rate = s.upload_rate;
                    st.download_rate = s.download_rate;
                    st.total_uploaded = s.total_uploaded;
                    st.total_payload_uploaded = s.total_payload_uploaded;
                    st.num_peers = s.num_peers;
                    st.progress = s.progress;
                    st.is_finished = s.is_finished;
                    st.is_seeding = s.is_seeding;
                    st.needs_save_resume = s.needs_save_resume;
                    st.has_error = s.has_error;
                    // Map libtorrent's state enum onto our TorrentPhase.
                    // libtorrent state_t values:
                    //   0=queued_for_checking (deprecated), 1=checking_files,
                    //   2=downloading_metadata, 3=downloading, 4=finished,
                    //   5=seeding, 6=allocating, 7=checking_resume_data
                    //
                    // The paused bit wins over the state enum, because
                    // libtorrent keeps reporting `seeding` for a paused
                    // torrent: pausing stops the transfers, it does not change
                    // `state`. Mapping on the enum alone is why
                    // `TorrentPhase::Paused` was never assigned by anything
                    // and `/status` reported a permanent zero however many
                    // torrents were paused — including a whole profile the VPN
                    // monitor had fenced, which is exactly when someone looks.
                    //
                    // `Errored` / `DiskError` are deliberately *not* pinned
                    // above this. They are cleared by a healthy `seeding`
                    // update, which is how a torrent that recovered from a
                    // disk error leaves `DiskError`; making them sticky would
                    // strand it there. libtorrent pauses a torrent whose disk
                    // error it cannot route to upload mode, so paused usually
                    // shows — the state an operator acts on first — and if
                    // the disk error is still there when it resumes, the
                    // alert fires again.
                    //
                    // `downloading_metadata` and `downloading` have phases of
                    // their own. Folding them into whatever came before left a
                    // torrent whose check found pieces missing reporting
                    // `Checking` forever, and the disk-error retry, which waits
                    // out a check, deferring for as long. A torrent that was
                    // `DiskError` or `Errored` stays so through them: neither
                    // says the error cleared.
                    let flags = TorrentFlags::from_bits_truncate(s.flags);
                    let sticky =
                        matches!(st.phase, TorrentPhase::DiskError | TorrentPhase::Errored);
                    let phase = if flags.contains(TorrentFlags::PAUSED) {
                        TorrentPhase::Paused
                    } else {
                        match s.state {
                            0 | 1 | 7 => TorrentPhase::Checking,
                            2 if !sticky => TorrentPhase::AwaitingMetadata,
                            3 if !sticky => TorrentPhase::Incomplete,
                            4 | 5 => {
                                if s.is_seeding {
                                    TorrentPhase::Seeding
                                } else {
                                    TorrentPhase::Idle
                                }
                            }
                            // Preserve the current phase: `allocating` says
                            // nothing a seeder acts on, and `DiskError` and
                            // `Errored` are set by the error handler and must
                            // survive here.
                            _ => st.phase,
                        }
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
                    target: "torrentd_engine::handler::state_update",
                    infohash = %ih,
                    "torrent finished",
                );
                ctx.metrics.inc_counter(
                    "torrents_finished_total",
                    &[("profile_id", ctx.profile_id.as_str())],
                );
            }
        }
        _ => unreachable!("state_update::handle called with non-state_update alert"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::alert::TorrentStatusView;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;
    use libtorrent_safe::TorrentHandle;

    use super::*;
    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::MetricCall;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::state::StateMap;
    use crate::state::TorrentState;
    use crate::torrent_store::MemoryTorrentStore;

    fn ih(b: u8) -> InfoHash {
        InfoHash([b; 20])
    }

    fn seed_state(state: &StateMap, h: TorrentHandle) {
        state.insert(
            h.infohash,
            TorrentState::newly_added(h, ProfileId::new("p"), Instant::now()),
        );
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
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        handle(alert, &mut ctx);
    }

    #[test]
    fn state_update_sets_seeding_phase_and_rates() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle {
            id: 1,
            infohash: ih(0x44),
        };
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
            has_error: false,
        };
        dispatch(
            &Alert::StateUpdate {
                hdr: AlertHeader {
                    kind: AlertKind::StateUpdate,
                    infohash: None,
                    handle: None,
                    timestamp_us: 0,
                },
                statuses: vec![view],
            },
            &state,
            &metrics,
        );
        let st = state.get(&ih(0x44)).unwrap();
        assert_eq!(st.phase, TorrentPhase::Seeding);
        assert_eq!(st.upload_rate, 4242);
        assert_eq!(st.total_uploaded, 100);
        assert_eq!(st.total_payload_uploaded, 90);
        assert_eq!(st.num_peers, 3);
        assert!(st.is_seeding && st.needs_save_resume);
    }

    #[test]
    fn state_update_tracks_libtorrent_error_both_ways() {
        // A read-class disk error leaves the torrent paused with an error set;
        // `resume()` clears both. The retry timer keys on `has_error`, so it
        // must follow libtorrent in each direction, not latch.
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle {
            id: 3,
            infohash: ih(0x66),
        };
        seed_state(&state, h);
        let view = |paused: bool, has_error: bool| TorrentStatusView {
            handle: h,
            state: 5,
            flags: if paused {
                TorrentFlags::PAUSED.bits()
            } else {
                0
            },
            total_uploaded: 0,
            total_payload_uploaded: 0,
            upload_rate: 0,
            download_rate: 0,
            num_peers: 0,
            num_seeds: 0,
            num_connections: 0,
            progress: 1.0,
            has_metadata: true,
            needs_save_resume: false,
            is_finished: true,
            is_seeding: !paused,
            has_error,
        };
        let update = |v: TorrentStatusView| Alert::StateUpdate {
            hdr: AlertHeader {
                kind: AlertKind::StateUpdate,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            statuses: vec![v],
        };

        dispatch(&update(view(true, true)), &state, &metrics);
        let st = state.get(&ih(0x66)).unwrap();
        assert!(st.has_error);
        assert_eq!(st.phase, TorrentPhase::Paused);

        dispatch(&update(view(false, false)), &state, &metrics);
        let st = state.get(&ih(0x66)).unwrap();
        assert!(!st.has_error);
        assert_eq!(st.phase, TorrentPhase::Seeding);
    }

    /// libtorrent's `downloading_metadata` and `downloading` get phases of
    /// their own rather than inheriting the one before. A torrent whose check
    /// found pieces missing used to report `Checking` for good.
    #[test]
    fn metadata_and_missing_pieces_have_their_own_phases() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle {
            id: 4,
            infohash: ih(0x77),
        };
        seed_state(&state, h);
        let update = |lt_state: u32| Alert::StateUpdate {
            hdr: AlertHeader {
                kind: AlertKind::StateUpdate,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            statuses: vec![TorrentStatusView {
                handle: h,
                state: lt_state,
                flags: TorrentFlags::UPLOAD_MODE.bits(),
                total_uploaded: 0,
                total_payload_uploaded: 0,
                upload_rate: 0,
                download_rate: 0,
                num_peers: 0,
                num_seeds: 0,
                num_connections: 0,
                progress: 0.5,
                has_metadata: lt_state != 2,
                needs_save_resume: false,
                is_finished: false,
                is_seeding: false,
                has_error: false,
            }],
        };
        let phase = |state: &StateMap| state.get(&ih(0x77)).unwrap().phase;

        dispatch(&update(2), &state, &metrics);
        assert_eq!(phase(&state), TorrentPhase::AwaitingMetadata);
        dispatch(&update(1), &state, &metrics);
        assert_eq!(phase(&state), TorrentPhase::Checking);
        // The check found pieces missing.
        dispatch(&update(3), &state, &metrics);
        assert_eq!(phase(&state), TorrentPhase::Incomplete);

        // An error the handlers recorded is not cleared by either.
        for (sticky, lt_state) in [(TorrentPhase::DiskError, 3), (TorrentPhase::Errored, 2)] {
            state.update(&ih(0x77), |st| st.phase = sticky);
            dispatch(&update(lt_state), &state, &metrics);
            assert_eq!(phase(&state), sticky);
        }
    }

    #[test]
    fn torrent_finished_marks_finished_seeding() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle {
            id: 2,
            infohash: ih(0x55),
        };
        seed_state(&state, h);
        dispatch(
            &Alert::TorrentFinished {
                hdr: AlertHeader {
                    kind: AlertKind::TorrentFinished,
                    infohash: Some(ih(0x55)),
                    handle: None,
                    timestamp_us: 0,
                },
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
