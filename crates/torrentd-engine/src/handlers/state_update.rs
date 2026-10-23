//! `StateUpdate` and `TorrentFinished` handlers.

use libtorrent_safe::alert::TorrentStatusView;
use libtorrent_safe::Alert;
use libtorrent_safe::TorrentFlags;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::handlers::HandlerCtx;
use crate::state::TorrentPhase;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::StateUpdate { statuses, .. } => {
            for s in statuses {
                apply(s, ctx);
            }
        }
        Alert::TorrentFinished { hdr } => {
            let _enter = ctx.span.enter();
            if let Some(ih) = hdr.infohash {
                ctx.state.update(&ih, |st| {
                    st.is_finished = true;
                    st.phase = TorrentPhase::Seeding;
                    st.phase_since_check = true;
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

/// Fold one torrent's status into its state-map entry, as a
/// `state_update_alert` reports it. Also fed the statuses the overflow
/// handler reads from the session when such an alert was dropped.
pub(crate) fn apply(s: &TorrentStatusView, ctx: &HandlerCtx<'_>) {
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
        // above this: a torrent libtorrent error-paused reports
        // `Paused` — the state an operator acts on first — and
        // leaves it when the disk-error retry resumes it.
        //
        // `downloading_metadata` and `downloading` have phases of
        // their own. Folding them into whatever came before left a
        // torrent whose check found pieces missing reporting
        // `Checking` forever, and the disk-error retry, which waits
        // out a check, deferring for as long. A torrent that was
        // `DiskError` or `Errored` stays so through them: neither
        // says the error cleared.
        //
        // `finished` and `seeding` keep `DiskError` too. Not every
        // `file_error_alert` comes with a libtorrent error: a disk
        // read for a peer's request that fails
        // (vendor/libtorrent/src/peer_connection.cpp,
        // `on_disk_read_complete`) rejects the request and posts
        // the alert, and nothing else — no `set_error`, no
        // `pause()` — so the torrent goes on reporting `seeding`
        // while it cannot serve a block. Mapping that to
        // `Seeding` hid it from the phase filter, `/status` and
        // the disk-error retry alike. The retry clears it: it
        // re-checks a torrent in `DiskError` with no libtorrent
        // error, which moves it to `Checking`, and the check's
        // verdict decides where it goes from there. `Errored` is
        // cleared by a healthy update as before: `torrent_error`
        // comes from `set_error`, so the error that recorded it
        // shows in `has_error` until it is gone.
        let flags = TorrentFlags::from_bits_truncate(s.flags);
        let sticky = matches!(st.phase, TorrentPhase::DiskError | TorrentPhase::Errored);
        let phase = if flags.contains(TorrentFlags::PAUSED) {
            TorrentPhase::Paused
        } else {
            match s.state {
                0 | 1 | 7 => TorrentPhase::Checking,
                2 if !sticky => TorrentPhase::AwaitingMetadata,
                3 if !sticky => TorrentPhase::Incomplete,
                4 | 5 if st.phase == TorrentPhase::DiskError => st.phase,
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
        st.phase_since_check = true;
    });
    reassert_no_download(s, ctx);
}

/// Put a torrent whose status shows the no-download invariant lapsed —
/// `UPLOAD_MODE` missing, or a [`crate::policy::forbidden`] flag in force —
/// back under it, and count the re-assert.
///
/// Every add applies the invariant, but nothing held it afterwards: a torrent
/// found out of upload mode went on requesting pieces until the next restart
/// re-added it. Called outside the state-map update so no map lock is held
/// across the engine call. Each status that shows the lapse re-asserts again,
/// so one that does not take is retried at the next update and counted again;
/// no resume save is queued, because every add path re-applies the invariant
/// whatever the resume data says.
fn reassert_no_download(s: &TorrentStatusView, ctx: &HandlerCtx<'_>) {
    let flags = TorrentFlags::from_bits_truncate(s.flags);
    let forbidden = crate::policy::forbidden();
    if flags.contains(TorrentFlags::UPLOAD_MODE) && !flags.intersects(forbidden) {
        return;
    }
    let _enter = ctx.span.enter();
    let ih = s.handle.infohash;
    ctx.metrics.inc_counter(
        "upload_mode_reasserts_total",
        &[("profile_id", ctx.profile_id.as_str())],
    );
    match ctx.engine.enforce_no_download(s.handle) {
        Ok(()) => warn!(
            target: "torrentd_engine::handler::state_update",
            infohash = %ih,
            flags = ?flags,
            "a torrent's status showed upload mode lifted or a forbidden flag set; re-asserted \
             upload mode",
        ),
        Err(e) => error!(
            target: "torrentd_engine::handler::state_update",
            infohash = %ih,
            flags = ?flags,
            error.kind = "enforce_no_download",
            error.cause = %e,
            "a torrent's status showed upload mode lifted or a forbidden flag set, and \
             re-asserting upload mode failed; retried at the next status update",
        ),
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
    use crate::clock::Clock;
    use crate::clock::MockClock;
    use crate::engine::EngineError;
    use crate::engine::TorrentEngine;
    use crate::metrics::MetricCall;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::mock::RecordedCall;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::state::RetryState;
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
            profile_fenced: None,
            fence_hold: None,
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
        assert!(st.phase_since_check);
    }

    #[test]
    fn state_update_tracks_libtorrent_error_both_ways() {
        // A disk error that reaches libtorrent's `handle_disk_error` (a failed
        // check, say) leaves the torrent paused with an error set; `resume()`
        // clears both. The retry timer keys on `has_error`, so it
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

    /// A disk read for a peer's request that fails posts `file_error` and
    /// nothing else: libtorrent neither sets an error nor pauses the torrent,
    /// and goes on reporting `seeding`. That report must not clear the
    /// `DiskError` the alert recorded, or a torrent that cannot serve a block
    /// lists as healthy. A paused report still wins, and `Errored` is still
    /// cleared by a healthy one.
    #[test]
    fn a_peer_read_file_error_survives_a_seeding_report() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle {
            id: 5,
            infohash: ih(0x88),
        };
        seed_state(&state, h);
        let update = |lt_state: u32, flags: TorrentFlags| Alert::StateUpdate {
            hdr: AlertHeader {
                kind: AlertKind::StateUpdate,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            statuses: vec![TorrentStatusView {
                handle: h,
                state: lt_state,
                flags: flags.bits(),
                total_uploaded: 0,
                total_payload_uploaded: 0,
                upload_rate: 0,
                download_rate: 0,
                num_peers: 4,
                num_seeds: 0,
                num_connections: 4,
                progress: 1.0,
                has_metadata: true,
                needs_save_resume: false,
                is_finished: true,
                is_seeding: true,
                has_error: false,
            }],
        };
        let phase = |state: &StateMap| state.get(&ih(0x88)).unwrap().phase;

        dispatch(&update(5, TorrentFlags::empty()), &state, &metrics);
        assert_eq!(phase(&state), TorrentPhase::Seeding);
        let clock = MockClock::new();
        {
            let resume = MemoryResumeStore::new();
            let torrents = MemoryTorrentStore::new();
            let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
            let mut ctx = HandlerCtx {
                state: &state,
                resume: &resume,
                torrents: &torrents,
                metrics: &metrics,
                clock: &clock,
                engine: &engine,
                profile_fenced: None,
                fence_hold: None,
                profile_id: ProfileId::new("p"),
                span: tracing::info_span!("test"),
            };
            crate::handlers::error::handle(
                &Alert::FileError {
                    hdr: AlertHeader {
                        kind: AlertKind::FileError,
                        infohash: Some(ih(0x88)),
                        handle: None,
                        timestamp_us: 0,
                    },
                    error_code: 13,
                    filename: "data.bin".into(),
                    operation: "file_read".into(),
                    message: "Permission denied".into(),
                },
                &mut ctx,
            );
        }
        assert_eq!(phase(&state), TorrentPhase::DiskError);
        let due = clock.now() + RetryState::INITIAL_DELAY;

        for lt_state in [5, 4] {
            dispatch(&update(lt_state, TorrentFlags::empty()), &state, &metrics);
            let st = state.get(&ih(0x88)).unwrap();
            assert_eq!(
                st.phase,
                TorrentPhase::DiskError,
                "a seeding report with no error cleared the peer-read disk error",
            );
            assert!(!st.has_error, "has_error still follows libtorrent");
            let retry = st.retry.expect("the retry that clears it stays armed");
            assert_eq!(
                (retry.next_attempt, retry.attempts),
                (due, 1),
                "a status report leaves the armed retry as the error set it",
            );
        }

        dispatch(&update(5, TorrentFlags::PAUSED), &state, &metrics);
        assert_eq!(phase(&state), TorrentPhase::Paused);

        state.update(&ih(0x88), |st| st.phase = TorrentPhase::Errored);
        dispatch(&update(5, TorrentFlags::empty()), &state, &metrics);
        assert_eq!(phase(&state), TorrentPhase::Seeding);
    }

    /// `torrent_checked` leaves `phase` as it was before the check and says
    /// so; the next phase report is the first one a re-hash's verdict can be
    /// read from.
    #[test]
    fn a_check_marks_the_phase_stale_until_the_next_report() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let h = TorrentHandle {
            id: 3,
            infohash: ih(0x66),
        };
        seed_state(&state, h);
        state.update(&ih(0x66), |st| {
            st.phase = TorrentPhase::Seeding;
            st.phase_since_check = true;
        });
        let hdr = |kind| AlertHeader {
            kind,
            infohash: Some(ih(0x66)),
            handle: None,
            timestamp_us: 0,
        };
        let checked = Alert::TorrentChecked {
            hdr: hdr(AlertKind::TorrentChecked),
        };
        let clock = MockClock::new();
        {
            let resume = MemoryResumeStore::new();
            let torrents = MemoryTorrentStore::new();
            let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
            let mut ctx = HandlerCtx {
                state: &state,
                resume: &resume,
                torrents: &torrents,
                metrics: &metrics,
                clock: &clock,
                engine: &engine,
                profile_fenced: None,
                fence_hold: None,
                profile_id: ProfileId::new("p"),
                span: tracing::info_span!("test"),
            };
            crate::handlers::storage::handle(&checked, &mut ctx);
        }
        let st = state.get(&ih(0x66)).unwrap();
        assert_eq!(
            st.checked_at,
            Some(clock.now()),
            "stamped when the check ended"
        );
        assert!(!st.phase_since_check);
        assert_eq!(st.phase, TorrentPhase::Seeding, "stale, and marked so");

        dispatch(
            &Alert::TorrentFinished {
                hdr: hdr(AlertKind::TorrentFinished),
            },
            &state,
            &metrics,
        );
        assert!(state.get(&ih(0x66)).unwrap().phase_since_check);
    }

    fn reasserts(metrics: &RecordingSink) -> usize {
        metrics
            .calls()
            .iter()
            .filter(|c| {
                matches!(c, MetricCall::IncCounter { name, labels, .. }
                    if name == "upload_mode_reasserts_total"
                        && labels.iter().any(|(k, v)| k == "profile_id" && v == "p"))
            })
            .count()
    }

    /// A status showing a torrent out of upload mode, or carrying a flag that
    /// can take it out, re-asserts upload mode on that torrent and counts it
    /// for the profile; one that shows the invariant holding does neither.
    /// The overflow handler feeds its statuses through the same `apply`.
    #[test]
    fn a_status_out_of_upload_mode_reasserts_it_and_counts() {
        let h = TorrentHandle {
            id: 9,
            infohash: ih(0x99),
        };
        let view = |flags: TorrentFlags| TorrentStatusView {
            handle: h,
            state: 5,
            flags: flags.bits(),
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
            is_seeding: true,
            has_error: false,
        };
        let cases = [
            (TorrentFlags::UPLOAD_MODE, false),
            (TorrentFlags::UPLOAD_MODE | TorrentFlags::PAUSED, false),
            (TorrentFlags::empty(), true),
            (TorrentFlags::PAUSED, true),
            (TorrentFlags::UPLOAD_MODE | TorrentFlags::AUTO_MANAGED, true),
            (TorrentFlags::UPLOAD_MODE | TorrentFlags::SHARE_MODE, true),
            (
                TorrentFlags::UPLOAD_MODE | TorrentFlags::SUPER_SEEDING,
                true,
            ),
            (
                TorrentFlags::UPLOAD_MODE | TorrentFlags::SEQUENTIAL_DOWNLOAD,
                true,
            ),
            (
                TorrentFlags::UPLOAD_MODE | TorrentFlags::STOP_WHEN_READY,
                true,
            ),
        ];
        for (flags, lapsed) in cases {
            let state = StateMap::new();
            seed_state(&state, h);
            let metrics = RecordingSink::new();
            let resume = MemoryResumeStore::new();
            let torrents = MemoryTorrentStore::new();
            let clock = MockClock::new();
            let mock = Arc::new(MockEngine::new());
            let engine: Arc<dyn TorrentEngine> = mock.clone();
            let ctx = HandlerCtx {
                state: &state,
                resume: &resume,
                torrents: &torrents,
                metrics: &metrics,
                clock: &clock,
                engine: &engine,
                profile_fenced: None,
                fence_hold: None,
                profile_id: ProfileId::new("p"),
                span: tracing::info_span!("test"),
            };
            apply(&view(flags), &ctx);
            let calls: Vec<_> = mock
                .calls()
                .into_iter()
                .filter(|c| matches!(c, RecordedCall::EnforceNoDownload(_)))
                .collect();
            if lapsed {
                assert!(
                    matches!(calls.as_slice(), [RecordedCall::EnforceNoDownload(c)] if *c == h),
                    "{flags:?}: {calls:?}"
                );
                assert_eq!(reasserts(&metrics), 1, "{flags:?}");
            } else {
                assert!(calls.is_empty(), "{flags:?}");
                assert_eq!(reasserts(&metrics), 0, "{flags:?}");
            }
        }
    }

    /// A re-assert the engine refuses is still counted, and the status is
    /// still folded into the state map; the next update tries again.
    #[test]
    fn a_failed_reassert_is_counted_and_retried_at_the_next_update() {
        let h = TorrentHandle {
            id: 10,
            infohash: ih(0xAA),
        };
        let state = StateMap::new();
        seed_state(&state, h);
        let metrics = RecordingSink::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let mock = Arc::new(MockEngine::new());
        mock.inject_error(
            "enforce_no_download",
            EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(h.infohash)),
        );
        let engine: Arc<dyn TorrentEngine> = mock.clone();
        let ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        let view = TorrentStatusView {
            handle: h,
            state: 5,
            flags: 0,
            total_uploaded: 7,
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
            is_seeding: true,
            has_error: false,
        };
        apply(&view, &ctx);
        assert_eq!(state.get(&ih(0xAA)).unwrap().total_uploaded, 7);
        apply(&view, &ctx);
        let enforced = mock
            .calls()
            .into_iter()
            .filter(|c| matches!(c, RecordedCall::EnforceNoDownload(_)))
            .count();
        assert_eq!(enforced, 2);
        assert_eq!(reasserts(&metrics), 2);
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
