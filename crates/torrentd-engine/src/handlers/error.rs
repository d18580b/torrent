//! Error handlers: TorrentError, FileError, HashFailed.
//!
//! These set the relevant phase on the state map, increment metrics, and
//! (for FileError) arm the disk-error retry timer. The retry itself runs in
//! `alert_loop::execute_due_retries`.

use libtorrent_safe::Alert;
use tracing::error;
use tracing::warn;

use crate::handlers::HandlerCtx;
use crate::state::RetryState;
use crate::state::TorrentPhase;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::TorrentError {
            hdr,
            error_code,
            filename,
            message,
        } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else { return };
            // `torrent_error_alert` is posted by `set_error` itself, so the
            // error is known to be set; record it before the status update
            // that would report it, for the same reason as `FileError`.
            ctx.state.update(&ih, |st| {
                st.phase = TorrentPhase::Errored;
                st.has_error = true;
            });
            error!(
                target: "torrentd_engine::handler::error",
                infohash = %ih,
                filename = %filename,
                error.kind = "torrent_error",
                error.code = *error_code,
                error.cause = %message,
                "torrent entered error state",
            );
            ctx.metrics.inc_counter(
                "torrent_errors_total",
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
        Alert::FileError {
            hdr,
            error_code,
            filename,
            operation,
            message,
        } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else { return };
            let now = ctx.clock.now();
            // Record the error now rather than waiting for the next
            // `state_update` to report it. A `file_error_alert` from a failed
            // check, a failed `read_piece` or a failed priority change comes
            // with `set_error` + `pause()` (vendor/libtorrent/src/torrent.cpp),
            // but the status that carries `errc` arrives later.
            // A retry timer that comes due in between would otherwise see no
            // error and a phase other than `Checking`, and retire, leaving
            // the torrent error-paused with no timer.
            //
            // Where libtorrent did not set an error, the next status update
            // clears the flag again and `DiskError` stays: a disk read for a
            // peer's request that fails only rejects the request and posts
            // this alert (vendor/libtorrent/src/peer_connection.cpp), so the
            // torrent keeps reporting `seeding` while it cannot serve; ENOMEM
            // and a write failure routed to upload mode leave no error
            // either. The retry re-checks such a torrent, which is the one
            // probe that settles whether its files can be read.
            ctx.state.update(&ih, |st| {
                st.phase = TorrentPhase::DiskError;
                st.has_error = true;
                if st.retry.is_none() {
                    st.retry = Some(RetryState::first(now));
                }
            });
            warn!(
                target: "torrentd_engine::handler::error",
                infohash = %ih,
                filename = %filename,
                op = %operation,
                error.kind = "file_error",
                error.code = *error_code,
                error.cause = %message,
                "file error; disk-error retry timer armed",
            );
            ctx.metrics.inc_counter(
                "disk_errors_total",
                &[
                    ("profile_id", ctx.profile_id.as_str()),
                    ("op", operation.as_str()),
                ],
            );
        }
        Alert::HashFailed { hdr, piece_index } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else { return };
            ctx.state.update(&ih, |st| {
                st.phase = TorrentPhase::Checking;
            });
            warn!(
                target: "torrentd_engine::handler::error",
                infohash = %ih,
                piece_index = *piece_index,
                "hash failed; libtorrent will recheck full torrent",
            );
            ctx.metrics.inc_counter(
                "hash_failures_total",
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
        _ => unreachable!("error::handle called with non-error alert"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use libtorrent_safe::alert::AlertHeader;
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

    fn seed_state(state: &StateMap, b: u8) {
        let h = TorrentHandle {
            id: b as u64,
            infohash: ih(b),
        };
        state.insert(
            ih(b),
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
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        handle(alert, &mut ctx);
    }

    fn hdr(b: u8, kind: AlertKind) -> AlertHeader {
        AlertHeader {
            kind,
            infohash: Some(ih(b)),
            handle: None,
            timestamp_us: 0,
        }
    }

    #[test]
    fn file_error_enters_disk_error_with_retry() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        seed_state(&state, 0x11);
        dispatch(
            &Alert::FileError {
                hdr: hdr(0x11, AlertKind::FileError),
                error_code: 28,
                filename: "data.bin".into(),
                operation: "write".into(),
                message: "no space left".into(),
            },
            &state,
            &metrics,
        );
        let st = state.get(&ih(0x11)).unwrap();
        assert_eq!(st.phase, TorrentPhase::DiskError);
        assert!(st.has_error, "file error must record the libtorrent error");
        assert!(st.retry.is_some(), "retry timer must be armed");
        assert!(metrics.calls().iter().any(
            |c| matches!(c, MetricCall::IncCounter { name, .. } if name == "disk_errors_total")
        ));
    }

    #[test]
    fn torrent_error_marks_errored() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        seed_state(&state, 0x22);
        dispatch(
            &Alert::TorrentError {
                hdr: hdr(0x22, AlertKind::TorrentError),
                error_code: 2,
                filename: String::new(),
                message: "boom".into(),
            },
            &state,
            &metrics,
        );
        let st = state.get(&ih(0x22)).unwrap();
        assert_eq!(st.phase, TorrentPhase::Errored);
        assert!(
            st.has_error,
            "torrent error must record the libtorrent error"
        );
    }

    #[test]
    fn hash_failed_marks_checking() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        seed_state(&state, 0x33);
        dispatch(
            &Alert::HashFailed {
                hdr: hdr(0x33, AlertKind::HashFailed),
                piece_index: 7,
            },
            &state,
            &metrics,
        );
        assert_eq!(state.get(&ih(0x33)).unwrap().phase, TorrentPhase::Checking);
    }
}
