//! Error handlers: TorrentError, FileError, HashFailed.
//!
//! These set the relevant phase on the state map, increment metrics, and
//! (for FileError) schedule the upload-mode retry timer
//! Handling. The retry execution itself happens in `alert_loop::tick`.

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
            ctx.state.update(&ih, |st| {
                st.phase = TorrentPhase::Errored;
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
            ctx.state.update(&ih, |st| {
                st.phase = TorrentPhase::UploadMode;
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
                "file error; entering upload_mode with retry timer",
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
            TorrentState::newly_added(h, ProfileId::default_single(), Instant::now()),
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
            profile_id: ProfileId::default_single(),
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
    fn file_error_enters_upload_mode_with_retry() {
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
        assert_eq!(st.phase, TorrentPhase::UploadMode);
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
        assert_eq!(state.get(&ih(0x22)).unwrap().phase, TorrentPhase::Errored);
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
