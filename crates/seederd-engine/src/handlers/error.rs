//! Error handlers: TorrentError, FileError, HashFailed.
//!
//! These set the relevant phase on the state map, increment metrics, and
//! (for FileError) schedule the upload-mode retry timer per PRD §Error
//! Handling. The retry execution itself happens in `alert_loop::tick`.

use tracing::{error, warn};

use crate::handlers::HandlerCtx;
use crate::state::{RetryState, TorrentPhase};
use libtorrent_safe::Alert;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::TorrentError { hdr, error_code, filename, message } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else { return };
            ctx.state.update(&ih, |st| { st.phase = TorrentPhase::Errored; });
            error!(
                target: "seederd_engine::handler::error",
                infohash = %ih,
                filename = %filename,
                error.kind = "torrent_error",
                error.code = *error_code,
                error.cause = %message,
                "torrent entered error state",
            );
            ctx.metrics.inc_counter(
                "torrent_errors_total",
                &[("slot_id", ctx.slot_id.as_str())],
            );
        }
        Alert::FileError { hdr, error_code, filename, operation, message } => {
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
                target: "seederd_engine::handler::error",
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
                &[("slot_id", ctx.slot_id.as_str()),
                  ("op", operation.as_str())],
            );
        }
        Alert::HashFailed { hdr, piece_index } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else { return };
            ctx.state.update(&ih, |st| { st.phase = TorrentPhase::Checking; });
            warn!(
                target: "seederd_engine::handler::error",
                infohash = %ih,
                piece_index = *piece_index,
                "hash failed; libtorrent will recheck full torrent",
            );
            ctx.metrics.inc_counter(
                "hash_failures_total",
                &[("slot_id", ctx.slot_id.as_str())],
            );
        }
        _ => unreachable!("error::handle called with non-error alert"),
    }
}
