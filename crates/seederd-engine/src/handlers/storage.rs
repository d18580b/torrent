//! Payload-lifecycle handlers: `TorrentChecked`, `StorageMoved`,
//! `StorageMovedFailed`.
//!
//! Both operations are asynchronous in libtorrent — `force_recheck` and
//! `move_storage` return immediately and report completion here. The pool
//! layer keys its adoption and relocation state machines off these alerts, so
//! they are logged and counted rather than dropped as unhandled.

use libtorrent_safe::Alert;
use tracing::error;
use tracing::info;

use crate::handlers::HandlerCtx;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::TorrentChecked { hdr } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else { return };
            // Stamp the state map: this alert is the only authoritative
            // "hashing is over" signal. The verdict itself (complete /
            // incomplete) arrives in the following state_update, and a torrent
            // that failed its check never reaches a distinct phase — so a
            // reader that waits for one waits forever. The verify queue keys
            // its retirement off this.
            ctx.state
                .update(&ih, |st| st.checked_at = Some(ctx.clock.now()));
            info!(
                target: "seederd_engine::handler::storage",
                infohash = %ih,
                "force_recheck complete",
            );
            ctx.metrics.inc_counter(
                "torrents_checked_total",
                &[("slot_id", ctx.slot_id.as_str())],
            );
        }
        Alert::StorageMoved { hdr, path } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else { return };
            info!(
                target: "seederd_engine::handler::storage",
                infohash = %ih,
                save_path = %path,
                "storage moved",
            );
            ctx.metrics
                .inc_counter("storage_moves_total", &[("slot_id", ctx.slot_id.as_str())]);
        }
        Alert::StorageMovedFailed {
            hdr,
            error_code,
            operation,
            path,
            message,
        } => {
            let _enter = ctx.span.enter();
            let infohash = hdr.infohash.map(|i| i.to_hex()).unwrap_or_default();
            // The torrent keeps seeding from its original location: libtorrent
            // only commits the new save_path on success. A relocation plan
            // treats this as a failed step and stops rather than continuing.
            error!(
                target: "seederd_engine::handler::storage",
                infohash = %infohash,
                save_path = %path,
                op = %operation,
                error.kind = "storage_moved_failed",
                error.code = *error_code,
                error.cause = %message,
                "storage move failed; torrent still served from its old path",
            );
            ctx.metrics.inc_counter(
                "storage_move_failures_total",
                &[("slot_id", ctx.slot_id.as_str())],
            );
        }
        _ => unreachable!("storage::handle called with non-storage alert"),
    }
}
