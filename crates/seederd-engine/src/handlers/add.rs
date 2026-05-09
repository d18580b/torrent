//! `AddTorrent` and `TorrentRemoved` alert handlers.

use tracing::{error, info};

use crate::handlers::HandlerCtx;
use crate::state::TorrentState;
use libtorrent_safe::Alert;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::AddTorrent { hdr, error_code, message } => {
            let _enter = ctx.span.enter();
            if *error_code != 0 {
                error!(
                    target: "seederd_engine::handler::add",
                    alert_type = "add_torrent",
                    error.code = *error_code,
                    error.cause = %message.as_deref().unwrap_or(""),
                    "add_torrent failed",
                );
                ctx.metrics.inc_counter(
                    "torrent_add_errors_total",
                    &[("slot_id", ctx.slot_id.as_str())],
                );
                return;
            }
            let Some(handle) = hdr.handle else {
                error!(
                    target: "seederd_engine::handler::add",
                    "add_torrent_alert missing handle",
                );
                return;
            };
            let now = ctx.clock.now();
            ctx.state.insert(
                handle.infohash,
                TorrentState::newly_added(handle, ctx.slot_id.clone(), now),
            );
            info!(
                target: "seederd_engine::handler::add",
                infohash = %handle.infohash,
                "torrent added",
            );
            ctx.metrics.inc_counter(
                "torrents_added_total",
                &[("slot_id", ctx.slot_id.as_str())],
            );
        }
        Alert::TorrentRemoved { hdr } => {
            let _enter = ctx.span.enter();
            if let Some(ih) = hdr.infohash {
                ctx.state.remove(&ih);
                info!(
                    target: "seederd_engine::handler::add",
                    infohash = %ih,
                    "torrent removed",
                );
                ctx.metrics.inc_counter(
                    "torrents_removed_total",
                    &[("slot_id", ctx.slot_id.as_str())],
                );
            }
        }
        _ => unreachable!("add::handle called with non-add alert"),
    }
}
