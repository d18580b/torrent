//! `AddTorrent` and `TorrentRemoved` alert handlers.

use tracing::{error, info, warn};

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
                // Delete persisted state so a removed torrent doesn't
                // resurrect from disk on the next startup scan. This fires
                // after libtorrent has fully removed the torrent, so it can't
                // race a still-pending save_resume_data write.
                if let Err(e) = ctx.resume.delete(&ctx.slot_id, &ih) {
                    warn!(
                        target: "seederd_engine::handler::add",
                        infohash = %ih,
                        error.cause = %e,
                        "failed to delete resume file on remove",
                    );
                }
                if let Err(e) = ctx.torrents.delete(&ctx.slot_id, &ih) {
                    warn!(
                        target: "seederd_engine::handler::add",
                        infohash = %ih,
                        error.cause = %e,
                        "failed to delete torrent file on remove",
                    );
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::clock::{Clock, MockClock};
    use crate::engine::TorrentEngine;
    use crate::metrics::NoopSink;
    use crate::mock::MockEngine;
    use crate::resume_store::{MemoryResumeStore, ResumeStore};
    use crate::slot::SlotId;
    use crate::state::{StateMap, TorrentState};
    use crate::torrent_store::{MemoryTorrentStore, TorrentStore};
    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::{AlertKind, InfoHash, TorrentHandle};

    #[test]
    fn removed_torrent_deletes_resume_and_torrent_files() {
        let ih = InfoHash([0x77; 20]);
        let slot = SlotId::default_single();
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());

        // The torrent exists with persisted resume + .torrent on disk.
        let th = TorrentHandle { id: 1, infohash: ih };
        state.insert(ih, TorrentState::newly_added(th, slot.clone(), clock.now()));
        resume.write(&slot, &ih, b"resume-bytes").unwrap();
        torrents.write(&slot, &ih, b"torrent-bytes").unwrap();

        let alert = Alert::TorrentRemoved {
            hdr: AlertHeader {
                kind: AlertKind::TorrentRemoved,
                infohash: Some(ih),
                handle: None,
                timestamp_us: 0,
            },
        };
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            slot_id: slot.clone(),
            span: tracing::info_span!("test"),
        };

        handle(&alert, &mut ctx);

        // No resurrection: state, resume file, and .torrent are all gone.
        assert!(!state.contains(&ih));
        assert!(resume.snapshot(&slot).is_empty());
        assert!(torrents.load_all(&slot).unwrap().is_empty());
    }
}
