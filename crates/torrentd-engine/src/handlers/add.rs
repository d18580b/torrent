//! `AddTorrent` and `TorrentRemoved` alert handlers.

use std::sync::atomic::fence;
use std::sync::atomic::Ordering;

use libtorrent_safe::Alert;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::TorrentHandle;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::handlers::HandlerCtx;
use crate::state::TorrentState;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::AddTorrent {
            hdr,
            error_code,
            message,
        } => {
            let _enter = ctx.span.enter();
            if *error_code != 0 {
                error!(
                    target: "torrentd_engine::handler::add",
                    alert_type = "add_torrent",
                    error.code = *error_code,
                    error.cause = %message.as_deref().unwrap_or(""),
                    "add_torrent failed",
                );
                ctx.metrics.inc_counter(
                    "torrent_add_errors_total",
                    &[("profile_id", ctx.profile_id.as_str())],
                );
                return;
            }
            let Some(handle) = hdr.handle else {
                error!(
                    target: "torrentd_engine::handler::add",
                    "add_torrent_alert missing handle",
                );
                return;
            };
            let now = ctx.clock.now();
            ctx.state.insert(
                handle.infohash,
                TorrentState::newly_added(handle, ctx.profile_id.clone(), now),
            );
            hold_if_fenced(handle, ctx);
            // Make the add durable now rather than at the next 30-minute sweep
            // or the shutdown drain: until a resume file exists, a crash
            // leaves the registry claiming a torrent no session reloads.
            // Unconditional, because an `ONLY_IF_MODIFIED` save depends on
            // libtorrent's modified bit, which says nothing about whether
            // this torrent has a file on disk yet.
            ctx.state
                .queue_resume_save(handle.infohash, ResumeFlags::empty());
            info!(
                target: "torrentd_engine::handler::add",
                infohash = %handle.infohash,
                "torrent added",
            );
            ctx.metrics.inc_counter(
                "torrents_added_total",
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
        Alert::TorrentRemoved { hdr } => {
            let _enter = ctx.span.enter();
            if let Some(ih) = hdr.infohash {
                ctx.state.remove(&ih);
                // Settle a save that was in flight when the torrent went: its
                // answer arrives with no info-hash (the shim skips an invalid
                // handle), so `resume::handle` cannot settle it, and the drain
                // would wait out its deadline on it while it held a cap slot.
                // A queued one is dropped at dispatch, which finds no state.
                ctx.state.note_resume_settled(&ih);
                // Delete persisted state so a removed torrent doesn't
                // resurrect from disk on the next startup scan. This fires
                // after libtorrent has fully removed the torrent, so it can't
                // race a still-pending save_resume_data write.
                if let Err(e) = ctx.resume.delete(&ctx.profile_id, &ih) {
                    warn!(
                        target: "torrentd_engine::handler::add",
                        infohash = %ih,
                        error.cause = %e,
                        "failed to delete resume file on remove",
                    );
                }
                if let Err(e) = ctx.torrents.delete(&ctx.profile_id, &ih) {
                    warn!(
                        target: "torrentd_engine::handler::add",
                        infohash = %ih,
                        error.cause = %e,
                        "failed to delete torrent file on remove",
                    );
                }
                info!(
                    target: "torrentd_engine::handler::add",
                    infohash = %ih,
                    "torrent removed",
                );
                ctx.metrics.inc_counter(
                    "torrents_removed_total",
                    &[("profile_id", ctx.profile_id.as_str())],
                );
            }
        }
        _ => unreachable!("add::handle called with non-add alert"),
    }
}

/// Pause a torrent just inserted into the state map if its profile is fenced.
///
/// The VPN monitor fences a profile by pausing the torrents the state map
/// holds, and a torrent enters the map only here, when its `add_torrent_alert`
/// is handled. One the session added before the fence and whose alert lands
/// after it was not in the map the fence walked, so without this it would seed
/// on in a profile whose tunnel is down.
///
/// The fence marks the profile before it walks the map, and this inserts
/// before it asks. The `SeqCst` fence here pairs with the one in the VPN
/// monitor between those two steps, so at least one side sees the other: the
/// fence finds the torrent in the map, or this finds the profile fenced.
///
/// A torrent paused here is not added to the profile's `paused_for_vpn`
/// count: the fence's walk and the daemon's own post-add re-check can pause
/// the same torrent, so counting each pause would overcount.
fn hold_if_fenced(handle: TorrentHandle, ctx: &HandlerCtx<'_>) {
    fence(Ordering::SeqCst);
    if !ctx.profile_fenced.is_some_and(|f| f(&ctx.profile_id)) {
        return;
    }
    match ctx.engine.pause_torrent(handle) {
        Ok(()) => info!(
            target: "torrentd_engine::handler::add",
            infohash = %handle.infohash,
            "torrent added into a fenced profile; paused",
        ),
        Err(e) => {
            error!(
                target: "torrentd_engine::handler::add",
                infohash = %handle.infohash,
                error.cause = %e,
                "could not pause a torrent added into a fenced profile",
            );
            ctx.metrics.inc_counter(
                "profile_fence_pause_errors_total",
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;
    use libtorrent_safe::TorrentHandle;

    use super::*;
    use crate::clock::Clock;
    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::NoopSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::resume_store::ResumeStore;
    use crate::state::StateMap;
    use crate::state::TorrentState;
    use crate::torrent_store::MemoryTorrentStore;
    use crate::torrent_store::TorrentStore;

    #[test]
    fn removed_torrent_deletes_resume_and_torrent_files() {
        let ih = InfoHash([0x77; 20]);
        let profile = ProfileId::new("p");
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());

        // The torrent exists with persisted resume + .torrent on disk.
        let th = TorrentHandle {
            id: 1,
            infohash: ih,
        };
        state.insert(
            ih,
            TorrentState::newly_added(th, profile.clone(), clock.now()),
        );
        resume.write(&profile, &ih, b"resume-bytes").unwrap();
        torrents.write(&profile, &ih, b"torrent-bytes").unwrap();

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
            profile_fenced: None,
            profile_id: profile.clone(),
            span: tracing::info_span!("test"),
        };

        handle(&alert, &mut ctx);

        // No resurrection: state, resume file, and .torrent are all gone.
        assert!(!state.contains(&ih));
        assert!(resume.snapshot(&profile).is_empty());
        assert!(torrents.load_all(&profile).unwrap().is_empty());
    }

    #[test]
    fn removing_a_torrent_settles_its_in_flight_save() {
        use libtorrent_safe::ResumeFlags;

        use crate::handlers::resume;

        let ih = InfoHash([0x78; 20]);
        let profile = ProfileId::new("p");
        let state = StateMap::new();
        let resume_store = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let th = TorrentHandle {
            id: 1,
            infohash: ih,
        };
        state.insert(
            ih,
            TorrentState::newly_added(th, profile.clone(), clock.now()),
        );
        assert!(state.queue_resume_save(ih, ResumeFlags::empty()));
        assert_eq!(state.dispatch_resume_saves(8).len(), 1);
        assert_eq!(state.resume_saves_in_flight(), 1);

        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume_store,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            profile_id: profile.clone(),
            span: tracing::info_span!("test"),
        };
        handle(
            &Alert::TorrentRemoved {
                hdr: AlertHeader {
                    kind: AlertKind::TorrentRemoved,
                    infohash: Some(ih),
                    handle: None,
                    timestamp_us: 0,
                },
            },
            &mut ctx,
        );
        // The save's answer for the removed torrent carries no info-hash.
        resume::handle(
            &Alert::SaveResumeDataFailed {
                hdr: AlertHeader {
                    kind: AlertKind::SaveResumeDataFailed,
                    infohash: None,
                    handle: None,
                    timestamp_us: 0,
                },
                error_code: 0,
                not_modified: false,
                message: String::new(),
            },
            &mut ctx,
        );

        assert_eq!(state.resume_saves_in_flight(), 0);
        assert_eq!(state.pending_resume_count(), 0);
    }

    fn add_alert(ih: InfoHash, handle: Option<TorrentHandle>, error_code: i32) -> Alert {
        Alert::AddTorrent {
            hdr: AlertHeader {
                kind: AlertKind::AddTorrent,
                infohash: Some(ih),
                handle,
                timestamp_us: 0,
            },
            error_code,
            message: (error_code != 0).then(|| "refused".to_string()),
        }
    }

    #[test]
    fn an_added_torrent_gets_an_unconditional_resume_save_at_once() {
        let ih = InfoHash([0x79; 20]);
        let profile = ProfileId::new("p");
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let th = TorrentHandle {
            id: 1,
            infohash: ih,
        };
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            profile_id: profile,
            span: tracing::info_span!("test"),
        };

        handle(&add_alert(ih, Some(th), 0), &mut ctx);

        // Queued for the dispatcher, not left for the 30-minute sweep, and
        // without `ONLY_IF_MODIFIED`: nothing is on disk for it yet.
        assert_eq!(state.pending_resume_count(), 1);
        assert_eq!(
            state.dispatch_resume_saves(8),
            vec![(ih, ResumeFlags::empty())],
        );
    }

    #[test]
    fn a_failed_add_queues_no_resume_save() {
        let ih = InfoHash([0x7A; 20]);
        let profile = ProfileId::new("p");
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            profile_id: profile,
            span: tracing::info_span!("test"),
        };

        handle(&add_alert(ih, None, 1), &mut ctx);

        assert!(!state.contains(&ih));
        assert_eq!(state.pending_resume_count(), 0);
    }

    /// Add a torrent to a mock session, let `fenced_after_add` decide whether
    /// the profile is fenced before its `add_torrent_alert` is handled, then
    /// handle it. Returns the handle and the engine's recorded calls.
    fn add_then_handle_alert(
        fenced_after_add: bool,
    ) -> (TorrentHandle, Vec<crate::mock::RecordedCall>) {
        use std::sync::atomic::AtomicBool;

        use libtorrent_safe::AddParams;
        use libtorrent_safe::TorrentFlags;

        use crate::alert_loop::ProfileFenced;

        let profile = ProfileId::new("p");
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let mock = Arc::new(MockEngine::new());
        let engine: Arc<dyn TorrentEngine> = mock.clone();
        let fenced = Arc::new(AtomicBool::new(false));
        let profile_fenced: ProfileFenced = {
            let fenced = fenced.clone();
            Arc::new(move |_: &ProfileId| fenced.load(Ordering::SeqCst))
        };

        let th = engine
            .add_torrent(AddParams::Magnet {
                uri: "magnet:?xt=urn:btih:".to_string() + &"ab".repeat(20),
                save_path: "/data".to_string(),
                flags: TorrentFlags::empty(),
            })
            .unwrap();
        // The fence walks the state map now, which does not hold the torrent:
        // its alert is still queued.
        assert!(!state.contains(&th.infohash));
        fenced.store(fenced_after_add, Ordering::SeqCst);

        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: Some(&profile_fenced),
            profile_id: profile,
            span: tracing::info_span!("test"),
        };
        handle(
            &Alert::AddTorrent {
                hdr: AlertHeader {
                    kind: AlertKind::AddTorrent,
                    infohash: Some(th.infohash),
                    handle: Some(th),
                    timestamp_us: 0,
                },
                error_code: 0,
                message: None,
            },
            &mut ctx,
        );
        assert!(state.contains(&th.infohash));
        (th, mock.calls())
    }

    #[test]
    fn a_torrent_whose_profile_is_fenced_before_its_add_alert_lands_is_paused() {
        use crate::mock::RecordedCall;

        let (th, calls) = add_then_handle_alert(true);
        assert!(
            calls
                .iter()
                .any(|c| matches!(c, RecordedCall::PauseTorrent(h) if *h == th)),
            "the fence missed it, so the add handler must pause it: {calls:?}",
        );
    }

    #[test]
    fn a_torrent_added_to_an_unfenced_profile_is_not_paused() {
        use crate::mock::RecordedCall;

        let (_, calls) = add_then_handle_alert(false);
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, RecordedCall::PauseTorrent(_))),
            "{calls:?}",
        );
    }
}
