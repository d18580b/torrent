//! `AlertsDropped` handler: if libtorrent's alert queue overflowed, count
//! the overflow and log how many alert types were lost. Indicates the alert
//! loop is falling behind.
//!
//! When the lost types include the resume-data answers, every save in flight
//! is asked for again: libtorrent reports which *types* it dropped and never
//! which torrents, so any of them may be one whose answer is gone, and a save
//! nobody answers holds the shutdown drain open until its deadline.
//!
//! When they include `add_torrent_alert`, the session's torrents are compared
//! against the state map and every one it is missing is tracked, since the
//! map learns of a torrent from that alert.

use libtorrent_safe::Alert;
use libtorrent_safe::ResumeFlags;
use tracing::error;
use tracing::warn;

use crate::handlers::add;
use crate::handlers::HandlerCtx;

/// `save_resume_data_alert::alert_type` and
/// `save_resume_data_failed_alert::alert_type` in libtorrent 2.0
/// (`include/libtorrent/alert_types.hpp`). The shim copies libtorrent's
/// `dropped_alerts` bitset bit for bit, so bit *n* of the pair is alert type
/// *n*.
const SAVE_RESUME_DATA_TYPE: u32 = 37;
const SAVE_RESUME_DATA_FAILED_TYPE: u32 = 38;
/// `add_torrent_alert::alert_type` in libtorrent 2.0.
const ADD_TORRENT_TYPE: u32 = 67;

/// Whether alert type `ty` is set in a `dropped_alerts` bitset.
fn dropped(bits: &[u64; 2], ty: u32) -> bool {
    let (word, bit) = ((ty / 64) as usize, ty % 64);
    bits.get(word).is_some_and(|w| w & (1u64 << bit) != 0)
}

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    let Alert::AlertsDropped { bits, .. } = alert else {
        unreachable!("dropped::handle called with non-dropped alert");
    };
    let _enter = ctx.span.enter();
    let total = bits[0].count_ones() + bits[1].count_ones();
    warn!(
        target: "torrentd_engine::handler::dropped",
        bits_lo = bits[0],
        bits_hi = bits[1],
        kinds = total,
        "libtorrent alert queue overflowed; alerts dropped",
    );
    if dropped(bits, SAVE_RESUME_DATA_TYPE) || dropped(bits, SAVE_RESUME_DATA_FAILED_TYPE) {
        // Without `ONLY_IF_MODIFIED`: producing the lost answer cleared
        // libtorrent's modified bit, so asking conditionally would be told
        // "not modified" about data that was never written.
        let requeued = ctx
            .state
            .requeue_in_flight_resume_saves(ResumeFlags::empty());
        warn!(
            target: "torrentd_engine::handler::dropped",
            torrent_count = requeued,
            "resume-data answers were among the dropped alerts; asking again for every save in \
             flight",
        );
        // Under the profile whose queue overflowed, like every other counter
        // this loop emits: that is the session falling behind.
        ctx.metrics.add_counter(
            "resume_saves_requeued_total",
            requeued as u64,
            &[("profile_id", ctx.profile_id.as_str())],
        );
    }
    if dropped(bits, ADD_TORRENT_TYPE) {
        reconcile_session(ctx);
    }
    // One per overflow. libtorrent reports *which alert types* it dropped, as
    // a bitset, and never how many alerts; this used to add the bitset's
    // popcount to `alerts_dropped_total`, which is a count of neither. The
    // number of overflow events is what the alert can honestly rest on, and
    // the series is named for that.
    ctx.metrics.inc_counter(
        "alert_queue_overflows_total",
        &[("profile_id", ctx.profile_id.as_str())],
    );
}

/// Track every torrent the session holds that the state map does not, for an
/// overflow that dropped `add_torrent_alert`s.
///
/// A torrent enters the map from its add alert, so one whose alert was lost
/// would seed with nothing tracking it: no fence pauses it, no sweep or drain
/// saves it, and `DELETE` refuses it. libtorrent names the lost type and never
/// the torrents, so the whole session is compared against the map, and each
/// torrent missing from it gets what its alert would have given it
/// (`add::track`). An add alert that was not lost and is still queued finds
/// its torrent tracked and keeps the entry.
fn reconcile_session(ctx: &HandlerCtx<'_>) {
    let held = match ctx.engine.torrents() {
        Ok(held) => held,
        Err(e) => {
            error!(
                target: "torrentd_engine::handler::dropped",
                op = "torrents",
                error.cause = %e,
                "add-torrent alerts were dropped and the session's torrents could not be listed; \
                 torrents whose alert was lost stay untracked",
            );
            return;
        }
    };
    let mut recovered = 0u64;
    for h in held {
        // Only the missing: a tracked torrent's add was handled, or seeded by
        // the boot scan, and re-asking its save and hold for every torrent in
        // a 100K session would cost a store lookup each.
        let tracked = ctx
            .state
            .get(&h.infohash)
            .is_some_and(|st| st.handle == h && st.profile_id == ctx.profile_id);
        if !tracked && add::track(h, ctx) {
            recovered += 1;
        }
    }
    warn!(
        target: "torrentd_engine::handler::dropped",
        torrent_count = recovered,
        "add-torrent alerts were among the dropped alerts; tracked the session's torrents the \
         state map was missing",
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;

    use super::*;
    use crate::clock::MockClock;
    use crate::engine::EngineError;
    use crate::engine::TorrentEngine;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::state::StateMap;
    use crate::torrent_store::MemoryTorrentStore;

    fn overflow(bits: [u64; 2]) -> Alert {
        Alert::AlertsDropped {
            hdr: AlertHeader {
                kind: AlertKind::AlertsDropped,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            bits,
        }
    }

    fn run(state: &StateMap, metrics: &RecordingSink, bits: [u64; 2]) {
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
        handle(&overflow(bits), &mut ctx);
    }

    fn in_flight(state: &StateMap, n: u8) {
        for b in 0..n {
            state.queue_resume_save(InfoHash([b; 20]), ResumeFlags::ONLY_IF_MODIFIED);
        }
        state.dispatch_resume_saves(usize::MAX);
    }

    #[test]
    fn a_dropped_resume_answer_puts_every_save_in_flight_back_on_the_queue() {
        for ty in [SAVE_RESUME_DATA_TYPE, SAVE_RESUME_DATA_FAILED_TYPE] {
            let state = StateMap::new();
            let metrics = RecordingSink::new();
            in_flight(&state, 3);
            run(&state, &metrics, [1u64 << ty, 0]);
            assert_eq!(state.resume_saves_in_flight(), 0, "type {ty}");
            assert_eq!(state.pending_resume_count(), 3, "none forgotten");
            // Asked again unconditionally: the lost answer cleared
            // libtorrent's modified bit.
            let again = state.dispatch_resume_saves(usize::MAX);
            assert!(again.iter().all(|(_, f)| f.is_empty()));
            // Counted, under the profile whose queue overflowed.
            let requeued: Vec<_> = metrics
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    crate::metrics::MetricCall::AddCounter {
                        name,
                        value,
                        labels,
                    } if name == "resume_saves_requeued_total" => Some((value, labels)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                requeued,
                vec![(3, vec![("profile_id".to_string(), "p".to_string())])],
                "type {ty}",
            );
        }
    }

    #[test]
    fn an_overflow_that_spared_the_resume_answers_leaves_saves_in_flight() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        in_flight(&state, 3);
        // Every other type set, both words.
        let mut bits = [u64::MAX, u64::MAX];
        bits[0] &= !(1u64 << SAVE_RESUME_DATA_TYPE);
        bits[0] &= !(1u64 << SAVE_RESUME_DATA_FAILED_TYPE);
        run(&state, &metrics, bits);
        assert_eq!(state.resume_saves_in_flight(), 3);
        assert_eq!(metrics.count_for("resume_saves_requeued_total"), 0);
    }

    /// Handle an overflow with `bits` against `engine`, in profile `p`.
    fn run_on(
        engine: Arc<dyn TorrentEngine>,
        state: &StateMap,
        metrics: &RecordingSink,
        bits: [u64; 2],
    ) {
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
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
        handle(&overflow(bits), &mut ctx);
    }

    const ADD_DROPPED: [u64; 2] = [0, 1u64 << (ADD_TORRENT_TYPE - 64)];

    #[test]
    fn dropped_add_alerts_track_every_torrent_the_session_holds_and_the_map_lacks() {
        use crate::state::TorrentPhase;

        let mock = Arc::new(MockEngine::new());
        let (a, b, c) = (
            mock.register_handle(InfoHash([1; 20])),
            mock.register_handle(InfoHash([2; 20])),
            mock.register_handle(InfoHash([3; 20])),
        );
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let p = ProfileId::new("p");
        // `a`'s alert was handled, and its entry has moved on since.
        assert!(state.track_added(a, &p, std::time::Instant::now()));
        state.update(&a.infohash, |st| st.phase = TorrentPhase::Seeding);

        run_on(mock.clone(), &state, &metrics, ADD_DROPPED);

        for h in [a, b, c] {
            let st = state.get(&h.infohash).expect("tracked");
            assert_eq!((st.handle, &st.profile_id), (h, &p));
        }
        assert_eq!(state.get(&a.infohash).unwrap().phase, TorrentPhase::Seeding);
        assert_eq!(state.handles_for_profile(&p).len(), 3, "all fenceable");
        // The recovered ones get the first save their alert would have queued.
        let mut saved: Vec<_> = state
            .dispatch_resume_saves(usize::MAX)
            .into_iter()
            .map(|(ih, _)| ih)
            .collect();
        saved.sort_by_key(|ih| ih.0);
        assert_eq!(saved, vec![b.infohash, c.infohash]);
    }

    #[test]
    fn an_overflow_that_spared_the_add_alerts_does_not_list_the_session() {
        let mock = Arc::new(MockEngine::new());
        let h = mock.register_handle(InfoHash([4; 20]));
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let mut bits = [u64::MAX, u64::MAX];
        bits[1] &= !ADD_DROPPED[1];
        run_on(mock, &state, &metrics, bits);
        assert!(!state.contains(&h.infohash));
    }

    #[test]
    fn a_session_that_cannot_be_listed_leaves_the_map_as_it_was() {
        let mock = Arc::new(MockEngine::new());
        let h = mock.register_handle(InfoHash([5; 20]));
        mock.inject_error("torrents", EngineError::Shutdown);
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        run_on(mock, &state, &metrics, ADD_DROPPED);
        assert!(!state.contains(&h.infohash));
        // The overflow is still counted.
        assert_eq!(metrics.count_for("alert_queue_overflows_total"), 1);
    }

    #[test]
    fn one_overflow_counts_once_however_many_types_it_dropped() {
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = RecordingSink::new();
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
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        let alert = Alert::AlertsDropped {
            hdr: AlertHeader {
                kind: AlertKind::AlertsDropped,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            bits: [0b1011, 1],
        };
        handle(&alert, &mut ctx);
        assert_eq!(metrics.count_for("alert_queue_overflows_total"), 1);
        assert_eq!(metrics.count_for("alerts_dropped_total"), 0);
    }
}
