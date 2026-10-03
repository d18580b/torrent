//! `AlertsDropped` handler: if libtorrent's alert queue overflowed, count
//! the overflow and log how many alert types were lost. Indicates the alert
//! loop is falling behind.
//!
//! When the lost types include the resume-data answers, every save in flight
//! is asked for again: libtorrent reports which *types* it dropped and never
//! which torrents, so any of them may be one whose answer is gone, and a save
//! nobody answers holds the shutdown drain open until its deadline.

use libtorrent_safe::Alert;
use libtorrent_safe::ResumeFlags;
use tracing::warn;

use crate::handlers::HandlerCtx;

/// `save_resume_data_alert::alert_type` and
/// `save_resume_data_failed_alert::alert_type` in libtorrent 2.0
/// (`include/libtorrent/alert_types.hpp`). The shim copies libtorrent's
/// `dropped_alerts` bitset bit for bit, so bit *n* of the pair is alert type
/// *n*.
const SAVE_RESUME_DATA_TYPE: u32 = 37;
const SAVE_RESUME_DATA_FAILED_TYPE: u32 = 38;

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;

    use super::*;
    use crate::clock::MockClock;
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
