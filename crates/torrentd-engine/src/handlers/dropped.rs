//! `AlertsDropped` handler: if libtorrent's alert queue overflowed, count
//! the overflow and log how many alert types were lost. Indicates the alert
//! loop is falling behind.

use libtorrent_safe::Alert;
use tracing::warn;

use crate::handlers::HandlerCtx;

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

    use super::*;
    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::state::StateMap;
    use crate::torrent_store::MemoryTorrentStore;

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
