//! Pacing for the bulk operations that make a profile's torrents announce.
//!
//! The reannounce after a port forward rebinds a session
//! (`port_forward_monitor`), and every bulk resume (`vpn_monitor`'s fence
//! lift, the profile online endpoint), hand their torrents to the session a
//! batch at a time through one [`Pacer`] each.

use std::time::Duration;

use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentHandle;

/// How many torrents a bulk operation that makes them announce hands to the
/// session at once: the reannounce after a port change, and every bulk
/// resume (see [`Pacer`]).
///
/// A rebind used to reannounce every torrent in the profile in one burst. At
/// the scale this daemon runs — tens of thousands of torrents per session —
/// that is tens of thousands of announces handed to the session in the same
/// instant, which the trackers see as a flood from one address and which
/// queues behind `max_concurrent_http_announces` anyway. Each of those
/// announces also raises a tracker alert, and a burst of them overflows the
/// session's alert queue. Paced at `REANNOUNCE_BATCH` per
/// [`REANNOUNCE_PACE`], 10 000 torrents are all reannounced within 100
/// seconds, and a tracker never sees more than a batch at once.
pub const REANNOUNCE_BATCH: usize = 100;

/// The pause between two batches of [`REANNOUNCE_BATCH`].
pub const REANNOUNCE_PACE: Duration = Duration::from_secs(1);

/// Splits a bulk operation over `len` torrents into batches of
/// [`REANNOUNCE_BATCH`], handed out `pace` apart, the first at once.
///
/// The one pacer every bulk operation that makes the sessions announce goes
/// through, so that none of them hands a session a profile's worth of
/// announces in one instant. [`Pacer::next_batch`] sleeps on the runtime's
/// timer, so a paced operation holds no thread while it waits; what each
/// batch does, and on which thread, is the caller's. Each pacer paces only
/// its own operation: two over the same profile at once announce at twice
/// the rate.
#[derive(Debug)]
pub struct Pacer {
    len: usize,
    next: usize,
    pace: Duration,
}

impl Pacer {
    pub fn new(len: usize, pace: Duration) -> Self {
        Self { len, next: 0, pace }
    }

    /// The indices of the next batch, once `pace` has passed since the last
    /// one was handed out; `None` once all `len` have been.
    pub async fn next_batch(&mut self) -> Option<std::ops::Range<usize>> {
        if self.next >= self.len {
            return None;
        }
        if self.next > 0 {
            tokio::time::sleep(self.pace).await;
        }
        let batch = self.next..self.len.min(self.next + REANNOUNCE_BATCH);
        self.next = batch.end;
        Some(batch)
    }
}

/// Ask each torrent in `handles` to reannounce, and count what the session
/// accepted and refused. One batch of the paced reannounce; the pacing is the
/// caller's, since it has to sleep without holding a thread.
pub fn reannounce_batch(engine: &dyn TorrentEngine, handles: &[TorrentHandle]) -> (usize, usize) {
    let mut dispatched = 0;
    let mut failed = 0;
    for h in handles {
        match engine.force_reannounce(*h) {
            Ok(()) => dispatched += 1,
            Err(_) => failed += 1,
        }
    }
    (dispatched, failed)
}

#[cfg(test)]
mod tests {
    use torrentd_engine::EngineError;
    use torrentd_engine::InfoHash;
    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;

    use super::*;

    fn reannounced(eng: &MockEngine) -> Vec<TorrentHandle> {
        eng.calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::ForceReannounce(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_refused_reannounce_is_counted_and_the_rest_of_the_batch_still_goes_out() {
        let eng = MockEngine::new();
        let a = eng.register_handle(InfoHash([1; 20]));
        let b = eng.register_handle(InfoHash([2; 20]));
        // One-shot: the first reannounce is refused, the second is not.
        eng.inject_error("force_reannounce", EngineError::Shutdown);
        assert_eq!(reannounce_batch(&eng, &[a, b]), (1, 1));
        assert_eq!(reannounced(&eng), vec![a, b]);
    }

    /// The pace the batch constants set is the one the docs state: 10 000
    /// torrents within 100 seconds, never more than a batch at once.
    #[test]
    fn the_reannounce_pace_clears_ten_thousand_torrents_within_a_hundred_seconds() {
        let batches = 10_000usize.div_ceil(REANNOUNCE_BATCH);
        assert!(REANNOUNCE_PACE * (batches as u32 - 1) <= Duration::from_secs(100));
    }

    /// The pacer hands out a batch at once and each next one only a pace
    /// later, until every torrent has been handed out.
    #[tokio::test(start_paused = true)]
    async fn the_pacer_hands_out_a_batch_per_pace() {
        let len = 2 * REANNOUNCE_BATCH + 1;
        let start = tokio::time::Instant::now();
        let mut pacer = Pacer::new(len, REANNOUNCE_PACE);
        let mut seen = Vec::new();
        while let Some(batch) = pacer.next_batch().await {
            seen.push((start.elapsed(), batch));
        }
        assert_eq!(
            seen,
            [
                (Duration::ZERO, 0..REANNOUNCE_BATCH),
                (REANNOUNCE_PACE, REANNOUNCE_BATCH..2 * REANNOUNCE_BATCH),
                (2 * REANNOUNCE_PACE, 2 * REANNOUNCE_BATCH..len),
            ],
        );
        assert_eq!(
            start.elapsed(),
            2 * REANNOUNCE_PACE,
            "no wait after the last"
        );
        assert_eq!(Pacer::new(0, REANNOUNCE_PACE).next_batch().await, None);
    }
}
