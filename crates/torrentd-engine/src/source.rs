//! `AlertSource` — the seam between the alert loop and the per-profile engines.
//!
//! The alert loop and handlers always see `(profile_id, alert)` pairs and
//! resolve their target engine via `AlertSource::engine_for(profile)`.
//! `ProfileSource` iterates a `Vec<(ProfileId, Arc<dyn TorrentEngine>)>` and
//! drains each in turn. There is one implementation and one shape: a daemon
//! with a single profile is that vector with one entry, and handler logic does
//! not branch on how many there are.

use std::collections::VecDeque;
use std::sync::Arc;

use libtorrent_safe::Alert;
use parking_lot::Mutex;

use crate::engine::TorrentEngine;
use crate::profile::ProfileId;
use crate::real::MAX_ALERTS_PER_POP;

pub trait AlertSource: Send + Sync + std::fmt::Debug {
    /// Drain all queued alerts from every engine in this source.
    /// `(profile_id, alert)` pairs preserve provenance so handlers can route
    /// to the correct profile's resume store, retry timer, etc.
    fn drain(&self) -> Vec<(ProfileId, Alert)>;

    /// All profiles represented by this source. Stable ordering for
    /// predictable alert poll iteration.
    fn profiles(&self) -> Vec<ProfileId>;

    /// Engine for a profile, or `None` if the source doesn't know the profile
    /// (handler logged and continued).
    fn engine_for(&self, profile: &ProfileId) -> Option<Arc<dyn TorrentEngine>>;

    /// Convenience: trigger `post_torrent_updates` on every engine. Used
    /// by the alert-loop's 1-second tick.
    fn post_updates_all(&self) {
        for profile in self.profiles() {
            if let Some(eng) = self.engine_for(&profile) {
                eng.post_updates();
            }
        }
    }

    /// Convenience: trigger `post_session_stats` on every engine. Used by
    /// the alert-loop's 30-second tick.
    fn post_stats_all(&self) {
        for profile in self.profiles() {
            if let Some(eng) = self.engine_for(&profile) {
                eng.post_stats();
            }
        }
    }
}

/// The alert source. One entry per configured profile, `(ProfileId, engine)`;
/// `drain` iterates them in declaration order.
///
/// There is exactly one implementation because there is exactly one shape: a
/// daemon runs one session per configured profile, and a deployment with one
/// profile is that with n = 1 rather than a mode of its own.
#[derive(Debug)]
pub struct ProfileSource {
    entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)>,
    held: Mutex<Held>,
}

/// Alerts [`ProfileSource::hold_alerts`] took off a session before the alert
/// loop ran. `drain` hands them out a bounded batch at a time, ahead of
/// anything their own session posted since.
#[derive(Debug)]
struct Held {
    /// Oldest first, each tagged with its profile's index in `entries`.
    queue: VecDeque<(usize, Alert)>,
    /// How many of `queue`'s alerts each entry has, by the same index, so a
    /// drain learns which profiles still hold alerts without walking `queue`.
    counts: Vec<usize>,
}

impl ProfileSource {
    pub fn new(entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)>) -> Self {
        let held = Held {
            queue: VecDeque::new(),
            counts: vec![0; entries.len()],
        };
        Self {
            entries,
            held: Mutex::new(held),
        }
    }

    /// Pop every alert `profile`'s session has queued and hold it for the
    /// following [`AlertSource::drain`]s. Returns how many were taken.
    ///
    /// For the boot scans, which add every torrent before the alert loop
    /// starts. libtorrent's alert queue is bounded and drops what overflows
    /// it, `add_torrent_alert`s included, and a torrent whose add alert is
    /// lost is one the state map never learns of. Popping between scan
    /// batches keeps the queue from filling; holding what was popped, rather
    /// than handling it, leaves every alert for the loop to dispatch in the
    /// order the session posted it.
    pub fn hold_alerts(&self, profile: &ProfileId) -> usize {
        let Some(idx) = self.entries.iter().position(|(p, _)| p == profile) else {
            return 0;
        };
        let engine = &self.entries[idx].1;
        let mut held = self.held.lock();
        let before = held.queue.len();
        loop {
            let popped = engine.pop_alerts();
            if popped.is_empty() {
                break;
            }
            held.queue.extend(popped.into_iter().map(|a| (idx, a)));
        }
        let taken = held.queue.len() - before;
        held.counts[idx] += taken;
        taken
    }
}

impl AlertSource for ProfileSource {
    /// Held alerts come out at most [`MAX_ALERTS_PER_POP`] a call, oldest
    /// first, as a session's own pop does: a boot holds one or more alerts
    /// per loaded torrent, and handing them all to one alert-loop iteration
    /// would stall its heartbeat and shutdown probe in proportion to the pool.
    /// The loop drains again at once while a drain comes back non-empty, so
    /// this costs no throughput.
    ///
    /// A profile with alerts still held is not popped, so nothing its session
    /// posted since overtakes them; the other profiles are popped as usual.
    /// Which profiles still hold alerts comes from a per-profile count, so a
    /// drain costs its batch and the profile count, not the held queue's
    /// length.
    fn drain(&self) -> Vec<(ProfileId, Alert)> {
        let (mut out, still_held) = {
            let mut held = self.held.lock();
            let Held { queue, counts } = &mut *held;
            let n = queue.len().min(MAX_ALERTS_PER_POP);
            let batch: Vec<_> = queue
                .drain(..n)
                .map(|(idx, a)| {
                    counts[idx] -= 1;
                    (self.entries[idx].0.clone(), a)
                })
                .collect();
            let still_held: Vec<bool> = counts.iter().map(|&c| c > 0).collect();
            (batch, still_held)
        };
        for ((profile, engine), &is_held) in self.entries.iter().zip(&still_held) {
            if is_held {
                continue;
            }
            for a in engine.pop_alerts() {
                out.push((profile.clone(), a));
            }
        }
        out
    }

    fn profiles(&self) -> Vec<ProfileId> {
        self.entries.iter().map(|(s, _)| s.clone()).collect()
    }

    fn engine_for(&self, profile: &ProfileId) -> Option<Arc<dyn TorrentEngine>> {
        self.entries
            .iter()
            .find(|(s, _)| s == profile)
            .map(|(_, e)| e.clone())
    }
}

#[cfg(test)]
mod tests {
    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;

    use super::*;
    use crate::mock::MockEngine;

    fn finished(byte: u8) -> Alert {
        Alert::TorrentFinished {
            hdr: AlertHeader {
                kind: AlertKind::TorrentFinished,
                infohash: Some(InfoHash([byte; 20])),
                handle: None,
                timestamp_us: 0,
            },
        }
    }

    #[test]
    fn one_profile_is_just_n_equals_one() {
        let eng = Arc::new(MockEngine::new());
        eng.push_alert(finished(7));
        let src = ProfileSource::new(vec![(
            ProfileId::new("public"),
            eng as Arc<dyn TorrentEngine>,
        )]);
        let drained = src.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0.as_str(), "public");
    }

    /// Adds that would overflow the queue several times over, popped between
    /// batches as the boot scans do: none is dropped, and the next drain
    /// hands them out first, in order, ahead of what was queued since.
    #[test]
    fn held_alerts_survive_adds_that_would_overflow_the_queue() {
        use libtorrent_safe::AddParams;
        use libtorrent_safe::TorrentFlags;

        let eng = Arc::new(
            MockEngine::new()
                .with_alert_capacity(10)
                .with_add_alerts(true),
        );
        let p = ProfileId::new("p");
        let src = ProfileSource::new(vec![(p.clone(), eng.clone() as Arc<dyn TorrentEngine>)]);
        let mut added = Vec::new();
        for n in 0..40u8 {
            if n % 8 == 0 {
                src.hold_alerts(&p);
            }
            let h = eng
                .add_torrent(AddParams::File {
                    bytes: vec![n + 1; 20],
                    save_path: "/data".into(),
                    flags: TorrentFlags::empty(),
                    trackers: Vec::new(),
                })
                .unwrap();
            added.push(h);
        }
        assert_eq!(src.hold_alerts(&p), 8);
        assert_eq!(src.hold_alerts(&ProfileId::new("unknown")), 0);
        eng.push_alert(finished(0xEE));

        let drained = src.drain();
        let handles: Vec<_> = drained
            .iter()
            .filter_map(|(_, a)| match a {
                Alert::AddTorrent { hdr, .. } => hdr.handle,
                _ => None,
            })
            .collect();
        assert_eq!(handles, added, "every add alert, in order");
        assert!(matches!(
            drained.last(),
            Some((_, Alert::TorrentFinished { .. }))
        ));
        assert!(!drained
            .iter()
            .any(|(_, a)| matches!(a, Alert::AlertsDropped { .. })));
        assert!(src.drain().is_empty(), "held alerts are handed out once");
    }

    /// A boot's held alerts outnumber one pop many times over: each drain
    /// hands out at most `MAX_ALERTS_PER_POP` of them, so one alert-loop
    /// iteration never dispatches the whole pool's. The profile they came from
    /// is not popped until they are all out, so nothing it posted since
    /// overtakes them; another profile is popped as usual meanwhile.
    #[test]
    fn held_alerts_come_out_in_bounded_batches() {
        fn numbered(n: i64) -> Alert {
            Alert::TorrentFinished {
                hdr: AlertHeader {
                    kind: AlertKind::TorrentFinished,
                    infohash: Some(InfoHash([1; 20])),
                    handle: None,
                    timestamp_us: n,
                },
            }
        }
        let stamp = |(_, a): &(ProfileId, Alert)| match a {
            Alert::TorrentFinished { hdr } => hdr.timestamp_us,
            _ => unreachable!(),
        };

        const HELD: i64 = 2 * MAX_ALERTS_PER_POP as i64 + 100;
        let (a, b) = (Arc::new(MockEngine::new()), Arc::new(MockEngine::new()));
        let (pa, pb) = (ProfileId::new("a"), ProfileId::new("b"));
        let src = ProfileSource::new(vec![
            (pa.clone(), a.clone() as Arc<dyn TorrentEngine>),
            (pb.clone(), b.clone() as Arc<dyn TorrentEngine>),
        ]);
        a.push_alerts((0..HELD).map(numbered));
        assert_eq!(src.hold_alerts(&pa), HELD as usize);
        a.push_alert(numbered(HELD));
        b.push_alert(numbered(i64::MAX));

        let first = src.drain();
        assert_eq!(first.len(), MAX_ALERTS_PER_POP + 1);
        assert!(first[..MAX_ALERTS_PER_POP].iter().all(|(p, _)| *p == pa));
        assert_eq!(first.last().map(stamp), Some(i64::MAX), "b is popped");
        assert_eq!(first.last().map(|(p, _)| p), Some(&pb));

        let second = src.drain();
        assert_eq!(second.len(), MAX_ALERTS_PER_POP, "a is still not popped");
        let third = src.drain();
        assert_eq!(third.len(), 100 + 1, "the rest, then what a posted since");
        assert!(src.drain().is_empty());

        let from_a: Vec<i64> = first[..MAX_ALERTS_PER_POP]
            .iter()
            .chain(&second)
            .chain(&third)
            .map(stamp)
            .collect();
        assert_eq!(from_a, (0..=HELD).collect::<Vec<_>>(), "in posted order");
    }

    /// Two profiles hold alerts, and one batch empties the first one's and
    /// cuts into the second one's: the first is popped again from that very
    /// drain, the second only once a later drain has handed out the rest of
    /// what it held.
    #[test]
    fn a_profile_is_popped_once_its_own_held_alerts_are_out() {
        let (a, b) = (Arc::new(MockEngine::new()), Arc::new(MockEngine::new()));
        let (pa, pb) = (ProfileId::new("a"), ProfileId::new("b"));
        let src = ProfileSource::new(vec![
            (pa.clone(), a.clone() as Arc<dyn TorrentEngine>),
            (pb.clone(), b.clone() as Arc<dyn TorrentEngine>),
        ]);
        let from_a = MAX_ALERTS_PER_POP - 10;
        a.push_alerts((0..from_a).map(|_| finished(1)));
        assert_eq!(src.hold_alerts(&pa), from_a);
        b.push_alerts((0..100).map(|_| finished(2)));
        assert_eq!(src.hold_alerts(&pb), 100);
        a.push_alert(finished(0xA0));
        b.push_alert(finished(0xB0));

        let first = src.drain();
        assert_eq!(first.len(), MAX_ALERTS_PER_POP + 1, "a is popped");
        assert_eq!(first.iter().filter(|(p, _)| *p == pa).count(), from_a + 1);
        assert_eq!(first.iter().filter(|(p, _)| *p == pb).count(), 10);
        assert!(matches!(
            first.last(),
            Some((p, Alert::TorrentFinished { hdr })) if *p == pa
                && hdr.infohash == Some(InfoHash([0xA0; 20]))
        ));

        let second = src.drain();
        assert_eq!(second.len(), 90 + 1, "the rest of b's, then b is popped");
        assert!(second.iter().all(|(p, _)| *p == pb));
        assert!(matches!(
            second.last(),
            Some((_, Alert::TorrentFinished { hdr }))
                if hdr.infohash == Some(InfoHash([0xB0; 20]))
        ));
        assert!(src.drain().is_empty());
    }

    #[test]
    fn multi_profile_preserves_provenance() {
        let a: Arc<MockEngine> = Arc::new(MockEngine::new());
        let b: Arc<MockEngine> = Arc::new(MockEngine::new());
        a.push_alert(finished(1));
        b.push_alert(finished(2));
        let src = ProfileSource::new(vec![
            (
                ProfileId::new("acct_a"),
                a.clone() as Arc<dyn TorrentEngine>,
            ),
            (
                ProfileId::new("acct_b"),
                b.clone() as Arc<dyn TorrentEngine>,
            ),
        ]);
        let drained = src.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0.as_str(), "acct_a");
        assert_eq!(drained[1].0.as_str(), "acct_b");
    }
}
