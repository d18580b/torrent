//! `AlertSource` — the seam between the alert loop and the per-profile engines.
//!
//! The alert loop and handlers always see `(profile_id, alert)` pairs and
//! resolve their target engine via `AlertSource::engine_for(profile)`.
//! `ProfileSource` iterates a `Vec<(ProfileId, Arc<dyn TorrentEngine>)>` and
//! drains each in turn. There is one implementation and one shape: a daemon
//! with a single profile is that vector with one entry, and handler logic does
//! not branch on how many there are.

use std::sync::Arc;

use libtorrent_safe::Alert;
use parking_lot::Mutex;

use crate::engine::TorrentEngine;
use crate::profile::ProfileId;

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
    /// Alerts [`ProfileSource::hold_alerts`] took off a session before the
    /// alert loop ran, oldest first. The next `drain` hands them out ahead of
    /// anything it pops.
    held: Mutex<Vec<(ProfileId, Alert)>>,
}

impl ProfileSource {
    pub fn new(entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)>) -> Self {
        Self {
            entries,
            held: Mutex::new(Vec::new()),
        }
    }

    /// Pop every alert `profile`'s session has queued and hold it for the
    /// next [`AlertSource::drain`]. Returns how many were taken.
    ///
    /// For the boot scans, which add every torrent before the alert loop
    /// starts. libtorrent's alert queue is bounded and drops what overflows
    /// it, `add_torrent_alert`s included, and a torrent whose add alert is
    /// lost is one the state map never learns of. Popping between scan
    /// batches keeps the queue from filling; holding what was popped, rather
    /// than handling it, leaves every alert for the loop to dispatch in the
    /// order the session posted it.
    pub fn hold_alerts(&self, profile: &ProfileId) -> usize {
        let Some(engine) = self.engine_for(profile) else {
            return 0;
        };
        let mut held = self.held.lock();
        let before = held.len();
        loop {
            let popped = engine.pop_alerts();
            if popped.is_empty() {
                break;
            }
            held.extend(popped.into_iter().map(|a| (profile.clone(), a)));
        }
        held.len() - before
    }
}

impl AlertSource for ProfileSource {
    fn drain(&self) -> Vec<(ProfileId, Alert)> {
        let mut out = std::mem::take(&mut *self.held.lock());
        for (profile, engine) in &self.entries {
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
