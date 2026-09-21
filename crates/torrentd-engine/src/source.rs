//! `AlertSource` — the seam between single-session and multi-profile mode.
//!
//! The alert loop and handlers always see `(profile_id, alert)` pairs and
//! resolve their target engine via `AlertSource::engine_for(profile)`. The
//! single-session impl reports a single profile, `ProfileId::DEFAULT`. The
//! multi-profile impl iterates a `Vec<(ProfileId, Arc<dyn TorrentEngine>)>` and
//! drains each in turn. Handler logic is identical in both modes.

use std::sync::Arc;

use libtorrent_safe::Alert;

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

/// Single-session adapter — wraps one engine and reports a single profile
/// (`ProfileId::DEFAULT`).
#[derive(Debug)]
pub struct SingleSessionSource {
    engine: Arc<dyn TorrentEngine>,
}

impl SingleSessionSource {
    pub fn new(engine: Arc<dyn TorrentEngine>) -> Self {
        Self { engine }
    }
}

impl AlertSource for SingleSessionSource {
    fn drain(&self) -> Vec<(ProfileId, Alert)> {
        let profile = ProfileId::default_single();
        self.engine
            .pop_alerts()
            .into_iter()
            .map(move |a| (profile.clone(), a))
            .collect()
    }

    fn profiles(&self) -> Vec<ProfileId> {
        vec![ProfileId::default_single()]
    }

    fn engine_for(&self, profile: &ProfileId) -> Option<Arc<dyn TorrentEngine>> {
        if profile.is_default() {
            Some(self.engine.clone())
        } else {
            None
        }
    }
}

/// Multi-profile adapter. Each entry is `(ProfileId, engine)` and `drain`
/// iterates them in declaration order.
#[derive(Debug)]
pub struct ProfileSource {
    entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)>,
}

impl ProfileSource {
    pub fn new(entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)>) -> Self {
        Self { entries }
    }
}

impl AlertSource for ProfileSource {
    fn drain(&self) -> Vec<(ProfileId, Alert)> {
        let mut out = Vec::new();
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
    fn single_session_tags_default_profile() {
        let eng = Arc::new(MockEngine::new());
        eng.push_alert(finished(7));
        let src = SingleSessionSource::new(eng);
        let drained = src.drain();
        assert_eq!(drained.len(), 1);
        assert!(drained[0].0.is_default());
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
