//! `AlertSource` — the seam between single-session and multi-slot mode.
//!
//! The alert loop and handlers always see `(slot_id, alert)` pairs and
//! resolve their target engine via `AlertSource::engine_for(slot)`. The
//! single-session impl reports a single slot, `SlotId::DEFAULT`. The
//! multi-slot impl iterates a `Vec<(SlotId, Arc<dyn TorrentEngine>)>` and
//! drains each in turn. Handler logic is identical in both modes.

use std::sync::Arc;

use crate::engine::TorrentEngine;
use crate::slot::SlotId;
use libtorrent_safe::Alert;

pub trait AlertSource: Send + Sync + std::fmt::Debug {
    /// Drain all queued alerts from every engine in this source.
    /// `(slot_id, alert)` pairs preserve provenance so handlers can route
    /// to the correct slot's resume store, retry timer, etc.
    fn drain(&self) -> Vec<(SlotId, Alert)>;

    /// All slots represented by this source. Stable ordering for
    /// predictable alert poll iteration.
    fn slots(&self) -> Vec<SlotId>;

    /// Engine for a slot, or `None` if the source doesn't know the slot
    /// (handler logged and continued).
    fn engine_for(&self, slot: &SlotId) -> Option<Arc<dyn TorrentEngine>>;

    /// Convenience: trigger `post_torrent_updates` on every engine. Used
    /// by the alert-loop's 1-second tick.
    fn post_updates_all(&self) {
        for slot in self.slots() {
            if let Some(eng) = self.engine_for(&slot) {
                eng.post_updates();
            }
        }
    }

    /// Convenience: trigger `post_session_stats` on every engine. Used by
    /// the alert-loop's 30-second tick.
    fn post_stats_all(&self) {
        for slot in self.slots() {
            if let Some(eng) = self.engine_for(&slot) {
                eng.post_stats();
            }
        }
    }
}

/// Single-session adapter — wraps one engine and reports a single slot
/// (`SlotId::DEFAULT`).
#[derive(Debug)]
pub struct SingleSessionSource {
    engine: Arc<dyn TorrentEngine>,
}

impl SingleSessionSource {
    pub fn new(engine: Arc<dyn TorrentEngine>) -> Self { Self { engine } }
}

impl AlertSource for SingleSessionSource {
    fn drain(&self) -> Vec<(SlotId, Alert)> {
        let slot = SlotId::default_single();
        self.engine
            .pop_alerts()
            .into_iter()
            .map(move |a| (slot.clone(), a))
            .collect()
    }

    fn slots(&self) -> Vec<SlotId> { vec![SlotId::default_single()] }

    fn engine_for(&self, slot: &SlotId) -> Option<Arc<dyn TorrentEngine>> {
        if slot.is_default() { Some(self.engine.clone()) } else { None }
    }
}

/// Multi-slot adapter. Each entry is `(SlotId, engine)` and `drain`
/// iterates them in declaration order.
#[derive(Debug)]
pub struct MultiSlotSource {
    entries: Vec<(SlotId, Arc<dyn TorrentEngine>)>,
}

impl MultiSlotSource {
    pub fn new(entries: Vec<(SlotId, Arc<dyn TorrentEngine>)>) -> Self {
        Self { entries }
    }
}

impl AlertSource for MultiSlotSource {
    fn drain(&self) -> Vec<(SlotId, Alert)> {
        let mut out = Vec::new();
        for (slot, engine) in &self.entries {
            for a in engine.pop_alerts() { out.push((slot.clone(), a)); }
        }
        out
    }

    fn slots(&self) -> Vec<SlotId> {
        self.entries.iter().map(|(s, _)| s.clone()).collect()
    }

    fn engine_for(&self, slot: &SlotId) -> Option<Arc<dyn TorrentEngine>> {
        self.entries.iter().find(|(s, _)| s == slot).map(|(_, e)| e.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockEngine;
    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::{AlertKind, InfoHash};

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
    fn single_session_tags_default_slot() {
        let eng = Arc::new(MockEngine::new());
        eng.push_alert(finished(7));
        let src = SingleSessionSource::new(eng);
        let drained = src.drain();
        assert_eq!(drained.len(), 1);
        assert!(drained[0].0.is_default());
    }

    #[test]
    fn multi_slot_preserves_provenance() {
        let a: Arc<MockEngine> = Arc::new(MockEngine::new());
        let b: Arc<MockEngine> = Arc::new(MockEngine::new());
        a.push_alert(finished(1));
        b.push_alert(finished(2));
        let src = MultiSlotSource::new(vec![
            (SlotId::new("acct_a"), a.clone() as Arc<dyn TorrentEngine>),
            (SlotId::new("acct_b"), b.clone() as Arc<dyn TorrentEngine>),
        ]);
        let drained = src.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0.as_str(), "acct_a");
        assert_eq!(drained[1].0.as_str(), "acct_b");
    }
}
