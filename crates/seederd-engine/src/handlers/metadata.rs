//! `MetadataReceived` handler.
//!
//! Magnet adds arrive without a `.torrent` file; once libtorrent fetches the
//! metadata we persist it so the startup inventory scan can re-add the torrent
//! if its resume file is ever lost (PRD §6 / §Session Management).

use libtorrent_safe::Alert;
use tracing::debug;
use tracing::warn;

use crate::handlers::HandlerCtx;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    let Alert::MetadataReceived { hdr, info_section } = alert else {
        unreachable!("metadata::handle called with non-metadata alert");
    };
    let _enter = ctx.span.enter();
    let Some(ih) = hdr.infohash else { return };
    if info_section.is_empty() {
        return;
    }

    // Wrap the bencoded info dictionary as a minimal `.torrent`:
    //   d 4:info <info-dict> e   ==   { "info": <dict> }
    // libtorrent's torrent_info parser accepts this for a later startup-scan
    // re-add. Trackers from the magnet are not preserved here — they ride in
    // the resume data, which is the normal re-add path; the `.torrent` is the
    // resume-lost fallback.
    let mut torrent = Vec::with_capacity(info_section.len() + 8);
    torrent.extend_from_slice(b"d4:info");
    torrent.extend_from_slice(info_section);
    torrent.push(b'e');

    match ctx.torrents.write(&ctx.slot_id, &ih, &torrent) {
        Ok(()) => debug!(
            target: "seederd_engine::handler::metadata",
            infohash = %ih,
            bytes = torrent.len(),
            "persisted magnet metadata as .torrent",
        ),
        Err(e) => warn!(
            target: "seederd_engine::handler::metadata",
            infohash = %ih,
            error.kind = "torrent_write",
            error.cause = %e,
            "failed to persist magnet metadata",
        ),
    }
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
    use crate::metrics::NoopSink;
    use crate::mock::MockEngine;
    use crate::resume_store::MemoryResumeStore;
    use crate::slot::SlotId;
    use crate::state::StateMap;
    use crate::torrent_store::MemoryTorrentStore;
    use crate::torrent_store::TorrentStore;

    #[test]
    fn persists_wrapped_info_dict_as_torrent() {
        let ih = InfoHash([0x55; 20]);
        let info = b"d6:lengthi5ee".to_vec(); // stand-in bencoded info dict
        let alert = Alert::MetadataReceived {
            hdr: AlertHeader {
                kind: AlertKind::MetadataReceived,
                infohash: Some(ih),
                handle: None,
                timestamp_us: 0,
            },
            info_section: info.clone(),
        };
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
            slot_id: SlotId::default_single(),
            span: tracing::info_span!("test"),
        };

        handle(&alert, &mut ctx);

        let saved = torrents.load_all(&SlotId::default_single()).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].0, ih);
        // Wrapped as a minimal `.torrent`: { "info": <info_section> }.
        let mut expected = b"d4:info".to_vec();
        expected.extend_from_slice(&info);
        expected.push(b'e');
        assert_eq!(saved[0].1, expected);
    }
}
