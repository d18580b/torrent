//! `MetadataReceived` handler.
//!
//! Magnet adds arrive without a `.torrent` file; once libtorrent fetches the
//! metadata we persist it so the startup inventory scan can re-add the torrent
//! if its resume file is ever lost.
//!
//! The metadata is also the first word on whether the torrent is private. A
//! magnet is added with DHT, PEX and LSD disabled on every profile
//! ([`crate::policy::magnet_flags`]) because that is unknown until now; when
//! the info dict shows it public, the part of that guard the profile does not
//! keep for itself (`lift`, [`crate::policy::public_magnet_lift`]) is cleared,
//! and a resume save is queued so the cleared bits outlast a restart.

use libtorrent_safe::Alert;
use libtorrent_safe::InfoHash;
use libtorrent_safe::TorrentFlags;
use libtorrent_safe::TorrentHandle;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::handlers::HandlerCtx;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>, lift: TorrentFlags) {
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

    // Batched: this runs on the alert loop, which must not wait on the disk.
    // A failure the writer meets later is counted by the store's error hook
    // under the same series.
    match ctx.torrents.write_batched(&ctx.profile_id, &ih, &torrent) {
        Ok(()) => debug!(
            target: "torrentd_engine::handler::metadata",
            infohash = %ih,
            bytes = torrent.len(),
            "persisted magnet metadata as .torrent",
        ),
        Err(e) => {
            warn!(
                target: "torrentd_engine::handler::metadata",
                infohash = %ih,
                error.kind = "torrent_write",
                error.cause = %e,
                "failed to persist magnet metadata",
            );
            // The torrent keeps seeding from resume data, so nothing else
            // notices; lose the resume file too and it is gone at the next
            // restart. `source` matches the API's own persist failure.
            ctx.metrics.inc_counter(
                "torrent_file_persist_errors_total",
                &[
                    ("profile_id", ctx.profile_id.as_str()),
                    ("source", "metadata"),
                ],
            );
        }
    }

    lift_discovery_guards(ctx, ih, hdr.handle, info_section, lift);
}

/// Clear `lift` on the magnet `ih` names when `info` shows it public, and
/// queue a resume save so the cleared bits reach its resume file.
///
/// Every doubt keeps the guard: private metadata, an info dict this cannot
/// read, a torrent with no handle, and a session that refuses the clear. The
/// cost of keeping it is peers; the cost of lifting it wrongly is a private
/// torrent's infohash and the host's address on the DHT.
fn lift_discovery_guards(
    ctx: &HandlerCtx<'_>,
    ih: InfoHash,
    handle: Option<TorrentHandle>,
    info: &[u8],
    lift: TorrentFlags,
) {
    if lift.is_empty() {
        return;
    }
    match info_is_private(info) {
        Some(false) => {}
        Some(true) => {
            debug!(
                target: "torrentd_engine::handler::metadata",
                infohash = %ih,
                "magnet metadata is private; DHT, PEX and LSD stay disabled",
            );
            return;
        }
        None => {
            warn!(
                target: "torrentd_engine::handler::metadata",
                infohash = %ih,
                error.kind = "metadata_private_unreadable",
                "could not read the `private` key of the magnet's metadata; DHT, PEX and LSD \
                 stay disabled",
            );
            return;
        }
    }
    let handle = handle.or_else(|| {
        ctx.state
            .get(&ih)
            .filter(|st| st.profile_id == ctx.profile_id)
            .map(|st| st.handle)
    });
    let Some(handle) = handle else {
        warn!(
            target: "torrentd_engine::handler::metadata",
            infohash = %ih,
            error.kind = "metadata_no_handle",
            "public magnet metadata arrived for a torrent with no handle; DHT, PEX and LSD stay \
             disabled",
        );
        return;
    };
    match ctx.engine.unset_flags(handle, lift) {
        Ok(()) => {
            info!(
                target: "torrentd_engine::handler::metadata",
                infohash = %ih,
                lifted = ?lift,
                "magnet metadata is public; lifted its discovery guards",
            );
            // Until this save lands, the resume file still holds the guards,
            // and a restart before it reloads them: safe, and only peers lost.
            ctx.state.queue_resume_save_now(ih);
        }
        Err(e) => warn!(
            target: "torrentd_engine::handler::metadata",
            infohash = %ih,
            error.kind = "unset_flags",
            error.cause = %e,
            "could not lift a public magnet's discovery guards; DHT, PEX and LSD stay disabled",
        ),
    }
}

/// Whether the bencoded info dict `info` marks its torrent private, read as
/// libtorrent reads it: a top-level `private` key holding a non-zero integer.
///
/// `None` where that cannot be told — `info` is not one well-formed dict, or
/// its `private` key holds something other than an integer, which libtorrent
/// would read as public. The caller treats `None` as private.
///
/// Not a general bencode reader: it walks the top level of one dict and
/// skips every value but `private`'s, with no recursion, so a hostile dict
/// costs one pass over its bytes and nothing more.
fn info_is_private(info: &[u8]) -> Option<bool> {
    let mut rest = info.strip_prefix(b"d")?;
    let mut private = false;
    loop {
        if let Some(after) = rest.strip_prefix(b"e") {
            return after.is_empty().then_some(private);
        }
        let (key, after_key) = split_string(rest)?;
        let (value, after_value) = split_value(after_key)?;
        if key == b"private" {
            // Every `private` key counts: a dict carrying it twice is read
            // as private if either says so.
            private |= int_value(value)? != 0;
        }
        rest = after_value;
    }
}

/// Split a bencoded string (`<len>:<bytes>`) off the front of `buf`: its
/// bytes, and what follows it.
fn split_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = buf.iter().take(21).position(|&b| b == b':')?;
    let digits = &buf[..colon];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let len: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    let start = colon + 1;
    let end = start.checked_add(len)?;
    Some((buf.get(start..end)?, &buf[end..]))
}

/// Split one bencoded value off the front of `buf`: the value's bytes, and
/// what follows it. Nesting is counted, not recursed into.
fn split_value(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut at = 0usize;
    let mut depth = 0usize;
    loop {
        match *buf.get(at)? {
            b'd' | b'l' => {
                depth += 1;
                at += 1;
            }
            b'e' => {
                depth = depth.checked_sub(1)?;
                at += 1;
            }
            b'i' => at += buf[at..].iter().position(|&b| b == b'e')? + 1,
            b'0'..=b'9' => {
                let (_, after) = split_string(&buf[at..])?;
                at = buf.len() - after.len();
            }
            _ => return None,
        }
        if depth == 0 {
            return Some((&buf[..at], &buf[at..]));
        }
    }
}

/// The integer a bencoded `i<n>e` value holds, or `None` for any other value.
fn int_value(value: &[u8]) -> Option<i64> {
    let digits = value.strip_prefix(b"i")?.strip_suffix(b"e")?;
    std::str::from_utf8(digits).ok()?.parse().ok()
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
    use crate::metrics::NoopSink;
    use crate::mock::MockEngine;
    use crate::mock::RecordedCall;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
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
            profile_fenced: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };

        handle(&alert, &mut ctx, TorrentFlags::empty());

        let saved = torrents.load_all(&ProfileId::new("p")).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].0, ih);
        // Wrapped as a minimal `.torrent`: { "info": <info_section> }.
        let mut expected = b"d4:info".to_vec();
        expected.extend_from_slice(&info);
        expected.push(b'e');
        assert_eq!(saved[0].1, expected);
    }

    #[test]
    fn a_failed_persist_is_counted_against_the_profile() {
        // A regular file where the store's base directory should be: every
        // write under it fails.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"").unwrap();
        let torrents = crate::torrent_store::FsTorrentStore::new(&blocker);

        let alert = Alert::MetadataReceived {
            hdr: AlertHeader {
                kind: AlertKind::MetadataReceived,
                infohash: Some(InfoHash([0x56; 20])),
                handle: None,
                timestamp_us: 0,
            },
            info_section: b"d6:lengthi5ee".to_vec(),
        };
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let metrics = crate::metrics::RecordingSink::new();
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

        handle(&alert, &mut ctx, TorrentFlags::empty());

        assert_eq!(metrics.count_for("torrent_file_persist_errors_total"), 1);
    }

    const GUARDS: TorrentFlags = TorrentFlags::DISABLE_PEX
        .union(TorrentFlags::DISABLE_DHT)
        .union(TorrentFlags::DISABLE_LSD);

    fn tracked(byte: u8) -> TorrentHandle {
        TorrentHandle {
            id: u64::from(byte),
            infohash: InfoHash([byte; 20]),
        }
    }

    /// Dispatch `info` as `h`'s metadata on profile `p` with `lift`, and
    /// return the flags each `unset_flags` call cleared and the saves queued.
    fn receive(
        engine: Arc<MockEngine>,
        h: TorrentHandle,
        info: &[u8],
        lift: TorrentFlags,
    ) -> (Vec<TorrentFlags>, Vec<InfoHash>) {
        let alert = Alert::MetadataReceived {
            hdr: AlertHeader {
                kind: AlertKind::MetadataReceived,
                infohash: Some(h.infohash),
                handle: Some(h),
                timestamp_us: 0,
            },
            info_section: info.to_vec(),
        };
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let dyn_engine: Arc<dyn TorrentEngine> = engine.clone();
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &dyn_engine,
            profile_fenced: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };

        handle(&alert, &mut ctx, lift);

        let unset = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::UnsetFlags { handle, flags } => {
                    assert_eq!(handle, h);
                    Some(flags)
                }
                _ => None,
            })
            .collect();
        let saves = state
            .dispatch_resume_saves(usize::MAX)
            .into_iter()
            .map(|(ih, flags)| {
                assert!(flags.is_empty(), "the save must be unconditional");
                ih
            })
            .collect();
        (unset, saves)
    }

    const PUBLIC: &[u8] = b"d6:lengthi5e4:name1:a12:piece lengthi16384e6:pieces0:e";
    const PRIVATE: &[u8] = b"d6:lengthi5e4:name1:a12:piece lengthi16384e6:pieces0:7:privatei1ee";

    #[test]
    fn public_metadata_on_a_host_profile_lifts_the_guards_and_saves() {
        let h = tracked(0x61);
        let (unset, saves) = receive(Arc::new(MockEngine::new()), h, PUBLIC, GUARDS);
        assert_eq!(unset, vec![GUARDS]);
        assert_eq!(saves, vec![h.infohash]);

        // `private` present and 0 is public too.
        let h = tracked(0x62);
        let zero = b"d4:name1:a7:privatei0ee";
        let (unset, saves) = receive(Arc::new(MockEngine::new()), h, zero, GUARDS);
        assert_eq!(unset, vec![GUARDS]);
        assert_eq!(saves, vec![h.infohash]);
    }

    #[test]
    fn private_metadata_keeps_the_guards() {
        let (unset, saves) = receive(Arc::new(MockEngine::new()), tracked(0x63), PRIVATE, GUARDS);
        assert!(unset.is_empty(), "{unset:?}");
        assert!(saves.is_empty(), "{saves:?}");
    }

    #[test]
    fn a_vpn_profile_lifts_nothing_whatever_the_metadata() {
        // `public_magnet_lift` of a vpn profile is empty.
        let (unset, saves) = receive(
            Arc::new(MockEngine::new()),
            tracked(0x64),
            PUBLIC,
            TorrentFlags::empty(),
        );
        assert!(unset.is_empty(), "{unset:?}");
        assert!(saves.is_empty(), "{saves:?}");
    }

    #[test]
    fn unreadable_metadata_keeps_the_guards() {
        for info in [
            &b"not bencode"[..],
            b"d7:private1:1e",       // `private` is not an integer
            b"d4:name1:a",           // unterminated
            b"d4:name1:ae trailing", // bytes past the dict
        ] {
            let (unset, saves) = receive(Arc::new(MockEngine::new()), tracked(0x65), info, GUARDS);
            assert!(unset.is_empty(), "{}", String::from_utf8_lossy(info));
            assert!(saves.is_empty(), "{}", String::from_utf8_lossy(info));
        }
    }

    #[test]
    fn a_refused_clear_queues_no_save() {
        let engine = Arc::new(MockEngine::new());
        engine.inject_error(
            "unset_flags",
            EngineError::MockInjected {
                op: "unset_flags",
                message: "refused".into(),
            },
        );
        let (unset, saves) = receive(engine, tracked(0x66), PUBLIC, GUARDS);
        assert_eq!(unset, vec![GUARDS], "the clear was asked for");
        assert!(saves.is_empty(), "{saves:?}");
    }

    #[test]
    fn only_a_top_level_private_key_counts() {
        // A `private` key inside a nested dict or list is not the torrent's.
        assert_eq!(
            info_is_private(b"d5:filesld7:privatei1eee4:name1:ae"),
            Some(false)
        );
        assert_eq!(
            info_is_private(b"d1:xl7:privatei1ee4:name1:ae"),
            Some(false)
        );
        assert_eq!(info_is_private(PRIVATE), Some(true));
        assert_eq!(info_is_private(b"d7:privatei-1ee"), Some(true));
        // Twice, either one private: private.
        assert_eq!(info_is_private(b"d7:privatei0e7:privatei1ee"), Some(true));
        assert_eq!(info_is_private(PUBLIC), Some(false));
        assert_eq!(info_is_private(b"de"), Some(false));
        assert_eq!(info_is_private(b""), None);
        assert_eq!(info_is_private(b"d99999999999999999999999:ae"), None);
        assert_eq!(info_is_private(b"d4:namei1ee"), Some(false));
        assert_eq!(info_is_private(b"d4:namexe"), None);
        // An unbalanced close inside a value.
        assert_eq!(info_is_private(b"d4:namee"), None);
    }
}
