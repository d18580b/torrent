//! `RealEngine` — delegates to a `libtorrent_safe::Session` 1:1.
//!
//! No business logic here; that lives in the alert loop and handlers.
//! `RealEngine` exists only to satisfy `TorrentEngine` so production code
//! can swap in `MockEngine` for tests.
//!
//! Concurrency: `libtorrent_safe::Session` is `!Send + !Sync`. We park it
//! behind a `parking_lot::Mutex` and route every call through that lock.
//! libtorrent's session is internally thread-safe but the C shim's per-
//! session handle map is mutex-guarded already, so the contention overhead
//! is small for the shape of work torrentd does (one engine call per
//! second per torrent, max).

use std::collections::HashMap;

use libtorrent_safe::AddParams;
use libtorrent_safe::Alert;
use libtorrent_safe::FilePage;
use libtorrent_safe::InfoHash;
use libtorrent_safe::MoveFlags;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::Session;
use libtorrent_safe::Settings;
use libtorrent_safe::TorrentDetails;
use libtorrent_safe::TorrentFile;
use libtorrent_safe::TorrentHandle;
use libtorrent_safe::TrackerEntry;
use parking_lot::MappedMutexGuard;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use tracing::instrument;

use crate::engine::EngineError;
use crate::engine::TorrentEngine;

/// The most alerts one `pop_alerts` converts while holding the session lock.
///
/// Every engine call takes that lock, the HTTP handlers' included, so an
/// uncapped drain — up to the whole `alert_queue_size` of 10000, each alert a
/// ~3 KiB union to convert — stalls every one of them behind it. The alert
/// loop drains again at once while a pop comes back non-empty, so a cap costs
/// no throughput; it only lets other callers in between batches.
pub const MAX_ALERTS_PER_POP: usize = 512;

pub struct RealEngine {
    /// `None` once [`TorrentEngine::close`] has destroyed the session; every
    /// call after that answers [`EngineError::Shutdown`].
    session: Mutex<Option<Session>>,
    /// Every torrent the session holds, by info-hash: what `add_torrent`
    /// returned, less what `remove_torrent` took out. Written with the
    /// session lock held, so it changes in the order the session does.
    ///
    /// This is [`TorrentEngine::torrents`]' answer. The shim's own handle map
    /// cannot answer it: it also registers torrents an alert names, a removed
    /// one included until its disk jobs finish.
    held: Mutex<HashMap<InfoHash, TorrentHandle>>,
}

impl std::fmt::Debug for RealEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealEngine").finish_non_exhaustive()
    }
}

impl RealEngine {
    /// Construct a new engine with the given settings layered on top of
    /// libtorrent's `high_performance_seed()` preset.
    pub fn new(settings: &Settings) -> Result<Self, EngineError> {
        let session = Session::new(settings)?;
        Ok(Self::from_session(session))
    }

    /// Build from an existing `Session`, such as one restored with
    /// `Session::with_state`.
    pub fn from_session(session: Session) -> Self {
        Self {
            session: Mutex::new(Some(session)),
            held: Mutex::new(HashMap::new()),
        }
    }

    /// The live session, locked, or `Shutdown` once it has been closed.
    fn session(&self) -> Result<MappedMutexGuard<'_, Session>, EngineError> {
        MutexGuard::try_map(self.session.lock(), Option::as_mut).map_err(|_| EngineError::Shutdown)
    }
}

impl TorrentEngine for RealEngine {
    #[instrument(skip_all, fields(op = "add_torrent"))]
    fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle, EngineError> {
        let session = self.session()?;
        let h = session.add_torrent(params)?;
        // The handle the session just returned is the torrent it holds for
        // the info-hash, whatever was recorded for it before.
        self.held.lock().insert(h.infohash, h);
        drop(session);
        Ok(h)
    }

    #[instrument(skip_all, fields(op = "remove_torrent", infohash = %h.infohash, delete_files))]
    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError> {
        let session = self.session()?;
        let removed = session.remove_torrent(h, delete_files);
        // Gone either way: removed now, or not a torrent the session holds,
        // which is what a refusal says. Only where it is still the torrent
        // recorded, since a stale handle names one the info-hash outlived.
        let mut held = self.held.lock();
        if held.get(&h.infohash) == Some(&h) {
            held.remove(&h.infohash);
        }
        drop(held);
        drop(session);
        Ok(removed?)
    }

    #[instrument(skip_all, fields(op = "pause_torrent", infohash = %h.infohash))]
    fn pause_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.pause_torrent(h)?)
    }

    #[instrument(skip_all, fields(op = "resume_torrent", infohash = %h.infohash))]
    fn resume_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.resume_torrent(h)?)
    }

    #[instrument(skip_all, fields(op = "save_resume_data", infohash = %h.infohash))]
    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError> {
        Ok(self.session()?.save_resume_data(h, flags)?)
    }

    #[instrument(skip_all, fields(op = "set_upload_limit", infohash = %h.infohash))]
    fn set_upload_limit(&self, h: TorrentHandle, bytes_per_sec: i32) -> Result<(), EngineError> {
        Ok(self.session()?.set_upload_limit(h, bytes_per_sec)?)
    }

    #[instrument(skip_all, fields(op = "set_file_priority", infohash = %h.infohash))]
    fn set_file_priority(
        &self,
        h: TorrentHandle,
        file_idx: i32,
        priority: u8,
    ) -> Result<(), EngineError> {
        Ok(self.session()?.set_file_priority(h, file_idx, priority)?)
    }

    #[instrument(skip_all, fields(op = "force_recheck", infohash = %h.infohash))]
    fn force_recheck(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.force_recheck(h)?)
    }

    #[instrument(skip_all, fields(op = "force_reannounce", infohash = %h.infohash))]
    fn force_reannounce(&self, h: TorrentHandle) -> Result<(), EngineError> {
        Ok(self.session()?.force_reannounce(h)?)
    }

    #[instrument(skip_all, fields(op = "move_storage", infohash = %h.infohash, new_path))]
    fn move_storage(
        &self,
        h: TorrentHandle,
        new_path: &str,
        flags: MoveFlags,
    ) -> Result<(), EngineError> {
        Ok(self.session()?.move_storage(h, new_path, flags)?)
    }

    fn pop_alerts(&self) -> Vec<Alert> {
        self.session()
            .map(|s| s.drain_alerts_up_to(MAX_ALERTS_PER_POP))
            .unwrap_or_default()
    }

    fn post_updates(&self) {
        if let Ok(s) = self.session() {
            s.post_torrent_updates()
        }
    }
    fn post_stats(&self) {
        if let Ok(s) = self.session() {
            s.post_session_stats()
        }
    }

    fn close(&self) {
        // Taken out of the lock before it is dropped: the destructor blocks
        // until libtorrent has closed every socket and flushed its disk
        // threads, and nothing else should queue behind the lock meanwhile
        // only to be told the session is gone.
        let session = self.session.lock().take();
        self.held.lock().clear();
        drop(session);
    }

    #[instrument(skip_all, fields(op = "apply_settings"))]
    fn apply_settings(&self, settings: &Settings) -> Result<(), EngineError> {
        Ok(self.session()?.apply_settings(settings)?)
    }

    fn session_state(&self) -> Result<Vec<u8>, EngineError> {
        Ok(self.session()?.save_state()?)
    }

    #[instrument(skip_all, fields(op = "pause_session"))]
    fn pause_session(&self) -> Result<(), EngineError> {
        Ok(self.session()?.pause()?)
    }

    #[instrument(skip_all, fields(op = "resume_session"))]
    fn resume_session(&self) -> Result<(), EngineError> {
        Ok(self.session()?.resume()?)
    }

    fn session_paused(&self) -> Result<bool, EngineError> {
        Ok(self.session()?.is_paused()?)
    }

    #[instrument(skip_all, fields(op = "torrent_details", infohash = %h.infohash))]
    fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails, EngineError> {
        Ok(self.session()?.torrent_details(h)?)
    }

    #[instrument(skip_all, fields(op = "torrent_files", infohash = %h.infohash))]
    fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>, EngineError> {
        // The session lock covers the shim call only. Converting the list
        // copies every path, up to 250k of them, and needs no session.
        let raw = self.session()?.torrent_files_raw(h, 0, usize::MAX)?;
        Ok(raw.into_files())
    }

    #[instrument(skip_all, fields(op = "torrent_files_page", infohash = %h.infohash, start, limit))]
    fn torrent_files_page(
        &self,
        h: TorrentHandle,
        start: u32,
        limit: u32,
    ) -> Result<Option<FilePage>, EngineError> {
        // As above, but the shim copies only the page under the lock.
        let raw = self
            .session()?
            .torrent_files_raw(h, start as usize, limit as usize)?;
        Ok(raw.into_page())
    }

    #[instrument(skip_all, fields(op = "torrent_trackers", infohash = %h.infohash))]
    fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>, EngineError> {
        Ok(self.session()?.torrent_trackers(h)?)
    }

    fn torrents(&self) -> Result<Vec<TorrentHandle>, EngineError> {
        let _session = self.session()?;
        Ok(self.held.lock().values().copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    use libtorrent_safe::TorrentFlags;

    use super::*;

    /// The most files a torrent the shim admits may have.
    const FILES: u32 = 250_000;

    /// A `.torrent` of `FILES` one-byte files under one root, in one piece.
    /// The piece hash is filler: the torrent is added paused and never
    /// checked, so nothing reads it.
    fn many_file_torrent() -> Vec<u8> {
        let mut out = b"d4:infod5:filesl".to_vec();
        for i in 0..FILES {
            out.extend_from_slice(format!("d6:lengthi1e4:pathl6:{i:06}ee").as_bytes());
        }
        out.extend_from_slice(b"e4:name4:many");
        out.extend_from_slice(format!("12:piece lengthi{}e", 1u64 << 24).as_bytes());
        out.extend_from_slice(b"6:pieces20:");
        out.extend_from_slice(&[0xab; 20]);
        out.extend_from_slice(b"ee");
        out
    }

    fn local_settings() -> Settings {
        let mut s = Settings::server_seed_overrides();
        s.enable_dht = Some(false);
        s.enable_lsd = Some(false);
        s.enable_upnp = Some(false);
        s.enable_natpmp = Some(false);
        s.listen_interfaces = Some("127.0.0.1:0".into());
        s
    }

    /// A one-file, one-piece `.torrent` whose info-hash `n` makes unique.
    fn tiny_torrent(n: u32) -> Vec<u8> {
        let name = format!("t{n:08}");
        let mut out = b"d4:infod6:lengthi1e".to_vec();
        out.extend_from_slice(format!("4:name{}:{name}", name.len()).as_bytes());
        out.extend_from_slice(b"12:piece lengthi16384e6:pieces20:");
        out.extend_from_slice(&[0xab; 20]);
        out.extend_from_slice(b"ee");
        out
    }

    fn add_tiny(engine: &RealEngine, dir: &std::path::Path, n: u32) -> TorrentHandle {
        engine
            .add_torrent(AddParams::File {
                bytes: tiny_torrent(n),
                save_path: dir.to_string_lossy().into_owned(),
                flags: TorrentFlags::PAUSED | TorrentFlags::UPLOAD_MODE,
                trackers: Vec::new(),
            })
            .expect("add")
    }

    #[test]
    fn torrents_lists_what_the_session_holds() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let engine = RealEngine::new(&local_settings()).expect("session");
        let (a, b) = (
            add_tiny(&engine, dir.path(), 1),
            add_tiny(&engine, dir.path(), 2),
        );
        let mut held = engine.torrents().expect("list");
        held.sort_by_key(|h| h.id);
        assert_eq!(held, vec![a, b]);

        engine.remove_torrent(a, false).expect("remove");
        assert_eq!(engine.torrents().expect("list"), vec![b]);
        // A refused removal of what is already gone changes nothing else.
        assert!(engine.remove_torrent(a, false).is_err());
        assert_eq!(engine.torrents().expect("list"), vec![b]);

        engine.close();
        assert!(matches!(engine.torrents(), Err(EngineError::Shutdown)));
    }

    /// More torrents added before any alert is popped than the alert queue
    /// holds, as a boot scan does: libtorrent drops add alerts, and every
    /// torrent still ends up tracked, under the handle a `DELETE` removes.
    #[test]
    fn torrents_whose_add_alerts_overflowed_the_queue_are_all_tracked() {
        use crate::alert_loop::AlertLoopBuilder;
        use crate::alert_loop::ShutdownReason;
        use crate::metrics::RecordingSink;
        use crate::profile::ProfileId;
        use crate::resume_store::MemoryResumeStore;
        use crate::source::ProfileSource;
        use crate::state::StateMap;
        use crate::torrent_store::MemoryTorrentStore;

        // libtorrent lets critical alerts, adds among them, fill three times
        // `alert_queue_size`: 1 500 adds overflow a queue of 100 many times.
        const ADDS: u32 = 1_500;
        let mut settings = local_settings();
        settings.alert_queue_size = Some(100);
        let dir = tempfile::tempdir().expect("scratch dir");
        let engine = Arc::new(RealEngine::new(&settings).expect("session"));
        let added: Vec<TorrentHandle> = (0..ADDS)
            .map(|n| add_tiny(&engine, dir.path(), n))
            .collect();

        let p = ProfileId::new("p");
        let state = Arc::new(StateMap::new());
        let metrics = Arc::new(RecordingSink::new());
        let alert_loop = AlertLoopBuilder::new(
            Arc::new(ProfileSource::new(vec![(p.clone(), engine.clone())])),
            state.clone(),
            Arc::new(MemoryResumeStore::new()),
            Arc::new(MemoryTorrentStore::new()),
            metrics.clone(),
            Arc::new(crate::clock::SystemClock),
        )
        .shutdown_deadline(Duration::from_secs(1))
        .spawn();

        let deadline = Instant::now() + Duration::from_secs(20);
        while state.len() < ADDS as usize && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            metrics.count_for("alert_queue_overflows_total") > 0,
            "the queue overflowed, or this test proves nothing",
        );
        assert_eq!(state.len(), ADDS as usize, "every torrent is tracked");
        // Fenceable: the VPN monitor pauses what this returns.
        assert_eq!(state.handles_for_profile(&p).len(), ADDS as usize);
        // Deletable: `DELETE` removes the handle the entry holds.
        for h in &added {
            let st = state.get(&h.infohash).expect("tracked");
            assert_eq!((st.handle, &st.profile_id), (*h, &p));
        }
        // Tracking each torrent asked for its first resume save, and those
        // 1 500 answers still overflow a queue of 100: one could crowd out
        // the `torrent_removed_alert` the removal below waits for. Give the
        // queue the default's room before removing, so that alert arrives.
        let roomy = Settings {
            alert_queue_size: Some(10_000),
            ..Settings::default()
        };
        engine
            .apply_settings(&roomy)
            .expect("raise the alert queue");
        engine.remove_torrent(added[0], false).expect("remove");
        let deadline = Instant::now() + Duration::from_secs(10);
        while state.contains(&added[0].infohash) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!state.contains(&added[0].infohash), "its removal settled");

        alert_loop.signal_shutdown(ShutdownReason::Test);
        alert_loop.join().expect("alert loop");
    }

    /// Many parallel listers paging a 250,000-file torrent, as parallel
    /// `GET /v1/torrents/{ih}/files` requests do, leave the alert loop's
    /// `pop_alerts` + `post_updates` the session lock between pages. Copying
    /// the whole list per page held the lock ~90 ms a call, and 32 listers
    /// stretched one loop iteration to seconds.
    #[test]
    fn parallel_file_pages_do_not_starve_the_alert_loop() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let engine = Arc::new(RealEngine::new(&local_settings()).expect("session"));
        let h = engine
            .add_torrent(AddParams::File {
                bytes: many_file_torrent(),
                save_path: dir.path().to_string_lossy().into_owned(),
                flags: TorrentFlags::PAUSED | TorrentFlags::UPLOAD_MODE,
                trackers: Vec::new(),
            })
            .expect("add");
        let last = engine
            .torrent_files_page(h, FILES - 1, 100)
            .expect("page")
            .expect("metadata");
        assert_eq!(last.total, FILES);
        assert_eq!(last.files.len(), 1);
        assert_eq!(last.files[0].index, FILES - 1);
        assert_eq!(last.files[0].path, format!("many/{:06}", FILES - 1));

        let stop = Arc::new(AtomicBool::new(false));
        let pages = Arc::new(AtomicU64::new(0));
        let listers: Vec<_> = (0..32u32)
            .map(|n| {
                let (engine, stop, pages) = (engine.clone(), stop.clone(), pages.clone());
                std::thread::spawn(move || {
                    let mut start = n * 7_919 % FILES;
                    while !stop.load(Ordering::Relaxed) {
                        let page = engine
                            .torrent_files_page(h, start, 100)
                            .expect("page")
                            .expect("metadata");
                        assert!(page.files.len() <= 100);
                        pages.fetch_add(1, Ordering::Relaxed);
                        start = (start + 100) % FILES;
                    }
                })
            })
            .collect();

        let mut worst = Duration::ZERO;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let t = Instant::now();
            drop(engine.pop_alerts());
            engine.post_updates();
            worst = worst.max(t.elapsed());
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Relaxed);
        for l in listers {
            l.join().expect("lister");
        }
        assert!(
            pages.load(Ordering::Relaxed) > 32,
            "the listers made progress"
        );
        assert!(
            worst < Duration::from_secs(1),
            "an alert-loop iteration waited {worst:?} behind the listers"
        );
    }
}
