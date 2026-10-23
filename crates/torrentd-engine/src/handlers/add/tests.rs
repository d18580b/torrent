
use std::sync::Arc;

use libtorrent_safe::alert::AlertHeader;
use libtorrent_safe::AlertKind;
use libtorrent_safe::InfoHash;
use libtorrent_safe::TorrentHandle;

use super::*;
use crate::clock::Clock;
use crate::clock::MockClock;
use crate::engine::TorrentEngine;
use crate::metrics::NoopSink;
use crate::metrics::REMOVE_CLEANUP_ERRORS;
use crate::mock::MockEngine;
use crate::profile::ProfileId;
use crate::resume_store::MemoryResumeStore;
use crate::resume_store::ResumeStore;
use crate::state::StateMap;
use crate::state::TorrentState;
use crate::torrent_store::MemoryTorrentStore;
use crate::torrent_store::TorrentStore;

#[test]
fn removed_torrent_deletes_resume_and_torrent_files() {
    let ih = InfoHash([0x77; 20]);
    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());

    // The torrent exists with persisted resume + .torrent on disk.
    let th = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    state.insert(
        ih,
        TorrentState::newly_added(th, profile.clone(), clock.now()),
    );
    resume.write(&profile, &ih, b"resume-bytes").unwrap();
    torrents.write(&profile, &ih, b"torrent-bytes").unwrap();

    let alert = Alert::TorrentRemoved {
        hdr: AlertHeader {
            kind: AlertKind::TorrentRemoved,
            infohash: Some(ih),
            handle: None,
            timestamp_us: 0,
        },
    };
    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile.clone(),
        span: tracing::info_span!("test"),
    };

    handle(&alert, &mut ctx);

    // No resurrection: state, resume file, and .torrent are all gone.
    assert!(!state.contains(&ih));
    assert!(resume.snapshot(&profile).is_empty());
    assert!(torrents.load_all(&profile).unwrap().is_empty());
}

fn removed_alert(ih: InfoHash) -> Alert {
    Alert::TorrentRemoved {
        hdr: AlertHeader {
            kind: AlertKind::TorrentRemoved,
            infohash: Some(ih),
            handle: None,
            timestamp_us: 0,
        },
    }
}

/// `DELETE`'s removal is recorded, the same profile adds the info-hash
/// again and writes its `.torrent` and save path, and only then is the old
/// torrent's `torrent_removed_alert` handled.
#[test]
fn a_removal_handled_after_a_same_profile_re_add_keeps_the_new_files() {
    let ih = InfoHash([0x7B; 20]);
    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let old = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    state.insert(
        ih,
        TorrentState::newly_added(old, profile.clone(), clock.now()),
    );
    resume.write(&profile, &ih, b"old-resume").unwrap();

    state.begin_removal(&profile, old);
    state.note_readded(&profile, &ih);
    torrents.write(&profile, &ih, b"new-torrent").unwrap();
    torrents.write_save_path(&profile, &ih, "/new").unwrap();

    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile.clone(),
        span: tracing::info_span!("test"),
    };
    handle(&removed_alert(ih), &mut ctx);

    assert!(!state.contains(&ih), "the removed torrent's entry is gone");
    assert_eq!(
        torrents.load_all(&profile).unwrap(),
        vec![(ih, b"new-torrent".to_vec())],
    );
    assert_eq!(
        torrents.read_save_path(&profile, &ih).unwrap().as_deref(),
        Some("/new"),
    );
    // Still the removed torrent's, recording where that one was.
    assert!(resume.snapshot(&profile).is_empty());
}

/// Re-added to another profile, whose `AddTorrent` is handled before the
/// first profile's `TorrentRemoved`: the new entry and its in-flight save
/// are left, and only the first profile's files are deleted.
#[test]
fn a_removal_handled_after_a_cross_profile_re_add_leaves_the_new_entry() {
    let ih = InfoHash([0x7C; 20]);
    let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let old = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    let new = TorrentHandle {
        id: 2,
        infohash: ih,
    };
    state.insert(ih, TorrentState::newly_added(old, p.clone(), clock.now()));
    torrents.write(&p, &ih, b"torrent").unwrap();
    torrents.write(&q, &ih, b"torrent").unwrap();
    state.begin_removal(&p, old);
    state.note_readded(&q, &ih);

    let ctx_for = |profile: &ProfileId| HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile.clone(),
        span: tracing::info_span!("test"),
    };
    handle(&add_alert(ih, Some(new), 0), &mut ctx_for(&q));
    assert_eq!(state.dispatch_resume_saves(8).len(), 1);
    handle(&removed_alert(ih), &mut ctx_for(&p));

    let st = state.get(&ih).expect("q's entry survives");
    assert_eq!((st.handle, st.profile_id), (new, q.clone()));
    assert_eq!(state.resume_saves_in_flight(), 1, "q's save is still owed");
    assert!(torrents.load_all(&p).unwrap().is_empty());
    assert_eq!(torrents.load_all(&q).unwrap().len(), 1);
}

#[test]
fn removing_a_torrent_settles_its_in_flight_save() {
    use libtorrent_safe::ResumeFlags;

    use crate::handlers::resume;

    let ih = InfoHash([0x78; 20]);
    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume_store = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let th = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    state.insert(
        ih,
        TorrentState::newly_added(th, profile.clone(), clock.now()),
    );
    assert!(state.queue_resume_save(ih, ResumeFlags::empty()));
    assert_eq!(state.dispatch_resume_saves(8).len(), 1);
    assert_eq!(state.resume_saves_in_flight(), 1);

    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume_store,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile.clone(),
        span: tracing::info_span!("test"),
    };
    handle(
        &Alert::TorrentRemoved {
            hdr: AlertHeader {
                kind: AlertKind::TorrentRemoved,
                infohash: Some(ih),
                handle: None,
                timestamp_us: 0,
            },
        },
        &mut ctx,
    );
    // The save's answer for the removed torrent carries no info-hash.
    resume::handle(
        &Alert::SaveResumeDataFailed {
            hdr: AlertHeader {
                kind: AlertKind::SaveResumeDataFailed,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            error_code: 0,
            not_modified: false,
            message: String::new(),
        },
        &mut ctx,
    );

    assert_eq!(state.resume_saves_in_flight(), 0);
    assert_eq!(state.pending_resume_count(), 0);
}

fn add_alert(ih: InfoHash, handle: Option<TorrentHandle>, error_code: i32) -> Alert {
    Alert::AddTorrent {
        hdr: AlertHeader {
            kind: AlertKind::AddTorrent,
            infohash: Some(ih),
            handle,
            timestamp_us: 0,
        },
        error_code,
        message: (error_code != 0).then(|| "refused".to_string()),
    }
}

#[test]
fn an_added_torrent_gets_an_unconditional_resume_save_at_once() {
    let ih = InfoHash([0x79; 20]);
    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let th = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile,
        span: tracing::info_span!("test"),
    };

    handle(&add_alert(ih, Some(th), 0), &mut ctx);

    // Queued for the dispatcher, not left for the 30-minute sweep, and
    // without `ONLY_IF_MODIFIED`: nothing is on disk for it yet.
    assert_eq!(state.pending_resume_count(), 1);
    assert_eq!(
        state.dispatch_resume_saves(8),
        vec![(ih, ResumeFlags::empty())],
    );
}

/// The boot scan tracked the torrent from the handle `add_torrent`
/// returned, and a state update reached its entry before its
/// `add_torrent_alert` was handled. The alert keeps the entry rather than
/// resetting it, and still queues the first save.
#[test]
fn an_add_alert_for_a_torrent_already_tracked_keeps_its_entry() {
    use crate::state::TorrentPhase;

    let ih = InfoHash([0x82; 20]);
    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let th = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    assert!(state.track_added(th, &profile, true, clock.now()));
    state.update(&ih, |st| {
        st.phase = TorrentPhase::Seeding;
        st.total_uploaded = 5;
    });

    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile.clone(),
        span: tracing::info_span!("test"),
    };
    handle(&add_alert(ih, Some(th), 0), &mut ctx);

    let st = state.get(&ih).expect("still tracked");
    assert_eq!((st.handle, &st.profile_id), (th, &profile));
    assert_eq!((st.phase, st.total_uploaded), (TorrentPhase::Seeding, 5));
    assert_eq!(
        state.dispatch_resume_saves(8),
        vec![(ih, ResumeFlags::empty())],
    );
}

/// The phase an add alert's fresh entry carries before any state update,
/// with the session describing the torrent as `details` does (`None`: it
/// cannot describe it), and whether the handler asked the session.
fn phase_after_add_alert(
    details: Option<bool>,
    tracked: bool,
) -> (crate::state::TorrentPhase, bool) {
    let ih = InfoHash([0x83; 20]);
    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let clock = MockClock::new();
    let mock = Arc::new(MockEngine::new());
    let th = mock.register_handle(ih);
    match details {
        Some(has_metadata) => mock.set_torrent_details(
            th,
            libtorrent_safe::TorrentDetails {
                has_metadata,
                ..MockEngine::default_details()
            },
        ),
        None => mock.inject_error("torrent_details", crate::engine::EngineError::Shutdown),
    }
    if tracked {
        assert!(state.track_added(th, &profile, false, clock.now()));
    }
    let engine: Arc<dyn TorrentEngine> = mock.clone();
    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &NoopSink,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile,
        span: tracing::info_span!("test"),
    };
    handle(&add_alert(ih, Some(th), 0), &mut ctx);
    let asked = mock
        .calls()
        .iter()
        .any(|c| matches!(c, crate::mock::RecordedCall::TorrentDetails(h) if *h == th));
    (state.get(&ih).expect("tracked").phase, asked)
}

/// A magnet whose metadata has not arrived is listed as fetching it, and
/// a torrent with metadata as checking, from the moment its add alert is
/// handled: neither as `Idle`, which says the torrent was checked.
#[test]
fn an_added_torrent_reads_the_phase_its_metadata_implies_before_any_update() {
    use crate::state::TorrentPhase;
    assert_eq!(
        phase_after_add_alert(Some(false), false),
        (TorrentPhase::AwaitingMetadata, true)
    );
    assert_eq!(
        phase_after_add_alert(Some(true), false),
        (TorrentPhase::Checking, true)
    );
    // A session that cannot describe it: libtorrent's starting state.
    assert_eq!(
        phase_after_add_alert(None, false),
        (TorrentPhase::Checking, true)
    );
    // Already tracked (the boot scan's torrents): the session is not
    // asked, and the entry keeps its phase.
    assert_eq!(
        phase_after_add_alert(Some(true), true),
        (TorrentPhase::AwaitingMetadata, false)
    );
}

/// Handle a successful `add_torrent_alert` for `ih` in `profile` against
/// `resume`, returning the saves it queued.
fn saves_queued_by_add(
    resume: &dyn ResumeStore,
    profile: &ProfileId,
    ih: InfoHash,
) -> Vec<(InfoHash, ResumeFlags)> {
    let state = StateMap::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let th = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    let mut ctx = HandlerCtx {
        state: &state,
        resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile.clone(),
        span: tracing::info_span!("test"),
    };
    handle(&add_alert(ih, Some(th), 0), &mut ctx);
    assert!(state.contains(&ih));
    state.dispatch_resume_saves(8)
}

/// The boot's resume scan loads each torrent from the file it just read:
/// saving it again rewrote every resume file at every boot, and the saves
/// crowded out the shutdown drain's `ONLY_IF_MODIFIED` requests (#190).
#[test]
fn a_torrent_loaded_from_its_own_resume_file_queues_no_save() {
    let ih = InfoHash([0x7D; 20]);
    let profile = ProfileId::new("p");
    let resume = MemoryResumeStore::new();
    resume.write(&profile, &ih, b"resume-bytes").unwrap();

    assert_eq!(saves_queued_by_add(&resume, &profile, ih), vec![]);
    assert_eq!(
        resume.snapshot(&profile),
        vec![(ih, b"resume-bytes".to_vec())],
        "the file is left as the boot read it",
    );
}

/// Another profile's resume file for the same info-hash is not this
/// torrent's: the add still saves its own.
#[test]
fn another_profiles_resume_file_does_not_skip_the_save() {
    let ih = InfoHash([0x7E; 20]);
    let resume = MemoryResumeStore::new();
    resume.write(&ProfileId::new("q"), &ih, b"q's").unwrap();

    assert_eq!(
        saves_queued_by_add(&resume, &ProfileId::new("p"), ih),
        vec![(ih, ResumeFlags::empty())],
    );
}

/// Removed and added again in the same profile: the removal's alert,
/// handled first, deleted the old torrent's file, so the new one is saved.
#[test]
fn a_re_add_after_a_removal_is_saved() {
    let ih = InfoHash([0x80; 20]);
    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let old = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    let new = TorrentHandle {
        id: 2,
        infohash: ih,
    };
    state.insert(
        ih,
        TorrentState::newly_added(old, profile.clone(), clock.now()),
    );
    resume.write(&profile, &ih, b"old-resume").unwrap();
    state.begin_removal(&profile, old);
    state.note_readded(&profile, &ih);

    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile,
        span: tracing::info_span!("test"),
    };
    handle(&removed_alert(ih), &mut ctx);
    handle(&add_alert(ih, Some(new), 0), &mut ctx);

    assert_eq!(
        state.dispatch_resume_saves(8),
        vec![(ih, ResumeFlags::empty())],
    );
}

/// The removal's delete fails, so the removed torrent's resume file is
/// still there when the same profile's re-add is handled. It is the old
/// torrent's, so the re-add is saved over it, whether the re-add was
/// accepted before the removal's alert or after it, and the mark is
/// spent on that save.
#[test]
fn a_re_add_over_a_resume_file_the_removal_failed_to_delete_is_saved() {
    use crate::resume_store::ResumeStoreError;
    use crate::resume_store::Scan;

    #[derive(Debug, Default)]
    struct UndeletableResume(MemoryResumeStore);
    impl ResumeStore for UndeletableResume {
        fn scan(
            &self,
            p: &ProfileId,
        ) -> Result<Scan<libtorrent_safe::ResumeData>, ResumeStoreError> {
            self.0.scan(p)
        }
        fn write(&self, p: &ProfileId, ih: &InfoHash, d: &[u8]) -> Result<(), ResumeStoreError> {
            self.0.write(p, ih, d)
        }
        fn delete(&self, _: &ProfileId, _: &InfoHash) -> Result<(), ResumeStoreError> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        }
        fn exists(&self, p: &ProfileId, ih: &InfoHash) -> Result<bool, ResumeStoreError> {
            self.0.exists(p, ih)
        }
    }

    for readded_before_alert in [true, false] {
        let ih = InfoHash([0x81; 20]);
        let profile = ProfileId::new("p");
        let state = StateMap::new();
        let resume = UndeletableResume::default();
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let old = TorrentHandle {
            id: 1,
            infohash: ih,
        };
        state.insert(
            ih,
            TorrentState::newly_added(old, profile.clone(), clock.now()),
        );
        resume.write(&profile, &ih, b"old-resume").unwrap();
        state.begin_removal(&profile, old);
        if readded_before_alert {
            state.note_readded(&profile, &ih);
        }

        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: profile.clone(),
            span: tracing::info_span!("test"),
        };
        handle(&removed_alert(ih), &mut ctx);
        assert!(resume.exists(&profile, &ih).unwrap());
        let new = TorrentHandle {
            id: 2,
            infohash: ih,
        };
        handle(&add_alert(ih, Some(new), 0), &mut ctx);

        assert_eq!(
            state.dispatch_resume_saves(8),
            vec![(ih, ResumeFlags::empty())],
            "re-added before the alert: {readded_before_alert}",
        );
        assert!(!state.take_stale_resume_file(&profile, &ih));
    }
}

/// A resume store whose deletes fail, as on a read-only or failing
/// directory, and whose tombstones work.
#[derive(Debug, Default)]
struct FailingDelete(MemoryResumeStore);
impl ResumeStore for FailingDelete {
    fn scan(
        &self,
        p: &ProfileId,
    ) -> Result<
        crate::resume_store::Scan<libtorrent_safe::ResumeData>,
        crate::resume_store::ResumeStoreError,
    > {
        self.0.scan(p)
    }
    fn write(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
        d: &[u8],
    ) -> Result<(), crate::resume_store::ResumeStoreError> {
        self.0.write(p, ih, d)
    }
    fn delete(
        &self,
        _: &ProfileId,
        _: &InfoHash,
    ) -> Result<(), crate::resume_store::ResumeStoreError> {
        Err(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem).into())
    }
    fn exists(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<bool, crate::resume_store::ResumeStoreError> {
        self.0.exists(p, ih)
    }
    fn write_tombstone(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<(), crate::resume_store::ResumeStoreError> {
        self.0.write_tombstone(p, ih)
    }
    fn clear_tombstone(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<(), crate::resume_store::ResumeStoreError> {
        self.0.clear_tombstone(p, ih)
    }
    fn tombstones(
        &self,
        p: &ProfileId,
    ) -> Result<Vec<InfoHash>, crate::resume_store::ResumeStoreError> {
        self.0.tombstones(p)
    }
}

/// Handle the removal alert of a torrent `DELETE` removed from `profile`
/// (tombstone written, removal recorded) against `resume`, after giving
/// it a resume file and a `.torrent`. Returns the `.torrent` store and
/// the metrics.
fn handle_removal(
    resume: &dyn ResumeStore,
    profile: &ProfileId,
    ih: InfoHash,
    tombstoned: bool,
) -> (MemoryTorrentStore, crate::metrics::RecordingSink) {
    let state = StateMap::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = crate::metrics::RecordingSink::new();
    let clock = MockClock::new();
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let th = TorrentHandle {
        id: 1,
        infohash: ih,
    };
    state.insert(
        ih,
        TorrentState::newly_added(th, profile.clone(), clock.now()),
    );
    resume.write(profile, &ih, b"resume").unwrap();
    torrents.write(profile, &ih, b"torrent").unwrap();
    if tombstoned {
        resume.write_tombstone(profile, &ih).unwrap();
    }
    state.begin_removal(profile, th);
    let mut ctx = HandlerCtx {
        state: &state,
        resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: profile.clone(),
        span: tracing::info_span!("test"),
    };
    handle(&removed_alert(ih), &mut ctx);
    (torrents, metrics)
}

/// The labels of every `torrent_remove_cleanup_errors_total` increment.
fn cleanup_errors(metrics: &crate::metrics::RecordingSink) -> Vec<Vec<(String, String)>> {
    metrics
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            crate::metrics::MetricCall::IncCounter { name, labels }
                if name == REMOVE_CLEANUP_ERRORS =>
            {
                Some(labels)
            }
            _ => None,
        })
        .collect()
}

/// The removal's handler is the fallback for what `DELETE` deleted: it
/// deletes a file that came back and spends the tombstone once all are
/// gone, counting nothing.
#[test]
fn a_removal_whose_files_delete_spends_its_tombstone() {
    let ih = InfoHash([0x91; 20]);
    let profile = ProfileId::new("p");
    let resume = MemoryResumeStore::new();
    let (torrents, metrics) = handle_removal(&resume, &profile, ih, true);
    assert!(!resume.exists(&profile, &ih).unwrap());
    assert!(!torrents.exists(&profile, &ih));
    assert!(resume.tombstones(&profile).unwrap().is_empty());
    assert!(cleanup_errors(&metrics).is_empty());
}

/// A resume file that will not delete used to be logged and nothing
/// else: no counter, no retry, and the next boot loaded the torrent from
/// it. It is counted now, and a tombstone stands for the boot to finish
/// the delete, whether `DELETE` wrote one or not.
#[test]
fn a_removal_whose_resume_delete_fails_counts_it_and_leaves_a_tombstone() {
    for tombstoned in [true, false] {
        let ih = InfoHash([0x92; 20]);
        let profile = ProfileId::new("p");
        let resume = FailingDelete::default();
        let (torrents, metrics) = handle_removal(&resume, &profile, ih, tombstoned);
        assert_eq!(
            cleanup_errors(&metrics),
            vec![vec![
                ("profile_id".to_owned(), "p".to_owned()),
                ("store".to_owned(), "resume".to_owned()),
            ]],
            "tombstoned by DELETE: {tombstoned}",
        );
        assert!(resume.exists(&profile, &ih).unwrap());
        assert_eq!(
            resume.tombstones(&profile).unwrap(),
            vec![ih],
            "tombstoned by DELETE: {tombstoned}",
        );
        assert!(!torrents.exists(&profile, &ih), "the .torrent still goes");
    }
}

/// A store that cannot say whether the file exists gets the save: an
/// extra write costs far less than a torrent no boot reloads.
#[test]
fn a_store_that_cannot_answer_gets_the_save() {
    use crate::resume_store::ResumeStoreError;
    use crate::resume_store::Scan;

    #[derive(Debug)]
    struct Unanswerable;
    impl ResumeStore for Unanswerable {
        fn scan(
            &self,
            _: &ProfileId,
        ) -> Result<Scan<libtorrent_safe::ResumeData>, ResumeStoreError> {
            Ok(Scan {
                entries: Vec::new(),
                unreadable: 0,
            })
        }
        fn write(&self, _: &ProfileId, _: &InfoHash, _: &[u8]) -> Result<(), ResumeStoreError> {
            Ok(())
        }
        fn delete(&self, _: &ProfileId, _: &InfoHash) -> Result<(), ResumeStoreError> {
            Ok(())
        }
        fn exists(&self, _: &ProfileId, _: &InfoHash) -> Result<bool, ResumeStoreError> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        }
    }

    let ih = InfoHash([0x7F; 20]);
    assert_eq!(
        saves_queued_by_add(&Unanswerable, &ProfileId::new("p"), ih),
        vec![(ih, ResumeFlags::empty())],
    );
}

#[test]
fn a_failed_add_queues_no_resume_save() {
    let ih = InfoHash([0x7A; 20]);
    let profile = ProfileId::new("p");
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
        fence_hold: None,
        profile_id: profile,
        span: tracing::info_span!("test"),
    };

    handle(&add_alert(ih, None, 1), &mut ctx);

    assert!(!state.contains(&ih));
    assert_eq!(state.pending_resume_count(), 0);
}

/// Add a torrent to a mock session, let `fenced_after_add` decide whether
/// the profile is fenced before its `add_torrent_alert` is handled, then
/// handle it. Returns the handle, the engine's recorded calls, and what
/// the handler ran through its fence hold: each handle with what the hold
/// answered, and the engine's calls by the time it had.
fn add_then_handle_alert(fenced_after_add: bool) -> AddedUnderFence {
    use std::sync::atomic::AtomicBool;

    use libtorrent_safe::AddParams;
    use libtorrent_safe::TorrentFlags;

    use crate::alert_loop::FenceHold;
    use crate::alert_loop::ProfileFenced;

    let profile = ProfileId::new("p");
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();
    let mock = Arc::new(MockEngine::new());
    let engine: Arc<dyn TorrentEngine> = mock.clone();
    let fenced = Arc::new(AtomicBool::new(false));
    let profile_fenced: ProfileFenced = {
        let fenced = fenced.clone();
        Arc::new(move |_: &ProfileId| fenced.load(Ordering::SeqCst))
    };
    let held = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let fence_hold: FenceHold = {
        let held = held.clone();
        let mock = mock.clone();
        Arc::new(
            move |id: &ProfileId, h: TorrentHandle, hold: &mut dyn FnMut() -> bool| {
                assert_eq!(id.as_str(), "p");
                let answered = hold();
                held.lock().push((h, answered, mock.calls()));
            },
        )
    };

    let th = engine
        .add_torrent(AddParams::Magnet {
            uri: "magnet:?xt=urn:btih:".to_string() + &"ab".repeat(20),
            save_path: "/data".to_string(),
            flags: TorrentFlags::empty(),
        })
        .unwrap();
    // The fence walks the state map now, which does not hold the torrent:
    // its alert is still queued.
    assert!(!state.contains(&th.infohash));
    fenced.store(fenced_after_add, Ordering::SeqCst);

    let mut ctx = HandlerCtx {
        state: &state,
        resume: &resume,
        torrents: &torrents,
        metrics: &metrics,
        clock: &clock,
        engine: &engine,
        profile_fenced: Some(&profile_fenced),
        fence_hold: Some(&fence_hold),
        profile_id: profile,
        span: tracing::info_span!("test"),
    };
    handle(
        &Alert::AddTorrent {
            hdr: AlertHeader {
                kind: AlertKind::AddTorrent,
                infohash: Some(th.infohash),
                handle: Some(th),
                timestamp_us: 0,
            },
            error_code: 0,
            message: None,
        },
        &mut ctx,
    );
    assert!(state.contains(&th.infohash));
    let held = std::mem::take(&mut *held.lock());
    AddedUnderFence {
        th,
        calls: mock.calls(),
        held,
    }
}

/// What [`add_then_handle_alert`] observed.
struct AddedUnderFence {
    th: TorrentHandle,
    calls: Vec<crate::mock::RecordedCall>,
    /// Each handle run through the fence hold, what the hold answered,
    /// and the engine's calls once it had.
    held: Vec<(TorrentHandle, bool, Vec<crate::mock::RecordedCall>)>,
}

#[test]
fn a_torrent_whose_profile_is_fenced_before_its_add_alert_lands_is_paused() {
    use crate::mock::RecordedCall;

    let AddedUnderFence { th, calls, .. } = add_then_handle_alert(true);
    assert!(
        calls
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(h) if *h == th)),
        "the fence missed it, so the add handler must pause it: {calls:?}",
    );
}

/// The daemon's kill-switch fence resumes only what it recorded, and its
/// walk did not find this torrent: the pause runs inside the hold, where
/// the daemon holds that fence's lock, and is answered as fenced so the
/// daemon records the handle for the lift.
#[test]
fn a_torrent_paused_into_a_fenced_profile_is_held_through_the_fence_hold() {
    use crate::mock::RecordedCall;

    let AddedUnderFence { th, held, .. } = add_then_handle_alert(true);
    let [(h, answered, calls)] = held.as_slice() else {
        panic!("the hold must run once, through the hook: {held:?}");
    };
    assert_eq!(*h, th);
    assert!(*answered, "a fenced profile must answer the hold as fenced");
    assert!(
        calls
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(p) if *p == th)),
        "the pause must land inside the hold, under the daemon's lock: {calls:?}",
    );
}

#[test]
fn a_torrent_added_to_an_unfenced_profile_is_not_paused() {
    use crate::mock::RecordedCall;

    let AddedUnderFence { th, calls, held } = add_then_handle_alert(false);
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(_))),
        "{calls:?}",
    );
    // Asked, and answered unfenced, so the daemon records nothing.
    assert!(
        matches!(held.as_slice(), [(h, false, _)] if *h == th),
        "{held:?}",
    );
}
