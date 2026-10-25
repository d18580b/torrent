//! Removing torrents: payload deletes, store and registry failures, and a
//! delete racing a re-add.

use super::*;

pub(super) async fn deleting(h: &Harness, e: &Engines) {
    // Taken now: the mock forgets a handle once it is removed.
    let loaded = handle(&e.p, LOADED);
    // Erasing payload needs `[pool] allow_mutations`, and this daemon has no
    // pool at all.
    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{}?delete_files=true", hex(LOADED)),
        )
        .await;
    assert_problem(&resp, 403, "mutations-disabled");
    assert!(h.state.registry.lookup(&LOADED).is_some());

    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{}", hex(InfoHash([0xee; 20]))),
        )
        .await;
    assert_problem(&resp, 404, "torrent-not-found");

    // Mid-add: the session may hold it, so the assignment must stay or a
    // second profile could take the torrent.
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await;
    assert_problem(&resp, 409, "torrent-adding");
    assert!(h.state.registry.lookup(&ADDING).is_some());
    // Once the boot is known to have left it unloaded, a plain delete still
    // refuses while its stores hold the resume file or `.torrent` its failed
    // add left (#354): those are what the next boot loads it from, once the
    // reason the add failed is fixed.
    h.state.unloaded_at_boot.lock().insert(ADDING);
    let live = ProfileId::new("p");
    let in_resume = |h: &Harness| {
        h.state
            .resume
            .load_all(&live)
            .unwrap()
            .iter()
            .any(|(ih, _)| *ih == ADDING)
    };
    let in_torrents = |h: &Harness| {
        h.state
            .torrents
            .load_all(&live)
            .unwrap()
            .iter()
            .any(|(ih, _)| *ih == ADDING)
    };
    for (resume, torrent) in [(true, true), (true, false), (false, true)] {
        if resume {
            h.state
                .resume
                .write(&live, &ADDING, b"resume-bytes")
                .unwrap();
        }
        if torrent {
            h.state
                .torrents
                .write(&live, &ADDING, b"torrent-bytes")
                .unwrap();
        }
        let resp = h
            .write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
            .await;
        assert_problem(&resp, 409, "torrent-unloaded");
        let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
        for (held, name) in [
            (resume, format!("{}.resume", hex(ADDING))),
            (torrent, format!("{}.torrent", hex(ADDING))),
        ] {
            assert_eq!(detail.contains(&name), held, "{name}: {detail}");
        }
        assert!(
            detail.contains("torrentd_boot_torrent_load_failures"),
            "{detail}"
        );
        assert_eq!(h.state.registry.lookup(&ADDING), Some(live.clone()));
        assert!(h.state.unloaded_at_boot.lock().contains(&ADDING));
        assert_eq!(in_resume(h), resume, "the refusal touched the resume file");
        assert_eq!(in_torrents(h), torrent, "the refusal touched the .torrent");
        // What the operator does to retire it anyway: move the files out.
        h.state.resume.delete(&live, &ADDING).unwrap();
        h.state.torrents.delete(&live, &ADDING).unwrap();
    }
    // A claim with nothing behind it, as a crash between an add's claim and
    // its first record leaves, is cleared.
    h.write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(h.state.registry.lookup(&ADDING).is_none());
    assert!(
        !h.state.unloaded_at_boot.lock().contains(&ADDING),
        "a later add of the same infohash must not be taken for a boot leftover"
    );

    // A session error keeps the assignment.
    e.p.inject_error("remove_torrent", injected("remove_torrent"));
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(LOADED)))
        .await;
    assert_problem(&resp, 500, "internal");
    assert!(h.state.registry.lookup(&LOADED).is_some());
    // A loaded torrent leaves its session and its assignment.
    h.write(
        "DELETE",
        &format!("/v1/torrents/{}?delete_files=false", hex(LOADED)),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert!(called(
        &e.p,
        &RecordedCall::RemoveTorrent {
            handle: loaded,
            delete_files: false
        }
    ));
    assert!(h.state.registry.lookup(&LOADED).is_none());

    // A profile with no session: the assignment and the two stores that
    // would resurrect it at the next start are cleared.
    let down = ProfileId::new("down");
    h.state
        .resume
        .write(&down, &STALE, b"resume-bytes")
        .unwrap();
    h.state
        .torrents
        .write(&down, &STALE, b"torrent-bytes")
        .unwrap();
    h.write("DELETE", &format!("/v1/torrents/{}", hex(STALE)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(h.state.registry.lookup(&STALE).is_none());
    assert!(h.state.resume.load_all(&down).unwrap().is_empty());
    assert!(h.state.torrents.load_all(&down).unwrap().is_empty());
}

/// Drop the write bit on `dir`, returning the mode to restore afterwards.
///
/// Restoring matters: `tempfile::TempDir`'s cleanup cannot remove a file from
/// a directory it may not write.
fn make_readonly(dir: &Path) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    let original = std::fs::metadata(dir).unwrap().permissions();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    original
}

#[tokio::test]
async fn a_store_delete_that_fails_leaves_the_assignment_for_the_retry() {
    // Both of the sessionless branch's store errors tell the operator to
    // retry the delete. With the registry cleared first the retry could not
    // reach the work: it found no assignment, answered 404, and the resume
    // file stayed to re-assign the infohash at the next start.
    //
    // `MemoryResumeStore`'s deletes cannot fail, so this uses the filesystem
    // store with its profile directory made read-only.
    let dir = tempfile::tempdir().unwrap();
    let down = ProfileId::new("down");
    let resume_root = dir.path().join("resume");
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
        let fs: Arc<dyn torrentd_engine::ResumeStore> =
            Arc::new(torrentd_engine::FsResumeStore::new(resume_root.clone()));
        fs.write(&down, &STALE, b"resume-bytes").unwrap();
        s.resume = fs;
    });

    let profile_dir = resume_root.join(down.as_str());
    let original = make_readonly(&profile_dir);
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(STALE)))
        .await;
    std::fs::set_permissions(&profile_dir, original).unwrap();

    assert_problem(&resp, 500, "internal");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(
        detail.contains("resume file") && detail.contains("Retry the delete"),
        "{detail}"
    );
    assert!(
        h.state.registry.lookup(&STALE).is_some(),
        "the assignment must stay, or the retry answers 404 and never reaches the file"
    );

    // And the retry finishes the work once the directory is writable.
    h.write("DELETE", &format!("/v1/torrents/{}", hex(STALE)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(h.state.registry.lookup(&STALE).is_none());
    assert!(h.state.resume.load_all(&down).unwrap().is_empty());
}

#[tokio::test]
async fn a_delete_that_cannot_clear_the_assignment_says_so_rather_than_answering_204() {
    // On a full or read-only state directory the payload is gone, the
    // assignment write fails, and a 204 would bring the claim back from the
    // file at the next restart, over a torrent that no longer exists.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("failing.db");
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p);
        // The torrent is assigned, and from then on every write to the
        // registry fails, as on a full or read-only state directory.
        s.registry = Arc::new(AssignmentRegistry::new_empty(&db));
        s.registry.assign(LOADED, ProfileId::new("p")).unwrap();
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_delete BEFORE DELETE ON assignment \
                   BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        s.pool = crate::pool_service::PoolService::open(&crate::config::Config::minimal_for_tests(
            dir.path(),
            false,
        ))
        .unwrap();
    });
    // The pool index records `p` owning the torrent, as an adoption leaves it.
    let index = Arc::clone(h.state.pool.as_ref().unwrap());
    index
        .with_store_mut(|st| {
            st.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: hex(LOADED),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: "L".into(),
                    total_size: 1,
                    num_files: 1,
                    source_path: dir.path().join("l.torrent"),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: Some("p".into()),
                },
                0,
            )
        })
        .unwrap();
    let owner = || index.with_reader(|st| st.profile_of(&hex(LOADED)).unwrap());
    assert_eq!(owner().as_deref(), Some("p"));
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(LOADED)))
        .await;
    assert_problem(&resp, 500, "internal");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(
        detail.contains("assignment") && detail.contains("removed from its session"),
        "the operator has to know which half failed: {detail}"
    );
    let engine = engine.unwrap();
    let removals = || {
        engine
            .calls()
            .iter()
            .filter(|c| matches!(c, RecordedCall::RemoveTorrent { .. }))
            .count()
    };
    assert_eq!(removals(), 1);
    // The detail says to retry. That only works if the failed write left the
    // claim in memory too; dropping it there first made the retry a 404 and
    // the claim came back from disk at the next restart.
    assert_eq!(
        h.state.registry.lookup(&LOADED),
        Some(ProfileId::new("p")),
        "a remove that failed to persist releases nothing",
    );
    assert_eq!(
        owner().as_deref(),
        Some("p"),
        "the index owner is released with the assignment, not before",
    );

    // The session confirms the removal, which drops the state-map entry, and
    // the operator frees the disk.
    let settled = h
        .state
        .state
        .settle_removal(&ProfileId::new("p"), &LOADED, |_| {});
    assert!(settled.entry_released);
    assert!(h.state.state.get(&LOADED).is_none());
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("DROP TRIGGER no_delete;")
        .unwrap();

    // The retry the detail asked for clears the assignment. It used to find
    // no state and no boot record, answer `409 torrent-adding`, and go on
    // answering it until a restart.
    h.write("DELETE", &format!("/v1/torrents/{}", hex(LOADED)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(removals(), 1, "the session is not asked a second time");
    assert_eq!(h.state.registry.lookup(&LOADED), None);
    assert!(h.state.removed_unassigned.lock().is_empty());
    let deadline = Instant::now() + Duration::from_secs(5);
    while owner().is_some() {
        assert!(
            Instant::now() < deadline,
            "the index owner the failed delete skipped was never released",
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // And the info-hash can be added again.
    let uri = format!("magnet:?xt=urn:btih:{}", hex(LOADED));
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "magnet", "uri": uri}}),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
    assert_eq!(h.state.registry.lookup(&LOADED), Some(ProfileId::new("p")));
}

#[tokio::test]
async fn a_retried_delete_with_delete_files_refuses_a_payload_the_removal_did_not_trash() {
    // A plain delete removed the torrent and failed to clear the assignment.
    // A retry asking for the payload too cannot reach it — no session holds
    // the torrent — so it refuses rather than answering 204 for files that
    // never moved, and a plain retry still clears it.
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
        s.pool = crate::pool_service::PoolService::open(&crate::config::Config::minimal_for_tests(
            dir.path(),
            true,
        ))
        .unwrap();
    });
    h.state.removed_unassigned.lock().insert(ADDING, false);
    let resp = h
        .write(
            "DELETE",
            &format!(
                "/v1/torrents/{}?delete_files=true&confirm={}",
                hex(ADDING),
                hex(ADDING)
            ),
        )
        .await;
    assert_problem(&resp, 409, "payload-untrashable");
    assert_eq!(h.state.registry.lookup(&ADDING), Some(ProfileId::new("p")));

    h.write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(h.state.registry.lookup(&ADDING), None);
    assert!(h.state.removed_unassigned.lock().is_empty());
}

#[tokio::test]
async fn a_delete_dropped_mid_call_still_clears_the_assignment() {
    // The torrent leaves its session whatever happens to the request; were
    // the assignment cleared only after the await, it would stay on a torrent
    // no session holds, and every later delete answer `409 torrent-adding`.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p)
    });
    let engine = engine.unwrap();
    let held = engine.hold_next("remove_torrent");
    drop_mid_call(
        h.write("DELETE", &format!("/v1/torrents/{}", hex(LOADED))),
        held,
    )
    .await;
    eventually("the removed torrent's assignment is cleared", || {
        h.state.registry.lookup(&LOADED).is_none()
    })
    .await;
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(LOADED)))
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
}

/// Hand `alert` to the alert handler as `profile`'s session would.
fn deliver(h: &Harness, profile: &str, alert: &torrentd_engine::Alert) {
    let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
    let clock = torrentd_engine::MockClock::new();
    let mut ctx = torrentd_engine::handlers::HandlerCtx {
        state: &h.state.state,
        resume: h.state.resume.as_ref(),
        torrents: h.state.torrents.as_ref(),
        metrics: &torrentd_engine::NoopSink,
        clock: &clock,
        engine: &engine,
        profile_fenced: None,
        fence_hold: None,
        profile_id: ProfileId::new(profile),
        span: tracing::info_span!("test"),
    };
    torrentd_engine::handlers::add::handle(alert, &mut ctx);
}

fn alert_header(
    kind: torrentd_engine::AlertKind,
    ih: InfoHash,
    handle: Option<TorrentHandle>,
) -> libtorrent_safe::alert::AlertHeader {
    libtorrent_safe::alert::AlertHeader {
        kind,
        infohash: Some(ih),
        handle,
        timestamp_us: 0,
    }
}

fn removed(ih: InfoHash) -> torrentd_engine::Alert {
    torrentd_engine::Alert::TorrentRemoved {
        hdr: alert_header(torrentd_engine::AlertKind::TorrentRemoved, ih, None),
    }
}

fn added(h: TorrentHandle) -> torrentd_engine::Alert {
    torrentd_engine::Alert::AddTorrent {
        hdr: alert_header(torrentd_engine::AlertKind::AddTorrent, h.infohash, Some(h)),
        error_code: 0,
        message: None,
    }
}

/// `DELETE` a loaded torrent, then `POST` the same `.torrent` to `to` before
/// the session's `torrent_removed_alert` for the old one is handled. Returns
/// the info-hash and the removed torrent's handle.
async fn delete_then_re_add(h: &Harness, e: &MockEngine, to: &str) -> (InfoHash, TorrentHandle) {
    let bytes = torrent_bytes('r');
    let ih = libtorrent_safe::info_hash_from_torrent(&bytes).unwrap();
    let old = load(&h.state, e, ih, "p", TorrentPhase::Seeding);
    let p = ProfileId::new("p");
    h.state.torrents.write(&p, &ih, &bytes).unwrap();
    h.state.torrents.write_save_path(&p, &ih, "/old").unwrap();

    h.write("DELETE", &format!("/v1/torrents/{}", hex(ih)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    h.write_json("POST", "/v1/torrents", metainfo(to, &bytes))
        .await
        .assert_status(StatusCode::CREATED);
    (ih, old)
}

/// The handle `e` gave the re-added torrent: the mock keys what it hands out
/// by the `.torrent`'s infohash, as a session does.
fn re_added_handle(e: &MockEngine, ih: InfoHash, old: TorrentHandle) -> TorrentHandle {
    let new = e.register_handle(ih);
    assert_ne!(new.id, old.id, "a distinct torrent");
    new
}

#[tokio::test]
async fn a_torrent_re_added_right_after_delete_keeps_its_files_and_entry() {
    // The documented recovery for a torrent reloaded at the wrong path,
    // scripted back to back: the old removal's alert used to delete the new
    // add's `.torrent` and save path, so the next boot reloaded it with no
    // metadata.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p)
    });
    let engine = engine.unwrap();
    let (ih, old) = delete_then_re_add(&h, &engine, "p").await;
    let new = re_added_handle(&engine, ih, old);

    // One session, so its alerts arrive in order: the removal, then the add.
    deliver(&h, "p", &removed(ih));
    deliver(&h, "p", &added(new));

    let p = ProfileId::new("p");
    assert_eq!(
        h.state.torrents.read(&p, &ih).unwrap(),
        Some(torrent_bytes('r'))
    );
    let save_path = dir.path().to_string_lossy().into_owned();
    assert_eq!(
        h.state.torrents.read_save_path(&p, &ih).unwrap(),
        Some(save_path),
        "the new add's save path, not the removed torrent's"
    );
    let st = h.state.state.get(&ih).expect("the new torrent is tracked");
    assert_eq!((st.handle, st.profile_id.clone()), (new, p.clone()));
    assert_eq!(h.state.registry.lookup(&ih).unwrap().as_str(), "p");
    assert!(
        h.state.resume.tombstones(&p).unwrap().is_empty(),
        "the removal's tombstone is spent, or the next boot deletes the re-add's files"
    );
}

#[tokio::test]
async fn delete_removes_the_stores_files_before_it_answers_and_the_removal_settles_its_tombstone() {
    // The files used to go only when the session's `torrent_removed_alert`
    // was handled, after the 204: a SIGKILL in between left the resume file
    // for the next boot to load the torrent from.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p)
    });
    let engine = engine.unwrap();
    let bytes = torrent_bytes('d');
    let ih = libtorrent_safe::info_hash_from_torrent(&bytes).unwrap();
    load(&h.state, &engine, ih, "p", TorrentPhase::Seeding);
    let p = ProfileId::new("p");
    h.state.torrents.write(&p, &ih, &bytes).unwrap();
    h.state.torrents.write_save_path(&p, &ih, "/old").unwrap();
    h.state.resume.write(&p, &ih, b"resume").unwrap();

    h.write("DELETE", &format!("/v1/torrents/{}", hex(ih)))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert!(!h.state.resume.exists(&p, &ih).unwrap());
    assert_eq!(h.state.torrents.read(&p, &ih).unwrap(), None);
    assert_eq!(h.state.torrents.read_save_path(&p, &ih).unwrap(), None);
    assert_eq!(
        h.state.resume.tombstones(&p).unwrap(),
        vec![ih],
        "the tombstone stands until the removal alert, the torrent's last"
    );

    // A resume save libtorrent queued before the removal lands after the
    // request's delete; the removal's handler deletes it and spends the
    // tombstone.
    h.state.resume.write(&p, &ih, b"late").unwrap();
    deliver(&h, "p", &removed(ih));
    assert!(!h.state.resume.exists(&p, &ih).unwrap());
    assert!(h.state.resume.tombstones(&p).unwrap().is_empty());
}

/// A resume store whose tombstone writes fail and whose files delete.
#[derive(Debug, Default)]
struct UntombstonableResume(torrentd_engine::MemoryResumeStore);
impl torrentd_engine::ResumeStore for UntombstonableResume {
    fn scan(
        &self,
        p: &ProfileId,
    ) -> Result<
        torrentd_engine::resume_store::Scan<libtorrent_safe::ResumeData>,
        torrentd_engine::resume_store::ResumeStoreError,
    > {
        self.0.scan(p)
    }
    fn write(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
        d: &[u8],
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        self.0.write(p, ih, d)
    }
    fn delete(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        self.0.delete(p, ih)
    }
    fn exists(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<bool, torrentd_engine::resume_store::ResumeStoreError> {
        self.0.exists(p, ih)
    }
    fn write_tombstone(
        &self,
        _: &ProfileId,
        _: &InfoHash,
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        Err(std::io::Error::from(std::io::ErrorKind::StorageFull).into())
    }
    fn clear_tombstone(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        self.0.clear_tombstone(p, ih)
    }
    fn tombstones(
        &self,
        p: &ProfileId,
    ) -> Result<Vec<InfoHash>, torrentd_engine::resume_store::ResumeStoreError> {
        self.0.tombstones(p)
    }
}

#[tokio::test]
async fn a_delete_whose_tombstone_write_fails_counts_it_and_still_answers_204() {
    // A full disk must not block a delete, which is often how an operator
    // frees space: the failed tombstone write is counted, and the request's
    // own deletes carry the durability.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p);
        s.resume = Arc::new(UntombstonableResume::default());
    });
    let engine = engine.unwrap();
    let bytes = torrent_bytes('t');
    let ih = libtorrent_safe::info_hash_from_torrent(&bytes).unwrap();
    load(&h.state, &engine, ih, "p", TorrentPhase::Seeding);
    let p = ProfileId::new("p");
    h.state.torrents.write(&p, &ih, &bytes).unwrap();
    h.state.torrents.write_save_path(&p, &ih, "/old").unwrap();
    h.state.resume.write(&p, &ih, b"resume").unwrap();

    h.write("DELETE", &format!("/v1/torrents/{}", hex(ih)))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert!(!h.state.resume.exists(&p, &ih).unwrap());
    assert_eq!(h.state.torrents.read(&p, &ih).unwrap(), None);
    assert_eq!(h.state.torrents.read_save_path(&p, &ih).unwrap(), None);
    assert!(h.state.resume.tombstones(&p).unwrap().is_empty());
    assert!(h.state.registry.lookup(&ih).is_none());
    let text = String::from_utf8(h.state.metrics.render()).unwrap();
    let counted: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("torrentd_torrent_remove_cleanup_errors_total{"))
        .collect();
    assert_eq!(
        counted,
        ["torrentd_torrent_remove_cleanup_errors_total{profile_id=\"p\",store=\"tombstone\"} 1"],
        "only the tombstone write failed: {text}"
    );
}

/// A resume store that cannot say whether it holds a file, until
/// `recovered` is set, and otherwise works.
#[derive(Debug, Default)]
struct UncheckableResume(
    torrentd_engine::MemoryResumeStore,
    std::sync::atomic::AtomicBool,
);

impl UncheckableResume {
    /// From now on, answer whether it holds a file.
    fn recover(&self) {
        self.1.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
impl torrentd_engine::ResumeStore for UncheckableResume {
    fn scan(
        &self,
        p: &ProfileId,
    ) -> Result<
        torrentd_engine::resume_store::Scan<libtorrent_safe::ResumeData>,
        torrentd_engine::resume_store::ResumeStoreError,
    > {
        self.0.scan(p)
    }
    fn write(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
        d: &[u8],
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        self.0.write(p, ih, d)
    }
    fn delete(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        self.0.delete(p, ih)
    }
    fn exists(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<bool, torrentd_engine::resume_store::ResumeStoreError> {
        if self.1.load(std::sync::atomic::Ordering::SeqCst) {
            return self.0.exists(p, ih);
        }
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
    }
    fn write_tombstone(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        self.0.write_tombstone(p, ih)
    }
    fn clear_tombstone(
        &self,
        p: &ProfileId,
        ih: &InfoHash,
    ) -> Result<(), torrentd_engine::resume_store::ResumeStoreError> {
        self.0.clear_tombstone(p, ih)
    }
    fn tombstones(
        &self,
        p: &ProfileId,
    ) -> Result<Vec<InfoHash>, torrentd_engine::resume_store::ResumeStoreError> {
        self.0.tombstones(p)
    }
}

#[tokio::test]
async fn an_unloaded_delete_whose_resume_store_cannot_answer_answers_500_and_changes_nothing() {
    // Whether the resume file is there decides whether the delete may clear
    // the claim (#354). A store that cannot say must not be read as "absent",
    // or a load failure becomes a lost torrent.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(UncheckableResume::default());
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
        s.resume = store.clone();
    });
    let p = ProfileId::new("p");
    // What the boot leaves for a claim none of its scans loaded.
    h.state.unloaded_at_boot.lock().insert(ADDING);
    h.state.resume.write(&p, &ADDING, b"resume-bytes").unwrap();
    h.state
        .torrents
        .write(&p, &ADDING, b"torrent-bytes")
        .unwrap();

    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await;
    assert_problem(&resp, 500, "internal");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(detail.contains("resume file"), "{detail}");
    assert!(detail.contains("Nothing was changed"), "{detail}");
    assert_eq!(h.state.registry.lookup(&ADDING), Some(p.clone()));
    assert!(
        h.state
            .resume
            .load_all(&p)
            .unwrap()
            .iter()
            .any(|(ih, _)| *ih == ADDING),
        "the resume file is kept"
    );
    assert!(h.state.torrents.exists(&p, &ADDING), "the .torrent is kept");

    // Still a boot leftover once the store answers again: the retry is
    // refused for the resume file it keeps, not taken for an add in flight.
    store.recover();
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await;
    assert_problem(&resp, 409, "torrent-unloaded");
}

#[tokio::test]
async fn an_unloaded_delete_whose_pool_index_cannot_be_read_keeps_a_resume_less_torrent() {
    // A `.torrent` with no resume file is cleared only where the pool index
    // records its adoption `drifted`. An index that cannot be read says
    // nothing of the kind, so the `.torrent` is what the next boot loads and
    // the delete refuses.
    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), true);
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
        s.pool = crate::pool_service::PoolService::open(&cfg).unwrap();
    });
    let p = ProfileId::new("p");
    h.state.unloaded_at_boot.lock().insert(ADDING);
    h.state
        .torrents
        .write(&p, &ADDING, b"torrent-bytes")
        .unwrap();
    h.state
        .pool
        .as_ref()
        .unwrap()
        .with_store_mut(|st| {
            st.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: hex(ADDING),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: "A".into(),
                    total_size: 1,
                    num_files: 1,
                    source_path: dir.path().join("a.torrent"),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: Some("p".into()),
                },
                0,
            )?;
            st.set_adoption(
                &hex(ADDING),
                torrentd_pool::AdoptionState::Drifted,
                None,
                None,
                None,
                Some(1),
                None,
            )
        })
        .unwrap();
    // The reader fails from here on, as on a corrupt or unreadable index.
    let index = rusqlite::Connection::open(cfg.pool_db_path()).unwrap();
    index
        .execute_batch("ALTER TABLE adoption RENAME TO adoption_unreadable")
        .unwrap();

    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await;
    assert_problem(&resp, 409, "torrent-unloaded");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(
        detail.contains(&format!("{}.torrent", hex(ADDING))),
        "{detail}"
    );
    assert_eq!(h.state.registry.lookup(&ADDING), Some(p.clone()));
    assert!(h.state.unloaded_at_boot.lock().contains(&ADDING));
    assert!(h.state.torrents.exists(&p, &ADDING), "the .torrent is kept");

    // The unreadable index is what refused: readable again, the `drifted`
    // record clears it.
    index
        .execute_batch("ALTER TABLE adoption_unreadable RENAME TO adoption")
        .unwrap();
    h.write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(h.state.registry.lookup(&ADDING).is_none());
    assert!(!h.state.torrents.exists(&p, &ADDING));
}

#[tokio::test]
async fn a_torrent_re_added_to_another_profile_right_after_delete_stays_tracked() {
    // Two sessions, whose alerts are handled on two loops: the new profile's
    // `AddTorrent` can be handled before the old one's `TorrentRemoved`, which
    // used to drop the new entry and leave the torrent untracked.
    let dir = tempfile::tempdir().unwrap();
    let mut engines = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        let e = fixture(s, dir.path());
        let q = Arc::new(MockEngine::new());
        s.profiles = Arc::new(ProfileRegistry::new(vec![
            test_entry("p", ProfileStatus::Active),
            ProfileEntry::new(
                test_entry("q", ProfileStatus::Active).config,
                q.clone(),
                None,
                None,
                0,
            ),
        ]));
        s.source = Arc::new(ProfileSource::new(vec![
            (ProfileId::new("p"), e.p.clone() as Arc<dyn TorrentEngine>),
            (ProfileId::new("q"), q.clone() as Arc<dyn TorrentEngine>),
        ]));
        engines = Some((e.p, q));
    });
    let (p_engine, q_engine) = engines.unwrap();
    let (ih, old) = delete_then_re_add(&h, &p_engine, "q").await;
    let new = re_added_handle(&q_engine, ih, old);

    deliver(&h, "q", &added(new));
    deliver(&h, "p", &removed(ih));

    let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
    let st = h
        .state
        .state
        .get(&ih)
        .expect("q's torrent is still tracked");
    assert_eq!((st.handle, st.profile_id), (new, q.clone()));
    assert_eq!(
        h.state.torrents.read(&q, &ih).unwrap(),
        Some(torrent_bytes('r'))
    );
    assert!(h.state.torrents.read_save_path(&q, &ih).unwrap().is_some());
    // The removed torrent's own files went with it.
    assert_eq!(h.state.torrents.read(&p, &ih).unwrap(), None);
    assert_eq!(h.state.torrents.read_save_path(&p, &ih).unwrap(), None);
}
