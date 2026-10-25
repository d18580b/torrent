//! Deleting a torrent the pool index knows: the owner record it releases, and
//! payload deletes that answer while a scan holds the writer.

use super::*;

#[tokio::test]
async fn a_delete_clears_the_pool_index_owner_it_set() {
    // Adoption refuses a torrent the index says another profile owns, so the
    // record has to go with the torrent, or it refuses every later adoption
    // into anything else.
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let index = Arc::clone(&pool);
    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));
    for (ih, owner, kept) in [(IH_A, "p", None), (IH_B, "q", Some("q"))] {
        let hash = libtorrent_safe::InfoHash::from_hex(ih).unwrap();
        h.state
            .registry
            .assign(hash, torrentd_engine::ProfileId::new("p"))
            .unwrap();
        h.state.unloaded_at_boot.lock().insert(hash);
        index.with_store(|st| st.set_profile(ih, Some(owner)).unwrap());
        let resp = h.write("DELETE", &format!("/v1/torrents/{ih}")).await;
        resp.assert_status(StatusCode::NO_CONTENT);
        assert_eq!(
            index.with_store(|st| st.profile_of(ih).unwrap()).as_deref(),
            kept,
            "a record naming {owner} after deleting p's torrent",
        );
    }
}

/// How long [`hold_writer_as_a_scan`] holds the writer at most. A handler
/// that waits on it on the test's current-thread runtime stalls every timer,
/// so a regression shows up as an answer later than this rather than a test
/// that never ends.
const SCAN_HOLD: std::time::Duration = std::time::Duration::from_secs(10);

/// Hold the writer inside a transaction, as a running scan does, until the
/// returned sender is used or dropped, or [`SCAN_HOLD`] passes.
fn hold_writer_as_a_scan(
    pool: &Arc<PoolService>,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let held = Arc::clone(pool);
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        held.with_store_mut(|st| {
            st.in_transaction(|_| {
                locked_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(SCAN_HOLD);
                Ok::<(), torrentd_pool::PoolError>(())
            })
        })
        .unwrap();
    });
    locked_rx.recv().unwrap();
    (release_tx, holder)
}

/// Issue #217: a delete of a loaded torrent answers while a scan holds the
/// writer. It used to wait out the scan to release the index's owner record,
/// after the torrent was already gone from the registry, so a client that
/// timed out and retried got `404` for a delete that had succeeded. The
/// release lands once the scan lets go.
#[tokio::test]
async fn a_delete_answers_while_a_scan_holds_the_writer_and_releases_the_owner_after() {
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let index = Arc::clone(&pool);
    let h = Harness::authed(&Coverage::new(), |s| {
        profiles(s);
        s.pool = Some(pool);
    });
    let hash = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    let p = torrentd_engine::ProfileId::new("p");
    h.state.registry.assign(hash, p.clone()).unwrap();
    h.state.state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle {
                id: 1,
                infohash: hash,
            },
            p,
            std::time::Instant::now(),
        ),
    );
    index.with_store(|st| st.set_profile(IH_A, Some("p")).unwrap());
    let owner = || index.with_reader(|st| st.profile_of(IH_A).unwrap());

    let (release, holder) = hold_writer_as_a_scan(&index);
    let asked = std::time::Instant::now();
    let resp = h.write("DELETE", &format!("/v1/torrents/{IH_A}")).await;
    assert!(
        asked.elapsed() < SCAN_HOLD / 2,
        "the delete waited {:?} on the writer",
        asked.elapsed(),
    );
    resp.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        h.state.registry.lookup(&hash),
        None,
        "the assignment is gone"
    );
    assert_eq!(
        owner().as_deref(),
        Some("p"),
        "the owner record waits for the writer",
    );

    release.send(()).unwrap();
    holder.join().unwrap();
    // Nothing else takes the writer: the release lands on its own.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while owner().is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "the owner record was never released once the writer was free",
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Issue #217: `delete_files`' co-claimant check reads the committed index,
/// so a refusal answers while a scan holds the writer rather than after it.
#[tokio::test]
async fn a_shared_payload_delete_is_refused_while_a_scan_holds_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), true);
    pool.with_store_mut(|st| {
        st.replace_claims(IH_B, &[(root_id, "movies/a.bin".to_owned())])
            .unwrap();
    });
    let index = Arc::clone(&pool);
    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));

    let (release, holder) = hold_writer_as_a_scan(&index);
    let asked = std::time::Instant::now();
    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{IH_A}?delete_files=true&confirm={IH_A}"),
        )
        .await;
    assert!(
        asked.elapsed() < SCAN_HOLD / 2,
        "the co-claimant check waited {:?} on the writer",
        asked.elapsed(),
    );
    assert_problem(&resp, 409, "payload-shared");
    release.send(()).unwrap();
    holder.join().unwrap();
}

/// The handler's early co-claimant check reads the committed index, which a
/// running scan can rewrite before it lets go of the writer. A cross-seed
/// that commits a claim on this torrent's files after that check, and before
/// the payload is proven, is refused there rather than having its files
/// moved to the trash.
#[tokio::test]
async fn a_co_claimant_committed_after_the_early_check_is_refused_before_the_trash() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), true);
    let index = Arc::clone(&pool);
    let engine = Arc::new(torrentd_engine::MockEngine::new());
    let hash = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    let p = torrentd_engine::ProfileId::new("p");
    let handle = engine.register_handle(hash);
    engine.set_torrent_details(
        handle,
        torrentd_engine::TorrentDetails {
            save_path: dir
                .path()
                .join("pool/movies")
                .to_string_lossy()
                .into_owned(),
            ..torrentd_engine::MockEngine::default_details()
        },
    );
    engine.set_torrent_files(
        handle,
        Some(
            ["a.bin", "b.bin"]
                .into_iter()
                .enumerate()
                .map(|(i, path)| torrentd_engine::TorrentFile {
                    index: u32::try_from(i).unwrap(),
                    path: path.into(),
                    size: 0,
                    downloaded: 0,
                    priority: 4,
                })
                .collect(),
        ),
    );
    let session = Arc::clone(&engine);
    let h = Harness::authed(&Coverage::new(), |s| {
        profiles(s);
        s.source = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            p.clone(),
            session as Arc<dyn torrentd_engine::TorrentEngine>,
        )]));
        s.pool = Some(pool);
    });
    h.state.registry.assign(hash, p.clone()).unwrap();
    h.state.state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(handle, p, std::time::Instant::now()),
    );

    // Park the delete just past the early check, commit the cross-seed's
    // claim as a scan ending then would, and let it go on to the writer.
    let held = engine.hold_next("torrent_files");
    let commit = tokio::task::spawn_blocking(move || {
        held.wait_entered();
        index.with_store_mut(|st| {
            st.replace_claims(IH_B, &[(root_id, "movies/a.bin".to_owned())])
                .unwrap();
        });
        held.release();
    });
    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{IH_A}?delete_files=true&confirm={IH_A}"),
        )
        .await;
    commit.await.unwrap();

    assert_problem(&resp, 409, "payload-shared");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(
        detail.contains(IH_B) && detail.contains("pool index"),
        "{detail}"
    );
    assert!(dir.path().join("pool/movies/a.bin").exists());
    assert!(dir.path().join("pool/movies/b.bin").exists());
    assert_eq!(
        h.state.registry.lookup(&hash),
        Some(torrentd_engine::ProfileId::new("p"))
    );
    assert!(
        !engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::RemoveTorrent { .. })),
        "a refused delete leaves the torrent in its session",
    );
}

/// Issue #292: a `delete_files` delete of a torrent whose payload is
/// provable answers while a scan holds the writer. Its proof read the claims
/// and every file's row on the writer, so it waited out the scan before
/// anything was removed.
#[tokio::test]
async fn a_provable_payload_delete_answers_while_a_scan_holds_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), true);
    let index = Arc::clone(&pool);
    let engine = Arc::new(torrentd_engine::MockEngine::new());
    let hash = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    let p = torrentd_engine::ProfileId::new("p");
    let handle = engine.register_handle(hash);
    let movies = dir.path().join("pool/movies");
    engine.set_torrent_details(
        handle,
        torrentd_engine::TorrentDetails {
            save_path: movies.to_string_lossy().into_owned(),
            ..torrentd_engine::MockEngine::default_details()
        },
    );
    engine.set_torrent_files(
        handle,
        Some(
            ["a.bin", "b.bin"]
                .into_iter()
                .enumerate()
                .map(|(i, path)| torrentd_engine::TorrentFile {
                    index: u32::try_from(i).unwrap(),
                    path: path.into(),
                    size: 0,
                    downloaded: 0,
                    priority: 4,
                })
                .collect(),
        ),
    );
    let session = Arc::clone(&engine);
    let h = Harness::authed(&Coverage::new(), |s| {
        profiles(s);
        s.source = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            p.clone(),
            session as Arc<dyn torrentd_engine::TorrentEngine>,
        )]));
        s.pool = Some(pool);
    });
    h.state.registry.assign(hash, p.clone()).unwrap();
    h.state.state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(handle, p, std::time::Instant::now()),
    );

    let (release, holder) = hold_writer_as_a_scan(&index);
    let asked = std::time::Instant::now();
    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{IH_A}?delete_files=true&confirm={IH_A}"),
        )
        .await;
    assert!(
        asked.elapsed() < SCAN_HOLD / 2,
        "the payload proof waited {:?} on the writer",
        asked.elapsed(),
    );
    resp.assert_status(StatusCode::NO_CONTENT);
    assert!(!movies.join("a.bin").exists() && !movies.join("b.bin").exists());
    let trash = dir.path().join("pool/.torrentd-trash");
    let bucket = std::fs::read_dir(&trash)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(bucket.len(), 1, "{bucket:?}");
    assert!(bucket[0].join("movies/a.bin").exists());
    assert!(bucket[0].join("movies/b.bin").exists());
    assert_eq!(
        h.state.registry.lookup(&hash),
        None,
        "the assignment is gone"
    );
    release.send(()).unwrap();
    holder.join().unwrap();
}
