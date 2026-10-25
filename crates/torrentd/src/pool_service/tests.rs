use std::time::Instant;

use torrentd_engine::InfoHash;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentState;

use crate::profile_registry::ProfileStatus;

/// Both adoption adds keep the torrent in upload mode, and the resume one
/// clears every flag another client's resume data could carry to lift it.
#[test]
fn both_adoption_adds_forbid_downloading() {
    use torrentd_engine::MockEngine;
    use torrentd_engine::ProfileConfig;
    use torrentd_engine::ProfileNetwork;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::TorrentEngine;

    let profile = ProfileConfig {
        id: ProfileId::new("public"),
        network: ProfileNetwork::Host {
            listen_interfaces: "0.0.0.0:6881".into(),
            dht: true,
        },
        peer_fingerprint: None,
        user_agent: None,
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    };
    let engine = MockEngine::new();
    engine
        .add_torrent(super::verify_add_params(
            &profile,
            vec![1; 32],
            "/p".into(),
            Vec::new(),
        ))
        .unwrap();
    engine
        .add_torrent(super::adoption_resume_params(
            &profile,
            // Resume data libtorrent reads: the add refuses anything else.
            b"d11:file-format22:libtorrent resume file12:file-versioni1e\
                  9:info-hash20:\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\
                  \x02\x02\x02\x02\x02\x02\x02\x02\x02\x02e"
                .to_vec(),
            None,
            "/p".into(),
        ))
        .unwrap();
    let adds: Vec<_> = engine
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            RecordedCall::AddTorrent(a) => Some(a),
            _ => None,
        })
        .collect();
    assert_eq!(adds.len(), 2);
    for a in &adds {
        assert!(a.forbids_downloading(), "{a:?}");
    }
    assert!(adds[1]
        .flags_clear()
        .contains(torrentd_engine::TorrentFlags::PAUSED));
}

#[test]
fn a_scan_counts_its_errors_by_kind() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    let metrics = std::sync::Arc::new(crate::metrics_sink::PromSink::new());
    pool.set_metrics(metrics.clone());
    std::fs::create_dir_all(dir.path().join("library")).unwrap();
    std::fs::write(dir.path().join("library/broken.torrent"), b"not bencode").unwrap();

    let summary = pool.scan().unwrap();

    assert_eq!(summary.errors, 1);
    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(
        text.contains("torrentd_pool_scan_errors_total{kind=\"parse\"} 1"),
        "{text}"
    );
}

/// The daemon's scan keeps a torrent its sessions serve in the index after
/// its `.torrent` leaves the library, whatever its adoption state.
#[test]
fn a_scan_keeps_a_loaded_torrent_gone_from_the_library() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    let library = dir.path().join("library");
    std::fs::create_dir_all(&library).unwrap();
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../torrentd-pool/tests/fixtures/pad_file.torrent"),
        library.join("pad_file.torrent"),
    )
    .unwrap();
    pool.scan().unwrap();
    let ih = pool.with_store(|s| s.torrents().unwrap())[0]
        .infohash
        .clone();

    let state = std::sync::Arc::new(torrentd_engine::StateMap::new());
    let hash = InfoHash::from_hex(&ih).unwrap();
    state.insert(
        hash,
        TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: hash,
            },
            ProfileId::new("p"),
            Instant::now(),
        ),
    );
    pool.set_state(state.clone());
    std::fs::remove_file(library.join("pad_file.torrent")).unwrap();
    pool.scan().unwrap();
    assert!(pool.with_store(|s| s.torrent(&ih).unwrap()).is_some());

    state.remove(&hash, &ProfileId::new("p"), None);
    pool.scan().unwrap();
    assert!(pool.with_store(|s| s.torrent(&ih).unwrap()).is_none());
}

/// The daemon's scan places a loaded torrent where its session holds it,
/// not where the index recorded it, when both copies are complete.
#[test]
fn a_scan_places_a_loaded_torrent_at_its_session_save_path() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    let root = dir.path().join("pool");
    std::fs::create_dir_all(root.join("seed")).unwrap();
    std::fs::write(root.join("a"), b"x").unwrap();
    std::fs::write(root.join("seed/a"), b"x").unwrap();
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    std::fs::write(dir.path().join("library/t.torrent"), &bare).unwrap();
    let hash = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
    let ih = hash.to_hex();
    pool.scan().unwrap();
    let root_id = pool.roots()[0].0;
    // Recorded at the copy under `seed`.
    pool.with_store_mut(|s| {
        s.set_adoption(
            &ih,
            super::AdoptionState::Adopted,
            Some(root_id),
            Some("seed"),
            Some(1),
            None,
            None,
        )
    })
    .unwrap();

    // The session reads from the root.
    let mock = std::sync::Arc::new(torrentd_engine::MockEngine::new());
    let handle = mock.register_handle(hash);
    mock.set_torrent_details(
        handle,
        libtorrent_safe::TorrentDetails {
            save_path: root.to_string_lossy().into_owned(),
            ..torrentd_engine::MockEngine::default_details()
        },
    );
    let engine: std::sync::Arc<dyn torrentd_engine::TorrentEngine> = mock;
    let state = std::sync::Arc::new(torrentd_engine::StateMap::new());
    state.insert(
        hash,
        TorrentState::newly_added(handle, ProfileId::new("p"), Instant::now()),
    );
    pool.set_state(state);

    // Without the sessions to ask, the recorded base stands.
    pool.scan().unwrap();
    assert_eq!(
        pool.with_store(|s| s.adoption_base(&ih).unwrap()),
        Some((root_id, "seed".to_owned()))
    );

    pool.set_source(std::sync::Arc::new(torrentd_engine::ProfileSource::new(
        vec![(ProfileId::new("p"), engine)],
    )));
    pool.scan().unwrap();
    assert_eq!(
        pool.with_store(|s| s.adoption_base(&ih).unwrap()),
        Some((root_id, String::new()))
    );
    assert_eq!(
        pool.with_store(|s| s.adoption_state(&ih).unwrap()),
        Some(super::AdoptionState::Adopted)
    );
    let orphans = pool.with_store(|s| s.orphan_files(root_id, "").unwrap());
    assert_eq!(orphans, vec!["seed/a".to_owned()]);
}

/// `torrent` with an unknown top-level key holding a cap's worth of
/// bytes put in front: the same torrent to a parser, past the library
/// read cap, so only the cap keeps it from being read whole.
pub(crate) fn padded_past_the_cap(torrent: &[u8]) -> Vec<u8> {
    let pad = torrentd_pool::scan::MAX_LIBRARY_FILE_BYTES as usize;
    let mut big = format!("d1:a{pad}:").into_bytes();
    big.resize(big.len() + pad, 0);
    big.extend_from_slice(&torrent[1..]);
    assert_eq!(
        libtorrent_safe::info_hashes_from_torrent(&big).unwrap(),
        libtorrent_safe::info_hashes_from_torrent(torrent).unwrap(),
    );
    big
}

pub(crate) fn pending(ih: InfoHash, profile: &str) -> super::PendingVerify {
    super::PendingVerify {
        infohash: ih.to_hex(),
        torrent_path: "/nonexistent.torrent".into(),
        save_path: "/nonexistent".into(),
        profile: ProfileId::new(profile),
        owner_recorded: false,
        trackers: Vec::new(),
    }
}

/// A pool index holding one torrent, `ih`, owned by `owner`.
pub(crate) fn pool_with(
    dir: &std::path::Path,
    ih: InfoHash,
    owner: Option<&str>,
) -> super::PoolService {
    let cfg = crate::config::Config::minimal_for_tests(dir, false);
    let pool =
        std::sync::Arc::into_inner(super::PoolService::open(&cfg).unwrap().unwrap()).unwrap();
    let hex = ih.to_hex();
    let row = torrentd_pool::PoolTorrent {
        infohash: hex.clone(),
        infohash_v1: None,
        infohash_v2: None,
        name: "t".into(),
        total_size: 1,
        num_files: 1,
        source_path: dir.join("t.torrent"),
        fastresume_path: None,
        declared_save_path: None,
        category: None,
        tags: vec![],
        profile: None,
    };
    pool.with_store(|s| {
        s.upsert_torrent(&row, 0).unwrap();
        s.set_profile(&hex, owner).unwrap();
    });
    pool
}

#[test]
fn a_release_deferred_behind_the_writer_lands_before_the_next_takers_work() {
    // An adoption that takes the writer after a `DELETE` answered must
    // find the owner record the delete released, not the one it left
    // queued: otherwise the release would land after the adoption and
    // clear the owner it just wrote.
    let dir = tempfile::tempdir().unwrap();
    let ih = InfoHash([0x91; 20]);
    let pool = std::sync::Arc::new(pool_with(dir.path(), ih, Some("p")));
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let pool = std::sync::Arc::clone(&pool);
        std::thread::spawn(move || {
            let _store = pool.store.lock();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        })
    };
    held_rx.recv().unwrap();

    pool.release_owner_soon(ih.to_hex(), "p".into(), false);
    // A second release while the first is queued is applied with it.
    pool.release_owner_soon(ih.to_hex(), "q".into(), false);
    assert_eq!(
        pool.with_reader(|s| s.profile_of(&ih.to_hex()).unwrap())
            .as_deref(),
        Some("p"),
        "the release waits for the writer",
    );

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(
        pool.with_store(|s| s.profile_of(&ih.to_hex()).unwrap()),
        None,
        "the next taker of the writer saw the record already released",
    );
    assert!(pool.deferred_releases.lock().is_empty());
}

/// A pool index over `dir` holding one complete, adopted torrent owned by
/// profile `p`, with a registry handed over as the daemon hands the
/// boot's, assigning the torrent to `claim` or to nobody.
fn adopted_by_p(
    dir: &std::path::Path,
    claim: Option<&str>,
) -> (std::sync::Arc<super::PoolService>, InfoHash) {
    let cfg = crate::config::Config::minimal_for_tests(dir, false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    std::fs::create_dir_all(dir.join("pool")).unwrap();
    std::fs::write(dir.join("pool/a"), b"x").unwrap();
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    std::fs::write(dir.join("library/t.torrent"), &bare).unwrap();
    let ih = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
    pool.scan().unwrap();
    let hex = ih.to_hex();
    pool.with_store(|s| {
        let (r, b) = s.adoption_base(&hex).unwrap().unwrap();
        s.set_adoption(
            &hex,
            super::AdoptionState::Adopted,
            Some(r),
            Some(&b),
            Some(1),
            None,
            None,
        )
        .unwrap();
        s.set_profile(&hex, Some("p")).unwrap();
    });
    let registry = super::AssignmentRegistry::new_empty(dir.join("registry.db"));
    if let Some(claimant) = claim {
        registry.assign(ih, ProfileId::new(claimant)).unwrap();
    }
    pool.set_registry(std::sync::Arc::new(registry));
    (pool, ih)
}

fn adopt_plan(pool: &super::PoolService, ih: InfoHash) -> super::AdoptPlan {
    let roots = pool.roots().to_vec();
    pool.with_store(|s| {
        torrentd_pool::adopt::plan(s, &ih.to_hex(), |id| {
            roots.iter().find(|(r, _)| *r == id).map(|(_, p)| p.clone())
        })
        .unwrap()
    })
}

/// A `DELETE`'s release queued behind a held writer, then a restart
/// before the writer was free: the new daemon's boot clears the owner
/// record the lost release left, and the `adopted` verdict with it.
#[test]
fn a_release_lost_to_a_restart_is_reconciled_at_boot() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ih) = adopted_by_p(dir.path(), None);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let pool = std::sync::Arc::clone(&pool);
        std::thread::spawn(move || {
            let _store = pool.store.lock();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        })
    };
    held_rx.recv().unwrap();
    pool.release_owner_soon(ih.to_hex(), "p".into(), false);
    // The daemon stops before the writer is free: the queue dies with it.
    pool.deferred_releases.lock().clear();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

    // The restart: a new service over the same `pool.db`.
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let reopened = super::PoolService::open(&cfg).unwrap().unwrap();
    reopened.set_registry(std::sync::Arc::new(super::AssignmentRegistry::new_empty(
        dir.path().join("registry.db"),
    )));
    assert_eq!(
        reopened.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
        Some(super::AdoptionState::Adopted),
    );
    let cleared = reopened
        .clear_unbacked_owners(&torrentd_engine::StateMap::new())
        .unwrap();
    assert_eq!(cleared, vec![(ih.to_hex(), "p".to_owned())]);
    assert_eq!(owner_of(&reopened, ih), None);
    assert_eq!(
        reopened.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
        Some(super::AdoptionState::Matched),
    );
    // A rescan keeps it adoptable.
    reopened.set_state(std::sync::Arc::new(torrentd_engine::StateMap::new()));
    reopened.scan().unwrap();
    assert_eq!(
        reopened.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
        Some(super::AdoptionState::Matched),
    );
}

/// An owner record no registry claim, session or verify item backs is
/// cleared at boot, and adoption then plans the torrent instead of
/// refusing it as already adopted.
#[test]
fn the_boot_clears_an_owner_record_nothing_backs_so_adoption_accepts_it() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ih) = adopted_by_p(dir.path(), None);
    assert!(matches!(
        adopt_plan(&pool, ih),
        super::AdoptPlan::Refuse {
            reason: "already adopted"
        }
    ));

    let cleared = pool
        .clear_unbacked_owners(&torrentd_engine::StateMap::new())
        .unwrap();
    assert_eq!(cleared.len(), 1);
    assert_eq!(owner_of(&pool, ih), None);
    let plan = adopt_plan(&pool, ih);
    assert!(!plan.is_refusal(), "{plan:?}");
}

/// An owner record a registry claim, a session or a verify item backs
/// stands, and so does every record where no registry is set.
#[test]
fn the_boot_leaves_an_owner_record_something_backs() {
    let empty = torrentd_engine::StateMap::new();

    // A registry claim, under the record's profile or another's.
    for claimant in ["p", "q"] {
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), Some(claimant));
        assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
        assert_eq!(
            pool.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
            Some(super::AdoptionState::Adopted),
        );
    }

    // A session holding it.
    let dir = tempfile::tempdir().unwrap();
    let (pool, ih) = adopted_by_p(dir.path(), None);
    let state = torrentd_engine::StateMap::new();
    state.insert(
        ih,
        TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: ih,
            },
            ProfileId::new("p"),
            Instant::now(),
        ),
    );
    assert!(pool.clear_unbacked_owners(&state).unwrap().is_empty());
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

    // A verify item, in memory or in `pool.db`.
    let dir = tempfile::tempdir().unwrap();
    let (pool, ih) = adopted_by_p(dir.path(), None);
    pool.verify_queue().enqueue(pending(ih, "p"));
    assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
    let dir = tempfile::tempdir().unwrap();
    let (pool, ih) = adopted_by_p(dir.path(), None);
    pool.with_store(|s| s.enqueue_verify(&pending(ih, "p").to_row()))
        .unwrap();
    assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

    // No registry set: nothing can tell, so nothing is cleared.
    let dir = tempfile::tempdir().unwrap();
    let ih = InfoHash([0x93; 20]);
    let pool = pool_with(dir.path(), ih, Some("p"));
    assert!(pool.clear_unbacked_owners(&empty).unwrap().is_empty());
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
}

/// An owner record naming `p` where the registry gives the torrent to
/// `q` is rewritten to `q` at boot, so a `DELETE` from `q` releases it and
/// a later adoption plans the torrent instead of refusing it.
#[test]
fn the_boot_rewrites_an_owner_record_the_registry_contradicts() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ih) = adopted_by_p(dir.path(), Some("q"));
    assert!(!pool.with_store_mut(|s| s.release_owner(&ih.to_hex(), "q", false).unwrap()));

    let rewritten = pool.follow_registry_owners().unwrap();
    assert_eq!(
        rewritten,
        vec![(ih.to_hex(), "q".to_owned(), "p".to_owned())]
    );
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("q"));
    assert!(
        pool.follow_registry_owners().unwrap().is_empty(),
        "nothing disagrees any more",
    );

    assert!(pool.with_store_mut(|s| s.release_owner(&ih.to_hex(), "q", false).unwrap()));
    assert_eq!(owner_of(&pool, ih), None);
    assert_eq!(
        pool.with_store(|s| s.adoption_state(&ih.to_hex()).unwrap()),
        Some(super::AdoptionState::Matched),
    );
    let plan = adopt_plan(&pool, ih);
    assert!(!plan.is_refusal(), "{plan:?}");
}

/// The boot's reconciliation clears a record nothing backs, rewrites one
/// the registry contradicts, and reports no disagreement left behind.
#[test]
fn the_boot_reconciliation_clears_rewrites_and_reports_what_still_disagrees() {
    for (claim, owner) in [(None, None), (Some("q"), Some("q"))] {
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), claim);
        let registry = super::AssignmentRegistry::new_empty(dir.path().join("boot.db"));
        if let Some(claimant) = claim {
            registry.assign(ih, ProfileId::new(claimant)).unwrap();
        }
        let metrics = torrentd_engine::RecordingSink::new();

        pool.reconcile_owners_at_boot(&torrentd_engine::StateMap::new(), &registry, &metrics);

        assert_eq!(owner_of(&pool, ih).as_deref(), owner, "claim {claim:?}");
        let gauges: Vec<f64> = metrics
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                torrentd_engine::metrics::MetricCall::SetGauge { name, value, .. }
                    if name == "pool_index_profile_disagreements" =>
                {
                    Some(value)
                }
                _ => None,
            })
            .collect();
        assert_eq!(gauges, [0.0], "claim {claim:?}");
    }
}

/// A record the registry agrees with, or does not mention, is left
/// alone, as is every record where no registry is set.
#[test]
fn the_boot_rewrites_no_owner_record_the_registry_does_not_contradict() {
    for claim in [Some("p"), None] {
        let dir = tempfile::tempdir().unwrap();
        let (pool, ih) = adopted_by_p(dir.path(), claim);
        assert!(pool.follow_registry_owners().unwrap().is_empty());
        assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
    }
    let dir = tempfile::tempdir().unwrap();
    let ih = InfoHash([0x94; 20]);
    let pool = pool_with(dir.path(), ih, Some("p"));
    assert!(pool.follow_registry_owners().unwrap().is_empty());
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
}

pub(crate) fn owner_of(pool: &super::PoolService, ih: InfoHash) -> Option<String> {
    pool.with_store(|s| s.profile_of(&ih.to_hex()).unwrap())
}

/// The in-memory verify queue alone makes a torrent owned: an item
/// waiting or in flight with no registry claim, no `pool.db` row, and no
/// index owner is still refused by a relocate and kept by a delete plan.
#[test]
fn the_in_memory_verify_queue_alone_makes_a_torrent_owned() {
    let dir = tempfile::tempdir().unwrap();
    let waiting = InfoHash::from_hex(&"a1".repeat(20)).unwrap();
    let flying = InfoHash::from_hex(&"b2".repeat(20)).unwrap();
    let pool = pool_with(dir.path(), waiting, None);
    let state = torrentd_engine::StateMap::new();

    assert_eq!(pool.unloaded_owner(&waiting.to_hex()).unwrap(), None);
    assert_eq!(pool.unloaded_owner(&flying.to_hex()).unwrap(), None);
    assert!(pool.owned_infohashes(&state).unwrap().is_empty());

    pool.verify_queue().enqueue(pending(waiting, "p"));
    pool.verify_queue().track_in_flight(flying.to_hex());
    assert!(pool.with_store(|s| s.verify_queue().unwrap()).is_empty());

    for ih in [waiting, flying] {
        let why = pool.unloaded_owner(&ih.to_hex()).unwrap();
        assert_eq!(why.as_deref(), Some("it is waiting in the verify queue"));
    }
    let owned = pool.owned_infohashes(&state).unwrap();
    assert_eq!(owned, vec![waiting.to_hex(), flying.to_hex()]);
}

/// The enqueue reads the `.fastresume`'s trackers into the item, so the
/// worker adds with them; on a profile with an allow-list it holds a
/// tracker-less `.torrent` to them, and admits it.
#[test]
fn the_enqueue_carries_the_fastresumes_trackers_to_the_worker() {
    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let ih = InfoHash([0x56; 20]);
    let pool = pool_with(dir.path(), ih, None);
    let mut acct = test_entry("acct", ProfileStatus::Active);
    acct.config.allowed_tracker_domains = vec!["allowed.example".to_owned()];
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active), acct]);
    let torrent = dir.path().join("t.torrent");
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    std::fs::write(&torrent, bare).unwrap();
    let resume = dir.path().join("t.fastresume");
    std::fs::write(
        &resume,
        "d8:trackersll39:http://tracker.allowed.example/announceeee",
    )
    .unwrap();
    let want = vec![vec!["http://tracker.allowed.example/announce".to_owned()]];

    for profile in ["p", "acct"] {
        super::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            torrent.clone(),
            dir.path().join("payload"),
            Some(&resume),
            ProfileId::new(profile),
            false,
        )
        .unwrap_or_else(|e| panic!("{profile}: {}", e.reason));
        let item = pool.verify_queue().pop_pending().unwrap();
        assert_eq!(item.trackers, want, "{profile}");
        pool.with_store(|s| s.set_profile(&ih.to_hex(), None).unwrap());
    }

    // Without the `.fastresume`, the allow-list refuses it for having
    // no tracker at all.
    let e = super::enqueue_verify(
        &pool,
        &profiles,
        &ih.to_hex(),
        torrent.clone(),
        dir.path().join("payload"),
        None,
        ProfileId::new("acct"),
        false,
    )
    .unwrap_err();
    assert!(e.isolation);
    assert!(e.reason.contains("no tracker"), "{}", e.reason);

    // Issue #543: past the library read cap the `.torrent` is not read,
    // so the allow-list cannot pass it, its trackers allowed or not.
    let bare = std::fs::read(&torrent).unwrap();
    std::fs::write(&torrent, padded_past_the_cap(&bare)).unwrap();
    let e = super::enqueue_verify(
        &pool,
        &profiles,
        &ih.to_hex(),
        torrent,
        dir.path().join("payload"),
        Some(&resume),
        ProfileId::new("acct"),
        false,
    )
    .unwrap_err();
    assert!(
        e.reason.contains("cannot read the .torrent"),
        "{}",
        e.reason
    );
    assert!(pool.verify_queue().pop_pending().is_none());
}

/// `execute_adopt` hands the verify queue the `.fastresume` the scan
/// paired, both from a verify plan and when the fast path's add is
/// rejected and falls back to verifying, so either announces to its
/// trackers.
#[test]
fn an_adopt_that_verifies_carries_the_paired_fastresumes_trackers() {
    use torrentd_engine::AlertSource;
    use torrentd_engine::MockEngine;
    use torrentd_engine::TorrentEngine;

    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    std::fs::write(dir.path().join("pool/a"), b"x").unwrap();
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    std::fs::write(dir.path().join("library/t.torrent"), bare).unwrap();
    // `pieces` is the bitfield the fast path trusts: one piece had, or not.
    let resume = |had: u8| {
        let mut b = b"d6:pieces1:".to_vec();
        b.push(had);
        b.extend_from_slice(b"8:trackersll39:http://tracker.allowed.example/announceeee");
        std::fs::write(dir.path().join("library/t.fastresume"), b).unwrap();
    };
    let want = vec![vec!["http://tracker.allowed.example/announce".to_owned()]];
    resume(0);
    pool.scan().unwrap();
    let ih = pool.with_store(|s| s.torrents().unwrap())[0]
        .infohash
        .clone();

    let engine = std::sync::Arc::new(MockEngine::new());
    let source: std::sync::Arc<dyn AlertSource> =
        std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
        )]));
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    let adopt = || {
        super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), false)
            .unwrap_or_else(|e| panic!("{}", e.reason))
    };

    // Incomplete: planned as a verify.
    assert_eq!(adopt(), super::Adopted::QueuedForVerification);
    let item = pool.verify_queue().pop_pending().unwrap();
    assert_eq!(item.trackers, want);
    assert!(engine.calls().is_empty(), "{:?}", engine.calls());

    // Complete: the fast path adds, the add is rejected, and it falls
    // back to verifying.
    resume(1);
    engine.inject_error("add_torrent", torrentd_engine::EngineError::Shutdown);
    assert_eq!(adopt(), super::Adopted::QueuedForVerification);
    assert_eq!(engine.calls().len(), 1, "{:?}", engine.calls());
    let item = pool.verify_queue().pop_pending().unwrap();
    assert_eq!(item.trackers, want);
}

/// A fast-path adopt writes the `.torrent` it handed the session to the
/// profile's torrent store, which the resume scan re-attaches metadata
/// from; and the library's copy is offered as the scan's fallback only
/// while it still describes the torrent.
#[test]
fn a_fast_path_adopt_persists_its_torrent_and_the_library_backs_it() {
    use torrentd_engine::AlertSource;
    use torrentd_engine::MockEngine;
    use torrentd_engine::TorrentEngine;
    use torrentd_engine::TorrentStore;

    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    let store = std::sync::Arc::new(torrentd_engine::MemoryTorrentStore::new());
    pool.set_torrent_store(store.clone());
    std::fs::write(dir.path().join("pool/a"), b"x").unwrap();
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    std::fs::write(dir.path().join("library/t.torrent"), &bare).unwrap();
    // One piece had: the fast path. In libtorrent's own format, with the
    // info-hash it requires: the session's add, and the mock's, refuse
    // resume data short of that.
    let mut fastresume =
        b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
    fastresume.extend_from_slice(&libtorrent_safe::info_hash_from_torrent(&bare).unwrap().0);
    fastresume.extend_from_slice(b"6:pieces1:\x01e");
    std::fs::write(dir.path().join("library/t.fastresume"), &fastresume).unwrap();
    pool.scan().unwrap();
    let ih = pool.with_store(|s| s.torrents().unwrap())[0]
        .infohash
        .clone();
    let hash = InfoHash::from_hex(&ih).unwrap();

    let engine = std::sync::Arc::new(MockEngine::new());
    let source: std::sync::Arc<dyn AlertSource> =
        std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
        )]));
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    let adopted = super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), false)
        .unwrap_or_else(|e| panic!("{}", e.reason));
    assert_eq!(adopted, super::Adopted::FastPath);
    assert_eq!(
        store.read(&ProfileId::new("p"), &hash).unwrap().as_deref(),
        Some(bare.as_slice()),
    );
    // Beside it, the library path the session was handed, which the
    // torrent-dir scan re-adds it at if its resume file is lost.
    let handed = engine
        .calls()
        .into_iter()
        .find_map(|c| match c {
            torrentd_engine::RecordedCall::AddTorrent(
                torrentd_engine::mock::AddParamsSummary::Resume { save_path, .. },
            ) => save_path,
            _ => None,
        })
        .expect("the fast path adds from resume data at a save path");
    assert_eq!(
        handed,
        dir.path().join("pool").to_string_lossy(),
        "the adopt hands the session the library root's path",
    );
    assert_eq!(
        store
            .read_save_path(&ProfileId::new("p"), &hash)
            .unwrap()
            .as_deref(),
        Some(handed.as_str()),
    );

    assert_eq!(
        pool.library_torrent(&hash).as_deref(),
        Some(bare.as_slice())
    );
    // Replaced in the library by another torrent since the index was
    // written: not this one's metadata.
    let mut other = b"d4:infod6:lengthi1e4:name1:b12:piece lengthi16384e6:pieces20:".to_vec();
    other.extend_from_slice(&[0u8; 20]);
    other.extend_from_slice(b"ee");
    std::fs::write(dir.path().join("library/t.torrent"), other).unwrap();
    assert_eq!(pool.library_torrent(&hash), None);
    assert_eq!(pool.library_torrent(&InfoHash([0x77; 20])), None);
}

/// A library over `dir` whose one torrent's `.torrent` and `.fastresume`
/// the scan indexed and paired for a fast-path adopt into `p`, with the
/// engine that adopt adds to.
pub(crate) fn fast_path_library(
    dir: &std::path::Path,
) -> (
    std::sync::Arc<super::PoolService>,
    String,
    std::sync::Arc<torrentd_engine::MockEngine>,
    std::sync::Arc<dyn torrentd_engine::AlertSource>,
) {
    use torrentd_engine::MockEngine;
    use torrentd_engine::TorrentEngine;

    let cfg = crate::config::Config::minimal_for_tests(dir, false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    pool.set_torrent_store(std::sync::Arc::new(
        torrentd_engine::MemoryTorrentStore::new(),
    ));
    std::fs::write(dir.join("pool/a"), b"x").unwrap();
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    std::fs::write(dir.join("library/t.torrent"), &bare).unwrap();
    let mut fastresume =
        b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
    fastresume.extend_from_slice(&libtorrent_safe::info_hash_from_torrent(&bare).unwrap().0);
    fastresume.extend_from_slice(b"6:pieces1:\x01e");
    std::fs::write(dir.join("library/t.fastresume"), &fastresume).unwrap();
    pool.scan().unwrap();
    let ih = pool.with_store(|s| s.torrents().unwrap())[0]
        .infohash
        .clone();
    let engine = std::sync::Arc::new(MockEngine::new());
    let source: std::sync::Arc<dyn torrentd_engine::AlertSource> =
        std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
        )]));
    (pool, ih, engine, source)
}

/// Issue #543: a `.torrent` the library has grown past the read cap
/// since the scan is not read whole. The plan cannot hold the resume
/// data to metadata it did not read, so the adopt verifies instead of
/// adding; and the file is not offered as the resume scan's fallback.
#[test]
fn an_adopt_does_not_read_a_torrent_past_the_cap() {
    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let (pool, ih, engine, source) = fast_path_library(dir.path());
    let torrent = dir.path().join("library/t.torrent");
    std::fs::write(
        &torrent,
        padded_past_the_cap(&std::fs::read(&torrent).unwrap()),
    )
    .unwrap();
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);

    let adopted = super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), false)
        .unwrap_or_else(|e| panic!("{}", e.reason));
    assert_eq!(adopted, super::Adopted::QueuedForVerification);
    assert!(engine.calls().is_empty(), "{:?}", engine.calls());
    assert_eq!(
        pool.library_torrent(&InfoHash::from_hex(&ih).unwrap()),
        None
    );
}

/// Persisting an adopted torrent writes its save path and trackers, then
/// its `.torrent`; a store that refuses all three counts each failure.
#[test]
fn persisting_an_adopted_torrent_counts_each_failed_write() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let p = ProfileId::new("p");
    let hash = InfoHash([0x5b; 20]);

    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    let metrics = std::sync::Arc::new(crate::metrics_sink::PromSink::new());
    pool.set_metrics(metrics.clone());
    // A torrent store whose base is a regular file: every write fails.
    std::fs::write(dir.path().join("blocker"), b"not a directory").unwrap();
    pool.set_torrent_store(std::sync::Arc::new(torrentd_engine::FsTorrentStore::new(
        dir.path().join("blocker"),
    )));
    pool.persist_torrent(
        &p,
        &hash.to_hex(),
        b"d4:infode",
        "/pool/lib",
        &[vec!["https://t.example/announce".into()]],
    );
    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(
        text.contains(
            "torrentd_torrent_file_persist_errors_total{profile_id=\"p\",source=\"api\"} 3"
        ),
        "{text}"
    );
}

/// A relocation rewrites the save path recorded beside the `.torrent`,
/// which the boot scan re-adds a torrent at when its resume file is
/// lost; a write that fails is counted, and the move still stands.
#[test]
fn a_relocated_torrent_records_its_new_save_path() {
    use torrentd_engine::TorrentStore;

    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let p = ProfileId::new("p");
    let hash = InfoHash([0x5a; 20]);

    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    let store = std::sync::Arc::new(torrentd_engine::MemoryTorrentStore::new());
    pool.set_torrent_store(store.clone());
    store.write_save_path(&p, &hash, "/pool/old").unwrap();
    pool.record_save_path(&p, &hash.to_hex(), "/pool/new/place");
    assert_eq!(
        store.read_save_path(&p, &hash).unwrap().as_deref(),
        Some("/pool/new/place"),
    );

    // A torrent store whose base is a regular file: every write fails.
    drop(pool);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    let metrics = std::sync::Arc::new(crate::metrics_sink::PromSink::new());
    pool.set_metrics(metrics.clone());
    std::fs::write(dir.path().join("blocker"), b"not a directory").unwrap();
    pool.set_torrent_store(std::sync::Arc::new(torrentd_engine::FsTorrentStore::new(
        dir.path().join("blocker"),
    )));
    pool.record_save_path(&p, &hash.to_hex(), "/pool/new/place");
    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(
        text.contains(
            "torrentd_torrent_file_persist_errors_total{profile_id=\"p\",source=\"api\"} 1"
        ),
        "{text}"
    );
}

/// Payload rewritten in place at the same size after the scan still
/// matches the index's sizes, so the fast path would trust the previous
/// client's "complete" for it. The drift pass every adopt runs first is
/// what sends it to verification instead.
#[test]
fn the_drift_pass_before_an_adopt_takes_rewritten_payload_off_the_fast_path() {
    use torrentd_engine::AlertSource;
    use torrentd_engine::MockEngine;
    use torrentd_engine::TorrentEngine;

    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = super::PoolService::open(&cfg).unwrap().unwrap();
    std::fs::write(dir.path().join("pool/a"), b"x").unwrap();
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    std::fs::write(dir.path().join("library/t.torrent"), &bare).unwrap();
    std::fs::write(dir.path().join("library/t.fastresume"), b"d6:pieces1:\x01e").unwrap();
    pool.scan().unwrap();
    let ih = pool.with_store(|s| s.torrents().unwrap())[0]
        .infohash
        .clone();

    let engine = std::sync::Arc::new(MockEngine::new());
    let source: std::sync::Arc<dyn AlertSource> =
        std::sync::Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            std::sync::Arc::clone(&engine) as std::sync::Arc<dyn TorrentEngine>,
        )]));
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    let dry_run = || {
        super::execute_adopt(&pool, &source, &profiles, &ih, ProfileId::new("p"), true)
            .unwrap_or_else(|e| panic!("{}", e.reason))
    };

    // Untouched since the scan: the pass finds nothing and the fast path
    // stands.
    let report = pool
        .check_drift_before_adopt(std::slice::from_ref(&ih))
        .unwrap();
    assert!(report.drifted.is_empty(), "{report:?}");
    assert_eq!(dry_run(), super::Adopted::FastPath);

    // Same size, new bytes: invisible to the index until the pass runs.
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(dir.path().join("pool/a"), b"y").unwrap();
    assert_eq!(dry_run(), super::Adopted::FastPath);
    let report = pool
        .check_drift_before_adopt(std::slice::from_ref(&ih))
        .unwrap();
    assert_eq!(report.drifted, vec![ih.clone()]);
    assert_eq!(dry_run(), super::Adopted::QueuedForVerification);
}
