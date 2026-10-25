//! Adding torrents: sources, guards, the check queue, and adds that fail or
//! race.

use super::*;

pub(super) async fn adding(h: &Harness, e: &Engines, dir: &Path) {
    // The mock keys a handle by the infohash the magnet names, as a session
    // does; the 201 carries the details for that handle.
    e.p.set_torrent_details(
        e.p.register_handle(InfoHash::from_hex(MAGNET_HEX).unwrap()),
        TorrentDetails {
            name: Some("from-dn".into()),
            ..MockEngine::default_details()
        },
    );

    // A magnet: 201, Location, the torrent, and the assignment.
    let resp = h.write_json("POST", "/v1/torrents", magnet("p")).await;
    resp.assert_status(StatusCode::CREATED);
    resp.assert_header("location", &format!("/v1/torrents/{MAGNET_HEX}"));
    let t: Value = resp.json();
    assert_eq!(t["infohash"], MAGNET_HEX);
    assert_eq!(t["profile_id"], "p");
    assert_eq!(t["phase"], "unknown", "no state update yet");
    assert_eq!(t["session"]["name"], "from-dn");
    let ih = InfoHash::from_hex(MAGNET_HEX).unwrap();
    assert_eq!(h.state.registry.lookup(&ih).unwrap().as_str(), "p");

    // A duplicate, to this profile or another, never reaches a session.
    let before = e.p.calls().len();
    let resp = h.write_json("POST", "/v1/torrents", magnet("p")).await;
    assert_problem(&resp, 409, "torrent-exists");
    // To `strict` by way of a tracker its allow-list admits, so it is the
    // duplicate that refuses it.
    let allowed = format!("{MAGNET}&tr=https%3A%2F%2Ftracker.allowed.example%2Fannounce");
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "strict", "source": {"kind": "magnet", "uri": allowed}}),
        )
        .await;
    assert_problem(&resp, 409, "torrent-exists");
    assert_eq!(e.p.calls().len(), before);

    // Profiles: unknown, failed, fenced.
    let resp = h.write_json("POST", "/v1/torrents", magnet("nope")).await;
    assert_problem(&resp, 404, "profile-not-found");
    let resp = h.write_json("POST", "/v1/torrents", magnet("down")).await;
    assert_problem(&resp, 409, "profile-unavailable");
    let body: Value = resp.json();
    assert_eq!(body["profile_status"], "failed");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("wg-down did not come up"));
    let resp = h.write_json("POST", "/v1/torrents", magnet("f")).await;
    assert_problem(&resp, 409, "profile-unavailable");
    assert_eq!(resp.json::<Value>()["profile_status"], "vpn_down");
    assert!(
        e.f.calls().is_empty(),
        "a fenced profile takes no new torrent"
    );

    // Constraints the schema declares.
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "magnet", "uri": "http://x"}}),
        )
        .await;
    assert_problem(&resp, 422, "validation-failed");
    assert_eq!(errors_at(&resp), ["/source/uri"]);
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "metainfo", "data": "not base64!"}}),
        )
        .await;
    assert_problem(&resp, 422, "validation-failed");
    assert_eq!(errors_at(&resp), ["/source/data"]);
    // Closed request bodies, at the top and in the source alike.
    for body in [
        json!({"profile_id": "p", "source": {"kind": "magnet", "uri": MAGNET}, "x": 1}),
        json!({"profile_id": "p", "source": {"kind": "magnet", "uri": MAGNET, "x": 1}}),
        json!({"source": {"kind": "magnet", "uri": MAGNET}}),
        json!({"profile_id": "p", "source": {"kind": "torrent_url", "url": "http://x"}}),
    ] {
        let resp = h.write_json("POST", "/v1/torrents", body.clone()).await;
        assert_eq!(resp.status().as_u16(), 422, "{body}");
    }

    // Confinement, which never says whether a path exists.
    let mut body = magnet("p");
    body["save_path"] = json!("/etc");
    let resp = h.write_json("POST", "/v1/torrents", body).await;
    assert_problem(&resp, 422, "path-not-confined");
    assert!(resp.json::<Value>()["detail"]
        .as_str()
        .unwrap()
        .contains("save_path must be inside"));
    // A missing directory followed by `..`: the non-existent tail used to be
    // re-appended lexically and read as inside `default_save_path`.
    let mut body = magnet("p");
    body["save_path"] = json!(dir.join("nx/../../../etc"));
    let resp = h.write_json("POST", "/v1/torrents", body).await;
    assert_problem(&resp, 422, "path-not-confined");
    let escaping = dir.join("nx/../../../etc/x.torrent");
    for outside in [
        "/etc/shadow",
        "/nonexistent/x.torrent",
        escaping.to_str().unwrap(),
    ] {
        let resp = h
            .write_json(
                "POST",
                "/v1/torrents",
                json!({"profile_id": "p", "source": {"kind": "server_path", "path": outside}}),
            )
            .await;
        assert_problem(&resp, 422, "path-not-confined");
        let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
        assert!(detail.contains("must be inside"), "{detail}");
        assert!(!detail.contains("No such file"), "{detail}");
    }

    // Unreadable or unparseable metainfo.
    let missing = dir.join("missing.torrent");
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "server_path", "path": missing}}),
        )
        .await;
    assert_problem(&resp, 422, "invalid-metainfo");
    let big = dir.join("huge.torrent");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(crate::http::v1::torrents::MAX_TORRENT_FILE_BYTES + 1)
        .unwrap();
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "server_path", "path": big}}),
        )
        .await;
    assert_problem(&resp, 422, "invalid-metainfo");
    assert!(resp.json::<Value>()["detail"]
        .as_str()
        .unwrap()
        .contains("implausibly large"));
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", b"not bencode"))
        .await;
    assert_problem(&resp, 422, "invalid-metainfo");
    // Past kynos' 2 MiB default for a buffered body: this operation's own
    // limit is what it is read under, so the body reaches the handler.
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            metainfo("p", &vec![b'x'; 3 * 1024 * 1024]),
        )
        .await;
    assert_problem(&resp, 422, "invalid-metainfo");

    // The profile's tracker allow-list.
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            metainfo("strict", &torrent_bytes('s')),
        )
        .await;
    assert_problem(&resp, 422, "tracker-not-allowed");
    // A magnet is held to it through its `tr=` trackers: a foreign one is
    // refused before anything is assigned.
    for tr in [
        "tr=https%3A%2F%2Fother.example%2Fannounce",
        "tr.1=https%3A%2F%2Fother.example%2Fannounce",
        "TR=https%3A%2F%2Fother.example%2Fannounce",
        "tr=not-a-url",
    ] {
        let foreign = format!("{MAGNET}&{tr}");
        let resp = h
            .write_json(
                "POST",
                "/v1/torrents",
                json!({"profile_id": "strict", "source": {"kind": "magnet", "uri": foreign}}),
            )
            .await;
        assert_problem(&resp, 422, "tracker-not-allowed");
    }
    assert_ne!(
        h.state
            .registry
            .lookup(&InfoHash::from_hex(MAGNET_HEX).unwrap())
            .map(|p| p.as_str().to_owned())
            .as_deref(),
        Some("strict"),
        "a refused magnet is never assigned to the profile that refused it"
    );

    // A `.torrent` in the body, and one on disk: both added and persisted.
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes('a')))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let added = InfoHash::from_hex(resp.json::<Value>()["infohash"].as_str().unwrap()).unwrap();
    assert_eq!(
        h.state
            .torrents
            .load_all(&ProfileId::new("p"))
            .unwrap()
            .len(),
        1,
        "the .torrent is kept for the startup scan"
    );
    assert!(h.state.registry.lookup(&added).is_some());
    let on_disk = dir.join("b.torrent");
    std::fs::write(&on_disk, torrent_bytes('b')).unwrap();
    let mut body = json!({"profile_id": "p", "source": {"kind": "server_path", "path": on_disk}});
    body["save_path"] = json!(dir.join("payload"));
    let resp = h.write_json("POST", "/v1/torrents", body).await;
    resp.assert_status(StatusCode::CREATED);
    let from_disk = InfoHash::from_hex(resp.json::<Value>()["infohash"].as_str().unwrap()).unwrap();

    // Each add records the save path it was given beside its `.torrent`, so
    // the startup scan can re-add it there if its resume file is lost: the
    // one the caller named, or `default_save_path` when it named none. A
    // magnet's is recorded before its `.torrent` arrives with the metadata.
    let p = ProfileId::new("p");
    let recorded = |ih: &InfoHash| h.state.torrents.read_save_path(&p, ih).unwrap();
    let default = dir.to_string_lossy().into_owned();
    assert_eq!(
        recorded(&from_disk),
        Some(dir.join("payload").to_string_lossy().into_owned())
    );
    assert_eq!(recorded(&added).as_ref(), Some(&default));
    assert_eq!(
        recorded(&InfoHash::from_hex(MAGNET_HEX).unwrap()).as_ref(),
        Some(&default)
    );
    // Issue #627: a magnet records its URI too, the one thing the boot can
    // re-add it from before its metadata or its first resume save lands. A
    // `.torrent` add records none: its `.torrent` is that record.
    let magnet_of = |ih: &InfoHash| h.state.torrents.read_magnet(&p, ih).unwrap();
    assert_eq!(
        magnet_of(&InfoHash::from_hex(MAGNET_HEX).unwrap()).as_deref(),
        Some(MAGNET)
    );
    assert_eq!(magnet_of(&added), None);
    assert_eq!(magnet_of(&from_disk), None);

    // Every add the API made — the magnet, the metainfo and the server path —
    // kept its torrent in upload mode with no flag that could lift it.
    let adds: Vec<_> =
        e.p.calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::AddTorrent(a) => Some(a),
                _ => None,
            })
            .collect();
    assert_eq!(adds.len(), 3, "{adds:?}");
    for a in &adds {
        assert!(a.forbids_downloading(), "{a:?}");
    }

    // Issue #383: a `.torrent`'s first check waits for a slot in the check
    // queue, `[pool]` or not: it is added paused, queued, and named in the
    // record the next boot reads. A magnet has nothing to check yet.
    let paused: Vec<bool> = adds
        .iter()
        .map(|a| {
            a.flags_set()
                .contains(torrentd_engine::TorrentFlags::PAUSED)
        })
        .collect();
    assert_eq!(paused, [false, true, true], "{adds:?}");
    assert_eq!(h.state.checks.depth(), 2);
    for ih in [added, from_disk] {
        assert!(h.state.checks.holds().holds(&p, &ih), "{ih}");
    }

    // A session that refuses the torrent releases the claim for a retry,
    // and its place in the check queue and the record.
    e.p.inject_error("add_torrent", injected("add_torrent"));
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes('c')))
        .await;
    assert_problem(&resp, 500, "internal");
    assert!(!resp.text().contains("boom"), "the cause stays in the log");
    assert_eq!(h.state.checks.depth(), 2);
    assert_eq!(h.state.checks.holds().held(&p).len(), 2);
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes('c')))
        .await;
    resp.assert_status(StatusCode::CREATED);
    assert_eq!(h.state.checks.depth(), 3);

    body_framework_rejections(
        h,
        "POST",
        "/v1/torrents",
        crate::http::v1::ADD_REQUEST_DEADLINE,
    )
    .await;
}

/// Issue #383: twelve `.torrent`s posted to `POST /v1/torrents` in a row,
/// with no `[pool]`, never have more than the default check limit of four
/// hashing at once. Each used to be added running, so all twelve hashed at
/// once, uncounted. Each is added paused instead, and the check queue resumes
/// it once a slot is free, counting it in `checks_started_total`.
#[tokio::test]
async fn a_burst_of_torrent_adds_hashes_at_most_the_check_limit_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        let e = fixture(s, dir.path());
        s.checks.set_metrics(s.metrics.clone());
        engine = Some(e.p);
    });
    let engine = engine.unwrap();
    assert!(h.state.pool.is_none(), "the bound holds without [pool]");
    let p = ProfileId::new("p");
    let mut added = Vec::new();
    for name in 'a'..='l' {
        let resp = h
            .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes(name)))
            .await;
        resp.assert_status(StatusCode::CREATED);
        let ih = InfoHash::from_hex(resp.json::<Value>()["infohash"].as_str().unwrap()).unwrap();
        // What the add alert does: the state map takes the torrent in.
        let mut st = TorrentState::newly_added(handle(&engine, ih), p.clone(), Instant::now());
        st.phase = TorrentPhase::Paused;
        h.state.state.insert(ih, st);
        added.push(ih);
    }
    let resumed = || -> Vec<InfoHash> {
        engine
            .calls()
            .iter()
            .filter_map(|c| match c {
                RecordedCall::ResumeTorrent(h) => Some(h.infohash),
                _ => None,
            })
            .collect()
    };
    assert!(
        resumed().is_empty(),
        "nothing hashes before the queue admits it"
    );
    let q = &h.state.checks;
    assert_eq!(q.depth(), 12);
    assert_eq!(q.holds().held(&p).len(), 12);

    let tick = || {
        crate::check_queue::admit_tick_for_tests(
            q,
            None,
            &h.state.source,
            &h.state.state,
            &h.state.profiles,
            &h.state.registry,
        );
    };
    let mut finished = std::collections::HashSet::new();
    let mut peak = 0;
    for n in 0..100 {
        tick();
        let started = resumed();
        let checking = started.iter().filter(|h| !finished.contains(*h)).count();
        assert!(checking <= 4, "tick {n}: {checking} checking at once");
        assert_eq!(q.in_flight(), checking, "tick {n}");
        assert_eq!(q.depth(), 12 - started.len(), "tick {n}");
        peak = peak.max(checking);
        if started.len() == added.len() && checking == 0 {
            break;
        }
        // libtorrent reports the oldest running check over.
        if let Some(ih) = started.iter().find(|h| !finished.contains(*h)) {
            std::thread::sleep(Duration::from_millis(2));
            h.state.state.update(ih, |st| {
                st.checked_at = Some(Instant::now());
                st.phase = TorrentPhase::Seeding;
            });
            finished.insert(*ih);
        }
    }
    assert_eq!(resumed(), added, "every torrent resumed once, in order");
    assert_eq!(peak, 4, "the limit is reached, not merely respected");
    assert_eq!(q.in_flight(), 0);
    assert!(
        q.holds().held(&p).is_empty(),
        "a check that ended leaves the record, so the next boot loads it as it is"
    );
    let rendered = String::from_utf8(h.state.metrics.render()).unwrap();
    assert!(
        rendered.contains(r#"torrentd_checks_started_total{source="add"} 12"#),
        "{rendered}"
    );
}

/// A `.torrent` waiting for its first check that the operator pauses is
/// theirs: the queue no longer resumes it, and the record lets it go. One
/// the operator resumes takes its slot at once.
#[tokio::test]
async fn a_held_add_follows_the_operators_pause_and_resume() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        let e = fixture(s, dir.path());
        engine = Some(e.p);
    });
    let engine = engine.unwrap();
    let p = ProfileId::new("p");
    let mut added = Vec::new();
    for name in ['a', 'b'] {
        let resp = h
            .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes(name)))
            .await;
        resp.assert_status(StatusCode::CREATED);
        let ih = InfoHash::from_hex(resp.json::<Value>()["infohash"].as_str().unwrap()).unwrap();
        let mut st = TorrentState::newly_added(handle(&engine, ih), p.clone(), Instant::now());
        st.phase = TorrentPhase::Paused;
        h.state.state.insert(ih, st);
        added.push(ih);
    }
    let q = &h.state.checks;
    assert_eq!(q.depth(), 2);

    h.write("POST", &format!("/v1/torrents/{}/pause", hex(added[0])))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(q.depth(), 1);
    assert!(
        !q.holds().holds(&p, &added[0]),
        "the pause is the operator's"
    );

    h.write("POST", &format!("/v1/torrents/{}/resume", hex(added[1])))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(q.depth(), 0);
    assert_eq!(q.in_flight(), 1, "a check resumed by hand holds a slot");
    assert!(
        q.holds().holds(&p, &added[1]),
        "held until its check ends, so a restart before then queues it again"
    );

    crate::check_queue::admit_tick_for_tests(
        q,
        None,
        &h.state.source,
        &h.state.state,
        &h.state.profiles,
        &h.state.registry,
    );
    let resumes = engine
        .calls()
        .iter()
        .filter(|c| matches!(c, RecordedCall::ResumeTorrent(_)))
        .count();
    assert_eq!(
        resumes,
        1,
        "only the operator's resume: {:?}",
        engine.calls()
    );

    // A pause-all is the operator's too, for every torrent still waiting.
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes('c')))
        .await;
    resp.assert_status(StatusCode::CREATED);
    assert_eq!(q.depth(), 1);
    h.write("POST", "/v1/torrents/pause-all")
        .await
        .assert_status(StatusCode::OK);
    assert_eq!((q.depth(), q.in_flight()), (0, 0));
    assert!(q.holds().held(&p).is_empty());
}

/// A `.torrent` the queue already resumed that the operator pauses mid-check
/// frees its slot and leaves the record at once. So does one whose check
/// ended while others still wait, whose release from the record waits for
/// the batched write: a restart before that write would otherwise load it,
/// queue it again, and resume it over the operator's pause.
#[tokio::test]
async fn a_held_add_the_queue_resumed_follows_the_operators_pause() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        let e = fixture(s, dir.path());
        engine = Some(e.p);
    });
    let engine = engine.unwrap();
    let p = ProfileId::new("p");
    let add = |name: char| {
        let (h, engine, p) = (&h, &engine, &p);
        async move {
            let resp = h
                .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes(name)))
                .await;
            resp.assert_status(StatusCode::CREATED);
            let ih =
                InfoHash::from_hex(resp.json::<Value>()["infohash"].as_str().unwrap()).unwrap();
            let mut st = TorrentState::newly_added(handle(engine, ih), p.clone(), Instant::now());
            st.phase = TorrentPhase::Paused;
            h.state.state.insert(ih, st);
            ih
        }
    };
    let q = &h.state.checks;
    let tick = || {
        crate::check_queue::admit_tick_for_tests(
            q,
            None,
            &h.state.source,
            &h.state.state,
            &h.state.profiles,
            &h.state.registry,
        );
    };
    let pause = |ih: InfoHash| {
        let h = &h;
        async move {
            h.write("POST", &format!("/v1/torrents/{}/pause", hex(ih)))
                .await
                .assert_status(StatusCode::NO_CONTENT);
        }
    };

    let (checking, ended) = (add('a').await, add('b').await);
    tick();
    assert_eq!((q.depth(), q.in_flight()), (0, 2), "the queue resumed both");

    pause(checking).await;
    assert_eq!(q.in_flight(), 1, "the paused check's slot is free");
    assert!(
        !q.holds().holds(&p, &checking),
        "the pause is the operator's"
    );

    // `ended`'s check finishes while another add still waits, so its
    // release from the record is batched.
    let _waiting = add('c').await;
    std::thread::sleep(Duration::from_millis(2));
    h.state.state.update(&ended, |st| {
        st.checked_at = Some(Instant::now());
        st.phase = TorrentPhase::Seeding;
    });
    tick();
    assert!(
        q.holds().holds(&p, &ended),
        "released with the next batched write"
    );

    pause(ended).await;
    assert!(
        !q.holds().holds(&p, &ended),
        "the operator's pause releases it at once"
    );
}

#[tokio::test]
async fn an_add_dropped_mid_call_still_releases_the_claim_when_the_add_fails() {
    // The claim is taken before the engine call; a handler dropped at the
    // await would never reach the release, and the infohash would read as
    // `torrent-exists` until a restart.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p)
    });
    let engine = engine.unwrap();
    let ih = InfoHash([1; 20]); // MAGNET's btih
    engine.inject_error("add_torrent", injected("add_torrent"));
    let held = engine.hold_next("add_torrent");
    drop_mid_call(h.write_json("POST", "/v1/torrents", magnet("p")), held).await;
    eventually("the failed add's claim is released", || {
        h.state.registry.lookup(&ih).is_none()
    })
    .await;
}

/// Issue #167: two adds of one info-hash into one profile, where the second's
/// lookup ran before the first's claim was visible. The first add's claim is
/// written through a second handle on the same database, which is exactly what
/// the second add's `assign` finds: a row naming its own profile that its
/// lookup did not see.
///
/// The second add used to take that as its own claim, reach the session,
/// fail on libtorrent's duplicate, and release the first add's claim, leaving
/// the torrent seeding with no owner and free to be added into another
/// profile.
#[tokio::test]
async fn a_same_profile_add_that_loses_the_claim_race_is_refused_and_keeps_the_winners_claim() {
    let dir = tempfile::tempdir().unwrap();
    let reg_path = dir.path().join("reg.db");
    let (p, q) = (Arc::new(MockEngine::new()), Arc::new(MockEngine::new()));
    let h = Harness::authed(&Coverage::new(), |s| {
        s.profiles = Arc::new(ProfileRegistry::new(vec![
            test_entry("p", ProfileStatus::Active),
            test_entry("q", ProfileStatus::Active),
        ]));
        s.source = Arc::new(ProfileSource::new(vec![
            (ProfileId::new("p"), p.clone() as Arc<dyn TorrentEngine>),
            (ProfileId::new("q"), q.clone() as Arc<dyn TorrentEngine>),
        ]));
        s.registry = Arc::new(AssignmentRegistry::new_empty(&reg_path));
        s.default_save_path = dir.path().to_path_buf();
        s.torrent_dir = dir.path().to_path_buf();
    });
    let ih = InfoHash([1; 20]); // MAGNET's btih
                                // The winning add's claim, and the duplicate the session would answer the
                                // losing add with if it got that far.
    AssignmentRegistry::new_empty(&reg_path)
        .assign(ih, ProfileId::new("p"))
        .unwrap();
    p.inject_error(
        "add_torrent",
        EngineError::MockInjected {
            op: "add_torrent",
            message: "torrent already exists in session".into(),
        },
    );

    let resp = h.write_json("POST", "/v1/torrents", magnet("p")).await;
    assert_problem(&resp, 409, "torrent-exists");
    assert!(
        !p.calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::AddTorrent(_))),
        "the losing add reached the session: {:?}",
        p.calls()
    );
    assert_eq!(h.state.registry.lookup(&ih), Some(ProfileId::new("p")));

    let resp = h.write_json("POST", "/v1/torrents", magnet("q")).await;
    assert_problem(&resp, 409, "torrent-exists");
    assert!(q.calls().is_empty(), "{:?}", q.calls());
    assert_eq!(h.state.registry.lookup(&ih), Some(ProfileId::new("p")));
}

/// Issue #212: a registry that cannot be written is not a duplicate. The add
/// used to answer `409 torrent-exists`, which the docs tell a client to read
/// as "already added", so an automation stopped retrying a torrent that was
/// never assigned and whose re-read answered 404.
#[tokio::test]
async fn an_add_whose_registry_write_fails_answers_500_and_assigns_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p);
        // Every insert into the registry fails, as on a full or read-only
        // state directory.
        let db = dir.path().join("failing.db");
        s.registry = Arc::new(AssignmentRegistry::new_empty(&db));
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_insert BEFORE INSERT ON assignment \
                   BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
    });
    let engine = engine.unwrap();
    let ih = InfoHash([1; 20]); // MAGNET's btih

    let resp = h.write_json("POST", "/v1/torrents", magnet("p")).await;
    assert_problem(&resp, 500, "internal");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(
        detail.contains("registry"),
        "the detail names what failed: {detail}"
    );
    assert!(
        h.state.registry.lookup(&ih).is_none(),
        "a failed write assigns nothing"
    );
    assert!(
        !engine
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::AddTorrent(_))),
        "the add reached the session: {:?}",
        engine.calls()
    );
    let text = String::from_utf8(h.state.metrics.render()).unwrap();
    assert!(
        text.contains("profile_assignment_registry_errors_total{profile_id=\"p\"} 1"),
        "{text}"
    );
    let resp = h.read(&format!("/v1/torrents/{}", hex(ih))).await;
    assert_eq!(resp.status().as_u16(), 404, "nothing was added to re-read");
}

/// The other half of issue #212: a real duplicate that only `assign` finds —
/// a row another process wrote for another profile — is still
/// `torrent-exists`.
#[tokio::test]
async fn an_add_whose_infohash_another_process_assigned_elsewhere_is_still_torrent_exists() {
    let dir = tempfile::tempdir().unwrap();
    let reg_path = dir.path().join("reg.db");
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p);
        s.registry = Arc::new(AssignmentRegistry::new_empty(&reg_path));
    });
    let engine = engine.unwrap();
    let ih = InfoHash([1; 20]); // MAGNET's btih
    AssignmentRegistry::new_empty(&reg_path)
        .assign(ih, ProfileId::new("strict"))
        .unwrap();

    let resp = h.write_json("POST", "/v1/torrents", magnet("p")).await;
    assert_problem(&resp, 409, "torrent-exists");
    assert!(engine.calls().is_empty(), "{:?}", engine.calls());
    assert_eq!(h.state.registry.lookup(&ih), Some(ProfileId::new("strict")));
}

#[tokio::test]
async fn an_add_whose_profile_is_fenced_mid_add_pauses_the_torrent() {
    // The add passed the fence check, then the VPN monitor fenced the profile
    // while `add_torrent` ran. The torrent is in the session but not yet in
    // the state map the fence walked, so the add itself has to pause it.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p)
    });
    let engine = engine.unwrap();
    let held = engine.hold_next("add_torrent");
    let entered = tokio::task::spawn_blocking(move || {
        held.wait_entered();
        held
    });
    let req = h.write_json("POST", "/v1/torrents", magnet("p"));
    let fence_mid_add = async {
        let held = entered.await.unwrap();
        h.state
            .profiles
            .resolve(&ProfileId::new("p"))
            .active()
            .unwrap()
            .update_health(|hh| hh.status = ProfileStatus::VpnDown);
        held.release();
    };
    let (resp, ()) = tokio::join!(req, fence_mid_add);
    resp.assert_status(StatusCode::CREATED);
    // The mock keys the handle by the infohash the magnet names.
    let th = handle(&engine, InfoHash::from_hex(MAGNET_HEX).unwrap());
    assert!(
        called(&engine, &RecordedCall::PauseTorrent(th)),
        "{:?}",
        engine.calls()
    );
}

#[tokio::test]
async fn an_add_the_kill_switch_fences_mid_add_is_resumed_by_the_fences_lift() {
    // The kill-switch fence lands while `add_torrent` runs: its walk of the
    // state map misses the torrent, so the add's own re-check pauses it, and
    // has to record it with the fence through `AppState::kill_switch`, or
    // the lift resumes the rest and leaves this one paused in a profile that
    // reads active.
    use crate::vpn::killswitch::Fence as _;

    let dir = tempfile::tempdir().unwrap();
    let mut wired = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        let engines = fixture(s, dir.path());
        // `p`'s entry fences and lifts through the engine its session adds
        // through, as the daemon's do.
        let p = test_entry("p", ProfileStatus::Active);
        let p = ProfileEntry::new(p.config, engines.p.clone(), p.session_ip, None, 0);
        s.profiles = Arc::new(ProfileRegistry::new(vec![p]));
        let healthy: crate::vpn_monitor::Prober =
            Arc::new(|_, _| crate::vpn_monitor::TunnelProbes {
                ip: Ok(Some(std::net::IpAddr::from([10, 2, 0, 2]))),
                route: Some(Ok(crate::vpn::route::RouteProbe::ViaTunnel)),
                handshake: None,
            });
        let fence = Arc::new(crate::fence::KillSwitchFence::new(
            s.profiles.clone(),
            s.state.clone(),
            s.metrics.clone(),
            healthy,
        ));
        s.kill_switch = Some(fence.clone());
        wired = Some((engines.p, fence));
    });
    let (engine, fence) = wired.unwrap();
    let held = engine.hold_next("add_torrent");
    let entered = tokio::task::spawn_blocking(move || {
        held.wait_entered();
        held
    });
    let req = h.write_json("POST", "/v1/torrents", magnet("p"));
    let fence_mid_add = async {
        let held = entered.await.unwrap();
        fence.fence_all();
        held.release();
    };
    let (resp, ()) = tokio::join!(req, fence_mid_add);
    resp.assert_status(StatusCode::CREATED);
    // The mock keys the handle by the infohash the magnet names.
    let th = handle(&engine, InfoHash::from_hex(MAGNET_HEX).unwrap());
    assert!(
        !h.state.state.contains(&th.infohash),
        "the fence's walk cannot have found it"
    );
    assert!(
        called(&engine, &RecordedCall::PauseTorrent(th)),
        "the add pauses it: {:?}",
        engine.calls()
    );

    fence.lift();
    eventually("the lift resumes the added torrent", || {
        called(&engine, &RecordedCall::ResumeTorrent(th))
    })
    .await;
    let loaded = handle(&engine, LOADED);
    eventually("and the torrent its walk paused", || {
        called(&engine, &RecordedCall::ResumeTorrent(loaded))
    })
    .await;
    assert_eq!(
        h.state
            .profiles
            .resolve(&ProfileId::new("p"))
            .active()
            .unwrap()
            .health()
            .status,
        ProfileStatus::Active
    );
}

#[tokio::test]
async fn a_torrent_file_that_cannot_be_persisted_is_counted_and_the_add_still_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
        // A torrent store whose base is a regular file: every write fails, as
        // on a torrent dir that is full, read-only or gone.
        std::fs::write(dir.path().join("blocker"), b"not a directory").unwrap();
        s.torrents = Arc::new(torrentd_engine::FsTorrentStore::new(
            dir.path().join("blocker"),
        ));
    });
    h.write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes('a')))
        .await
        .assert_status(StatusCode::CREATED);
    // Two files could not be written: the save path, then the `.torrent`.
    let text = String::from_utf8(h.state.metrics.render()).unwrap();
    assert!(
        text.contains(
            "torrentd_torrent_file_persist_errors_total{profile_id=\"p\",source=\"api\"} 2"
        ),
        "{text}"
    );
}

#[tokio::test]
async fn a_magnet_whose_trackers_are_all_allowed_is_added() {
    // The allow-list's other half: refusing a foreign tracker is only useful
    // if a magnet naming nothing but allowed ones still gets through,
    // whichever spelling of `tr` it uses.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p);
    });
    let allowed = format!(
        "{MAGNET}&tr=https%3A%2F%2Ftracker.allowed.example%2Fannounce\
         &tr.1=udp%3A%2F%2Fsub.tracker.allowed.example%3A6969%2Fannounce"
    );
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "strict", "source": {"kind": "magnet", "uri": allowed}}),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
    assert_eq!(
        h.state
            .registry
            .lookup(&InfoHash::from_hex(MAGNET_HEX).unwrap())
            .unwrap()
            .as_str(),
        "strict"
    );

    // `strict` is a host profile set up for a tracker account, so it trusts
    // a torrent's own `private` bit, and a magnet has none until its
    // metadata arrives: the add itself keeps it off DHT, PEX and LSD.
    let adds: Vec<_> = engine
        .unwrap()
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            RecordedCall::AddTorrent(a) => Some(a),
            _ => None,
        })
        .collect();
    assert_eq!(adds.len(), 1, "{adds:?}");
    assert!(
        adds[0].flags_set().contains(
            TorrentFlags::DISABLE_DHT | TorrentFlags::DISABLE_PEX | TorrentFlags::DISABLE_LSD
        ),
        "{adds:?}"
    );
    assert!(adds[0].forbids_downloading(), "{adds:?}");
}

#[tokio::test]
async fn one_foreign_tracker_refuses_a_torrent_whatever_else_it_announces_to() {
    // All-match: an allowed tracker beside a foreign one still announces the
    // foreign one, and with it another account's passkey. And a torrent that
    // announces to nothing names no account of this profile's.
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
    });
    let both = {
        let (ours, theirs) = (
            "https://tracker.allowed.example/announce",
            "https://other.example/announce",
        );
        let mut t = format!(
            "d8:announce{}:{ours}13:announce-listll{}:{ours}el{}:{theirs}ee\
             4:infod6:lengthi1e4:name1:m12:piece lengthi16384e6:pieces20:",
            ours.len(),
            ours.len(),
            theirs.len(),
        )
        .into_bytes();
        t.extend_from_slice(&[0u8; 20]);
        t.extend_from_slice(b"ee");
        t
    };
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("strict", &both))
        .await;
    assert_problem(&resp, 422, "tracker-not-allowed");
    for uri in [
        format!(
            "{MAGNET}&tr=https%3A%2F%2Ftracker.allowed.example%2Fannounce\
             &tr=https%3A%2F%2Fother.example%2Fannounce"
        ),
        MAGNET.to_owned(),
    ] {
        let resp = h
            .write_json(
                "POST",
                "/v1/torrents",
                json!({"profile_id": "strict", "source": {"kind": "magnet", "uri": uri}}),
            )
            .await;
        assert_problem(&resp, 422, "tracker-not-allowed");
    }
    assert_eq!(
        h.state
            .registry
            .lookup(&InfoHash::from_hex(MAGNET_HEX).unwrap()),
        None
    );
}

/// A one-file `.torrent` announcing to `url` alone; `name` sets its infohash.
fn announcing(url: &str, name: char) -> Vec<u8> {
    let mut t = format!(
        "d8:announce{}:{url}4:infod6:lengthi1e4:name1:{name}12:piece lengthi16384e6:pieces20:",
        url.len()
    )
    .into_bytes();
    t.extend_from_slice(&[0u8; 20]);
    t.extend_from_slice(b"ee");
    t
}

/// Issue 166: account B's profile, bound to B's passkey, refuses account A's
/// torrent on every source `POST /v1/torrents` takes — a `.torrent` in the
/// body, one on disk (`server_path`), a magnet's `tr=` — though A's tracker
/// is on B's domain list, and says why in the detail. B's own is added.
#[tokio::test]
async fn another_accounts_passkey_is_refused_on_every_api_source() {
    const A: &str = "https://tracker.allowed.example/PASS-A/announce";
    const B: &str = "https://tracker.allowed.example/PASS-B/announce";
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(MockEngine::new());
    let h = Harness::authed(&Coverage::new(), |s| {
        let mut b = test_host_entry("acct_b").config;
        b.allowed_tracker_domains = vec!["tracker.allowed.example".to_owned()];
        b.allowed_tracker_urls = vec!["https://tracker.allowed.example/PASS-B/".to_owned()];
        s.profiles = Arc::new(ProfileRegistry::new(vec![ProfileEntry::new(
            b,
            engine.clone(),
            None,
            None,
            0,
        )]));
        s.source = Arc::new(ProfileSource::new(vec![(
            ProfileId::new("acct_b"),
            engine.clone() as Arc<dyn TorrentEngine>,
        )]));
        s.registry = Arc::new(AssignmentRegistry::new_empty(dir.path().join("reg.json")));
        s.default_save_path = dir.path().to_path_buf();
        s.torrent_dir = dir.path().to_path_buf();
    });
    let foreign_account = |resp: &TestResponse| {
        assert_problem(resp, 422, "tracker-not-allowed");
        let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
        assert!(detail.contains("allowed_tracker_urls"), "{detail}");
    };

    foreign_account(
        &h.write_json(
            "POST",
            "/v1/torrents",
            metainfo("acct_b", &announcing(A, 'a')),
        )
        .await,
    );
    let on_disk = dir.path().join("a.torrent");
    std::fs::write(&on_disk, announcing(A, 'd')).unwrap();
    foreign_account(
        &h.write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "acct_b", "source": {"kind": "server_path", "path": on_disk}}),
        )
        .await,
    );
    let tr = A.replace(':', "%3A").replace('/', "%2F");
    foreign_account(
        &h.write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "acct_b", "source": {"kind": "magnet", "uri": format!("{MAGNET}&tr={tr}")}}),
        )
        .await,
    );
    assert_eq!(
        h.state
            .registry
            .lookup(&InfoHash::from_hex(MAGNET_HEX).unwrap()),
        None
    );

    h.write_json(
        "POST",
        "/v1/torrents",
        metainfo("acct_b", &announcing(B, 'b')),
    )
    .await
    .assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn a_server_path_that_is_a_symlink_is_refused_even_to_a_real_torrent() {
    // The path is opened once, refusing a symlink at the last component, and
    // everything after is read from that descriptor. A symlink planted in a
    // confined directory therefore cannot point the read anywhere else.
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
    });
    let real = dir.path().join("real.torrent");
    std::fs::write(&real, torrent_bytes('r')).unwrap();
    let link = dir.path().join("link.torrent");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "server_path", "path": link}}),
        )
        .await;
    assert_problem(&resp, 422, "invalid-metainfo");
    // The file it names is still readable by its own path.
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "server_path", "path": real}}),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn a_torrent_outside_the_allow_list_is_counted_as_a_registry_error() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
    });
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            metainfo("strict", &torrent_bytes('s')),
        )
        .await;
    assert_problem(&resp, 422, "tracker-not-allowed");
    let text = String::from_utf8(h.state.metrics.render()).unwrap();
    assert!(
        text.contains("profile_assignment_registry_errors_total{profile_id=\"strict\"} 1"),
        "{text}"
    );
}

/// The repository's own hybrid (v1+v2) test torrent, and its two hashes.
/// `cargo test` runs without the vendor submodules, so not libtorrent's.
fn hybrid_torrent() -> (Vec<u8>, InfoHash, InfoHash) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let hashes = libtorrent_safe::info_hashes_from_torrent(&bytes).unwrap();
    let v1 = hashes.v1.expect("a hybrid has a v1 hash");
    let v2 = hashes.v2.expect("a hybrid has a v2 hash").truncated();
    assert_ne!(v1, v2);
    (bytes, v1, v2)
}

#[tokio::test]
async fn a_hybrid_torrent_is_added_and_found_under_its_v1_infohash() {
    // The infohash a tracker site shows, and the one a btih-only magnet for
    // the same torrent carries: a key of the truncated v2 hash was a 404 for
    // it, and let the magnet into a second profile.
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
    });
    let (bytes, v1, v2) = hybrid_torrent();

    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &bytes))
        .await;
    resp.assert_status(StatusCode::CREATED);
    resp.assert_header("location", &format!("/v1/torrents/{}", hex(v1)));
    assert_eq!(resp.json::<Value>()["infohash"], hex(v1));
    assert_eq!(h.state.registry.lookup(&v1).unwrap().as_str(), "p");
    assert_eq!(h.state.registry.lookup(&v2), None);

    let resp = h.read(&format!("/v1/torrents/{}", hex(v1))).await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.json::<Value>()["infohash"], hex(v1));

    // A btih-only magnet for it is the same torrent.
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "magnet",
                   "uri": format!("magnet:?xt=urn:btih:{}", hex(v1))}}),
        )
        .await;
    assert_problem(&resp, 409, "torrent-exists");
}

#[tokio::test]
async fn a_hybrid_torrent_recorded_under_its_truncated_v2_infohash_is_a_duplicate() {
    // An earlier build keyed hybrid torrents by the truncated v2 hash, and the
    // registry may still hold one under it.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p);
    });
    let e = engine.unwrap();
    let (bytes, v1, v2) = hybrid_torrent();
    h.state.registry.assign(v2, ProfileId::new("f")).unwrap();

    let before = e.calls().len();
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &bytes))
        .await;
    assert_problem(&resp, 409, "torrent-exists");
    assert_eq!(e.calls().len(), before, "the session never sees it");
    assert_eq!(h.state.registry.lookup(&v1), None);
}

#[tokio::test]
async fn a_magnet_without_a_v1_infohash_is_refused() {
    // Its key would be the truncated v2 hash until the metadata arrived, and
    // the v1 hash after, if that metadata is hybrid.
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
    });
    let v2 = "5c".repeat(32);
    let resp = h
        .write_json(
            "POST",
            "/v1/torrents",
            json!({"profile_id": "p", "source": {"kind": "magnet",
                   "uri": format!("magnet:?xt=urn:btmh:1220{v2}")}}),
        )
        .await;
    assert_problem(&resp, 422, "invalid-metainfo");
    assert!(resp.json::<Value>()["detail"]
        .as_str()
        .unwrap()
        .contains("xt=urn:btih"));
    assert_eq!(
        h.state
            .registry
            .lookup(&InfoHash::from_hex(&v2[..40]).unwrap()),
        None
    );
}
