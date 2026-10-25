//! Per-torrent controls: pause, resume, recheck, reannounce, and the upload
//! limit.

use super::*;

pub(super) async fn controls(h: &Harness, e: &Engines) {
    let loaded = handle(&e.p, LOADED);
    let unknown = hex(InfoHash([0xee; 20]));
    // A recheck is queued, `[pool]` or not: the check queue's tick starts
    // it, and a check that ends frees its slot for the next.
    let tick = || {
        crate::check_queue::admit_tick_for_tests(
            &h.state.checks,
            None,
            &h.state.source,
            &h.state.state,
            &h.state.profiles,
            &h.state.registry,
        );
    };
    let end_check = |ih: InfoHash| {
        h.state
            .state
            .update(&ih, |st| st.checked_at = Some(std::time::Instant::now()));
        tick();
    };

    // Pause: allowed on a fenced profile, which it puts nothing on the
    // network for.
    h.write("POST", &format!("/v1/torrents/{}/pause", hex(LOADED)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(called(&e.p, &RecordedCall::PauseTorrent(loaded)));
    h.write("POST", &format!("/v1/torrents/{}/pause", hex(FENCED)))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Resume, recheck, reannounce: refused on the fenced profile.
    for (verb, status, call) in [
        (
            "resume",
            StatusCode::NO_CONTENT,
            RecordedCall::ResumeTorrent(loaded),
        ),
        (
            "recheck",
            StatusCode::ACCEPTED,
            RecordedCall::ForceRecheck(loaded),
        ),
        (
            "reannounce",
            StatusCode::ACCEPTED,
            RecordedCall::ForceReannounce(loaded),
        ),
    ] {
        h.write("POST", &format!("/v1/torrents/{}/{verb}", hex(LOADED)))
            .await
            .assert_status(status);
        if verb == "recheck" {
            assert!(!called(&e.p, &call), "a recheck waits for the queue");
            tick();
        }
        assert!(called(&e.p, &call), "{verb}");
        let resp = h
            .write("POST", &format!("/v1/torrents/{}/{verb}", hex(FENCED)))
            .await;
        assert_problem(&resp, 409, "profile-unavailable");
        assert_eq!(resp.json::<Value>()["profile_status"], "vpn_down");
    }
    let fenced_calls = e.f.calls();
    assert!(
        fenced_calls
            .iter()
            .all(|c| matches!(c, RecordedCall::PauseTorrent(_))),
        "a fenced profile's torrent must not resume or announce: {fenced_calls:?}"
    );

    // A recheck marks a torrent in `DiskError` `Checking` before it starts,
    // so a check that fails before any status update is not read as a
    // failed peer read; one that fails to start leaves `DiskError` in place;
    // any other phase is left for the status updates to move.
    let recheck = format!("/v1/torrents/{}/recheck", hex(LOADED));
    let set_phase = |phase| h.state.state.update(&LOADED, |st| st.phase = phase);
    let phase = || h.state.state.get(&LOADED).unwrap().phase;
    end_check(LOADED);
    set_phase(TorrentPhase::DiskError);
    h.write("POST", &recheck)
        .await
        .assert_status(StatusCode::ACCEPTED);
    tick();
    assert_eq!(phase(), TorrentPhase::Checking);
    end_check(LOADED);
    set_phase(TorrentPhase::DiskError);
    e.p.inject_error("force_recheck", injected("force_recheck"));
    // Accepted, and dropped when it fails to start: the queue counts it in
    // `pool_recheck_dropped_total{reason="start_failed"}`.
    h.write("POST", &recheck)
        .await
        .assert_status(StatusCode::ACCEPTED);
    tick();
    assert_eq!(phase(), TorrentPhase::DiskError);
    set_phase(TorrentPhase::Seeding);
    h.write("POST", &recheck)
        .await
        .assert_status(StatusCode::ACCEPTED);
    tick();
    assert_eq!(phase(), TorrentPhase::Seeding);
    end_check(LOADED);

    // Unloaded — never loaded, or mid-add — is 404; a session error is 500.
    for (verb, op) in [
        ("pause", "pause_torrent"),
        ("resume", "resume_torrent"),
        ("recheck", "force_recheck"),
        ("reannounce", "force_reannounce"),
    ] {
        for ih in [unknown.clone(), hex(ADDING)] {
            let resp = h.write("POST", &format!("/v1/torrents/{ih}/{verb}")).await;
            assert_problem(&resp, 404, "torrent-not-found");
        }
        // A recheck of a paused torrent is asked for at once, so the
        // session's refusal is the request's to report.
        if verb == "recheck" {
            set_phase(TorrentPhase::Paused);
        }
        e.p.inject_error(op, injected(op));
        let resp = h
            .write("POST", &format!("/v1/torrents/{}/{verb}", hex(LOADED)))
            .await;
        assert_problem(&resp, 500, "internal");
        set_phase(TorrentPhase::Seeding);
    }

    // The upload limit: set, removed with null or absence, bounded, and
    // allowed on a fenced profile.
    let path = format!("/v1/torrents/{}/upload-limit", hex(LOADED));
    for (body, rate) in [
        (json!({"bytes_per_sec": 1000}), 1000),
        (json!({"bytes_per_sec": null}), 0),
        (json!({}), 0),
    ] {
        h.write_json("PUT", &path, body)
            .await
            .assert_status(StatusCode::NO_CONTENT);
        assert!(last_call_was(
            &e.p,
            &RecordedCall::SetUploadLimit {
                handle: loaded,
                bytes_per_sec: rate
            }
        ));
    }
    for bad in [0u64, 3_000_000_000] {
        let resp = h
            .write_json("PUT", &path, json!({"bytes_per_sec": bad}))
            .await;
        assert_problem(&resp, 422, "validation-failed");
        assert_eq!(errors_at(&resp), ["/bytes_per_sec"]);
    }
    let resp = h
        .write_json("PUT", &path, json!({"bytes_per_sec": -1}))
        .await;
    assert_eq!(resp.status().as_u16(), 422, "not a u32");
    let resp = h
        .write_json("PUT", &path, json!({"bytes_per_sec": 1, "burst": 2}))
        .await;
    assert_eq!(resp.status().as_u16(), 422, "unknown fields are refused");
    h.write_json(
        "PUT",
        &format!("/v1/torrents/{}/upload-limit", hex(FENCED)),
        json!({"bytes_per_sec": 5}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    let resp = h
        .write_json(
            "PUT",
            &format!("/v1/torrents/{unknown}/upload-limit"),
            json!({"bytes_per_sec": 5}),
        )
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
    e.p.inject_error("set_upload_limit", injected("set_upload_limit"));
    let resp = h
        .write_json("PUT", &path, json!({"bytes_per_sec": 5}))
        .await;
    assert_problem(&resp, 500, "internal");
    body_framework_rejections(h, "PUT", &path, crate::http::v1::REQUEST_DEADLINE).await;
}

/// Issue #352: `POST /v1/torrents/{ih}/recheck` sent for twelve torrents in a
/// row, with `[pool] max_concurrent_verify = 4`, never has more than four
/// checking at once, and starts the rest as earlier checks end. Each used to
/// call `force_recheck` itself, so all twelve hashed at once, each with its
/// peers disconnected, while `torrentd_pool_verify_in_flight` read 0.
#[tokio::test]
async fn a_burst_of_rechecks_hashes_at_most_the_verify_limit_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    cfg.pool.as_mut().unwrap().max_concurrent_verify = 4;
    let pool = crate::pool_service::PoolService::open(&cfg)
        .unwrap()
        .expect("the config has [pool]");
    let hashes: Vec<InfoHash> = (0..12u8).map(|i| InfoHash([0x40 + i; 20])).collect();
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        let e = fixture(s, dir.path());
        for ih in &hashes {
            load(s, &e.p, *ih, "p", TorrentPhase::Seeding);
        }
        s.checks = crate::check_queue::VerifyQueue::for_daemon(Some(&pool));
        s.pool = Some(Arc::clone(&pool));
        engine = Some(e.p);
    });
    let engine = engine.unwrap();
    let rechecked = || -> Vec<InfoHash> {
        engine
            .calls()
            .iter()
            .filter_map(|c| match c {
                RecordedCall::ForceRecheck(h) => Some(h.infohash),
                _ => None,
            })
            .collect()
    };
    let recheck = |ih: InfoHash| {
        let h = &h;
        async move {
            h.write("POST", &format!("/v1/torrents/{}/recheck", hex(ih)))
                .await
                .assert_status(StatusCode::ACCEPTED);
        }
    };

    for ih in &hashes {
        recheck(*ih).await;
    }
    // Asked for twice, queued once.
    recheck(hashes[0]).await;
    assert!(
        rechecked().is_empty(),
        "nothing hashes before the verify queue admits it: {:?}",
        engine.calls(),
    );
    let q = pool.verify_queue();
    assert_eq!(q.depth(), 12);
    let resp = h.read("/v1/pool").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.json::<Value>()["verify_queue_depth"], 12);

    let tick = || {
        crate::check_queue::admit_tick_for_tests(
            pool.verify_queue(),
            Some(&pool),
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
        let started = rechecked();
        let checking = started.iter().filter(|h| !finished.contains(*h)).count();
        assert!(checking <= 4, "tick {n}: {checking} checking at once");
        assert_eq!(q.in_flight(), checking, "tick {n}");
        assert_eq!(q.depth(), 12 - started.len(), "tick {n}");
        peak = peak.max(checking);
        if started.len() == hashes.len() && checking == 0 {
            break;
        }
        // The session reports the oldest running check over, as
        // `torrent_checked` does: after the start, on any clock resolution.
        if let Some(ih) = started.iter().find(|h| !finished.contains(*h)) {
            std::thread::sleep(Duration::from_millis(2));
            h.state
                .state
                .update(ih, |st| st.checked_at = Some(Instant::now()));
            finished.insert(*ih);
        }
    }
    assert_eq!(
        rechecked(),
        hashes,
        "every torrent re-hashed once, in order"
    );
    assert_eq!(peak, 4, "the limit is reached, not merely respected");
    assert_eq!(q.in_flight(), 0);

    // A paused torrent starts no disk work, and the queue would drop its
    // re-hash: libtorrent is asked at once, as it always was, and marks it
    // to check once it is resumed.
    h.state
        .state
        .update(&LOADED, |st| st.phase = TorrentPhase::Paused);
    recheck(LOADED).await;
    assert_eq!(rechecked().last(), Some(&LOADED));
    assert_eq!(q.depth(), 0);

    // So does a magnet still without metadata: there is nothing to hash
    // against yet, and libtorrent checks it once its metadata arrives.
    let magnet = hashes[1];
    h.state
        .state
        .update(&magnet, |st| st.phase = TorrentPhase::AwaitingMetadata);
    let before = rechecked().len();
    recheck(magnet).await;
    assert_eq!(rechecked().len(), before + 1);
    assert_eq!(rechecked().last(), Some(&magnet));
    assert_eq!(q.depth(), 0);
    assert_eq!(q.in_flight(), 0);
}

/// The saves queued since the last call, as `(infohash, unconditional)`.
fn queued_saves(h: &Harness) -> Vec<(InfoHash, bool)> {
    h.state
        .state
        .dispatch_resume_saves(usize::MAX)
        .into_iter()
        .map(|(ih, flags)| {
            h.state.state.note_resume_settled(&ih);
            (ih, flags.is_empty())
        })
        .collect()
}

#[tokio::test]
async fn every_pause_the_api_takes_queues_an_unconditional_resume_save() {
    // Issue #311: a pause is saved at once, not at the next 30-minute sweep,
    // so a crash before it cannot bring the torrent back running. A torrent
    // whose pause the engine refused is not paused, and queues nothing.
    let dir = tempfile::tempdir().unwrap();
    let mut engines = None;
    let h = Harness::authed(&Coverage::new(), |s| engines = Some(fixture(s, dir.path())));
    let e = engines.unwrap();
    assert_eq!(queued_saves(&h), []);

    h.write("POST", &format!("/v1/torrents/{}/pause", hex(LOADED)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(queued_saves(&h), [(LOADED, true)]);

    let resp = h.write("POST", "/v1/profiles/p/pause-all").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.json::<Value>()["torrent_count"], 1);
    assert_eq!(queued_saves(&h), [(LOADED, true)]);

    e.p.inject_error("pause_torrent", injected("pause_torrent"));
    let resp = h.write("POST", "/v1/profiles/p/pause-all").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.json::<Value>()["failed_count"], 1);
    assert_eq!(queued_saves(&h), []);

    // Daemon-wide, the fenced profile's torrent is paused again, and saved
    // too.
    let resp = h.write("POST", "/v1/torrents/pause-all").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.json::<Value>()["torrent_count"], 2);
    let mut saves = queued_saves(&h);
    saves.sort_by_key(|(ih, _)| ih.0);
    assert_eq!(saves, [(LOADED, true), (FENCED, true)]);
}

#[tokio::test]
async fn a_pause_the_engine_refuses_restores_the_note_before_it() {
    // A refused pause leaves the torrent as it was, so what the kill-switch
    // fence and a set-online read as running is put back too: here the
    // running note a resume left, which a refused pause must not turn into a
    // paused one.
    let dir = tempfile::tempdir().unwrap();
    let mut engines = None;
    let h = Harness::authed(&Coverage::new(), |s| engines = Some(fixture(s, dir.path())));
    let e = engines.unwrap();
    let loaded = handle(&e.p, LOADED);
    let entry = h
        .state
        .profiles
        .resolve(&ProfileId::new("p"))
        .active()
        .unwrap();
    entry.note_running(loaded, true);

    e.p.inject_error("pause_torrent", injected("pause_torrent"));
    let resp = h
        .write("POST", &format!("/v1/torrents/{}/pause", hex(LOADED)))
        .await;
    assert_problem(&resp, 500, "internal");
    assert_eq!(
        entry.running(vec![(loaded, false)]),
        [(loaded, true)],
        "the resume's note stands",
    );
}
