//! Listing and reading torrents, and the phase counts that read the same
//! state.

use super::*;

pub(super) async fn listing(h: &Harness) {
    let page: Value = h.read("/v1/torrents").await.json();
    let items = page["items"].as_array().unwrap();
    let got: Vec<&str> = items
        .iter()
        .map(|t| t["infohash"].as_str().unwrap())
        .collect();
    let mut want = vec![hex(LOADED), hex(FENCED), hex(ADDING), hex(STALE)];
    want.sort();
    assert_eq!(got, want, "every assignment, loaded or not, by infohash");
    assert_eq!(page["next_cursor"], Value::Null);
    let loaded = items.iter().find(|t| t["infohash"] == hex(LOADED)).unwrap();
    assert_eq!(loaded["profile_id"], "p");
    assert_eq!(loaded["phase"], "seeding");
    assert_eq!(loaded["upload_rate"], 1234);
    assert_eq!(loaded["num_peers"], 3);
    assert_eq!(loaded["is_seeding"], true);
    // A listing reads nothing from the sessions, and says so by shape.
    assert!(loaded.get("session").is_none(), "{loaded}");
    assert!(loaded.get("name").is_none(), "{loaded}");
    let adding = items.iter().find(|t| t["infohash"] == hex(ADDING)).unwrap();
    assert_eq!(adding["phase"], "unknown");

    // Filtered by profile, including one that failed to come up.
    let only_p: Value = h.read("/v1/torrents?profile_id=p").await.json();
    let got: Vec<&str> = only_p["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["infohash"].as_str().unwrap())
        .collect();
    let mut want = vec![hex(LOADED), hex(ADDING)];
    want.sort();
    assert_eq!(got, want);
    let down: Value = h.read("/v1/torrents?profile_id=down").await.json();
    assert_eq!(down["items"].as_array().unwrap().len(), 1);
    assert_eq!(down["items"][0]["infohash"], hex(STALE));
    assert_eq!(down["items"][0]["profile_id"], "down");
    // An empty page would read as "this account has nothing", which is what a
    // typo would then tell the operator.
    let resp = h.read("/v1/torrents?profile_id=typo").await;
    assert_problem(&resp, 404, "profile-not-found");

    // Filtered by phase.
    let paused: Value = h.read("/v1/torrents?phase=paused").await.json();
    assert_eq!(paused["items"].as_array().unwrap().len(), 1);
    assert_eq!(paused["items"][0]["infohash"], hex(FENCED));
    let unknown: Value = h
        .read("/v1/torrents?phase=unknown&profile_id=p")
        .await
        .json();
    assert_eq!(unknown["items"].as_array().unwrap().len(), 1);
    assert_eq!(unknown["items"][0]["infohash"], hex(ADDING));
    let resp = h.read("/v1/torrents?phase=sleeping").await;
    assert_eq!(resp.status().as_u16(), 400, "a phase outside the enum");

    // Paged.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(c) => format!("/v1/torrents?limit=3&cursor={c}"),
            None => "/v1/torrents?limit=3".to_owned(),
        };
        let page: Value = h.read(&path).await.json();
        for t in page["items"].as_array().unwrap() {
            seen.push(t["infohash"].as_str().unwrap().to_owned());
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert!(seen.windows(2).all(|w| w[0] < w[1]));

    let resp = h.read("/v1/torrents?cursor=garbage!").await;
    assert_problem(&resp, 400, "invalid-cursor");
    let files_cursor = crate::http::page::encode("files", "0000000001");
    let resp = h.read(&format!("/v1/torrents?cursor={files_cursor}")).await;
    assert_problem(&resp, 400, "invalid-cursor");
    for bad in ["0", "1001"] {
        let resp = h.read(&format!("/v1/torrents?limit={bad}")).await;
        assert_problem(&resp, 422, "validation-failed");
        assert_eq!(errors_at(&resp), ["#/query/limit"]);
    }
}

pub(super) async fn reading(h: &Harness, e: &Engines) {
    e.p.set_torrent_details(
        handle(&e.p, LOADED),
        TorrentDetails {
            name: Some("loaded".into()),
            has_metadata: true,
            total_size: Some(4096),
            save_path: "/srv/data".into(),
            upload_limit: Some(2048),
            added_at: Some(1_700_000_000),
        },
    );
    let t: Value = h
        .read(&format!("/v1/torrents/{}", hex(LOADED)))
        .await
        .json();
    assert_eq!(t["session"]["name"], "loaded");
    assert_eq!(t["session"]["total_size"], 4096);
    assert_eq!(t["session"]["save_path"], "/srv/data");
    assert_eq!(t["session"]["upload_limit_bytes_per_sec"], 2048);
    assert_eq!(t["session"]["added_at"], "2023-11-14T22:13:20Z");
    assert_eq!(t["phase"], "seeding");
    assert_eq!(t["progress"], 1.0);

    // A session that cannot be asked costs the details, not the torrent.
    e.p.inject_error("torrent_details", injected("torrent_details"));
    let t: Value = h
        .read(&format!("/v1/torrents/{}", hex(LOADED)))
        .await
        .json();
    assert_eq!(t["session"], Value::Null);
    assert_eq!(t["phase"], "seeding");

    // Assigned but held by no session: reported, without details.
    for ih in [ADDING, STALE] {
        let t: Value = h.read(&format!("/v1/torrents/{}", hex(ih))).await.json();
        assert_eq!(t["phase"], "unknown");
        assert_eq!(t["session"], Value::Null);
        assert_eq!(t["upload_rate"], 0);
    }

    let resp = h
        .read(&format!("/v1/torrents/{}", hex(InfoHash([0xee; 20]))))
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
}

#[tokio::test]
async fn status_counts_every_phase_across_profiles() {
    // Every counter `GET /v1/status` reports, each non-zero, so a counter
    // wired to the wrong phase cannot hide behind a zero.
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::authed(&Coverage::new(), |s| {
        let e = fixture(s, dir.path());
        load(s, &e.p, InfoHash([20; 20]), "p", TorrentPhase::Seeding);
        load(s, &e.p, InfoHash([21; 20]), "p", TorrentPhase::Checking);
        load(s, &e.p, InfoHash([22; 20]), "p", TorrentPhase::DiskError);
        load(s, &e.p, InfoHash([23; 20]), "p", TorrentPhase::Errored);
        load(s, &e.f, InfoHash([24; 20]), "f", TorrentPhase::Paused);
    });
    let status: Value = h.read("/v1/status").await.json();
    // LOADED seeding, FENCED paused, ADDING and STALE assigned but not
    // loaded, and the five above.
    assert_eq!(status["torrents_total"], 9);
    assert_eq!(status["seeding"], 2);
    assert_eq!(status["paused"], 2);
    assert_eq!(status["checking"], 1);
    assert_eq!(status["disk_error"], 1);
    assert_eq!(status["errored"], 1);
    // Seven loaded torrents at 3 peers and 1234 B/s each.
    assert_eq!(status["peers_total"], 21);
    assert_eq!(status["upload_rate_total"], 7 * 1234);
    assert_eq!(status["download_rate_total"], 0);
    assert_eq!(status["profile_count"], 3);
}
