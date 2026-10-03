//! `pool`: the index, adoption, verification and mutation plans.

use std::path::Path;
use std::sync::Arc;

use kynos::http::StatusCode;
use serde_json::json;
use serde_json::Value;
use torrentd_engine::ProfileStatus;
use torrentd_pool::model::TorrentFileRow;
use torrentd_pool::AdoptionState;
use torrentd_pool::PoolFile;
use torrentd_pool::PoolTorrent;

use super::support::assert_problem;
use super::support::Coverage;
use super::support::Harness;
use crate::config::Config;
use crate::pool_service::PoolService;
use crate::profile_registry::test_entry;
use crate::profile_registry::test_failed_profile;
use crate::profile_registry::ProfileRegistry;

/// Matched under `movies/`, claiming both files there.
const IH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Partial, based under `movies/`, claiming nothing.
const IH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// In the library, never matched.
const IH_C: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn service(dir: &Path, allow_mutations: bool) -> Arc<PoolService> {
    PoolService::open(&Config::minimal_for_tests(dir, allow_mutations))
        .unwrap()
        .expect("the fixture configures [pool]")
}

fn write(root: &Path, rel: &str, len: usize) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, vec![7u8; len]).unwrap();
}

fn torrent(dir: &Path, infohash: &str, total_size: u64, num_files: usize) -> PoolTorrent {
    PoolTorrent {
        infohash: infohash.to_owned(),
        infohash_v1: None,
        infohash_v2: None,
        name: format!("t-{}", &infohash[..4]),
        total_size,
        num_files,
        source_path: dir.join("library").join(format!("{infohash}.torrent")),
        fastresume_path: None,
        declared_save_path: None,
        category: None,
        tags: vec![],
        profile: None,
    }
}

fn file_row(infohash: &str, idx: i64, rel_path: &str, size: u64) -> TorrentFileRow {
    TorrentFileRow {
        infohash: infohash.to_owned(),
        idx,
        rel_path: rel_path.to_owned(),
        size,
        pieces_root: None,
        pad_file: false,
    }
}

/// A pool whose one root holds
///
/// ```text
/// junk/orphan.bin   16  unclaimed
/// movies/a.bin      64  claimed by IH_A (matched)
/// movies/b.bin      32  claimed by IH_A
/// top.bin            8  unclaimed
/// ```
///
/// with IH_B partial and IH_C unmatched in the library. Written straight into
/// the index: a scan would need real `.torrent` files, and would rebuild the
/// claims this lays down.
fn fixture(dir: &Path, allow_mutations: bool) -> (Arc<PoolService>, i64) {
    let root = dir.join("pool");
    write(&root, "junk/orphan.bin", 16);
    write(&root, "movies/a.bin", 64);
    write(&root, "movies/b.bin", 32);
    write(&root, "top.bin", 8);
    let pool = service(dir, allow_mutations);
    pool.scan().unwrap();
    let root_id = pool.roots()[0].0;
    pool.with_store_mut(|st| {
        st.upsert_torrent(&torrent(dir, IH_A, 96, 2), 0).unwrap();
        st.upsert_torrent(&torrent(dir, IH_B, 10, 1), 0).unwrap();
        st.upsert_torrent(&torrent(dir, IH_C, 5, 1), 0).unwrap();
        st.replace_torrent_files(
            IH_A,
            &[
                file_row(IH_A, 0, "a.bin", 64),
                file_row(IH_A, 1, "b.bin", 32),
            ],
        )
        .unwrap();
        st.set_adoption(
            IH_A,
            AdoptionState::Matched,
            Some(root_id),
            Some("movies"),
            None,
            None,
            None,
        )
        .unwrap();
        st.set_adoption(
            IH_B,
            AdoptionState::Partial,
            Some(root_id),
            Some("movies"),
            None,
            None,
            None,
        )
        .unwrap();
        st.replace_claims(
            IH_A,
            &[
                (root_id, "movies/a.bin".to_owned()),
                (root_id, "movies/b.bin".to_owned()),
            ],
        )
        .unwrap();
    });
    (pool, root_id)
}

/// Profiles `p` (live), `down` (live, fenced) and `acct_b` (failed at boot).
fn profiles(s: &mut crate::app_state::AppState) {
    let reg = Arc::new(
        ProfileRegistry::new(vec![
            test_entry("p", ProfileStatus::Active),
            test_entry("down", ProfileStatus::VpnDown),
        ])
        .with_failed(vec![test_failed_profile(
            "acct_b",
            "wg-acct_b did not come up within 30s",
        )]),
    );
    *s = crate::app_state::build_test_state_with_sessions(Some(reg), &["p", "down"]);
}

/// Every pool operation, with a path that exists in the fixture.
const OPERATIONS: &[(&str, &str)] = &[
    ("GET", "/v1/pool"),
    ("GET", "/v1/pool/roots/1/tree"),
    ("GET", "/v1/pool/roots/1/orphans"),
    ("GET", "/v1/pool/torrents"),
    ("POST", "/v1/pool/scan"),
    ("POST", "/v1/pool/drift-check"),
    ("POST", "/v1/pool/adoptions"),
    ("POST", "/v1/pool/verifications"),
    ("GET", "/v1/pool/plans"),
    ("POST", "/v1/pool/plans"),
    ("GET", "/v1/pool/plans/1"),
    ("DELETE", "/v1/pool/plans/1"),
    ("POST", "/v1/pool/plans/1/apply"),
];

/// A well-formed body for each body-taking operation.
fn body_for(method: &str, path: &str) -> Option<Value> {
    match (method, path) {
        ("POST", "/v1/pool/adoptions") => Some(json!({
            "profile_id": "p",
            "dry_run": true,
            "selector": {"kind": "infohashes", "infohashes": [IH_A]},
        })),
        ("POST", "/v1/pool/verifications") => Some(json!({"infohashes": [IH_A]})),
        ("POST", "/v1/pool/plans") => Some(json!({
            "kind": "delete_orphans", "root_id": 1, "prefix": "junk",
        })),
        ("POST", "/v1/pool/plans/1/apply") => Some(json!({"confirm_token": null})),
        _ => None,
    }
}

/// Every declared response of the `pool` tag.
pub(crate) async fn scenarios(cov: &Arc<Coverage>) {
    reads(cov).await;
    adoption(cov).await;
    verification(cov).await;
    plans(cov).await;
    unconfigured_and_unauthorised(cov).await;
    internal_failures(cov).await;
    malformed_requests(cov).await;
    // The fault build's one operation has no tag of its own to run it.
}

#[tokio::test]
async fn pool_behaves_as_documented() {
    scenarios(&Coverage::new()).await;
}

fn items(v: &Value) -> Vec<Value> {
    v["items"].as_array().cloned().unwrap_or_default()
}

/// One string member of every item of a page.
fn field(page: &Value, key: &str) -> Vec<String> {
    items(page)
        .iter()
        .map(|e| e[key].as_str().unwrap().to_owned())
        .collect()
}

async fn reads(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), false);
    let h = Harness::authed(cov, |s| s.pool = Some(pool));

    // The overview: one root, its accounting, and closed state counts.
    let resp = h.read("/v1/pool").await;
    resp.assert_status(StatusCode::OK);
    let o: Value = resp.json();
    assert_eq!(o["roots"][0]["root_id"], root_id);
    assert_eq!(o["roots"][0]["bytes_total"], 120, "the rollup is flattened");
    assert_eq!(o["roots"][0]["bytes_matched"], 96);
    assert_eq!(o["roots"][0]["bytes_orphan"], 24);
    assert_eq!(o["torrents"], 3);
    assert_eq!(o["files"], 4);
    assert_eq!(
        o["states"],
        json!({"missing": 0, "partial": 1, "matched": 1, "adopted": 0, "drifted": 0, "overlap": 0,
               "shared": 0})
    );
    assert_eq!(o["verify_queue_depth"], 0);

    // The tree, paged: directories first, then files, and a cursor that
    // resumes exactly after the last entry.
    let tree = format!("/v1/pool/roots/{root_id}/tree");
    let first: Value = h.read(&format!("{tree}?limit=2")).await.json();
    let names = field(&first, "name");
    assert_eq!(names, ["junk", "movies"]);
    let movies = &first["items"][1];
    assert_eq!(movies["is_dir"], true);
    assert_eq!(movies["path"], "movies");
    assert_eq!(movies["bytes_matched"], 96);
    assert_eq!(movies["states"], json!(["matched"]));
    let cursor = first["next_cursor"].as_str().expect("a file follows");
    let second: Value = h
        .read(&format!("{tree}?limit=2&cursor={cursor}"))
        .await
        .json();
    assert_eq!(items(&second).len(), 1);
    assert_eq!(second["items"][0]["path"], "top.bin");
    assert_eq!(second["items"][0]["is_dir"], false);
    // A file row carries its own accounting, not the empty rollup of a
    // directory by that name.
    assert_eq!(second["items"][0]["bytes_total"], 8);
    assert_eq!(second["items"][0]["bytes_orphan"], 8);
    assert_eq!(second["items"][0]["files_total"], 1);
    assert_eq!(second["next_cursor"], Value::Null);
    // Inside a directory, with slashes forgiven.
    let inside: Value = h.read(&format!("{tree}?path=/movies/")).await.json();
    let paths = field(&inside, "path");
    assert_eq!(paths, ["movies/a.bin", "movies/b.bin"]);
    // Paged inside it: the cursor is a child of this directory, and it
    // resumes after the first entry.
    let first: Value = h.read(&format!("{tree}?path=movies&limit=1")).await.json();
    assert_eq!(field(&first, "path"), ["movies/a.bin"]);
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    let rest: Value = h
        .read(&format!("{tree}?path=movies&limit=1&cursor={cursor}"))
        .await
        .json();
    assert_eq!(field(&rest, "path"), ["movies/b.bin"]);
    assert_eq!(rest["next_cursor"], Value::Null);
    // The same cursor is refused on the root listing.
    let resp = h.read(&format!("{tree}?cursor={cursor}")).await;
    assert_problem(&resp, 400, "invalid-cursor");
    assert_eq!(inside["items"][0]["bytes_matched"], 64);
    assert_eq!(inside["items"][0]["bytes_orphan"], 0);
    assert_eq!(inside["items"][0]["states"], json!(["matched"]));

    // Orphans: only what holds unclaimed bytes, with no states.
    let orphans = format!("/v1/pool/roots/{root_id}/orphans");
    let o: Value = h.read(&orphans).await.json();
    let paths = field(&o, "path");
    assert_eq!(paths, ["junk", "top.bin"]);
    assert_eq!(o["items"][0]["states"], json!([]));
    let o: Value = h.read(&format!("{orphans}?limit=1")).await.json();
    let cursor = o["next_cursor"].as_str().unwrap();
    let o: Value = h
        .read(&format!("{orphans}?limit=1&cursor={cursor}"))
        .await
        .json();
    assert_eq!(o["items"][0]["path"], "top.bin");
    assert_eq!(o["next_cursor"], Value::Null);

    // An unknown root, a garbled cursor, a cursor from another listing and an
    // out-of-range limit.
    for listing in ["tree", "orphans"] {
        let resp = h.read(&format!("/v1/pool/roots/999/{listing}")).await;
        assert_problem(&resp, 404, "root-not-found");
        let resp = h
            .read(&format!("/v1/pool/roots/{root_id}/{listing}?cursor=!!"))
            .await;
        assert_problem(&resp, 400, "invalid-cursor");
        let foreign = crate::http::page::encode("pool-torrents", IH_A);
        let resp = h
            .read(&format!(
                "/v1/pool/roots/{root_id}/{listing}?cursor={foreign}"
            ))
            .await;
        assert_problem(&resp, 400, "invalid-cursor");
        // A cursor for this listing of another directory — including one
        // whose path would make its name a prefix of this one's — or of
        // another root, and a key no child of this directory could have.
        let name = format!(
            "pool-{}",
            if listing == "tree" { "tree" } else { "orphans" }
        );
        for (listing_name, key) in [
            (format!("{name}:{root_id}:5:a:dfo"), "da:dfo/x".to_owned()),
            (format!("{name}:{}:0:", root_id + 1), "dx".to_owned()),
            (format!("{name}:{root_id}:0:"), "zzz".to_owned()),
            (format!("{name}:{root_id}:0:"), "fa/b".to_owned()),
        ] {
            let cursor = crate::http::page::encode(&listing_name, &key);
            let resp = h
                .read(&format!(
                    "/v1/pool/roots/{root_id}/{listing}?cursor={cursor}"
                ))
                .await;
            assert_problem(&resp, 400, "invalid-cursor");
        }
        let resp = h
            .read(&format!("/v1/pool/roots/{root_id}/{listing}?limit=0"))
            .await;
        assert_problem(&resp, 422, "validation-failed");
        let body: Value = resp.json();
        assert_eq!(body["errors"][0]["pointer"], "#/query/limit");
        // A root id that is not a number never reaches the handler.
        let resp = h.read(&format!("/v1/pool/roots/abc/{listing}")).await;
        assert_eq!(resp.status().as_u16(), 400);
    }

    // The library, in infohash order, filtered and paged.
    let all: Value = h.read("/v1/pool/torrents").await.json();
    let ihs = field(&all, "infohash");
    assert_eq!(ihs, [IH_A, IH_B, IH_C]);
    assert_eq!(all["items"][0]["state"], "matched");
    assert_eq!(all["items"][0]["base_rel"], "movies");
    assert_eq!(all["items"][0]["num_files"], 2);
    assert_eq!(all["items"][2]["state"], Value::Null);
    let matched: Value = h.read("/v1/pool/torrents?state=matched").await.json();
    assert_eq!(items(&matched).len(), 1);
    assert_eq!(matched["items"][0]["infohash"], IH_A);
    let page: Value = h.read("/v1/pool/torrents?limit=2").await.json();
    let cursor = page["next_cursor"].as_str().unwrap();
    let page: Value = h
        .read(&format!("/v1/pool/torrents?limit=2&cursor={cursor}"))
        .await
        .json();
    assert_eq!(page["items"][0]["infohash"], IH_C);
    assert_eq!(page["next_cursor"], Value::Null);
    let resp = h.read("/v1/pool/torrents?state=bogus").await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "the state filter is a closed enum"
    );
    let resp = h.read("/v1/pool/torrents?cursor=!!").await;
    assert_problem(&resp, 400, "invalid-cursor");
    let resp = h.read("/v1/pool/torrents?limit=1001").await;
    assert_problem(&resp, 422, "validation-failed");

    // A scan re-indexes and reports what it found. The library is empty on
    // disk, so the hand-written torrents are gone afterwards.
    let resp = h.write("POST", "/v1/pool/scan").await;
    resp.assert_status(StatusCode::OK);
    let summary: Value = resp.json();
    assert_eq!(summary["files"], 4);
    assert_eq!(summary["bytes"], 120);

    // A drift check with nothing matched finds nothing.
    let resp = h.write("POST", "/v1/pool/drift-check").await;
    resp.assert_status(StatusCode::OK);
    let report: Value = resp.json();
    assert_eq!(report["drifted"], json!([]));

    h.assert_conformance();
}

#[tokio::test]
async fn a_drift_check_marks_a_torrent_whose_payload_vanished() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));
    std::fs::remove_file(dir.path().join("pool/movies/b.bin")).unwrap();
    let report: Value = h.write("POST", "/v1/pool/drift-check").await.json();
    assert_eq!(report["drifted"], json!([IH_A]));
    assert_eq!(report["files_vanished"], 1);
    let t: Value = h.read("/v1/pool/torrents?state=drifted").await.json();
    assert_eq!(t["items"][0]["infohash"], IH_A);
}

#[tokio::test]
async fn a_scan_or_drift_check_holds_the_work_gate_after_its_request_is_gone() {
    // The teardown waits on the gate for the blocking task, not the request:
    // a drain that cut the request off, or a client that went away, used to
    // leave the task running while the sessions it works through closed.
    use std::time::Duration;

    for path in ["/v1/pool/scan", "/v1/pool/drift-check"] {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _) = fixture(dir.path(), false);
        let held = Arc::clone(&pool);
        let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));

        // Block the task on the store, then abandon its request.
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            held.with_store(|_| {
                locked_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
        });
        locked_rx.recv().unwrap();
        let abandoned =
            tokio::time::timeout(Duration::from_millis(300), h.write("POST", path)).await;
        assert!(abandoned.is_err(), "{path} finished with the store held");
        assert_eq!(
            h.state.work.in_flight(),
            1,
            "{path}'s blocking task no longer counts once its request is gone",
        );

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(
            h.state.work.wait_idle(Duration::from_secs(10)).await,
            "{path} released the gate when its task finished",
        );
    }
}

fn adopt(profile_id: &str, dry_run: bool, selector: Value) -> Option<Value> {
    Some(json!({"profile_id": profile_id, "dry_run": dry_run, "selector": selector}))
}

async fn adoption(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), false);
    let h = Harness::authed(cov, |s| {
        profiles(s);
        s.pool = Some(pool);
    });
    let w = h.tokens.write.clone();
    let post = |body| h.send("POST", "/v1/pool/adoptions", Some(&w), body);

    // A dry run over the subtree: what would be verified, what is refused and
    // why, and nothing claimed.
    let resp = post(adopt(
        "p",
        true,
        json!({"kind": "subtree", "root_id": root_id, "path": ""}),
    ))
    .await;
    resp.assert_status(StatusCode::OK);
    let r: Value = resp.json();
    assert_eq!(r["dry_run"], true);
    assert_eq!(r["queued_for_verification"], json!([IH_A]));
    assert_eq!(r["verify_bytes"], 96);
    assert_eq!(r["refused"][0]["infohash"], IH_B);
    assert!(r["refused"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("incomplete"));
    assert_eq!(h.state.registry.len(), 0, "a dry run claims nothing");

    // By infohash, for real: the partial one is refused before the registry
    // is touched, the matched one is claimed for the profile and queued.
    let r: Value = post(adopt(
        "p",
        false,
        json!({"kind": "infohashes", "infohashes": [IH_B, IH_A]}),
    ))
    .await
    .json();
    assert_eq!(r["refused"][0]["infohash"], IH_B);
    assert_eq!(r["queued_for_verification"], json!([IH_A]));
    let a = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    assert_eq!(
        h.state.registry.lookup(&a),
        Some(torrentd_engine::ProfileId::new("p"))
    );
    // Adopting it again is refused by the registry, not by a session.
    let r: Value = post(adopt(
        "p",
        false,
        json!({"kind": "infohashes", "infohashes": [IH_A]}),
    ))
    .await
    .json();
    assert!(
        r["refused"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("already"),
        "{r}"
    );

    // Profiles: unknown, failed at boot (with the reason — the whole point),
    // and fenced.
    let resp = post(adopt(
        "nope",
        true,
        json!({"kind": "infohashes", "infohashes": [IH_A]}),
    ))
    .await;
    assert_problem(&resp, 404, "profile-not-found");
    let resp = post(adopt(
        "acct_b",
        true,
        json!({"kind": "infohashes", "infohashes": [IH_A]}),
    ))
    .await;
    assert_problem(&resp, 409, "profile-unavailable");
    let body: Value = resp.json();
    assert_eq!(body["profile_status"], "failed");
    assert!(
        body["detail"].as_str().unwrap().contains("did not come up"),
        "{body}"
    );
    let resp = post(adopt(
        "down",
        true,
        json!({"kind": "infohashes", "infohashes": [IH_A]}),
    ))
    .await;
    assert_problem(&resp, 409, "profile-unavailable");
    let body: Value = resp.json();
    assert_eq!(body["profile_status"], "vpn_down");

    // An unknown root in the selector.
    let resp = post(adopt(
        "p",
        true,
        json!({"kind": "subtree", "root_id": 999, "path": ""}),
    ))
    .await;
    assert_problem(&resp, 404, "root-not-found");

    // The selector's bounds.
    let resp = post(adopt(
        "p",
        true,
        json!({"kind": "infohashes", "infohashes": []}),
    ))
    .await;
    assert_problem(&resp, 422, "validation-failed");
    let body: Value = resp.json();
    assert_eq!(body["errors"][0]["pointer"], "/selector/infohashes");
    let many: Vec<String> = (0..1001).map(|i| format!("{i:040x}")).collect();
    let resp = post(adopt(
        "p",
        true,
        json!({"kind": "infohashes", "infohashes": many}),
    ))
    .await;
    assert_problem(&resp, 422, "validation-failed");

    // `profile_id` is required: a request without one does not parse. The
    // shipped web client once sent `{root_id, path}` and nothing else, and
    // every adopt it made was dead.
    let resp = post(Some(
        json!({"selector": {"kind": "subtree", "root_id": root_id, "path": ""}}),
    ))
    .await;
    assert_eq!(resp.status().as_u16(), 422);
    // The old either/or shape is gone.
    let resp = post(Some(
        json!({"profile_id": "p", "root_id": root_id, "path": ""}),
    ))
    .await;
    assert_eq!(resp.status().as_u16(), 422);
    let resp = post(adopt(
        "p",
        true,
        json!({"kind": "subtree", "root_id": root_id, "path": "", "x": 1}),
    ))
    .await;
    assert_eq!(resp.status().as_u16(), 422, "the selector is closed");

    h.assert_conformance();
}

#[tokio::test]
async fn adoption_ignores_allow_mutations() {
    // Adoption records an existing file's ownership; it is deliberately
    // outside the `allow_mutations` switch.
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    assert!(!pool.allow_mutations());
    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));
    let resp = h
        .send(
            "POST",
            "/v1/pool/adoptions",
            Some(&h.tokens.write.clone()),
            adopt(
                "p",
                false,
                json!({"kind": "infohashes", "infohashes": [IH_A]}),
            ),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let r: Value = resp.json();
    assert_eq!(r["queued_for_verification"], json!([IH_A]));
}

async fn verification(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let h = Harness::authed(cov, |s| s.pool = Some(pool));
    let a = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    h.state.state.insert(
        a,
        torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle { id: 1, infohash: a },
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        ),
    );
    let w = h.tokens.write.clone();
    let resp = h
        .send(
            "POST",
            "/v1/pool/verifications",
            Some(&w),
            Some(json!({"infohashes": [IH_A, IH_C]})),
        )
        .await;
    resp.assert_status(StatusCode::ACCEPTED);
    let r: Value = resp.json();
    assert_eq!(r["requested"], 2);
    assert_eq!(r["started"], json!([IH_A]));
    assert_eq!(r["skipped"][0]["infohash"], IH_C);
    assert_eq!(r["skipped"][0]["reason"], "not loaded in any session");

    let resp = h
        .send(
            "POST",
            "/v1/pool/verifications",
            Some(&w),
            Some(json!({"infohashes": []})),
        )
        .await;
    assert_problem(&resp, 422, "validation-failed");
    let body: Value = resp.json();
    assert_eq!(body["errors"][0]["pointer"], "/infohashes");
    // Not an infohash: refused where it is parsed.
    let resp = h
        .send(
            "POST",
            "/v1/pool/verifications",
            Some(&w),
            Some(json!({"infohashes": ["zz"]})),
        )
        .await;
    assert_eq!(resp.status().as_u16(), 422);
    h.assert_conformance();

    // A fenced profile's torrents are skipped, as resume-all skips them: a
    // recheck puts the torrent back on the network once it finishes.
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let h = Harness::authed(cov, |s| {
        profiles(s);
        s.pool = Some(pool);
    });
    for (ih, profile) in [(IH_A, "p"), (IH_C, "down")] {
        let hash = libtorrent_safe::InfoHash::from_hex(ih).unwrap();
        h.state.state.insert(
            hash,
            torrentd_engine::TorrentState::newly_added(
                torrentd_engine::TorrentHandle {
                    id: 1,
                    infohash: hash,
                },
                torrentd_engine::ProfileId::new(profile),
                std::time::Instant::now(),
            ),
        );
    }
    let resp = h
        .send(
            "POST",
            "/v1/pool/verifications",
            Some(&h.tokens.write.clone()),
            Some(json!({"infohashes": [IH_A, IH_C]})),
        )
        .await;
    resp.assert_status(StatusCode::ACCEPTED);
    let r: Value = resp.json();
    assert_eq!(r["started"], json!([IH_A]));
    assert_eq!(r["skipped"][0]["infohash"], IH_C);
    let reason = r["skipped"][0]["reason"].as_str().unwrap();
    assert!(reason.contains("vpn_down"), "{reason}");
    h.assert_conformance();
}

async fn plans(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), true);
    let store = Arc::clone(&pool);
    let h = Harness::authed(cov, |s| s.pool = Some(pool));
    let w = h.tokens.write.clone();

    // A delete plan: created, located, described with its confirm token.
    let resp = h
        .send(
            "POST",
            "/v1/pool/plans",
            Some(&w),
            Some(json!({"kind": "delete_orphans", "root_id": root_id, "prefix": "junk"})),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
    let plan: Value = resp.json();
    let id = plan["id"].as_i64().unwrap();
    resp.assert_header("location", &format!("/v1/pool/plans/{id}"));
    assert_eq!(plan["kind"], "delete_orphans");
    assert_eq!(plan["status"], "draft");
    assert!(plan["created_at"].is_string());
    assert_eq!(plan["applied_at"], Value::Null);
    assert_eq!(plan["steps"][0]["op"], "delete_file");
    assert_eq!(plan["steps"][0]["status"], "pending");
    assert_eq!(plan["steps"][0]["dst"], Value::Null);
    let token = plan["confirm_token"].as_str().unwrap().to_owned();
    let fetched: Value = h.read(&format!("/v1/pool/plans/{id}")).await.json();
    assert_eq!(fetched, plan);

    // The planner's refusal is a 409 with its reason.
    let resp = h
        .send(
            "POST",
            "/v1/pool/plans",
            Some(&w),
            Some(json!({"kind": "relocate", "infohash": IH_B, "dest_root_id": root_id, "dest_rel": "elsewhere"})),
        )
        .await;
    assert_problem(&resp, 409, "plan-refused");
    let body: Value = resp.json();
    assert!(
        body["detail"].as_str().unwrap().contains("partial"),
        "{body}"
    );

    // Applying a delete takes its token: absent, then wrong, then right.
    let apply = format!("/v1/pool/plans/{id}/apply");
    let resp = h
        .send(
            "POST",
            &apply,
            Some(&w),
            Some(json!({"confirm_token": null})),
        )
        .await;
    assert_problem(&resp, 422, "confirm-token-required");
    let resp = h.send("POST", &apply, Some(&w), Some(json!({}))).await;
    assert_problem(&resp, 422, "confirm-token-required");
    let resp = h
        .send(
            "POST",
            &apply,
            Some(&w),
            Some(json!({"confirm_token": "0000000000000000"})),
        )
        .await;
    assert_problem(&resp, 422, "confirm-token-mismatch");
    assert!(dir.path().join("pool/junk/orphan.bin").exists());
    let resp = h
        .send(
            "POST",
            &apply,
            Some(&w),
            Some(json!({"confirm_token": token})),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let outcome: Value = resp.json();
    assert_eq!(
        outcome,
        json!({"plan_id": id, "done": 1, "failed": 0, "skipped": 0, "status": "applied"})
    );
    assert!(!dir.path().join("pool/junk/orphan.bin").exists());
    // An applied plan is not applied twice.
    let resp = h
        .send(
            "POST",
            &apply,
            Some(&w),
            Some(json!({"confirm_token": token})),
        )
        .await;
    assert_problem(&resp, 409, "plan-not-draft");

    // The listing, oldest first, filtered and paged.
    let second: Value = h
        .send(
            "POST",
            "/v1/pool/plans",
            Some(&w),
            Some(json!({"kind": "delete_orphans", "root_id": root_id, "prefix": ""})),
        )
        .await
        .json();
    let id2 = second["id"].as_i64().unwrap();
    let list: Value = h.read("/v1/pool/plans").await.json();
    let ids: Vec<i64> = items(&list)
        .iter()
        .map(|p| p["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [id, id2]);
    assert!(
        list["items"][0].get("steps").is_none(),
        "a listing carries no steps"
    );
    let drafts: Value = h.read("/v1/pool/plans?status=draft").await.json();
    assert_eq!(drafts["items"][0]["id"], id2);
    assert_eq!(items(&drafts).len(), 1);
    let page: Value = h.read("/v1/pool/plans?limit=1").await.json();
    let cursor = page["next_cursor"].as_str().unwrap();
    let page: Value = h
        .read(&format!("/v1/pool/plans?limit=1&cursor={cursor}"))
        .await
        .json();
    assert_eq!(page["items"][0]["id"], id2);
    assert_eq!(page["next_cursor"], Value::Null);
    let resp = h.read("/v1/pool/plans?cursor=!!").await;
    assert_problem(&resp, 400, "invalid-cursor");
    let resp = h.read("/v1/pool/plans?limit=0").await;
    assert_problem(&resp, 422, "validation-failed");
    let resp = h.read("/v1/pool/plans?status=bogus").await;
    assert_eq!(resp.status().as_u16(), 400);

    // A plan a crash left mid-step: it is failed, and applying it again stops
    // on the unknown step rather than guessing.
    store.with_store(|st| {
        st.set_plan_status(id2, torrentd_pool::model::plan_status::FAILED, None)
            .unwrap();
        st.set_step_status(id2, 0, torrentd_pool::model::step_status::IN_PROGRESS, None)
            .unwrap();
    });
    let token2 = second["confirm_token"].as_str().unwrap();
    let resp = h
        .send(
            "POST",
            &format!("/v1/pool/plans/{id2}/apply"),
            Some(&w),
            Some(json!({"confirm_token": token2})),
        )
        .await;
    assert_problem(&resp, 409, "apply-failed");
    let body: Value = resp.json();
    assert!(
        body["detail"].as_str().unwrap().contains("interrupted"),
        "{body}"
    );

    // A plan mid-apply is neither discarded nor applied again.
    let third: Value = h
        .send(
            "POST",
            "/v1/pool/plans",
            Some(&w),
            Some(json!({"kind": "delete_orphans", "root_id": root_id, "prefix": ""})),
        )
        .await
        .json();
    let id3 = third["id"].as_i64().unwrap();
    assert!(store
        .with_store(|st| st.claim_plan_for_apply(id3, false))
        .unwrap());
    let resp = h
        .send("DELETE", &format!("/v1/pool/plans/{id3}"), Some(&w), None)
        .await;
    assert_problem(&resp, 409, "plan-applying");
    let resp = h
        .send(
            "POST",
            &format!("/v1/pool/plans/{id3}/apply"),
            Some(&w),
            Some(json!({"confirm_token": third["confirm_token"]})),
        )
        .await;
    assert_problem(&resp, 409, "plan-not-draft");

    // Discarding: gone, then not found.
    let resp = h
        .send("DELETE", &format!("/v1/pool/plans/{id}"), Some(&w), None)
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);
    let resp = h.read(&format!("/v1/pool/plans/{id}")).await;
    assert_problem(&resp, 404, "plan-not-found");
    let resp = h
        .send("DELETE", &format!("/v1/pool/plans/{id}"), Some(&w), None)
        .await;
    assert_problem(&resp, 404, "plan-not-found");
    let resp = h
        .send(
            "POST",
            &format!("/v1/pool/plans/{id}/apply"),
            Some(&w),
            Some(json!({"confirm_token": null})),
        )
        .await;
    assert_problem(&resp, 404, "plan-not-found");
    for path in ["/v1/pool/plans/abc", "/v1/pool/plans/abc/apply"] {
        let method = if path.ends_with("apply") {
            "POST"
        } else {
            "DELETE"
        };
        let resp = h
            .send(method, path, Some(&w), Some(json!({"confirm_token": null})))
            .await;
        assert_eq!(resp.status().as_u16(), 400, "{method} {path}");
    }
    let resp = h.read("/v1/pool/plans/abc").await;
    assert_eq!(resp.status().as_u16(), 400);

    // The body of an apply is required, and closed.
    let resp = h
        .send_with(
            "POST",
            &format!("/v1/pool/plans/{id2}/apply"),
            Some(&w),
            None,
            &[("content-type", "application/json")],
        )
        .await;
    assert_eq!(resp.status().as_u16(), 400);
    let resp = h
        .send(
            "POST",
            &format!("/v1/pool/plans/{id2}/apply"),
            Some(&w),
            Some(json!({"confirm": token2})),
        )
        .await;
    assert_eq!(resp.status().as_u16(), 422, "the old field name is refused");
    h.assert_conformance();

    // Without `allow_mutations`, neither creating nor applying a plan.
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), false);
    let h = Harness::authed(cov, |s| s.pool = Some(pool));
    let w = h.tokens.write.clone();
    let resp = h
        .send(
            "POST",
            "/v1/pool/plans",
            Some(&w),
            Some(json!({"kind": "delete_orphans", "root_id": root_id, "prefix": ""})),
        )
        .await;
    assert_problem(&resp, 403, "mutations-disabled");
    let resp = h
        .send(
            "POST",
            "/v1/pool/plans/1/apply",
            Some(&w),
            Some(json!({"confirm_token": null})),
        )
        .await;
    assert_problem(&resp, 403, "mutations-disabled");
    h.assert_conformance();
}

async fn unconfigured_and_unauthorised(cov: &Arc<Coverage>) {
    let h = Harness::authed(cov, |_| {});
    for (method, path) in OPERATIONS {
        let body = body_for(method, path);
        let token = if *method == "GET" {
            h.tokens.read.clone()
        } else {
            h.tokens.write.clone()
        };
        let resp = h.send(method, path, Some(&token), body.clone()).await;
        assert_problem(&resp, 404, "pool-not-configured");

        let resp = h.send(method, path, None, body.clone()).await;
        assert_eq!(resp.status().as_u16(), 401, "{method} {path}");
        let resp = h
            .send(method, path, Some(&h.tokens.metrics.clone()), body.clone())
            .await;
        assert_problem(&resp, 403, "insufficient-scope");
        if *method != "GET" {
            let resp = h
                .send(method, path, Some(&h.tokens.read.clone()), body)
                .await;
            assert_problem(&resp, 403, "insufficient-scope");
        }
    }
    h.assert_conformance();
}

async fn malformed_requests(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), true);
    let h = Harness::authed(cov, |s| s.pool = Some(pool));
    let w = h.tokens.write.clone();
    for (method, path) in OPERATIONS {
        if body_for(method, path).is_none() {
            continue;
        }
        let resp = h
            .send_with(
                method,
                path,
                Some(&w),
                None,
                &[("content-type", "application/json")],
            )
            .await;
        assert_eq!(resp.status().as_u16(), 400, "{method} {path}: no JSON");
        let resp = h
            .send_with(
                method,
                path,
                Some(&w),
                None,
                &[("content-type", "text/plain")],
            )
            .await;
        assert_eq!(resp.status().as_u16(), 415, "{method} {path}");
        let resp = h
            .send(method, path, Some(&w), Some(json!({"nope": 1})))
            .await;
        assert_eq!(
            resp.status().as_u16(),
            422,
            "{method} {path}: unknown member"
        );
        let huge = "x".repeat(crate::http::v1::MAX_BODY_BYTES + 1);
        let resp = h
            .send(method, path, Some(&w), Some(json!({"pad": huge})))
            .await;
        assert_eq!(resp.status().as_u16(), 413, "{method} {path}");
        // Applying a plan waits for every step and carries no deadline, so
        // a stalled body there is bounded by nothing but `write`; every
        // other operation cuts one off.
        if !path.ends_with("/apply") {
            let (status, _) = h.slow_body(method, path, Some(&w)).await;
            assert_eq!(status.as_u16(), 408, "{method} {path}: stalled body");
        }
    }
    h.assert_conformance();
}

/// Hold the pool index's write lock from a second connection until the
/// returned sender is dropped, as `torrentd pool scan` from the CLI would.
fn hold_write_lock(db: std::path::PathBuf) -> std::sync::mpsc::Sender<()> {
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut other = torrentd_pool::PoolStore::open(&db).unwrap();
        other
            .in_transaction(|_| {
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
                Ok::<(), torrentd_pool::PoolError>(())
            })
            .unwrap();
    });
    held_rx.recv().unwrap();
    release_tx
}

/// The pool index failing, one way per operation: every one of these is a
/// `500 internal` that names what was attempted and not why.
async fn internal_failures(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let pool = service(dir.path(), true);
    let root_id = pool.roots()[0].0;
    const BAD: &str = "not-an-infohash";
    pool.with_store_mut(|st| {
        // Two files whose sizes sum past `i64::MAX`: SQLite refuses the
        // rollup with an integer overflow.
        let huge = |rel: &str, ino| PoolFile {
            root_id,
            rel_path: rel.to_owned(),
            size: i64::MAX as u64,
            mtime_ns: 0,
            ino,
            dev: 1,
            v2_root: None,
        };
        st.replace_root_files(root_id, &[huge("big/x", 1), huge("big/y", 2)], 0)
            .unwrap();
        // A library row that is not an infohash, matched under `big/` with a
        // file that is not on disk, so a drift check reports it.
        st.upsert_torrent(&torrent(dir.path(), BAD, 1, 1), 0)
            .unwrap();
        st.replace_torrent_files(BAD, &[file_row(BAD, 0, "x", 1)])
            .unwrap();
        st.set_adoption(
            BAD,
            AdoptionState::Matched,
            Some(root_id),
            Some("big"),
            None,
            None,
            None,
        )
        .unwrap();
        // A plan of a kind this build has no name for.
        st.create_plan("bogus", "{}", 0).unwrap();
    });
    let bogus_plan = pool
        .with_store(|st| st.plans())
        .unwrap()
        .first()
        .unwrap()
        .id;
    let h = Harness::authed(cov, |s| s.pool = Some(pool));
    let w = h.tokens.write.clone();
    let assert_internal = |resp: &kynos::test::TestResponse| {
        assert_problem(resp, 500, "internal");
        let body: Value = resp.json();
        assert!(
            body["detail"]
                .as_str()
                .unwrap()
                .contains("the daemon's log has the cause"),
            "{body}"
        );
    };

    assert_internal(&h.read("/v1/pool").await);
    assert_internal(&h.read(&format!("/v1/pool/roots/{root_id}/tree")).await);
    assert_internal(&h.read(&format!("/v1/pool/roots/{root_id}/orphans")).await);
    assert_internal(&h.read("/v1/pool/torrents").await);
    assert_internal(
        &h.send(
            "POST",
            "/v1/pool/adoptions",
            Some(&w),
            adopt(
                "p",
                true,
                json!({"kind": "subtree", "root_id": root_id, "path": ""}),
            ),
        )
        .await,
    );
    assert_internal(&h.write("POST", "/v1/pool/drift-check").await);
    assert_internal(&h.read("/v1/pool/plans").await);
    assert_internal(&h.read(&format!("/v1/pool/plans/{bogus_plan}")).await);
    assert_internal(
        &h.send(
            "POST",
            &format!("/v1/pool/plans/{bogus_plan}/apply"),
            Some(&w),
            Some(json!({"confirm_token": null})),
        )
        .await,
    );

    // Writers, while another process holds the index's write lock.
    let release = hold_write_lock(dir.path().join("pool.db"));
    assert_internal(&h.write("POST", "/v1/pool/scan").await);
    assert_internal(
        &h.send(
            "POST",
            "/v1/pool/plans",
            Some(&w),
            Some(json!({"kind": "delete_orphans", "root_id": root_id, "prefix": "big"})),
        )
        .await,
    );
    assert_internal(
        &h.send(
            "DELETE",
            &format!("/v1/pool/plans/{bogus_plan}"),
            Some(&w),
            None,
        )
        .await,
    );
    drop(release);
    h.assert_conformance();
}
