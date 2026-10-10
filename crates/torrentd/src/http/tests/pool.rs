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
use crate::profile_registry::ProfileEntry;
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
        // What the matcher ends with, since this stands in for it: the
        // materialised tree is read off the claim set.
        st.rebuild_all_rollups().unwrap();
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

/// The body-taking operations mounted without `REQUEST_DEADLINE`.
const UNTIMED: &[(&str, &str)] = &[
    ("POST", "/v1/pool/adoptions"),
    ("POST", "/v1/pool/plans"),
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

#[tokio::test]
async fn every_read_answers_while_a_scan_holds_the_writer() {
    // A scan holds the writer for its whole run — on a large pool, an hour.
    // Every read goes through the read connection, which sees the last
    // committed index meanwhile; before, each waited on the writer's mutex.
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), false);
    let held = Arc::clone(&pool);
    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        held.with_store_mut(|st| {
            st.in_transaction(|_| {
                locked_tx.send(()).unwrap();
                let _ = release_rx.recv();
                Ok::<(), torrentd_pool::PoolError>(())
            })
        })
        .unwrap();
    });
    locked_rx.recv().unwrap();

    for path in [
        "/v1/pool".to_owned(),
        "/v1/pool/torrents".to_owned(),
        "/v1/pool/torrents?state=matched".to_owned(),
        format!("/v1/pool/roots/{root_id}/tree"),
        format!("/v1/pool/roots/{root_id}/tree?path=movies"),
        format!("/v1/pool/roots/{root_id}/orphans"),
        "/v1/pool/plans".to_owned(),
    ] {
        let resp = tokio::time::timeout(Duration::from_secs(5), h.read(&path))
            .await
            .unwrap_or_else(|_| panic!("{path} waited on the writer"));
        assert_eq!(resp.status(), 200, "{path}");
    }
    let t: Value = h.read("/v1/pool/torrents?state=matched").await.json();
    assert_eq!(
        field(&t, "infohash"),
        [IH_A],
        "the committed index, in full"
    );

    release_tx.send(()).unwrap();
    holder.join().unwrap();
}

#[tokio::test]
async fn an_adoption_or_plan_waiting_on_a_scan_answers_with_its_outcome_past_the_deadline() {
    // Adopting and creating a plan wait on the writer, which a scan holds
    // for its whole run. Under `REQUEST_DEADLINE` either answered `408`
    // after 30 s and then ran to completion all the same, so the client
    // never saw the outcome and torrentctl offered the adoption again.
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), true);
    let held = Arc::clone(&pool);
    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));
    let w = h.tokens.write.clone();

    for (path, body) in [
        (
            "/v1/pool/adoptions",
            adopt(
                "p",
                false,
                json!({"kind": "infohashes", "infohashes": [IH_A]}),
            ),
        ),
        (
            "/v1/pool/plans",
            Some(json!({"kind": "delete_orphans", "root_id": root_id, "prefix": "junk"})),
        ),
    ] {
        // A scan in progress.
        let held = Arc::clone(&held);
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            held.with_store_mut(|st| {
                st.in_transaction(|_| {
                    locked_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                    Ok::<(), torrentd_pool::PoolError>(())
                })
            })
            .unwrap();
        });
        locked_rx.recv().unwrap();

        // Run the clock past the deadline while the request waits on the
        // writer, then let the scan finish.
        tokio::time::pause();
        let (resp, ()) = tokio::join!(h.send("POST", path, Some(&w), body), async {
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            tokio::time::advance(crate::http::v1::REQUEST_DEADLINE + Duration::from_secs(1)).await;
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            release_tx.send(()).unwrap();
        });
        tokio::time::resume();
        holder.join().unwrap();

        assert!(
            resp.status().is_success(),
            "{path}: answered {} once the scan finished",
            resp.status()
        );
    }
    let a = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    assert_eq!(
        h.state.registry.lookup(&a),
        Some(torrentd_engine::ProfileId::new("p")),
        "adopted, and said so",
    );
}

#[tokio::test]
async fn a_token_read_before_a_scan_does_not_apply_after_it() {
    // The plan reads come from the read connection, which shows the index
    // as it was before a running scan. A confirm token taken from that view
    // binds the old generation; once the scan commits it must no longer
    // apply, or the plan deletes files the rescan may since have placed.
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), true);
    let held = Arc::clone(&pool);
    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));
    let w = h.tokens.write.clone();
    let plan: Value = h
        .send(
            "POST",
            "/v1/pool/plans",
            Some(&w),
            Some(json!({"kind": "delete_orphans", "root_id": root_id, "prefix": "junk"})),
        )
        .await
        .json();
    let id = plan["id"].as_i64().unwrap();
    let token = plan["confirm_token"].as_str().unwrap().to_owned();

    // A scan in progress: the writer held, and the generation moved when it
    // commits.
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        held.with_store_mut(|st| {
            st.in_transaction(|st| {
                locked_tx.send(()).unwrap();
                let _ = release_rx.recv();
                torrentd_pool::match_all(st).map(|_| ())
            })
        })
        .unwrap();
    });
    locked_rx.recv().unwrap();

    // The token still reads as current while the scan runs.
    let during: Value = h.read(&format!("/v1/pool/plans/{id}")).await.json();
    assert_eq!(during["confirm_token"], token.as_str());

    let apply = format!("/v1/pool/plans/{id}/apply");
    let (resp, ()) = tokio::join!(
        h.send(
            "POST",
            &apply,
            Some(&w),
            Some(json!({"confirm_token": token})),
        ),
        async {
            // Let the apply read the plan from the pre-scan snapshot first.
            tokio::time::sleep(Duration::from_millis(200)).await;
            release_tx.send(()).unwrap();
        },
    );
    holder.join().unwrap();
    assert_problem(&resp, 422, "confirm-token-mismatch");
    assert!(dir.path().join("pool/junk/orphan.bin").exists());

    // The plan re-read against the rescanned index carries a token that
    // applies.
    let after: Value = h.read(&format!("/v1/pool/plans/{id}")).await.json();
    assert_ne!(after["confirm_token"], token.as_str());
    let resp = h
        .send(
            "POST",
            &apply,
            Some(&w),
            Some(json!({"confirm_token": after["confirm_token"]})),
        )
        .await;
    resp.assert_status(StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_store_call_waiting_on_the_writer_does_not_take_a_runtime_worker() {
    // Handlers outside the pool module, and the verify queue, still call the
    // writer from async code. Waiting there for a scan used to hold a worker
    // thread for the scan's whole run; with one worker, that was every task.
    use std::time::Duration;

    // The holder lets go on its own after `HOLD`, so a stalled runtime shows
    // up as a late answer rather than a test that never ends: with the one
    // worker blocked, not even a timer would fire.
    const HOLD: Duration = Duration::from_secs(5);
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let held = Arc::clone(&pool);
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        held.with_store(|_| {
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(HOLD);
        });
    });
    locked_rx.recv().unwrap();

    let waiter = tokio::spawn(async move { pool.with_store(|st| st.torrent_count().unwrap()) });
    // Let the waiter take the one worker, then ask that worker for something
    // else.
    std::thread::sleep(Duration::from_millis(100));
    let asked = std::time::Instant::now();
    assert_eq!(tokio::spawn(async { 7 }).await.unwrap(), 7);
    assert!(
        asked.elapsed() < HOLD / 2,
        "the runtime stalled behind a store call for {:?}",
        asked.elapsed(),
    );

    let _ = release_tx.send(());
    assert_eq!(waiter.await.unwrap(), 3);
    holder.join().unwrap();
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
    // And one the operator set offline, refused the same way and for the
    // same reason: nothing it claimed could seed.
    let set_p = |state| {
        h.state
            .profiles
            .change_states(
                |r| r.set(&torrentd_engine::ProfileId::new("p"), state),
                &torrentd_engine::NoopSink,
            )
            .unwrap()
    };
    set_p(torrentd_engine::DesiredState::Offline);
    let claims = h.state.registry.len();
    let resp = post(adopt(
        "p",
        false,
        json!({"kind": "infohashes", "infohashes": [IH_C]}),
    ))
    .await;
    assert_problem(&resp, 409, "profile-unavailable");
    assert_eq!(resp.json::<Value>()["profile_status"], "offline");
    assert_eq!(h.state.registry.len(), claims, "nothing was claimed");
    set_p(torrentd_engine::DesiredState::Online);

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

/// A one-file `.torrent` announcing to `announce`.
fn metainfo(announce: &str) -> Vec<u8> {
    let mut t = format!(
        "d8:announce{}:{announce}4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:",
        announce.len()
    )
    .into_bytes();
    t.extend_from_slice(&[0u8; 20]);
    t.extend_from_slice(b"ee");
    t
}

/// A complete torrent's `.fastresume` as libtorrent writes one, with a
/// `trackers` list naming `tracker` when given.
fn fastresume(torrent: &[u8], tracker: Option<&str>) -> Vec<u8> {
    let ih = libtorrent_safe::info_hash_from_torrent(torrent).unwrap();
    let mut r =
        b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
    r.extend_from_slice(&ih.0);
    // Completion is the `pieces` bitfield with every piece had: `metainfo`
    // has one piece.
    r.extend_from_slice(b"6:pieces1:\x01");
    r.extend_from_slice(b"9:seed_modei1e");
    if let Some(url) = tracker {
        r.extend_from_slice(format!("8:trackersll{}:{url}ee", url.len()).as_bytes());
    }
    r.extend_from_slice(b"e");
    r
}

/// Issue #72's adoption acceptance: a torrent adopted into a profile with
/// `allowed_tracker_domains` is held to it on both paths, through the
/// trackers libtorrent would announce to; and the pool index's own owner
/// refuses another profile.
#[tokio::test]
async fn adoption_holds_every_torrent_to_the_profiles_tracker_domains() {
    const ALLOWED: &str = "http://tracker.allowed.example/announce";
    const FOREIGN: &str = "http://tracker.foreign.example/announce";
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), false);
    let index = Arc::clone(&pool);
    let library = dir.path().join("library");
    std::fs::create_dir_all(&library).unwrap();
    let source = library.join(format!("{IH_A}.torrent"));
    let h = Harness::authed(&Coverage::new(), |s| {
        let mut acct = test_entry("acct", ProfileStatus::Active).config;
        acct.allowed_tracker_domains = vec!["allowed.example".to_owned()];
        let reg = Arc::new(ProfileRegistry::new(vec![
            test_entry("p", ProfileStatus::Active),
            ProfileEntry::new(
                acct,
                Arc::new(torrentd_engine::MockEngine::new()),
                None,
                None,
                0,
            ),
        ]));
        *s = crate::app_state::build_test_state_with_sessions(Some(reg), &["p", "acct"]);
        s.pool = Some(pool);
    });
    let w = h.tokens.write.clone();
    let post = |dry_run, selector| {
        let w = w.clone();
        let h = &h;
        async move {
            let resp = h
                .send(
                    "POST",
                    "/v1/pool/adoptions",
                    Some(&w),
                    adopt("acct", dry_run, selector),
                )
                .await;
            resp.assert_status(StatusCode::OK);
            resp.json::<Value>()
        }
    };
    let subtree = json!({"kind": "subtree", "root_id": root_id, "path": ""});
    let just_a = json!({"kind": "infohashes", "infohashes": [IH_A]});
    let refused_for = |r: &Value, what: &str| {
        let refused = r["refused"].as_array().unwrap();
        assert!(
            refused
                .iter()
                .any(|t| t["infohash"] == IH_A && t["reason"].as_str().unwrap().contains(what)),
            "{IH_A} should be refused for {what:?}: {r}"
        );
        assert!(r["fast_path"].as_array().unwrap().is_empty(), "{r}");
        assert!(
            r["queued_for_verification"].as_array().unwrap().is_empty(),
            "{r}"
        );
    };

    // The verify path: a `.torrent` announcing outside the list is refused,
    // by a dry run as by the adoption, and nothing is claimed.
    std::fs::write(&source, metainfo(FOREIGN)).unwrap();
    refused_for(
        &post(true, subtree.clone()).await,
        "allowed_tracker_domains",
    );
    refused_for(
        &post(false, just_a.clone()).await,
        "allowed_tracker_domains",
    );
    assert_eq!(h.state.registry.len(), 0);
    // A `.torrent` whose trackers cannot be read is refused too, but it is
    // not an isolation refusal, so the count at the end leaves it out.
    std::fs::write(&source, b"not bencode").unwrap();
    refused_for(&post(false, just_a.clone()).await, "could not be read");
    assert_eq!(h.state.registry.len(), 0);
    std::fs::write(&source, metainfo(ALLOWED)).unwrap();
    let r = post(true, subtree.clone()).await;
    assert_eq!(r["queued_for_verification"], json!([IH_A]), "{r}");

    // The index's own owner: another profile's torrent is refused even with
    // no session holding it.
    index.with_store(|st| st.set_profile(IH_A, Some("p")).unwrap());
    refused_for(
        &post(false, just_a.clone()).await,
        "assigns this torrent to profile p",
    );
    assert_eq!(h.state.registry.len(), 0);
    index.with_store(|st| st.set_profile(IH_A, None).unwrap());

    // The fast path: resume data whose own tracker list names a foreign
    // tracker is refused behind an allowed `.torrent`, and does not fall back
    // to verifying it.
    let resume = library.join(format!("{IH_A}.fastresume"));
    let mut row = torrent(dir.path(), IH_A, 96, 2);
    row.fastresume_path = Some(resume.clone());
    index.with_store_mut(|st| st.upsert_torrent(&row, 0).unwrap());
    let allowed = metainfo(ALLOWED);
    std::fs::write(&resume, fastresume(&allowed, Some(FOREIGN))).unwrap();
    refused_for(&post(true, just_a.clone()).await, "allowed_tracker_domains");
    refused_for(
        &post(false, just_a.clone()).await,
        "allowed_tracker_domains",
    );
    assert_eq!(h.state.registry.len(), 0);

    // Without it, the `.torrent`'s allowed tracker is what is announced, and
    // the adoption goes through.
    std::fs::write(&resume, fastresume(&allowed, None)).unwrap();
    let r = post(false, just_a).await;
    assert_eq!(r["fast_path"], json!([IH_A]), "{r}");
    assert_eq!(
        h.state
            .registry
            .lookup(&libtorrent_safe::InfoHash::from_hex(IH_A).unwrap()),
        Some(torrentd_engine::ProfileId::new("acct"))
    );
    assert_eq!(
        index
            .with_store(|st| st.profile_of(IH_A).unwrap())
            .as_deref(),
        Some("acct")
    );
    // The three refusals by an adoption are counted with every add path's;
    // the dry runs, which change nothing, are not.
    let text = String::from_utf8(h.state.metrics.render()).unwrap();
    assert!(
        text.contains("profile_assignment_registry_errors_total{profile_id=\"acct\"} 3"),
        "{text}"
    );
}

/// Issue #115's acceptance: payload rewritten in place at the same size after
/// the scan is caught by the adopt itself, with no drift check run first. The
/// index's sizes still match, so without the adopt's own pass the previous
/// client's "complete" would seed bytes nobody verified.
#[tokio::test]
async fn an_adopt_checks_its_selection_for_drift_before_trusting_resume_data() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), false);
    let index = Arc::clone(&pool);
    let library = dir.path().join("library");
    std::fs::create_dir_all(&library).unwrap();
    let source = metainfo("http://tracker.example/announce");
    std::fs::write(library.join(format!("{IH_A}.torrent")), &source).unwrap();
    let resume = library.join(format!("{IH_A}.fastresume"));
    std::fs::write(&resume, fastresume(&source, None)).unwrap();
    let mut row = torrent(dir.path(), IH_A, 96, 2);
    row.fastresume_path = Some(resume);
    index.with_store_mut(|st| st.upsert_torrent(&row, 0).unwrap());

    let h = Harness::authed(&Coverage::new(), |s| s.pool = Some(pool));
    let w = h.tokens.write.clone();
    let post = |dry_run| {
        let w = w.clone();
        let h = &h;
        async move {
            let resp = h
                .send(
                    "POST",
                    "/v1/pool/adoptions",
                    Some(&w),
                    adopt(
                        "p",
                        dry_run,
                        json!({"kind": "subtree", "root_id": root_id, "path": "movies"}),
                    ),
                )
                .await;
            resp.assert_status(StatusCode::OK);
            resp.json::<Value>()
        }
    };

    // Untouched since the scan: the pass finds nothing, the fast path stands.
    let r = post(true).await;
    assert_eq!(r["fast_path"], json!([IH_A]), "{r}");
    assert_eq!(
        index.with_store(|st| st.adoption_state(IH_A).unwrap()),
        Some(AdoptionState::Matched)
    );

    // Re-encoded at the same size. The dry run already sees it: the pass
    // runs before its result is computed, and records what it found.
    std::thread::sleep(std::time::Duration::from_millis(10));
    write(&dir.path().join("pool"), "movies/a.bin", 64);
    let r = post(true).await;
    assert!(r["fast_path"].as_array().unwrap().is_empty(), "{r}");
    assert_eq!(r["queued_for_verification"], json!([IH_A]), "{r}");
    assert_eq!(
        index.with_store(|st| st.adoption_state(IH_A).unwrap()),
        Some(AdoptionState::Drifted)
    );
    assert_eq!(h.state.registry.len(), 0, "a dry run claims nothing");

    // And the adoption hashes it rather than seeding it on the old claim.
    let r = post(false).await;
    assert!(r["fast_path"].as_array().unwrap().is_empty(), "{r}");
    assert_eq!(r["queued_for_verification"], json!([IH_A]), "{r}");
}

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

/// Issue #111's acceptance: a torrent adopted into one profile, deleted
/// without its files, adopts into another. The delete used to leave the
/// index's `adopted` verdict behind, and adoption refuses `adopted` outright.
#[tokio::test]
async fn a_deleted_adoption_adopts_again_into_another_profile() {
    const TRACKER: &str = "http://tracker.example/announce";
    let dir = tempfile::tempdir().unwrap();
    let (pool, root_id) = fixture(dir.path(), false);
    let index = Arc::clone(&pool);
    let library = dir.path().join("library");
    std::fs::create_dir_all(&library).unwrap();
    let source = metainfo(TRACKER);
    std::fs::write(library.join(format!("{IH_A}.torrent")), &source).unwrap();
    let resume = library.join(format!("{IH_A}.fastresume"));
    std::fs::write(&resume, fastresume(&source, None)).unwrap();
    let mut row = torrent(dir.path(), IH_A, 96, 2);
    row.fastresume_path = Some(resume);
    index.with_store_mut(|st| st.upsert_torrent(&row, 0).unwrap());
    let h = Harness::authed(&Coverage::new(), |s| {
        let reg = Arc::new(ProfileRegistry::new(vec![
            test_entry("p", ProfileStatus::Active),
            test_entry("q", ProfileStatus::Active),
        ]));
        *s = crate::app_state::build_test_state_with_sessions(Some(reg), &["p", "q"]);
        s.pool = Some(pool);
    });
    let w = h.tokens.write.clone();
    let just_a = json!({"kind": "infohashes", "infohashes": [IH_A]});
    let adopt_into = |profile: &'static str| {
        let (w, just_a, h) = (w.clone(), just_a.clone(), &h);
        async move {
            let resp = h
                .send(
                    "POST",
                    "/v1/pool/adoptions",
                    Some(&w),
                    adopt(profile, false, just_a),
                )
                .await;
            resp.assert_status(StatusCode::OK);
            resp.json::<Value>()
        }
    };
    let state = || index.with_store(|st| st.adoption_state(IH_A).unwrap());
    let owner = || index.with_store(|st| st.profile_of(IH_A).unwrap());

    let r = adopt_into("p").await;
    assert_eq!(r["fast_path"], json!([IH_A]), "{r}");
    assert_eq!(state(), Some(AdoptionState::Adopted));
    assert_eq!(owner().as_deref(), Some("p"));

    // The session reports it, as its add alert would.
    let hash = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    h.state.state.insert(
        hash,
        torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle {
                id: 1,
                infohash: hash,
            },
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        ),
    );
    h.write("DELETE", &format!("/v1/torrents/{IH_A}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(state(), Some(AdoptionState::Matched));
    assert_eq!(owner(), None);
    assert_eq!(
        index.with_store(|st| st.adoption_base(IH_A).unwrap()),
        Some((root_id, "movies".to_owned())),
    );
    // And the session drops it, as its removal alert would.
    h.state
        .state
        .remove(&hash, &torrentd_engine::ProfileId::new("p"), None);

    let r = adopt_into("q").await;
    assert_eq!(r["fast_path"], json!([IH_A]), "{r}");
    assert_eq!(state(), Some(AdoptionState::Adopted));
    assert_eq!(owner().as_deref(), Some("q"));
    assert_eq!(
        h.state.registry.lookup(&hash),
        Some(torrentd_engine::ProfileId::new("q"))
    );
}

/// Issue #167, for adoption: an adoption into `p` whose lookup ran before a
/// concurrent add's claim into `p` was visible. The concurrent claim is
/// written through a second handle on the same database, which is what the
/// adoption's `assign` then finds.
///
/// The adoption used to take that claim as its own and hand the torrent to
/// the session, which refuses the duplicate. The fast path then falls back to
/// the verify queue, whose worker meets the same duplicate and releases the
/// claim as its own, so the torrent seeded in `p` with no owner and could be
/// adopted into `q`.
#[tokio::test]
async fn a_same_profile_adoption_that_loses_the_claim_race_is_refused_and_keeps_the_claim() {
    const TRACKER: &str = "http://tracker.example/announce";
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let index = Arc::clone(&pool);
    let library = dir.path().join("library");
    std::fs::create_dir_all(&library).unwrap();
    let source = metainfo(TRACKER);
    std::fs::write(library.join(format!("{IH_A}.torrent")), &source).unwrap();
    let resume = library.join(format!("{IH_A}.fastresume"));
    std::fs::write(&resume, fastresume(&source, None)).unwrap();
    let mut row = torrent(dir.path(), IH_A, 96, 2);
    row.fastresume_path = Some(resume);
    index.with_store_mut(|st| st.upsert_torrent(&row, 0).unwrap());
    let reg_path = dir.path().join("reg.db");
    let (p, q) = (
        Arc::new(torrentd_engine::MockEngine::new()),
        Arc::new(torrentd_engine::MockEngine::new()),
    );
    let h = Harness::authed(&Coverage::new(), |s| {
        let reg = Arc::new(ProfileRegistry::new(vec![
            test_entry("p", ProfileStatus::Active),
            test_entry("q", ProfileStatus::Active),
        ]));
        *s = crate::app_state::build_test_state_with_sessions(Some(reg), &["p", "q"]);
        s.source = Arc::new(torrentd_engine::ProfileSource::new(vec![
            (
                torrentd_engine::ProfileId::new("p"),
                p.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
            ),
            (
                torrentd_engine::ProfileId::new("q"),
                q.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
            ),
        ]));
        s.registry = Arc::new(torrentd_engine::AssignmentRegistry::new_empty(&reg_path));
        s.pool = Some(pool);
    });
    let hash = libtorrent_safe::InfoHash::from_hex(IH_A).unwrap();
    // The concurrent add's claim, and the duplicate the session would answer
    // the adoption with if it got that far.
    torrentd_engine::AssignmentRegistry::new_empty(&reg_path)
        .assign(hash, torrentd_engine::ProfileId::new("p"))
        .unwrap();
    p.inject_error(
        "add_torrent",
        torrentd_engine::EngineError::MockInjected {
            op: "add_torrent",
            message: "torrent already exists in session".into(),
        },
    );
    let w = h.tokens.write.clone();
    let just_a = json!({"kind": "infohashes", "infohashes": [IH_A]});
    let adopt_into = |profile: &'static str| {
        let (w, just_a, h) = (w.clone(), just_a.clone(), &h);
        async move {
            let resp = h
                .send(
                    "POST",
                    "/v1/pool/adoptions",
                    Some(&w),
                    adopt(profile, false, just_a),
                )
                .await;
            resp.assert_status(StatusCode::OK);
            resp.json::<Value>()
        }
    };

    for profile in ["p", "q"] {
        let r = adopt_into(profile).await;
        assert_eq!(r["fast_path"], json!([]), "into {profile}: {r}");
        assert_eq!(
            r["queued_for_verification"],
            json!([]),
            "into {profile}: {r}"
        );
        assert_eq!(
            r["refused"][0]["infohash"],
            json!(IH_A),
            "into {profile}: {r}"
        );
        assert_eq!(
            h.state.registry.lookup(&hash),
            Some(torrentd_engine::ProfileId::new("p")),
            "after adopting into {profile}",
        );
    }
    assert!(p.calls().is_empty(), "{:?}", p.calls());
    assert!(q.calls().is_empty(), "{:?}", q.calls());
}

async fn verification(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let (pool, _) = fixture(dir.path(), false);
    let watched = Arc::clone(&pool);
    let h = Harness::authed(cov, |s| s.pool = Some(pool));
    let loaded = |ih: &str, id: u64, phase: torrentd_engine::TorrentPhase| {
        let hash = libtorrent_safe::InfoHash::from_hex(ih).unwrap();
        let mut st = torrentd_engine::TorrentState::newly_added(
            torrentd_engine::TorrentHandle { id, infohash: hash },
            torrentd_engine::ProfileId::new("p"),
            std::time::Instant::now(),
        );
        st.phase = phase;
        h.state.state.insert(hash, st);
    };
    loaded(IH_A, 1, torrentd_engine::TorrentPhase::Seeding);
    // Loaded, but not a torrent the pool index holds.
    const IH_OUTSIDE: &str = "dddddddddddddddddddddddddddddddddddddddd";
    loaded(IH_OUTSIDE, 4, torrentd_engine::TorrentPhase::Seeding);
    // Paused, as a failed verification leaves it.
    loaded(IH_B, 2, torrentd_engine::TorrentPhase::Paused);
    let w = h.tokens.write.clone();
    let resp = h
        .send(
            "POST",
            "/v1/pool/verifications",
            Some(&w),
            Some(json!({"infohashes": [IH_A, IH_C, IH_OUTSIDE, IH_B]})),
        )
        .await;
    resp.assert_status(StatusCode::ACCEPTED);
    let r: Value = resp.json();
    assert_eq!(r["requested"], 4);
    assert_eq!(r["started"], json!([IH_A, IH_OUTSIDE]));
    assert_eq!(r["skipped"][0]["infohash"], IH_C);
    assert_eq!(r["skipped"][0]["reason"], "not loaded in any session");
    assert_eq!(r["skipped"][1]["infohash"], IH_B);
    let reason = r["skipped"][1]["reason"].as_str().unwrap();
    assert!(reason.contains("paused"), "{reason}");
    // Only the pool's own torrent has an outcome to record: the other is
    // re-hashed, and neither paused on a failure nor written to the index.
    let q = watched.verify_queue();
    assert!(q.tracks_recheck(IH_A));
    assert!(!q.tracks_recheck(IH_OUTSIDE));
    assert!(!q.tracks_recheck(IH_B));

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
        // Applying a plan waits for every step, and adopting or creating a
        // plan waits on a scan, so the three carry no deadline: a stalled
        // body there is bounded by nothing, with or without a token
        // (`docs/running.md` §7). Every other operation cuts one off.
        if !UNTIMED.contains(&(*method, *path)) {
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
        // Two files whose sizes sum past `i64::MAX`. The materialised tree
        // saturates rather than failing the scan over them; the reads fail
        // on the corrupt rows written below.
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
    // Directory rows whose byte total does not read back as a number, as a
    // corrupt index would hold: the overview and both listings fail to load
    // the accounting.
    rusqlite::Connection::open(dir.path().join("pool.db"))
        .unwrap()
        .execute(
            "UPDATE dir SET bytes_total = 'corrupt' WHERE root_id = ?1",
            [root_id],
        )
        .unwrap();
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
