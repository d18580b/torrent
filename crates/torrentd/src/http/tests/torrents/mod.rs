//! `torrents`: listing, adding, removing, per-torrent controls, files and
//! trackers.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kynos::http::StatusCode;
use kynos::test::TestResponse;
use serde_json::json;
use serde_json::Value;
use torrentd_engine::EngineError;
use torrentd_engine::HeldCall;
use torrentd_engine::InfoHash;
use torrentd_engine::MockEngine;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileSource;
use torrentd_engine::RecordedCall;
use torrentd_engine::TorrentDetails;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentFile;
use torrentd_engine::TorrentFlags;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentPhase;
use torrentd_engine::TorrentState;
use torrentd_engine::TrackerEntry;

use super::support::assert_problem;
use super::support::Coverage;
use super::support::Harness;
use crate::app_state::AppState;
use crate::profile_registry::test_entry;
use crate::profile_registry::test_failed_profile;
use crate::profile_registry::test_host_entry;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ProfileStatus;
use crate::registry::AssignmentRegistry;

mod actions;
mod add;
mod delete;
mod files;
mod list;
mod trackers;

use actions::controls;
use add::adding;
use delete::deleting;
use files::files;
use list::listing;
use list::reading;
use trackers::trackers;

const MAGNET: &str = "magnet:?xt=urn:btih:0101010101010101010101010101010101010101";
const MAGNET_HEX: &str = "0101010101010101010101010101010101010101";
const PASSKEY: &str = "0123456789abcdef0123456789abcdef";

/// A loaded torrent on the live profile `p`.
const LOADED: InfoHash = InfoHash([7; 20]);
/// A loaded torrent on `f`, the profile the VPN monitor fenced.
const FENCED: InfoHash = InfoHash([8; 20]);
/// Assigned to `p`, never loaded: an add whose alert has not landed.
const ADDING: InfoHash = InfoHash([9; 20]);
/// Assigned to `down`, the profile that failed to come up.
const STALE: InfoHash = InfoHash([10; 20]);

fn hex(ih: InfoHash) -> String {
    ih.to_hex()
}

/// A minimal single-file `.torrent` announcing to `http://t/announce`.
/// `name` is one byte, so each distinct name is a distinct infohash.
pub(crate) fn torrent_bytes(name: char) -> Vec<u8> {
    let mut t = format!(
        "d8:announce17:http://t/announce4:infod6:lengthi1e4:name1:{name}12:piece lengthi16384e6:pieces20:"
    )
    .into_bytes();
    t.extend_from_slice(&[0u8; 20]);
    t.extend_from_slice(b"ee");
    t
}

/// The engines behind the fixture's profiles.
struct Engines {
    /// Profile `p` (and `strict`, which shares it).
    p: Arc<MockEngine>,
    /// Profile `f`, fenced.
    f: Arc<MockEngine>,
}

/// The fixture: profiles `p` (live), `f` (live, fenced), `strict` (live, with
/// `allowed_tracker_domains`) and `down` (failed at boot); one loaded torrent
/// on each of `p` and `f`, one mid-add and one stale.
fn fixture(s: &mut AppState, dir: &Path) -> Engines {
    let engines = Engines {
        p: Arc::new(MockEngine::new()),
        f: Arc::new(MockEngine::new()),
    };
    let mut strict = test_host_entry("strict").config;
    strict.allowed_tracker_domains = vec!["tracker.allowed.example".to_owned()];
    s.profiles = Arc::new(
        ProfileRegistry::new(vec![
            test_entry("p", ProfileStatus::Active),
            test_entry("f", ProfileStatus::VpnDown),
            ProfileEntry::new(strict, engines.p.clone(), None, None, 0),
        ])
        .with_failed(vec![test_failed_profile("down", "wg-down did not come up")]),
    );
    s.source = Arc::new(ProfileSource::new(vec![
        (
            ProfileId::new("p"),
            engines.p.clone() as Arc<dyn TorrentEngine>,
        ),
        (
            ProfileId::new("f"),
            engines.f.clone() as Arc<dyn TorrentEngine>,
        ),
        (
            ProfileId::new("strict"),
            engines.p.clone() as Arc<dyn TorrentEngine>,
        ),
    ]));
    s.registry = Arc::new(AssignmentRegistry::new_empty(dir.join("reg.json")));
    s.default_save_path = dir.to_path_buf();
    s.torrent_dir = dir.to_path_buf();

    load(s, &engines.p, LOADED, "p", TorrentPhase::Seeding);
    load(s, &engines.f, FENCED, "f", TorrentPhase::Paused);
    s.registry.assign(ADDING, ProfileId::new("p")).unwrap();
    s.registry.assign(STALE, ProfileId::new("down")).unwrap();
    engines
}

/// Assign `ih` to `profile` and give it a live state entry.
fn load(
    s: &AppState,
    engine: &MockEngine,
    ih: InfoHash,
    profile: &str,
    phase: TorrentPhase,
) -> TorrentHandle {
    let h = engine.register_handle(ih);
    s.registry.assign(ih, ProfileId::new(profile)).unwrap();
    let mut st = TorrentState::newly_added(h, ProfileId::new(profile), Instant::now());
    st.phase = phase;
    st.upload_rate = 1234;
    st.num_peers = 3;
    st.progress = 1.0;
    st.is_seeding = phase == TorrentPhase::Seeding;
    s.state.insert(ih, st);
    h
}

fn handle(engine: &MockEngine, ih: InfoHash) -> TorrentHandle {
    engine.register_handle(ih)
}

fn injected(op: &'static str) -> EngineError {
    EngineError::MockInjected {
        op,
        message: "boom".into(),
    }
}

fn errors_at(resp: &TestResponse) -> Vec<String> {
    let body: Value = resp.json();
    body["errors"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| e["pointer"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// A request with the `write` token and a JSON body.
trait WriteJson {
    async fn write_json(&self, method: &str, path: &str, body: Value) -> TestResponse;
}

impl WriteJson for Harness {
    async fn write_json(&self, method: &str, path: &str, body: Value) -> TestResponse {
        self.send(method, path, Some(&self.tokens.write.clone()), Some(body))
            .await
    }
}

/// Whether `engine` recorded `call`. `RecordedCall` has no `PartialEq`; its
/// `Debug` form is exact.
fn called(engine: &MockEngine, call: &RecordedCall) -> bool {
    let want = format!("{call:?}");
    engine.calls().iter().any(|c| format!("{c:?}") == want)
}

/// Whether `call` is the last thing `engine` recorded.
fn last_call_was(engine: &MockEngine, call: &RecordedCall) -> bool {
    engine
        .calls()
        .last()
        .is_some_and(|c| format!("{c:?}") == format!("{call:?}"))
}

/// Every declared response of the `torrents` tag.
pub(crate) async fn scenarios(cov: &Arc<Coverage>) {
    let dir = tempfile::tempdir().unwrap();
    let mut engines = None;
    let h = Harness::authed(cov, |s| engines = Some(fixture(s, dir.path())));
    let engines = engines.unwrap();

    auth_and_malformed_paths(&h).await;
    listing(&h).await;
    reading(&h, &engines).await;
    adding(&h, &engines, dir.path()).await;
    controls(&h, &engines).await;
    files(&h, &engines).await;
    trackers(&h, &engines).await;
    deleting(&h, &engines).await;
    h.assert_conformance();

    // `delete_files` on a sessionless profile, with mutations allowed so the
    // guard in front of it is not what refuses.
    let dir = tempfile::tempdir().unwrap();
    let mut engines = None;
    let h = Harness::authed(cov, |s| {
        engines = Some(fixture(s, dir.path()));
        s.pool = crate::pool_service::PoolService::open(&crate::config::Config::minimal_for_tests(
            dir.path(),
            true,
        ))
        .unwrap();
    });
    let engines = engines.unwrap();
    assert!(h.state.pool.as_ref().is_some_and(|p| p.allow_mutations()));
    // One flag is not enough: the infohash has to be repeated as `confirm`,
    // and another torrent's is refused the same way.
    for query in [
        "delete_files=true".to_owned(),
        format!("delete_files=true&confirm={}", hex(STALE)),
    ] {
        let resp = h
            .write("DELETE", &format!("/v1/torrents/{}?{query}", hex(LOADED)))
            .await;
        assert_problem(&resp, 422, "delete-unconfirmed");
        let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
        assert!(detail.contains(&hex(LOADED)), "{detail}");
        assert!(h.state.registry.lookup(&LOADED).is_some());
    }
    assert!(
        engines.p.calls().is_empty(),
        "an unconfirmed delete reaches no session"
    );
    let resp = h
        .write(
            "DELETE",
            &format!(
                "/v1/torrents/{}?delete_files=true&confirm={}",
                hex(STALE),
                hex(STALE)
            ),
        )
        .await;
    assert_problem(&resp, 409, "profile-unavailable");
    let body: Value = resp.json();
    assert_eq!(body["profile_status"], "failed");
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.contains("no running session"), "{detail}");
    assert!(detail.contains("delete_files"), "{detail}");
    assert!(
        h.state.registry.lookup(&STALE).is_some(),
        "the entry stays, to clear with a plain delete"
    );
    // A torrent the boot left unloaded on a live profile: no session holds
    // it either, so `delete_files` is refused before anything changes, rather
    // than answered 204 over a payload nothing touched.
    h.state.unloaded_at_boot.lock().insert(ADDING);
    let live = ProfileId::new("p");
    h.state
        .resume
        .write(&live, &ADDING, b"resume-bytes")
        .unwrap();
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
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(detail.contains("unloaded"), "{detail}");
    assert!(detail.contains("delete_files"), "{detail}");
    assert_eq!(h.state.registry.lookup(&ADDING), Some(live.clone()));
    assert!(
        h.state
            .resume
            .load_all(&live)
            .unwrap()
            .iter()
            .any(|(ih, _)| *ih == ADDING),
        "a refused delete leaves the resume file in place"
    );
    // Without `delete_files` too, while its resume file is there: the boot's
    // add of it failed, and the next boot loads it from that file (#354).
    // That it answers `torrent-unloaded`, not `torrent-adding`, is the
    // refused delete above having left it a boot leftover.
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await;
    assert_problem(&resp, 409, "torrent-unloaded");
    assert_eq!(h.state.registry.lookup(&ADDING), Some(live.clone()));
    // An adoption the pool index records `drifted`, with a `.torrent` and no
    // resume file, is one no boot loads: the delete clears it and its
    // `.torrent`, so it can be adopted again and verified.
    h.state.resume.delete(&live, &ADDING).unwrap();
    h.state
        .torrents
        .write(&live, &ADDING, b"torrent-bytes")
        .unwrap();
    let drift = |state| {
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
                st.set_adoption(&hex(ADDING), state, None, None, None, Some(1), None)
            })
            .unwrap();
    };
    // Recorded `adopted`, the `.torrent` is what the next boot loads.
    drift(torrentd_pool::AdoptionState::Adopted);
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await;
    assert_problem(&resp, 409, "torrent-unloaded");
    assert!(h.state.torrents.exists(&live, &ADDING));
    drift(torrentd_pool::AdoptionState::Drifted);
    h.write("DELETE", &format!("/v1/torrents/{}", hex(ADDING)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(h.state.registry.lookup(&ADDING).is_none());
    assert!(!h.state.torrents.exists(&live, &ADDING));
    // Back to what the rest of this test expects: assigned, held by no
    // session, and not one the boot left unloaded.
    h.state.registry.assign(ADDING, live.clone()).unwrap();
    // A cross-seed claims the same file in the pool index: deleting this
    // torrent's payload would delete that one's, so it is refused, and the
    // torrent stays loaded.
    let pool = h.state.pool.as_ref().unwrap();
    let shared_with = "cd".repeat(20);
    let add = |ih: &str| -> Result<(), torrentd_pool::PoolError> {
        pool.with_store_mut(|st| {
            st.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: ih.to_owned(),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: "X".into(),
                    total_size: 1,
                    num_files: 1,
                    source_path: dir.path().join(format!("{ih}.torrent")),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: None,
                },
                0,
            )?;
            let root_id = st.upsert_root(&dir.path().join("pool"))?;
            st.replace_claims(ih, &[(root_id, "X/data.bin".to_owned())])
        })
    };
    let delete_files = format!(
        "/v1/torrents/{}?delete_files=true&confirm={}",
        hex(LOADED),
        hex(LOADED)
    );
    add(&hex(LOADED)).unwrap();
    add(&shared_with).unwrap();
    let resp = h.write("DELETE", &delete_files).await;
    assert_problem(&resp, 409, "payload-shared");
    assert!(resp.json::<Value>()["detail"]
        .as_str()
        .unwrap()
        .contains(&shared_with));
    assert!(h.state.registry.lookup(&LOADED).is_some());
    pool.with_store_mut(|st| st.replace_claims(&shared_with, &[]))
        .unwrap();

    // The session puts the payload under the managed root, where a file the
    // index has never scanned sits: nothing proves it is this torrent's, so
    // the delete changes nothing and the torrent keeps seeding.
    let loaded = handle(&engines.p, LOADED);
    let root = dir.path().join("pool");
    engines.p.set_torrent_details(
        loaded,
        TorrentDetails {
            save_path: root.to_string_lossy().into_owned(),
            ..MockEngine::default_details()
        },
    );
    engines
        .p
        .set_torrent_files(loaded, Some(vec![file(0, "X/data.bin")]));
    let data = root.join("X/data.bin");
    std::fs::create_dir_all(data.parent().unwrap()).unwrap();
    std::fs::write(&data, vec![5u8; 64]).unwrap();
    let resp = h.write("DELETE", &delete_files).await;
    assert_problem(&resp, 409, "payload-untrashable");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(detail.contains("not in the index"), "{detail}");
    assert!(data.exists());
    assert!(h.state.registry.lookup(&LOADED).is_some());
    assert!(!engines
        .p
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::RemoveTorrent { .. })));

    // Scanned and claimed, so the index proves it this torrent's alone. Every
    // other torrent the daemon holds must also be shown not to have a file at
    // the same path, which the index cannot say for one added through
    // `POST /v1/torrents`.
    pool.scan().unwrap();
    add(&hex(LOADED)).unwrap();
    let untouched = |resp: &TestResponse, problem: &str, names: InfoHash| {
        assert_problem(resp, 409, problem);
        let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
        assert!(detail.contains(&hex(names)), "{detail}");
        assert!(data.exists());
        assert!(h.state.registry.lookup(&LOADED).is_some());
        assert!(!engines
            .p
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::RemoveTorrent { .. })));
    };
    // Other torrents are compared in infohash order: FENCED, ADDING, STALE.
    // A torrent with no metadata yet could write anything under its save
    // path, and the mock's default save path is `/`.
    let fenced = handle(&engines.f, FENCED);
    let resp = h.write("DELETE", &delete_files).await;
    untouched(&resp, "payload-shared", FENCED);
    // A cross-seed in another profile, with the same file under its own save
    // path and file list.
    engines.f.set_torrent_details(
        fenced,
        TorrentDetails {
            save_path: root.join("X").to_string_lossy().into_owned(),
            ..MockEngine::default_details()
        },
    );
    engines
        .f
        .set_torrent_files(fenced, Some(vec![file(0, "data.bin")]));
    let resp = h.write("DELETE", &delete_files).await;
    untouched(&resp, "payload-shared", FENCED);
    // A session that cannot report one is no proof either.
    engines
        .f
        .inject_error("torrent_files", injected("torrent_files"));
    let resp = h.write("DELETE", &delete_files).await;
    untouched(&resp, "payload-untrashable", FENCED);
    engines
        .f
        .set_torrent_files(fenced, Some(vec![file(0, "other.bin")]));
    // Assigned but held by no session — mid-add, or on a profile that failed
    // to come up: its files cannot be read, so they cannot be compared.
    let resp = h.write("DELETE", &delete_files).await;
    untouched(&resp, "payload-untrashable", ADDING);
    h.state.registry.remove(&ADDING).unwrap();
    let resp = h.write("DELETE", &delete_files).await;
    untouched(&resp, "payload-untrashable", STALE);
    h.state.registry.remove(&STALE).unwrap();

    // Nothing else has a file there: the torrent leaves its session with
    // libtorrent deleting nothing, and the file moves to the root's trash
    // intact.
    let resp = h.write("DELETE", &delete_files).await;
    resp.assert_status(StatusCode::NO_CONTENT);
    assert!(called(
        &engines.p,
        &RecordedCall::RemoveTorrent {
            handle: loaded,
            delete_files: false
        }
    ));
    assert!(!data.exists());
    let buckets: Vec<_> = std::fs::read_dir(root.join(".torrentd-trash"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(buckets.len(), 1, "{buckets:?}");
    let bucket = buckets[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        bucket.starts_with(&format!("torrent-{}-", hex(LOADED))),
        "{bucket}"
    );
    assert_eq!(
        std::fs::read(buckets[0].join("X/data.bin")).unwrap(),
        vec![5u8; 64]
    );
    assert!(h.state.registry.lookup(&LOADED).is_none());
    h.assert_conformance();
}

/// Every operation, its credential checks, and its malformed-infohash `400`.
async fn auth_and_malformed_paths(h: &Harness) {
    let ih = hex(LOADED);
    let ops: Vec<(&str, String, bool, Option<Value>)> = vec![
        ("GET", "/v1/torrents".into(), false, None),
        (
            "POST",
            "/v1/torrents".into(),
            true,
            Some(json!({"profile_id": "p", "source": {"kind": "magnet", "uri": MAGNET}})),
        ),
        ("GET", format!("/v1/torrents/{ih}"), false, None),
        ("DELETE", format!("/v1/torrents/{ih}"), true, None),
        ("POST", format!("/v1/torrents/{ih}/pause"), true, None),
        ("POST", format!("/v1/torrents/{ih}/resume"), true, None),
        ("POST", format!("/v1/torrents/{ih}/recheck"), true, None),
        ("POST", format!("/v1/torrents/{ih}/reannounce"), true, None),
        (
            "PUT",
            format!("/v1/torrents/{ih}/upload-limit"),
            true,
            Some(json!({"bytes_per_sec": 10})),
        ),
        ("GET", format!("/v1/torrents/{ih}/files"), false, None),
        (
            "PUT",
            format!("/v1/torrents/{ih}/files/0/priority"),
            true,
            Some(json!({"priority": 4})),
        ),
        ("GET", format!("/v1/torrents/{ih}/trackers"), false, None),
    ];
    for (method, path, write, body) in ops {
        let resp = h.send(method, &path, None, body.clone()).await;
        assert_eq!(resp.status().as_u16(), 401, "{method} {path}");
        resp.assert_header("www-authenticate", "Bearer");
        // `metrics` reaches neither scope; `read` does not reach `write`.
        let wrong = if write {
            h.tokens.read.clone()
        } else {
            h.tokens.metrics.clone()
        };
        let resp = h.send(method, &path, Some(&wrong), body.clone()).await;
        assert_problem(&resp, 403, "insufficient-scope");

        if path.contains(&ih) {
            // Not an infohash: refused before any handler runs.
            let bad = path.replace(&ih, "zz");
            let token = if write {
                h.tokens.write.clone()
            } else {
                h.tokens.read.clone()
            };
            let resp = h.send(method, &bad, Some(&token), body).await;
            assert_eq!(resp.status().as_u16(), 400, "{method} {bad}");
        }
    }
    // An infohash in upper case names the same torrent.
    let upper = hex(LOADED).to_uppercase();
    let got: Value = h.read(&format!("/v1/torrents/{upper}")).await.json();
    assert_eq!(got["infohash"], hex(LOADED));
}

fn magnet(profile: &str) -> Value {
    json!({"profile_id": profile, "source": {"kind": "magnet", "uri": MAGNET}})
}

fn metainfo(profile: &str, bytes: &[u8]) -> Value {
    json!({"profile_id": profile, "source": {"kind": "metainfo", "data": STANDARD.encode(bytes)}})
}

/// `400`, `415`, `413` and `408` for an operation with a JSON body, the
/// `408` arriving at the operation's `deadline`.
pub(super) async fn body_framework_rejections(
    h: &Harness,
    method: &str,
    path: &str,
    deadline: Duration,
) {
    let token = h.tokens.write.clone();
    let resp = h
        .send_with(
            method,
            path,
            Some(&token),
            None,
            &[("content-type", "application/json")],
        )
        .await;
    assert_eq!(resp.status().as_u16(), 400, "{method} {path}: empty JSON");
    let resp = h
        .send_with(
            method,
            path,
            Some(&token),
            None,
            &[("content-type", "text/plain")],
        )
        .await;
    assert_eq!(resp.status().as_u16(), 415, "{method} {path}");
    // Refused on the declared length, before a byte is read.
    let resp = h
        .send_with(
            method,
            path,
            Some(&token),
            Some(json!({})),
            &[("content-length", "1000000000")],
        )
        .await;
    assert_eq!(resp.status().as_u16(), 413, "{method} {path}");
    // A body that stalls is cut off at the operation's deadline.
    let (status, waited) = h.slow_body(method, path, Some(&token)).await;
    assert_eq!(status.as_u16(), 408, "{method} {path}: stalled body");
    assert!(
        // The server arms its deadline a moment before the clock is paused,
        // so the paused clock sees a hair less than the whole of it. The
        // window is narrow enough that the add's 300 s cannot pass for the
        // 30 s every other body gets, or the reverse.
        waited + Duration::from_secs(1) > deadline && waited <= deadline + Duration::from_secs(1),
        "{method} {path}: cut off at {deadline:?}, not before or long after: {waited:?}",
    );
    // So is one that declares no length, which the body limit reads whole.
    let (status, waited) = h.stalled_chunked_body(method, path, Some(&token)).await;
    assert_eq!(
        status.as_u16(),
        408,
        "{method} {path}: stalled chunked body"
    );
    assert!(
        waited + Duration::from_secs(1) > deadline && waited <= deadline + Duration::from_secs(1),
        "{method} {path}: chunked body cut off at {waited:?}, not {deadline:?}",
    );
    // Without a credential, that body is refused from the head, before a
    // byte of it is read: it can neither hold the connection until the
    // deadline nor be buffered up to the limit.
    let (status, waited) = h.stalled_chunked_body(method, path, None).await;
    assert_eq!(
        status.as_u16(),
        401,
        "{method} {path}: unauthenticated chunked body"
    );
    assert!(
        waited < Duration::from_secs(1),
        "{method} {path}: answered only after {waited:?}"
    );
}

fn file(index: u32, path: &str) -> TorrentFile {
    TorrentFile {
        index,
        path: path.into(),
        size: 100,
        downloaded: 50,
        priority: 4,
    }
}

#[tokio::test]
async fn torrents_behave_as_documented() {
    scenarios(&Coverage::new()).await;
}

/// Wait, up to ten seconds, for `cond` to hold.
async fn eventually(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "never happened: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Start `req`, wait until `held` is reached, then drop `req` as a client
/// that disconnects would, and let the held engine call go on.
async fn drop_mid_call(req: impl std::future::Future<Output = TestResponse>, held: HeldCall) {
    let entered = tokio::task::spawn_blocking(move || {
        held.wait_entered();
        held
    });
    let held = tokio::select! {
        _ = req => panic!("the request answered while its engine call was held"),
        held = entered => held.unwrap(),
    };
    held.release();
}
