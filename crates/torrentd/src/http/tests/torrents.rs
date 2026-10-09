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
use torrentd_engine::AssignmentRegistry;
use torrentd_engine::EngineError;
use torrentd_engine::HeldCall;
use torrentd_engine::InfoHash;
use torrentd_engine::MockEngine;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileSource;
use torrentd_engine::ProfileStatus;
use torrentd_engine::RecordedCall;
use torrentd_engine::TorrentDetails;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentFile;
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
    let h = Harness::authed(cov, |s| {
        fixture(s, dir.path());
        s.pool = crate::pool_service::PoolService::open(&crate::config::Config::minimal_for_tests(
            dir.path(),
            true,
        ))
        .unwrap();
    });
    assert!(h.state.pool.as_ref().is_some_and(|p| p.allow_mutations()));
    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{}?delete_files=true", hex(STALE)),
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
    add(&hex(LOADED)).unwrap();
    add(&shared_with).unwrap();
    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{}?delete_files=true", hex(LOADED)),
        )
        .await;
    assert_problem(&resp, 409, "payload-shared");
    assert!(resp.json::<Value>()["detail"]
        .as_str()
        .unwrap()
        .contains(&shared_with));
    assert!(h.state.registry.lookup(&LOADED).is_some());
    pool.with_store_mut(|st| st.replace_claims(&shared_with, &[]))
        .unwrap();

    // With mutations allowed, a loaded torrent's payload goes with it.
    let resp = h
        .write(
            "DELETE",
            &format!("/v1/torrents/{}?delete_files=true", hex(LOADED)),
        )
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);
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

async fn listing(h: &Harness) {
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

async fn reading(h: &Harness, e: &Engines) {
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

fn magnet(profile: &str) -> Value {
    json!({"profile_id": profile, "source": {"kind": "magnet", "uri": MAGNET}})
}

fn metainfo(profile: &str, bytes: &[u8]) -> Value {
    json!({"profile_id": profile, "source": {"kind": "metainfo", "data": STANDARD.encode(bytes)}})
}

async fn adding(h: &Harness, e: &Engines, dir: &Path) {
    // The mock derives a handle's infohash from the first 20 bytes of what it
    // is given; the 201 carries the details for that handle.
    let mut synthetic = [0u8; 20];
    synthetic.copy_from_slice(&MAGNET.as_bytes()[..20]);
    e.p.set_torrent_details(
        e.p.register_handle(InfoHash(synthetic)),
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

    // A session that refuses the torrent releases the claim for a retry.
    e.p.inject_error("add_torrent", injected("add_torrent"));
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes('c')))
        .await;
    assert_problem(&resp, 500, "internal");
    assert!(!resp.text().contains("boom"), "the cause stays in the log");
    let resp = h
        .write_json("POST", "/v1/torrents", metainfo("p", &torrent_bytes('c')))
        .await;
    resp.assert_status(StatusCode::CREATED);

    body_framework_rejections(
        h,
        "POST",
        "/v1/torrents",
        crate::http::v1::ADD_REQUEST_DEADLINE,
    )
    .await;
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
}

async fn controls(h: &Harness, e: &Engines) {
    let loaded = handle(&e.p, LOADED);
    let unknown = hex(InfoHash([0xee; 20]));

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
        e.p.inject_error(op, injected(op));
        let resp = h
            .write("POST", &format!("/v1/torrents/{}/{verb}", hex(LOADED)))
            .await;
        assert_problem(&resp, 500, "internal");
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

fn file(index: u32, path: &str) -> TorrentFile {
    TorrentFile {
        index,
        path: path.into(),
        size: 100,
        downloaded: 50,
        priority: 4,
    }
}

async fn files(h: &Harness, e: &Engines) {
    let loaded = handle(&e.p, LOADED);
    let list = format!("/v1/torrents/{}/files", hex(LOADED));
    let priority = |i: u32| format!("/v1/torrents/{}/files/{i}/priority", hex(LOADED));

    // A magnet still fetching its metadata has no files.
    let resp = h.read(&list).await;
    assert_problem(&resp, 409, "metadata-pending");
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 409, "metadata-pending");

    let all: Vec<TorrentFile> = (0..12).map(|i| file(i, &format!("d/f{i}"))).collect();
    e.p.set_torrent_files(loaded, Some(all));
    let page: Value = h.read(&format!("{list}?limit=5")).await.json();
    assert_eq!(page["items"].as_array().unwrap().len(), 5);
    assert_eq!(
        page["items"][0],
        json!({"index": 0, "path": "d/f0", "size": 100, "downloaded": 50, "priority": 4})
    );
    // Index 10 sorts after 9, not after 1.
    let mut seen: Vec<u64> = Vec::new();
    let mut cursor = None::<String>;
    loop {
        let path = match &cursor {
            Some(c) => format!("{list}?limit=5&cursor={c}"),
            None => format!("{list}?limit=5"),
        };
        let page: Value = h.read(&path).await.json();
        seen.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["index"].as_u64().unwrap()),
        );
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen, (0..12).collect::<Vec<u64>>());
    let resp = h.read(&format!("{list}?cursor=nope!")).await;
    assert_problem(&resp, 400, "invalid-cursor");
    let torrents_cursor = crate::http::page::encode("torrents", &hex(LOADED));
    let resp = h.read(&format!("{list}?cursor={torrents_cursor}")).await;
    assert_problem(&resp, 400, "invalid-cursor");
    // Another torrent's files cursor, and a key no file index could be.
    for (listing, key) in [
        (format!("files:{}", hex(ADDING)), "0000000001"),
        (format!("files:{}", hex(LOADED)), "zzz"),
    ] {
        let cursor = crate::http::page::encode(&listing, key);
        let resp = h.read(&format!("{list}?cursor={cursor}")).await;
        assert_problem(&resp, 400, "invalid-cursor");
    }
    let resp = h.read(&format!("{list}?limit=0")).await;
    assert_problem(&resp, 422, "validation-failed");
    assert_eq!(errors_at(&resp), ["#/query/limit"]);
    let resp = h.read(&format!("/v1/torrents/{}/files", hex(ADDING))).await;
    assert_problem(&resp, 404, "torrent-not-found");
    e.p.inject_error("torrent_files", injected("torrent_files"));
    let resp = h.read(&list).await;
    assert_problem(&resp, 500, "internal");
    e.p.inject_error(
        "torrent_files",
        EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(LOADED)),
    );
    let resp = h.read(&list).await;
    assert_problem(&resp, 404, "torrent-not-found");

    // Priorities.
    h.write_json("PUT", &priority(11), json!({"priority": 7}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(last_call_was(
        &e.p,
        &RecordedCall::SetFilePriority {
            handle: loaded,
            file_idx: 11,
            priority: 7
        }
    ));
    let resp = h
        .write_json("PUT", &priority(12), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 404, "file-not-found");
    let resp = h
        .write_json("PUT", &priority(u32::MAX), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 404, "file-not-found");
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 8}))
        .await;
    assert_problem(&resp, 422, "validation-failed");
    assert_eq!(errors_at(&resp), ["/priority"]);
    for body in [
        json!({"priority": 256}),
        json!({"priority": 1, "x": 1}),
        json!({}),
    ] {
        let resp = h.write_json("PUT", &priority(0), body.clone()).await;
        assert_eq!(resp.status().as_u16(), 422, "{body}");
    }
    let resp = h
        .write_json(
            "PUT",
            &format!("/v1/torrents/{}/files/0/priority", hex(ADDING)),
            json!({"priority": 1}),
        )
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
    e.p.inject_error("set_file_priority", injected("set_file_priority"));
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 500, "internal");
    // Removed from its session between the count and the set.
    e.p.inject_error(
        "set_file_priority",
        EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(LOADED)),
    );
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
    body_framework_rejections(h, "PUT", &priority(0), crate::http::v1::REQUEST_DEADLINE).await;
}

async fn trackers(h: &Harness, e: &Engines) {
    let loaded = handle(&e.p, LOADED);
    let path = format!("/v1/torrents/{}/trackers", hex(LOADED));
    let entry = |url: String, tier: u8| TrackerEntry {
        url,
        tier,
        verified: false,
        updating: false,
        working: false,
        fails: 0,
        message: None,
        last_error: None,
        next_announce: None,
        scrape_complete: None,
        scrape_incomplete: None,
    };
    e.p.set_torrent_trackers(
        loaded,
        vec![
            TrackerEntry {
                verified: true,
                message: Some(format!(
                    "moved to https://new.example/announce?passkey={PASSKEY}"
                )),
                next_announce: Some(1_700_000_000),
                scrape_complete: Some(12),
                scrape_incomplete: Some(3),
                ..entry(
                    format!("https://user:{PASSKEY}@t.example:8443/{PASSKEY}/announce?passkey={PASSKEY}"),
                    0,
                )
            },
            TrackerEntry {
                fails: 2,
                last_error: Some("connection refused".into()),
                message: Some("ignored while there is an error".into()),
                ..entry("udp://backup.example:6969/announce".into(), 1)
            },
            entry("http://idle.example/announce".into(), 2),
        ],
    );
    let resp = h.read(&path).await;
    resp.assert_status(StatusCode::OK);
    assert!(
        !resp.text().contains(PASSKEY),
        "a passkey left the daemon: {}",
        resp.text()
    );
    let list: Value = resp.json();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["tier"], 0);
    assert_eq!(items[0]["host"], "t.example:8443");
    assert!(
        items[0]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://t.example:8443/[redacted:"),
        "{}",
        items[0]["url"]
    );
    assert_eq!(items[0]["status"], "working");
    assert!(items[0]["message"]
        .as_str()
        .unwrap()
        .contains("https://new.example/[redacted:"));
    assert_eq!(items[0]["next_announce_at"], "2023-11-14T22:13:20Z");
    assert_eq!(items[0]["seeds"], 12);
    assert_eq!(items[0]["peers"], 3);
    assert_eq!(items[1]["url"], "udp://backup.example:6969/announce");
    assert_eq!(items[1]["status"], "error");
    assert_eq!(items[1]["message"], "connection refused");
    assert_eq!(items[2]["status"], "not_contacted");
    assert_eq!(items[2]["message"], Value::Null);
    assert_eq!(items[2]["seeds"], Value::Null);

    // A magnet has its trackers before its metadata: no metadata-pending.
    let fenced = handle(&e.f, FENCED);
    e.f.set_torrent_trackers(fenced, vec![entry("http://t.example/a".into(), 0)]);
    let list: Value = h
        .read(&format!("/v1/torrents/{}/trackers", hex(FENCED)))
        .await
        .json();
    assert_eq!(list["items"].as_array().unwrap().len(), 1);

    let resp = h
        .read(&format!("/v1/torrents/{}/trackers", hex(ADDING)))
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
    e.p.inject_error("torrent_trackers", injected("torrent_trackers"));
    let resp = h.read(&path).await;
    assert_problem(&resp, 500, "internal");
}

async fn deleting(h: &Harness, e: &Engines) {
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
    // Once the boot is known to have left it unloaded, it is clearable.
    h.state.unloaded_at_boot.lock().insert(ADDING);
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

#[tokio::test]
async fn torrents_behave_as_documented() {
    scenarios(&Coverage::new()).await;
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
    let mut engine = None;
    let h = Harness::authed(&Coverage::new(), |s| {
        engine = Some(fixture(s, dir.path()).p);
        // The torrent is assigned, and from then on every write to the
        // registry fails, as on a full or read-only state directory.
        let db = dir.path().join("failing.db");
        s.registry = Arc::new(AssignmentRegistry::new_empty(&db));
        s.registry.assign(LOADED, ProfileId::new("p")).unwrap();
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_delete BEFORE DELETE ON assignment \
                   BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
    });
    let resp = h
        .write("DELETE", &format!("/v1/torrents/{}", hex(LOADED)))
        .await;
    assert_problem(&resp, 500, "internal");
    let detail = resp.json::<Value>()["detail"].as_str().unwrap().to_owned();
    assert!(
        detail.contains("assignment") && detail.contains("removed from its session"),
        "the operator has to know which half failed: {detail}"
    );
    assert!(engine
        .unwrap()
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::RemoveTorrent { .. })));
    // The detail says to retry. That only works if the failed write left the
    // claim in memory too; dropping it there first made the retry a 404 and
    // the claim came back from disk at the next restart.
    assert_eq!(
        h.state.registry.lookup(&LOADED),
        Some(ProfileId::new("p")),
        "a remove that failed to persist releases nothing",
    );
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
    // The mock derives the handle's infohash from the magnet's first 20 bytes.
    let mut synthetic = [0u8; 20];
    synthetic.copy_from_slice(&MAGNET.as_bytes()[..20]);
    let th = handle(&engine, InfoHash(synthetic));
    assert!(
        called(&engine, &RecordedCall::PauseTorrent(th)),
        "{:?}",
        engine.calls()
    );
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
    let text = String::from_utf8(h.state.metrics.render()).unwrap();
    assert!(
        text.contains(
            "torrentd_torrent_file_persist_errors_total{profile_id=\"p\",source=\"api\"} 1"
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
    let h = Harness::authed(&Coverage::new(), |s| {
        fixture(s, dir.path());
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
