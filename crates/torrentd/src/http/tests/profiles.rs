//! `profiles`, and the daemon-wide `torrents/pause-all` and
//! `torrents/resume-all` that iterate them.

use std::sync::Arc;

use serde_json::json;
use serde_json::Value;
use torrentd_engine::EngineError;
use torrentd_engine::InfoHash;
use torrentd_engine::MockEngine;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileSource;
use torrentd_engine::ProfileStatus;
use torrentd_engine::RecordedCall;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentState;

use super::support::assert_problem;
use super::support::Coverage;
use super::support::Harness;
use crate::app_state::AppState;
use crate::profile_registry::test_failed_profile;
use crate::profile_registry::test_host_entry;
use crate::profile_registry::test_vpn_entry;
use crate::profile_registry::FailedProfile;
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;

/// A live profile whose engine the test keeps a handle on.
fn live(id: &str, status: ProfileStatus) -> (ProfileEntry, Arc<MockEngine>) {
    let engine = Arc::new(MockEngine::new());
    let entry = ProfileEntry::new(
        test_vpn_entry(id, ProfileStatus::Active).config,
        engine.clone(),
        Some("10.2.0.2".parse().unwrap()),
        None,
        0,
    );
    entry.update_health(|h| h.status = status);
    (entry, engine)
}

/// Make `entries` (and `failed`) the daemon's profiles, each live one with a
/// session on its own engine, as startup wires them.
fn install(state: &mut AppState, entries: Vec<ProfileEntry>, failed: Vec<FailedProfile>) {
    state.source = Arc::new(ProfileSource::new(
        entries
            .iter()
            .map(|e| {
                (
                    e.id().clone(),
                    Arc::clone(&e.engine) as Arc<dyn TorrentEngine>,
                )
            })
            .collect(),
    ));
    state.profiles = Arc::new(ProfileRegistry::new(entries).with_failed(failed));
}

/// Put one loaded torrent into `profile`'s slice of the state map.
fn load(s: &AppState, byte: u8, profile: &str) -> TorrentHandle {
    let ih = InfoHash([byte; 20]);
    let h = TorrentHandle {
        id: u64::from(byte),
        infohash: ih,
    };
    s.state.insert(
        ih,
        TorrentState::newly_added(h, ProfileId::new(profile), std::time::Instant::now()),
    );
    h
}

fn calls(engine: &MockEngine, f: impl Fn(&RecordedCall) -> bool) -> usize {
    engine.calls().iter().filter(|c| f(c)).count()
}

const REASON: &str = "wg-acct_c: no handshake";

/// A daemon with an active profile, a fenced one, and one that failed at
/// bring-up.
fn three(cov: &Arc<Coverage>) -> (Harness, Arc<MockEngine>, Arc<MockEngine>) {
    let (a, eng_a) = live("acct_a", ProfileStatus::Active);
    let (b, eng_b) = live("acct_b", ProfileStatus::VpnDown);
    let h = Harness::authed(cov, |s| {
        install(s, vec![a, b], vec![test_failed_profile("acct_c", REASON)]);
    });
    (h, eng_a, eng_b)
}

/// Every declared response of the `profiles` tag, and of the two daemon-wide
/// bulk operations under `torrents`.
pub(crate) async fn scenarios(cov: &Arc<Coverage>) {
    let (h, eng_a, eng_b) = three(cov);
    let ha = load(&h.state, 1, "acct_a");
    let hb = load(&h.state, 2, "acct_b");
    h.state
        .registry
        .assign(InfoHash([1; 20]), ProfileId::new("acct_a"))
        .unwrap();
    // A failed profile's assignments are its stranded torrents.
    h.state
        .registry
        .assign(InfoHash([3; 20]), ProfileId::new("acct_c"))
        .unwrap();

    // The list: live profiles in config order, then the failed one.
    let resp = h.read("/v1/profiles").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    let list: Value = resp.json();
    let items = list["items"].as_array().unwrap();
    let ids: Vec<&str> = items
        .iter()
        .map(|p| p["profile_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["acct_a", "acct_b", "acct_c"]);
    assert_eq!(items[0]["status"], "active");
    assert_eq!(items[0]["tunnel_ip"], "10.2.0.2");
    assert_eq!(items[0]["torrent_count"], 1);
    assert_eq!(items[0]["listen_port"], 6881);
    assert_eq!(items[0]["port_forward"], "static");
    assert_eq!(
        items[0]["forwarded_port"], 6881,
        "static: the configured port"
    );
    assert_eq!(items[0]["user_agent"], "ua-acct_a");
    assert_eq!(
        items[0]["failure_reason"],
        Value::Null,
        "present and null, never omitted"
    );
    assert_eq!(items[1]["status"], "vpn_down");
    assert_eq!(items[2]["status"], "failed");
    assert_eq!(items[2]["failure_reason"], REASON);
    assert_eq!(items[2]["tunnel_ip"], Value::Null);
    assert_eq!(items[2]["forwarded_port"], Value::Null);
    assert_eq!(
        items[2]["torrent_count"], 1,
        "a failed profile's stranded torrents are counted from the registry"
    );

    // One profile, live.
    let resp = h.read("/v1/profiles/acct_a").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    let detail: Value = resp.json();
    assert_eq!(detail["profile_id"], "acct_a");
    assert_eq!(detail["status"], "active");
    assert_eq!(detail["vpn_interface"], "wg-acct_a");
    assert_eq!(detail["allowed_tracker_domains"], json!([]));
    assert_eq!(detail["paused_for_vpn"], 0);
    assert_eq!(detail["port_forward_ok"], true);
    assert_eq!(detail["failure_reason"], Value::Null);

    // One profile, failed: described, not denied.
    let resp = h.read("/v1/profiles/acct_c").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    let detail: Value = resp.json();
    assert_eq!(detail["status"], "failed");
    assert_eq!(detail["failure_reason"], REASON);
    assert_eq!(detail["vpn_interface"], "wg-acct_c");
    assert_eq!(detail["port_forward_ok"], false);
    assert_eq!(detail["torrent_count"], 1);

    // An id no profile declares.
    assert_problem(&h.read("/v1/profiles/typo").await, 404, "profile-not-found");
    // A path segment that is not UTF-8 once decoded.
    let resp = h.read("/v1/profiles/%FF").await;
    assert_eq!(resp.status().as_u16(), 400, "{}", resp.text());

    // Per-profile pause: a fenced profile is paused too.
    let resp = h.write("POST", "/v1/profiles/acct_b/pause-all").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    let out: Value = resp.json();
    assert_eq!(
        out,
        json!({"torrent_count": 1, "failed_count": 0, "skipped_profiles": []})
    );
    assert_eq!(
        calls(
            &eng_b,
            |c| matches!(c, RecordedCall::PauseTorrent(x) if *x == hb)
        ),
        1
    );
    // Per-profile resume of an active one.
    let resp = h.write("POST", "/v1/profiles/acct_a/resume-all").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    assert_eq!(resp.json::<Value>()["torrent_count"], 1);
    assert_eq!(
        calls(
            &eng_a,
            |c| matches!(c, RecordedCall::ResumeTorrent(x) if *x == ha)
        ),
        1
    );

    // A fenced profile is not resumed.
    let resp = h.write("POST", "/v1/profiles/acct_b/resume-all").await;
    assert_problem(&resp, 409, "profile-unavailable");
    let body: Value = resp.json();
    assert_eq!(body["profile_status"], "vpn_down");
    assert_eq!(
        calls(&eng_b, |c| matches!(c, RecordedCall::ResumeTorrent(_))),
        0,
        "a fenced profile must never be un-quarantined"
    );

    // A failed profile: 409 with its reason on both, since the id is
    // configured and 404 would send the operator hunting a typo.
    for op in ["pause-all", "resume-all"] {
        let resp = h.write("POST", &format!("/v1/profiles/acct_c/{op}")).await;
        assert_problem(&resp, 409, "profile-unavailable");
        let body: Value = resp.json();
        assert_eq!(body["profile_status"], "failed", "{op}");
        let detail = body["detail"].as_str().unwrap();
        assert!(
            detail.starts_with(&format!("profile has no session: {REASON}.")),
            "{op}: the bring-up reason is what says what to fix: {detail}"
        );
        assert!(detail.contains("restart the daemon"), "{op}: {detail}");

        assert_problem(
            &h.write("POST", &format!("/v1/profiles/typo/{op}")).await,
            404,
            "profile-not-found",
        );
        let resp = h.write("POST", &format!("/v1/profiles/%FF/{op}")).await;
        assert_eq!(resp.status().as_u16(), 400, "{op}: {}", resp.text());
    }

    // Daemon-wide pause: every live profile, fenced included; the failed one
    // reported.
    let resp = h.write("POST", "/v1/torrents/pause-all").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    let out: Value = resp.json();
    assert_eq!(out["torrent_count"], 2);
    assert_eq!(out["failed_count"], 0);
    assert_eq!(out["skipped_profiles"].as_array().unwrap().len(), 1);
    assert_eq!(out["skipped_profiles"][0]["profile_id"], "acct_c");
    assert_eq!(out["skipped_profiles"][0]["reason"], "failed");
    assert!(out["skipped_profiles"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("no handshake"));
    assert_eq!(
        calls(
            &eng_a,
            |c| matches!(c, RecordedCall::PauseTorrent(x) if *x == ha)
        ),
        1
    );
    assert_eq!(
        calls(
            &eng_b,
            |c| matches!(c, RecordedCall::PauseTorrent(x) if *x == hb)
        ),
        2
    );

    // Daemon-wide resume: the fenced profile is skipped, not the request.
    let resume_b_before = calls(&eng_b, |c| matches!(c, RecordedCall::ResumeTorrent(_)));
    let resp = h.write("POST", "/v1/torrents/resume-all").await;
    resp.assert_status(kynos::http::StatusCode::OK);
    let out: Value = resp.json();
    assert_eq!(out["torrent_count"], 1);
    assert_eq!(out["failed_count"], 0);
    let skipped: Vec<(&str, &str)> = out["skipped_profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["profile_id"].as_str().unwrap(),
                p["reason"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(skipped, [("acct_c", "failed"), ("acct_b", "vpn_down")]);
    assert!(out["skipped_profiles"][1]["detail"]
        .as_str()
        .unwrap()
        .contains("vpn_down"));
    assert_eq!(
        calls(&eng_b, |c| matches!(c, RecordedCall::ResumeTorrent(_))),
        resume_b_before,
        "a fenced profile must never be un-quarantined by a bulk resume"
    );

    // Credentials: missing is 401, the wrong scope 403.
    for (method, path) in [
        ("GET", "/v1/profiles"),
        ("GET", "/v1/profiles/acct_a"),
        ("POST", "/v1/profiles/acct_a/pause-all"),
        ("POST", "/v1/profiles/acct_a/resume-all"),
        ("POST", "/v1/torrents/pause-all"),
        ("POST", "/v1/torrents/resume-all"),
    ] {
        let resp = h.send(method, path, None, None).await;
        assert_eq!(resp.status().as_u16(), 401, "{method} {path}");
        resp.assert_header("www-authenticate", "Bearer");
        let wrong = if method == "GET" {
            h.tokens.metrics.clone()
        } else {
            h.tokens.read.clone()
        };
        let resp = h.send(method, path, Some(&wrong), None).await;
        assert_problem(&resp, 403, "insufficient-scope");
    }

    h.assert_conformance();
}

#[tokio::test]
async fn profiles_behave_as_documented() {
    scenarios(&Coverage::new()).await;
}

#[tokio::test]
async fn bulk_operations_count_what_the_engine_refused() {
    let (a, eng_a) = live("acct_a", ProfileStatus::Active);
    let h = Harness::authed(&Coverage::new(), |s| install(s, vec![a], vec![]));
    load(&h.state, 1, "acct_a");

    for (path, op) in [
        ("/v1/torrents/pause-all", "pause_torrent"),
        ("/v1/torrents/resume-all", "resume_torrent"),
        ("/v1/profiles/acct_a/pause-all", "pause_torrent"),
        ("/v1/profiles/acct_a/resume-all", "resume_torrent"),
    ] {
        // One-shot: armed afresh for each request.
        eng_a.inject_error(
            op,
            EngineError::MockInjected {
                op,
                message: "boom".into(),
            },
        );
        let resp = h.write("POST", path).await;
        resp.assert_status(kynos::http::StatusCode::OK);
        let out: Value = resp.json();
        assert_eq!(out["torrent_count"], 0, "{path}");
        assert_eq!(
            out["failed_count"], 1,
            "{path}: a torrent left running must not read as reached"
        );
    }
    h.assert_conformance();
}

#[tokio::test]
async fn a_profile_with_nothing_loaded_reports_zero_and_a_natpmp_one_its_negotiated_port() {
    let (a, _) = live("acct_a", ProfileStatus::Active);
    // Host profiles have no tunnel; they are still listed.
    let host = test_host_entry("host");
    let h = Harness::authed(&Coverage::new(), |s| install(s, vec![a, host], vec![]));

    let out: Value = h
        .write("POST", "/v1/profiles/acct_a/pause-all")
        .await
        .json();
    assert_eq!(
        out,
        json!({"torrent_count": 0, "failed_count": 0, "skipped_profiles": []})
    );

    let detail: Value = h.read("/v1/profiles/host").await.json();
    assert_eq!(detail["tunnel_ip"], Value::Null);
    assert_eq!(detail["vpn_interface"], Value::Null);
    assert_eq!(detail["user_agent"], Value::Null);
    assert_eq!(detail["port_forward_ok"], true);

    // The effective port is the negotiated one once NAT-PMP reports it.
    h.state
        .profiles
        .resolve(&ProfileId::new("acct_a"))
        .active()
        .unwrap()
        .update_health(|hl| hl.forwarded_port = Some(51413));
    let detail: Value = h.read("/v1/profiles/acct_a").await.json();
    assert_eq!(detail["forwarded_port"], 51413);
    h.assert_conformance();
}

#[tokio::test]
async fn with_no_live_profile_the_list_leads_with_a_failed_one() {
    // Why a client filters on `status` rather than taking the first entry.
    let h = Harness::authed(&Coverage::new(), |s| {
        install(
            s,
            vec![],
            vec![test_failed_profile("acct_b", "wg-acct_b: no handshake")],
        );
    });
    let list: Value = h.read("/v1/profiles").await.json();
    assert_eq!(list["items"][0]["status"], "failed");
    let out: Value = h.write("POST", "/v1/torrents/resume-all").await.json();
    assert_eq!(out["torrent_count"], 0);
    assert_eq!(out["skipped_profiles"][0]["profile_id"], "acct_b");
    h.assert_conformance();
}
