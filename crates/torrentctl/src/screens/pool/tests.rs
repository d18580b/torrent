//! The pool screen's reducers, keys and views: the fixtures and drivers
//! here, the tests by view in the modules below.

mod adoption;
mod library_view;
mod plan_view;
mod snapshots;
mod tree_view;
mod views;

use crossterm::event::KeyCode;
use serde_json::json;
use tui_input::Input;

use super::*;
use crate::api::types;
use crate::testing;

// Fixtures.

fn hash(n: u8) -> String {
    format!("{n:02x}").repeat(20)
}

fn overview_json() -> serde_json::Value {
    const TIB: i64 = 1 << 40;
    const GIB: i64 = 1 << 30;
    json!({
        "library_dir": "/srv/library", "torrents": 1234, "files": 56789,
        "states": {"missing": 40, "partial": 50, "matched": 300, "adopted": 800,
                   "drifted": 3, "overlap": 11, "shared": 6},
        "verify_queue_depth": 4, "verify_in_flight": 2,
        "roots": [
            {"root_id": 1, "path": "/srv/pool/a", "bytes_total": 4 * TIB,
             "bytes_adopted": 2 * TIB + 512 * GIB, "bytes_matched": TIB, "bytes_orphan": 200 * GIB,
             "files_total": 40000, "files_orphan": 1200},
            {"root_id": 2, "path": "/srv/pool/b", "bytes_total": 2 * TIB,
             "bytes_adopted": TIB, "bytes_matched": 0, "bytes_orphan": 0,
             "files_total": 12000, "files_orphan": 0},
            {"root_id": 3, "path": "/mnt/archive/cold-storage", "bytes_total": 800 * GIB,
             "bytes_adopted": 0, "bytes_matched": 100 * GIB, "bytes_orphan": 650 * GIB,
             "files_total": 5000, "files_orphan": 4100},
        ],
    })
}

fn overview() -> types::PoolOverview {
    testing::from_json(overview_json())
}

fn entry(name: &str, path: &str, is_dir: bool, states: &[&str]) -> serde_json::Value {
    const GIB: i64 = 1 << 30;
    json!({
        "name": name, "path": path, "is_dir": is_dir, "states": states,
        "bytes_total": 120 * GIB, "bytes_adopted": if states.contains(&"adopted") { 80 * GIB } else { 0 },
        "bytes_matched": if states.contains(&"matched") { 30 * GIB } else { 0 },
        "bytes_orphan": if states.is_empty() { 120 * GIB } else { 10 * GIB },
        "files_total": 340, "files_orphan": 12,
    })
}

fn tree_page(next: Option<&str>) -> types::TreePage {
    testing::from_json(json!({
        "items": [
            entry("movies", "movies", true, &["adopted", "matched"]),
            entry("series", "series", true, &["adopted", "partial", "drifted"]),
            entry("stray", "stray", true, &[]),
            entry("readme.nfo", "readme.nfo", false, &["overlap"]),
        ],
        "next_cursor": next,
    }))
}

fn movies_page() -> types::TreePage {
    testing::from_json(json!({
        "items": [
            entry("2023", "movies/2023", true, &["adopted"]),
            entry("2024", "movies/2024", true, &["matched"]),
        ],
    }))
}

fn torrents(n: u8, next: Option<&str>) -> types::PoolTorrentPage {
    let states = [
        Some("adopted"),
        Some("matched"),
        Some("partial"),
        None,
        Some("drifted"),
        Some("missing"),
    ];
    let items: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            let state = states[i as usize % states.len()];
            json!({
                "infohash": hash(i + 1), "name": format!("Some.Linux.Distro.{i}.x86_64.iso"),
                "total_size": (i as i64 + 1) * 3_000_000_000_i64, "num_files": i as i64 * 7 + 1,
                "state": state, "base_rel": null,
                "note": if state == Some("partial") { Some("1 of 2 files present") } else { None },
                "profile_id": if state == Some("adopted") { Some("acct_a") } else { None },
                "category": null, "tags": [], "has_fastresume": i % 2 == 0,
            })
        })
        .collect();
    testing::from_json(json!({"items": items, "next_cursor": next}))
}

fn plans_page() -> types::PlanPage {
    testing::from_json(json!({"items": [
        {"id": 7, "kind": "relocate", "status": "applied",
         "created_at": "2026-09-20T08:15:00Z", "applied_at": "2026-09-20T08:20:00Z"},
        {"id": 8, "kind": "delete_orphans", "status": "draft",
         "created_at": "2026-09-27T10:00:00Z", "applied_at": null},
        {"id": 9, "kind": "relocate", "status": "failed",
         "created_at": "2026-09-27T11:30:00Z", "applied_at": null},
    ]}))
}

fn delete_plan(status: &str) -> types::Plan {
    testing::from_json(json!({
        "id": 8, "kind": "delete_orphans", "status": status,
        "created_at": "2026-09-27T10:00:00Z", "applied_at": null,
        "confirm_token": "7f3a-9c21",
        "steps": [
            {"seq": 1, "op": "delete_file", "src": "stray/old.mkv", "dst": null, "status": "done", "error": null},
            {"seq": 2, "op": "delete_file", "src": "stray/sample.mkv", "dst": null, "status": "failed",
             "error": "permission denied"},
            {"seq": 3, "op": "delete_file", "src": "stray/extras/cover.jpg", "dst": null,
             "status": "pending", "error": null},
        ],
        "steps_next_cursor": null,
        "step_counts": {"total": 3, "pending": 1, "in_progress": 0, "done": 1, "failed": 1, "skipped": 0},
    }))
}

fn relocate_plan() -> types::Plan {
    testing::from_json(json!({
        "id": 9, "kind": "relocate", "status": "draft",
        "created_at": "2026-09-27T11:30:00Z", "applied_at": null, "confirm_token": null,
        "steps": [
            {"seq": 1, "op": "move_torrent", "src": "a:movies/Film", "dst": "b:archive/Film",
             "status": "pending", "error": null},
        ],
        "steps_next_cursor": null,
        "step_counts": {"total": 1, "pending": 1, "in_progress": 0, "done": 0, "failed": 0, "skipped": 0},
    }))
}

fn step_json(seq: usize) -> serde_json::Value {
    json!({"seq": seq, "op": "delete_file", "src": format!("stray/{seq:04}.mkv"), "dst": null,
           "status": "pending", "error": null})
}

/// A page of steps `from..=to`, continuing at `next`.
fn steps_page(from: usize, to: usize, next: Option<&str>) -> types::PlanStepPage {
    let items: Vec<_> = (from..=to).map(step_json).collect();
    testing::from_json(json!({"items": items, "next_cursor": next}))
}

/// A 250-step deleting plan, of which the body carries the first 100.
fn big_plan() -> types::Plan {
    let steps: Vec<_> = (1..=100).map(step_json).collect();
    testing::from_json(json!({
        "id": 8, "kind": "delete_orphans", "status": "draft",
        "created_at": "2026-09-27T10:00:00Z", "applied_at": null,
        "confirm_token": "7f3a-9c21",
        "steps": steps,
        "steps_next_cursor": "after-100",
        "step_counts": {"total": 250, "pending": 247, "in_progress": 1, "done": 1, "failed": 1,
                        "skipped": 0},
    }))
}

fn adoption(dry_run: bool) -> types::AdoptionResult {
    testing::from_json(json!({
        "dry_run": dry_run,
        "fast_path": [hash(1), hash(3)],
        "queued_for_verification": [hash(5)],
        "refused": [{"infohash": hash(4), "reason": "not matched: its state is partial"}],
        "verify_bytes": 15_000_000_000_i64,
    }))
}

fn profiles() -> Vec<types::Profile> {
    testing::from_json(json!([
        {"profile_id": "acct_a", "status": "active", "tunnel_ip": "10.2.0.2", "torrent_count": 900,
         "desired_state": "online", "effective_state": "online",
         "listen_port": 51413, "port_forward": "natpmp", "forwarded_port": 51413,
         "user_agent": null, "failure_reason": null},
        {"profile_id": "acct_b", "status": "vpn_down", "tunnel_ip": "10.3.0.2", "torrent_count": 3,
         "desired_state": "online", "effective_state": "offline",
         "listen_port": 51414, "port_forward": "static", "forwarded_port": null,
         "user_agent": null, "failure_reason": null},
        {"profile_id": "acct_c", "status": "active", "tunnel_ip": null, "torrent_count": 0,
         "desired_state": "online", "effective_state": "online",
         "listen_port": null, "port_forward": "static", "forwarded_port": null,
         "user_agent": null, "failure_reason": null},
    ]))
}

fn problem(status: u16, slug: &str, detail: Option<&str>) -> Failure {
    Failure {
        status: Some(status),
        slug: Some(slug.to_owned()),
        title: "Refused".to_owned(),
        detail: detail.map(str::to_owned),
        request_id: None,
        ..Default::default()
    }
}

/// A drift report: `fields` over one that found and missed nothing.
fn drift_report(fields: serde_json::Value) -> types::DriftReport {
    let mut report = json!({"drifted": [], "files_changed": 0, "files_vanished": 0,
        "files_unreadable": 0, "unreadable_roots": [], "unmounted_dirs": [], "unchecked": []});
    for (k, v) in fields.as_object().unwrap() {
        report[k] = v.clone();
    }
    testing::from_json(report)
}

// Driving.

/// What reloading the plan list and plan 8 sends: every page request names
/// its size.
const PLAN_RELOAD: [&str; 2] = ["GET /v1/pool/plans?limit=100", "GET /v1/pool/plans/8"];

/// Apply `msg` under a daemon with the pool configured and `mutations` as
/// given, returning how many effects it asked for.
fn send(state: &mut State, msg: Msg, mutations: bool) -> usize {
    let server = testing::server(true, mutations);
    testing::with_ctx(Some(&server), |ctx| update(state, msg, ctx).len())
}

fn press(state: &mut State, code: KeyCode, mutations: bool) -> usize {
    match on_key(state, testing::key(code)) {
        Some(msg) => send(state, msg, mutations),
        None => 0,
    }
}

fn shot(state: &State, w: u16, h: u16, mutations: bool) -> String {
    let server = testing::server(true, mutations);
    testing::render(w, h, Some(&server), |ctx, frame, area| {
        view(state, ctx, frame, area)
    })
}

fn snapshot(name: &str, screen: String) {
    // Snapshots sit beside the other screens', one directory up.
    insta::with_settings!({ snapshot_path => "../snapshots" }, {
        insta::assert_snapshot!(name, screen);
    });
}

fn with_overview() -> State {
    let mut state = State::default();
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let generation = state.overview.generation;
    send(
        &mut state,
        Msg::Overview(overview::Msg::Loaded(generation, Ok(overview()))),
        true,
    );
    state
}

fn with_tree() -> State {
    let mut state = with_overview();
    assert_eq!(send(&mut state, Msg::OpenRoot, true), 1);
    let generation = state.tree.entries.generation;
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: true,
            result: Ok(tree_page(None)),
        }),
        true,
    );
    state
}

fn with_library(n: u8, next: Option<&str>) -> State {
    let mut state = State {
        view: View::Library,
        ..State::default()
    };
    let server = testing::server(true, true);
    let effects = testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx).len());
    assert_eq!(effects, 1, "the first page");
    let generation = state.library.items.generation;
    send(
        &mut state,
        Msg::Library(library::Msg::Page {
            generation,
            first: true,
            result: Ok(torrents(n, next)),
        }),
        true,
    );
    state
}

fn with_plans() -> State {
    let mut state = State {
        view: View::Plans,
        ..State::default()
    };
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let generation = state.plans.list.generation;
    send(
        &mut state,
        Msg::Plans(plans::Msg::Page {
            generation,
            first: true,
            result: Ok(plans_page()),
        }),
        true,
    );
    state
}

/// The plans view with plan `plan` open.
fn with_detail(plan: types::Plan) -> State {
    let mut state = with_plans();
    let at = state
        .plans
        .list
        .items
        .iter()
        .position(|p| p.id == plan.id)
        .unwrap();
    state.plans.selected = at;
    assert_eq!(send(&mut state, Msg::Plans(plans::Msg::Open), true), 1);
    let id = plan.id;
    send(
        &mut state,
        Msg::Plans(plans::Msg::DetailLoaded {
            id,
            result: Ok(plan),
        }),
        true,
    );
    state
}
