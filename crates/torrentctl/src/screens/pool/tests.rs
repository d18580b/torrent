//! The pool screen's reducers, keys and views.

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

// Views and keys.

#[test]
fn views_switch_with_brackets_and_arrows_but_not_tab() {
    let mut state = with_overview();
    assert!(matches!(
        on_key(&state, testing::key(KeyCode::Char(']'))),
        Some(Msg::Next)
    ));
    assert!(matches!(
        on_key(&state, testing::key(KeyCode::Left)),
        Some(Msg::Prev)
    ));
    assert!(
        on_key(&state, testing::key(KeyCode::Tab)).is_none(),
        "Tab switches screens"
    );
    assert_eq!(
        press(&mut state, KeyCode::Right, true),
        1,
        "the tree opens the selected root"
    );
    assert_eq!(state.view, View::Tree);
    assert_eq!(state.tree.root.as_ref().map(|r| r.id), Some(1));
    press(&mut state, KeyCode::Char('['), true);
    press(&mut state, KeyCode::Char('['), true);
    assert_eq!(state.view, View::Plans, "wraps around");
}

#[test]
fn the_tree_waits_for_the_overview_to_pick_a_root() {
    let mut state = State::default();
    assert_eq!(
        send(&mut state, Msg::Next, true),
        1,
        "the overview is loaded first"
    );
    assert!(state.tree.root.is_none());
    let generation = state.overview.generation;
    let effects = send(
        &mut state,
        Msg::Overview(overview::Msg::Loaded(generation, Ok(overview()))),
        true,
    );
    assert_eq!(effects, 1, "then the first root is browsed");
    assert_eq!(
        state.tree.root.as_ref().map(|r| r.path.as_str()),
        Some("/srv/pool/a")
    );
}

#[test]
fn an_overview_answer_to_an_older_load_is_dropped() {
    let mut state = State::default();
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| {
        assert_eq!(refresh(&mut state, ctx).len(), 1);
        assert!(refresh(&mut state, ctx).is_empty(), "one load at a time");
    });
    let old = state.overview.generation;
    // A scan finishing reloads at once, superseding the refresh.
    let summary = testing::from_json(json!({"files": 1, "bytes": 1, "torrents": 1, "matched": 1,
        "partial": 0, "missing": 0, "overlap": 0, "shared": 0, "drifted": 0, "errors": 0}));
    assert_eq!(
        send(
            &mut state,
            Msg::Overview(overview::Msg::Scanned(Ok(summary))),
            true
        ),
        2
    );
    send(
        &mut state,
        Msg::Overview(overview::Msg::Loaded(old, Ok(overview()))),
        true,
    );
    assert!(state.overview.pool.is_none(), "stale answer dropped");
    let new = state.overview.generation;
    send(
        &mut state,
        Msg::Overview(overview::Msg::Loaded(new, Ok(overview()))),
        true,
    );
    assert_eq!(state.overview.pool.as_ref().map(|p| p.roots.len()), Some(3));
    assert!(state.overview.scan.is_some());
}

#[test]
fn a_failed_overview_load_keeps_the_last_good_data() {
    let mut state = with_overview();
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let generation = state.overview.generation;
    let failure = Failure::local("Cannot reach the daemon", Some("refused".to_owned()));
    assert_eq!(
        send(
            &mut state,
            Msg::Overview(overview::Msg::Loaded(generation, Err(failure))),
            true
        ),
        0
    );
    assert!(state.overview.pool.is_some());
    let screen = shot(&state, 160, 48, true);
    assert!(
        screen.contains("✖ Cannot reach the daemon: refused"),
        "{screen}"
    );
    assert!(screen.contains("/srv/pool/a"));
}

#[test]
fn pool_not_configured_shows_why_and_clears_on_success() {
    let mut state = State::default();
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let generation = state.overview.generation;
    let failure = problem(404, "pool-not-configured", None);
    send(
        &mut state,
        Msg::Overview(overview::Msg::Loaded(generation, Err(failure))),
        true,
    );
    assert!(state.not_configured);
    assert!(shot(&state, 80, 24, true).contains("no [pool] section"));
    assert!(
        on_key(&state, testing::key(KeyCode::Char('s'))).is_none(),
        "no actions"
    );
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let generation = state.overview.generation;
    send(
        &mut state,
        Msg::Overview(overview::Msg::Loaded(generation, Ok(overview()))),
        true,
    );
    assert!(!state.not_configured);
}

#[test]
fn scanning_asks_first_and_drift_runs_once_at_a_time() {
    let mut state = with_overview();
    assert_eq!(press(&mut state, KeyCode::Char('s'), true), 0);
    assert!(capturing(&state));
    assert_eq!(
        press(&mut state, KeyCode::Char('n'), true),
        0,
        "nothing is sent"
    );
    assert!(!capturing(&state));
    press(&mut state, KeyCode::Char('s'), true);
    assert_eq!(
        press(&mut state, KeyCode::Char('y'), true),
        1,
        "one scan request"
    );
    assert!(state.overview.scanning);
    assert_eq!(
        press(&mut state, KeyCode::Char('s'), true),
        1,
        "a toast: already running"
    );

    assert_eq!(press(&mut state, KeyCode::Char('d'), true), 1);
    assert_eq!(
        press(&mut state, KeyCode::Char('d'), true),
        0,
        "already checking"
    );
    let report =
        testing::from_json(json!({"drifted": [hash(9)], "files_changed": 2, "files_vanished": 1}));
    let effects = send(
        &mut state,
        Msg::Overview(overview::Msg::DriftChecked(Ok(report))),
        true,
    );
    assert_eq!(effects, 2, "a toast and a reload");
    assert!(!state.overview.checking_drift);
}

// The tree.

#[test]
fn the_tree_enters_directories_and_climbs_back_to_where_it_was() {
    let mut state = with_tree();
    assert_eq!(state.tree.entries.items.len(), 4);
    assert_eq!(state.tree.breadcrumb(), "/srv/pool/a");

    assert_eq!(press(&mut state, KeyCode::Enter, true), 1);
    assert_eq!(state.tree.path, ["movies"]);
    assert!(state.tree.entries.items.is_empty() && state.tree.entries.loading);
    let old = state.tree.entries.generation - 1;
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation: old,
            first: true,
            result: Ok(tree_page(None)),
        }),
        true,
    );
    assert!(
        state.tree.entries.items.is_empty(),
        "a page for the old directory is dropped"
    );
    let generation = state.tree.entries.generation;
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: true,
            result: Ok(movies_page()),
        }),
        true,
    );
    assert_eq!(state.tree.breadcrumb(), "/srv/pool/a › movies");

    press(&mut state, KeyCode::Down, true);
    assert_eq!(press(&mut state, KeyCode::Enter, true), 1);
    assert_eq!(state.tree.path, ["movies", "2024"]);

    assert_eq!(press(&mut state, KeyCode::Backspace, true), 1);
    assert_eq!(state.tree.path, ["movies"]);
    let generation = state.tree.entries.generation;
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: true,
            result: Ok(movies_page()),
        }),
        true,
    );
    assert_eq!(
        state.tree.selected, 1,
        "back on 2024, the directory just left"
    );

    assert_eq!(press(&mut state, KeyCode::Char('h'), true), 1);
    assert_eq!(
        press(&mut state, KeyCode::Char('h'), true),
        0,
        "already at the root"
    );
}

#[test]
fn a_file_is_not_entered() {
    let mut state = with_tree();
    press(&mut state, KeyCode::Char('G'), true);
    assert_eq!(press(&mut state, KeyCode::Enter, true), 0);
    assert!(state.tree.path.is_empty());
}

#[test]
fn the_tree_pages_as_the_selection_nears_the_end() {
    let mut state = with_overview();
    send(&mut state, Msg::OpenRoot, true);
    let generation = state.tree.entries.generation;
    // A short first page with more behind it is followed at once.
    let effects = send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: true,
            result: Ok(tree_page(Some("c1"))),
        }),
        true,
    );
    assert_eq!(effects, 1, "the next page");
    assert!(state.tree.entries.loading);
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: false,
            result: Ok(tree_page(None)),
        }),
        true,
    );
    assert_eq!(state.tree.entries.items.len(), 8, "appended");
    assert!(state.tree.entries.complete);
}

#[test]
fn orphans_toggle_for_the_same_directory() {
    let mut state = with_tree();
    press(&mut state, KeyCode::Char('j'), true);
    assert_eq!(press(&mut state, KeyCode::Char('o'), true), 1);
    assert!(state.tree.orphans);
    assert_eq!(state.tree.reselect.as_deref(), Some("series"));
    assert!(shot(&state, 80, 24, true).contains("orphans only"));
}

#[test]
fn a_tree_refresh_keeps_the_selected_entry() {
    let mut state = with_tree();
    press(&mut state, KeyCode::Char('G'), true);
    let server = testing::server(true, true);
    assert_eq!(
        testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx).len()),
        1
    );
    assert_eq!(
        state.tree.entries.items.len(),
        4,
        "the old listing stays up meanwhile"
    );
    let generation = state.tree.entries.generation;
    let mut page = tree_page(None);
    page.items.reverse();
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: true,
            result: Ok(page),
        }),
        true,
    );
    assert_eq!(
        state.tree.entries.items[state.tree.selected].name,
        "readme.nfo"
    );
}

/// `n` directory entries from the `from`th, in name order, continuing at
/// `next`.
fn wide_tree(from: usize, n: usize, next: Option<&str>) -> types::TreePage {
    let items: Vec<_> = (from..from + n)
        .map(|i| {
            let name = format!("d{i:05}");
            entry(&name, &name, true, &["adopted"])
        })
        .collect();
    testing::from_json(json!({"items": items, "next_cursor": next}))
}

#[test]
fn a_tree_refresh_past_1000_entries_keeps_them_and_the_selection() {
    let mut state = with_overview();
    send(&mut state, Msg::OpenRoot, true);
    let tree_page = |state: &State, first: bool, page: types::TreePage| {
        Msg::Tree(tree::Msg::Page {
            generation: state.tree.entries.generation,
            first,
            result: Ok(page),
        })
    };
    let msg = tree_page(&state, true, wide_tree(0, 1000, Some("k1000")));
    send(&mut state, msg, true);
    let msg = tree_page(&state, false, wide_tree(1000, 300, None));
    send(&mut state, msg, true);
    state.tree.selected = 1200;

    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let server = testing::server(true, true);
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| refresh(&mut state, ctx));
    testing::run(effects);
    assert_eq!(daemon.lines(), ["GET /v1/pool/roots/1/tree?limit=1000"]);

    let msg = tree_page(&state, true, wide_tree(0, 1000, Some("k1000")));
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| {
        update(&mut state, msg, ctx)
    });
    assert_eq!(
        state.tree.entries.items.len(),
        1300,
        "kept while it re-pages"
    );
    assert_eq!(state.tree.selected, 1200, "not clamped to row 999");
    testing::run(effects);
    assert_eq!(
        daemon.lines()[1],
        "GET /v1/pool/roots/1/tree?cursor=k1000&limit=300"
    );
    let msg = tree_page(&state, false, wide_tree(1000, 300, None));
    send(&mut state, msg, true);
    assert!(!state.tree.entries.loading);
    assert_eq!(state.tree.entries.items.len(), 1300);
    assert_eq!(state.tree.entries.items[state.tree.selected].name, "d01200");
}

#[test]
fn a_list_that_shrank_scrolls_back_to_fill_its_window() {
    let offset = std::cell::Cell::new(50);
    assert_eq!(
        scroll(&offset, 9, 20, 10),
        0,
        "ten rows fit a twenty-row window from the top"
    );
    assert_eq!(offset.get(), 0);
    let offset = std::cell::Cell::new(50);
    assert_eq!(scroll(&offset, 39, 20, 40), 20, "the last twenty rows");
    let offset = std::cell::Cell::new(5);
    assert_eq!(scroll(&offset, 10, 20, 100), 5, "steady, not re-centred");
}

// The library.

#[test]
fn marking_moves_on_and_escape_clears_the_marks() {
    let mut state = with_library(6, None);
    press(&mut state, KeyCode::Char(' '), true);
    press(&mut state, KeyCode::Char(' '), true);
    assert_eq!(state.library.marks.len(), 2);
    assert_eq!(state.library.selected, 2);
    assert_eq!(state.library.targets(), [hash(1), hash(2)]);
    press(&mut state, KeyCode::Char('k'), true);
    press(&mut state, KeyCode::Char(' '), true);
    assert_eq!(state.library.marks.len(), 1, "a second space unmarks");
    press(&mut state, KeyCode::Esc, true);
    assert!(state.library.marks.is_empty());
    assert_eq!(
        state.library.targets(),
        [hash(3)],
        "with no marks, the selected row"
    );
}

#[test]
fn the_library_filter_cycles_through_every_state_and_back_to_all() {
    let mut state = with_library(6, None);
    let before = state.library.items.generation;
    assert_eq!(press(&mut state, KeyCode::Char('F'), true), 1);
    assert_eq!(state.library.filter, Some(types::State::Missing));
    assert!(state.library.items.items.is_empty());
    send(
        &mut state,
        Msg::Library(library::Msg::Page {
            generation: before,
            first: true,
            result: Ok(torrents(6, None)),
        }),
        true,
    );
    assert!(
        state.library.items.items.is_empty(),
        "a page for the old filter is dropped"
    );
    for _ in 0..6 {
        press(&mut state, KeyCode::Char('F'), true);
    }
    assert_eq!(state.library.filter, None);
}

#[test]
fn the_library_pages_and_a_refresh_keeps_the_selected_torrent() {
    let mut state = with_library(30, Some("next"));
    assert_eq!(
        press(&mut state, KeyCode::Char('j'), true),
        0,
        "far from the end"
    );
    assert_eq!(
        press(&mut state, KeyCode::PageDown, true),
        1,
        "near the end: the next page"
    );
    let generation = state.library.items.generation;
    send(
        &mut state,
        Msg::Library(library::Msg::Page {
            generation,
            first: false,
            result: Ok(torrents(6, None)),
        }),
        true,
    );
    assert_eq!(state.library.items.items.len(), 36);

    let selected = state.library.selected_infohash();
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let generation = state.library.items.generation;
    let mut page = torrents(30, None);
    page.items.reverse();
    send(
        &mut state,
        Msg::Library(library::Msg::Page {
            generation,
            first: true,
            result: Ok(page),
        }),
        true,
    );
    assert_eq!(state.library.selected_infohash(), selected);
}

/// `n` library torrents from the `from`th, in infohash order, continuing at
/// `next`.
fn wide_library(from: usize, n: usize, next: Option<&str>) -> types::PoolTorrentPage {
    let mut page = torrents(1, next);
    let row = page.items.remove(0);
    page.items = (from..from + n)
        .map(|i| types::PoolTorrent {
            infohash: format!("{i:040x}"),
            ..row.clone()
        })
        .collect();
    page
}

#[test]
fn a_library_refresh_past_1000_rows_keeps_them_and_the_selection() {
    let mut state = with_library(0, None);
    let library_page = |state: &State, first: bool, page: types::PoolTorrentPage| {
        Msg::Library(library::Msg::Page {
            generation: state.library.items.generation,
            first,
            result: Ok(page),
        })
    };
    // Loaded as the operator scrolled: two pages, 1800 rows.
    let msg = library_page(&state, true, wide_library(0, 1000, Some("k1000")));
    send(&mut state, msg, true);
    let msg = library_page(&state, false, wide_library(1000, 800, Some("k1800")));
    send(&mut state, msg, true);
    assert_eq!(state.library.items.items.len(), 1800);
    state.library.selected = 1700;

    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let server = testing::server(true, true);
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| refresh(&mut state, ctx));
    testing::run(effects);
    assert_eq!(daemon.lines(), ["GET /v1/pool/torrents?limit=1000"]);

    let msg = library_page(&state, true, wide_library(0, 1000, Some("k1000")));
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| {
        update(&mut state, msg, ctx)
    });
    assert_eq!(
        state.library.items.items.len(),
        1800,
        "kept while it re-pages"
    );
    assert_eq!(press(&mut state, KeyCode::Char('j'), true), 0);
    assert_eq!(
        state.library.selected, 1701,
        "a key moves, not clamped to 999"
    );
    let chosen = state.library.selected_infohash();
    testing::run(effects);
    assert_eq!(
        daemon.lines()[1],
        "GET /v1/pool/torrents?cursor=k1000&limit=800"
    );
    let msg = library_page(&state, false, wide_library(1000, 800, Some("k1800")));
    send(&mut state, msg, true);
    assert!(!state.library.items.loading);
    assert_eq!(state.library.items.items.len(), 1800);
    assert_eq!(
        state.library.selected_infohash(),
        chosen,
        "the selection follows the torrent the operator moved to during the reload"
    );
}

#[test]
fn a_failed_library_refresh_does_not_snap_a_later_page_back() {
    let mut state = with_library(0, None);
    let library_page = |state: &State, first: bool, page: types::PoolTorrentPage| {
        Msg::Library(library::Msg::Page {
            generation: state.library.items.generation,
            first,
            result: Ok(page),
        })
    };
    let msg = library_page(&state, true, wide_library(0, 1000, Some("k1000")));
    send(&mut state, msg, true);
    state.library.selected = 10;

    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let generation = state.library.items.generation;
    send(
        &mut state,
        Msg::Library(library::Msg::Page {
            generation,
            first: true,
            result: Err(problem(500, "internal", None)),
        }),
        true,
    );
    assert!(!state.library.items.loading);

    // The operator scrolls on, to the end: the next page is fetched.
    state.library.selected = 998;
    assert_eq!(press(&mut state, KeyCode::Char('j'), true), 1);
    let msg = library_page(&state, false, wide_library(1000, 800, None));
    send(&mut state, msg, true);
    assert_eq!(state.library.items.items.len(), 1800);
    assert_eq!(
        state.library.selected, 999,
        "not snapped back to the row selected when the failed refresh began"
    );
}

#[test]
fn verifying_several_asks_first_and_shows_what_started() {
    let mut state = with_library(6, None);
    press(&mut state, KeyCode::Char(' '), true);
    press(&mut state, KeyCode::Char(' '), true);
    assert_eq!(press(&mut state, KeyCode::Char('v'), true), 0);
    assert!(capturing(&state));
    assert_eq!(
        press(&mut state, KeyCode::Char('y'), true),
        1,
        "one verify request"
    );
    let result = testing::from_json(json!({"requested": 2, "started": [hash(1)],
        "skipped": [{"infohash": hash(2), "reason": "not loaded in any session"}]}));
    assert_eq!(
        send(
            &mut state,
            Msg::Library(library::Msg::Verified(Ok(result))),
            true
        ),
        1,
        "a toast"
    );
    assert!(state.library.marks.is_empty());
    assert!(shot(&state, 160, 48, true).contains("not loaded in any session"));
    press(&mut state, KeyCode::Esc, true);
    assert!(state.library.verify.is_none());

    assert_eq!(
        press(&mut state, KeyCode::Char('v'), true),
        1,
        "one torrent: no question"
    );
}

// Adoption.

#[test]
fn adopting_previews_a_dry_run_then_applies_the_same_request() {
    let mut state = with_library(6, None);
    press(&mut state, KeyCode::Char(' '), true);
    press(&mut state, KeyCode::Char(' '), true);
    assert_eq!(
        press(&mut state, KeyCode::Char('a'), true),
        1,
        "the profiles are fetched"
    );
    assert!(capturing(&state));
    let serial = state.adopt.as_ref().unwrap().serial;
    let dialog = state.adopt.as_ref().unwrap();
    assert_eq!(
        dialog.selector,
        adopt::Selector::Infohashes(vec![hash(1), hash(2)])
    );

    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    let dialog = state.adopt.as_ref().unwrap();
    assert_eq!(
        dialog.profiles.as_deref(),
        Some(&["acct_a".to_owned(), "acct_c".to_owned()][..]),
        "active only"
    );

    assert_eq!(
        press(&mut state, KeyCode::Enter, true),
        0,
        "no profile is chosen for the operator"
    );
    assert!(state.adopt.as_ref().unwrap().profile.is_none());
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Char('k'), true);
    assert_eq!(state.adopt.as_ref().unwrap().profile, Some(0));
    assert_eq!(press(&mut state, KeyCode::Enter, true), 1, "the dry run");
    assert!(matches!(
        state.adopt.as_ref().unwrap().stage,
        adopt::Stage::Previewing
    ));

    let stale = adopt::Msg::Answered {
        serial: serial - 1,
        dry_run: true,
        result: Ok(adoption(true)),
    };
    send(&mut state, Msg::Adopt(stale), true);
    assert!(
        matches!(
            state.adopt.as_ref().unwrap().stage,
            adopt::Stage::Previewing
        ),
        "another dialog's answer"
    );

    let answer = adopt::Msg::Answered {
        serial,
        dry_run: true,
        result: Ok(adoption(true)),
    };
    send(&mut state, Msg::Adopt(answer), true);
    assert!(matches!(
        state.adopt.as_ref().unwrap().stage,
        adopt::Stage::Preview(_)
    ));

    assert_eq!(
        press(&mut state, KeyCode::Enter, true),
        1,
        "the real request"
    );
    assert!(matches!(
        state.adopt.as_ref().unwrap().stage,
        adopt::Stage::Applying(_)
    ));
    assert_eq!(press(&mut state, KeyCode::Esc, true), 0);
    assert!(
        state.adopt.is_some(),
        "the real request cannot be walked away from"
    );

    let answer = adopt::Msg::Answered {
        serial,
        dry_run: false,
        result: Ok(adoption(false)),
    };
    assert_eq!(
        send(&mut state, Msg::Adopt(answer), true),
        2,
        "a toast and a library reload"
    );
    assert!(matches!(
        state.adopt.as_ref().unwrap().stage,
        adopt::Stage::Done(_)
    ));
    assert!(state.library.marks.is_empty());
    press(&mut state, KeyCode::Enter, true);
    assert!(state.adopt.is_none());
}

/// The preview of a large adoption can take longer than the 15s request
/// timeout; it is not given up on, any more than the adoption itself.
#[test]
fn the_adoption_preview_outlasts_the_request_timeout() {
    let mut state = with_library(1, None);
    press(&mut state, KeyCode::Char('a'), true);
    let serial = state.adopt.as_ref().unwrap().serial;
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('j'), true);

    // A daemon that takes the request and is still working on it.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", busy.local_addr().expect("an address"));
    let api = crate::api::Api::new(&url, Some("tdp_test")).expect("a valid URL");
    let msg = on_key(&state, testing::key(KeyCode::Enter)).expect("the dry run");
    let server = testing::server(true, true);
    let mut effects = testing::with_api(&api, Some(&server), |ctx| update(&mut state, msg, ctx));
    assert_eq!(effects.len(), 1, "the dry run");

    // The clock is paused: it moves only to the next deadline, so past the
    // request timeout the preview is still waiting for its answer.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("a test runtime");
    let past_the_timeout = crate::api::REQUEST_TIMEOUT * 4;
    let effect = effects.remove(0).0;
    let answered = runtime.block_on(async { tokio::time::timeout(past_the_timeout, effect).await });
    assert!(
        answered.is_err(),
        "the preview gave up on a daemon still working: {answered:?}"
    );
    drop(busy);
}

#[test]
fn a_refused_dry_run_returns_to_the_profile_and_says_why() {
    let mut state = with_library(1, None);
    press(&mut state, KeyCode::Char('a'), true);
    let serial = state.adopt.as_ref().unwrap().serial;
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Enter, true);
    let failure = problem(409, "profile-unavailable", Some("acct_a is vpn_down"));
    let answer = adopt::Msg::Answered {
        serial,
        dry_run: true,
        result: Err(failure),
    };
    assert_eq!(send(&mut state, Msg::Adopt(answer), true), 1, "a toast");
    let dialog = state.adopt.as_ref().unwrap();
    assert!(matches!(dialog.stage, adopt::Stage::Pick));
    assert_eq!(dialog.error.as_deref(), Some("Refused: acct_a is vpn_down"));
}

#[test]
fn an_adoption_lost_in_transit_is_not_offered_again() {
    let mut state = with_library(1, None);
    press(&mut state, KeyCode::Char('a'), true);
    let serial = state.adopt.as_ref().unwrap().serial;
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Enter, true);
    let preview = adopt::Msg::Answered {
        serial,
        dry_run: true,
        result: Ok(adoption(true)),
    };
    send(&mut state, Msg::Adopt(preview), true);
    press(&mut state, KeyCode::Enter, true);
    assert!(matches!(
        state.adopt.as_ref().unwrap().stage,
        adopt::Stage::Applying(_)
    ));

    // No answer: the daemon may have adopted them all the same.
    let failure = Failure::local("Cannot reach the daemon", None);
    let answer = adopt::Msg::Answered {
        serial,
        dry_run: false,
        result: Err(failure),
    };
    assert_eq!(send(&mut state, Msg::Adopt(answer), true), 1, "a toast");
    assert!(state.adopt.is_none(), "nothing left to send again");

    // A proxy's timeout is just as unclear.
    let mut state = with_library(1, None);
    press(&mut state, KeyCode::Char('a'), true);
    let serial = state.adopt.as_ref().unwrap().serial;
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Enter, true);
    let preview = adopt::Msg::Answered {
        serial,
        dry_run: true,
        result: Ok(adoption(true)),
    };
    send(&mut state, Msg::Adopt(preview), true);
    press(&mut state, KeyCode::Enter, true);
    let answer = adopt::Msg::Answered {
        serial,
        dry_run: false,
        result: Err(problem(504, "gateway-timeout", None)),
    };
    send(&mut state, Msg::Adopt(answer), true);
    assert!(state.adopt.is_none());

    // And so is a `408`: a deadline cut the request off, not the work. The
    // daemon's own carries `about:blank`.
    let mut state = with_library(1, None);
    press(&mut state, KeyCode::Char('a'), true);
    let serial = state.adopt.as_ref().unwrap().serial;
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Enter, true);
    let preview = adopt::Msg::Answered {
        serial,
        dry_run: true,
        result: Ok(adoption(true)),
    };
    send(&mut state, Msg::Adopt(preview), true);
    press(&mut state, KeyCode::Enter, true);
    let answer = adopt::Msg::Answered {
        serial,
        dry_run: false,
        result: Err(problem(408, "about:blank", None)),
    };
    assert_eq!(send(&mut state, Msg::Adopt(answer), true), 1, "a toast");
    assert!(
        state.adopt.is_none(),
        "a 408 is not offered again as a refusal"
    );
}

#[test]
fn a_preview_with_nothing_to_adopt_cannot_be_applied() {
    let mut state = with_library(1, None);
    press(&mut state, KeyCode::Char('a'), true);
    let serial = state.adopt.as_ref().unwrap().serial;
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Enter, true);
    let mut nothing = adoption(true);
    nothing.fast_path.clear();
    nothing.queued_for_verification.clear();
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Answered {
            serial,
            dry_run: true,
            result: Ok(nothing),
        }),
        true,
    );
    assert_eq!(press(&mut state, KeyCode::Enter, true), 0);
    assert_eq!(press(&mut state, KeyCode::Backspace, true), 0);
    assert!(
        matches!(state.adopt.as_ref().unwrap().stage, adopt::Stage::Pick),
        "back to the profile"
    );
}

#[test]
fn the_tree_adopts_the_directory_it_shows_whatever_mutations_allow() {
    let mut state = with_tree();
    press(&mut state, KeyCode::Enter, true);
    assert_eq!(press(&mut state, KeyCode::Char('A'), false), 1);
    let selector = &state.adopt.as_ref().unwrap().selector;
    assert_eq!(
        *selector,
        adopt::Selector::Subtree {
            root_id: 1,
            root_path: "/srv/pool/a".to_owned(),
            path: "movies".to_owned()
        }
    );
}

// Plans.

#[test]
fn plans_open_and_close_and_a_stale_page_is_dropped() {
    let mut state = with_plans();
    assert_eq!(state.plans.list.items.len(), 3);
    let old = state.plans.list.generation;
    assert_eq!(press(&mut state, KeyCode::Char('F'), true), 1);
    assert!(matches!(
        state.plans.filter,
        Some(types::Status4ee43c98::Draft)
    ));
    send(
        &mut state,
        Msg::Plans(plans::Msg::Page {
            generation: old,
            first: true,
            result: Ok(plans_page()),
        }),
        true,
    );
    assert!(
        state.plans.list.items.is_empty(),
        "the unfiltered page is dropped"
    );
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

    press(&mut state, KeyCode::Char('j'), true);
    assert_eq!(press(&mut state, KeyCode::Enter, true), 1);
    assert_eq!(state.plans.detail.as_ref().map(|d| d.id), Some(8));
    let other = plans::Msg::DetailLoaded {
        id: 7,
        result: Ok(relocate_plan()),
    };
    send(&mut state, Msg::Plans(other), true);
    assert!(
        state.plans.detail.as_ref().unwrap().plan.is_none(),
        "an answer for another plan"
    );
    send(
        &mut state,
        Msg::Plans(plans::Msg::DetailLoaded {
            id: 8,
            result: Ok(delete_plan("draft")),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('G'), true);
    assert_eq!(
        state.plans.detail.as_ref().unwrap().selected,
        2,
        "steps move"
    );
    press(&mut state, KeyCode::Esc, true);
    assert!(state.plans.detail.is_none());
}

#[test]
fn creating_and_applying_are_refused_up_front_when_mutations_are_off() {
    let mut state = with_detail(relocate_plan());
    assert_eq!(
        press(&mut state, KeyCode::Char('c'), false),
        1,
        "a toast saying why"
    );
    assert!(state.plans.form.is_none());
    assert_eq!(
        press(&mut state, KeyCode::Char('x'), false),
        1,
        "a toast saying why"
    );
    assert!(state.plans.confirm.is_none());
    let screen = shot(&state, 160, 48, false);
    assert!(screen.contains("allow_mutations is off"), "{screen}");
    assert!(!screen.contains("x apply"));
    assert_eq!(
        press(&mut state, KeyCode::Char('X'), false),
        0,
        "discarding is still allowed"
    );
    assert!(state.plans.confirm.is_some());
}

#[test]
fn a_plan_is_drafted_from_a_checked_form() {
    let mut state = with_tree();
    press(&mut state, KeyCode::Enter, true);
    state.view = View::Plans;
    assert_eq!(press(&mut state, KeyCode::Char('c'), true), 0);
    assert!(capturing(&state));
    {
        let form = state.plans.form.as_ref().unwrap();
        assert_eq!(form.kind, types::PlanKind::Relocate);
        assert_eq!(form.fields[1].input.value(), "1", "the tree's root");
    }
    // Switch to delete_orphans: the tree's directory is the prefix.
    press(&mut state, KeyCode::BackTab, true);
    press(&mut state, KeyCode::Right, true);
    let form = state.plans.form.as_ref().unwrap();
    assert_eq!(form.kind, types::PlanKind::DeleteOrphans);
    assert_eq!(form.fields[1].input.value(), "movies");

    // Back to relocate, and an infohash that is not one.
    press(&mut state, KeyCode::Char(' '), true);
    press(&mut state, KeyCode::Tab, true);
    for c in "abc".chars() {
        press(&mut state, KeyCode::Char(c), true);
    }
    assert_eq!(
        press(&mut state, KeyCode::Enter, true),
        0,
        "nothing is sent"
    );
    let form = state.plans.form.as_ref().unwrap();
    assert_eq!(form.fields[0].error.as_deref(), Some("40 hex digits"));
    assert_eq!(
        form.fields[2].error.as_deref(),
        Some("a directory under the root")
    );

    let form = state.plans.form.as_mut().unwrap();
    form.fields[0].input = Input::new(hash(0xab));
    form.fields[2].input = Input::new("archive".to_owned());
    assert_eq!(
        press(&mut state, KeyCode::Enter, true),
        1,
        "the create request"
    );
    assert!(state.plans.form.as_ref().unwrap().sending);

    let refused = problem(409, "plan-refused", Some("the destination is occupied"));
    send(
        &mut state,
        Msg::Plans(plans::Msg::Created(Err(refused))),
        true,
    );
    let form = state.plans.form.as_ref().unwrap();
    assert!(!form.sending);
    assert_eq!(
        form.error.as_deref(),
        Some("Refused: the destination is occupied")
    );

    let invalid = problem(
        422,
        "validation-failed",
        Some("/dest_rel: must be relative"),
    );
    send(
        &mut state,
        Msg::Plans(plans::Msg::Created(Err(invalid))),
        true,
    );
    let form = state.plans.form.as_ref().unwrap();
    assert!(
        form.fields[2]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("must be relative")),
        "inline"
    );

    assert_eq!(
        send(
            &mut state,
            Msg::Plans(plans::Msg::Created(Ok(relocate_plan()))),
            true
        ),
        2
    );
    assert!(state.plans.form.is_none());
    assert_eq!(
        state
            .plans
            .detail
            .as_ref()
            .and_then(|d| d.plan.as_ref())
            .map(|p| p.id),
        Some(9)
    );
}

#[test]
fn a_deleting_plan_applies_only_with_its_token_typed_back() {
    let mut state = with_detail(delete_plan("draft"));
    assert_eq!(press(&mut state, KeyCode::Char('x'), true), 0);
    assert!(capturing(&state));
    assert_eq!(
        press(&mut state, KeyCode::Char('y'), true),
        0,
        "y is typed, not a yes"
    );
    assert_eq!(press(&mut state, KeyCode::Enter, true), 0, "the wrong word");
    let Some(plans::Pending::Apply { confirm, token, .. }) = state.plans.confirm.as_mut() else {
        panic!("an apply confirmation");
    };
    assert_eq!(token.as_deref(), Some("7f3a-9c21"));
    confirm.input = Input::new("7f3a-9c21".to_owned());
    assert_eq!(
        press(&mut state, KeyCode::Enter, true),
        1,
        "the apply request"
    );
    assert_eq!(state.plans.applying, Some(8));
    assert_eq!(
        press(&mut state, KeyCode::Char('x'), true),
        1,
        "a toast: one at a time"
    );

    let outcome = testing::from_json(json!({"plan_id": 8, "done": 1, "failed": 1, "skipped": 0,
        "status": "failed"}));
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let server = testing::server(true, true);
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| {
        update(
            &mut state,
            Msg::Plans(plans::Msg::Applied {
                id: 8,
                result: Ok(outcome),
            }),
            ctx,
        )
    });
    assert!(state.plans.applying.is_none());
    let msgs = testing::run(effects);
    assert!(
        matches!(&msgs[0], crate::app::Msg::Toast(_)),
        "a toast: {msgs:?}"
    );
    assert_eq!(
        daemon.lines(),
        PLAN_RELOAD,
        "and the list and the plan reloaded"
    );
    assert!(state.plans.detail.as_ref().unwrap().outcome.is_some());
}

#[test]
fn the_apply_confirmation_counts_every_step_not_the_first_page() {
    // A plan carries only its first page of steps inline; the apply runs all
    // of them, so the dialog counts from `step_counts`.
    let mut plan = delete_plan("draft");
    plan.step_counts = testing::from_json(json!({"total": 10_000, "pending": 9_998,
        "in_progress": 0, "done": 1, "failed": 1, "skipped": 0}));
    let mut state = with_detail(plan);
    press(&mut state, KeyCode::Char('x'), true);
    let Some(plans::Pending::Apply { confirm, .. }) = state.plans.confirm.as_ref() else {
        panic!("an apply confirmation");
    };
    assert!(
        confirm.body.starts_with("This moves 9999 files "),
        "{}",
        confirm.body
    );

    let mut plan = relocate_plan();
    plan.step_counts = testing::from_json(json!({"total": 250, "pending": 248,
        "in_progress": 0, "done": 2, "failed": 0, "skipped": 0}));
    let mut state = with_detail(plan);
    press(&mut state, KeyCode::Char('x'), true);
    let Some(plans::Pending::Apply { confirm, .. }) = state.plans.confirm.as_ref() else {
        panic!("an apply confirmation");
    };
    assert!(
        confirm.body.starts_with("Run its 248 steps still to do "),
        "{}",
        confirm.body
    );
}

/// The open plan's `(opening, steps generation)`, to answer its page with.
fn steps_tag(state: &State) -> (u64, u64) {
    let detail = state.plans.detail.as_ref().unwrap();
    (detail.opening, detail.steps.generation)
}

fn steps_answer(state: &mut State, first: bool, page: types::PlanStepPage) -> usize {
    let (opening, generation) = steps_tag(state);
    send(
        state,
        Msg::Plans(plans::Msg::StepsPage {
            opening,
            generation,
            first,
            result: Ok(page),
        }),
        true,
    )
}

#[test]
fn the_step_table_pages_past_the_plans_inline_steps() {
    let mut state = with_detail(big_plan());
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 100, "the inline steps");
    assert!(!detail.steps.complete);
    let screen = shot(&state, 160, 48, true);
    assert!(
        screen.contains("250 steps · 1 done · 1 running · 1 failed"),
        "counted from step_counts: {screen}"
    );
    assert!(screen.contains(" steps · 100 of 250 "), "{screen}");

    assert_eq!(
        press(&mut state, KeyCode::Char('G'), true),
        1,
        "the page after the inline steps"
    );
    assert_eq!(state.plans.detail.as_ref().unwrap().selected, 99);
    assert_eq!(
        press(&mut state, KeyCode::Char('G'), true),
        0,
        "one page at a time"
    );

    // A page answering an earlier opening of this same plan is dropped.
    let (opening, generation) = steps_tag(&state);
    send(
        &mut state,
        Msg::Plans(plans::Msg::StepsPage {
            opening: opening - 1,
            generation,
            first: false,
            result: Ok(steps_page(101, 200, None)),
        }),
        true,
    );
    assert_eq!(state.plans.detail.as_ref().unwrap().steps.items.len(), 100);

    assert_eq!(
        steps_answer(&mut state, false, steps_page(101, 200, Some("after-200"))),
        0
    );
    assert_eq!(press(&mut state, KeyCode::Char('G'), true), 1);
    assert_eq!(
        steps_answer(&mut state, false, steps_page(201, 250, None)),
        0
    );
    press(&mut state, KeyCode::Char('G'), true);
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 250);
    assert!(detail.steps.complete);
    assert_eq!(detail.selected, 249, "the last step, not the 100th");
    let screen = shot(&state, 160, 48, true);
    assert!(screen.contains("stray/0250.mkv"), "{screen}");
    assert!(!screen.contains(" of 250 "), "every step is loaded");

    // A refresh fetches as many steps as were loaded rather than falling back
    // to the inline 100, so the selection keeps its place.
    let server = testing::server(true, true);
    assert_eq!(
        testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx).len()),
        2,
        "the list and the plan"
    );
    let stale = steps_tag(&state);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    let (url, daemon) = runtime.block_on(testing::serve_once(
        "200 OK",
        json!({"items": [], "next_cursor": null}).to_string(),
    ));
    let api = crate::api::Api::new(&url, Some("tdp_test")).expect("a valid URL");
    let theme = testing::theme();
    let ctx = Ctx {
        api: &api,
        server: Some(&server),
        theme: &theme,
        tick: 0,
    };
    let mut effects = update(
        &mut state,
        Msg::Plans(plans::Msg::DetailLoaded {
            id: 8,
            result: Ok(big_plan()),
        }),
        &ctx,
    );
    assert_eq!(effects.len(), 1, "every loaded step, again");
    runtime.block_on(effects.remove(0).0);
    let request = runtime.block_on(daemon).expect("the request");
    let line = request.lines().next().unwrap_or_default();
    assert!(
        line.starts_with("GET /v1/pool/plans/8/steps?") && line.contains("limit=300"),
        "the 250 loaded steps rounded up to a page, not the default 100: {line}"
    );
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 250, "kept until the answer");
    assert_eq!(detail.selected, 249);
    send(
        &mut state,
        Msg::Plans(plans::Msg::StepsPage {
            opening: stale.0,
            generation: stale.1,
            first: false,
            result: Ok(steps_page(251, 260, None)),
        }),
        true,
    );
    assert_eq!(
        state.plans.detail.as_ref().unwrap().steps.items.len(),
        250,
        "a page from before the refresh is dropped"
    );
    assert_eq!(steps_answer(&mut state, true, steps_page(1, 250, None)), 0);
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 250);
    assert_eq!(detail.selected, 249);
}

#[test]
fn a_plan_refreshed_while_its_steps_re_read_lets_the_re_read_finish() {
    let mut state = with_detail(big_plan());
    assert_eq!(press(&mut state, KeyCode::Char('G'), true), 1);
    steps_answer(&mut state, false, steps_page(101, 250, None));
    assert_eq!(state.plans.detail.as_ref().unwrap().steps.items.len(), 250);
    let loaded = || {
        Msg::Plans(plans::Msg::DetailLoaded {
            id: 8,
            result: Ok(big_plan()),
        })
    };
    assert_eq!(send(&mut state, loaded(), true), 1, "the steps, re-read");
    let (_, generation) = steps_tag(&state);
    assert_eq!(
        send(&mut state, loaded(), true),
        0,
        "the next refresh leaves the re-read in flight alone"
    );
    assert_eq!(steps_tag(&state).1, generation, "its answer is still taken");
    assert_eq!(steps_answer(&mut state, true, steps_page(1, 250, None)), 0);
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 250);
    assert!(!detail.steps.loading);
}

/// `n` plan summaries from id `from`, continuing at `next`.
fn wide_plans(from: usize, n: usize, next: Option<&str>) -> types::PlanPage {
    let items: Vec<_> = (from..from + n)
        .map(|id| {
            json!({"id": id, "kind": "relocate", "status": "draft",
                   "created_at": "2026-09-27T10:00:00Z", "applied_at": null})
        })
        .collect();
    testing::from_json(json!({"items": items, "next_cursor": next}))
}

#[test]
fn a_plan_list_refresh_past_1000_plans_keeps_them_and_the_selection() {
    let mut state = State {
        view: View::Plans,
        ..State::default()
    };
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    let plans_page = |state: &State, first: bool, page: types::PlanPage| {
        Msg::Plans(plans::Msg::Page {
            generation: state.plans.list.generation,
            first,
            result: Ok(page),
        })
    };
    // Loaded as the operator scrolled: two pages, 1800 plans.
    let msg = plans_page(&state, true, wide_plans(0, 1000, Some("p1000")));
    send(&mut state, msg, true);
    let msg = plans_page(&state, false, wide_plans(1000, 800, Some("p1800")));
    send(&mut state, msg, true);
    assert_eq!(state.plans.list.items.len(), 1800);
    state.plans.selected = 1700;

    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| refresh(&mut state, ctx));
    testing::run(effects);
    assert_eq!(daemon.lines(), ["GET /v1/pool/plans?limit=1000"]);

    let msg = plans_page(&state, true, wide_plans(0, 1000, Some("p1000")));
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| {
        update(&mut state, msg, ctx)
    });
    assert_eq!(state.plans.list.items.len(), 1800, "kept while it re-pages");
    assert_eq!(press(&mut state, KeyCode::Char('j'), true), 0);
    assert_eq!(
        state.plans.selected, 1701,
        "a key moves, not clamped to 999"
    );
    testing::run(effects);
    assert_eq!(
        daemon.lines()[1],
        "GET /v1/pool/plans?cursor=p1000&limit=800"
    );
    let msg = plans_page(&state, false, wide_plans(1000, 800, Some("p1800")));
    send(&mut state, msg, true);
    assert!(!state.plans.list.loading);
    assert_eq!(state.plans.list.items.len(), 1800);
    assert_eq!(
        state.plans.list.items[state.plans.selected].id, 1701,
        "the selection follows the plan the operator moved to during the reload"
    );
}

#[test]
fn a_plan_steps_refresh_past_1000_steps_keeps_them_and_the_selection() {
    // A 1300-step plan whose body carries the first 100.
    let plan = || -> types::Plan {
        let steps: Vec<_> = (1..=100).map(step_json).collect();
        testing::from_json(json!({
            "id": 8, "kind": "delete_orphans", "status": "draft",
            "created_at": "2026-09-27T10:00:00Z", "applied_at": null,
            "confirm_token": "7f3a-9c21",
            "steps": steps,
            "steps_next_cursor": "after-100",
            "step_counts": {"total": 1300, "pending": 1300, "in_progress": 0, "done": 0,
                            "failed": 0, "skipped": 0},
        }))
    };
    let mut state = with_detail(plan());
    assert_eq!(press(&mut state, KeyCode::Char('G'), true), 1);
    steps_answer(&mut state, false, steps_page(101, 1000, Some("after-1000")));
    assert_eq!(press(&mut state, KeyCode::Char('G'), true), 1);
    steps_answer(&mut state, false, steps_page(1001, 1300, None));
    press(&mut state, KeyCode::Char('G'), true);
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 1300);
    assert_eq!(detail.selected, 1299);

    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let server = testing::server(true, true);
    let loaded = Msg::Plans(plans::Msg::DetailLoaded {
        id: 8,
        result: Ok(plan()),
    });
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| {
        update(&mut state, loaded, ctx)
    });
    testing::run(effects);
    assert_eq!(
        daemon.lines(),
        ["GET /v1/pool/plans/8/steps?limit=1000"],
        "one request's worth of the 1300 loaded steps first"
    );

    let (opening, generation) = steps_tag(&state);
    let first = Msg::Plans(plans::Msg::StepsPage {
        opening,
        generation,
        first: true,
        result: Ok(steps_page(1, 1000, Some("after-1000"))),
    });
    let effects = testing::with_api(&daemon.api(), Some(&server), |ctx| {
        update(&mut state, first, ctx)
    });
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 1300, "kept while it re-pages");
    assert_eq!(detail.selected, 1299, "not clamped to 999");
    testing::run(effects);
    assert_eq!(
        daemon.lines()[1],
        "GET /v1/pool/plans/8/steps?cursor=after-1000&limit=300"
    );
    assert_eq!(
        steps_answer(&mut state, false, steps_page(1001, 1300, None)),
        0
    );
    let detail = state.plans.detail.as_ref().unwrap();
    assert!(!detail.steps.loading);
    assert_eq!(detail.steps.items.len(), 1300);
    assert_eq!(detail.selected, 1299);
}

#[test]
fn a_drafted_plan_is_counted_from_step_counts() {
    let mut state = with_plans();
    let server = testing::server(true, true);
    let effects = testing::with_ctx(Some(&server), |ctx| {
        update(
            &mut state,
            Msg::Plans(plans::Msg::Created(Ok(big_plan()))),
            ctx,
        )
    });
    let toast = effects.into_iter().next().map(testing::deliver);
    let Some(crate::app::Msg::Toast(toast)) = toast else {
        panic!("a toast first, got {toast:?}");
    };
    assert_eq!(toast.text, "plan #8 drafted: 250 steps — x applies it");
    let detail = state.plans.detail.as_ref().unwrap();
    assert_eq!(detail.steps.items.len(), 100);
    assert_eq!(detail.steps.next_cursor.as_deref(), Some("after-100"));
}

#[test]
fn a_moving_plan_applies_on_a_yes_from_the_list() {
    let mut state = with_plans();
    state.plans.selected = 2;
    assert_eq!(
        press(&mut state, KeyCode::Char('x'), true),
        1,
        "the plan is fetched for its token"
    );
    assert!(state.plans.confirm.is_none());
    send(
        &mut state,
        Msg::Plans(plans::Msg::DetailLoaded {
            id: 9,
            result: Ok(relocate_plan()),
        }),
        true,
    );
    assert!(matches!(
        state.plans.confirm,
        Some(plans::Pending::Apply { token: None, .. })
    ));
    assert_eq!(press(&mut state, KeyCode::Char('y'), true), 1);
}

#[test]
fn an_applied_plan_is_not_applied_again_and_can_be_discarded() {
    let mut state = with_detail(delete_plan("applied"));
    assert_eq!(
        press(&mut state, KeyCode::Char('x'), true),
        1,
        "a toast: not a draft"
    );
    assert!(state.plans.confirm.is_none());
    press(&mut state, KeyCode::Char('X'), true);
    assert_eq!(
        press(&mut state, KeyCode::Char('y'), true),
        1,
        "the delete request"
    );
    let effects = send(
        &mut state,
        Msg::Plans(plans::Msg::Discarded {
            id: 8,
            result: Ok(()),
        }),
        true,
    );
    assert_eq!(effects, 2, "a toast and the list reloaded");
    assert!(state.plans.detail.is_none());
}

// Snapshots.

#[test]
fn the_overview_renders() {
    let mut state = with_overview();
    state.overview.scan = Some(testing::from_json(
        json!({"files": 57000, "bytes": 7_500_000_000_000_i64,
        "torrents": 1234, "matched": 300, "partial": 50, "missing": 40, "overlap": 11, "shared": 6,
        "drifted": 3, "errors": 2}),
    ));
    state.overview.drift = Some(testing::from_json(
        json!({"drifted": [hash(9), hash(10), hash(11)],
        "files_changed": 4, "files_vanished": 1}),
    ));
    for (w, h) in [(80, 24), (160, 48)] {
        snapshot(&format!("pool_overview_{w}x{h}"), shot(&state, w, h, false));
    }
}

#[test]
fn the_tree_renders() {
    let state = with_tree();
    for (w, h) in [(80, 24), (160, 48)] {
        snapshot(&format!("pool_tree_{w}x{h}"), shot(&state, w, h, true));
    }
}

#[test]
fn the_library_renders_with_marks() {
    let mut state = with_library(6, None);
    press(&mut state, KeyCode::Char(' '), true);
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Char(' '), true);
    snapshot("pool_library_marked_160x48", shot(&state, 160, 48, true));
}

#[test]
fn the_adopt_preview_renders() {
    let mut state = with_library(6, None);
    for _ in 0..3 {
        press(&mut state, KeyCode::Char(' '), true);
    }
    press(&mut state, KeyCode::Char('a'), true);
    let serial = state.adopt.as_ref().unwrap().serial;
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Profiles {
            serial,
            result: Ok(profiles()),
        }),
        true,
    );
    press(&mut state, KeyCode::Char('j'), true);
    press(&mut state, KeyCode::Enter, true);
    send(
        &mut state,
        Msg::Adopt(adopt::Msg::Answered {
            serial,
            dry_run: true,
            result: Ok(adoption(true)),
        }),
        true,
    );
    snapshot("pool_adopt_preview_160x48", shot(&state, 160, 48, true));
}

#[test]
fn the_plan_detail_renders() {
    let mut state = with_detail(delete_plan("failed"));
    state.plans.detail.as_mut().unwrap().outcome = Some(testing::from_json(json!({"plan_id": 8,
        "done": 1, "failed": 1, "skipped": 0, "status": "failed"})));
    snapshot("pool_plan_detail_160x48", shot(&state, 160, 48, true));
}

#[test]
fn the_apply_confirmation_renders() {
    let mut state = with_detail(delete_plan("draft"));
    press(&mut state, KeyCode::Char('x'), true);
    for c in "7f3a".chars() {
        press(&mut state, KeyCode::Char(c), true);
    }
    snapshot("pool_apply_confirm_160x48", shot(&state, 160, 48, true));
}
