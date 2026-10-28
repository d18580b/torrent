//! Switching views, what a load in flight or failed means for each, and the
//! overview's scan and drift check.

use super::*;

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
fn busy_reads_the_load_of_the_view_shown() {
    // Overview: its own load.
    let mut state = with_overview();
    assert!(!busy(&state));
    state.overview.loading = true;
    assert!(busy(&state), "the overview is loading");

    // Tree before a root is picked: the overview that picks it.
    let mut state = with_overview();
    state.view = View::Tree;
    assert!(state.tree.root.is_none());
    state.tree.entries.loading = true;
    assert!(!busy(&state), "no root: the tree's entries are not read");
    state.overview.loading = true;
    assert!(busy(&state), "no root: the overview picking one is");

    // Tree with a root: its entries, not the overview.
    let mut state = with_tree();
    assert_eq!(state.view, View::Tree);
    assert!(!busy(&state));
    state.overview.loading = true;
    assert!(!busy(&state), "a root: the overview's load is not read");
    state.tree.entries.loading = true;
    assert!(busy(&state), "a root: its entries are loading");

    // Library: its page of items, and no other view's load.
    let mut state = with_library(3, None);
    assert!(!busy(&state));
    state.overview.loading = true;
    state.tree.entries.loading = true;
    state.plans.list.loading = true;
    assert!(!busy(&state), "other views' loads are not read");
    state.library.items.loading = true;
    assert!(busy(&state), "the library is loading");

    // Plans: the list, and an open plan's detail or its steps.
    let mut state = with_plans();
    assert!(!busy(&state));
    state.library.items.loading = true;
    assert!(!busy(&state), "the library's load is not read");
    state.plans.list.loading = true;
    assert!(busy(&state), "the plan list is loading");

    let mut state = with_detail(delete_plan("draft"));
    assert!(!busy(&state));
    state.plans.detail.as_mut().unwrap().loading = true;
    assert!(busy(&state), "the open plan is loading");
    let detail = state.plans.detail.as_mut().unwrap();
    detail.loading = false;
    detail.steps.loading = true;
    assert!(busy(&state), "the open plan's steps are loading");
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
        drift_report(json!({"drifted": [hash(9)], "files_changed": 2, "files_vanished": 1}));
    let effects = send(
        &mut state,
        Msg::Overview(overview::Msg::DriftChecked(Ok(report))),
        true,
    );
    assert_eq!(effects, 2, "a toast and a reload");
    assert!(!state.overview.checking_drift);
}

/// The toast a drift report raises.
fn drift_toast(report: types::DriftReport) -> crate::screens::contract::Toast {
    let mut state = with_overview();
    let server = testing::server(true, true);
    let effects = testing::with_ctx(Some(&server), |ctx| {
        update(
            &mut state,
            Msg::Overview(overview::Msg::DriftChecked(Ok(report))),
            ctx,
        )
    });
    match effects.into_iter().next().map(testing::deliver) {
        Some(crate::app::Msg::Toast(toast)) => toast,
        other => panic!("a toast first, got {other:?}"),
    }
}

#[test]
fn a_drift_check_that_could_not_read_a_root_does_not_say_nothing_drifted() {
    use crate::screens::contract::ToastKind;

    let clean = drift_toast(drift_report(json!({})));
    assert_eq!(
        (clean.kind, clean.text.as_str()),
        (ToastKind::Success, "drift check: nothing drifted")
    );
    // An unmounted root: nothing marked, everything over it unchecked.
    let unmounted = drift_toast(drift_report(
        json!({"unreadable_roots": ["/srv/pool/a"], "unchecked": [hash(9), hash(10)]}),
    ));
    assert_eq!(unmounted.kind, ToastKind::Info);
    assert_eq!(
        unmounted.text,
        "drift check: 1 roots could not be read — 2 torrents unchecked"
    );
    let unstatable = drift_toast(drift_report(
        json!({"files_unreadable": 1, "unchecked": [hash(9)]}),
    ));
    assert_eq!(unstatable.kind, ToastKind::Info);
    assert_eq!(
        unstatable.text,
        "drift check: nothing drifted, 1 torrents unchecked"
    );
    // Drift with every root read and every torrent checked asks for a
    // rescan and claims nothing went unseen.
    let drifted = drift_toast(drift_report(
        json!({"drifted": [hash(11)], "files_changed": 1}),
    ));
    assert_eq!(drifted.kind, ToastKind::Info);
    assert_eq!(
        drifted.text,
        "drift check: 1 torrents drifted — rescan and verify them"
    );
    // Drift under a readable root still asks for a rescan when another
    // root could not be read.
    let both = drift_toast(drift_report(json!({
        "drifted": [hash(11)],
        "files_changed": 1,
        "unreadable_roots": ["/srv/pool/a"],
        "unchecked": [hash(9), hash(10)]
    })));
    assert_eq!(both.kind, ToastKind::Info);
    assert_eq!(
        both.text,
        "drift check: 1 torrents drifted — rescan and verify them; \
         1 roots could not be read — 2 torrents unchecked"
    );
    // Drift alongside unstatable files keeps the unchecked count too.
    let drifted_unstatable = drift_toast(drift_report(json!({
        "drifted": [hash(11)],
        "files_unreadable": 1,
        "unchecked": [hash(9)]
    })));
    assert_eq!(
        drifted_unstatable.text,
        "drift check: 1 torrents drifted — rescan and verify them; 1 torrents unchecked"
    );
}
