//! The tree: walking directories, paging, orphans, and refreshes.

use super::*;

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

#[test]
fn a_move_during_a_tree_refresh_is_the_entry_kept() {
    let mut state = with_tree();
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    assert!(state.tree.entries.loading);
    assert_eq!(state.tree.reselect.as_deref(), Some("movies"));

    assert_eq!(press(&mut state, KeyCode::Char('j'), true), 0);
    assert_eq!(state.tree.selected, 1, "a key moves while the reload runs");
    assert_eq!(
        state.tree.reselect.as_deref(),
        Some("series"),
        "the reload now restores the entry the operator moved to"
    );

    // An entry appeared ahead of it: its row moved, and the selection must
    // follow the name rather than stay on row 1.
    let mut page = tree_page(None);
    page.items.insert(
        0,
        testing::from_json(entry("anime", "anime", true, &["adopted"])),
    );
    let generation = state.tree.entries.generation;
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: true,
            result: Ok(page),
        }),
        true,
    );
    assert!(!state.tree.entries.loading);
    assert_eq!(
        state.tree.entries.items[state.tree.selected].name, "series",
        "the selection follows the entry the operator moved to during the reload"
    );
    assert!(
        state.tree.reselect.is_none(),
        "spent once the reload settles"
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
fn a_failed_tree_refresh_does_not_snap_a_later_page_back() {
    let mut state = with_overview();
    send(&mut state, Msg::OpenRoot, true);
    let tree_page = |state: &State, first: bool, page: types::TreePage| {
        Msg::Tree(tree::Msg::Page {
            generation: state.tree.entries.generation,
            first,
            result: Ok(page),
        })
    };
    let msg = tree_page(&state, true, wide_tree(0, 100, Some("k100")));
    send(&mut state, msg, true);
    state.tree.selected = 10;

    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    assert_eq!(state.tree.reselect.as_deref(), Some("d00010"));
    let generation = state.tree.entries.generation;
    send(
        &mut state,
        Msg::Tree(tree::Msg::Page {
            generation,
            first: true,
            result: Err(problem(500, "internal", None)),
        }),
        true,
    );
    assert!(!state.tree.entries.loading);
    assert!(
        state.tree.reselect.is_none(),
        "the failed refresh will not settle"
    );

    // The operator scrolls on, to the end: the next page is fetched.
    state.tree.selected = 98;
    assert_eq!(press(&mut state, KeyCode::Char('j'), true), 1);
    let msg = tree_page(&state, false, wide_tree(100, 50, None));
    send(&mut state, msg, true);
    assert_eq!(state.tree.entries.items.len(), 150);
    assert_eq!(
        state.tree.selected, 99,
        "not snapped back to the entry selected when the failed refresh began"
    );
}
