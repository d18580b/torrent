//! The library: marks, filters, paging, refreshes, and verifying.

use super::*;

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
