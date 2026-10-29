//! What each view draws, as snapshots.

use super::*;

#[test]
fn the_overview_renders() {
    let mut state = with_overview();
    state.overview.scan = Some(testing::from_json(
        json!({"files": 57000, "bytes": 7_500_000_000_000_i64,
        "torrents": 1234, "matched": 300, "partial": 50, "missing": 40, "overlap": 11, "shared": 6,
        "drifted": 3, "errors": 2}),
    ));
    state.overview.drift = Some(drift_report(
        json!({"drifted": [hash(9), hash(10), hash(11)],
        "files_changed": 4, "files_vanished": 1, "files_unreadable": 2,
        "unreadable_roots": ["/srv/pool/b", "/srv/pool/c", "/srv/pool/d"],
        "unmounted_dirs": ["/srv/pool/a/disk"], "unchecked": [hash(12)]}),
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
