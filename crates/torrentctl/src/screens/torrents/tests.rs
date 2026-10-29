//! The torrents screen's reducer, keys, add dialog and views.

use serde_json::json;

use super::*;
use crate::api::Api;
use crate::screens::contract::ToastKind;
use crate::testing;
use crate::ui::widgets::caps;

const NOW: i64 = 1_790_000_000;

/// What reloading the unfiltered list sends: the profiles, then the
/// first page.
const RELOAD: [&str; 2] = ["GET /v1/profiles", "GET /v1/torrents?limit=100"];

fn hash(n: u8) -> String {
    format!("{n:02x}{}", "a1b2c3d4e5".repeat(4))[..40].to_owned()
}

fn summary(n: u8, profile: &str, phase: &str) -> serde_json::Value {
    json!({
        "infohash": hash(n), "profile_id": profile, "phase": phase,
        "progress": if phase == "checking" { 0.42 } else { 1.0 },
        "upload_rate": if phase == "seeding" { 1_572_864 * i64::from(n) } else { 0 },
        "download_rate": 0,
        "total_uploaded": 5_368_709_120_i64 * i64::from(n),
        "total_payload_uploaded": 5_000_000_000_i64 * i64::from(n),
        "num_peers": i64::from(n) * 3,
        "is_finished": phase != "checking", "is_seeding": phase == "seeding",
    })
}

fn page(range: std::ops::Range<u8>, next: Option<&str>) -> types::TorrentPage {
    let phases = [
        "seeding",
        "seeding",
        "paused",
        "checking",
        "errored",
        "disk_error",
        "idle",
    ];
    let items: Vec<_> = range
        .map(|n| {
            let profile = if n % 3 == 0 { "acct_b" } else { "acct_a" };
            summary(n, profile, phases[n as usize % phases.len()])
        })
        .collect();
    testing::from_json(json!({"items": items, "next_cursor": next}))
}

fn profiles() -> Vec<types::Profile> {
    testing::from_json(json!([
        {"profile_id": "acct_a", "status": "active", "tunnel_ip": "10.2.0.2",
         "desired_state": "online", "effective_state": "online",
         "torrent_count": 900, "listen_port": 51413, "port_forward": "natpmp",
         "forwarded_port": 51413, "user_agent": null, "failure_reason": null},
        {"profile_id": "acct_b", "status": "vpn_down", "tunnel_ip": "10.3.0.2",
         "desired_state": "online", "effective_state": "offline",
         "torrent_count": 334, "listen_port": 51414, "port_forward": "static",
         "forwarded_port": null, "user_agent": null, "failure_reason": null},
        {"profile_id": "acct_c", "status": "active", "tunnel_ip": null,
         "desired_state": "online", "effective_state": "online",
         "torrent_count": 0, "listen_port": 51415, "port_forward": "static",
         "forwarded_port": null, "user_agent": null, "failure_reason": null},
    ]))
}

fn failure(status: u16, slug: &str, detail: &str) -> Failure {
    Failure {
        status: Some(status),
        slug: Some(slug.to_owned()),
        title: "Refused".to_owned(),
        detail: Some(detail.to_owned()),
        request_id: None,
        ..Default::default()
    }
}

/// A list with `range` loaded as its first page.
fn loaded(range: std::ops::Range<u8>, next: Option<&str>) -> State {
    let mut state = State {
        now: Some(time::OffsetDateTime::from_unix_timestamp(NOW).unwrap()),
        ..State::default()
    };
    testing::with_ctx(None, |ctx| {
        refresh(&mut state, ctx);
        update(&mut state, Msg::Profiles(Ok(profiles())), ctx);
        let generation = state.list.generation;
        update(
            &mut state,
            Msg::Page {
                generation,
                first: true,
                result: Ok(page(range, next)),
            },
            ctx,
        );
    });
    state
}

fn torrent(n: u8, session: bool) -> types::Torrent {
    let mut value = summary(n, "acct_a", "seeding");
    value["session"] = if session {
        json!({
            "name": "debian-13.1.0-amd64-netinst.iso", "total_size": 792_723_456,
            "save_path": "/srv/seed/acct_a", "upload_limit_bytes_per_sec": 2_097_152,
            "added_at": "2026-09-01T08:30:00Z",
        })
    } else {
        serde_json::Value::Null
    };
    testing::from_json(value)
}

fn opened(session: bool) -> State {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Open, ctx);
        let hash = state.detail.as_ref().unwrap().hash.clone();
        update(
            &mut state,
            Msg::Torrent {
                hash,
                result: Ok(torrent(1, session)),
            },
            ctx,
        );
    });
    state
}

fn with_files(state: &mut State) {
    let files: types::TorrentFilePage = testing::from_json(json!({"items": [
            {"index": 0, "path": "debian/debian-13.1.0-amd64-netinst.iso", "size": 792_723_456,
             "downloaded": 792_723_456, "priority": 4},
            {"index": 1, "path": "debian/SHA256SUMS", "size": 1_024, "downloaded": 512, "priority": 7},
            {"index": 2, "path": "debian/README.txt", "size": 0, "downloaded": 0, "priority": 0},
        ], "next_cursor": null}));
    testing::with_ctx(None, |ctx| {
        update(state, Msg::Tab(true), ctx);
        let detail = state.detail.as_ref().unwrap();
        let (hash, generation) = (detail.hash.clone(), detail.files.generation);
        update(
            state,
            Msg::FilesPage {
                hash,
                generation,
                first: true,
                result: Ok(files),
            },
            ctx,
        );
    });
}

fn with_trackers(state: &mut State) {
    let trackers: types::TrackerList = testing::from_json(json!({"items": [
        {"tier": 0, "host": "tracker.example.org:443", "url": "https://tracker.example.org/announce",
         "status": "working", "message": null, "next_announce_at": "2026-09-21T14:40:00Z",
         "seeds": 1240, "peers": 18},
        {"tier": 1, "host": "backup.example.net", "url": "https://backup.example.net/[redacted:9f2c]",
         "status": "error", "message": "unregistered torrent",
         "next_announce_at": "2026-09-21T14:30:00Z", "seeds": null, "peers": null},
        {"tier": 2, "host": "udp.example.com:6969", "url": "udp://udp.example.com:6969/announce",
         "status": "not_contacted", "message": null, "next_announce_at": null,
         "seeds": null, "peers": null},
    ]}));
    testing::with_ctx(None, |ctx| {
        state.detail.as_mut().unwrap().tab = detail::Tab::Files;
        assert_eq!(
            update(state, Msg::Tab(true), ctx).len(),
            1,
            "the trackers load"
        );
        let hash = state.detail.as_ref().unwrap().hash.clone();
        update(
            state,
            Msg::Trackers {
                hash,
                result: Ok(trackers),
            },
            ctx,
        );
    });
}

fn keys(state: &mut State, ctx: &Ctx<'_>, text: &str) {
    for c in text.chars() {
        let msg = on_key(state, testing::key(KeyCode::Char(c))).unwrap();
        update(state, msg, ctx);
    }
}

fn page_msg(state: &State, first: bool, result: Result<types::TorrentPage, Failure>) -> Msg {
    Msg::Page {
        generation: state.list.generation,
        first,
        result,
    }
}

// Paging.

#[test]
fn the_first_page_is_shown_and_the_next_is_fetched_near_the_end() {
    let mut state = State::default();
    testing::with_ctx(None, |ctx| {
        let effects = refresh(&mut state, ctx);
        assert_eq!(effects.len(), 2, "profiles and the first page");
        assert!(state.list.loading);
        let msg = page_msg(&state, true, Ok(page(1..11, Some("c1"))));
        let effects = update(&mut state, msg, ctx);
        assert_eq!(state.list.items.len(), 10);
        assert_eq!(
            effects.len(),
            1,
            "ten rows is near the end: the next page is asked for"
        );
        assert!(state.list.loading);
        let msg = page_msg(&state, false, Ok(page(11..21, None)));
        let effects = update(&mut state, msg, ctx);
        assert!(effects.is_empty(), "no more pages");
        assert_eq!(state.list.items.len(), 20);
        assert!(state.list.complete && !state.list.loading);
    });
}

/// `n` torrents from the `from`th, in infohash order, continuing at
/// `next`: lists longer than `page`'s `u8` range reaches.
fn wide_page(from: usize, n: usize, next: Option<&str>) -> types::TorrentPage {
    let items: Vec<_> = (from..from + n)
        .map(|i| {
            let mut row = summary(1, "acct_a", "seeding");
            row["infohash"] = json!(format!("{i:040x}"));
            row
        })
        .collect();
    testing::from_json(json!({"items": items, "next_cursor": next}))
}

#[test]
fn a_refresh_past_1000_rows_keeps_them_and_the_selection_while_it_re_pages() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut state = State::default();
    testing::with_api(&daemon.api(), None, |ctx| {
        state.profiles_loading = true;
        let _ = refresh(&mut state, ctx);
        let msg = page_msg(&state, true, Ok(wide_page(0, 1000, Some("k1000"))));
        update(&mut state, msg, ctx);
        let msg = page_msg(&state, false, Ok(wide_page(1000, 500, Some("k1500"))));
        update(&mut state, msg, ctx);
        assert_eq!(state.list.items.len(), 1500);
        update(&mut state, Msg::Move(Motion::Top), ctx);
        for _ in 0..140 {
            update(&mut state, Msg::Move(Motion::PageDown), ctx);
        }
        assert_eq!(state.selected, 1400);
        let chosen = format!("{:040x}", 1400);

        let effects = refresh(&mut state, ctx);
        testing::run(effects);
        assert_eq!(
            daemon.lines(),
            ["GET /v1/torrents?limit=1000"],
            "one request's reach"
        );
        let msg = page_msg(&state, true, Ok(wide_page(0, 1000, Some("k1000"))));
        let effects = update(&mut state, msg, ctx);
        assert_eq!(state.list.items.len(), 1500, "not cut to the first page");
        assert_eq!(state.selected, 1400, "nor the selection to row 999");
        testing::run(effects);
        assert_eq!(
            daemon.lines()[1],
            "GET /v1/torrents?cursor=k1000&limit=500",
            "pages on towards the 1500 loaded"
        );

        // A key while it re-pages moves among the rows still shown.
        update(&mut state, Msg::Move(Motion::Down), ctx);
        assert_eq!(state.selected, 1401);
        let chosen_now = format!("{:040x}", 1401);
        assert_ne!(chosen, chosen_now);

        let msg = page_msg(&state, false, Ok(wide_page(1000, 500, Some("k1500"))));
        update(&mut state, msg, ctx);
        assert!(!state.list.loading);
        assert_eq!(state.list.items.len(), 1500);
        assert_eq!(
            selected_summary(&state).unwrap().infohash,
            chosen_now,
            "the torrent the operator moved to, after the reload"
        );
    });
}

#[test]
fn a_page_answering_an_older_reload_is_dropped() {
    let mut state = loaded(1..4, None);
    testing::with_ctx(None, |ctx| {
        let old = state.list.generation;
        refresh(&mut state, ctx);
        let effects = update(
            &mut state,
            Msg::Page {
                generation: old,
                first: true,
                result: Ok(page(50..52, None)),
            },
            ctx,
        );
        assert!(effects.is_empty());
        assert_eq!(state.list.items.len(), 3, "the old data is still shown");
        assert!(state.list.loading, "still waiting for the current reload");
        let stale_error = Msg::Page {
            generation: old,
            first: true,
            result: Err(failure(500, "internal", "boom")),
        };
        update(&mut state, stale_error, ctx);
        assert!(state.list.error.is_none());
    });
}

#[test]
fn a_failed_load_keeps_the_last_good_rows() {
    let mut state = loaded(1..4, None);
    testing::with_ctx(None, |ctx| {
        refresh(&mut state, ctx);
        let msg = page_msg(&state, true, Err(failure(500, "internal", "engine gone")));
        assert!(
            update(&mut state, msg, ctx).is_empty(),
            "shown in the panel, not a toast"
        );
        assert_eq!(state.list.items.len(), 3);
        assert_eq!(state.list.error.as_deref(), Some("Refused: engine gone"));
        let msg = page_msg(&state, true, Err(failure(401, "about:blank", "")));
        state.list.loading = true;
        assert_eq!(update(&mut state, msg, ctx).len(), 1, "a 401 signs out");
    });
}

#[test]
fn a_failed_refresh_does_not_snap_a_later_load_back() {
    let mut state = loaded(1..31, Some("c31"));
    testing::with_ctx(None, |ctx| {
        state.profiles_loading = true;
        state.selected = 2;
        refresh(&mut state, ctx);
        assert_eq!(state.restore.as_deref(), Some(hash(3).as_str()));
        let msg = page_msg(&state, true, Err(failure(500, "internal", "engine gone")));
        update(&mut state, msg, ctx);
        assert!(!state.list.loading);
        assert!(
            state.restore.is_none(),
            "the failed refresh will not settle"
        );

        // The operator scrolls on, to the end: the next page is fetched
        // and settles without jumping back.
        update(&mut state, Msg::Move(Motion::Bottom), ctx);
        assert!(state.list.loading, "near the end: the next page");
        let msg = page_msg(&state, false, Ok(page(31..41, None)));
        update(&mut state, msg, ctx);
        assert_eq!(state.list.items.len(), 40);
        assert_eq!(
            selected_summary(&state).unwrap().infohash,
            hash(30),
            "not snapped back to the torrent selected when the refresh failed"
        );
    });
}

#[test]
fn a_refresh_after_a_failed_one_keeps_the_torrent_selected_now() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        state.profiles_loading = true;
        update(&mut state, Msg::Move(Motion::Down), ctx);
        refresh(&mut state, ctx);
        assert_eq!(state.restore.as_deref(), Some(hash(2).as_str()));
        let msg = page_msg(&state, true, Err(failure(500, "internal", "engine gone")));
        update(&mut state, msg, ctx);
        assert!(
            state.restore.is_none(),
            "the failed refresh will not settle"
        );

        update(&mut state, Msg::Move(Motion::Bottom), ctx);
        refresh(&mut state, ctx);
        assert_eq!(state.restore.as_deref(), Some(hash(7).as_str()));
        let msg = page_msg(&state, true, Ok(page(1..8, None)));
        update(&mut state, msg, ctx);
        assert_eq!(
            selected_summary(&state).unwrap().infohash,
            hash(7),
            "the torrent selected when this refresh began, not the failed one's"
        );
    });
}

#[test]
fn one_reload_at_a_time() {
    let mut state = loaded(1..4, None);
    testing::with_ctx(None, |ctx| {
        state.profiles_loading = true;
        assert_eq!(refresh(&mut state, ctx).len(), 1);
        assert!(refresh(&mut state, ctx).is_empty());
    });
}

// Selection.

#[test]
fn the_selection_follows_its_torrent_across_a_refresh() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Move(Motion::Down), ctx);
        update(&mut state, Msg::Move(Motion::Down), ctx);
        assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));
        refresh(&mut state, ctx);
        // Two torrents ahead of it went away and one arrived.
        let mut fresh = page(3..8, None);
        fresh.items.insert(0, page(0..1, None).items.remove(0));
        let msg = page_msg(&state, true, Ok(fresh));
        update(&mut state, msg, ctx);
        assert_eq!(state.selected, 1);
        assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));
        assert!(state.restore.is_none());
    });
}

#[test]
fn a_torrent_being_selected_is_paged_towards() {
    let mut state = loaded(1..4, Some("c1"));
    testing::with_ctx(None, |ctx| {
        state.list.loading = false;
        state.restore = Some(hash(9));
        assert_eq!(
            settle(&mut state, ctx).len(),
            1,
            "it sorts after what is loaded"
        );
        let msg = page_msg(&state, false, Ok(page(8..11, None)));
        update(&mut state, msg, ctx);
        assert_eq!(selected_summary(&state).unwrap().infohash, hash(9));
    });
}

#[test]
fn a_vanished_torrent_leaves_the_selection_in_range() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Move(Motion::Bottom), ctx);
        assert_eq!(state.selected, 6);
        refresh(&mut state, ctx);
        let msg = page_msg(&state, true, Ok(page(1..4, None)));
        update(&mut state, msg, ctx);
        assert_eq!(state.selected, 2);
        assert!(state.restore.is_none());
    });
}

/// The `/` filter shows 11 of rows 3..34; `G` selects the last, row 33.
/// A refresh then remembers it, and its first page, rows 1..32, shows
/// only 10 under the filter while it pages on towards row 33.
fn chasing_past_the_filtered_rows(state: &mut State, ctx: &Ctx<'_>) {
    update(state, Msg::StartFilter, ctx);
    keys(state, ctx, "acct_b");
    update(state, Msg::FilterKey(testing::key(KeyCode::Enter)), ctx);
    assert_eq!(visible(state).len(), 11);
    update(state, Msg::Move(Motion::Bottom), ctx);
    assert_eq!(selected_summary(state).unwrap().infohash, hash(33));
    assert!(state.list.loading, "near the end: the next page");
    let msg = page_msg(state, false, Ok(page(34..34, None)));
    update(state, msg, ctx);

    refresh(state, ctx);
    assert_eq!(state.restore.as_deref(), Some(hash(33).as_str()));
    let msg = page_msg(state, true, Ok(page(1..32, Some("c32"))));
    assert_eq!(update(state, msg, ctx).len(), 1, "it pages on towards 33");
    assert_eq!(visible(state).len(), 10);
    assert!(
        selected_summary(state).is_some(),
        "selected {} of {} rows while paging on",
        state.selected,
        visible(state).len()
    );
}

#[test]
fn a_reload_paging_towards_its_torrent_keeps_the_selection_in_range() {
    let mut state = loaded(3..34, Some("c34"));
    testing::with_ctx(None, |ctx| {
        state.profiles_loading = true;
        chasing_past_the_filtered_rows(&mut state, ctx);
        let msg = page_msg(&state, false, Err(failure(500, "internal", "engine gone")));
        update(&mut state, msg, ctx);
        assert!(state.restore.is_none(), "the failed reload will not settle");
        assert_eq!(state.selected, 9, "the last row shown, not past it");
        assert_eq!(selected_summary(&state).unwrap().infohash, hash(30));
    });

    let mut state = loaded(3..34, Some("c34"));
    testing::with_ctx(None, |ctx| {
        state.profiles_loading = true;
        chasing_past_the_filtered_rows(&mut state, ctx);
        let msg = page_msg(&state, false, Ok(page(32..35, None)));
        update(&mut state, msg, ctx);
        assert_eq!(
            selected_summary(&state).unwrap().infohash,
            hash(33),
            "the torrent paged towards is selected once it arrives"
        );
        assert!(state.restore.is_none());
    });
}

#[test]
fn moving_is_bounded() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Move(Motion::Up), ctx);
        assert_eq!(state.selected, 0);
        update(&mut state, Msg::Move(Motion::PageDown), ctx);
        assert_eq!(state.selected, 6);
        update(&mut state, Msg::Move(Motion::Top), ctx);
        assert_eq!(state.selected, 0);
    });
}

// Filters.

#[test]
fn f_cycles_profiles_and_back_to_all() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        let effects = update(&mut state, Msg::CycleProfile, ctx);
        assert_eq!(state.profile.as_deref(), Some("acct_a"));
        assert!(
            state.list.items.is_empty(),
            "another filter's rows are not shown under this one"
        );
        assert!(!effects.is_empty() && state.list.loading);
        update(&mut state, Msg::CycleProfile, ctx);
        update(&mut state, Msg::CycleProfile, ctx);
        assert_eq!(state.profile.as_deref(), Some("acct_c"));
        update(&mut state, Msg::CycleProfile, ctx);
        assert_eq!(state.profile, None);
    });
}

#[test]
fn capital_f_cycles_every_phase_then_all() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::CyclePhase, ctx);
        assert_eq!(state.phase, Some(types::Phase::Checking));
        for _ in 1..PHASES.len() {
            update(&mut state, Msg::CyclePhase, ctx);
        }
        assert_eq!(state.phase, Some(types::Phase::Unknown));
        update(&mut state, Msg::CyclePhase, ctx);
        assert_eq!(state.phase, None);
    });
}

#[test]
fn filter_profile_from_elsewhere_leaves_the_detail_view() {
    let mut state = opened(true);
    testing::with_ctx(None, |ctx| {
        let effects = update(&mut state, Msg::FilterProfile(Some("acct_b".into())), ctx);
        assert!(!effects.is_empty());
        assert!(state.detail.is_none());
        assert_eq!(state.profile.as_deref(), Some("acct_b"));
    });
}

#[test]
fn the_slash_filter_narrows_what_is_loaded_and_keeps_the_selection() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Move(Motion::Down), ctx);
        update(&mut state, Msg::Move(Motion::Down), ctx);
        let msg = on_key(&state, testing::key(KeyCode::Char('/'))).unwrap();
        update(&mut state, msg, ctx);
        assert!(capturing(&state), "q and digits are typed into the field");
        keys(&mut state, ctx, "ACCT_B");
        assert_eq!(state.filter, "ACCT_B", "as typed");
        assert_eq!(visible(&state).len(), 2, "3 and 6, matched in any case");
        assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));
        let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
        update(&mut state, msg, ctx);
        assert!(!capturing(&state));
        assert_eq!(state.filter, "ACCT_B", "Enter keeps the filter");
        update(&mut state, Msg::StartFilter, ctx);
        assert_eq!(
            state.filter_input.as_ref().unwrap().value(),
            "ACCT_B",
            "reopening the field shows what was typed, not a lowercased copy"
        );
        update(
            &mut state,
            Msg::FilterKey(testing::key(KeyCode::Enter)),
            ctx,
        );

        update(&mut state, Msg::StartFilter, ctx);
        update(&mut state, Msg::FilterKey(testing::key(KeyCode::Esc)), ctx);
        assert_eq!(visible(&state).len(), 7, "Esc in the field clears it");
        assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));

        update(&mut state, Msg::StartFilter, ctx);
        keys(&mut state, ctx, "05");
        assert_eq!(visible(&state).len(), 1, "an infohash prefix");
        update(
            &mut state,
            Msg::FilterKey(testing::key(KeyCode::Enter)),
            ctx,
        );
        let msg = on_key(&state, testing::key(KeyCode::Esc)).unwrap();
        update(&mut state, msg, ctx);
        assert!(state.filter.is_empty(), "Esc on the list clears it too");
    });
}

// Actions and confirmations.

#[test]
fn single_torrent_actions_go_at_once() {
    let daemon = testing::Recorder::start("204 No Content", "");
    let mut state = loaded(1..8, None);
    let h = selected_summary(&state).unwrap().infohash.clone();
    let effects = testing::with_api(&daemon.api(), None, |ctx| {
        let mut effects = Vec::new();
        for c in ['p', 'r', 'c', 'a'] {
            let msg = on_key(&state, testing::key(KeyCode::Char(c))).unwrap();
            effects.extend(update(&mut state, msg, ctx));
            assert!(state.confirm.is_none(), "{c}");
        }
        effects
    });
    testing::run(effects);
    assert_eq!(
        daemon.lines(),
        ["pause", "resume", "recheck", "reannounce"].map(|a| format!("POST /v1/torrents/{h}/{a}"))
    );
}

#[test]
fn remove_asks_yes_or_no() {
    let daemon = testing::Recorder::start("204 No Content", "");
    let mut state = loaded(1..8, None);
    let h = selected_summary(&state).unwrap().infohash.clone();
    let effects = testing::with_api(&daemon.api(), None, |ctx| {
        let msg = on_key(&state, testing::key(KeyCode::Char('d'))).unwrap();
        assert!(update(&mut state, msg, ctx).is_empty());
        assert!(matches!(
            state.confirm,
            Some((_, Pending::Act(Action::Remove, _)))
        ));
        assert!(capturing(&state));
        let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
        let effects = update(&mut state, msg, ctx);
        assert!(state.confirm.is_none());
        effects
    });
    testing::run(effects);
    assert_eq!(
        daemon.lines(),
        [format!("DELETE /v1/torrents/{h}")],
        "one DELETE, keeping the files"
    );
}

#[test]
fn deleting_files_is_refused_locally_without_pool_mutations() {
    let mut state = loaded(1..8, None);
    let server = testing::server(true, false);
    testing::with_ctx(Some(&server), |ctx| {
        let msg = on_key(&state, testing::key(KeyCode::Char('D'))).unwrap();
        assert_eq!(update(&mut state, msg, ctx).len(), 1, "a toast saying why");
        assert!(state.confirm.is_none());
    });
}

#[test]
fn deleting_files_needs_the_word_typed() {
    let mut state = loaded(1..8, None);
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| {
        let msg = on_key(&state, testing::key(KeyCode::Char('D'))).unwrap();
        update(&mut state, msg, ctx);
        let Some((confirm, Pending::Act(Action::RemoveFiles, target))) = &state.confirm else {
            panic!("a typed confirmation");
        };
        assert_eq!(confirm.typed.as_deref(), Some("delete"));
        assert_eq!(*target, hash(1));
        keys(&mut state, ctx, "y");
        assert!(state.confirm.is_some(), "y is typed, not a yes");
        let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
        assert!(update(&mut state, msg, ctx).is_empty(), "the word is wrong");
        update(
            &mut state,
            Msg::ConfirmKey(testing::key(KeyCode::Backspace)),
            ctx,
        );
        keys(&mut state, ctx, "delete");
        let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
        assert_eq!(
            update(&mut state, msg, ctx).len(),
            1,
            "one DELETE ?delete_files=true"
        );
        assert!(state.confirm.is_none());
    });
}

#[tokio::test]
async fn deleting_files_sends_the_infohash_as_confirm() {
    let (url, server) = crate::testing::serve_once("204 No Content", String::new()).await;
    let api = Api::new(&url, Some("tdp_wire")).unwrap();
    let msg = perform(&api, Action::RemoveFiles, hash(1)).0.await;
    assert!(
        matches!(
            msg,
            crate::app::Msg::Torrents(Msg::Acted {
                action: Action::RemoveFiles,
                result: Ok(()),
                ..
            })
        ),
        "{msg:?}"
    );
    let request = server.await.unwrap();
    let line = request.lines().next().unwrap();
    assert_eq!(
        line,
        format!(
            "DELETE /v1/torrents/{h}?delete_files=true&confirm={h} HTTP/1.1",
            h = hash(1)
        )
    );
}

#[test]
fn pause_all_and_resume_all_ask_first() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut state = loaded(1..8, None);
    let effects = testing::with_api(&daemon.api(), None, |ctx| {
        let mut effects = Vec::new();
        for c in ['P', 'U'] {
            let msg = on_key(&state, testing::key(KeyCode::Char(c))).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty());
            let msg = on_key(&state, testing::key(KeyCode::Esc)).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty(), "cancelled");
            assert!(state.confirm.is_none());
            let msg = on_key(&state, testing::key(KeyCode::Char(c))).unwrap();
            update(&mut state, msg, ctx);
            let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
            effects.extend(update(&mut state, msg, ctx));
        }
        effects
    });
    testing::run(effects);
    assert_eq!(
        daemon.lines(),
        [
            "POST /v1/torrents/pause-all",
            "POST /v1/torrents/resume-all"
        ]
    );
}

#[test]
fn a_bulk_outcome_says_what_was_not_reached() {
    let outcome: types::BulkOutcome = testing::from_json(json!({
        "torrent_count": 1200, "failed_count": 0, "failed_infohashes": [],
        "skipped_profiles": [{"profile_id": "acct_b", "reason": "vpn_down",
                              "detail": "profile vpn_down; restart daemon to resume"}],
    }));
    let toast = bulk_toast(false, &outcome);
    assert_eq!(toast.kind, ToastKind::Info);
    assert_eq!(
            toast.text,
            "resumed 1,200 torrents; skipped acct_b (vpn_down: profile vpn_down; restart daemon to resume)"
        );
    let outcome: types::BulkOutcome = testing::from_json(json!({
        "torrent_count": 10, "failed_count": 2,
        "failed_infohashes": ["0101010101010101010101010101010101010101",
                              "0202020202020202020202020202020202020202"],
        "skipped_profiles": [],
    }));
    let toast = bulk_toast(true, &outcome);
    assert_eq!(toast.kind, ToastKind::Error);
    assert_eq!(
        toast.text,
        "paused 10 torrents; 2 failed and are still running"
    );
}

#[test]
fn an_action_result_is_a_toast_and_a_reload() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut state = opened(true);
    let (removed, refused) = testing::with_api(&daemon.api(), None, |ctx| {
        let removed = update(
            &mut state,
            Msg::Acted {
                action: Action::Remove,
                hash: hash(1),
                result: Ok(()),
            },
            ctx,
        );
        assert!(state.detail.is_none(), "a removed torrent's view closes");
        let refused = update(
            &mut state,
            Msg::Acted {
                action: Action::Resume,
                hash: hash(1),
                result: Err(failure(409, "profile-unavailable", "vpn_down")),
            },
            ctx,
        );
        (removed, refused)
    });

    let msgs = testing::run(removed);
    assert!(
        matches!(&msgs[0], crate::app::Msg::Toast(t) if t.kind == ToastKind::Success),
        "a toast: {msgs:?}"
    );
    assert_eq!(daemon.lines(), RELOAD, "and the reload");

    let msgs = testing::run(refused);
    assert!(
        matches!(&msgs[..], [crate::app::Msg::Toast(t)] if t.kind == ToastKind::Error),
        "a failure toast: {msgs:?}"
    );
    assert_eq!(daemon.lines(), RELOAD, "and nothing sent");
}

// The detail view.

#[test]
fn opening_loads_the_record_and_tabs_load_their_own_data() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        let effects = update(&mut state, Msg::Open, ctx);
        assert_eq!(effects.len(), 1, "the record");
        assert_eq!(state.detail.as_ref().unwrap().hash, hash(1));
        assert_eq!(update(&mut state, Msg::Tab(true), ctx).len(), 1, "files");
        assert_eq!(update(&mut state, Msg::Tab(true), ctx).len(), 1, "trackers");
        assert!(
            update(&mut state, Msg::Tab(true), ctx).is_empty(),
            "actions"
        );
        assert!(
            update(&mut state, Msg::Tab(true), ctx).is_empty(),
            "overview"
        );
        let effects = update(&mut state, Msg::Back, ctx);
        assert!(state.detail.is_none());
        assert_eq!(effects.len(), 1, "the list reloads");
    });
}

#[test]
fn an_answer_for_another_torrent_is_dropped() {
    let mut state = opened(false);
    testing::with_ctx(None, |ctx| {
        update(
            &mut state,
            Msg::Torrent {
                hash: hash(5),
                result: Ok(torrent(5, true)),
            },
            ctx,
        );
        assert!(state
            .detail
            .as_ref()
            .unwrap()
            .torrent
            .as_ref()
            .unwrap()
            .session
            .is_none());
    });
}

#[test]
fn a_magnet_without_metadata_says_so() {
    let mut state = opened(false);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Tab(true), ctx);
        let detail = state.detail.as_ref().unwrap();
        let (hash, generation) = (detail.hash.clone(), detail.files.generation);
        update(
            &mut state,
            Msg::FilesPage {
                hash,
                generation,
                first: true,
                result: Err(failure(409, "metadata-pending", "no metadata yet")),
            },
            ctx,
        );
    });
    assert!(state.detail.as_ref().unwrap().metadata_pending);
    let screen = testing::render(80, 24, None, |ctx, frame, area| {
        view(&state, ctx, frame, area)
    });
    assert!(screen.contains("metadata not yet received"), "{screen}");
}

#[test]
fn the_trackers_tab_polls_its_trackers_on_its_own_timer() {
    let mut state = opened(true);
    with_trackers(&mut state);
    let asked = state.detail.as_ref().unwrap().trackers_asked.unwrap();
    let due = asked + TRACKERS_POLL_INTERVAL;
    testing::with_ctx(None, |ctx| {
        assert!(
            poll(&mut state, due - Duration::from_millis(1), ctx).is_empty(),
            "not before the interval"
        );
        state.detail.as_mut().unwrap().trackers_selected = 1;
        assert_eq!(poll(&mut state, due, ctx).len(), 1, "due: re-read");
        assert!(state.detail.as_ref().unwrap().trackers_loading);
        assert!(
            poll(&mut state, due + TRACKERS_POLL_INTERVAL, ctx).is_empty(),
            "not while a read is in flight"
        );

        // The tracker that worked now fails: the poll's answer shows it,
        // and the operator's place in the list holds.
        let failing: types::TrackerList = testing::from_json(json!({"items": [
            {"tier": 0, "host": "tracker.example.org:443",
             "url": "https://tracker.example.org/announce", "status": "error",
             "message": "connection refused", "next_announce_at": null,
             "seeds": null, "peers": null},
            {"tier": 1, "host": "backup.example.net",
             "url": "https://backup.example.net/[redacted:9f2c]", "status": "error",
             "message": "unregistered torrent", "next_announce_at": null,
             "seeds": null, "peers": null},
        ]}));
        update(
            &mut state,
            Msg::Trackers {
                hash: hash(1),
                result: Ok(failing),
            },
            ctx,
        );
        let detail = state.detail.as_ref().unwrap();
        let trackers = detail.trackers.as_ref().unwrap();
        assert_eq!(trackers[0].message.as_deref(), Some("connection refused"));
        assert_eq!(detail.trackers_selected, 1);

        // Only the Trackers tab polls.
        let later = Instant::now() + TRACKERS_POLL_INTERVAL;
        update(&mut state, Msg::Tab(true), ctx);
        assert!(poll(&mut state, later, ctx).is_empty(), "Actions tab");
        update(&mut state, Msg::Tab(true), ctx);
        assert!(poll(&mut state, later, ctx).is_empty(), "Overview tab");
        update(&mut state, Msg::Back, ctx);
        assert!(state.detail.is_none());
        assert!(poll(&mut state, later, ctx).is_empty(), "the list");
    });
}

#[test]
fn only_an_error_a_refresh_re_reads_counts_as_failed() {
    let mut state = opened(false);
    with_files(&mut state);
    with_trackers(&mut state);
    testing::with_ctx(None, |ctx| {
        update(
            &mut state,
            Msg::Trackers {
                hash: hash(1),
                result: Err(failure(500, "internal", "boom")),
            },
            ctx,
        );
        assert!(load_failed(&state), "trackers, on the Trackers tab");
        update(&mut state, Msg::Tab(false), ctx);
        let detail = state.detail.as_mut().unwrap();
        let generation = detail.files.generation;
        detail.files.fail(generation, "no metadata yet".to_owned());
        assert!(load_failed(&state), "files, on the Files tab");
        // A refresh re-reads neither from the Overview tab.
        update(&mut state, Msg::Tab(false), ctx);
        assert!(!load_failed(&state), "neither, on the Overview tab");
        // Nor a files list longer than one request.
        update(&mut state, Msg::Tab(true), ctx);
        let detail = state.detail.as_mut().unwrap();
        let row = detail.files.items[0].clone();
        detail.files.items.resize(caps::PAGE_MAX + 1, row);
        assert!(!load_failed(&state), "a long files list");
    });
}

#[test]
fn file_priority_is_shown_at_once_and_put_back_on_refusal() {
    let mut state = opened(true);
    with_files(&mut state);
    testing::with_ctx(None, |ctx| {
        let msg = on_key(&state, testing::key(KeyCode::Char('+'))).unwrap();
        assert_eq!(update(&mut state, msg, ctx).len(), 1);
        assert_eq!(state.detail.as_ref().unwrap().files.items[0].priority, 5);
        let effects = update(
            &mut state,
            Msg::PrioritySet {
                hash: hash(1),
                index: 0,
                previous: 4,
                priority: 5,
                result: Err(failure(422, "validation-failed", "priority")),
            },
            ctx,
        );
        assert_eq!(effects.len(), 1, "a failure toast");
        assert_eq!(
            state.detail.as_ref().unwrap().files.items[0].priority,
            4,
            "put back"
        );

        update(&mut state, Msg::Move(Motion::Down), ctx);
        assert!(
            update(&mut state, Msg::Priority(Priority::Up), ctx).is_empty(),
            "7 is the top"
        );
        let msg = on_key(&state, testing::key(KeyCode::Char('0'))).unwrap();
        assert_eq!(update(&mut state, msg, ctx).len(), 1);
        assert_eq!(state.detail.as_ref().unwrap().files.items[1].priority, 0);

        let msg = on_key(&state, testing::key(KeyCode::Char('='))).unwrap();
        update(&mut state, msg, ctx);
        assert!(capturing(&state), "a digit is a priority, not a screen");
        assert!(update(
            &mut state,
            Msg::PromptKey(testing::key(KeyCode::Char('9'))),
            ctx
        )
        .is_empty());
        let msg = on_key(&state, testing::key(KeyCode::Char('6'))).unwrap();
        assert_eq!(update(&mut state, msg, ctx).len(), 1);
        assert_eq!(state.detail.as_ref().unwrap().files.items[1].priority, 6);
        assert!(!capturing(&state));
    });
}

#[test]
fn priority_keys_do_nothing_off_the_files_tab() {
    let mut state = opened(true);
    testing::with_ctx(None, |ctx| {
        assert!(update(&mut state, Msg::Priority(Priority::Up), ctx).is_empty());
        update(&mut state, Msg::PriorityPrompt, ctx);
        assert!(!capturing(&state));
    });
}

#[test]
fn an_upload_limit_is_checked_before_it_is_sent() {
    assert_eq!(detail::parse_limit(""), Ok(None));
    assert_eq!(detail::parse_limit(" 2_097_152 "), Ok(Some(2_097_152)));
    assert_eq!(detail::parse_limit("2147483647"), Ok(Some(2_147_483_647)));
    assert!(detail::parse_limit("0").is_err());
    assert!(detail::parse_limit("2147483648").is_err());
    assert!(detail::parse_limit("-5").is_err());
    assert!(detail::parse_limit("2M")
        .unwrap_err()
        .contains("whole number"));

    let mut state = opened(true);
    testing::with_ctx(None, |ctx| {
        let msg = on_key(&state, testing::key(KeyCode::Char('l'))).unwrap();
        update(&mut state, msg, ctx);
        assert!(capturing(&state));
        let limit = &state.detail.as_ref().unwrap().limit.as_ref().unwrap().input;
        assert_eq!(limit.value(), "2097152", "prefilled with the current limit");
        state.detail.as_mut().unwrap().limit.as_mut().unwrap().input = Input::new("0".into());
        let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
        assert!(update(&mut state, msg, ctx).is_empty());
        let error = state
            .detail
            .as_ref()
            .unwrap()
            .limit
            .as_ref()
            .unwrap()
            .error
            .clone();
        assert!(error.unwrap().contains("between 1 and"));
        state.detail.as_mut().unwrap().limit.as_mut().unwrap().input = Input::default();
        let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
        assert_eq!(
            update(&mut state, msg, ctx).len(),
            1,
            "null removes the limit"
        );
        assert!(!capturing(&state));
    });
}

#[test]
fn the_actions_tab_runs_the_selected_entry() {
    let mut state = opened(true);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Tab(false), ctx);
        assert_eq!(state.detail.as_ref().unwrap().tab, detail::Tab::Actions);
        let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
        assert_eq!(update(&mut state, msg, ctx).len(), 1, "pause");
        for _ in 0..4 {
            update(&mut state, Msg::Move(Motion::Down), ctx);
        }
        update(&mut state, Msg::RunEntry, ctx);
        assert!(
            state.detail.as_ref().unwrap().limit.is_some(),
            "the limit field"
        );
    });
}

// Adding.

fn dialog(state: &mut State, ctx: &Ctx<'_>) {
    let msg = on_key(state, testing::key(KeyCode::Char('n'))).unwrap();
    update(state, msg, ctx);
    assert!(capturing(state));
}

#[test]
fn the_add_dialog_checks_its_fields() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        dialog(&mut state, ctx);
        let add = state.add.as_ref().unwrap();
        assert_eq!(add.profile, None, "no profile is chosen for the operator");
        let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
        assert!(update(&mut state, msg, ctx).is_empty(), "nothing is sent");
        let add = state.add.as_ref().unwrap();
        assert_eq!(add.errors.source.as_deref(), Some("enter a magnet URI"));
        assert_eq!(add.errors.profile.as_deref(), Some("choose a profile"));

        keys(&mut state, ctx, "http://x");
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
        assert!(state
            .add
            .as_ref()
            .unwrap()
            .errors
            .source
            .as_ref()
            .unwrap()
            .contains("magnet:?"));

        // Another kind: a path on the server, which must be absolute.
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Up)), ctx);
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
        assert_eq!(
            state.add.as_ref().unwrap().kind,
            add::SourceKind::ServerPath
        );
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
        let add = state.add.as_ref().unwrap();
        assert_eq!(
            add.focus,
            add::Field::Source,
            "focus moves to the field at fault"
        );
        assert!(add.errors.source.as_ref().unwrap().contains("absolute"));

        // Profiles cycle through the active ones only: acct_b is fenced.
        let add = state.add.as_mut().unwrap();
        add.source = Input::new("/srv/torrents/x.torrent".into());
        add.focus = add::Field::Profile;
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
        assert_eq!(
            state.add.as_ref().unwrap().profile.as_deref(),
            Some("acct_a")
        );
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
        assert_eq!(
            state.add.as_ref().unwrap().profile.as_deref(),
            Some("acct_c")
        );
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
        assert_eq!(
            state.add.as_ref().unwrap().profile.as_deref(),
            Some("acct_a")
        );

        update(&mut state, Msg::AddKey(testing::key(KeyCode::Down)), ctx);
        keys(&mut state, ctx, "relative/dir");
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
        let add = state.add.as_ref().unwrap();
        assert!(add.errors.save_path.is_some() && add.errors.source.is_none());

        state.add.as_mut().unwrap().save_path = Input::new("/srv/seed/acct_a".into());
        let effects = update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
        assert_eq!(effects.len(), 1, "one POST");
        let add = state.add.as_ref().unwrap();
        assert!(add.submitting.is_some() && add.errors.is_empty());
        assert!(
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx).is_empty(),
            "sent once"
        );
    });
}

#[test]
fn no_active_profile_is_said_in_the_dialog() {
    let mut state = State::default();
    testing::with_ctx(None, |ctx| {
        assert_eq!(
            update(&mut state, Msg::OpenAdd, ctx).len(),
            1,
            "profiles are fetched"
        );
        update(
            &mut state,
            Msg::Profiles(Ok(profiles()[1..2].to_vec())),
            ctx,
        );
        state.add.as_mut().unwrap().source = Input::new("magnet:?xt=urn:btih:abc".into());
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
        let add = state.add.as_ref().unwrap();
        assert!(add
            .errors
            .profile
            .as_ref()
            .unwrap()
            .contains("no profile is active"));
    });
}

fn refused(kind: add::SourceKind, save_path: &str, failure: add::AddFailure) -> add::FieldErrors {
    let mut state = loaded(1..2, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::OpenAdd, ctx);
        let add = state.add.as_mut().unwrap();
        add.kind = kind;
        add.save_path = Input::new(save_path.into());
        add.submitting = Some(1);
        let msg = Msg::Added {
            request: 1,
            result: Err(failure),
        };
        assert!(update(&mut state, msg, ctx).is_empty());
    });
    let add = state.add.unwrap();
    assert_eq!(add.submitting, None);
    add.errors
}

fn api(slug: &str, detail: &str) -> add::AddFailure {
    add::AddFailure::Api {
        failure: failure(422, slug, detail),
        errors: Vec::new(),
    }
}

#[test]
fn refusals_land_on_the_field_at_fault() {
    use add::SourceKind::LocalFile;
    use add::SourceKind::Magnet;
    use add::SourceKind::ServerPath;
    let e = refused(
        ServerPath,
        "",
        api("path-not-confined", "the server_path must be inside …"),
    );
    assert!(e.source.is_some() && e.save_path.is_none());
    let e = refused(
        Magnet,
        "/etc",
        api("path-not-confined", "save_path must be inside …"),
    );
    assert!(e.save_path.is_some() && e.source.is_none());
    let e = refused(
        ServerPath,
        "/etc",
        api("path-not-confined", "save_path must be inside …"),
    );
    assert!(
        e.save_path.is_some() && e.source.is_none(),
        "the detail tells them apart"
    );
    let e = refused(ServerPath, "/etc", api("path-not-confined", "outside"));
    assert!(
        e.save_path.is_some() && e.source.is_some(),
        "no hint: both are marked"
    );
    let e = refused(
        LocalFile,
        "",
        api("tracker-not-allowed", "announces to none"),
    );
    assert!(e.profile.as_ref().unwrap().contains("announces to none"));
    let e = refused(Magnet, "", api("profile-unavailable", "vpn_down"));
    assert!(e.profile.is_some());
    let e = refused(Magnet, "", api("invalid-metainfo", "not a magnet"));
    assert!(e.source.is_some());
    let e = refused(Magnet, "", api("torrent-exists", "assigned to acct_b"));
    assert_eq!(e.general.as_deref(), Some("Refused: assigned to acct_b"));
    let e = refused(
        LocalFile,
        "",
        add::AddFailure::Api {
            failure: failure(422, "validation-failed", "2 violations"),
            errors: vec![
                ("/save_path".into(), "too long".into()),
                ("/source/data".into(), "not base64".into()),
                ("/other".into(), "odd".into()),
            ],
        },
    );
    assert_eq!(e.save_path.as_deref(), Some("too long"));
    assert_eq!(e.source.as_deref(), Some("not base64"));
    assert_eq!(e.general.as_deref(), Some("/other: odd"));
    let e = refused(
        LocalFile,
        "",
        add::AddFailure::Local {
            field: add::Field::Source,
            message: "too big".into(),
        },
    );
    assert_eq!(e.source.as_deref(), Some("too big"));
}

#[test]
fn an_added_torrent_is_selected_once_loaded() {
    let mut state = loaded(1..4, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::OpenAdd, ctx);
        state.add.as_mut().unwrap().submitting = Some(1);
        let msg = Msg::Added {
            request: 1,
            result: Ok(torrent(2, true)),
        };
        let effects = update(&mut state, msg, ctx);
        assert_eq!(effects.len(), 2, "a toast and the reload");
        assert!(state.add.is_none());
        assert_eq!(state.restore.as_deref(), Some(hash(2).as_str()));
        let msg = page_msg(&state, true, Ok(page(1..4, None)));
        update(&mut state, msg, ctx);
        assert_eq!(selected_summary(&state).unwrap().infohash, hash(2));
    });
}

/// An add cancelled while in flight answers after a newer dialog has
/// opened, and sent its own: the answer leaves that dialog alone.
#[test]
fn a_stale_add_result_does_not_touch_a_newer_dialog() {
    let mut state = loaded(1..4, None);
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::OpenAdd, ctx);
        state.add.as_mut().unwrap().submitting = Some(1);
        update(&mut state, Msg::AddKey(testing::key(KeyCode::Esc)), ctx);
        assert!(state.add.is_none(), "cancelled in flight");
        update(&mut state, Msg::OpenAdd, ctx);
        let newer = state.add.as_mut().unwrap();
        newer.source = Input::new("magnet:?xt=urn:btih:abc".into());
        newer.submitting = Some(2);

        let msg = Msg::Added {
            request: 1,
            result: Ok(torrent(2, true)),
        };
        let effects = update(&mut state, msg, ctx);
        assert_eq!(effects.len(), 2, "the success still toasts and reloads");
        assert_ne!(
            state.restore.as_deref(),
            Some(hash(2).as_str()),
            "the selection is not moved to it"
        );
        let newer = state.add.as_ref().expect("the newer dialog stays open");
        assert_eq!(newer.submitting, Some(2));

        let msg = Msg::Added {
            request: 1,
            result: Err(api("torrent-exists", "assigned to acct_b")),
        };
        let effects = update(&mut state, msg, ctx);
        assert_eq!(effects.len(), 1, "the failure is toasted");
        let newer = state.add.as_ref().expect("the newer dialog stays open");
        assert_eq!(newer.submitting, Some(2), "still waiting on its own");
        assert!(newer.errors.is_empty(), "{:?}", newer.errors);
        assert_eq!(newer.source.value(), "magnet:?xt=urn:btih:abc");
    });
}

#[test]
fn a_local_torrent_over_64_mib_is_refused_before_sending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.torrent");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(caps::MAX_METAINFO + 1)
        .unwrap();
    let request = add::Request {
        profile: "acct_a".into(),
        save_path: None,
        source: add::Source::LocalFile(path),
    };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(add::submit(testing::api(), request));
    match result {
        Err(add::AddFailure::Local { field, message }) => {
            assert_eq!(field, add::Field::Source);
            assert!(message.contains("at most 64.0 MiB"), "{message}");
        }
        other => panic!("refused locally, got {other:?}"),
    }
}

/// Why a `.torrent` is sent by hand: the generated type puts its bytes on
/// the wire as an array of numbers, not base64. When this fails, spargen
/// has fixed it and `add::post_metainfo` can go.
#[test]
fn the_generated_metainfo_source_does_not_serialize_as_base64() {
    let source = types::TorrentSourceVariant2 {
        kind: types::TorrentSourceVariant2kind::Metainfo,
        data: bytes::Bytes::from_static(b"d4:infoe"),
    };
    let value = serde_json::to_value(source).unwrap();
    assert!(value["data"].is_array(), "{value}");
}

// Keys.

#[test]
fn keys_map_by_mode() {
    let k = |state: &State, code| on_key(state, testing::key(code));
    let state = loaded(1..8, None);
    assert!(matches!(
        k(&state, KeyCode::Char('j')),
        Some(Msg::Move(Motion::Down))
    ));
    assert!(matches!(
        k(&state, KeyCode::Up),
        Some(Msg::Move(Motion::Up))
    ));
    assert!(matches!(
        k(&state, KeyCode::Char('G')),
        Some(Msg::Move(Motion::Bottom))
    ));
    assert!(matches!(
        k(&state, KeyCode::PageDown),
        Some(Msg::Move(Motion::PageDown))
    ));
    assert!(matches!(k(&state, KeyCode::Enter), Some(Msg::Open)));
    assert!(matches!(
        k(&state, KeyCode::Char('f')),
        Some(Msg::CycleProfile)
    ));
    assert!(matches!(
        k(&state, KeyCode::Char('F')),
        Some(Msg::CyclePhase)
    ));
    assert!(matches!(k(&state, KeyCode::Char('n')), Some(Msg::OpenAdd)));
    assert!(matches!(
        k(&state, KeyCode::Char('P')),
        Some(Msg::Act(Action::PauseAll))
    ));
    assert!(matches!(
        k(&state, KeyCode::Char('U')),
        Some(Msg::Act(Action::ResumeAll))
    ));
    assert!(k(&state, KeyCode::Esc).is_none(), "no filter to clear");
    assert!(k(&state, KeyCode::Char('q')).is_none(), "global");
    assert!(!capturing(&state));

    let state = opened(true);
    assert!(matches!(k(&state, KeyCode::Esc), Some(Msg::Back)));
    assert!(matches!(k(&state, KeyCode::Char('h')), Some(Msg::Back)));
    assert!(matches!(k(&state, KeyCode::Backspace), Some(Msg::Back)));
    assert!(matches!(k(&state, KeyCode::Right), Some(Msg::Tab(true))));
    assert!(matches!(
        k(&state, KeyCode::Char('[')),
        Some(Msg::Tab(false))
    ));
    assert!(matches!(
        k(&state, KeyCode::Char('D')),
        Some(Msg::Act(Action::RemoveFiles))
    ));
    assert!(matches!(
        k(&state, KeyCode::Char('l')),
        Some(Msg::OpenLimit)
    ));
    assert!(
        k(&state, KeyCode::Char('P')).is_none(),
        "every torrent is a list action"
    );
    assert!(
        k(&state, KeyCode::Char('1')).is_none(),
        "digits stay global"
    );
    assert!(
        k(&state, KeyCode::Enter).is_none(),
        "Enter runs only on the actions tab"
    );
    assert!(!capturing(&state));
}

// Snapshots.

fn snapshot(name: &str, state: &State, sizes: &[(u16, u16)], mutations: bool) {
    let server = testing::server(true, mutations);
    for (w, h) in sizes {
        let screen = testing::render(*w, *h, Some(&server), |ctx, frame, area| {
            view(state, ctx, frame, area)
        });
        // Snapshots sit beside the other screens', one directory up.
        insta::with_settings!({ snapshot_path => "../snapshots" }, {
            insta::assert_snapshot!(format!("torrents_{name}_{w}x{h}"), screen);
        });
    }
}

#[test]
fn the_list_renders_at_both_sizes() {
    let mut state = loaded(1..30, Some("c1"));
    state.list.loading = false;
    state.selected = 2;
    snapshot("list", &state, &[(80, 24), (160, 48)], true);
}

#[test]
fn the_detail_overview_renders() {
    snapshot(
        "detail_overview",
        &opened(true),
        &[(80, 24), (160, 48)],
        true,
    );
    let screen = testing::render(160, 48, None, |ctx, frame, area| {
        view(&opened(false), ctx, frame, area)
    });
    assert!(screen.contains("not loaded in a session"), "{screen}");
}

#[test]
fn the_detail_files_render() {
    let mut state = opened(true);
    with_files(&mut state);
    state.detail.as_mut().unwrap().files_selected = 1;
    snapshot("detail_files", &state, &[(160, 48)], true);
}

#[test]
fn the_detail_trackers_render() {
    let mut state = opened(true);
    with_trackers(&mut state);
    snapshot("detail_trackers", &state, &[(160, 48)], true);
}

#[test]
fn the_detail_actions_say_what_is_disabled() {
    let mut state = opened(true);
    testing::with_ctx(None, |ctx| update(&mut state, Msg::Tab(false), ctx));
    let screen = testing::render(80, 24, None, |ctx, frame, area| {
        view(&state, ctx, frame, area)
    });
    assert!(screen.contains("needs [pool] allow_mutations"), "{screen}");
}

#[test]
fn the_add_dialog_renders_with_its_errors() {
    let mut state = loaded(1..8, None);
    testing::with_ctx(None, |ctx| {
        dialog(&mut state, ctx);
        let add = state.add.as_mut().unwrap();
        add.kind = add::SourceKind::ServerPath;
        add.source = Input::new("/home/op/x.torrent".into());
        add.save_path = Input::new("/srv/seed/acct_a".into());
        add.submitting = Some(1);
        update(
            &mut state,
            Msg::Added {
                request: 1,
                result: Err(api(
                    "path-not-confined",
                    "the server_path must be inside the daemon's torrent directory",
                )),
            },
            ctx,
        );
    });
    snapshot("add", &state, &[(80, 24)], true);
}

#[test]
fn the_delete_confirmation_renders() {
    let mut state = opened(true);
    let server = testing::server(true, true);
    testing::with_ctx(Some(&server), |ctx| {
        update(&mut state, Msg::Act(Action::RemoveFiles), ctx);
        keys(&mut state, ctx, "del");
    });
    snapshot("delete_confirm", &state, &[(80, 24)], true);
}

mod props {
    use proptest::prelude::*;

    use super::*;

    /// Rows `from..from + n`, in infohash order, every third in
    /// `acct_b`, so a `/b` filter shows some rows and hides others.
    fn rows(from: usize, n: usize, next: Option<&str>) -> types::TorrentPage {
        let items: Vec<_> = (from..from + n)
            .map(|i| {
                let mut row = summary(1, if i % 3 == 0 { "acct_b" } else { "acct_a" }, "seeding");
                row["infohash"] = json!(format!("{i:040x}"));
                row
            })
            .collect();
        testing::from_json(json!({"items": items, "next_cursor": next}))
    }

    #[derive(Clone, Debug)]
    enum Op {
        Key(KeyCode),
        /// The daemon answers the request in flight, if there is one,
        /// with `n` rows and more to come or not. A first page of a
        /// reload starts the daemon's rows at `shift`: what it lists can
        /// change between reloads.
        Page {
            shift: usize,
            n: usize,
            more: bool,
        },
        PageFailed,
        Refresh,
    }

    fn op() -> impl Strategy<Value = Op> {
        let key = prop::sample::select(vec![
            KeyCode::Char('j'),
            KeyCode::Char('k'),
            KeyCode::Char('g'),
            KeyCode::Char('G'),
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Char('/'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Backspace,
            KeyCode::Char('0'),
            KeyCode::Char('1'),
            KeyCode::Char('b'),
            KeyCode::Char('e'),
            KeyCode::Char('f'),
            KeyCode::Char('F'),
        ]);
        prop_oneof![
            6 => key.prop_map(Op::Key),
            3 => (0usize..30, 0usize..40, any::<bool>()).prop_map(|(shift, n, more)| Op::Page { shift, n, more }),
            1 => Just(Op::PageFailed),
            1 => Just(Op::Refresh),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Whatever keys are pressed and whatever the daemon answers,
        /// failed or short, filtered or not, the list's selection is a
        /// row it shows, or 0 when it shows none.
        ///
        /// The daemon is faithful to the protocol: it answers only the
        /// request in flight, a reload's with a first page, a cursor's
        /// with the rows from that cursor on.
        #[test]
        fn the_selection_stays_within_the_visible_rows(ops in prop::collection::vec(op(), 0..80)) {
            let mut state = State::default();
            testing::with_ctx(None, |ctx| -> Result<(), TestCaseError> {
                // The request in flight: `None` for a reload's first
                // page, else the row its cursor resumes at. A cursor is
                // `k<row>`.
                let mut in_flight: Option<Option<usize>> = None;
                let cursor_row = |c: &Option<String>| -> Option<usize> {
                    c.as_deref().and_then(|c| c.strip_prefix('k')).and_then(|n| n.parse().ok())
                };
                let (mut generation, mut loading) = (state.list.generation, false);
                let _ = update(&mut state, Msg::Profiles(Ok(profiles())), ctx);
                let _ = refresh(&mut state, ctx);
                for op in std::iter::once(None).chain(ops.into_iter().map(Some)) {
                    // The row after the page just sent: where the next
                    // request, a reload's or for more, resumes.
                    let mut resume_at = None;
                    let msg = match &op {
                        None => None,
                        Some(Op::Key(code)) => on_key(&state, testing::key(*code)),
                        Some(Op::Page { .. } | Op::PageFailed) if in_flight.is_none() => None,
                        Some(Op::Page { shift, n, more }) => {
                            let request = in_flight.take().unwrap();
                            let from = request.unwrap_or(*shift);
                            let next = more.then(|| format!("k{}", from + n));
                            resume_at = Some(from + n);
                            let page = rows(from, *n, next.as_deref());
                            Some(page_msg(&state, request.is_none(), Ok(page)))
                        }
                        Some(Op::PageFailed) => {
                            in_flight = None;
                            Some(page_msg(&state, false, Err(failure(500, "internal", "boom"))))
                        }
                        Some(Op::Refresh) => {
                            let _ = refresh(&mut state, ctx);
                            None
                        }
                    };
                    if let Some(msg) = msg {
                        let _ = update(&mut state, msg, ctx);
                    }
                    // What the client asked for since: a reload, or a
                    // page from its cursor (a reload's next page, or more
                    // rows near the end).
                    if state.list.generation != generation {
                        in_flight = Some(None);
                    } else if let (true, Some(at)) = (state.list.loading, resume_at) {
                        in_flight = Some(Some(at));
                    } else if state.list.loading && !loading {
                        in_flight = Some(cursor_row(&state.list.next_cursor));
                    }
                    if !state.list.loading {
                        in_flight = None;
                    }
                    (generation, loading) = (state.list.generation, state.list.loading);
                    let op = op.unwrap_or(Op::Refresh);
                    if state.detail.is_none() {
                        let shown = visible(&state).len();
                        prop_assert!(
                            state.selected < shown.max(1),
                            "after {:?}: selected {} of {} shown",
                            op,
                            state.selected,
                            shown,
                        );
                    }
                }
                Ok(())
            })?;
        }
    }
}
