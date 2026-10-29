//! The profiles screen's reducer, keys and views.

use serde_json::json;

use super::*;
use crate::testing;

fn profiles() -> Vec<types::Profile> {
    testing::from_json(json!([
        {"profile_id": "acct_a", "status": "active", "tunnel_ip": "10.2.0.2",
         "desired_state": "online", "effective_state": "online",
         "torrent_count": 900, "listen_port": null, "port_forward": "natpmp",
         "forwarded_port": 51413, "user_agent": "qBittorrent/4.6.2", "failure_reason": null},
        {"profile_id": "acct_b", "status": "vpn_down", "tunnel_ip": "10.3.0.2",
         "desired_state": "online", "effective_state": "offline",
         "torrent_count": 334, "listen_port": 51414, "port_forward": "static",
         "forwarded_port": null, "user_agent": null, "failure_reason": null},
        {"profile_id": "host", "status": "active", "tunnel_ip": null,
         "desired_state": "offline", "effective_state": "offline",
         "torrent_count": 1, "listen_port": 6881, "port_forward": "static",
         "forwarded_port": null, "user_agent": null, "failure_reason": null},
        {"profile_id": "acct_c", "status": "failed", "tunnel_ip": null,
         "desired_state": "online", "effective_state": "offline",
         "torrent_count": 12, "listen_port": null, "port_forward": "natpmp",
         "forwarded_port": null, "user_agent": null,
         "failure_reason": "wg-c did not come up within 30s"},
    ]))
}

fn detail_of(id: &str) -> types::ProfileDetail {
    let mut value = serde_json::to_value(
        profiles()
            .into_iter()
            .find(|p| p.profile_id == id)
            .expect("a fixture profile"),
    )
    .expect("serialisable");
    let (iface, domains, paused, ok) = match id {
        "acct_a" => (
            json!("wg-a"),
            json!(["tracker.example.org", "announce.example.net"]),
            0,
            true,
        ),
        "acct_b" => (json!("wg-b"), json!(["tracker.example.org"]), 334, true),
        "host" => (json!(null), json!([]), 0, true),
        _ => (json!("wg-c"), json!([]), 0, false),
    };
    value["vpn_interface"] = iface;
    value["allowed_tracker_domains"] = domains;
    value["paused_for_vpn"] = json!(paused);
    value["port_forward_ok"] = json!(ok);
    testing::from_json(value)
}

/// Answer the detail request that is out, if any, with the fixture.
fn answer(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(profile_id) = state.detail_pending.clone() else {
        return Vec::new();
    };
    let generation = state.generation;
    let result = Ok(detail_of(&profile_id));
    update(
        state,
        Msg::DetailLoaded {
            profile_id,
            generation,
            result,
        },
        ctx,
    )
}

/// Loaded, with `id` selected and its detail answered.
fn loaded(id: &str) -> State {
    let mut state = State::default();
    testing::with_ctx(None, |ctx| {
        refresh(&mut state, ctx);
        update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
        answer(&mut state, ctx);
        let index = state
            .profiles
            .iter()
            .position(|p| p.profile_id == id)
            .unwrap();
        update(&mut state, Msg::Move(index as isize), ctx);
        answer(&mut state, ctx);
    });
    state
}

fn conflict(detail: &str) -> Failure {
    Failure {
        status: Some(409),
        slug: Some("profile-unavailable".into()),
        title: "The profile is unavailable".into(),
        detail: Some(detail.into()),
        request_id: Some("req-1".into()),
        ..Default::default()
    }
}

/// `id`'s detail as the daemon answers a switch: `status` and
/// `effective_state` as they stand after it.
fn switched(id: &str, status: &str, effective: &str) -> types::ProfileDetail {
    let mut value = serde_json::to_value(detail_of(id)).expect("serialisable");
    value["status"] = json!(status);
    value["effective_state"] = json!(effective);
    value["desired_state"] = json!(effective);
    testing::from_json(value)
}

/// The message an effect delivers, for effects that are `Effect::now`.
fn run(effect: Effect) -> crate::app::Msg {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(effect.0)
}

fn toast_of(effect: Effect) -> Toast {
    match run(effect) {
        crate::app::Msg::Toast(toast) => toast,
        other => panic!("expected a toast, got {other:?}"),
    }
}

#[test]
fn loading_selects_the_first_and_fetches_its_detail() {
    let mut state = State::default();
    testing::with_ctx(None, |ctx| {
        assert_eq!(refresh(&mut state, ctx).len(), 1);
        assert!(state.loading);
        assert!(
            refresh(&mut state, ctx).is_empty(),
            "one list load at a time"
        );
        let effects = update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
        assert_eq!(effects.len(), 1, "the selected profile's detail");
        assert!(state.loaded && !state.loading);
        assert_eq!(state.detail_pending.as_deref(), Some("acct_a"));
        assert!(answer(&mut state, ctx).is_empty(), "nothing else to fetch");
        assert!(state.details.contains_key("acct_a"));
    });
}

#[test]
fn a_refresh_keeps_the_selection_on_the_same_profile_and_refetches_its_detail() {
    let mut state = loaded("host");
    testing::with_ctx(None, |ctx| {
        assert_eq!(refresh(&mut state, ctx).len(), 1);
        // `host` moved up one place.
        let mut reordered = profiles();
        reordered.remove(1);
        let effects = update(&mut state, Msg::Loaded(Ok(reordered)), ctx);
        assert_eq!(state.current().unwrap().profile_id, "host");
        assert_eq!(effects.len(), 1, "its detail is older than the refresh");
        assert!(
            state.details.contains_key("host"),
            "the old detail shows meanwhile"
        );
    });
}

#[test]
fn a_failed_list_load_keeps_the_last_good_list() {
    let mut state = loaded("acct_a");
    testing::with_ctx(None, |ctx| {
        refresh(&mut state, ctx);
        let effects = update(
            &mut state,
            Msg::Loaded(Err(Failure::local("Cannot reach the daemon", None))),
            ctx,
        );
        assert!(effects.is_empty(), "shown in the panel, not a toast");
        assert_eq!(state.profiles.len(), 4);
        assert_eq!(state.error.as_deref(), Some("Cannot reach the daemon"));
    });
}

#[test]
fn scrolling_fast_fires_one_detail_request_and_drops_stale_answers() {
    let mut state = State::default();
    testing::with_ctx(None, |ctx| {
        refresh(&mut state, ctx);
        update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
        assert_eq!(state.detail_pending.as_deref(), Some("acct_a"));
        // Scroll to the bottom while acct_a's detail is out: no requests.
        for _ in 0..3 {
            assert!(update(&mut state, Msg::Move(1), ctx).is_empty());
        }
        assert_eq!(state.current().unwrap().profile_id, "acct_c");
        // acct_a answers: kept for acct_a, not shown for acct_c, and
        // acct_c is fetched.
        let effects = answer(&mut state, ctx);
        assert_eq!(effects.len(), 1);
        assert_eq!(state.detail_pending.as_deref(), Some("acct_c"));
        assert!(!state.details.contains_key("acct_c"));
        let screen = testing::render(160, 48, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        assert!(
            !screen.contains("wg-a"),
            "acct_a's detail is not shown for acct_c"
        );
        answer(&mut state, ctx);
        // Back to acct_a: its detail is on hand from this refresh.
        assert!(update(&mut state, Msg::Top, ctx).is_empty());
        assert!(
            update(&mut state, Msg::Move(-1), ctx).is_empty(),
            "clamped at the top"
        );
    });
}

#[test]
fn a_failed_detail_load_is_shown_for_its_profile() {
    let mut state = State::default();
    testing::with_ctx(None, |ctx| {
        refresh(&mut state, ctx);
        update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
        let generation = state.generation;
        let effects = update(
            &mut state,
            Msg::DetailLoaded {
                profile_id: "acct_a".into(),
                generation,
                result: Err(Failure::local("The daemon did not answer", None)),
            },
            ctx,
        );
        assert!(effects.is_empty());
        assert_eq!(
            state.detail_error,
            Some(("acct_a".into(), "The daemon did not answer".into()))
        );
        assert!(state.detail_pending.is_none());
        let screen = testing::render(160, 48, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        assert!(screen.contains("✖ The daemon did not answer"), "{screen}");
    });
}

#[test]
fn taking_offline_asks_naming_the_profile_and_its_torrents_then_sends_one_request() {
    let mut state = loaded("acct_a");
    testing::with_ctx(None, |ctx| {
        let msg = on_key(&state, testing::key(KeyCode::Char('p'))).unwrap();
        assert!(update(&mut state, msg, ctx).is_empty());
        assert!(capturing(&state));
        let asking = state.asking.as_ref().unwrap();
        assert_eq!(asking.action, Switch::Offline);
        assert!(asking.confirm.body.contains("acct_a"));
        assert!(asking.confirm.body.contains("its 900 torrents"));
        assert!(asking.confirm.body.contains("Kept across restarts"));

        let msg = on_key(&state, testing::key(KeyCode::Char('n'))).unwrap();
        assert!(update(&mut state, msg, ctx).is_empty(), "nothing is sent");
        assert!(!capturing(&state));

        update(&mut state, Msg::Ask(Switch::Online), ctx);
        let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
        assert_eq!(update(&mut state, msg, ctx).len(), 1, "one request");
        assert!(state.asking.is_none());
    });
}

#[test]
fn a_fenced_profile_is_brought_online_through_the_tunnel_check() {
    let mut state = loaded("acct_b");
    testing::with_ctx(None, |ctx| {
        assert!(update(&mut state, Msg::Ask(Switch::Online), ctx).is_empty());
        let body = &state.asking.as_ref().unwrap().confirm.body;
        assert!(body.contains("It is fenced"), "{body}");
        assert!(body.contains("checks its tunnel first"), "{body}");
        let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
        assert_eq!(update(&mut state, msg, ctx).len(), 1, "sent, not refused");
    });
}

#[test]
fn a_profile_that_never_came_up_records_the_choice_for_its_next_boot() {
    let mut state = loaded("acct_c");
    testing::with_ctx(None, |ctx| {
        assert!(update(&mut state, Msg::Ask(Switch::Offline), ctx).is_empty());
        let body = &state.asking.as_ref().unwrap().confirm.body;
        assert!(body.contains("never came up"), "{body}");
        assert!(body.contains("next comes up"), "{body}");
    });
}

#[test]
fn a_switch_is_toasted_and_refreshes() {
    let mut state = loaded("acct_a");
    testing::with_ctx(None, |ctx| {
        let effects = update(
            &mut state,
            Msg::Ran {
                action: Switch::Offline,
                profile_id: "acct_a".into(),
                result: Ok(switched("acct_a", "active", "offline")),
            },
            ctx,
        );
        assert_eq!(effects.len(), 2, "a toast and a refresh");
        let toast = toast_of(effects.into_iter().next().unwrap());
        assert_eq!(toast.kind, ToastKind::Success);
        assert_eq!(toast.text, "acct_a: offline");

        // The list had acct_b fenced: the answer means its fence lifted.
        state.loading = false;
        let effects = update(
            &mut state,
            Msg::Ran {
                action: Switch::Online,
                profile_id: "acct_b".into(),
                result: Ok(switched("acct_b", "active", "online")),
            },
            ctx,
        );
        let toast = toast_of(effects.into_iter().next().unwrap());
        assert_eq!(
            toast.text,
            "acct_b: tunnel checked healthy; fence lifted, online"
        );

        // Set online, and offline-all still holds it.
        state.loading = false;
        let effects = update(
            &mut state,
            Msg::Ran {
                action: Switch::Online,
                profile_id: "host".into(),
                result: Ok(switched("host", "active", "offline")),
            },
            ctx,
        );
        let toast = toast_of(effects.into_iter().next().unwrap());
        assert_eq!(
            toast.text,
            "host: set online, still off the network (offline-all is on)"
        );
    });
}

#[test]
fn a_lifted_fence_under_offline_all_is_toasted_as_still_off_the_network() {
    let mut state = loaded("acct_b");
    testing::with_ctx(None, |ctx| {
        // The list had acct_b fenced; the probe passed and the fence
        // lifted, but offline-all keeps it off the network.
        let effects = update(
            &mut state,
            Msg::Ran {
                action: Switch::Online,
                profile_id: "acct_b".into(),
                result: Ok(switched("acct_b", "active", "offline")),
            },
            ctx,
        );
        assert_eq!(effects.len(), 2, "a toast and a refresh");
        let toast = toast_of(effects.into_iter().next().unwrap());
        assert_eq!(toast.kind, ToastKind::Success);
        assert_eq!(
                toast.text,
                "acct_b: tunnel checked healthy; fence lifted; still off the network (offline-all is on)"
            );
    });
}

#[test]
fn a_409_says_which_check_the_tunnel_still_fails() {
    let mut state = loaded("acct_b");
    testing::with_ctx(None, |ctx| {
        let effects = update(
            &mut state,
            Msg::Ran {
                action: Switch::Online,
                profile_id: "acct_b".into(),
                result: Err(conflict(
                    "profile vpn_down: its tunnel still fails the health check \
                         (route_mismatch), so it stays fenced",
                )),
            },
            ctx,
        );
        assert_eq!(effects.len(), 2, "a toast and a refresh");
        let toast = toast_of(effects.into_iter().next().unwrap());
        assert_eq!(toast.kind, ToastKind::Error);
        assert!(
            toast
                .text
                .starts_with("cannot bring online acct_b: profile vpn_down"),
            "{}",
            toast.text
        );
        assert!(toast.text.contains("route_mismatch"), "{}", toast.text);
        assert_eq!(toast.request_id.as_deref(), Some("req-1"));
    });
}

#[test]
fn any_other_failure_is_a_failure_toast() {
    let mut state = loaded("acct_a");
    testing::with_ctx(None, |ctx| {
        let effects = update(
            &mut state,
            Msg::Ran {
                action: Switch::Offline,
                profile_id: "acct_a".into(),
                result: Err(Failure::local("Cannot reach the daemon", None)),
            },
            ctx,
        );
        assert_eq!(effects.len(), 1);
        let toast = toast_of(effects.into_iter().next().unwrap());
        assert_eq!(toast.text, "take offline acct_a: Cannot reach the daemon");
    });
}

#[test]
fn enter_and_t_show_the_selected_profiles_torrents() {
    let mut state = loaded("acct_b");
    for code in [KeyCode::Enter, KeyCode::Char('t')] {
        let msg = on_key(&state, testing::key(code)).unwrap();
        let effects = testing::with_ctx(None, |ctx| update(&mut state, msg, ctx));
        assert_eq!(effects.len(), 1);
        match run(effects.into_iter().next().unwrap()) {
            crate::app::Msg::ShowTorrentsOf(id) => assert_eq!(id, "acct_b"),
            other => panic!("expected ShowTorrentsOf, got {other:?}"),
        }
    }
}

#[test]
fn keys_map_to_messages() {
    let state = State::default();
    let cases = [
        (KeyCode::Char('j'), "Move(1)"),
        (KeyCode::Down, "Move(1)"),
        (KeyCode::Char('k'), "Move(-1)"),
        (KeyCode::Up, "Move(-1)"),
        (KeyCode::PageDown, "Move(10)"),
        (KeyCode::PageUp, "Move(-10)"),
        (KeyCode::Char('g'), "Top"),
        (KeyCode::Char('G'), "Bottom"),
        (KeyCode::Enter, "ShowTorrents"),
        (KeyCode::Char('t'), "ShowTorrents"),
        (KeyCode::Char('p'), "Ask(Offline)"),
        (KeyCode::Char('r'), "Ask(Online)"),
    ];
    for (code, expected) in cases {
        let msg = on_key(&state, testing::key(code));
        assert_eq!(format!("{msg:?}"), format!("Some({expected})"), "{code:?}");
    }
    for global in ['q', '?', ':', '1', '9'] {
        assert!(
            on_key(&state, testing::key(KeyCode::Char(global))).is_none(),
            "{global}"
        );
    }
    assert!(on_key(&state, testing::key(KeyCode::Tab)).is_none());
}

#[test]
fn the_list_with_the_detail_of_an_active_a_fenced_an_offline_and_a_failed_profile() {
    for id in ["acct_a", "acct_b", "host", "acct_c"] {
        let state = loaded(id);
        let screen = testing::render(160, 48, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        snapshot(&format!("profiles_{id}_160x48"), screen);
    }
}

#[test]
fn the_list_fits_a_small_terminal() {
    let state = loaded("acct_b");
    let screen = testing::render(80, 24, None, |ctx, frame, area| {
        view(&state, ctx, frame, area)
    });
    assert!(screen.contains("FENCED"), "{screen}");
    assert!(!screen.contains("restart the daemon"), "{screen}");
    snapshot("profiles_80x24", screen);
}

#[test]
fn the_take_offline_confirm() {
    let mut state = loaded("acct_a");
    testing::with_ctx(None, |ctx| {
        update(&mut state, Msg::Ask(Switch::Offline), ctx)
    });
    let screen = testing::render(80, 24, None, |ctx, frame, area| {
        view(&state, ctx, frame, area)
    });
    snapshot("profiles_confirm_offline_80x24", screen);
}

fn snapshot(name: &str, screen: String) {
    // Snapshots sit beside the other screens', one directory up.
    insta::with_settings!({ snapshot_path => "../snapshots" }, {
        insta::assert_snapshot!(name, screen);
    });
}
