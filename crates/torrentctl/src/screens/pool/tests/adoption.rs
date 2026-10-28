//! Adoption: the dry run, applying what it previewed, and its refusals.

use super::*;

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
