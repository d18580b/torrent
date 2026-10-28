//! The root's reducer: the session, the live connection, toasts, the help
//! overlay and the command palette, driven by messages alone.

use crossterm::event::KeyCode;
use serde_json::json;

use super::*;
use crate::testing;

fn model() -> Model {
    Model::new(testing::api(), testing::theme())
}

/// What `GET /v1/server` then `GET /v1/sessions/current` — asking who
/// we are — sends.
const CHECK: [&str; 2] = ["GET /v1/server", "GET /v1/sessions/current"];
const REVOKE: &str = "DELETE /v1/sessions/current";

fn principal(kind: &str) -> types::Principal {
    testing::from_json(json!({
        "kind": kind, "name": null, "scopes": ["read", "write"], "expires_at": null,
    }))
}

/// A model whose effects reach `recorder`.
fn model_at(recorder: &testing::Recorder) -> Model {
    Model::new(recorder.api(), testing::theme())
}

fn signed_in(pool: bool) -> Model {
    signed_in_as(model(), pool)
}

fn signed_in_as(mut m: Model, pool: bool) -> Model {
    update(
        &mut m,
        Msg::SessionChecked(Ok((testing::server(pool, false), principal("token")))),
    );
    m
}

/// A 401, confirmed by the re-check it triggers.
fn refused(m: &mut Model) {
    update(m, Msg::SignedOut(unauthorized()));
    update(m, Msg::SessionChecked(Err(unauthorized())));
}

fn unauthorized() -> Failure {
    Failure {
        status: Some(401),
        slug: Some("about:blank".into()),
        title: "Unauthorized".into(),
        detail: None,
        request_id: None,
        ..Default::default()
    }
}

#[test]
fn a_checked_session_signs_in_and_refreshes_the_visible_screen() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = model_at(&daemon);
    assert!(matches!(m.session, Session::Checking));
    let effects = update(
        &mut m,
        Msg::SessionChecked(Ok((testing::server(false, false), principal("token")))),
    );
    assert!(matches!(m.session, Session::SignedIn { .. }));
    assert!(m.dashboard.loading);
    testing::run(effects);
    assert_eq!(
        daemon.lines(),
        ["GET /v1/status", "GET /v1/profiles"],
        "the dashboard loads"
    );
}

#[test]
fn a_refused_credential_asks_for_the_password() {
    let mut m = model();
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    assert!(matches!(m.session, Session::SignedOut));

    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = signed_in_as(model_at(&daemon), false);
    let effects = update(&mut m, Msg::SignedOut(unauthorized()));
    assert!(matches!(m.session, Session::Checking));
    testing::run(effects);
    assert_eq!(daemon.lines(), CHECK, "a 401 is re-checked first");
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    assert!(matches!(m.session, Session::SignedOut));
    assert!(m
        .login
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("no longer accepted"));
    assert_eq!(failed("x", unauthorized()).to_string_kind(), "SignedOut");
}

#[test]
fn a_minted_session_is_revoked_on_quit_and_a_static_token_is_not() {
    let mut m = signed_in(false);
    assert!(update(&mut m, Msg::Quit).is_empty());
    assert!(m.quit, "a static token needs no revoking");

    let daemon = testing::Recorder::start("204 No Content", "");
    let mut m = model();
    update(
        &mut m,
        Msg::SignedIn(daemon.api().with_token("tds_minted").unwrap()),
    );
    assert!(m.minted);
    update(
        &mut m,
        Msg::SessionChecked(Ok((testing::server(false, false), principal("session")))),
    );
    let effects = update(&mut m, Msg::Quit);
    assert!(!m.quit, "waits for it");
    let msgs = testing::run(effects);
    assert_eq!(
        daemon.requests(),
        [testing::Request {
            line: REVOKE.to_owned(),
            bearer: Some("tds_minted".to_owned()),
        }],
        "one revocation, of the minted token"
    );
    assert!(matches!(msgs[..], [Msg::Exit(None)]), "{msgs:?}");
    update(&mut m, Msg::Exit(None));
    assert!(m.quit);
    assert_eq!(m.exit_notice, None, "revoked: nothing to report");
}

/// A background task's panic with nothing to revoke quits at once.
#[test]
fn a_fatal_message_with_nothing_minted_quits_at_once() {
    let mut m = signed_in(false);
    assert!(update(&mut m, Msg::Fatal("a request panicked: x".into())).is_empty());
    assert!(m.quit);
    assert_eq!(m.fatal.as_deref(), Some("a request panicked: x"));
    assert_eq!(m.exit_notice, None);
}

/// After a password sign-in, a background task's panic revokes the
/// minted token as a quit does; a second panic leaves at once and says
/// the token stayed valid.
#[test]
fn a_fatal_message_revokes_a_minted_token_and_a_second_one_reports_it() {
    let daemon = testing::Recorder::start("204 No Content", "");
    let mut m = model_at(&daemon);
    let minted = m.api.with_token("tds_minted").unwrap();
    update(&mut m, Msg::SignedIn(minted));
    let effects = update(&mut m, Msg::Fatal("a request panicked: x".into()));
    assert!(!m.quit, "waits for the revocation");
    assert!(m.quitting);
    assert_eq!(m.fatal.as_deref(), Some("a request panicked: x"));
    let msgs = testing::run(effects);
    assert_eq!(
        daemon.requests(),
        [testing::Request {
            line: REVOKE.to_owned(),
            bearer: Some("tds_minted".to_owned()),
        }],
        "one revocation, of the minted token"
    );
    assert!(matches!(msgs[..], [Msg::Exit(None)]), "{msgs:?}");
    update(&mut m, Msg::Exit(None));
    assert!(m.quit);
    assert_eq!(m.exit_notice, None, "revoked: nothing to report");

    // A second panic before the revocation answers.
    let mut m = model();
    let minted = m.api.with_token("tds_minted").unwrap();
    update(&mut m, Msg::SignedIn(minted));
    update(&mut m, Msg::Fatal("a request panicked: x".into()));
    assert!(update(&mut m, Msg::Fatal("a request panicked: y".into())).is_empty());
    assert!(m.quit);
    assert_eq!(
        m.fatal.as_deref(),
        Some("a request panicked: x"),
        "the first"
    );
    let notice = m.exit_notice.expect("a notice");
    assert!(notice.contains("was not revoked"), "{notice}");
}

/// A panic while a quit's revocation is in flight starts no second one,
/// and a sign-in answered during the quit counts as minted: a second
/// panic reports its token.
#[test]
fn a_fatal_message_during_a_quit_keeps_its_revocation_and_counts_a_late_sign_in() {
    let mut m = model();
    let minted = m.api.with_token("tds_minted").unwrap();
    update(&mut m, Msg::SignedIn(minted));
    assert_eq!(update(&mut m, Msg::Quit).len(), 1, "the revocation");
    assert!(update(&mut m, Msg::Fatal("a request panicked: x".into())).is_empty());
    assert!(!m.quit, "still waits for the revocation in flight");

    let mut m = model();
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    m.login.busy = true;
    update(&mut m, Msg::Quit);
    assert!(!m.minted);
    let effects = update(
        &mut m,
        Msg::Login(screens::login::Msg::Answered(Ok("tds_late".into()))),
    );
    assert_eq!(effects.len(), 1, "its revocation");
    assert!(m.minted, "the late token is counted");
    update(&mut m, Msg::Fatal("a request panicked: x".into()));
    update(&mut m, Msg::Fatal("a request panicked: y".into()));
    assert!(m.quit);
    let notice = m.exit_notice.expect("a notice");
    assert!(notice.contains("was not revoked"), "{notice}");

    // A second panic while the sign-in is still in flight: nothing is
    // minted yet, but whatever the daemon mints for it goes unrevoked.
    let mut m = model();
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    m.login.busy = true;
    update(&mut m, Msg::Fatal("a request panicked: x".into()));
    assert!(!m.quit, "waits for the sign-in to revoke what it mints");
    assert!(update(&mut m, Msg::Fatal("a request panicked: y".into())).is_empty());
    assert!(m.quit);
    assert!(!m.minted);
    let notice = m.exit_notice.expect("a notice");
    assert!(notice.contains("sign-in had not answered"), "{notice}");
    assert!(!notice.contains("was not revoked"), "{notice}");
}

/// A daemon that accepts the connection and never answers: the
/// revocation gives up after [`REVOKE_TIMEOUT`], not the 15s request
/// timeout, and the user is told the token is still live.
#[test]
fn a_revocation_on_quit_is_bounded_and_reported_when_it_fails() {
    let wedged = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", wedged.local_addr().expect("an address"));
    let mut m = model();
    update(
        &mut m,
        Msg::SignedIn(
            Api::new(&url, None)
                .and_then(|api| api.with_token("tds_minted"))
                .expect("a valid URL"),
        ),
    );
    let effects = update(&mut m, Msg::Quit);
    let started = Instant::now();
    let msgs = testing::run(effects);
    let waited = started.elapsed();
    assert!(
        waited >= REVOKE_TIMEOUT && waited < REVOKE_TIMEOUT + Duration::from_secs(2),
        "gave up after {waited:?}"
    );
    let [Msg::Exit(Some(notice))] = &msgs[..] else {
        panic!("leaves, saying why: {msgs:?}");
    };
    assert!(
        notice.contains("could not be revoked") && notice.contains("did not answer"),
        "{notice}"
    );
    let notice = notice.clone();
    update(&mut m, msgs.into_iter().next().expect("one message"));
    assert!(m.quit);
    assert_eq!(m.exit_notice, Some(notice), "kept for main to print");

    // A refusal is reported the same way, with what the daemon said.
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = model();
    update(
        &mut m,
        Msg::SignedIn(daemon.api().with_token("tds_minted").expect("a valid URL")),
    );
    let msgs = testing::run(update(&mut m, Msg::Quit));
    assert!(
        matches!(&msgs[..], [Msg::Exit(Some(n))] if n.contains("HTTP 500")),
        "{msgs:?}"
    );

    // A `401` says the token is already invalid: nothing to report.
    let daemon = testing::Recorder::start(
        "401 Unauthorized",
        r#"{"type":"about:blank","title":"Unauthorized","status":401}"#,
    );
    let mut m = model();
    update(
        &mut m,
        Msg::SignedIn(daemon.api().with_token("tds_minted").expect("a valid URL")),
    );
    let msgs = testing::run(update(&mut m, Msg::Quit));
    assert_eq!(daemon.lines(), [REVOKE], "asked to revoke it");
    assert!(matches!(msgs[..], [Msg::Exit(None)]), "{msgs:?}");
}

#[test]
fn the_pool_tab_exists_only_where_the_pool_does() {
    let m = signed_in(false);
    assert_eq!(m.tabs(), [Tab::Dashboard, Tab::Torrents, Tab::Profiles]);
    let m = signed_in(true);
    assert_eq!(m.tabs(), Tab::ALL);

    let mut m = signed_in(false);
    update(&mut m, Msg::Key(testing::key(KeyCode::Char('4'))));
    assert_eq!(m.tab, Tab::Dashboard, "no fourth tab to switch to");
    update(&mut m, Msg::Key(testing::key(KeyCode::Char('3'))));
    assert_eq!(m.tab, Tab::Profiles);
    update(&mut m, Msg::Key(testing::key(KeyCode::Tab)));
    assert_eq!(m.tab, Tab::Dashboard, "Tab wraps");
    update(&mut m, Msg::Key(testing::key(KeyCode::BackTab)));
    assert_eq!(m.tab, Tab::Profiles);
}

#[test]
fn the_command_palette_runs_commands_and_says_what_it_does_not_know() {
    let mut m = signed_in(false);
    update(&mut m, Msg::Key(testing::key(KeyCode::Char(':'))));
    assert!(m.palette.is_some());
    for c in "torrents".chars() {
        update(&mut m, Msg::Key(testing::key(KeyCode::Char(c))));
    }
    update(&mut m, Msg::Key(testing::key(KeyCode::Enter)));
    assert!(m.palette.is_none());
    assert_eq!(m.tab, Tab::Torrents);

    let effects = run_command(&mut m, "pool");
    assert_eq!(effects.len(), 1, "a toast: no pool here");
    assert_eq!(m.tab, Tab::Torrents);
    assert_eq!(run_command(&mut m, "frobnicate").len(), 1);
    assert!(run_command(&mut m, "").is_empty());
    run_command(&mut m, "help");
    assert!(m.help);
}

#[test]
fn help_closes_on_any_key_and_global_keys_quit() {
    let mut m = signed_in(false);
    update(&mut m, Msg::Key(testing::key(KeyCode::Char('?'))));
    assert!(m.help);
    update(&mut m, Msg::Key(testing::key(KeyCode::Char('x'))));
    assert!(!m.help);
    update(&mut m, Msg::Key(testing::key(KeyCode::Char('q'))));
    assert!(m.quit);
}

#[test]
fn toasts_are_capped_and_expire() {
    let mut m = signed_in(false);
    for i in 0..6 {
        update(&mut m, Msg::Toast(Toast::info(format!("t{i}"))));
    }
    assert_eq!(m.toasts.len(), 4);
    assert_eq!(m.toasts.front().unwrap().0.text, "t2");
    for (_, at) in m.toasts.iter_mut() {
        *at -= TOAST_TTL + Duration::from_secs(1);
    }
    update(&mut m, Msg::Tick);
    assert!(m.toasts.is_empty());
}

#[test]
fn the_polling_fallback_refreshes_only_while_the_stream_is_down() {
    let mut m = signed_in(false);
    m.dashboard.loading = false;
    m.last_refresh = Some(Instant::now() - POLL_INTERVAL - Duration::from_secs(1));
    m.live = Live::Streaming;
    assert!(
        update(&mut m, Msg::Tick).is_empty(),
        "live: the stream drives refreshes"
    );
    m.live = Live::Reconnecting {
        reason: "down".into(),
    };
    assert_eq!(update(&mut m, Msg::Tick).len(), 1, "polling while down");
    assert!(
        update(&mut m, Msg::Tick).is_empty(),
        "and not again until the interval"
    );
    m.dashboard.loading = false;
    assert_eq!(
        update(&mut m, Msg::Changed("00000000000000aa".into())).len(),
        1,
        "a change notification refreshes"
    );
}

#[test]
fn an_open_trackers_tab_is_polled_while_the_stream_is_up() {
    use screens::torrents::Msg as T;
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = signed_in_as(model_at(&daemon), false);
    m.tab = Tab::Torrents;
    update(&mut m, Msg::LiveChanged(Live::Streaming));
    let infohash = "ab".repeat(20);
    let page: types::TorrentPage = testing::from_json(serde_json::json!({
        "items": [{
            "infohash": infohash, "profile_id": "acct_a", "phase": "seeding",
            "progress": 1.0, "upload_rate": 0, "download_rate": 0,
            "total_uploaded": 0, "total_payload_uploaded": 0, "num_peers": 0,
            "is_finished": true, "is_seeding": true,
        }],
        "next_cursor": null,
    }));
    let generation = m.torrents.list.generation;
    update(
        &mut m,
        Msg::Torrents(T::Page {
            generation,
            first: true,
            result: Ok(page),
        }),
    );
    update(&mut m, Msg::Torrents(T::Open));
    update(&mut m, Msg::Torrents(T::Tab(true)));
    update(&mut m, Msg::Torrents(T::Tab(true)));
    let trackers: types::TrackerList = testing::from_json(serde_json::json!({"items": []}));
    update(
        &mut m,
        Msg::Torrents(T::Trackers {
            hash: infohash.clone(),
            result: Ok(trackers),
        }),
    );
    // Nothing the stream reports has changed, and the screen refreshed
    // just now; only the trackers' own timer is due.
    m.last_refresh = Some(Instant::now());
    let detail = m.torrents.detail.as_mut().unwrap();
    detail.trackers_asked = detail
        .trackers_asked
        .map(|at| at - screens::torrents::TRACKERS_POLL_INTERVAL);

    testing::run(update(&mut m, Msg::Tick));
    assert_eq!(
        daemon.lines(),
        [format!("GET /v1/torrents/{infohash}/trackers")]
    );
    assert!(
        update(&mut m, Msg::Tick).is_empty(),
        "and not again until the interval"
    );
}

#[test]
fn a_tick_with_an_unchanged_fingerprint_fetches_nothing() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = signed_in_as(model_at(&daemon), false);
    m.tab = Tab::Torrents;
    update(&mut m, Msg::LiveChanged(Live::Streaming));
    let tick = |fp: &str| Msg::Changed(fp.to_owned());

    testing::run(update(&mut m, tick("00000000000000aa")));
    assert_eq!(
        daemon.lines(),
        ["GET /v1/profiles", "GET /v1/torrents?limit=100"],
        "the first tick refreshes what is on screen"
    );
    // Let the list's answer land so a refresh is not skipped as one
    // already in flight.
    m.torrents.list.loading = false;
    m.torrents.profiles_loading = false;

    assert!(
        update(&mut m, tick("00000000000000aa")).is_empty(),
        "the daemon re-sent the same state: nothing to fetch"
    );
    testing::run(update(&mut m, tick("00000000000000bb")));
    assert_eq!(daemon.lines().len(), 4, "a new fingerprint refreshes");
    m.torrents.list.loading = false;
    m.torrents.profiles_loading = false;

    // A reconnect forgets it: what changed while the stream was down is
    // unknown, so the first tick after refreshes even if it matches.
    update(
        &mut m,
        Msg::LiveChanged(Live::Reconnecting {
            reason: "down".into(),
        }),
    );
    update(&mut m, Msg::LiveChanged(Live::Streaming));
    assert_eq!(update(&mut m, tick("00000000000000bb")).len(), 2);
}

#[test]
fn a_change_that_lands_while_the_list_is_loading_is_retried_on_its_re_send() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = signed_in_as(model_at(&daemon), false);
    m.tab = Tab::Torrents;
    update(&mut m, Msg::LiveChanged(Live::Streaming));
    let tick = |fp: &str| Msg::Changed(fp.to_owned());

    testing::run(update(&mut m, tick("00000000000000aa")));
    assert_eq!(daemon.lines().len(), 2, "the first tick refreshes");
    // The list's re-read is still in flight (a multi-page reload, say)
    // when the state changes: the screen skips the list, whose answer
    // may predate the change.
    m.torrents.profiles_loading = false;
    testing::run(update(&mut m, tick("00000000000000bb")));
    assert_eq!(
        daemon.lines()[2..],
        ["GET /v1/profiles"],
        "the list is not restarted mid-load"
    );
    m.torrents.list.loading = false;
    m.torrents.profiles_loading = false;

    // The daemon re-sends the same fingerprint: the skipped list is
    // re-read now that it can be.
    testing::run(update(&mut m, tick("00000000000000bb")));
    assert_eq!(
        daemon.lines()[3..],
        ["GET /v1/profiles", "GET /v1/torrents?limit=100"],
        "the change skipped mid-load is fetched on its re-send"
    );
    m.torrents.list.loading = false;
    m.torrents.profiles_loading = false;
    assert!(
        update(&mut m, tick("00000000000000bb")).is_empty(),
        "once seen, a re-send fetches nothing"
    );
}

#[test]
fn a_change_is_remembered_only_when_the_visible_screen_is_not_loading() {
    // Each tab's own busy() decides, through the load flag it reads.
    type SetLoading = fn(&mut Model, bool);
    let tabs: [(Tab, SetLoading); 3] = [
        (Tab::Dashboard, |m, on| m.dashboard.loading = on),
        (Tab::Profiles, |m, on| m.profiles.loading = on),
        (Tab::Pool, |m, on| m.pool.overview.loading = on),
    ];
    for (tab, set_loading) in tabs {
        let mut m = signed_in(true);
        m.tab = tab;
        update(&mut m, Msg::LiveChanged(Live::Streaming));
        // Every screen idle but the one shown, so only its gate decides.
        m.dashboard.loading = false;
        m.profiles.loading = false;
        m.pool.overview.loading = false;
        let tick = || Msg::Changed("00000000000000aa".to_owned());

        set_loading(&mut m, true);
        update(&mut m, tick());
        assert_eq!(
            m.fingerprint, None,
            "{tab:?}: a change skipped mid-load is not remembered"
        );

        set_loading(&mut m, false);
        assert!(
            !update(&mut m, tick()).is_empty(),
            "{tab:?}: its re-send refreshes the screen"
        );
        assert_eq!(
            m.fingerprint.as_deref(),
            Some("00000000000000aa"),
            "{tab:?}: a change refreshed in full is remembered"
        );

        set_loading(&mut m, false);
        assert!(
            update(&mut m, tick()).is_empty(),
            "{tab:?}: once remembered, a re-send fetches nothing"
        );
    }
}

#[test]
fn a_change_whose_refresh_fails_is_retried_on_its_re_send() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = signed_in_as(model_at(&daemon), false);
    m.tab = Tab::Profiles;
    update(&mut m, Msg::LiveChanged(Live::Streaming));
    let tick = |fp: &str| Msg::Changed(fp.to_owned());
    let answer = |m: &mut Model, effects: Vec<Effect>| {
        for msg in testing::run(effects) {
            update(m, msg);
        }
    };

    // The refresh the change triggers fails: a transient 500, say.
    let effects = update(&mut m, tick("00000000000000aa"));
    answer(&mut m, effects);
    assert_eq!(daemon.lines(), ["GET /v1/profiles"]);
    assert!(m.profiles.error.is_some(), "the failure is shown");

    // The daemon re-sends the same fingerprint: the failed load is
    // retried, not left on screen until some other change arrives.
    let effects = update(&mut m, tick("00000000000000aa"));
    answer(&mut m, effects);
    assert_eq!(
        daemon.lines(),
        ["GET /v1/profiles", "GET /v1/profiles"],
        "a change whose refresh failed is fetched again on its re-send"
    );

    // Once a refresh it triggered succeeds, a re-send fetches nothing.
    assert_eq!(update(&mut m, tick("00000000000000aa")).len(), 1);
    update(
        &mut m,
        Msg::Profiles(screens::profiles::Msg::Loaded(Ok(Vec::new()))),
    );
    assert!(m.profiles.error.is_none());
    assert!(
        update(&mut m, tick("00000000000000aa")).is_empty(),
        "once loaded, a re-send fetches nothing"
    );
}

#[test]
fn an_unreachable_daemon_is_retried_not_treated_as_a_sign_out() {
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = model_at(&daemon);
    let down = Failure::local("Cannot reach the daemon", Some("refused".to_owned()));
    assert!(update(&mut m, Msg::SessionChecked(Err(down))).is_empty());
    assert!(matches!(m.session, Session::Unreachable { .. }));
    assert!(
        update(&mut m, Msg::Tick).is_empty(),
        "not before the interval"
    );
    if let Session::Unreachable { since, .. } = &mut m.session {
        *since -= RETRY_INTERVAL;
    }
    testing::run(update(&mut m, Msg::Tick));
    assert_eq!(daemon.lines(), CHECK, "asks again");
    assert!(matches!(m.session, Session::Checking));

    // `r` asks at once; typing is not a password.
    update(
        &mut m,
        Msg::SessionChecked(Err(Failure::local("down", None))),
    );
    assert!(update(&mut m, Msg::Key(testing::key(KeyCode::Char('x')))).is_empty());
    testing::run(update(&mut m, Msg::Key(testing::key(KeyCode::Char('r')))));
    assert_eq!(daemon.lines(), [CHECK, CHECK].concat(), "`r` asks again");
}

#[test]
fn a_refused_session_check_is_not_asked_again_unprompted() {
    for (slug, refusal) in [
        ("insufficient-scope", Refusal::Scope),
        ("about:blank", Refusal::Forbidden),
    ] {
        let mut m = model();
        let refused = Failure {
            status: Some(403),
            slug: Some(slug.to_owned()),
            ..Failure::local("Forbidden", None)
        };
        update(&mut m, Msg::SessionChecked(Err(refused)));
        let Session::Unreachable { since, refused, .. } = &mut m.session else {
            panic!("{slug}: {:?}", m.session);
        };
        assert_eq!(*refused, Some(refusal), "{slug}");
        *since -= RETRY_INTERVAL;
        assert!(
            update(&mut m, Msg::Tick).is_empty(),
            "{slug}: no retry loop"
        );
        assert_eq!(
            update(&mut m, Msg::Key(testing::key(KeyCode::Char('r')))).len(),
            1,
            "{slug}: `r` still asks"
        );
    }
}

#[test]
fn a_minted_token_is_revoked_whatever_state_the_session_is_in() {
    // Quit while the new session is still being described.
    let daemon = testing::Recorder::start("204 No Content", "");
    let mut m = model();
    update(
        &mut m,
        Msg::SignedIn(daemon.api().with_token("tds_1").unwrap()),
    );
    assert!(matches!(m.session, Session::Checking));
    testing::run(update(&mut m, Msg::Quit));
    assert!(!m.quit);
    assert_eq!(
        daemon.requests(),
        [testing::Request {
            line: REVOKE.to_owned(),
            bearer: Some("tds_1".to_owned()),
        }],
        "revoked, not orphaned"
    );

    // Signing in again revokes the first token before replacing it.
    let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
    let mut m = model();
    let first = daemon.api().with_token("tds_1").unwrap();
    update(&mut m, Msg::SignedIn(first.clone()));
    let effects = update(&mut m, Msg::SignedIn(first.with_token("tds_2").unwrap()));
    testing::run(effects);
    let sent: Vec<_> = daemon
        .requests()
        .into_iter()
        .map(|r| (r.line, r.bearer.unwrap_or_default()))
        .collect();
    let expected: Vec<_> = [(REVOKE, "tds_1"), (CHECK[0], "tds_2"), (CHECK[1], "tds_2")]
        .into_iter()
        .map(|(line, bearer)| (line.to_owned(), bearer.to_owned()))
        .collect();
    assert_eq!(sent, expected, "revoke the old, describe the new");
    assert_eq!(m.api.epoch, 2);
}

#[test]
fn the_reload_command_asks_first_and_a_sign_out_closes_open_dialogs() {
    let mut m = signed_in(false);
    m.tab = Tab::Torrents;
    assert!(run_command(&mut m, "reload").is_empty(), "nothing sent yet");
    assert_eq!(m.tab, Tab::Dashboard);
    assert!(
        m.dashboard.confirm_reload.is_some(),
        "the same confirm `R` opens"
    );

    refused(&mut m);
    assert!(
        m.dashboard.confirm_reload.is_none(),
        "stale dialogs are gone"
    );
}

#[test]
fn a_stale_401_does_not_sign_out_a_credential_that_still_works() {
    let mut m = model();
    update(&mut m, Msg::SignedIn(testing::api()));
    update(
        &mut m,
        Msg::SessionChecked(Ok((testing::server(false, false), principal("session")))),
    );
    // A 401 answering a request made before this sign-in.
    update(&mut m, Msg::SignedOut(unauthorized()));
    update(
        &mut m,
        Msg::SessionChecked(Ok((testing::server(false, false), principal("session")))),
    );
    assert!(
        matches!(m.session, Session::SignedIn { .. }),
        "still signed in"
    );
    assert!(m.minted, "and the live token is still owed a revocation");
}

#[test]
fn quitting_during_a_sign_in_revokes_the_token_it_mints() {
    let daemon = testing::Recorder::start("204 No Content", "");
    let mut m = model_at(&daemon);
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    m.login.busy = true;
    let effects = update(&mut m, Msg::Quit);
    assert!(!m.quit, "waits for the sign-in");
    let msgs = testing::run(effects);
    assert!(
        matches!(&msgs[..], [Msg::Toast(t)] if t.text.starts_with("finishing sign-in")),
        "says so: {msgs:?}"
    );
    let effects = update(
        &mut m,
        Msg::Login(screens::login::Msg::Answered(Ok("tds_late".into()))),
    );
    assert!(!m.quit);
    let msgs = testing::run(effects);
    assert_eq!(
        daemon.requests(),
        [testing::Request {
            line: REVOKE.to_owned(),
            bearer: Some("tds_late".to_owned()),
        }],
        "revokes what it minted"
    );
    assert!(
        matches!(msgs[..], [Msg::Exit(None)]),
        "then leaves: {msgs:?}"
    );

    // A second quit leaves at once.
    let mut m = model();
    m.login.busy = true;
    update(&mut m, Msg::Quit);
    update(&mut m, Msg::Quit);
    assert!(m.quit);
}

#[test]
fn quitting_between_the_sign_in_answer_and_signed_in_revokes_the_new_token() {
    let daemon = testing::Recorder::start("204 No Content", "");
    let mut m = model_at(&daemon);
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    m.login.busy = true;
    // The daemon answered; `SignedIn` is on its way but not yet applied.
    let msgs = testing::run(update(
        &mut m,
        Msg::Login(screens::login::Msg::Answered(Ok("tds_gap".into()))),
    ));
    let [Msg::SignedIn(api)] = &msgs[..] else {
        panic!("SignedIn on its way: {msgs:?}");
    };
    assert!(m.login.busy, "a token is on its way");

    let effects = update(&mut m, Msg::Quit);
    assert!(!m.quit, "waits for the token on its way");
    testing::run(effects);
    let msgs = testing::run(update(&mut m, Msg::SignedIn(api.clone())));
    assert_eq!(
        daemon.requests(),
        [testing::Request {
            line: REVOKE.to_owned(),
            bearer: Some("tds_gap".to_owned()),
        }],
        "revokes the new token and describes nothing"
    );
    assert!(
        matches!(msgs[..], [Msg::Exit(None)]),
        "then leaves: {msgs:?}"
    );
    assert!(!m.login.busy);
}

#[test]
fn the_first_check_asks_for_a_password_without_calling_it_an_error() {
    let mut m = model();
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    assert!(matches!(m.session, Session::SignedOut));
    assert_eq!(m.login.error, None);
}

#[test]
fn keys_during_a_recheck_reach_nothing_and_do_not_quit() {
    let mut m = signed_in(false);
    update(&mut m, Msg::SignedOut(unauthorized()));
    assert!(matches!(m.session, Session::Checking));
    for code in [KeyCode::Char('q'), KeyCode::Esc] {
        assert!(update(&mut m, Msg::Key(testing::key(code))).is_empty());
    }
    assert!(!m.quit && !m.quitting);
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    // A static token: nothing to revoke, so it leaves at once.
    assert!(update(&mut m, Msg::Key(ctrl_c)).is_empty());
    assert!(m.quit, "Ctrl-C still quits");
}

#[test]
fn a_second_esc_during_a_sign_in_quits_at_once() {
    let mut m = model();
    update(&mut m, Msg::SessionChecked(Err(unauthorized())));
    m.login.busy = true;
    update(&mut m, Msg::Key(testing::key(KeyCode::Esc)));
    assert!(!m.quit);
    update(&mut m, Msg::Key(testing::key(KeyCode::Esc)));
    assert!(m.quit);
}

#[test]
fn keys_while_checking_do_not_type_into_a_hidden_password() {
    let mut m = model();
    assert!(matches!(m.session, Session::Checking));
    update(&mut m, Msg::Key(testing::key(KeyCode::Char('r'))));
    assert!(m.login.password.value().is_empty());
    assert!(update(&mut m, Msg::Key(testing::key(KeyCode::Enter))).is_empty());
    update(&mut m, Msg::Key(testing::key(KeyCode::Char('q'))));
    assert!(m.quit);
}

impl Msg {
    fn to_string_kind(&self) -> &'static str {
        match self {
            Msg::SignedOut(_) => "SignedOut",
            Msg::Toast(_) => "Toast",
            _ => "other",
        }
    }
}
