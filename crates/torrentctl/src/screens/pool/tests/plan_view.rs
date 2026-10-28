//! Plans: drafting, applying with consent, the step table, and refreshes.

use super::*;

#[test]
fn plans_open_and_close_and_a_stale_page_is_dropped() {
    let mut state = with_plans();
    assert_eq!(state.plans.list.items.len(), 3);
    let old = state.plans.list.generation;
    assert_eq!(press(&mut state, KeyCode::Char('F'), true), 1);
    assert!(matches!(
        state.plans.filter,
        Some(crate::api::PlanStatus::Draft)
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
fn a_failed_plan_list_refresh_does_not_snap_a_later_page_back() {
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
    let msg = plans_page(&state, true, wide_plans(0, 100, Some("p100")));
    send(&mut state, msg, true);
    state.plans.selected = 10;

    testing::with_ctx(Some(&server), |ctx| refresh(&mut state, ctx));
    assert_eq!(state.plans.reselect, Some(10));
    let generation = state.plans.list.generation;
    send(
        &mut state,
        Msg::Plans(plans::Msg::Page {
            generation,
            first: true,
            result: Err(problem(500, "internal", None)),
        }),
        true,
    );
    assert!(!state.plans.list.loading);
    assert!(
        state.plans.reselect.is_none(),
        "the failed refresh will not settle"
    );

    // The operator scrolls on, to the end: the next page is fetched.
    state.plans.selected = 98;
    assert_eq!(press(&mut state, KeyCode::Char('j'), true), 1);
    let msg = plans_page(&state, false, wide_plans(100, 50, None));
    send(&mut state, msg, true);
    assert_eq!(state.plans.list.items.len(), 150);
    assert_eq!(
        state.plans.list.items[state.plans.selected].id, 99,
        "not snapped back to the plan selected when the failed refresh began"
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
