//! Plans: the pool's changes to payload on disk — relocating a torrent,
//! deleting orphaned files — each created as a `draft` that touches
//! nothing, inspected step by step, and applied only with consent. A plan
//! that deletes data applies only once its confirm token is typed back.
//!
//! Creating and applying need `[pool] allow_mutations`; listing, inspecting
//! and discarding do not.

mod form;
mod view;

use std::cell::Cell;

use crossterm::event::KeyEvent;

use self::form::form_key;
pub use self::form::Form;
pub use self::form::Prefill;
pub use self::view::overlay;
pub use self::view::view;
use super::wrap;
use super::MUTATIONS_OFF;
use crate::api::generated::ListPlanStepsParams;
use crate::api::generated::ListPlansParams;
use crate::api::types;
use crate::api::Failure;
use crate::api::PlanStatus;
use crate::screens::contract::failed;
use crate::screens::contract::sign_out_on_401;
use crate::screens::contract::Ctx;
use crate::screens::contract::Effect;
use crate::screens::contract::Toast;
use crate::screens::contract::ToastKind;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;
use crate::ui::widgets::Motion;
use crate::ui::widgets::PageRequest;
use crate::ui::widgets::Paged;
use crate::ui::widgets::Received;

/// The filters `F` cycles through, after "all".
const FILTERS: [PlanStatus; 5] = [
    PlanStatus::Draft,
    PlanStatus::Applying,
    PlanStatus::Applied,
    PlanStatus::Failed,
    PlanStatus::Cancelled,
];

#[derive(Debug, Default)]
pub struct State {
    /// Only plans with this status; `None` for all.
    pub filter: Option<PlanStatus>,
    pub list: Paged<types::PlanSummary>,
    pub selected: usize,
    pub offset: Cell<usize>,
    /// The plan to select once a reload settles.
    pub reselect: Option<i64>,
    /// The plan open with its steps.
    pub detail: Option<Detail>,
    pub form: Option<Form>,
    pub confirm: Option<Pending>,
    /// The plan being applied.
    pub applying: Option<i64>,
    /// How many plans have been opened, so a page of steps answering one
    /// opening is not taken by the next — even of the same plan.
    pub opened: u64,
}

impl State {
    /// Whether a form or a confirmation has the keyboard.
    pub fn capturing(&self) -> bool {
        self.form.is_some() || self.confirm.is_some()
    }

    fn selected_id(&self) -> Option<i64> {
        self.list.items.get(self.selected).map(|p| p.id)
    }
}

/// One plan, open.
#[derive(Debug, Default)]
pub struct Detail {
    pub id: i64,
    /// Which opening this is: see [`State::opened`].
    pub opening: u64,
    /// The plan, its `steps` moved into [`Detail::steps`].
    pub plan: Option<types::Plan>,
    /// The steps loaded so far: the plan's inline first page, then the pages
    /// after it from `GET /v1/pool/plans/{plan_id}/steps`.
    pub steps: Paged<types::PlanStep>,
    pub loading: bool,
    pub error: Option<String>,
    /// What the last apply of this plan reported.
    pub outcome: Option<types::ApplyOutcome>,
    /// Ask to apply as soon as the plan (and its token) is loaded.
    pub then_apply: bool,
    pub selected: usize,
    pub offset: Cell<usize>,
}

/// A decision waiting on the operator.
#[derive(Debug)]
pub enum Pending {
    Apply {
        id: i64,
        token: Option<String>,
        confirm: Confirm,
    },
    Discard {
        id: i64,
        confirm: Confirm,
    },
}

#[derive(Debug)]
pub enum Msg {
    Page {
        generation: u64,
        first: bool,
        result: Result<types::PlanPage, Failure>,
    },
    /// Move the list's selection, or the open plan's step.
    Move(Motion),
    CycleFilter,
    /// Open the selected plan.
    Open,
    /// Close the open plan.
    Back,
    DetailLoaded {
        id: i64,
        result: Result<types::Plan, Failure>,
    },
    /// A page of the open plan's steps.
    StepsPage {
        opening: u64,
        generation: u64,
        first: bool,
        result: Result<types::PlanStepPage, Failure>,
    },
    AskCreate(Prefill),
    /// A key for the form or the confirmation.
    Key(KeyEvent),
    Created(Result<types::Plan, Failure>),
    AskApply,
    Applied {
        id: i64,
        result: Result<types::ApplyOutcome, Failure>,
    },
    AskDiscard,
    Discarded {
        id: i64,
        result: Result<(), Failure>,
    },
}

/// Reload the list, keeping the selection on the same plan, and the open
/// plan.
pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    let mut effects = Vec::new();
    if !state.list.loading {
        state.reselect = state.selected_id();
        effects.extend(reload(state, ctx));
    }
    if let Some(detail) = state.detail.as_mut() {
        if !detail.loading {
            effects.push(load_detail(detail, ctx));
        }
    }
    effects
}

/// Re-read as many plans as are loaded (see [`Paged`]).
fn reload(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    let request = state.list.reload();
    vec![fetch(ctx, state.filter.clone(), request)]
}

fn more(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if !state.list.wants_more(state.selected) {
        return Vec::new();
    }
    match state.list.begin_more() {
        Some(request) => vec![fetch(ctx, state.filter.clone(), request)],
        None => Vec::new(),
    }
}

fn fetch(ctx: &Ctx<'_>, filter: Option<PlanStatus>, request: PageRequest) -> Effect {
    let api = ctx.api.clone();
    let PageRequest {
        cursor,
        limit,
        generation,
    } = request;
    Effect::new(async move {
        let first = cursor.is_none();
        let params = ListPlansParams {
            status: filter,
            cursor,
            limit: Some(limit as i64),
        };
        let result = crate::api::call(api.client.list_plans(params)).await;
        wrap(super::Msg::Plans(Msg::Page {
            generation,
            first,
            result,
        }))
    })
}

fn load_detail(detail: &mut Detail, ctx: &Ctx<'_>) -> Effect {
    detail.loading = true;
    let id = detail.id;
    let api = ctx.api.clone();
    Effect::new(async move {
        let result = crate::api::call(api.client.get_plan(id)).await;
        wrap(super::Msg::Plans(Msg::DetailLoaded { id, result }))
    })
}

/// Fetch `request`'s page of the open plan's steps.
fn fetch_steps(detail: &Detail, ctx: &Ctx<'_>, request: PageRequest) -> Effect {
    let (id, opening) = (detail.id, detail.opening);
    let api = ctx.api.clone();
    let PageRequest {
        cursor,
        limit,
        generation,
    } = request;
    Effect::new(async move {
        let first = cursor.is_none();
        let params = ListPlanStepsParams {
            cursor,
            limit: Some(limit as i64),
        };
        let result = crate::api::call(api.client.list_plan_steps(id, params)).await;
        wrap(super::Msg::Plans(Msg::StepsPage {
            opening,
            generation,
            first,
            result,
        }))
    })
}

/// The next page of the open plan's steps, when its selection nears the end
/// of what is loaded.
fn more_steps(detail: &mut Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    if !detail.steps.wants_more(detail.selected) {
        return Vec::new();
    }
    match detail.steps.begin_more() {
        Some(request) => vec![fetch_steps(detail, ctx, request)],
        None => Vec::new(),
    }
}

/// Show `plan` in `detail`. Its inline steps replace those loaded, unless
/// more than them were loaded: then the steps are re-read from the first, as
/// many as were loaded (see [`Paged`]), so a refresh keeps the selection
/// where it was.
fn show(detail: &mut Detail, mut plan: types::Plan, ctx: &Ctx<'_>) -> Vec<Effect> {
    let inline = std::mem::take(&mut plan.steps);
    let next = plan.steps_next_cursor.clone();
    detail.plan = Some(plan);
    let loaded = detail.steps.items.len();
    if loaded > inline.len() && detail.steps.loading {
        // Steps are already being read: restarting would bump the
        // generation and drop them, and a plan refreshed faster than its
        // steps re-read would never finish.
        return Vec::new();
    }
    let request = detail.steps.reload();
    if loaded > inline.len() {
        return vec![fetch_steps(detail, ctx, request)];
    }
    match detail.steps.receive(request.generation, true, inline, next) {
        Received::Stale => Vec::new(),
        Received::Continue(request) => vec![fetch_steps(detail, ctx, request)],
        Received::Settled => settle_steps(detail, ctx),
    }
}

/// After the open plan's steps changed: keep the selection in range, and
/// page on when it nears the end.
fn settle_steps(detail: &mut Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    detail.selected = detail
        .selected
        .min(detail.steps.items.len().saturating_sub(1));
    more_steps(detail, ctx)
}

fn open(state: &mut State, id: i64, then_apply: bool, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.opened += 1;
    let mut detail = Detail {
        id,
        opening: state.opened,
        then_apply,
        ..Detail::default()
    };
    let effect = load_detail(&mut detail, ctx);
    state.detail = Some(detail);
    vec![effect]
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match msg {
        Msg::Page {
            generation,
            first,
            result: Ok(page),
        } => {
            match state
                .list
                .receive(generation, first, page.items, page.next_cursor)
            {
                Received::Stale => return Vec::new(),
                Received::Continue(request) => {
                    return vec![fetch(ctx, state.filter.clone(), request)]
                }
                Received::Settled => {}
            }
            if let Some(id) = state.reselect.take() {
                if let Some(at) = state.list.items.iter().position(|p| p.id == id) {
                    state.selected = at;
                }
            }
            state.selected = state.selected.min(state.list.items.len().saturating_sub(1));
            more(state, ctx)
        }
        Msg::Page {
            generation,
            result: Err(failure),
            ..
        } => {
            if state.list.fail(generation, failure.message()) {
                // The reload will not settle: a later page must not snap
                // the selection back to where it began.
                state.reselect = None;
            }
            sign_out_on_401(&failure)
        }
        Msg::Move(motion) => match state.detail.as_mut() {
            Some(detail) => {
                detail.selected = motion.apply(detail.selected, detail.steps.items.len());
                more_steps(detail, ctx)
            }
            None => {
                state.selected = motion.apply(state.selected, state.list.items.len());
                if state.list.loading {
                    // A reload is in flight: keep what the operator chose.
                    if let Some(id) = state.selected_id() {
                        state.reselect = Some(id);
                    }
                }
                more(state, ctx)
            }
        },
        Msg::CycleFilter => {
            state.filter = match &state.filter {
                None => Some(FILTERS[0].clone()),
                Some(f) => FILTERS
                    .iter()
                    .position(|x| x == f)
                    .and_then(|at| FILTERS.get(at + 1))
                    .cloned(),
            };
            state.list.reset();
            state.selected = 0;
            state.offset.set(0);
            state.reselect = None;
            reload(state, ctx)
        }
        Msg::Open => match state.selected_id() {
            Some(id) => open(state, id, false, ctx),
            None => Vec::new(),
        },
        Msg::Back => {
            state.detail = None;
            Vec::new()
        }
        Msg::DetailLoaded { id, result } => {
            let Some(detail) = state.detail.as_mut().filter(|d| d.id == id) else {
                return Vec::new();
            };
            detail.loading = false;
            match result {
                Ok(plan) => {
                    detail.error = None;
                    let mut effects = show(detail, plan, ctx);
                    if std::mem::take(&mut detail.then_apply) {
                        effects.extend(ask_apply(state, ctx));
                    }
                    effects
                }
                Err(failure) => {
                    detail.then_apply = false;
                    detail.error = Some(failure.message());
                    sign_out_on_401(&failure)
                }
            }
        }
        Msg::StepsPage {
            opening,
            generation,
            first,
            result,
        } => {
            let Some(detail) = state.detail.as_mut().filter(|d| d.opening == opening) else {
                return Vec::new();
            };
            match result {
                Ok(page) => {
                    match detail
                        .steps
                        .receive(generation, first, page.items, page.next_cursor)
                    {
                        Received::Stale => Vec::new(),
                        Received::Continue(request) => vec![fetch_steps(detail, ctx, request)],
                        Received::Settled => settle_steps(detail, ctx),
                    }
                }
                Err(failure) => {
                    detail.steps.fail(generation, failure.message());
                    sign_out_on_401(&failure)
                }
            }
        }
        Msg::AskCreate(_) if !ctx.pool_mutations_allowed() => {
            vec![Effect::toast(Toast::info(MUTATIONS_OFF))]
        }
        Msg::AskCreate(prefill) => {
            state.form = Some(Form::new(types::PlanKind::Relocate, prefill));
            Vec::new()
        }
        Msg::Key(key) => {
            if state.confirm.is_some() {
                confirm_key(state, key, ctx)
            } else {
                form_key(state, key, ctx)
            }
        }
        Msg::Created(Ok(plan)) => {
            state.form = None;
            let toast = Toast::success(format!(
                "plan #{} drafted: {} — x applies it",
                plan.id,
                steps(count(plan.step_counts.total))
            ));
            state.opened += 1;
            let mut detail = Detail {
                id: plan.id,
                opening: state.opened,
                ..Detail::default()
            };
            let mut effects = vec![Effect::toast(toast)];
            effects.extend(show(&mut detail, plan, ctx));
            state.detail = Some(detail);
            effects.extend(reload(state, ctx));
            effects
        }
        Msg::Created(Err(failure)) => {
            let Some(form) = state.form.as_mut() else {
                return Vec::new();
            };
            form.sending = false;
            form.refused(&failure);
            sign_out_on_401(&failure)
        }
        Msg::AskApply | Msg::AskDiscard if state.applying.is_some() => {
            vec![Effect::toast(Toast::info(
                "a plan is being applied — wait for it to finish",
            ))]
        }
        Msg::AskApply if !ctx.pool_mutations_allowed() => {
            vec![Effect::toast(Toast::info(MUTATIONS_OFF))]
        }
        Msg::AskApply => match state.detail.as_mut() {
            Some(detail) if detail.plan.is_some() => ask_apply(state, ctx),
            Some(detail) => {
                detail.then_apply = true;
                Vec::new()
            }
            None => match state.selected_id() {
                Some(id) => open(state, id, true, ctx),
                None => Vec::new(),
            },
        },
        Msg::Applied { id, result } => {
            state.applying = None;
            let mut effects = match result {
                Ok(outcome) => {
                    let text = format!(
                        "plan #{id} {}: {} done, {} failed, {} skipped",
                        outcome.status, outcome.done, outcome.failed, outcome.skipped
                    );
                    let toast = if outcome.status == types::PlanStatus::Applied {
                        Toast::success(text)
                    } else {
                        Toast {
                            kind: ToastKind::Error,
                            text: format!("{text} — its steps say why; x retries"),
                            request_id: None,
                        }
                    };
                    if let Some(detail) = state.detail.as_mut().filter(|d| d.id == id) {
                        detail.outcome = Some(outcome);
                    }
                    vec![Effect::toast(toast)]
                }
                Err(failure) => vec![Effect::now(failed(
                    &format!("applying plan #{id}"),
                    failure,
                ))],
            };
            effects.extend(refresh(state, ctx));
            effects
        }
        Msg::AskDiscard => {
            let id = match &state.detail {
                Some(detail) => Some(detail.id),
                None => state.selected_id(),
            };
            if let Some(id) = id {
                state.confirm = Some(Pending::Discard {
                    id,
                    confirm: Confirm::new(
                        format!("Discard plan #{id}"),
                        "Remove the plan and its steps? Nothing on disk changes: discarding an \
                         applied plan does not undo it.",
                    ),
                });
            }
            Vec::new()
        }
        Msg::Discarded { id, result } => match result {
            Ok(()) => {
                if state.detail.as_ref().is_some_and(|d| d.id == id) {
                    state.detail = None;
                }
                let mut effects = vec![Effect::toast(Toast::success(format!(
                    "plan #{id} discarded"
                )))];
                effects.extend(reload(state, ctx));
                effects
            }
            Err(failure) => vec![Effect::now(failed(
                &format!("discarding plan #{id}"),
                failure,
            ))],
        },
    }
}

/// Ask to apply the open plan: typed back its token if it deletes data, a
/// yes otherwise.
fn ask_apply(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if !ctx.pool_mutations_allowed() {
        return vec![Effect::toast(Toast::info(MUTATIONS_OFF))];
    }
    let Some(plan) = state.detail.as_ref().and_then(|d| d.plan.as_ref()) else {
        return Vec::new();
    };
    if !matches!(
        plan.status,
        types::PlanStatus::Draft | types::PlanStatus::Failed
    ) {
        return vec![Effect::toast(Toast::info(format!(
            "plan #{} is {}: only a draft or failed plan can be applied",
            plan.id, plan.status
        )))];
    }
    // From the counts, not `plan.steps`: that holds only the plan's first page
    // of steps, and an apply runs all of them.
    let counts = &plan.step_counts;
    let pending = counts.total.saturating_sub(counts.done);
    let title = format!("Apply plan #{}", plan.id);
    let confirm = match &plan.confirm_token {
        // Only a `delete_orphans` plan carries a token, and its every step is
        // a `delete_file`, so each step still to do moves one file.
        Some(token) => Confirm::new(
            title,
            format!(
                "This moves {pending} files to the pool's trash; they can be restored from \
                 .torrentd-trash/{}-{}. The daemon waits until every step has run.",
                plan.id,
                plan.created_at.0.unix_timestamp()
            ),
        )
        .typed(token.clone()),
        None => Confirm::new(
            title,
            format!(
                "Run its {} still to do ({})? A cross-device move can take minutes; each step \
                 is journalled first.",
                steps(count(pending)),
                plan.kind
            ),
        ),
    };
    state.confirm = Some(Pending::Apply {
        id: plan.id,
        token: plan.confirm_token.clone(),
        confirm,
    });
    Vec::new()
}

/// `1 step`, `3 steps`.
fn steps(n: usize) -> String {
    if n == 1 {
        "1 step".to_owned()
    } else {
        format!("{n} steps")
    }
}

/// A step count from `step_counts`, for [`steps`]. The document declares
/// them unsigned; the generated type is `i64`, so a negative one reads as 0.
fn count(n: i64) -> usize {
    usize::try_from(n.max(0)).unwrap_or(usize::MAX)
}

fn confirm_key(state: &mut State, key: KeyEvent, ctx: &Ctx<'_>) -> Vec<Effect> {
    let decided = match state.confirm.as_mut() {
        Some(Pending::Apply { confirm, .. } | Pending::Discard { confirm, .. }) => {
            confirm.on_key(key)
        }
        None => return Vec::new(),
    };
    match decided {
        Confirmed::Pending => Vec::new(),
        Confirmed::No => {
            state.confirm = None;
            Vec::new()
        }
        Confirmed::Yes => {
            let api = ctx.api.clone();
            match state.confirm.take() {
                Some(Pending::Apply { id, token, .. }) => {
                    state.applying = Some(id);
                    vec![Effect::new(async move {
                        let body = types::ApplyRequest {
                            confirm_token: token,
                        };
                        let result =
                            crate::api::call_unbounded(api.client.apply_plan(id, &body)).await;
                        wrap(super::Msg::Plans(Msg::Applied { id, result }))
                    })]
                }
                Some(Pending::Discard { id, .. }) => vec![Effect::new(async move {
                    let result = crate::api::call(api.client.delete_plan(id)).await;
                    wrap(super::Msg::Plans(Msg::Discarded { id, result }))
                })],
                None => Vec::new(),
            }
        }
    }
}
