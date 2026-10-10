//! Plans: the pool's changes to payload on disk — relocating a torrent,
//! deleting orphaned files — each created as a `draft` that touches
//! nothing, inspected step by step, and applied only with consent. A plan
//! that deletes data applies only once its confirm token is typed back.
//!
//! Creating and applying need `[pool] allow_mutations`; listing, inspecting
//! and discarding do not.

use std::cell::Cell;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Clear;
use ratatui::widgets::HighlightSpacing;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::TableState;
use ratatui::widgets::Wrap;
use ratatui::Frame;
use tui_input::backend::crossterm::EventHandler as _;
use tui_input::Input;

use super::hints;
use super::mutations_allowed;
use super::refresh_limit;
use super::scroll;
use super::signed_out;
use super::strong;
use super::title;
use super::when;
use super::wrap;
use super::Motion;
use super::MUTATIONS_OFF;
use crate::api::generated::ListPlansParams;
use crate::api::types;
use crate::api::Failure;
use crate::app::failed;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Toast;
use crate::app::ToastKind;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::centered;
use crate::ui::widgets::key_hints;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;
use crate::ui::widgets::Paged;

/// The filters `F` cycles through, after "all".
const FILTERS: [types::Status4ee43c98; 5] = [
    types::Status4ee43c98::Draft,
    types::Status4ee43c98::Applying,
    types::Status4ee43c98::Applied,
    types::Status4ee43c98::Failed,
    types::Status4ee43c98::Cancelled,
];

#[derive(Debug, Default)]
pub struct State {
    /// Only plans with this status; `None` for all.
    pub filter: Option<types::Status4ee43c98>,
    pub list: Paged<types::PlanSummary>,
    pub selected: usize,
    pub offset: Cell<usize>,
    /// The plan to select once the first page arrives.
    pub reselect: Option<i64>,
    /// The plan open with its steps.
    pub detail: Option<Detail>,
    pub form: Option<Form>,
    pub confirm: Option<Pending>,
    /// The plan being applied.
    pub applying: Option<i64>,
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
    pub plan: Option<types::Plan>,
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

/// What a new plan's form starts with, from what the other views show.
#[derive(Clone, Debug, Default)]
pub struct Prefill {
    pub infohash: Option<String>,
    pub root_id: Option<i64>,
    pub prefix: String,
}

/// The create-plan form.
#[derive(Debug)]
pub struct Form {
    pub kind: types::PlanKind,
    /// `0` is the kind; `1..` the fields.
    pub focus: usize,
    pub fields: Vec<Field>,
    pub error: Option<String>,
    pub sending: bool,
    prefill: Prefill,
}

#[derive(Debug)]
pub struct Field {
    pub label: &'static str,
    pub input: Input,
    pub error: Option<String>,
}

impl Field {
    fn new(label: &'static str, value: String) -> Self {
        Self {
            label,
            input: Input::new(value),
            error: None,
        }
    }
}

impl Form {
    fn new(kind: types::PlanKind, prefill: Prefill) -> Self {
        let root = prefill.root_id.map(|r| r.to_string()).unwrap_or_default();
        let fields = match kind {
            types::PlanKind::Relocate => vec![
                Field::new("infohash", prefill.infohash.clone().unwrap_or_default()),
                Field::new("to root id", root),
                Field::new("to path", String::new()),
            ],
            types::PlanKind::DeleteOrphans => vec![
                Field::new("root id", root),
                Field::new("under path", prefill.prefix.clone()),
            ],
        };
        Self {
            kind,
            focus: 1,
            fields,
            error: None,
            sending: false,
            prefill,
        }
    }

    /// The request the form describes, or each field's complaint.
    fn request(&mut self) -> Option<types::CreatePlanRequest> {
        for field in &mut self.fields {
            field.error = None;
        }
        self.error = None;
        let value = |i: usize| self.fields[i].input.value().trim().to_owned();
        let root = |text: String| text.parse::<i64>().ok().filter(|id| *id >= 0);
        match self.kind {
            types::PlanKind::Relocate => {
                let (infohash, dest_root, dest_rel) = (value(0), root(value(1)), value(2));
                let hex = infohash.len() == 40 && infohash.chars().all(|c| c.is_ascii_hexdigit());
                if !hex {
                    self.fields[0].error = Some("40 hex digits".to_owned());
                }
                if dest_root.is_none() {
                    self.fields[1].error = Some("a root id, as the overview lists it".to_owned());
                }
                if dest_rel.is_empty() {
                    self.fields[2].error = Some("a directory under the root".to_owned());
                }
                let dest_root_id = dest_root.filter(|_| hex && !dest_rel.is_empty())?;
                Some(types::CreatePlanRequest::CreatePlanRequestVariant0(
                    Box::new(types::CreatePlanRequestVariant0 {
                        kind: types::CreatePlanRequestVariant0kind::Relocate,
                        infohash: infohash.to_ascii_lowercase(),
                        dest_root_id,
                        dest_rel,
                    }),
                ))
            }
            types::PlanKind::DeleteOrphans => {
                let Some(root_id) = root(value(0)) else {
                    self.fields[0].error = Some("a root id, as the overview lists it".to_owned());
                    return None;
                };
                Some(types::CreatePlanRequest::CreatePlanRequestVariant1(
                    Box::new(types::CreatePlanRequestVariant1 {
                        kind: types::CreatePlanRequestVariant1kind::DeleteOrphans,
                        root_id,
                        prefix: value(1),
                    }),
                ))
            }
        }
    }

    /// Put a refusal next to the field it is about, where that is clear.
    fn refused(&mut self, failure: &Failure) {
        let text = failure.message();
        let field = if failure.is("root-not-found") {
            Some(if self.kind == types::PlanKind::Relocate {
                1
            } else {
                0
            })
        } else if failure.is("validation-failed") {
            let detail = failure.detail.as_deref().unwrap_or_default();
            self.fields.iter().position(|f| match f.label {
                "infohash" => detail.contains("infohash"),
                "to root id" | "root id" => detail.contains("root_id"),
                "to path" => detail.contains("dest_rel"),
                "under path" => detail.contains("prefix"),
                _ => false,
            })
        } else {
            None
        };
        match field {
            Some(i) => self.fields[i].error = Some(text),
            None if failure.is("mutations-disabled") => self.error = Some(MUTATIONS_OFF.to_owned()),
            None => self.error = Some(text),
        }
    }
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
        let limit = refresh_limit(state.list.items.len());
        effects.extend(reload(state, ctx, limit));
    }
    if let Some(detail) = state.detail.as_mut() {
        if !detail.loading {
            effects.push(load_detail(detail, ctx));
        }
    }
    effects
}

fn reload(state: &mut State, ctx: &Ctx<'_>, limit: Option<i64>) -> Vec<Effect> {
    let generation = state.list.reload();
    vec![fetch(
        ctx,
        state.filter.clone(),
        None,
        limit,
        generation,
        true,
    )]
}

fn more(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if !state.list.wants_more(state.selected) {
        return Vec::new();
    }
    match state.list.begin_more() {
        Some((cursor, generation)) => {
            vec![fetch(
                ctx,
                state.filter.clone(),
                Some(cursor),
                None,
                generation,
                false,
            )]
        }
        None => Vec::new(),
    }
}

fn fetch(
    ctx: &Ctx<'_>,
    filter: Option<types::Status4ee43c98>,
    cursor: Option<String>,
    limit: Option<i64>,
    generation: u64,
    first: bool,
) -> Effect {
    let api = ctx.api.clone();
    Effect::new(async move {
        let params = ListPlansParams {
            status: filter,
            cursor,
            limit,
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

fn open(state: &mut State, id: i64, then_apply: bool, ctx: &Ctx<'_>) -> Vec<Effect> {
    let mut detail = Detail {
        id,
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
            if generation != state.list.generation {
                return Vec::new();
            }
            state
                .list
                .receive(generation, first, page.items, page.next_cursor);
            if first {
                if let Some(id) = state.reselect.take() {
                    if let Some(at) = state.list.items.iter().position(|p| p.id == id) {
                        state.selected = at;
                    }
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
            state.list.fail(generation, failure.message());
            signed_out(&failure)
        }
        Msg::Move(motion) => match state.detail.as_mut() {
            Some(detail) => {
                let len = detail.plan.as_ref().map_or(0, |p| p.steps.len());
                detail.selected = motion.apply(detail.selected, len);
                Vec::new()
            }
            None => {
                state.selected = motion.apply(state.selected, state.list.items.len());
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
            state.list.items.clear();
            state.list.next_cursor = None;
            state.selected = 0;
            state.offset.set(0);
            state.reselect = None;
            reload(state, ctx, None)
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
                    detail.selected = detail.selected.min(plan.steps.len().saturating_sub(1));
                    detail.plan = Some(plan);
                    if std::mem::take(&mut detail.then_apply) {
                        return ask_apply(state, ctx);
                    }
                    Vec::new()
                }
                Err(failure) => {
                    detail.then_apply = false;
                    detail.error = Some(failure.message());
                    signed_out(&failure)
                }
            }
        }
        Msg::AskCreate(_) if !mutations_allowed(ctx) => {
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
                steps(plan.steps.len())
            ));
            state.detail = Some(Detail {
                id: plan.id,
                plan: Some(plan),
                ..Detail::default()
            });
            let mut effects = vec![Effect::toast(toast)];
            effects.extend(reload(state, ctx, refresh_limit(state.list.items.len())));
            effects
        }
        Msg::Created(Err(failure)) => {
            let Some(form) = state.form.as_mut() else {
                return Vec::new();
            };
            form.sending = false;
            form.refused(&failure);
            signed_out(&failure)
        }
        Msg::AskApply | Msg::AskDiscard if state.applying.is_some() => {
            vec![Effect::toast(Toast::info(
                "a plan is being applied — wait for it to finish",
            ))]
        }
        Msg::AskApply if !mutations_allowed(ctx) => {
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
                effects.extend(reload(state, ctx, refresh_limit(state.list.items.len())));
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
    if !mutations_allowed(ctx) {
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
    let pending = plan
        .steps
        .iter()
        .filter(|s| s.status != types::StepStatus::Done)
        .count();
    let title = format!("Apply plan #{}", plan.id);
    let confirm = match &plan.confirm_token {
        Some(token) => {
            let deletes = plan
                .steps
                .iter()
                .filter(|s| {
                    s.op == types::StepOp::DeleteFile && s.status != types::StepStatus::Done
                })
                .count();
            Confirm::new(
                title,
                format!(
                    "This moves {deletes} files to the pool's trash; they can be restored from \
                     .torrentd-trash/{}-{}. The daemon waits until every step has run.",
                    plan.id,
                    plan.created_at.0.unix_timestamp()
                ),
            )
            .typed(token.clone())
        }
        None => Confirm::new(
            title,
            format!(
                "Run its {} still to do ({})? A cross-device move can take minutes; each step \
                 is journalled first.",
                steps(pending),
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

fn form_key(state: &mut State, key: KeyEvent, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(form) = state.form.as_mut() else {
        return Vec::new();
    };
    if form.sending {
        return Vec::new();
    }
    let last = form.fields.len();
    match key.code {
        KeyCode::Esc => state.form = None,
        KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % (last + 1),
        KeyCode::BackTab | KeyCode::Up => form.focus = (form.focus + last) % (last + 1),
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if form.focus == 0 => {
            let kind = match form.kind {
                types::PlanKind::Relocate => types::PlanKind::DeleteOrphans,
                types::PlanKind::DeleteOrphans => types::PlanKind::Relocate,
            };
            *form = Form::new(kind, form.prefill.clone());
            form.focus = 0;
        }
        KeyCode::Enter => {
            let Some(body) = form.request() else {
                return Vec::new();
            };
            form.sending = true;
            let api = ctx.api.clone();
            return vec![Effect::new(async move {
                let result = crate::api::call(api.client.create_plan(&body)).await;
                wrap(super::Msg::Plans(Msg::Created(result)))
            })];
        }
        _ if form.focus > 0 => {
            let field = &mut form.fields[form.focus - 1];
            field.input.handle_event(&crossterm::event::Event::Key(key));
            field.error = None;
        }
        _ => {}
    }
    Vec::new()
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    match &state.detail {
        Some(detail) => draw_detail(state, detail, ctx, frame, area),
        None => draw_list(state, ctx, frame, area),
    }
}

/// The form and the confirmations, over the whole screen.
pub fn overlay(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    if let Some(form) = &state.form {
        draw_form(form, ctx, frame, area);
    }
    match &state.confirm {
        Some(Pending::Apply { confirm, .. } | Pending::Discard { confirm, .. }) => {
            confirm.view(frame, area, ctx.theme)
        }
        None => {}
    }
}

/// The keys a plan view offers, or why creating and applying are not
/// among them.
fn plan_hints<'a>(theme: &Theme, ctx: &Ctx<'_>, in_detail: bool) -> Line<'a> {
    let mut keys = if in_detail {
        vec![("Esc", "back")]
    } else {
        vec![("Enter", "open"), ("F", "filter")]
    };
    if mutations_allowed(ctx) {
        keys.extend([("c", "create"), ("x", "apply")]);
    }
    keys.push(("X", "discard"));
    let mut line = hints(theme, &keys);
    if !mutations_allowed(ctx) {
        line.spans.push(Span::styled(
            " ‖ read-only: allow_mutations is off ",
            theme.fg(Tone::Warn),
        ));
    }
    line
}

fn draw_list(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let name = format!(
        "plans · {}",
        state
            .filter
            .as_ref()
            .map_or("all".to_owned(), |f| f.to_string())
    );
    let block = panel(
        theme,
        title(
            theme,
            name,
            state.list.loading,
            state.list.error.as_deref(),
            ctx.tick,
        ),
        true,
    )
    .title_bottom(plan_hints(theme, ctx, false));
    if state.list.items.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if !state.list.loading {
            placeholder(frame, inner, theme, "No plans.", Tone::Muted);
        }
        return;
    }
    let rows = state.list.items.iter().map(|p| {
        Row::new(vec![
            Line::from(format!("#{}", p.id)),
            Line::from(p.kind.to_string()),
            Line::from(state_span(theme, &p.status.to_string())),
            Line::from(when(p.created_at.0)),
            Line::from(Span::styled(
                p.applied_at.map_or("—".to_owned(), |at| when(at.0)),
                theme.fg(if p.applied_at.is_some() {
                    Tone::Plain
                } else {
                    Tone::Muted
                }),
            )),
        ])
    });
    let widths = [
        Constraint::Length(7),
        Constraint::Length(15),
        Constraint::Length(13),
        Constraint::Length(17),
        Constraint::Fill(1),
    ];
    let visible = block.inner(area).height.saturating_sub(1) as usize;
    let offset = scroll(&state.offset, state.selected, visible);
    let mut table_state = TableState::default()
        .with_offset(offset)
        .with_selected(Some(state.selected));
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .header(
                Row::new(["id", "kind", "status", "created (UTC)", "applied"])
                    .style(theme.fg(Tone::Muted)),
            )
            .row_highlight_style(theme.selected())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always)
            .block(block),
        area,
        &mut table_state,
    );
}

fn draw_detail(state: &State, detail: &Detail, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let applying = state.applying == Some(detail.id);
    let Some(plan) = &detail.plan else {
        let block = panel(
            theme,
            title(
                theme,
                format!("plan #{}", detail.id),
                detail.loading,
                detail.error.as_deref(),
                ctx.tick,
            ),
            true,
        )
        .title_bottom(plan_hints(theme, ctx, true));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if let Some(error) = &detail.error {
            placeholder(frame, inner, theme, &format!("✖ {error}"), Tone::Bad);
        }
        return;
    };

    let label = |text: &str| Span::styled(format!("{text:>13}  "), theme.fg(Tone::Muted));
    let mut lines = vec![
        Line::from(vec![
            label("plan"),
            strong(theme, format!("#{}", plan.id), Tone::Accent),
            Span::raw(format!("  {}  ", plan.kind)),
            state_span(theme, &plan.status.to_string()),
            Span::styled(
                format!("  {}", steps(plan.steps.len())),
                theme.fg(Tone::Muted),
            ),
        ]),
        Line::from(vec![
            label("created"),
            Span::raw(format!("{} UTC", when(plan.created_at.0))),
            Span::styled("   applied ", theme.fg(Tone::Muted)),
            Span::raw(
                plan.applied_at
                    .map_or("—".to_owned(), |at| format!("{} UTC", when(at.0))),
            ),
        ]),
    ];
    if let Some(token) = &plan.confirm_token {
        lines.push(Line::from(vec![
            label("confirm token"),
            strong(theme, token.clone(), Tone::Bad),
            Span::styled(
                "  deletes data: applying asks for this, typed back",
                theme.fg(Tone::Muted),
            ),
        ]));
    }
    if applying {
        lines.push(Line::from(vec![
            label("applying"),
            Span::styled(
                format!(
                    "{} running every step — this can take minutes",
                    spinner(ctx.tick)
                ),
                theme.fg(Tone::Accent),
            ),
        ]));
    } else if let Some(o) = &detail.outcome {
        lines.push(Line::from(vec![
            label("last apply"),
            state_span(theme, &o.status.to_string()),
            Span::raw(format!(" · {} done · ", o.done)),
            Span::styled(
                format!("{} failed", o.failed),
                theme.fg(if o.failed > 0 { Tone::Bad } else { Tone::Muted }),
            ),
            Span::raw(format!(" · {} skipped", o.skipped)),
        ]));
    }
    let [head, steps_area] = Layout::vertical([
        Constraint::Length(lines.len() as u16 + 2),
        Constraint::Fill(1),
    ])
    .areas(area);
    frame.render_widget(
        Paragraph::new(lines).block(panel(
            theme,
            title(
                theme,
                format!("plan #{}", plan.id),
                detail.loading,
                detail.error.as_deref(),
                ctx.tick,
            ),
            false,
        )),
        head,
    );

    let rows = plan.steps.iter().map(|s| {
        let path = match &s.dst {
            Some(dst) => format!("{} → {dst}", s.src),
            None => s.src.clone(),
        };
        let mut place = vec![Line::from(path)];
        if let Some(error) = &s.error {
            place.push(Line::from(Span::styled(
                format!("✖ {error}"),
                theme.fg(Tone::Bad),
            )));
        }
        let height = place.len() as u16;
        Row::new(vec![
            ratatui::text::Text::from(Line::from(s.seq.to_string()).right_aligned()),
            ratatui::text::Text::from(s.op.to_string()),
            ratatui::text::Text::from(Line::from(state_span(theme, &s.status.to_string()))),
            ratatui::text::Text::from(place),
        ])
        .height(height)
    });
    let widths = [
        Constraint::Length(5),
        Constraint::Length(13),
        Constraint::Length(14),
        Constraint::Fill(1),
    ];
    let block = panel(theme, " steps ", true).title_bottom(plan_hints(theme, ctx, true));
    let visible = block.inner(steps_area).height.saturating_sub(1) as usize;
    let offset = scroll(&detail.offset, detail.selected, visible);
    let mut table_state = TableState::default()
        .with_offset(offset)
        .with_selected(Some(detail.selected));
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .header(Row::new(["seq", "op", "status", "path"]).style(theme.fg(Tone::Muted)))
            .row_highlight_style(theme.selected())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always)
            .block(block),
        steps_area,
        &mut table_state,
    );
}

fn draw_form(form: &Form, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let marker = |focused: bool| if focused { "› " } else { "  " };
    let choice = |kind: types::PlanKind| {
        let on = form.kind == kind;
        Span::styled(
            format!("{} {kind}  ", if on { "(•)" } else { "( )" }),
            if on {
                theme.fg(Tone::Accent)
            } else {
                theme.fg(Tone::Muted)
            },
        )
    };
    let mut lines = vec![Line::from(vec![
        Span::raw(marker(form.focus == 0)),
        Span::styled(format!("{:>11}  ", "kind"), theme.fg(Tone::Muted)),
        choice(types::PlanKind::Relocate),
        choice(types::PlanKind::DeleteOrphans),
    ])];
    lines.push(Line::from(Span::styled(
        match form.kind {
            types::PlanKind::Relocate => {
                "               Move a torrent's payload to a directory under a root."
            }
            types::PlanKind::DeleteOrphans => {
                "               Delete the files no library torrent claims, under a path."
            }
        },
        theme.fg(Tone::Muted),
    )));
    lines.push(Line::from(""));
    for (i, field) in form.fields.iter().enumerate() {
        let focused = form.focus == i + 1;
        let cursor = if focused { "▏" } else { "" };
        lines.push(Line::from(vec![
            Span::raw(marker(focused)),
            Span::styled(format!("{:>11}  ", field.label), theme.fg(Tone::Muted)),
            Span::styled(
                format!("{}{cursor}", field.input.value()),
                theme.fg(if focused { Tone::Accent } else { Tone::Plain }),
            ),
        ]));
        if let Some(error) = &field.error {
            lines.push(Line::from(Span::styled(
                format!("               ✖ {error}"),
                theme.fg(Tone::Bad),
            )));
        }
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  ✖ {error}"),
            theme.fg(Tone::Bad),
        )));
    }
    lines.push(Line::from(""));
    let mut last = if form.sending {
        Line::from(Span::styled(
            format!("{} drafting the plan…", spinner(ctx.tick)),
            theme.fg(Tone::Accent),
        ))
    } else {
        key_hints(
            theme,
            &[
                ("Tab/↑↓", "field"),
                ("←/→", "kind"),
                ("Enter", "draft plan"),
                ("Esc", "cancel"),
            ],
        )
    };
    last.spans.insert(0, Span::raw("  "));
    lines.push(last);
    let width = area.width.saturating_sub(4).min(80);
    // A border each side, and a row for a long error to wrap into.
    let height = (lines.len() as u16 + 3).min(area.height);
    let rect = centered(area, width, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(
                theme,
                " New plan — a draft; nothing changes until applied ",
                true,
            )),
        rect,
    );
}
