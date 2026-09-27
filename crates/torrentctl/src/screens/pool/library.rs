//! Every `.torrent` the pool read from its library, with where it stands
//! against the payload on disk. Rows are marked with `space` for the batch
//! actions — verifying and adopting — which otherwise act on the selected
//! row alone.

use std::cell::Cell;
use std::collections::BTreeSet;

use crossterm::event::KeyEvent;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::HighlightSpacing;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::TableState;
use ratatui::widgets::Wrap;
use ratatui::Frame;

use super::hints;
use super::refresh_limit;
use super::scroll;
use super::signed_out;
use super::strong;
use super::title;
use super::wrap;
use super::Motion;
use super::MAX_BATCH;
use crate::api::generated::ListPoolTorrentsParams;
use crate::api::types;
use crate::api::Failure;
use crate::app::failed;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Toast;
use crate::fmt;
use crate::theme::Tone;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;
use crate::ui::widgets::Paged;

/// The filters `F` cycles through, after "all".
const FILTERS: [types::State; 6] = [
    types::State::Missing,
    types::State::Partial,
    types::State::Matched,
    types::State::Adopted,
    types::State::Drifted,
    types::State::Overlap,
];

#[derive(Debug, Default)]
pub struct State {
    /// Only torrents in this adoption state; `None` for all.
    pub filter: Option<types::State>,
    pub items: Paged<types::PoolTorrent>,
    pub selected: usize,
    pub offset: Cell<usize>,
    /// Marked infohashes. Marks outlive a filter change and a refresh.
    pub marks: BTreeSet<String>,
    /// The verification asked about, with the infohashes it would send.
    pub confirm_verify: Option<(Confirm, Vec<String>)>,
    pub verifying: bool,
    /// What the last verification request started and skipped.
    pub verify: Option<types::VerifyResult>,
    /// The infohash to select once the first page arrives.
    pub reselect: Option<String>,
}

impl State {
    /// What a batch action acts on: the marked rows, or else the selected
    /// one.
    pub fn targets(&self) -> Vec<String> {
        if self.marks.is_empty() {
            self.selected_infohash().into_iter().collect()
        } else {
            self.marks.iter().cloned().collect()
        }
    }

    pub fn selected_infohash(&self) -> Option<String> {
        self.items
            .items
            .get(self.selected)
            .map(|t| t.infohash.clone())
    }
}

#[derive(Debug)]
pub enum Msg {
    Page {
        generation: u64,
        first: bool,
        result: Result<types::PoolTorrentPage, Failure>,
    },
    Move(Motion),
    /// Mark or unmark the selected row, and move on.
    ToggleMark,
    /// The next adoption-state filter.
    CycleFilter,
    /// Close the verification result, or else clear the marks.
    Back,
    AskVerify,
    ConfirmKey(KeyEvent),
    Verified(Result<types::VerifyResult, Failure>),
}

/// Reload what is shown, keeping the selection on the same torrent; the
/// first time, load the first page.
pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.items.loading {
        return Vec::new();
    }
    state.reselect = state.selected_infohash();
    let limit = refresh_limit(state.items.items.len());
    reload(state, ctx, limit)
}

fn reload(state: &mut State, ctx: &Ctx<'_>, limit: Option<i64>) -> Vec<Effect> {
    let generation = state.items.reload();
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
    if !state.items.wants_more(state.selected) {
        return Vec::new();
    }
    match state.items.begin_more() {
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
    filter: Option<types::State>,
    cursor: Option<String>,
    limit: Option<i64>,
    generation: u64,
    first: bool,
) -> Effect {
    let api = ctx.api.clone();
    Effect::new(async move {
        let params = ListPoolTorrentsParams {
            state: filter,
            cursor,
            limit,
        };
        let result = crate::api::call(api.client.list_pool_torrents(params)).await;
        wrap(super::Msg::Library(Msg::Page {
            generation,
            first,
            result,
        }))
    })
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match msg {
        Msg::Page {
            generation,
            first,
            result: Ok(page),
        } => {
            if generation != state.items.generation {
                return Vec::new();
            }
            state
                .items
                .receive(generation, first, page.items, page.next_cursor);
            if first {
                if let Some(hash) = state.reselect.take() {
                    if let Some(at) = state.items.items.iter().position(|t| t.infohash == hash) {
                        state.selected = at;
                    }
                }
            }
            state.selected = state
                .selected
                .min(state.items.items.len().saturating_sub(1));
            more(state, ctx)
        }
        Msg::Page {
            generation,
            result: Err(failure),
            ..
        } => {
            state.items.fail(generation, failure.message());
            signed_out(&failure)
        }
        Msg::Move(motion) => {
            state.selected = motion.apply(state.selected, state.items.items.len());
            more(state, ctx)
        }
        Msg::ToggleMark => {
            let Some(hash) = state.selected_infohash() else {
                return Vec::new();
            };
            if !state.marks.remove(&hash) {
                state.marks.insert(hash);
            }
            update(state, Msg::Move(Motion::Down), ctx)
        }
        Msg::CycleFilter => {
            state.filter = match &state.filter {
                None => Some(FILTERS[0].clone()),
                Some(f) => FILTERS
                    .iter()
                    .position(|x| x == f)
                    .and_then(|at| FILTERS.get(at + 1))
                    .cloned(),
            };
            state.items.items.clear();
            state.items.next_cursor = None;
            state.selected = 0;
            state.offset.set(0);
            state.reselect = None;
            reload(state, ctx, None)
        }
        Msg::Back => {
            if state.verify.is_some() {
                state.verify = None;
            } else {
                state.marks.clear();
            }
            Vec::new()
        }
        Msg::AskVerify if state.verifying => Vec::new(),
        Msg::AskVerify => {
            let targets = state.targets();
            match targets.len() {
                0 => Vec::new(),
                n if n > MAX_BATCH => vec![Effect::toast(Toast::info(format!(
                    "{n} marked: verify at most {MAX_BATCH} at a time"
                )))],
                1 => verify(state, targets, ctx),
                n => {
                    state.confirm_verify = Some((
                        Confirm::new(
                            "Verify torrents",
                            format!(
                                "Hash {n} torrents' payload against their pieces? Each reads every \
                                 byte it claims and reports checking until done."
                            ),
                        ),
                        targets,
                    ));
                    Vec::new()
                }
            }
        }
        Msg::ConfirmKey(key) => {
            let Some((confirm, _)) = state.confirm_verify.as_mut() else {
                return Vec::new();
            };
            match confirm.on_key(key) {
                Confirmed::Yes => match state.confirm_verify.take() {
                    Some((_, targets)) => verify(state, targets, ctx),
                    None => Vec::new(),
                },
                Confirmed::No => {
                    state.confirm_verify = None;
                    Vec::new()
                }
                Confirmed::Pending => Vec::new(),
            }
        }
        Msg::Verified(Ok(result)) => {
            state.verifying = false;
            state.marks.clear();
            let toast = Toast::success(format!(
                "verification started for {} of {}; {} skipped",
                result.started.len(),
                result.requested,
                result.skipped.len()
            ));
            state.verify = Some(result);
            vec![Effect::toast(toast)]
        }
        Msg::Verified(Err(failure)) => {
            state.verifying = false;
            vec![Effect::now(failed("starting verification", failure))]
        }
    }
}

fn verify(state: &mut State, infohashes: Vec<String>, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.verifying = true;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        let body = types::VerifyRequest { infohashes };
        let result = crate::api::call(api.client.verify_pool_torrents(&body)).await;
        wrap(super::Msg::Library(Msg::Verified(result)))
    })]
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let result = state.verify.as_ref().map(|r| verify_lines(r, ctx));
    let result_height = result.as_ref().map_or(0, |l| l.len().min(8) as u16 + 2);
    let [list_area, result_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(result_height)]).areas(area);

    let mut name = format!(
        "library · {}",
        state
            .filter
            .as_ref()
            .map_or("all states".to_owned(), |f| f.to_string())
    );
    if !state.marks.is_empty() {
        name.push_str(&format!(
            " · {} marked",
            fmt::count(state.marks.len() as i64)
        ));
    }
    let loading = state.items.loading || state.verifying;
    let block = panel(
        theme,
        title(theme, name, loading, state.items.error.as_deref(), ctx.tick),
        true,
    )
    .title_bottom(hints(
        theme,
        &[
            ("space", "mark"),
            ("v", "verify"),
            ("a", "adopt"),
            ("F", "filter"),
            ("Esc", "clear marks"),
        ],
    ));

    if state.items.items.is_empty() {
        let inner = block.inner(list_area);
        frame.render_widget(block, list_area);
        if !state.items.loading {
            placeholder(frame, inner, theme, "No torrents here.", Tone::Muted);
        }
    } else {
        draw_table(state, ctx, frame, list_area, block);
    }

    if let Some(lines) = result {
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                panel(theme, " last verification ", false)
                    .title_bottom(hints(theme, &[("Esc", "dismiss")])),
            ),
            result_area,
        );
    }
}

fn draw_table(
    state: &State,
    ctx: &Ctx<'_>,
    frame: &mut Frame,
    area: Rect,
    block: ratatui::widgets::Block<'_>,
) {
    let theme = ctx.theme;
    let wide = area.width >= 120;
    let rows = state.items.items.iter().map(|t| {
        let marked = state.marks.contains(&t.infohash);
        let mut cells = vec![Line::from(Span::styled(
            if marked { "✓" } else { " " },
            theme.fg(Tone::Accent),
        ))];
        if wide {
            cells.push(Line::from(Span::styled(
                fmt::short_hash(&t.infohash).to_owned(),
                theme.fg(Tone::Muted),
            )));
        }
        cells.push(Line::from(t.name.clone()));
        cells.push(Line::from(fmt::bytes(t.total_size)).right_aligned());
        if wide {
            cells.push(Line::from(fmt::count(t.num_files)).right_aligned());
        }
        let state_name = t
            .state
            .as_ref()
            .map_or("unmatched".to_owned(), |s| s.to_string());
        cells.push(Line::from(vec![
            Span::raw(" "),
            state_span(theme, &state_name),
        ]));
        cells.push(Line::from(Span::styled(
            t.profile_id.clone().unwrap_or_else(|| "—".to_owned()),
            theme.fg(if t.profile_id.is_some() {
                Tone::Plain
            } else {
                Tone::Muted
            }),
        )));
        let row = Row::new(cells);
        if marked {
            row.style(theme.fg(Tone::Accent))
        } else {
            row
        }
    });
    let mut widths = vec![Constraint::Length(1)];
    let mut header = vec![Line::from("")];
    if wide {
        widths.push(Constraint::Length(12));
        header.push(Line::from("infohash"));
    }
    widths.extend([Constraint::Fill(1), Constraint::Length(10)]);
    header.extend([Line::from("name"), Line::from("size").right_aligned()]);
    if wide {
        widths.push(Constraint::Length(7));
        header.push(Line::from("files").right_aligned());
    }
    widths.extend([Constraint::Length(13), Constraint::Length(14)]);
    header.extend([Line::from(" state"), Line::from("profile")]);

    let visible = block.inner(area).height.saturating_sub(1) as usize;
    let offset = scroll(&state.offset, state.selected, visible);
    let mut table_state = TableState::default()
        .with_offset(offset)
        .with_selected(Some(state.selected));
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .header(Row::new(header).style(theme.fg(Tone::Muted)))
            .row_highlight_style(theme.selected())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always)
            .block(block),
        area,
        &mut table_state,
    );
}

fn verify_lines<'a>(result: &types::VerifyResult, ctx: &Ctx<'_>) -> Vec<Line<'a>> {
    let theme = ctx.theme;
    let mut lines = vec![Line::from(vec![
        Span::raw(format!("{} requested · ", fmt::count(result.requested))),
        strong(
            theme,
            format!("● {} started", result.started.len()),
            Tone::Good,
        ),
        Span::raw(" · "),
        strong(
            theme,
            format!("‖ {} skipped", result.skipped.len()),
            if result.skipped.is_empty() {
                Tone::Muted
            } else {
                Tone::Warn
            },
        ),
    ])];
    for skipped in &result.skipped {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}  ", fmt::short_hash(&skipped.infohash)),
                theme.fg(Tone::Muted),
            ),
            Span::raw(skipped.reason.clone()),
        ]));
    }
    lines
}
