//! One managed root, a directory at a time: what each child holds, how much
//! of it is adopted, matched or orphaned, and which adoption states claim
//! it. `o` narrows the listing to children holding orphaned bytes — what a
//! `delete_orphans` plan would act on.

use std::cell::Cell;

use ratatui::layout::Constraint;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::HighlightSpacing;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::TableState;
use ratatui::Frame;

use super::hints;
use super::overview::Root;
use super::refresh_limit;
use super::scroll;
use super::signed_out;
use super::title;
use super::wrap;
use super::Motion;
use crate::api::generated::GetPoolTreeParams;
use crate::api::generated::ListPoolOrphansParams;
use crate::api::types;
use crate::api::Failure;
use crate::app::Ctx;
use crate::app::Effect;
use crate::fmt;
use crate::theme::Tone;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Paged;

#[derive(Debug, Default)]
pub struct State {
    /// The root being browsed; `None` until one is picked.
    pub root: Option<Root>,
    /// The directory shown, as segments below the root.
    pub path: Vec<String>,
    /// Whether only children holding orphaned bytes are listed.
    pub orphans: bool,
    pub entries: Paged<types::TreeEntry>,
    pub selected: usize,
    pub offset: Cell<usize>,
    /// The entry to select once the first page arrives: the directory just
    /// left, or what the selection was on before a refresh.
    pub reselect: Option<String>,
}

impl State {
    /// The directory shown, relative to the root and `/`-separated; empty
    /// for the root itself.
    pub fn dir(&self) -> String {
        self.path.join("/")
    }

    fn selected_entry(&self) -> Option<&types::TreeEntry> {
        self.entries.items.get(self.selected)
    }

    /// Where the listing is, as a title: the root, then each directory.
    pub fn breadcrumb(&self) -> String {
        let Some(root) = &self.root else {
            return "tree".to_owned();
        };
        let mut crumb = root.path.clone();
        for segment in &self.path {
            crumb.push_str(" › ");
            crumb.push_str(segment);
        }
        crumb
    }
}

#[derive(Debug)]
pub enum Msg {
    /// A page of the listing loaded for `generation`; `first` replaces what
    /// is shown.
    Page {
        generation: u64,
        first: bool,
        result: Result<types::TreePage, Failure>,
    },
    Move(Motion),
    /// Into the selected directory.
    Enter,
    /// Up to the parent directory.
    Up,
    ToggleOrphans,
}

/// Browse `root` from its top.
pub fn open(state: &mut State, root: Root, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.root = Some(root);
    state.path.clear();
    state.orphans = false;
    state.reselect = None;
    navigate(state, ctx)
}

/// Show a new place: forget the old listing and load the first page.
fn navigate(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.entries.items.clear();
    state.entries.next_cursor = None;
    state.selected = 0;
    state.offset.set(0);
    reload(state, ctx, None)
}

/// Reload what is shown, keeping the selection on the same entry.
pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.root.is_none() || state.entries.loading {
        return Vec::new();
    }
    state.reselect = state.selected_entry().map(|e| e.name.clone());
    let limit = refresh_limit(state.entries.items.len());
    reload(state, ctx, limit)
}

fn reload(state: &mut State, ctx: &Ctx<'_>, limit: Option<i64>) -> Vec<Effect> {
    let Some(root) = &state.root else {
        return Vec::new();
    };
    let root_id = root.id;
    let generation = state.entries.reload();
    vec![fetch(
        ctx,
        root_id,
        state.dir(),
        state.orphans,
        None,
        limit,
        generation,
        true,
    )]
}

/// Fetch the next page when the selection nears the end of what is loaded.
fn more(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(root_id) = state.root.as_ref().map(|r| r.id) else {
        return Vec::new();
    };
    if !state.entries.wants_more(state.selected) {
        return Vec::new();
    }
    match state.entries.begin_more() {
        Some((cursor, generation)) => vec![fetch(
            ctx,
            root_id,
            state.dir(),
            state.orphans,
            Some(cursor),
            None,
            generation,
            false,
        )],
        None => Vec::new(),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "one request's parameters, named at the call"
)]
fn fetch(
    ctx: &Ctx<'_>,
    root_id: i64,
    dir: String,
    orphans: bool,
    cursor: Option<String>,
    limit: Option<i64>,
    generation: u64,
    first: bool,
) -> Effect {
    let api = ctx.api.clone();
    Effect::new(async move {
        let path = (!dir.is_empty()).then_some(dir);
        let result = if orphans {
            let params = ListPoolOrphansParams {
                path,
                cursor,
                limit,
            };
            crate::api::call(api.client.list_pool_orphans(root_id, params)).await
        } else {
            let params = GetPoolTreeParams {
                path,
                cursor,
                limit,
            };
            crate::api::call(api.client.get_pool_tree(root_id, params)).await
        };
        wrap(super::Msg::Tree(Msg::Page {
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
            if generation != state.entries.generation {
                return Vec::new();
            }
            state
                .entries
                .receive(generation, first, page.items, page.next_cursor);
            if first {
                if let Some(name) = state.reselect.take() {
                    if let Some(at) = state.entries.items.iter().position(|e| e.name == name) {
                        state.selected = at;
                    }
                }
            }
            state.selected = state
                .selected
                .min(state.entries.items.len().saturating_sub(1));
            more(state, ctx)
        }
        Msg::Page {
            generation,
            result: Err(failure),
            ..
        } => {
            state.entries.fail(generation, failure.message());
            signed_out(&failure)
        }
        Msg::Move(motion) => {
            state.selected = motion.apply(state.selected, state.entries.items.len());
            more(state, ctx)
        }
        Msg::Enter => match state.selected_entry() {
            Some(entry) if entry.is_dir => {
                state.path = entry
                    .path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                state.reselect = None;
                navigate(state, ctx)
            }
            _ => Vec::new(),
        },
        Msg::Up => match state.path.pop() {
            Some(left) => {
                state.reselect = Some(left);
                navigate(state, ctx)
            }
            None => Vec::new(),
        },
        Msg::ToggleOrphans => {
            if state.root.is_none() {
                return Vec::new();
            }
            state.orphans = !state.orphans;
            state.reselect = state.selected_entry().map(|e| e.name.clone());
            navigate(state, ctx)
        }
    }
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let Some(root) = &state.root else {
        placeholder(
            frame,
            area,
            theme,
            "No root picked: select one on the overview and press Enter.",
            Tone::Muted,
        );
        return;
    };

    let mut name = format!(
        "#{} {}",
        root.id,
        fit_breadcrumb(&state.breadcrumb(), area.width)
    );
    if state.orphans {
        name.push_str(" · orphans only");
    }
    let mut keys = vec![("Enter", "open"), ("h/⌫", "up"), ("o", "orphans")];
    keys.push(("A", "adopt this directory"));
    let block = panel(
        theme,
        title(
            theme,
            name,
            state.entries.loading,
            state.entries.error.as_deref(),
            ctx.tick,
        ),
        true,
    )
    .title_bottom(hints(theme, &keys));

    if state.entries.items.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if !state.entries.loading {
            let text = if state.orphans {
                "Nothing orphaned here."
            } else {
                "An empty directory."
            };
            placeholder(frame, inner, theme, text, Tone::Muted);
        }
        return;
    }

    let wide = area.width >= 120;
    let rows = state.entries.items.iter().map(|e| {
        let name = if e.is_dir {
            Line::from(vec![
                Span::styled("▸ ", theme.fg(Tone::Accent)),
                Span::styled(format!("{}/", e.name), theme.fg(Tone::Accent)),
            ])
        } else {
            Line::from(vec![Span::raw("  "), Span::raw(e.name.clone())])
        };
        let orphan_tone = if e.bytes_orphan > 0 {
            Tone::Warn
        } else {
            Tone::Muted
        };
        let mut cells = vec![name, Line::from(fmt::bytes(e.bytes_total)).right_aligned()];
        if wide {
            cells.push(Line::from(fmt::bytes(e.bytes_adopted)).right_aligned());
            cells.push(Line::from(fmt::bytes(e.bytes_matched)).right_aligned());
        }
        cells.push(
            Line::from(Span::styled(
                fmt::bytes(e.bytes_orphan),
                theme.fg(orphan_tone),
            ))
            .right_aligned(),
        );
        if wide {
            cells.push(Line::from(fmt::count(e.files_total)).right_aligned());
        }
        let mut states = vec![Span::raw(" ")];
        for (i, s) in e.states.iter().enumerate() {
            if i > 0 {
                states.push(Span::raw(" "));
            }
            states.push(state_span(theme, &s.to_string()));
        }
        cells.push(Line::from(states));
        Row::new(cells)
    });
    let mut widths = vec![
        Constraint::Fill(if wide { 2 } else { 1 }),
        Constraint::Length(10),
    ];
    let mut header = vec![Line::from("name"), Line::from("total").right_aligned()];
    if wide {
        widths.extend([Constraint::Length(10), Constraint::Length(10)]);
        header.extend([
            Line::from("adopted").right_aligned(),
            Line::from("matched").right_aligned(),
        ]);
    }
    widths.push(Constraint::Length(10));
    header.push(Line::from("orphan").right_aligned());
    if wide {
        widths.push(Constraint::Length(8));
        header.push(Line::from("files").right_aligned());
    }
    widths.push(Constraint::Fill(1));
    header.push(Line::from(" claimed by"));

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

/// The breadcrumb, cut from the front with `…` so the deepest directories
/// stay readable in a panel `width` wide.
fn fit_breadcrumb(crumb: &str, width: u16) -> String {
    let room = (width as usize).saturating_sub(34).max(12);
    let chars = crumb.chars().count();
    if chars <= room {
        return crumb.to_owned();
    }
    let tail: String = crumb.chars().skip(chars - (room - 1)).collect();
    format!("…{tail}")
}
