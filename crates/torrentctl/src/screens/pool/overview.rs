//! The overview: the library, how many torrents stand in each adoption
//! state, the verify queue, and every managed root's byte accounting — plus
//! the two whole-pool actions, a rescan and a drift check.

use std::cell::Cell;

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
use ratatui::Frame;

use super::hints;
use super::scroll;
use super::share_bar;
use super::signed_out;
use super::strong;
use super::title;
use super::wrap;
use super::Motion;
use crate::api::types;
use crate::api::Failure;
use crate::app::failed;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Toast;
use crate::fmt;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;

/// A managed root, as the tree browses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub id: i64,
    pub path: String,
}

#[derive(Debug, Default)]
pub struct State {
    pub pool: Option<types::PoolOverview>,
    pub loading: bool,
    pub error: Option<String>,
    /// Bumped per load, so an answer to an older one is dropped.
    pub generation: u64,
    /// The selected root.
    pub selected: usize,
    pub offset: Cell<usize>,
    pub confirm_scan: Option<Confirm>,
    pub scanning: bool,
    pub scan: Option<types::ScanSummary>,
    pub checking_drift: bool,
    pub drift: Option<types::DriftReport>,
}

impl State {
    /// The root the selection is on.
    pub fn selected_root(&self) -> Option<Root> {
        let root = self.pool.as_ref()?.roots.get(self.selected)?;
        Some(Root {
            id: root.root_id,
            path: root.path.clone(),
        })
    }
}

#[derive(Debug)]
pub enum Msg {
    /// `GET /v1/pool` answered load `generation`.
    Loaded(u64, Result<types::PoolOverview, Failure>),
    Move(Motion),
    /// Ask to rescan the whole pool.
    AskScan,
    ConfirmKey(KeyEvent),
    Scanned(Result<types::ScanSummary, Failure>),
    CheckDrift,
    DriftChecked(Result<types::DriftReport, Failure>),
}

/// Reload unless a load is already on its way.
pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.loading {
        return Vec::new();
    }
    load(state, ctx)
}

/// Load now, superseding any load in flight.
fn load(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.loading = true;
    state.generation += 1;
    let generation = state.generation;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        let result = crate::api::call(api.client.get_pool()).await;
        wrap(super::Msg::Overview(Msg::Loaded(generation, result)))
    })]
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match msg {
        Msg::Loaded(generation, _) if generation != state.generation => Vec::new(),
        Msg::Loaded(_, Ok(pool)) => {
            state.loading = false;
            state.error = None;
            state.selected = state.selected.min(pool.roots.len().saturating_sub(1));
            state.pool = Some(pool);
            Vec::new()
        }
        Msg::Loaded(_, Err(failure)) => {
            state.loading = false;
            state.error = Some(failure.message());
            signed_out(&failure)
        }
        Msg::Move(motion) => {
            let len = state.pool.as_ref().map_or(0, |p| p.roots.len());
            state.selected = motion.apply(state.selected, len);
            Vec::new()
        }
        Msg::AskScan if state.scanning => {
            vec![Effect::toast(Toast::info("a scan is already running"))]
        }
        Msg::AskScan => {
            state.confirm_scan = Some(Confirm::new(
                "Scan the pool",
                "Walk every managed root, re-read the library and re-match every torrent? On a \
                 large pool this takes minutes; the index stays readable meanwhile.",
            ));
            Vec::new()
        }
        Msg::ConfirmKey(key) => {
            let Some(confirm) = state.confirm_scan.as_mut() else {
                return Vec::new();
            };
            match confirm.on_key(key) {
                Confirmed::Yes => {
                    state.confirm_scan = None;
                    state.scanning = true;
                    let api = ctx.api.clone();
                    vec![Effect::new(async move {
                        let result = crate::api::call_unbounded(api.client.scan_pool()).await;
                        wrap(super::Msg::Overview(Msg::Scanned(result)))
                    })]
                }
                Confirmed::No => {
                    state.confirm_scan = None;
                    Vec::new()
                }
                Confirmed::Pending => Vec::new(),
            }
        }
        Msg::Scanned(Ok(summary)) => {
            state.scanning = false;
            let toast = Toast::success(format!(
                "scan done: {} torrents, {} matched",
                fmt::count(summary.torrents),
                fmt::count(summary.matched)
            ));
            state.scan = Some(summary);
            let mut effects = vec![Effect::toast(toast)];
            effects.extend(load(state, ctx));
            effects
        }
        Msg::Scanned(Err(failure)) => {
            state.scanning = false;
            vec![Effect::now(failed("scanning the pool", failure))]
        }
        Msg::CheckDrift if state.checking_drift => Vec::new(),
        Msg::CheckDrift => {
            state.checking_drift = true;
            let api = ctx.api.clone();
            vec![Effect::new(async move {
                let result = crate::api::call_unbounded(api.client.check_pool_drift()).await;
                wrap(super::Msg::Overview(Msg::DriftChecked(result)))
            })]
        }
        Msg::DriftChecked(Ok(report)) => {
            state.checking_drift = false;
            let toast = if report.drifted.is_empty() {
                Toast::success("drift check: nothing drifted")
            } else {
                Toast::info(format!(
                    "drift check: {} torrents drifted — rescan and verify them",
                    report.drifted.len()
                ))
            };
            state.drift = Some(report);
            let mut effects = vec![Effect::toast(toast)];
            effects.extend(load(state, ctx));
            effects
        }
        Msg::DriftChecked(Err(failure)) => {
            state.checking_drift = false;
            vec![Effect::now(failed("checking for drift", failure))]
        }
    }
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let Some(pool) = &state.pool else {
        let (text, tone) = match &state.error {
            Some(e) => (format!("✖ {e}"), Tone::Bad),
            None => (
                format!("{} loading the pool…", spinner(ctx.tick)),
                Tone::Muted,
            ),
        };
        placeholder(frame, area, theme, &text, tone);
        return;
    };

    let results = result_lines(state, ctx, area.width >= 120);
    let results_height = if results.is_empty() {
        0
    } else {
        results.len() as u16 + 2
    };
    let [top, roots_area, results_area] = Layout::vertical([
        Constraint::Length(9),
        Constraint::Fill(1),
        Constraint::Length(results_height),
    ])
    .areas(area);
    let [library_area, states_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(top);

    draw_library(pool, theme, frame, library_area);
    draw_states(pool, theme, frame, states_area);
    draw_roots(state, pool, ctx, frame, roots_area);
    if !results.is_empty() {
        frame.render_widget(
            Paragraph::new(results).block(panel(theme, " last run ", false)),
            results_area,
        );
    }
}

fn draw_library(pool: &types::PoolOverview, theme: &Theme, frame: &mut Frame, area: Rect) {
    let queue_tone = if pool.verify_queue_depth + pool.verify_in_flight > 0 {
        Tone::Warn
    } else {
        Tone::Muted
    };
    let lines = vec![
        kv(
            theme,
            "library",
            Span::styled(pool.library_dir.clone(), theme.fg(Tone::Plain)),
        ),
        kv(
            theme,
            "torrents",
            strong(theme, fmt::count(pool.torrents), Tone::Accent),
        ),
        kv(
            theme,
            "files",
            Span::styled(fmt::count(pool.files), theme.fg(Tone::Plain)),
        ),
        kv(
            theme,
            "roots",
            Span::styled(fmt::count(pool.roots.len() as i64), theme.fg(Tone::Plain)),
        ),
        kv(
            theme,
            "verifying",
            Span::styled(
                format!(
                    "{} queued · {} running",
                    fmt::count(pool.verify_queue_depth),
                    fmt::count(pool.verify_in_flight)
                ),
                theme.fg(queue_tone),
            ),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(panel(theme, " library ", false)),
        area,
    );
}

fn kv<'a>(theme: &Theme, key: &'a str, value: Span<'a>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:>13}  "), theme.fg(Tone::Muted)),
        value,
    ])
}

/// One bar per adoption state, against the whole library.
fn draw_states(pool: &types::PoolOverview, theme: &Theme, frame: &mut Frame, area: Rect) {
    let s = &pool.states;
    let known = s.missing + s.partial + s.matched + s.adopted + s.drifted + s.overlap;
    let rows = [
        ("adopted", s.adopted),
        ("matched", s.matched),
        ("partial", s.partial),
        ("missing", s.missing),
        ("drifted", s.drifted),
        ("overlap", s.overlap),
        ("unmatched", (pool.torrents - known).max(0)),
    ];
    let block = panel(theme, " adoption ", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let bar_width = inner.width.saturating_sub(22);
    let lines: Vec<Line> = rows
        .iter()
        .map(|(state, n)| {
            let (symbol, tone) = crate::theme::badge(state);
            let tone = if *n == 0 { Tone::Muted } else { tone };
            let mut spans = vec![
                Span::styled(format!("{symbol} {state:<10}"), theme.fg(tone)),
                Span::styled(format!("{:>8} ", fmt::count(*n)), theme.fg(Tone::Plain)),
            ];
            spans.extend(share_bar(theme, &[(*n, '█', tone)], pool.torrents, bar_width).spans);
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_roots(
    state: &State,
    pool: &types::PoolOverview,
    ctx: &Ctx<'_>,
    frame: &mut Frame,
    area: Rect,
) {
    let theme = ctx.theme;
    let wide = area.width >= 120;
    let bar_width: u16 = if wide { 30 } else { 14 };
    let rows = pool.roots.iter().map(|r| {
        let mut cells = vec![
            Line::from(format!("#{}", r.root_id)),
            Line::from(r.path.clone()),
            Line::from(fmt::bytes(r.bytes_total)).right_aligned(),
        ];
        if wide {
            cells.push(Line::from(fmt::bytes(r.bytes_adopted)).right_aligned());
            cells.push(Line::from(fmt::bytes(r.bytes_matched)).right_aligned());
        }
        let orphan_tone = if r.bytes_orphan > 0 {
            Tone::Warn
        } else {
            Tone::Muted
        };
        cells.push(
            Line::from(Span::styled(
                fmt::bytes(r.bytes_orphan),
                theme.fg(orphan_tone),
            ))
            .right_aligned(),
        );
        if wide {
            cells.push(Line::from(fmt::count(r.files_total)).right_aligned());
            cells.push(
                Line::from(Span::styled(
                    fmt::count(r.files_orphan),
                    theme.fg(orphan_tone),
                ))
                .right_aligned(),
            );
        }
        let mut bar = root_bar(theme, r, bar_width);
        bar.spans.insert(0, Span::raw(" "));
        cells.push(bar);
        Row::new(cells)
    });
    let mut widths = vec![
        Constraint::Length(5),
        Constraint::Fill(1),
        Constraint::Length(10),
    ];
    let mut header = vec!["id", "path", "total"];
    if wide {
        widths.extend([Constraint::Length(10), Constraint::Length(10)]);
        header.extend(["adopted", "matched"]);
    }
    widths.push(Constraint::Length(10));
    header.push("orphan");
    if wide {
        widths.extend([Constraint::Length(9), Constraint::Length(9)]);
        header.extend(["files", "orphaned"]);
    }
    widths.push(Constraint::Length(bar_width + 1));
    header.push(" share");
    let header = Row::new(
        header
            .into_iter()
            .enumerate()
            .map(|(i, h)| {
                // Byte and file counts are right-aligned under their heading.
                let line = Line::from(h);
                if (2..widths.len() - 1).contains(&i) {
                    line.right_aligned()
                } else {
                    line
                }
            })
            .collect::<Vec<_>>(),
    )
    .style(theme.fg(Tone::Muted));

    let mut name = title(
        theme,
        "roots".to_owned(),
        state.loading,
        state.error.as_deref(),
        ctx.tick,
    );
    name.spans.splice(
        1..1,
        [
            Span::styled("█", theme.fg(Tone::Good)),
            Span::raw(" adopted "),
            Span::styled("▓", theme.fg(Tone::Accent)),
            Span::raw(" matched "),
            Span::styled("░", theme.fg(Tone::Warn)),
            Span::raw(" orphan "),
        ],
    );
    let block = panel(theme, name, true).title_bottom(hints(
        theme,
        &[
            ("Enter", "browse root"),
            ("s", "scan"),
            ("d", "drift check"),
        ],
    ));
    let visible = block.inner(area).height.saturating_sub(1) as usize;
    let offset = scroll(&state.offset, state.selected, visible);
    let mut table_state = TableState::default()
        .with_offset(offset)
        .with_selected(Some(state.selected));
    if pool.roots.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        placeholder(frame, inner, theme, "no managed roots", Tone::Muted);
        return;
    }
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .header(header)
            .row_highlight_style(theme.selected())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always)
            .block(block),
        area,
        &mut table_state,
    );
}

/// A root's bytes as a bar: adopted, matched, orphan, and the rest.
fn root_bar<'a>(theme: &Theme, r: &types::RootSummary, width: u16) -> Line<'a> {
    share_bar(
        theme,
        &[
            (r.bytes_adopted, '█', Tone::Good),
            (r.bytes_matched, '▓', Tone::Accent),
            (r.bytes_orphan, '░', Tone::Warn),
        ],
        r.bytes_total,
        width,
    )
}

/// What the last scan and drift check found, and what is running; on a
/// narrow screen the scan takes two lines and fewer hashes are listed.
fn result_lines<'a>(state: &State, ctx: &Ctx<'_>, wide: bool) -> Vec<Line<'a>> {
    let theme = ctx.theme;
    let mut lines = Vec::new();
    let label = |text: &str| Span::styled(format!("{text:>7}  "), theme.fg(Tone::Muted));
    if state.scanning {
        lines.push(Line::from(vec![
            label("scan"),
            Span::styled(
                format!(
                    "{} scanning every root — this can take minutes",
                    spinner(ctx.tick)
                ),
                theme.fg(Tone::Accent),
            ),
        ]));
    } else if let Some(s) = &state.scan {
        let errors = if s.errors > 0 { Tone::Bad } else { Tone::Muted };
        let mut spans = vec![
            label("scan"),
            Span::raw(format!(
                "{} files · {} · {} torrents ",
                fmt::count(s.files),
                fmt::bytes(s.bytes),
                fmt::count(s.torrents)
            )),
        ];
        if !wide {
            lines.push(Line::from(std::mem::take(&mut spans)));
            spans.push(label(""));
        }
        spans.extend([
            Span::raw(if wide { "→ " } else { "" }),
            state_span(theme, "matched"),
            Span::raw(format!(" {} · ", fmt::count(s.matched))),
            state_span(theme, "partial"),
            Span::raw(format!(" {} · ", fmt::count(s.partial))),
            state_span(theme, "missing"),
            Span::raw(format!(" {} · ", fmt::count(s.missing))),
            state_span(theme, "overlap"),
            Span::raw(format!(" {} · ", fmt::count(s.overlap))),
            Span::styled(format!("{} errors", fmt::count(s.errors)), theme.fg(errors)),
        ]);
        lines.push(Line::from(spans));
    }
    if state.checking_drift {
        lines.push(Line::from(vec![
            label("drift"),
            Span::styled(
                format!("{} checking every claimed file", spinner(ctx.tick)),
                theme.fg(Tone::Accent),
            ),
        ]));
    } else if let Some(d) = &state.drift {
        let mut spans = vec![label("drift")];
        if d.drifted.is_empty() {
            spans.push(Span::styled("● nothing drifted", theme.fg(Tone::Good)));
        } else {
            spans.push(Span::styled(
                format!("✖ {} drifted: ", d.drifted.len()),
                theme.fg(Tone::Bad),
            ));
            let shown: Vec<&str> = d
                .drifted
                .iter()
                .take(if wide { 4 } else { 1 })
                .map(|h| fmt::short_hash(h))
                .collect();
            spans.push(Span::raw(shown.join(" ")));
            if d.drifted.len() > shown.len() {
                spans.push(Span::styled(
                    format!(" +{}", d.drifted.len() - shown.len()),
                    theme.fg(Tone::Muted),
                ));
            }
        }
        spans.push(Span::raw(format!(
            " · {} files changed · {} vanished",
            fmt::count(d.files_changed),
            fmt::count(d.files_vanished)
        )));
        lines.push(Line::from(spans));
    }
    lines
}
