//! The torrent list: which rows the filters show, paging through the
//! daemon's list towards the selection, and drawing it.

use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::TableState;
use ratatui::Frame;

use super::Msg;
use super::State;
use crate::api::types;
use crate::api::Api;
use crate::fmt;
use crate::screens::contract::Ctx;
use crate::screens::contract::Effect;
use crate::theme::Tone;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::PageRequest;

/// Indices into the loaded list of the rows the `/` filter shows.
pub(super) fn visible(state: &State) -> Vec<usize> {
    // The daemon emits infohashes lowercase, so a lowercased needle matches
    // them in any case it was typed; profile ids are lowercased to compare.
    let needle = state.filter.to_lowercase();
    state
        .list
        .items
        .iter()
        .enumerate()
        .filter(|(_, t)| {
            needle.is_empty()
                || t.infohash.starts_with(&needle)
                || t.profile_id.to_lowercase().contains(&needle)
        })
        .map(|(i, _)| i)
        .collect()
}

pub(super) fn selected_summary(state: &State) -> Option<&types::TorrentSummary> {
    visible(state)
        .get(state.selected)
        .and_then(|i| state.list.items.get(*i))
}

/// Select `hash` among the visible rows when it is one, else keep the row
/// in range.
pub(super) fn reselect(state: &mut State, hash: Option<String>) {
    let rows = visible(state);
    if let Some(at) =
        hash.and_then(|h| rows.iter().position(|i| state.list.items[*i].infohash == h))
    {
        state.selected = at;
    }
    state.selected = state.selected.min(rows.len().saturating_sub(1));
}

/// Change the server-side filters and start over.
pub(super) fn set_server_filter(
    state: &mut State,
    profile: Option<String>,
    phase: Option<types::Phase>,
    ctx: &Ctx<'_>,
) -> Vec<Effect> {
    state.profile = profile;
    state.phase = phase;
    // What was loaded belongs to another filter: drop it rather than show it
    // under this one.
    state.list.reset();
    state.selected = 0;
    state.list_offset.set(0);
    state.restore = None;
    let mut effects = load_list(state, ctx);
    effects.extend(load_profiles(state, ctx));
    effects
}

/// Reload the list from its first page, as many rows as are loaded (see
/// [`crate::ui::widgets::Paged`]), keeping the selection.
pub(super) fn load_list(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.restore.is_none() {
        state.restore = selected_summary(state).map(|s| s.infohash.clone());
    }
    let request = state.list.reload();
    vec![fetch_page(
        ctx.api,
        state.profile.clone(),
        state.phase.clone(),
        request,
    )]
}

pub(super) fn fetch_page(
    api: &Api,
    profile: Option<String>,
    phase: Option<types::Phase>,
    request: PageRequest,
) -> Effect {
    let api = api.clone();
    let PageRequest {
        cursor,
        limit,
        generation,
    } = request;
    Effect::new(async move {
        let first = cursor.is_none();
        let params = crate::api::generated::ListTorrentsParams {
            profile_id: profile,
            phase,
            cursor,
            limit: Some(limit as i64),
        };
        let result = crate::api::call(api.client.list_torrents(params)).await;
        crate::app::Msg::Torrents(Msg::Page {
            generation,
            first,
            result,
        })
    })
}

/// The next page, when the selection is near the end of what is loaded.
pub(super) fn load_more(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    let rows = visible(state);
    let at = rows
        .get(state.selected)
        .copied()
        .unwrap_or(state.list.items.len());
    // With the `/` filter hiding rows, the selection's place among all that
    // is loaded is what says whether more are wanted; when it hides every
    // row, keep loading so a match can turn up.
    if !state.list.wants_more(at) {
        return Vec::new();
    }
    next_page(state, ctx)
}

fn next_page(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    match state.list.begin_more() {
        Some(request) => vec![fetch_page(
            ctx.api,
            state.profile.clone(),
            state.phase.clone(),
            request,
        )],
        None => Vec::new(),
    }
}

/// After a page: select the torrent being restored when it has arrived,
/// or page on towards it while it may still come (the list is ordered by
/// infohash). The selection is in range on every path, paging on included:
/// a reload can show fewer rows than were selectable before it, and the
/// page it pages on for may never arrive.
pub(super) fn settle(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.selected = state.selected.min(visible(state).len().saturating_sub(1));
    if let Some(want) = state.restore.clone() {
        let rows = visible(state);
        if let Some(at) = rows
            .iter()
            .position(|i| state.list.items[*i].infohash == want)
        {
            state.selected = at;
            state.restore = None;
        } else if state.list.next_cursor.is_some()
            && state
                .list
                .items
                .last()
                .is_some_and(|last| last.infohash < want)
        {
            return next_page(state, ctx);
        } else {
            state.restore = None;
        }
    }
    load_more(state, ctx)
}

pub(super) fn load_profiles(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.profiles_loading {
        return Vec::new();
    }
    state.profiles_loading = true;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        let result = crate::api::call(api.client.list_profiles())
            .await
            .map(|p| p.items);
        crate::app::Msg::Torrents(Msg::Profiles(result))
    })]
}
/// The list panel: the filters in its title, a row per torrent the `/`
/// filter shows.
pub(super) fn list(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let mut title = vec![Span::raw(" torrents ")];
    if state.list.loading {
        title.push(Span::styled(
            format!("{} ", spinner(ctx.tick)),
            theme.fg(Tone::Muted),
        ));
    }
    let block = panel(theme, Line::from(title), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let editing = state.filter_input.is_some();
    let [header, status, table_area, filter_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(u16::from(state.list.error.is_some())),
        Constraint::Fill(1),
        Constraint::Length(u16::from(editing)),
    ])
    .areas(inner);

    let rows = visible(state);
    let muted = theme.fg(Tone::Muted);
    let mut spans = vec![
        Span::styled(fmt::count(rows.len() as i64), theme.fg(Tone::Plain).bold()),
        Span::styled(" shown · ", muted),
        Span::styled(
            fmt::count(state.list.items.len() as i64),
            theme.fg(Tone::Plain),
        ),
        Span::styled(" loaded · ", muted),
        if state.list.next_cursor.is_some() {
            Span::styled("more pages", theme.fg(Tone::Warn))
        } else if state.list.complete {
            Span::styled("all loaded", muted)
        } else {
            Span::styled("loading", muted)
        },
        Span::styled("   profile ", muted),
        Span::styled(
            state.profile.clone().unwrap_or_else(|| "all".to_owned()),
            theme.fg(Tone::Accent),
        ),
        Span::styled("  phase ", muted),
        Span::styled(
            state
                .phase
                .as_ref()
                .map_or_else(|| "all".to_owned(), ToString::to_string),
            theme.fg(Tone::Accent),
        ),
    ];
    if !state.filter.is_empty() && !editing {
        spans.push(Span::styled("  /", muted));
        spans.push(Span::styled(state.filter.clone(), theme.fg(Tone::Accent)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), header);
    if let Some(error) = &state.list.error {
        frame.render_widget(
            Paragraph::new(Span::styled(format!("✖ {error}"), theme.fg(Tone::Bad))),
            status,
        );
    }
    if let Some(input) = &state.filter_input {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("/", theme.key()),
                Span::raw(input.value().to_owned()),
                Span::styled(
                    "   infohash prefix or profile · Enter keep · Esc clear",
                    muted,
                ),
            ])),
            filter_area,
        );
        frame.set_cursor_position((
            filter_area.x + 1 + input.visual_cursor() as u16,
            filter_area.y,
        ));
    }

    if rows.is_empty() {
        let text = if state.list.loading || (!state.list.complete && state.list.error.is_none()) {
            "loading…"
        } else if state.list.error.is_some() {
            ""
        } else if state.list.items.is_empty() {
            "no torrents here — n adds one"
        } else {
            "nothing loaded matches the filter"
        };
        placeholder(frame, table_area, theme, text, Tone::Muted);
        return;
    }

    // Columns, dropped from the right as the terminal narrows.
    let width = table_area.width;
    let wide = width >= 150;
    let show_profile = width >= 60;
    let show_peers = width >= 70;
    let show_uploaded = width >= 76;
    let show_down = width >= 110;

    let mut widths = vec![
        Constraint::Length(12),
        Constraint::Length(if wide { 40 } else { 12 }),
    ];
    let mut head = vec![Line::from("state"), Line::from("infohash")];
    if show_profile {
        widths.push(Constraint::Fill(1));
        head.push(Line::from("profile"));
    }
    // Wide enough, progress is a bar as well as a number.
    widths.push(Constraint::Length(if show_down { 17 } else { 6 }));
    head.push(Line::from("done").right_aligned());
    widths.push(Constraint::Length(12));
    head.push(Line::from("↑ rate").right_aligned());
    if show_down {
        widths.push(Constraint::Length(12));
        head.push(Line::from("↓ rate").right_aligned());
    }
    if show_peers {
        widths.push(Constraint::Length(5));
        head.push(Line::from("peers").right_aligned());
    }
    if show_uploaded {
        widths.push(Constraint::Length(10));
        head.push(Line::from("uploaded").right_aligned());
    }
    if wide {
        widths.push(Constraint::Length(10));
        head.push(Line::from("payload").right_aligned());
    }

    let table_rows = rows.iter().map(|i| {
        let t = &state.list.items[*i];
        let hash = if wide {
            t.infohash.as_str()
        } else {
            fmt::short_hash(&t.infohash)
        };
        let mut cells = vec![
            Line::from(state_span(theme, &t.phase.to_string())),
            Line::from(Span::styled(hash.to_owned(), theme.fg(Tone::Accent))),
        ];
        if show_profile {
            cells.push(Line::from(t.profile_id.clone()));
        }
        let percent = fmt::percent(t.progress).replace(".0%", "%");
        cells.push(if show_down {
            let filled = (t.progress.clamp(0.0, 1.0) * 10.0).round() as usize;
            let tone = if t.progress >= 1.0 {
                Tone::Good
            } else {
                Tone::Warn
            };
            Line::from(vec![
                Span::styled("█".repeat(filled), theme.fg(tone)),
                Span::styled("░".repeat(10 - filled), muted),
                Span::raw(format!("{percent:>7}")),
            ])
        } else {
            Line::from(percent).right_aligned()
        });
        let up_tone = if t.upload_rate > 0 {
            Tone::Good
        } else {
            Tone::Muted
        };
        cells.push(
            Line::from(Span::styled(fmt::rate(t.upload_rate), theme.fg(up_tone))).right_aligned(),
        );
        if show_down {
            cells.push(Line::from(Span::styled(fmt::rate(t.download_rate), muted)).right_aligned());
        }
        if show_peers {
            cells.push(Line::from(fmt::count(t.num_peers)).right_aligned());
        }
        if show_uploaded {
            cells.push(Line::from(fmt::bytes(t.total_uploaded)).right_aligned());
        }
        if wide {
            cells.push(
                Line::from(Span::styled(fmt::bytes(t.total_payload_uploaded), muted))
                    .right_aligned(),
            );
        }
        Row::new(cells)
    });
    let table = Table::new(table_rows, widths)
        .header(Row::new(head).style(muted))
        .row_highlight_style(theme.selected())
        .highlight_symbol("› ");
    let mut table_state = TableState::default()
        .with_offset(state.list_offset.get())
        .with_selected(Some(state.selected));
    frame.render_stateful_widget(table, table_area, &mut table_state);
    state.list_offset.set(table_state.offset());
}
