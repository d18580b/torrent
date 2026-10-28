//! Drawing plans: the list, one plan's steps, and the confirmations over
//! them.

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

use super::count;
use super::form::draw_form;
use super::steps;
use super::Detail;
use super::Pending;
use super::State;
use crate::api::types;
use crate::fmt::when;
use crate::screens::contract::Ctx;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::hints;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::scroll;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::strong;
use crate::ui::widgets::title;

/// The open plan's size and progress, from its counts: `3 steps · 1 done ·
/// 1 failed`, naming only the statuses some step stands in.
fn progress<'a>(theme: &Theme, counts: &types::StepCounts) -> Vec<Span<'a>> {
    let mut spans = vec![Span::styled(
        format!("  {}", steps(count(counts.total))),
        theme.fg(Tone::Muted),
    )];
    for (n, what, tone) in [
        (counts.done, "done", Tone::Muted),
        (counts.in_progress, "running", Tone::Accent),
        (counts.failed, "failed", Tone::Bad),
    ] {
        if n > 0 {
            spans.push(Span::styled(format!(" · {n} {what}"), theme.fg(tone)));
        }
    }
    spans
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
    if ctx.pool_mutations_allowed() {
        keys.extend([("c", "create"), ("x", "apply")]);
    }
    keys.push(("X", "discard"));
    let mut line = hints(theme, &keys);
    if !ctx.pool_mutations_allowed() {
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
    let offset = scroll(
        &state.offset,
        state.selected,
        visible,
        state.list.items.len(),
    );
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
    let mut head_line = vec![
        label("plan"),
        strong(theme, format!("#{}", plan.id), Tone::Accent),
        Span::raw(format!("  {}  ", plan.kind)),
        state_span(theme, &plan.status.to_string()),
    ];
    head_line.extend(progress(theme, &plan.step_counts));
    let mut lines = vec![
        Line::from(head_line),
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

    let rows = detail.steps.items.iter().map(|s| {
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
    // Until every step is loaded, say how many of them are.
    let name = if detail.steps.complete {
        "steps".to_owned()
    } else {
        format!(
            "steps · {} of {}",
            detail.steps.items.len(),
            plan.step_counts.total
        )
    };
    let block = panel(
        theme,
        title(
            theme,
            name,
            detail.steps.loading,
            detail.steps.error.as_deref(),
            ctx.tick,
        ),
        true,
    )
    .title_bottom(plan_hints(theme, ctx, true));
    let visible = block.inner(steps_area).height.saturating_sub(1) as usize;
    let offset = scroll(
        &detail.offset,
        detail.selected,
        visible,
        detail.steps.items.len(),
    );
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
