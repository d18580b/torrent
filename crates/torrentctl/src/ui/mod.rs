//! The frame around every screen: tabs and status up top, key hints below,
//! toasts, the help overlay and the command palette on top.

pub mod widgets;

use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Tabs;
use ratatui::Frame;
use widgets::centered;
use widgets::key_hints;
use widgets::panel;

use crate::app::Ctx;
use crate::app::Live;
use crate::app::Model;
use crate::app::Session;
use crate::app::Tab;
use crate::app::ToastKind;
use crate::screens;
use crate::theme::Tone;

/// Keys every screen shares, for the help overlay and the footer.
pub const GLOBAL_KEYS: &[(&str, &str)] = &[
    ("1-n / Tab", "switch screen"),
    (":", "command"),
    ("?", "help"),
    ("Ctrl-r", "refresh"),
    ("q", "quit"),
];

/// Draw the whole UI.
pub fn view(model: &Model, frame: &mut Frame) {
    let area = frame.area();
    let theme = &model.theme;
    let server = model.server().cloned();
    let ctx = Ctx {
        api: &model.api,
        server: server.as_ref(),
        theme,
        tick: model.tick,
    };

    if !matches!(model.session, Session::SignedIn { .. }) {
        screens::login::view(&model.login, &model.session, &ctx, frame, area);
        draw_toasts(model, frame, area);
        return;
    }

    let [top, body, bottom] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_top(model, frame, top);

    match model.tab {
        Tab::Dashboard => screens::dashboard::view(&model.dashboard, &ctx, frame, body),
        Tab::Torrents => screens::torrents::view(&model.torrents, &ctx, frame, body),
        Tab::Profiles => screens::profiles::view(&model.profiles, &ctx, frame, body),
        Tab::Pool => screens::pool::view(&model.pool, &ctx, frame, body),
    }

    let keys: &[(&str, &str)] = match model.tab {
        Tab::Dashboard => screens::dashboard::KEYS,
        Tab::Torrents => screens::torrents::KEYS,
        Tab::Profiles => screens::profiles::KEYS,
        Tab::Pool => screens::pool::KEYS,
    };
    let mut hints: Vec<(&str, &str)> = keys.iter().take(6).copied().collect();
    hints.extend([("?", "help"), ("q", "quit")]);
    frame.render_widget(Paragraph::new(key_hints(theme, &hints)), bottom);

    draw_toasts(model, frame, body);
    if model.help {
        draw_help(model, keys, frame, area);
    }
    if let Some(input) = &model.palette {
        draw_palette(model, input, frame, area);
    }
}

fn draw_top(model: &Model, frame: &mut Frame, area: Rect) {
    let theme = &model.theme;
    // The tabs come first: on a narrow terminal the status gives up the URL
    // rather than hide a screen.
    let wide = area.width >= 120;
    let [tabs_area, status_area] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(if wide { 64 } else { 30 }),
    ])
    .areas(area);
    let tabs = model.tabs();
    let titles: Vec<Line> = tabs
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(format!("{} ", i + 1), theme.fg(Tone::Muted)),
                Span::raw(t.title()),
            ])
        })
        .collect();
    let selected = tabs.iter().position(|t| *t == model.tab);
    frame.render_widget(
        Tabs::new(titles)
            .select(selected)
            .style(theme.fg(Tone::Plain))
            .highlight_style(theme.title().underlined())
            .divider(Span::styled("│", theme.fg(Tone::Muted))),
        tabs_area,
    );

    let (live_symbol, live_text, live_tone) = match &model.live {
        Live::Streaming => ("●", "live".to_owned(), Tone::Good),
        Live::Connecting => (
            widgets::spinner(model.tick),
            "connecting".to_owned(),
            Tone::Warn,
        ),
        Live::Reconnecting { .. } => ("◌", "polling".to_owned(), Tone::Warn),
    };
    let who = match &model.session {
        Session::SignedIn { principal, .. } => match &principal.name {
            Some(name) => format!("{} {name}", principal.kind),
            None => principal.kind.to_string(),
        },
        _ => String::new(),
    };
    let mut spans = vec![
        Span::styled(format!("{live_symbol} {live_text}"), theme.fg(live_tone)),
        Span::styled("  ", theme.fg(Tone::Muted)),
        Span::styled(who, theme.fg(Tone::Muted)),
    ];
    if wide {
        spans.push(Span::styled("  ", theme.fg(Tone::Muted)));
        spans.push(Span::styled(
            model.api.base_url.clone(),
            theme.fg(Tone::Accent),
        ));
    }
    let status = Line::from(spans).right_aligned();
    frame.render_widget(Paragraph::new(status), status_area);
}

fn draw_toasts(model: &Model, frame: &mut Frame, area: Rect) {
    let theme = &model.theme;
    let width = area.width.min(60);
    let mut y = area.y;
    for (toast, _) in model.toasts.iter().rev() {
        let (symbol, tone) = match toast.kind {
            ToastKind::Info => ("ℹ", Tone::Accent),
            ToastKind::Success => ("✔", Tone::Good),
            ToastKind::Error => ("✖", Tone::Bad),
        };
        let mut text = format!("{symbol} {}", toast.text);
        if let Some(id) = &toast.request_id {
            text.push_str(&format!("  (request {})", &id[..id.len().min(8)]));
        }
        let lines = (text.chars().count() as u16).div_ceil(width.saturating_sub(4).max(1)) + 2;
        let rect = Rect::new(area.right().saturating_sub(width), y, width, lines);
        if rect.bottom() > area.bottom() {
            continue;
        }
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(text)
                .style(theme.fg(tone))
                .wrap(ratatui::widgets::Wrap { trim: true })
                .block(panel(theme, "", false).border_style(theme.fg(tone))),
            rect,
        );
        y += lines;
    }
}

fn draw_help(model: &Model, keys: &[(&str, &str)], frame: &mut Frame, area: Rect) {
    let theme = &model.theme;
    let switch = format!("1-{} / Tab", model.tabs().len());
    let globals: Vec<(&str, &str)> = GLOBAL_KEYS
        .iter()
        .map(|&(key, action)| {
            if action == "switch screen" {
                (switch.as_str(), action)
            } else {
                (key, action)
            }
        })
        .collect();
    let entries: Vec<(&str, &str)> = keys
        .iter()
        .copied()
        .chain([("", "")])
        .chain(globals.iter().copied())
        .collect();
    // One column where it fits, two where it does not: every key stays on
    // screen at 80×24, and so does the line that says how to close it.
    let available = area.height.saturating_sub(4) as usize;
    let columns = if entries.len() <= available { 1 } else { 2 };
    let per_column = entries.len().div_ceil(columns);
    let width = if columns == 1 {
        60
    } else {
        area.width.min(110)
    };
    let rect = centered(area, width, per_column as u16 + 4);
    frame.render_widget(Clear, rect);
    let block = panel(theme, format!(" {} — keys ", model.tab.title()), true);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let [body, footer] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);
    let cells = Layout::horizontal(vec![Constraint::Fill(1); columns]).split(body);
    for (column, cell) in entries.chunks(per_column).zip(cells.iter()) {
        let lines: Vec<Line> = column
            .iter()
            .map(|(key, action)| {
                if key.is_empty() {
                    Line::from("")
                } else {
                    Line::from(vec![
                        Span::styled(format!("{key:>12}  "), theme.key()),
                        Span::styled(*action, theme.fg(Tone::Plain)),
                    ])
                }
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), *cell);
    }
    frame.render_widget(
        Paragraph::new(
            Line::from(Span::styled("any key to close", theme.fg(Tone::Muted))).centered(),
        ),
        footer,
    );
}

fn draw_palette(model: &Model, input: &tui_input::Input, frame: &mut Frame, area: Rect) {
    let theme = &model.theme;
    let rect = Rect::new(area.x, area.bottom().saturating_sub(3), area.width, 3);
    frame.render_widget(Clear, rect);
    let block = panel(
        theme,
        " command: dashboard torrents profiles pool add reload help quit ",
        true,
    );
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(":", theme.key()),
            Span::raw(input.value().to_owned()),
        ])),
        inner,
    );
    frame.set_cursor_position((inner.x + 1 + input.visual_cursor() as u16, inner.y));
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use serde_json::json;

    use super::*;
    use crate::app;
    use crate::app::Msg;
    use crate::app::Toast;
    use crate::testing;

    fn signed_in(pool: bool) -> Model {
        let mut m = Model::new(testing::api(), testing::theme());
        let principal = testing::from_json(json!({
            "kind": "token", "name": "operator", "scopes": ["read", "write"], "expires_at": null,
        }));
        app::update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(pool, true), principal))),
        );
        m.live = Live::Streaming;
        m
    }

    fn draw(model: &Model, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|frame| view(model, frame)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            let line: String = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    #[test]
    fn the_shell_shows_tabs_status_and_keys() {
        let m = signed_in(true);
        for (w, h) in [(80, 24), (160, 48)] {
            let screen = draw(&m, w, h);
            assert!(screen.contains("1 Dashboard"), "{screen}");
            assert!(screen.contains("4 Pool"));
            assert!(screen.contains("● live"));
            assert!(screen.contains("token operator"));
            insta::assert_snapshot!(format!("shell_{w}x{h}"), screen);
        }
        let without_pool = draw(&signed_in(false), 160, 48);
        assert!(!without_pool.contains("Pool"), "no pool tab without [pool]");
    }

    #[test]
    fn toasts_help_and_the_palette_draw_over_the_screen() {
        let mut m = signed_in(false);
        app::update(&mut m, Msg::Toast(Toast::success("reload queued")));
        let failure = crate::api::Failure {
            status: Some(409),
            title: "Conflict".into(),
            detail: Some("a reload is already queued".into()),
            request_id: Some("0123456789abcdef".into()),
            ..Default::default()
        };
        app::update(
            &mut m,
            Msg::Toast(Toast::failure("reloading config", &failure)),
        );
        let screen = draw(&m, 100, 30);
        assert!(screen.contains("✔ reload queued"), "{screen}");
        assert!(
            screen.contains("request 01234567"),
            "the request id is quotable"
        );

        app::update(&mut m, Msg::Key(testing::key(KeyCode::Char('?'))));
        let screen = draw(&m, 100, 30);
        assert!(screen.contains("Dashboard — keys"), "{screen}");
        assert!(screen.contains("reload config"));
        insta::assert_snapshot!("shell_help_100x30", screen);

        app::update(&mut m, Msg::Key(testing::key(KeyCode::Esc)));
        app::update(&mut m, Msg::Key(testing::key(KeyCode::Char(':'))));
        app::update(&mut m, Msg::Key(testing::key(KeyCode::Char('t'))));
        let screen = draw(&m, 100, 30);
        assert!(screen.contains(":t"), "{screen}");
    }

    #[test]
    fn the_help_overlay_fits_at_80x24_on_every_screen() {
        let mut m = signed_in(true);
        for tab in Tab::ALL {
            m.tab = tab;
            m.help = true;
            let screen = draw(&m, 80, 24);
            assert!(screen.contains("any key to close"), "{tab:?}:\n{screen}");
            assert!(screen.contains("1-4 / Tab"), "the real number of screens");
        }
    }

    #[test]
    fn signed_out_shows_only_the_sign_in() {
        let mut m = Model::new(testing::api(), testing::theme());
        app::update(
            &mut m,
            Msg::SessionChecked(Err(crate::api::Failure {
                status: Some(401),
                title: "Unauthorized".into(),
                ..Default::default()
            })),
        );
        let screen = draw(&m, 80, 24);
        assert!(screen.contains("password"), "{screen}");
        assert!(!screen.contains("Dashboard"));
    }
}
