//! The daemon at a glance: counts, rates over time, profile health, and the
//! server itself.

use std::collections::VecDeque;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Sparkline;
use ratatui::widgets::Table;
use ratatui::Frame;

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
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;

/// Rate samples kept for the sparklines: one per refresh.
const HISTORY: usize = 120;

#[derive(Debug, Default)]
pub struct State {
    pub status: Option<types::Status>,
    pub profiles: Vec<types::Profile>,
    pub loading: bool,
    pub error: Option<String>,
    pub up: VecDeque<u64>,
    pub down: VecDeque<u64>,
    pub confirm_reload: Option<Confirm>,
}

#[derive(Debug)]
pub enum Msg {
    Loaded(Result<(types::Status, Vec<types::Profile>), Failure>),
    /// Ask to reload the daemon's configuration.
    AskReload,
    ConfirmKey(KeyEvent),
    Reload,
    Reloaded(Result<(), Failure>),
}

pub const KEYS: &[(&str, &str)] = &[("R", "reload config")];

pub fn capturing(state: &State) -> bool {
    state.confirm_reload.is_some()
}

pub fn on_key(state: &State, key: KeyEvent) -> Option<Msg> {
    if state.confirm_reload.is_some() {
        return Some(Msg::ConfirmKey(key));
    }
    match key.code {
        KeyCode::Char('R') => Some(Msg::AskReload),
        _ => None,
    }
}

#[allow(
    clippy::result_large_err,
    reason = "a Failure is built once per failed request and moved straight to the UI"
)]
pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.loading {
        return Vec::new();
    }
    state.loading = true;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        let status = crate::api::call(api.client.get_status()).await;
        let profiles = crate::api::call(api.client.list_profiles()).await;
        crate::app::Msg::Dashboard(Msg::Loaded(
            status.and_then(|s| profiles.map(|p| (s, p.items))),
        ))
    })]
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match msg {
        Msg::Loaded(Ok((status, profiles))) => {
            state.loading = false;
            state.error = None;
            push(&mut state.up, status.upload_rate_total.max(0) as u64);
            push(&mut state.down, status.download_rate_total.max(0) as u64);
            state.status = Some(status);
            state.profiles = profiles;
            Vec::new()
        }
        Msg::Loaded(Err(failure)) => {
            state.loading = false;
            state.error = Some(failure.message());
            if failure.is_unauthenticated() {
                vec![Effect::now(failed("loading status", failure))]
            } else {
                Vec::new()
            }
        }
        Msg::AskReload => {
            state.confirm_reload = Some(Confirm::new(
                "Reload configuration",
                "Re-read the daemon's config file, as SIGHUP does? Keys that need a restart are \
                 logged and ignored.",
            ));
            Vec::new()
        }
        Msg::ConfirmKey(key) => {
            let Some(confirm) = state.confirm_reload.as_mut() else {
                return Vec::new();
            };
            match confirm.on_key(key) {
                Confirmed::Yes => {
                    state.confirm_reload = None;
                    update(state, Msg::Reload, ctx)
                }
                Confirmed::No => {
                    state.confirm_reload = None;
                    Vec::new()
                }
                Confirmed::Pending => Vec::new(),
            }
        }
        Msg::Reload => {
            let api = ctx.api.clone();
            vec![Effect::new(async move {
                let result = crate::api::call(api.client.reload_config())
                    .await
                    .map(|_| ());
                crate::app::Msg::Dashboard(Msg::Reloaded(result))
            })]
        }
        Msg::Reloaded(Ok(())) => vec![Effect::toast(Toast::success(
            "reload queued — the daemon's log says what it applied",
        ))],
        Msg::Reloaded(Err(failure)) => vec![Effect::now(failed("reloading config", failure))],
    }
}

fn push(history: &mut VecDeque<u64>, value: u64) {
    if history.len() == HISTORY {
        history.pop_front();
    }
    history.push_back(value);
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let Some(status) = &state.status else {
        let text = match &state.error {
            Some(e) => format!("✖ {e}"),
            None => format!("{} loading…", spinner(ctx.tick)),
        };
        let tone = if state.error.is_some() {
            Tone::Bad
        } else {
            Tone::Muted
        };
        placeholder(frame, area, theme, &text, tone);
        return;
    };

    // A later failure keeps the last good numbers on screen, marked stale.
    let area = match &state.error {
        Some(error) => {
            let [banner, rest] =
                Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
            frame.render_widget(
                Paragraph::new(format!("✖ {error} — showing the last good figures"))
                    .style(theme.fg(Tone::Bad)),
                banner,
            );
            rest
        }
        None => area,
    };
    let [counts, rates, lower] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Fill(1),
    ])
    .areas(area);

    // Counts by phase.
    let tiles = [
        ("total", status.torrents_total, Tone::Accent),
        ("seeding", status.seeding, Tone::Good),
        ("checking", status.checking, Tone::Warn),
        ("paused", status.paused, Tone::Warn),
        ("disk err", status.disk_error, Tone::Bad),
        ("errored", status.errored, Tone::Bad),
        ("peers", status.peers_total, Tone::Plain),
    ];
    let cells = Layout::horizontal(tiles.iter().map(|_| Constraint::Fill(1))).split(counts);
    for ((label, value, tone), cell) in tiles.iter().zip(cells.iter()) {
        let tone = if *value == 0 && matches!(tone, Tone::Bad | Tone::Warn) {
            Tone::Muted
        } else {
            *tone
        };
        let block = panel(theme, format!(" {label} "), false);
        let inner = block.inner(*cell);
        frame.render_widget(block, *cell);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                fmt::count(*value),
                theme.fg(tone).bold(),
            )))
            .centered(),
            Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1),
        );
    }

    // Rates over time.
    let [up_area, down_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(rates);
    for (area, title, history, now, tone) in [
        (
            up_area,
            "upload",
            &state.up,
            status.upload_rate_total,
            Tone::Good,
        ),
        (
            down_area,
            "download",
            &state.down,
            status.download_rate_total,
            Tone::Accent,
        ),
    ] {
        let block = panel(
            theme,
            Line::from(vec![
                Span::raw(format!(" {title} ")),
                Span::styled(format!("{} ", fmt::rate(now)), theme.fg(tone)),
            ]),
            false,
        );
        let data: Vec<u64> = history.iter().copied().collect();
        frame.render_widget(
            Sparkline::default()
                .block(block)
                .data(&data)
                .style(theme.fg(tone)),
            area,
        );
    }

    // Profiles, and the server beside them where there is room.
    let server_width = if lower.width >= 110 { 46 } else { 0 };
    let [profiles_area, server_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(server_width)]).areas(lower);
    let rows = state.profiles.iter().map(|p| {
        let note = match (&p.status, &p.failure_reason) {
            (types::ProfileStatus::Failed, Some(reason)) => format!("never came up: {reason}"),
            (types::ProfileStatus::VpnDown, _) => "fenced: bring online in Profiles (r)".to_owned(),
            _ if p.effective_state == types::ProfileState::Offline => {
                "offline: held off the network".to_owned()
            }
            _ => match p.forwarded_port {
                Some(port) => format!("forwarded :{port}"),
                None => p.port_forward.to_string(),
            },
        };
        Row::new(vec![
            Line::from(p.profile_id.clone()),
            Line::from(state_span(theme, &p.status.to_string())),
            Line::from(fmt::count(p.torrent_count)),
            Line::from(match (&p.status, &p.tunnel_ip) {
                (_, Some(ip)) => ip.clone(),
                // A failed profile never got a tunnel; a live one without an
                // address is a host profile.
                (types::ProfileStatus::Failed, None) => "—".to_owned(),
                (_, None) => "host".to_owned(),
            }),
            Line::from(Span::styled(note, theme.fg(Tone::Muted))),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Length(12),
                Constraint::Length(9),
                Constraint::Length(16),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(["profile", "status", "torrents", "tunnel", ""]).style(theme.fg(Tone::Muted)),
        )
        .block(panel(theme, " profiles ", false)),
        profiles_area,
    );

    let server = ctx.server;
    let mut lines = vec![];
    if let Some(server) = server {
        lines.push(kv(ctx, "daemon", format!("torrentd {}", server.version)));
        lines.push(kv(ctx, "api", format!("v{}", server.api_version)));
        lines.push(kv(ctx, "auth", server.auth.mode.to_string()));
        if let Some(ttl) = server.auth.session_ttl_secs {
            lines.push(kv(ctx, "session ttl", fmt::duration(ttl)));
        }
        lines.push(kv(
            ctx,
            "pool",
            match (server.pool.configured, server.pool.allow_mutations) {
                (false, _) => "not configured".to_owned(),
                (true, false) => "configured, read-only".to_owned(),
                (true, true) => "configured, mutations allowed".to_owned(),
            },
        ));
    }
    lines.push(kv(
        ctx,
        "resume saves",
        fmt::count(status.pending_resume_count),
    ));
    lines.push(kv(ctx, "live profiles", fmt::count(status.profile_count)));
    if server_width > 0 {
        frame.render_widget(
            Paragraph::new(lines).block(panel(theme, " server ", false)),
            server_area,
        );
    }

    if let Some(confirm) = &state.confirm_reload {
        confirm.view(frame, area, theme);
    }
}

fn kv<'a>(ctx: &Ctx<'_>, key: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:>14}  "), ctx.theme.fg(Tone::Muted)),
        Span::styled(value, ctx.theme.fg(Tone::Plain)),
    ])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing;

    fn loaded() -> State {
        let mut state = State::default();
        let status: types::Status = testing::from_json(json!({
            "torrents_total": 1234, "seeding": 1180, "paused": 20, "checking": 30,
            "disk_error": 1, "errored": 3, "peers_total": 812,
            "upload_rate_total": 52_428_800, "download_rate_total": 0,
            "pending_resume_count": 2, "profile_count": 2,
        }));
        let profiles: Vec<types::Profile> = testing::from_json(json!([
            {"profile_id": "acct_a", "status": "active", "tunnel_ip": "10.2.0.2",
             "desired_state": "online", "effective_state": "online",
             "torrent_count": 900, "listen_port": 51413, "port_forward": "natpmp",
             "forwarded_port": 51413, "user_agent": null, "failure_reason": null},
            {"profile_id": "acct_b", "status": "vpn_down", "tunnel_ip": "10.3.0.2",
             "desired_state": "online", "effective_state": "offline",
             "torrent_count": 334, "listen_port": 51414, "port_forward": "static",
             "forwarded_port": null, "user_agent": null, "failure_reason": null},
            {"profile_id": "acct_c", "status": "failed", "tunnel_ip": null,
             "desired_state": "online", "effective_state": "offline",
             "torrent_count": 0, "listen_port": null, "port_forward": "static",
             "forwarded_port": null, "user_agent": null,
             "failure_reason": "wg-c did not come up within 30s"},
        ]));
        testing::with_ctx(None, |ctx| {
            for rate in [1_000_000, 30_000_000, 52_428_800] {
                let mut s = status.clone();
                s.upload_rate_total = rate;
                update(&mut state, Msg::Loaded(Ok((s, profiles.clone()))), ctx);
            }
        });
        state
    }

    #[test]
    fn the_dashboard_renders_counts_rates_profiles_and_the_server() {
        let state = loaded();
        let server = testing::server(true, false);
        for (w, h) in [(80, 24), (160, 48)] {
            let screen = testing::render(w, h, Some(&server), |ctx, frame, area| {
                view(&state, ctx, frame, area)
            });
            insta::assert_snapshot!(format!("dashboard_{w}x{h}"), screen);
        }
    }

    #[test]
    fn a_fenced_or_failed_profile_says_why() {
        let screen = testing::render(160, 48, None, |ctx, frame, area| {
            view(&loaded(), ctx, frame, area)
        });
        assert!(screen.contains("✖ vpn_down"), "{screen}");
        assert!(
            screen.contains("fenced: bring online in Profiles (r)"),
            "{screen}"
        );
        assert!(!screen.contains("restart the daemon"), "{screen}");
        assert!(screen.contains("never came up: wg-c did not come up within 30s"));
    }

    #[test]
    fn rates_are_kept_as_a_bounded_history() {
        let mut state = loaded();
        assert_eq!(state.up, [1_000_000, 30_000_000, 52_428_800]);
        for _ in 0..HISTORY + 5 {
            push(&mut state.up, 1);
        }
        assert_eq!(state.up.len(), HISTORY);
    }

    #[test]
    fn reload_asks_first_and_escape_cancels() {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('R'))).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty());
            assert!(capturing(&state), "the dialog has the keyboard");
            let msg = on_key(&state, testing::key(KeyCode::Esc)).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty(), "nothing is sent");
            assert!(!capturing(&state));

            update(&mut state, Msg::AskReload, ctx);
            let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1, "one reload request");
        });
    }
}
