//! Drawing the profiles screen: the list, the selected profile's pane, and
//! the words a bad state is described in.

use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::TableState;
use ratatui::widgets::Wrap;
use ratatui::Frame;

use super::State;
use super::Switch;
use super::WIDE;
use crate::api::types;
use crate::fmt;
use crate::screens::contract::Ctx;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;

/// The status a row shows: the daemon's `status`, except that a live profile
/// held offline reads `offline`, which is what an operator acts on.
fn shown_status(profile: &types::Profile) -> String {
    if profile.status == types::ProfileStatus::Active
        && profile.effective_state == types::ProfileState::Offline
    {
        "offline".to_owned()
    } else {
        profile.status.to_string()
    }
}

/// The tunnel column: the address, `host` for a live profile with none, `—`
/// for one that never got a tunnel.
fn tunnel(status: &types::ProfileStatus, tunnel_ip: Option<&String>) -> String {
    match (status, tunnel_ip) {
        (_, Some(ip)) => ip.clone(),
        (types::ProfileStatus::Failed, None) => "—".to_owned(),
        (_, None) => "host".to_owned(),
    }
}

/// The port-forward column: the mode, and the forwarded port where NAT-PMP
/// has one.
fn forward(mode: &types::PortForwardMode, forwarded: Option<i64>) -> String {
    match (mode, forwarded) {
        (_, Some(port)) => format!("{mode} :{port}"),
        (types::PortForwardMode::Natpmp, None) => "natpmp —".to_owned(),
        (types::PortForwardMode::Static, None) => "static".to_owned(),
    }
}

fn port(port: Option<i64>) -> String {
    port.map_or_else(|| "—".to_owned(), |p| p.to_string())
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    if !state.loaded || state.profiles.is_empty() {
        let (text, tone) = match (&state.error, state.loaded) {
            (Some(e), _) => (format!("✖ {e}"), Tone::Bad),
            (None, false) => (
                format!("{} loading profiles…", spinner(ctx.tick)),
                Tone::Muted,
            ),
            (None, true) => ("This daemon has no profiles.".to_owned(), Tone::Muted),
        };
        placeholder(frame, area, theme, &text, tone);
        return;
    }

    // The table takes what its rows need, up to half the screen; the detail
    // pane gets the rest.
    let wanted = state.profiles.len() as u16 + 3;
    let table_height = wanted.min(area.height / 2).max(5.min(area.height));
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Length(table_height), Constraint::Fill(1)]).areas(area);

    list(state, ctx, frame, table_area);
    if let Some(profile) = state.current() {
        detail(state, profile, ctx, frame, detail_area);
    }

    if let Some(asking) = &state.asking {
        asking.confirm.view(frame, area, theme);
    }
}

fn list(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let wide = area.width >= WIDE;
    let rows = state.profiles.iter().map(|p| {
        let bad = p.status != types::ProfileStatus::Active;
        let mut cells = vec![
            Line::from(Span::styled(
                if bad { "!" } else { " " },
                theme.fg(Tone::Bad),
            )),
            Line::from(Span::styled(
                p.profile_id.clone(),
                theme.fg(if bad { Tone::Bad } else { Tone::Plain }),
            )),
            Line::from(state_span(theme, &shown_status(p))),
            Line::from(fmt::count(p.torrent_count)).right_aligned(),
            Line::from(tunnel(&p.status, p.tunnel_ip.as_ref())),
            Line::from(port(p.listen_port)).right_aligned(),
            Line::from(forward(&p.port_forward, p.forwarded_port)),
        ];
        if wide {
            cells.push(Line::from(Span::styled(
                p.user_agent.clone().unwrap_or_else(|| "default".to_owned()),
                theme.fg(Tone::Muted),
            )));
        }
        Row::new(cells)
    });
    let mut widths = vec![
        Constraint::Length(1),
        Constraint::Min(12),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(15),
        Constraint::Length(6),
        Constraint::Length(14),
    ];
    let mut header = vec![
        "", "profile", "status", "torrents", "tunnel", "listen", "forward",
    ];
    if wide {
        widths[1] = Constraint::Length(20);
        widths.push(Constraint::Fill(1));
        header.push("user agent");
    }

    let mut title = vec![Span::raw(format!(" profiles ({}) ", state.profiles.len()))];
    if state.loading {
        title.push(Span::styled(
            format!("{} ", spinner(ctx.tick)),
            theme.fg(Tone::Muted),
        ));
    }
    if let Some(e) = &state.error {
        title.push(Span::styled(format!("✖ {e} "), theme.fg(Tone::Bad)));
    }

    let table = Table::new(rows, widths)
        .header(Row::new(header).style(theme.fg(Tone::Muted)))
        .row_highlight_style(theme.selected())
        .highlight_symbol("▶ ")
        .block(panel(theme, Line::from(title), true));
    let mut table_state = TableState::default().with_selected(Some(state.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn detail(state: &State, profile: &types::Profile, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let id = &profile.profile_id;
    let detail = state.details.get(id).map(|(_, d)| d);
    let pending = state.detail_pending.as_ref() == Some(id);
    let error = state
        .detail_error
        .as_ref()
        .filter(|(for_id, _)| for_id == id)
        .map(|(_, e)| e);

    let mut title = vec![Span::raw(format!(" {id} "))];
    if pending {
        title.push(Span::styled(
            format!("{} ", spinner(ctx.tick)),
            theme.fg(Tone::Muted),
        ));
    }
    if let Some(e) = error {
        title.push(Span::styled(format!("✖ {e} "), theme.fg(Tone::Bad)));
    }
    let block = panel(theme, Line::from(title), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // What the state means, first and in words.
    let banner: Vec<Line> = match profile.status {
        types::ProfileStatus::Active if profile.effective_state == types::ProfileState::Offline => {
            vec![
                Line::from(vec![
                    Span::styled("‖ OFFLINE", theme.fg(Tone::Warn).bold()),
                    Span::styled(" — r brings it online", theme.fg(Tone::Warn)),
                ]),
                Line::from(Span::styled(
                    if profile.desired_state == types::ProfileState::Offline {
                        "Set offline: its session is paused, so none of its torrents announces \
                         or connects to peers, and adds into it are refused. Kept across \
                         restarts."
                    } else {
                        "Held offline by offline-all: its session is paused until online-all \
                         clears it."
                    },
                    theme.fg(Tone::Plain),
                )),
            ]
        }
        types::ProfileStatus::Active => vec![Line::from(vec![
            state_span(theme, "active"),
            Span::styled(" — session up", theme.fg(Tone::Muted)),
        ])],
        types::ProfileStatus::VpnDown => vec![
            Line::from(vec![
                Span::styled("✖ FENCED", theme.fg(Tone::Bad).bold()),
                Span::styled(
                    " — once the tunnel is back, r checks it and brings the profile online",
                    theme.fg(Tone::Bad),
                ),
            ]),
            Line::from(Span::styled(
                "Its tunnel failed after it came up, so the VPN monitor paused its torrents. \
                 Bringing it online re-checks the tunnel and lifts the fence only if the check \
                 passes; no restart is needed.",
                theme.fg(Tone::Plain),
            )),
        ],
        types::ProfileStatus::Failed => {
            vec![
                Line::from(vec![
                    Span::styled("✖ NEVER CAME UP", theme.fg(Tone::Bad).bold()),
                    Span::styled(
                        format!(
                            " — {}",
                            profile
                                .failure_reason
                                .as_deref()
                                .unwrap_or("no reason given")
                        ),
                        theme.fg(Tone::Bad),
                    ),
                ]),
                Line::from(Span::styled(
                    format!(
                        "Its session was never built at boot: its {} {} stranded, not loaded. Fix \
                         the cause and restart the daemon.",
                        fmt::count(profile.torrent_count),
                        if profile.torrent_count == 1 {
                            "torrent is"
                        } else {
                            "torrents are"
                        }
                    ),
                    theme.fg(Tone::Plain),
                )),
            ]
        }
    };

    let waiting = || {
        if error.is_some() {
            Span::styled("✖ unavailable", theme.fg(Tone::Bad))
        } else {
            Span::styled(format!("{} …", spinner(ctx.tick)), theme.fg(Tone::Muted))
        }
    };
    let plain = |s: String| Span::styled(s, theme.fg(Tone::Plain));

    let mut facts =
        vec![
            kv(
                theme,
                "status",
                state_span(theme, &profile.status.to_string()),
            ),
            kv(theme, "set to", plain(profile.desired_state.to_string())),
            kv(theme, "torrents", plain(fmt::count(profile.torrent_count))),
            kv(
                theme,
                "tunnel ip",
                plain(tunnel(&profile.status, profile.tunnel_ip.as_ref())),
            ),
            kv(
                theme,
                "vpn interface",
                match detail {
                    Some(d) => plain(d.vpn_interface.clone().unwrap_or_else(
                        || match profile.status {
                            types::ProfileStatus::Failed => "—".to_owned(),
                            _ => "none (host)".to_owned(),
                        },
                    )),
                    None => waiting(),
                },
            ),
            kv(theme, "listen port", plain(port(profile.listen_port))),
            kv(
                theme,
                "port forward",
                plain(forward(&profile.port_forward, profile.forwarded_port)),
            ),
            kv(
                theme,
                "forward health",
                match detail {
                    Some(d) if d.port_forward_ok => Span::styled("● ok", theme.fg(Tone::Good)),
                    Some(_) => Span::styled("✖ not ok", theme.fg(Tone::Bad)),
                    None => waiting(),
                },
            ),
            kv(
                theme,
                "paused for vpn",
                match detail {
                    Some(d) if d.paused_for_vpn > 0 => {
                        Span::styled(fmt::count(d.paused_for_vpn), theme.fg(Tone::Warn))
                    }
                    Some(d) => plain(fmt::count(d.paused_for_vpn)),
                    None => waiting(),
                },
            ),
            kv(
                theme,
                "user agent",
                plain(
                    profile
                        .user_agent
                        .clone()
                        .unwrap_or_else(|| "default".to_owned()),
                ),
            ),
        ];

    // Tracker domains: beside the facts where there is room, else inline.
    let trackers: Vec<Line> = match detail {
        Some(d) if d.allowed_tracker_domains.is_empty() => {
            vec![Line::from(Span::styled(
                "any (no allow-list)",
                theme.fg(Tone::Muted),
            ))]
        }
        Some(d) => d
            .allowed_tracker_domains
            .iter()
            .map(|domain| Line::from(Span::styled(format!("· {domain}"), theme.fg(Tone::Plain))))
            .collect(),
        None => vec![Line::from(waiting())],
    };

    let [banner_area, body] = Layout::vertical([
        Constraint::Length(banner_height(&banner, inner.width) + 1),
        Constraint::Fill(1),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(banner).wrap(Wrap { trim: true }),
        banner_area,
    );

    if body.width >= 90 {
        let [left, right] =
            Layout::horizontal([Constraint::Length(48), Constraint::Fill(1)]).areas(body);
        frame.render_widget(Paragraph::new(facts), left);
        let mut lines = vec![Line::from(Span::styled(
            "allowed trackers",
            theme.fg(Tone::Muted),
        ))];
        lines.extend(trackers);
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("actions", theme.fg(Tone::Muted))));
        for (key, action) in [("p", Switch::Offline), ("r", Switch::Online)] {
            let what = match (action, &profile.status) {
                (Switch::Online, types::ProfileStatus::VpnDown) => {
                    "check the tunnel, lift the fence, bring online".to_owned()
                }
                _ => action.verb().to_owned(),
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{key:<6}"), theme.key()),
                Span::styled(what, theme.fg(Tone::Plain)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("Enter ", theme.key()),
            Span::styled("show its torrents", theme.fg(Tone::Plain)),
        ]));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), right);
    } else {
        let inline = match detail {
            Some(d) if !d.allowed_tracker_domains.is_empty() => {
                plain(d.allowed_tracker_domains.join(", "))
            }
            _ => trackers
                .into_iter()
                .next()
                .and_then(|l| l.spans.into_iter().next())
                .unwrap_or_default(),
        };
        facts.push(kv(theme, "trackers", inline));
        frame.render_widget(Paragraph::new(facts).wrap(Wrap { trim: false }), body);
    }
}

/// Rows `lines` take wrapped to `width`, roughly: enough for the banner.
fn banner_height(lines: &[Line], width: u16) -> u16 {
    let width = usize::from(width.max(1));
    lines
        .iter()
        .map(|l| l.width().div_ceil(width).max(1) as u16)
        .sum()
}

fn kv<'a>(theme: &Theme, key: &'a str, value: Span<'a>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:>15}  "), theme.fg(Tone::Muted)),
        value,
    ])
}
