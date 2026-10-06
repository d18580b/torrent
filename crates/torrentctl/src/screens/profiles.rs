//! Profiles: every session the daemon runs, whether its tunnel is up, and
//! what to do about one that is not.
//!
//! The list is `GET /v1/profiles`, in the daemon's order (live profiles in
//! config order, then the ones that failed to come up). The pane under it
//! describes the selected profile from `GET /v1/profiles/{id}` and says in
//! words what a bad state means: *fenced* (`vpn_down`: the tunnel failed after
//! bring-up, and only a restart lifts it) is not *never came up* (`failed`:
//! the session was never built, and its torrents are stranded).
//!
//! Details are fetched one at a time. Scrolling past profiles while a request
//! is out fires nothing; when it answers, the profile then selected is
//! fetched if its detail is missing or older than the last refresh. So a fast
//! scroll costs at most two requests, and an answer for a profile no longer
//! selected is kept for that profile but never shown for another.

use std::collections::HashMap;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
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

use crate::api::types;
use crate::api::Failure;
use crate::app::failed;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Toast;
use crate::app::ToastKind;
use crate::fmt;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;

/// Rows `PgUp`/`PgDn` move by.
const PAGE: isize = 10;

/// Terminals at least this wide also show the user agent column.
const WIDE: u16 = 120;

/// A pause or resume of every torrent in one profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bulk {
    Pause,
    Resume,
}

impl Bulk {
    fn verb(self) -> &'static str {
        match self {
            Bulk::Pause => "pause",
            Bulk::Resume => "resume",
        }
    }

    fn past(self) -> &'static str {
        match self {
            Bulk::Pause => "paused",
            Bulk::Resume => "resumed",
        }
    }
}

/// A pending bulk action and the dialog asking about it.
#[derive(Debug)]
pub struct Asking {
    pub action: Bulk,
    pub profile_id: String,
    pub confirm: Confirm,
}

#[derive(Debug, Default)]
pub struct State {
    /// The profiles, in the daemon's order.
    pub profiles: Vec<types::Profile>,
    pub selected: usize,
    /// Whether the list has loaded at least once.
    pub loaded: bool,
    pub loading: bool,
    pub error: Option<String>,
    /// Details by profile id, each with the refresh generation it answers.
    pub details: HashMap<String, (u64, types::ProfileDetail)>,
    /// Bumped on every refresh, so a detail from before it is re-fetched.
    pub generation: u64,
    /// The profile whose detail is being fetched; at most one at a time.
    pub detail_pending: Option<String>,
    /// The last failed detail load: the profile, and why.
    pub detail_error: Option<(String, String)>,
    pub asking: Option<Asking>,
}

impl State {
    /// The selected profile, if any.
    pub fn current(&self) -> Option<&types::Profile> {
        self.profiles.get(self.selected)
    }
}

#[derive(Debug)]
pub enum Msg {
    Loaded(Result<Vec<types::Profile>, Failure>),
    DetailLoaded {
        profile_id: String,
        generation: u64,
        result: Result<types::ProfileDetail, Failure>,
    },
    /// Move the selection by this many rows.
    Move(isize),
    Top,
    Bottom,
    /// Ask to pause or resume every torrent of the selected profile.
    Ask(Bulk),
    ConfirmKey(KeyEvent),
    /// Pause or resume every torrent of this profile, now.
    Run(Bulk, String),
    Ran {
        action: Bulk,
        profile_id: String,
        result: Result<types::BulkOutcome, Failure>,
    },
    /// Show the selected profile's torrents.
    ShowTorrents,
}

pub const KEYS: &[(&str, &str)] = &[
    ("Enter/t", "its torrents"),
    ("p", "pause all"),
    ("r", "resume all"),
    ("j/k", "select"),
    ("g/G", "top/bottom"),
    ("PgUp/PgDn", "page"),
    ("↑/↓", "select"),
];

pub fn capturing(state: &State) -> bool {
    state.asking.is_some()
}

pub fn on_key(state: &State, key: KeyEvent) -> Option<Msg> {
    if state.asking.is_some() {
        return Some(Msg::ConfirmKey(key));
    }
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => Some(Msg::Move(1)),
        KeyCode::Char('k') | KeyCode::Up => Some(Msg::Move(-1)),
        KeyCode::PageDown => Some(Msg::Move(PAGE)),
        KeyCode::PageUp => Some(Msg::Move(-PAGE)),
        KeyCode::Char('g') | KeyCode::Home => Some(Msg::Top),
        KeyCode::Char('G') | KeyCode::End => Some(Msg::Bottom),
        KeyCode::Enter | KeyCode::Char('t') => Some(Msg::ShowTorrents),
        KeyCode::Char('p') => Some(Msg::Ask(Bulk::Pause)),
        KeyCode::Char('r') => Some(Msg::Ask(Bulk::Resume)),
        _ => None,
    }
}

pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    // Every detail on hand is now older than this refresh; the selected one
    // is re-fetched once the list answers.
    state.generation += 1;
    if state.loading {
        return Vec::new();
    }
    state.loading = true;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        let result = crate::api::call(api.client.list_profiles()).await;
        crate::app::Msg::Profiles(Msg::Loaded(result.map(|list| list.items)))
    })]
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match msg {
        Msg::Loaded(Ok(profiles)) => {
            // Keep the selection on the same profile where it still exists.
            let was = state.current().map(|p| p.profile_id.clone());
            state.profiles = profiles;
            state.selected = was
                .and_then(|id| state.profiles.iter().position(|p| p.profile_id == id))
                .unwrap_or(state.selected)
                .min(state.profiles.len().saturating_sub(1));
            state.loaded = true;
            state.loading = false;
            state.error = None;
            load_detail(state, ctx)
        }
        Msg::Loaded(Err(failure)) => {
            state.loading = false;
            state.error = Some(failure.message());
            if failure.is_unauthenticated() {
                vec![Effect::now(failed("loading profiles", failure))]
            } else {
                Vec::new()
            }
        }
        Msg::DetailLoaded {
            profile_id,
            generation,
            result,
        } => {
            if state.detail_pending.as_ref() == Some(&profile_id) {
                state.detail_pending = None;
            }
            match result {
                Ok(detail) => {
                    if state
                        .detail_error
                        .as_ref()
                        .is_some_and(|(id, _)| *id == profile_id)
                    {
                        state.detail_error = None;
                    }
                    state.details.insert(profile_id, (generation, detail));
                    // The selection may have moved on while this was out.
                    load_detail(state, ctx)
                }
                Err(failure) if failure.is_unauthenticated() => {
                    vec![Effect::now(failed("loading a profile", failure))]
                }
                Err(failure) => {
                    let moved_on = state.current().is_some_and(|p| p.profile_id != profile_id);
                    state.detail_error = Some((profile_id, failure.message()));
                    if moved_on {
                        load_detail(state, ctx)
                    } else {
                        Vec::new()
                    }
                }
            }
        }
        Msg::Move(by) => {
            let last = state.profiles.len().saturating_sub(1) as isize;
            select(
                state,
                (state.selected as isize + by).clamp(0, last.max(0)) as usize,
                ctx,
            )
        }
        Msg::Top => select(state, 0, ctx),
        Msg::Bottom => select(state, state.profiles.len().saturating_sub(1), ctx),
        Msg::Ask(action) => {
            let Some(profile) = state.current() else {
                return Vec::new();
            };
            // Refused by the daemon whatever we send: say why instead.
            if refusal(&profile.status, action).is_some() {
                return vec![Effect::toast(unavailable(action, profile, None))];
            }
            let torrents = match profile.torrent_count {
                1 => "its 1 torrent".to_owned(),
                n => format!("all {} of its torrents", fmt::count(n)),
            };
            let mut body = format!(
                "{} {torrents} in profile {}?",
                capitalised(action.verb()),
                profile.profile_id
            );
            if profile.status == types::ProfileStatus::VpnDown {
                body.push_str(" It is fenced, so they are paused already.");
            }
            state.asking = Some(Asking {
                action,
                profile_id: profile.profile_id.clone(),
                confirm: Confirm::new(
                    format!(
                        "{} all — {}",
                        capitalised(action.verb()),
                        profile.profile_id
                    ),
                    body,
                ),
            });
            Vec::new()
        }
        Msg::ConfirmKey(key) => {
            let Some(asking) = state.asking.as_mut() else {
                return Vec::new();
            };
            match asking.confirm.on_key(key) {
                Confirmed::Yes => match state.asking.take() {
                    Some(asking) => update(state, Msg::Run(asking.action, asking.profile_id), ctx),
                    None => Vec::new(),
                },
                Confirmed::No => {
                    state.asking = None;
                    Vec::new()
                }
                Confirmed::Pending => Vec::new(),
            }
        }
        Msg::Run(action, profile_id) => {
            let api = ctx.api.clone();
            vec![Effect::new(async move {
                let result = match action {
                    Bulk::Pause => {
                        crate::api::call(api.client.pause_profile(profile_id.clone())).await
                    }
                    Bulk::Resume => {
                        crate::api::call(api.client.resume_profile(profile_id.clone())).await
                    }
                };
                crate::app::Msg::Profiles(Msg::Ran {
                    action,
                    profile_id,
                    result,
                })
            })]
        }
        Msg::Ran {
            action,
            profile_id,
            result: Ok(outcome),
        } => {
            let mut text = format!(
                "{profile_id}: {} {} torrent{}",
                action.past(),
                fmt::count(outcome.torrent_count),
                if outcome.torrent_count == 1 { "" } else { "s" },
            );
            let toast = if outcome.failed_count > 0 {
                text.push_str(&format!(
                    "; {} refused by the engine",
                    fmt::count(outcome.failed_count)
                ));
                Toast {
                    kind: ToastKind::Error,
                    text,
                    request_id: None,
                }
            } else {
                Toast::success(text)
            };
            let mut effects = vec![Effect::toast(toast)];
            effects.extend(refresh(state, ctx));
            effects
        }
        Msg::Ran {
            action,
            profile_id,
            result: Err(failure),
        } if failure.is("profile-unavailable") => {
            let toast = match state.profiles.iter().find(|p| p.profile_id == profile_id) {
                Some(profile) => unavailable(action, profile, Some(&failure)),
                None => Toast::failure(&format!("{} all in {profile_id}", action.verb()), &failure),
            };
            // The list said it could; it is out of date.
            let mut effects = vec![Effect::toast(toast)];
            effects.extend(refresh(state, ctx));
            effects
        }
        Msg::Ran {
            action,
            profile_id,
            result: Err(failure),
        } => vec![Effect::now(failed(
            &format!("{} all in {profile_id}", action.verb()),
            failure,
        ))],
        Msg::ShowTorrents => match state.current() {
            Some(profile) => vec![Effect::now(crate::app::Msg::ShowTorrentsOf(
                profile.profile_id.clone(),
            ))],
            None => Vec::new(),
        },
    }
}

/// Select row `index`, fetching its detail if needed.
fn select(state: &mut State, index: usize, ctx: &Ctx<'_>) -> Vec<Effect> {
    if index == state.selected {
        return Vec::new();
    }
    state.selected = index;
    load_detail(state, ctx)
}

/// Fetch the selected profile's detail, unless one fetch is already out (its
/// answer calls this again) or what is on hand is from this refresh.
fn load_detail(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.detail_pending.is_some() {
        return Vec::new();
    }
    let Some(profile) = state.current() else {
        return Vec::new();
    };
    let profile_id = profile.profile_id.clone();
    let fresh = state
        .details
        .get(&profile_id)
        .is_some_and(|(generation, _)| *generation >= state.generation);
    if fresh {
        return Vec::new();
    }
    state.detail_pending = Some(profile_id.clone());
    let generation = state.generation;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        let result = crate::api::call(api.client.get_profile(profile_id.clone())).await;
        crate::app::Msg::Profiles(Msg::DetailLoaded {
            profile_id,
            generation,
            result,
        })
    })]
}

/// Why the daemon refuses `action` for a profile in `status`, if it does:
/// nothing of a profile that never came up is loaded, and a fenced one's
/// torrents stay paused until a restart (pausing them again is harmless).
fn refusal(status: &types::ProfileStatus, action: Bulk) -> Option<&'static str> {
    match (status, action) {
        (types::ProfileStatus::Failed, _) => Some("never came up"),
        (types::ProfileStatus::VpnDown, Bulk::Resume) => Some("fenced until the daemon restarts"),
        _ => None,
    }
}

/// The toast for a pause or resume the daemon refuses (or would refuse)
/// because `profile` is unavailable.
fn unavailable(action: Bulk, profile: &types::Profile, failure: Option<&Failure>) -> Toast {
    let why = match profile.status {
        types::ProfileStatus::Failed => format!(
            "never came up: {}",
            profile
                .failure_reason
                .clone()
                .or_else(|| failure.and_then(|f| f.detail.clone()))
                .unwrap_or_else(|| "no reason given".to_owned())
        ),
        types::ProfileStatus::VpnDown => {
            "fenced (its tunnel failed); restart the daemon to resume it".to_owned()
        }
        types::ProfileStatus::Active => failure
            .map(Failure::message)
            .unwrap_or_else(|| "the profile is unavailable".to_owned()),
    };
    Toast {
        kind: ToastKind::Error,
        text: format!(
            "cannot {} all in {}: {why}",
            action.verb(),
            profile.profile_id
        ),
        request_id: failure.and_then(|f| f.request_id.clone()),
    }
}

fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
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
            Line::from(state_span(theme, &p.status.to_string())),
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
        types::ProfileStatus::Active => vec![Line::from(vec![
            state_span(theme, "active"),
            Span::styled(" — session up", theme.fg(Tone::Muted)),
        ])],
        types::ProfileStatus::VpnDown => vec![
            Line::from(vec![
                Span::styled("✖ FENCED", theme.fg(Tone::Bad).bold()),
                Span::styled(" — restart the daemon to resume", theme.fg(Tone::Bad)),
            ]),
            Line::from(Span::styled(
                "Its tunnel failed after it came up, so the VPN monitor paused its torrents. \
                 It stays fenced until the daemon restarts; nothing lifts it before then.",
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
        for (key, action) in [("p", Bulk::Pause), ("r", Bulk::Resume)] {
            let what = format!(
                "{} all {} torrents",
                action.verb(),
                fmt::count(profile.torrent_count)
            );
            lines.push(match refusal(&profile.status, action) {
                None => Line::from(vec![
                    Span::styled(format!("{key:<6}"), theme.key()),
                    Span::styled(what, theme.fg(Tone::Plain)),
                ]),
                Some(why) => Line::from(vec![
                    Span::styled(format!("{key:<6}"), theme.fg(Tone::Muted)),
                    Span::styled(format!("✖ {what} — refused: {why}"), theme.fg(Tone::Muted)),
                ]),
            });
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing;

    fn profiles() -> Vec<types::Profile> {
        testing::from_json(json!([
            {"profile_id": "acct_a", "status": "active", "tunnel_ip": "10.2.0.2",
             "torrent_count": 900, "listen_port": null, "port_forward": "natpmp",
             "forwarded_port": 51413, "user_agent": "qBittorrent/4.6.2", "failure_reason": null},
            {"profile_id": "acct_b", "status": "vpn_down", "tunnel_ip": "10.3.0.2",
             "torrent_count": 334, "listen_port": 51414, "port_forward": "static",
             "forwarded_port": null, "user_agent": null, "failure_reason": null},
            {"profile_id": "host", "status": "active", "tunnel_ip": null,
             "torrent_count": 1, "listen_port": 6881, "port_forward": "static",
             "forwarded_port": null, "user_agent": null, "failure_reason": null},
            {"profile_id": "acct_c", "status": "failed", "tunnel_ip": null,
             "torrent_count": 12, "listen_port": null, "port_forward": "natpmp",
             "forwarded_port": null, "user_agent": null,
             "failure_reason": "wg-c did not come up within 30s"},
        ]))
    }

    fn detail_of(id: &str) -> types::ProfileDetail {
        let mut value = serde_json::to_value(
            profiles()
                .into_iter()
                .find(|p| p.profile_id == id)
                .expect("a fixture profile"),
        )
        .expect("serialisable");
        let (iface, domains, paused, ok) = match id {
            "acct_a" => (
                json!("wg-a"),
                json!(["tracker.example.org", "announce.example.net"]),
                0,
                true,
            ),
            "acct_b" => (json!("wg-b"), json!(["tracker.example.org"]), 334, true),
            "host" => (json!(null), json!([]), 0, true),
            _ => (json!("wg-c"), json!([]), 0, false),
        };
        value["vpn_interface"] = iface;
        value["allowed_tracker_domains"] = domains;
        value["paused_for_vpn"] = json!(paused);
        value["port_forward_ok"] = json!(ok);
        testing::from_json(value)
    }

    /// Answer the detail request that is out, if any, with the fixture.
    fn answer(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
        let Some(profile_id) = state.detail_pending.clone() else {
            return Vec::new();
        };
        let generation = state.generation;
        let result = Ok(detail_of(&profile_id));
        update(
            state,
            Msg::DetailLoaded {
                profile_id,
                generation,
                result,
            },
            ctx,
        )
    }

    /// Loaded, with `id` selected and its detail answered.
    fn loaded(id: &str) -> State {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            refresh(&mut state, ctx);
            update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
            answer(&mut state, ctx);
            let index = state
                .profiles
                .iter()
                .position(|p| p.profile_id == id)
                .unwrap();
            update(&mut state, Msg::Move(index as isize), ctx);
            answer(&mut state, ctx);
        });
        state
    }

    fn conflict(detail: &str) -> Failure {
        Failure {
            status: Some(409),
            slug: Some("profile-unavailable".into()),
            title: "The profile is unavailable".into(),
            detail: Some(detail.into()),
            request_id: Some("req-1".into()),
            ..Default::default()
        }
    }

    fn outcome(torrents: i64, failed: i64) -> types::BulkOutcome {
        testing::from_json(json!({
            "torrent_count": torrents, "failed_count": failed, "failed_infohashes": [],
            "skipped_profiles": [],
        }))
    }

    /// The message an effect delivers, for effects that are `Effect::now`.
    fn run(effect: Effect) -> crate::app::Msg {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(effect.0)
    }

    fn toast_of(effect: Effect) -> Toast {
        match run(effect) {
            crate::app::Msg::Toast(toast) => toast,
            other => panic!("expected a toast, got {other:?}"),
        }
    }

    #[test]
    fn loading_selects_the_first_and_fetches_its_detail() {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            assert_eq!(refresh(&mut state, ctx).len(), 1);
            assert!(state.loading);
            assert!(
                refresh(&mut state, ctx).is_empty(),
                "one list load at a time"
            );
            let effects = update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
            assert_eq!(effects.len(), 1, "the selected profile's detail");
            assert!(state.loaded && !state.loading);
            assert_eq!(state.detail_pending.as_deref(), Some("acct_a"));
            assert!(answer(&mut state, ctx).is_empty(), "nothing else to fetch");
            assert!(state.details.contains_key("acct_a"));
        });
    }

    #[test]
    fn a_refresh_keeps_the_selection_on_the_same_profile_and_refetches_its_detail() {
        let mut state = loaded("host");
        testing::with_ctx(None, |ctx| {
            assert_eq!(refresh(&mut state, ctx).len(), 1);
            // `host` moved up one place.
            let mut reordered = profiles();
            reordered.remove(1);
            let effects = update(&mut state, Msg::Loaded(Ok(reordered)), ctx);
            assert_eq!(state.current().unwrap().profile_id, "host");
            assert_eq!(effects.len(), 1, "its detail is older than the refresh");
            assert!(
                state.details.contains_key("host"),
                "the old detail shows meanwhile"
            );
        });
    }

    #[test]
    fn a_failed_list_load_keeps_the_last_good_list() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            refresh(&mut state, ctx);
            let effects = update(
                &mut state,
                Msg::Loaded(Err(Failure::local("Cannot reach the daemon", None))),
                ctx,
            );
            assert!(effects.is_empty(), "shown in the panel, not a toast");
            assert_eq!(state.profiles.len(), 4);
            assert_eq!(state.error.as_deref(), Some("Cannot reach the daemon"));
        });
    }

    #[test]
    fn scrolling_fast_fires_one_detail_request_and_drops_stale_answers() {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            refresh(&mut state, ctx);
            update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
            assert_eq!(state.detail_pending.as_deref(), Some("acct_a"));
            // Scroll to the bottom while acct_a's detail is out: no requests.
            for _ in 0..3 {
                assert!(update(&mut state, Msg::Move(1), ctx).is_empty());
            }
            assert_eq!(state.current().unwrap().profile_id, "acct_c");
            // acct_a answers: kept for acct_a, not shown for acct_c, and
            // acct_c is fetched.
            let effects = answer(&mut state, ctx);
            assert_eq!(effects.len(), 1);
            assert_eq!(state.detail_pending.as_deref(), Some("acct_c"));
            assert!(!state.details.contains_key("acct_c"));
            let screen = testing::render(160, 48, None, |ctx, frame, area| {
                view(&state, ctx, frame, area)
            });
            assert!(
                !screen.contains("wg-a"),
                "acct_a's detail is not shown for acct_c"
            );
            answer(&mut state, ctx);
            // Back to acct_a: its detail is on hand from this refresh.
            assert!(update(&mut state, Msg::Top, ctx).is_empty());
            assert!(
                update(&mut state, Msg::Move(-1), ctx).is_empty(),
                "clamped at the top"
            );
        });
    }

    #[test]
    fn a_failed_detail_load_is_shown_for_its_profile() {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            refresh(&mut state, ctx);
            update(&mut state, Msg::Loaded(Ok(profiles())), ctx);
            let generation = state.generation;
            let effects = update(
                &mut state,
                Msg::DetailLoaded {
                    profile_id: "acct_a".into(),
                    generation,
                    result: Err(Failure::local("The daemon did not answer", None)),
                },
                ctx,
            );
            assert!(effects.is_empty());
            assert_eq!(
                state.detail_error,
                Some(("acct_a".into(), "The daemon did not answer".into()))
            );
            assert!(state.detail_pending.is_none());
            let screen = testing::render(160, 48, None, |ctx, frame, area| {
                view(&state, ctx, frame, area)
            });
            assert!(screen.contains("✖ The daemon did not answer"), "{screen}");
        });
    }

    #[test]
    fn pause_all_asks_naming_the_profile_and_its_torrents_then_sends_one_request() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('p'))).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty());
            assert!(capturing(&state));
            let asking = state.asking.as_ref().unwrap();
            assert_eq!(asking.action, Bulk::Pause);
            assert!(asking.confirm.body.contains("acct_a"));
            assert!(asking.confirm.body.contains("all 900 of its torrents"));

            let msg = on_key(&state, testing::key(KeyCode::Char('n'))).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty(), "nothing is sent");
            assert!(!capturing(&state));

            update(&mut state, Msg::Ask(Bulk::Resume), ctx);
            let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1, "one resume request");
            assert!(state.asking.is_none());
        });
    }

    #[test]
    fn a_fenced_profile_may_be_paused_but_not_resumed() {
        let mut state = loaded("acct_b");
        testing::with_ctx(None, |ctx| {
            assert!(update(&mut state, Msg::Ask(Bulk::Pause), ctx).is_empty());
            assert!(state
                .asking
                .as_ref()
                .unwrap()
                .confirm
                .body
                .contains("paused already"));
            state.asking = None;

            let effects = update(&mut state, Msg::Ask(Bulk::Resume), ctx);
            assert!(state.asking.is_none(), "no dialog for a refused action");
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.kind, ToastKind::Error);
            assert!(toast.text.contains("fenced"), "{}", toast.text);
            assert!(toast.text.contains("restart the daemon"));
        });
    }

    #[test]
    fn a_profile_that_never_came_up_cannot_be_paused_and_says_why() {
        let mut state = loaded("acct_c");
        testing::with_ctx(None, |ctx| {
            let effects = update(&mut state, Msg::Ask(Bulk::Pause), ctx);
            assert!(state.asking.is_none());
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(
                toast.text,
                "cannot pause all in acct_c: never came up: wg-c did not come up within 30s"
            );
        });
    }

    #[test]
    fn a_bulk_outcome_is_toasted_with_its_counts_and_refreshes() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Bulk::Pause,
                    profile_id: "acct_a".into(),
                    result: Ok(outcome(900, 0)),
                },
                ctx,
            );
            assert_eq!(effects.len(), 2, "a toast and a refresh");
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.kind, ToastKind::Success);
            assert_eq!(toast.text, "acct_a: paused 900 torrents");

            state.loading = false;
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Bulk::Resume,
                    profile_id: "acct_a".into(),
                    result: Ok(outcome(898, 2)),
                },
                ctx,
            );
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.kind, ToastKind::Error, "not everything was reached");
            assert_eq!(
                toast.text,
                "acct_a: resumed 898 torrents; 2 refused by the engine"
            );
        });
    }

    #[test]
    fn a_409_explains_the_profile_state_the_list_had_not_caught_up_with() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            // The list says acct_b is fenced: the explanation is ours.
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Bulk::Resume,
                    profile_id: "acct_b".into(),
                    result: Err(conflict("profile vpn_down; restart daemon to resume")),
                },
                ctx,
            );
            assert_eq!(effects.len(), 2, "a toast and a refresh");
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert!(toast.text.contains("fenced"), "{}", toast.text);
            assert_eq!(toast.request_id.as_deref(), Some("req-1"));

            // The list said acct_a was fine: the daemon's words.
            state.loading = false;
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Bulk::Pause,
                    profile_id: "acct_a".into(),
                    result: Err(conflict("profile vpn_down; restart daemon to resume")),
                },
                ctx,
            );
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(
                toast.text,
                "cannot pause all in acct_a: The profile is unavailable: profile vpn_down; \
                 restart daemon to resume"
            );
        });
    }

    #[test]
    fn any_other_failure_is_a_failure_toast() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Bulk::Pause,
                    profile_id: "acct_a".into(),
                    result: Err(Failure::local("Cannot reach the daemon", None)),
                },
                ctx,
            );
            assert_eq!(effects.len(), 1);
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.text, "pause all in acct_a: Cannot reach the daemon");
        });
    }

    #[test]
    fn enter_and_t_show_the_selected_profiles_torrents() {
        let mut state = loaded("acct_b");
        for code in [KeyCode::Enter, KeyCode::Char('t')] {
            let msg = on_key(&state, testing::key(code)).unwrap();
            let effects = testing::with_ctx(None, |ctx| update(&mut state, msg, ctx));
            assert_eq!(effects.len(), 1);
            match run(effects.into_iter().next().unwrap()) {
                crate::app::Msg::ShowTorrentsOf(id) => assert_eq!(id, "acct_b"),
                other => panic!("expected ShowTorrentsOf, got {other:?}"),
            }
        }
    }

    #[test]
    fn keys_map_to_messages() {
        let state = State::default();
        let cases = [
            (KeyCode::Char('j'), "Move(1)"),
            (KeyCode::Down, "Move(1)"),
            (KeyCode::Char('k'), "Move(-1)"),
            (KeyCode::Up, "Move(-1)"),
            (KeyCode::PageDown, "Move(10)"),
            (KeyCode::PageUp, "Move(-10)"),
            (KeyCode::Char('g'), "Top"),
            (KeyCode::Char('G'), "Bottom"),
            (KeyCode::Enter, "ShowTorrents"),
            (KeyCode::Char('t'), "ShowTorrents"),
            (KeyCode::Char('p'), "Ask(Pause)"),
            (KeyCode::Char('r'), "Ask(Resume)"),
        ];
        for (code, expected) in cases {
            let msg = on_key(&state, testing::key(code));
            assert_eq!(format!("{msg:?}"), format!("Some({expected})"), "{code:?}");
        }
        for global in ['q', '?', ':', '1', '9'] {
            assert!(
                on_key(&state, testing::key(KeyCode::Char(global))).is_none(),
                "{global}"
            );
        }
        assert!(on_key(&state, testing::key(KeyCode::Tab)).is_none());
    }

    #[test]
    fn the_list_with_the_detail_of_an_active_a_fenced_and_a_failed_profile() {
        for id in ["acct_a", "acct_b", "acct_c"] {
            let state = loaded(id);
            let screen = testing::render(160, 48, None, |ctx, frame, area| {
                view(&state, ctx, frame, area)
            });
            insta::assert_snapshot!(format!("profiles_{id}_160x48"), screen);
        }
    }

    #[test]
    fn the_list_fits_a_small_terminal() {
        let state = loaded("acct_b");
        let screen = testing::render(80, 24, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        assert!(
            screen.contains("FENCED — restart the daemon to resume"),
            "{screen}"
        );
        insta::assert_snapshot!("profiles_80x24", screen);
    }

    #[test]
    fn the_pause_all_confirm() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| update(&mut state, Msg::Ask(Bulk::Pause), ctx));
        let screen = testing::render(80, 24, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        insta::assert_snapshot!("profiles_confirm_pause_80x24", screen);
    }
}
