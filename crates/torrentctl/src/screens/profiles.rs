//! Profiles: every session the daemon runs, whether its tunnel is up, and
//! what to do about one that is not.
//!
//! The list is `GET /v1/profiles`, in the daemon's order (live profiles in
//! config order, then the ones that failed to come up). The pane under it
//! describes the selected profile from `GET /v1/profiles/{id}` and says in
//! words what a bad state means: *fenced* (`vpn_down`: the tunnel failed after
//! bring-up, and bringing the profile online lifts it once the tunnel checks
//! healthy) is not *offline* (the operator holds it off the network) and
//! neither is *never came up* (`failed`: the session was never built, and its
//! torrents are stranded).
//!
//! `p` takes the selected profile offline and `r` brings it online, through
//! `PATCH /v1/profiles/{id}`. Bringing a fenced profile online is how its
//! fence is lifted without a restart; the daemon refuses while the tunnel
//! still fails, and says why.
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

/// Taking one profile offline, or bringing it online.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Switch {
    Offline,
    Online,
}

impl Switch {
    fn verb(self) -> &'static str {
        match self {
            Switch::Offline => "take offline",
            Switch::Online => "bring online",
        }
    }

    fn state(self) -> types::ProfileState {
        match self {
            Switch::Offline => types::ProfileState::Offline,
            Switch::Online => types::ProfileState::Online,
        }
    }
}

/// A pending switch and the dialog asking about it.
#[derive(Debug)]
pub struct Asking {
    pub action: Switch,
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
    /// Ask to take the selected profile offline or bring it online.
    Ask(Switch),
    ConfirmKey(KeyEvent),
    /// Set this profile offline or online, now.
    Run(Switch, String),
    Ran {
        action: Switch,
        profile_id: String,
        result: Result<types::ProfileDetail, Failure>,
    },
    /// Show the selected profile's torrents.
    ShowTorrents,
}

pub const KEYS: &[(&str, &str)] = &[
    ("Enter/t", "its torrents"),
    ("p", "take offline"),
    ("r", "bring online"),
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
        KeyCode::Char('p') => Some(Msg::Ask(Switch::Offline)),
        KeyCode::Char('r') => Some(Msg::Ask(Switch::Online)),
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
            let body = ask_body(action, profile);
            state.asking = Some(Asking {
                action,
                profile_id: profile.profile_id.clone(),
                confirm: Confirm::new(
                    format!("{} — {}", capitalised(action.verb()), profile.profile_id),
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
                let body = types::SetProfileState {
                    state: action.state(),
                };
                let result =
                    crate::api::call(api.client.set_profile_state(profile_id.clone(), &body)).await;
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
            result: Ok(detail),
        } => {
            let was_fenced = state
                .profiles
                .iter()
                .find(|p| p.profile_id == profile_id)
                .is_some_and(|p| p.status == types::ProfileStatus::VpnDown);
            let online = detail.effective_state == types::ProfileState::Online;
            let text = match action {
                Switch::Offline => format!("{profile_id}: offline"),
                Switch::Online if was_fenced && online => {
                    format!("{profile_id}: tunnel checked healthy; fence lifted, online")
                }
                // The fence lifted, but something else (offline-all) still
                // holds the profile off the network.
                Switch::Online if was_fenced => format!(
                    "{profile_id}: tunnel checked healthy; fence lifted; still off the network ({})",
                    still_off(&detail.status)
                ),
                Switch::Online if online => format!("{profile_id}: online"),
                Switch::Online => format!(
                    "{profile_id}: set online, still off the network ({})",
                    still_off(&detail.status)
                ),
            };
            let mut effects = vec![Effect::toast(Toast::success(text))];
            effects.extend(refresh(state, ctx));
            effects
        }
        Msg::Ran {
            action,
            profile_id,
            result: Err(failure),
        } if failure.is("profile-unavailable") => {
            // A fenced profile whose tunnel still fails: the daemon's words
            // say which check, and the profile is unchanged.
            let toast = Toast {
                kind: ToastKind::Error,
                text: format!(
                    "cannot {} {profile_id}: {}",
                    action.verb(),
                    failure.detail.clone().unwrap_or_else(|| failure.message())
                ),
                request_id: failure.request_id.clone(),
            };
            let mut effects = vec![Effect::toast(toast)];
            effects.extend(refresh(state, ctx));
            effects
        }
        Msg::Ran {
            action,
            profile_id,
            result: Err(failure),
        } => vec![Effect::now(failed(
            &format!("{} {profile_id}", action.verb()),
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

/// What the confirm dialog says `action` will do to `profile`.
fn ask_body(action: Switch, profile: &types::Profile) -> String {
    let id = &profile.profile_id;
    let torrents = match profile.torrent_count {
        1 => "its 1 torrent".to_owned(),
        n => format!("its {} torrents", fmt::count(n)),
    };
    match (action, &profile.status) {
        (Switch::Offline, types::ProfileStatus::Failed) => format!(
            "Take profile {id} offline? It never came up, so this only records the choice: it \
             starts offline when it next comes up."
        ),
        (Switch::Offline, _) => format!(
            "Take profile {id} offline? None of {torrents} will announce or connect to peers, \
             and adds into it are refused, until it is brought online. Kept across restarts."
        ),
        (Switch::Online, types::ProfileStatus::VpnDown) => format!(
            "Bring profile {id} online? It is fenced: the daemon checks its tunnel first, and \
             lifts the fence and resumes {torrents} only if the check passes."
        ),
        (Switch::Online, types::ProfileStatus::Failed) => format!(
            "Bring profile {id} online? It never came up, so this only records the choice for \
             when it next comes up."
        ),
        (Switch::Online, types::ProfileStatus::Active) => {
            format!("Bring profile {id} online? This puts {torrents} back on the network.")
        }
    }
}

/// Why a profile set online is still off the network.
fn still_off(status: &types::ProfileStatus) -> &'static str {
    match status {
        types::ProfileStatus::Failed => "it never came up",
        types::ProfileStatus::VpnDown => "it is fenced",
        types::ProfileStatus::Active => "offline-all is on",
    }
}

fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing;

    fn profiles() -> Vec<types::Profile> {
        testing::from_json(json!([
            {"profile_id": "acct_a", "status": "active", "tunnel_ip": "10.2.0.2",
             "desired_state": "online", "effective_state": "online",
             "torrent_count": 900, "listen_port": null, "port_forward": "natpmp",
             "forwarded_port": 51413, "user_agent": "qBittorrent/4.6.2", "failure_reason": null},
            {"profile_id": "acct_b", "status": "vpn_down", "tunnel_ip": "10.3.0.2",
             "desired_state": "online", "effective_state": "offline",
             "torrent_count": 334, "listen_port": 51414, "port_forward": "static",
             "forwarded_port": null, "user_agent": null, "failure_reason": null},
            {"profile_id": "host", "status": "active", "tunnel_ip": null,
             "desired_state": "offline", "effective_state": "offline",
             "torrent_count": 1, "listen_port": 6881, "port_forward": "static",
             "forwarded_port": null, "user_agent": null, "failure_reason": null},
            {"profile_id": "acct_c", "status": "failed", "tunnel_ip": null,
             "desired_state": "online", "effective_state": "offline",
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

    /// `id`'s detail as the daemon answers a switch: `status` and
    /// `effective_state` as they stand after it.
    fn switched(id: &str, status: &str, effective: &str) -> types::ProfileDetail {
        let mut value = serde_json::to_value(detail_of(id)).expect("serialisable");
        value["status"] = json!(status);
        value["effective_state"] = json!(effective);
        value["desired_state"] = json!(effective);
        testing::from_json(value)
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
    fn taking_offline_asks_naming_the_profile_and_its_torrents_then_sends_one_request() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('p'))).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty());
            assert!(capturing(&state));
            let asking = state.asking.as_ref().unwrap();
            assert_eq!(asking.action, Switch::Offline);
            assert!(asking.confirm.body.contains("acct_a"));
            assert!(asking.confirm.body.contains("its 900 torrents"));
            assert!(asking.confirm.body.contains("Kept across restarts"));

            let msg = on_key(&state, testing::key(KeyCode::Char('n'))).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty(), "nothing is sent");
            assert!(!capturing(&state));

            update(&mut state, Msg::Ask(Switch::Online), ctx);
            let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1, "one request");
            assert!(state.asking.is_none());
        });
    }

    #[test]
    fn a_fenced_profile_is_brought_online_through_the_tunnel_check() {
        let mut state = loaded("acct_b");
        testing::with_ctx(None, |ctx| {
            assert!(update(&mut state, Msg::Ask(Switch::Online), ctx).is_empty());
            let body = &state.asking.as_ref().unwrap().confirm.body;
            assert!(body.contains("It is fenced"), "{body}");
            assert!(body.contains("checks its tunnel first"), "{body}");
            let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1, "sent, not refused");
        });
    }

    #[test]
    fn a_profile_that_never_came_up_records_the_choice_for_its_next_boot() {
        let mut state = loaded("acct_c");
        testing::with_ctx(None, |ctx| {
            assert!(update(&mut state, Msg::Ask(Switch::Offline), ctx).is_empty());
            let body = &state.asking.as_ref().unwrap().confirm.body;
            assert!(body.contains("never came up"), "{body}");
            assert!(body.contains("next comes up"), "{body}");
        });
    }

    #[test]
    fn a_switch_is_toasted_and_refreshes() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Switch::Offline,
                    profile_id: "acct_a".into(),
                    result: Ok(switched("acct_a", "active", "offline")),
                },
                ctx,
            );
            assert_eq!(effects.len(), 2, "a toast and a refresh");
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.kind, ToastKind::Success);
            assert_eq!(toast.text, "acct_a: offline");

            // The list had acct_b fenced: the answer means its fence lifted.
            state.loading = false;
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Switch::Online,
                    profile_id: "acct_b".into(),
                    result: Ok(switched("acct_b", "active", "online")),
                },
                ctx,
            );
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(
                toast.text,
                "acct_b: tunnel checked healthy; fence lifted, online"
            );

            // Set online, and offline-all still holds it.
            state.loading = false;
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Switch::Online,
                    profile_id: "host".into(),
                    result: Ok(switched("host", "active", "offline")),
                },
                ctx,
            );
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(
                toast.text,
                "host: set online, still off the network (offline-all is on)"
            );
        });
    }

    #[test]
    fn a_lifted_fence_under_offline_all_is_toasted_as_still_off_the_network() {
        let mut state = loaded("acct_b");
        testing::with_ctx(None, |ctx| {
            // The list had acct_b fenced; the probe passed and the fence
            // lifted, but offline-all keeps it off the network.
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Switch::Online,
                    profile_id: "acct_b".into(),
                    result: Ok(switched("acct_b", "active", "offline")),
                },
                ctx,
            );
            assert_eq!(effects.len(), 2, "a toast and a refresh");
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.kind, ToastKind::Success);
            assert_eq!(
                toast.text,
                "acct_b: tunnel checked healthy; fence lifted; still off the network (offline-all is on)"
            );
        });
    }

    #[test]
    fn a_409_says_which_check_the_tunnel_still_fails() {
        let mut state = loaded("acct_b");
        testing::with_ctx(None, |ctx| {
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Switch::Online,
                    profile_id: "acct_b".into(),
                    result: Err(conflict(
                        "profile vpn_down: its tunnel still fails the health check \
                         (route_mismatch), so it stays fenced",
                    )),
                },
                ctx,
            );
            assert_eq!(effects.len(), 2, "a toast and a refresh");
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.kind, ToastKind::Error);
            assert!(
                toast
                    .text
                    .starts_with("cannot bring online acct_b: profile vpn_down"),
                "{}",
                toast.text
            );
            assert!(toast.text.contains("route_mismatch"), "{}", toast.text);
            assert_eq!(toast.request_id.as_deref(), Some("req-1"));
        });
    }

    #[test]
    fn any_other_failure_is_a_failure_toast() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            let effects = update(
                &mut state,
                Msg::Ran {
                    action: Switch::Offline,
                    profile_id: "acct_a".into(),
                    result: Err(Failure::local("Cannot reach the daemon", None)),
                },
                ctx,
            );
            assert_eq!(effects.len(), 1);
            let toast = toast_of(effects.into_iter().next().unwrap());
            assert_eq!(toast.text, "take offline acct_a: Cannot reach the daemon");
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
            (KeyCode::Char('p'), "Ask(Offline)"),
            (KeyCode::Char('r'), "Ask(Online)"),
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
    fn the_list_with_the_detail_of_an_active_a_fenced_an_offline_and_a_failed_profile() {
        for id in ["acct_a", "acct_b", "host", "acct_c"] {
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
        assert!(screen.contains("FENCED"), "{screen}");
        assert!(!screen.contains("restart the daemon"), "{screen}");
        insta::assert_snapshot!("profiles_80x24", screen);
    }

    #[test]
    fn the_take_offline_confirm() {
        let mut state = loaded("acct_a");
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Ask(Switch::Offline), ctx)
        });
        let screen = testing::render(80, 24, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        insta::assert_snapshot!("profiles_confirm_offline_80x24", screen);
    }
}
