//! The application: a model, the messages that change it, and the effects a
//! change asks for.
//!
//! The Elm architecture. [`update`] is the only thing that changes the
//! [`Model`]; it never waits on the network, and returns [`Effect`]s — futures
//! the runtime spawns and whose results come back as messages. So every rule
//! the UI follows is testable by feeding messages to `update` and reading the
//! model, with no terminal and no daemon.
//!
//! Each screen follows the same contract in its own module: a `State`, a
//! `Msg`, `update`, `on_key`, `refresh` and `view`. The root routes to the
//! screen on screen, and owns what they share: the session, the live
//! connection, toasts, the help overlay and the command palette.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use std::time::Instant;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyModifiers;

use crate::api::types;
use crate::api::Api;
use crate::api::Failure;
use crate::screens;
use crate::theme::Theme;

/// A future whose result is a message, spawned by the runtime.
pub struct Effect(pub Pin<Box<dyn Future<Output = Msg> + Send + 'static>>);

impl std::fmt::Debug for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Effect")
    }
}

impl Effect {
    /// An effect from a future.
    pub fn new(future: impl Future<Output = Msg> + Send + 'static) -> Self {
        Self(Box::pin(future))
    }

    /// A message delivered on the next turn of the loop.
    pub fn now(msg: Msg) -> Self {
        Self::new(async move { msg })
    }

    /// A toast.
    pub fn toast(toast: Toast) -> Self {
        Self::now(Msg::Toast(toast))
    }
}

/// What a screen may read while it handles a message or draws.
pub struct Ctx<'a> {
    pub api: &'a Api,
    /// What this daemon is; `None` until the first `GET /v1/server`.
    pub server: Option<&'a types::ServerInfo>,
    pub theme: &'a Theme,
    /// Render ticks since start, for spinners.
    pub tick: u64,
}

/// The screens, in tab order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Torrents,
    Profiles,
    Pool,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Dashboard, Tab::Torrents, Tab::Profiles, Tab::Pool];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Torrents => "Torrents",
            Tab::Profiles => "Profiles",
            Tab::Pool => "Pool",
        }
    }
}

/// Whether change notifications are arriving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Live {
    /// Opening the stream.
    Connecting,
    /// Ticks are arriving.
    Streaming,
    /// The stream dropped; polling until it is back.
    Reconnecting { reason: String },
}

/// Who the user is to the daemon.
#[derive(Clone, Debug)]
pub enum Session {
    /// Asking the daemon.
    Checking,
    /// The daemon could not be asked; retried every [`RETRY_INTERVAL`]. Not a
    /// sign-out: the credential in use may be fine.
    Unreachable { reason: String, since: Instant },
    /// The daemon wants a password.
    SignedOut,
    /// Signed in, or authentication is disabled.
    SignedIn {
        server: Box<types::ServerInfo>,
        principal: Box<types::Principal>,
    },
}

/// A transient notice in the corner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toast {
    pub kind: ToastKind,
    pub text: String,
    /// A request id to quote, when the notice is a failure.
    pub request_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

impl Toast {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Info,
            text: text.into(),
            request_id: None,
        }
    }

    pub fn success(text: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Success,
            text: text.into(),
            request_id: None,
        }
    }

    /// A failure, with what was being attempted.
    pub fn failure(attempt: &str, failure: &Failure) -> Self {
        Self {
            kind: ToastKind::Error,
            text: format!("{attempt}: {}", failure.message()),
            request_id: failure.request_id.clone(),
        }
    }
}

/// How long a toast stays up.
pub const TOAST_TTL: Duration = Duration::from_secs(6);

/// Everything the UI shows.
pub struct Model {
    pub api: Api,
    pub theme: Theme,
    pub tab: Tab,
    pub session: Session,
    /// Whether the credential in use is a session token this client minted
    /// from the password, and so revokes on quit.
    pub minted: bool,
    pub live: Live,
    pub toasts: VecDeque<(Toast, Instant)>,
    pub help: bool,
    /// The `:` command line, while open.
    pub palette: Option<tui_input::Input>,
    pub tick: u64,
    pub quit: bool,
    pub login: screens::login::State,
    pub dashboard: screens::dashboard::State,
    pub torrents: screens::torrents::State,
    pub profiles: screens::profiles::State,
    pub pool: screens::pool::State,
    /// When the visible screen last refreshed, for the polling fallback.
    pub last_refresh: Option<Instant>,
}

/// Everything that can happen.
#[derive(Debug)]
pub enum Msg {
    Key(KeyEvent),
    /// A render tick (250 ms): spinners, toast expiry, the polling fallback.
    Tick,
    /// `GET /v1/events` delivered a tick: something visible may have changed.
    Changed,
    LiveChanged(Live),
    /// The answer to "who am I": the server's description and the principal.
    SessionChecked(Result<(types::ServerInfo, types::Principal), Failure>),
    /// A password sign-in produced this API handle.
    SignedIn(Api),
    /// A request came back `401`: the credential is gone.
    SignedOut(Failure),
    /// Show the torrents of one profile: the torrents screen, filtered.
    ShowTorrentsOf(String),
    Toast(Toast),
    Quit,
    /// Quit now: the session token is revoked (or needed no revoking).
    Exit,
    Login(screens::login::Msg),
    Dashboard(screens::dashboard::Msg),
    Torrents(screens::torrents::Msg),
    Profiles(screens::profiles::Msg),
    Pool(screens::pool::Msg),
}

/// How often an unreachable daemon is asked again who we are.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// How often the visible screen refreshes while the event stream is down.
pub const POLL_INTERVAL: Duration = Duration::from_secs(15);

impl Model {
    pub fn new(api: Api, theme: Theme) -> Self {
        Self {
            api,
            theme,
            tab: Tab::Dashboard,
            session: Session::Checking,
            minted: false,
            live: Live::Connecting,
            toasts: VecDeque::new(),
            help: false,
            palette: None,
            tick: 0,
            quit: false,
            login: Default::default(),
            dashboard: Default::default(),
            torrents: Default::default(),
            profiles: Default::default(),
            pool: Default::default(),
            last_refresh: None,
        }
    }

    /// The server's description, once signed in.
    pub fn server(&self) -> Option<&types::ServerInfo> {
        match &self.session {
            Session::SignedIn { server, .. } => Some(server),
            _ => None,
        }
    }

    fn ctx(&self) -> (Api, Option<types::ServerInfo>, Theme, u64) {
        (
            self.api.clone(),
            self.server().cloned(),
            self.theme,
            self.tick,
        )
    }

    /// Whether the pool tab means anything here.
    pub fn pool_configured(&self) -> bool {
        self.server().is_some_and(|s| s.pool.configured)
    }

    /// The tabs this daemon has.
    pub fn tabs(&self) -> Vec<Tab> {
        Tab::ALL
            .into_iter()
            .filter(|t| *t != Tab::Pool || self.pool_configured())
            .collect()
    }
}

/// Ask the daemon who we are.
pub fn check_session(api: &Api) -> Effect {
    let api = api.clone();
    Effect::new(async move {
        let server = crate::api::call(api.client.get_server()).await;
        let principal = crate::api::call(api.client.get_current_session()).await;
        Msg::SessionChecked(server.and_then(|s| principal.map(|p| (s, p))))
    })
}

/// Apply `msg` to `model`, returning what should happen next.
pub fn update(model: &mut Model, msg: Msg) -> Vec<Effect> {
    match msg {
        Msg::Tick => {
            model.tick = model.tick.wrapping_add(1);
            let now = Instant::now();
            while model
                .toasts
                .front()
                .is_some_and(|(_, at)| now.duration_since(*at) > TOAST_TTL)
            {
                model.toasts.pop_front();
            }
            if let Session::Unreachable { since, .. } = model.session {
                if now.duration_since(since) >= RETRY_INTERVAL {
                    model.session = Session::Checking;
                    return vec![check_session(&model.api)];
                }
                return Vec::new();
            }
            // The polling fallback: while the stream is down, refresh what is
            // on screen every POLL_INTERVAL.
            let due = model
                .last_refresh
                .is_none_or(|at| now.duration_since(at) >= POLL_INTERVAL);
            if model.live != Live::Streaming
                && due
                && matches!(model.session, Session::SignedIn { .. })
            {
                return refresh_visible(model);
            }
            Vec::new()
        }
        Msg::Changed => {
            if matches!(model.session, Session::SignedIn { .. }) {
                refresh_visible(model)
            } else {
                Vec::new()
            }
        }
        Msg::LiveChanged(live) => {
            model.live = live;
            Vec::new()
        }
        Msg::SessionChecked(Ok((server, principal))) => {
            model.session = Session::SignedIn {
                server: Box::new(server),
                principal: Box::new(principal),
            };
            if !model.tabs().contains(&model.tab) {
                model.tab = Tab::Dashboard;
            }
            refresh_visible(model)
        }
        Msg::SessionChecked(Err(failure)) if failure.is_unauthenticated() => {
            model.session = Session::SignedOut;
            Vec::new()
        }
        Msg::SessionChecked(Err(failure)) => {
            // Not a refusal: the daemon is down, or answered something else.
            // Keep the credential and ask again, rather than asking a
            // static-token user for a password they may not have.
            model.session = Session::Unreachable {
                reason: failure.message(),
                since: Instant::now(),
            };
            Vec::new()
        }
        Msg::SignedIn(api) => {
            // A token minted earlier in this run is revoked before it is
            // replaced, not orphaned for the rest of its lifetime.
            let mut effects = Vec::new();
            if model.minted {
                effects.push(revoke(&model.api, None));
            }
            model.api = api;
            model.minted = true;
            model.session = Session::Checking;
            effects.push(check_session(&model.api));
            effects
        }
        Msg::SignedOut(failure) => {
            model.session = Session::SignedOut;
            model.minted = false;
            // Whatever was open belongs to the credential that is gone.
            model.dashboard = Default::default();
            model.torrents = Default::default();
            model.profiles = Default::default();
            model.pool = Default::default();
            model.palette = None;
            model.help = false;
            model.login.error = Some(match failure.detail {
                Some(_) => failure.message(),
                None => "signed out: the credential is no longer accepted".to_owned(),
            });
            Vec::new()
        }
        Msg::ShowTorrentsOf(profile_id) => {
            model.tab = Tab::Torrents;
            model.last_refresh = Some(Instant::now());
            route(model, |m, ctx| {
                screens::torrents::update(
                    &mut m.torrents,
                    screens::torrents::Msg::FilterProfile(Some(profile_id)),
                    ctx,
                )
            })
        }
        Msg::Toast(toast) => {
            model.toasts.push_back((toast, Instant::now()));
            while model.toasts.len() > 4 {
                model.toasts.pop_front();
            }
            Vec::new()
        }
        Msg::Quit => {
            // A session token this client minted is revoked on the way out,
            // so it does not outlive the terminal it was typed into.
            // Whatever the session looks like right now: a token minted a
            // moment ago, still being described, is just as live.
            if model.minted {
                vec![revoke(&model.api, Some(Msg::Exit))]
            } else {
                model.quit = true;
                Vec::new()
            }
        }
        Msg::Exit => {
            model.quit = true;
            Vec::new()
        }
        Msg::Key(key) => on_key(model, key),
        Msg::Login(msg) => {
            let (api, server, theme, tick) = model.ctx();
            let ctx = Ctx {
                api: &api,
                server: server.as_ref(),
                theme: &theme,
                tick,
            };
            screens::login::update(&mut model.login, msg, &ctx)
        }
        Msg::Dashboard(msg) => route(model, |m, ctx| {
            screens::dashboard::update(&mut m.dashboard, msg, ctx)
        }),
        Msg::Torrents(msg) => route(model, |m, ctx| {
            screens::torrents::update(&mut m.torrents, msg, ctx)
        }),
        Msg::Profiles(msg) => route(model, |m, ctx| {
            screens::profiles::update(&mut m.profiles, msg, ctx)
        }),
        Msg::Pool(msg) => route(model, |m, ctx| screens::pool::update(&mut m.pool, msg, ctx)),
    }
}

/// Run a screen's handler with a context built from the model, turning a
/// 401 among its results into a sign-out.
fn route(model: &mut Model, f: impl FnOnce(&mut Model, &Ctx<'_>) -> Vec<Effect>) -> Vec<Effect> {
    let (api, server, theme, tick) = model.ctx();
    let ctx = Ctx {
        api: &api,
        server: server.as_ref(),
        theme: &theme,
        tick,
    };
    f(model, &ctx)
}

/// Refresh whatever is on screen.
pub fn refresh_visible(model: &mut Model) -> Vec<Effect> {
    model.last_refresh = Some(Instant::now());
    match model.tab {
        Tab::Dashboard => route(model, |m, ctx| {
            screens::dashboard::refresh(&mut m.dashboard, ctx)
        }),
        Tab::Torrents => route(model, |m, ctx| {
            screens::torrents::refresh(&mut m.torrents, ctx)
        }),
        Tab::Profiles => route(model, |m, ctx| {
            screens::profiles::refresh(&mut m.profiles, ctx)
        }),
        Tab::Pool => route(model, |m, ctx| screens::pool::refresh(&mut m.pool, ctx)),
    }
}

/// Whether a screen is capturing text, so global keys must not fire.
fn capturing(model: &Model) -> bool {
    match model.tab {
        Tab::Dashboard => screens::dashboard::capturing(&model.dashboard),
        Tab::Torrents => screens::torrents::capturing(&model.torrents),
        Tab::Profiles => screens::profiles::capturing(&model.profiles),
        Tab::Pool => screens::pool::capturing(&model.pool),
    }
}

fn on_key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return update(model, Msg::Quit);
    }
    if let Session::Unreachable { .. } = model.session {
        return match key.code {
            KeyCode::Char('r') => {
                model.session = Session::Checking;
                vec![check_session(&model.api)]
            }
            KeyCode::Esc | KeyCode::Char('q') => update(model, Msg::Quit),
            _ => Vec::new(),
        };
    }
    if !matches!(model.session, Session::SignedIn { .. }) {
        let (api, server, theme, tick) = model.ctx();
        let ctx = Ctx {
            api: &api,
            server: server.as_ref(),
            theme: &theme,
            tick,
        };
        return match screens::login::on_key(&model.login, key) {
            Some(msg) => screens::login::update(&mut model.login, msg, &ctx),
            None if key.code == KeyCode::Esc => update(model, Msg::Quit),
            None => Vec::new(),
        };
    }
    if model.help {
        model.help = false;
        return Vec::new();
    }
    if let Some(input) = model.palette.as_mut() {
        match key.code {
            KeyCode::Esc => model.palette = None,
            KeyCode::Enter => {
                let command = input.value().trim().to_owned();
                model.palette = None;
                return run_command(model, &command);
            }
            _ => {
                use tui_input::backend::crossterm::EventHandler as _;
                input.handle_event(&crossterm::event::Event::Key(key));
            }
        }
        return Vec::new();
    }
    if !capturing(model) {
        let tabs = model.tabs();
        match key.code {
            KeyCode::Char('q') => return update(model, Msg::Quit),
            KeyCode::Char('?') => {
                model.help = true;
                return Vec::new();
            }
            KeyCode::Char(':') => {
                model.palette = Some(tui_input::Input::default());
                return Vec::new();
            }
            KeyCode::Char(d @ '1'..='9') => {
                let index = d as usize - '1' as usize;
                if let Some(tab) = tabs.get(index) {
                    return switch_tab(model, *tab);
                }
                return Vec::new();
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let at = tabs.iter().position(|t| *t == model.tab).unwrap_or(0);
                let next = if key.code == KeyCode::Tab {
                    (at + 1) % tabs.len()
                } else {
                    (at + tabs.len() - 1) % tabs.len()
                };
                return switch_tab(model, tabs[next]);
            }
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return refresh_visible(model);
            }
            _ => {}
        }
    }
    match model.tab {
        Tab::Dashboard => match screens::dashboard::on_key(&model.dashboard, key) {
            Some(msg) => update(model, Msg::Dashboard(msg)),
            None => Vec::new(),
        },
        Tab::Torrents => match screens::torrents::on_key(&model.torrents, key) {
            Some(msg) => update(model, Msg::Torrents(msg)),
            None => Vec::new(),
        },
        Tab::Profiles => match screens::profiles::on_key(&model.profiles, key) {
            Some(msg) => update(model, Msg::Profiles(msg)),
            None => Vec::new(),
        },
        Tab::Pool => match screens::pool::on_key(&model.pool, key) {
            Some(msg) => update(model, Msg::Pool(msg)),
            None => Vec::new(),
        },
    }
}

/// Show `tab`, refreshing it.
pub fn switch_tab(model: &mut Model, tab: Tab) -> Vec<Effect> {
    model.tab = tab;
    refresh_visible(model)
}

/// A command-palette command.
pub fn run_command(model: &mut Model, command: &str) -> Vec<Effect> {
    let mut words = command.split_whitespace();
    match words.next() {
        None => Vec::new(),
        Some("q" | "quit") => update(model, Msg::Quit),
        Some("dashboard" | "d") => switch_tab(model, Tab::Dashboard),
        Some("torrents" | "t") => switch_tab(model, Tab::Torrents),
        Some("profiles" | "p") => switch_tab(model, Tab::Profiles),
        Some("pool") if model.pool_configured() => switch_tab(model, Tab::Pool),
        Some("pool") => vec![Effect::toast(Toast::info("this daemon has no [pool]"))],
        // Through the same confirmation `R` asks for.
        Some("reload") => {
            model.tab = Tab::Dashboard;
            route(model, |m, ctx| {
                screens::dashboard::update(
                    &mut m.dashboard,
                    screens::dashboard::Msg::AskReload,
                    ctx,
                )
            })
        }
        Some("add") => {
            model.tab = Tab::Torrents;
            route(model, |m, ctx| {
                screens::torrents::update(&mut m.torrents, screens::torrents::Msg::OpenAdd, ctx)
            })
        }
        Some("help") => {
            model.help = true;
            Vec::new()
        }
        Some(other) => vec![Effect::toast(Toast::info(format!(
            "unknown command `{other}` — try :help"
        )))],
    }
}

/// Revoke the session token `api` holds, then deliver `then` (or a no-op
/// tick).
fn revoke(api: &Api, then: Option<Msg>) -> Effect {
    let api = api.clone();
    Effect::new(async move {
        let _ = crate::api::call(api.client.delete_current_session()).await;
        then.unwrap_or(Msg::Tick)
    })
}

/// The message a failed request produces: a sign-out for a `401`, otherwise
/// a toast saying what was being attempted.
pub fn failed(attempt: &str, failure: Failure) -> Msg {
    if failure.is_unauthenticated() {
        Msg::SignedOut(failure)
    } else {
        Msg::Toast(Toast::failure(attempt, &failure))
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;
    use serde_json::json;

    use super::*;
    use crate::testing;

    fn model() -> Model {
        Model::new(testing::api(), testing::theme())
    }

    fn principal(kind: &str) -> types::Principal {
        testing::from_json(json!({
            "kind": kind, "name": null, "scopes": ["read", "write"], "expires_at": null,
        }))
    }

    fn signed_in(pool: bool) -> Model {
        let mut m = model();
        update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(pool, false), principal("token")))),
        );
        m
    }

    fn unauthorized() -> Failure {
        Failure {
            status: Some(401),
            slug: Some("about:blank".into()),
            title: "Unauthorized".into(),
            detail: None,
            request_id: None,
            ..Default::default()
        }
    }

    #[test]
    fn a_checked_session_signs_in_and_refreshes_the_visible_screen() {
        let mut m = model();
        assert!(matches!(m.session, Session::Checking));
        let effects = update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(false, false), principal("token")))),
        );
        assert!(matches!(m.session, Session::SignedIn { .. }));
        assert_eq!(effects.len(), 1, "the dashboard loads");
        assert!(m.dashboard.loading);
    }

    #[test]
    fn a_refused_credential_asks_for_the_password() {
        let mut m = model();
        update(&mut m, Msg::SessionChecked(Err(unauthorized())));
        assert!(matches!(m.session, Session::SignedOut));

        let mut m = signed_in(false);
        update(&mut m, Msg::SignedOut(unauthorized()));
        assert!(matches!(m.session, Session::SignedOut));
        assert!(m
            .login
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("no longer accepted"));
        assert_eq!(failed("x", unauthorized()).to_string_kind(), "SignedOut");
    }

    #[test]
    fn a_minted_session_is_revoked_on_quit_and_a_static_token_is_not() {
        let mut m = signed_in(false);
        assert!(update(&mut m, Msg::Quit).is_empty());
        assert!(m.quit, "a static token needs no revoking");

        let mut m = model();
        update(&mut m, Msg::SignedIn(testing::api()));
        assert!(m.minted);
        update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(false, false), principal("session")))),
        );
        let effects = update(&mut m, Msg::Quit);
        assert_eq!(effects.len(), 1, "one revocation");
        assert!(!m.quit, "waits for it");
        update(&mut m, Msg::Exit);
        assert!(m.quit);
    }

    #[test]
    fn the_pool_tab_exists_only_where_the_pool_does() {
        let m = signed_in(false);
        assert_eq!(m.tabs(), [Tab::Dashboard, Tab::Torrents, Tab::Profiles]);
        let m = signed_in(true);
        assert_eq!(m.tabs(), Tab::ALL);

        let mut m = signed_in(false);
        update(&mut m, Msg::Key(testing::key(KeyCode::Char('4'))));
        assert_eq!(m.tab, Tab::Dashboard, "no fourth tab to switch to");
        update(&mut m, Msg::Key(testing::key(KeyCode::Char('3'))));
        assert_eq!(m.tab, Tab::Profiles);
        update(&mut m, Msg::Key(testing::key(KeyCode::Tab)));
        assert_eq!(m.tab, Tab::Dashboard, "Tab wraps");
        update(&mut m, Msg::Key(testing::key(KeyCode::BackTab)));
        assert_eq!(m.tab, Tab::Profiles);
    }

    #[test]
    fn the_command_palette_runs_commands_and_says_what_it_does_not_know() {
        let mut m = signed_in(false);
        update(&mut m, Msg::Key(testing::key(KeyCode::Char(':'))));
        assert!(m.palette.is_some());
        for c in "torrents".chars() {
            update(&mut m, Msg::Key(testing::key(KeyCode::Char(c))));
        }
        update(&mut m, Msg::Key(testing::key(KeyCode::Enter)));
        assert!(m.palette.is_none());
        assert_eq!(m.tab, Tab::Torrents);

        let effects = run_command(&mut m, "pool");
        assert_eq!(effects.len(), 1, "a toast: no pool here");
        assert_eq!(m.tab, Tab::Torrents);
        assert_eq!(run_command(&mut m, "frobnicate").len(), 1);
        assert!(run_command(&mut m, "").is_empty());
        run_command(&mut m, "help");
        assert!(m.help);
    }

    #[test]
    fn help_closes_on_any_key_and_global_keys_quit() {
        let mut m = signed_in(false);
        update(&mut m, Msg::Key(testing::key(KeyCode::Char('?'))));
        assert!(m.help);
        update(&mut m, Msg::Key(testing::key(KeyCode::Char('x'))));
        assert!(!m.help);
        update(&mut m, Msg::Key(testing::key(KeyCode::Char('q'))));
        assert!(m.quit);
    }

    #[test]
    fn toasts_are_capped_and_expire() {
        let mut m = signed_in(false);
        for i in 0..6 {
            update(&mut m, Msg::Toast(Toast::info(format!("t{i}"))));
        }
        assert_eq!(m.toasts.len(), 4);
        assert_eq!(m.toasts.front().unwrap().0.text, "t2");
        for (_, at) in m.toasts.iter_mut() {
            *at -= TOAST_TTL + Duration::from_secs(1);
        }
        update(&mut m, Msg::Tick);
        assert!(m.toasts.is_empty());
    }

    #[test]
    fn the_polling_fallback_refreshes_only_while_the_stream_is_down() {
        let mut m = signed_in(false);
        m.dashboard.loading = false;
        m.last_refresh = Some(Instant::now() - POLL_INTERVAL - Duration::from_secs(1));
        m.live = Live::Streaming;
        assert!(
            update(&mut m, Msg::Tick).is_empty(),
            "live: the stream drives refreshes"
        );
        m.live = Live::Reconnecting {
            reason: "down".into(),
        };
        assert_eq!(update(&mut m, Msg::Tick).len(), 1, "polling while down");
        assert!(
            update(&mut m, Msg::Tick).is_empty(),
            "and not again until the interval"
        );
        m.dashboard.loading = false;
        assert_eq!(
            update(&mut m, Msg::Changed).len(),
            1,
            "a change notification refreshes"
        );
    }

    #[test]
    fn an_unreachable_daemon_is_retried_not_treated_as_a_sign_out() {
        let mut m = model();
        let down = Failure::local("Cannot reach the daemon", Some("refused".to_owned()));
        assert!(update(&mut m, Msg::SessionChecked(Err(down))).is_empty());
        assert!(matches!(m.session, Session::Unreachable { .. }));
        assert!(
            update(&mut m, Msg::Tick).is_empty(),
            "not before the interval"
        );
        if let Session::Unreachable { since, .. } = &mut m.session {
            *since -= RETRY_INTERVAL;
        }
        assert_eq!(update(&mut m, Msg::Tick).len(), 1, "asks again");
        assert!(matches!(m.session, Session::Checking));

        // `r` asks at once; typing is not a password.
        update(
            &mut m,
            Msg::SessionChecked(Err(Failure::local("down", None))),
        );
        assert!(update(&mut m, Msg::Key(testing::key(KeyCode::Char('x')))).is_empty());
        assert_eq!(
            update(&mut m, Msg::Key(testing::key(KeyCode::Char('r')))).len(),
            1
        );
    }

    #[test]
    fn a_minted_token_is_revoked_whatever_state_the_session_is_in() {
        // Quit while the new session is still being described.
        let mut m = model();
        update(&mut m, Msg::SignedIn(testing::api()));
        assert!(matches!(m.session, Session::Checking));
        assert_eq!(update(&mut m, Msg::Quit).len(), 1, "revoked, not orphaned");
        assert!(!m.quit);

        // Signing in again revokes the first token before replacing it.
        let mut m = model();
        update(&mut m, Msg::SignedIn(testing::api()));
        let effects = update(
            &mut m,
            Msg::SignedIn(testing::api().with_token("tds_2").unwrap()),
        );
        assert_eq!(effects.len(), 2, "revoke the old, describe the new");
        assert_eq!(m.api.epoch, 1);
    }

    #[test]
    fn the_reload_command_asks_first_and_a_sign_out_closes_open_dialogs() {
        let mut m = signed_in(false);
        m.tab = Tab::Torrents;
        assert!(run_command(&mut m, "reload").is_empty(), "nothing sent yet");
        assert_eq!(m.tab, Tab::Dashboard);
        assert!(
            m.dashboard.confirm_reload.is_some(),
            "the same confirm `R` opens"
        );

        update(&mut m, Msg::SignedOut(unauthorized()));
        assert!(
            m.dashboard.confirm_reload.is_none(),
            "stale dialogs are gone"
        );
    }

    impl Msg {
        fn to_string_kind(&self) -> &'static str {
            match self {
                Msg::SignedOut(_) => "SignedOut",
                Msg::Toast(_) => "Toast",
                _ => "other",
            }
        }
    }
}
