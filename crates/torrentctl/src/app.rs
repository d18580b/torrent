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
    /// Ticks are arriving: one has on this stream, and none has been missing
    /// for [`crate::runtime::IDLE_TIMEOUT`].
    Streaming,
    /// The stream dropped; polling until it is back.
    Reconnecting { reason: String },
}

/// Who the user is to the daemon.
#[derive(Clone, Debug)]
pub enum Session {
    /// Asking the daemon.
    Checking,
    /// The daemon could not be asked, or refused what was asked; retried
    /// every [`RETRY_INTERVAL`] unless it refused. Not a sign-out: the
    /// credential in use may be fine.
    Unreachable {
        reason: String,
        since: Instant,
        /// Whether to ask again unprompted. Not after a 403: a token
        /// without the `read` scope stays without it, and every refusal
        /// raises the daemon's scope-denial alert.
        retry: bool,
    },
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
    /// The user asked to quit and the client is finishing up first: revoking
    /// a minted token, or waiting for an in-flight sign-in to answer so the
    /// token it mints can be revoked too. A second quit leaves at once.
    pub quitting: bool,
    /// Why the credential is being re-checked after a 401, to show if the
    /// re-check confirms it.
    pub pending_sign_out: Option<Failure>,
    pub live: Live,
    pub toasts: VecDeque<(Toast, Instant)>,
    pub help: bool,
    /// The `:` command line, while open.
    pub palette: Option<tui_input::Input>,
    pub tick: u64,
    pub quit: bool,
    /// What to print once the terminal is restored: a revocation on the way
    /// out that failed.
    pub exit_notice: Option<String>,
    pub login: screens::login::State,
    pub dashboard: screens::dashboard::State,
    pub torrents: screens::torrents::State,
    pub profiles: screens::profiles::State,
    pub pool: screens::pool::State,
    /// When the visible screen last refreshed, for the polling fallback.
    pub last_refresh: Option<Instant>,
    /// The fingerprint of the stream tick that last refreshed the visible
    /// screen. A tick carrying the same one says nothing changed, so it
    /// fetches nothing. Not recorded when the screen had a load in flight
    /// and skipped it, so a re-send retries; forgotten when the screen's load
    /// fails, so a re-send retries that too. Forgotten whenever the stream's
    /// state changes, so the first tick after a reconnect always refreshes.
    pub fingerprint: Option<String>,
}

/// Everything that can happen.
#[derive(Debug)]
pub enum Msg {
    Key(KeyEvent),
    /// A render tick (250 ms): spinners, toast expiry, the polling fallback,
    /// and the poll of an open torrent's trackers.
    Tick,
    /// `GET /v1/events` delivered a tick carrying this fingerprint of the
    /// daemon's state: something visible changed if it differs from the last.
    Changed(String),
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
    /// Quit now: the session token is revoked, needed no revoking, or could
    /// not be revoked — then this says so, to print once the terminal is
    /// back.
    Exit(Option<String>),
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
            quitting: false,
            pending_sign_out: None,
            live: Live::Connecting,
            toasts: VecDeque::new(),
            help: false,
            palette: None,
            tick: 0,
            quit: false,
            exit_notice: None,
            login: Default::default(),
            dashboard: Default::default(),
            torrents: Default::default(),
            profiles: Default::default(),
            pool: Default::default(),
            last_refresh: None,
            fingerprint: None,
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
#[allow(
    clippy::result_large_err,
    reason = "a Failure is built once per failed request and moved straight to the UI"
)]
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
            if let Session::Unreachable { since, retry, .. } = model.session {
                if retry && now.duration_since(since) >= RETRY_INTERVAL {
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
            if !matches!(model.session, Session::SignedIn { .. }) {
                return Vec::new();
            }
            if model.live != Live::Streaming && due {
                return refresh_visible(model);
            }
            // What the stream does not cover and the screen shows: an open
            // torrent's trackers, polled on their own timer.
            if model.tab == Tab::Torrents {
                return route(model, |m, ctx| {
                    screens::torrents::poll(&mut m.torrents, now, ctx)
                });
            }
            Vec::new()
        }
        Msg::Changed(fingerprint) => {
            // The daemon re-sends an unchanged fingerprint at least every ten
            // seconds; refetching each time would re-read every loaded row
            // of a list that did not change.
            if !matches!(model.session, Session::SignedIn { .. })
                || model.fingerprint.as_ref() == Some(&fingerprint)
            {
                return Vec::new();
            }
            // A screen with a load in flight skips it rather than restart
            // it, and that load may have been answered before this change.
            // Remember the fingerprint only when nothing was skipped, so the
            // daemon's next re-send of it retries until the screen reloads.
            let skipped = busy(model);
            model.fingerprint = (!skipped).then_some(fingerprint);
            refresh_visible(model)
        }
        Msg::LiveChanged(live) => {
            model.live = live;
            model.fingerprint = None;
            Vec::new()
        }
        Msg::SessionChecked(Ok((server, principal))) => {
            model.pending_sign_out = None;
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
            if model.pending_sign_out.is_some() || model.minted {
                // A credential that worked is now refused.
                sign_out(model, &failure);
            } else {
                // The first check, with no credential or a refused one: the
                // sign-in is simply what comes next, not an error.
                model.session = Session::SignedOut;
            }
            Vec::new()
        }
        Msg::SessionChecked(Err(failure)) => {
            // Not a refusal: the daemon is down, or answered something else.
            // Keep the credential and ask again, rather than asking a
            // static-token user for a password they may not have.
            model.session = Session::Unreachable {
                reason: failure.message(),
                since: Instant::now(),
                retry: failure.status != Some(403),
            };
            Vec::new()
        }
        Msg::SignedIn(api) => {
            // A token minted earlier in this run is revoked before it is
            // replaced, not orphaned for the rest of its lifetime.
            let mut effects = Vec::new();
            if model.minted {
                effects.push(revoke(&model.api, false));
            }
            model.api = api;
            model.minted = true;
            model.session = Session::Checking;
            effects.push(check_session(&model.api));
            effects
        }
        Msg::SignedOut(failure) => {
            // A 401 may answer a request made with an earlier credential that
            // a sign-in has since replaced. Ask again with the credential in
            // use; only a 401 to that signs out (and only then is a minted
            // token known to be gone).
            if matches!(model.session, Session::SignedIn { .. }) {
                model.pending_sign_out = Some(failure);
                model.session = Session::Checking;
                vec![check_session(&model.api)]
            } else {
                Vec::new()
            }
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
            if model.quitting {
                // Asked twice: leave now, whatever is outstanding.
                model.quit = true;
                return Vec::new();
            }
            model.quitting = true;
            // A session token this client minted is revoked on the way out,
            // so it does not outlive the terminal it was typed into — in
            // whatever state the session is, since a token minted a moment
            // ago and still being described is just as live.
            if model.minted {
                vec![revoke(&model.api, true)]
            } else if model.login.busy {
                // A sign-in is in flight: its token is revoked when it lands
                // (see `Msg::Login`), not left live on the daemon.
                vec![Effect::toast(Toast::info(
                    "finishing sign-in to revoke it; Esc again to quit now",
                ))]
            } else {
                model.quit = true;
                Vec::new()
            }
        }
        Msg::Exit(notice) => {
            model.exit_notice = notice;
            model.quit = true;
            Vec::new()
        }
        Msg::Key(key) => on_key(model, key),
        Msg::Login(screens::login::Msg::Answered(result)) if model.quitting => {
            // Quitting while this sign-in was in flight: revoke what it
            // minted, then leave.
            match result
                .ok()
                .and_then(|token| model.api.with_token(&token).ok())
            {
                Some(api) => vec![revoke(&api, true)],
                None => {
                    model.quit = true;
                    Vec::new()
                }
            }
        }
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
        Msg::Dashboard(msg) => answered(model, |m, ctx| {
            screens::dashboard::update(&mut m.dashboard, msg, ctx)
        }),
        Msg::Torrents(msg) => answered(model, |m, ctx| {
            screens::torrents::update(&mut m.torrents, msg, ctx)
        }),
        Msg::Profiles(msg) => answered(model, |m, ctx| {
            screens::profiles::update(&mut m.profiles, msg, ctx)
        }),
        Msg::Pool(msg) => answered(model, |m, ctx| screens::pool::update(&mut m.pool, msg, ctx)),
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

/// Route a screen's message, most often a load's answer. Where the visible
/// screen's load has failed, the fingerprint that triggered it is forgotten,
/// so the daemon's next re-send of it retries rather than leaving the error
/// and the rows from before the change on screen until something else
/// changes.
fn answered(model: &mut Model, f: impl FnOnce(&mut Model, &Ctx<'_>) -> Vec<Effect>) -> Vec<Effect> {
    let effects = route(model, f);
    if load_failed(model) {
        model.fingerprint = None;
    }
    effects
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

/// Whether the visible screen has a load in flight, which a refresh skips.
fn busy(model: &Model) -> bool {
    match model.tab {
        Tab::Dashboard => screens::dashboard::busy(&model.dashboard),
        Tab::Torrents => screens::torrents::busy(&model.torrents),
        Tab::Profiles => screens::profiles::busy(&model.profiles),
        Tab::Pool => screens::pool::busy(&model.pool),
    }
}

/// Whether the visible screen's last load failed, so what it shows may
/// predate the change that triggered it.
fn load_failed(model: &Model) -> bool {
    match model.tab {
        Tab::Dashboard => screens::dashboard::load_failed(&model.dashboard),
        Tab::Torrents => screens::torrents::load_failed(&model.torrents),
        Tab::Profiles => screens::profiles::load_failed(&model.profiles),
        Tab::Pool => screens::pool::load_failed(&model.pool),
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
    if let Session::Checking = model.session {
        // Re-checking after a 401 takes a moment the user did not ask for:
        // a key meant for the screen underneath must not quit. Ctrl-C
        // (above) still does.
        if model.pending_sign_out.is_some() {
            return Vec::new();
        }
        return match key.code {
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

/// Sign out after the credential in use was refused: the session, the
/// minted flag and every screen's state go with it.
fn sign_out(model: &mut Model, failure: &Failure) {
    model.session = Session::SignedOut;
    model.minted = false;
    // Whatever was open belongs to the credential that is gone.
    model.dashboard = Default::default();
    model.torrents = Default::default();
    model.profiles = Default::default();
    model.pool = Default::default();
    model.palette = None;
    model.help = false;
    let reason = model.pending_sign_out.take();
    let failure = reason.as_ref().unwrap_or(failure);
    model.login.error = Some(match failure.detail {
        Some(_) => failure.message(),
        None => "signed out: the credential is no longer accepted".to_owned(),
    });
}

/// How long revoking a session token may take: quitting waits for it, and a
/// daemon that does not answer must not hold the terminal for the full
/// request timeout.
pub const REVOKE_TIMEOUT: Duration = Duration::from_secs(3);

/// Revoke the session token `api` holds. Quitting, deliver [`Msg::Exit`]
/// with what to tell the user if the revocation failed; otherwise a no-op
/// tick.
fn revoke(api: &Api, quitting: bool) -> Effect {
    let api = api.clone();
    Effect::new(async move {
        let failure = match tokio::time::timeout(
            REVOKE_TIMEOUT,
            crate::api::call(api.client.delete_current_session()),
        )
        .await
        {
            Ok(Ok(_)) => None,
            // A `401` means the daemon no longer accepts the token (it
            // expired or was revoked already): what revoking it was for.
            Ok(Err(failure)) if failure.is_unauthenticated() => None,
            Ok(Err(failure)) => Some(failure),
            Err(_) => Some(Failure::local(
                "The daemon did not answer",
                Some(format!("no response within {}s", REVOKE_TIMEOUT.as_secs())),
            )),
        };
        if !quitting {
            return Msg::Tick;
        }
        Msg::Exit(failure.map(|failure| {
            format!(
                "torrentctl: the session token could not be revoked ({failure}); it stays \
                 valid on the daemon until it expires"
            )
        }))
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

    /// What `GET /v1/server` then `GET /v1/sessions/current` — asking who
    /// we are — sends.
    const CHECK: [&str; 2] = ["GET /v1/server", "GET /v1/sessions/current"];
    const REVOKE: &str = "DELETE /v1/sessions/current";

    fn principal(kind: &str) -> types::Principal {
        testing::from_json(json!({
            "kind": kind, "name": null, "scopes": ["read", "write"], "expires_at": null,
        }))
    }

    /// A model whose effects reach `recorder`.
    fn model_at(recorder: &testing::Recorder) -> Model {
        Model::new(recorder.api(), testing::theme())
    }

    fn signed_in(pool: bool) -> Model {
        signed_in_as(model(), pool)
    }

    fn signed_in_as(mut m: Model, pool: bool) -> Model {
        update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(pool, false), principal("token")))),
        );
        m
    }

    /// A 401, confirmed by the re-check it triggers.
    fn refused(m: &mut Model) {
        update(m, Msg::SignedOut(unauthorized()));
        update(m, Msg::SessionChecked(Err(unauthorized())));
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
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = model_at(&daemon);
        assert!(matches!(m.session, Session::Checking));
        let effects = update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(false, false), principal("token")))),
        );
        assert!(matches!(m.session, Session::SignedIn { .. }));
        assert!(m.dashboard.loading);
        testing::run(effects);
        assert_eq!(
            daemon.lines(),
            ["GET /v1/status", "GET /v1/profiles"],
            "the dashboard loads"
        );
    }

    #[test]
    fn a_refused_credential_asks_for_the_password() {
        let mut m = model();
        update(&mut m, Msg::SessionChecked(Err(unauthorized())));
        assert!(matches!(m.session, Session::SignedOut));

        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = signed_in_as(model_at(&daemon), false);
        let effects = update(&mut m, Msg::SignedOut(unauthorized()));
        assert!(matches!(m.session, Session::Checking));
        testing::run(effects);
        assert_eq!(daemon.lines(), CHECK, "a 401 is re-checked first");
        update(&mut m, Msg::SessionChecked(Err(unauthorized())));
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

        let daemon = testing::Recorder::start("204 No Content", "");
        let mut m = model();
        update(
            &mut m,
            Msg::SignedIn(daemon.api().with_token("tds_minted").unwrap()),
        );
        assert!(m.minted);
        update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(false, false), principal("session")))),
        );
        let effects = update(&mut m, Msg::Quit);
        assert!(!m.quit, "waits for it");
        let msgs = testing::run(effects);
        assert_eq!(
            daemon.requests(),
            [testing::Request {
                line: REVOKE.to_owned(),
                bearer: Some("tds_minted".to_owned()),
            }],
            "one revocation, of the minted token"
        );
        assert!(matches!(msgs[..], [Msg::Exit(None)]), "{msgs:?}");
        update(&mut m, Msg::Exit(None));
        assert!(m.quit);
        assert_eq!(m.exit_notice, None, "revoked: nothing to report");
    }

    /// A daemon that accepts the connection and never answers: the
    /// revocation gives up after [`REVOKE_TIMEOUT`], not the 15s request
    /// timeout, and the user is told the token is still live.
    #[test]
    fn a_revocation_on_quit_is_bounded_and_reported_when_it_fails() {
        let wedged = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", wedged.local_addr().expect("an address"));
        let mut m = model();
        update(
            &mut m,
            Msg::SignedIn(
                Api::new(&url, None)
                    .and_then(|api| api.with_token("tds_minted"))
                    .expect("a valid URL"),
            ),
        );
        let effects = update(&mut m, Msg::Quit);
        let started = Instant::now();
        let msgs = testing::run(effects);
        let waited = started.elapsed();
        assert!(
            waited >= REVOKE_TIMEOUT && waited < REVOKE_TIMEOUT + Duration::from_secs(2),
            "gave up after {waited:?}"
        );
        let [Msg::Exit(Some(notice))] = &msgs[..] else {
            panic!("leaves, saying why: {msgs:?}");
        };
        assert!(
            notice.contains("could not be revoked") && notice.contains("did not answer"),
            "{notice}"
        );
        let notice = notice.clone();
        update(&mut m, msgs.into_iter().next().expect("one message"));
        assert!(m.quit);
        assert_eq!(m.exit_notice, Some(notice), "kept for main to print");

        // A refusal is reported the same way, with what the daemon said.
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = model();
        update(
            &mut m,
            Msg::SignedIn(daemon.api().with_token("tds_minted").expect("a valid URL")),
        );
        let msgs = testing::run(update(&mut m, Msg::Quit));
        assert!(
            matches!(&msgs[..], [Msg::Exit(Some(n))] if n.contains("HTTP 500")),
            "{msgs:?}"
        );

        // A `401` says the token is already invalid: nothing to report.
        let daemon = testing::Recorder::start(
            "401 Unauthorized",
            r#"{"type":"about:blank","title":"Unauthorized","status":401}"#,
        );
        let mut m = model();
        update(
            &mut m,
            Msg::SignedIn(daemon.api().with_token("tds_minted").expect("a valid URL")),
        );
        let msgs = testing::run(update(&mut m, Msg::Quit));
        assert_eq!(daemon.lines(), [REVOKE], "asked to revoke it");
        assert!(matches!(msgs[..], [Msg::Exit(None)]), "{msgs:?}");
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
            update(&mut m, Msg::Changed("00000000000000aa".into())).len(),
            1,
            "a change notification refreshes"
        );
    }

    #[test]
    fn an_open_trackers_tab_is_polled_while_the_stream_is_up() {
        use screens::torrents::Msg as T;
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = signed_in_as(model_at(&daemon), false);
        m.tab = Tab::Torrents;
        update(&mut m, Msg::LiveChanged(Live::Streaming));
        let infohash = "ab".repeat(20);
        let page: types::TorrentPage = testing::from_json(serde_json::json!({
            "items": [{
                "infohash": infohash, "profile_id": "acct_a", "phase": "seeding",
                "progress": 1.0, "upload_rate": 0, "download_rate": 0,
                "total_uploaded": 0, "total_payload_uploaded": 0, "num_peers": 0,
                "is_finished": true, "is_seeding": true,
            }],
            "next_cursor": null,
        }));
        let generation = m.torrents.list.generation;
        update(
            &mut m,
            Msg::Torrents(T::Page {
                generation,
                first: true,
                result: Ok(page),
            }),
        );
        update(&mut m, Msg::Torrents(T::Open));
        update(&mut m, Msg::Torrents(T::Tab(true)));
        update(&mut m, Msg::Torrents(T::Tab(true)));
        let trackers: types::TrackerList = testing::from_json(serde_json::json!({"items": []}));
        update(
            &mut m,
            Msg::Torrents(T::Trackers {
                hash: infohash.clone(),
                result: Ok(trackers),
            }),
        );
        // Nothing the stream reports has changed, and the screen refreshed
        // just now; only the trackers' own timer is due.
        m.last_refresh = Some(Instant::now());
        let detail = m.torrents.detail.as_mut().unwrap();
        detail.trackers_asked = detail
            .trackers_asked
            .map(|at| at - screens::torrents::TRACKERS_POLL_INTERVAL);

        testing::run(update(&mut m, Msg::Tick));
        assert_eq!(
            daemon.lines(),
            [format!("GET /v1/torrents/{infohash}/trackers")]
        );
        assert!(
            update(&mut m, Msg::Tick).is_empty(),
            "and not again until the interval"
        );
    }

    #[test]
    fn a_tick_with_an_unchanged_fingerprint_fetches_nothing() {
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = signed_in_as(model_at(&daemon), false);
        m.tab = Tab::Torrents;
        update(&mut m, Msg::LiveChanged(Live::Streaming));
        let tick = |fp: &str| Msg::Changed(fp.to_owned());

        testing::run(update(&mut m, tick("00000000000000aa")));
        assert_eq!(
            daemon.lines(),
            ["GET /v1/profiles", "GET /v1/torrents?limit=100"],
            "the first tick refreshes what is on screen"
        );
        // Let the list's answer land so a refresh is not skipped as one
        // already in flight.
        m.torrents.list.loading = false;
        m.torrents.profiles_loading = false;

        assert!(
            update(&mut m, tick("00000000000000aa")).is_empty(),
            "the daemon re-sent the same state: nothing to fetch"
        );
        testing::run(update(&mut m, tick("00000000000000bb")));
        assert_eq!(daemon.lines().len(), 4, "a new fingerprint refreshes");
        m.torrents.list.loading = false;
        m.torrents.profiles_loading = false;

        // A reconnect forgets it: what changed while the stream was down is
        // unknown, so the first tick after refreshes even if it matches.
        update(
            &mut m,
            Msg::LiveChanged(Live::Reconnecting {
                reason: "down".into(),
            }),
        );
        update(&mut m, Msg::LiveChanged(Live::Streaming));
        assert_eq!(update(&mut m, tick("00000000000000bb")).len(), 2);
    }

    #[test]
    fn a_change_that_lands_while_the_list_is_loading_is_retried_on_its_re_send() {
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = signed_in_as(model_at(&daemon), false);
        m.tab = Tab::Torrents;
        update(&mut m, Msg::LiveChanged(Live::Streaming));
        let tick = |fp: &str| Msg::Changed(fp.to_owned());

        testing::run(update(&mut m, tick("00000000000000aa")));
        assert_eq!(daemon.lines().len(), 2, "the first tick refreshes");
        // The list's re-read is still in flight (a multi-page reload, say)
        // when the state changes: the screen skips the list, whose answer
        // may predate the change.
        m.torrents.profiles_loading = false;
        testing::run(update(&mut m, tick("00000000000000bb")));
        assert_eq!(
            daemon.lines()[2..],
            ["GET /v1/profiles"],
            "the list is not restarted mid-load"
        );
        m.torrents.list.loading = false;
        m.torrents.profiles_loading = false;

        // The daemon re-sends the same fingerprint: the skipped list is
        // re-read now that it can be.
        testing::run(update(&mut m, tick("00000000000000bb")));
        assert_eq!(
            daemon.lines()[3..],
            ["GET /v1/profiles", "GET /v1/torrents?limit=100"],
            "the change skipped mid-load is fetched on its re-send"
        );
        m.torrents.list.loading = false;
        m.torrents.profiles_loading = false;
        assert!(
            update(&mut m, tick("00000000000000bb")).is_empty(),
            "once seen, a re-send fetches nothing"
        );
    }

    #[test]
    fn a_change_is_remembered_only_when_the_visible_screen_is_not_loading() {
        // Each tab's own busy() decides, through the load flag it reads.
        type SetLoading = fn(&mut Model, bool);
        let tabs: [(Tab, SetLoading); 3] = [
            (Tab::Dashboard, |m, on| m.dashboard.loading = on),
            (Tab::Profiles, |m, on| m.profiles.loading = on),
            (Tab::Pool, |m, on| m.pool.overview.loading = on),
        ];
        for (tab, set_loading) in tabs {
            let mut m = signed_in(true);
            m.tab = tab;
            update(&mut m, Msg::LiveChanged(Live::Streaming));
            // Every screen idle but the one shown, so only its gate decides.
            m.dashboard.loading = false;
            m.profiles.loading = false;
            m.pool.overview.loading = false;
            let tick = || Msg::Changed("00000000000000aa".to_owned());

            set_loading(&mut m, true);
            update(&mut m, tick());
            assert_eq!(
                m.fingerprint, None,
                "{tab:?}: a change skipped mid-load is not remembered"
            );

            set_loading(&mut m, false);
            assert!(
                !update(&mut m, tick()).is_empty(),
                "{tab:?}: its re-send refreshes the screen"
            );
            assert_eq!(
                m.fingerprint.as_deref(),
                Some("00000000000000aa"),
                "{tab:?}: a change refreshed in full is remembered"
            );

            set_loading(&mut m, false);
            assert!(
                update(&mut m, tick()).is_empty(),
                "{tab:?}: once remembered, a re-send fetches nothing"
            );
        }
    }

    #[test]
    fn a_change_whose_refresh_fails_is_retried_on_its_re_send() {
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = signed_in_as(model_at(&daemon), false);
        m.tab = Tab::Profiles;
        update(&mut m, Msg::LiveChanged(Live::Streaming));
        let tick = |fp: &str| Msg::Changed(fp.to_owned());
        let answer = |m: &mut Model, effects: Vec<Effect>| {
            for msg in testing::run(effects) {
                update(m, msg);
            }
        };

        // The refresh the change triggers fails: a transient 500, say.
        let effects = update(&mut m, tick("00000000000000aa"));
        answer(&mut m, effects);
        assert_eq!(daemon.lines(), ["GET /v1/profiles"]);
        assert!(m.profiles.error.is_some(), "the failure is shown");

        // The daemon re-sends the same fingerprint: the failed load is
        // retried, not left on screen until some other change arrives.
        let effects = update(&mut m, tick("00000000000000aa"));
        answer(&mut m, effects);
        assert_eq!(
            daemon.lines(),
            ["GET /v1/profiles", "GET /v1/profiles"],
            "a change whose refresh failed is fetched again on its re-send"
        );

        // Once a refresh it triggered succeeds, a re-send fetches nothing.
        assert_eq!(update(&mut m, tick("00000000000000aa")).len(), 1);
        update(
            &mut m,
            Msg::Profiles(screens::profiles::Msg::Loaded(Ok(Vec::new()))),
        );
        assert!(m.profiles.error.is_none());
        assert!(
            update(&mut m, tick("00000000000000aa")).is_empty(),
            "once loaded, a re-send fetches nothing"
        );
    }

    #[test]
    fn an_unreachable_daemon_is_retried_not_treated_as_a_sign_out() {
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = model_at(&daemon);
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
        testing::run(update(&mut m, Msg::Tick));
        assert_eq!(daemon.lines(), CHECK, "asks again");
        assert!(matches!(m.session, Session::Checking));

        // `r` asks at once; typing is not a password.
        update(
            &mut m,
            Msg::SessionChecked(Err(Failure::local("down", None))),
        );
        assert!(update(&mut m, Msg::Key(testing::key(KeyCode::Char('x')))).is_empty());
        testing::run(update(&mut m, Msg::Key(testing::key(KeyCode::Char('r')))));
        assert_eq!(daemon.lines(), [CHECK, CHECK].concat(), "`r` asks again");
    }

    #[test]
    fn a_token_without_the_read_scope_is_not_asked_again_unprompted() {
        let mut m = model();
        let refused = Failure {
            status: Some(403),
            ..Failure::local("Forbidden", None)
        };
        update(&mut m, Msg::SessionChecked(Err(refused)));
        if let Session::Unreachable { since, .. } = &mut m.session {
            *since -= RETRY_INTERVAL;
        }
        assert!(update(&mut m, Msg::Tick).is_empty(), "no retry loop");
        assert_eq!(
            update(&mut m, Msg::Key(testing::key(KeyCode::Char('r')))).len(),
            1,
            "`r` still asks"
        );
    }

    #[test]
    fn a_minted_token_is_revoked_whatever_state_the_session_is_in() {
        // Quit while the new session is still being described.
        let daemon = testing::Recorder::start("204 No Content", "");
        let mut m = model();
        update(
            &mut m,
            Msg::SignedIn(daemon.api().with_token("tds_1").unwrap()),
        );
        assert!(matches!(m.session, Session::Checking));
        testing::run(update(&mut m, Msg::Quit));
        assert!(!m.quit);
        assert_eq!(
            daemon.requests(),
            [testing::Request {
                line: REVOKE.to_owned(),
                bearer: Some("tds_1".to_owned()),
            }],
            "revoked, not orphaned"
        );

        // Signing in again revokes the first token before replacing it.
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut m = model();
        let first = daemon.api().with_token("tds_1").unwrap();
        update(&mut m, Msg::SignedIn(first.clone()));
        let effects = update(&mut m, Msg::SignedIn(first.with_token("tds_2").unwrap()));
        testing::run(effects);
        let sent: Vec<_> = daemon
            .requests()
            .into_iter()
            .map(|r| (r.line, r.bearer.unwrap_or_default()))
            .collect();
        let expected: Vec<_> = [(REVOKE, "tds_1"), (CHECK[0], "tds_2"), (CHECK[1], "tds_2")]
            .into_iter()
            .map(|(line, bearer)| (line.to_owned(), bearer.to_owned()))
            .collect();
        assert_eq!(sent, expected, "revoke the old, describe the new");
        assert_eq!(m.api.epoch, 2);
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

        refused(&mut m);
        assert!(
            m.dashboard.confirm_reload.is_none(),
            "stale dialogs are gone"
        );
    }

    #[test]
    fn a_stale_401_does_not_sign_out_a_credential_that_still_works() {
        let mut m = model();
        update(&mut m, Msg::SignedIn(testing::api()));
        update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(false, false), principal("session")))),
        );
        // A 401 answering a request made before this sign-in.
        update(&mut m, Msg::SignedOut(unauthorized()));
        update(
            &mut m,
            Msg::SessionChecked(Ok((testing::server(false, false), principal("session")))),
        );
        assert!(
            matches!(m.session, Session::SignedIn { .. }),
            "still signed in"
        );
        assert!(m.minted, "and the live token is still owed a revocation");
    }

    #[test]
    fn quitting_during_a_sign_in_revokes_the_token_it_mints() {
        let daemon = testing::Recorder::start("204 No Content", "");
        let mut m = model_at(&daemon);
        update(&mut m, Msg::SessionChecked(Err(unauthorized())));
        m.login.busy = true;
        let effects = update(&mut m, Msg::Quit);
        assert!(!m.quit, "waits for the sign-in");
        let msgs = testing::run(effects);
        assert!(
            matches!(&msgs[..], [Msg::Toast(t)] if t.text.starts_with("finishing sign-in")),
            "says so: {msgs:?}"
        );
        let effects = update(
            &mut m,
            Msg::Login(screens::login::Msg::Answered(Ok("tds_late".into()))),
        );
        assert!(!m.quit);
        let msgs = testing::run(effects);
        assert_eq!(
            daemon.requests(),
            [testing::Request {
                line: REVOKE.to_owned(),
                bearer: Some("tds_late".to_owned()),
            }],
            "revokes what it minted"
        );
        assert!(
            matches!(msgs[..], [Msg::Exit(None)]),
            "then leaves: {msgs:?}"
        );

        // A second quit leaves at once.
        let mut m = model();
        m.login.busy = true;
        update(&mut m, Msg::Quit);
        update(&mut m, Msg::Quit);
        assert!(m.quit);
    }

    #[test]
    fn the_first_check_asks_for_a_password_without_calling_it_an_error() {
        let mut m = model();
        update(&mut m, Msg::SessionChecked(Err(unauthorized())));
        assert!(matches!(m.session, Session::SignedOut));
        assert_eq!(m.login.error, None);
    }

    #[test]
    fn keys_during_a_recheck_reach_nothing_and_do_not_quit() {
        let mut m = signed_in(false);
        update(&mut m, Msg::SignedOut(unauthorized()));
        assert!(matches!(m.session, Session::Checking));
        for code in [KeyCode::Char('q'), KeyCode::Esc] {
            assert!(update(&mut m, Msg::Key(testing::key(code))).is_empty());
        }
        assert!(!m.quit && !m.quitting);
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        // A static token: nothing to revoke, so it leaves at once.
        assert!(update(&mut m, Msg::Key(ctrl_c)).is_empty());
        assert!(m.quit, "Ctrl-C still quits");
    }

    #[test]
    fn a_second_esc_during_a_sign_in_quits_at_once() {
        let mut m = model();
        update(&mut m, Msg::SessionChecked(Err(unauthorized())));
        m.login.busy = true;
        update(&mut m, Msg::Key(testing::key(KeyCode::Esc)));
        assert!(!m.quit);
        update(&mut m, Msg::Key(testing::key(KeyCode::Esc)));
        assert!(m.quit);
    }

    #[test]
    fn keys_while_checking_do_not_type_into_a_hidden_password() {
        let mut m = model();
        assert!(matches!(m.session, Session::Checking));
        update(&mut m, Msg::Key(testing::key(KeyCode::Char('r'))));
        assert!(m.login.password.value().is_empty());
        assert!(update(&mut m, Msg::Key(testing::key(KeyCode::Enter))).is_empty());
        update(&mut m, Msg::Key(testing::key(KeyCode::Char('q'))));
        assert!(m.quit);
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
