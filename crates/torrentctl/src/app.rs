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
        /// Why the daemon refused (a 403), or `None` when it is asked again
        /// unprompted. A refusal is not retried: a token without the `read`
        /// scope stays without it, a Host outside `allowed_hosts` stays
        /// outside it, and every refusal is counted by the daemon.
        refused: Option<Refusal>,
    },
    /// The daemon wants a password.
    SignedOut,
    /// Signed in, or authentication is disabled.
    SignedIn {
        server: Box<types::ServerInfo>,
        principal: Box<types::Principal>,
    },
}

/// Why the daemon answered the session check with a 403.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `insufficient-scope`: the token lacks the `read` scope.
    Scope,
    /// Any other 403, such as a daemon without `[auth]` refusing a Host it
    /// does not answer to.
    Forbidden,
}

impl Refusal {
    /// The refusal a session-check failure carries, if it is one.
    fn of(failure: &Failure) -> Option<Self> {
        if failure.status != Some(403) {
            None
        } else if failure.is("insufficient-scope") {
            Some(Self::Scope)
        } else {
            Some(Self::Forbidden)
        }
    }
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
    /// from the password, and so revokes on the way out.
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
    /// Why the client stopped, when a background task panicked: the loop
    /// ends and the process exits non-zero with it.
    pub fatal: Option<String>,
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
    /// A background task panicked, with what it said: the model can no
    /// longer be trusted to reflect the daemon, so the client stops, after
    /// revoking a minted token as a quit does. A second one leaves at once.
    Fatal(String),
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
            fatal: None,
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
            if let Session::Unreachable { since, refused, .. } = model.session {
                if refused.is_none() && now.duration_since(since) >= RETRY_INTERVAL {
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
                refused: Refusal::of(&failure),
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
            model.login.busy = false;
            if model.quitting {
                // The quit came after the daemon answered but before this
                // landed: the token is live and owed a revocation, then the
                // exit the quit asked for.
                effects.push(revoke(&model.api, true));
                return effects;
            }
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
        Msg::Fatal(what) => {
            if model.fatal.is_some() {
                // A second panic: leave now, reporting a minted token the
                // revocation under way may not have reached, or a sign-in
                // still in flight whose token nothing will revoke.
                if model.minted {
                    model.exit_notice.get_or_insert_with(|| {
                        "torrentctl: the session token signed in here was not revoked; it \
                         stays valid on the daemon until it expires"
                            .to_owned()
                    });
                } else if model.login.busy {
                    model.exit_notice.get_or_insert_with(|| {
                        "torrentctl: the sign-in had not answered; if the daemon mints a \
                         session token for it, that token stays valid on the daemon until \
                         it expires"
                            .to_owned()
                    });
                }
                model.quit = true;
                return Vec::new();
            }
            // The runtime caught the panic and is intact: the loop stops
            // drawing (see `runtime::run_with`), and the exit finishes as a
            // quit does — revoking a minted token, or waiting for an
            // in-flight sign-in to revoke what it mints. A quit already
            // under way keeps its revocation in flight.
            model.fatal = Some(what);
            if model.quitting {
                Vec::new()
            } else {
                update(model, Msg::Quit)
            }
        }
        Msg::Key(key) => on_key(model, key),
        Msg::Login(screens::login::Msg::Answered(result)) if model.quitting => {
            // Quitting while this sign-in was in flight: revoke what it
            // minted, then leave.
            match result
                .ok()
                .and_then(|token| model.api.with_token(&token).ok())
            {
                Some(api) => {
                    // The token is live and owed this revocation: counted
                    // as minted, so an exit that cannot wait for it (a
                    // second panic or signal, or a timeout) reports it.
                    model.api = api;
                    model.minted = true;
                    vec![revoke(&model.api, true)]
                }
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
mod tests;
