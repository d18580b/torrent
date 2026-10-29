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

#[cfg(test)]
mod tests;
mod view;

use std::collections::HashMap;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;

pub use self::view::view;
use crate::api::types;
use crate::api::Failure;
use crate::fmt;
use crate::screens::contract::failed;
use crate::screens::contract::sign_out_on_401;
use crate::screens::contract::Ctx;
use crate::screens::contract::Effect;
use crate::screens::contract::Toast;
use crate::screens::contract::ToastKind;
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

/// Whether a load is in flight, so a refresh now would skip it.
pub fn busy(state: &State) -> bool {
    state.loading
}

/// Whether the last load of the list, or of the selected profile's detail,
/// failed, so what is shown may predate a change.
pub fn load_failed(state: &State) -> bool {
    state.error.is_some()
        || state
            .detail_error
            .as_ref()
            .is_some_and(|(id, _)| state.current().is_some_and(|p| p.profile_id == *id))
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
            sign_out_on_401(&failure)
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
