//! Torrents: every torrent the daemon holds, page by page, filtered by
//! profile, phase and text; one torrent's overview, files and trackers; the
//! actions on one or all of them; and adding one.

mod actions;
mod add;
mod detail;
mod list;
#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::Frame;
use tui_input::backend::crossterm::EventHandler as _;
use tui_input::Input;

use self::actions::act;
use self::actions::bulk;
use self::actions::bulk_toast;
use self::actions::perform;
pub use self::actions::Action;
use self::detail::fetch_files;
use self::detail::load_detail;
use self::detail::load_files;
use self::detail::load_trackers;
use self::detail::more_files;
use self::detail::move_in_detail;
use self::detail::open_detail;
use self::detail::rereads_files;
use self::detail::rereads_trackers;
use self::list::fetch_page;
use self::list::list;
use self::list::load_list;
use self::list::load_more;
use self::list::load_profiles;
use self::list::reselect;
use self::list::selected_summary;
use self::list::set_server_filter;
use self::list::settle;
use self::list::visible;
use crate::api::types;
use crate::api::Failure;
use crate::fmt;
use crate::screens::contract::failed;
use crate::screens::contract::sign_out_on_401;
use crate::screens::contract::Ctx;
use crate::screens::contract::Effect;
use crate::screens::contract::Toast;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;
use crate::ui::widgets::Motion;
use crate::ui::widgets::Paged;
use crate::ui::widgets::Received;

/// The phases `F` cycles through, after "all".
const PHASES: [types::Phase; 10] = [
    types::Phase::Checking,
    types::Phase::AwaitingMetadata,
    types::Phase::Incomplete,
    types::Phase::Idle,
    types::Phase::Seeding,
    types::Phase::Paused,
    types::Phase::DiskError,
    types::Phase::Errored,
    types::Phase::Removed,
    types::Phase::Unknown,
];

/// The id the last add request was sent with; each one takes the next.
/// Process-wide rather than in [`State`], which a sign-out resets while an
/// add sent before it may still answer.
static ADD_REQUESTS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
pub struct State {
    pub list: Paged<types::TorrentSummary>,
    /// Only this profile's torrents (server-side).
    pub profile: Option<String>,
    /// Only torrents in this phase (server-side).
    pub phase: Option<types::Phase>,
    /// The `/` filter over what is loaded: an infohash prefix or part of a
    /// profile id, as typed. It matches in any case.
    pub filter: String,
    /// The `/` field, while it has the keyboard.
    pub filter_input: Option<Input>,
    /// The selected row among those the filter shows.
    pub selected: usize,
    pub list_offset: Cell<usize>,
    /// A torrent to select once a page holding it arrives: the selection
    /// across a reload, or a torrent just added.
    pub restore: Option<String>,
    pub profiles: Vec<types::Profile>,
    pub profiles_loading: bool,
    pub confirm: Option<(Confirm, Pending)>,
    pub detail: Option<detail::Detail>,
    pub add: Option<add::Dialog>,
    /// The clock relative times are drawn against; the wall clock when
    /// `None` (tests fix it).
    pub now: Option<time::OffsetDateTime>,
}

/// What a confirmation dialog is asking about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    Act(Action, String),
    PauseAll,
    ResumeAll,
}

/// A change to the selected file's priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    Up,
    Down,
    Set(i64),
}

#[derive(Debug)]
pub enum Msg {
    /// Open the add-torrent dialog.
    OpenAdd,
    /// Show only this profile's torrents (`None` for every profile), and
    /// reload.
    FilterProfile(Option<String>),
    /// A page of the list, answering reload `generation`.
    Page {
        generation: u64,
        first: bool,
        result: Result<types::TorrentPage, Failure>,
    },
    Profiles(Result<Vec<types::Profile>, Failure>),
    Move(Motion),
    /// Open the selected torrent.
    Open,
    /// Back from the detail view to the list.
    Back,
    /// `f`: the next profile, or every profile after the last.
    CycleProfile,
    /// `F`: the next phase, or every phase after the last.
    CyclePhase,
    StartFilter,
    FilterKey(KeyEvent),
    ClearFilter,
    /// An action on the selected (or open) torrent, or on all.
    Act(Action),
    ConfirmKey(KeyEvent),
    Acted {
        action: Action,
        hash: String,
        result: Result<(), Failure>,
    },
    Bulk {
        pause: bool,
        result: Result<types::BulkOutcome, Failure>,
    },
    /// The open torrent's record.
    Torrent {
        hash: String,
        result: Result<types::Torrent, Failure>,
    },
    FilesPage {
        hash: String,
        generation: u64,
        first: bool,
        result: Result<types::TorrentFilePage, Failure>,
    },
    Trackers {
        hash: String,
        result: Result<types::TrackerList, Failure>,
    },
    /// The next (`true`) or previous detail tab.
    Tab(bool),
    Priority(Priority),
    /// `=`: ask for a priority digit.
    PriorityPrompt,
    PromptKey(KeyEvent),
    PrioritySet {
        hash: String,
        index: i64,
        previous: i64,
        priority: i64,
        result: Result<(), Failure>,
    },
    OpenLimit,
    LimitKey(KeyEvent),
    LimitSet {
        hash: String,
        value: Option<i64>,
        result: Result<(), Failure>,
    },
    /// `Enter` on the actions tab.
    RunEntry,
    AddKey(KeyEvent),
    /// The answer to the add sent with id `request`.
    Added {
        request: u64,
        result: Result<types::Torrent, add::AddFailure>,
    },
}

/// The keys, list first, then the detail view's (the help overlay shows
/// them all; the detail view's own hints are in its bottom border).
pub const KEYS: &[(&str, &str)] = &[
    ("Enter", "open"),
    ("n", "add"),
    ("/", "filter"),
    ("f/F", "profile/phase"),
    ("p/r", "pause/resume"),
    ("d/D", "remove/+files"),
    ("c/a", "recheck/reannounce"),
    ("P/U", "pause/resume all"),
    ("j/k g/G", "move, top/bottom"),
    ("PgUp/PgDn", "page"),
    ("←/→ [/]", "detail: tab"),
    ("Esc/h", "detail: back"),
    ("+/- 0 =", "detail: file priority"),
    ("l", "detail: upload limit"),
];

pub fn capturing(state: &State) -> bool {
    state.confirm.is_some()
        || state.add.is_some()
        || state.filter_input.is_some()
        || state
            .detail
            .as_ref()
            .is_some_and(|d| d.prompt || d.limit.is_some())
}

/// Whether a load is in flight, so a refresh now would skip it.
pub fn busy(state: &State) -> bool {
    state.profiles_loading
        || match &state.detail {
            Some(d) => d.loading || d.files.loading || d.trackers_loading,
            None => state.list.loading,
        }
}

/// Whether the last load of what is shown, the list or the open torrent,
/// failed, so it may predate a change. A files or trackers error counts only
/// where [`load_detail`] re-reads it: one it will not re-read would never
/// clear, and the change would be refetched on every re-send.
pub fn load_failed(state: &State) -> bool {
    match &state.detail {
        Some(d) => {
            d.error.is_some()
                || (rereads_files(d) && d.files.error.is_some())
                || (rereads_trackers(d) && d.trackers_error.is_some())
        }
        None => state.list.error.is_some(),
    }
}

pub fn on_key(state: &State, key: KeyEvent) -> Option<Msg> {
    if state.confirm.is_some() {
        return Some(Msg::ConfirmKey(key));
    }
    if state.add.is_some() {
        return Some(Msg::AddKey(key));
    }
    if state.filter_input.is_some() {
        return Some(Msg::FilterKey(key));
    }
    let movement = Motion::from_key(key);
    let action = match key.code {
        KeyCode::Char('p') => Some(Action::Pause),
        KeyCode::Char('r') => Some(Action::Resume),
        KeyCode::Char('c') => Some(Action::Recheck),
        KeyCode::Char('a') => Some(Action::Reannounce),
        KeyCode::Char('d') => Some(Action::Remove),
        KeyCode::Char('D') => Some(Action::RemoveFiles),
        _ => None,
    };
    if let Some(detail) = &state.detail {
        if detail.limit.is_some() {
            return Some(Msg::LimitKey(key));
        }
        if detail.prompt {
            return Some(Msg::PromptKey(key));
        }
        if let Some(m) = movement {
            return Some(Msg::Move(m));
        }
        if let Some(a) = action {
            return Some(Msg::Act(a));
        }
        return match key.code {
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Backspace => Some(Msg::Back),
            KeyCode::Left | KeyCode::Char('[') => Some(Msg::Tab(false)),
            KeyCode::Right | KeyCode::Char(']') => Some(Msg::Tab(true)),
            KeyCode::Enter if detail.tab == detail::Tab::Actions => Some(Msg::RunEntry),
            KeyCode::Char('+') => Some(Msg::Priority(Priority::Up)),
            KeyCode::Char('-') => Some(Msg::Priority(Priority::Down)),
            KeyCode::Char('0') => Some(Msg::Priority(Priority::Set(0))),
            KeyCode::Char('=') => Some(Msg::PriorityPrompt),
            KeyCode::Char('l') => Some(Msg::OpenLimit),
            KeyCode::Char('n') => Some(Msg::OpenAdd),
            _ => None,
        };
    }
    if let Some(m) = movement {
        return Some(Msg::Move(m));
    }
    if let Some(a) = action {
        return Some(Msg::Act(a));
    }
    match key.code {
        KeyCode::Enter => Some(Msg::Open),
        KeyCode::Char('/') => Some(Msg::StartFilter),
        KeyCode::Esc if !state.filter.is_empty() => Some(Msg::ClearFilter),
        KeyCode::Char('f') => Some(Msg::CycleProfile),
        KeyCode::Char('F') => Some(Msg::CyclePhase),
        KeyCode::Char('n') => Some(Msg::OpenAdd),
        KeyCode::Char('P') => Some(Msg::Act(Action::PauseAll)),
        KeyCode::Char('U') => Some(Msg::Act(Action::ResumeAll)),
        _ => None,
    }
}

pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    let mut effects = load_profiles(state, ctx);
    match &mut state.detail {
        Some(detail) => effects.extend(load_detail(detail, ctx)),
        None if state.list.loading => {}
        None => effects.extend(load_list(state, ctx)),
    }
    effects
}

/// How often an open torrent's trackers are re-read while its Trackers tab is
/// shown, whatever the event stream says.
pub const TRACKERS_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Re-read the open torrent's trackers when its Trackers tab is shown and
/// they were last asked for at least [`TRACKERS_POLL_INTERVAL`] before `now`.
/// `GET /v1/events`' fingerprint does not cover a tracker's status or
/// message, which the daemon reads from the session on request, so on an
/// idle seeding torrent a tracker that starts failing changes nothing the
/// stream reports: only this poll shows it.
pub fn poll(state: &mut State, now: Instant, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(detail) = state.detail.as_mut() else {
        return Vec::new();
    };
    let due = detail
        .trackers_asked
        .is_none_or(|at| now.saturating_duration_since(at) >= TRACKERS_POLL_INTERVAL);
    if rereads_trackers(detail) && !detail.trackers_loading && due {
        load_trackers(detail, ctx)
    } else {
        Vec::new()
    }
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match msg {
        Msg::OpenAdd => {
            let active = active_profiles(state);
            state.add = Some(add::Dialog::new(state.profile.as_deref(), &active));
            load_profiles(state, ctx)
        }
        Msg::FilterProfile(profile) => {
            state.detail = None;
            set_server_filter(state, profile, state.phase.clone(), ctx)
        }
        Msg::Page {
            generation,
            first,
            result,
        } => {
            if generation != state.list.generation {
                return Vec::new();
            }
            match result {
                Ok(page) => {
                    match state
                        .list
                        .receive(generation, first, page.items, page.next_cursor)
                    {
                        Received::Stale => Vec::new(),
                        Received::Continue(request) => vec![fetch_page(
                            ctx.api,
                            state.profile.clone(),
                            state.phase.clone(),
                            request,
                        )],
                        Received::Settled => settle(state, ctx),
                    }
                }
                Err(failure) => {
                    if state.list.fail(generation, failure.message()) {
                        // The reload will not settle: a later page must not
                        // snap the selection back to where it began.
                        state.restore = None;
                    }
                    sign_out_on_401(&failure)
                }
            }
        }
        Msg::Profiles(result) => {
            state.profiles_loading = false;
            match result {
                Ok(profiles) => {
                    state.profiles = profiles;
                    let active = active_profiles(state);
                    if let Some(dialog) = &mut state.add {
                        dialog.profiles_arrived(&active);
                    }
                    Vec::new()
                }
                Err(failure) => {
                    let effects = sign_out_on_401(&failure);
                    if effects.is_empty() && state.add.is_some() {
                        vec![Effect::now(failed("loading profiles", failure))]
                    } else {
                        effects
                    }
                }
            }
        }
        Msg::Move(movement) => match &mut state.detail {
            Some(detail) => move_in_detail(detail, movement, ctx),
            None => {
                let len = visible(state).len();
                state.selected = movement.apply(state.selected, len);
                if state.list.loading {
                    // A reload is in flight: keep what the operator chose.
                    state.restore = selected_summary(state).map(|s| s.infohash.clone());
                }
                load_more(state, ctx)
            }
        },
        Msg::Open => {
            let Some(summary) = selected_summary(state).cloned() else {
                return Vec::new();
            };
            let mut detail = detail::Detail::new(summary.infohash.clone(), Some(summary));
            let effects = load_detail(&mut detail, ctx);
            state.detail = Some(detail);
            effects
        }
        Msg::Back => {
            state.detail = None;
            if state.list.loading {
                Vec::new()
            } else {
                load_list(state, ctx)
            }
        }
        Msg::CycleProfile => {
            let ids: Vec<String> = state
                .profiles
                .iter()
                .map(|p| p.profile_id.clone())
                .collect();
            if ids.is_empty() {
                let mut effects = vec![Effect::toast(Toast::info("profiles are still loading"))];
                effects.extend(load_profiles(state, ctx));
                return effects;
            }
            let next = match state
                .profile
                .as_ref()
                .and_then(|p| ids.iter().position(|i| i == p))
            {
                None => ids.first().cloned(),
                Some(at) => ids.get(at + 1).cloned(),
            };
            set_server_filter(state, next, state.phase.clone(), ctx)
        }
        Msg::CyclePhase => {
            let next = match state
                .phase
                .as_ref()
                .and_then(|p| PHASES.iter().position(|x| x == p))
            {
                None => Some(PHASES[0].clone()),
                Some(at) => PHASES.get(at + 1).cloned(),
            };
            set_server_filter(state, state.profile.clone(), next, ctx)
        }
        Msg::StartFilter => {
            state.filter_input = Some(Input::new(state.filter.clone()));
            Vec::new()
        }
        Msg::FilterKey(key) => {
            let keep = selected_summary(state).map(|s| s.infohash.clone());
            let Some(input) = state.filter_input.as_mut() else {
                return Vec::new();
            };
            match key.code {
                KeyCode::Enter => state.filter_input = None,
                KeyCode::Esc => {
                    state.filter_input = None;
                    state.filter.clear();
                }
                _ => {
                    input.handle_event(&crossterm::event::Event::Key(key));
                    state.filter = input.value().trim().to_owned();
                }
            }
            reselect(state, keep);
            load_more(state, ctx)
        }
        Msg::ClearFilter => {
            let keep = selected_summary(state).map(|s| s.infohash.clone());
            state.filter.clear();
            reselect(state, keep);
            Vec::new()
        }
        Msg::Act(action) => act(state, action, ctx),
        Msg::ConfirmKey(key) => {
            let Some((confirm, _)) = state.confirm.as_mut() else {
                return Vec::new();
            };
            match confirm.on_key(key) {
                Confirmed::Pending => Vec::new(),
                Confirmed::No => {
                    state.confirm = None;
                    Vec::new()
                }
                Confirmed::Yes => match state.confirm.take() {
                    Some((_, Pending::Act(action, hash))) => vec![perform(ctx.api, action, hash)],
                    Some((_, Pending::PauseAll)) => vec![bulk(ctx.api, true)],
                    Some((_, Pending::ResumeAll)) => vec![bulk(ctx.api, false)],
                    None => Vec::new(),
                },
            }
        }
        Msg::Acted {
            action,
            hash,
            result: Ok(()),
        } => {
            let short = fmt::short_hash(&hash).to_owned();
            let text = match action {
                Action::Pause => format!("paused {short}"),
                Action::Resume => format!("resumed {short}"),
                Action::Recheck => {
                    format!(
                        "recheck accepted for {short}; it shows `checking` once its check starts, \
                         which waits for a verify slot with [pool]"
                    )
                }
                Action::Reannounce => {
                    format!("reannounce sent for {short}; its trackers show the outcome")
                }
                Action::Remove => format!("removed {short}; its payload stays on disk"),
                Action::RemoveFiles => format!("removed {short} and moved its files to the trash"),
                Action::PauseAll | Action::ResumeAll => String::new(),
            };
            if matches!(action, Action::Remove | Action::RemoveFiles)
                && state.detail.as_ref().is_some_and(|d| d.hash == hash)
            {
                state.detail = None;
            }
            let mut effects = vec![Effect::toast(Toast::success(text))];
            effects.extend(refresh(state, ctx));
            effects
        }
        Msg::Acted {
            action,
            hash,
            result: Err(failure),
        } => {
            let attempt = format!("{} {}", action.doing(), fmt::short_hash(&hash));
            vec![Effect::now(failed(&attempt, failure))]
        }
        Msg::Bulk {
            pause,
            result: Ok(outcome),
        } => {
            let mut effects = vec![Effect::toast(bulk_toast(pause, &outcome))];
            effects.extend(refresh(state, ctx));
            effects
        }
        Msg::Bulk {
            pause,
            result: Err(failure),
        } => {
            let action = if pause {
                Action::PauseAll
            } else {
                Action::ResumeAll
            };
            vec![Effect::now(failed(action.doing(), failure))]
        }
        Msg::Torrent { hash, result } => {
            let Some(detail) = open_detail(state, &hash) else {
                return Vec::new();
            };
            detail.loading = false;
            match result {
                Ok(torrent) => {
                    detail.error = None;
                    detail.torrent = Some(torrent);
                    Vec::new()
                }
                Err(failure) => {
                    detail.error = Some(failure.message());
                    sign_out_on_401(&failure)
                }
            }
        }
        Msg::FilesPage {
            hash,
            generation,
            first,
            result,
        } => {
            let Some(detail) = open_detail(state, &hash) else {
                return Vec::new();
            };
            if generation != detail.files.generation {
                return Vec::new();
            }
            match result {
                Ok(page) => {
                    detail.metadata_pending = false;
                    match detail
                        .files
                        .receive(generation, first, page.items, page.next_cursor)
                    {
                        Received::Stale => Vec::new(),
                        Received::Continue(request) => {
                            vec![fetch_files(ctx.api, detail.hash.clone(), request)]
                        }
                        Received::Settled => {
                            detail.files_selected = detail
                                .files_selected
                                .min(detail.files.items.len().saturating_sub(1));
                            more_files(detail, ctx)
                        }
                    }
                }
                Err(failure) => {
                    detail.metadata_pending = failure.is("metadata-pending");
                    detail.files.fail(generation, failure.message());
                    sign_out_on_401(&failure)
                }
            }
        }
        Msg::Trackers { hash, result } => {
            let Some(detail) = open_detail(state, &hash) else {
                return Vec::new();
            };
            detail.trackers_loading = false;
            match result {
                Ok(list) => {
                    detail.trackers_error = None;
                    detail.trackers_selected = detail
                        .trackers_selected
                        .min(list.items.len().saturating_sub(1));
                    detail.trackers = Some(list.items);
                    Vec::new()
                }
                Err(failure) => {
                    detail.trackers_error = Some(failure.message());
                    sign_out_on_401(&failure)
                }
            }
        }
        Msg::Tab(forward) => {
            let Some(detail) = state.detail.as_mut() else {
                return Vec::new();
            };
            detail.tab = detail.tab.step(forward);
            match detail.tab {
                detail::Tab::Files if detail.files.items.is_empty() && !detail.files.loading => {
                    load_files(detail, ctx)
                }
                detail::Tab::Trackers if detail.trackers.is_none() && !detail.trackers_loading => {
                    load_trackers(detail, ctx)
                }
                _ => Vec::new(),
            }
        }
        Msg::Priority(change) => {
            let Some(detail) = state.detail.as_mut() else {
                return Vec::new();
            };
            detail.prompt = false;
            if detail.tab != detail::Tab::Files {
                return Vec::new();
            }
            let hash = detail.hash.clone();
            let Some(file) = detail.files.items.get_mut(detail.files_selected) else {
                return Vec::new();
            };
            let previous = file.priority;
            let priority = match change {
                Priority::Up => previous + 1,
                Priority::Down => previous - 1,
                Priority::Set(p) => p,
            }
            .clamp(0, 7);
            if priority == previous {
                return Vec::new();
            }
            // Shown at once; put back if the daemon refuses it.
            file.priority = priority;
            let index = file.index;
            let api = ctx.api.clone();
            vec![Effect::new(async move {
                let body = types::FilePriority { priority };
                let result =
                    crate::api::call(api.client.set_file_priority(hash.clone(), index, &body))
                        .await;
                crate::app::Msg::Torrents(Msg::PrioritySet {
                    hash,
                    index,
                    previous,
                    priority,
                    result,
                })
            })]
        }
        Msg::PriorityPrompt => {
            if let Some(detail) = state.detail.as_mut() {
                detail.prompt = detail.tab == detail::Tab::Files && !detail.files.items.is_empty();
            }
            Vec::new()
        }
        Msg::PromptKey(key) => match key.code {
            KeyCode::Char(d @ '0'..='7') => update(
                state,
                Msg::Priority(Priority::Set(i64::from(d as u8 - b'0'))),
                ctx,
            ),
            KeyCode::Esc => {
                if let Some(detail) = state.detail.as_mut() {
                    detail.prompt = false;
                }
                Vec::new()
            }
            _ => Vec::new(),
        },
        Msg::PrioritySet {
            hash,
            index,
            previous,
            priority,
            result,
        } => match result {
            Ok(()) => vec![Effect::toast(Toast::success(format!(
                "file {index} of {}: priority {}",
                fmt::short_hash(&hash),
                detail::priority_label(priority)
            )))],
            Err(failure) => {
                if let Some(detail) = open_detail(state, &hash) {
                    if let Some(file) = detail
                        .files
                        .items
                        .iter_mut()
                        .find(|f| f.index == index && f.priority == priority)
                    {
                        file.priority = previous;
                    }
                    if failure.is("metadata-pending") {
                        detail.metadata_pending = true;
                    }
                }
                vec![Effect::now(failed(
                    &format!("setting file {index}'s priority"),
                    failure,
                ))]
            }
        },
        Msg::OpenLimit => {
            if let Some(detail) = state.detail.as_mut() {
                let current = detail
                    .torrent
                    .as_ref()
                    .and_then(|t| t.session.as_ref())
                    .and_then(|s| s.upload_limit_bytes_per_sec)
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                detail.limit = Some(detail::LimitInput {
                    input: Input::new(current),
                    error: None,
                });
            }
            Vec::new()
        }
        Msg::LimitKey(key) => {
            let Some(detail) = state.detail.as_mut() else {
                return Vec::new();
            };
            let Some(limit) = detail.limit.as_mut() else {
                return Vec::new();
            };
            match key.code {
                KeyCode::Esc => {
                    detail.limit = None;
                    Vec::new()
                }
                KeyCode::Enter => match detail::parse_limit(limit.input.value()) {
                    Err(e) => {
                        limit.error = Some(e);
                        Vec::new()
                    }
                    Ok(value) => {
                        detail.limit = None;
                        let hash = detail.hash.clone();
                        let api = ctx.api.clone();
                        vec![Effect::new(async move {
                            let body = types::UploadLimit {
                                bytes_per_sec: value,
                            };
                            let result =
                                crate::api::call(api.client.set_upload_limit(hash.clone(), &body))
                                    .await;
                            crate::app::Msg::Torrents(Msg::LimitSet {
                                hash,
                                value,
                                result,
                            })
                        })]
                    }
                },
                _ => {
                    limit.input.handle_event(&crossterm::event::Event::Key(key));
                    limit.error = None;
                    Vec::new()
                }
            }
        }
        Msg::LimitSet {
            hash,
            value,
            result,
        } => match result {
            Ok(()) => {
                let text = match value {
                    Some(n) => format!("{}: upload limit {}", fmt::short_hash(&hash), fmt::rate(n)),
                    None => format!(
                        "{}: own upload limit removed; the profile's and daemon's still apply",
                        fmt::short_hash(&hash)
                    ),
                };
                let mut effects = vec![Effect::toast(Toast::success(text))];
                effects.extend(refresh(state, ctx));
                effects
            }
            Err(failure) => vec![Effect::now(failed("setting the upload limit", failure))],
        },
        Msg::RunEntry => {
            let Some(detail) = state.detail.as_ref() else {
                return Vec::new();
            };
            match detail::ENTRIES.get(detail.action_selected).map(|e| e.0) {
                Some(detail::Entry::Act(action)) => act(state, action, ctx),
                Some(detail::Entry::UploadLimit) => update(state, Msg::OpenLimit, ctx),
                None => Vec::new(),
            }
        }
        Msg::AddKey(key) => {
            let active = active_profiles(state);
            let Some(dialog) = state.add.as_mut() else {
                return Vec::new();
            };
            match dialog.on_key(key, &active) {
                add::Outcome::Pending => Vec::new(),
                add::Outcome::Cancel => {
                    state.add = None;
                    Vec::new()
                }
                add::Outcome::Submit => match dialog.validate(&active) {
                    None => Vec::new(),
                    Some(request) => {
                        let id = ADD_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
                        dialog.submitting = Some(id);
                        let api = ctx.api.clone();
                        vec![Effect::new(async move {
                            crate::app::Msg::Torrents(Msg::Added {
                                request: id,
                                result: add::submit(api, request).await,
                            })
                        })]
                    }
                },
            }
        }
        Msg::Added { request, result } => {
            // Only the dialog that sent this request may be closed or shown
            // its failure; a cancelled or superseded add's answer leaves a
            // newer dialog alone.
            let current = state
                .add
                .as_ref()
                .is_some_and(|d| d.submitting == Some(request));
            added(state, current, result, ctx)
        }
    }
}

/// The answer to an add, `current` when the open dialog sent it.
fn added(
    state: &mut State,
    current: bool,
    result: Result<types::Torrent, add::AddFailure>,
    ctx: &Ctx<'_>,
) -> Vec<Effect> {
    match result {
        Ok(torrent) => {
            let name = torrent
                .session
                .as_ref()
                .and_then(|s| s.name.clone())
                .unwrap_or_else(|| "a magnet (name once metadata arrives)".to_owned());
            let text = format!(
                "added {name} · {} to {}",
                fmt::short_hash(&torrent.infohash),
                torrent.profile_id
            );
            // The torrent exists either way, so the list reloads; only the
            // add still on screen moves the view to it.
            if current {
                state.add = None;
                state.detail = None;
                state.restore = Some(torrent.infohash);
            }
            let mut effects = vec![Effect::toast(Toast::success(text))];
            effects.extend(load_list(state, ctx));
            effects
        }
        Err(failure) => {
            if let add::AddFailure::Api { failure, .. } = &failure {
                if failure.is_unauthenticated() {
                    if current {
                        state.add = None;
                    }
                    return vec![Effect::now(failed("adding a torrent", failure.clone()))];
                }
            }
            match state.add.as_mut() {
                Some(dialog) if current => dialog.show_failure(failure),
                // The dialog that sent it was closed while the request was
                // in flight, and perhaps another opened since.
                _ => {
                    if let add::AddFailure::Api { failure, .. } = failure {
                        return vec![Effect::now(failed("adding a torrent", failure))];
                    }
                }
            }
            Vec::new()
        }
    }
}

/// The ids of the profiles that can take a new torrent: on the network, so
/// neither fenced nor set offline, both of which the daemon refuses.
fn active_profiles(state: &State) -> Vec<String> {
    state
        .profiles
        .iter()
        .filter(|p| p.effective_state == types::ProfileState::Online)
        .map(|p| p.profile_id.clone())
        .collect()
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let now = state.now.unwrap_or_else(time::OffsetDateTime::now_utc);
    let mutations = ctx.pool_mutations_allowed();
    match &state.detail {
        Some(detail) => detail::view(detail, theme, ctx.tick, now, mutations, frame, area),
        None => list(state, ctx, frame, area),
    }
    if let Some(dialog) = &state.add {
        add::view(
            dialog,
            &active_profiles(state),
            state.profiles_loading,
            ctx.tick,
            frame,
            area,
            theme,
        );
    }
    if let Some((confirm, _)) = &state.confirm {
        confirm.view(frame, area, theme);
    }
}
