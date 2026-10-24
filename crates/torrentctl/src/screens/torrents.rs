//! Torrents: every torrent the daemon holds, page by page, filtered by
//! profile, phase and text; one torrent's overview, files and trackers; the
//! actions on one or all of them; and adding one.

mod add;
mod detail;

use std::cell::Cell;
use std::time::Duration;
use std::time::Instant;

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
use ratatui::Frame;
use tui_input::backend::crossterm::EventHandler as _;
use tui_input::Input;

use crate::api::types;
use crate::api::Api;
use crate::api::Failure;
use crate::app::failed;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Toast;
use crate::app::ToastKind;
use crate::fmt;
use crate::theme::Tone;
use crate::ui::widgets::caps;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Confirm;
use crate::ui::widgets::Confirmed;
use crate::ui::widgets::PageRequest;
use crate::ui::widgets::Paged;
use crate::ui::widgets::Received;

/// Rows `PgUp`/`PgDn` move.
const PAGE_STEP: usize = 10;

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

/// Something done to one torrent, or to all of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Pause,
    Resume,
    Recheck,
    Reannounce,
    Remove,
    /// Remove, and delete the payload.
    RemoveFiles,
    PauseAll,
    ResumeAll,
}

impl Action {
    fn doing(self) -> &'static str {
        match self {
            Action::Pause => "pausing",
            Action::Resume => "resuming",
            Action::Recheck => "rechecking",
            Action::Reannounce => "reannouncing",
            Action::Remove => "removing",
            Action::RemoveFiles => "removing with files",
            Action::PauseAll => "pausing every torrent",
            Action::ResumeAll => "resuming every torrent",
        }
    }
}

/// A cursor movement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    Up,
    Down,
    PageUp,
    PageDown,
    Top,
    Bottom,
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
    Move(Move),
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
    Added(Result<types::Torrent, add::AddFailure>),
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
    let movement = match key.code {
        KeyCode::Char('j') | KeyCode::Down => Some(Move::Down),
        KeyCode::Char('k') | KeyCode::Up => Some(Move::Up),
        KeyCode::Char('g') | KeyCode::Home => Some(Move::Top),
        KeyCode::Char('G') | KeyCode::End => Some(Move::Bottom),
        KeyCode::PageUp => Some(Move::PageUp),
        KeyCode::PageDown => Some(Move::PageDown),
        _ => None,
    };
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
                    unauthenticated("loading torrents", failure)
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
                    let effects = unauthenticated("loading profiles", failure.clone());
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
                state.selected = step(state.selected, len, movement);
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
                    unauthenticated("loading the torrent", failure)
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
                    unauthenticated("loading files", failure)
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
                    unauthenticated("loading trackers", failure)
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
                        dialog.submitting = true;
                        let api = ctx.api.clone();
                        vec![Effect::new(async move {
                            crate::app::Msg::Torrents(Msg::Added(add::submit(api, request).await))
                        })]
                    }
                },
            }
        }
        Msg::Added(Ok(torrent)) => {
            state.add = None;
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
            state.detail = None;
            state.restore = Some(torrent.infohash);
            let mut effects = vec![Effect::toast(Toast::success(text))];
            effects.extend(load_list(state, ctx));
            effects
        }
        Msg::Added(Err(failure)) => {
            if let add::AddFailure::Api { failure, .. } = &failure {
                if failure.is_unauthenticated() {
                    state.add = None;
                    return vec![Effect::now(failed("adding a torrent", failure.clone()))];
                }
            }
            match state.add.as_mut() {
                Some(dialog) => dialog.show_failure(failure),
                // The dialog was closed while the request was in flight.
                None => {
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

fn mutations_allowed(ctx: &Ctx<'_>) -> bool {
    ctx.server.is_some_and(|s| s.pool.allow_mutations)
}

/// A failure that only matters here when it signs the user out; the rest
/// are shown in the panel.
fn unauthenticated(attempt: &str, failure: Failure) -> Vec<Effect> {
    if failure.is_unauthenticated() {
        vec![Effect::now(failed(attempt, failure))]
    } else {
        Vec::new()
    }
}

/// Indices into the loaded list of the rows the `/` filter shows.
fn visible(state: &State) -> Vec<usize> {
    // The daemon emits infohashes lowercase, so a lowercased needle matches
    // them in any case it was typed; profile ids are lowercased to compare.
    let needle = state.filter.to_lowercase();
    state
        .list
        .items
        .iter()
        .enumerate()
        .filter(|(_, t)| {
            needle.is_empty()
                || t.infohash.starts_with(&needle)
                || t.profile_id.to_lowercase().contains(&needle)
        })
        .map(|(i, _)| i)
        .collect()
}

fn selected_summary(state: &State) -> Option<&types::TorrentSummary> {
    visible(state)
        .get(state.selected)
        .and_then(|i| state.list.items.get(*i))
}

/// Select `hash` among the visible rows when it is one, else keep the row
/// in range.
fn reselect(state: &mut State, hash: Option<String>) {
    let rows = visible(state);
    if let Some(at) =
        hash.and_then(|h| rows.iter().position(|i| state.list.items[*i].infohash == h))
    {
        state.selected = at;
    }
    state.selected = state.selected.min(rows.len().saturating_sub(1));
}

fn step(at: usize, len: usize, movement: Move) -> usize {
    let last = len.saturating_sub(1);
    match movement {
        Move::Up => at.saturating_sub(1),
        Move::Down => (at + 1).min(last),
        Move::PageUp => at.saturating_sub(PAGE_STEP),
        Move::PageDown => (at + PAGE_STEP).min(last),
        Move::Top => 0,
        Move::Bottom => last,
    }
}

/// Change the server-side filters and start over.
fn set_server_filter(
    state: &mut State,
    profile: Option<String>,
    phase: Option<types::Phase>,
    ctx: &Ctx<'_>,
) -> Vec<Effect> {
    state.profile = profile;
    state.phase = phase;
    // What was loaded belongs to another filter: drop it rather than show it
    // under this one.
    state.list.reset();
    state.selected = 0;
    state.list_offset.set(0);
    state.restore = None;
    let mut effects = load_list(state, ctx);
    effects.extend(load_profiles(state, ctx));
    effects
}

/// Reload the list from its first page, as many rows as are loaded (see
/// [`Paged`]), keeping the selection.
fn load_list(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.restore.is_none() {
        state.restore = selected_summary(state).map(|s| s.infohash.clone());
    }
    let request = state.list.reload();
    vec![fetch_page(
        ctx.api,
        state.profile.clone(),
        state.phase.clone(),
        request,
    )]
}

fn fetch_page(
    api: &Api,
    profile: Option<String>,
    phase: Option<types::Phase>,
    request: PageRequest,
) -> Effect {
    let api = api.clone();
    let PageRequest {
        cursor,
        limit,
        generation,
    } = request;
    Effect::new(async move {
        let first = cursor.is_none();
        let params = crate::api::generated::ListTorrentsParams {
            profile_id: profile,
            phase,
            cursor,
            limit: Some(limit as i64),
        };
        let result = crate::api::call(api.client.list_torrents(params)).await;
        crate::app::Msg::Torrents(Msg::Page {
            generation,
            first,
            result,
        })
    })
}

/// The next page, when the selection is near the end of what is loaded.
fn load_more(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    let rows = visible(state);
    let at = rows
        .get(state.selected)
        .copied()
        .unwrap_or(state.list.items.len());
    // With the `/` filter hiding rows, the selection's place among all that
    // is loaded is what says whether more are wanted; when it hides every
    // row, keep loading so a match can turn up.
    if !state.list.wants_more(at) {
        return Vec::new();
    }
    next_page(state, ctx)
}

fn next_page(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    match state.list.begin_more() {
        Some(request) => vec![fetch_page(
            ctx.api,
            state.profile.clone(),
            state.phase.clone(),
            request,
        )],
        None => Vec::new(),
    }
}

/// After a page: select the torrent being restored when it has arrived,
/// or page on towards it while it may still come (the list is ordered by
/// infohash); otherwise keep the selection in range.
fn settle(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if let Some(want) = state.restore.clone() {
        let rows = visible(state);
        if let Some(at) = rows
            .iter()
            .position(|i| state.list.items[*i].infohash == want)
        {
            state.selected = at;
            state.restore = None;
        } else if state.list.next_cursor.is_some()
            && state
                .list
                .items
                .last()
                .is_some_and(|last| last.infohash < want)
        {
            return next_page(state, ctx);
        } else {
            state.restore = None;
        }
    }
    state.selected = state.selected.min(visible(state).len().saturating_sub(1));
    load_more(state, ctx)
}

fn load_profiles(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    if state.profiles_loading {
        return Vec::new();
    }
    state.profiles_loading = true;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        let result = crate::api::call(api.client.list_profiles())
            .await
            .map(|p| p.items);
        crate::app::Msg::Torrents(Msg::Profiles(result))
    })]
}

/// The open torrent, when it is `hash`: an answer for another is stale.
fn open_detail<'a>(state: &'a mut State, hash: &str) -> Option<&'a mut detail::Detail> {
    state.detail.as_mut().filter(|d| d.hash == hash)
}

/// Reload the open torrent and its current tab.
fn load_detail(detail: &mut detail::Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    let mut effects = Vec::new();
    if !detail.loading {
        detail.loading = true;
        let api = ctx.api.clone();
        let hash = detail.hash.clone();
        effects.push(Effect::new(async move {
            let result = crate::api::call(api.client.get_torrent(hash.clone())).await;
            crate::app::Msg::Torrents(Msg::Torrent { hash, result })
        }));
    }
    if rereads_files(detail) && !detail.files.loading {
        effects.extend(load_files(detail, ctx));
    } else if rereads_trackers(detail) && !detail.trackers_loading {
        effects.extend(load_trackers(detail, ctx));
    }
    effects
}

/// Whether [`load_detail`] re-reads the open torrent's files: only on the
/// Files tab, and only a list that fits one request. A longer list would take
/// a request per thousand files on every change, and files do not change
/// while a torrent seeds (a priority edit updates its row in place). Such a
/// list is left as it is; reopening the torrent reloads it, in as many
/// requests as it needs.
fn rereads_files(detail: &detail::Detail) -> bool {
    detail.tab == detail::Tab::Files && detail.files.items.len() <= caps::PAGE_MAX
}

/// Whether [`load_detail`] re-reads the open torrent's trackers: only on the
/// Trackers tab.
fn rereads_trackers(detail: &detail::Detail) -> bool {
    detail.tab == detail::Tab::Trackers
}

fn load_files(detail: &mut detail::Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    let request = detail.files.reload();
    vec![fetch_files(ctx.api, detail.hash.clone(), request)]
}

fn more_files(detail: &mut detail::Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    if !detail.files.wants_more(detail.files_selected) {
        return Vec::new();
    }
    match detail.files.begin_more() {
        Some(request) => vec![fetch_files(ctx.api, detail.hash.clone(), request)],
        None => Vec::new(),
    }
}

fn fetch_files(api: &Api, hash: String, request: PageRequest) -> Effect {
    let api = api.clone();
    let PageRequest {
        cursor,
        limit,
        generation,
    } = request;
    Effect::new(async move {
        let first = cursor.is_none();
        let params = crate::api::generated::ListTorrentFilesParams {
            cursor,
            limit: Some(limit as i64),
        };
        let result = crate::api::call(api.client.list_torrent_files(hash.clone(), params)).await;
        crate::app::Msg::Torrents(Msg::FilesPage {
            hash,
            generation,
            first,
            result,
        })
    })
}

fn load_trackers(detail: &mut detail::Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    detail.trackers_loading = true;
    detail.trackers_asked = Some(Instant::now());
    let api = ctx.api.clone();
    let hash = detail.hash.clone();
    vec![Effect::new(async move {
        let result = crate::api::call(api.client.list_torrent_trackers(hash.clone())).await;
        crate::app::Msg::Torrents(Msg::Trackers { hash, result })
    })]
}

fn move_in_detail(detail: &mut detail::Detail, movement: Move, ctx: &Ctx<'_>) -> Vec<Effect> {
    match detail.tab {
        detail::Tab::Overview => Vec::new(),
        detail::Tab::Files => {
            detail.files_selected = step(detail.files_selected, detail.files.items.len(), movement);
            more_files(detail, ctx)
        }
        detail::Tab::Trackers => {
            let len = detail.trackers.as_ref().map_or(0, Vec::len);
            detail.trackers_selected = step(detail.trackers_selected, len, movement);
            Vec::new()
        }
        detail::Tab::Actions => {
            detail.action_selected = step(detail.action_selected, detail::ENTRIES.len(), movement);
            Vec::new()
        }
    }
}

/// Start `action`: at once for what is harmless and undoable, behind a
/// confirmation for what removes anything or touches every torrent.
fn act(state: &mut State, action: Action, ctx: &Ctx<'_>) -> Vec<Effect> {
    match action {
        Action::PauseAll => {
            state.confirm = Some((
                Confirm::new(
                    "Pause every torrent",
                    "Pause every torrent of every live profile? They stop announcing and serving \
                     peers until resumed.",
                ),
                Pending::PauseAll,
            ));
            return Vec::new();
        }
        Action::ResumeAll => {
            state.confirm = Some((
                Confirm::new(
                    "Resume every torrent",
                    "Resume every torrent? Fenced (vpn_down) and failed profiles are skipped.",
                ),
                Pending::ResumeAll,
            ));
            return Vec::new();
        }
        _ => {}
    }
    let target = match &state.detail {
        Some(detail) => Some((detail.hash.clone(), detail.name().map(str::to_owned))),
        None => selected_summary(state).map(|s| (s.infohash.clone(), None)),
    };
    let Some((hash, name)) = target else {
        return Vec::new();
    };
    let what = match name {
        Some(name) => format!("{name} ({})", fmt::short_hash(&hash)),
        None => fmt::short_hash(&hash).to_owned(),
    };
    match action {
        Action::Remove => {
            state.confirm = Some((
                Confirm::new(
                    "Remove torrent",
                    format!("Remove {what}? The daemon forgets it; its payload stays on disk."),
                ),
                Pending::Act(action, hash),
            ));
            Vec::new()
        }
        Action::RemoveFiles if !mutations_allowed(ctx) => vec![Effect::toast(Toast::info(
            "deleting files needs [pool] allow_mutations in the daemon's config; `d` removes and \
             keeps them",
        ))],
        Action::RemoveFiles => {
            state.confirm = Some((
                Confirm::new(
                    "Remove torrent and delete files",
                    format!(
                        "Remove {what} and move its payload to the pool's trash? The daemon \
                         forgets it; the files can be restored from .torrentd-trash."
                    ),
                )
                .typed("delete"),
                Pending::Act(action, hash),
            ));
            Vec::new()
        }
        _ => vec![perform(ctx.api, action, hash)],
    }
}

fn perform(api: &Api, action: Action, hash: String) -> Effect {
    let api = api.clone();
    Effect::new(async move {
        let client = &api.client;
        let h = hash.clone();
        let result = match action {
            Action::Pause => crate::api::call(client.pause_torrent(h)).await,
            Action::Resume => crate::api::call(client.resume_torrent(h)).await,
            Action::Recheck => crate::api::call(client.recheck_torrent(h)).await,
            Action::Reannounce => crate::api::call(client.reannounce_torrent(h)).await,
            Action::Remove => crate::api::call(client.delete_torrent(h, None)).await,
            Action::RemoveFiles => {
                // The typed confirmation the operator gave is what the
                // daemon's `confirm` stands for: name the torrent again.
                let params = crate::api::generated::DeleteTorrentParams {
                    delete_files: Some(true),
                    confirm: Some(h.clone()),
                };
                crate::api::call(client.delete_torrent(h, params)).await
            }
            // Never reach here: every torrent goes through `bulk`.
            Action::PauseAll | Action::ResumeAll => Ok(()),
        };
        crate::app::Msg::Torrents(Msg::Acted {
            action,
            hash,
            result,
        })
    })
}

fn bulk(api: &Api, pause: bool) -> Effect {
    let api = api.clone();
    Effect::new(async move {
        let result = if pause {
            crate::api::call(api.client.pause_all_torrents()).await
        } else {
            // Unbounded: the daemon resumes 100 torrents a second, and
            // answers once the last is.
            crate::api::call_unbounded(api.client.resume_all_torrents()).await
        };
        crate::app::Msg::Torrents(Msg::Bulk { pause, result })
    })
}

/// What a pause-all or resume-all did, with what it did not reach.
fn bulk_toast(pause: bool, outcome: &types::BulkOutcome) -> Toast {
    let verb = if pause { "paused" } else { "resumed" };
    let mut text = format!("{verb} {} torrents", fmt::count(outcome.torrent_count));
    if outcome.failed_count > 0 {
        text.push_str(&format!(
            "; {} failed and are still {}",
            fmt::count(outcome.failed_count),
            if pause { "running" } else { "paused" }
        ));
    }
    for skipped in &outcome.skipped_profiles {
        text.push_str(&format!(
            "; skipped {} ({}: {})",
            skipped.profile_id, skipped.reason, skipped.detail
        ));
    }
    let kind = if outcome.failed_count > 0 {
        ToastKind::Error
    } else if outcome.skipped_profiles.is_empty() {
        ToastKind::Success
    } else {
        ToastKind::Info
    };
    Toast {
        kind,
        text,
        request_id: None,
    }
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let now = state.now.unwrap_or_else(time::OffsetDateTime::now_utc);
    let mutations = mutations_allowed(ctx);
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

fn list(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let mut title = vec![Span::raw(" torrents ")];
    if state.list.loading {
        title.push(Span::styled(
            format!("{} ", spinner(ctx.tick)),
            theme.fg(Tone::Muted),
        ));
    }
    let block = panel(theme, Line::from(title), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let editing = state.filter_input.is_some();
    let [header, status, table_area, filter_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(u16::from(state.list.error.is_some())),
        Constraint::Fill(1),
        Constraint::Length(u16::from(editing)),
    ])
    .areas(inner);

    let rows = visible(state);
    let muted = theme.fg(Tone::Muted);
    let mut spans = vec![
        Span::styled(fmt::count(rows.len() as i64), theme.fg(Tone::Plain).bold()),
        Span::styled(" shown · ", muted),
        Span::styled(
            fmt::count(state.list.items.len() as i64),
            theme.fg(Tone::Plain),
        ),
        Span::styled(" loaded · ", muted),
        if state.list.next_cursor.is_some() {
            Span::styled("more pages", theme.fg(Tone::Warn))
        } else if state.list.complete {
            Span::styled("all loaded", muted)
        } else {
            Span::styled("loading", muted)
        },
        Span::styled("   profile ", muted),
        Span::styled(
            state.profile.clone().unwrap_or_else(|| "all".to_owned()),
            theme.fg(Tone::Accent),
        ),
        Span::styled("  phase ", muted),
        Span::styled(
            state
                .phase
                .as_ref()
                .map_or_else(|| "all".to_owned(), ToString::to_string),
            theme.fg(Tone::Accent),
        ),
    ];
    if !state.filter.is_empty() && !editing {
        spans.push(Span::styled("  /", muted));
        spans.push(Span::styled(state.filter.clone(), theme.fg(Tone::Accent)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), header);
    if let Some(error) = &state.list.error {
        frame.render_widget(
            Paragraph::new(Span::styled(format!("✖ {error}"), theme.fg(Tone::Bad))),
            status,
        );
    }
    if let Some(input) = &state.filter_input {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("/", theme.key()),
                Span::raw(input.value().to_owned()),
                Span::styled(
                    "   infohash prefix or profile · Enter keep · Esc clear",
                    muted,
                ),
            ])),
            filter_area,
        );
        frame.set_cursor_position((
            filter_area.x + 1 + input.visual_cursor() as u16,
            filter_area.y,
        ));
    }

    if rows.is_empty() {
        let text = if state.list.loading || (!state.list.complete && state.list.error.is_none()) {
            "loading…"
        } else if state.list.error.is_some() {
            ""
        } else if state.list.items.is_empty() {
            "no torrents here — n adds one"
        } else {
            "nothing loaded matches the filter"
        };
        placeholder(frame, table_area, theme, text, Tone::Muted);
        return;
    }

    // Columns, dropped from the right as the terminal narrows.
    let width = table_area.width;
    let wide = width >= 150;
    let show_profile = width >= 60;
    let show_peers = width >= 70;
    let show_uploaded = width >= 76;
    let show_down = width >= 110;

    let mut widths = vec![
        Constraint::Length(12),
        Constraint::Length(if wide { 40 } else { 12 }),
    ];
    let mut head = vec![Line::from("state"), Line::from("infohash")];
    if show_profile {
        widths.push(Constraint::Fill(1));
        head.push(Line::from("profile"));
    }
    // Wide enough, progress is a bar as well as a number.
    widths.push(Constraint::Length(if show_down { 17 } else { 6 }));
    head.push(Line::from("done").right_aligned());
    widths.push(Constraint::Length(12));
    head.push(Line::from("↑ rate").right_aligned());
    if show_down {
        widths.push(Constraint::Length(12));
        head.push(Line::from("↓ rate").right_aligned());
    }
    if show_peers {
        widths.push(Constraint::Length(5));
        head.push(Line::from("peers").right_aligned());
    }
    if show_uploaded {
        widths.push(Constraint::Length(10));
        head.push(Line::from("uploaded").right_aligned());
    }
    if wide {
        widths.push(Constraint::Length(10));
        head.push(Line::from("payload").right_aligned());
    }

    let table_rows = rows.iter().map(|i| {
        let t = &state.list.items[*i];
        let hash = if wide {
            t.infohash.as_str()
        } else {
            fmt::short_hash(&t.infohash)
        };
        let mut cells = vec![
            Line::from(state_span(theme, &t.phase.to_string())),
            Line::from(Span::styled(hash.to_owned(), theme.fg(Tone::Accent))),
        ];
        if show_profile {
            cells.push(Line::from(t.profile_id.clone()));
        }
        let percent = fmt::percent(t.progress).replace(".0%", "%");
        cells.push(if show_down {
            let filled = (t.progress.clamp(0.0, 1.0) * 10.0).round() as usize;
            let tone = if t.progress >= 1.0 {
                Tone::Good
            } else {
                Tone::Warn
            };
            Line::from(vec![
                Span::styled("█".repeat(filled), theme.fg(tone)),
                Span::styled("░".repeat(10 - filled), muted),
                Span::raw(format!("{percent:>7}")),
            ])
        } else {
            Line::from(percent).right_aligned()
        });
        let up_tone = if t.upload_rate > 0 {
            Tone::Good
        } else {
            Tone::Muted
        };
        cells.push(
            Line::from(Span::styled(fmt::rate(t.upload_rate), theme.fg(up_tone))).right_aligned(),
        );
        if show_down {
            cells.push(Line::from(Span::styled(fmt::rate(t.download_rate), muted)).right_aligned());
        }
        if show_peers {
            cells.push(Line::from(fmt::count(t.num_peers)).right_aligned());
        }
        if show_uploaded {
            cells.push(Line::from(fmt::bytes(t.total_uploaded)).right_aligned());
        }
        if wide {
            cells.push(
                Line::from(Span::styled(fmt::bytes(t.total_payload_uploaded), muted))
                    .right_aligned(),
            );
        }
        Row::new(cells)
    });
    let table = Table::new(table_rows, widths)
        .header(Row::new(head).style(muted))
        .row_highlight_style(theme.selected())
        .highlight_symbol("› ");
    let mut table_state = TableState::default()
        .with_offset(state.list_offset.get())
        .with_selected(Some(state.selected));
    frame.render_stateful_widget(table, table_area, &mut table_state);
    state.list_offset.set(table_state.offset());
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing;

    const NOW: i64 = 1_790_000_000;

    /// What reloading the unfiltered list sends: the profiles, then the
    /// first page.
    const RELOAD: [&str; 2] = ["GET /v1/profiles", "GET /v1/torrents?limit=100"];

    fn hash(n: u8) -> String {
        format!("{n:02x}{}", "a1b2c3d4e5".repeat(4))[..40].to_owned()
    }

    fn summary(n: u8, profile: &str, phase: &str) -> serde_json::Value {
        json!({
            "infohash": hash(n), "profile_id": profile, "phase": phase,
            "progress": if phase == "checking" { 0.42 } else { 1.0 },
            "upload_rate": if phase == "seeding" { 1_572_864 * i64::from(n) } else { 0 },
            "download_rate": 0,
            "total_uploaded": 5_368_709_120_i64 * i64::from(n),
            "total_payload_uploaded": 5_000_000_000_i64 * i64::from(n),
            "num_peers": i64::from(n) * 3,
            "is_finished": phase != "checking", "is_seeding": phase == "seeding",
        })
    }

    fn page(range: std::ops::Range<u8>, next: Option<&str>) -> types::TorrentPage {
        let phases = [
            "seeding",
            "seeding",
            "paused",
            "checking",
            "errored",
            "disk_error",
            "idle",
        ];
        let items: Vec<_> = range
            .map(|n| {
                let profile = if n % 3 == 0 { "acct_b" } else { "acct_a" };
                summary(n, profile, phases[n as usize % phases.len()])
            })
            .collect();
        testing::from_json(json!({"items": items, "next_cursor": next}))
    }

    fn profiles() -> Vec<types::Profile> {
        testing::from_json(json!([
            {"profile_id": "acct_a", "status": "active", "tunnel_ip": "10.2.0.2",
             "desired_state": "online", "effective_state": "online",
             "torrent_count": 900, "listen_port": 51413, "port_forward": "natpmp",
             "forwarded_port": 51413, "user_agent": null, "failure_reason": null},
            {"profile_id": "acct_b", "status": "vpn_down", "tunnel_ip": "10.3.0.2",
             "desired_state": "online", "effective_state": "offline",
             "torrent_count": 334, "listen_port": 51414, "port_forward": "static",
             "forwarded_port": null, "user_agent": null, "failure_reason": null},
            {"profile_id": "acct_c", "status": "active", "tunnel_ip": null,
             "desired_state": "online", "effective_state": "online",
             "torrent_count": 0, "listen_port": 51415, "port_forward": "static",
             "forwarded_port": null, "user_agent": null, "failure_reason": null},
        ]))
    }

    fn failure(status: u16, slug: &str, detail: &str) -> Failure {
        Failure {
            status: Some(status),
            slug: Some(slug.to_owned()),
            title: "Refused".to_owned(),
            detail: Some(detail.to_owned()),
            request_id: None,
            ..Default::default()
        }
    }

    /// A list with `range` loaded as its first page.
    fn loaded(range: std::ops::Range<u8>, next: Option<&str>) -> State {
        let mut state = State {
            now: Some(time::OffsetDateTime::from_unix_timestamp(NOW).unwrap()),
            ..State::default()
        };
        testing::with_ctx(None, |ctx| {
            refresh(&mut state, ctx);
            update(&mut state, Msg::Profiles(Ok(profiles())), ctx);
            let generation = state.list.generation;
            update(
                &mut state,
                Msg::Page {
                    generation,
                    first: true,
                    result: Ok(page(range, next)),
                },
                ctx,
            );
        });
        state
    }

    fn torrent(n: u8, session: bool) -> types::Torrent {
        let mut value = summary(n, "acct_a", "seeding");
        value["session"] = if session {
            json!({
                "name": "debian-13.1.0-amd64-netinst.iso", "total_size": 792_723_456,
                "save_path": "/srv/seed/acct_a", "upload_limit_bytes_per_sec": 2_097_152,
                "added_at": "2026-09-01T08:30:00Z",
            })
        } else {
            serde_json::Value::Null
        };
        testing::from_json(value)
    }

    fn opened(session: bool) -> State {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Open, ctx);
            let hash = state.detail.as_ref().unwrap().hash.clone();
            update(
                &mut state,
                Msg::Torrent {
                    hash,
                    result: Ok(torrent(1, session)),
                },
                ctx,
            );
        });
        state
    }

    fn with_files(state: &mut State) {
        let files: types::TorrentFilePage = testing::from_json(json!({"items": [
            {"index": 0, "path": "debian/debian-13.1.0-amd64-netinst.iso", "size": 792_723_456,
             "downloaded": 792_723_456, "priority": 4},
            {"index": 1, "path": "debian/SHA256SUMS", "size": 1_024, "downloaded": 512, "priority": 7},
            {"index": 2, "path": "debian/README.txt", "size": 0, "downloaded": 0, "priority": 0},
        ], "next_cursor": null}));
        testing::with_ctx(None, |ctx| {
            update(state, Msg::Tab(true), ctx);
            let detail = state.detail.as_ref().unwrap();
            let (hash, generation) = (detail.hash.clone(), detail.files.generation);
            update(
                state,
                Msg::FilesPage {
                    hash,
                    generation,
                    first: true,
                    result: Ok(files),
                },
                ctx,
            );
        });
    }

    fn with_trackers(state: &mut State) {
        let trackers: types::TrackerList = testing::from_json(json!({"items": [
            {"tier": 0, "host": "tracker.example.org:443", "url": "https://tracker.example.org/announce",
             "status": "working", "message": null, "next_announce_at": "2026-09-21T14:40:00Z",
             "seeds": 1240, "peers": 18},
            {"tier": 1, "host": "backup.example.net", "url": "https://backup.example.net/[redacted:9f2c]",
             "status": "error", "message": "unregistered torrent",
             "next_announce_at": "2026-09-21T14:30:00Z", "seeds": null, "peers": null},
            {"tier": 2, "host": "udp.example.com:6969", "url": "udp://udp.example.com:6969/announce",
             "status": "not_contacted", "message": null, "next_announce_at": null,
             "seeds": null, "peers": null},
        ]}));
        testing::with_ctx(None, |ctx| {
            state.detail.as_mut().unwrap().tab = detail::Tab::Files;
            assert_eq!(
                update(state, Msg::Tab(true), ctx).len(),
                1,
                "the trackers load"
            );
            let hash = state.detail.as_ref().unwrap().hash.clone();
            update(
                state,
                Msg::Trackers {
                    hash,
                    result: Ok(trackers),
                },
                ctx,
            );
        });
    }

    fn keys(state: &mut State, ctx: &Ctx<'_>, text: &str) {
        for c in text.chars() {
            let msg = on_key(state, testing::key(KeyCode::Char(c))).unwrap();
            update(state, msg, ctx);
        }
    }

    fn page_msg(state: &State, first: bool, result: Result<types::TorrentPage, Failure>) -> Msg {
        Msg::Page {
            generation: state.list.generation,
            first,
            result,
        }
    }

    // Paging.

    #[test]
    fn the_first_page_is_shown_and_the_next_is_fetched_near_the_end() {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            let effects = refresh(&mut state, ctx);
            assert_eq!(effects.len(), 2, "profiles and the first page");
            assert!(state.list.loading);
            let msg = page_msg(&state, true, Ok(page(1..11, Some("c1"))));
            let effects = update(&mut state, msg, ctx);
            assert_eq!(state.list.items.len(), 10);
            assert_eq!(
                effects.len(),
                1,
                "ten rows is near the end: the next page is asked for"
            );
            assert!(state.list.loading);
            let msg = page_msg(&state, false, Ok(page(11..21, None)));
            let effects = update(&mut state, msg, ctx);
            assert!(effects.is_empty(), "no more pages");
            assert_eq!(state.list.items.len(), 20);
            assert!(state.list.complete && !state.list.loading);
        });
    }

    /// `n` torrents from the `from`th, in infohash order, continuing at
    /// `next`: lists longer than `page`'s `u8` range reaches.
    fn wide_page(from: usize, n: usize, next: Option<&str>) -> types::TorrentPage {
        let items: Vec<_> = (from..from + n)
            .map(|i| {
                let mut row = summary(1, "acct_a", "seeding");
                row["infohash"] = json!(format!("{i:040x}"));
                row
            })
            .collect();
        testing::from_json(json!({"items": items, "next_cursor": next}))
    }

    #[test]
    fn a_refresh_past_1000_rows_keeps_them_and_the_selection_while_it_re_pages() {
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut state = State::default();
        testing::with_api(&daemon.api(), None, |ctx| {
            state.profiles_loading = true;
            let _ = refresh(&mut state, ctx);
            let msg = page_msg(&state, true, Ok(wide_page(0, 1000, Some("k1000"))));
            update(&mut state, msg, ctx);
            let msg = page_msg(&state, false, Ok(wide_page(1000, 500, Some("k1500"))));
            update(&mut state, msg, ctx);
            assert_eq!(state.list.items.len(), 1500);
            update(&mut state, Msg::Move(Move::Top), ctx);
            for _ in 0..140 {
                update(&mut state, Msg::Move(Move::PageDown), ctx);
            }
            assert_eq!(state.selected, 1400);
            let chosen = format!("{:040x}", 1400);

            let effects = refresh(&mut state, ctx);
            testing::run(effects);
            assert_eq!(
                daemon.lines(),
                ["GET /v1/torrents?limit=1000"],
                "one request's reach"
            );
            let msg = page_msg(&state, true, Ok(wide_page(0, 1000, Some("k1000"))));
            let effects = update(&mut state, msg, ctx);
            assert_eq!(state.list.items.len(), 1500, "not cut to the first page");
            assert_eq!(state.selected, 1400, "nor the selection to row 999");
            testing::run(effects);
            assert_eq!(
                daemon.lines()[1],
                "GET /v1/torrents?cursor=k1000&limit=500",
                "pages on towards the 1500 loaded"
            );

            // A key while it re-pages moves among the rows still shown.
            update(&mut state, Msg::Move(Move::Down), ctx);
            assert_eq!(state.selected, 1401);
            let chosen_now = format!("{:040x}", 1401);
            assert_ne!(chosen, chosen_now);

            let msg = page_msg(&state, false, Ok(wide_page(1000, 500, Some("k1500"))));
            update(&mut state, msg, ctx);
            assert!(!state.list.loading);
            assert_eq!(state.list.items.len(), 1500);
            assert_eq!(
                selected_summary(&state).unwrap().infohash,
                chosen_now,
                "the torrent the operator moved to, after the reload"
            );
        });
    }

    #[test]
    fn a_page_answering_an_older_reload_is_dropped() {
        let mut state = loaded(1..4, None);
        testing::with_ctx(None, |ctx| {
            let old = state.list.generation;
            refresh(&mut state, ctx);
            let effects = update(
                &mut state,
                Msg::Page {
                    generation: old,
                    first: true,
                    result: Ok(page(50..52, None)),
                },
                ctx,
            );
            assert!(effects.is_empty());
            assert_eq!(state.list.items.len(), 3, "the old data is still shown");
            assert!(state.list.loading, "still waiting for the current reload");
            let stale_error = Msg::Page {
                generation: old,
                first: true,
                result: Err(failure(500, "internal", "boom")),
            };
            update(&mut state, stale_error, ctx);
            assert!(state.list.error.is_none());
        });
    }

    #[test]
    fn a_failed_load_keeps_the_last_good_rows() {
        let mut state = loaded(1..4, None);
        testing::with_ctx(None, |ctx| {
            refresh(&mut state, ctx);
            let msg = page_msg(&state, true, Err(failure(500, "internal", "engine gone")));
            assert!(
                update(&mut state, msg, ctx).is_empty(),
                "shown in the panel, not a toast"
            );
            assert_eq!(state.list.items.len(), 3);
            assert_eq!(state.list.error.as_deref(), Some("Refused: engine gone"));
            let msg = page_msg(&state, true, Err(failure(401, "about:blank", "")));
            state.list.loading = true;
            assert_eq!(update(&mut state, msg, ctx).len(), 1, "a 401 signs out");
        });
    }

    #[test]
    fn a_failed_refresh_does_not_snap_a_later_load_back() {
        let mut state = loaded(1..31, Some("c31"));
        testing::with_ctx(None, |ctx| {
            state.profiles_loading = true;
            state.selected = 2;
            refresh(&mut state, ctx);
            assert_eq!(state.restore.as_deref(), Some(hash(3).as_str()));
            let msg = page_msg(&state, true, Err(failure(500, "internal", "engine gone")));
            update(&mut state, msg, ctx);
            assert!(!state.list.loading);
            assert!(
                state.restore.is_none(),
                "the failed refresh will not settle"
            );

            // The operator scrolls on, to the end: the next page is fetched
            // and settles without jumping back.
            update(&mut state, Msg::Move(Move::Bottom), ctx);
            assert!(state.list.loading, "near the end: the next page");
            let msg = page_msg(&state, false, Ok(page(31..41, None)));
            update(&mut state, msg, ctx);
            assert_eq!(state.list.items.len(), 40);
            assert_eq!(
                selected_summary(&state).unwrap().infohash,
                hash(30),
                "not snapped back to the torrent selected when the refresh failed"
            );
        });
    }

    #[test]
    fn a_refresh_after_a_failed_one_keeps_the_torrent_selected_now() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            state.profiles_loading = true;
            update(&mut state, Msg::Move(Move::Down), ctx);
            refresh(&mut state, ctx);
            assert_eq!(state.restore.as_deref(), Some(hash(2).as_str()));
            let msg = page_msg(&state, true, Err(failure(500, "internal", "engine gone")));
            update(&mut state, msg, ctx);
            assert!(
                state.restore.is_none(),
                "the failed refresh will not settle"
            );

            update(&mut state, Msg::Move(Move::Bottom), ctx);
            refresh(&mut state, ctx);
            assert_eq!(state.restore.as_deref(), Some(hash(7).as_str()));
            let msg = page_msg(&state, true, Ok(page(1..8, None)));
            update(&mut state, msg, ctx);
            assert_eq!(
                selected_summary(&state).unwrap().infohash,
                hash(7),
                "the torrent selected when this refresh began, not the failed one's"
            );
        });
    }

    #[test]
    fn one_reload_at_a_time() {
        let mut state = loaded(1..4, None);
        testing::with_ctx(None, |ctx| {
            state.profiles_loading = true;
            assert_eq!(refresh(&mut state, ctx).len(), 1);
            assert!(refresh(&mut state, ctx).is_empty());
        });
    }

    // Selection.

    #[test]
    fn the_selection_follows_its_torrent_across_a_refresh() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Move(Move::Down), ctx);
            update(&mut state, Msg::Move(Move::Down), ctx);
            assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));
            refresh(&mut state, ctx);
            // Two torrents ahead of it went away and one arrived.
            let mut fresh = page(3..8, None);
            fresh.items.insert(0, page(0..1, None).items.remove(0));
            let msg = page_msg(&state, true, Ok(fresh));
            update(&mut state, msg, ctx);
            assert_eq!(state.selected, 1);
            assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));
            assert!(state.restore.is_none());
        });
    }

    #[test]
    fn a_torrent_being_selected_is_paged_towards() {
        let mut state = loaded(1..4, Some("c1"));
        testing::with_ctx(None, |ctx| {
            state.list.loading = false;
            state.restore = Some(hash(9));
            assert_eq!(
                settle(&mut state, ctx).len(),
                1,
                "it sorts after what is loaded"
            );
            let msg = page_msg(&state, false, Ok(page(8..11, None)));
            update(&mut state, msg, ctx);
            assert_eq!(selected_summary(&state).unwrap().infohash, hash(9));
        });
    }

    #[test]
    fn a_vanished_torrent_leaves_the_selection_in_range() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Move(Move::Bottom), ctx);
            assert_eq!(state.selected, 6);
            refresh(&mut state, ctx);
            let msg = page_msg(&state, true, Ok(page(1..4, None)));
            update(&mut state, msg, ctx);
            assert_eq!(state.selected, 2);
            assert!(state.restore.is_none());
        });
    }

    #[test]
    fn moving_is_bounded() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Move(Move::Up), ctx);
            assert_eq!(state.selected, 0);
            update(&mut state, Msg::Move(Move::PageDown), ctx);
            assert_eq!(state.selected, 6);
            update(&mut state, Msg::Move(Move::Top), ctx);
            assert_eq!(state.selected, 0);
        });
    }

    // Filters.

    #[test]
    fn f_cycles_profiles_and_back_to_all() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            let effects = update(&mut state, Msg::CycleProfile, ctx);
            assert_eq!(state.profile.as_deref(), Some("acct_a"));
            assert!(
                state.list.items.is_empty(),
                "another filter's rows are not shown under this one"
            );
            assert!(!effects.is_empty() && state.list.loading);
            update(&mut state, Msg::CycleProfile, ctx);
            update(&mut state, Msg::CycleProfile, ctx);
            assert_eq!(state.profile.as_deref(), Some("acct_c"));
            update(&mut state, Msg::CycleProfile, ctx);
            assert_eq!(state.profile, None);
        });
    }

    #[test]
    fn capital_f_cycles_every_phase_then_all() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::CyclePhase, ctx);
            assert_eq!(state.phase, Some(types::Phase::Checking));
            for _ in 1..PHASES.len() {
                update(&mut state, Msg::CyclePhase, ctx);
            }
            assert_eq!(state.phase, Some(types::Phase::Unknown));
            update(&mut state, Msg::CyclePhase, ctx);
            assert_eq!(state.phase, None);
        });
    }

    #[test]
    fn filter_profile_from_elsewhere_leaves_the_detail_view() {
        let mut state = opened(true);
        testing::with_ctx(None, |ctx| {
            let effects = update(&mut state, Msg::FilterProfile(Some("acct_b".into())), ctx);
            assert!(!effects.is_empty());
            assert!(state.detail.is_none());
            assert_eq!(state.profile.as_deref(), Some("acct_b"));
        });
    }

    #[test]
    fn the_slash_filter_narrows_what_is_loaded_and_keeps_the_selection() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Move(Move::Down), ctx);
            update(&mut state, Msg::Move(Move::Down), ctx);
            let msg = on_key(&state, testing::key(KeyCode::Char('/'))).unwrap();
            update(&mut state, msg, ctx);
            assert!(capturing(&state), "q and digits are typed into the field");
            keys(&mut state, ctx, "ACCT_B");
            assert_eq!(state.filter, "ACCT_B", "as typed");
            assert_eq!(visible(&state).len(), 2, "3 and 6, matched in any case");
            assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));
            let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
            update(&mut state, msg, ctx);
            assert!(!capturing(&state));
            assert_eq!(state.filter, "ACCT_B", "Enter keeps the filter");
            update(&mut state, Msg::StartFilter, ctx);
            assert_eq!(
                state.filter_input.as_ref().unwrap().value(),
                "ACCT_B",
                "reopening the field shows what was typed, not a lowercased copy"
            );
            update(
                &mut state,
                Msg::FilterKey(testing::key(KeyCode::Enter)),
                ctx,
            );

            update(&mut state, Msg::StartFilter, ctx);
            update(&mut state, Msg::FilterKey(testing::key(KeyCode::Esc)), ctx);
            assert_eq!(visible(&state).len(), 7, "Esc in the field clears it");
            assert_eq!(selected_summary(&state).unwrap().infohash, hash(3));

            update(&mut state, Msg::StartFilter, ctx);
            keys(&mut state, ctx, "05");
            assert_eq!(visible(&state).len(), 1, "an infohash prefix");
            update(
                &mut state,
                Msg::FilterKey(testing::key(KeyCode::Enter)),
                ctx,
            );
            let msg = on_key(&state, testing::key(KeyCode::Esc)).unwrap();
            update(&mut state, msg, ctx);
            assert!(state.filter.is_empty(), "Esc on the list clears it too");
        });
    }

    // Actions and confirmations.

    #[test]
    fn single_torrent_actions_go_at_once() {
        let daemon = testing::Recorder::start("204 No Content", "");
        let mut state = loaded(1..8, None);
        let h = selected_summary(&state).unwrap().infohash.clone();
        let effects = testing::with_api(&daemon.api(), None, |ctx| {
            let mut effects = Vec::new();
            for c in ['p', 'r', 'c', 'a'] {
                let msg = on_key(&state, testing::key(KeyCode::Char(c))).unwrap();
                effects.extend(update(&mut state, msg, ctx));
                assert!(state.confirm.is_none(), "{c}");
            }
            effects
        });
        testing::run(effects);
        assert_eq!(
            daemon.lines(),
            ["pause", "resume", "recheck", "reannounce"]
                .map(|a| format!("POST /v1/torrents/{h}/{a}"))
        );
    }

    #[test]
    fn remove_asks_yes_or_no() {
        let daemon = testing::Recorder::start("204 No Content", "");
        let mut state = loaded(1..8, None);
        let h = selected_summary(&state).unwrap().infohash.clone();
        let effects = testing::with_api(&daemon.api(), None, |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('d'))).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty());
            assert!(matches!(
                state.confirm,
                Some((_, Pending::Act(Action::Remove, _)))
            ));
            assert!(capturing(&state));
            let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
            let effects = update(&mut state, msg, ctx);
            assert!(state.confirm.is_none());
            effects
        });
        testing::run(effects);
        assert_eq!(
            daemon.lines(),
            [format!("DELETE /v1/torrents/{h}")],
            "one DELETE, keeping the files"
        );
    }

    #[test]
    fn deleting_files_is_refused_locally_without_pool_mutations() {
        let mut state = loaded(1..8, None);
        let server = testing::server(true, false);
        testing::with_ctx(Some(&server), |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('D'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1, "a toast saying why");
            assert!(state.confirm.is_none());
        });
    }

    #[test]
    fn deleting_files_needs_the_word_typed() {
        let mut state = loaded(1..8, None);
        let server = testing::server(true, true);
        testing::with_ctx(Some(&server), |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('D'))).unwrap();
            update(&mut state, msg, ctx);
            let Some((confirm, Pending::Act(Action::RemoveFiles, target))) = &state.confirm else {
                panic!("a typed confirmation");
            };
            assert_eq!(confirm.typed.as_deref(), Some("delete"));
            assert_eq!(*target, hash(1));
            keys(&mut state, ctx, "y");
            assert!(state.confirm.is_some(), "y is typed, not a yes");
            let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty(), "the word is wrong");
            update(
                &mut state,
                Msg::ConfirmKey(testing::key(KeyCode::Backspace)),
                ctx,
            );
            keys(&mut state, ctx, "delete");
            let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
            assert_eq!(
                update(&mut state, msg, ctx).len(),
                1,
                "one DELETE ?delete_files=true"
            );
            assert!(state.confirm.is_none());
        });
    }

    #[tokio::test]
    async fn deleting_files_sends_the_infohash_as_confirm() {
        let (url, server) = crate::testing::serve_once("204 No Content", String::new()).await;
        let api = Api::new(&url, Some("tdp_wire")).unwrap();
        let msg = perform(&api, Action::RemoveFiles, hash(1)).0.await;
        assert!(
            matches!(
                msg,
                crate::app::Msg::Torrents(Msg::Acted {
                    action: Action::RemoveFiles,
                    result: Ok(()),
                    ..
                })
            ),
            "{msg:?}"
        );
        let request = server.await.unwrap();
        let line = request.lines().next().unwrap();
        assert_eq!(
            line,
            format!(
                "DELETE /v1/torrents/{h}?delete_files=true&confirm={h} HTTP/1.1",
                h = hash(1)
            )
        );
    }

    #[test]
    fn pause_all_and_resume_all_ask_first() {
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut state = loaded(1..8, None);
        let effects = testing::with_api(&daemon.api(), None, |ctx| {
            let mut effects = Vec::new();
            for c in ['P', 'U'] {
                let msg = on_key(&state, testing::key(KeyCode::Char(c))).unwrap();
                assert!(update(&mut state, msg, ctx).is_empty());
                let msg = on_key(&state, testing::key(KeyCode::Esc)).unwrap();
                assert!(update(&mut state, msg, ctx).is_empty(), "cancelled");
                assert!(state.confirm.is_none());
                let msg = on_key(&state, testing::key(KeyCode::Char(c))).unwrap();
                update(&mut state, msg, ctx);
                let msg = on_key(&state, testing::key(KeyCode::Char('y'))).unwrap();
                effects.extend(update(&mut state, msg, ctx));
            }
            effects
        });
        testing::run(effects);
        assert_eq!(
            daemon.lines(),
            [
                "POST /v1/torrents/pause-all",
                "POST /v1/torrents/resume-all"
            ]
        );
    }

    #[test]
    fn a_bulk_outcome_says_what_was_not_reached() {
        let outcome: types::BulkOutcome = testing::from_json(json!({
            "torrent_count": 1200, "failed_count": 0, "failed_infohashes": [],
            "skipped_profiles": [{"profile_id": "acct_b", "reason": "vpn_down",
                                  "detail": "profile vpn_down; restart daemon to resume"}],
        }));
        let toast = bulk_toast(false, &outcome);
        assert_eq!(toast.kind, ToastKind::Info);
        assert_eq!(
            toast.text,
            "resumed 1,200 torrents; skipped acct_b (vpn_down: profile vpn_down; restart daemon to resume)"
        );
        let outcome: types::BulkOutcome = testing::from_json(json!({
            "torrent_count": 10, "failed_count": 2,
            "failed_infohashes": ["0101010101010101010101010101010101010101",
                                  "0202020202020202020202020202020202020202"],
            "skipped_profiles": [],
        }));
        let toast = bulk_toast(true, &outcome);
        assert_eq!(toast.kind, ToastKind::Error);
        assert_eq!(
            toast.text,
            "paused 10 torrents; 2 failed and are still running"
        );
    }

    #[test]
    fn an_action_result_is_a_toast_and_a_reload() {
        let daemon = testing::Recorder::start("500 Internal Server Error", "{}");
        let mut state = opened(true);
        let (removed, refused) = testing::with_api(&daemon.api(), None, |ctx| {
            let removed = update(
                &mut state,
                Msg::Acted {
                    action: Action::Remove,
                    hash: hash(1),
                    result: Ok(()),
                },
                ctx,
            );
            assert!(state.detail.is_none(), "a removed torrent's view closes");
            let refused = update(
                &mut state,
                Msg::Acted {
                    action: Action::Resume,
                    hash: hash(1),
                    result: Err(failure(409, "profile-unavailable", "vpn_down")),
                },
                ctx,
            );
            (removed, refused)
        });

        let msgs = testing::run(removed);
        assert!(
            matches!(&msgs[0], crate::app::Msg::Toast(t) if t.kind == ToastKind::Success),
            "a toast: {msgs:?}"
        );
        assert_eq!(daemon.lines(), RELOAD, "and the reload");

        let msgs = testing::run(refused);
        assert!(
            matches!(&msgs[..], [crate::app::Msg::Toast(t)] if t.kind == ToastKind::Error),
            "a failure toast: {msgs:?}"
        );
        assert_eq!(daemon.lines(), RELOAD, "and nothing sent");
    }

    // The detail view.

    #[test]
    fn opening_loads_the_record_and_tabs_load_their_own_data() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            let effects = update(&mut state, Msg::Open, ctx);
            assert_eq!(effects.len(), 1, "the record");
            assert_eq!(state.detail.as_ref().unwrap().hash, hash(1));
            assert_eq!(update(&mut state, Msg::Tab(true), ctx).len(), 1, "files");
            assert_eq!(update(&mut state, Msg::Tab(true), ctx).len(), 1, "trackers");
            assert!(
                update(&mut state, Msg::Tab(true), ctx).is_empty(),
                "actions"
            );
            assert!(
                update(&mut state, Msg::Tab(true), ctx).is_empty(),
                "overview"
            );
            let effects = update(&mut state, Msg::Back, ctx);
            assert!(state.detail.is_none());
            assert_eq!(effects.len(), 1, "the list reloads");
        });
    }

    #[test]
    fn an_answer_for_another_torrent_is_dropped() {
        let mut state = opened(false);
        testing::with_ctx(None, |ctx| {
            update(
                &mut state,
                Msg::Torrent {
                    hash: hash(5),
                    result: Ok(torrent(5, true)),
                },
                ctx,
            );
            assert!(state
                .detail
                .as_ref()
                .unwrap()
                .torrent
                .as_ref()
                .unwrap()
                .session
                .is_none());
        });
    }

    #[test]
    fn a_magnet_without_metadata_says_so() {
        let mut state = opened(false);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Tab(true), ctx);
            let detail = state.detail.as_ref().unwrap();
            let (hash, generation) = (detail.hash.clone(), detail.files.generation);
            update(
                &mut state,
                Msg::FilesPage {
                    hash,
                    generation,
                    first: true,
                    result: Err(failure(409, "metadata-pending", "no metadata yet")),
                },
                ctx,
            );
        });
        assert!(state.detail.as_ref().unwrap().metadata_pending);
        let screen = testing::render(80, 24, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        assert!(screen.contains("metadata not yet received"), "{screen}");
    }

    #[test]
    fn the_trackers_tab_polls_its_trackers_on_its_own_timer() {
        let mut state = opened(true);
        with_trackers(&mut state);
        let asked = state.detail.as_ref().unwrap().trackers_asked.unwrap();
        let due = asked + TRACKERS_POLL_INTERVAL;
        testing::with_ctx(None, |ctx| {
            assert!(
                poll(&mut state, due - Duration::from_millis(1), ctx).is_empty(),
                "not before the interval"
            );
            state.detail.as_mut().unwrap().trackers_selected = 1;
            assert_eq!(poll(&mut state, due, ctx).len(), 1, "due: re-read");
            assert!(state.detail.as_ref().unwrap().trackers_loading);
            assert!(
                poll(&mut state, due + TRACKERS_POLL_INTERVAL, ctx).is_empty(),
                "not while a read is in flight"
            );

            // The tracker that worked now fails: the poll's answer shows it,
            // and the operator's place in the list holds.
            let failing: types::TrackerList = testing::from_json(json!({"items": [
                {"tier": 0, "host": "tracker.example.org:443",
                 "url": "https://tracker.example.org/announce", "status": "error",
                 "message": "connection refused", "next_announce_at": null,
                 "seeds": null, "peers": null},
                {"tier": 1, "host": "backup.example.net",
                 "url": "https://backup.example.net/[redacted:9f2c]", "status": "error",
                 "message": "unregistered torrent", "next_announce_at": null,
                 "seeds": null, "peers": null},
            ]}));
            update(
                &mut state,
                Msg::Trackers {
                    hash: hash(1),
                    result: Ok(failing),
                },
                ctx,
            );
            let detail = state.detail.as_ref().unwrap();
            let trackers = detail.trackers.as_ref().unwrap();
            assert_eq!(trackers[0].message.as_deref(), Some("connection refused"));
            assert_eq!(detail.trackers_selected, 1);

            // Only the Trackers tab polls.
            let later = Instant::now() + TRACKERS_POLL_INTERVAL;
            update(&mut state, Msg::Tab(true), ctx);
            assert!(poll(&mut state, later, ctx).is_empty(), "Actions tab");
            update(&mut state, Msg::Tab(true), ctx);
            assert!(poll(&mut state, later, ctx).is_empty(), "Overview tab");
            update(&mut state, Msg::Back, ctx);
            assert!(state.detail.is_none());
            assert!(poll(&mut state, later, ctx).is_empty(), "the list");
        });
    }

    #[test]
    fn only_an_error_a_refresh_re_reads_counts_as_failed() {
        let mut state = opened(false);
        with_files(&mut state);
        with_trackers(&mut state);
        testing::with_ctx(None, |ctx| {
            update(
                &mut state,
                Msg::Trackers {
                    hash: hash(1),
                    result: Err(failure(500, "internal", "boom")),
                },
                ctx,
            );
            assert!(load_failed(&state), "trackers, on the Trackers tab");
            update(&mut state, Msg::Tab(false), ctx);
            let detail = state.detail.as_mut().unwrap();
            let generation = detail.files.generation;
            detail.files.fail(generation, "no metadata yet".to_owned());
            assert!(load_failed(&state), "files, on the Files tab");
            // A refresh re-reads neither from the Overview tab.
            update(&mut state, Msg::Tab(false), ctx);
            assert!(!load_failed(&state), "neither, on the Overview tab");
            // Nor a files list longer than one request.
            update(&mut state, Msg::Tab(true), ctx);
            let detail = state.detail.as_mut().unwrap();
            let row = detail.files.items[0].clone();
            detail.files.items.resize(caps::PAGE_MAX + 1, row);
            assert!(!load_failed(&state), "a long files list");
        });
    }

    #[test]
    fn file_priority_is_shown_at_once_and_put_back_on_refusal() {
        let mut state = opened(true);
        with_files(&mut state);
        testing::with_ctx(None, |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('+'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1);
            assert_eq!(state.detail.as_ref().unwrap().files.items[0].priority, 5);
            let effects = update(
                &mut state,
                Msg::PrioritySet {
                    hash: hash(1),
                    index: 0,
                    previous: 4,
                    priority: 5,
                    result: Err(failure(422, "validation-failed", "priority")),
                },
                ctx,
            );
            assert_eq!(effects.len(), 1, "a failure toast");
            assert_eq!(
                state.detail.as_ref().unwrap().files.items[0].priority,
                4,
                "put back"
            );

            update(&mut state, Msg::Move(Move::Down), ctx);
            assert!(
                update(&mut state, Msg::Priority(Priority::Up), ctx).is_empty(),
                "7 is the top"
            );
            let msg = on_key(&state, testing::key(KeyCode::Char('0'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1);
            assert_eq!(state.detail.as_ref().unwrap().files.items[1].priority, 0);

            let msg = on_key(&state, testing::key(KeyCode::Char('='))).unwrap();
            update(&mut state, msg, ctx);
            assert!(capturing(&state), "a digit is a priority, not a screen");
            assert!(update(
                &mut state,
                Msg::PromptKey(testing::key(KeyCode::Char('9'))),
                ctx
            )
            .is_empty());
            let msg = on_key(&state, testing::key(KeyCode::Char('6'))).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1);
            assert_eq!(state.detail.as_ref().unwrap().files.items[1].priority, 6);
            assert!(!capturing(&state));
        });
    }

    #[test]
    fn priority_keys_do_nothing_off_the_files_tab() {
        let mut state = opened(true);
        testing::with_ctx(None, |ctx| {
            assert!(update(&mut state, Msg::Priority(Priority::Up), ctx).is_empty());
            update(&mut state, Msg::PriorityPrompt, ctx);
            assert!(!capturing(&state));
        });
    }

    #[test]
    fn an_upload_limit_is_checked_before_it_is_sent() {
        assert_eq!(detail::parse_limit(""), Ok(None));
        assert_eq!(detail::parse_limit(" 2_097_152 "), Ok(Some(2_097_152)));
        assert_eq!(detail::parse_limit("2147483647"), Ok(Some(2_147_483_647)));
        assert!(detail::parse_limit("0").is_err());
        assert!(detail::parse_limit("2147483648").is_err());
        assert!(detail::parse_limit("-5").is_err());
        assert!(detail::parse_limit("2M")
            .unwrap_err()
            .contains("whole number"));

        let mut state = opened(true);
        testing::with_ctx(None, |ctx| {
            let msg = on_key(&state, testing::key(KeyCode::Char('l'))).unwrap();
            update(&mut state, msg, ctx);
            assert!(capturing(&state));
            let limit = &state.detail.as_ref().unwrap().limit.as_ref().unwrap().input;
            assert_eq!(limit.value(), "2097152", "prefilled with the current limit");
            state.detail.as_mut().unwrap().limit.as_mut().unwrap().input = Input::new("0".into());
            let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty());
            let error = state
                .detail
                .as_ref()
                .unwrap()
                .limit
                .as_ref()
                .unwrap()
                .error
                .clone();
            assert!(error.unwrap().contains("between 1 and"));
            state.detail.as_mut().unwrap().limit.as_mut().unwrap().input = Input::default();
            let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
            assert_eq!(
                update(&mut state, msg, ctx).len(),
                1,
                "null removes the limit"
            );
            assert!(!capturing(&state));
        });
    }

    #[test]
    fn the_actions_tab_runs_the_selected_entry() {
        let mut state = opened(true);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Tab(false), ctx);
            assert_eq!(state.detail.as_ref().unwrap().tab, detail::Tab::Actions);
            let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
            assert_eq!(update(&mut state, msg, ctx).len(), 1, "pause");
            for _ in 0..4 {
                update(&mut state, Msg::Move(Move::Down), ctx);
            }
            update(&mut state, Msg::RunEntry, ctx);
            assert!(
                state.detail.as_ref().unwrap().limit.is_some(),
                "the limit field"
            );
        });
    }

    // Adding.

    fn dialog(state: &mut State, ctx: &Ctx<'_>) {
        let msg = on_key(state, testing::key(KeyCode::Char('n'))).unwrap();
        update(state, msg, ctx);
        assert!(capturing(state));
    }

    #[test]
    fn the_add_dialog_checks_its_fields() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            dialog(&mut state, ctx);
            let add = state.add.as_ref().unwrap();
            assert_eq!(add.profile, None, "no profile is chosen for the operator");
            let msg = on_key(&state, testing::key(KeyCode::Enter)).unwrap();
            assert!(update(&mut state, msg, ctx).is_empty(), "nothing is sent");
            let add = state.add.as_ref().unwrap();
            assert_eq!(add.errors.source.as_deref(), Some("enter a magnet URI"));
            assert_eq!(add.errors.profile.as_deref(), Some("choose a profile"));

            keys(&mut state, ctx, "http://x");
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
            assert!(state
                .add
                .as_ref()
                .unwrap()
                .errors
                .source
                .as_ref()
                .unwrap()
                .contains("magnet:?"));

            // Another kind: a path on the server, which must be absolute.
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Up)), ctx);
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
            assert_eq!(
                state.add.as_ref().unwrap().kind,
                add::SourceKind::ServerPath
            );
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
            let add = state.add.as_ref().unwrap();
            assert_eq!(
                add.focus,
                add::Field::Source,
                "focus moves to the field at fault"
            );
            assert!(add.errors.source.as_ref().unwrap().contains("absolute"));

            // Profiles cycle through the active ones only: acct_b is fenced.
            let add = state.add.as_mut().unwrap();
            add.source = Input::new("/srv/torrents/x.torrent".into());
            add.focus = add::Field::Profile;
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
            assert_eq!(
                state.add.as_ref().unwrap().profile.as_deref(),
                Some("acct_a")
            );
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
            assert_eq!(
                state.add.as_ref().unwrap().profile.as_deref(),
                Some("acct_c")
            );
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Right)), ctx);
            assert_eq!(
                state.add.as_ref().unwrap().profile.as_deref(),
                Some("acct_a")
            );

            update(&mut state, Msg::AddKey(testing::key(KeyCode::Down)), ctx);
            keys(&mut state, ctx, "relative/dir");
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
            let add = state.add.as_ref().unwrap();
            assert!(add.errors.save_path.is_some() && add.errors.source.is_none());

            state.add.as_mut().unwrap().save_path = Input::new("/srv/seed/acct_a".into());
            let effects = update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
            assert_eq!(effects.len(), 1, "one POST");
            let add = state.add.as_ref().unwrap();
            assert!(add.submitting && add.errors.is_empty());
            assert!(
                update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx).is_empty(),
                "sent once"
            );
        });
    }

    #[test]
    fn no_active_profile_is_said_in_the_dialog() {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            assert_eq!(
                update(&mut state, Msg::OpenAdd, ctx).len(),
                1,
                "profiles are fetched"
            );
            update(
                &mut state,
                Msg::Profiles(Ok(profiles()[1..2].to_vec())),
                ctx,
            );
            state.add.as_mut().unwrap().source = Input::new("magnet:?xt=urn:btih:abc".into());
            update(&mut state, Msg::AddKey(testing::key(KeyCode::Enter)), ctx);
            let add = state.add.as_ref().unwrap();
            assert!(add
                .errors
                .profile
                .as_ref()
                .unwrap()
                .contains("no profile is active"));
        });
    }

    fn refused(
        kind: add::SourceKind,
        save_path: &str,
        failure: add::AddFailure,
    ) -> add::FieldErrors {
        let mut state = loaded(1..2, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::OpenAdd, ctx);
            let add = state.add.as_mut().unwrap();
            add.kind = kind;
            add.save_path = Input::new(save_path.into());
            add.submitting = true;
            assert!(update(&mut state, Msg::Added(Err(failure)), ctx).is_empty());
        });
        let add = state.add.unwrap();
        assert!(!add.submitting);
        add.errors
    }

    fn api(slug: &str, detail: &str) -> add::AddFailure {
        add::AddFailure::Api {
            failure: failure(422, slug, detail),
            errors: Vec::new(),
        }
    }

    #[test]
    fn refusals_land_on_the_field_at_fault() {
        use add::SourceKind::LocalFile;
        use add::SourceKind::Magnet;
        use add::SourceKind::ServerPath;
        let e = refused(
            ServerPath,
            "",
            api("path-not-confined", "the server_path must be inside …"),
        );
        assert!(e.source.is_some() && e.save_path.is_none());
        let e = refused(
            Magnet,
            "/etc",
            api("path-not-confined", "save_path must be inside …"),
        );
        assert!(e.save_path.is_some() && e.source.is_none());
        let e = refused(
            ServerPath,
            "/etc",
            api("path-not-confined", "save_path must be inside …"),
        );
        assert!(
            e.save_path.is_some() && e.source.is_none(),
            "the detail tells them apart"
        );
        let e = refused(ServerPath, "/etc", api("path-not-confined", "outside"));
        assert!(
            e.save_path.is_some() && e.source.is_some(),
            "no hint: both are marked"
        );
        let e = refused(
            LocalFile,
            "",
            api("tracker-not-allowed", "announces to none"),
        );
        assert!(e.profile.as_ref().unwrap().contains("announces to none"));
        let e = refused(Magnet, "", api("profile-unavailable", "vpn_down"));
        assert!(e.profile.is_some());
        let e = refused(Magnet, "", api("invalid-metainfo", "not a magnet"));
        assert!(e.source.is_some());
        let e = refused(Magnet, "", api("torrent-exists", "assigned to acct_b"));
        assert_eq!(e.general.as_deref(), Some("Refused: assigned to acct_b"));
        let e = refused(
            LocalFile,
            "",
            add::AddFailure::Api {
                failure: failure(422, "validation-failed", "2 violations"),
                errors: vec![
                    ("/save_path".into(), "too long".into()),
                    ("/source/data".into(), "not base64".into()),
                    ("/other".into(), "odd".into()),
                ],
            },
        );
        assert_eq!(e.save_path.as_deref(), Some("too long"));
        assert_eq!(e.source.as_deref(), Some("not base64"));
        assert_eq!(e.general.as_deref(), Some("/other: odd"));
        let e = refused(
            LocalFile,
            "",
            add::AddFailure::Local {
                field: add::Field::Source,
                message: "too big".into(),
            },
        );
        assert_eq!(e.source.as_deref(), Some("too big"));
    }

    #[test]
    fn an_added_torrent_is_selected_once_loaded() {
        let mut state = loaded(1..4, None);
        testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::OpenAdd, ctx);
            let effects = update(&mut state, Msg::Added(Ok(torrent(2, true))), ctx);
            assert_eq!(effects.len(), 2, "a toast and the reload");
            assert!(state.add.is_none());
            assert_eq!(state.restore.as_deref(), Some(hash(2).as_str()));
            let msg = page_msg(&state, true, Ok(page(1..4, None)));
            update(&mut state, msg, ctx);
            assert_eq!(selected_summary(&state).unwrap().infohash, hash(2));
        });
    }

    #[test]
    fn a_local_torrent_over_64_mib_is_refused_before_sending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.torrent");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(caps::MAX_METAINFO + 1)
            .unwrap();
        let request = add::Request {
            profile: "acct_a".into(),
            save_path: None,
            source: add::Source::LocalFile(path),
        };
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(add::submit(testing::api(), request));
        match result {
            Err(add::AddFailure::Local { field, message }) => {
                assert_eq!(field, add::Field::Source);
                assert!(message.contains("at most 64.0 MiB"), "{message}");
            }
            other => panic!("refused locally, got {other:?}"),
        }
    }

    /// Why a `.torrent` is sent by hand: the generated type puts its bytes on
    /// the wire as an array of numbers, not base64. When this fails, spargen
    /// has fixed it and `add::post_metainfo` can go.
    #[test]
    fn the_generated_metainfo_source_does_not_serialize_as_base64() {
        let source = types::TorrentSourceVariant2 {
            kind: types::TorrentSourceVariant2kind::Metainfo,
            data: bytes::Bytes::from_static(b"d4:infoe"),
        };
        let value = serde_json::to_value(source).unwrap();
        assert!(value["data"].is_array(), "{value}");
    }

    // Keys.

    #[test]
    fn keys_map_by_mode() {
        let k = |state: &State, code| on_key(state, testing::key(code));
        let state = loaded(1..8, None);
        assert!(matches!(
            k(&state, KeyCode::Char('j')),
            Some(Msg::Move(Move::Down))
        ));
        assert!(matches!(k(&state, KeyCode::Up), Some(Msg::Move(Move::Up))));
        assert!(matches!(
            k(&state, KeyCode::Char('G')),
            Some(Msg::Move(Move::Bottom))
        ));
        assert!(matches!(
            k(&state, KeyCode::PageDown),
            Some(Msg::Move(Move::PageDown))
        ));
        assert!(matches!(k(&state, KeyCode::Enter), Some(Msg::Open)));
        assert!(matches!(
            k(&state, KeyCode::Char('f')),
            Some(Msg::CycleProfile)
        ));
        assert!(matches!(
            k(&state, KeyCode::Char('F')),
            Some(Msg::CyclePhase)
        ));
        assert!(matches!(k(&state, KeyCode::Char('n')), Some(Msg::OpenAdd)));
        assert!(matches!(
            k(&state, KeyCode::Char('P')),
            Some(Msg::Act(Action::PauseAll))
        ));
        assert!(matches!(
            k(&state, KeyCode::Char('U')),
            Some(Msg::Act(Action::ResumeAll))
        ));
        assert!(k(&state, KeyCode::Esc).is_none(), "no filter to clear");
        assert!(k(&state, KeyCode::Char('q')).is_none(), "global");
        assert!(!capturing(&state));

        let state = opened(true);
        assert!(matches!(k(&state, KeyCode::Esc), Some(Msg::Back)));
        assert!(matches!(k(&state, KeyCode::Char('h')), Some(Msg::Back)));
        assert!(matches!(k(&state, KeyCode::Backspace), Some(Msg::Back)));
        assert!(matches!(k(&state, KeyCode::Right), Some(Msg::Tab(true))));
        assert!(matches!(
            k(&state, KeyCode::Char('[')),
            Some(Msg::Tab(false))
        ));
        assert!(matches!(
            k(&state, KeyCode::Char('D')),
            Some(Msg::Act(Action::RemoveFiles))
        ));
        assert!(matches!(
            k(&state, KeyCode::Char('l')),
            Some(Msg::OpenLimit)
        ));
        assert!(
            k(&state, KeyCode::Char('P')).is_none(),
            "every torrent is a list action"
        );
        assert!(
            k(&state, KeyCode::Char('1')).is_none(),
            "digits stay global"
        );
        assert!(
            k(&state, KeyCode::Enter).is_none(),
            "Enter runs only on the actions tab"
        );
        assert!(!capturing(&state));
    }

    // Snapshots.

    fn snapshot(name: &str, state: &State, sizes: &[(u16, u16)], mutations: bool) {
        let server = testing::server(true, mutations);
        for (w, h) in sizes {
            let screen = testing::render(*w, *h, Some(&server), |ctx, frame, area| {
                view(state, ctx, frame, area)
            });
            insta::assert_snapshot!(format!("torrents_{name}_{w}x{h}"), screen);
        }
    }

    #[test]
    fn the_list_renders_at_both_sizes() {
        let mut state = loaded(1..30, Some("c1"));
        state.list.loading = false;
        state.selected = 2;
        snapshot("list", &state, &[(80, 24), (160, 48)], true);
    }

    #[test]
    fn the_detail_overview_renders() {
        snapshot(
            "detail_overview",
            &opened(true),
            &[(80, 24), (160, 48)],
            true,
        );
        let screen = testing::render(160, 48, None, |ctx, frame, area| {
            view(&opened(false), ctx, frame, area)
        });
        assert!(screen.contains("not loaded in a session"), "{screen}");
    }

    #[test]
    fn the_detail_files_render() {
        let mut state = opened(true);
        with_files(&mut state);
        state.detail.as_mut().unwrap().files_selected = 1;
        snapshot("detail_files", &state, &[(160, 48)], true);
    }

    #[test]
    fn the_detail_trackers_render() {
        let mut state = opened(true);
        with_trackers(&mut state);
        snapshot("detail_trackers", &state, &[(160, 48)], true);
    }

    #[test]
    fn the_detail_actions_say_what_is_disabled() {
        let mut state = opened(true);
        testing::with_ctx(None, |ctx| update(&mut state, Msg::Tab(false), ctx));
        let screen = testing::render(80, 24, None, |ctx, frame, area| {
            view(&state, ctx, frame, area)
        });
        assert!(screen.contains("needs [pool] allow_mutations"), "{screen}");
    }

    #[test]
    fn the_add_dialog_renders_with_its_errors() {
        let mut state = loaded(1..8, None);
        testing::with_ctx(None, |ctx| {
            dialog(&mut state, ctx);
            let add = state.add.as_mut().unwrap();
            add.kind = add::SourceKind::ServerPath;
            add.source = Input::new("/home/op/x.torrent".into());
            add.save_path = Input::new("/srv/seed/acct_a".into());
            update(
                &mut state,
                Msg::Added(Err(api(
                    "path-not-confined",
                    "the server_path must be inside the daemon's torrent directory",
                ))),
                ctx,
            );
        });
        snapshot("add", &state, &[(80, 24)], true);
    }

    #[test]
    fn the_delete_confirmation_renders() {
        let mut state = opened(true);
        let server = testing::server(true, true);
        testing::with_ctx(Some(&server), |ctx| {
            update(&mut state, Msg::Act(Action::RemoveFiles), ctx);
            keys(&mut state, ctx, "del");
        });
        snapshot("delete_confirm", &state, &[(80, 24)], true);
    }

    mod props {
        use proptest::prelude::*;

        use super::*;

        /// Rows `from..from + n`, in infohash order, every third in
        /// `acct_b`, so a `/b` filter shows some rows and hides others.
        fn rows(from: usize, n: usize, next: Option<&str>) -> types::TorrentPage {
            let items: Vec<_> = (from..from + n)
                .map(|i| {
                    let mut row =
                        summary(1, if i % 3 == 0 { "acct_b" } else { "acct_a" }, "seeding");
                    row["infohash"] = json!(format!("{i:040x}"));
                    row
                })
                .collect();
            testing::from_json(json!({"items": items, "next_cursor": next}))
        }

        #[derive(Clone, Debug)]
        enum Op {
            Key(KeyCode),
            /// The daemon answers the request in flight, if there is one,
            /// with `n` rows and more to come or not. A first page of a
            /// reload starts the daemon's rows at `shift`: what it lists can
            /// change between reloads.
            Page {
                shift: usize,
                n: usize,
                more: bool,
            },
            PageFailed,
            Refresh,
        }

        fn op() -> impl Strategy<Value = Op> {
            let key = prop::sample::select(vec![
                KeyCode::Char('j'),
                KeyCode::Char('k'),
                KeyCode::Char('g'),
                KeyCode::Char('G'),
                KeyCode::Up,
                KeyCode::Down,
                KeyCode::Home,
                KeyCode::End,
                KeyCode::PageUp,
                KeyCode::PageDown,
                KeyCode::Char('/'),
                KeyCode::Enter,
                KeyCode::Esc,
                KeyCode::Backspace,
                KeyCode::Char('0'),
                KeyCode::Char('1'),
                KeyCode::Char('b'),
                KeyCode::Char('e'),
                KeyCode::Char('f'),
                KeyCode::Char('F'),
            ]);
            prop_oneof![
                6 => key.prop_map(Op::Key),
                3 => (0usize..30, 0usize..40, any::<bool>()).prop_map(|(shift, n, more)| Op::Page { shift, n, more }),
                1 => Just(Op::PageFailed),
                1 => Just(Op::Refresh),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Whatever keys are pressed and whatever the daemon answers,
            /// failed or short, filtered or not, the list's selection is a
            /// row it shows, or 0 when it shows none.
            ///
            /// The daemon is faithful to the protocol: it answers only the
            /// request in flight, a reload's with a first page, a cursor's
            /// with the rows from that cursor on.
            #[test]
            fn the_selection_stays_within_the_visible_rows(ops in prop::collection::vec(op(), 0..80)) {
                let mut state = State::default();
                testing::with_ctx(None, |ctx| -> Result<(), TestCaseError> {
                    // The request in flight: `None` for a reload's first
                    // page, else the row its cursor resumes at. A cursor is
                    // `k<row>`.
                    let mut in_flight: Option<Option<usize>> = None;
                    let cursor_row = |c: &Option<String>| -> Option<usize> {
                        c.as_deref().and_then(|c| c.strip_prefix('k')).and_then(|n| n.parse().ok())
                    };
                    let (mut generation, mut loading) = (state.list.generation, false);
                    let _ = update(&mut state, Msg::Profiles(Ok(profiles())), ctx);
                    let _ = refresh(&mut state, ctx);
                    for op in std::iter::once(None).chain(ops.into_iter().map(Some)) {
                        // The row after the page just sent: where the next
                        // request, a reload's or for more, resumes.
                        let mut resume_at = None;
                        let msg = match &op {
                            None => None,
                            Some(Op::Key(code)) => on_key(&state, testing::key(*code)),
                            Some(Op::Page { .. } | Op::PageFailed) if in_flight.is_none() => None,
                            Some(Op::Page { shift, n, more }) => {
                                let request = in_flight.take().unwrap();
                                let from = request.unwrap_or(*shift);
                                let next = more.then(|| format!("k{}", from + n));
                                resume_at = Some(from + n);
                                let page = rows(from, *n, next.as_deref());
                                Some(page_msg(&state, request.is_none(), Ok(page)))
                            }
                            Some(Op::PageFailed) => {
                                in_flight = None;
                                Some(page_msg(&state, false, Err(failure(500, "internal", "boom"))))
                            }
                            Some(Op::Refresh) => {
                                let _ = refresh(&mut state, ctx);
                                None
                            }
                        };
                        if let Some(msg) = msg {
                            let _ = update(&mut state, msg, ctx);
                        }
                        // What the client asked for since: a reload, or a
                        // page from its cursor (a reload's next page, or more
                        // rows near the end).
                        if state.list.generation != generation {
                            in_flight = Some(None);
                        } else if let (true, Some(at)) = (state.list.loading, resume_at) {
                            in_flight = Some(Some(at));
                        } else if state.list.loading && !loading {
                            in_flight = Some(cursor_row(&state.list.next_cursor));
                        }
                        if !state.list.loading {
                            in_flight = None;
                        }
                        (generation, loading) = (state.list.generation, state.list.loading);
                        let op = op.unwrap_or(Op::Refresh);
                        if state.detail.is_none() {
                            let shown = visible(&state).len();
                            prop_assert!(
                                state.selected < shown.max(1),
                                "after {:?}: selected {} of {} shown",
                                op,
                                state.selected,
                                shown,
                            );
                        }
                    }
                    Ok(())
                })?;
            }
        }
    }
}
