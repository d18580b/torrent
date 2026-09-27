//! The managed pool: what is on disk under each root, what the library holds
//! and where each torrent stands against it, handing matched payload to a
//! profile, and the plans that move or delete payload.
//!
//! Four views, switched with `[`/`]` or `←`/`→` (`Tab` is the screens'):
//!
//! - **overview** — the library, adoption counts, the verify queue and every
//!   root's byte accounting; `s` scans, `d` checks for drift, `Enter` browses
//!   a root;
//! - **tree** — one root's directories, a page at a time, with what each
//!   holds; `o` narrows to orphans, `A` adopts the directory;
//! - **library** — every `.torrent` the pool read, filtered by adoption
//!   state; `space` marks, `v` verifies, `a` adopts;
//! - **plans** — relocations and orphan deletions, created as drafts and
//!   applied only with consent (and, for a delete, the plan's token).
//!
//! Adoption is a dialog over whichever view opened it: a dry run first, then
//! the same request for real.

mod adopt;
mod library;
mod overview;
mod plans;
#[cfg(test)]
mod tests;
mod tree;

use std::cell::Cell;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::api::Failure;
use crate::app::failed;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Toast;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;

/// The pool's views, in the order `]` walks them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    #[default]
    Overview,
    Tree,
    Library,
    Plans,
}

impl View {
    const ALL: [View; 4] = [View::Overview, View::Tree, View::Library, View::Plans];

    fn title(self) -> &'static str {
        match self {
            View::Overview => "Overview",
            View::Tree => "Tree",
            View::Library => "Library",
            View::Plans => "Plans",
        }
    }

    fn step(self, by: isize) -> View {
        let at = Self::ALL.iter().position(|v| *v == self).unwrap_or(0) as isize;
        let len = Self::ALL.len() as isize;
        Self::ALL[(at + by).rem_euclid(len) as usize]
    }
}

#[derive(Debug, Default)]
pub struct State {
    pub view: View,
    /// The daemon answered `pool-not-configured`: there is no `[pool]`.
    pub not_configured: bool,
    pub overview: overview::State,
    pub tree: tree::State,
    pub library: library::State,
    pub plans: plans::State,
    /// The adopt dialog, while open.
    pub adopt: Option<adopt::Dialog>,
    /// Numbers adopt dialogs, so an answer to a closed one is dropped.
    pub adopt_serial: u64,
}

#[derive(Debug)]
pub enum Msg {
    /// The next view (`]`, `→`).
    Next,
    /// The previous view (`[`, `←`).
    Prev,
    /// Browse the root selected on the overview.
    OpenRoot,
    /// Adopt the directory the tree is showing.
    AdoptSubtree,
    /// Adopt the library's marked torrents, or the selected one.
    AdoptMarked,
    /// Start a plan, prefilled from what the tree and library show.
    CreatePlan,
    Overview(overview::Msg),
    Tree(tree::Msg),
    Library(library::Msg),
    Plans(plans::Msg),
    Adopt(adopt::Msg),
}

pub const KEYS: &[(&str, &str)] = &[
    ("[ ] / ← →", "view"),
    ("Enter", "open"),
    ("space", "mark"),
    ("a / A", "adopt"),
    ("v", "verify"),
    ("x", "apply plan"),
    ("j/k ↑/↓ g/G PgUp/PgDn", "move"),
    ("s", "scan the pool"),
    ("d", "drift check"),
    ("h / Backspace", "up a directory"),
    ("o", "orphans only"),
    ("F", "filter by state / status"),
    ("c", "create a plan"),
    ("X", "discard a plan"),
    ("Esc", "back / clear marks"),
];

/// What the operator is told when a plan operation is unavailable.
const MUTATIONS_OFF: &str = "pool mutations are disabled: creating and applying plans needs \
                             `allow_mutations = true` under [pool] in the daemon's config";

/// Where each listing's page size starts; a refresh asks for as many rows as
/// are loaded, up to [`MAX_REFRESH`], so the selection keeps its place.
const PAGE: i64 = 100;
const MAX_REFRESH: i64 = 1000;

/// Most infohashes one adopt or verify request may carry.
const MAX_BATCH: usize = 1000;

pub fn capturing(state: &State) -> bool {
    state.adopt.is_some()
        || state.overview.confirm_scan.is_some()
        || state.library.confirm_verify.is_some()
        || state.plans.capturing()
}

pub fn on_key(state: &State, key: KeyEvent) -> Option<Msg> {
    if state.adopt.is_some() {
        return Some(Msg::Adopt(adopt::Msg::Key(key)));
    }
    if state.overview.confirm_scan.is_some() {
        return Some(Msg::Overview(overview::Msg::ConfirmKey(key)));
    }
    if state.library.confirm_verify.is_some() {
        return Some(Msg::Library(library::Msg::ConfirmKey(key)));
    }
    if state.plans.capturing() {
        return Some(Msg::Plans(plans::Msg::Key(key)));
    }
    match key.code {
        KeyCode::Char(']') | KeyCode::Right => return Some(Msg::Next),
        KeyCode::Char('[') | KeyCode::Left => return Some(Msg::Prev),
        _ => {}
    }
    if state.not_configured {
        return None;
    }
    let motion = Motion::from_key(key);
    match state.view {
        View::Overview => match key.code {
            _ if motion.is_some() => motion.map(|m| Msg::Overview(overview::Msg::Move(m))),
            KeyCode::Enter => Some(Msg::OpenRoot),
            KeyCode::Char('s') => Some(Msg::Overview(overview::Msg::AskScan)),
            KeyCode::Char('d') => Some(Msg::Overview(overview::Msg::CheckDrift)),
            _ => None,
        },
        View::Tree => match key.code {
            _ if motion.is_some() => motion.map(|m| Msg::Tree(tree::Msg::Move(m))),
            KeyCode::Enter | KeyCode::Char('l') => Some(Msg::Tree(tree::Msg::Enter)),
            KeyCode::Backspace | KeyCode::Char('h') | KeyCode::Esc => {
                Some(Msg::Tree(tree::Msg::Up))
            }
            KeyCode::Char('o') => Some(Msg::Tree(tree::Msg::ToggleOrphans)),
            KeyCode::Char('A') => Some(Msg::AdoptSubtree),
            _ => None,
        },
        View::Library => match key.code {
            _ if motion.is_some() => motion.map(|m| Msg::Library(library::Msg::Move(m))),
            KeyCode::Char(' ') => Some(Msg::Library(library::Msg::ToggleMark)),
            KeyCode::Char('v') => Some(Msg::Library(library::Msg::AskVerify)),
            KeyCode::Char('a') => Some(Msg::AdoptMarked),
            KeyCode::Char('F') => Some(Msg::Library(library::Msg::CycleFilter)),
            KeyCode::Esc => Some(Msg::Library(library::Msg::Back)),
            _ => None,
        },
        View::Plans => {
            let in_detail = state.plans.detail.is_some();
            match key.code {
                _ if motion.is_some() => motion.map(|m| Msg::Plans(plans::Msg::Move(m))),
                KeyCode::Enter if !in_detail => Some(Msg::Plans(plans::Msg::Open)),
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('h') if in_detail => {
                    Some(Msg::Plans(plans::Msg::Back))
                }
                KeyCode::Char('F') if !in_detail => Some(Msg::Plans(plans::Msg::CycleFilter)),
                KeyCode::Char('c') => Some(Msg::CreatePlan),
                KeyCode::Char('x') => Some(Msg::Plans(plans::Msg::AskApply)),
                KeyCode::Char('X') => Some(Msg::Plans(plans::Msg::AskDiscard)),
                _ => None,
            }
        }
    }
}

pub fn refresh(state: &mut State, ctx: &Ctx<'_>) -> Vec<Effect> {
    match state.view {
        View::Overview => overview::refresh(&mut state.overview, ctx),
        View::Tree if state.tree.root.is_some() => tree::refresh(&mut state.tree, ctx),
        // No root picked yet: browse the overview's selection once it is
        // known.
        View::Tree => match state.overview.selected_root() {
            Some(root) => tree::open(&mut state.tree, root, ctx),
            None => overview::refresh(&mut state.overview, ctx),
        },
        View::Library => library::refresh(&mut state.library, ctx),
        View::Plans => plans::refresh(&mut state.plans, ctx),
    }
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match load_outcome(&msg) {
        Some(Some(failure)) if failure.is("pool-not-configured") => state.not_configured = true,
        Some(None) => state.not_configured = false,
        _ => {}
    }
    match msg {
        Msg::Next => show(state, state.view.step(1), ctx),
        Msg::Prev => show(state, state.view.step(-1), ctx),
        Msg::OpenRoot => match state.overview.selected_root() {
            Some(root) => {
                state.view = View::Tree;
                tree::open(&mut state.tree, root, ctx)
            }
            None => Vec::new(),
        },
        Msg::AdoptSubtree => match &state.tree.root {
            Some(root) => {
                let selector = adopt::Selector::Subtree {
                    root_id: root.id,
                    root_path: root.path.clone(),
                    path: state.tree.dir(),
                };
                open_adopt(state, selector, ctx)
            }
            None => Vec::new(),
        },
        Msg::AdoptMarked => {
            let targets = state.library.targets();
            if targets.is_empty() {
                Vec::new()
            } else if targets.len() > MAX_BATCH {
                vec![Effect::toast(Toast::info(format!(
                    "{} marked: adopt at most {MAX_BATCH} at a time",
                    targets.len()
                )))]
            } else {
                open_adopt(state, adopt::Selector::Infohashes(targets), ctx)
            }
        }
        Msg::CreatePlan => {
            let prefill = plans::Prefill {
                infohash: state.library.selected_infohash(),
                root_id: state
                    .tree
                    .root
                    .as_ref()
                    .map(|r| r.id)
                    .or_else(|| state.overview.selected_root().map(|r| r.id)),
                prefix: state.tree.dir(),
            };
            plans::update(&mut state.plans, plans::Msg::AskCreate(prefill), ctx)
        }
        Msg::Overview(msg) => {
            let loaded = matches!(msg, overview::Msg::Loaded(_, Ok(_)));
            let mut effects = overview::update(&mut state.overview, msg, ctx);
            // The tree was asked for before any root was known.
            if loaded && state.view == View::Tree && state.tree.root.is_none() {
                if let Some(root) = state.overview.selected_root() {
                    effects.extend(tree::open(&mut state.tree, root, ctx));
                }
            }
            effects
        }
        Msg::Tree(msg) => tree::update(&mut state.tree, msg, ctx),
        Msg::Library(msg) => library::update(&mut state.library, msg, ctx),
        Msg::Plans(msg) => plans::update(&mut state.plans, msg, ctx),
        Msg::Adopt(msg) => {
            let adopted = matches!(
                &msg,
                adopt::Msg::Answered { serial, dry_run: false, result: Ok(_) }
                    if state.adopt.as_ref().is_some_and(|d| d.serial == *serial)
            );
            let mut effects = adopt::update(&mut state.adopt, msg, ctx);
            if adopted {
                state.library.marks.clear();
                effects.extend(refresh(state, ctx));
            }
            effects
        }
    }
}

fn show(state: &mut State, view: View, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.view = view;
    refresh(state, ctx)
}

fn open_adopt(state: &mut State, selector: adopt::Selector, ctx: &Ctx<'_>) -> Vec<Effect> {
    state.adopt_serial += 1;
    let (dialog, effects) = adopt::open(state.adopt_serial, selector, ctx);
    state.adopt = Some(dialog);
    effects
}

/// What a message says about loading the pool: `Some(None)` for a load that
/// succeeded, `Some(Some(failure))` for one that failed, `None` for anything
/// that is not a load.
fn load_outcome(msg: &Msg) -> Option<Option<&Failure>> {
    fn of<T>(result: &Result<T, Failure>) -> Option<Option<&Failure>> {
        Some(result.as_ref().err())
    }
    match msg {
        Msg::Overview(overview::Msg::Loaded(_, result)) => of(result),
        Msg::Tree(tree::Msg::Page { result, .. }) => of(result),
        Msg::Library(library::Msg::Page { result, .. }) => of(result),
        Msg::Plans(plans::Msg::Page { result, .. }) => of(result),
        _ => None,
    }
}

pub fn view(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    if state.not_configured {
        placeholder(
            frame,
            area,
            theme,
            "This daemon has no [pool] section, so there is no pool to manage. Add one to its \
             config and restart it.",
            Tone::Muted,
        );
        return;
    }
    let [bar, body] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    draw_views(state, ctx, frame, bar);
    match state.view {
        View::Overview => overview::view(&state.overview, ctx, frame, body),
        View::Tree => tree::view(&state.tree, ctx, frame, body),
        View::Library => library::view(&state.library, ctx, frame, body),
        View::Plans => plans::view(&state.plans, ctx, frame, body),
    }
    if let Some(confirm) = &state.overview.confirm_scan {
        confirm.view(frame, area, theme);
    }
    if let Some((confirm, _)) = &state.library.confirm_verify {
        confirm.view(frame, area, theme);
    }
    plans::overlay(&state.plans, ctx, frame, area);
    if let Some(dialog) = &state.adopt {
        adopt::view(dialog, ctx, frame, area);
    }
}

/// The views as a strip, the current one bracketed, and what the daemon
/// lets this screen change.
fn draw_views(state: &State, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let mut spans = Vec::new();
    for view in View::ALL {
        if view == state.view {
            spans.push(Span::styled(format!("[{}]", view.title()), theme.title()));
        } else {
            spans.push(Span::styled(
                format!(" {} ", view.title()),
                theme.fg(Tone::Muted),
            ));
        }
        spans.push(Span::raw(" "));
    }
    let (mode, tone) = if mutations_allowed(ctx) {
        ("● mutations allowed", Tone::Good)
    } else {
        ("‖ read-only plans", Tone::Warn)
    };
    let right = Line::from(vec![
        Span::styled("[ ]", theme.key()),
        Span::styled(" views  ", theme.fg(Tone::Muted)),
        Span::styled(mode, theme.fg(tone)),
    ]);
    let width = right.width() as u16;
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(width)]).areas(area);
    frame.render_widget(Paragraph::new(Line::from(spans)), left_area);
    frame.render_widget(Paragraph::new(right), right_area);
}

/// Whether the daemon lets plans be created and applied.
fn mutations_allowed(ctx: &Ctx<'_>) -> bool {
    ctx.server.is_some_and(|s| s.pool.allow_mutations)
}

/// Wrap a pool message for the root.
fn wrap(msg: Msg) -> crate::app::Msg {
    crate::app::Msg::Pool(msg)
}

/// A failed load shows in its panel; only a `401` needs more — a sign-out.
fn signed_out(failure: &Failure) -> Vec<Effect> {
    if failure.is_unauthenticated() {
        vec![Effect::now(failed("loading the pool", failure.clone()))]
    } else {
        Vec::new()
    }
}

/// How many rows a refresh asks for: as many as are loaded, so the
/// selection keeps its place, within one request's reach.
fn refresh_limit(loaded: usize) -> Option<i64> {
    let loaded = loaded as i64;
    (loaded > PAGE).then(|| ((loaded + PAGE - 1) / PAGE * PAGE).min(MAX_REFRESH))
}

/// A move of a list's selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motion {
    Up,
    Down,
    Top,
    Bottom,
    PageUp,
    PageDown,
}

impl Motion {
    /// Rows a page key moves.
    const PAGE_ROWS: usize = 10;

    fn from_key(key: KeyEvent) -> Option<Motion> {
        Some(match key.code {
            KeyCode::Char('j') | KeyCode::Down => Motion::Down,
            KeyCode::Char('k') | KeyCode::Up => Motion::Up,
            KeyCode::Char('g') | KeyCode::Home => Motion::Top,
            KeyCode::Char('G') | KeyCode::End => Motion::Bottom,
            KeyCode::PageUp => Motion::PageUp,
            KeyCode::PageDown => Motion::PageDown,
            _ => return None,
        })
    }

    /// The selection after this move, from `at` in a list of `len`.
    fn apply(self, at: usize, len: usize) -> usize {
        let last = len.saturating_sub(1);
        match self {
            Motion::Up => at.saturating_sub(1),
            Motion::Down => (at + 1).min(last),
            Motion::Top => 0,
            Motion::Bottom => last,
            Motion::PageUp => at.saturating_sub(Self::PAGE_ROWS),
            Motion::PageDown => (at + Self::PAGE_ROWS).min(last),
        }
    }
}

/// The first row to draw so `selected` stays in view, moving the window
/// only as far as it must: scrolling is steady rather than re-centred.
fn scroll(offset: &Cell<usize>, selected: usize, rows: usize) -> usize {
    let mut at = offset.get();
    if selected < at {
        at = selected;
    } else if rows > 0 && selected >= at + rows {
        at = selected + 1 - rows;
    }
    offset.set(at);
    at
}

/// A panel title: the name, then a spinner while loading, then the last
/// failure.
fn title<'a>(
    theme: &Theme,
    name: String,
    loading: bool,
    error: Option<&str>,
    tick: u64,
) -> Line<'a> {
    let mut spans = vec![Span::raw(format!(" {name} "))];
    if loading {
        spans.push(Span::styled(
            format!("{} ", spinner(tick)),
            theme.fg(Tone::Accent),
        ));
    }
    if let Some(error) = error {
        spans.push(Span::styled(format!("✖ {error} "), theme.fg(Tone::Bad)));
    }
    Line::from(spans)
}

/// A bar of `width` cells split between `parts` in proportion to `total`,
/// each part drawn in its own character so it reads without colour.
fn share_bar<'a>(theme: &Theme, parts: &[(i64, char, Tone)], total: i64, width: u16) -> Line<'a> {
    let width = width as i64;
    let total = total.max(1);
    let mut spans = Vec::new();
    let mut used = 0;
    for (value, symbol, tone) in parts {
        let mut cells = (value.max(&0) * width / total).min(width - used);
        // Anything present shows, however small its share.
        if cells == 0 && *value > 0 && used < width {
            cells = 1;
        }
        if cells > 0 {
            spans.push(Span::styled(
                symbol.to_string().repeat(cells as usize),
                theme.fg(*tone),
            ));
            used += cells;
        }
    }
    if used < width {
        spans.push(Span::styled(
            "·".repeat((width - used) as usize),
            theme.fg(Tone::Muted),
        ));
    }
    Line::from(spans)
}

/// `2026-09-27 14:03`: a timestamp in UTC, to the minute.
fn when(at: time::OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        at.year(),
        at.month() as u8,
        at.day(),
        at.hour(),
        at.minute()
    )
}

/// A row of key hints for a panel's bottom border.
fn hints<'a>(theme: &Theme, keys: &[(&'a str, &'a str)]) -> Line<'a> {
    let mut line = crate::ui::widgets::key_hints(theme, keys);
    line.spans.insert(0, Span::raw(" "));
    line.spans.push(Span::raw(" "));
    line
}

/// `n` in bold, for counts inside sentences.
fn strong<'a>(theme: &Theme, text: String, tone: Tone) -> Span<'a> {
    Span::styled(text, theme.fg(tone).bold())
}
