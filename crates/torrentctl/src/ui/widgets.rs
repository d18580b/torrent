//! Building blocks every screen draws with.

use std::cell::Cell;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Constraint;
use ratatui::layout::Flex;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::BorderType;
use ratatui::widgets::Borders;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use ratatui::Frame;
use tui_input::backend::crossterm::EventHandler as _;
use tui_input::Input;

use crate::theme::badge;
use crate::theme::Theme;
use crate::theme::Tone;

/// A rounded, titled panel.
pub fn panel<'a>(theme: &Theme, title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border(focused))
        .title(title.into().style(theme.title()))
}

/// A state as a symbol and a word in its tone.
pub fn state_span<'a>(theme: &Theme, state: &str) -> Span<'a> {
    let (symbol, tone) = badge(state);
    Span::styled(format!("{symbol} {state}"), theme.fg(tone))
}

/// A frame of the spinner for render tick `tick`.
pub fn spinner(tick: u64) -> &'static str {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    FRAMES[(tick % FRAMES.len() as u64) as usize]
}

/// A `width` × `height` rectangle centred in `area`.
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [cell] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(row);
    cell
}

/// A line of `key action` pairs for the footer.
pub fn key_hints<'a>(theme: &Theme, keys: &[(&'a str, &'a str)]) -> Line<'a> {
    let mut spans = Vec::with_capacity(keys.len() * 3);
    for (i, (key, action)) in keys.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", theme.fg(Tone::Muted)));
        }
        spans.push(Span::styled(*key, theme.key()));
        spans.push(Span::styled(format!(" {action}"), theme.fg(Tone::Muted)));
    }
    Line::from(spans)
}

/// A message for an empty or failed panel, centred.
pub fn placeholder(frame: &mut Frame, area: Rect, theme: &Theme, text: &str, tone: Tone) {
    let inner = centered(area, area.width.saturating_sub(4), 3);
    frame.render_widget(
        Paragraph::new(text.to_owned())
            .style(theme.fg(tone))
            .centered()
            .wrap(Wrap { trim: true }),
        inner,
    );
}

/// What the daemon allows one request, in one place. Each is the daemon's own
/// limit restated: asking past one is refused, so the client holds itself to
/// it before sending.
pub mod caps {
    /// Rows a list asks for per page when paging on, and the least a reload
    /// asks for. The daemon's `DEFAULT_LIMIT`.
    pub const PAGE: usize = 100;
    /// The most rows one list request may ask for: the daemon's `MAX_LIMIT`
    /// on every paged listing (`limit` is `1..=1000`). A reload holding more
    /// than this re-reads them in several requests; see [`super::Paged`].
    pub const PAGE_MAX: usize = 1000;
    /// The most infohashes one adopt or verify request may name: the
    /// daemon's `MAX_INFOHASHES`.
    pub const MAX_BATCH: usize = 1000;
    /// The largest `.torrent` the daemon takes, decoded: its
    /// `MAX_TORRENT_FILE_BYTES`.
    pub const MAX_METAINFO: u64 = 64 * 1024 * 1024;
}

/// One request for a page: from `cursor` (the first page when `None`), at
/// most `limit` rows, tagged with the `generation` it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub cursor: Option<String>,
    pub limit: usize,
    pub generation: u64,
}

/// What [`Paged::receive`] made of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Received {
    /// The page answered an older reload, and was dropped.
    Stale,
    /// A reload has not yet re-read as many rows as were loaded: fetch this
    /// next. What is shown is unchanged until it has.
    Continue(PageRequest),
    /// [`Paged::items`] changed: settle the selection against it.
    Settled,
}

/// A list loaded a page at a time by following `next_cursor`, and reloaded
/// without losing the operator's place.
///
/// The policy every list screen shares:
///
/// - **Paging on.** [`Paged::wants_more`] asks for the next page of
///   [`caps::PAGE`] rows once the selection nears the end of what is loaded.
/// - **Reloading.** [`Paged::reload`] re-reads from the first page as many
///   rows as are loaded — rounded up to a whole page, at most
///   [`caps::PAGE_MAX`] a request — following the cursor until it has them
///   all or the list ends. What is shown stays as it was until then, so a
///   refresh neither shrinks the list nor moves the selection, at any size;
///   a failed reload leaves it as it was.
/// - **Staleness.** Each reload bumps [`Paged::generation`]; a page tagged
///   with an older one is dropped.
#[derive(Debug, Clone)]
pub struct Paged<T> {
    /// What is shown.
    pub items: Vec<T>,
    /// Where the page after [`Paged::items`] starts; `None` once the last
    /// page is loaded.
    pub next_cursor: Option<String>,
    /// Whether the last page is loaded: `next_cursor` is `None`.
    pub complete: bool,
    /// A request is in flight.
    pub loading: bool,
    /// Why the last request failed, until one succeeds.
    pub error: Option<String>,
    /// Bumped on every reload, so a page answering an older reload is
    /// dropped rather than appended to a list it no longer belongs to.
    pub generation: u64,
    /// The reload in flight: the rows it has re-read, and how many it wants.
    refill: Option<Refill<T>>,
}

#[derive(Debug, Clone)]
struct Refill<T> {
    items: Vec<T>,
    want: usize,
}

impl<T> Default for Paged<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            complete: false,
            loading: false,
            error: None,
            generation: 0,
            refill: None,
        }
    }
}

/// How many rows to ask for when `want` are wanted: a whole number of
/// pages, within one request's reach.
fn limit_for(want: usize) -> usize {
    (want.div_ceil(caps::PAGE) * caps::PAGE).clamp(caps::PAGE, caps::PAGE_MAX)
}

impl<T> Paged<T> {
    /// Forget what is loaded: the list now means something else (another
    /// filter, another directory). Follow with [`Paged::reload`].
    pub fn reset(&mut self) {
        self.items.clear();
        self.next_cursor = None;
        self.complete = false;
        self.refill = None;
    }

    /// Start over from the first page, re-reading as many rows as are
    /// loaded; returns the first request.
    pub fn reload(&mut self) -> PageRequest {
        self.generation += 1;
        self.loading = true;
        self.error = None;
        let want = self.items.len();
        self.refill = Some(Refill {
            items: Vec::new(),
            want,
        });
        PageRequest {
            cursor: None,
            limit: limit_for(want),
            generation: self.generation,
        }
    }

    /// Whether another page should be fetched for a view whose selection is
    /// at `selected`: near the end of what is loaded, with more to load.
    pub fn wants_more(&self, selected: usize) -> bool {
        !self.loading && self.next_cursor.is_some() && selected + 20 >= self.items.len()
    }

    /// Start fetching the page after what is loaded; `None` while a request
    /// is in flight or when there is none.
    pub fn begin_more(&mut self) -> Option<PageRequest> {
        if self.loading {
            return None;
        }
        let cursor = self.next_cursor.clone()?;
        self.loading = true;
        Some(PageRequest {
            cursor: Some(cursor),
            limit: caps::PAGE,
            generation: self.generation,
        })
    }

    /// Take in a page answering `generation`; `first` when it is a first
    /// page. A reload's pages are gathered aside and replace what is shown
    /// only once they hold as many rows as it did, or the list ends; any
    /// other page appends.
    pub fn receive(
        &mut self,
        generation: u64,
        first: bool,
        items: Vec<T>,
        next: Option<String>,
    ) -> Received {
        if generation != self.generation {
            return Received::Stale;
        }
        match self.refill.as_mut() {
            Some(refill) => {
                if first {
                    refill.items = items;
                } else {
                    refill.items.extend(items);
                }
                let short = refill.want.saturating_sub(refill.items.len());
                if let (Some(cursor), true) = (&next, short > 0) {
                    return Received::Continue(PageRequest {
                        cursor: Some(cursor.clone()),
                        limit: limit_for(short),
                        generation,
                    });
                }
                self.items = std::mem::take(&mut refill.items);
                self.refill = None;
            }
            None if first => self.items = items,
            None => self.items.extend(items),
        }
        self.next_cursor = next;
        self.complete = self.next_cursor.is_none();
        self.loading = false;
        self.error = None;
        Received::Settled
    }

    /// A page for `generation` failed. A reload in flight is abandoned and
    /// what is shown kept. Whether it was the request in flight: when it
    /// was, a selection the screen meant to restore once it settled will
    /// never be restored, and must be forgotten.
    pub fn fail(&mut self, generation: u64, error: String) -> bool {
        if generation != self.generation {
            return false;
        }
        self.loading = false;
        self.refill = None;
        self.error = Some(error);
        true
    }
}

/// What a confirmation dialog decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmed {
    Yes,
    No,
    /// Still deciding.
    Pending,
}

/// A yes/no question, optionally demanding the operator type a word back —
/// for anything that deletes data.
#[derive(Debug, Clone, Default)]
pub struct Confirm {
    pub title: String,
    pub body: String,
    /// When set, `Enter` confirms only once the input equals this.
    pub typed: Option<String>,
    pub input: Input,
}

impl Confirm {
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            typed: None,
            input: Input::default(),
        }
    }

    /// Require `word` to be typed before confirming.
    pub fn typed(mut self, word: impl Into<String>) -> Self {
        self.typed = Some(word.into());
        self
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Confirmed {
        match (key.code, &self.typed) {
            (KeyCode::Esc, _) => Confirmed::No,
            (KeyCode::Char('n' | 'N'), None) => Confirmed::No,
            // Not `Enter`: the key that opened the dialog, repeated or
            // double-tapped, must not also answer it.
            (KeyCode::Char('y' | 'Y'), None) => Confirmed::Yes,
            (KeyCode::Enter, Some(word)) if self.input.value() == word => Confirmed::Yes,
            (KeyCode::Enter, Some(_)) => Confirmed::Pending,
            (_, Some(_)) => {
                self.input.handle_event(&crossterm::event::Event::Key(key));
                Confirmed::Pending
            }
            _ => Confirmed::Pending,
        }
    }

    pub fn view(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let width: u16 = 64;
        let body_lines = (self.body.chars().count() as u16)
            .div_ceil(width - 2)
            .max(1);
        let height = body_lines + if self.typed.is_some() { 7 } else { 5 };
        let rect = centered(area, width, height);
        frame.render_widget(Clear, rect);
        let block = panel(theme, format!(" {} ", self.title), true);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let mut lines = vec![Line::from(self.body.clone()), Line::from("")];
        match &self.typed {
            Some(word) => {
                lines.push(Line::from(vec![
                    "Type ".into(),
                    Span::styled(word.clone(), theme.fg(Tone::Bad).bold()),
                    " to confirm:".into(),
                ]));
                lines.push(Line::from(Span::styled(
                    format!("› {}", self.input.value()),
                    theme.fg(Tone::Accent),
                )));
                lines.push(key_hints(theme, &[("Enter", "confirm"), ("Esc", "cancel")]));
            }
            None => lines.push(key_hints(theme, &[("y", "yes"), ("n/Esc", "no")])),
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
    }
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

    /// The move a key asks for: `j`/`k` and the arrows a row, `g`/`G` and
    /// Home/End the ends, PageUp/PageDown a page.
    pub fn from_key(key: KeyEvent) -> Option<Motion> {
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
    pub fn apply(self, at: usize, len: usize) -> usize {
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

/// The first row to draw, of `len`, so `selected` stays in view in a window
/// of `rows`, moving the window only as far as it must: scrolling is steady
/// rather than re-centred. A list that shrank pulls the window back so it
/// stays full rather than showing its last row alone at the top.
pub fn scroll(offset: &Cell<usize>, selected: usize, rows: usize, len: usize) -> usize {
    let mut at = offset.get().min(len.saturating_sub(rows));
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
pub fn title<'a>(
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
pub fn share_bar<'a>(
    theme: &Theme,
    parts: &[(i64, char, Tone)],
    total: i64,
    width: u16,
) -> Line<'a> {
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

/// A row of key hints for a panel's bottom border.
pub fn hints<'a>(theme: &Theme, keys: &[(&'a str, &'a str)]) -> Line<'a> {
    let mut line = key_hints(theme, keys);
    line.spans.insert(0, Span::raw(" "));
    line.spans.push(Span::raw(" "));
    line
}

/// `n` in bold, for counts inside sentences.
pub fn strong<'a>(theme: &Theme, text: String, tone: Tone) -> Span<'a> {
    Span::styled(text, theme.fg(tone).bold())
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyModifiers;

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn a_typed_confirmation_needs_the_word_exactly() {
        let mut c = Confirm::new("Delete", "really?").typed("delete");
        assert_eq!(c.on_key(key(KeyCode::Enter)), Confirmed::Pending);
        assert_eq!(
            c.on_key(key(KeyCode::Char('y'))),
            Confirmed::Pending,
            "y is typed, not a yes"
        );
        for ch in "elete".chars() {
            c.on_key(key(KeyCode::Char(ch)));
        }
        assert_eq!(c.input.value(), "yelete");
        c.input = Input::new("delete".into());
        assert_eq!(c.on_key(key(KeyCode::Enter)), Confirmed::Yes);
        assert_eq!(c.on_key(key(KeyCode::Esc)), Confirmed::No);
    }

    #[test]
    fn only_y_answers_an_untyped_confirmation() {
        let mut c = Confirm::new("Remove", "really?");
        assert_eq!(
            c.on_key(key(KeyCode::Enter)),
            Confirmed::Pending,
            "the Enter that opened it, repeated"
        );
        assert_eq!(c.on_key(key(KeyCode::Char('y'))), Confirmed::Yes);
        assert_eq!(c.on_key(key(KeyCode::Char('n'))), Confirmed::No);
    }

    #[test]
    fn a_page_from_an_old_reload_is_dropped() {
        let mut p: Paged<u32> = Paged::default();
        let old = p.reload().generation;
        let new = p.reload().generation;
        assert_eq!(p.receive(old, true, vec![1], None), Received::Stale);
        assert!(p.items.is_empty() && p.loading, "stale page ignored");
        assert_eq!(
            p.receive(new, true, vec![1, 2], Some("c".into())),
            Received::Settled
        );
        assert_eq!(p.items, [1, 2]);
        assert!(!p.complete && p.wants_more(1));
        let more = p.begin_more().unwrap();
        assert_eq!(more.cursor.as_deref(), Some("c"));
        assert_eq!(more.limit, caps::PAGE);
        assert!(!p.wants_more(1), "one page at a time");
        assert!(p.begin_more().is_none(), "nor a second request in flight");
        assert_eq!(
            p.receive(more.generation, false, vec![3], None),
            Received::Settled
        );
        assert_eq!(p.items, [1, 2, 3]);
        assert!(p.complete && !p.wants_more(2));
    }

    /// `n` rows, numbered from `from`.
    fn rows(from: usize, n: usize) -> Vec<usize> {
        (from..from + n).collect()
    }

    /// A list of `n` rows, loaded.
    fn loaded(n: usize) -> Paged<usize> {
        let mut p = Paged::default();
        let first = p.reload();
        assert_eq!(
            p.receive(first.generation, true, rows(0, n), Some("more".into())),
            Received::Settled
        );
        p
    }

    #[test]
    fn a_reload_past_one_request_pages_up_to_what_was_loaded_and_keeps_it_meanwhile() {
        let mut p = loaded(2500);
        let first = p.reload();
        assert_eq!(first.cursor, None);
        assert_eq!(first.limit, caps::PAGE_MAX, "one request's reach");

        let next = p.receive(first.generation, true, rows(0, 1000), Some("k1000".into()));
        let Received::Continue(next) = next else {
            panic!("pages on towards the 2500 loaded: {next:?}");
        };
        assert_eq!(next.cursor.as_deref(), Some("k1000"));
        assert_eq!(next.limit, caps::PAGE_MAX);
        assert_eq!(
            p.items.len(),
            2500,
            "what is shown stays until it is all re-read"
        );
        assert!(p.loading && !p.wants_more(2499));

        let last = p.receive(
            next.generation,
            false,
            rows(1000, 1000),
            Some("k2000".into()),
        );
        let Received::Continue(last) = last else {
            panic!("500 short still: {last:?}");
        };
        assert_eq!(last.limit, 500, "the shortfall, as whole pages");
        assert_eq!(
            p.receive(
                last.generation,
                false,
                rows(2000, 500),
                Some("k2500".into())
            ),
            Received::Settled
        );
        assert_eq!(p.items, rows(0, 2500));
        assert_eq!(
            p.next_cursor.as_deref(),
            Some("k2500"),
            "paging on continues"
        );
        assert!(!p.loading && !p.complete);
    }

    #[test]
    fn a_reload_of_a_list_that_shrank_settles_at_its_end() {
        let mut p = loaded(1500);
        let first = p.reload();
        assert_eq!(
            p.receive(first.generation, true, rows(0, 600), None),
            Received::Settled
        );
        assert_eq!(p.items.len(), 600);
        assert!(p.complete);
    }

    #[test]
    fn a_failed_reload_keeps_what_is_shown() {
        let mut p = loaded(1500);
        let first = p.reload();
        assert!(matches!(
            p.receive(first.generation, true, rows(0, 1000), Some("k".into())),
            Received::Continue(_)
        ));
        p.fail(first.generation, "boom".into());
        assert_eq!(p.items, rows(0, 1500));
        assert_eq!(p.error.as_deref(), Some("boom"));
        assert!(!p.loading);
        let again = p.reload();
        assert_eq!(again.limit, caps::PAGE_MAX);
        assert_eq!(
            p.receive(again.generation, true, rows(7, 1000), None),
            Received::Settled,
            "a fresh reload starts its own gathering, not the abandoned one's"
        );
        assert_eq!(p.items, rows(7, 1000));
    }

    #[test]
    fn a_reload_asks_for_whole_pages() {
        let mut p: Paged<usize> = Paged::default();
        assert_eq!(p.reload().limit, caps::PAGE, "nothing loaded: one page");
        let mut p = loaded(250);
        assert_eq!(p.reload().limit, 300);
        p.reset();
        assert!(p.items.is_empty() && p.next_cursor.is_none());
        assert_eq!(p.reload().limit, caps::PAGE);
    }

    #[test]
    fn a_list_that_shrank_scrolls_back_to_fill_its_window() {
        let offset = Cell::new(50);
        assert_eq!(
            scroll(&offset, 9, 20, 10),
            0,
            "ten rows fit a twenty-row window from the top"
        );
        assert_eq!(offset.get(), 0);
        let offset = Cell::new(50);
        assert_eq!(scroll(&offset, 39, 20, 40), 20, "the last twenty rows");
        let offset = Cell::new(5);
        assert_eq!(scroll(&offset, 10, 20, 100), 5, "steady, not re-centred");
    }
}
