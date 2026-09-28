//! Building blocks every screen draws with.

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

/// One page-at-a-time collection, loaded by following `next_cursor`.
#[derive(Debug, Clone)]
pub struct Paged<T> {
    pub items: Vec<T>,
    /// Where the next page starts; `None` once everything is loaded.
    pub next_cursor: Option<String>,
    /// Whether everything has been loaded at least once.
    pub complete: bool,
    pub loading: bool,
    pub error: Option<String>,
    /// Bumped on every reload, so a page answering an older reload is
    /// dropped rather than appended to a list it no longer belongs to.
    pub generation: u64,
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
        }
    }
}

impl<T> Paged<T> {
    /// Start over from the first page; returns the generation to tag the
    /// request with.
    pub fn reload(&mut self) -> u64 {
        self.generation += 1;
        self.loading = true;
        self.error = None;
        self.generation
    }

    /// Whether another page should be fetched for a view whose selection is
    /// at `selected`: near the end of what is loaded, with more to load.
    pub fn wants_more(&self, selected: usize) -> bool {
        !self.loading && self.next_cursor.is_some() && selected + 20 >= self.items.len()
    }

    /// Start fetching the next page; returns the cursor and generation.
    pub fn begin_more(&mut self) -> Option<(String, u64)> {
        let cursor = self.next_cursor.clone()?;
        self.loading = true;
        Some((cursor, self.generation))
    }

    /// Take in a page answering `generation`. `first` replaces what is
    /// loaded; any later page appends.
    pub fn receive(&mut self, generation: u64, first: bool, items: Vec<T>, next: Option<String>) {
        if generation != self.generation {
            return;
        }
        if first {
            self.items = items;
        } else {
            self.items.extend(items);
        }
        self.next_cursor = next;
        self.complete = self.next_cursor.is_none();
        self.loading = false;
        self.error = None;
    }

    /// A page for `generation` failed.
    pub fn fail(&mut self, generation: u64, error: String) {
        if generation == self.generation {
            self.loading = false;
            self.error = Some(error);
        }
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
        let old = p.reload();
        let new = p.reload();
        p.receive(old, true, vec![1], None);
        assert!(p.items.is_empty() && p.loading, "stale page ignored");
        p.receive(new, true, vec![1, 2], Some("c".into()));
        assert_eq!(p.items, [1, 2]);
        assert!(!p.complete && p.wants_more(1));
        let (cursor, generation) = p.begin_more().unwrap();
        assert_eq!(cursor, "c");
        assert!(!p.wants_more(1), "one page at a time");
        p.receive(generation, false, vec![3], None);
        assert_eq!(p.items, [1, 2, 3]);
        assert!(p.complete && !p.wants_more(2));
    }
}
