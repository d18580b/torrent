//! One semantic palette for every screen.
//!
//! Screens ask for what a thing *is* — seeding, fenced, an error — and never
//! for a colour, so the palette changes in one place. Every state that has a
//! colour also has a symbol, so nothing is carried by colour alone: a
//! colour-blind operator, a monochrome terminal and `NO_COLOR` all read the
//! same screen.

use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;

/// How much colour the terminal gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    /// 24-bit colour (`COLORTERM=truecolor|24bit`).
    TrueColor,
    /// The 256-colour palette.
    Ansi256,
    /// No colour at all (`NO_COLOR` is set): attributes only.
    Mono,
}

impl Depth {
    /// What the environment asks for.
    pub fn detect() -> Self {
        Self::from_env(
            std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
            std::env::var("COLORTERM").ok().as_deref(),
        )
    }

    fn from_env(no_color: bool, colorterm: Option<&str>) -> Self {
        if no_color {
            Self::Mono
        } else if matches!(colorterm, Some("truecolor" | "24bit")) {
            Self::TrueColor
        } else {
            Self::Ansi256
        }
    }
}

/// A meaning something on screen has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Healthy and working: seeding, active, ready.
    Good,
    /// Needs attention but not broken: checking, paused, updating.
    Warn,
    /// Broken: errored, fenced, failed.
    Bad,
    /// Informational accent: selection, headings, the live badge.
    Accent,
    /// Present but unimportant: idle, unknown, secondary text.
    Muted,
    /// Ordinary text.
    Plain,
}

/// The palette.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub depth: Depth,
}

impl Theme {
    pub fn new(depth: Depth) -> Self {
        Self { depth }
    }

    fn color(&self, tone: Tone) -> Option<Color> {
        // Catppuccin Mocha where the terminal can show it, the nearest
        // 256-colour entries where it cannot.
        let (rgb, indexed) = match tone {
            Tone::Good => ((0xa6, 0xe3, 0xa1), 114),
            Tone::Warn => ((0xf9, 0xe2, 0xaf), 222),
            Tone::Bad => ((0xf3, 0x8b, 0xa8), 211),
            Tone::Accent => ((0x89, 0xb4, 0xfa), 111),
            Tone::Muted => ((0x6c, 0x70, 0x86), 243),
            Tone::Plain => ((0xcd, 0xd6, 0xf4), 189),
        };
        match self.depth {
            Depth::TrueColor => Some(Color::Rgb(rgb.0, rgb.1, rgb.2)),
            Depth::Ansi256 => Some(Color::Indexed(indexed)),
            Depth::Mono => None,
        }
    }

    /// Text in `tone`.
    pub fn fg(&self, tone: Tone) -> Style {
        let style = Style::default();
        match (self.color(tone), tone) {
            (Some(c), _) => style.fg(c),
            // Mono: carry the meaning in attributes instead.
            (None, Tone::Bad) => style.add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            (None, Tone::Accent) => style.add_modifier(Modifier::BOLD),
            (None, Tone::Muted) => style.add_modifier(Modifier::DIM),
            (None, _) => style,
        }
    }

    /// A heading.
    pub fn title(&self) -> Style {
        self.fg(Tone::Accent).add_modifier(Modifier::BOLD)
    }

    /// The selected row of a table or list.
    pub fn selected(&self) -> Style {
        match self.depth {
            Depth::TrueColor => Style::default()
                .bg(Color::Rgb(0x31, 0x32, 0x44))
                .add_modifier(Modifier::BOLD),
            Depth::Ansi256 => Style::default()
                .bg(Color::Indexed(237))
                .add_modifier(Modifier::BOLD),
            Depth::Mono => Style::default().add_modifier(Modifier::REVERSED),
        }
    }

    /// A key in the footer or help overlay.
    pub fn key(&self) -> Style {
        self.fg(Tone::Accent).add_modifier(Modifier::BOLD)
    }

    /// A border.
    pub fn border(&self, focused: bool) -> Style {
        if focused {
            self.fg(Tone::Accent)
        } else {
            self.fg(Tone::Muted)
        }
    }
}

/// A state's symbol and tone, so it reads without colour.
pub fn badge(state: &str) -> (&'static str, Tone) {
    match state {
        "seeding" | "active" | "working" | "ready" | "adopted" | "done" | "applied" => {
            ("●", Tone::Good)
        }
        "checking" | "awaiting_metadata" | "updating" | "applying" | "in_progress" | "partial"
        | "matched" | "shared" => ("◐", Tone::Warn),
        "paused" | "offline" | "draft" | "pending" | "skipped" | "not_contacted" => {
            ("‖", Tone::Warn)
        }
        // `incomplete`: pieces are missing and a seeder never fetches them,
        // so it stays there until an operator supplies the payload.
        "disk_error" | "errored" | "error" | "failed" | "vpn_down" | "drifted" | "overlap"
        | "incomplete" => ("✖", Tone::Bad),
        "missing" | "cancelled" | "removed" => ("○", Tone::Muted),
        _ => ("·", Tone::Muted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_wins_and_truecolor_is_asked_for() {
        assert_eq!(Depth::from_env(true, Some("truecolor")), Depth::Mono);
        assert_eq!(Depth::from_env(false, Some("truecolor")), Depth::TrueColor);
        assert_eq!(Depth::from_env(false, Some("24bit")), Depth::TrueColor);
        assert_eq!(Depth::from_env(false, None), Depth::Ansi256);
    }

    #[test]
    fn every_bad_state_is_marked_without_colour() {
        let mono = Theme::new(Depth::Mono);
        for state in [
            "errored",
            "disk_error",
            "failed",
            "vpn_down",
            "error",
            "incomplete",
        ] {
            let (symbol, tone) = badge(state);
            assert_eq!(tone, Tone::Bad, "{state}");
            assert_eq!(symbol, "✖");
            assert!(mono.fg(tone).add_modifier.contains(Modifier::BOLD));
        }
    }
}
