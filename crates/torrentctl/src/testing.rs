//! Rendering and driving screens in tests, with no terminal and no daemon.

use ratatui::backend::TestBackend;
use ratatui::layout::Rect;
use ratatui::Frame;
use ratatui::Terminal;

use crate::api::types;
use crate::api::Api;
use crate::app::Ctx;
use crate::theme::Depth;
use crate::theme::Theme;

/// An API handle pointed at a port nothing listens on: a test that
/// accidentally awaits an effect fails fast instead of reaching a daemon.
pub fn api() -> Api {
    Api::new("http://127.0.0.1:9", Some("tdp_test")).expect("a valid URL")
}

/// Snapshots render without colour, so they record layout and symbols — the
/// things a colour change must not move.
pub fn theme() -> Theme {
    Theme::new(Depth::Mono)
}

/// A `ServerInfo` from JSON-ish parts.
pub fn server(pool: bool, mutations: bool) -> types::ServerInfo {
    serde_json::from_value(serde_json::json!({
        "version": "0.1.0", "api_version": "1",
        "auth": {"mode": "password", "session_ttl_secs": 43200},
        "pool": {"configured": pool, "allow_mutations": mutations},
    }))
    .expect("a valid ServerInfo")
}

/// Any generated type from JSON, for fixtures.
pub fn from_json<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).expect("fixture matches the generated type")
}

/// Render `draw` into a `width` × `height` buffer and return its text, one
/// line per row, trailing spaces trimmed.
pub fn render(
    width: u16,
    height: u16,
    server: Option<&types::ServerInfo>,
    draw: impl FnOnce(&Ctx<'_>, &mut Frame, Rect),
) -> String {
    let api = api();
    let theme = theme();
    let ctx = Ctx {
        api: &api,
        server,
        theme: &theme,
        tick: 0,
    };
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a test terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            draw(&ctx, frame, area);
        })
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buffer.area.height {
        let mut line = String::new();
        for x in 0..buffer.area.width {
            line.push_str(buffer[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Run `f` with a context over `server`, for driving `update`.
pub fn with_ctx<R>(server: Option<&types::ServerInfo>, f: impl FnOnce(&Ctx<'_>) -> R) -> R {
    let api = api();
    let theme = theme();
    let ctx = Ctx {
        api: &api,
        server,
        theme: &theme,
        tick: 0,
    };
    f(&ctx)
}

/// A key press.
pub fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}
