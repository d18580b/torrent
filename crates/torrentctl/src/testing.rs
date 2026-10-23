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
    with_api(&api(), server, f)
}

/// [`with_ctx`], with the effects `f` gets back aimed at `api` — a
/// [`Recorder`]'s, to see what they send.
pub fn with_api<R>(
    api: &Api,
    server: Option<&types::ServerInfo>,
    f: impl FnOnce(&Ctx<'_>) -> R,
) -> R {
    let theme = theme();
    let ctx = Ctx {
        api,
        server,
        theme: &theme,
        tick: 0,
    };
    f(&ctx)
}

/// One request a [`Recorder`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `METHOD /path?query`.
    pub line: String,
    /// The bearer token presented, if any.
    pub bearer: Option<String>,
}

/// A stand-in daemon: answers every request with one status and body, and
/// records what each asked for. It lives until the test process exits.
pub struct Recorder {
    pub url: String,
    requests: std::sync::Arc<std::sync::Mutex<Vec<Request>>>,
}

impl Recorder {
    /// Listen on a free loopback port, answering `status` (`"204 No
    /// Content"`) with `body`.
    pub fn start(status: &'static str, body: &str) -> Self {
        use std::io::Read as _;
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("an address"));
        let requests = std::sync::Arc::<std::sync::Mutex<Vec<Request>>>::default();
        let record = requests.clone();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nx-request-id: \
             feedface\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let Ok(mut socket) = socket else { continue };
                let mut received = Vec::new();
                let mut buf = [0u8; 65536];
                let head = loop {
                    let n = socket.read(&mut buf).unwrap_or(0);
                    received.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&received).into_owned();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if received.len() >= end + 4 + length {
                            break text[..end].to_owned();
                        }
                    }
                    if n == 0 {
                        break text;
                    }
                };
                let mut lines = head.lines();
                let line = lines
                    .next()
                    .unwrap_or_default()
                    .trim_end_matches(" HTTP/1.1")
                    .to_owned();
                let bearer = lines.find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    let value = value.trim();
                    (name.eq_ignore_ascii_case("authorization")
                        && value.len() > 7
                        && value[..7].eq_ignore_ascii_case("bearer "))
                    .then(|| value[7..].to_owned())
                });
                // Recorded before the answer, so an effect that has
                // finished has been recorded.
                record
                    .lock()
                    .expect("not poisoned")
                    .push(Request { line, bearer });
                let _ = socket.write_all(response.as_bytes());
            }
        });
        Self { url, requests }
    }

    /// An API handle aimed here, presenting `tdp_test`.
    pub fn api(&self) -> Api {
        Api::new(&self.url, Some("tdp_test")).expect("a valid URL")
    }

    /// Every request so far, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().expect("not poisoned").clone()
    }

    /// Every request line so far, `METHOD /path?query`, in arrival order.
    pub fn lines(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| r.line).collect()
    }
}

/// Run `effects` to completion, one after another, returning their
/// messages: what they send arrives at the [`Recorder`] they are aimed at in
/// the order given.
pub fn run(effects: Vec<crate::app::Effect>) -> Vec<crate::app::Msg> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    effects
        .into_iter()
        .map(|effect| runtime.block_on(effect.0))
        .collect()
}

/// The message an effect that needs no daemon — an `Effect::now`, such as a
/// toast — delivers.
pub fn deliver(effect: crate::app::Effect) -> crate::app::Msg {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime")
        .block_on(effect.0)
}

/// Serve one request with `status` and `body`, returning what was sent.
pub async fn serve_once(
    status: &'static str,
    body: String,
) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            received.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&received);
            if let Some(head_end) = text.find("\r\n\r\n") {
                let length = text[..head_end]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if received.len() >= head_end + 4 + length {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nx-request-id: \
             feedface\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&received).into_owned()
    });
    (url, handle)
}

/// A key press.
pub fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}
