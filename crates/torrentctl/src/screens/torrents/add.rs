//! The add-torrent dialog: a source (magnet, a path on the server, or a
//! local `.torrent`), an active profile, and an optional save path.

use std::path::PathBuf;

use base64::Engine as _;
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use ratatui::Frame;
use tui_input::backend::crossterm::EventHandler as _;
use tui_input::Input;

use crate::api::generated::Credential;
use crate::api::generated::ExposeSecret as _;
use crate::api::types;
use crate::api::Api;
use crate::api::Failure;
use crate::fmt;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::centered;
use crate::ui::widgets::key_hints;
use crate::ui::widgets::panel;
use crate::ui::widgets::spinner;

/// The largest `.torrent` the daemon takes, decoded.
pub const MAX_METAINFO: u64 = 64 * 1024 * 1024;

/// Where the torrent's metadata comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceKind {
    #[default]
    Magnet,
    /// A `.torrent` on the daemon's filesystem.
    ServerPath,
    /// A `.torrent` on this machine, sent in the request.
    LocalFile,
}

impl SourceKind {
    const ALL: [SourceKind; 3] = [
        SourceKind::Magnet,
        SourceKind::ServerPath,
        SourceKind::LocalFile,
    ];

    fn label(self) -> &'static str {
        match self {
            SourceKind::Magnet => "magnet",
            SourceKind::ServerPath => "path on server",
            SourceKind::LocalFile => "local .torrent",
        }
    }

    fn field_label(self) -> &'static str {
        match self {
            SourceKind::Magnet => "magnet URI",
            SourceKind::ServerPath => "server path",
            SourceKind::LocalFile => "local file",
        }
    }

    fn step(self, forward: bool) -> Self {
        let at = Self::ALL.iter().position(|k| *k == self).unwrap_or(0);
        let n = Self::ALL.len();
        Self::ALL[if forward {
            (at + 1) % n
        } else {
            (at + n - 1) % n
        }]
    }
}

/// The dialog's rows, top to bottom.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Field {
    Kind,
    #[default]
    Source,
    Profile,
    SavePath,
}

impl Field {
    const ALL: [Field; 4] = [Field::Kind, Field::Source, Field::Profile, Field::SavePath];

    fn step(self, forward: bool) -> Self {
        let at = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        let n = Self::ALL.len();
        Self::ALL[if forward {
            (at + 1) % n
        } else {
            (at + n - 1) % n
        }]
    }
}

/// What is wrong, field by field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldErrors {
    pub source: Option<String>,
    pub profile: Option<String>,
    pub save_path: Option<String>,
    /// What belongs to no one field.
    pub general: Option<String>,
}

impl FieldErrors {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn set(&mut self, field: Field, message: String) {
        match field {
            Field::Kind | Field::Source => self.source = Some(message),
            Field::Profile => self.profile = Some(message),
            Field::SavePath => self.save_path = Some(message),
        }
    }
}

/// The dialog.
#[derive(Debug, Default)]
pub struct Dialog {
    pub kind: SourceKind,
    pub focus: Field,
    pub source: Input,
    pub save_path: Input,
    /// The chosen profile; only an `active` one may be chosen.
    pub profile: Option<String>,
    /// A request is in flight.
    pub submitting: bool,
    pub errors: FieldErrors,
}

/// What a key did to the dialog.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Cancel,
    Submit,
}

/// A validated request, before any file is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub profile: String,
    pub save_path: Option<String>,
    pub source: Source,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Magnet(String),
    ServerPath(String),
    LocalFile(PathBuf),
}

/// Why an add did not succeed.
#[derive(Debug)]
pub enum AddFailure {
    /// Refused before anything was sent, against a field.
    Local { field: Field, message: String },
    /// The daemon refused it. `errors` are a `validation-failed` problem's
    /// `(pointer, detail)` pairs, where they could be read.
    Api {
        failure: Failure,
        errors: Vec<(String, String)>,
    },
}

impl Dialog {
    /// A dialog preselecting `profile`, the list's profile filter, when it
    /// is one of `active`. Otherwise nothing is chosen: a torrent added to
    /// the wrong profile announces one account's passkey from another
    /// account's session, so the operator picks.
    pub fn new(profile: Option<&str>, active: &[String]) -> Self {
        let profile = profile
            .filter(|p| active.iter().any(|a| a == p))
            .map(str::to_owned);
        Self {
            profile,
            ..Self::default()
        }
    }

    /// Drop a choice that is no longer active, now that `active` has
    /// arrived.
    pub fn profiles_arrived(&mut self, active: &[String]) {
        if self.profile.as_ref().is_some_and(|p| !active.contains(p)) {
            self.profile = None;
        }
    }

    pub fn on_key(&mut self, key: KeyEvent, active: &[String]) -> Outcome {
        if self.submitting {
            // Nothing to edit while the daemon decides; Esc still leaves.
            return if key.code == KeyCode::Esc {
                Outcome::Cancel
            } else {
                Outcome::Pending
            };
        }
        match key.code {
            KeyCode::Esc => return Outcome::Cancel,
            KeyCode::Enter => return Outcome::Submit,
            KeyCode::Up => self.focus = self.focus.step(false),
            KeyCode::Down => self.focus = self.focus.step(true),
            KeyCode::Left | KeyCode::Right if matches!(self.focus, Field::Kind) => {
                self.kind = self.kind.step(key.code == KeyCode::Right);
                self.errors.source = None;
            }
            KeyCode::Left | KeyCode::Right if matches!(self.focus, Field::Profile) => {
                self.profile =
                    step_profile(self.profile.as_deref(), active, key.code == KeyCode::Right);
                self.errors.profile = None;
            }
            _ => match self.focus {
                Field::Source => {
                    self.source.handle_event(&crossterm::event::Event::Key(key));
                    self.errors.source = None;
                }
                Field::SavePath => {
                    self.save_path
                        .handle_event(&crossterm::event::Event::Key(key));
                    self.errors.save_path = None;
                }
                Field::Kind | Field::Profile => {}
            },
        }
        Outcome::Pending
    }

    /// Check what can be checked here; on failure, the errors are set on
    /// the dialog and focus moves to the first field at fault.
    pub fn validate(&mut self, active: &[String]) -> Option<Request> {
        let mut errors = FieldErrors::default();
        let source = self.source.value().trim().to_owned();
        let source = match self.kind {
            _ if source.is_empty() => {
                errors.source = Some(format!("enter a {}", self.kind.field_label()));
                None
            }
            SourceKind::Magnet if !source.starts_with("magnet:?") => {
                errors.source = Some("a magnet URI starts with `magnet:?`".to_owned());
                None
            }
            SourceKind::Magnet => Some(Source::Magnet(source)),
            SourceKind::ServerPath if !source.starts_with('/') => {
                errors.source = Some("the daemon needs an absolute path".to_owned());
                None
            }
            SourceKind::ServerPath => Some(Source::ServerPath(source)),
            SourceKind::LocalFile => Some(Source::LocalFile(expand_home(&source))),
        };
        let profile = match &self.profile {
            Some(p) if active.contains(p) => Some(p.clone()),
            Some(p) => {
                errors.profile = Some(format!(
                    "{p} is not active; only an active profile can take a torrent"
                ));
                None
            }
            None if active.is_empty() => {
                errors.profile =
                    Some("no profile is active, so none can take a torrent".to_owned());
                None
            }
            None => {
                errors.profile = Some("choose a profile".to_owned());
                None
            }
        };
        let save_path = self.save_path.value().trim().to_owned();
        if !save_path.is_empty() && !save_path.starts_with('/') {
            errors.save_path = Some("the daemon needs an absolute path".to_owned());
        }
        match (source, profile, errors.is_empty()) {
            (Some(source), Some(profile), true) => {
                self.errors = FieldErrors::default();
                Some(Request {
                    profile,
                    save_path: (!save_path.is_empty()).then_some(save_path),
                    source,
                })
            }
            _ => {
                self.focus = if errors.source.is_some() {
                    Field::Source
                } else if errors.profile.is_some() {
                    Field::Profile
                } else {
                    Field::SavePath
                };
                self.errors = errors;
                None
            }
        }
    }

    /// Show a failed add against the field at fault.
    pub fn show_failure(&mut self, failure: AddFailure) {
        self.submitting = false;
        let mut errors = FieldErrors::default();
        match failure {
            AddFailure::Local { field, message } => errors.set(field, message),
            AddFailure::Api {
                failure,
                errors: pointers,
            } => {
                let message = failure.message();
                match failure.slug.as_deref() {
                    Some("path-not-confined") => {
                        for field in self.confinement_fields(failure.detail.as_deref()) {
                            errors.set(field, message.clone());
                        }
                    }
                    Some("invalid-metainfo") => errors.source = Some(message),
                    Some("tracker-not-allowed" | "profile-unavailable" | "profile-not-found") => {
                        errors.profile = Some(message);
                    }
                    Some("validation-failed") if !pointers.is_empty() => {
                        for (pointer, detail) in pointers {
                            match pointer.as_str() {
                                "/save_path" => errors.set(Field::SavePath, detail),
                                "/profile_id" => errors.set(Field::Profile, detail),
                                p if p.starts_with("/source") => errors.set(Field::Source, detail),
                                _ => {
                                    errors.general = Some(match errors.general.take() {
                                        Some(g) => format!("{g}; {pointer}: {detail}"),
                                        None => format!("{pointer}: {detail}"),
                                    });
                                }
                            }
                        }
                    }
                    _ => errors.general = Some(message),
                }
            }
        }
        self.errors = errors;
    }

    /// Which fields a `path-not-confined` is about. Only a server-path
    /// source and a save path are paths; when both were sent, the detail's
    /// wording is the only hint, and without it both are marked.
    fn confinement_fields(&self, detail: Option<&str>) -> Vec<Field> {
        let server = matches!(self.kind, SourceKind::ServerPath);
        let save = !self.save_path.value().trim().is_empty();
        match (server, save) {
            (true, false) => vec![Field::Source],
            (false, _) => vec![Field::SavePath],
            (true, true) => match detail {
                Some(d) if d.contains("save_path") => vec![Field::SavePath],
                Some(d) if d.contains("server_path") => vec![Field::Source],
                _ => vec![Field::Source, Field::SavePath],
            },
        }
    }
}

fn step_profile(current: Option<&str>, active: &[String], forward: bool) -> Option<String> {
    if active.is_empty() {
        return None;
    }
    let n = active.len();
    let next = match current.and_then(|c| active.iter().position(|a| a == c)) {
        Some(at) if forward => (at + 1) % n,
        Some(at) => (at + n - 1) % n,
        None => 0,
    };
    Some(active[next].clone())
}

/// `~/x` as `$HOME/x`; anything else as written.
fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(path),
    }
}

/// Send `request`, reading a local `.torrent` first.
#[allow(
    clippy::result_large_err,
    reason = "an AddFailure is built once per failed add and moved straight to the dialog"
)]
pub async fn submit(api: Api, request: Request) -> Result<types::Torrent, AddFailure> {
    // A typed request's `validation-failed` carries its violations too, so
    // they land on their fields whichever way the torrent was sent.
    let api_failure = |failure: Failure| AddFailure::Api {
        errors: failure.errors.clone(),
        failure,
    };
    let source = match request.source {
        Source::Magnet(uri) => {
            types::TorrentSource::TorrentSourceVariant0(Box::new(types::TorrentSourceVariant0 {
                kind: types::TorrentSourceVariant0kind::Magnet,
                uri,
            }))
        }
        Source::ServerPath(path) => {
            types::TorrentSource::TorrentSourceVariant1(Box::new(types::TorrentSourceVariant1 {
                kind: types::TorrentSourceVariant1kind::ServerPath,
                path,
            }))
        }
        Source::LocalFile(path) => {
            let data = read_metainfo(&path).await?;
            return post_metainfo(&api, &request.profile, request.save_path.as_deref(), &data)
                .await;
        }
    };
    let body = types::AddTorrentRequest {
        profile_id: request.profile,
        save_path: request.save_path,
        source,
    };
    crate::api::call(api.client.add_torrent(&body))
        .await
        .map_err(api_failure)
}

/// A local `.torrent`'s bytes, refused over [`MAX_METAINFO`].
#[allow(
    clippy::result_large_err,
    reason = "an AddFailure is built once per failed add and moved straight to the dialog"
)]
async fn read_metainfo(path: &std::path::Path) -> Result<Vec<u8>, AddFailure> {
    let local = |message: String| AddFailure::Local {
        field: Field::Source,
        message,
    };
    let shown = path.display();
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| local(format!("cannot read {shown}: {e}")))?;
    if !meta.is_file() {
        return Err(local(format!("{shown} is not a file")));
    }
    if meta.len() > MAX_METAINFO {
        return Err(local(format!(
            "{shown} is {}; the daemon takes a .torrent of at most {}",
            fmt::bytes(meta.len() as i64),
            fmt::bytes(MAX_METAINFO as i64)
        )));
    }
    tokio::fs::read(path)
        .await
        .map_err(|e| local(format!("cannot read {shown}: {e}")))
}

/// `POST /v1/torrents` with a `metainfo` source, built by hand.
///
/// The generated `TorrentSourceVariant2::data` is a `bytes::Bytes`, which
/// serializes as a JSON array of numbers rather than the base64 string the
/// API document declares, so the typed `add_torrent` cannot send a
/// `.torrent`. This sends the same request with the data base64-encoded,
/// through the client's own HTTP client, base URL and credential.
#[allow(
    clippy::result_large_err,
    reason = "an AddFailure is built once per failed add and moved straight to the dialog"
)]
async fn post_metainfo(
    api: &Api,
    profile: &str,
    save_path: Option<&str>,
    data: &[u8],
) -> Result<types::Torrent, AddFailure> {
    let mut body = serde_json::json!({
        "profile_id": profile,
        "source": {
            "kind": "metainfo",
            "data": base64::engine::general_purpose::STANDARD.encode(data),
        },
    });
    if let Some(save_path) = save_path {
        body["save_path"] = serde_json::Value::from(save_path);
    }
    let core = api.client.core();
    let mut url = core.base_url().clone();
    url.path_segments_mut()
        .map_err(|()| AddFailure::Api {
            failure: Failure::local("Invalid daemon URL", Some(url_error(core.base_url()))),
            errors: Vec::new(),
        })?
        .pop_if_empty()
        .extend(["v1", "torrents"]);
    let mut request = core.http().post(url).json(&body);
    if let Some(Credential::Bearer(token)) = core.credential("bearer") {
        request = request.bearer_auth(token.expose_secret());
    }
    let exchange = async move {
        let response = request.send().await.map_err(|e| AddFailure::Api {
            failure: Failure::local("Cannot reach the daemon", Some(e.to_string())),
            errors: Vec::new(),
        })?;
        let status = response.status();
        if status.is_success() {
            return response
                .json::<types::Torrent>()
                .await
                .map_err(|e| AddFailure::Api {
                    failure: Failure::local(
                        "The daemon's answer did not match the API document",
                        Some(e.to_string()),
                    ),
                    errors: Vec::new(),
                });
        }
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let problem: serde_json::Value = response.json().await.unwrap_or_default();
        Err(problem_failure(status.as_u16(), &problem, request_id))
    };
    match tokio::time::timeout(UPLOAD_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_) => Err(AddFailure::Api {
            failure: Failure::local(
                "The daemon did not answer",
                Some(format!(
                    "no response within {}s; the torrent may still have been added — refresh \
                     before retrying",
                    UPLOAD_TIMEOUT.as_secs()
                )),
            ),
            errors: Vec::new(),
        }),
    }
}

/// How long a `.torrent` upload may take: up to ~85 MiB of base64 on a slow
/// link, far past the ordinary request timeout.
const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

fn url_error(url: &reqwest::Url) -> String {
    format!("{url} cannot take a path")
}

/// A problem document as a failure, with a `validation-failed`'s `errors`.
fn problem_failure(
    status: u16,
    problem: &serde_json::Value,
    request_id: Option<String>,
) -> AddFailure {
    let failure = crate::api::from_problem(status, problem, request_id);
    AddFailure::Api {
        errors: failure.errors.clone(),
        failure,
    }
}

/// Width of the label column.
const LABEL: u16 = 14;

/// Draw the dialog over `area`.
pub fn view(
    dialog: &Dialog,
    active: &[String],
    profiles_loading: bool,
    tick: u64,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) {
    let rect = centered(area, 76, 14);
    frame.render_widget(Clear, rect);
    let title = if dialog.submitting {
        format!(" Add a torrent {} ", spinner(tick))
    } else {
        " Add a torrent ".to_owned()
    };
    let block = panel(theme, title, true);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    // An error takes as many rows as it wraps to, up to two.
    let value_width = inner.width.saturating_sub(LABEL).max(1);
    let rows_for = |error: &Option<String>| match error {
        Some(e) => (e.chars().count() as u16 + 2)
            .div_ceil(value_width)
            .clamp(1, 2),
        None => 0,
    };
    let [kind_row, _, source_row, source_err, profile_row, profile_err, save_row, save_err, general, hints] =
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(rows_for(&dialog.errors.source)),
            Constraint::Length(1),
            Constraint::Length(rows_for(&dialog.errors.profile)),
            Constraint::Length(1),
            Constraint::Length(rows_for(&dialog.errors.save_path)),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(inner);

    // Each row: a label, then its value in the column after it.
    let split = |row: Rect| {
        let [label, value] =
            Layout::horizontal([Constraint::Length(LABEL), Constraint::Fill(1)]).areas(row);
        (label, value)
    };
    let label = |field: Field, text: &str, row: Rect, frame: &mut Frame| {
        let focused = dialog.focus == field;
        let marker = if focused { "▸ " } else { "  " };
        let style = if focused {
            theme.key()
        } else {
            theme.fg(Tone::Muted)
        };
        frame.render_widget(
            Paragraph::new(Span::styled(format!("{marker}{text}"), style)),
            split(row).0,
        );
    };
    let error = |error: &Option<String>, row: Rect, frame: &mut Frame| {
        if let Some(e) = error {
            frame.render_widget(
                Paragraph::new(Span::styled(format!("✖ {e}"), theme.fg(Tone::Bad)))
                    .wrap(Wrap { trim: true }),
                split(row).1,
            );
        }
    };
    let width = value_width.saturating_sub(2) as usize;
    let input = |input: &Input, placeholder: &str| {
        if input.value().is_empty() {
            Span::styled(format!("› {placeholder}"), theme.fg(Tone::Muted))
        } else {
            let shown: String = input
                .value()
                .chars()
                .skip(input.visual_scroll(width))
                .take(width)
                .collect();
            Span::styled(format!("› {shown}"), theme.fg(Tone::Plain))
        }
    };

    label(Field::Kind, "source", kind_row, frame);
    let mut kinds = Vec::new();
    for (i, kind) in SourceKind::ALL.iter().enumerate() {
        if i > 0 {
            kinds.push(Span::styled(" │ ", theme.fg(Tone::Muted)));
        }
        if *kind == dialog.kind {
            kinds.push(Span::styled(
                format!("◉ {}", kind.label()),
                theme.fg(Tone::Accent).bold(),
            ));
        } else {
            kinds.push(Span::styled(
                format!("○ {}", kind.label()),
                theme.fg(Tone::Muted),
            ));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(kinds)), split(kind_row).1);

    label(Field::Source, dialog.kind.field_label(), source_row, frame);
    let source_hint = match dialog.kind {
        SourceKind::Magnet => "magnet:?xt=urn:btih:…",
        SourceKind::ServerPath => "/srv/torrents/file.torrent",
        SourceKind::LocalFile => "~/Downloads/file.torrent (at most 64 MiB)",
    };
    frame.render_widget(
        Paragraph::new(input(&dialog.source, source_hint)),
        split(source_row).1,
    );
    error(&dialog.errors.source, source_err, frame);

    label(Field::Profile, "profile", profile_row, frame);
    let profile = match (&dialog.profile, active.is_empty(), profiles_loading) {
        (_, true, true) => Span::styled(
            format!("{} loading profiles…", spinner(tick)),
            theme.fg(Tone::Muted),
        ),
        (_, true, false) => Span::styled("✖ no active profile", theme.fg(Tone::Bad)),
        (Some(p), false, _) => Span::styled(format!("‹ {p} ›"), theme.fg(Tone::Accent).bold()),
        (None, false, _) => Span::styled("‹ choose ›", theme.fg(Tone::Muted)),
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            profile,
            Span::styled(
                format!("  active only: {} of them", active.len()),
                theme.fg(Tone::Muted),
            ),
        ])),
        split(profile_row).1,
    );
    error(&dialog.errors.profile, profile_err, frame);

    label(Field::SavePath, "save path", save_row, frame);
    frame.render_widget(
        Paragraph::new(input(
            &dialog.save_path,
            "empty: the daemon's default_save_path",
        )),
        split(save_row).1,
    );
    error(&dialog.errors.save_path, save_err, frame);

    if let Some(e) = &dialog.errors.general {
        let [_, text] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(general);
        frame.render_widget(
            Paragraph::new(Span::styled(format!("✖ {e}"), theme.fg(Tone::Bad)))
                .wrap(Wrap { trim: true }),
            text,
        );
    }
    frame.render_widget(
        Paragraph::new(key_hints(
            theme,
            &[
                ("↑/↓", "field"),
                ("←/→", "choose"),
                ("Enter", "add"),
                ("Esc", "cancel"),
            ],
        )),
        hints,
    );

    // The terminal cursor sits in the focused text field.
    let cursor = match dialog.focus {
        Field::Source => Some((source_row, &dialog.source)),
        Field::SavePath => Some((save_row, &dialog.save_path)),
        Field::Kind | Field::Profile => None,
    };
    if let (Some((row, input)), false) = (cursor, dialog.submitting) {
        let col = input
            .visual_cursor()
            .saturating_sub(input.visual_scroll(width)) as u16;
        frame.set_cursor_position((row.x + LABEL + 2 + col, row.y));
    }
}

#[cfg(test)]
mod wire_tests {
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    /// Serve one request with `status` and `body`, returning what was sent.
    async fn serve_once(
        status: &'static str,
        body: String,
    ) -> (String, tokio::task::JoinHandle<String>) {
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

    fn torrent_json() -> String {
        serde_json::json!({
            "infohash": "0808080808080808080808080808080808080808",
            "profile_id": "acct_a", "phase": "unknown", "progress": 0.0,
            "upload_rate": 0, "download_rate": 0, "total_uploaded": 0,
            "total_payload_uploaded": 0, "num_peers": 0,
            "is_finished": false, "is_seeding": false, "session": null,
        })
        .to_string()
    }

    #[tokio::test]
    async fn a_torrent_file_is_sent_base64_encoded_with_the_bearer_credential() {
        let (url, server) = serve_once("201 Created", torrent_json()).await;
        let api = Api::new(&url, Some("tdp_wire")).unwrap();
        let bytes = b"d8:announce3:urle".to_vec();
        let torrent = post_metainfo(&api, "acct_a", Some("/srv/data"), &bytes)
            .await
            .unwrap_or_else(|_| panic!("the 201 decodes"));
        assert_eq!(torrent.infohash, "0808080808080808080808080808080808080808");

        let request = server.await.unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /v1/torrents HTTP/1.1"), "{head}");
        assert!(
            head.to_ascii_lowercase()
                .contains("authorization: bearer tdp_wire"),
            "{head}"
        );
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["profile_id"], "acct_a");
        assert_eq!(body["save_path"], "/srv/data");
        assert_eq!(body["source"]["kind"], "metainfo");
        let data = body["source"]["data"]
            .as_str()
            .expect("a base64 string, not an array");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn a_refusal_carries_its_field_errors_and_request_id() {
        let problem = serde_json::json!({
            "type": "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#validation-failed",
            "title": "The request is invalid", "status": 422,
            "detail": "/save_path: must be absolute",
            "errors": [{"pointer": "/save_path", "detail": "must be absolute"}],
        })
        .to_string();
        let (url, server) = serve_once("422 Unprocessable Entity", problem).await;
        let api = Api::new(&url, Some("tdp_wire")).unwrap();
        let failure = post_metainfo(&api, "acct_a", Some("rel"), b"x").await;
        server.await.unwrap();
        match failure {
            Err(AddFailure::Api { failure, errors }) => {
                assert!(failure.is("validation-failed"));
                assert_eq!(failure.request_id.as_deref(), Some("feedface"));
                assert_eq!(
                    errors,
                    [("/save_path".to_owned(), "must be absolute".to_owned())]
                );
            }
            _ => panic!("expected the 422's field errors"),
        }
    }
}
