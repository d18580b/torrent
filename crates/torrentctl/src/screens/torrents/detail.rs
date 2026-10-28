//! One torrent: its overview, files, trackers and actions.

use std::cell::Cell;
use std::time::Instant;

use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::TableState;
use ratatui::widgets::Tabs;
use ratatui::Frame;
use tui_input::Input;

use super::Action;
use super::Msg;
use super::State;
use crate::api::types;
use crate::api::Api;
use crate::fmt;
use crate::screens::contract::Ctx;
use crate::screens::contract::Effect;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::caps;
use crate::ui::widgets::centered;
use crate::ui::widgets::key_hints;
use crate::ui::widgets::panel;
use crate::ui::widgets::placeholder;
use crate::ui::widgets::spinner;
use crate::ui::widgets::state_span;
use crate::ui::widgets::Motion;
use crate::ui::widgets::PageRequest;
use crate::ui::widgets::Paged;

/// The detail view's tabs, in order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Overview,
    Files,
    Trackers,
    Actions,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Overview, Tab::Files, Tab::Trackers, Tab::Actions];

    fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Files => "Files",
            Tab::Trackers => "Trackers",
            Tab::Actions => "Actions",
        }
    }

    pub fn step(self, forward: bool) -> Self {
        let at = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        let n = Self::ALL.len();
        Self::ALL[if forward {
            (at + 1) % n
        } else {
            (at + n - 1) % n
        }]
    }
}

/// An entry of the actions tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Act(Action),
    UploadLimit,
}

/// The actions tab, in order, with their keys.
pub const ENTRIES: [(Entry, &str, &str); 7] = [
    (
        Entry::Act(Action::Pause),
        "p",
        "pause: stop announcing and serving peers",
    ),
    (Entry::Act(Action::Resume), "r", "resume"),
    (
        Entry::Act(Action::Recheck),
        "c",
        "recheck: re-hash the payload",
    ),
    (
        Entry::Act(Action::Reannounce),
        "a",
        "reannounce to every tracker now",
    ),
    (Entry::UploadLimit, "l", "set this torrent's upload limit"),
    (
        Entry::Act(Action::Remove),
        "d",
        "remove: forget it, keep the payload",
    ),
    (
        Entry::Act(Action::RemoveFiles),
        "D",
        "remove and delete its files",
    ),
];

/// The upload-limit field, while open.
#[derive(Debug, Default)]
pub struct LimitInput {
    pub input: Input,
    pub error: Option<String>,
}

/// One torrent, open.
#[derive(Debug, Default)]
pub struct Detail {
    pub hash: String,
    /// What the list knew, shown until the full record arrives.
    pub summary: Option<types::TorrentSummary>,
    pub torrent: Option<types::Torrent>,
    pub loading: bool,
    pub error: Option<String>,
    pub tab: Tab,
    pub files: Paged<types::TorrentFile>,
    /// `409 metadata-pending`: a magnet with no file list yet.
    pub metadata_pending: bool,
    pub files_selected: usize,
    pub files_offset: Cell<usize>,
    pub trackers: Option<Vec<types::Tracker>>,
    pub trackers_loading: bool,
    /// When the trackers were last asked for, for the Trackers tab's poll.
    pub trackers_asked: Option<Instant>,
    pub trackers_error: Option<String>,
    pub trackers_selected: usize,
    pub trackers_offset: Cell<usize>,
    pub action_selected: usize,
    /// The priority prompt (`=`), waiting for a digit.
    pub prompt: bool,
    pub limit: Option<LimitInput>,
}

impl Detail {
    pub fn new(hash: String, summary: Option<types::TorrentSummary>) -> Self {
        Self {
            hash,
            summary,
            ..Self::default()
        }
    }

    /// The name, when the session knows it.
    pub fn name(&self) -> Option<&str> {
        self.torrent
            .as_ref()
            .and_then(|t| t.session.as_ref())
            .and_then(|s| s.name.as_deref())
    }
}

/// Parse an upload limit: empty for none, else bytes per second in
/// `1..=2147483647`.
pub fn parse_limit(text: &str) -> Result<Option<i64>, String> {
    let digits: String = text
        .trim()
        .chars()
        .filter(|c| !matches!(c, '_' | ','))
        .collect();
    if digits.is_empty() {
        return Ok(None);
    }
    let range = "between 1 and 2,147,483,647 bytes/s; empty removes the limit";
    match digits.parse::<u64>() {
        Ok(n) if (1..=2_147_483_647).contains(&n) => Ok(Some(n as i64)),
        Ok(_) => Err(range.to_owned()),
        Err(_) if digits.starts_with('-') || digits.chars().all(|c| c.is_ascii_digit()) => {
            Err(range.to_owned())
        }
        Err(_) => Err(format!("a whole number of bytes per second, {range}")),
    }
}

/// A priority as libtorrent means it.
pub fn priority_label(priority: i64) -> String {
    match priority {
        0 => "0 skip".to_owned(),
        1 => "1 low".to_owned(),
        4 => "4 normal".to_owned(),
        7 => "7 top".to_owned(),
        p => p.to_string(),
    }
}

/// Draw the detail view.
pub fn view(
    detail: &Detail,
    theme: &Theme,
    tick: u64,
    now: time::OffsetDateTime,
    mutations: bool,
    frame: &mut Frame,
    area: Rect,
) {
    let busy = detail.loading || detail.files.loading || detail.trackers_loading;
    let mut title = vec![Span::raw(" ")];
    if let Some(name) = detail.name() {
        title.push(Span::raw(format!("{name} · ")));
    }
    title.push(Span::styled(
        fmt::short_hash(&detail.hash).to_owned(),
        theme.fg(Tone::Accent),
    ));
    title.push(Span::raw(" "));
    if busy {
        title.push(Span::styled(
            format!("{} ", spinner(tick)),
            theme.fg(Tone::Muted),
        ));
    }
    let hints: &[(&str, &str)] = match detail.tab {
        Tab::Overview => &[
            ("←/→", "tab"),
            ("Esc", "back"),
            ("p/r", "pause/resume"),
            ("l", "limit"),
        ],
        Tab::Files => &[
            ("←/→", "tab"),
            ("Esc", "back"),
            ("+/-", "priority"),
            ("0", "skip"),
            ("=", "set 0-7"),
        ],
        Tab::Trackers => &[
            ("←/→", "tab"),
            ("Esc", "back"),
            ("a", "reannounce"),
            ("j/k", "move"),
        ],
        Tab::Actions => &[
            ("←/→", "tab"),
            ("Esc", "back"),
            ("Enter", "run"),
            ("j/k", "move"),
        ],
    };
    let mut bottom = key_hints(theme, hints);
    bottom.spans.insert(0, Span::raw(" "));
    bottom.spans.push(Span::raw(" "));
    let block = panel(theme, Line::from(title), true).title_bottom(bottom);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [tabs_area, status_area, body] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(inner);
    let selected = Tab::ALL.iter().position(|t| *t == detail.tab);
    frame.render_widget(
        Tabs::new(Tab::ALL.iter().map(|t| t.title()))
            .select(selected)
            .style(theme.fg(Tone::Muted))
            .highlight_style(theme.title().underlined())
            .divider(Span::styled("│", theme.fg(Tone::Muted))),
        tabs_area,
    );
    if let Some(error) = &detail.error {
        frame.render_widget(
            Paragraph::new(Span::styled(format!("✖ {error}"), theme.fg(Tone::Bad))),
            status_area,
        );
    }

    match detail.tab {
        Tab::Overview => overview(detail, theme, now, frame, body),
        Tab::Files => files(detail, theme, tick, frame, body),
        Tab::Trackers => trackers(detail, theme, tick, now, frame, body),
        Tab::Actions => actions(detail, theme, mutations, frame, body),
    }

    if detail.prompt {
        let rect = centered(area, 44, 5);
        frame.render_widget(Clear, rect);
        let block = panel(theme, " File priority ", true);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("0 skip · 1 low · 4 normal · 7 top"),
                Line::from(""),
                key_hints(theme, &[("0-7", "set"), ("Esc", "cancel")]),
            ]),
            inner,
        );
    }
    if let Some(limit) = &detail.limit {
        let rect = centered(area, 60, 8);
        frame.render_widget(Clear, rect);
        let block = panel(theme, " Upload limit ", true);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let mut lines = vec![
            Line::from(Span::styled(
                "bytes per second; empty removes it",
                theme.fg(Tone::Muted),
            )),
            Line::from(Span::styled(
                format!("› {}", limit.input.value()),
                theme.fg(Tone::Accent),
            )),
        ];
        lines.push(match &limit.error {
            Some(e) => Line::from(Span::styled(format!("✖ {e}"), theme.fg(Tone::Bad))),
            None => match parse_limit(limit.input.value()) {
                Ok(Some(n)) => Line::from(Span::styled(
                    format!("= {}", fmt::rate(n)),
                    theme.fg(Tone::Muted),
                )),
                _ => Line::from(""),
            },
        });
        lines.push(Line::from(""));
        lines.push(key_hints(theme, &[("Enter", "set"), ("Esc", "cancel")]));
        frame.render_widget(
            Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }),
            inner,
        );
        frame.set_cursor_position((
            inner.x + 2 + limit.input.visual_cursor() as u16,
            inner.y + 1,
        ));
    }
}

fn kv<'a>(theme: &Theme, key: &'a str, value: impl Into<Span<'a>>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:>16}  "), theme.fg(Tone::Muted)),
        value.into(),
    ])
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn date(at: time::OffsetDateTime) -> String {
    format!(
        "{}-{:02}-{:02} {:02}:{:02} UTC",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute()
    )
}

fn overview(
    detail: &Detail,
    theme: &Theme,
    now: time::OffsetDateTime,
    frame: &mut Frame,
    area: Rect,
) {
    // What the list knew stands in for the record until it arrives.
    let summary = match (&detail.torrent, &detail.summary) {
        (Some(t), _) => types::TorrentSummary {
            infohash: t.infohash.clone(),
            profile_id: t.profile_id.clone(),
            phase: t.phase.clone(),
            progress: t.progress,
            upload_rate: t.upload_rate,
            download_rate: t.download_rate,
            total_uploaded: t.total_uploaded,
            total_payload_uploaded: t.total_payload_uploaded,
            num_peers: t.num_peers,
            is_finished: t.is_finished,
            is_seeding: t.is_seeding,
        },
        (None, Some(s)) => s.clone(),
        (None, None) => {
            let text = match &detail.error {
                Some(e) => format!("✖ {e}"),
                None => "loading…".to_owned(),
            };
            placeholder(frame, area, theme, &text, Tone::Muted);
            return;
        }
    };
    let left = vec![
        kv(theme, "infohash", Span::raw(summary.infohash.clone())),
        kv(theme, "profile", Span::raw(summary.profile_id.clone())),
        kv(
            theme,
            "phase",
            state_span(theme, &summary.phase.to_string()),
        ),
        kv(theme, "progress", Span::raw(fmt::percent(summary.progress))),
        kv(
            theme,
            "upload rate",
            Span::styled(fmt::rate(summary.upload_rate), theme.fg(Tone::Good)),
        ),
        kv(
            theme,
            "download rate",
            Span::raw(fmt::rate(summary.download_rate)),
        ),
        kv(
            theme,
            "uploaded",
            Span::raw(fmt::bytes(summary.total_uploaded)),
        ),
        kv(
            theme,
            "payload uploaded",
            Span::raw(fmt::bytes(summary.total_payload_uploaded)),
        ),
        kv(theme, "peers", Span::raw(fmt::count(summary.num_peers))),
        kv(theme, "finished", Span::raw(yes_no(summary.is_finished))),
        kv(theme, "seeding", Span::raw(yes_no(summary.is_seeding))),
    ];
    let mut right = vec![Line::from(Span::styled(
        format!("{:>16}", "session"),
        theme.title(),
    ))];
    match detail.torrent.as_ref().map(|t| t.session.as_ref()) {
        None => right.push(Line::from(Span::styled("loading…", theme.fg(Tone::Muted)))),
        Some(None) => right.push(Line::from(Span::styled(
            "○ not loaded in a session: still being added, its profile never came up, or the \
             session could not be asked",
            theme.fg(Tone::Muted),
        ))),
        Some(Some(session)) => {
            let unknown = || Span::styled("— (no metadata yet)", theme.fg(Tone::Muted));
            right.push(kv(
                theme,
                "name",
                session.name.clone().map_or_else(unknown, Span::raw),
            ));
            right.push(kv(
                theme,
                "size",
                session
                    .total_size
                    .map(fmt::bytes)
                    .map_or_else(unknown, Span::raw),
            ));
            right.push(kv(theme, "save path", Span::raw(session.save_path.clone())));
            right.push(kv(
                theme,
                "upload limit",
                match session.upload_limit_bytes_per_sec {
                    Some(n) => Span::raw(fmt::rate(n)),
                    None => Span::styled("none of its own", theme.fg(Tone::Muted)),
                },
            ));
            right.push(kv(
                theme,
                "added",
                match session.added_at {
                    Some(at) => Span::raw(format!("{} ({})", date(*at), fmt::relative(*at, now))),
                    None => Span::styled("unknown", theme.fg(Tone::Muted)),
                },
            ));
        }
    }
    let wrap = ratatui::widgets::Wrap { trim: false };
    if area.width >= 120 {
        let [l, r] = Layout::horizontal([Constraint::Length(64), Constraint::Fill(1)]).areas(area);
        frame.render_widget(Paragraph::new(left), l);
        frame.render_widget(Paragraph::new(right).wrap(wrap), r);
    } else {
        let mut lines = left;
        lines.push(Line::from(""));
        lines.extend(right);
        frame.render_widget(Paragraph::new(lines).wrap(wrap), area);
    }
}

fn files(detail: &Detail, theme: &Theme, tick: u64, frame: &mut Frame, area: Rect) {
    let [status, table_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    if detail.metadata_pending {
        placeholder(
            frame,
            area,
            theme,
            "◐ metadata not yet received — a magnet has no file list until peers send it",
            Tone::Warn,
        );
        return;
    }
    let files = &detail.files;
    let mut line = vec![Span::styled(
        format!(
            "{} files loaded{}",
            fmt::count(files.items.len() as i64),
            if files.complete {
                ""
            } else {
                " · more to load"
            }
        ),
        theme.fg(Tone::Muted),
    )];
    if files.loading {
        line.push(Span::styled(
            format!("  {} loading", spinner(tick)),
            theme.fg(Tone::Muted),
        ));
    }
    if let Some(e) = &files.error {
        line.push(Span::styled(format!("  ✖ {e}"), theme.fg(Tone::Bad)));
    }
    frame.render_widget(Paragraph::new(Line::from(line)), status);
    if files.items.is_empty() {
        if files.error.is_none() {
            let text = if files.loading || !files.complete {
                "loading…"
            } else {
                "no files"
            };
            placeholder(frame, table_area, theme, text, Tone::Muted);
        }
        return;
    }
    let rows = files.items.iter().map(|f| {
        let done = if f.size <= 0 {
            1.0
        } else {
            f.downloaded as f64 / f.size as f64
        };
        let priority_tone = match f.priority {
            0 => Tone::Muted,
            7 => Tone::Accent,
            _ => Tone::Plain,
        };
        Row::new(vec![
            Line::from(f.index.to_string()).right_aligned(),
            Line::from(Span::styled(
                f.path.clone(),
                if f.priority == 0 {
                    theme.fg(Tone::Muted)
                } else {
                    theme.fg(Tone::Plain)
                },
            )),
            Line::from(fmt::bytes(f.size)).right_aligned(),
            Line::from(fmt::percent(done)).right_aligned(),
            Line::from(Span::styled(
                priority_label(f.priority),
                theme.fg(priority_tone),
            )),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Fill(1),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(vec![
            Line::from("#").right_aligned(),
            Line::from("path"),
            Line::from("size").right_aligned(),
            Line::from("have").right_aligned(),
            Line::from("priority"),
        ])
        .style(theme.fg(Tone::Muted)),
    )
    .row_highlight_style(theme.selected())
    .highlight_symbol("› ");
    let mut state = TableState::default()
        .with_offset(detail.files_offset.get())
        .with_selected(Some(detail.files_selected));
    frame.render_stateful_widget(table, table_area, &mut state);
    detail.files_offset.set(state.offset());
}

fn trackers(
    detail: &Detail,
    theme: &Theme,
    tick: u64,
    now: time::OffsetDateTime,
    frame: &mut Frame,
    area: Rect,
) {
    let [status, table_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    let mut line = vec![];
    if detail.trackers_loading {
        line.push(Span::styled(
            format!("{} loading  ", spinner(tick)),
            theme.fg(Tone::Muted),
        ));
    }
    if let Some(e) = &detail.trackers_error {
        line.push(Span::styled(format!("✖ {e}"), theme.fg(Tone::Bad)));
    }
    frame.render_widget(Paragraph::new(Line::from(line)), status);
    let Some(trackers) = &detail.trackers else {
        if detail.trackers_error.is_none() {
            placeholder(frame, table_area, theme, "loading…", Tone::Muted);
        }
        return;
    };
    if trackers.is_empty() {
        placeholder(
            frame,
            table_area,
            theme,
            "no trackers: peers come from DHT and PEX alone",
            Tone::Muted,
        );
        return;
    }
    let wide = area.width >= 110;
    let rows = trackers.iter().map(|t| {
        let unknown = || "—".to_owned();
        let mut cells = vec![
            Line::from(t.tier.to_string()).right_aligned(),
            Line::from(if t.host.is_empty() {
                "(unparsed URL)".to_owned()
            } else {
                t.host.clone()
            }),
            Line::from(state_span(theme, &t.status.to_string())),
            Line::from(
                t.next_announce_at
                    .map_or_else(unknown, |at| fmt::relative(*at, now)),
            ),
            Line::from(t.seeds.map_or_else(unknown, fmt::count)).right_aligned(),
            Line::from(t.peers.map_or_else(unknown, fmt::count)).right_aligned(),
        ];
        let tone = if matches!(t.status, types::TrackerStatus::Error) {
            Tone::Bad
        } else {
            Tone::Muted
        };
        cells.push(Line::from(Span::styled(
            t.message.clone().unwrap_or_default(),
            theme.fg(tone),
        )));
        Row::new(cells)
    });
    let host = if wide { 28 } else { 18 };
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(host),
            Constraint::Length(15),
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(vec![
            Line::from("tier").right_aligned(),
            Line::from("host"),
            Line::from("status"),
            Line::from("next"),
            Line::from("seeds").right_aligned(),
            Line::from("peers").right_aligned(),
            Line::from("message"),
        ])
        .style(theme.fg(Tone::Muted)),
    )
    .row_highlight_style(theme.selected())
    .highlight_symbol("› ");
    let mut state = TableState::default()
        .with_offset(detail.trackers_offset.get())
        .with_selected(Some(detail.trackers_selected));
    frame.render_stateful_widget(table, table_area, &mut state);
    detail.trackers_offset.set(state.offset());
}

fn actions(detail: &Detail, theme: &Theme, mutations: bool, frame: &mut Frame, area: Rect) {
    let mut lines = Vec::new();
    for (i, (entry, key, text)) in ENTRIES.iter().enumerate() {
        let selected = i == detail.action_selected;
        let disabled = matches!(entry, Entry::Act(Action::RemoveFiles)) && !mutations;
        let marker = if selected { "› " } else { "  " };
        let mut spans = vec![
            Span::raw(marker),
            Span::styled(
                format!("{key:>2}  "),
                if disabled {
                    theme.fg(Tone::Muted)
                } else {
                    theme.key()
                },
            ),
            Span::styled(
                *text,
                if disabled {
                    theme.fg(Tone::Muted)
                } else {
                    theme.fg(Tone::Plain)
                },
            ),
        ];
        if disabled {
            spans.push(Span::styled(
                "  — needs [pool] allow_mutations on the daemon",
                theme.fg(Tone::Muted),
            ));
        }
        if matches!(entry, Entry::UploadLimit) {
            let current = detail
                .torrent
                .as_ref()
                .and_then(|t| t.session.as_ref())
                .and_then(|s| s.upload_limit_bytes_per_sec);
            spans.push(Span::styled(
                format!(
                    "  (now {})",
                    current.map_or_else(|| "none of its own".to_owned(), fmt::rate)
                ),
                theme.fg(Tone::Muted),
            ));
        }
        let line = Line::from(spans);
        lines.push(if selected {
            line.style(theme.selected())
        } else {
            line
        });
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// The open torrent, when it is `hash`: an answer for another is stale.
pub(super) fn open_detail<'a>(state: &'a mut State, hash: &str) -> Option<&'a mut Detail> {
    state.detail.as_mut().filter(|d| d.hash == hash)
}

/// Reload the open torrent and its current tab.
pub(super) fn load_detail(detail: &mut Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
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
pub(super) fn rereads_files(detail: &Detail) -> bool {
    detail.tab == Tab::Files && detail.files.items.len() <= caps::PAGE_MAX
}

/// Whether [`load_detail`] re-reads the open torrent's trackers: only on the
/// Trackers tab.
pub(super) fn rereads_trackers(detail: &Detail) -> bool {
    detail.tab == Tab::Trackers
}

/// Reload the open torrent's files from the first page.
pub(super) fn load_files(detail: &mut Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    let request = detail.files.reload();
    vec![fetch_files(ctx.api, detail.hash.clone(), request)]
}

/// The next page of files, when the selection is near the end of them.
pub(super) fn more_files(detail: &mut Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    if !detail.files.wants_more(detail.files_selected) {
        return Vec::new();
    }
    match detail.files.begin_more() {
        Some(request) => vec![fetch_files(ctx.api, detail.hash.clone(), request)],
        None => Vec::new(),
    }
}

/// One page of the torrent `hash`'s files.
pub(super) fn fetch_files(api: &Api, hash: String, request: PageRequest) -> Effect {
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

/// Re-read the open torrent's trackers.
pub(super) fn load_trackers(detail: &mut Detail, ctx: &Ctx<'_>) -> Vec<Effect> {
    detail.trackers_loading = true;
    detail.trackers_asked = Some(Instant::now());
    let api = ctx.api.clone();
    let hash = detail.hash.clone();
    vec![Effect::new(async move {
        let result = crate::api::call(api.client.list_torrent_trackers(hash.clone())).await;
        crate::app::Msg::Torrents(Msg::Trackers { hash, result })
    })]
}

/// Move the selection of the open tab.
pub(super) fn move_in_detail(detail: &mut Detail, movement: Motion, ctx: &Ctx<'_>) -> Vec<Effect> {
    match detail.tab {
        Tab::Overview => Vec::new(),
        Tab::Files => {
            detail.files_selected = movement.apply(detail.files_selected, detail.files.items.len());
            more_files(detail, ctx)
        }
        Tab::Trackers => {
            let len = detail.trackers.as_ref().map_or(0, Vec::len);
            detail.trackers_selected = movement.apply(detail.trackers_selected, len);
            Vec::new()
        }
        Tab::Actions => {
            detail.action_selected = movement.apply(detail.action_selected, ENTRIES.len());
            Vec::new()
        }
    }
}
