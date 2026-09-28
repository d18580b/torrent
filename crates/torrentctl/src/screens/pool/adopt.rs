//! Adopting: handing library torrents whose payload the pool matched to one
//! profile's session.
//!
//! The dialog asks for the profile, then sends the request as a dry run and
//! shows what would happen — which torrents seed at once, which are hashed
//! first and how many bytes that reads, which are refused and why — and
//! only on a second `Enter` sends the same request for real. Adoption moves
//! nothing on disk, so it is not gated on `allow_mutations`.

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use ratatui::Frame;

use super::strong;
use super::wrap;
use crate::api::types;
use crate::api::Failure;
use crate::app::failed;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Toast;
use crate::fmt;
use crate::theme::Theme;
use crate::theme::Tone;
use crate::ui::widgets::centered;
use crate::ui::widgets::key_hints;
use crate::ui::widgets::panel;
use crate::ui::widgets::spinner;

/// What to adopt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// These library torrents.
    Infohashes(Vec<String>),
    /// Every library torrent whose payload lies under `path` of a root.
    Subtree {
        root_id: i64,
        root_path: String,
        path: String,
    },
}

impl Selector {
    fn describe(&self) -> String {
        match self {
            Selector::Infohashes(hashes) if hashes.len() == 1 => {
                format!("torrent {}", fmt::short_hash(&hashes[0]))
            }
            Selector::Infohashes(hashes) => format!("{} marked torrents", hashes.len()),
            Selector::Subtree {
                root_id,
                root_path,
                path,
            } => {
                let under = if path.is_empty() {
                    root_path.clone()
                } else {
                    format!("{}/{path}", root_path.trim_end_matches('/'))
                };
                format!("everything under {under} (root #{root_id})")
            }
        }
    }

    fn to_api(&self) -> types::AdoptSelector {
        match self {
            Selector::Infohashes(hashes) => types::AdoptSelector::AdoptSelectorVariant0(Box::new(
                types::AdoptSelectorVariant0 {
                    kind: types::AdoptSelectorVariant0kind::Infohashes,
                    infohashes: hashes.clone(),
                },
            )),
            Selector::Subtree { root_id, path, .. } => types::AdoptSelector::AdoptSelectorVariant1(
                Box::new(types::AdoptSelectorVariant1 {
                    kind: types::AdoptSelectorVariant1kind::Subtree,
                    root_id: *root_id,
                    path: path.clone(),
                }),
            ),
        }
    }
}

/// Where the dialog is.
#[derive(Debug)]
pub enum Stage {
    /// Choosing the profile.
    Pick,
    /// The dry run is on its way.
    Previewing,
    /// What the dry run says would happen.
    Preview(types::AdoptionResult),
    /// The real request is on its way.
    Applying(types::AdoptionResult),
    /// What happened.
    Done(types::AdoptionResult),
}

#[derive(Debug)]
pub struct Dialog {
    /// Which dialog this is, so an answer to a closed one is dropped.
    pub serial: u64,
    pub selector: Selector,
    /// The profiles that can take torrents; `None` until loaded.
    pub profiles: Option<Vec<String>>,
    /// The chosen profile. Nothing is chosen until the operator moves to
    /// one: adopting into the wrong profile announces one account's
    /// torrents from another account's session.
    pub profile: Option<usize>,
    pub stage: Stage,
    pub error: Option<String>,
}

impl Dialog {
    fn profile_id(&self) -> Option<&str> {
        self.profiles
            .as_ref()?
            .get(self.profile?)
            .map(String::as_str)
    }
}

#[derive(Debug)]
pub enum Msg {
    Profiles {
        serial: u64,
        result: Result<Vec<types::Profile>, Failure>,
    },
    Key(KeyEvent),
    Answered {
        serial: u64,
        dry_run: bool,
        result: Result<types::AdoptionResult, Failure>,
    },
}

/// A dialog for `selector`, and the request for the profiles it offers.
pub fn open(serial: u64, selector: Selector, ctx: &Ctx<'_>) -> (Dialog, Vec<Effect>) {
    let api = ctx.api.clone();
    let effect = Effect::new(async move {
        let result = crate::api::call(api.client.list_profiles())
            .await
            .map(|l| l.items);
        wrap(super::Msg::Adopt(Msg::Profiles { serial, result }))
    });
    let dialog = Dialog {
        serial,
        selector,
        profiles: None,
        profile: None,
        stage: Stage::Pick,
        error: None,
    };
    (dialog, vec![effect])
}

pub fn update(dialog: &mut Option<Dialog>, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(d) = dialog.as_mut() else {
        return Vec::new();
    };
    match msg {
        Msg::Profiles { serial, .. } | Msg::Answered { serial, .. } if serial != d.serial => {
            Vec::new()
        }
        Msg::Profiles {
            result: Ok(profiles),
            ..
        } => {
            // Only a running profile can take torrents.
            d.profiles = Some(
                profiles
                    .into_iter()
                    .filter(|p| p.status == types::ProfileStatus::Active)
                    .map(|p| p.profile_id)
                    .collect(),
            );
            Vec::new()
        }
        Msg::Profiles {
            result: Err(failure),
            ..
        } => {
            d.error = Some(format!("cannot list profiles: {}", failure.message()));
            d.profiles = Some(Vec::new());
            super::signed_out(&failure)
        }
        Msg::Answered {
            dry_run,
            result: Ok(result),
            ..
        } => {
            d.error = None;
            if dry_run {
                d.stage = Stage::Preview(result);
                Vec::new()
            } else {
                let toast = Toast::success(format!(
                    "adopted {} into {}: {} seeding now, {} hashing first",
                    result.fast_path.len() + result.queued_for_verification.len(),
                    d.profile_id().unwrap_or("the profile"),
                    result.fast_path.len(),
                    result.queued_for_verification.len()
                ));
                d.stage = Stage::Done(result);
                vec![Effect::toast(toast)]
            }
        }
        Msg::Answered {
            dry_run,
            result: Err(failure),
            ..
        } => {
            // A real adoption that failed without an answer, or with a 5xx
            // (the daemon's own, or a proxy's timeout), may still have
            // adopted some or all of them; sending it again would refuse
            // every torrent already adopted. Close the dialog and say so.
            // A 4xx is a refusal before anything changed.
            if !dry_run && failure.status.is_none_or(|status| status >= 500) {
                *dialog = None;
                return vec![Effect::toast(crate::app::Toast::failure(
                    "adopting — it may still have gone through; refresh the library before retrying",
                    &failure,
                ))];
            }
            d.error = Some(failure.message());
            d.stage = match std::mem::replace(&mut d.stage, Stage::Pick) {
                Stage::Applying(preview) => Stage::Preview(preview),
                _ => Stage::Pick,
            };
            let attempt = if dry_run {
                "previewing adoption"
            } else {
                "adopting"
            };
            vec![Effect::now(failed(attempt, failure))]
        }
        Msg::Key(key) => on_key(dialog, key, ctx),
    }
}

fn on_key(dialog: &mut Option<Dialog>, key: KeyEvent, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(d) = dialog.as_mut() else {
        return Vec::new();
    };
    match (&d.stage, key.code) {
        // Nothing may interrupt the real request: its answer is the record
        // of what changed.
        (Stage::Applying(_), _) => Vec::new(),
        (Stage::Done(_), KeyCode::Enter | KeyCode::Esc) | (_, KeyCode::Esc) => {
            *dialog = None;
            Vec::new()
        }
        (Stage::Pick, KeyCode::Char('j') | KeyCode::Down) => {
            let len = d.profiles.as_ref().map_or(0, Vec::len);
            if len > 0 {
                d.profile = Some(d.profile.map_or(0, |i| (i + 1).min(len - 1)));
            }
            Vec::new()
        }
        (Stage::Pick, KeyCode::Char('k') | KeyCode::Up) => {
            if d.profiles.as_ref().is_some_and(|p| !p.is_empty()) {
                d.profile = Some(d.profile.map_or(0, |i| i.saturating_sub(1)));
            }
            Vec::new()
        }
        (Stage::Pick, KeyCode::Enter) => send(d, true, ctx),
        (Stage::Preview(_), KeyCode::Backspace | KeyCode::Char('h')) => {
            d.stage = Stage::Pick;
            Vec::new()
        }
        (Stage::Preview(preview), KeyCode::Enter) if adoptable(preview) > 0 => send(d, false, ctx),
        _ => Vec::new(),
    }
}

/// How many torrents a result hands over.
fn adoptable(result: &types::AdoptionResult) -> usize {
    result.fast_path.len() + result.queued_for_verification.len()
}

/// Send the request, as a dry run or for real.
fn send(d: &mut Dialog, dry_run: bool, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(profile_id) = d.profile_id().map(str::to_owned) else {
        return Vec::new();
    };
    d.error = None;
    d.stage = match std::mem::replace(&mut d.stage, Stage::Pick) {
        Stage::Preview(preview) if !dry_run => Stage::Applying(preview),
        _ => Stage::Previewing,
    };
    let body = types::AdoptRequest {
        profile_id,
        dry_run: Some(dry_run),
        selector: d.selector.to_api(),
    };
    let serial = d.serial;
    let api = ctx.api.clone();
    vec![Effect::new(async move {
        // The preview is quick; the adoption itself claims and loads every
        // target before answering, which for a large subtree outlasts the
        // ordinary timeout — and giving up early would report a failure for
        // work that went on.
        let result = if dry_run {
            crate::api::call(api.client.adopt_pool_torrents(&body)).await
        } else {
            crate::api::call_unbounded(api.client.adopt_pool_torrents(&body)).await
        };
        wrap(super::Msg::Adopt(Msg::Answered {
            serial,
            dry_run,
            result,
        }))
    })]
}

pub fn view(d: &Dialog, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let width = area.width.saturating_sub(4).min(84);
    let mut lines = vec![Line::from(vec![
        Span::styled("  what  ", theme.fg(Tone::Muted)),
        Span::styled(d.selector.describe(), theme.fg(Tone::Plain)),
    ])];
    let into = d.profile_id().unwrap_or("—").to_owned();
    match &d.stage {
        Stage::Pick => {
            lines.push(Line::from(Span::styled("  into", theme.fg(Tone::Muted))));
            match &d.profiles {
                None => lines.push(Line::from(Span::styled(
                    format!("        {} loading profiles…", spinner(ctx.tick)),
                    theme.fg(Tone::Muted),
                ))),
                Some(profiles) if profiles.is_empty() => lines.push(Line::from(Span::styled(
                    "        no active profile can take torrents",
                    theme.fg(Tone::Warn),
                ))),
                Some(profiles) => {
                    for (i, p) in profiles.iter().enumerate() {
                        let selected = Some(i) == d.profile;
                        lines.push(Line::from(vec![
                            Span::raw(if selected { "      › " } else { "        " }),
                            Span::styled(
                                p.clone(),
                                if selected {
                                    theme.selected()
                                } else {
                                    theme.fg(Tone::Plain)
                                },
                            ),
                        ]));
                    }
                }
            }
        }
        Stage::Previewing => {
            lines.push(into_line(theme, &into));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(
                    "  {} asking the daemon what would happen…",
                    spinner(ctx.tick)
                ),
                theme.fg(Tone::Accent),
            )));
        }
        Stage::Preview(result) | Stage::Applying(result) | Stage::Done(result) => {
            lines.push(into_line(theme, &into));
            lines.push(Line::from(""));
            let heading = match &d.stage {
                Stage::Done(_) => Span::styled("  Done:", theme.fg(Tone::Good)),
                _ => Span::styled(
                    "  Preview — a dry run, nothing has changed yet:",
                    theme.title(),
                ),
            };
            lines.push(Line::from(heading));
            lines.extend(result_lines(theme, result, width as usize));
        }
    }
    if let Some(error) = &d.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  ✖ {error}"),
            theme.fg(Tone::Bad),
        )));
    }
    lines.push(Line::from(""));
    let keys: Vec<(&str, &str)> = match &d.stage {
        Stage::Pick if d.profile.is_none() => vec![("j/k", "choose a profile"), ("Esc", "cancel")],
        Stage::Pick => vec![("j/k", "profile"), ("Enter", "preview"), ("Esc", "cancel")],
        Stage::Previewing => vec![("Esc", "cancel")],
        Stage::Preview(result) if adoptable(result) > 0 => {
            vec![
                ("Enter", "adopt"),
                ("⌫", "change profile"),
                ("Esc", "cancel"),
            ]
        }
        Stage::Preview(_) => vec![("⌫", "change profile"), ("Esc", "close")],
        Stage::Applying(_) => vec![],
        Stage::Done(_) => vec![("Enter", "close")],
    };
    let mut hint = key_hints(theme, &keys);
    hint.spans.insert(0, Span::raw("  "));
    if let Stage::Preview(result) = &d.stage {
        if adoptable(result) == 0 {
            hint.spans
                .push(Span::styled("   nothing to adopt", theme.fg(Tone::Muted)));
        }
    }
    if let Stage::Applying(_) = d.stage {
        hint = Line::from(Span::styled(
            format!("  {} adopting…", spinner(ctx.tick)),
            theme.fg(Tone::Accent),
        ));
    }
    lines.push(hint);

    let height = (lines.len() as u16 + 2).min(area.height);
    let rect = centered(area, width, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(theme, " Adopt ", true)),
        rect,
    );
}

fn into_line<'a>(theme: &Theme, profile: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled("  into  ", theme.fg(Tone::Muted)),
        Span::styled(profile.to_owned(), theme.fg(Tone::Accent)),
    ])
}

/// An adoption result: what seeds at once, what is hashed first, what is
/// refused and why.
fn result_lines<'a>(theme: &Theme, r: &types::AdoptionResult, width: usize) -> Vec<Line<'a>> {
    let hashes = |list: &[String]| -> String {
        let room = width.saturating_sub(56) / 13;
        let mut shown: Vec<&str> = list
            .iter()
            .take(room.max(1))
            .map(|h| fmt::short_hash(h))
            .collect();
        if list.len() > shown.len() {
            shown.push("…");
        }
        shown.join(" ")
    };
    let mut lines = vec![
        Line::from(vec![
            Span::raw("    "),
            strong(theme, format!("● {:>5}", r.fast_path.len()), Tone::Good),
            Span::raw(format!("{:<42}", " seed at once (fast path)")),
            Span::styled(hashes(&r.fast_path), theme.fg(Tone::Muted)),
        ]),
        Line::from(vec![
            Span::raw("    "),
            strong(
                theme,
                format!("◐ {:>5}", r.queued_for_verification.len()),
                Tone::Warn,
            ),
            Span::raw(format!(
                "{:<42}",
                format!(
                    " hashed before seeding: {} to read",
                    fmt::bytes(r.verify_bytes)
                )
            )),
            Span::styled(hashes(&r.queued_for_verification), theme.fg(Tone::Muted)),
        ]),
        Line::from(vec![
            Span::raw("    "),
            strong(
                theme,
                format!("✖ {:>5}", r.refused.len()),
                if r.refused.is_empty() {
                    Tone::Muted
                } else {
                    Tone::Bad
                },
            ),
            Span::raw(" refused"),
        ]),
    ];
    const SHOWN: usize = 6;
    for refused in r.refused.iter().take(SHOWN) {
        lines.push(Line::from(vec![
            Span::styled(
                format!("        {}  ", fmt::short_hash(&refused.infohash)),
                theme.fg(Tone::Muted),
            ),
            Span::raw(refused.reason.clone()),
        ]));
    }
    if r.refused.len() > SHOWN {
        lines.push(Line::from(Span::styled(
            format!("        … and {} more", r.refused.len() - SHOWN),
            theme.fg(Tone::Muted),
        )));
    }
    lines
}
