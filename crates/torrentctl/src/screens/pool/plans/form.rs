//! The create-plan form: its fields, the keys that edit and submit it, and
//! drawing it.

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use ratatui::Frame;
use tui_input::backend::crossterm::EventHandler as _;
use tui_input::Input;

use super::Msg;
use super::State;
use crate::api::types;
use crate::api::Failure;
use crate::screens::contract::Ctx;
use crate::screens::contract::Effect;
use crate::screens::pool::wrap;
use crate::screens::pool::MUTATIONS_OFF;
use crate::theme::Tone;
use crate::ui::widgets::centered;
use crate::ui::widgets::key_hints;
use crate::ui::widgets::panel;
use crate::ui::widgets::spinner;

/// What a new plan's form starts with, from what the other views show.
#[derive(Clone, Debug, Default)]
pub struct Prefill {
    pub infohash: Option<String>,
    pub root_id: Option<i64>,
    pub prefix: String,
}

/// The create-plan form.
#[derive(Debug)]
pub struct Form {
    pub kind: types::PlanKind,
    /// `0` is the kind; `1..` the fields.
    pub focus: usize,
    pub fields: Vec<Field>,
    pub error: Option<String>,
    pub sending: bool,
    prefill: Prefill,
}

#[derive(Debug)]
pub struct Field {
    pub label: &'static str,
    pub input: Input,
    pub error: Option<String>,
}

impl Field {
    fn new(label: &'static str, value: String) -> Self {
        Self {
            label,
            input: Input::new(value),
            error: None,
        }
    }
}

impl Form {
    pub(super) fn new(kind: types::PlanKind, prefill: Prefill) -> Self {
        let root = prefill.root_id.map(|r| r.to_string()).unwrap_or_default();
        let fields = match kind {
            types::PlanKind::Relocate => vec![
                Field::new("infohash", prefill.infohash.clone().unwrap_or_default()),
                Field::new("to root id", root),
                Field::new("to path", String::new()),
            ],
            types::PlanKind::DeleteOrphans => vec![
                Field::new("root id", root),
                Field::new("under path", prefill.prefix.clone()),
            ],
        };
        Self {
            kind,
            focus: 1,
            fields,
            error: None,
            sending: false,
            prefill,
        }
    }

    /// The request the form describes, or each field's complaint.
    fn request(&mut self) -> Option<types::CreatePlanRequest> {
        for field in &mut self.fields {
            field.error = None;
        }
        self.error = None;
        let value = |i: usize| self.fields[i].input.value().trim().to_owned();
        let root = |text: String| text.parse::<i64>().ok().filter(|id| *id >= 0);
        match self.kind {
            types::PlanKind::Relocate => {
                let (infohash, dest_root, dest_rel) = (value(0), root(value(1)), value(2));
                let hex = infohash.len() == 40 && infohash.chars().all(|c| c.is_ascii_hexdigit());
                if !hex {
                    self.fields[0].error = Some("40 hex digits".to_owned());
                }
                if dest_root.is_none() {
                    self.fields[1].error = Some("a root id, as the overview lists it".to_owned());
                }
                if dest_rel.is_empty() {
                    self.fields[2].error = Some("a directory under the root".to_owned());
                }
                let dest_root_id = dest_root.filter(|_| hex && !dest_rel.is_empty())?;
                Some(types::CreatePlanRequest::CreatePlanRequestVariant0(
                    Box::new(types::CreatePlanRequestVariant0 {
                        kind: types::CreatePlanRequestVariant0kind::Relocate,
                        infohash: infohash.to_ascii_lowercase(),
                        dest_root_id,
                        dest_rel,
                    }),
                ))
            }
            types::PlanKind::DeleteOrphans => {
                let Some(root_id) = root(value(0)) else {
                    self.fields[0].error = Some("a root id, as the overview lists it".to_owned());
                    return None;
                };
                Some(types::CreatePlanRequest::CreatePlanRequestVariant1(
                    Box::new(types::CreatePlanRequestVariant1 {
                        kind: types::CreatePlanRequestVariant1kind::DeleteOrphans,
                        root_id,
                        prefix: value(1),
                    }),
                ))
            }
        }
    }

    /// Put a refusal next to the field it is about, where that is clear.
    pub(super) fn refused(&mut self, failure: &Failure) {
        let text = failure.message();
        let field = if failure.is("root-not-found") {
            Some(if self.kind == types::PlanKind::Relocate {
                1
            } else {
                0
            })
        } else if failure.is("validation-failed") {
            let detail = failure.detail.as_deref().unwrap_or_default();
            self.fields.iter().position(|f| match f.label {
                "infohash" => detail.contains("infohash"),
                "to root id" | "root id" => detail.contains("root_id"),
                "to path" => detail.contains("dest_rel"),
                "under path" => detail.contains("prefix"),
                _ => false,
            })
        } else {
            None
        };
        match field {
            Some(i) => self.fields[i].error = Some(text),
            None if failure.is("mutations-disabled") => self.error = Some(MUTATIONS_OFF.to_owned()),
            None => self.error = Some(text),
        }
    }
}

/// A key while the form has the keyboard.
pub(super) fn form_key(state: &mut State, key: KeyEvent, ctx: &Ctx<'_>) -> Vec<Effect> {
    let Some(form) = state.form.as_mut() else {
        return Vec::new();
    };
    if form.sending {
        return Vec::new();
    }
    let last = form.fields.len();
    match key.code {
        KeyCode::Esc => state.form = None,
        KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % (last + 1),
        KeyCode::BackTab | KeyCode::Up => form.focus = (form.focus + last) % (last + 1),
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if form.focus == 0 => {
            let kind = match form.kind {
                types::PlanKind::Relocate => types::PlanKind::DeleteOrphans,
                types::PlanKind::DeleteOrphans => types::PlanKind::Relocate,
            };
            *form = Form::new(kind, form.prefill.clone());
            form.focus = 0;
        }
        KeyCode::Enter => {
            let Some(body) = form.request() else {
                return Vec::new();
            };
            form.sending = true;
            let api = ctx.api.clone();
            return vec![Effect::new(async move {
                let result = crate::api::call(api.client.create_plan(&body)).await;
                wrap(crate::screens::pool::Msg::Plans(Msg::Created(result)))
            })];
        }
        _ if form.focus > 0 => {
            let field = &mut form.fields[form.focus - 1];
            field.input.handle_event(&crossterm::event::Event::Key(key));
            field.error = None;
        }
        _ => {}
    }
    Vec::new()
}

/// The form, over the whole screen.
pub(super) fn draw_form(form: &Form, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let marker = |focused: bool| if focused { "› " } else { "  " };
    let choice = |kind: types::PlanKind| {
        let on = form.kind == kind;
        Span::styled(
            format!("{} {kind}  ", if on { "(•)" } else { "( )" }),
            if on {
                theme.fg(Tone::Accent)
            } else {
                theme.fg(Tone::Muted)
            },
        )
    };
    let mut lines = vec![Line::from(vec![
        Span::raw(marker(form.focus == 0)),
        Span::styled(format!("{:>11}  ", "kind"), theme.fg(Tone::Muted)),
        choice(types::PlanKind::Relocate),
        choice(types::PlanKind::DeleteOrphans),
    ])];
    lines.push(Line::from(Span::styled(
        match form.kind {
            types::PlanKind::Relocate => {
                "               Move a torrent's payload to a directory under a root."
            }
            types::PlanKind::DeleteOrphans => {
                "               Delete the files no library torrent claims, under a path."
            }
        },
        theme.fg(Tone::Muted),
    )));
    lines.push(Line::from(""));
    for (i, field) in form.fields.iter().enumerate() {
        let focused = form.focus == i + 1;
        let cursor = if focused { "▏" } else { "" };
        lines.push(Line::from(vec![
            Span::raw(marker(focused)),
            Span::styled(format!("{:>11}  ", field.label), theme.fg(Tone::Muted)),
            Span::styled(
                format!("{}{cursor}", field.input.value()),
                theme.fg(if focused { Tone::Accent } else { Tone::Plain }),
            ),
        ]));
        if let Some(error) = &field.error {
            lines.push(Line::from(Span::styled(
                format!("               ✖ {error}"),
                theme.fg(Tone::Bad),
            )));
        }
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  ✖ {error}"),
            theme.fg(Tone::Bad),
        )));
    }
    lines.push(Line::from(""));
    let mut last = if form.sending {
        Line::from(Span::styled(
            format!("{} drafting the plan…", spinner(ctx.tick)),
            theme.fg(Tone::Accent),
        ))
    } else {
        key_hints(
            theme,
            &[
                ("Tab/↑↓", "field"),
                ("←/→", "kind"),
                ("Enter", "draft plan"),
                ("Esc", "cancel"),
            ],
        )
    };
    last.spans.insert(0, Span::raw("  "));
    lines.push(last);
    let width = area.width.saturating_sub(4).min(80);
    // A border each side, and a row for a long error to wrap into.
    let height = (lines.len() as u16 + 3).min(area.height);
    let rect = centered(area, width, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(
                theme,
                " New plan — a draft; nothing changes until applied ",
                true,
            )),
        rect,
    );
}
