//! Signing in with the operator password.
//!
//! Shown when there is no token, or when the daemon refused the one in use.
//! The session token `POST /v1/sessions` returns is held in memory only and
//! revoked on quit.

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use ratatui::Frame;
use tui_input::backend::crossterm::EventHandler as _;
use tui_input::Input;

use crate::api::types;
use crate::api::Failure;
use crate::app::Ctx;
use crate::app::Effect;
use crate::app::Session;
use crate::theme::Tone;
use crate::ui::widgets::centered;
use crate::ui::widgets::key_hints;
use crate::ui::widgets::panel;
use crate::ui::widgets::spinner;

#[derive(Debug, Default)]
pub struct State {
    pub password: Input,
    pub busy: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum Msg {
    Key(KeyEvent),
    Submit,
    /// The daemon answered the sign-in.
    Answered(Result<String, Failure>),
}

pub fn on_key(state: &State, key: KeyEvent) -> Option<Msg> {
    if state.busy {
        return None;
    }
    match key.code {
        KeyCode::Enter => Some(Msg::Submit),
        KeyCode::Esc => None,
        _ => Some(Msg::Key(key)),
    }
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx<'_>) -> Vec<Effect> {
    match msg {
        Msg::Key(key) => {
            state
                .password
                .handle_event(&crossterm::event::Event::Key(key));
            Vec::new()
        }
        Msg::Submit if state.password.value().is_empty() => {
            state.error = Some("enter the operator password".to_owned());
            Vec::new()
        }
        Msg::Submit => {
            state.busy = true;
            state.error = None;
            let api = ctx.api.clone();
            let body = types::CreateSession {
                password: state.password.value().to_owned(),
            };
            vec![Effect::new(async move {
                let grant = crate::api::call(api.client.create_session(&body)).await;
                crate::app::Msg::Login(Msg::Answered(grant.map(|g| g.token)))
            })]
        }
        Msg::Answered(Ok(token)) => {
            state.busy = false;
            state.password.reset();
            match ctx.api.with_token(&token) {
                Ok(api) => vec![Effect::now(crate::app::Msg::SignedIn(api))],
                Err(e) => {
                    state.error = Some(e);
                    Vec::new()
                }
            }
        }
        Msg::Answered(Err(failure)) => {
            state.busy = false;
            state.password.reset();
            state.error = Some(if failure.is("invalid-credentials") {
                "wrong password".to_owned()
            } else {
                failure.message()
            });
            Vec::new()
        }
    }
}

pub fn view(state: &State, session: &Session, ctx: &Ctx<'_>, frame: &mut Frame, area: Rect) {
    let theme = ctx.theme;
    let rect = centered(area, 58, 11);
    let block = panel(theme, " torrentd ", true);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mut lines = vec![
        Line::from(Span::styled(
            ctx.api.base_url.clone(),
            theme.fg(Tone::Accent),
        ))
        .centered(),
        Line::from(""),
    ];
    match session {
        Session::Checking => lines.push(
            Line::from(Span::styled(
                format!("{} connecting…", spinner(ctx.tick)),
                theme.fg(Tone::Muted),
            ))
            .centered(),
        ),
        Session::Unreachable { reason, since } => {
            let wait = crate::app::RETRY_INTERVAL.saturating_sub(since.elapsed());
            lines.push(Line::from(Span::styled(
                format!("✖ {reason}"),
                theme.fg(Tone::Bad),
            )));
            lines.push(Line::from(""));
            lines.push(
                Line::from(Span::styled(
                    format!("retrying in {}s", wait.as_secs() + 1),
                    theme.fg(Tone::Muted),
                ))
                .centered(),
            );
            lines.push(Line::from(""));
            lines.push(key_hints(theme, &[("r", "retry now"), ("Esc", "quit")]).centered());
        }
        _ => {
            let masked = "•".repeat(state.password.value().chars().count());
            lines.push(Line::from(vec![
                Span::styled("password ", theme.fg(Tone::Muted)),
                Span::styled(format!("› {masked}"), theme.fg(Tone::Plain)),
                if state.busy {
                    Span::styled(format!("  {}", spinner(ctx.tick)), theme.fg(Tone::Warn))
                } else {
                    Span::raw("")
                },
            ]));
            lines.push(Line::from(""));
            if let Some(error) = &state.error {
                lines.push(Line::from(Span::styled(
                    format!("✖ {error}"),
                    theme.fg(Tone::Bad),
                )));
            }
            lines.push(Line::from(""));
            lines.push(key_hints(theme, &[("Enter", "sign in"), ("Esc", "quit")]).centered());
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    fn typed(password: &str) -> State {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            for c in password.chars() {
                let msg = on_key(&state, testing::key(KeyCode::Char(c))).unwrap();
                update(&mut state, msg, ctx);
            }
        });
        state
    }

    #[test]
    fn the_password_is_masked_and_an_empty_one_is_not_sent() {
        let mut state = State::default();
        testing::with_ctx(None, |ctx| {
            assert!(update(&mut state, Msg::Submit, ctx).is_empty());
        });
        assert_eq!(state.error.as_deref(), Some("enter the operator password"));

        let state = typed("hunter2");
        for (w, h) in [(80, 24), (160, 48)] {
            let screen = testing::render(w, h, None, |ctx, frame, area| {
                view(&state, &Session::SignedOut, ctx, frame, area)
            });
            assert!(!screen.contains("hunter2"), "the password never renders");
            assert!(screen.contains("•••••••"));
            insta::assert_snapshot!(format!("login_{w}x{h}"), screen);
        }
    }

    #[test]
    fn submitting_sends_once_and_ignores_keys_until_answered() {
        let mut state = typed("pw");
        testing::with_ctx(None, |ctx| {
            assert_eq!(update(&mut state, Msg::Submit, ctx).len(), 1);
        });
        assert!(state.busy);
        assert!(on_key(&state, testing::key(KeyCode::Enter)).is_none());
    }

    #[test]
    fn a_wrong_password_says_so_and_clears_the_field() {
        let mut state = typed("pw");
        state.busy = true;
        let failure = Failure {
            status: Some(401),
            slug: Some("invalid-credentials".into()),
            title: "Invalid credentials".into(),
            detail: Some("invalid password".into()),
            request_id: None,
            ..Default::default()
        };
        testing::with_ctx(None, |ctx| {
            assert!(update(&mut state, Msg::Answered(Err(failure)), ctx).is_empty());
        });
        assert!(!state.busy);
        assert_eq!(state.error.as_deref(), Some("wrong password"));
        assert!(state.password.value().is_empty());
    }

    #[test]
    fn a_granted_token_signs_the_app_in() {
        let mut state = typed("pw");
        let effects = testing::with_ctx(None, |ctx| {
            update(&mut state, Msg::Answered(Ok("tds_abc".into())), ctx)
        });
        assert_eq!(effects.len(), 1, "SignedIn with the new credential");
        assert!(
            state.password.value().is_empty(),
            "the password is not kept"
        );
    }
}
