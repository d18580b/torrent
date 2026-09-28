//! The screens. Each module follows one contract, which `app` routes to:
//!
//! - `State: Default` — what the screen shows;
//! - `Msg` — what can happen to it;
//! - `update(&mut State, Msg, &Ctx) -> Vec<Effect>` — the only thing that
//!   changes `State`; network calls are returned as effects;
//! - `refresh(&mut State, &Ctx) -> Vec<Effect>` — reload what is on screen,
//!   called when the screen is shown, on every change notification, and by
//!   the polling fallback;
//! - `on_key(&State, KeyEvent) -> Option<Msg>` — a key, read as a message;
//! - `capturing(&State) -> bool` — whether a text field or dialog has the
//!   keyboard, so global keys (`q`, digits, `:`) must not fire;
//! - `view(&State, &Ctx, &mut Frame, Rect)`;
//! - `KEYS` — the screen's keys, for the footer and the help overlay.

pub mod dashboard;
pub mod login;
pub mod pool;
pub mod profiles;
pub mod torrents;
