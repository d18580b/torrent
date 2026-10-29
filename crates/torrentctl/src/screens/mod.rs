//! The screens. Each module follows one contract, which `app` routes to; the
//! types it is written in — [`contract::Effect`], [`contract::Ctx`] and
//! [`contract::Toast`] — live in [`contract`]:
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
//!
//! [`login`] is the exception. It is shown in place of the tabs while
//! signed out, not as one of them, and takes every key, so it has `State`,
//! `Msg`, `on_key`, `update` and a `view` that also reads the
//! [`crate::app::Session`], but no `refresh`, `capturing` or `KEYS`; the
//! root calls it directly rather than through its screen routing.

pub mod contract;
pub mod dashboard;
pub mod login;
pub mod pool;
pub mod profiles;
pub mod torrents;
