//! `torrentctl`'s client, model, screens and loop, as a library so the
//! integration tests in `tests/` can drive the [`app`] the binary runs
//! against a real daemon. The binary (`main.rs`) only resolves the
//! configuration, owns the terminal, and calls [`runtime::run`].
//!
//! Only the modules `main.rs` or `tests/` name are `pub`. Items reachable
//! from them are exempt from `dead_code`, which the binary-only crate
//! enforced; the private modules keep that check.

// `clippy.toml` forbids a bare `tokio::spawn` so that torrentd's tasks carry
// the span that started them. A client has no request spans to carry, and
// its tasks report through the model, not a log.
#![allow(
    clippy::disallowed_methods,
    reason = "a client: no request span to carry into the tasks it spawns"
)]

pub mod api;
pub mod app;
pub mod config;
mod fmt;
pub mod runtime;
mod screens;
#[cfg(test)]
mod testing;
pub mod theme;
pub mod ui;
