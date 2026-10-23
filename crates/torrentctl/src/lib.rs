//! `torrentctl`'s client, model, screens and loop, as a library so the
//! integration tests in `tests/` can drive the [`app`] the binary runs
//! against a real daemon. The binary (`main.rs`) only resolves the
//! configuration, owns the terminal, and calls [`runtime::run`].

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
