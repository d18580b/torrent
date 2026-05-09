//! Safe RAII wrappers over `libtorrent-sys`.
//!
//! Every entry point in this crate is `unsafe`-free for downstream callers.
//! The crate is deliberately thin: it owns the C++ session lifetime, marshals
//! payloads, and converts shim error codes into typed `Result`s. No business
//! logic — that lives in `seederd-engine`.

#![warn(missing_debug_implementations)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod alert;
pub mod error;
pub mod handle;
pub mod resume;
pub mod session;
pub mod settings;

pub use alert::{Alert, AlertKind};
pub use error::{Error, Result};
pub use handle::{InfoHash, TorrentHandle};
pub use resume::ResumeData;
pub use session::{AddParams, Session};
pub use settings::{ResumeFlags, Settings, TorrentFlags};
