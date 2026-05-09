//! Error type for the safe wrappers.

use thiserror::Error;

use crate::handle::InfoHash;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors surfaced by the safe libtorrent wrappers.
///
/// `ShimError` is the catch-all for failures reported by the C shim (libtorrent
/// exceptions, parse errors, etc.). Specific variants exist for failure modes
/// callers commonly want to branch on.
#[derive(Debug, Error)]
pub enum Error {
    /// Wrapped error string from the C shim's `err_out` buffer.
    #[error("libtorrent shim error: {0}")]
    Shim(String),

    /// I/O error from a Rust-side operation (e.g. resume file write).
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Failed to serialize settings to the JSON form the shim expects.
    #[error("settings serialization failed: {0}")]
    SettingsSerialize(#[from] serde_json::Error),

    /// The session has been destroyed; the wrapper is no longer usable.
    #[error("session is closed")]
    SessionClosed,

    /// Caller provided an `lt_handle` the session does not know about.
    #[error("torrent not found: {}", hex::encode(.0.as_bytes()))]
    TorrentNotFound(InfoHash),

    /// A NUL byte was found in a string we needed to pass through C.
    #[error("string contained interior NUL: {0}")]
    InteriorNul(String),

    /// Caller-supplied buffer was malformed (e.g. zero-length resume data).
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}
