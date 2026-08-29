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
pub mod metadata;
pub mod resume;
pub mod session;
pub mod settings;

pub use alert::Alert;
pub use alert::AlertKind;
pub use error::Error;
pub use error::Result;
pub use handle::InfoHash;
pub use handle::TorrentHandle;
pub use metadata::torrent_metadata;
pub use metadata::InfoHashV2;
pub use metadata::TorrentMeta;
pub use metadata::TorrentMetaFile;
pub use resume::ResumeData;
pub use session::info_hash_from_magnet;
pub use session::info_hash_from_torrent;
pub use session::session_stats_metric_index;
pub use session::torrent_tracker_host_matches;
pub use session::AddParams;
pub use session::Session;
pub use settings::MoveFlags;
pub use settings::ResumeFlags;
pub use settings::Settings;
pub use settings::TorrentFlags;
