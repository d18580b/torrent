//! The managed pool: what is on disk, what torrents claim it, and what is
//! adopted.
//!
//! torrentd's original model was "the operator hands me torrents". That does not
//! survive contact with a multi-terabyte library already sitting on disk, where
//! the real questions are which files are protected by a torrent, which are
//! not, and which torrents reference data that has moved or vanished.
//!
//! The pool answers those. It indexes **managed roots** (directories the daemon
//! owns) and a **torrent library** (a directory of `.torrent` files, which for a
//! qBittorrent migration is simply its `BT_backup`), matches one against the
//! other, and records an adoption state per torrent plus byte rollups per
//! directory. Migrating from another client is then not a special code path —
//! it is the first scan.
//!
//! ## Change detection is tiered
//!
//! Hashing a petabyte is days of I/O, so it cannot be the routine check:
//!
//! 1. **Cheap sweep** — `(size, mtime, inode)` against the recorded snapshot.
//!    Catches essentially every real change and runs over a large pool
//!    routinely. See [`drift`].
//! 2. **Authoritative verify** — libtorrent re-hashes the payload (v1 SHA-1,
//!    v2 SHA-256 merkle). Triggered on adopt and on drift. torrentd never
//!    reimplements piece hashing.
//! 3. **Content-addressed match** — a v2 torrent carries a per-file merkle
//!    root, which identifies a file independently of its name and location.
//!    That is what lets the matcher follow a file that was moved or renamed,
//!    and what surfaces two torrents claiming the same bytes. v1 torrents have
//!    no per-file digest — pieces span file boundaries — so they match on
//!    `(path, size)` and are only confirmed by step 2.

pub mod adopt;
pub mod drift;
pub mod fastresume;
pub mod matcher;
pub mod model;
pub mod plan;
pub mod scan;
pub mod store;

pub use adopt::AdoptPlan;
pub use adopt::AdoptPreview;
pub use matcher::match_all;
pub use matcher::MatchStats;
pub use model::AdoptionState;
pub use model::DirRollup;
pub use model::PoolError;
pub use model::PoolFile;
pub use model::PoolTorrent;
pub use model::TorrentFileRow;
pub use plan::PlanSpec;
pub use scan::file_stamp;
pub use scan::scan_library;
pub use scan::scan_root;
pub use scan::ScanStats;
pub use store::PoolStore;
