//! seederd's domain layer.
//!
//! `seederd-engine` lives between the safe libtorrent wrappers and the
//! daemon binary. It defines the `TorrentEngine` trait that every business-
//! logic component is written against, plus the supporting traits
//! (`Clock`, `ResumeStore`, `VpnManager`, `MetricsSink`, `AlertSource`)
//! that close every coupling to libtorrent or the OS so unit tests can
//! drive the system in process.

#![warn(missing_debug_implementations)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod clock;
pub mod engine;
pub mod handlers;
pub mod metrics;
pub mod mock;
pub mod real;
pub mod registry;
pub mod resume_store;
pub mod slot;
pub mod source;
pub mod state;
pub mod torrent_store;
pub mod vpn;

pub mod alert_loop;

// Re-exports from libtorrent-safe so downstream crates don't need to know
// about the internal crate split.
pub use libtorrent_safe::{
    AddParams, Alert, AlertKind, Error as SafeError, InfoHash, ResumeData, ResumeFlags, Settings,
    TorrentFlags, TorrentHandle,
};

pub use clock::{Clock, MockClock, SystemClock};
pub use engine::{EngineError, TorrentEngine};
pub use metrics::{MetricsSink, NoopSink, RecordingSink};
pub use mock::{MockEngine, RecordedCall};
pub use real::RealEngine;
pub use registry::{AssignmentRegistry, RegistryError};
pub use resume_store::{FsResumeStore, MemoryResumeStore, ResumeStore};
pub use slot::{Slot, SlotConfig, SlotId, SlotStatus};
pub use source::{AlertSource, MultiSlotSource, SingleSessionSource};
pub use state::{RetryState, StateMap, TorrentPhase, TorrentState};
pub use torrent_store::{FsTorrentStore, MemoryTorrentStore, TorrentStore};
pub use vpn::{MockVpn, VpnError, VpnManager, VpnProfile, VpnType};

pub use alert_loop::{AlertLoopBuilder, AlertLoopHandle, ShutdownReason};
