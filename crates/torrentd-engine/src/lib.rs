//! torrentd's domain layer.
//!
//! `torrentd-engine` lives between the safe libtorrent wrappers and the
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
pub mod policy;
pub mod port_forward;
pub mod profile;
pub mod real;
pub mod registry;
pub mod resume_store;
pub mod source;
pub mod state;
pub mod torrent_store;
pub mod vpn;

pub mod alert_loop;

// Re-exports from libtorrent-safe so downstream crates don't need to know
// about the internal crate split.
pub use alert_loop::heartbeat_age;
pub use alert_loop::AlertLoopBuilder;
pub use alert_loop::AlertLoopHandle;
pub use alert_loop::FatalCallback;
pub use alert_loop::ProfileFenced;
pub use alert_loop::ShutdownReason;
pub use alert_loop::DEFAULT_SHUTDOWN_DEADLINE;
pub use alert_loop::POST_UPDATES_INTERVAL;
pub use clock::Clock;
pub use clock::MockClock;
pub use clock::SystemClock;
pub use engine::EngineError;
pub use engine::MoveFlags;
pub use engine::TorrentEngine;
pub use libtorrent_safe::AddParams;
pub use libtorrent_safe::Alert;
pub use libtorrent_safe::AlertKind;
pub use libtorrent_safe::Error as SafeError;
pub use libtorrent_safe::InfoHash;
pub use libtorrent_safe::ResumeData;
pub use libtorrent_safe::ResumeFlags;
pub use libtorrent_safe::Settings;
pub use libtorrent_safe::TorrentDetails;
pub use libtorrent_safe::TorrentFile;
pub use libtorrent_safe::TorrentFlags;
pub use libtorrent_safe::TorrentHandle;
pub use libtorrent_safe::TrackerEntry;
pub use metrics::MetricsSink;
pub use metrics::NoopSink;
pub use metrics::RecordingSink;
pub use mock::MockEngine;
pub use mock::RecordedCall;
pub use policy::discovery_guards;
pub use policy::resume_flags_set;
pub use policy::seed_flags;
pub use policy::verify_flags;
pub use port_forward::renew_and_rebind;
pub use port_forward::MapResult;
pub use port_forward::MockForwarder;
pub use port_forward::PortForwardError;
pub use port_forward::PortForwardMode;
pub use port_forward::PortForwarder;
pub use port_forward::PortMapRequest;
pub use port_forward::RenewOutcome;
pub use profile::bind_endpoint;
pub use profile::ProfileConfig;
pub use profile::ProfileConfigError;
pub use profile::ProfileId;
pub use profile::ProfileNetwork;
pub use profile::ProfileStatus;
pub use real::RealEngine;
pub use registry::AssignmentRegistry;
pub use registry::RegistryError;
pub use resume_store::FsResumeStore;
pub use resume_store::MemoryResumeStore;
pub use resume_store::ResumeStore;
pub use source::AlertSource;
pub use source::ProfileSource;
pub use state::RetryState;
pub use state::StateMap;
pub use state::StorageMove;
pub use state::TorrentPhase;
pub use state::TorrentState;
pub use torrent_store::FsTorrentStore;
pub use torrent_store::MemoryTorrentStore;
pub use torrent_store::TorrentStore;
pub use vpn::MockVpn;
pub use vpn::VpnError;
pub use vpn::VpnManager;
pub use vpn::VpnTunnel;
pub use vpn::VpnType;
