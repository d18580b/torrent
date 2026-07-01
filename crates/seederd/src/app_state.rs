//! Shared state passed to axum handlers via extractors.

use std::path::PathBuf;
use std::sync::Arc;

use seederd_engine::AlertSource;
use seederd_engine::AssignmentRegistry;
use seederd_engine::StateMap;
use seederd_engine::TorrentStore;

use crate::metrics_sink::PromSink;
use crate::slot_registry::SlotRegistry;

#[derive(Clone)]
pub struct AppState {
    pub source: Arc<dyn AlertSource>,
    pub registry: Arc<AssignmentRegistry>,
    /// Runtime slot registry; `None` in single-session mode. Drives the
    /// `/slots` endpoints and the VPN health monitor.
    pub slots: Option<Arc<SlotRegistry>>,
    pub state: Arc<StateMap>,
    /// Raw `.torrent` file store; the add path persists uploads here so the
    /// startup inventory scan can re-add them if resume data is lost.
    pub torrents: Arc<dyn TorrentStore>,
    pub metrics: Arc<PromSink>,
    /// Save path used when `POST /torrents` omits `save_path` (PRD).
    pub default_save_path: PathBuf,
    /// One of `single` | `multi-slot`. Used by routes that decide
    /// whether `slot_id` is required on POST /torrents.
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Single,
    MultiSlot,
}
