//! Per-alert dispatch. One module per alert family; each exposes a
//! `handle(&Alert, &mut HandlerCtx)` free function. The central dispatcher
//! in `alert_loop.rs` matches on the `Alert` variant and routes here.

pub mod add;
pub mod dropped;
pub mod error;
pub mod listen;
pub mod log_msg;
pub mod metadata;
pub mod resume;
pub mod state_update;
pub mod stats;
pub mod storage;

use std::sync::Arc;

use tracing::Span;

use crate::clock::Clock;
use crate::engine::TorrentEngine;
use crate::metrics::MetricsSink;
use crate::profile::ProfileId;
use crate::resume_store::ResumeStore;
use crate::state::StateMap;
use crate::torrent_store::TorrentStore;

/// Borrowed state passed to every handler. One ctx per alert (cheap to
/// build because everything is a reference). The lifetime is tied to the
/// dispatch call, not the alert loop's lifetime.
pub struct HandlerCtx<'a> {
    pub state: &'a StateMap,
    pub resume: &'a dyn ResumeStore,
    pub torrents: &'a dyn TorrentStore,
    pub metrics: &'a dyn MetricsSink,
    pub clock: &'a dyn Clock,
    pub engine: &'a Arc<dyn TorrentEngine>,
    pub profile_id: ProfileId,
    pub span: Span,
}

impl<'a> std::fmt::Debug for HandlerCtx<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerCtx")
            .field("profile_id", &self.profile_id)
            .finish_non_exhaustive()
    }
}
