//! Shared state passed to axum handlers via extractors.

use std::sync::Arc;

use seederd_engine::{AlertSource, AssignmentRegistry, StateMap};

use crate::metrics_sink::PromSink;

#[derive(Clone)]
pub struct AppState {
    pub source: Arc<dyn AlertSource>,
    pub registry: Arc<AssignmentRegistry>,
    pub state: Arc<StateMap>,
    pub metrics: Arc<PromSink>,
    /// One of `single` | `multi-slot`. Used by routes that decide
    /// whether `slot_id` is required on POST /torrents.
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode { Single, MultiSlot }
