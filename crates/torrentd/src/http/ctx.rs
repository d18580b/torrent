//! The context every handler runs against.

use std::sync::Arc;

use kynos::security::Authenticates;

use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Gate;
use crate::http::OpenApiJson;

/// What kynos hands each request: the daemon's shared state, the rendered
/// OpenAPI document, and the authenticator for the bearer scheme.
///
/// Handlers are provided the state and the document; the authenticator is
/// reached only through [`Authenticates`].
#[derive(Clone, kynos::Provider)]
pub struct AppCtx {
    pub state: Arc<AppState>,
    openapi: OpenApiJson,
    #[provide(skip)]
    gate: Gate,
}

impl AppCtx {
    pub fn new(state: AppState, openapi: OpenApiJson) -> Self {
        let gate = Gate {
            auth: state.auth.clone(),
            metrics: Arc::clone(&state.metrics),
            allowed_hosts: state.allowed_hosts.clone(),
            refusal_log: Arc::default(),
        };
        Self {
            state: Arc::new(state),
            openapi,
            gate,
        }
    }
}

impl Authenticates<Bearer> for AppCtx {
    type Authenticator = Gate;

    fn authenticator(&self) -> &Gate {
        &self.gate
    }
}
