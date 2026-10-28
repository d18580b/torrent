//! What a screen and the root share: the effects a screen returns, what it
//! may read while it handles a message or draws, and the toasts it raises.
//!
//! The screens depend on this module rather than on `app`. Only the root's
//! message, [`Msg`], is named here from `app`: an effect's future answers
//! with it, and it enumerates every screen's own message, so it lives with
//! the root that routes them.

use std::future::Future;
use std::pin::Pin;

use crate::api::types;
use crate::api::Api;
use crate::api::Failure;
pub use crate::app::Msg;
use crate::theme::Theme;

/// A future whose result is a message, spawned by the runtime.
pub struct Effect(pub Pin<Box<dyn Future<Output = Msg> + Send + 'static>>);

impl std::fmt::Debug for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Effect")
    }
}

impl Effect {
    /// An effect from a future.
    pub fn new(future: impl Future<Output = Msg> + Send + 'static) -> Self {
        Self(Box::pin(future))
    }

    /// A message delivered on the next turn of the loop.
    pub fn now(msg: Msg) -> Self {
        Self::new(async move { msg })
    }

    /// A toast.
    pub fn toast(toast: Toast) -> Self {
        Self::now(Msg::Toast(toast))
    }
}

/// What a screen may read while it handles a message or draws.
pub struct Ctx<'a> {
    pub api: &'a Api,
    /// What this daemon is; `None` until the first `GET /v1/server`.
    pub server: Option<&'a types::ServerInfo>,
    pub theme: &'a Theme,
    /// Render ticks since start, for spinners.
    pub tick: u64,
}

impl Ctx<'_> {
    /// Whether the daemon allows pool mutations: creating and applying
    /// plans, and deleting a torrent's files. `false` until the daemon has
    /// said what it is.
    pub fn pool_mutations_allowed(&self) -> bool {
        self.server.is_some_and(|s| s.pool.allow_mutations)
    }
}

/// A transient notice in the corner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toast {
    pub kind: ToastKind,
    pub text: String,
    /// A request id to quote, when the notice is a failure.
    pub request_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

impl Toast {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Info,
            text: text.into(),
            request_id: None,
        }
    }

    pub fn success(text: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Success,
            text: text.into(),
            request_id: None,
        }
    }

    /// A failure, with what was being attempted.
    pub fn failure(attempt: &str, failure: &Failure) -> Self {
        Self {
            kind: ToastKind::Error,
            text: format!("{attempt}: {}", failure.message()),
            request_id: failure.request_id.clone(),
        }
    }
}

/// The message a failed request produces: a sign-out for a `401`, otherwise
/// a toast saying what was being attempted.
pub fn failed(attempt: &str, failure: Failure) -> Msg {
    if failure.is_unauthenticated() {
        Msg::SignedOut(failure)
    } else {
        Msg::Toast(Toast::failure(attempt, &failure))
    }
}

/// The effects of a failure a screen shows in its own panel: a sign-out
/// when it is a `401`, and nothing otherwise.
pub fn sign_out_on_401(failure: &Failure) -> Vec<Effect> {
    if failure.is_unauthenticated() {
        vec![Effect::now(Msg::SignedOut(failure.clone()))]
    } else {
        Vec::new()
    }
}
