//! Listener-side handlers: ListenFailed, ListenSucceeded.
//!
//! ListenFailed in single-session mode is fatal (PRD §Error Handling);
//! the alert loop sets the `listen_failure_fatal` flag on the state map
//! via `MetricsSink` so the daemon can flush logs and exit non-zero. In
//! multi-slot mode the affected slot is marked failed but the daemon
//! continues — that variant of the dispatch lives alongside slot
//! management.
//!
//! For now we log + record the metric; the seederd binary's main loop
//! reads the metric to decide whether to exit.

use tracing::{error, info};

use crate::handlers::HandlerCtx;
use libtorrent_safe::Alert;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::ListenFailed { error_code, operation, endpoint, iface, message, .. } => {
            let _enter = ctx.span.enter();
            error!(
                target: "seederd_engine::handler::listen",
                op = %operation,
                endpoint = %endpoint,
                vpn_iface = %iface,
                error.kind = "listen_failed",
                error.code = *error_code,
                error.cause = %message,
                "listen socket failed",
            );
            ctx.metrics.inc_counter(
                "listen_failures_total",
                &[("slot_id", ctx.slot_id.as_str())],
            );
            // Also set a gauge so the binary can poll it for fatal exit.
            ctx.metrics.set_gauge(
                "listen_failure_active",
                1.0,
                &[("slot_id", ctx.slot_id.as_str())],
            );
        }
        Alert::ListenSucceeded { endpoint, .. } => {
            let _enter = ctx.span.enter();
            info!(
                target: "seederd_engine::handler::listen",
                endpoint = %endpoint,
                "listen socket up",
            );
            ctx.metrics.set_gauge(
                "listen_failure_active",
                0.0,
                &[("slot_id", ctx.slot_id.as_str())],
            );
        }
        _ => unreachable!("listen::handle called with non-listen alert"),
    }
}
