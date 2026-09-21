//! Listener-side handlers: ListenFailed, ListenSucceeded.
//!
//! A `ListenFailed` is fatal when it happens to the **only live session** —
//! there is nothing else listening, so seeding would otherwise stop silently.
//! The alert loop decides that (`AlertLoopBuilder::fatal_listen_failure`,
//! keyed on the live-session count rather than on the configured profile
//! count) and sets the `listen_failure_fatal` flag on the state map via
//! `MetricsSink`, so the daemon can flush logs and exit non-zero.
//!
//! With two or more live sessions it is not fatal: the affected profile is
//! logged and counted here, the alert loop warns naming it, and the other
//! sessions keep serving.
//!
//! This handler logs and records the metric; the torrentd binary's main loop
//! reads the metric to decide whether to exit.

use libtorrent_safe::Alert;
use tracing::error;
use tracing::info;

use crate::handlers::HandlerCtx;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::ListenFailed {
            error_code,
            operation,
            endpoint,
            iface,
            message,
            ..
        } => {
            let _enter = ctx.span.enter();
            error!(
                target: "torrentd_engine::handler::listen",
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
                &[("profile_id", ctx.profile_id.as_str())],
            );
            // Also set a gauge so the binary can poll it for fatal exit.
            ctx.metrics.set_gauge(
                "listen_failure_active",
                1.0,
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
        Alert::ListenSucceeded { endpoint, .. } => {
            let _enter = ctx.span.enter();
            info!(
                target: "torrentd_engine::handler::listen",
                endpoint = %endpoint,
                "listen socket up",
            );
            ctx.metrics.set_gauge(
                "listen_failure_active",
                0.0,
                &[("profile_id", ctx.profile_id.as_str())],
            );
        }
        _ => unreachable!("listen::handle called with non-listen alert"),
    }
}
