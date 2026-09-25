//! Listener-side handlers: ListenFailed, ListenSucceeded.
//!
//! A `ListenFailed` is fatal when it happens to the **only live session** —
//! there is nothing else listening, so seeding would otherwise stop silently.
//! The alert loop decides that, not this handler: with its
//! `AlertLoopBuilder::fatal_listen_failure` hook set (keyed on the live-session
//! count rather than on the configured profile count), a `ListenFailed` alert
//! makes it record the failure, which the daemon reads back through
//! `AlertLoopHandle::listen_failed`, and signal `ShutdownReason::ListenFailed`,
//! so the daemon drains resume data and exits non-zero.
//!
//! With two or more live sessions it is not fatal: the affected profile is
//! logged and counted here, the alert loop warns naming it, and the other
//! sessions keep serving.
//!
//! This handler only logs and records metrics. Nothing in the daemon reads
//! those metrics back; they are exported for scraping and alerting.

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
            // Exported for alerting: 1 while this profile's listen socket is
            // failed, back to 0 on `ListenSucceeded`. Nothing reads it back;
            // the fatal exit is decided by the alert loop's
            // `fatal_listen_failure` hook on this same `ListenFailed` alert.
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
