//! `AlertsDropped` handler: if libtorrent's alert queue overflowed, count
//! it and log which alert types were lost. Indicates the alert loop is
//! falling behind.

use tracing::warn;

use crate::handlers::HandlerCtx;
use libtorrent_safe::Alert;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    let Alert::AlertsDropped { bits, .. } = alert else {
        unreachable!("dropped::handle called with non-dropped alert");
    };
    let _enter = ctx.span.enter();
    let total = bits[0].count_ones() + bits[1].count_ones();
    warn!(
        target: "seederd_engine::handler::dropped",
        bits_lo = bits[0],
        bits_hi = bits[1],
        kinds = total,
        "libtorrent alert queue overflowed; alerts dropped",
    );
    ctx.metrics.add_counter(
        "alerts_dropped_total",
        u64::from(total),
        &[("slot_id", ctx.slot_id.as_str())],
    );
}
