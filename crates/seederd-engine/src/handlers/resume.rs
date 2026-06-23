//! Resume-data success / failure handlers.
//!
//! These are the two alerts that resolve an outstanding
//! `engine.save_resume_data(handle, flags)`. The state map's
//! `pending_resume_count` is decremented here; the shutdown coordinator
//! waits for it to reach zero.

use tracing::{debug, error};

use crate::handlers::HandlerCtx;
use libtorrent_safe::Alert;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::SaveResumeData { hdr, data } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else {
                error!(
                    target: "seederd_engine::handler::resume",
                    "save_resume_data alert missing infohash",
                );
                ctx.state.note_resume_settled();
                return;
            };
            match ctx.resume.write(&ctx.slot_id, &ih, data.as_bytes()) {
                Ok(()) => {
                    debug!(
                        target: "seederd_engine::handler::resume",
                        infohash = %ih,
                        bytes = data.as_bytes().len(),
                        "resume data persisted",
                    );
                    ctx.metrics
                        .inc_counter("resume_writes_total", &[("slot_id", ctx.slot_id.as_str())]);
                    ctx.state.update(&ih, |st| {
                        st.needs_save_resume = false;
                    });
                }
                Err(e) => {
                    error!(
                        target: "seederd_engine::handler::resume",
                        infohash = %ih,
                        error.kind = "resume_write",
                        error.cause = %e,
                        "failed to persist resume data",
                    );
                    ctx.metrics.inc_counter(
                        "resume_write_errors_total",
                        &[("slot_id", ctx.slot_id.as_str())],
                    );
                }
            }
            ctx.state.note_resume_settled();
        }
        Alert::SaveResumeDataFailed {
            hdr,
            error_code,
            not_modified,
            message,
        } => {
            let _enter = ctx.span.enter();
            // PRD: resume_data_not_modified is the silent path — libtorrent
            // signals the resume buffer is unchanged since the last save, so
            // we just decrement and move on.
            if !*not_modified {
                let infohash_str = hdr.infohash.map(|i| i.to_hex()).unwrap_or_default();
                error!(
                    target: "seederd_engine::handler::resume",
                    infohash = %infohash_str,
                    error.code = *error_code,
                    error.cause = %message,
                    "save_resume_data failed",
                );
                ctx.metrics.inc_counter(
                    "resume_save_failures_total",
                    &[("slot_id", ctx.slot_id.as_str())],
                );
            }
            ctx.state.note_resume_settled();
        }
        _ => unreachable!("resume::handle called with non-resume alert"),
    }
}
