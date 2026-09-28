//! Resume-data success / failure handlers.
//!
//! These are the two alerts that resolve an outstanding
//! `engine.save_resume_data(handle, flags)`. The state map's in-flight entry
//! for the torrent is settled here; the shutdown coordinator waits for every
//! one to settle.

use libtorrent_safe::Alert;
use tracing::debug;
use tracing::error;

use crate::handlers::HandlerCtx;

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    match alert {
        Alert::SaveResumeData { hdr, data } => {
            let _enter = ctx.span.enter();
            let Some(ih) = hdr.infohash else {
                error!(
                    target: "torrentd_engine::handler::resume",
                    "save_resume_data alert missing infohash",
                );
                return;
            };
            // Batched: two fsyncs per file on this thread were what made a
            // 100K-torrent drain outlast its deadline. The shutdown drain
            // flushes the store before it returns, and a failure the writer
            // meets later is counted by the store's error hook under
            // `resume_write_errors_total`, as one here is.
            match ctx
                .resume
                .write_batched(&ctx.profile_id, &ih, data.as_bytes())
            {
                Ok(()) => {
                    debug!(
                        target: "torrentd_engine::handler::resume",
                        infohash = %ih,
                        bytes = data.as_bytes().len(),
                        "resume data accepted for writing",
                    );
                    ctx.metrics.inc_counter(
                        "resume_writes_total",
                        &[("profile_id", ctx.profile_id.as_str())],
                    );
                    ctx.state.update(&ih, |st| {
                        st.needs_save_resume = false;
                    });
                }
                Err(e) => {
                    error!(
                        target: "torrentd_engine::handler::resume",
                        infohash = %ih,
                        error.kind = "resume_write",
                        error.cause = %e,
                        "failed to persist resume data",
                    );
                    ctx.metrics.inc_counter(
                        "resume_write_errors_total",
                        &[("profile_id", ctx.profile_id.as_str())],
                    );
                }
            }
            ctx.state.note_resume_settled(&ih);
        }
        Alert::SaveResumeDataFailed {
            hdr,
            error_code,
            not_modified,
            message,
        } => {
            let _enter = ctx.span.enter();
            // the spec: resume_data_not_modified is the silent path — libtorrent
            // signals the resume buffer is unchanged since the last save, so
            // we just decrement and move on.
            if !*not_modified {
                let infohash_str = hdr.infohash.map(|i| i.to_hex()).unwrap_or_default();
                error!(
                    target: "torrentd_engine::handler::resume",
                    infohash = %infohash_str,
                    error.code = *error_code,
                    error.cause = %message,
                    "save_resume_data failed",
                );
                ctx.metrics.inc_counter(
                    "resume_save_failures_total",
                    &[("profile_id", ctx.profile_id.as_str())],
                );
            }
            if let Some(ih) = hdr.infohash {
                ctx.state.note_resume_settled(&ih);
            }
        }
        _ => unreachable!("resume::handle called with non-resume alert"),
    }
}
