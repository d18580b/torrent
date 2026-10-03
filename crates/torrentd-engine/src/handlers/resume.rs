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
            // `resume_write_errors_total`, as one here is. That hook also
            // calls `StateMap::note_resume_write_failed`, because the
            // `needs_save_resume` cleared below and libtorrent's modified bit
            // are both gone by then, and nothing else would rewrite the file.
            //
            // The stale mark is cleared before the write is queued: once it
            // is queued the writer may fail it and set the mark at any
            // moment, and a clear after that would erase the mark. A write
            // the store refuses outright leaves the mark as it was.
            let mut was_stale = false;
            ctx.state.update(&ih, |st| {
                was_stale = std::mem::take(&mut st.resume_write_failed);
            });
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
                    ctx.state.update(&ih, |st| st.needs_save_resume = false);
                }
                Err(e) => {
                    if was_stale {
                        ctx.state.update(&ih, |st| st.resume_write_failed = true);
                    }
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;
    use libtorrent_safe::ResumeData;
    use libtorrent_safe::TorrentHandle;

    use super::*;
    use crate::clock::MockClock;
    use crate::engine::TorrentEngine;
    use crate::metrics::NoopSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::resume_store::ResumeStore;
    use crate::resume_store::ResumeStoreError;
    use crate::resume_store::Scan;
    use crate::state::StateMap;
    use crate::state::TorrentState;
    use crate::torrent_store::MemoryTorrentStore;

    /// A store whose writer fails every batched write before `write_batched`
    /// returns, calling the hook boot installs, or refuses it outright.
    #[derive(Debug)]
    struct FailingWriter {
        state: Arc<StateMap>,
        refuse: bool,
        inner: MemoryResumeStore,
    }

    impl ResumeStore for FailingWriter {
        fn scan(&self, profile: &ProfileId) -> Result<Scan<ResumeData>, ResumeStoreError> {
            self.inner.scan(profile)
        }
        fn write(
            &self,
            profile: &ProfileId,
            ih: &InfoHash,
            data: &[u8],
        ) -> Result<(), ResumeStoreError> {
            self.inner.write(profile, ih, data)
        }
        fn write_batched(
            &self,
            _profile: &ProfileId,
            ih: &InfoHash,
            _data: &[u8],
        ) -> Result<(), ResumeStoreError> {
            if self.refuse {
                return Err(std::io::Error::other("refused").into());
            }
            self.state.note_resume_write_failed(ih);
            Ok(())
        }
        fn delete(&self, profile: &ProfileId, ih: &InfoHash) -> Result<(), ResumeStoreError> {
            self.inner.delete(profile, ih)
        }
    }

    /// Deliver one resume answer for a torrent marked stale, through a store
    /// that fails its write, and return whether the torrent is still marked.
    fn stale_after_a_failed_write(refuse: bool) -> bool {
        let ih = InfoHash([0x21; 20]);
        let state = Arc::new(StateMap::new());
        let h = TorrentHandle {
            id: 1,
            infohash: ih,
        };
        let mut st = TorrentState::newly_added(h, ProfileId::new("p"), Instant::now());
        st.resume_write_failed = true;
        state.insert(ih, st);
        let resume = FailingWriter {
            state: Arc::clone(&state),
            refuse,
            inner: MemoryResumeStore::new(),
        };
        let torrents = MemoryTorrentStore::new();
        let metrics = NoopSink;
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        let alert = Alert::SaveResumeData {
            hdr: AlertHeader {
                kind: AlertKind::SaveResumeData,
                infohash: Some(ih),
                handle: Some(h),
                timestamp_us: 0,
            },
            data: ResumeData::new(b"d4:datae".to_vec()),
        };
        handle(&alert, &mut ctx);
        state.get(&ih).unwrap().resume_write_failed
    }

    #[test]
    fn a_writer_failure_before_the_handler_returns_keeps_the_stale_mark() {
        // The writer runs on its own thread and may fail the write, and set
        // the mark, before the handler gets past `write_batched`. Clearing
        // the mark after queueing erased that, and the file stayed stale.
        assert!(stale_after_a_failed_write(false));
    }

    #[test]
    fn a_write_the_store_refuses_leaves_the_stale_mark() {
        assert!(stale_after_a_failed_write(true));
    }
}
