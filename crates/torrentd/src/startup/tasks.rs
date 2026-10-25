//! The daemon's long-running background tasks, supervised under `task_up`.

use std::sync::Arc;

use torrentd_engine::MetricsSink;
use tracing::error;
use tracing::info;

use crate::metrics_sink::PromSink;

/// Spawn a long-running task under `task_up{task}`: 1 from now, 0 once the
/// task returns or panics.
///
/// A task spawned with its handle discarded that panicked would leave the
/// daemon healthy by every signal it has — `/healthz` reads the alert loop
/// only — with its tunnels unwatched; here a panic is logged at `error` and
/// the gauge drops to 0. A task that returns, or is stopped, is logged at
/// `info`: each of these returns only on shutdown, and at shutdown the gauge
/// going to 0 is harmless. The handle returned stops the task, for a failed
/// boot to stop what it started.
pub(super) fn spawn_supervised<F>(
    task: &'static str,
    metrics: Arc<PromSink>,
    fut: F,
) -> tokio::task::AbortHandle
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let labels = [("task", task)];
    metrics.set_gauge("task_up", 1.0, &labels);
    let handle = tokio::spawn(fut);
    let abort = handle.abort_handle();
    tokio::spawn(async move {
        match handle.await {
            Ok(()) => info!(task, "background task exited"),
            Err(e) if e.is_cancelled() => info!(task, "background task stopped"),
            Err(e) => error!(
                task,
                error.cause = %e,
                "background task panicked; what it watched is no longer watched",
            ),
        }
        metrics.set_gauge("task_up", 0.0, &[("task", task)]);
    });
    abort
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A supervised task stopped through the handle `spawn_supervised`
    /// returns is logged as stopped, not as a panic, and `task_up` goes to 0.
    #[tokio::test]
    async fn a_stopped_supervised_task_is_logged_as_stopped_not_as_a_panic() {
        let log = crate::tracing_init::Buf::default();
        let (_handle, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let _guard = torrentd_engine::testing::set_subscriber(subscriber);
        let metrics = Arc::new(PromSink::new());
        let up = || {
            String::from_utf8(metrics.render())
                .unwrap()
                .lines()
                .find(|l| {
                    !l.starts_with('#')
                        && l.contains("task_up{")
                        && l.contains("task=\"kill_switch_watch\"")
                })
                .map(str::to_owned)
        };

        let stop = spawn_supervised(
            "kill_switch_watch",
            metrics.clone(),
            std::future::pending::<()>(),
        );
        let line = up().expect("task_up is exported");
        assert!(line.ends_with(" 1"), "{line}");
        stop.abort();
        for _ in 0..1_000 {
            if up().is_some_and(|l| l.ends_with(" 0")) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let line = up().expect("task_up is exported");
        assert!(line.ends_with(" 0"), "{line}");
        let text = log.text();
        assert!(
            text.contains("background task stopped")
                && !text.contains("panicked")
                && !text.contains("\"level\":\"ERROR\""),
            "{text}"
        );
    }
}
