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

/// Spawn a task that ends on its own — one a request, a renewal or a fence
/// lift starts, whose life is its work's rather than the daemon's — so that
/// a panic in it says what it left undone.
///
/// Such a task has no place in `task_up`: many run at once, and none being
/// up is the normal state. The panic hook already logs and counts the panic
/// itself; this adds the ERROR line naming `task` and `consequence`, then
/// carries the panic on to whoever awaits the handle returned, as a task
/// spawned without it would.
pub(crate) fn spawn_transient<F>(
    task: &'static str,
    consequence: &'static str,
    fut: F,
) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    use futures_util::FutureExt as _;

    tokio::spawn(async move {
        match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
            Ok(out) => out,
            Err(panic) => {
                error!(task, consequence, "transient task panicked");
                std::panic::resume_unwind(panic)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use super::*;
    use crate::metrics_sink::tests::daemon_sources;
    use crate::metrics_sink::tests::literal;

    /// Every `tokio::spawn` in the daemon's source outside the supervisor,
    /// by file, with why it is not a long-lived task: each ends on its own,
    /// or is awaited or aborted by what started it. A long-lived task goes
    /// through `spawn_supervised` instead, and is in `TASKS`.
    const UNSUPERVISED: &[(&str, usize, &str)] = &[
        (
            "startup/tasks.rs",
            3,
            "the supervisor: a supervised task and its watcher, and a transient task",
        ),
        (
            "sd_notify.rs",
            1,
            "a boot phase's systemd timeout extender, aborted when the phase ends",
        ),
        (
            "port_forward_monitor.rs",
            1,
            "a rebind's paced reannounce, held and awaited or aborted by its profile's renewal",
        ),
        (
            "http/v1/server.rs",
            1,
            "the /v1/events feed, which runs only while a stream listens to it",
        ),
        (
            "http/healthz.rs",
            1,
            "/livez's scheduling check, awaited within its bound and aborted past it",
        ),
        (
            "http/v1/profiles.rs",
            1,
            "a bulk resume's paced run, which the request awaits",
        ),
    ];

    /// Every task the daemon spawns is either supervised, under a name in
    /// `TASKS`, or listed in `UNSUPERVISED` with why it ends on its own; and
    /// every `TASKS` entry is a task the source still supervises. A new
    /// `tokio::spawn` fails this until it is one or the other.
    #[test]
    fn every_long_lived_task_is_supervised() {
        let mut spawns: BTreeMap<String, usize> = BTreeMap::new();
        let mut supervised = BTreeSet::new();
        for (file, _, text) in daemon_sources() {
            let n = text.matches("tokio::spawn(").count()
                + text.matches("Handle::current().spawn(").count();
            if n > 0 {
                spawns.insert(file.clone(), n);
            }
            for (at, call) in text.match_indices("spawn_supervised(") {
                let name = literal(&text[at + call.len()..])
                    .unwrap_or_else(|| panic!("{file}: a supervised task is named by a literal"));
                supervised.insert(name.to_string());
            }
        }
        let listed: BTreeMap<String, usize> = UNSUPERVISED
            .iter()
            .map(|(file, n, _)| ((*file).to_string(), *n))
            .collect();
        assert_eq!(
            spawns, listed,
            "a task is spawned outside the supervisor: run a long-lived one through \
             spawn_supervised, or list one that ends on its own in UNSUPERVISED with why"
        );
        let tasks: BTreeSet<String> = crate::metrics_sink::TASKS
            .iter()
            .map(|t| (*t).to_string())
            .collect();
        assert_eq!(
            supervised, tasks,
            "TASKS has drifted from the supervised tasks"
        );
    }

    /// A transient task that panics carries the panic to whoever awaits it,
    /// having logged what it left undone.
    #[tokio::test]
    async fn a_transient_task_that_panics_says_so_and_carries_the_panic_on() {
        let log = crate::tracing_init::Buf::default();
        let (_handle, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let _guard = torrentd_engine::testing::set_subscriber(subscriber);
        let ok = spawn_transient("fence_lift", "nothing", async { 7 });
        assert_eq!(ok.await.unwrap(), 7);
        let task = spawn_transient("fence_lift", "torrents stay paused", async {
            panic!("injected");
        });
        let err = task.await.expect_err("the panic is carried on");
        assert!(err.is_panic());
        let text = log.text();
        assert!(
            text.contains("transient task panicked")
                && text.contains("\"task\":\"fence_lift\"")
                && text.contains("torrents stay paused")
                && text.contains("\"level\":\"ERROR\""),
            "{text}"
        );
    }

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
