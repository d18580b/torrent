//! The stop after the HTTP drain: waiting for pool work, stopping the
//! fencing, and taking the daemon off the network in the order that leaks
//! nothing.

use std::sync::Arc;

use torrentd_engine::ProfileId;
use torrentd_engine::TorrentEngine;
use tracing::info;
use tracing::warn;

use crate::sd_notify;

/// How long the teardown waits for pool work — a scan, a drift check, an
/// apply finishing its current step — before stopping the alert loop around
/// it. See `WorkGate`.
pub(super) const POOL_WORK_DRAIN: std::time::Duration = std::time::Duration::from_secs(20);

/// What the teardown after the resume drain is given: stopping the fencing
/// tasks (up to [`FENCING_STOP_BOUND`]), closing the sessions, the tunnels
/// (up to 7 s an OpenVPN profile, in parallel), the kill switch.
pub(super) const TEARDOWN_ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(60);

/// How long the teardown waits for the VPN monitor and the kill-switch
/// watch to return once told to stop, and for the stop's gate to close: a
/// poll or check of theirs already running shells out to `ip`, `wg` or
/// `nft`, and finishes first.
const FENCING_STOP_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Stop the VPN monitor and the kill-switch watch, waiting up to
/// [`FENCING_STOP_BOUND`] for each to return, then abort the watch in case it
/// did not, so that no later check starts.
///
/// The abort cannot cancel a check already on the blocking pool, and that
/// check would read the teardown's removal of the table as a flush. What
/// keeps it from installing the table again, or fencing the closing
/// sessions, is the stop's gate (`vpn_monitor::FencingGate`): the stop
/// closes it within the bound, after any fence or install inside it ends,
/// and the check's later ones are refused. Only a fence or install that
/// itself outlasts the bound can still land after the teardown, which the
/// warning below reports.
pub(super) async fn stop_fencing(
    fencing: crate::vpn_monitor::FencingStop,
    kill_switch_watch: Option<&tokio::task::AbortHandle>,
) {
    if !fencing.stop(FENCING_STOP_BOUND).await {
        warn!(
            bound_secs = FENCING_STOP_BOUND.as_secs(),
            "the vpn monitor or the kill-switch watch was still running at its bound; \
             tearing down the network around it",
        );
    }
    if let Some(watch) = kill_switch_watch {
        watch.abort();
    }
    info!("vpn fencing stopped; tearing down the network");
}

/// Wait up to `bound` for pool work still in flight, returning whether none
/// is left. Past the bound the teardown goes on around the work, warning.
pub(super) async fn wait_for_pool_work(
    work: &crate::app_state::WorkGate,
    bound: std::time::Duration,
) -> bool {
    if work.in_flight() == 0 {
        return true;
    }
    sd_notify::status("waiting for pool work to stop");
    info!(
        in_flight = work.in_flight(),
        bound_secs = bound.as_secs(),
        "waiting for pool work to stop",
    );
    let idle = work.wait_idle(bound).await;
    if !idle {
        warn!(
            in_flight = work.in_flight(),
            "pool work still running at its bound; tearing down around it",
        );
    }
    idle
}

/// Take the daemon off the network in the one order that leaks nothing:
///
/// 1. **Close every session**, so no socket bound to a tunnel's address is
///    left to send when the tunnel goes.
/// 2. **Bring the tunnels down**, link before rules (`wireguard::native`).
/// 3. **Remove the kill switch last**: it confines the daemon's uid to the
///    tunnels while they go.
///
/// Each session closes on the blocking pool — libtorrent's destructor waits for
/// its sockets and disk threads — and all of them at once, then the tunnels
/// the same way (`join_teardowns`).
pub(super) async fn teardown_network<K>(
    engines: Vec<Arc<dyn TorrentEngine>>,
    tunnels: Vec<(ProfileId, String, Arc<dyn torrentd_engine::VpnManager>)>,
    remove_kill_switch: K,
) where
    K: FnOnce(),
{
    let closing: Vec<_> = engines
        .into_iter()
        .map(|e| tokio::task::spawn_blocking(move || e.close()))
        .collect();
    for c in closing {
        if let Err(e) = c.await {
            warn!(error.cause = %e, "closing a session failed");
        }
    }
    info!("sessions closed");
    join_teardowns(
        tunnels
            .into_iter()
            .map(|(id, iface, vpn)| {
                let job_iface = iface.clone();
                (id, iface, move || vpn.bring_down(&job_iface))
            })
            .collect(),
    )
    .await;
    remove_kill_switch();
}

/// Put every tunnel teardown in flight at once, then join them in profile
/// order: an OpenVPN teardown can take seven seconds, and serialized they
/// would come out of the stop budget once per profile. A job that panicked is
/// warned and skipped; shutdown must not fail on a teardown.
async fn join_teardowns<J>(jobs: Vec<(ProfileId, String, J)>)
where
    J: FnOnce() + Send + 'static,
{
    let handles: Vec<_> = jobs
        .into_iter()
        .map(|(id, iface, job)| (id, iface, tokio::task::spawn_blocking(job)))
        .collect();
    for (id, iface, handle) in handles {
        if let Err(e) = handle.await {
            warn!(
                vpn_iface = %iface,
                error.cause = %e,
                "tunnel teardown task failed",
            );
            continue;
        }
        info!(profile_id = %id, vpn_iface = %iface, "tunnel down");
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast;

    use super::*;
    use crate::startup::http_stage::run_http_stage;
    use crate::startup::test_support::RecordingVpn;

    /// The fencing tasks do not hear the shutdown broadcast that starts the
    /// drain; `stop_fencing` stops them, and aborts a watch that outran its
    /// bound, so nothing reinstalls the table the teardown removes.
    #[tokio::test(start_paused = true)]
    async fn the_fencing_stops_at_stop_fencing_and_a_stuck_watch_is_aborted() {
        let (tx, _keep) = broadcast::channel(8);
        let fencing = crate::vpn_monitor::FencingStop::new();
        let mut stopped = fencing.subscribe();
        let monitor = tokio::spawn(async move { stopped.stopped().await });
        // A watch stuck in a check: it holds its stop and never reads it.
        let held = fencing.subscribe();
        let watch = tokio::spawn(async move {
            let _held = held;
            std::future::pending::<()>().await;
        });

        let code = run_http_stage(None::<()>, Some(()), |(), ()| async { 0 }, &tx).await;
        assert_eq!(code, 70);
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        assert!(
            !monitor.is_finished(),
            "the shutdown broadcast does not stop the fencing"
        );

        stop_fencing(fencing, Some(&watch.abort_handle())).await;
        monitor.await.unwrap();
        assert!(
            watch.await.unwrap_err().is_cancelled(),
            "the stuck watch is aborted"
        );
    }

    /// A teardown as [`join_teardowns`] takes one, boxed so two closures of
    /// different types can share one `Vec`.
    type BoxedTeardown = (ProfileId, String, Box<dyn FnOnce() + Send>);

    /// Every tunnel teardown is in flight at once: each job waits for the
    /// rest, and the peak count inside the closure is asserted. The deadline
    /// is a failure bound, not a measurement.
    #[tokio::test]
    async fn every_tunnel_teardown_is_in_flight_at_once() {
        const SLOTS: usize = 6;
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let jobs: Vec<_> = (0..SLOTS)
            .map(|i| {
                let live = Arc::clone(&live);
                let peak = Arc::clone(&peak);
                (
                    ProfileId::new(format!("account_{i}")),
                    format!("tun-{i}"),
                    move || {
                        use std::sync::atomic::Ordering::SeqCst;
                        let now = live.fetch_add(1, SeqCst) + 1;
                        peak.fetch_max(now, SeqCst);
                        // Hold until everyone has arrived — or give up, so a
                        // serialized `join_teardowns` fails rather than hangs.
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(5);
                        while live.load(SeqCst) < SLOTS && std::time::Instant::now() < deadline {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        live.fetch_sub(1, SeqCst);
                    },
                )
            })
            .collect();

        join_teardowns(jobs).await;

        assert_eq!(
            peak.load(std::sync::atomic::Ordering::SeqCst),
            SLOTS,
            "at most this many teardowns were ever inside the job at once; \
             a deployment's stop time must not scale with its profile count",
        );
    }

    /// The teardown's wait for pool work: nothing in flight passes straight
    /// through, work that finishes inside the bound is waited for, and work
    /// still running at the bound is torn down around rather than waited on.
    #[tokio::test]
    async fn the_teardown_waits_for_pool_work_up_to_its_bound() {
        use std::time::Duration;

        let work: Arc<crate::app_state::WorkGate> = Arc::default();
        let started = std::time::Instant::now();
        assert!(wait_for_pool_work(&work, Duration::from_secs(30)).await);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "nothing in flight"
        );

        let guard = work.enter();
        let finisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(guard);
        });
        assert!(
            wait_for_pool_work(&work, Duration::from_secs(30)).await,
            "work that finishes inside the bound is waited for",
        );
        finisher.await.unwrap();
        assert_eq!(work.in_flight(), 0);

        let _stuck = work.enter();
        let started = std::time::Instant::now();
        assert!(
            !wait_for_pool_work(&work, Duration::from_millis(100)).await,
            "work still running at the bound is reported, not waited on",
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(work.in_flight(), 1);
    }

    /// The teardown order that leaks nothing: every session closed before any
    /// tunnel goes, and the kill switch removed only after every tunnel has.
    ///
    /// The shutdown removed the kill switch first, then brought the tunnels
    /// down with the sessions still open — they were dropped only when
    /// `run_until_signal` returned — so for the length of the teardown the
    /// uid was unconfined and its sockets still bound to tunnel addresses.
    #[tokio::test]
    async fn teardown_closes_sessions_then_tunnels_then_the_kill_switch() {
        let log: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let engines: Vec<Arc<torrentd_engine::MockEngine>> = (0..2)
            .map(|_| Arc::new(torrentd_engine::MockEngine::new()))
            .collect();
        let vpn = RecordingVpn {
            log: Arc::clone(&log),
            engines: engines.clone(),
        };
        let tunnels = ["wg-a", "wg-b"]
            .into_iter()
            .map(|iface| {
                (
                    ProfileId::new(iface),
                    iface.to_string(),
                    Arc::new(vpn.clone()) as Arc<dyn torrentd_engine::VpnManager>,
                )
            })
            .collect();

        teardown_network(
            engines
                .iter()
                .map(|e| Arc::clone(e) as Arc<dyn TorrentEngine>)
                .collect(),
            tunnels,
            {
                let log = Arc::clone(&log);
                move || log.lock().unwrap().push("kill switch removed".into())
            },
        )
        .await;

        let log = log.lock().unwrap().clone();
        let mut tunnels_down: Vec<&String> = log[..2].iter().collect();
        tunnels_down.sort();
        assert_eq!(
            tunnels_down,
            vec![
                "tunnel wg-a down (every session closed: true)",
                "tunnel wg-b down (every session closed: true)",
            ],
            "each tunnel went down after every session closed: {log:?}",
        );
        assert_eq!(
            log[2], "kill switch removed",
            "the switch goes last: {log:?}"
        );
        assert_eq!(log.len(), 3);
    }

    /// And a teardown that panics is warned past rather than taking the rest
    /// of the drain with it — shutdown must not fail on a tunnel.
    #[tokio::test]
    async fn a_teardown_that_panics_does_not_abandon_the_others() {
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let jobs: Vec<BoxedTeardown> = vec![
            (
                ProfileId::new("account_a"),
                "tun-a".to_string(),
                Box::new(|| panic!("wg-quick down went wrong")),
            ),
            (
                ProfileId::new("account_b"),
                "tun-b".to_string(),
                Box::new({
                    let done = Arc::clone(&done);
                    move || {
                        done.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }),
            ),
        ];

        join_teardowns(jobs).await;

        assert_eq!(
            done.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second profile's tunnel still came down",
        );
    }
}
