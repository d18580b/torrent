//! What a failed boot leaves on the host, and the guard that takes it down.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context;
use torrentd_engine::TorrentEngine;
use tracing::warn;

use super::shutdown_report::finish_boot_kill_switch_removal;

/// Undoes what `boot` raised on the host — sessions, tunnels and the kill
/// switch, all of which outlive the process — for every exit from `boot` that
/// is not a successful one. Armed from construction; `disarm` hands ownership
/// to the shutdown path.
pub(super) struct BootCleanup {
    run_dir: std::path::PathBuf,
    /// How a tunnel's manager is built, for bring-up and teardown alike.
    /// Production passes `vpn::for_type`; tests pass a mock.
    vpn_for: VpnFactory,
    tunnels: Vec<(torrentd_engine::VpnType, String)>,
    /// Every session boot built, closed before any tunnel goes.
    sessions: Vec<Arc<dyn TorrentEngine>>,
    kill_switch: bool,
    /// The kill-switch watch, stopped before the switch is removed: left
    /// running, its next check would read the removal as a flush and install
    /// the table again.
    kill_switch_watch: Option<tokio::task::AbortHandle>,
    armed: bool,
}

/// Builds the `VpnManager` for a tunnel `BootCleanup` has to take down.
type VpnFactory = Arc<
    dyn Fn(torrentd_engine::VpnType, &std::path::Path) -> Arc<dyn torrentd_engine::VpnManager>
        + Send
        + Sync,
>;

impl std::fmt::Debug for BootCleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootCleanup")
            .field("run_dir", &self.run_dir)
            .field("tunnels", &self.tunnels)
            .field("sessions", &self.sessions.len())
            .field("kill_switch", &self.kill_switch)
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl BootCleanup {
    pub(super) fn new(run_dir: std::path::PathBuf) -> Self {
        Self::with_vpn_factory(run_dir, Arc::new(crate::vpn::for_type))
    }

    pub(super) fn with_vpn_factory(run_dir: std::path::PathBuf, vpn_for: VpnFactory) -> Self {
        Self {
            run_dir,
            vpn_for,
            tunnels: Vec::new(),
            sessions: Vec::new(),
            kill_switch: false,
            kill_switch_watch: None,
            armed: true,
        }
    }

    /// Record a tunnel this boot may have raised.
    ///
    /// Called *before* the bring-up attempt, not after it succeeds — see
    /// `bring_up_tracked`.
    fn note_tunnel(&mut self, t: torrentd_engine::VpnType, iface: &str) {
        self.tunnels.push((t, iface.to_string()));
    }

    pub(super) fn note_kill_switch(&mut self) {
        self.kill_switch = true;
    }

    /// Record the kill-switch watch, for the drop guard to stop first.
    pub(super) fn note_kill_switch_watch(&mut self, watch: tokio::task::AbortHandle) {
        self.kill_switch_watch = Some(watch);
    }

    /// Record the sessions boot built, for the drop guard to close before it
    /// takes any tunnel down.
    pub(super) fn note_sessions(
        &mut self,
        sessions: impl IntoIterator<Item = Arc<dyn TorrentEngine>>,
    ) {
        self.sessions.extend(sessions);
    }

    /// Bring one recorded tunnel down and stop tracking it — for a profile
    /// that failed after its tunnel came up. The only teardown `boot` runs
    /// outside `Drop`.
    ///
    /// On `spawn_blocking`, because an OpenVPN teardown polls for the process
    /// to exit for up to seven seconds. An interface this boot did not record
    /// spawns nothing.
    pub(super) async fn take_down_off_worker(&mut self, iface: &str) -> anyhow::Result<()> {
        let Some(i) = self.tunnels.iter().position(|(_, n)| n == iface) else {
            return Ok(());
        };
        let (t, name) = self.tunnels.remove(i);
        let vpn_for = Arc::clone(&self.vpn_for);
        let run_dir = self.run_dir.clone();
        tokio::task::spawn_blocking(move || vpn_for(t, &run_dir).bring_down(&name))
            .await
            .context("vpn teardown task")?;
        Ok(())
    }

    /// The manager for a tunnel of this type, built by the same factory the
    /// teardown paths use.
    pub(super) fn manager_for(
        &self,
        t: torrentd_engine::VpnType,
    ) -> Arc<dyn torrentd_engine::VpnManager> {
        (self.vpn_for)(t, &self.run_dir)
    }

    /// Stop tracking `iface` without bringing it down — for an interface this
    /// boot turned out not to own.
    fn forget_tunnel(&mut self, iface: &str) {
        self.tunnels.retain(|(_, n)| n != iface);
    }

    /// Bring a profile's tunnel up on `spawn_blocking`, recording it
    /// **before** the attempt: a failed bring-up can leave a link or a forked
    /// `openvpn` behind, and only a record lets this teardown or `Drop` reach
    /// it. `bring_down` of something never raised is a logged no-op.
    ///
    /// The exception is `VpnError::ForeignInterface`: an interface that was
    /// already standing when the attempt began is not this boot's, so it is
    /// forgotten rather than torn down.
    pub(super) async fn bring_up_tracked(
        &mut self,
        t: torrentd_engine::VpnType,
        tunnel: torrentd_engine::VpnTunnel,
    ) -> anyhow::Result<Result<IpAddr, torrentd_engine::VpnError>> {
        let iface = tunnel.interface.clone();
        let vpn = self.manager_for(t);
        self.note_tunnel(t, &iface);
        let brought_up = tokio::task::spawn_blocking(move || vpn.bring_up(&tunnel))
            .await
            .context("vpn bring-up task")?;
        match &brought_up {
            Ok(_) => {}
            Err(torrentd_engine::VpnError::ForeignInterface { .. }) => {
                warn!(
                    vpn_iface = %iface,
                    "an interface of this name is already up and is not this profile's; \
                     leaving it alone",
                );
                self.forget_tunnel(&iface);
            }
            Err(_) => {
                self.take_down_off_worker(&iface).await?;
            }
        }
        Ok(brought_up)
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BootCleanup {
    /// Runs on whatever worker drops the guard, since `drop` cannot await:
    /// acceptable only because the boot has failed and the process is exiting.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // The watch first: it fences the sessions and reinstalls the table
        // this guard is about to remove. A check already running on the
        // blocking pool finishes; aborting stops every one after it.
        if let Some(watch) = self.kill_switch_watch.take() {
            watch.abort();
        }
        // Sessions, then tunnels, then the kill switch, as `teardown_network`
        // does: no socket outlives its route, and the switch confines the uid
        // until the tunnels are gone.
        for session in std::mem::take(&mut self.sessions) {
            session.close();
        }
        for (t, iface) in std::mem::take(&mut self.tunnels) {
            warn!(vpn_iface = %iface, "boot failed: bringing tunnel down");
            (self.vpn_for)(t, &self.run_dir).bring_down(&iface);
        }
        if self.kill_switch {
            finish_boot_kill_switch_removal(&self.run_dir, crate::vpn::killswitch::disable());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use torrentd_engine::MockVpn;
    use torrentd_engine::VpnTunnel;
    use torrentd_engine::VpnType;

    use super::*;
    use crate::startup::test_support::RecordingVpn;

    fn profile(iface: &str) -> VpnTunnel {
        VpnTunnel {
            r#type: VpnType::Wireguard,
            config_path: PathBuf::from(format!("/etc/wireguard/{iface}.conf")),
            interface: iface.to_string(),
        }
    }

    /// `BootCleanup` wired to a `MockVpn`, so a teardown is observable
    /// without shelling out to `wg-quick`.
    fn cleanup_with(vpn: MockVpn) -> BootCleanup {
        BootCleanup::with_vpn_factory(
            PathBuf::from("/var/lib/torrentd"),
            Arc::new(move |_t, _dir| Arc::new(vpn.clone()) as Arc<dyn torrentd_engine::VpnManager>),
        )
    }

    /// A `VpnManager` that records **which thread** its teardown ran on.
    ///
    /// `MockVpn` records the interface, which cannot tell a teardown that
    /// held a runtime worker for its bounded exit wait from one that did
    /// not — and that distinction is the whole of what the teardown paths
    /// here were repaired for.
    #[derive(Clone, Debug, Default)]
    struct ThreadWatchingVpn {
        down_on: Arc<std::sync::Mutex<Vec<std::thread::ThreadId>>>,
    }

    impl torrentd_engine::VpnManager for ThreadWatchingVpn {
        fn bring_up(&self, profile: &VpnTunnel) -> Result<IpAddr, torrentd_engine::VpnError> {
            Err(torrentd_engine::VpnError::BringUpTimeout {
                iface: profile.interface.clone(),
            })
        }

        fn current_ip(&self, iface: &str) -> Result<IpAddr, torrentd_engine::VpnError> {
            Err(torrentd_engine::VpnError::NoAddress {
                iface: iface.to_string(),
            })
        }

        fn global_ipv6(
            &self,
            _iface: &str,
        ) -> Result<Vec<std::net::Ipv6Addr>, torrentd_engine::VpnError> {
            Ok(Vec::new())
        }

        fn bring_down(&self, _iface: &str) {
            self.down_on
                .lock()
                .expect("no test panics while holding this")
                .push(std::thread::current().id());
        }
    }

    /// A tunnel whose bring-up fails *after* the spawn.
    ///
    /// `openvpn --daemon` exits 0 as soon as it forks, and `wg-quick up`
    /// creates the interface before any address appears, so the 30-second
    /// address poll expiring leaves something live behind. Recording the
    /// tunnel only once an address had appeared meant nothing ever brought
    /// that one down: the failure arm called neither `note_tunnel` nor any
    /// teardown, unlike its four siblings, and `ProfileRegistry::iter()`
    /// excludes failed profiles so the shutdown loop never saw it either.
    #[tokio::test]
    async fn a_tunnel_whose_bring_up_fails_is_still_brought_down() {
        let vpn = MockVpn::new();
        // No `set_ip`, so `bring_up` fails the way the address poll does.
        let mut cleanup = cleanup_with(vpn.clone());
        let r = cleanup
            .bring_up_tracked(VpnType::Wireguard, profile("wg-a"))
            .await
            .expect("the bring-up task itself did not fail");
        assert!(r.is_err(), "the mock has no address for wg-a");
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-a".to_string()],
            "a half-up tunnel must be torn down, not left standing",
        );
        // And it is no longer tracked, so the drop guard does not try again.
        drop(cleanup);
        assert_eq!(vpn.bring_down_calls(), vec!["wg-a".to_string()]);
    }

    /// The exception to "record it before the attempt": a foreign interface
    /// of that name is touched neither by this arm nor by the drop guard.
    #[tokio::test]
    async fn a_bring_up_refused_by_a_foreign_interface_leaves_it_standing() {
        let vpn = MockVpn::new();
        vpn.set_foreign("wg-a");
        let mut cleanup = cleanup_with(vpn.clone());
        let r = cleanup
            .bring_up_tracked(VpnType::Wireguard, profile("wg-a"))
            .await
            .expect("the bring-up task itself did not fail");
        assert!(
            matches!(r, Err(torrentd_engine::VpnError::ForeignInterface { .. })),
            "the manager refuses an interface it cannot vouch for; got {r:?}",
        );
        assert!(
            vpn.bring_down_calls().is_empty(),
            "a tunnel this boot did not raise is not this boot's to tear down",
        );
        // And it was never tracked, so the drop guard does not take it down
        // when boot goes on to fail for want of that profile either.
        drop(cleanup);
        assert!(
            vpn.bring_down_calls().is_empty(),
            "nor is it the drop guard's",
        );
    }

    /// The other half of the same repair: a tunnel that came up is left
    /// standing for the daemon that is about to use it, and is handed to the
    /// drop guard rather than torn down here.
    #[tokio::test]
    async fn a_tunnel_that_came_up_is_left_running_and_tracked() {
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        let mut cleanup = cleanup_with(vpn.clone());
        let r = cleanup
            .bring_up_tracked(VpnType::Wireguard, profile("wg-a"))
            .await
            .expect("the bring-up task itself did not fail");
        assert_eq!(
            r.expect("wg-a came up"),
            IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
        );
        assert!(
            vpn.bring_down_calls().is_empty(),
            "a tunnel that came up is not torn down by the bring-up path",
        );
        // Boot then fails somewhere later — a pool that will not open, a
        // resume directory that cannot be read — and the guard takes it down.
        drop(cleanup);
        assert_eq!(vpn.bring_down_calls(), vec!["wg-a".to_string()]);
    }

    /// `boot`'s teardown keeps its bounded wait off the runtime worker.
    #[tokio::test]
    async fn boots_only_teardown_keeps_its_bounded_wait_off_the_worker() {
        let vpn = ThreadWatchingVpn::default();
        let observed = Arc::clone(&vpn.down_on);
        let mut cleanup = BootCleanup::with_vpn_factory(
            PathBuf::from("/var/lib/torrentd"),
            Arc::new(move |_t, _dir| Arc::new(vpn.clone()) as Arc<dyn torrentd_engine::VpnManager>),
        );
        cleanup.note_tunnel(VpnType::Openvpn, "tun-a");

        cleanup
            .take_down_off_worker("tun-a")
            .await
            .expect("the teardown task itself did not fail");

        let threads = observed.lock().expect("uncontended").clone();
        assert_eq!(threads.len(), 1, "the tunnel was torn down exactly once");
        assert_ne!(
            threads[0],
            std::thread::current().id(),
            "the bounded exit wait must not run on the thread `boot` is on",
        );

        // And it is no longer tracked, so the drop guard does not wait again.
        drop(cleanup);
        assert_eq!(
            observed.lock().expect("uncontended").len(),
            1,
            "a tunnel taken down here is not the drop guard's to take again",
        );
    }

    /// The other half of the helper's contract: an interface this boot never
    /// recorded spawns nothing, so nothing waits.
    #[tokio::test]
    async fn an_untracked_interface_yields_no_teardown_at_all() {
        let vpn = ThreadWatchingVpn::default();
        let observed = Arc::clone(&vpn.down_on);
        let mut cleanup = BootCleanup::with_vpn_factory(
            PathBuf::from("/var/lib/torrentd"),
            Arc::new(move |_t, _dir| Arc::new(vpn.clone()) as Arc<dyn torrentd_engine::VpnManager>),
        );
        cleanup
            .take_down_off_worker("tun-never-raised")
            .await
            .expect("nothing to do is not a failure");
        assert!(
            observed.lock().expect("uncontended").is_empty(),
            "an interface this boot did not record is not brought down",
        );
    }

    /// A failed boot closes the sessions it built before any tunnel goes,
    /// as `teardown_network` does: past the port-forward monitor's start,
    /// dropping `boot`'s own handles no longer destroys them.
    #[test]
    fn a_failed_boot_closes_its_sessions_before_its_tunnels() {
        let log: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let engines: Vec<Arc<torrentd_engine::MockEngine>> = (0..2)
            .map(|_| Arc::new(torrentd_engine::MockEngine::new()))
            .collect();
        let vpn = RecordingVpn {
            log: Arc::clone(&log),
            engines: engines.clone(),
        };
        let mut cleanup = BootCleanup::with_vpn_factory(
            PathBuf::from("/var/lib/torrentd"),
            Arc::new(move |_t, _dir| Arc::new(vpn.clone()) as Arc<dyn torrentd_engine::VpnManager>),
        );
        cleanup.note_tunnel(VpnType::Wireguard, "wg-a");
        cleanup.note_sessions(
            engines
                .iter()
                .map(|e| Arc::clone(e) as Arc<dyn TorrentEngine>),
        );

        drop(cleanup);

        assert_eq!(
            log.lock().unwrap().clone(),
            vec!["tunnel wg-a down (every session closed: true)".to_string()],
        );
    }

    /// A disarmed guard closes nothing: the sessions are the shutdown path's.
    #[test]
    fn a_disarmed_boot_cleanup_leaves_its_sessions_open() {
        let engine = Arc::new(torrentd_engine::MockEngine::new());
        let mut cleanup = cleanup_with(MockVpn::default());
        cleanup.note_sessions([Arc::clone(&engine) as Arc<dyn TorrentEngine>]);
        cleanup.disarm();
        drop(cleanup);
        assert!(!engine
            .calls()
            .iter()
            .any(|c| matches!(c, torrentd_engine::RecordedCall::Close)));
    }

    /// `disarm` hands the tunnels to the shutdown path; dropping after it
    /// must not stop the daemon that just started.
    #[tokio::test]
    async fn a_disarmed_guard_leaves_the_running_daemon_alone() {
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        let mut cleanup = cleanup_with(vpn.clone());
        let _ = cleanup
            .bring_up_tracked(VpnType::Wireguard, profile("wg-a"))
            .await;
        cleanup.disarm();
        drop(cleanup);
        assert!(vpn.bring_down_calls().is_empty());
    }

    /// A failed boot stops the kill-switch watch it started, which would
    /// otherwise read the guard's removal of the table as a flush and install
    /// it again; a boot that succeeded leaves it running.
    #[tokio::test]
    async fn a_failed_boot_stops_the_kill_switch_watch() {
        let watch = |cleanup: &mut BootCleanup| {
            let task = tokio::spawn(std::future::pending::<()>());
            cleanup.note_kill_switch_watch(task.abort_handle());
            task
        };

        let mut failed = cleanup_with(MockVpn::new());
        let stopped = watch(&mut failed);
        drop(failed);
        let joined = stopped.await.expect_err("the watch was stopped");
        assert!(joined.is_cancelled(), "{joined}");

        let mut booted = cleanup_with(MockVpn::new());
        let running = watch(&mut booted);
        booted.disarm();
        drop(booted);
        tokio::task::yield_now().await;
        assert!(
            !running.is_finished(),
            "a booted daemon's watch keeps running"
        );
        running.abort();
    }
}
