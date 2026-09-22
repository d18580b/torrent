//! Startup orchestrator: build the engine(s), wire the alert loop, bind
//! the HTTP server, install signal handlers, and run until shutdown.
//!
//! The single-session and multi-slot paths converge at the AlertSource
//! trait — both produce an `Arc<dyn AlertSource>` that the rest of the
//! daemon consumes uniformly.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use torrentd_engine::AddParams;
use torrentd_engine::AlertLoopBuilder;
use torrentd_engine::AlertSource;
use torrentd_engine::AssignmentRegistry;
use torrentd_engine::FsResumeStore;
use torrentd_engine::FsTorrentStore;
use torrentd_engine::MetricsSink;
use torrentd_engine::MultiSlotSource;
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use torrentd_engine::RealEngine;
use torrentd_engine::ResumeStore;
use torrentd_engine::ShutdownReason;
use torrentd_engine::SingleSessionSource;
use torrentd_engine::SlotId;
use torrentd_engine::SlotStatus;
use torrentd_engine::StateMap;
use torrentd_engine::SystemClock;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentFlags;
use torrentd_engine::TorrentStore;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::app_state::Mode;
use crate::config::Config;
use crate::http;
use crate::metrics_sink::PromSink;
use crate::reload;
use crate::sd_notify;
use crate::signals::SignalChannels;
use crate::signals::{self};
use crate::slot_registry::SlotEntry;
use crate::slot_registry::SlotRegistry;
use crate::vpn;

/// How stale the alert loop's heartbeat may be before the watchdog ping is
/// withheld.
///
/// Matches `/healthz`'s bound: both are asking the same question, and a
/// daemon that reports 503 to a load balancer while telling systemd it is
/// healthy is the worst of both answers.
const WATCHDOG_MAX_HEARTBEAT_AGE: std::time::Duration = std::time::Duration::from_secs(15);

/// Undoes what `boot` raised on the host, for every exit from `boot` that is
/// not a successful one.
///
/// Tunnels and the nftables kill-switch table outlive the process that created
/// them, and `boot` has a dozen `?`s after the point where it starts creating
/// them — a pool database that will not open, a resume directory that cannot
/// be read. Each of those used to leave the host with live tunnels, a table
/// confining a uid that no longer exists, and no daemon to explain either.
///
/// Armed from construction; `disarm` hands ownership to the shutdown path.
struct BootCleanup {
    run_dir: std::path::PathBuf,
    /// How a recorded tunnel's manager is built. Injected so the teardown
    /// paths below are reachable by a test without shelling out to
    /// `wg-quick` or `kill`; production always passes `vpn::for_type`.
    vpn_for: VpnFactory,
    tunnels: Vec<(torrentd_engine::VpnType, String)>,
    kill_switch: bool,
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
            .field("kill_switch", &self.kill_switch)
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl BootCleanup {
    fn new(run_dir: std::path::PathBuf) -> Self {
        Self::with_vpn_factory(run_dir, Arc::new(crate::vpn::for_type))
    }

    fn with_vpn_factory(run_dir: std::path::PathBuf, vpn_for: VpnFactory) -> Self {
        Self {
            run_dir,
            vpn_for,
            tunnels: Vec::new(),
            kill_switch: false,
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

    fn note_kill_switch(&mut self) {
        self.kill_switch = true;
    }

    /// Bring one tunnel down and stop tracking it — for a slot that failed
    /// after its tunnel came up, whose tunnel must go even if boot succeeds.
    ///
    /// The wait goes to `spawn_blocking`, which is what makes this the only
    /// teardown `boot` has. There used to be a synchronous `take_down`
    /// beside it whose own doc asserted that "**every** `async` caller puts
    /// the returned job on `spawn_blocking` rather than calling this", while
    /// all three of its callers were statements inside this `async fn` and
    /// none of them did — a wrapper that must not be called from `async`
    /// code, living in an `async fn`'s own module, which is a hazard that
    /// gets used again. It is gone rather than fixed at its call sites.
    ///
    /// "The only teardown `boot` has" was asserted here while a second shape
    /// stood forty lines further down and a third in `bring_up_tracked` above
    /// — each a `take_down_job` handed straight to `spawn_blocking`, each
    /// byte-equivalent to this body, each correct today and each invisible to
    /// a change made through this function. The job-returning helper they were
    /// built from is gone too, for the reason `take_down` went: an API from
    /// which a second teardown shape can be assembled is one that will be, and
    /// deleting it closes the class where converting its call sites closes
    /// three instances. Every teardown in `boot` is now this call.
    ///
    /// `OpenvpnManager::bring_down` signals the process and then polls for it
    /// to exit — up to `TERM_GRACE + KILL_GRACE`, seven seconds, per tunnel.
    /// On a runtime worker that is seven seconds in which nothing else
    /// scheduled on that thread runs. This series already moved bring-up, the
    /// NAT-PMP exchange and the monitor probes onto `spawn_blocking` for
    /// exactly that reason.
    ///
    /// An interface this boot did not record spawns nothing at all.
    async fn take_down_off_worker(&mut self, iface: &str) -> anyhow::Result<()> {
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
    ///
    /// Bring-up called `crate::vpn::for_type` directly while teardown went
    /// through the injected factory, so the manager that raised a tunnel and
    /// the one that took it down were different objects and the seam covered
    /// half the lifecycle — a test could drive teardown with a mock while
    /// bring-up quietly shelled out to `wg-quick` beside it.
    fn manager_for(&self, t: torrentd_engine::VpnType) -> Arc<dyn torrentd_engine::VpnManager> {
        (self.vpn_for)(t, &self.run_dir)
    }

    /// Stop tracking `iface` without bringing it down — for an interface this
    /// boot turned out not to own.
    fn forget_tunnel(&mut self, iface: &str) {
        self.tunnels.retain(|(_, n)| n != iface);
    }

    /// Bring a slot's tunnel up, recording it **before** the attempt.
    ///
    /// `bring_up` spawns the tunnel and only then polls up to 30 seconds for
    /// an address, so every failure after the spawn leaves something running:
    /// a WireGuard interface `wg-quick up` already created, or an
    /// `openvpn --daemon` that forked, exited 0, and is still retrying. Both
    /// outlive this process. Recording the tunnel only once an address had
    /// appeared left that one failure path — and only that one — with nothing
    /// tracking it: the failure teardown had nothing to remove, `Drop` had
    /// nothing to bring down, `SlotRegistry::iter()` excludes failed slots so the
    /// graceful-shutdown loop never saw it either, and the next boot
    /// overwrote the `--writepid` file that was the only remaining handle on
    /// the orphan.
    ///
    /// Recorded first, the tunnel is torn down on failure here and is still
    /// tracked by the drop guard if boot aborts. `bring_down` on an interface
    /// that was never raised is a logged no-op, which is the conservative
    /// direction.
    ///
    /// With one exception, and it is the reason `VpnError::ForeignInterface`
    /// exists: a bring-up that failed over an interface of that name that was
    /// **already standing when the attempt started**. Recording before the
    /// attempt turned that case into `wg-quick down <iface>` on a tunnel this
    /// boot did not raise, taking its routes and rules with it — the daemon
    /// destroying a stranger's tunnel over a name collision. Nothing of ours
    /// is running there, so it is forgotten rather than torn down, and the
    /// drop guard does not see it either.
    ///
    /// That exception is decided by `bring_up`, not here, and it is wider than
    /// the key-based refusal it started as. A raised-interface record for a
    /// link that some other tunnel has since taken the name of makes
    /// `ownership` answer `Ours` on the record alone; the link then has no
    /// address this boot can use, `adoptable` returns `Adoption::No`, and
    /// before this the `Err(_)` arm below tore it down. Every non-adoption
    /// over a link that was standing beforehand is now `ForeignInterface`, so
    /// the only failures that reach the teardown arm are the ones where the
    /// name was free when this attempt began and whatever is standing there is
    /// this attempt's own residue.
    ///
    /// The bring-up itself runs on `spawn_blocking`: it shells out and polls,
    /// and on a runtime worker that is 30 seconds per slot during which
    /// nothing else — including the signal handler that is supposed to
    /// interrupt exactly this — gets to run on that thread.
    ///
    /// The manager comes from the same factory the teardown uses, so the
    /// object that raises a tunnel is the object that takes it down.
    async fn bring_up_tracked(
        &mut self,
        t: torrentd_engine::VpnType,
        profile: torrentd_engine::VpnProfile,
    ) -> anyhow::Result<Result<IpAddr, torrentd_engine::VpnError>> {
        let iface = profile.interface.clone();
        let vpn = self.manager_for(t);
        self.note_tunnel(t, &iface);
        let brought_up = tokio::task::spawn_blocking(move || vpn.bring_up(&profile))
            .await
            .context("vpn bring-up task")?;
        match &brought_up {
            Ok(_) => {}
            Err(torrentd_engine::VpnError::ForeignInterface { .. }) => {
                warn!(
                    vpn_iface = %iface,
                    "an interface of this name is already up and is not this slot's; \
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

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BootCleanup {
    /// The one teardown that stays on whatever thread it lands on.
    ///
    /// `drop` cannot await, so an OpenVPN tunnel's bounded exit wait — up to
    /// `TERM_GRACE + KILL_GRACE` per tunnel — runs here on the worker that
    /// happens to drop the guard, where every other teardown path in this
    /// file hands the job to `spawn_blocking`. That is a forced move rather
    /// than an oversight: this runs only on a boot that has already failed
    /// and is on its way to exiting, so the worker it holds has nothing left
    /// to serve.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.kill_switch {
            match crate::vpn::killswitch::disable() {
                Ok(()) => info!("boot failed: network kill switch removed"),
                Err(e) => warn!(error.cause = %e, "boot failed: could not remove kill switch"),
            }
        }
        for (t, iface) in std::mem::take(&mut self.tunnels) {
            warn!(vpn_iface = %iface, "boot failed: bringing tunnel down");
            (self.vpn_for)(t, &self.run_dir).bring_down(&iface);
        }
    }
}

/// Take both shutdown receivers `boot` needs, on one line.
///
/// `broadcast::Sender::subscribe()` sets the new receiver's cursor to the
/// channel's current tail, so a receiver created later provably cannot see a
/// send that already happened, and a send with no live receiver behind it is
/// discarded outright. `boot` used to subscribe the receiver that outlives
/// boot only after the resume and torrent-dir scans — 400-odd lines after the
/// signal listener was installed, and the whole of a single-session boot after
/// it. A SIGTERM in that window was consumed by `boot_shutdown`, which the
/// slot loop has already finished with, and the HTTP server's graceful
/// shutdown then waited on a receiver that could never see it: the daemon
/// served indefinitely and only SIGKILL ended it, skipping the resume drain
/// and the tunnel teardown this boot path exists to guarantee.
///
/// Returned as a pair so the two subscriptions cannot drift apart again, and
/// taken **before the listener is installed**, which is the rest of the
/// property. `signals::run` spawns its listener and returns without an await
/// point, and the runtime is multi-threaded, so the spawned task can install
/// all three handlers, take a SIGTERM and send on another worker before the
/// next two instructions of `boot` execute. A send with no live receiver is
/// not buffered for a later `subscribe()` — `broadcast::Sender::send` returns
/// the value back in its error and writes nothing to the ring — so a send
/// landing in that window is lost outright, and with the listener looping
/// nothing re-reports it. After the install the guarantee is probabilistic;
/// before it, where the sender already exists and is all this needs, it is
/// structural.
fn boot_shutdown_receivers(
    tx: &broadcast::Sender<ShutdownReason>,
) -> (
    broadcast::Receiver<ShutdownReason>,
    broadcast::Receiver<ShutdownReason>,
) {
    (tx.subscribe(), tx.subscribe())
}

/// [`boot_shutdown_receivers`], and then install the signal listener — the
/// order being the whole of the property.
///
/// Taking the pair and installing the listener were two adjacent statements
/// in `boot`, and their order was pinned by nothing: swapping them left the
/// entire suite green while reopening the window above. `boot` has no test at
/// any revision, and `signals::run` cannot be called from one — tokio's
/// handlers are process-wide and are never uninstalled, so a test that
/// installs them leaves SIGINT swallowed and Ctrl-C ignored for the rest of
/// the `cargo test` run. Taking the install as a closure puts the order
/// inside one function, where a test drives it with a stand-in that sends the
/// instant it is "installed" — which is precisely the race.
async fn boot_shutdown_receivers_before<F, Fut>(
    tx: &broadcast::Sender<ShutdownReason>,
    install_listener: F,
) -> (
    broadcast::Receiver<ShutdownReason>,
    broadcast::Receiver<ShutdownReason>,
)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let pair = boot_shutdown_receivers(tx);
    install_listener().await;
    pair
}

pub struct DaemonHandle {
    cfg: Config,
    /// Where a VPN manager keeps state a *later* process has to find, as
    /// `boot` resolved it once at `run_dir`.
    ///
    /// Threaded through rather than re-derived from `cfg` in the shutdown
    /// teardown. A manager built on one path and torn down through a manager
    /// built on another cannot find the pid file or the raised-interface
    /// record the first one wrote, and `boot` already resolves this once "so
    /// bring-up and teardown agree". Re-deriving it here is the second source
    /// of truth for one path that was rejected one frame further down, taken
    /// one frame up.
    run_dir: std::path::PathBuf,
    /// The `--config` path exactly as parsed by clap. Threaded through rather
    /// than re-derived from `std::env::args()`, which mishandles `--config=X`
    /// and the `-c X` short form and so silently disabled SIGHUP reload.
    config_path: std::path::PathBuf,
    state: Arc<StateMap>,
    source: Arc<dyn AlertSource>,
    torrents: Arc<dyn TorrentStore>,
    shutdown_tx: broadcast::Sender<ShutdownReason>,
    /// Subscribed in `boot`, before the HTTP server exists, so a SIGTERM
    /// arriving during startup is buffered rather than dropped on the floor.
    shutdown_rx: broadcast::Receiver<ShutdownReason>,
    reload_rx: mpsc::Receiver<()>,
    metrics: Arc<PromSink>,
    pool: Option<Arc<crate::pool_service::PoolService>>,
    registry: Arc<AssignmentRegistry>,
    slot_registry: Option<Arc<SlotRegistry>>,
    /// Whether the nftables kill switch was installed and must be torn down on
    /// graceful shutdown.
    kill_switch_active: bool,
    log_handle: crate::tracing_init::LogReloadHandle,
    alert_loop: torrentd_engine::AlertLoopHandle,
}

pub async fn boot(
    cfg: Config,
    config_path: std::path::PathBuf,
    log_handle: crate::tracing_init::LogReloadHandle,
) -> anyhow::Result<DaemonHandle> {
    info!("starting torrentd");
    let mode = if cfg.slot.is_empty() {
        Mode::Single
    } else {
        Mode::MultiSlot
    };
    // Where a VPN manager keeps state a *later* process has to find — see
    // `vpn::for_type`. Resolved once here so bring-up and teardown agree.
    let run_dir = cfg.state_dir();

    // Signals, installed before anything that can block or fail.
    //
    // They used to go in after the resume and torrent-dir scans, which left
    // the whole of startup running on the default disposition — and startup is
    // where the daemon spends up to 30 seconds *per slot* waiting for a tunnel
    // to come up. A SIGTERM in that window killed the process outright, with
    // every tunnel it had already raised still up and nothing left to take
    // them down.
    let channels = SignalChannels::new();
    let (reload_tx, reload_rx) = mpsc::channel::<()>(8);
    let channels = SignalChannels::from_parts(channels.shutdown_tx, reload_tx);
    let shutdown_tx = channels.shutdown_tx.clone();
    // Both shutdown receivers, taken here rather than 400 lines apart — the
    // one the slot loop polls during bring-up, and the one that outlives boot
    // and the HTTP server's graceful shutdown waits on — and taken *before*
    // the listener that can send to them is installed. See
    // `boot_shutdown_receivers` for what subscribing the second one late
    // cost, and `boot_shutdown_receivers_before` for why the order is not two
    // adjacent statements here any more.
    let (mut boot_shutdown, shutdown_rx) =
        boot_shutdown_receivers_before(&shutdown_tx, || signals::run(channels.clone())).await;

    // Discard raised-interface records whose interface is no longer standing,
    // before anything can consult one.
    //
    // A record names a link this daemon raised. Nothing in the process is told
    // when a link later goes away, so a record for an interface an operator
    // removed by hand — the one remedy the runbook names for a stuck tunnel —
    // stays on disk inside the same host boot. This is the only place that can
    // drop it: the record outlives the process that wrote it, so the process
    // that finds it spent is a later one entirely. It runs before any
    // `bring_up`, and therefore before anything can consult or overwrite one.
    //
    // *Below* the signal install, and on `spawn_blocking`, for the two reasons
    // this file already applies to every other blocking call in `boot`. It
    // walks a directory and unlinks files, which is synchronous filesystem
    // I/O on a runtime worker; and "signals first" is structural here, so a
    // SIGTERM arriving while a slow or wedged state directory is being read is
    // handled rather than killing the process outright.
    {
        let sweep_dir = run_dir.clone();
        tokio::task::spawn_blocking(move || crate::vpn::sweep_raised_records(&sweep_dir))
            .await
            .context("raised-interface record sweep")?;
    }

    // Undoes what boot has raised, for every exit that is not a successful
    // one. Tunnels and the kill-switch table outlive the process, so a `?`
    // anywhere after the slot loop used to leave a host with live tunnels, an
    // nftables table confining a uid that no longer exists, and no daemon.
    let mut cleanup = BootCleanup::new(run_dir.clone());

    // Resume store — rooted at the top-level `resume_dir` and partitioned by
    // slot id, except where a `[[slot]]` names its own directory. Those keys
    // were validated for uniqueness and then ignored, so files landed under
    // the derived path and only matched the configured one by coincidence.
    let resume_store: Arc<dyn ResumeStore> = Arc::new(
        cfg.slot
            .iter()
            .fold(FsResumeStore::new(cfg.resume_dir.clone()), |st, slot| {
                st.with_slot_dir(slot.id.clone(), slot.resume_dir.clone())
            }),
    );

    // Torrent store — same per-slot partitioning as the resume store; holds
    // the raw .torrent files for the startup inventory scan, magnet-metadata
    // persistence, and removal cleanup.
    let torrent_store: Arc<dyn TorrentStore> = Arc::new(
        cfg.slot
            .iter()
            .fold(FsTorrentStore::new(cfg.torrent_dir.clone()), |st, slot| {
                st.with_slot_dir(slot.id.clone(), slot.torrent_dir.clone())
            }),
    );

    // Assignment registry.
    let registry = Arc::new(
        AssignmentRegistry::load(cfg.registry_path()).context("load assignment registry")?,
    );

    // Metrics sink — created early so the startup scans can record registry
    // rejections (slot_assignment_registry_errors_total).
    let metrics = Arc::new(PromSink::new());

    // Engines per slot (or one for single-session). In multi-slot mode we
    // also build the runtime slot registry that the /slots API and the VPN
    // health monitor consume.
    let mut slot_registry: Option<Arc<SlotRegistry>> = None;
    let source: Arc<dyn AlertSource> = match mode {
        Mode::Single => {
            // Restore the DHT routing table + session state across restarts.
            // DHT is enabled only in single-session
            // mode, so this is the only path that loads/saves session state.
            let settings = cfg.libtorrent_settings();
            let session = match load_session_state(&cfg.session_state_path()) {
                Some(state) => {
                    info!(bytes = state.len(), "restoring session state");
                    libtorrent_safe::Session::with_state(&settings, &state)
                        .context("construct session from saved state")?
                }
                None => libtorrent_safe::Session::new(&settings).context("construct session")?,
            };
            let engine: Arc<dyn TorrentEngine> = Arc::new(RealEngine::from_session(session));
            Arc::new(SingleSessionSource::new(engine))
        }
        Mode::MultiSlot => {
            let mut slot_entries: Vec<SlotEntry> = Vec::new();
            // Safety Rule 1: a slot whose tunnel does not come up never gets a
            // session, and the others carry on. It still has to be *reported*
            // as failed — skipping it outright made it vanish from `/slots`,
            // so an operator wondering why an account was quiet found no trace
            // of it anywhere but the startup log.
            let mut failed_slots: Vec<crate::slot_registry::FailedSlot> = Vec::new();
            macro_rules! fail_slot {
                ($cfg:expr, $reason:expr) => {{
                    failed_slots.push(crate::slot_registry::FailedSlot {
                        config: $cfg.clone(),
                        reason: $reason,
                    });
                    continue;
                }};
            }
            // A bring-up or teardown task that does not join — a panic inside
            // `spawn_blocking`, or the runtime shutting down under it — fails
            // **that slot**, and the boot carries on with the rest. Every one
            // of these sites was a `?`, which aborted the whole boot: one
            // slot's panicking `wg-quick` wrapper took every other slot's
            // tunnel down with it, on a daemon whose entire purpose is to keep
            // the remaining slots seeding. Failing the slot is what the
            // surrounding code does with every other per-slot failure, it is
            // what this daemon did before this series, and a failed slot is
            // still visible: `SlotRegistry::with_failed` keeps it in `/slots`
            // and `vpn_monitor` emits its fenced series.
            //
            // `boot` as a whole still fails when *no* slot comes up, which is
            // the check twenty lines below.
            macro_rules! slot_task_failed {
                ($cfg:expr, $what:literal, $err:expr) => {{
                    let e = $err;
                    error!(
                        slot_id = %$cfg.id,
                        error.cause = %e,
                        concat!($what, " task did not join; slot disabled"),
                    );
                    fail_slot!($cfg, format!(concat!($what, " task failed: {}"), e));
                }};
            }
            // The teardowns below all run on a slot that is failing anyway, so
            // a task that does not join is reported against the slot and does
            // not replace the reason it is failing for. It does not abort the
            // boot either: the tunnel that may still be standing belongs to
            // this slot, and taking the other slots down does not remove it.
            macro_rules! tear_down_or_warn {
                ($cfg:expr) => {
                    if let Err(e) = cleanup.take_down_off_worker(&$cfg.vpn_interface).await {
                        warn!(
                            slot_id = %$cfg.id,
                            vpn_iface = %$cfg.vpn_interface,
                            error.cause = %e,
                            "VPN teardown task did not join; the slot is disabled \
                             either way and its tunnel may still be standing",
                        );
                    }
                };
            }
            for s in &cfg.slot {
                // 1) Bring the VPN up first. Safety Rule 1: if it
                //    fails, the slot's lt::session is never constructed
                //    — no bare-IP fallback.
                // A shutdown asked for during a previous slot's bring-up is
                // honoured here rather than after every remaining tunnel has
                // been raised.
                if boot_shutdown.try_recv().is_ok() {
                    anyhow::bail!("shutdown requested during slot bring-up");
                }
                // Recorded before the attempt and torn down on failure — a
                // half-up tunnel is the one failure path nothing else can
                // reach. See `BootCleanup::bring_up_tracked`.
                let brought_up = match cleanup.bring_up_tracked(s.vpn_type, s.vpn_profile()).await {
                    Ok(r) => r,
                    Err(e) => slot_task_failed!(s, "VPN bring-up", e),
                };
                let tunnel_ip = match brought_up {
                    Ok(ip) => ip,
                    Err(e) => {
                        error!(
                            slot_id = %s.id,
                            error.cause = %e,
                            "VPN bring-up failed; slot disabled (no bare-IP fallback)",
                        );
                        fail_slot!(s, format!("VPN bring-up failed: {e}"));
                    }
                };

                // 2) Determine the listening port. Static slots bind the
                //    operator's `listen_port`; natpmp slots negotiate an
                //    ephemeral forwarded port from the tunnel gateway
                //    (ProtonVPN et al.). A startup negotiation failure disables
                //    the slot — loud, like a VPN bring-up failure — rather than
                //    silently seeding on an unforwarded port. Mid-session
                //    renewal failures are the soft warn+keep-seeding path
                //    (see port_forward_monitor).
                let (effective_port, forwarded_port, forwarded_epoch) = match s.port_forward {
                    PortForwardMode::Static => match s.listen_port {
                        Some(port) => (port, None, 0),
                        None => {
                            // validate_set should have caught this; be defensive.
                            error!(slot_id = %s.id, "static slot missing listen_port; slot disabled");
                            tear_down_or_warn!(s);
                            fail_slot!(s, "static slot has no listen_port".to_string());
                        }
                    },
                    PortForwardMode::Natpmp => {
                        let gw_str = s.port_forward_gateway_or_default();
                        let gateway: IpAddr = match gw_str.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                error!(slot_id = %s.id, gateway = %gw_str, error.cause = %e, "invalid port_forward_gateway; slot disabled");
                                tear_down_or_warn!(s);
                                fail_slot!(s, format!("invalid port_forward_gateway: {e}"));
                            }
                        };
                        let req = PortMapRequest {
                            gateway,
                            bind_ip: tunnel_ip,
                            internal_port: 0,
                            lifetime_secs: crate::port_forward_monitor::LEASE_SECS,
                        };
                        match vpn::NatpmpForwarder::for_startup().map(&req) {
                            Ok(m) => {
                                info!(slot_id = %s.id, tunnel_ip = %tunnel_ip, gateway = %gateway, forwarded_port = m.port, gateway_epoch = m.epoch, "NAT-PMP port negotiated");
                                (m.port, Some(m.port), m.epoch)
                            }
                            Err(e) => {
                                error!(slot_id = %s.id, tunnel_ip = %tunnel_ip, gateway = %gateway, error.cause = %e, "NAT-PMP negotiation failed at startup; slot disabled (no bare-IP fallback)");
                                tear_down_or_warn!(s);
                                fail_slot!(s, format!("NAT-PMP negotiation failed: {e}"));
                            }
                        }
                    }
                };

                // 3) Bind libtorrent to the tunnel IP + effective port only.
                let mut settings = cfg.libtorrent_settings();
                settings.user_agent = Some(s.user_agent.clone());
                settings.handshake_client_version = Some(s.user_agent.clone());
                settings.peer_fingerprint = Some(s.peer_fingerprint_hex.clone());
                settings.listen_interfaces =
                    Some(torrentd_engine::bind_endpoint(tunnel_ip, effective_port));
                settings.outgoing_interfaces = Some(tunnel_ip.to_string());
                // `[[slot]] upload_rate_limit` was parsed, documented in the
                // sample config, and applied nowhere — a slot's limit silently
                // did nothing. Omitted means "inherit the top-level limit";
                // `0` means explicitly unlimited, which is what `0` means for
                // the identically named top-level key and everywhere else in
                // this configuration.
                if let Some(v) = s.upload_rate_limit {
                    settings.upload_rate_limit = Some(v);
                }
                settings.enable_dht = Some(false);
                settings.enable_lsd = Some(false);
                settings.enable_upnp = Some(false);
                settings.enable_natpmp = Some(false);

                match RealEngine::new(&settings) {
                    Ok(engine) => {
                        info!(
                            slot_id = %s.id,
                            tunnel_ip = %tunnel_ip,
                            listen_port = effective_port,
                            "slot engine up",
                        );
                        let engine: Arc<dyn TorrentEngine> = Arc::new(engine);
                        slot_entries.push(SlotEntry::new(
                            s.clone(),
                            engine,
                            tunnel_ip,
                            forwarded_port,
                            forwarded_epoch,
                        ));
                    }
                    Err(e) => {
                        error!(
                            slot_id = %s.id,
                            error.cause = %e,
                            "slot engine construction failed; tearing down VPN",
                        );
                        // Through the helper, like every other teardown in
                        // `boot`: the same bounded exit wait, reached by a
                        // fifth path. Hand-inlining it here meant a change to
                        // the teardown contract — a timeout on the join, a
                        // retry, a metric — applied through the helper missed
                        // this arm silently.
                        tear_down_or_warn!(s);
                        failed_slots.push(crate::slot_registry::FailedSlot {
                            config: s.clone(),
                            reason: format!("session construction failed: {e}"),
                        });
                    }
                }
            }
            if slot_entries.is_empty() {
                anyhow::bail!("multi-slot mode: no slots came up");
            }
            let source_entries: Vec<(SlotId, Arc<dyn TorrentEngine>)> = slot_entries
                .iter()
                .map(|e| (e.config.id.clone(), e.engine.clone()))
                .collect();
            slot_registry = Some(Arc::new(
                SlotRegistry::new(slot_entries).with_failed(failed_slots),
            ));
            Arc::new(MultiSlotSource::new(source_entries))
        }
    };

    // The slot loop's own check is only re-evaluated at the top of the *next*
    // iteration, so the last slot's 30-second bring-up had no check against
    // it at all — and a one-slot deployment, or single-session mode, had
    // none anywhere. Ask once more before boot commits to running, while the
    // drop guard still owns every tunnel this boot raised.
    if boot_shutdown.try_recv().is_ok() {
        anyhow::bail!("shutdown requested during slot bring-up");
    }

    // Network-layer kill switch (defence-in-depth; multi-slot + opt-in).
    // Installed once, after every slot's tunnel is up, so the ruleset covers all
    // tunnel interfaces. Fail-closed: if the operator asked for it and it can't
    // be installed, abort rather than seed without the backstop.
    let mut kill_switch_active = false;
    // Seed the gauge at zero so `kill_switch_active == 0` is a series that
    // exists and can be alerted on. Registered lazily on first emission, it
    // was previously only ever set to 1 — so on a daemon running without the
    // backstop the metric was simply absent, and an alert for exactly that
    // condition could never fire.
    metrics.set_gauge("kill_switch_active", 0.0, &[]);
    if cfg.network_kill_switch {
        match &slot_registry {
            Some(sr) => {
                let tunnels: Vec<String> =
                    sr.iter().map(|e| e.config.vpn_interface.clone()).collect();
                let uid = vpn::killswitch::enable(&tunnels)
                    .context("install nftables kill switch (network_kill_switch=true)")?;
                kill_switch_active = true;
                cleanup.note_kill_switch();
                metrics.set_gauge("kill_switch_active", 1.0, &[]);
                info!(uid, "network kill switch active");
            }
            None => {
                // Fail closed, like every other path here. The operator set
                // this flag precisely because they do not want traffic on the
                // bare IP; warning and continuing gives them exactly that,
                // with nothing but a startup log line to say so. Single-session
                // mode has no tunnel to confine egress to, so the honest answer
                // is that the config is contradictory.
                anyhow::bail!(
                    "network_kill_switch = true but no [[slot]] entries are configured. \
                     The kill switch confines the daemon's egress to its slots' tunnel \
                     interfaces, and single-session mode has none — it would seed from \
                     the bare IP with no backstop. Configure slots, or unset \
                     network_kill_switch.",
                );
            }
        }
    }

    // Resume scan: load every saved resume file per slot. The shim
    // already deduplicates duplicate adds so a future torrent dir scan
    // won't double-add.
    for slot in source.slots() {
        let entries = resume_store.load_all(&slot).context("scan resume dir")?;
        let count = entries.len();
        let mut missing_metadata = 0usize;
        let engine = source
            .engine_for(&slot)
            .ok_or_else(|| anyhow::anyhow!("no engine for slot {}", slot))?;
        for (ih, data) in entries {
            // Cross-check the registry; the spec aborts the slot on mismatch.
            // Single-session always uses SlotId::DEFAULT, so the check
            // mainly guards multi-slot mode.
            if let Some(existing) = registry.lookup(&ih) {
                if existing != slot {
                    warn!(
                        slot_id = %slot,
                        infohash = %ih,
                        existing_slot = %existing,
                        "resume file in wrong slot; skipping (operator must reconcile)",
                    );
                    metrics.inc_counter(
                        "slot_assignment_registry_errors_total",
                        &[("slot_id", slot.as_str())],
                    );
                    continue;
                }
            } else if let Err(e) = registry.assign(ih, slot.clone()) {
                // Rule 4 makes the registry the gate every load passes. An
                // assignment that failed to persist is one that disappears at
                // the next restart, after which nothing knows this info-hash
                // belongs to this slot — so refuse the load rather than seed a
                // torrent the uniqueness rule can no longer see.
                warn!(
                    slot_id = %slot,
                    infohash = %ih,
                    error.cause = %e,
                    "could not record the resume assignment; skipping this torrent",
                );
                metrics.inc_counter(
                    "slot_assignment_registry_errors_total",
                    &[("slot_id", slot.as_str())],
                );
                continue;
            }
            // Re-attach metadata. libtorrent writes the info dict into resume
            // data only when save_resume_data was called with SAVE_INFO_DICT
            // (vendor/libtorrent/src/torrent.cpp: `ret.ti = m_torrent_file` is
            // gated on that flag), so resume data alone leaves the torrent with
            // no metadata and it re-enters downloading_metadata on restart —
            // fatal for a private slot with DHT and PEX disabled. Setting the
            // flag instead would embed a full piece-hash table in every resume
            // file, so pass the .torrent already on disk.
            let torrent = match torrent_store.read(&slot, &ih) {
                Ok(t) => t,
                Err(e) => {
                    warn!(slot_id = %slot, infohash = %ih, error.cause = %e,
                          "could not read .torrent for resume add; continuing without metadata");
                    None
                }
            };
            if torrent.is_none() {
                missing_metadata += 1;
            }
            // Which flags are re-asserted here, and why, is
            // `torrentd_engine::policy`'s to decide — the short version is
            // that a guard which lapses on restart is not a guard.
            //
            // PAUSED is deliberately *not* cleared. It is tempting: the VPN
            // monitor pauses a whole slot when its tunnel drops, and if the
            // resume sweep lands in that window every torrent comes back
            // paused. But resume data does not record *why* a torrent was
            // paused, so clearing it also silently restarts a torrent an
            // operator paused on purpose — on a private tracker, the kind of
            // mistake that ends an account. A pool that comes back paused is
            // visible in `/status` and fixed with `resume-all`; a pool that
            // comes back seeding when it was told not to is not recoverable.
            let flags_set = torrentd_engine::resume_flags_set(&slot);
            let flags_clear = TorrentFlags::empty();
            if let Err(e) = engine.add_torrent(AddParams::Resume {
                bytes: data.into_inner(),
                torrent,
                save_path: None,
                flags_set,
                flags_clear,
            }) {
                warn!(slot_id = %slot, infohash = %ih, error.cause = %e, "resume add failed");
            }
        }
        if missing_metadata > 0 {
            // Not fatal — libtorrent can still fetch metadata from peers where
            // discovery is enabled — but on a private slot it usually means the
            // torrent will sit idle, so make it visible rather than silent.
            warn!(
                slot_id = %slot,
                torrent_count = missing_metadata,
                "resume entries with no .torrent on disk; these rely on peer metadata exchange",
            );
        }
        info!(slot_id = %slot, torrent_count = count, "resume scan complete");
    }

    // Torrent-dir scan: add any .torrent whose info-hash has no resume file
    // (resume always wins; startup inventory). After this the torrent
    // dir is not re-scanned — new torrents arrive only via the API.
    let scan_save_path = cfg.default_save_path.to_string_lossy().into_owned();
    for slot in source.slots() {
        let entries = torrent_store.load_all(&slot).context("scan torrent dir")?;
        let engine = source
            .engine_for(&slot)
            .ok_or_else(|| anyhow::anyhow!("no engine for slot {}", slot))?;
        let mut added = 0usize;
        for (ih, bytes) in entries {
            // Resume data already loaded this torrent (the registry holds
            // every resume-loaded info-hash after the scan above) — skip.
            if registry.lookup(&ih).is_some() {
                continue;
            }
            // Rule 4 again: claim first, load second. Claiming afterwards
            // left a window in which the session held a torrent the registry
            // had never agreed to, and dropped the claim silently if it could
            // not be written.
            if let Err(e) = registry.assign(ih, slot.clone()) {
                warn!(
                    slot_id = %slot,
                    infohash = %ih,
                    error.cause = %e,
                    "could not record the torrent-dir assignment; skipping this torrent",
                );
                metrics.inc_counter(
                    "slot_assignment_registry_errors_total",
                    &[("slot_id", slot.as_str())],
                );
                continue;
            }
            let flags = torrentd_engine::seed_flags(&slot);
            match engine.add_torrent(AddParams::File {
                bytes,
                save_path: scan_save_path.clone(),
                flags,
            }) {
                Ok(_) => {
                    added += 1;
                }
                Err(e) => {
                    // Release the claim so a later run can retry the add.
                    let _ = registry.remove(&ih);
                    warn!(
                        slot_id = %slot,
                        infohash = %ih,
                        error.cause = %e,
                        "torrent-dir add failed",
                    );
                }
            }
        }
        if added > 0 {
            info!(slot_id = %slot, torrent_count = added, "torrent dir scan: added new torrents");
        }
    }

    // Managed pool. Opened before the alert loop so a bad index path fails
    // startup rather than surfacing as a 500 on the first API call.
    let pool = crate::pool_service::PoolService::open(&cfg).context("open pool index")?;

    // Alert loop.
    let metrics_for_loop: Arc<dyn MetricsSink> = metrics.clone();
    let state = Arc::new(StateMap::new());
    let clock: Arc<dyn torrentd_engine::Clock> = Arc::new(SystemClock);

    let alert_loop = AlertLoopBuilder::new(
        source.clone(),
        state.clone(),
        resume_store.clone(),
        torrent_store.clone(),
        metrics_for_loop,
        clock,
    )
    // `listen_failed` is fatal in single-session mode
    // (nothing else is listening, so seeding just stops silently). In
    // multi-slot mode the per-slot handler marks that slot failed and the
    // remaining slots carry on.
    .fatal_listen_failure(mode == Mode::Single)
    .on_fatal({
        let tx = shutdown_tx.clone();
        Arc::new(move |reason| {
            let _ = tx.send(reason);
        }) as torrentd_engine::FatalCallback
    })
    // The engine resumes torrents on its own upload-mode retry schedule and
    // has no concept of a tunnel, so it has to be told which slots the VPN
    // monitor has fenced.
    .slot_fenced({
        let slots = slot_registry.clone();
        Arc::new(move |id: &torrentd_engine::SlotId| {
            slots
                .as_ref()
                .and_then(|sr| sr.get(id))
                .is_some_and(|e| e.health().status == SlotStatus::VpnDown)
        }) as torrentd_engine::SlotFenced
    })
    .spawn();

    // Boot succeeded: the shutdown path owns the tunnels and the kill switch
    // from here, and tearing them down now would stop the daemon it just
    // started.
    cleanup.disarm();

    Ok(DaemonHandle {
        cfg,
        run_dir,
        config_path,
        state,
        source,
        torrents: torrent_store,
        shutdown_tx,
        shutdown_rx,
        reload_rx,
        metrics,
        pool,
        registry,
        slot_registry,
        kill_switch_active,
        log_handle,
        alert_loop,
    })
}

impl DaemonHandle {
    /// Run the daemon until a shutdown signal arrives, returning the
    /// process exit code.
    pub async fn run_until_signal(self) -> i32 {
        let DaemonHandle {
            cfg,
            run_dir,
            config_path,
            state,
            source,
            torrents,
            shutdown_tx,
            shutdown_rx,
            reload_rx,
            metrics,
            pool,
            registry,
            slot_registry,
            kill_switch_active,
            log_handle,
            alert_loop,
        } = self;

        // VPN health monitor (multi-slot only). Spawned before AppState
        // consumes the registry/state/metrics.
        if let Some(slots) = slot_registry.clone() {
            tokio::spawn(crate::vpn_monitor::run(
                slots.clone(),
                state.clone(),
                metrics.clone(),
                std::time::Duration::from_secs(cfg.vpn_handshake_max_age_secs),
                shutdown_tx.subscribe(),
            ));
            // Port-forward renewal monitor: keeps NAT-PMP leases alive and
            // rebinds the live session if the forwarded port changes.
            tokio::spawn(crate::port_forward_monitor::run(
                slots,
                metrics.clone(),
                shutdown_tx.subscribe(),
            ));
        }

        // Re-drive any plan a crash or a kill left mid-apply, before the API
        // can accept new ones. A half-applied reorganisation is exactly the
        // state an operator cannot reason about.
        if let Some(pool) = pool.clone() {
            let src = source.clone();
            let st = state.clone();
            tokio::task::spawn_blocking(move || {
                crate::pool_apply::resume_unfinished(&pool, &src, &st)
            });
        }

        // Verify queue: admits a bounded number of adopt-time re-hashes so a
        // bulk adopt cannot starve whatever is already seeding.
        if let Some(pool) = pool.clone() {
            tokio::spawn(crate::pool_service::run_verify_queue(
                pool,
                source.clone(),
                state.clone(),
                metrics.clone(),
                slot_registry.clone(),
                shutdown_tx.subscribe(),
            ));
        }

        let app_state = AppState {
            source: source.clone(),
            registry: registry.clone(),
            slots: slot_registry.clone(),
            state,
            torrents,
            metrics: metrics.clone(),
            auth: cfg.auth.clone().map(crate::auth::Auth::new),
            pool,
            alert_heartbeat: alert_loop.heartbeat(),
            default_save_path: cfg.default_save_path.clone(),
            torrent_dir: cfg.torrent_dir.clone(),
            mode: if cfg.slot.is_empty() {
                Mode::Single
            } else {
                Mode::MultiSlot
            },
        };

        let app: Router = http::router(app_state);
        let http_listen = cfg.http_listen;

        // SIGHUP pump.
        let reload_source = source.clone();
        let cfg_clone = cfg.clone();
        tokio::spawn(reload::run(
            config_path,
            cfg_clone,
            reload_source,
            reload_rx,
            log_handle,
        ));

        let listener = match tokio::net::TcpListener::bind(http_listen).await {
            Ok(l) => l,
            Err(e) => {
                error!(addr = %http_listen, error.cause = %e, "bind HTTP listener");
                return 70;
            }
        };
        info!(addr = %http_listen, "HTTP server listening");

        // The unit is `Type=notify`: systemd holds it in `activating` until
        // READY=1, so this must come after the listener is actually bound.
        sd_notify::ready();
        sd_notify::status(&format!("seeding; API on {http_listen}"));
        if let Some(interval) = sd_notify::watchdog_interval() {
            info!(
                interval_secs = interval.as_secs(),
                "systemd watchdog enabled"
            );
            let mut wd_shutdown = shutdown_tx.subscribe();
            let wd_heartbeat = alert_loop.heartbeat();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {
                            // Ping only while the alert loop is still making
                            // progress. This task is independent of that
                            // thread, so an unconditional ping tells systemd
                            // the daemon is healthy for as long as the process
                            // is alive — including when the loop has died and
                            // seeding, resume saves and status updates have all
                            // stopped. `/healthz` reports that correctly, and
                            // nothing reads `/healthz`.
                            let age = torrentd_engine::heartbeat_age(&wd_heartbeat);
                            if age > WATCHDOG_MAX_HEARTBEAT_AGE {
                                error!(
                                    heartbeat_age_secs = age.as_secs(),
                                    "alert loop is not making progress; withholding the \
                                     systemd watchdog ping so the unit is restarted",
                                );
                            } else {
                                sd_notify::watchdog();
                            }
                        }
                        _ = wd_shutdown.recv() => return,
                    }
                }
            });
        }

        let mut shutdown_rx = shutdown_rx;
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
        });

        let mut exit_code = match server.await {
            Ok(()) => 0,
            Err(e) => {
                error!(error.cause = %e, "HTTP server exited with error");
                70
            }
        };

        // Tell systemd we're stopping before the resume drain, which may take
        // the full 30s deadline — otherwise the watchdog can fire mid-drain.
        sd_notify::stopping();
        sd_notify::status("draining resume data");

        // Trigger alert-loop shutdown and join (saves all resume data). If the
        // loop already unwound on a fatal listen failure this is a no-op, but
        // the daemon must still exit non-zero so systemd restarts it.
        alert_loop.signal_shutdown(ShutdownReason::Sigterm);
        if alert_loop.listen_failed() {
            error!("exiting non-zero: listen socket failed");
            exit_code = 70;
        }
        if alert_loop.panicked() {
            // Must be non-zero or `Restart=on-failure` treats a daemon that
            // stopped seeding as a clean stop and leaves it down.
            error!("exiting non-zero: the alert loop panicked");
            exit_code = 70;
        }
        if let Err(e) = alert_loop.join() {
            warn!(error.cause = ?e, "alert loop join panicked");
        }

        // Persist DHT/session state for the next start (single-session mode;
        // slots run with enable_dht=false and skip this). The session
        // is still alive here — only dropped when `source` goes out of scope.
        if cfg.slot.is_empty() {
            if let Some(engine) = source.engine_for(&SlotId::default_single()) {
                match engine.session_state() {
                    Ok(bytes) if !bytes.is_empty() => {
                        match save_session_state(&cfg.session_state_path(), &bytes) {
                            Ok(()) => info!(bytes = bytes.len(), "session state saved"),
                            Err(e) => warn!(error.cause = %e, "failed to save session state"),
                        }
                    }
                    Ok(_) => {}
                    Err(e) => warn!(error.cause = %e, "session_state() failed"),
                }
            }
        }

        // Remove the network kill switch last, once seeding has drained. The
        // tunnel is still up during a graceful shutdown, so the slots' sockets
        // (still source-bound to the tunnel IP) can't leak in this window.
        if kill_switch_active {
            match crate::vpn::killswitch::disable() {
                Ok(()) => info!("network kill switch removed"),
                Err(e) => warn!(error.cause = %e, "failed to remove network kill switch"),
            }
            metrics.set_gauge("kill_switch_active", 0.0, &[]);
        }

        // Then bring the tunnels down, after the sessions are gone. The daemon
        // brought them up, so it owns tearing them down; leaving them up meant
        // every restart accumulated interfaces and left an idle tunnel
        // connected to the provider indefinitely. Only on the graceful path —
        // a startup failure already tears down what it created.
        if let Some(slots) = &slot_registry {
            let jobs: Vec<_> = slots
                .iter()
                .map(|entry| {
                    let vpn = crate::vpn::for_type(entry.config.vpn_type, &run_dir);
                    let iface = entry.config.vpn_interface.clone();
                    (
                        entry.config.id.clone(),
                        entry.config.vpn_interface.clone(),
                        move || vpn.bring_down(&iface),
                    )
                })
                .collect();
            join_teardowns(jobs).await;
        }

        info!("torrentd: clean exit");
        exit_code
    }
}

/// Put every tunnel teardown in flight at once, then join them.
///
/// Moving the bounded exit wait to `spawn_blocking` took it off the runtime's
/// workers and left the daemon's **wall-clock** stop time where it was:
/// awaiting each job before spawning the next is still up to
/// `TERM_GRACE + KILL_GRACE` — seven seconds — per OpenVPN slot, serialized,
/// which is the `7N` this series named as the thing it was avoiding. Each
/// tunnel is an independent interface and an independent process, so there is
/// nothing to serialise for, and `deploy/torrentd.service` sets no
/// `TimeoutStopSec`, which leaves systemd's default as the only bound on the
/// drain.
///
/// Spawning happens in one pass and the awaits in a second, so the jobs run
/// concurrently and the log still reads in slot order. A `JoinError` — the
/// job panicked, or the runtime is shutting down — is warned and skipped:
/// shutdown must not fail on a teardown, and the tunnels that did come down
/// are still worth reporting.
async fn join_teardowns<J>(jobs: Vec<(SlotId, String, J)>)
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
        info!(slot_id = %id, vpn_iface = %iface, "tunnel down");
    }
}

/// Read the persisted DHT/session-state blob, or `None` if absent/empty.
fn load_session_state(path: &std::path::Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(b) if !b.is_empty() => Some(b),
        _ => None,
    }
}

/// Atomically persist the DHT/session-state blob (temp + fsync + rename), so a
/// crash mid-write leaves the previous blob intact.
fn save_session_state(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Fsync the directory too. Without it the rename may not survive a crash,
    // which loses the DHT routing table and the session's listen state. The
    // resume store, the torrent store and the assignment registry all do this;
    // this was the one atomic-write site that claimed the guarantee in its
    // comment without providing it.
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            d.sync_all()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use torrentd_engine::MockVpn;
    use torrentd_engine::VpnProfile;
    use torrentd_engine::VpnType;

    use super::*;

    fn profile(iface: &str) -> VpnProfile {
        VpnProfile {
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

    /// A teardown as [`join_teardowns`] takes one, boxed so two closures of
    /// different types can share one `Vec`.
    type BoxedTeardown = (SlotId, String, Box<dyn FnOnce() + Send>);

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
        fn bring_up(&self, profile: &VpnProfile) -> Result<IpAddr, torrentd_engine::VpnError> {
            Err(torrentd_engine::VpnError::BringUpTimeout {
                iface: profile.interface.clone(),
            })
        }

        fn current_ip(&self, iface: &str) -> Result<IpAddr, torrentd_engine::VpnError> {
            Err(torrentd_engine::VpnError::NoAddress {
                iface: iface.to_string(),
            })
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
    /// teardown, unlike its four siblings, and `SlotRegistry::iter()`
    /// excludes failed slots so the shutdown loop never saw it either.
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

    /// The exception to "record it before the attempt": an interface of that
    /// name that is already up and is **not** this slot's.
    ///
    /// `wg-quick up` refuses a name that exists, adoption then finds a
    /// different public key and refuses it too — and the teardown-on-failure
    /// arm ran `wg-quick down` on it anyway, removing a tunnel this daemon
    /// did not raise along with its routes and its rules. Nothing of ours is
    /// running there, so neither this arm nor the drop guard may touch it.
    ///
    /// This is the arm, and it is now reached by every non-adoption over a
    /// link that was standing before the attempt began — not only the
    /// key-based refusal it started as. `wireguard.rs`'s `refusal` decides
    /// which failures arrive here and which reach the `Err(_)` catch-all
    /// below; see `a_link_that_was_standing_before_the_attempt_is_never_torn_down`
    /// for that half.
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
        // when boot goes on to fail for want of that slot either.
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

    /// `boot`'s only teardown keeps its bounded wait off the worker.
    ///
    /// `boot` had three call sites that reached a *synchronous* `take_down`
    /// instead — a static slot with no `listen_port`, an unparseable
    /// `port_forward_gateway`, and a NAT-PMP negotiation that failed, which
    /// is what an `openvpn` slot on a provider account without port
    /// forwarding looks like. `validate_set` ties `vpn_type` to neither
    /// `port_forward` nor the gateway, so each reached
    /// `OpenvpnManager::bring_down`'s `thread::sleep` poll — up to
    /// `TERM_GRACE + KILL_GRACE`, seven seconds, on the runtime worker,
    /// during which the signal handling the neighbouring commits exist to
    /// keep responsive does not run either. `take_down` is deleted, so the
    /// shape below is the only one `boot` has.
    ///
    /// Call `job()` directly in `take_down_off_worker` instead of handing it
    /// to `spawn_blocking` and this fails.
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

    /// `boot` has exactly one teardown shape, and this is what says so.
    ///
    /// `take_down_off_worker`'s doc asserts it is "the only teardown `boot`
    /// has". That was false three times over: a hand-inlined
    /// spawn-the-job-and-await stood in `bring_up_tracked` and again in the
    /// engine-construction arm, each byte-equivalent to the helper's body and
    /// each correct on its own — so nothing failed, and a change made through
    /// the helper (a timeout on the join, a retry, a metric) would have
    /// missed them in silence while the next reader of that doc believed
    /// there was nothing else to change. `boot` is not reachable by a test at
    /// any revision, so the invariant is asserted where it lives: the wrapper
    /// that turns a `JoinError` into this module's teardown error appears
    /// once, inside the one helper.
    ///
    /// This is the shape the repository already uses for an invariant no
    /// runtime assertion can carry — the tracing field-name gate is a grep
    /// over these same sources, and `no_source_invokes_the_binaries_procps_ng_provides`
    /// walks the tree the same way. Hand-inline a second teardown anywhere in
    /// `crates/torrentd/src/` and it fails.
    ///
    /// **Scope, and why that sentence is true.** It used to count one literal
    /// — the `context(…)` string the helper names its join with — in
    /// `startup.rs` alone, which is the whole of what replaces a test of
    /// `boot`: a fourth teardown written with any other context string, or in
    /// any other module of this crate, passed it in silence. Both halves are
    /// now checked across the crate's sources: the helper is defined and
    /// wrapped once, and `bring_down` is called at exactly the two sites that
    /// document why they are not the helper — `Drop for BootCleanup`, which
    /// cannot await, and the shutdown job builder in `run_until_signal`, which
    /// is outside `boot` entirely.
    ///
    /// What is excluded is **`#[cfg(test)]` regions**, not a directory. The
    /// filter used to drop every path under `vpn/`, on the accurate reasoning
    /// that `vpn/` is where the trait's implementations and their own tests
    /// live — but `vpn/mod.rs` already holds `for_type` and
    /// `sweep_raised_records` and is the natural home for a teardown helper,
    /// so a second teardown shape written there passed in silence while the
    /// headline above said it would not. Excluding what the compiler excludes
    /// from a release build makes the two coincide: the counted set is exactly
    /// the code that ships, wherever in the crate it lives.
    #[test]
    fn boot_has_exactly_one_teardown_shape() {
        let sources = shipped_crate_sources();

        let wrappers: Vec<_> = sources
            .iter()
            .filter_map(|(path, text)| {
                let n = text.matches("context(\"vpn teardown task\")").count();
                (n > 0).then(|| format!("{path}: {n}"))
            })
            .collect();
        assert_eq!(
            wrappers,
            vec!["startup.rs: 1".to_string()],
            "the wrapper that turns a teardown `JoinError` into this module's \
             error belongs to `take_down_off_worker` and to nothing else; found \
             {wrappers:?}",
        );

        // And the helper is what every teardown in `boot` reaches for, so a
        // direct `bring_down` outside the two documented sites is the same
        // hazard arriving without the context string.
        //
        // Counted rather than located: a line number would have to be moved
        // by every edit above it, and a gate its readers keep re-pinning stops
        // being read.
        let call = concat!(".", "bring_down", "(");
        let direct: Vec<_> = sources
            .iter()
            .filter_map(|(path, text)| {
                let n = text.matches(call).count();
                (n > 0).then(|| format!("{path}: {n}"))
            })
            .collect();
        assert_eq!(
            direct,
            // One inside `take_down_off_worker`, which is the helper, plus the
            // two sites that document why they are not it: `Drop for
            // BootCleanup`, where `drop` cannot await, and the shutdown job
            // builder in `run_until_signal`, which is outside `boot` entirely.
            vec!["startup.rs: 3".to_string()],
            "every teardown in `boot` goes through `take_down_off_worker`; the \
             only other `bring_down` calls are the two that say why they are \
             not it. Found {direct:?} — a new one wants the helper, and a \
             fourth documented site wants this count and its comment moved \
             together",
        );
    }

    /// Every `.rs` under this crate's `src/` with its `#[cfg(test)]` regions
    /// removed — the code that actually ships.
    ///
    /// This is what makes
    /// [`boot_has_exactly_one_teardown_shape`]'s "anywhere in
    /// `crates/torrentd/src/`" true. The census it replaces dropped whole
    /// paths under `vpn/`, which was one directory narrower than the claim
    /// above it and left `vpn/mod.rs` — which already holds `for_type` and
    /// `sweep_raised_records` — outside a gate whose headline said it was
    /// inside.
    fn shipped_crate_sources() -> Vec<(String, String)> {
        let sources = crate_sources();
        let stripped: Vec<(String, String)> = sources
            .iter()
            .map(|(path, text)| (path.clone(), strip_cfg_test_regions(text)))
            .collect();

        // The stripper is what the gate's scope now rests on, so it is checked
        // against the tree it just walked rather than trusted. Too little
        // removed and a test's own call sites are counted as shipped code;
        // too much and the gate passes on an empty set, which is the failure
        // the census below it already guards against.
        let joined_before: usize = sources.iter().map(|(_, t)| t.len()).sum();
        let joined_after: usize = stripped.iter().map(|(_, t)| t.len()).sum();
        assert!(
            joined_after < joined_before,
            "this crate has `#[cfg(test)]` regions and the stripper removed none",
        );
        for (path, text) in &stripped {
            assert!(
                !text.contains("#[cfg(test)]"),
                "{path}: a `#[cfg(test)]` region survived the strip, so the \
                 census counts test code as shipped code",
            );
        }
        let startup = &stripped
            .iter()
            .find(|(p, _)| p == "startup.rs")
            .expect("this module")
            .1;
        assert!(
            startup.contains("async fn take_down_off_worker")
                && startup.contains("impl Drop for BootCleanup"),
            "the stripper removed shipped code: `take_down_off_worker` and \
             `Drop for BootCleanup` are both outside any `#[cfg(test)]`",
        );
        stripped
    }

    /// Remove every `#[cfg(test)]` item from a Rust source, body and all.
    ///
    /// Brace-matched from the first `{` after the attribute, which covers
    /// every shape this crate uses it in — `mod tests`, `impl`, and a bare
    /// `fn`. Braces inside string, raw-string, byte-string and character
    /// literals and inside comments are not braces, so those are skipped
    /// rather than counted; a naive count would run off the end of a test that
    /// merely contains a `"{"`.
    fn strip_cfg_test_regions(text: &str) -> String {
        const ATTR: &str = "#[cfg(test)]";
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while let Some(rel) = text[i..].find(ATTR) {
            let attr_at = i + rel;
            let Some(open) = text[attr_at..].find('{').map(|o| attr_at + o) else {
                break;
            };
            let Some(close) = match_brace(bytes, open) else {
                break;
            };
            out.push_str(&text[i..attr_at]);
            i = close + 1;
        }
        out.push_str(&text[i..]);
        out
    }

    /// The index of the `}` closing the `{` at `open`, skipping literals and
    /// comments.
    fn match_brace(bytes: &[u8], open: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                b'/' if bytes.get(i + 1) == Some(&b'/') => {
                    i = bytes[i..]
                        .iter()
                        .position(|&c| c == b'\n')
                        .map_or(bytes.len(), |n| i + n);
                    continue;
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    let mut nest = 1usize;
                    i += 2;
                    while i < bytes.len() && nest > 0 {
                        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                            nest += 1;
                            i += 2;
                        } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                            nest -= 1;
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    continue;
                }
                b'r' if matches!(bytes.get(i + 1), Some(b'"') | Some(b'#')) => {
                    if let Some(end) = skip_raw_string(bytes, i) {
                        i = end;
                        continue;
                    }
                }
                b'"' => {
                    i = skip_quoted(bytes, i, b'"');
                    continue;
                }
                b'\'' => {
                    // A lifetime (`'a`, `'static`) is not a character
                    // literal: it has no closing quote. Only treat it as one
                    // when a matching `'` follows within four bytes, which
                    // covers `'x'`, `'\n'` and `'\u{7f}'`-free forms.
                    if let Some(end) = char_literal_end(bytes, i) {
                        i = end + 1;
                        continue;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// Index just past the closing delimiter of the string starting at
    /// `bytes[start] == delim`, honouring backslash escapes.
    fn skip_quoted(bytes: &[u8], start: usize, delim: u8) -> usize {
        let mut i = start + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                c if c == delim => return i + 1,
                _ => i += 1,
            }
        }
        bytes.len()
    }

    /// Index just past a raw string beginning at `bytes[start] == b'r'`, or
    /// `None` if that `r` does not begin one.
    fn skip_raw_string(bytes: &[u8], start: usize) -> Option<usize> {
        let mut i = start + 1;
        let hashes_at = i;
        while bytes.get(i) == Some(&b'#') {
            i += 1;
        }
        let hashes = i - hashes_at;
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        while i < bytes.len() {
            if bytes[i] == b'"' && bytes[i + 1..].iter().take(hashes).all(|&c| c == b'#') {
                return Some(i + 1 + hashes);
            }
            i += 1;
        }
        Some(bytes.len())
    }

    /// The index of the closing `'` of a character literal at `start`, or
    /// `None` when that `'` opens a lifetime instead.
    fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
        let mut i = start + 1;
        if bytes.get(i) == Some(&b'\\') {
            i += 1;
        }
        i += 1;
        (bytes.get(i) == Some(&b'\'')).then_some(i)
    }

    /// The stripper, against the shapes it has to survive.
    ///
    /// Each of these is a way a naive brace count runs off the end and takes
    /// shipped code with it — which would make the census pass on a set it
    /// silently emptied.
    #[test]
    fn the_census_strips_test_regions_and_nothing_else() {
        let kept = "fn shipped() { vpn.bring_down(\"a\"); }";

        for (name, src) in [
            (
                "a brace inside a string literal",
                "#[cfg(test)]\nmod tests {\n    fn t() { let s = \"{\"; }\n}\n",
            ),
            (
                "a brace inside a char literal",
                "#[cfg(test)]\nmod tests {\n    fn t() { let c = '{'; }\n}\n",
            ),
            (
                "a brace inside a raw string",
                "#[cfg(test)]\nmod tests {\n    fn t() { let s = r#\"{ \"}\"#; }\n}\n",
            ),
            (
                "a brace inside a line comment",
                "#[cfg(test)]\nmod tests {\n    // }\n    fn t() {}\n}\n",
            ),
            (
                "a brace inside a block comment",
                "#[cfg(test)]\nmod tests {\n    /* } /* } */ */\n    fn t() {}\n}\n",
            ),
            (
                "a lifetime, which is not a char literal",
                "#[cfg(test)]\nmod tests {\n    fn t<'a>(x: &'a str) -> &'a str { x }\n}\n",
            ),
            (
                "a bare `#[cfg(test)] fn`, not a module",
                "#[cfg(test)]\nfn helper() { let _ = 1; }\n",
            ),
        ] {
            let stripped = strip_cfg_test_regions(&format!("{src}{kept}"));
            assert_eq!(
                stripped.trim(),
                kept,
                "{name}: the strip took shipped code with it, or left test \
                 code behind",
            );
        }

        // And a source with no test region is returned whole.
        assert_eq!(strip_cfg_test_regions(kept), kept);
    }

    /// Every `.rs` under this crate's `src/`, as `(path relative to src/,
    /// text)`.
    ///
    /// Read from disk rather than `include_str!` because the invariant is
    /// about the crate and not about one file, which is the scope the
    /// single-literal count was missing.
    fn crate_sources() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir).expect("this crate's own sources");
            for e in entries.flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|x| x != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("a source file this crate built");
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, text));
            }
        }
        assert!(
            out.iter().any(|(p, _)| p == "startup.rs"),
            "the gate found no sources to walk, so it would pass on an empty \
             set; it read {}",
            root.display(),
        );
        out.sort();
        out
    }

    /// The graceful-shutdown drain does not scale with slot count.
    ///
    /// Moving the bounded exit wait onto `spawn_blocking` changed which
    /// thread waits, not how long the daemon takes to stop: awaiting each
    /// job before spawning the next left the wall-clock stop time at up to
    /// seven seconds per OpenVPN slot, serialized, which is the `7N` this
    /// series named as the thing it was avoiding. `deploy/torrentd.service`
    /// sets no `TimeoutStopSec`, so systemd's default is the only bound.
    ///
    /// The property is overlap, so overlap is what is counted.
    ///
    /// This used to assert that six 200 ms sleeps drained inside 600 ms — the
    /// only wall-clock assertion in the workspace, and one that says
    /// "concurrent" only as long as the runner is not busy. CI runners are
    /// busy, so that reading held by luck. Each job here instead announces
    /// itself, waits for the rest to arrive, and the peak count of jobs inside
    /// the closure at once is asserted directly: six means every teardown was
    /// in flight together, whatever the machine was doing at the time.
    ///
    /// The deadline is a failure bound, not a measurement. Serialized, job 0
    /// waits it out alone, the peak is 1 and the assertion fails on what it
    /// counted — where a stopwatch could only report a slow runner. Await each
    /// job in turn in `join_teardowns` and this fails.
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
                    SlotId::new(format!("account_{i}")),
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
             a deployment's stop time must not scale with its slot count",
        );
    }

    /// And a teardown that panics is warned past rather than taking the rest
    /// of the drain with it — shutdown must not fail on a tunnel.
    #[tokio::test]
    async fn a_teardown_that_panics_does_not_abandon_the_others() {
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let jobs: Vec<BoxedTeardown> = vec![
            (
                SlotId::new("account_a"),
                "tun-a".to_string(),
                Box::new(|| panic!("wg-quick down went wrong")),
            ),
            (
                SlotId::new("account_b"),
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
            "the second slot's tunnel still came down",
        );
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

    /// The signal seam that used to have 400 lines in it.
    ///
    /// `subscribe()` sets a new receiver's cursor to the channel's current
    /// tail, so a receiver created after a send provably cannot see it. Both
    /// of `boot`'s receivers therefore have to exist before the signal
    /// listener can send anything — which is what taking them as a pair
    /// enforces.
    #[test]
    fn both_boot_receivers_see_a_shutdown_raised_during_boot() {
        let (tx, _keep_open) = broadcast::channel(8);
        let (mut boot_shutdown, mut shutdown_rx) = boot_shutdown_receivers(&tx);

        // A SIGTERM arriving while boot is still scanning the resume dir.
        tx.send(ShutdownReason::Sigterm).expect("a live receiver");

        assert!(
            boot_shutdown.try_recv().is_ok(),
            "the slot loop's check sees it and aborts the boot",
        );
        assert!(
            matches!(shutdown_rx.try_recv(), Ok(ShutdownReason::Sigterm)),
            "and the receiver the HTTP server's graceful shutdown waits on \
             still has its own copy",
        );

        // The counterfactual, and the reason the pair exists: subscribing
        // after the send — where `boot` used to, past both startup scans —
        // sees nothing at all, and the daemon serves until SIGKILL.
        let mut subscribed_after = tx.subscribe();
        assert!(
            subscribed_after.try_recv().is_err(),
            "a receiver subscribed after the send cannot see it",
        );
    }

    /// The *ordering*, which the test above does not reach.
    ///
    /// `boot` took the pair and then installed the listener as two adjacent
    /// statements, and nothing pinned which came first: swapping them left
    /// the whole suite green while reopening the window that `send` with no
    /// live receiver discards outright. The stand-in listener below sends the
    /// instant it is installed, which is the race — `signals::run` spawns and
    /// returns with no await point, and its task can install all three
    /// handlers and take a SIGTERM before the next statement of `boot` runs.
    ///
    /// Install before taking the pair in `boot_shutdown_receivers_before` and
    /// this fails.
    #[tokio::test]
    async fn the_listener_is_installed_only_once_both_receivers_exist() {
        let (tx, first) = broadcast::channel(8);
        // No receiver of `boot`'s owns the channel at this point, which is
        // what makes a send in the window lost rather than merely unseen.
        drop(first);

        let sender = tx.clone();
        let (mut boot_shutdown, mut shutdown_rx) =
            boot_shutdown_receivers_before(&tx, || async move {
                let _ = sender.send(ShutdownReason::Sigterm);
            })
            .await;

        assert!(
            boot_shutdown.try_recv().is_ok(),
            "a SIGTERM taken the instant the listener is installed still \
             reaches the slot loop's check",
        );
        assert!(
            matches!(shutdown_rx.try_recv(), Ok(ShutdownReason::Sigterm)),
            "and the receiver the HTTP server's graceful shutdown waits on",
        );
    }
}
