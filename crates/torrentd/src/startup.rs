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

    /// Bring one tunnel down now and stop tracking it — for a slot that failed
    /// after its tunnel came up, whose tunnel must go even if boot succeeds.
    fn take_down(&mut self, iface: &str) {
        if let Some(i) = self.tunnels.iter().position(|(_, n)| n == iface) {
            let (t, name) = self.tunnels.remove(i);
            (self.vpn_for)(t, &self.run_dir).bring_down(&name);
        }
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
    /// tracking it: `take_down` had nothing to remove, `Drop` had nothing to
    /// bring down, `SlotRegistry::iter()` excludes failed slots so the
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
    /// exists: a bring-up that failed *because* an interface of that name
    /// already exists and belongs to something else. Recording before the
    /// attempt turned that case into `wg-quick down <iface>` on a tunnel the
    /// WireGuard manager had just refused to adopt, taking its routes and
    /// rules with it — the daemon destroying a stranger's tunnel over a name
    /// collision. Nothing of ours is running there, so it is forgotten
    /// rather than torn down, and the drop guard does not see it either.
    ///
    /// The bring-up itself runs on `spawn_blocking`: it shells out and polls,
    /// and on a runtime worker that is 30 seconds per slot during which
    /// nothing else — including the signal handler that is supposed to
    /// interrupt exactly this — gets to run on that thread.
    async fn bring_up_tracked(
        &mut self,
        vpn: Arc<dyn torrentd_engine::VpnManager>,
        t: torrentd_engine::VpnType,
        profile: torrentd_engine::VpnProfile,
    ) -> anyhow::Result<Result<IpAddr, torrentd_engine::VpnError>> {
        let iface = profile.interface.clone();
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
            Err(_) => self.take_down(&iface),
        }
        Ok(brought_up)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BootCleanup {
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
/// **called before `signals::run`**, which is the rest of the property.
/// `signals::run` spawns its listener and returns without an await point, and
/// the runtime is multi-threaded, so the spawned task can install all three
/// handlers, take a SIGTERM and send on another worker before the next two
/// instructions of `boot` execute. A send with no live receiver is not
/// buffered for a later `subscribe()` — `broadcast::Sender::send` returns the
/// value back in its error and writes nothing to the ring — so a send landing
/// in that window is lost outright, and with the listener looping nothing
/// re-reports it. Below the call the guarantee is probabilistic; above it,
/// where the sender already exists and is all this needs, it is structural.
fn boot_shutdown_receivers(
    tx: &broadcast::Sender<ShutdownReason>,
) -> (
    broadcast::Receiver<ShutdownReason>,
    broadcast::Receiver<ShutdownReason>,
) {
    (tx.subscribe(), tx.subscribe())
}

pub struct DaemonHandle {
    cfg: Config,
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
    // the listener that can send to them exists. See
    // `boot_shutdown_receivers` for what subscribing the second one late cost
    // and why the order of these two lines is the whole property.
    let (mut boot_shutdown, shutdown_rx) = boot_shutdown_receivers(&shutdown_tx);
    // Drop the receiver returned by signals::run; we wired our own pair.
    let _ = signals::run(channels.clone(), 8).await;

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
                let brought_up = cleanup
                    .bring_up_tracked(
                        vpn::for_type(s.vpn_type, &run_dir),
                        s.vpn_type,
                        s.vpn_profile(),
                    )
                    .await?;
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
                            cleanup.take_down(&s.vpn_interface);
                            fail_slot!(s, "static slot has no listen_port".to_string());
                        }
                    },
                    PortForwardMode::Natpmp => {
                        let gw_str = s.port_forward_gateway_or_default();
                        let gateway: IpAddr = match gw_str.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                error!(slot_id = %s.id, gateway = %gw_str, error.cause = %e, "invalid port_forward_gateway; slot disabled");
                                cleanup.take_down(&s.vpn_interface);
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
                                cleanup.take_down(&s.vpn_interface);
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
                        cleanup.take_down(&s.vpn_interface);
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
            let run_dir = cfg.state_dir();
            for entry in slots.iter() {
                let vpn = crate::vpn::for_type(entry.config.vpn_type, &run_dir);
                vpn.bring_down(&entry.config.vpn_interface);
                info!(
                    slot_id = %entry.config.id,
                    vpn_iface = %entry.config.vpn_interface,
                    "tunnel down",
                );
            }
        }

        info!("torrentd: clean exit");
        exit_code
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

    /// A tunnel whose bring-up fails *after* the spawn.
    ///
    /// `openvpn --daemon` exits 0 as soon as it forks, and `wg-quick up`
    /// creates the interface before any address appears, so the 30-second
    /// address poll expiring leaves something live behind. Recording the
    /// tunnel only once an address had appeared meant nothing ever brought
    /// that one down: the failure arm called neither `note_tunnel` nor
    /// `take_down`, unlike its four siblings, and `SlotRegistry::iter()`
    /// excludes failed slots so the shutdown loop never saw it either.
    #[tokio::test]
    async fn a_tunnel_whose_bring_up_fails_is_still_brought_down() {
        let vpn = MockVpn::new();
        // No `set_ip`, so `bring_up` fails the way the address poll does.
        let mut cleanup = cleanup_with(vpn.clone());
        let r = cleanup
            .bring_up_tracked(Arc::new(vpn.clone()), VpnType::Wireguard, profile("wg-a"))
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
    #[tokio::test]
    async fn a_bring_up_refused_by_a_foreign_interface_leaves_it_standing() {
        let vpn = MockVpn::new();
        vpn.set_foreign("wg-a");
        let mut cleanup = cleanup_with(vpn.clone());
        let r = cleanup
            .bring_up_tracked(Arc::new(vpn.clone()), VpnType::Wireguard, profile("wg-a"))
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
            .bring_up_tracked(Arc::new(vpn.clone()), VpnType::Wireguard, profile("wg-a"))
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

    /// `disarm` hands the tunnels to the shutdown path; dropping after it
    /// must not stop the daemon that just started.
    #[tokio::test]
    async fn a_disarmed_guard_leaves_the_running_daemon_alone() {
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        let mut cleanup = cleanup_with(vpn.clone());
        let _ = cleanup
            .bring_up_tracked(Arc::new(vpn.clone()), VpnType::Wireguard, profile("wg-a"))
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
}
