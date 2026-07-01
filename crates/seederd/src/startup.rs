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
use seederd_engine::AddParams;
use seederd_engine::AlertLoopBuilder;
use seederd_engine::AlertSource;
use seederd_engine::AssignmentRegistry;
use seederd_engine::FsResumeStore;
use seederd_engine::FsTorrentStore;
use seederd_engine::MetricsSink;
use seederd_engine::MultiSlotSource;
use seederd_engine::PortForwardMode;
use seederd_engine::PortForwarder;
use seederd_engine::PortMapRequest;
use seederd_engine::RealEngine;
use seederd_engine::ResumeStore;
use seederd_engine::ShutdownReason;
use seederd_engine::SingleSessionSource;
use seederd_engine::SlotId;
use seederd_engine::StateMap;
use seederd_engine::SystemClock;
use seederd_engine::TorrentEngine;
use seederd_engine::TorrentFlags;
use seederd_engine::TorrentStore;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::app_state::Mode;
use crate::config::Config;
use crate::http;
use crate::metrics_sink::PromSink;
use crate::reload;
use crate::signals::SignalChannels;
use crate::signals::{self};
use crate::slot_registry::SlotEntry;
use crate::slot_registry::SlotRegistry;
use crate::vpn;

pub struct DaemonHandle {
    cfg: Config,
    state: Arc<StateMap>,
    source: Arc<dyn AlertSource>,
    torrents: Arc<dyn TorrentStore>,
    shutdown_tx: broadcast::Sender<ShutdownReason>,
    reload_rx: mpsc::Receiver<()>,
    metrics: Arc<PromSink>,
    registry: Arc<AssignmentRegistry>,
    slot_registry: Option<Arc<SlotRegistry>>,
    /// Whether the nftables kill switch was installed and must be torn down on
    /// graceful shutdown.
    kill_switch_active: bool,
    log_handle: crate::tracing_init::LogReloadHandle,
    alert_loop: seederd_engine::AlertLoopHandle,
}

pub async fn boot(
    cfg: Config,
    log_handle: crate::tracing_init::LogReloadHandle,
) -> anyhow::Result<DaemonHandle> {
    info!("starting seederd");
    let mode = if cfg.slot.is_empty() {
        Mode::Single
    } else {
        Mode::MultiSlot
    };

    // Resume store — single root for both modes; FsResumeStore partitions
    // by slot id internally.
    let resume_store: Arc<dyn ResumeStore> = Arc::new(FsResumeStore::new(cfg.resume_dir.clone()));

    // Torrent store — same per-slot partitioning as the resume store; holds
    // the raw .torrent files for the startup inventory scan, magnet-metadata
    // persistence, and removal cleanup (PRD §6 / §Session Management).
    let torrent_store: Arc<dyn TorrentStore> =
        Arc::new(FsTorrentStore::new(cfg.torrent_dir.clone()));

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
            // Restore the DHT routing table + session state across restarts
            // (PRD §Session Management). DHT is enabled only in single-session
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
            for s in &cfg.slot {
                // 1) Bring the VPN up first. PRD Safety Rule 1: if it
                //    fails, the slot's lt::session is never constructed
                //    — no bare-IP fallback.
                let vpn = vpn::for_type(s.vpn_type);
                let tunnel_ip = match vpn.bring_up(&s.vpn_profile()) {
                    Ok(ip) => ip,
                    Err(e) => {
                        error!(
                            slot_id = %s.id,
                            error.cause = %e,
                            "VPN bring-up failed; slot disabled (no bare-IP fallback)",
                        );
                        continue;
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
                            vpn.bring_down(&s.vpn_interface);
                            continue;
                        }
                    },
                    PortForwardMode::Natpmp => {
                        let gw_str = s.port_forward_gateway_or_default();
                        let gateway: IpAddr = match gw_str.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                error!(slot_id = %s.id, gateway = %gw_str, error.cause = %e, "invalid port_forward_gateway; slot disabled");
                                vpn.bring_down(&s.vpn_interface);
                                continue;
                            }
                        };
                        let req = PortMapRequest {
                            gateway,
                            bind_ip: tunnel_ip,
                            internal_port: 0,
                            lifetime_secs: crate::port_forward_monitor::LEASE_SECS,
                        };
                        match vpn::NatpmpForwarder::new().map(&req) {
                            Ok(m) => {
                                info!(slot_id = %s.id, tunnel_ip = %tunnel_ip, gateway = %gateway, forwarded_port = m.port, gateway_epoch = m.epoch, "NAT-PMP port negotiated");
                                (m.port, Some(m.port), m.epoch)
                            }
                            Err(e) => {
                                error!(slot_id = %s.id, tunnel_ip = %tunnel_ip, gateway = %gateway, error.cause = %e, "NAT-PMP negotiation failed at startup; slot disabled (no bare-IP fallback)");
                                vpn.bring_down(&s.vpn_interface);
                                continue;
                            }
                        }
                    }
                };

                // 3) Bind libtorrent to the tunnel IP + effective port only.
                let mut settings = cfg.libtorrent_settings();
                settings.user_agent = Some(s.user_agent.clone());
                settings.handshake_client_version = Some(s.user_agent.clone());
                settings.peer_fingerprint = Some(s.peer_fingerprint_hex.clone());
                settings.listen_interfaces = Some(format!("{}:{}", tunnel_ip, effective_port));
                settings.outgoing_interfaces = Some(tunnel_ip.to_string());
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
                        vpn.bring_down(&s.vpn_interface);
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
            slot_registry = Some(Arc::new(SlotRegistry::new(slot_entries)));
            Arc::new(MultiSlotSource::new(source_entries))
        }
    };

    // Network-layer kill switch (defence-in-depth; multi-slot + opt-in).
    // Installed once, after every slot's tunnel is up, so the ruleset covers all
    // tunnel interfaces. Fail-closed: if the operator asked for it and it can't
    // be installed, abort rather than seed without the backstop.
    let mut kill_switch_active = false;
    if cfg.network_kill_switch {
        match &slot_registry {
            Some(sr) => {
                let tunnels: Vec<String> =
                    sr.iter().map(|e| e.config.vpn_interface.clone()).collect();
                let uid = vpn::killswitch::enable(&tunnels)
                    .context("install nftables kill switch (network_kill_switch=true)")?;
                kill_switch_active = true;
                metrics.set_gauge("kill_switch_active", 1.0, &[]);
                info!(uid, "network kill switch active");
            }
            None => warn!(
                "network_kill_switch set but no slots configured; \
                 ignoring (single-session mode has no tunnel to protect)",
            ),
        }
    }

    // Resume scan: load every saved resume file per slot. The shim
    // already deduplicates duplicate adds so a future torrent dir scan
    // won't double-add.
    for slot in source.slots() {
        let entries = resume_store.load_all(&slot).context("scan resume dir")?;
        let count = entries.len();
        let engine = source
            .engine_for(&slot)
            .ok_or_else(|| anyhow::anyhow!("no engine for slot {}", slot))?;
        for (ih, data) in entries {
            // Cross-check the registry; PRD aborts the slot on mismatch.
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
            } else {
                let _ = registry.assign(ih, slot.clone());
            }
            if let Err(e) = engine.add_torrent(AddParams::Resume {
                bytes: data.into_inner(),
            }) {
                warn!(slot_id = %slot, infohash = %ih, error.cause = %e, "resume add failed");
            }
        }
        info!(slot_id = %slot, torrent_count = count, "resume scan complete");
    }

    // Torrent-dir scan: add any .torrent whose info-hash has no resume file
    // (resume always wins; PRD §6 startup inventory). After this the torrent
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
            let flags = if slot.is_default() {
                TorrentFlags::SEED_MODE
            } else {
                TorrentFlags::SEED_MODE
                    | TorrentFlags::DISABLE_PEX
                    | TorrentFlags::DISABLE_DHT
                    | TorrentFlags::DISABLE_LSD
            };
            match engine.add_torrent(AddParams::File {
                bytes,
                save_path: scan_save_path.clone(),
                flags,
            }) {
                Ok(_) => {
                    let _ = registry.assign(ih, slot.clone());
                    added += 1;
                }
                Err(e) => warn!(
                    slot_id = %slot,
                    infohash = %ih,
                    error.cause = %e,
                    "torrent-dir add failed",
                ),
            }
        }
        if added > 0 {
            info!(slot_id = %slot, torrent_count = added, "torrent dir scan: added new torrents");
        }
    }

    // Alert loop.
    let metrics_for_loop: Arc<dyn MetricsSink> = metrics.clone();
    let state = Arc::new(StateMap::new());
    let clock: Arc<dyn seederd_engine::Clock> = Arc::new(SystemClock);

    let alert_loop = AlertLoopBuilder::new(
        source.clone(),
        state.clone(),
        resume_store.clone(),
        torrent_store.clone(),
        metrics_for_loop,
        clock,
    )
    .spawn();

    // Signals.
    let channels = SignalChannels::new();
    let (reload_tx, reload_rx) = mpsc::channel::<()>(8);
    let channels = SignalChannels::from_parts(channels.shutdown_tx, reload_tx);
    // Drop the receiver returned by signals::run; we wired our own pair.
    let _ = signals::run(channels.clone(), 8).await;
    let shutdown_tx = channels.shutdown_tx;

    Ok(DaemonHandle {
        cfg,
        state,
        source,
        torrents: torrent_store,
        shutdown_tx,
        reload_rx,
        metrics,
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
            state,
            source,
            torrents,
            shutdown_tx,
            reload_rx,
            metrics,
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

        let app_state = AppState {
            source: source.clone(),
            registry: registry.clone(),
            slots: slot_registry,
            state,
            torrents,
            metrics,
            default_save_path: cfg.default_save_path.clone(),
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
        let cfg_path = std::env::args()
            .skip_while(|a| a != "--config" && !a.starts_with("--config="))
            .nth(1)
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        let cfg_clone = cfg.clone();
        tokio::spawn(reload::run(
            cfg_path,
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

        let mut shutdown_rx = shutdown_tx.subscribe();
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
        });

        let exit_code = match server.await {
            Ok(()) => 0,
            Err(e) => {
                error!(error.cause = %e, "HTTP server exited with error");
                70
            }
        };

        // Trigger alert-loop shutdown and join (saves all resume data).
        alert_loop.signal_shutdown(ShutdownReason::Sigterm);
        if let Err(e) = alert_loop.join() {
            warn!(error.cause = ?e, "alert loop join panicked");
        }

        // Persist DHT/session state for the next start (single-session mode;
        // slots run with enable_dht=false and skip this per PRD). The session
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
        }

        info!("seederd: clean exit");
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
    Ok(())
}
