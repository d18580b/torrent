//! Startup orchestrator: build the engine(s), wire the alert loop, bind
//! the HTTP server, install signal handlers, and run until shutdown.
//!
//! The single-session and multi-profile paths converge at the AlertSource
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
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileSource;
use torrentd_engine::ProfileStatus;
use torrentd_engine::RealEngine;
use torrentd_engine::ResumeStore;
use torrentd_engine::ShutdownReason;
use torrentd_engine::SingleSessionSource;
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
use crate::profile_registry::ProfileEntry;
use crate::profile_registry::ProfileRegistry;
use crate::reload;
use crate::sd_notify;
use crate::signals::SignalChannels;
use crate::signals::{self};
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
#[derive(Debug)]
struct BootCleanup {
    run_dir: std::path::PathBuf,
    tunnels: Vec<(torrentd_engine::VpnType, String)>,
    kill_switch: bool,
    armed: bool,
}

impl BootCleanup {
    fn new(run_dir: std::path::PathBuf) -> Self {
        Self {
            run_dir,
            tunnels: Vec::new(),
            kill_switch: false,
            armed: true,
        }
    }

    /// Record a tunnel this boot raised.
    fn note_tunnel(&mut self, t: torrentd_engine::VpnType, iface: &str) {
        self.tunnels.push((t, iface.to_string()));
    }

    fn note_kill_switch(&mut self) {
        self.kill_switch = true;
    }

    /// Bring one tunnel down now and stop tracking it — for a profile that failed
    /// after its tunnel came up, whose tunnel must go even if boot succeeds.
    fn take_down(&mut self, iface: &str) {
        if let Some(i) = self.tunnels.iter().position(|(_, n)| n == iface) {
            let (t, name) = self.tunnels.remove(i);
            crate::vpn::for_type(t, &self.run_dir).bring_down(&name);
        }
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
            crate::vpn::for_type(t, &self.run_dir).bring_down(&iface);
        }
    }
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
    profile_registry: Option<Arc<ProfileRegistry>>,
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
    let mode = if cfg.profile.is_empty() {
        Mode::Single
    } else {
        Mode::MultiProfile
    };
    // Where a VPN manager keeps state a *later* process has to find — see
    // `vpn::for_type`. Resolved once here so bring-up and teardown agree.
    let run_dir = cfg.state_dir();

    // Signals, installed before anything that can block or fail.
    //
    // They used to go in after the resume and torrent-dir scans, which left
    // the whole of startup running on the default disposition — and startup is
    // where the daemon spends up to 30 seconds *per profile* waiting for a tunnel
    // to come up. A SIGTERM in that window killed the process outright, with
    // every tunnel it had already raised still up and nothing left to take
    // them down.
    let channels = SignalChannels::new();
    let (reload_tx, reload_rx) = mpsc::channel::<()>(8);
    let channels = SignalChannels::from_parts(channels.shutdown_tx, reload_tx);
    // Drop the receiver returned by signals::run; we wired our own pair.
    let _ = signals::run(channels.clone(), 8).await;
    let shutdown_tx = channels.shutdown_tx;
    // Subscribed before the profile loop so a signal raised during bring-up is
    // still there to be observed when the loop next checks.
    let mut boot_shutdown = shutdown_tx.subscribe();

    // Undoes what boot has raised, for every exit that is not a successful
    // one. Tunnels and the kill-switch table outlive the process, so a `?`
    // anywhere after the profile loop used to leave a host with live tunnels, an
    // nftables table confining a uid that no longer exists, and no daemon.
    let mut cleanup = BootCleanup::new(run_dir.clone());

    // Resume store — rooted at the top-level `resume_dir` and partitioned by
    // profile id, except where a `[[profile]]` names its own directory. Those keys
    // were validated for uniqueness and then ignored, so files landed under
    // the derived path and only matched the configured one by coincidence.
    let resume_store: Arc<dyn ResumeStore> = Arc::new(
        cfg.profile
            .iter()
            .fold(FsResumeStore::new(cfg.resume_dir.clone()), |st, profile| {
                st.with_profile_dir(profile.id.clone(), profile.resume_dir.clone())
            }),
    );

    // Torrent store — same per-profile partitioning as the resume store; holds
    // the raw .torrent files for the startup inventory scan, magnet-metadata
    // persistence, and removal cleanup.
    let torrent_store: Arc<dyn TorrentStore> = Arc::new(cfg.profile.iter().fold(
        FsTorrentStore::new(cfg.torrent_dir.clone()),
        |st, profile| st.with_profile_dir(profile.id.clone(), profile.torrent_dir.clone()),
    ));

    // Assignment registry.
    let registry = Arc::new(
        AssignmentRegistry::load_from(cfg.registry_path(), cfg.legacy_registry_path())
            .context("load assignment registry")?,
    );

    // Metrics sink — created early so the startup scans can record registry
    // rejections (profile_assignment_registry_errors_total).
    let metrics = Arc::new(PromSink::new());

    // Engines per profile (or one for single-session). In multi-profile mode we
    // also build the runtime profile registry that the /profiles API and the VPN
    // health monitor consume.
    let mut profile_registry: Option<Arc<ProfileRegistry>> = None;
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
        Mode::MultiProfile => {
            let mut profile_entries: Vec<ProfileEntry> = Vec::new();
            // Safety Rule 1: a profile whose tunnel does not come up never gets a
            // session, and the others carry on. It still has to be *reported*
            // as failed — skipping it outright made it vanish from `/profiles`,
            // so an operator wondering why an account was quiet found no trace
            // of it anywhere but the startup log.
            let mut failed_profiles: Vec<crate::profile_registry::FailedProfile> = Vec::new();
            macro_rules! fail_profile {
                ($cfg:expr, $reason:expr) => {{
                    failed_profiles.push(crate::profile_registry::FailedProfile {
                        config: $cfg.clone(),
                        reason: $reason,
                    });
                    continue;
                }};
            }
            for s in &cfg.profile {
                // 1) Bring the VPN up first. Safety Rule 1: if it
                //    fails, the profile's lt::session is never constructed
                //    — no bare-IP fallback.
                // A shutdown asked for during a previous profile's bring-up is
                // honoured here rather than after every remaining tunnel has
                // been raised.
                if boot_shutdown.try_recv().is_ok() {
                    anyhow::bail!("shutdown requested during profile bring-up");
                }
                let vpn = vpn::for_type(s.vpn_type, &run_dir);
                // `bring_up` shells out and polls for up to 30 seconds. On a
                // runtime worker that is 30 seconds per profile during which
                // nothing else — including the signal handler that is supposed
                // to interrupt exactly this — gets to run on that thread.
                let brought_up = {
                    let vpn = vpn.clone();
                    let profile = s.vpn_config();
                    tokio::task::spawn_blocking(move || vpn.bring_up(&profile))
                        .await
                        .context("vpn bring-up task")?
                };
                let tunnel_ip = match brought_up {
                    Ok(ip) => {
                        cleanup.note_tunnel(s.vpn_type, &s.vpn_interface);
                        ip
                    }
                    Err(e) => {
                        error!(
                            profile_id = %s.id,
                            error.cause = %e,
                            "VPN bring-up failed; profile disabled (no bare-IP fallback)",
                        );
                        fail_profile!(s, format!("VPN bring-up failed: {e}"));
                    }
                };

                // 2) Determine the listening port. Static profiles bind the
                //    operator's `listen_port`; natpmp profiles negotiate an
                //    ephemeral forwarded port from the tunnel gateway
                //    (ProtonVPN et al.). A startup negotiation failure disables
                //    the profile — loud, like a VPN bring-up failure — rather than
                //    silently seeding on an unforwarded port. Mid-session
                //    renewal failures are the soft warn+keep-seeding path
                //    (see port_forward_monitor).
                let (effective_port, forwarded_port, forwarded_epoch) = match s.port_forward {
                    PortForwardMode::Static => match s.listen_port {
                        Some(port) => (port, None, 0),
                        None => {
                            // validate_set should have caught this; be defensive.
                            error!(profile_id = %s.id, "static profile missing listen_port; profile disabled");
                            cleanup.take_down(&s.vpn_interface);
                            fail_profile!(s, "static profile has no listen_port".to_string());
                        }
                    },
                    PortForwardMode::Natpmp => {
                        let gw_str = s.port_forward_gateway_or_default();
                        let gateway: IpAddr = match gw_str.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                error!(profile_id = %s.id, gateway = %gw_str, error.cause = %e, "invalid port_forward_gateway; profile disabled");
                                cleanup.take_down(&s.vpn_interface);
                                fail_profile!(s, format!("invalid port_forward_gateway: {e}"));
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
                                info!(profile_id = %s.id, tunnel_ip = %tunnel_ip, gateway = %gateway, forwarded_port = m.port, gateway_epoch = m.epoch, "NAT-PMP port negotiated");
                                (m.port, Some(m.port), m.epoch)
                            }
                            Err(e) => {
                                error!(profile_id = %s.id, tunnel_ip = %tunnel_ip, gateway = %gateway, error.cause = %e, "NAT-PMP negotiation failed at startup; profile disabled (no bare-IP fallback)");
                                cleanup.take_down(&s.vpn_interface);
                                fail_profile!(s, format!("NAT-PMP negotiation failed: {e}"));
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
                // `[[profile]] upload_rate_limit` was parsed, documented in the
                // sample config, and applied nowhere — a profile's limit silently
                // did nothing. Zero means "inherit the top-level limit", which
                // is what the default has always meant in practice.
                if s.upload_rate_limit > 0 {
                    settings.upload_rate_limit = Some(s.upload_rate_limit);
                }
                settings.enable_dht = Some(false);
                settings.enable_lsd = Some(false);
                settings.enable_upnp = Some(false);
                settings.enable_natpmp = Some(false);

                match RealEngine::new(&settings) {
                    Ok(engine) => {
                        info!(
                            profile_id = %s.id,
                            tunnel_ip = %tunnel_ip,
                            listen_port = effective_port,
                            "profile engine up",
                        );
                        let engine: Arc<dyn TorrentEngine> = Arc::new(engine);
                        profile_entries.push(ProfileEntry::new(
                            s.clone(),
                            engine,
                            tunnel_ip,
                            forwarded_port,
                            forwarded_epoch,
                        ));
                    }
                    Err(e) => {
                        error!(
                            profile_id = %s.id,
                            error.cause = %e,
                            "profile engine construction failed; tearing down VPN",
                        );
                        cleanup.take_down(&s.vpn_interface);
                        failed_profiles.push(crate::profile_registry::FailedProfile {
                            config: s.clone(),
                            reason: format!("session construction failed: {e}"),
                        });
                    }
                }
            }
            if profile_entries.is_empty() {
                anyhow::bail!("multi-profile mode: no profiles came up");
            }
            let source_entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)> = profile_entries
                .iter()
                .map(|e| (e.config.id.clone(), e.engine.clone()))
                .collect();
            profile_registry = Some(Arc::new(
                ProfileRegistry::new(profile_entries).with_failed(failed_profiles),
            ));
            Arc::new(ProfileSource::new(source_entries))
        }
    };

    // Network-layer kill switch (defence-in-depth; multi-profile + opt-in).
    // Installed once, after every profile's tunnel is up, so the ruleset covers all
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
        match &profile_registry {
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
                    "network_kill_switch = true but no [[profile]] entries are configured. \
                     The kill switch confines the daemon's egress to its profiles' tunnel \
                     interfaces, and single-session mode has none — it would seed from \
                     the bare IP with no backstop. Configure profiles, or unset \
                     network_kill_switch.",
                );
            }
        }
    }

    // Resume scan: load every saved resume file per profile. The shim
    // already deduplicates duplicate adds so a future torrent dir scan
    // won't double-add.
    for profile in source.profiles() {
        let entries = resume_store.load_all(&profile).context("scan resume dir")?;
        let count = entries.len();
        let mut missing_metadata = 0usize;
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
        for (ih, data) in entries {
            // Cross-check the registry; the spec aborts the profile on mismatch.
            // Single-session always uses ProfileId::DEFAULT, so the check
            // mainly guards multi-profile mode.
            if let Some(existing) = registry.lookup(&ih) {
                if existing != profile {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        existing_profile = %existing,
                        "resume file in wrong profile; skipping (operator must reconcile)",
                    );
                    metrics.inc_counter(
                        "profile_assignment_registry_errors_total",
                        &[("profile_id", profile.as_str())],
                    );
                    continue;
                }
            } else if let Err(e) = registry.assign(ih, profile.clone()) {
                // Rule 4 makes the registry the gate every load passes. An
                // assignment that failed to persist is one that disappears at
                // the next restart, after which nothing knows this info-hash
                // belongs to this profile — so refuse the load rather than seed a
                // torrent the uniqueness rule can no longer see.
                warn!(
                    profile_id = %profile,
                    infohash = %ih,
                    error.cause = %e,
                    "could not record the resume assignment; skipping this torrent",
                );
                metrics.inc_counter(
                    "profile_assignment_registry_errors_total",
                    &[("profile_id", profile.as_str())],
                );
                continue;
            }
            // Re-attach metadata. libtorrent writes the info dict into resume
            // data only when save_resume_data was called with SAVE_INFO_DICT
            // (vendor/libtorrent/src/torrent.cpp: `ret.ti = m_torrent_file` is
            // gated on that flag), so resume data alone leaves the torrent with
            // no metadata and it re-enters downloading_metadata on restart —
            // fatal for a private profile with DHT and PEX disabled. Setting the
            // flag instead would embed a full piece-hash table in every resume
            // file, so pass the .torrent already on disk.
            let torrent = match torrent_store.read(&profile, &ih) {
                Ok(t) => t,
                Err(e) => {
                    warn!(profile_id = %profile, infohash = %ih, error.cause = %e,
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
            // monitor pauses a whole profile when its tunnel drops, and if the
            // resume sweep lands in that window every torrent comes back
            // paused. But resume data does not record *why* a torrent was
            // paused, so clearing it also silently restarts a torrent an
            // operator paused on purpose — on a private tracker, the kind of
            // mistake that ends an account. A pool that comes back paused is
            // visible in `/status` and fixed with `resume-all`; a pool that
            // comes back seeding when it was told not to is not recoverable.
            let flags_set = torrentd_engine::resume_flags_set(&profile);
            let flags_clear = TorrentFlags::empty();
            if let Err(e) = engine.add_torrent(AddParams::Resume {
                bytes: data.into_inner(),
                torrent,
                save_path: None,
                flags_set,
                flags_clear,
            }) {
                warn!(profile_id = %profile, infohash = %ih, error.cause = %e, "resume add failed");
            }
        }
        if missing_metadata > 0 {
            // Not fatal — libtorrent can still fetch metadata from peers where
            // discovery is enabled — but on a private profile it usually means the
            // torrent will sit idle, so make it visible rather than silent.
            warn!(
                profile_id = %profile,
                torrent_count = missing_metadata,
                "resume entries with no .torrent on disk; these rely on peer metadata exchange",
            );
        }
        info!(profile_id = %profile, torrent_count = count, "resume scan complete");
    }

    // Torrent-dir scan: add any .torrent whose info-hash has no resume file
    // (resume always wins; startup inventory). After this the torrent
    // dir is not re-scanned — new torrents arrive only via the API.
    let scan_save_path = cfg.default_save_path.to_string_lossy().into_owned();
    for profile in source.profiles() {
        let entries = torrent_store
            .load_all(&profile)
            .context("scan torrent dir")?;
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
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
            if let Err(e) = registry.assign(ih, profile.clone()) {
                warn!(
                    profile_id = %profile,
                    infohash = %ih,
                    error.cause = %e,
                    "could not record the torrent-dir assignment; skipping this torrent",
                );
                metrics.inc_counter(
                    "profile_assignment_registry_errors_total",
                    &[("profile_id", profile.as_str())],
                );
                continue;
            }
            let flags = torrentd_engine::seed_flags(&profile);
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
                        profile_id = %profile,
                        infohash = %ih,
                        error.cause = %e,
                        "torrent-dir add failed",
                    );
                }
            }
        }
        if added > 0 {
            info!(profile_id = %profile, torrent_count = added, "torrent dir scan: added new torrents");
        }
    }

    // Subscribe now, not when the HTTP server starts: a broadcast sent with no
    // live receiver is discarded, so a SIGTERM during the resume scan would
    // otherwise leave the daemon running with nothing left to stop it.
    let shutdown_rx = shutdown_tx.subscribe();

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
    // multi-profile mode the per-profile handler marks that profile failed and the
    // remaining profiles carry on.
    .fatal_listen_failure(mode == Mode::Single)
    .on_fatal({
        let tx = shutdown_tx.clone();
        Arc::new(move |reason| {
            let _ = tx.send(reason);
        }) as torrentd_engine::FatalCallback
    })
    // The engine resumes torrents on its own upload-mode retry schedule and
    // has no concept of a tunnel, so it has to be told which profiles the VPN
    // monitor has fenced.
    .profile_fenced({
        let profiles = profile_registry.clone();
        Arc::new(move |id: &torrentd_engine::ProfileId| {
            profiles
                .as_ref()
                .and_then(|sr| sr.get(id))
                .is_some_and(|e| e.health().status == ProfileStatus::VpnDown)
        }) as torrentd_engine::ProfileFenced
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
        profile_registry,
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
            profile_registry,
            kill_switch_active,
            log_handle,
            alert_loop,
        } = self;

        // VPN health monitor (multi-profile only). Spawned before AppState
        // consumes the registry/state/metrics.
        if let Some(profiles) = profile_registry.clone() {
            tokio::spawn(crate::vpn_monitor::run(
                profiles.clone(),
                state.clone(),
                metrics.clone(),
                std::time::Duration::from_secs(cfg.vpn_handshake_max_age_secs),
                shutdown_tx.subscribe(),
            ));
            // Port-forward renewal monitor: keeps NAT-PMP leases alive and
            // rebinds the live session if the forwarded port changes.
            tokio::spawn(crate::port_forward_monitor::run(
                profiles,
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
                profile_registry.clone(),
                shutdown_tx.subscribe(),
            ));
        }

        let app_state = AppState {
            source: source.clone(),
            registry: registry.clone(),
            profiles: profile_registry.clone(),
            state,
            torrents,
            metrics: metrics.clone(),
            auth: cfg.auth.clone().map(crate::auth::Auth::new),
            pool,
            alert_heartbeat: alert_loop.heartbeat(),
            default_save_path: cfg.default_save_path.clone(),
            torrent_dir: cfg.torrent_dir.clone(),
            mode: if cfg.profile.is_empty() {
                Mode::Single
            } else {
                Mode::MultiProfile
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
        // profiles run with enable_dht=false and skip this). The session
        // is still alive here — only dropped when `source` goes out of scope.
        if cfg.profile.is_empty() {
            if let Some(engine) = source.engine_for(&ProfileId::default_single()) {
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
        // tunnel is still up during a graceful shutdown, so the profiles' sockets
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
        if let Some(profiles) = &profile_registry {
            let run_dir = cfg.state_dir();
            for entry in profiles.iter() {
                let vpn = crate::vpn::for_type(entry.config.vpn_type, &run_dir);
                vpn.bring_down(&entry.config.vpn_interface);
                info!(
                    profile_id = %entry.config.id,
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
