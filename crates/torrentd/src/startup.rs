//! Startup orchestrator: build the engine(s), wire the alert loop, bind
//! the HTTP server, install signal handlers, and run until shutdown.
//!
//! There is one path, not two: every profile becomes a session, and the set
//! of them becomes one `Arc<dyn AlertSource>` that the rest of the daemon
//! consumes uniformly. A deployment with a single profile is that set with
//! n = 1.

use std::collections::HashSet;
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
use torrentd_engine::ProfileNetwork;
use torrentd_engine::ProfileSource;
use torrentd_engine::ProfileStatus;
use torrentd_engine::RealEngine;
use torrentd_engine::ResumeStore;
use torrentd_engine::ShutdownReason;
use torrentd_engine::StateMap;
use torrentd_engine::SystemClock;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentFlags;
use torrentd_engine::TorrentStore;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
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
    resume: Arc<dyn ResumeStore>,
    shutdown_tx: broadcast::Sender<ShutdownReason>,
    /// Subscribed in `boot`, before the HTTP server exists, so a SIGTERM
    /// arriving during startup is buffered rather than dropped on the floor.
    shutdown_rx: broadcast::Receiver<ShutdownReason>,
    reload_rx: mpsc::Receiver<()>,
    /// Lets `POST /api/reload` ask for the same thing SIGHUP asks for.
    reload_tx: mpsc::Sender<()>,
    metrics: Arc<PromSink>,
    pool: Option<Arc<crate::pool_service::PoolService>>,
    registry: Arc<AssignmentRegistry>,
    profile_registry: Arc<ProfileRegistry>,
    /// Whether the nftables kill switch was installed and must be torn down on
    /// graceful shutdown.
    kill_switch_active: bool,
    log_handle: crate::tracing_init::LogReloadHandle,
    alert_loop: torrentd_engine::AlertLoopHandle,
    /// Registry entries no startup scan loaded; see `AppState::unloaded_at_boot`.
    unloaded_at_boot: std::collections::HashSet<libtorrent_safe::InfoHash>,
}

pub async fn boot(
    cfg: Config,
    config_path: std::path::PathBuf,
    log_handle: crate::tracing_init::LogReloadHandle,
) -> anyhow::Result<DaemonHandle> {
    info!("starting torrentd");
    // Refusals that are pure functions of the file, before any tunnel is
    // raised: among them a host profile beside `network_kill_switch`, whose
    // egress the ruleset would drop while it reported itself Active.
    cfg.check_boot_rules()?;
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
    // The HTTP surface asks for a reload the same way SIGHUP does, through
    // this channel, so both paths converge on one implementation.
    let reload_tx_for_api = reload_tx.clone();
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
    let resume_store: Arc<dyn ResumeStore> = Arc::new(cfg.profile.iter().fold(
        FsResumeStore::new(cfg.resume_dir.clone()),
        |st, profile| match &profile.resume_dir {
            Some(dir) => st.with_profile_dir(profile.id.clone(), dir.clone()),
            None => st,
        },
    ));

    // Torrent store — same per-profile partitioning as the resume store; holds
    // the raw .torrent files for the startup inventory scan, magnet-metadata
    // persistence, and removal cleanup.
    let torrent_store: Arc<dyn TorrentStore> = Arc::new(cfg.profile.iter().fold(
        FsTorrentStore::new(cfg.torrent_dir.clone()),
        |st, profile| match &profile.torrent_dir {
            Some(dir) => st.with_profile_dir(profile.id.clone(), dir.clone()),
            None => st,
        },
    ));

    // Assignment registry.
    let registry = Arc::new(
        AssignmentRegistry::load_from(cfg.registry_path(), cfg.legacy_registry_path())
            .context("load assignment registry")?,
    );

    // Reconcile it against the configured profiles before anything reads it.
    //
    // The migration above carries a pre-profiles registry over verbatim, which
    // means it still names that deployment's ids — `default`, on the
    // single-session layout this release replaces. Nothing reconciles those
    // with the `[[profile]]` tables, and nothing prunes them, so an id with no
    // table behind it strands every torrent it holds: the resume and torrent
    // scans are partitioned per profile and never look at the old paths, so
    // nothing loads; re-adding answers 409 because the registry says the
    // info-hash is taken; and `DELETE` cannot clear it either. The daemon
    // reports itself healthy the whole time.
    //
    // Refusing is not the gentlest outcome, but it is the honest one: a silent
    // total outage that answers 200 on `/healthz` is worse than a daemon that
    // says which ids it does not recognise and what to do about them. The
    // check runs against the *configured* set rather than the profiles that
    // came up — a profile that failed its tunnel is Safety Rule 1's business,
    // not this one's.
    {
        let configured: HashSet<ProfileId> = cfg.profile.iter().map(|p| p.id.clone()).collect();
        let unknown = registry.unknown_profiles(&configured);
        if !unknown.is_empty() {
            let named = unknown
                .iter()
                .map(|(id, n)| format!("{id} ({n} torrent(s))"))
                .collect::<Vec<_>>()
                .join(", ");
            let known = cfg
                .profile
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            // Name the file the entries were *read from*. On the path this
            // fires on — a migrated registry, which is what produces ids like
            // `default` — that is the pre-rename `slot_assignments.json`, and
            // quoting the post-rename name sent the operator to look at a
            // file whose contents are a copy made moments earlier. Both are
            // named, because both now exist and only one is the one the
            // daemon will read next time.
            let source = registry.source_path().display().to_string();
            let current = cfg.registry_path().display().to_string();
            let where_to_edit = if source == current {
                format!("remove those entries from {current}")
            } else {
                format!(
                    "remove those entries from {current} (they were read from {source}, which is \
                     left intact for a rollback; editing that file alone will not help, because \
                     {current} is what the daemon reads from here on)"
                )
            };
            anyhow::bail!(
                "the assignment registry at {source} assigns torrents to profiles that no \
                 [[profile]] table declares: {named}. Configured profiles: {known}. Those \
                 torrents cannot be loaded, re-added or deleted while the mismatch stands. \
                 Either give one of the configured profiles the id the registry names — the \
                 upgrade path from the pre-profiles layout, where every entry says `default` — \
                 or {where_to_edit} and re-add the torrents.",
            );
        }
    }

    // Metrics sink — created early so the startup scans can record registry
    // rejections (profile_assignment_registry_errors_total).
    let metrics = Arc::new(PromSink::new());

    // One libtorrent session per configured profile. There is no other shape:
    // a deployment with one profile is this with n = 1, not a mode of its own.
    let mut profile_entries: Vec<ProfileEntry> = Vec::new();
    // Safety Rule 1: a profile whose tunnel does not come up never gets a
    // session, and the others carry on. It still has to be *reported* as
    // failed — skipping it outright made it vanish from `/profiles`, so an
    // operator wondering why an account was quiet found no trace of it
    // anywhere but the startup log.
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

    for p in &cfg.profile {
        // A shutdown asked for during a previous profile's bring-up is
        // honoured here rather than after every remaining tunnel is raised.
        if boot_shutdown.try_recv().is_ok() {
            anyhow::bail!("shutdown requested during profile bring-up");
        }

        let mut settings = cfg.libtorrent_settings();
        if let Some(ua) = &p.user_agent {
            settings.user_agent = Some(ua.clone());
            settings.handshake_client_version = Some(ua.clone());
        }
        if let Some(fp) = &p.peer_fingerprint_hex {
            settings.peer_fingerprint = Some(fp.clone());
        }
        // `is_some()`, not `> 0`. `0` is a legal per-profile value meaning
        // *unlimited* — the top-level key's own comment says so — and testing
        // `> 0` read it as "unset" and pushed the daemon-wide cap onto a
        // session the operator had explicitly uncapped.
        if let Some(limit) = p.upload_rate_limit {
            settings.upload_rate_limit = Some(limit);
        }

        // What differs between the two postures, and nothing else: where the
        // sockets bind, and whether discovery may run.
        let mut tunnel_ip: Option<IpAddr> = None;
        let mut forwarded_port: Option<u16> = None;
        let mut forwarded_epoch: u32 = 0;
        let mut session_state: Option<Vec<u8>> = None;

        match &p.network {
            ProfileNetwork::Host {
                listen_interfaces,
                dht,
            } => {
                settings.listen_interfaces = Some(listen_interfaces.clone());
                settings.enable_dht = Some(*dht);
                // DHT keeps a routing table worth restoring; without DHT there
                // is nothing in session state worth the file.
                if *dht {
                    session_state = load_session_state(&cfg.session_state_path(&p.id));
                    if let Some(bytes) = &session_state {
                        info!(profile_id = %p.id, bytes = bytes.len(), "restoring session state");
                    }
                }
            }
            ProfileNetwork::Vpn { .. } => {
                let iface = p.vpn_interface().expect("vpn profile has an interface");
                let vpn_type = p.vpn_type().expect("vpn profile has a type");
                let tunnel = p.vpn_tunnel().expect("vpn profile has a tunnel");

                // Bring the tunnel up first. Safety Rule 1: if it fails, this
                // profile's session is never constructed — no bare-IP
                // fallback. `bring_up` shells out and polls for up to 30
                // seconds, which does not belong on a runtime worker.
                let brought_up = {
                    let vpn = vpn::for_type(vpn_type, &run_dir);
                    tokio::task::spawn_blocking(move || vpn.bring_up(&tunnel))
                        .await
                        .context("vpn bring-up task")?
                };
                let ip = match brought_up {
                    Ok(ip) => {
                        cleanup.note_tunnel(vpn_type, iface);
                        ip
                    }
                    Err(e) => {
                        error!(
                            profile_id = %p.id,
                            error.cause = %e,
                            "VPN bring-up failed; profile disabled (no bare-IP fallback)",
                        );
                        fail_profile!(p, format!("VPN bring-up failed: {e}"));
                    }
                };

                // The listening port. A static profile binds the operator's
                // `listen_port`; a natpmp profile negotiates an ephemeral one
                // from the tunnel gateway. A startup negotiation failure
                // disables the profile — loud, like a bring-up failure —
                // rather than silently seeding on an unforwarded port.
                // Mid-session renewal failures are the soft keep-seeding path
                // (see port_forward_monitor).
                let effective_port = match p.port_forward() {
                    PortForwardMode::Static => match p.listen_port() {
                        Some(port) => port,
                        None => {
                            // validate_set should have caught this.
                            error!(profile_id = %p.id, "static profile missing listen_port; profile disabled");
                            cleanup.take_down(iface);
                            fail_profile!(p, "static profile has no listen_port".to_string());
                        }
                    },
                    PortForwardMode::Natpmp => {
                        let gw_str = p.port_forward_gateway_or_default();
                        let gateway: IpAddr = match gw_str.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                error!(profile_id = %p.id, gateway = %gw_str, error.cause = %e, "invalid port_forward_gateway; profile disabled");
                                cleanup.take_down(iface);
                                fail_profile!(p, format!("invalid port_forward_gateway: {e}"));
                            }
                        };
                        let req = PortMapRequest {
                            gateway,
                            bind_ip: ip,
                            internal_port: 0,
                            lifetime_secs: crate::port_forward_monitor::LEASE_SECS,
                        };
                        match vpn::NatpmpForwarder::for_startup().map(&req) {
                            Ok(m) => {
                                info!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, forwarded_port = m.port, gateway_epoch = m.epoch, "NAT-PMP port negotiated");
                                forwarded_port = Some(m.port);
                                forwarded_epoch = m.epoch;
                                m.port
                            }
                            Err(e) => {
                                error!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, error.cause = %e, "NAT-PMP negotiation failed at startup; profile disabled (no bare-IP fallback)");
                                cleanup.take_down(iface);
                                fail_profile!(p, format!("NAT-PMP negotiation failed: {e}"));
                            }
                        }
                    }
                };

                settings.listen_interfaces =
                    Some(torrentd_engine::bind_endpoint(ip, effective_port));
                settings.outgoing_interfaces = Some(ip.to_string());
                // Not configurable, by construction: there is no key on a vpn
                // profile that reaches these.
                settings.enable_dht = Some(false);
                settings.enable_lsd = Some(false);
                settings.enable_upnp = Some(false);
                settings.enable_natpmp = Some(false);
                tunnel_ip = Some(ip);
            }
        }

        let built = match session_state {
            Some(state) => libtorrent_safe::Session::with_state(&settings, &state)
                .map(RealEngine::from_session),
            None => libtorrent_safe::Session::new(&settings).map(RealEngine::from_session),
        };
        match built {
            Ok(engine) => {
                info!(
                    profile_id = %p.id,
                    network = if p.is_vpn() { "vpn" } else { "host" },
                    tunnel_ip = tunnel_ip.map(|i| i.to_string()).unwrap_or_default(),
                    dht = p.dht_enabled(),
                    "profile engine up",
                );
                profile_entries.push(ProfileEntry::new(
                    p.clone(),
                    Arc::new(engine),
                    tunnel_ip,
                    forwarded_port,
                    forwarded_epoch,
                ));
            }
            Err(e) => {
                error!(
                    profile_id = %p.id,
                    error.cause = %e,
                    "profile engine construction failed",
                );
                if let Some(iface) = p.vpn_interface() {
                    cleanup.take_down(iface);
                }
                failed_profiles.push(crate::profile_registry::FailedProfile {
                    config: p.clone(),
                    reason: format!("session construction failed: {e}"),
                });
            }
        }
    }
    if profile_entries.is_empty() {
        anyhow::bail!("no profile came up");
    }
    let source_entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)> = profile_entries
        .iter()
        .map(|e| (e.config.id.clone(), e.engine.clone()))
        .collect();
    let profile_registry =
        Arc::new(ProfileRegistry::new(profile_entries).with_failed(failed_profiles));
    let source: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(source_entries));

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
        let tunnels: Vec<String> = profile_registry
            .iter()
            .filter_map(|e| e.config.vpn_interface().map(str::to_string))
            .collect();
        if tunnels.is_empty() {
            // Fail closed, like every other path here. The operator set this
            // flag precisely because they do not want traffic on the bare
            // address; warning and continuing would give them exactly that,
            // with a startup log line as the only trace.
            //
            // `--check-config` reproduces the configured-set half of this
            // (`Config::check_boot_rules`), so a config with no vpn profile
            // fails the systemd pre-flight. This check stays because it reads
            // the profiles that actually came up: a config with one vpn
            // profile whose tunnel failed lands here too, and no config check
            // could have known.
            cfg.check_boot_rules()?;
            anyhow::bail!(
                "network_kill_switch = true and no configured vpn profile came up, so there is \
                 no tunnel to confine the daemon's egress to. Every profile would keep seeding \
                 from the host's own address with no backstop. Fix the tunnel bring-up reported \
                 above, or unset network_kill_switch.",
            );
        }
        let uid = vpn::killswitch::enable(&tunnels)
            .context("install nftables kill switch (network_kill_switch=true)")?;
        kill_switch_active = true;
        cleanup.note_kill_switch();
        metrics.set_gauge("kill_switch_active", 1.0, &[]);
        info!(uid, tunnels = ?tunnels, "network kill switch active");
    }

    /// The two store directories a profile's sessions actually read, from the
    /// one place that rule lives.
    fn dirs_of(cfg: &Config, profile: &ProfileId) -> (std::path::PathBuf, std::path::PathBuf) {
        match cfg.profile.iter().find(|p| &p.id == profile) {
            Some(p) => cfg.effective_store_dirs(p),
            None => (cfg.resume_dir.clone(), cfg.torrent_dir.clone()),
        }
    }

    // How many torrents each profile actually ended up holding, across both
    // scans. Compared against the registry's claim once both have run.
    let mut loaded_by_profile: std::collections::HashMap<ProfileId, usize> =
        std::collections::HashMap::new();
    // Which info-hashes a session accepted. Every registry entry outside this
    // set once both scans have run is held by no session, and is the one kind
    // of entry `DELETE` may clear without a state-map entry to remove.
    let mut loaded: std::collections::HashSet<libtorrent_safe::InfoHash> =
        std::collections::HashSet::new();

    // Resume scan: load every saved resume file per profile. The shim
    // already deduplicates duplicate adds so a future torrent dir scan
    // won't double-add.
    for profile in source.profiles() {
        let Some(profile_cfg) = profile_registry.config(&profile) else {
            continue;
        };
        let entries = resume_store.load_all(&profile).context("scan resume dir")?;
        let count = entries.len();
        let mut missing_metadata = 0usize;
        let mut added_from_resume = 0usize;
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
        for (ih, data) in entries {
            // Cross-check the registry; the spec aborts the profile on
            // mismatch. A resume file under one profile's directory that the
            // registry assigns to another is the operator's to reconcile.
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
            let flags_set = torrentd_engine::resume_flags_set(profile_cfg);
            let flags_clear = TorrentFlags::empty();
            match engine.add_torrent(AddParams::Resume {
                bytes: data.into_inner(),
                torrent,
                save_path: None,
                flags_set,
                flags_clear,
            }) {
                Ok(_) => {
                    added_from_resume += 1;
                    loaded.insert(ih);
                }
                Err(e) => {
                    warn!(profile_id = %profile, infohash = %ih, error.cause = %e, "resume add failed")
                }
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
        loaded_by_profile.insert(profile.clone(), added_from_resume);
    }

    // Torrent-dir scan: add any .torrent whose info-hash has no resume file
    // (resume always wins; startup inventory). After this the torrent
    // dir is not re-scanned — new torrents arrive only via the API.
    let scan_save_path = cfg.default_save_path.to_string_lossy().into_owned();
    for profile in source.profiles() {
        let Some(profile_cfg) = profile_registry.config(&profile) else {
            continue;
        };
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
            let flags = torrentd_engine::seed_flags(profile_cfg);
            match engine.add_torrent(AddParams::File {
                bytes,
                save_path: scan_save_path.clone(),
                flags,
            }) {
                Ok(_) => {
                    added += 1;
                    loaded.insert(ih);
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
        loaded_by_profile
            .entry(profile.clone())
            .and_modify(|n| *n += added)
            .or_insert(added);
    }

    // Reconcile what the registry claims against what the scans actually
    // loaded.
    //
    // The boot check above catches the adjacent mistake — a registry naming an
    // id no `[[profile]]` declares — and refuses well. But an operator who
    // takes its own advice ("give one of the configured profiles the id the
    // registry names") and stops there boots successfully with every file
    // still at the old un-partitioned root: `resume scan complete
    // torrent_count=0` at `info`, `/healthz` 200, and `GET /api/profiles`
    // reporting N torrents that no session holds, because it derives
    // `torrent_count` from the registry rather than from loaded state. A
    // silent total outage reported healthy is the failure mode this whole
    // section exists to prevent; nothing was comparing the two numbers.
    //
    // A warning rather than a refusal: an operator may legitimately have
    // deleted payload out from under a stale assignment, and the remedy — an
    // override pointing at the old directory — is theirs to choose. The
    // directory actually searched is named, because that is the value the
    // remedy sets.
    for profile in source.profiles() {
        let claimed = registry.for_profile(&profile).len();
        let loaded = loaded_by_profile.get(&profile).copied().unwrap_or(0);
        if claimed > loaded {
            warn!(
                profile_id = %profile,
                registry_torrents = claimed,
                loaded_torrents = loaded,
                resume_dir = %dirs_of(&cfg, &profile).0.display(),
                torrent_dir = %dirs_of(&cfg, &profile).1.display(),
                // Both files, as the refusal above names both. On the
                // migration boot `source_path()` is the pre-rename
                // `slot_assignments.json` — the file `docs/running.md` tells
                // the operator explicitly not to edit — so naming it alone
                // pointed at the wrong one. Its own justification for being
                // the name to quote, that the current file is "by
                // construction not on disk", stopped holding when the
                // migration began writing that file unconditionally.
                registry_path = %cfg.registry_path().display(),
                registry_read_from = %registry.source_path().display(),
                "the assignment registry claims more torrents for this profile than the scans \
                 loaded; the files are probably still at the pre-profiles root — point this \
                 profile's resume_dir and torrent_dir at it, or move the files into the \
                 directories named here",
            );
            metrics.set_gauge(
                "profile_unloaded_registry_torrents",
                (claimed - loaded) as f64,
                &[("profile_id", profile.as_str())],
            );
        } else {
            metrics.set_gauge(
                "profile_unloaded_registry_torrents",
                0.0,
                &[("profile_id", profile.as_str())],
            );
        }
    }

    let unloaded_at_boot: std::collections::HashSet<libtorrent_safe::InfoHash> = registry
        .entries()
        .into_iter()
        .map(|(ih, _)| ih)
        .filter(|ih| !loaded.contains(ih))
        .collect();

    // Subscribe now, not when the HTTP server starts: a broadcast sent with no
    // live receiver is discarded, so a SIGTERM during the resume scan would
    // otherwise leave the daemon running with nothing left to stop it.
    let shutdown_rx = shutdown_tx.subscribe();

    // Managed pool. Opened before the alert loop so a bad index path fails
    // startup rather than surfacing as a 500 on the first API call.
    let pool = crate::pool_service::PoolService::open(&cfg).context("open pool index")?;

    // Two artefacts persist a torrent→profile mapping, and nothing reconciled
    // them: `profile_assignments.json`, which the resume scan above writes and
    // every load is gated on, and the pool index's `torrent.profile` column,
    // which `pool scan` writes and an operator may never run. The registry is
    // the authority and the column is a cache of it — said so in both module
    // docs now — but where the two disagree, the disagreement was previously
    // resolved by whichever code path a reader happened to be in. Name both
    // values instead. Read-only: rewriting an operator's index during boot is
    // not this check's business.
    if let Some(pool) = pool.as_ref() {
        let stale = pool.with_store(|st| {
            let mut out: Vec<(String, String, String)> = Vec::new();
            for t in st.torrents().unwrap_or_default() {
                let Some(indexed) = t.profile.as_deref() else {
                    continue;
                };
                let Some(ih) = libtorrent_safe::InfoHash::from_hex(&t.infohash) else {
                    continue;
                };
                if let Some(owner) = registry.lookup(&ih) {
                    if owner.as_str() != indexed {
                        out.push((
                            t.infohash.clone(),
                            owner.as_str().to_string(),
                            indexed.to_string(),
                        ));
                    }
                }
            }
            out
        });
        for (infohash, registry_profile, index_profile) in &stale {
            warn!(
                infohash = %infohash,
                registry_profile = %registry_profile,
                index_profile = %index_profile,
                "the pool index and the assignment registry disagree about who owns this \
                 torrent; the registry is authoritative and the index is a cache of it, so \
                 `torrentd pool scan` will bring the index back into line",
            );
        }
        metrics.set_gauge("pool_index_profile_disagreements", stale.len() as f64, &[]);
    }

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
    // A listen failure is fatal only where it stops the daemon listening at
    // all: with a second session still up, the others keep serving and the
    // failure is reported per profile rather than taking everything down.
    //
    // Keyed on the sessions that actually came up, not on `cfg.profile.len()`.
    // A daemon configured with two profiles but reduced to one by a bring-up
    // failure has exactly the same exposure as one configured with one — and
    // keying on the configured count treated that survivor's listen failure as
    // non-fatal, leaving a daemon that is up, healthy and listening on nothing.
    .fatal_listen_failure(profile_registry.iter().count() == 1)
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
                .resolve(id)
                .active()
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
        resume: resume_store,
        shutdown_tx,
        shutdown_rx,
        reload_rx,
        reload_tx: reload_tx_for_api,
        metrics,
        pool,
        registry,
        profile_registry,
        kill_switch_active,
        log_handle,
        alert_loop,
        unloaded_at_boot,
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
            resume,
            shutdown_tx,
            shutdown_rx,
            reload_rx,
            reload_tx,
            metrics,
            pool,
            registry,
            profile_registry,
            kill_switch_active,
            log_handle,
            alert_loop,
            unloaded_at_boot,
        } = self;

        // VPN health monitor (multi-profile only). Spawned before AppState
        // consumes the registry/state/metrics.
        {
            let profiles = profile_registry.clone();
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
            resume,
            metrics: metrics.clone(),
            auth: cfg.auth.clone().map(crate::auth::Auth::new),
            pool,
            alert_heartbeat: alert_loop.heartbeat(),
            default_save_path: cfg.default_save_path.clone(),
            torrent_dir: cfg.torrent_dir.clone(),
            reload_tx: Some(reload_tx.clone()),
            unloaded_at_boot: Arc::new(parking_lot::Mutex::new(unloaded_at_boot)),
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
            profile_registry.clone(),
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

        // Persist DHT routing tables for the next start. Only a host profile
        // with DHT enabled has one; a tunnelled profile runs with DHT off by
        // construction and has nothing to save. The sessions are still alive
        // here — they are dropped when `source` goes out of scope.
        for p in cfg.profile.iter().filter(|p| p.dht_enabled()) {
            let Some(engine) = source.engine_for(&p.id) else {
                continue;
            };
            match engine.session_state() {
                Ok(bytes) if !bytes.is_empty() => {
                    match save_session_state(&cfg.session_state_path(&p.id), &bytes) {
                        Ok(()) => {
                            info!(profile_id = %p.id, bytes = bytes.len(), "session state saved")
                        }
                        Err(e) => {
                            warn!(profile_id = %p.id, error.cause = %e, "failed to save session state")
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => warn!(profile_id = %p.id, error.cause = %e, "session_state() failed"),
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
        {
            let run_dir = cfg.state_dir();
            for entry in profile_registry.iter() {
                // A host profile has no tunnel to take down.
                let (Some(vpn_type), Some(iface)) =
                    (entry.config.vpn_type(), entry.config.vpn_interface())
                else {
                    continue;
                };
                crate::vpn::for_type(vpn_type, &run_dir).bring_down(iface);
                info!(
                    profile_id = %entry.config.id,
                    vpn_iface = %iface,
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
