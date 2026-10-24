//! Startup orchestrator: build the engine(s), wire the alert loop, bind
//! the HTTP server, install signal handlers, and run until shutdown.
//!
//! There is one path, not two: every profile becomes a session, and the set
//! of them becomes one `Arc<dyn AlertSource>` that the rest of the daemon
//! consumes uniformly. A deployment with a single profile is that set with
//! n = 1.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use torrentd_engine::batch_writer::write_atomic;
use torrentd_engine::AlertLoopBuilder;
use torrentd_engine::AlertSource;
use torrentd_engine::FsResumeStore;
use torrentd_engine::FsTorrentStore;
use torrentd_engine::MetricsSink;
use torrentd_engine::PortForwardMode;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileSource;
use torrentd_engine::ResumeStore;
use torrentd_engine::ShutdownReason;
use torrentd_engine::StateMap;
use torrentd_engine::SystemClock;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentStore;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::config::Config;
use crate::http;
use crate::instance_lock::InstanceLock;
use crate::metrics_sink::PromSink;
use crate::profile_registry::ProfileRegistry;
use crate::profile_registry::ProfileStatus;
use crate::registry::AssignmentRegistry;
use crate::reload;
use crate::sd_notify;
use crate::signals::SignalChannels;
use crate::signals::{self};
use crate::vpn;

mod cleanup;
mod http_stage;
mod limits;
mod listen_check;
mod profiles;
mod refusal;
mod scan;
mod scan_fence;
mod shutdown_report;
mod tasks;
mod teardown;
#[cfg(test)]
mod test_support;

use cleanup::BootCleanup;
use http_stage::announce_ready;
use http_stage::bind_api_listener;
#[cfg(test)]
pub(crate) use http_stage::http_server;
use http_stage::run_http_stage;
use http_stage::serve_until_shutdown;
use http_stage::unauthenticated_posture;
use http_stage::ApiListener;
use http_stage::HTTP_DRAIN_TIMEOUT;
use http_stage::HTTP_HEADER_READ_TIMEOUT;
use http_stage::HTTP_MAX_CONNECTIONS;
pub(crate) use limits::descriptors_needed;
pub(crate) use limits::nofile_soft_limit;
use limits::warn_if_descriptors_are_short;
use listen_check::check_listen_devices;
use listen_check::listen_device_check;
use listen_check::CheckedHold;
use listen_check::LISTEN_CHECK_BOUND;
use profiles::boot_engine;
use profiles::build_profiles;
use refusal::acquire_table_lock;
pub use refusal::is_config_refusal;
use refusal::kill_switch_enable_failure;
pub use refusal::kill_switch_uid_refusal;
use refusal::refused;
use scan::resume_scan;
use scan::torrent_dir_scan;
use scan::ScanInputs;
use scan::ScanTally;
use scan_fence::ScanFence;
use shutdown_report::export_shutdown_report;
use shutdown_report::finish_kill_switch_removal;
use shutdown_report::remove_stale_kill_switch;
use shutdown_report::take_shutdown_report;
use shutdown_report::write_shutdown_report;
use shutdown_report::ShutdownReport;
use tasks::spawn_supervised;
use teardown::stop_fencing;
use teardown::teardown_network;
use teardown::wait_for_pool_work;
use teardown::POOL_WORK_DRAIN;
use teardown::TEARDOWN_ALLOWANCE;

/// Take both shutdown receivers `boot` needs — the one boot's own loops
/// watch, and the one that outlives boot — together, and **before the signal
/// listener is installed**: a broadcast receiver sees only sends after it
/// subscribes, and a send with no receiver is lost outright, so a SIGTERM
/// during boot would otherwise never reach the running daemon.
fn boot_shutdown_receivers(
    tx: &broadcast::Sender<ShutdownReason>,
) -> (
    broadcast::Receiver<ShutdownReason>,
    broadcast::Receiver<ShutdownReason>,
) {
    (tx.subscribe(), tx.subscribe())
}

/// How long boot `EXTEND_TIMEOUT_USEC` keeps a boot alive with no progress
/// reported. The boot advances its [`sd_notify::Progress`] as the scans get
/// through their entries and at each stage between them, so a boot still
/// loading a large pool is extended however long it runs; one that has gone
/// this long without getting further is treated as wedged, and systemd's own
/// start timeout fires from the last extension.
///
/// Fifteen minutes, the whole boot's budget before progress was tracked.
/// The scans advance it at each directory listing and every
/// [`SCAN_SHUTDOWN_CHECK_EVERY`](scan::SCAN_SHUTDOWN_CHECK_EVERY) entries, so
/// the longest stretch with no advance is one profile's tunnel bring-up (up
/// to 30 s), the listen device
/// check (up to [`LISTEN_CHECK_BOUND`]), or a listing of a 100K-file
/// directory on a cold disk, which can take minutes. The extender runs only
/// when the runtime gets to it, which the scans allow between batches
/// ([`between_scan_batches`](scan::between_scan_batches)).
const BOOT_STALL_BOUND: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// The resume store's batch-writer error hook: count the failure as the
/// handler used to, and mark the torrent's file stale. The handler has
/// already cleared `needs_save_resume` by then, and libtorrent its modified
/// bit, so without the mark no `ONLY_IF_MODIFIED` save, the shutdown drain's
/// included, would ever rewrite it.
fn resume_write_error_hook(
    metrics: Arc<dyn MetricsSink>,
    state: Arc<StateMap>,
) -> torrentd_engine::WriteErrorHook {
    Arc::new(
        move |profile: &ProfileId, ih: &libtorrent_safe::InfoHash, _: &std::io::Error| {
            metrics.inc_counter(
                "resume_write_errors_total",
                &[("profile_id", profile.as_str())],
            );
            state.note_resume_write_failed(ih);
        },
    )
}

/// The torrent store's batch-writer error hook. Its one batched writer is the
/// magnet-metadata handler, so a failure counts under that source.
fn torrent_write_error_hook(metrics: Arc<dyn MetricsSink>) -> torrentd_engine::WriteErrorHook {
    Arc::new(
        move |profile: &ProfileId, _: &libtorrent_safe::InfoHash, _: &std::io::Error| {
            metrics.inc_counter(
                "torrent_file_persist_errors_total",
                &[("profile_id", profile.as_str()), ("source", "metadata")],
            );
        },
    )
}

/// Whether a shutdown has been signalled on `rx`. A lagged or closed channel
/// counts: either means signals went past this receiver unread.
fn shutdown_requested(rx: &mut broadcast::Receiver<ShutdownReason>) -> bool {
    !matches!(rx.try_recv(), Err(broadcast::error::TryRecvError::Empty))
}

pub struct DaemonHandle {
    cfg: Config,
    /// Where a VPN manager keeps state a *later* process has to find, as
    /// `boot` resolved it, so teardown finds what bring-up wrote.
    run_dir: std::path::PathBuf,
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
    /// Lets `POST /v1/config/reload` ask for the same thing SIGHUP asks for.
    reload_tx: mpsc::Sender<()>,
    metrics: Arc<PromSink>,
    pool: Option<Arc<crate::pool_service::PoolService>>,
    /// The daemon's bound on hash checks, the pool's queue where there is one.
    checks: Arc<crate::pool_service::VerifyQueue>,
    registry: Arc<AssignmentRegistry>,
    profile_registry: Arc<ProfileRegistry>,
    /// The kill-switch watch's fence, where the nftables kill switch was
    /// installed: graceful shutdown tears the table down, and the API's adds
    /// record what they pause with the fence. `boot` started its watch.
    kill_switch: Option<Arc<crate::fence::KillSwitchFence>>,
    /// Stops the VPN monitor and the kill-switch watch, which `boot`
    /// started: fired just before the teardown closes the sessions, so both
    /// fence through the drain before it.
    fencing: crate::fence::FencingStop,
    /// The kill-switch watch, aborted after `fencing` in case it outran the
    /// stop's bound: left running, it would install the table again once
    /// the teardown removes it.
    kill_switch_watch: Option<tokio::task::AbortHandle>,
    log_handle: crate::tracing_init::LogReloadHandle,
    alert_loop: torrentd_engine::AlertLoopHandle,
    /// Registry entries no startup scan loaded; see `AppState::unloaded_at_boot`.
    unloaded_at_boot: std::collections::HashSet<libtorrent_safe::InfoHash>,
    /// Registry entries no startup scan loaded because they were waiting for
    /// verification, and that the verify queue holds again. Not in
    /// `unloaded_at_boot`: the queue adds them.
    requeued_at_boot: std::collections::HashSet<libtorrent_safe::InfoHash>,
    /// Held until `run_until_signal` returns, after the shutdown has taken
    /// down the kill switch and the tunnels: released any earlier, a new start
    /// could install its own and have this daemon's teardown remove them.
    instance_lock: InstanceLock,
    /// Held as long as `instance_lock`, for the same reason: a daemon of this
    /// uid started any earlier would install, or remove, the table this
    /// daemon's teardown is still to remove.
    table_lock: crate::vpn::killswitch::TableLock,
}

pub async fn boot(
    cfg: Config,
    config_path: std::path::PathBuf,
    log_handle: crate::tracing_init::LogReloadHandle,
) -> anyhow::Result<DaemonHandle> {
    info!("starting torrentd");
    // `cfg` came from `Config::load`, whose validation ran
    // `Config::check_boot_rules` before any tunnel could be raised.
    // Where a VPN manager keeps state a *later* process has to find — see
    // `vpn::for_type`. Resolved once here so bring-up and teardown agree.
    let run_dir = cfg.state_dir();

    // One daemon per state directory, decided before anything with an effect
    // outside this process. Declared before `cleanup`, so a failed boot's
    // teardown runs while the lock is still held.
    let instance_lock = {
        let path = cfg.instance_lock_path();
        tokio::task::spawn_blocking(move || InstanceLock::acquire(&path))
            .await
            .context("single-instance lock")??
    };
    // One daemon per uid in this network namespace, which is the kill
    // switch's table's scope: every boot touches that table, replacing it
    // with the switch on and removing it as stale with the switch off. Taken
    // after the state directory's lock, so a second start on the same state
    // directory is told that first.
    let table_lock = tokio::task::spawn_blocking(acquire_table_lock)
        .await
        .context("kill-switch table lock")??;

    // Signals, installed before anything that can block or fail, so a
    // SIGTERM during a tunnel bring-up is handled rather than fatal.
    let channels = SignalChannels::new();
    let (reload_tx, reload_rx) = mpsc::channel::<()>(8);
    // The HTTP surface asks for a reload the same way SIGHUP does, through
    // this channel, so both paths converge on one implementation.
    let reload_tx_for_api = reload_tx.clone();
    let channels = SignalChannels::from_parts(channels.shutdown_tx, reload_tx);
    let shutdown_tx = channels.shutdown_tx.clone();
    // Before the listener that can send to them: see `boot_shutdown_receivers`.
    let (mut boot_shutdown, shutdown_rx) = boot_shutdown_receivers(&shutdown_tx);
    signals::run(channels.clone()).await;

    // Tunnel bring-up (up to 30 s a profile) and the resume and torrent-dir
    // scans (minutes at 100K torrents) can outrun any fixed
    // `TimeoutStartSec`. Ask systemd for more time while boot runs — dropped,
    // and so stopped, when `boot` returns — for as long as the boot keeps
    // advancing `boot_progress`, so a wedged boot still meets the timeout
    // `BOOT_STALL_BOUND` after it stops getting further.
    let boot_progress = sd_notify::Progress::new();
    let _extend_start =
        sd_notify::TimeoutExtender::start_while_progressing(BOOT_STALL_BOUND, &boot_progress);

    warn_if_descriptors_are_short(&cfg);
    {
        let profiles = cfg.profile.clone();
        tokio::task::spawn_blocking(move || vpn::warn_if_exits_are_shared(&profiles))
            .await
            .context("shared WireGuard endpoint check")?;
    }

    // Discard raised-interface records whose interface is gone (removed by
    // hand, say) before any bring-up can consult one.
    {
        let sweep_dir = run_dir.clone();
        tokio::task::spawn_blocking(move || crate::vpn::sweep_raised_records(&sweep_dir))
            .await
            .context("raised-interface record sweep")?;
    }

    // Every tunnel interface this config names, of either type. Network state
    // an earlier run left under any other name is a retired profile's, and
    // nothing but the boot below would ever take it down.
    let configured: Arc<HashSet<String>> = Arc::new(
        cfg.profile
            .iter()
            .filter_map(|p| p.vpn_interface().map(str::to_string))
            .collect(),
    );

    // A WireGuard link an earlier run raised for a profile this config no
    // longer declares: nothing would adopt it or ever take it down, and its
    // per-source rules stay in the routing policy with it. A configured
    // profile's link is left to adoption and bring-up, as before.
    {
        let state_dir = run_dir.clone();
        let configured = Arc::clone(&configured);
        let released = tokio::task::spawn_blocking(move || {
            crate::vpn::release_recorded_wireguard(&state_dir, |iface| configured.contains(iface))
        })
        .await
        .context("unconfigured WireGuard link teardown")?;
        if let Err(e) = released {
            error!(
                path = %run_dir.display(),
                error.cause = %e,
                "could not read the state directory for WireGuard links raised by an earlier \
                 run; a link no configured profile names is left standing",
            );
        }
    }

    // The same for OpenVPN: an `openvpn-<iface>.pid` or `.table` record whose
    // interface this config no longer names gets the teardown `bring_down`
    // runs, so a retired profile's openvpn, its source-address rules and its
    // records do not outlive an unclean exit. A configured profile's records
    // are its own bring-up's to consume, as before.
    {
        let state_dir = run_dir.clone();
        let configured = Arc::clone(&configured);
        let released = tokio::task::spawn_blocking(move || {
            vpn::OpenvpnManager::new(state_dir).release_recorded(|iface| configured.contains(iface))
        })
        .await
        .context("unconfigured OpenVPN profile teardown")?;
        if let Err(e) = released {
            error!(
                path = %run_dir.display(),
                error.cause = %e,
                "could not read the state directory for OpenVPN records an earlier run left; \
                 an interface no configured profile names keeps its openvpn, rules and records",
            );
        }
    }

    // A kill-switch table an unclean exit left behind keeps dropping this
    // uid's non-tunnel egress, and a boot with the kill switch on replaces it
    // in the same transaction as its install. With it off nothing else would
    // remove it, so it goes here, before any session opens a socket.
    if !cfg.network_kill_switch {
        tokio::task::spawn_blocking(|| {
            remove_stale_kill_switch(
                crate::vpn::killswitch::nft_available(),
                &crate::vpn::killswitch::own_table_name(),
                crate::vpn::killswitch::remove_table,
            )
        })
        .await
        .context("stale kill-switch table check")?;
    }

    let mut cleanup = BootCleanup::new(run_dir.clone());

    // Metrics sink — created before the stores, whose batched writers count
    // their failures in it, and the startup scans, which record registry
    // rejections (profile_assignment_registry_errors_total).
    let metrics = Arc::new(PromSink::new());

    // Empty until the alert loop sees each torrent added. Created before the
    // stores, because a resume write that fails on the batch writer has to
    // mark its torrent for a fresh save; and before the port-forward monitor
    // below, which reannounces whatever it holds by the time a port changes.
    let state = Arc::new(StateMap::new());

    // Resume store — partitioned by profile id under `resume_dir`, or at a
    // profile's own directory; the alert loop's writes are batched, and a
    // failed one is counted and marks its torrent for a fresh save.
    let resume_store: Arc<dyn ResumeStore> = Arc::new(
        cfg.profile
            .iter()
            .fold(
                FsResumeStore::new(cfg.resume_dir.clone()),
                |st, profile| match &profile.resume_dir {
                    Some(dir) => st.with_profile_dir(profile.id.clone(), dir.clone()),
                    None => st,
                },
            )
            .with_batched_writes(Some(resume_write_error_hook(
                metrics.clone(),
                Arc::clone(&state),
            ))),
    );

    // Torrent store — same per-profile partitioning as the resume store; holds
    // the raw .torrent files for the startup inventory scan, magnet-metadata
    // persistence, and removal cleanup. Its one batched writer is the
    // magnet-metadata handler, whose failures it counts under that source.
    let torrent_store: Arc<dyn TorrentStore> = Arc::new(
        cfg.profile
            .iter()
            .fold(
                FsTorrentStore::new(cfg.torrent_dir.clone()),
                |st, profile| match &profile.torrent_dir {
                    Some(dir) => st.with_profile_dir(profile.id.clone(), dir.clone()),
                    None => st,
                },
            )
            .with_batched_writes(Some(torrent_write_error_hook(metrics.clone()))),
    );

    // Assignment registry.
    let registry = Arc::new(
        AssignmentRegistry::open(cfg.registry_path(), cfg.registry_import())
            .context("load assignment registry")?,
    );

    // Refuse a registry naming a profile id no `[[profile]]` configures (a
    // pre-profiles `default`, say): its torrents would be stranded, unloadable
    // and un-addable, behind a healthy `/healthz`. Checked against the
    // configured set, not the profiles that came up.
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
            // Name the file the entries were *read from* as well as the
            // database. On the path this fires on — an imported registry,
            // which is what produces ids like `default` — that is the JSON
            // file, now under its `.imported` name, and editing it changes
            // nothing: the database is what the daemon reads from here on.
            // The database is not a file to open in an editor, so the remedy
            // is the exact statement that clears those rows.
            let source = registry.source_path().display().to_string();
            let current = registry.path().display().to_string();
            let ids = unknown
                .keys()
                .map(|id| format!("'{id}'"))
                .collect::<Vec<_>>()
                .join(", ");
            let delete = format!(
                "sqlite3 {} \"DELETE FROM assignment WHERE profile_id IN ({ids})\"",
                sh_single_quote(&current)
            );
            let where_to_edit = if source == current {
                format!("remove those entries from {current} (`{delete}`)")
            } else {
                format!(
                    "remove those entries from {current} (`{delete}`; they were imported from \
                     {source}, which is kept for a rollback; editing that file will not help, \
                     because {current} is what the daemon reads from here on)"
                )
            };
            // Refused as configuration: no restart changes what the file and
            // the registry say.
            return Err(refused(anyhow::anyhow!(
                "the assignment registry at {source} assigns torrents to profiles that no \
                 [[profile]] table declares: {named}. Configured profiles: {known}. Those \
                 torrents cannot be loaded, re-added or deleted while the mismatch stands. \
                 Either give one of the configured profiles the id the registry names — the \
                 upgrade path from the pre-profiles layout, where every entry says `default` — \
                 or {where_to_edit} and re-add the torrents.",
            )));
        }
    }

    // The operator's online/offline choices, read before any session exists:
    // a profile left offline has its session paused as it is built, before
    // the scans below give it a torrent.
    let desired_states = {
        let path = cfg.profile_state_path();
        let (states, loaded) =
            tokio::task::spawn_blocking(move || crate::profile_state::DesiredStates::load(path))
                .await
                .context("read the profiles' online/offline states")?;
        if let crate::profile_state::Loaded::Unreadable(why) = &loaded {
            error!(
                path = %cfg.profile_state_path().display(),
                error.cause = %why,
                "the profiles' online/offline states could not be read; every profile is held \
                 offline as if by offline-all, until POST /v1/profiles/online-all rewrites the \
                 file",
            );
        }
        states
    };
    // The torrents a paced set-online paused and had not resumed when the
    // daemon stopped: the resume scan loads them unpaused.
    let paced_holds = {
        let path = cfg
            .profile_state_path()
            .with_file_name(crate::profile_state::PACED_HOLDS_FILE);
        let shown = path.display().to_string();
        let (holds, unreadable) =
            tokio::task::spawn_blocking(move || crate::profile_state::PacedHolds::load(path))
                .await
                .context("read the record of what paced set-onlines hold")?;
        if let Some(why) = unreadable {
            error!(
                path = %shown,
                error.cause = %why,
                "the record of the torrents a paced set-online paused could not be read; any it \
                 named come back paused, and POST /v1/profiles/{{id}}/resume-all resumes them",
            );
        }
        holds
    };

    // One libtorrent session per configured profile. There is no other shape:
    // a deployment with one profile is this with n = 1, not a mode of its own.
    // The NAT-PMP client is stateless — each `map` opens a fresh socket — so
    // one serves every profile's startup negotiation.
    let (profile_entries, failed_profiles) = build_profiles(
        &cfg,
        &mut cleanup,
        &vpn::NatpmpForwarder::for_startup(),
        &*metrics,
        &mut boot_shutdown,
        &desired_states.current(),
        boot_engine,
    )
    .await?;
    boot_progress.advance();
    // Every alert-referenced series exists from here, before the alert loop
    // or any request can move one. A profile that failed is seeded too: its
    // engine counters stay at zero, and `profile_boot_failed` says why.
    {
        let configured: Vec<&str> = cfg.profile.iter().map(|p| p.id.as_str()).collect();
        metrics.seed(&configured);
        for p in &cfg.profile {
            let failed = failed_profiles.iter().any(|f| f.config.id == p.id);
            metrics.set_gauge(
                "profile_boot_failed",
                if failed { 1.0 } else { 0.0 },
                &[("profile_id", p.id.as_str())],
            );
        }
        export_shutdown_report(&metrics, &take_shutdown_report(&run_dir));
    }
    // The profile loop's own check is only re-evaluated at the top of the
    // *next* iteration, so the last profile's 30-second bring-up had no check
    // against it at all — and a one-profile deployment had none anywhere. Ask
    // once more before boot commits to running, while the drop guard still
    // owns every tunnel this boot raised. A lagged or closed receiver counts
    // as a shutdown, as at every other boot check.
    if shutdown_requested(&mut boot_shutdown) {
        anyhow::bail!("shutdown requested during profile bring-up");
    }
    if profile_entries.is_empty() {
        anyhow::bail!("no profile came up");
    }
    let source_entries: Vec<(ProfileId, Arc<dyn TorrentEngine>)> = profile_entries
        .iter()
        .map(|e| (e.config.id.clone(), e.engine.clone()))
        .collect();
    // From here on something outside `boot` (the port-forward monitor below)
    // holds the sessions, so a failed boot has to close them itself before
    // its tunnels go.
    cleanup.note_sessions(source_entries.iter().map(|(_, e)| Arc::clone(e)));
    let profile_registry = Arc::new(
        ProfileRegistry::new(profile_entries)
            .with_failed(failed_profiles)
            .with_states(desired_states)
            .with_holds(paced_holds),
    );
    profile_registry.export_offline(&*metrics);
    // Kept as itself too: the scans below hold each session's alerts on it
    // between batches (`CheckedHold::hold`).
    let profile_source = Arc::new(ProfileSource::new(source_entries));
    let source: Arc<dyn AlertSource> = profile_source.clone();
    // Port-forward renewal monitor: keeps NAT-PMP leases alive, rebinds the
    // session if the forwarded port changes, and reannounces. Started as soon
    // as the profiles are built, so a 60 s lease is not left unrenewed through
    // the scans, and supervised only where a profile negotiates a port. It
    // confirms a rebind against the listen outcomes the alert loop publishes
    // into `listen_events`.
    let listen_events = Arc::new(torrentd_engine::port_forward::ListenEvents::new());
    let pf = crate::port_forward_monitor::run(
        profile_registry.clone(),
        state.clone(),
        metrics.clone(),
        listen_events.clone(),
        shutdown_tx.subscribe(),
    );
    if profile_registry
        .iter()
        .any(|e| e.config.port_forward() == PortForwardMode::Natpmp)
    {
        spawn_supervised("port_forward_monitor", metrics.clone(), pf);
    } else {
        tokio::spawn(pf);
    }
    // VPN health monitor, started here for the same reason: the scans below
    // run for minutes on a large pool, and a tunnel that drops during them
    // has to be fenced then, not at the first poll after boot. Its fence
    // pauses what the state map holds, which the scans fill only once both
    // have run, so the scans pause what they add to a fenced profile
    // themselves (`ScanFence`).
    //
    // It and the kill-switch watch stop on `fencing`, not on the shutdown
    // broadcast: the shutdown fires it just before it closes the sessions,
    // so both keep fencing through the drain while the sessions still seed.
    let fencing = crate::fence::FencingStop::new();
    spawn_supervised(
        "vpn_monitor",
        metrics.clone(),
        crate::vpn_monitor::run(
            profile_registry.clone(),
            state.clone(),
            metrics.clone(),
            std::time::Duration::from_secs(cfg.vpn_handshake_max_age_secs),
            fencing.subscribe(),
        ),
    );

    // Network-layer kill switch (defence-in-depth; multi-profile + opt-in).
    // Installed once, after every profile's tunnel is up, so the ruleset covers all
    // tunnel interfaces, each accepted only from the address its own link holds
    // — the one that profile's sessions were just bound to. Fail-closed: if the operator asked for it and it can't
    // be installed, abort rather than seed without the backstop.
    //
    // That leaves a window: each profile's bring-up can take up to 30 s, so
    // the sessions built first exist, with their listen sockets open, before
    // the backstop does. They hold no torrents until the scans below, which
    // run only after it is installed, so nothing is announced or seeded in
    // that window. Installing it before the sessions would need every
    // tunnel's transport port, which is known only once its link is up.
    let mut kill_switch = None;
    let mut kill_switch_watch = None;
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
            // Fail closed. A config with no vpn profile at all was refused by
            // `Config::check_boot_rules` as it loaded; this is the case no
            // config check can see, where every vpn profile's tunnel failed.
            anyhow::bail!(
                "network_kill_switch = true and no configured vpn profile came up, so there is \
                 no tunnel to confine the daemon's egress to. Every profile would keep seeding \
                 from the host's own address with no backstop. Fix the tunnel bring-up reported \
                 above, or unset network_kill_switch.",
            );
        }
        let installed = vpn::killswitch::enable(&tunnels).map_err(kill_switch_enable_failure)?;
        cleanup.note_kill_switch();
        // Read back as the watch will read it. A table this host's nft lists
        // in a shape the check does not read as the one rendered would read
        // as drift at the watch's first check, and fence every profile for
        // the rest of the run; it fails the boot here instead, where it says
        // why, and the guard above removes the table.
        match vpn::killswitch::verify(&installed)
            .context("verify the installed nftables kill switch (network_kill_switch=true)")?
        {
            vpn::killswitch::Verdict::Intact => {}
            verdict => anyhow::bail!(
                "the nftables kill switch was installed and does not read back as the ruleset \
                 rendered ({verdict:?}), so its runtime check could not tell it from a flushed \
                 one. Report this with `nft -j list table inet {}`, or unset \
                 network_kill_switch.",
                installed.table_name(),
            ),
        }
        metrics.set_gauge("kill_switch_active", 1.0, &[]);
        info!(uid = installed.uid, tunnels = ?tunnels, "network kill switch active");
        // The watch, started here for the reason the monitors above are: the
        // scans below run for minutes on a large pool, and a firewall reload
        // that flushes the ruleset during them has to fence every vpn profile
        // then, not at the first check after boot. Its fence walks the state
        // map, which the scans fill only once both have run, so the scans
        // record what they
        // pause under it themselves (`ScanFence`). A failed boot stops it
        // before its guard removes the table, which it would otherwise
        // install again.
        let fence = Arc::new(crate::fence::KillSwitchFence::new(
            profile_registry.clone(),
            state.clone(),
            metrics.clone(),
            crate::vpn_monitor::host_prober(),
        ));
        let watch = spawn_supervised(
            "kill_switch_watch",
            metrics.clone(),
            vpn::killswitch::watch(
                installed,
                fence.clone(),
                metrics.clone(),
                fencing.subscribe(),
            ),
        );
        cleanup.note_kill_switch_watch(watch.clone());
        kill_switch_watch = Some(watch);
        kill_switch = Some(fence);
    }

    /// The two store directories a profile's sessions actually read, from the
    /// one place that rule lives.
    fn dirs_of(cfg: &Config, profile: &ProfileId) -> (std::path::PathBuf, std::path::PathBuf) {
        match cfg.profile.iter().find(|p| &p.id == profile) {
            Some(p) => cfg.effective_store_dirs(p),
            None => (cfg.resume_dir.clone(), cfg.torrent_dir.clone()),
        }
    }

    // What the scans add, so a profile the VPN monitor or the kill-switch
    // watch fences mid-scan has it paused.
    let mut scan_fence = ScanFence::new(kill_switch.clone());

    // Managed pool. Opened before the alert loop so a bad index path fails
    // startup rather than surfacing as a 500 on the first API call, and
    // before the resume scan, which falls back to its library for a
    // torrent's `.torrent`.
    let pool = crate::pool_service::PoolService::open(&cfg).context("open pool index")?;
    if let Some(pool) = pool.as_ref() {
        pool.set_metrics(metrics.clone());
        pool.set_state(Arc::clone(&state));
        pool.set_source(Arc::clone(&source));
        pool.set_registry(Arc::clone(&registry));
        pool.set_torrent_store(Arc::clone(&torrent_store));
        if let Some(fence) = kill_switch.as_ref() {
            pool.set_kill_switch(Arc::clone(fence));
        }
    }
    // The daemon's one bound on hash checks, and the record of the
    // `.torrent`s it held paused for a slot when the daemon stopped: the
    // scans load each paused, and it queues them again.
    let checks = crate::pool_service::VerifyQueue::for_daemon(pool.as_deref());
    checks.set_metrics(metrics.clone());
    {
        let path = cfg
            .profile_state_path()
            .with_file_name(crate::pool_service::CHECK_HOLDS_FILE);
        let shown = path.display().to_string();
        let (holds, unreadable) =
            tokio::task::spawn_blocking(move || crate::profile_state::PacedHolds::load(path))
                .await
                .context("read the record of the .torrent adds held for a check slot")?;
        if let Some(why) = unreadable {
            error!(
                path = %shown,
                error.cause = %why,
                "the record of the .torrent adds held for a check slot could not be read; any it \
                 named come back paused, and POST /v1/torrents/{{infohash}}/resume resumes them",
            );
        }
        checks.set_holds(holds);
    }

    // The alert loop checks each listen socket's device as it comes up, and
    // it starts only after the scans: a vpn session's sockets are checked
    // here instead, before the scans give any session a torrent to announce,
    // and by every hold the scans take through `checked_hold` after it.
    let checked_hold = CheckedHold::new(
        &profile_source,
        listen_device_check(profile_registry.clone()),
    );
    check_listen_devices(
        &profile_registry,
        &checked_hold,
        LISTEN_CHECK_BOUND,
        &mut boot_shutdown,
    )
    .await?;
    boot_progress.advance();

    // The two boot scans, resume files first: a torrent with resume data is
    // loaded from it, and the torrent-dir scan adds only what no resume file
    // covered.
    let mut tally = ScanTally::default();
    {
        let inputs = ScanInputs {
            cfg: &cfg,
            source: &*source,
            profile_registry: &profile_registry,
            resume_store: &*resume_store,
            torrent_store: &*torrent_store,
            registry: &registry,
            metrics: &metrics,
            state: &state,
            pool: pool.as_deref(),
            checks: &checks,
            checked_hold: &checked_hold,
            boot_progress: &boot_progress,
        };
        resume_scan(&inputs, &mut tally, &mut scan_fence, &mut boot_shutdown).await?;
        torrent_dir_scan(&inputs, &mut tally, &mut scan_fence, &mut boot_shutdown).await?;
    }
    let ScanTally {
        loaded_by_profile,
        loaded,
        load_failures,
        ..
    } = tally;

    // Track what the scans loaded from the handles the sessions returned, not
    // only from their add alerts: an alert libtorrent dropped would leave its
    // torrent seeding with no fence, save or `DELETE` reaching it. The alert
    // loop's handling of each add alert, held above, keeps these entries.
    scan_fence.track_all(&state, &*source);

    // A profile fenced after its own scan's last add would otherwise keep
    // what that scan loaded running: a fenced profile is skipped by the
    // monitor from then on, so a fence that landed before the tracking above
    // walked a state map without them. One that lands after it finds them.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    scan_fence.enforce_all(&profile_registry, &metrics);

    // Every configured profile, so a failed one reads zero rather than absent.
    for profile in cfg.profile.iter().map(|p| &p.id) {
        let f = load_failures.get(profile).copied().unwrap_or_default();
        for (what, n) in [
            ("resume_add", f.resume_add),
            ("torrent_read", f.torrent_read),
            ("torrent_dir_add", f.torrent_dir_add),
            ("resume_file", f.resume_file),
            ("torrent_file", f.torrent_file),
        ] {
            metrics.set_gauge(
                "boot_torrent_load_failures",
                n as f64,
                &[("profile_id", profile.as_str()), ("source", what)],
            );
        }
    }

    // `.torrent`s held paused for a check slot, by this boot's torrent-dir
    // scan or by the run before it: each the scans loaded waits for its slot
    // again, and the record drops what they did not load.
    checks.restore_held_adds(source.profiles(), &loaded);

    // Adoptions a restart caught waiting for verification: their claims are
    // in the registry, no scan loads them, and the verify queue adds them
    // once it runs. Queued again here, they are accounted for rather than
    // reported unloaded.
    let requeued_at_boot: std::collections::HashSet<libtorrent_safe::InfoHash> = pool
        .as_ref()
        .map(|pool| pool.restore_verify_queue(&registry, &loaded))
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut requeued_by_profile: std::collections::HashMap<ProfileId, usize> =
        std::collections::HashMap::new();
    for ih in &requeued_at_boot {
        if let Some(profile) = registry.lookup(ih) {
            *requeued_by_profile.entry(profile).or_default() += 1;
        }
    }

    // Warn where the registry claims torrents for a profile that the scans
    // did not load — files left at an old, un-partitioned root, say — naming
    // the directory searched, since an override pointing elsewhere is the
    // remedy. A warning: the payload may have been deleted on purpose.
    for profile in source.profiles() {
        let claimed = registry.for_profile(&profile).len();
        let loaded = loaded_by_profile.get(&profile).copied().unwrap_or(0)
            + requeued_by_profile.get(&profile).copied().unwrap_or(0);
        if claimed > loaded {
            warn!(
                profile_id = %profile,
                registry_torrents = claimed,
                loaded_torrents = loaded,
                resume_dir = %dirs_of(&cfg, &profile).0.display(),
                torrent_dir = %dirs_of(&cfg, &profile).1.display(),
                // Both, as the refusal above names both. On the import boot
                // `source_path()` is the JSON file under its `.imported` name
                // — a file the daemon never reads again, so editing it changes
                // nothing — and naming it alone pointed at the wrong one.
                registry_path = %registry.path().display(),
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
        .filter(|ih| !loaded.contains(ih) && !requeued_at_boot.contains(ih))
        .collect();

    // The pool index's owner records follow the registry, now that the
    // sessions are loaded and the verify queue restored.
    if let Some(pool) = pool.as_ref() {
        pool.reconcile_owners_at_boot(&state, &registry, &*metrics);
    }

    // Alert loop.
    let metrics_for_loop: Arc<dyn MetricsSink> = metrics.clone();
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
    .shutdown_deadline(std::time::Duration::from_secs(cfg.shutdown_drain_secs))
    .fatal_listen_failure(profile_registry.iter().count() == 1)
    .on_fatal({
        let tx = shutdown_tx.clone();
        Arc::new(move |reason| {
            let _ = tx.send(reason);
        }) as torrentd_engine::FatalCallback
    })
    // The engine resumes torrents on its own disk-error retry schedule and
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
    // The kill-switch watch lifts its own fence by resuming only what it
    // recorded, and its walk of the state map misses a torrent whose add
    // alert lands after it: the add handler's pause of that torrent is
    // recorded with the fence, under its lock, so the lift resumes it too.
    .fence_hold(crate::fence::fence_hold(kill_switch.clone()))
    // The disk-error retry starts checks on the loop's own schedule: each
    // takes a slot in the daemon's check limit first, or waits for one.
    .check_slots(Arc::clone(&checks) as Arc<dyn torrentd_engine::CheckSlots>)
    // A magnet is added with DHT, PEX and LSD disabled because its `private`
    // bit is unknown; once its metadata shows it public, the engine lifts
    // what the profile's own posture does not keep. A profile the registry
    // does not know lifts nothing.
    .magnet_guard_lift({
        let profiles = profile_registry.clone();
        Arc::new(move |id: &torrentd_engine::ProfileId| {
            profiles
                .config(id)
                .map(torrentd_engine::policy::public_magnet_lift)
                .unwrap_or_else(torrentd_engine::TorrentFlags::empty)
        }) as torrentd_engine::MagnetGuardLift
    })
    // libtorrent's device binding of a listen socket is best effort, and its
    // `listen_succeeded` alert names no device, so every socket a vpn
    // session opens is checked against the kernel as it comes up.
    .listen_device_check(listen_device_check(profile_registry.clone()))
    .listen_events(listen_events)
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
        resume: resume_store,
        shutdown_tx,
        shutdown_rx,
        reload_rx,
        reload_tx: reload_tx_for_api,
        metrics,
        pool,
        checks,
        registry,
        profile_registry,
        kill_switch,
        fencing,
        kill_switch_watch,
        log_handle,
        alert_loop,
        unloaded_at_boot,
        requeued_at_boot,
        instance_lock,
        table_lock,
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
            resume,
            shutdown_tx,
            shutdown_rx,
            reload_rx,
            reload_tx,
            metrics,
            pool,
            checks,
            registry,
            profile_registry,
            kill_switch,
            fencing,
            kill_switch_watch,
            log_handle,
            alert_loop,
            unloaded_at_boot,
            requeued_at_boot,
            // Bound, not `_`: it has to live to the end of this function,
            // past the teardown. See the fields.
            instance_lock: _instance_lock,
            table_lock: _table_lock,
        } = self;

        // The VPN health and port-forward monitors and the kill-switch watch
        // are not here: `boot` starts each before the scans. The VPN monitor
        // and the watch run until `stop_fencing`, before the teardown.

        // Long-running pool work and the shutdown latch it checks; the
        // teardown below waits for it before stopping the alert loop.
        let work: Arc<crate::app_state::WorkGate> = Arc::default();

        // Re-drive any plan a crash or a kill left mid-apply. A half-applied
        // reorganisation is exactly the state an operator cannot reason about.
        // Started before the server, but not awaited: it first waits for every
        // torrent the boot loaded to reach the state map, so it runs alongside
        // the API rather than ahead of it. Held in the work gate like an API
        // apply, and stopped between steps the same way.
        if let Some(pool) = pool.clone() {
            // What the boot handed to sessions: the re-drive waits for every
            // one to reach the state map before acting on what is loaded. A
            // requeued adoption is not one: the queue adds it when its turn
            // comes, which can be hours away.
            let loaded: Vec<_> = registry
                .entries()
                .into_iter()
                .map(|(ih, _)| ih)
                .filter(|ih| !unloaded_at_boot.contains(ih) && !requeued_at_boot.contains(ih))
                .collect();
            // Read here, before the server below serves: a plan an API apply
            // claims during the wait is that apply's, not the re-drive's.
            let plans = crate::pool_apply::unfinished_at_boot(&pool);
            crate::pool_apply::spawn_resume_unfinished(
                pool,
                source.clone(),
                state.clone(),
                Arc::clone(&work),
                loaded,
                plans,
            );
        }

        // Verify queue: admits a bounded number of checks - adoptions,
        // re-hashes, `.torrent` adds' first checks - so a bulk adopt, recheck
        // or add cannot starve whatever is already seeding. Run with or
        // without `[pool]`.
        spawn_supervised(
            "verify_queue",
            metrics.clone(),
            crate::pool_service::run_verify_queue(
                Arc::clone(&checks),
                pool.clone(),
                source.clone(),
                state.clone(),
                metrics.clone(),
                profile_registry.clone(),
                registry.clone(),
                shutdown_tx.subscribe(),
            ),
        );

        let trusted_proxies = crate::http::forwarded::TrustedProxies::parse(&cfg.trusted_proxies)
            .expect("validated at startup");
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
            checks,
            alert_heartbeat: alert_loop.heartbeat(),
            default_save_path: cfg.default_save_path.clone(),
            torrent_dir: cfg.torrent_dir.clone(),
            reload_tx: Some(reload_tx.clone()),
            trusted_proxies: trusted_proxies.clone(),
            allowed_hosts: crate::http::security::HostAllowlist::parse(&cfg.allowed_hosts)
                .expect("validated at startup"),
            unloaded_at_boot: Arc::new(parking_lot::Mutex::new(unloaded_at_boot)),
            removed_unassigned: Arc::default(),
            shutdown: shutdown_tx.clone(),
            work: Arc::clone(&work),
            events: Arc::default(),
            tunnel_probe: crate::vpn_monitor::host_prober(),
            kill_switch: kill_switch.clone(),
        };

        // The trust set the process runs with, once: effective blocks, and
        // the text as configured beside them.
        if trusted_proxies.is_empty() {
            info!(
                target: "torrentd::auth",
                "trusted_proxies is empty: no forwarding header is read and the socket peer is the client",
            );
        } else {
            info!(
                target: "torrentd::auth",
                trusted_proxies = %trusted_proxies,
                configured = %cfg.trusted_proxies.join(", "),
                "forwarding headers are believed from these peers, and read once at startup",
            );
        }

        // The document is rendered once here and served verbatim, so
        // `GET /v1/openapi.json` costs nothing per request and is byte-for-byte
        // what `torrentd openapi` prints. Neither step can fail short of a bug
        // in a route's description; if one does, the daemon exits 70 through
        // the same teardown a bind failure takes.
        let app = http::document_json()
            // `{e:#}`: an `anyhow::Error`, whose plain Display drops its cause.
            .map_err(|e| error!(error.cause = %format_args!("{e:#}"), "build the HTTP API"))
            .ok()
            .and_then(|openapi| {
                let openapi = http::OpenApiJson(Arc::new(bytes::Bytes::from(openapi)));
                http::service(app_state, openapi)
                    .map_err(|e| error!(error.cause = %e, "build the HTTP router"))
                    .ok()
            });
        let http_listen = cfg.http_listen.clone();

        // SIGHUP pump.
        let reload_source = source.clone();
        let cfg_clone = cfg.clone();
        spawn_supervised(
            "reload",
            metrics.clone(),
            reload::run(
                config_path,
                cfg_clone,
                reload_source,
                profile_registry.clone(),
                reload_rx,
                log_handle,
                metrics.clone(),
            ),
        );

        // A bind failure does not return from here: `boot` has already
        // disarmed its cleanup guard, so this function is the only thing left
        // that removes the kill switch and brings the tunnels down. It skips
        // the server and falls through to the same drain and teardown a
        // signalled shutdown runs, exiting 70, after `run_http_stage` has told
        // the background tasks to stop.
        let listener = bind_api_listener(&cfg).await;
        let posture = unauthenticated_posture(&cfg);
        let (tx, alert, gate) = (&shutdown_tx, &alert_loop, &work);
        let mut exit_code = run_http_stage(
            listener,
            app,
            |listener, app| async move {
                announce_ready(&http_listen, posture, tx, alert);
                match listener {
                    ApiListener::Tcp(listener) => {
                        serve_until_shutdown(listener, app, shutdown_rx, gate).await
                    }
                    ApiListener::Unix(socket) => {
                        let work = Arc::clone(gate);
                        crate::api_socket::serve(
                            socket,
                            app,
                            shutdown_rx,
                            move || {
                                // As the TCP server's graceful-shutdown hook.
                                work.cancel();
                                sd_notify::stopping();
                                sd_notify::status("draining HTTP requests");
                            },
                            crate::api_socket::Limits {
                                max_connections: HTTP_MAX_CONNECTIONS.get(),
                                header_read_timeout: HTTP_HEADER_READ_TIMEOUT,
                                drain_timeout: HTTP_DRAIN_TIMEOUT,
                            },
                        )
                        .await;
                        0
                    }
                }
            },
            &shutdown_tx,
        )
        .await;
        // Already latched when the server saw the shutdown; this covers the
        // bind failure, which never served.
        work.cancel();

        // Tell systemd we're stopping before the resume drain, which may take
        // its whole deadline — otherwise the watchdog can fire mid-drain.
        sd_notify::stopping();
        // And ask for the time the rest of the stop may take, which on a
        // large pool can outrun `TimeoutStopSec`: capped at the sum of the
        // stages' own bounds, so a stop wedged past all of them is still
        // killed.
        let _extend_stop = sd_notify::TimeoutExtender::start(
            POOL_WORK_DRAIN
                + std::time::Duration::from_secs(cfg.shutdown_drain_secs)
                + TEARDOWN_ALLOWANCE,
        );

        // Pool work a drained request left behind, or the boot-time re-drive:
        // stopping the alert loop and closing the sessions under a plan that
        // is moving storage through them is the mid-step kill the latch
        // exists to prevent. Applies stop at their next step boundary; a scan
        // or drift check runs to its end or to this bound.
        wait_for_pool_work(&work, POOL_WORK_DRAIN).await;
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
        let unsaved_at_shutdown = alert_loop.unsaved_at_shutdown();
        // Joined off the runtime's workers: the drain can take its whole
        // deadline, and the timeout extender above has to keep running.
        match tokio::task::spawn_blocking(move || alert_loop.join()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(error.cause = ?e, "alert loop join panicked"),
            Err(e) => warn!(error.cause = %e, "alert loop join task failed"),
        }
        let mut shutdown_report = ShutdownReport {
            unsaved_resumes: unsaved_at_shutdown.load(std::sync::atomic::Ordering::Relaxed),
            kill_switch_removal_failed: false,
        };

        // Persist DHT routing tables for the next start. Only a host profile
        // with DHT enabled has one; a tunnelled profile runs with DHT off by
        // construction and has nothing to save. The sessions are still alive
        // here — `teardown_network` below closes them. A profile held
        // offline has its DHT node stopped and nothing to save; the file
        // from before keeps the last table it had.
        for p in cfg
            .profile
            .iter()
            .filter(|p| p.dht_enabled() && !profile_registry.held_offline(&p.id))
        {
            let Some(engine) = source.engine_for(&p.id) else {
                continue;
            };
            match engine.session_state() {
                Ok(bytes) if !bytes.is_empty() => {
                    match write_atomic(&cfg.session_state_path(&p.id), &bytes) {
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

        // Sessions, then tunnels, then the kill switch — see
        // `teardown_network`. The daemon brought the tunnels up, so it owns
        // tearing them down; leaving them up meant every restart accumulated
        // interfaces and left an idle tunnel connected to the provider
        // indefinitely. This runs on every exit from `run_until_signal`, the
        // HTTP bind failure included — a failure inside `boot` is torn down
        // by `BootCleanup` instead.
        let engines: Vec<Arc<dyn TorrentEngine>> = source
            .profiles()
            .iter()
            .filter_map(|p| source.engine_for(p))
            .collect();
        let tunnels: Vec<_> = profile_registry
            .iter()
            .filter_map(|entry| {
                // A host profile has no tunnel to take down.
                let (Some(vpn_type), Some(iface)) =
                    (entry.config.vpn_type(), entry.config.vpn_interface())
                else {
                    return None;
                };
                Some((
                    entry.config.id.clone(),
                    iface.to_string(),
                    crate::vpn::for_type(vpn_type, &run_dir),
                ))
            })
            .collect();
        // The fencing stops here and no earlier: through the drains above
        // the sessions still seed, and a tunnel lost or a ruleset flushed
        // then is fenced as at any other time. Past here the sessions close,
        // and the watch would read the switch's removal as a flush.
        stop_fencing(fencing, kill_switch_watch.as_ref()).await;
        teardown_network(engines, tunnels, || {
            if kill_switch.is_some() {
                finish_kill_switch_removal(
                    crate::vpn::killswitch::disable(),
                    &metrics,
                    &mut shutdown_report,
                );
            }
        })
        .await;
        write_shutdown_report(&run_dir, &shutdown_report);

        info!("torrentd: clean exit");
        exit_code
    }
}

/// `s` as one POSIX shell word: single-quoted, with each `'` closed, escaped
/// and reopened. The registry refusal prints a command to paste, and a state
/// directory holding a space or a shell metacharacter must not break it.
fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::test_support::counted;

    #[test]
    fn a_boot_scan_sees_a_shutdown_signalled_while_it_runs() {
        let (tx, mut rx) = broadcast::channel(8);
        assert!(!shutdown_requested(&mut rx), "nothing signalled yet");
        tx.send(ShutdownReason::Sigterm).unwrap();
        assert!(shutdown_requested(&mut rx));
        // A receiver that fell behind missed signals: that is a shutdown too.
        let (tx, mut rx) = broadcast::channel(1);
        tx.send(ShutdownReason::Sigterm).unwrap();
        tx.send(ShutdownReason::Sigint).unwrap();
        assert!(shutdown_requested(&mut rx));
    }

    /// A store rooted at `dir/store` whose profile `p` cannot be written: a
    /// file stands where its directory goes.
    fn refusing_store_root(dir: &std::path::Path) -> std::path::PathBuf {
        let base = dir.join("store");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("p"), b"x").unwrap();
        base
    }

    /// The hook boot installs on the torrent store counts a magnet-metadata
    /// write that fails on the batch writer under `source=metadata`.
    #[test]
    fn a_failed_batched_torrent_write_counts_under_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(torrentd_engine::RecordingSink::new());
        let store = FsTorrentStore::new(refusing_store_root(dir.path()))
            .with_batched_writes(Some(torrent_write_error_hook(sink.clone())));
        let p = ProfileId::new("p");
        store
            .write_batched(&p, &libtorrent_safe::InfoHash([0x21; 20]), b"d4:infoe")
            .unwrap();
        store.flush();
        assert_eq!(
            counted(&sink, "torrent_file_persist_errors_total"),
            vec![vec![
                ("profile_id".to_string(), "p".to_string()),
                ("source".to_string(), "metadata".to_string()),
            ]],
        );
    }

    /// The hook boot installs on the resume store counts a write that fails
    /// on the batch writer and marks the torrent's file stale.
    #[test]
    fn a_failed_batched_resume_write_counts_and_marks_the_torrent() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(torrentd_engine::RecordingSink::new());
        let state = Arc::new(StateMap::new());
        let ih = libtorrent_safe::InfoHash([0x22; 20]);
        let p = ProfileId::new("p");
        state.insert(
            ih,
            torrentd_engine::TorrentState::newly_added(
                libtorrent_safe::TorrentHandle {
                    id: 1,
                    infohash: ih,
                },
                p.clone(),
                std::time::Instant::now(),
            ),
        );
        let store = FsResumeStore::new(refusing_store_root(dir.path())).with_batched_writes(Some(
            resume_write_error_hook(sink.clone(), Arc::clone(&state)),
        ));
        store.write_batched(&p, &ih, b"resume").unwrap();
        store.flush();
        assert_eq!(
            counted(&sink, "resume_write_errors_total"),
            vec![vec![("profile_id".to_string(), "p".to_string())]],
        );
        assert!(state.get(&ih).unwrap().resume_write_failed);
    }

    /// The database path in the registry refusal's `sqlite3` command reaches
    /// the shell as one word, whatever the state directory is called.
    #[test]
    fn the_refusal_command_quotes_a_path_the_shell_would_split() {
        for path in [
            "/var/lib/torrentd/registry.db",
            "/srv/my state/registry.db",
            "/srv/it's; $(rm -rf ~) `x` \"q\" *&|/registry.db",
        ] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf '%s' {}", sh_single_quote(path)))
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
            assert_eq!(String::from_utf8(out.stdout).unwrap(), path);
        }
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
            "the profile loop's check sees it and aborts the boot",
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
