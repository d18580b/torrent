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
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use torrentd_engine::batch_writer::write_atomic;
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
use torrentd_engine::ProfileConfig;
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
use torrentd_engine::TorrentStore;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::app_state::AppState;
use crate::config::Config;
use crate::http;
use crate::metrics_sink::PromSink;
use crate::profile_registry::FailedProfile;
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

/// The most HTTP connections the API holds open at once; the next waits in
/// the listen backlog until one closes. The descriptor table is shared with
/// every session's peers and files, and the API's callers need a few dozen.
const HTTP_MAX_CONNECTIONS: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(256) {
    Some(n) => n,
    None => unreachable!(),
};

/// How long an HTTP/1 client has to send a request head, including the wait
/// for the next request on a kept-alive connection.
///
/// A head is a few hundred bytes. kynos' default of 30 s lets a client that
/// never finishes one hold a connection — one of [`HTTP_MAX_CONNECTIONS`] —
/// three times as long for no reason; the body's own deadline is
/// `http::v1::REQUEST_DEADLINE`.
const HTTP_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How often an HTTP/2 (h2c) connection is pinged, and how long the peer has
/// to acknowledge, so a silent peer is dropped within 30 s. It does not bound
/// a peer that answers pings and sends nothing else, nor a connection that
/// sends no byte at all (`docs/running.md` §7).
const HTTP2_KEEP_ALIVE: kynos::server::protocol::Http2KeepAlive =
    kynos::server::protocol::Http2KeepAlive {
        interval: std::time::Duration::from_secs(20),
        timeout: std::time::Duration::from_secs(10),
    };

/// How long the HTTP server's graceful shutdown waits for open requests
/// before cutting them off. A drain that runs out exits 0 with a warning
/// (`http_exit_code`).
///
/// One stage of the stop budget `deploy/torrentd.service` sizes
/// `TimeoutStopSec` to: this, then [`POOL_WORK_DRAIN`], then the resume
/// drain (`shutdown_drain_secs`), then the network teardown.
const HTTP_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the teardown waits for pool work — a scan, a drift check, an
/// apply finishing its current step — before stopping the alert loop around
/// it. See `WorkGate`.
const POOL_WORK_DRAIN: std::time::Duration = std::time::Duration::from_secs(20);

/// An exclusive `flock` on [`Config::instance_lock_path`], held for the life
/// of the daemon and taken first in `boot`, so a second `torrentd` against
/// the same state refuses before it can replace the running daemon's kill
/// switch or tear down its tunnels. The kernel releases it however the
/// process ends, so a crash leaves no stale lock.
///
/// `torrentd net-cleanup` takes it too, so it refuses to tear down a running
/// daemon's tunnels and kill switch.
#[derive(Debug)]
pub(crate) struct InstanceLock {
    /// Never read. Holding the open file is the lock.
    _file: std::fs::File,
}

impl InstanceLock {
    /// Lock `path`, creating it and its directory where missing, or refuse
    /// naming the process that holds it.
    pub(crate) fn acquire(path: &std::path::Path) -> anyhow::Result<Self> {
        use std::io::Read;
        use std::io::Seek;
        use std::io::Write;

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create the state directory {}", dir.display()))?;
        }
        // No `truncate`: the file may belong to a running daemon, and its pid
        // is what the refusal below names.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("open the single-instance lock {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut holder = String::new();
                // Best effort: the pid only sharpens the message.
                let _ = file.read_to_string(&mut holder);
                let who = match holder.trim().parse::<u32>() {
                    Ok(pid) => format!("another torrentd (pid {pid})"),
                    Err(_) => "another torrentd".to_string(),
                };
                anyhow::bail!(
                    "{who} is already running against this state directory: it holds the \
                     single-instance lock {}. Refusing to start before touching the kill switch, \
                     any tunnel or any state file, all of which belong to the running daemon. \
                     Stop that one first (`systemctl stop torrentd` for the packaged unit) or \
                     point this one at a different resume_dir.",
                    path.display(),
                );
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e)
                    .with_context(|| format!("take the single-instance lock {}", path.display()));
            }
        }
        // Record the holder for a later refusal to name. Written only once the
        // lock is ours, so it never overwrites a live daemon's pid; a failure
        // costs only the pid in that message, so it does not stop the boot.
        let record = file
            .set_len(0)
            .and_then(|()| file.rewind())
            .and_then(|()| writeln!(file, "{}", std::process::id()));
        if let Err(e) = record {
            warn!(
                path = %path.display(),
                error.cause = %e,
                "could not record this process's pid in the single-instance lock; the lock \
                 still holds, and a second start will refuse without naming this pid",
            );
        }
        Ok(Self { _file: file })
    }
}

/// Undoes what `boot` raised on the host — sessions, tunnels and the kill
/// switch, all of which outlive the process — for every exit from `boot` that
/// is not a successful one. Armed from construction; `disarm` hands ownership
/// to the shutdown path.
struct BootCleanup {
    run_dir: std::path::PathBuf,
    /// How a tunnel's manager is built, for bring-up and teardown alike.
    /// Production passes `vpn::for_type`; tests pass a mock.
    vpn_for: VpnFactory,
    tunnels: Vec<(torrentd_engine::VpnType, String)>,
    /// Every session boot built, closed before any tunnel goes.
    sessions: Vec<Arc<dyn TorrentEngine>>,
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
            .field("sessions", &self.sessions.len())
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
            sessions: Vec::new(),
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

    /// Record the sessions boot built, for the drop guard to close before it
    /// takes any tunnel down.
    fn note_sessions(&mut self, sessions: impl IntoIterator<Item = Arc<dyn TorrentEngine>>) {
        self.sessions.extend(sessions);
    }

    /// Bring one recorded tunnel down and stop tracking it — for a profile
    /// that failed after its tunnel came up. The only teardown `boot` runs
    /// outside `Drop`.
    ///
    /// On `spawn_blocking`, because an OpenVPN teardown polls for the process
    /// to exit for up to seven seconds. An interface this boot did not record
    /// spawns nothing.
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
    fn manager_for(&self, t: torrentd_engine::VpnType) -> Arc<dyn torrentd_engine::VpnManager> {
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
    async fn bring_up_tracked(
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

    fn disarm(&mut self) {
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

/// Marks a boot failure as the configuration's: `main` exits `EX_CONFIG` (78)
/// for it, which the unit's `RestartPreventExitStatus=78` does not restart,
/// rather than 70, which it does. Only for what no restart can change — a
/// tunnel that failed to come up is not one.
#[derive(Debug)]
pub struct ConfigRefused;

impl std::fmt::Display for ConfigRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the configuration is refused")
    }
}

/// Wrap `e` as a [`ConfigRefused`].
fn refused(e: anyhow::Error) -> anyhow::Error {
    e.context(ConfigRefused)
}

/// The kill switch's refusal of `uid`, as a [`ConfigRefused`]: the
/// pre-flight `main` runs before `boot` makes it, so a daemon running as root
/// exits 78 before any tunnel is raised rather than 70 after every one is.
pub fn kill_switch_uid_refusal(uid: u32) -> Option<anyhow::Error> {
    crate::vpn::killswitch::refusal_for_uid(uid).map(|e| refused(e.into()))
}

/// The error a failed [`crate::vpn::killswitch::enable`] fails the boot with:
/// its uid refusal is the configuration's, and anything else (an `nft`
/// failure, a tunnel address that could not be read) is not.
fn kill_switch_enable_failure(e: std::io::Error) -> anyhow::Error {
    let refusal = crate::vpn::killswitch::is_uid_refusal(&e);
    let e = anyhow::Error::new(e);
    let e = if refusal { refused(e) } else { e };
    e.context("install nftables kill switch (network_kill_switch=true)")
}

/// Whether a boot failure is a [`ConfigRefused`].
pub fn is_config_refusal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ConfigRefused>().is_some()
}

/// The longest boot `EXTEND_TIMEOUT_USEC` keeps alive. Past this a boot is
/// treated as wedged, and systemd's own start timeout fires from the last
/// extension.
const BOOT_EXTEND_CAP: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// What the teardown after the resume drain is given: closing the sessions,
/// the tunnels (up to 7 s an OpenVPN profile, in parallel), the kill switch.
const TEARDOWN_ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(60);

/// Every descriptor the daemon may hold at once, against `RLIMIT_NOFILE`.
///
/// Each session may open `connections_limit` peer sockets and keep
/// `file_pool_size` payload files open, and the API accepts up to
/// [`HTTP_MAX_CONNECTIONS`]. A soft limit below their sum is a daemon that seeds until
/// the pool grows and then fails `accept` and `open` with `EMFILE` — in
/// libtorrent's logs, as disk and peer errors, far from the cause. The values
/// are the effective ones: `Settings::server_seed_overrides` sets both, and
/// the config's keys override that.
fn warn_if_descriptors_are_short(cfg: &Config) {
    let need = descriptors_needed(cfg);
    match nofile_soft_limit() {
        Some(limit) if limit < need => warn!(
            rlimit_nofile = limit,
            needed = need,
            "the open-file limit is below what the daemon may hold at once \
             (connections_limit + file_pool_size per profile, plus the HTTP \
             connection cap); raise LimitNOFILE or lower those keys, or peers, \
             payload files and API clients will fail with EMFILE under load",
        ),
        Some(_) => {}
        None => warn!("could not read RLIMIT_NOFILE; the open-file limit is unchecked"),
    }
}

/// `connections_limit + file_pool_size` per configured profile, plus the
/// HTTP connection cap.
fn descriptors_needed(cfg: &Config) -> u64 {
    let s = cfg.libtorrent_settings();
    let per_session = u64::from(s.connections_limit.unwrap_or_default())
        + u64::from(s.file_pool_size.unwrap_or_default());
    per_session * cfg.profile.len() as u64 + http_connection_cap()
}

/// [`HTTP_MAX_CONNECTIONS`] as a descriptor count.
fn http_connection_cap() -> u64 {
    u64::try_from(HTTP_MAX_CONNECTIONS.get()).unwrap_or(u64::MAX)
}

/// The soft `RLIMIT_NOFILE`, or `None` if it cannot be read.
fn nofile_soft_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable `rlimit` for the whole call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    (rc == 0).then_some(lim.rlim_cur)
}

/// Warn about every server two `vpn` profiles' WireGuard configs both name as
/// their `Endpoint`.
///
/// A tracker sees the address a tunnel leaves from, not the tunnel's own
/// address, so two accounts whose configs name one server announce from one
/// public IP — the plainest sign of two accounts on one host a tracker can
/// see. A warning rather than a refusal: the host is compared as written, so
/// a match is not proof of one exit (a provider name can resolve to several
/// servers), and profiles on unrelated trackers lose nothing by sharing one.
fn warn_if_exits_are_shared(profiles: &[ProfileConfig]) {
    for shared in shared_endpoint_hosts(profiles, |path| std::fs::read_to_string(path)) {
        let profiles = shared
            .profiles
            .iter()
            .map(ProfileId::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            vpn_endpoint = %shared.host,
            profiles = %profiles,
            "these profiles' WireGuard configs name the same Endpoint, so their accounts \
             announce from one public address and a tracker can tie them together; give \
             each account a config for a different server",
        );
    }
}

/// An `Endpoint` host more than one profile's WireGuard config names.
#[derive(Debug, PartialEq, Eq)]
struct SharedEndpoint {
    host: String,
    /// In configuration order.
    profiles: Vec<ProfileId>,
}

/// Every `Endpoint` host ([`vpn::wireguard_endpoint_hosts`]) that more than one
/// WireGuard profile's config names, ordered by host. `read` returns a
/// config's text; a config it cannot read is skipped, since its bring-up
/// refuses it with the reason.
fn shared_endpoint_hosts(
    profiles: &[ProfileConfig],
    read: impl Fn(&std::path::Path) -> std::io::Result<String>,
) -> Vec<SharedEndpoint> {
    let mut by_host: std::collections::BTreeMap<String, Vec<ProfileId>> =
        std::collections::BTreeMap::new();
    for p in profiles {
        let ProfileNetwork::Vpn {
            vpn_type: torrentd_engine::VpnType::Wireguard,
            vpn_config,
            ..
        } = &p.network
        else {
            continue;
        };
        let Ok(text) = read(vpn_config) else {
            continue;
        };
        for host in vpn::wireguard_endpoint_hosts(&text) {
            let holders = by_host.entry(host).or_default();
            if !holders.contains(&p.id) {
                holders.push(p.id.clone());
            }
        }
    }
    by_host
        .into_iter()
        .filter(|(_, profiles)| profiles.len() > 1)
        .map(|(host, profiles)| SharedEndpoint { host, profiles })
        .collect()
}

/// How many entries a boot scan adds between looks at the shutdown receiver.
/// Cheap enough to check every time; every 256 keeps it out of profiles.
const SCAN_SHUTDOWN_CHECK_EVERY: usize = 256;

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
    registry: Arc<AssignmentRegistry>,
    profile_registry: Arc<ProfileRegistry>,
    /// The nftables kill switch, where it was installed: watched while the
    /// daemon runs, and torn down on graceful shutdown.
    kill_switch: Option<crate::vpn::killswitch::Installed>,
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
    // and so stopped, when `boot` returns — capped so a wedged boot still
    // meets the timeout eventually.
    let _extend_start = sd_notify::TimeoutExtender::start(BOOT_EXTEND_CAP);

    warn_if_descriptors_are_short(&cfg);
    {
        let profiles = cfg.profile.clone();
        tokio::task::spawn_blocking(move || warn_if_exits_are_shared(&profiles))
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
    // owns every tunnel this boot raised.
    if boot_shutdown.try_recv().is_ok() {
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
            .with_states(desired_states),
    );
    profile_registry.export_offline(&*metrics);
    let source: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(source_entries));
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
    // pauses what the state map holds, which the scans do not fill, so the
    // scans pause what they add to a fenced profile themselves (`ScanFence`).
    spawn_supervised(
        "vpn_monitor",
        metrics.clone(),
        crate::vpn_monitor::run(
            profile_registry.clone(),
            state.clone(),
            metrics.clone(),
            std::time::Duration::from_secs(cfg.vpn_handshake_max_age_secs),
            shutdown_tx.subscribe(),
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
        kill_switch = Some(installed);
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
    // What the scans could not load, per profile, by the `source` label of
    // `boot_torrent_load_failures`. Exported as gauges once both have run:
    // these happen before any scrape can, so a counter would appear already
    // incremented and `increase()` would never see it move.
    let mut load_failures: std::collections::HashMap<ProfileId, BootLoadFailures> =
        std::collections::HashMap::new();
    // What the scans add, so a profile the VPN monitor fences mid-scan has
    // it paused.
    let mut scan_fence = ScanFence::default();

    // Managed pool. Opened before the alert loop so a bad index path fails
    // startup rather than surfacing as a 500 on the first API call, and
    // before the resume scan, which falls back to its library for a
    // torrent's `.torrent`.
    let pool = crate::pool_service::PoolService::open(&cfg).context("open pool index")?;
    if let Some(pool) = pool.as_ref() {
        pool.set_metrics(metrics.clone());
        pool.set_state(Arc::clone(&state));
        pool.set_torrent_store(Arc::clone(&torrent_store));
    }

    // Resume scan: load every saved resume file per profile. The shim
    // already deduplicates duplicate adds so a future torrent dir scan
    // won't double-add.
    for profile in source.profiles() {
        let Some(profile_cfg) = profile_registry.config(&profile) else {
            continue;
        };
        // A file that cannot be read is skipped, logged and counted by the
        // store; only the directory itself failing to open stops the boot.
        let scan = resume_store.scan(&profile).context("scan resume dir")?;
        load_failures
            .entry(profile.clone())
            .or_default()
            .resume_file += scan.unreadable;
        let entries = scan.entries;
        let count = entries.len();
        let mut missing_metadata = 0usize;
        let mut from_library = 0usize;
        let mut added_from_resume = 0usize;
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
        for (i, (ih, data)) in entries.into_iter().enumerate() {
            // A 100K-torrent scan runs for minutes; a SIGTERM during it is
            // answered now, while `BootCleanup` still owns the tunnels, not
            // after the scan has added everything only for the drain to save
            // it all again.
            if i % SCAN_SHUTDOWN_CHECK_EVERY == 0 {
                if shutdown_requested(&mut boot_shutdown) {
                    anyhow::bail!("shutdown requested during the resume scan");
                }
                scan_fence.enforce_all(&profile_registry, &metrics);
            }
            // Cross-check the registry; the spec aborts the profile on
            // mismatch. A resume file under one profile's directory that the
            // registry assigns to another is the operator's to reconcile.
            let existing = registry.lookup(&ih);
            if let Some(existing) = &existing {
                if *existing != profile {
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
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_read += 1;
                    None
                }
            };
            // A torrent the pool adopted before adoption wrote its `.torrent`
            // to the store has none there; the library's copy the pool index
            // names is the same metadata. Written back to the store, so the
            // repair happens once and the library may move on.
            let torrent = match (torrent, pool.as_ref()) {
                (None, Some(pool)) => {
                    let found = pool.library_torrent(&ih);
                    if let Some(bytes) = &found {
                        from_library += 1;
                        if let Err(e) = torrent_store.write(&profile, &ih, bytes) {
                            warn!(profile_id = %profile, infohash = %ih, error.cause = %e,
                                  "could not copy the pool library's .torrent into the torrent store");
                            // Counted as the adoption's own write is: this
                            // completes it, and a store that keeps refusing
                            // repeats the repair at every boot.
                            metrics.inc_counter(
                                "torrent_file_persist_errors_total",
                                &[("profile_id", profile.as_str()), ("source", "api")],
                            );
                        }
                    }
                    found
                }
                (torrent, _) => torrent,
            };
            if torrent.is_none() {
                missing_metadata += 1;
            }
            // The flags re-asserted are `torrentd_engine::policy`'s. PAUSED is
            // not cleared: resume data does not say why a torrent was paused,
            // and restarting one an operator paused is not recoverable.
            let params = resume_scan_params(profile_cfg, data.into_inner(), torrent);
            // The account-isolation guard, on the trackers this resume data
            // would announce to — its own `trackers` list where it has one.
            // A file written before the profile's allow-list was set, or
            // dropped into the directory by hand, is held to it like an API
            // add. Checked before the registry claim, so a refusal claims
            // nothing.
            if let Err(refusal) = boot_scan_guard(&*metrics, profile_cfg, &ih, &params, "resume") {
                if matches!(refusal, torrentd_engine::TrackerRefusal::Unreadable(_)) {
                    load_failures.entry(profile.clone()).or_default().resume_add += 1;
                }
                continue;
            }
            // Unless it is already this profile's, claim it.
            let claimed = match existing {
                Some(_) => Ok(()),
                None => registry.assign(ih, profile.clone()).map(drop),
            };
            if let Err(e) = claimed {
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
            match engine.add_torrent(params) {
                Ok(h) => {
                    added_from_resume += 1;
                    loaded.insert(ih);
                    scan_fence.added(&profile_registry, &metrics, &profile, h);
                }
                Err(e) => {
                    warn!(profile_id = %profile, infohash = %ih, error.cause = %e, "resume add failed");
                    load_failures.entry(profile.clone()).or_default().resume_add += 1;
                }
            }
        }
        if from_library > 0 {
            info!(
                profile_id = %profile,
                torrent_count = from_library,
                "resume entries with no .torrent in the torrent store took it from the pool library",
            );
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
        let scan = torrent_store.scan(&profile).context("scan torrent dir")?;
        load_failures
            .entry(profile.clone())
            .or_default()
            .torrent_file += scan.unreadable;
        let entries = scan.entries;
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
        let mut added = 0usize;
        for (i, (ih, bytes)) in entries.into_iter().enumerate() {
            if i % SCAN_SHUTDOWN_CHECK_EVERY == 0 {
                if shutdown_requested(&mut boot_shutdown) {
                    anyhow::bail!("shutdown requested during the torrent-dir scan");
                }
                scan_fence.enforce_all(&profile_registry, &metrics);
            }
            // Resume data already loaded this torrent (the registry holds
            // every resume-loaded info-hash after the scan above) — skip.
            if registry.lookup(&ih).is_some() {
                continue;
            }
            // The account-isolation guard, before the claim: a `.torrent`
            // dropped into this profile's directory is held to its
            // allow-list like one posted to the API.
            let save_path =
                torrent_dir_save_path(&*metrics, &*torrent_store, &profile, &ih, &scan_save_path);
            let params = torrent_dir_scan_params(profile_cfg, bytes, save_path);
            if let Err(refusal) =
                boot_scan_guard(&*metrics, profile_cfg, &ih, &params, "torrent_dir")
            {
                if matches!(refusal, torrentd_engine::TrackerRefusal::Unreadable(_)) {
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_dir_add += 1;
                }
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
            match engine.add_torrent(params) {
                Ok(h) => {
                    added += 1;
                    loaded.insert(ih);
                    scan_fence.added(&profile_registry, &metrics, &profile, h);
                }
                Err(e) => {
                    warn!(
                        profile_id = %profile,
                        infohash = %ih,
                        error.cause = %e,
                        "torrent-dir add failed",
                    );
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_dir_add += 1;
                    // Release the claim so a later run can retry the add. A
                    // release that fails to persist leaves the claim on disk,
                    // and the next boot skips this torrent as already loaded.
                    if let Err(e) = registry.remove(&ih) {
                        warn!(
                            profile_id = %profile,
                            infohash = %ih,
                            error.cause = %e,
                            "could not release the claim of a torrent that failed to load",
                        );
                        metrics.inc_counter("store_write_errors_total", &[("store", "registry")]);
                    }
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

    // A profile fenced after its own scan's last add would otherwise keep
    // what that scan loaded running until the alert loop below has put it in
    // the state map, where the monitor no longer looks: a fenced profile is
    // skipped from then on.
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
                // — the file `docs/running.md` tells the operator explicitly
                // not to edit — so naming it alone pointed at the wrong one.
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

    // Two artefacts persist a torrent→profile mapping, and nothing reconciled
    // them: the assignment registry, which the resume scan above writes and
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
        registry,
        profile_registry,
        kill_switch,
        log_handle,
        alert_loop,
        unloaded_at_boot,
        requeued_at_boot,
        instance_lock,
    })
}

/// The alert loop's [`AlertLoopBuilder::listen_device_check`]: a vpn profile's
/// listen sockets must each be held to its `vpn_interface`.
///
/// A socket held to another device is the failure this exists for: its uTP
/// and UDP and HTTP tracker traffic leaves by that device with the tunnel's
/// address, and `vpn_monitor`'s route probe, which asks the routing table,
/// reports the tunnel healthy.
///
/// A socket held to no device, where the kernel refused the binding, follows
/// the source-address rules. On an IPv4 endpoint that is the path the route
/// probe asks about, from the tunnel's IPv4 address, so it is logged and not
/// fatal. On an IPv6 endpoint it is fatal too: the probe never asks from an
/// IPv6 address, so a lost `ip -6` source rule would send that socket's
/// traffic by the main IPv6 route with nothing to fence it.
///
/// A check that cannot run (an endpoint that does not parse, or a failed read
/// of this process's sockets) is fatal as well, unlike the route and
/// handshake probes: those run again next poll, and this check runs once per
/// listen socket. An endpoint at which no socket is found has nothing to
/// check; that is logged. A host profile is not checked.
fn listen_device_check(
    profiles: Arc<ProfileRegistry>,
) -> torrentd_engine::alert_loop::ListenDeviceCheck {
    listen_device_check_with(profiles, torrentd_engine::handlers::listen::sockets_at)
}

/// [`listen_device_check`], with the kernel read handed in so a test can
/// script what the sockets on an endpoint are held to, and a read that fails.
fn listen_device_check_with(
    profiles: Arc<ProfileRegistry>,
    sockets_at: impl Fn(
            std::net::SocketAddr,
        ) -> std::io::Result<Vec<torrentd_engine::handlers::listen::BoundSocket>>
        + Send
        + Sync
        + 'static,
) -> torrentd_engine::alert_loop::ListenDeviceCheck {
    Arc::new(move |id: &ProfileId, endpoint: &str| {
        let Some(iface) = profiles
            .resolve(id)
            .active()
            .and_then(|e| e.config.vpn_interface().map(str::to_owned))
        else {
            return Ok(());
        };
        let Some(at) = torrentd_engine::port_forward::parse_listen_endpoint(endpoint) else {
            return Err(format!(
                "could not read the listen endpoint {endpoint:?}, so could not check which \
                 device its sockets are held to"
            ));
        };
        let sockets = sockets_at(at).map_err(|e| {
            format!("could not list this process's sockets to check {at}'s device: {e}")
        })?;
        if sockets.is_empty() {
            warn!(
                profile_id = %id,
                endpoint = %at,
                vpn_iface = %iface,
                "found no socket of this process at a listen endpoint libtorrent reported \
                 open, so which device it is held to was not checked; it may have closed \
                 since",
            );
            return Ok(());
        }
        let unbound = listen_device_verdict(&iface, &sockets)?;
        if unbound > 0 && at.is_ipv6() {
            return Err(format!(
                "{unbound} socket(s) at the IPv6 endpoint {at} held to no device, not the \
                 tunnel device {iface}: the kernel refused the binding (SO_BINDTODEVICE needs \
                 CAP_NET_RAW before Linux 5.7), and the route probe asks only from the \
                 tunnel's IPv4 address, so nothing fences this traffic if its source rule \
                 is lost"
            ));
        }
        if unbound > 0 {
            warn!(
                profile_id = %id,
                endpoint = %at,
                vpn_iface = %iface,
                sockets = unbound,
                "a listen socket is held to no device, so its traffic follows the routing \
                 table rather than the tunnel device; the kernel refused the binding \
                 (SO_BINDTODEVICE needs CAP_NET_RAW before Linux 5.7)",
            );
        }
        Ok(())
    })
}

/// Judge one endpoint's sockets against the tunnel device `iface`: `Err`
/// naming each socket held to another device, else how many are held to
/// none.
fn listen_device_verdict(
    iface: &str,
    sockets: &[torrentd_engine::handlers::listen::BoundSocket],
) -> Result<usize, String> {
    let wrong: Vec<String> = sockets
        .iter()
        .filter_map(|s| match &s.device {
            Some(d) if d != iface => Some(format!("{} socket held to {d}", s.kind)),
            _ => None,
        })
        .collect();
    if !wrong.is_empty() {
        return Err(format!(
            "{}, not the tunnel device {iface}: its traffic leaves outside the tunnel",
            wrong.join(", ")
        ));
    }
    Ok(sockets.iter().filter(|s| s.device.is_none()).count())
}

/// The settings a profile's session is built with: the config's, plus whether
/// libtorrent posts its log alerts at all.
///
/// Those alerts are the bulk of libtorrent's alert traffic and feed only
/// `handlers::log_msg`'s debug lines, so a session subscribes to them only
/// when that target is at debug as the daemon starts. Raising the level at
/// runtime does not subscribe a running session.
fn session_settings(cfg: &Config) -> torrentd_engine::Settings {
    let mut s = cfg.libtorrent_settings();
    s.alert_logs = Some(tracing::enabled!(
        target: "torrentd_engine::handler::log",
        tracing::Level::DEBUG
    ));
    s
}

/// What the boot resume scan hands a session for one saved torrent.
///
/// Its flags are `torrentd_engine::policy`'s: the no-download guards are
/// re-asserted, and every flag that could lift upload mode is cleared from
/// whatever the resume data carried, since it may have been written by another
/// client.
fn resume_scan_params(
    profile: &ProfileConfig,
    resume: Vec<u8>,
    torrent: Option<Vec<u8>>,
) -> AddParams {
    AddParams::Resume {
        bytes: resume,
        torrent,
        save_path: None,
        flags_set: torrentd_engine::resume_flags_set(profile),
        flags_clear: torrentd_engine::resume_flags_clear(),
    }
}

/// The torrents the boot scans hand each profile's session, held so the VPN
/// monitor's fence reaches them.
///
/// The monitor runs from the moment the profiles are built, but its fence
/// pauses what the state map holds, and the state map is filled by the alert
/// loop, which starts only once both scans have run. A profile fenced
/// mid-scan would otherwise be marked down with nothing paused, and every
/// torrent the scans went on to add to it would seed over whatever route was
/// left.
#[derive(Default)]
struct ScanFence {
    profiles: std::collections::HashMap<ProfileId, ScanFenced>,
}

#[derive(Default)]
struct ScanFenced {
    /// Every handle the scans added to the profile, in order.
    handles: Vec<torrentd_engine::TorrentHandle>,
    /// How many of `handles`, from the front, have been paused.
    paused: usize,
}

impl ScanFence {
    /// Record a torrent a scan just added to `profile`, pausing it, and
    /// everything added before it, where the profile is fenced.
    fn added(
        &mut self,
        profiles: &ProfileRegistry,
        metrics: &PromSink,
        profile: &ProfileId,
        h: torrentd_engine::TorrentHandle,
    ) {
        let fenced = self.profiles.entry(profile.clone()).or_default();
        fenced.handles.push(h);
        Self::enforce(profiles, metrics, profile, fenced);
    }

    /// Pause what the scans have added to every profile fenced since.
    /// Between scan batches, so a profile whose own scan has finished is
    /// still reached, and once after both.
    fn enforce_all(&mut self, profiles: &ProfileRegistry, metrics: &PromSink) {
        for (profile, fenced) in &mut self.profiles {
            Self::enforce(profiles, metrics, profile, fenced);
        }
    }

    fn enforce(
        profiles: &ProfileRegistry,
        metrics: &PromSink,
        profile: &ProfileId,
        fenced: &mut ScanFenced,
    ) {
        if fenced.paused == fenced.handles.len() {
            return;
        }
        let Some(entry) = profiles.resolve(profile).active() else {
            return;
        };
        if entry.health().status != ProfileStatus::VpnDown {
            return;
        }
        let labels = [("profile_id", profile.as_str())];
        let mut paused = 0u64;
        for &h in &fenced.handles[fenced.paused..] {
            match entry.engine.pause_torrent(h) {
                Ok(()) => paused += 1,
                // As in the monitor's own fence: a torrent left running on a
                // fenced profile is the one thing fencing is for.
                Err(err) => {
                    error!(
                        profile_id = %profile,
                        infohash = %h.infohash,
                        error.cause = %err,
                        "could not pause a boot-scan torrent on a fenced profile",
                    );
                    metrics.inc_counter("profile_fence_pause_errors_total", &labels);
                }
            }
        }
        fenced.paused = fenced.handles.len();
        // The monitor's fence (`vpn_monitor::fence`) marks the profile
        // `VpnDown` before it walks the state map and adds what it paused to
        // the count afterwards, so this can run in between: what the scans
        // held is added, never assigned. Each writer sets the gauge from the
        // sum under the health lock, so whichever writes last writes it all.
        entry.update_health(|hh| {
            hh.paused_for_vpn += paused;
            metrics.set_gauge(
                "profile_torrents_paused_vpn_down",
                hh.paused_for_vpn as f64,
                &labels,
            );
        });
        warn!(
            profile_id = %profile,
            torrent_count = paused,
            "paused boot-scan torrents on a profile the VPN monitor fenced",
        );
    }
}

/// Run the account-isolation guard (`torrentd_engine::check_trackers`) on one
/// boot-scan add, before anything is claimed or loaded.
///
/// A torrent outside the profile's `allowed_tracker_domains` is logged and
/// counted where an API refusal is, in
/// `profile_assignment_registry_errors_total`. One whose trackers cannot be
/// read is logged only: the add would fail on the same bytes, and the caller
/// counts it as the load failure it is.
fn boot_scan_guard(
    metrics: &dyn MetricsSink,
    profile: &ProfileConfig,
    ih: &libtorrent_safe::InfoHash,
    params: &AddParams,
    scan: &'static str,
) -> Result<(), torrentd_engine::TrackerRefusal> {
    let refusal = match torrentd_engine::check_trackers(profile, params) {
        Ok(()) => return Ok(()),
        Err(refusal) => refusal,
    };
    warn!(
        profile_id = %profile.id,
        infohash = %ih,
        scan,
        error.cause = %refusal,
        "boot scan: torrent refused by the profile's allowed_tracker_domains; not loaded",
    );
    if refusal.is_guard_refusal() {
        metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", profile.id.as_str())],
        );
    }
    Err(refusal)
}

/// Where the boot torrent-dir scan re-adds a `.torrent` no resume data
/// covered: the save path recorded beside it when it was added, or `default`
/// when there is none to use.
///
/// The fallback is reported, never silent: the payload of a torrent added
/// elsewhere is not at `default`, and since downloading is forbidden the
/// torrent sits there with no data. A `.torrent` from before save paths were
/// recorded, or one dropped into the directory by hand, has none.
fn torrent_dir_save_path(
    metrics: &dyn MetricsSink,
    store: &dyn TorrentStore,
    profile: &ProfileId,
    ih: &libtorrent_safe::InfoHash,
    default: &str,
) -> String {
    let problem = match store.read_save_path(profile, ih) {
        Ok(Some(p)) if std::path::Path::new(&p).is_absolute() => return p,
        Ok(Some(p)) => format!("the recorded save path {p:?} is not absolute"),
        Ok(None) => "no save path was recorded beside its .torrent".to_owned(),
        Err(e) => format!("its recorded save path could not be read: {e}"),
    };
    warn!(
        profile_id = %profile,
        infohash = %ih,
        default_save_path = %default,
        problem = %problem,
        "torrent-dir scan: re-adding a torrent with no resume file at default_save_path; \
         if its payload is elsewhere it will find no data there",
    );
    metrics.inc_counter(
        "boot_save_path_fallbacks_total",
        &[("profile_id", profile.as_str())],
    );
    default.to_owned()
}

/// What the boot torrent-dir scan hands a session for a `.torrent` no resume
/// data covered.
fn torrent_dir_scan_params(
    profile: &ProfileConfig,
    bytes: Vec<u8>,
    save_path: String,
) -> AddParams {
    AddParams::File {
        bytes,
        save_path,
        flags: torrentd_engine::seed_flags(profile),
        trackers: Vec::new(),
    }
}

/// The production engine factory for [`build_profiles`]: a real libtorrent
/// session, restored from `state` where a host profile with DHT kept one.
fn real_engine(
    settings: &torrentd_engine::Settings,
    state: Option<Vec<u8>>,
) -> Result<Arc<dyn TorrentEngine>, libtorrent_safe::Error> {
    let session = match state {
        Some(state) => libtorrent_safe::Session::with_state(settings, &state),
        None => libtorrent_safe::Session::new(settings),
    }?;
    Ok(Arc::new(RealEngine::from_session(session)))
}

/// The engine factory `boot` hands [`build_profiles`]: [`real_engine`], and in
/// a `fault-injection` build that session with the drill's fault layer over
/// it (`http::fault_injection::FaultEngine`).
fn boot_engine(
    settings: &torrentd_engine::Settings,
    state: Option<Vec<u8>>,
) -> Result<Arc<dyn TorrentEngine>, libtorrent_safe::Error> {
    let engine = real_engine(settings, state)?;
    #[cfg(feature = "fault-injection")]
    let engine = {
        warn!(
            "fault-injection build: this session accepts injected faults over POST /v1/faults; \
             it exists for deploy/drill and must never seed for real",
        );
        crate::http::fault_injection::FaultEngine::wrap(engine)
    };
    Ok(engine)
}

/// Build every configured profile's session, in configuration order.
///
/// Safety Rule 1: a profile whose tunnel does not come up never gets a
/// session, and the others carry on; it is returned in `failed`, so it is
/// still reported. An empty `up` is the caller's to refuse.
///
/// The outside world arrives as parameters — tunnel managers through
/// `cleanup`'s factory, NAT-PMP through `forwarder`, sessions through
/// `make_engine` — so tests drive it with mocks. Before each bring-up the
/// leases of the profiles already built are renewed, bounding a lease's age
/// at boot to one profile's bring-up.
///
/// A profile `desired` holds offline has its session paused as soon as it is
/// built, before anything can give it a torrent.
///
/// `Err` only for a shutdown asked for between two profiles' bring-ups.
async fn build_profiles<F, E>(
    cfg: &Config,
    cleanup: &mut BootCleanup,
    forwarder: &dyn PortForwarder,
    metrics: &dyn MetricsSink,
    boot_shutdown: &mut broadcast::Receiver<ShutdownReason>,
    desired: &crate::profile_state::Record,
    mut make_engine: F,
) -> anyhow::Result<(Vec<ProfileEntry>, Vec<FailedProfile>)>
where
    F: FnMut(&torrentd_engine::Settings, Option<Vec<u8>>) -> Result<Arc<dyn TorrentEngine>, E>,
    E: std::fmt::Display,
{
    let mut profile_entries: Vec<ProfileEntry> = Vec::new();
    let mut failed_profiles: Vec<FailedProfile> = Vec::new();

    // Which profile holds each tunnel address: the link's IPv4 address and
    // each of its global IPv6 addresses, since a session sends from all of
    // them. A tunnel is routed by its address, so two tunnels that come up
    // with one address (every Proton WireGuard config assigns 10.2.0.2/32)
    // leave no source-address routing rule, and no kill-switch pairing, that
    // can keep one account's traffic out of the other's tunnel. Only known after
    // bring-up, since OpenVPN's address is pushed by the server.
    let mut tunnel_owner: std::collections::HashMap<IpAddr, ProfileId> =
        std::collections::HashMap::new();

    for p in &cfg.profile {
        // A shutdown asked for during a previous profile's bring-up is
        // honoured here rather than after every remaining tunnel is raised.
        if boot_shutdown.try_recv().is_ok() {
            anyhow::bail!("shutdown requested during profile bring-up");
        }

        // Keep the leases already negotiated alive across this bring-up. A
        // failure is the monitor's to retry; it renews first thing.
        for built in &profile_entries {
            let taken = ports_taken_at_boot(cfg, &profile_entries, &built.config.id);
            crate::port_forward_monitor::refresh_during_boot(built, forwarder, metrics, &taken);
        }

        match build_profile(
            p,
            session_settings(cfg),
            &cfg.session_state_path(&p.id),
            cleanup,
            forwarder,
            Held {
                tunnels: &tunnel_owner,
                ports: &ports_taken_at_boot(cfg, &profile_entries, &p.id),
            },
            desired.holds_offline(&p.id),
            &mut make_engine,
        )
        .await
        {
            Ok(entry) => {
                // Recorded only once this profile's session is built: a
                // profile that fails a later step has its tunnel taken down,
                // and still owning the address then disabled a later profile
                // over a tunnel that no longer exists.
                let (entry, v6) = entry;
                if let Some(ip) = entry.health().tunnel_ip {
                    tunnel_owner.insert(ip, p.id.clone());
                }
                for a in v6 {
                    tunnel_owner.insert(IpAddr::V6(a), p.id.clone());
                }
                profile_entries.push(entry);
            }
            Err(failed) => failed_profiles.push(*failed),
        }
    }
    Ok((profile_entries, failed_profiles))
}

/// What the profiles built so far already hold, which the next one must not
/// share.
#[derive(Clone, Copy)]
struct Held<'a> {
    /// Which profile holds each tunnel address.
    tunnels: &'a std::collections::HashMap<IpAddr, ProfileId>,
    /// Every port another profile holds or is configured with
    /// ([`ports_taken_at_boot`]).
    ports: &'a std::collections::BTreeSet<u16>,
}

/// The ports a NAT-PMP port for profile `except` must not collide with while
/// the profiles are being built: every other configured profile's static
/// ports — including profiles not built yet — and the ports already held by
/// the profiles that were (profile Safety Rule 8).
fn ports_taken_at_boot(
    cfg: &Config,
    built: &[ProfileEntry],
    except: &ProfileId,
) -> std::collections::BTreeSet<u16> {
    let mut taken = crate::port_forward_monitor::ports_held_by_others(built, except);
    for p in cfg.profile.iter().filter(|p| &p.id != except) {
        taken.extend(p.configured_listen_ports());
    }
    taken
}

/// Build one profile's session, or say why it has none.
///
/// Any tunnel this raised and then failed after is taken down before the
/// `Err` returns, so a failed profile leaves nothing standing whether or not
/// the boot around it goes on to succeed. A tunnel that came up for a profile
/// that succeeded stays tracked by `cleanup`, whose drop guard owns it until
/// `boot` disarms it.
#[allow(clippy::too_many_arguments)]
async fn build_profile<F, E>(
    p: &ProfileConfig,
    mut settings: torrentd_engine::Settings,
    session_state_path: &std::path::Path,
    cleanup: &mut BootCleanup,
    forwarder: &dyn PortForwarder,
    held: Held<'_>,
    held_offline: bool,
    make_engine: &mut F,
) -> Result<(ProfileEntry, Vec<std::net::Ipv6Addr>), Box<FailedProfile>>
where
    F: FnMut(&torrentd_engine::Settings, Option<Vec<u8>>) -> Result<Arc<dyn TorrentEngine>, E>,
    E: std::fmt::Display,
{
    macro_rules! fail_profile {
        ($reason:expr) => {
            return Err(Box::new(FailedProfile {
                config: p.clone(),
                reason: $reason,
            }))
        };
    }

    // A bring-up or teardown task that does not join (it panicked) fails that
    // profile, as every other per-profile failure does, rather than the boot.
    macro_rules! profile_task_failed {
        ($what:literal, $err:expr) => {{
            let e = $err;
            error!(
                profile_id = %p.id,
                error.cause = %e,
                concat!($what, " task did not join; profile disabled"),
            );
            fail_profile!(format!(concat!($what, " task failed: {}"), e));
        }};
    }
    // The teardowns below all run on a profile that is failing anyway, so a
    // task that does not join is reported against the profile and does not
    // replace the reason it is failing for. It does not abort the boot either:
    // the tunnel that may still be standing belongs to this profile, and
    // taking the other profiles down does not remove it.
    macro_rules! tear_down_or_warn {
        ($iface:expr) => {
            if let Err(e) = cleanup.take_down_off_worker($iface).await {
                warn!(
                    profile_id = %p.id,
                    vpn_iface = %$iface,
                    error.cause = %e,
                    "VPN teardown task did not join; the profile is disabled \
                     either way and its tunnel may still be standing",
                );
            }
        };
    }

    if let Some(ua) = &p.user_agent {
        settings.user_agent = Some(ua.clone());
        settings.handshake_client_version = Some(ua.clone());
    }
    if let Some(fp) = &p.peer_fingerprint {
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
    let mut tunnel_v6: Vec<std::net::Ipv6Addr> = Vec::new();
    let mut forwarded_port: Option<u16> = None;
    let mut forwarded_epoch: u32 = 0;
    let mut session_state: Option<Vec<u8>> = None;

    match &p.network {
        ProfileNetwork::Host {
            listen_interfaces,
            dht,
        } => {
            settings.listen_interfaces = Some(listen_interfaces.clone());
            // A paused session still runs its DHT node, so a profile left
            // offline starts with it stopped; setting it online starts it
            // (`ProfileRegistry::change_states`).
            settings.enable_dht = Some(*dht && !held_offline);
            // DHT keeps a routing table worth restoring; without DHT there
            // is nothing in session state worth the file. Restored while
            // offline too: the node starts from it once the profile is set
            // online.
            if *dht {
                session_state = load_session_state(session_state_path);
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
            // fallback. Recorded before the attempt and torn down on
            // failure — a half-up tunnel is the one failure path nothing
            // else can reach. See `BootCleanup::bring_up_tracked`.
            let brought_up = match cleanup.bring_up_tracked(vpn_type, tunnel).await {
                Ok(r) => r,
                Err(e) => profile_task_failed!("VPN bring-up", e),
            };
            let ip = match brought_up {
                Ok(ip) => ip,
                Err(e) => {
                    error!(
                        profile_id = %p.id,
                        error.cause = %e,
                        "VPN bring-up failed; profile disabled (no bare-IP fallback)",
                    );
                    fail_profile!(format!("VPN bring-up failed: {e}"));
                }
            };
            if let Some(owner) = held.tunnels.get(&ip) {
                error!(
                    profile_id = %p.id,
                    tunnel_ip = %ip,
                    other_profile_id = %owner,
                    "tunnel came up with an address another profile's tunnel already has; \
                     profile disabled, since a tunnel is routed by its address and a \
                     session on one cannot be kept out of the other account's tunnel",
                );
                let reason = format!(
                    "tunnel address {ip} is also profile {owner}'s, so neither session can \
                     be kept out of the other's tunnel"
                );
                tear_down_or_warn!(iface);
                fail_profile!(reason);
            }
            // The session listens on the device, so it also sends from each
            // global IPv6 address the link holds, and a shared one is shared
            // the same way: the kill switch accepts it on both links. An
            // address that cannot be read cannot be checked, so the profile
            // does not come up on it.
            let vpn = cleanup.manager_for(vpn_type);
            let read_iface = iface.to_string();
            let v6 = match tokio::task::spawn_blocking(move || vpn.global_ipv6(&read_iface)).await {
                Ok(Ok(v6)) => v6,
                Ok(Err(e)) => {
                    error!(
                        profile_id = %p.id,
                        vpn_iface = %iface,
                        error.cause = %e,
                        "could not read the tunnel's IPv6 addresses, so could not check that \
                         no other profile's tunnel has one; profile disabled",
                    );
                    tear_down_or_warn!(iface);
                    fail_profile!(format!(
                        "could not read tunnel {iface}'s IPv6 addresses to check none is \
                         another profile's: {e}"
                    ));
                }
                Err(e) => {
                    tear_down_or_warn!(iface);
                    profile_task_failed!("VPN IPv6 address read", e)
                }
            };
            if let Some((addr, owner)) = v6
                .iter()
                .find_map(|a| held.tunnels.get(&IpAddr::V6(*a)).map(|o| (a, o)))
            {
                error!(
                    profile_id = %p.id,
                    tunnel_ip = %addr,
                    other_profile_id = %owner,
                    "tunnel came up with an IPv6 address another profile's tunnel already \
                     has; profile disabled, since a tunnel is routed by its address and a \
                     session on one cannot be kept out of the other account's tunnel",
                );
                let reason = format!(
                    "tunnel address {addr} is also profile {owner}'s, so neither session can \
                     be kept out of the other's tunnel"
                );
                tear_down_or_warn!(iface);
                fail_profile!(reason);
            }
            tunnel_v6 = v6;

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
                        tear_down_or_warn!(iface);
                        fail_profile!("static profile has no listen_port".to_string());
                    }
                },
                PortForwardMode::Natpmp => {
                    let gw_str = p.port_forward_gateway_or_default();
                    let gateway: IpAddr = match gw_str.parse() {
                        Ok(ip) => ip,
                        Err(e) => {
                            error!(profile_id = %p.id, gateway = %gw_str, error.cause = %e, "invalid port_forward_gateway; profile disabled");
                            tear_down_or_warn!(iface);
                            fail_profile!(format!("invalid port_forward_gateway: {e}"));
                        }
                    };
                    let req = PortMapRequest {
                        gateway,
                        bind_ip: ip,
                        internal_port: PortMapRequest::INTERNAL_PORT,
                        // Nothing held yet: the gateway picks.
                        suggested_port: 0,
                        lifetime_secs: crate::port_forward_monitor::LEASE_SECS,
                    };
                    match forwarder.map(&req) {
                        Ok(m) if held.ports.contains(&m.port) => {
                            // Two gateways assign ports independently. A
                            // second profile announcing the same port is
                            // correlatable with the first by a tracker
                            // operator, whatever the addresses (Safety Rule
                            // 8), so this one does not come up on it.
                            error!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, forwarded_port = m.port, "NAT-PMP assigned a port another profile holds; profile disabled");
                            tear_down_or_warn!(iface);
                            fail_profile!(format!(
                                "NAT-PMP assigned port {}, which another profile already holds",
                                m.port
                            ));
                        }
                        Ok(m) => {
                            info!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, forwarded_port = m.port, gateway_epoch = m.epoch, "NAT-PMP port negotiated");
                            forwarded_port = Some(m.port);
                            forwarded_epoch = m.epoch;
                            m.port
                        }
                        Err(e) => {
                            error!(profile_id = %p.id, tunnel_ip = %ip, gateway = %gateway, error.cause = %e, "NAT-PMP negotiation failed at startup; profile disabled (no bare-IP fallback)");
                            tear_down_or_warn!(iface);
                            fail_profile!(format!("NAT-PMP negotiation failed: {e}"));
                        }
                    }
                }
            };

            // The listen sockets, which also carry outgoing uTP and UDP
            // tracker traffic and whose device HTTP tracker connections
            // reuse, are named by the tunnel device. Named by address,
            // libtorrent bound them to the first interface whose network
            // holds it, which is a LAN's where that network covers the
            // tunnel address, and the traffic left by the LAN where no route
            // probe looks (`bind_endpoint`). The alert loop checks each
            // socket's device as it comes up (`listen_device_check`).
            settings.listen_interfaces =
                Some(torrentd_engine::bind_endpoint(iface, effective_port));
            // Outgoing TCP is bound to the device too (`SO_BINDTODEVICE`,
            // where permitted), so it leaves by the tunnel even if the source
            // rule is lost. That narrows the window before `vpn_monitor`'s
            // route check fences the profile; it does not close it.
            settings.outgoing_interfaces = Some(iface.to_string());
            // Not configurable, by construction: there is no key on a vpn
            // profile that reaches these.
            settings.enable_dht = Some(false);
            settings.enable_lsd = Some(false);
            settings.enable_upnp = Some(false);
            settings.enable_natpmp = Some(false);
            tunnel_ip = Some(ip);
        }
    }

    match make_engine(&settings, session_state) {
        Ok(engine) => {
            // Before the session is handed to anything: the boot scans add
            // this profile's torrents next, and a profile the operator left
            // offline must not have one of them on the network for any part
            // of the boot. A session that cannot be held offline gets no
            // torrents at all.
            if held_offline {
                if let Err(e) = engine.pause_session() {
                    error!(
                        profile_id = %p.id,
                        error.cause = %e,
                        "could not hold an offline profile's session paused; profile disabled",
                    );
                    engine.close();
                    if let Some(iface) = p.vpn_interface() {
                        tear_down_or_warn!(iface);
                    }
                    fail_profile!(format!(
                        "the profile is set offline and its session could not be paused: {e}"
                    ));
                }
                info!(profile_id = %p.id, "profile is set offline; its session starts paused");
            }
            info!(
                profile_id = %p.id,
                network = if p.is_vpn() { "vpn" } else { "host" },
                tunnel_ip = tunnel_ip.map(|i| i.to_string()).unwrap_or_default(),
                dht = p.dht_enabled(),
                "profile engine up",
            );
            Ok((
                ProfileEntry::new(
                    p.clone(),
                    engine,
                    tunnel_ip,
                    forwarded_port,
                    forwarded_epoch,
                ),
                tunnel_v6,
            ))
        }
        Err(e) => {
            error!(
                profile_id = %p.id,
                error.cause = %e,
                "profile engine construction failed",
            );
            // Through the helper, like every other teardown in `boot`:
            // the same bounded exit wait, reached by one more path.
            // Hand-inlining it here meant a change to the teardown
            // contract — a timeout on the join, a retry, a metric —
            // applied through the helper missed this arm silently.
            if let Some(iface) = p.vpn_interface() {
                tear_down_or_warn!(iface);
            }
            fail_profile!(format!("session construction failed: {e}"));
        }
    }
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
            registry,
            profile_registry,
            kill_switch,
            log_handle,
            alert_loop,
            unloaded_at_boot,
            requeued_at_boot,
            // Bound, not `_`: it has to live to the end of this function,
            // past the teardown. See the field.
            instance_lock: _instance_lock,
        } = self;

        // The VPN health and port-forward monitors are not here: `boot`
        // starts both as soon as the profiles are built.

        // The kill switch was checked once, at install. Anything that flushes
        // the ruleset afterwards — an `nft flush ruleset` from a firewall
        // reload, another service replacing the tables — removed the backstop
        // with nothing noticing. The watch compares it with what was rendered,
        // and fences every vpn profile while it is not in force.
        let kill_switch_active = kill_switch.is_some();
        if let Some(installed) = kill_switch {
            let fence = Arc::new(crate::vpn_monitor::KillSwitchFence::new(
                profile_registry.clone(),
                state.clone(),
                metrics.clone(),
                crate::vpn_monitor::host_prober(),
            ));
            spawn_supervised(
                "kill_switch_watch",
                metrics.clone(),
                crate::vpn::killswitch::watch(
                    installed,
                    fence,
                    metrics.clone(),
                    shutdown_tx.subscribe(),
                ),
            );
        }

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
            crate::pool_apply::spawn_resume_unfinished(
                pool,
                source.clone(),
                state.clone(),
                Arc::clone(&work),
                loaded,
            );
        }

        // Verify queue: admits a bounded number of adopt-time re-hashes so a
        // bulk adopt cannot starve whatever is already seeding.
        if let Some(pool) = pool.clone() {
            spawn_supervised(
                "verify_queue",
                metrics.clone(),
                crate::pool_service::run_verify_queue(
                    pool,
                    source.clone(),
                    state.clone(),
                    metrics.clone(),
                    profile_registry.clone(),
                    registry.clone(),
                    shutdown_tx.subscribe(),
                ),
            );
        }

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
            alert_heartbeat: alert_loop.heartbeat(),
            default_save_path: cfg.default_save_path.clone(),
            torrent_dir: cfg.torrent_dir.clone(),
            reload_tx: Some(reload_tx.clone()),
            trusted_proxies: trusted_proxies.clone(),
            allowed_hosts: crate::http::security::HostAllowlist::parse(&cfg.allowed_hosts)
                .expect("validated at startup"),
            unloaded_at_boot: Arc::new(parking_lot::Mutex::new(unloaded_at_boot)),
            shutdown: shutdown_tx.clone(),
            work: Arc::clone(&work),
            events: Arc::default(),
            tunnel_probe: crate::vpn_monitor::host_prober(),
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
            .and_then(|openapi| {
                http::service(
                    app_state,
                    http::OpenApiJson(Arc::new(bytes::Bytes::from(openapi))),
                )
                .map_err(|e| anyhow::anyhow!("build the HTTP router: {e}"))
            })
            .map_err(|e| error!(error.cause = %e, "build the HTTP API"))
            .ok();
        let http_listen = cfg.http_listen;

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
        // signalled shutdown runs, exiting 70.
        let listener = match tokio::net::TcpListener::bind(http_listen).await {
            Ok(l) => Some(l),
            Err(e) => {
                error!(addr = %http_listen, error.cause = %e, "bind HTTP listener");
                None
            }
        };
        let mut exit_code = match listener.zip(app) {
            Some((listener, app)) => {
                serve_until_shutdown(
                    listener,
                    app,
                    http_listen,
                    unauthenticated_posture(&cfg),
                    &shutdown_tx,
                    shutdown_rx,
                    &alert_loop,
                    &work,
                )
                .await
            }
            None => 70,
        };
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
        teardown_network(engines, tunnels, || {
            if kill_switch_active {
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

/// Wait up to `bound` for pool work still in flight, returning whether none
/// is left. Past the bound the teardown goes on around the work, warning.
async fn wait_for_pool_work(work: &crate::app_state::WorkGate, bound: std::time::Duration) -> bool {
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

/// Serve the API on a bound listener until a shutdown is signalled, returning
/// the exit code the server's own outcome implies.
///
/// Split out of `run_until_signal` so that function has no early return
/// between `boot`'s `disarm` and its teardown: a failure to bind skips this
/// and nothing else.
#[allow(clippy::too_many_arguments)]
async fn serve_until_shutdown(
    listener: tokio::net::TcpListener,
    app: kynos::router::service::Service<http::ctx::AppCtx>,
    http_listen: std::net::SocketAddr,
    posture: Option<String>,
    shutdown_tx: &broadcast::Sender<ShutdownReason>,
    mut shutdown_rx: broadcast::Receiver<ShutdownReason>,
    alert_loop: &torrentd_engine::AlertLoopHandle,
    work: &Arc<crate::app_state::WorkGate>,
) -> i32 {
    info!(addr = %http_listen, "HTTP server listening");
    if let Some(posture) = posture {
        warn!(target: "torrentd::auth", addr = %http_listen, "{posture}");
    }

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

    // kynos records every connection's peer address, which is what lets the
    // session throttle and the auth failure log see who was calling.
    //
    // The limits are set here rather than left to kynos' defaults, which are
    // sized for a public web service: 10,000 connections and a 30 s header
    // timeout. This is a single-operator control plane sharing one descriptor
    // limit (`LimitNOFILE`) with libtorrent, whose peer connections and file
    // pool are what the limit is for; see `HTTP_MAX_CONNECTIONS`.
    let work = Arc::clone(work);
    let server = kynos::server::Server::new(app)
        .listener(listener)
        .max_connections(HTTP_MAX_CONNECTIONS)
        .http1(
            kynos::server::protocol::Http1Config::default()
                .header_read_timeout(Some(HTTP_HEADER_READ_TIMEOUT)),
        )
        .http2(kynos::server::protocol::Http2Config::default().keep_alive(Some(HTTP2_KEEP_ALIVE)))
        .graceful_shutdown(kynos::server::shutdown::Shutdown::on(async move {
            let _ = shutdown_rx.recv().await;
            // Latched first, so an apply still running stops at its next step
            // and a `/v1/events` stream opened from here on ends at once.
            work.cancel();
            sd_notify::stopping();
            sd_notify::status("draining HTTP requests");
        }))
        // Explicit rather than kynos's 25 s default: the drain is one stage
        // of a stop budget (`deploy/torrentd.service` `TimeoutStopSec`) that
        // the pool-work wait, the resume drain and the teardown share.
        .shutdown_timeout(HTTP_DRAIN_TIMEOUT)
        .serve();

    http_exit_code(server.await)
}

/// The exit code the HTTP server's outcome implies.
///
/// A drain that ran out of time is not a failure of the daemon: a client
/// holding a request open past the bound — a slow scan, a stream that did not
/// notice the shutdown — is cut off, and everything after the drain still
/// runs. Exiting 70 for it made `Restart=on-failure` restart a daemon that was
/// asked to stop.
fn http_exit_code(outcome: kynos::Result<()>) -> i32 {
    match outcome {
        Ok(()) => 0,
        Err(kynos::Error::Server(kynos::server::error::ServerError::ShutdownTimeout {
            timeout,
        })) => {
            warn!(
                timeout_secs = timeout.as_secs(),
                "HTTP drain timed out; the requests still open were cut off",
            );
            0
        }
        Err(e) => {
            error!(error.cause = %e, "HTTP server exited with error");
            70
        }
    }
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
async fn teardown_network<K>(
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

/// `s` as one POSIX shell word: single-quoted, with each `'` closed, escaped
/// and reopened. The registry refusal prints a command to paste, and a state
/// directory holding a space or a shell metacharacter must not break it.
fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Read the persisted DHT/session-state blob, or `None` if absent/empty.
fn load_session_state(path: &std::path::Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(b) if !b.is_empty() => Some(b),
        _ => None,
    }
}

/// What one profile's boot scans could not load, by the `source` label of
/// `boot_torrent_load_failures`.
#[derive(Clone, Copy, Debug, Default)]
struct BootLoadFailures {
    /// A resume file that read but libtorrent refused to add.
    resume_add: u64,
    /// A `.torrent` that could not be read to re-attach metadata.
    torrent_read: u64,
    /// A torrent-dir `.torrent` libtorrent refused to add.
    torrent_dir_add: u64,
    /// A resume file the scan could not read at all, skipped.
    resume_file: u64,
    /// A torrent-dir `.torrent` the scan could not read at all, skipped.
    torrent_file: u64,
}

/// What a run's exit left behind that no scrape of that run could see.
///
/// Both halves happen as the process is leaving: a metric set there is gone
/// before anything scrapes it, so an alert on it could never fire. The exiting
/// run writes this file and the next boot re-exports it as the
/// `last_shutdown_*` gauges, then deletes it — a run that dies without
/// writing one leaves the next boot reporting zero rather than a stale value
/// from an older exit.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ShutdownReport {
    /// Resume saves the shutdown drain's deadline left unsaved.
    unsaved_resumes: u64,
    /// The kill switch could not be removed on the way out.
    kill_switch_removal_failed: bool,
}

/// `<state_dir>/last_shutdown.json`.
fn shutdown_report_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join("last_shutdown.json")
}

/// Persist `report` for the next boot. A failure is logged and otherwise
/// ignored: the process is exiting, and the journal line is all that is left.
fn write_shutdown_report(state_dir: &std::path::Path, report: &ShutdownReport) {
    let bytes = serde_json::to_vec(report).expect("a plain struct serializes");
    if let Err(e) = write_atomic(&shutdown_report_path(state_dir), &bytes) {
        warn!(
            path = %shutdown_report_path(state_dir).display(),
            error.cause = %e,
            "could not persist the shutdown report; the next boot will report zero",
        );
    }
}

/// Read and delete the previous run's report. Absent, unreadable or
/// malformed all read as the default, the last two with a warning.
fn take_shutdown_report(state_dir: &std::path::Path) -> ShutdownReport {
    let path = shutdown_report_path(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ShutdownReport::default(),
        Err(e) => {
            warn!(path = %path.display(), error.cause = %e, "could not read the shutdown report");
            return ShutdownReport::default();
        }
    };
    let report = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        warn!(path = %path.display(), error.cause = %e, "malformed shutdown report; ignoring it");
        ShutdownReport::default()
    });
    if let Err(e) = std::fs::remove_file(&path) {
        warn!(path = %path.display(), error.cause = %e, "could not remove the shutdown report");
    }
    report
}

/// Record the outcome of removing the kill switch on a clean shutdown.
///
/// On success `kill_switch_active` drops to 0. On failure it stays 1, because
/// the table is still installed and still confines the uid, and the report
/// carries the failure to the next boot.
fn finish_kill_switch_removal(
    outcome: std::io::Result<()>,
    metrics: &PromSink,
    report: &mut ShutdownReport,
) {
    match outcome {
        Ok(()) => {
            info!("network kill switch removed");
            metrics.set_gauge("kill_switch_active", 0.0, &[]);
        }
        Err(e) => {
            error!(
                error.cause = %e,
                table = %crate::vpn::killswitch::own_table_name(),
                "failed to remove network kill switch; the daemon's uid stays \
                 confined to the tunnels until the table is removed \
                 (nft delete table inet <table>) or a kill-switch boot replaces it",
            );
            report.kill_switch_removal_failed = true;
        }
    }
}

/// Record the outcome of removing the kill switch after a failed boot. The
/// process is on its way out, so a failure goes to the report the next boot
/// reads.
fn finish_boot_kill_switch_removal(run_dir: &std::path::Path, outcome: std::io::Result<()>) {
    match outcome {
        Ok(()) => info!("boot failed: network kill switch removed"),
        Err(e) => {
            warn!(error.cause = %e, "boot failed: could not remove kill switch");
            write_shutdown_report(
                run_dir,
                &ShutdownReport {
                    unsaved_resumes: 0,
                    kill_switch_removal_failed: true,
                },
            );
        }
    }
}

/// What a boot with `network_kill_switch = false` found of an earlier run's
/// kill-switch table. See [`remove_stale_kill_switch`].
#[derive(Debug, PartialEq, Eq)]
enum StaleKillSwitch {
    /// `nft` is not installed, so no table can exist and none was asked for.
    NoNft,
    /// No table was there.
    Absent,
    /// A table was there and is gone.
    Removed,
    /// The tables could not be listed, or the one listed would not delete.
    Failed,
}

/// Remove a kill-switch table this boot did not install and will not use.
///
/// The table outlives an unclean exit (`kill -9`, an OOM kill, a panic
/// abort), and with the kill switch now off it keeps dropping every packet
/// the daemon's uid sends outside a tunnel: tracker requests time out and
/// host profiles go dark with nothing in the log to say why. Neither outcome
/// stops the boot. The operator asked for no kill switch, and a table that
/// could not be removed is reported with the command that removes it.
///
/// A listing that fails is logged at `info` rather than `warn`: without
/// `CAP_NET_ADMIN`, which a host-only deployment does not hold, it fails on
/// every boot, and such a daemon could not have installed a table either.
///
/// Only this uid's table is this boot's to remove
/// ([`crate::vpn::killswitch::remove_table`]): another uid's is another
/// daemon's kill switch, in force in the same network namespace.
fn remove_stale_kill_switch(
    nft_available: bool,
    table: &str,
    remove: impl FnOnce() -> std::io::Result<bool>,
) -> StaleKillSwitch {
    if !nft_available {
        return StaleKillSwitch::NoNft;
    }
    match remove() {
        Ok(false) => StaleKillSwitch::Absent,
        Ok(true) => {
            warn!(
                table,
                "removed a stale network kill-switch table left by an earlier run that did not \
                 exit cleanly; with network_kill_switch = false it would have dropped this \
                 daemon's traffic outside the tunnels",
            );
            StaleKillSwitch::Removed
        }
        Err(e) => {
            info!(
                table,
                error.cause = %e,
                "could not check for, or remove, a network kill-switch table left by an earlier \
                 run. If one is installed it drops this daemon's traffic outside the tunnels; \
                 remove it with `nft delete table inet <table>`",
            );
            StaleKillSwitch::Failed
        }
    }
}

/// Export the previous run's [`ShutdownReport`] and warn about what it holds.
fn export_shutdown_report(metrics: &PromSink, report: &ShutdownReport) {
    if report.unsaved_resumes > 0 {
        warn!(
            pending_resume_count = report.unsaved_resumes,
            "the previous run's shutdown left resume data unsaved; those torrents resumed from \
             older state",
        );
    }
    if report.kill_switch_removal_failed {
        warn!(
            table = %crate::vpn::killswitch::own_table_name(),
            "the previous run could not remove the network kill switch on its way out; a boot \
             with network_kill_switch replaces it and one without removes it, or remove it with \
             `nft delete table inet <table>`",
        );
    }
    metrics.set_gauge(
        "last_shutdown_unsaved_resumes",
        report.unsaved_resumes as f64,
        &[],
    );
    metrics.set_gauge(
        "last_shutdown_kill_switch_removal_failed",
        if report.kill_switch_removal_failed {
            1.0
        } else {
            0.0
        },
        &[],
    );
}

/// Spawn a long-running task under `task_up{task}`: 1 from now, 0 once the
/// task returns or panics.
///
/// Every background task was spawned with its handle discarded, so a monitor
/// that panicked left the daemon healthy by every signal it has — `/healthz`
/// reads the alert loop only — with its tunnels unwatched. A task that returns
/// is also logged: each of these returns only on shutdown, and at shutdown
/// the gauge going to 0 is harmless.
fn spawn_supervised<F>(task: &'static str, metrics: Arc<PromSink>, fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let labels = [("task", task)];
    metrics.set_gauge("task_up", 1.0, &labels);
    let handle = tokio::spawn(fut);
    tokio::spawn(async move {
        match handle.await {
            Ok(()) => info!(task, "background task exited"),
            Err(e) => error!(
                task,
                error.cause = %e,
                "background task panicked; what it watched is no longer watched",
            ),
        }
        metrics.set_gauge("task_up", 0.0, &[("task", task)]);
    });
}

/// What a daemon running without `[auth]` says about itself at boot.
///
/// `None` when `[auth]` is configured. Otherwise the operator opted into
/// authenticating nothing — a legitimate posture behind a proxy that does its
/// own access control, and one a running daemon stated nowhere: no boot line,
/// no `/healthz` field, and an `sd_notify` status of "seeding; API on {addr}"
/// either way. Somebody inheriting a host could not establish the posture from
/// the journal, which is the first place they look.
fn unauthenticated_posture(cfg: &Config) -> Option<String> {
    if cfg.auth.is_some() {
        return None;
    }
    Some(format!(
        "running unauthenticated: allow_unauthenticated = true and no [auth] section, so \
         every route on {} — including every mutating one — is open to anything that can \
         reach it. Access control belongs to whatever sits in front of this daemon.",
        cfg.http_listen,
    ))
}

#[cfg(test)]
mod shutdown_report_tests {
    use super::*;

    fn rendered(metrics: &PromSink) -> String {
        String::from_utf8(metrics.render()).unwrap()
    }

    fn failed() -> std::io::Result<()> {
        Err(std::io::Error::other("nft: permission denied"))
    }

    #[test]
    fn a_config_refusal_is_told_apart_from_other_boot_failures() {
        let e = refused(anyhow::anyhow!("host profile beside network_kill_switch"));
        assert!(is_config_refusal(&e));
        assert!(
            is_config_refusal(&e.context("boot")),
            "survives more context"
        );
        assert!(format!("{:#}", refused(anyhow::anyhow!("why"))).ends_with(": why"));
        assert!(!is_config_refusal(&anyhow::anyhow!("no profile came up")));
    }

    #[test]
    fn the_kill_switch_s_root_refusal_is_the_configuration_s_and_an_nft_failure_is_not() {
        // As root the kill switch is refused whatever the host does, so a
        // restart only raises every tunnel again to be refused again: it
        // exits 78, which the unit does not restart. An `nft` failure might
        // pass on the next try, so it keeps exiting 70.
        assert!(kill_switch_uid_refusal(1000).is_none());
        let pre_flight = kill_switch_uid_refusal(0).expect("uid 0 is refused");
        assert!(is_config_refusal(&pre_flight));
        assert!(format!("{pre_flight:#}").contains("non-root user"));

        let enable = crate::vpn::killswitch::refusal_for_uid(0).unwrap();
        let e = kill_switch_enable_failure(enable);
        assert!(is_config_refusal(&e), "got: {e:#}");
        assert!(format!("{e:#}").contains("install nftables kill switch"));

        let e = kill_switch_enable_failure(failed().unwrap_err());
        assert!(!is_config_refusal(&e), "got: {e:#}");
    }

    #[test]
    fn the_descriptor_budget_counts_every_session_and_the_api() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::minimal_for_tests(dir.path(), false);
        cfg.connections_limit = Some(1_000);
        cfg.file_pool_size = Some(100);
        cfg.profile = vec![
            crate::profile_registry::test_entry("a", ProfileStatus::Active).config,
            crate::profile_registry::test_entry("b", ProfileStatus::Active).config,
        ];
        assert_eq!(descriptors_needed(&cfg), 2 * 1_100 + 256);
        // And the shipped unit's LimitNOFILE covers a one-profile default.
        cfg.connections_limit = None;
        cfg.file_pool_size = None;
        cfg.profile.truncate(1);
        assert!(descriptors_needed(&cfg) <= 65_536);
        assert!(nofile_soft_limit().is_some_and(|n| n > 0));
    }

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

    /// The labels of every `IncCounter` of `name` the sink recorded.
    fn counted(sink: &torrentd_engine::RecordingSink, name: &str) -> Vec<Vec<(String, String)>> {
        sink.calls()
            .into_iter()
            .filter_map(|c| match c {
                torrentd_engine::metrics::MetricCall::IncCounter { name: n, labels }
                    if n == name =>
                {
                    Some(labels)
                }
                _ => None,
            })
            .collect()
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

    /// The torrent-dir scan re-adds a `.torrent` whose resume file is gone at
    /// the save path recorded beside it, and falls back to
    /// `default_save_path` only when there is no usable one, warning and
    /// counting each time.
    #[test]
    fn the_torrent_dir_scan_uses_the_recorded_save_path_and_reports_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let p = ProfileId::new("p");
        let store = FsTorrentStore::new(dir.path().join("torrents"));
        let sink = torrentd_engine::RecordingSink::new();

        // Recorded at add: used, and nothing is reported.
        let recorded = libtorrent_safe::InfoHash([0x31; 20]);
        store
            .write_save_path(&p, &recorded, "/data/torrents/movies/X")
            .unwrap();
        assert_eq!(
            torrent_dir_save_path(&sink, &store, &p, &recorded, "/data/torrents"),
            "/data/torrents/movies/X",
        );
        assert!(counted(&sink, "boot_save_path_fallbacks_total").is_empty());

        // Missing, relative, or unreadable: default_save_path, each counted.
        let missing = libtorrent_safe::InfoHash([0x32; 20]);
        let relative = libtorrent_safe::InfoHash([0x33; 20]);
        store.write_save_path(&p, &relative, "movies/X").unwrap();
        let garbled = libtorrent_safe::InfoHash([0x34; 20]);
        store.write_save_path(&p, &garbled, "").unwrap();
        std::fs::write(store.save_path_path_for(&p, &garbled), [0xff, 0xfe]).unwrap();
        for ih in [missing, relative, garbled] {
            assert_eq!(
                torrent_dir_save_path(&sink, &store, &p, &ih, "/data/torrents"),
                "/data/torrents",
                "{ih}",
            );
        }
        assert_eq!(
            counted(&sink, "boot_save_path_fallbacks_total"),
            vec![vec![("profile_id".to_string(), p.as_str().to_string())]; 3],
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

    #[test]
    fn an_http_drain_that_times_out_exits_zero() {
        // A client holding a request past the drain bound is cut off; the
        // daemon was still asked to stop, and 70 would have had
        // `Restart=on-failure` start it again.
        let timed_out = Err(kynos::Error::Server(
            kynos::server::error::ServerError::ShutdownTimeout {
                timeout: HTTP_DRAIN_TIMEOUT,
            },
        ));
        assert_eq!(http_exit_code(timed_out), 0);
        assert_eq!(http_exit_code(Ok(())), 0);
        let broken = Err(kynos::Error::Server(
            kynos::server::error::ServerError::NoListeners,
        ));
        assert_eq!(http_exit_code(broken), 70, "a real server failure stays 70");
    }

    #[test]
    fn a_written_report_is_read_back_once_and_then_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let report = ShutdownReport {
            unsaved_resumes: 3,
            kill_switch_removal_failed: true,
        };
        write_shutdown_report(dir.path(), &report);
        assert_eq!(take_shutdown_report(dir.path()), report);
        assert!(
            !shutdown_report_path(dir.path()).exists(),
            "the report is deleted once read"
        );
        // A second boot, with no exit in between that wrote one, reports zero.
        assert_eq!(take_shutdown_report(dir.path()), ShutdownReport::default());
    }

    #[test]
    fn a_malformed_report_reads_as_zero_and_is_still_deleted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(shutdown_report_path(dir.path()), b"{not json").unwrap();
        assert_eq!(take_shutdown_report(dir.path()), ShutdownReport::default());
        assert!(!shutdown_report_path(dir.path()).exists());
    }

    #[test]
    fn a_non_zero_report_is_exported_as_non_zero_gauges() {
        let metrics = PromSink::new();
        export_shutdown_report(
            &metrics,
            &ShutdownReport {
                unsaved_resumes: 7,
                kill_switch_removal_failed: true,
            },
        );
        let text = rendered(&metrics);
        assert!(
            text.contains("torrentd_last_shutdown_unsaved_resumes 7"),
            "{text}"
        );
        assert!(
            text.contains("torrentd_last_shutdown_kill_switch_removal_failed 1"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_kill_switch_removal_leaves_it_active_and_reports_it() {
        let metrics = PromSink::new();
        metrics.set_gauge("kill_switch_active", 1.0, &[]);
        let mut report = ShutdownReport::default();
        finish_kill_switch_removal(failed(), &metrics, &mut report);
        assert!(report.kill_switch_removal_failed);
        let text = rendered(&metrics);
        assert!(text.contains("torrentd_kill_switch_active 1"), "{text}");
    }

    #[test]
    fn a_removed_kill_switch_reads_inactive_and_reports_nothing() {
        let metrics = PromSink::new();
        metrics.set_gauge("kill_switch_active", 1.0, &[]);
        let mut report = ShutdownReport::default();
        finish_kill_switch_removal(Ok(()), &metrics, &mut report);
        assert!(!report.kill_switch_removal_failed);
        let text = rendered(&metrics);
        assert!(text.contains("torrentd_kill_switch_active 0"), "{text}");
    }

    #[test]
    fn a_failed_boot_that_cannot_remove_the_kill_switch_leaves_a_report() {
        let dir = tempfile::tempdir().unwrap();
        finish_boot_kill_switch_removal(dir.path(), failed());
        assert_eq!(
            take_shutdown_report(dir.path()),
            ShutdownReport {
                unsaved_resumes: 0,
                kill_switch_removal_failed: true,
            }
        );

        finish_boot_kill_switch_removal(dir.path(), Ok(()));
        assert!(
            !shutdown_report_path(dir.path()).exists(),
            "a removal that worked writes no report"
        );
    }

    /// The scenario in #105: an unclean exit left the table, and the operator
    /// turned the kill switch off. The boot removes it and says so, and
    /// neither a failure nor a host without `nft` stops the boot.
    #[test]
    fn a_boot_with_the_kill_switch_off_removes_a_stale_table() {
        const T: &str = "torrentd_ks_998";
        assert_eq!(
            remove_stale_kill_switch(true, T, || Ok(true)),
            StaleKillSwitch::Removed
        );
        assert_eq!(
            remove_stale_kill_switch(true, T, || Ok(false)),
            StaleKillSwitch::Absent
        );
        assert_eq!(
            remove_stale_kill_switch(true, T, || failed().map(|()| true)),
            StaleKillSwitch::Failed
        );
        assert_eq!(
            remove_stale_kill_switch(false, T, || panic!("no nft, so nothing is asked of it")),
            StaleKillSwitch::NoNft
        );
    }

    /// #168: an OpenVPN daemon with the kill switch off boots beside a
    /// WireGuard daemon whose kill switch is in force under another uid. Its
    /// boot finds that table listed and leaves it standing; only its own uid's
    /// stale table is removed.
    #[test]
    fn a_boot_with_the_kill_switch_off_leaves_another_daemons_table() {
        let others = || Ok("table inet torrentd_ks_998\n".to_string());
        assert_eq!(
            remove_stale_kill_switch(true, "torrentd_ks_1000", || {
                crate::vpn::killswitch::disable_with(
                    1000,
                    others,
                    |_| panic!("no legacy table is listed"),
                    |name| panic!("{name} is the other daemon's kill switch, and stays"),
                )
            }),
            StaleKillSwitch::Absent
        );

        let deleted = std::cell::RefCell::new(Vec::new());
        assert_eq!(
            remove_stale_kill_switch(true, "torrentd_ks_1000", || {
                crate::vpn::killswitch::disable_with(
                    1000,
                    || Ok("table inet torrentd_ks_998\ntable inet torrentd_ks_1000\n".into()),
                    |_| panic!("no legacy table is listed"),
                    |name| {
                        deleted.borrow_mut().push(name.to_string());
                        Ok(())
                    },
                )
            }),
            StaleKillSwitch::Removed
        );
        assert_eq!(*deleted.borrow(), ["torrentd_ks_1000"]);
    }
}

#[cfg(test)]
mod posture_tests {
    use super::*;

    /// Top-level keys only. `[[profile]]` is a TOML table, so anything a test
    /// appends has to land before it.
    const TOP_LEVEL: &str = r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
"#;

    const ONE_HOST_PROFILE: &str = r#"
[[profile]]
id = "public"
network = "host"
listen_interfaces = "0.0.0.0:6881"
"#;

    /// A config with `extra` appended to the top-level keys.
    fn cfg_from(extra: &str) -> Config {
        toml::from_str(&format!("{TOP_LEVEL}{extra}\n{ONE_HOST_PROFILE}")).expect("config parses")
    }

    #[test]
    fn an_unauthenticated_daemon_says_so_and_names_its_bind() {
        // The property: the posture is legible from the journal. A host
        // inherited from someone else answers "does this authenticate?" with
        // a log line, rather than with a config file the reader has to find
        // and a default they have to know.
        let line = unauthenticated_posture(&cfg_from("allow_unauthenticated = true"))
            .expect("a daemon with no [auth] states its posture");
        assert!(line.contains("unauthenticated"), "got: {line}");
        assert!(line.contains("127.0.0.1:8080"), "it names the bind: {line}");
    }

    #[test]
    fn a_daemon_with_auth_says_nothing() {
        // A warning that fires either way is one nobody reads.
        let hash = crate::auth::hash_password("hunter2").unwrap();
        let cfg = cfg_from(&format!("[auth]\npassword_hash = \"{hash}\""));
        assert_eq!(unauthenticated_posture(&cfg), None);
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

    fn socket(
        kind: &'static str,
        device: Option<&str>,
    ) -> torrentd_engine::handlers::listen::BoundSocket {
        torrentd_engine::handlers::listen::BoundSocket {
            kind,
            device: device.map(str::to_owned),
        }
    }

    /// A registry of one vpn profile (`acct_a`, tunnel `wg-acct_a`) and one
    /// host profile (`public`), the vpn one on `engine`.
    fn device_check_registry(engine: Arc<torrentd_engine::MockEngine>) -> Arc<ProfileRegistry> {
        use crate::profile_registry::test_host_entry;
        use crate::profile_registry::test_vpn_entry;
        use crate::profile_registry::ProfileEntry;

        let vpn = test_vpn_entry("acct_a", ProfileStatus::Active).config;
        let tunnel_ip = Some(std::net::IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        Arc::new(ProfileRegistry::new(vec![
            ProfileEntry::new(vpn, engine, tunnel_ip, None, 0),
            test_host_entry("public"),
        ]))
    }

    /// A kernel read that answers `sockets` for every endpoint, noting each
    /// endpoint it is asked about.
    #[allow(clippy::type_complexity)]
    fn scripted_sockets(
        sockets: std::io::Result<Vec<torrentd_engine::handlers::listen::BoundSocket>>,
    ) -> (
        Arc<parking_lot::Mutex<Vec<std::net::SocketAddr>>>,
        impl Fn(
                std::net::SocketAddr,
            ) -> std::io::Result<Vec<torrentd_engine::handlers::listen::BoundSocket>>
            + Send
            + Sync
            + 'static,
    ) {
        let asked: Arc<parking_lot::Mutex<Vec<std::net::SocketAddr>>> = Arc::default();
        let sockets = parking_lot::Mutex::new(sockets);
        let read = {
            let asked = Arc::clone(&asked);
            move |at| {
                asked.lock().push(at);
                match &*sockets.lock() {
                    Ok(s) => Ok(s.clone()),
                    Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
                }
            }
        };
        (asked, read)
    }

    /// The four answers the hook gives besides a wrong device: a host
    /// profile is not checked at all, an endpoint it cannot read and a
    /// kernel read that fails are each fatal, since the check could not run,
    /// and a socket held to no device is warned about and passes.
    #[test]
    fn the_listen_device_check_skips_host_profiles_and_refuses_what_it_cannot_check() {
        let engine = Arc::new(torrentd_engine::MockEngine::new());
        let profiles = device_check_registry(engine);
        let acct_a = ProfileId::new("acct_a");

        let (asked, read) = scripted_sockets(Ok(vec![socket("tcp", Some("eth0"))]));
        let check = listen_device_check_with(profiles.clone(), read);
        assert_eq!(check(&ProfileId::new("public"), "0.0.0.0:6881"), Ok(()));
        assert_eq!(
            check(&ProfileId::new("nobody"), "10.9.9.9:6881"),
            Ok(()),
            "an id the registry does not hold has no tunnel to check against"
        );
        assert!(
            asked.lock().is_empty(),
            "a profile with no tunnel is never read"
        );

        let err = check(&acct_a, "not an endpoint").unwrap_err();
        assert!(
            err.contains("could not read the listen endpoint \"not an endpoint\""),
            "{err}"
        );
        assert!(asked.lock().is_empty());

        let err = check(&acct_a, "10.2.0.2:6881").unwrap_err();
        assert!(
            err.contains("tcp socket held to eth0, not the tunnel device wg-acct_a"),
            "{err}"
        );
        assert_eq!(*asked.lock(), vec!["10.2.0.2:6881".parse().unwrap()]);

        let (_, read) = scripted_sockets(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no /proc",
        )));
        let err =
            listen_device_check_with(profiles.clone(), read)(&acct_a, "10.2.0.2:6881").unwrap_err();
        assert!(
            err.contains("could not list this process's sockets to check 10.2.0.2:6881's device")
                && err.contains("no /proc"),
            "{err}"
        );

        let log = crate::tracing_init::Buf::default();
        let (_handle, subscriber) =
            crate::tracing_init::for_tests(crate::config::LogLevel::Info, log.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let (_, read) = scripted_sockets(Ok(vec![
            socket("tcp", Some("wg-acct_a")),
            socket("udp", None),
        ]));
        let check = listen_device_check_with(profiles.clone(), read);
        assert_eq!(
            check(&acct_a, "10.2.0.2:6881"),
            Ok(()),
            "a socket held to no device follows the routing table, which the route probe \
             watches"
        );
        let text = log.text();
        assert!(
            text.contains("\"level\":\"WARN\"")
                && text.contains("a listen socket is held to no device")
                && text.contains("\"sockets\":1"),
            "{text}"
        );
        let err = check(&acct_a, "[2001:db8::2]:6881").unwrap_err();
        assert!(
            err.contains("1 socket(s) at the IPv6 endpoint [2001:db8::2]:6881 held to no device")
                && err.contains("asks only from the tunnel's IPv4 address"),
            "an unbound IPv6 socket is on a path the route probe never asks about: {err}"
        );

        let (_, read) = scripted_sockets(Ok(Vec::new()));
        assert_eq!(
            listen_device_check_with(profiles, read)(&acct_a, "10.2.0.2:6883"),
            Ok(()),
            "an endpoint with no socket left on it has nothing to check"
        );
        let text = log.text();
        assert!(
            text.contains("found no socket of this process at a listen endpoint")
                && text.contains("10.2.0.2:6883"),
            "{text}"
        );
    }

    /// The hook as `boot` wires it into the alert loop: a vpn session's
    /// listen socket on another device stops the loop as a fatal listen
    /// failure, with the session's listen sockets closed and the session
    /// paused first, and a host session's listen alert is let through.
    #[test]
    fn a_vpn_listen_socket_off_its_tunnel_stops_the_alert_loop_through_the_hook() {
        use libtorrent_safe::alert::AlertHeader;
        use torrentd_engine::state::StateMap;
        use torrentd_engine::AlertKind;
        use torrentd_engine::ProfileSource;
        use torrentd_engine::RecordedCall;

        let succeeded = |endpoint: &str| torrentd_engine::Alert::ListenSucceeded {
            hdr: AlertHeader {
                kind: AlertKind::ListenSucceeded,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            endpoint: endpoint.into(),
        };
        let vpn = Arc::new(torrentd_engine::MockEngine::new());
        let host = Arc::new(torrentd_engine::MockEngine::new());
        host.push_alert(succeeded("0.0.0.0:6881"));
        vpn.push_alert(succeeded("10.2.0.2:6881"));
        let profiles = device_check_registry(vpn.clone());
        let source: Arc<dyn torrentd_engine::AlertSource> = Arc::new(ProfileSource::new(vec![
            (
                ProfileId::new("public"),
                host.clone() as Arc<dyn TorrentEngine>,
            ),
            (
                ProfileId::new("acct_a"),
                vpn.clone() as Arc<dyn TorrentEngine>,
            ),
        ]));
        let (asked, read) = scripted_sockets(Ok(vec![socket("udp", Some("eth0"))]));
        let seen: Arc<parking_lot::Mutex<Vec<ShutdownReason>>> = Arc::default();
        let handle = AlertLoopBuilder::new(
            source,
            Arc::new(StateMap::new()),
            Arc::new(torrentd_engine::resume_store::MemoryResumeStore::new()),
            Arc::new(torrentd_engine::torrent_store::MemoryTorrentStore::new()),
            Arc::new(torrentd_engine::NoopSink),
            Arc::new(SystemClock),
        )
        .fatal_listen_failure(false)
        .shutdown_deadline(std::time::Duration::from_millis(200))
        .on_fatal({
            let seen = Arc::clone(&seen);
            Arc::new(move |r| seen.lock().push(r)) as torrentd_engine::FatalCallback
        })
        .listen_device_check(listen_device_check_with(profiles, read))
        .spawn();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !handle.listen_failed() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(handle.listen_failed(), "a wrong device binding is fatal");
        handle.join().expect("loop thread panicked");
        assert_eq!(*seen.lock(), vec![ShutdownReason::ListenFailed]);
        assert_eq!(
            *asked.lock(),
            vec!["10.2.0.2:6881".parse().unwrap()],
            "only the vpn session's socket is read"
        );
        let calls = vpn.calls();
        let closed = calls.iter().position(|c| {
            matches!(c, RecordedCall::ApplySettings(s)
                if s.listen_interfaces.as_deref() == Some(""))
        });
        let paused = calls
            .iter()
            .position(|c| matches!(c, RecordedCall::PauseSession));
        assert!(
            matches!((closed, paused), (Some(c), Some(p)) if c < p),
            "{calls:?}"
        );
        assert!(
            !host
                .calls()
                .iter()
                .any(|c| matches!(c, RecordedCall::PauseSession)),
            "the host session is not the one fenced"
        );
    }

    /// A socket held to any device but the tunnel's is refused, naming it;
    /// one held to none is counted, for a warning, since the route probe
    /// watches what it sends.
    #[test]
    fn a_listen_socket_off_the_tunnel_device_is_refused() {
        assert_eq!(
            listen_device_verdict(
                "wg0",
                &[socket("tcp", Some("wg0")), socket("udp", Some("wg0"))]
            ),
            Ok(0),
        );
        assert_eq!(
            listen_device_verdict("wg0", &[socket("tcp", Some("wg0")), socket("udp", None)]),
            Ok(1),
        );
        let err = listen_device_verdict(
            "wg0",
            &[
                socket("tcp", Some("eth0")),
                socket("udp", Some("eth0")),
                socket("udp", None),
            ],
        )
        .unwrap_err();
        assert!(
            err.contains(
                "tcp socket held to eth0, udp socket held to eth0, not the tunnel device wg0"
            ),
            "{err}"
        );
        assert_eq!(listen_device_verdict("wg0", &[]), Ok(0));
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

    /// A second holder of the same lock file is refused while the first is
    /// alive, told the first one's pid, and leaves that pid in place. `flock`
    /// conflicts between two open files of one process just as it does
    /// between two processes, which is what makes this reachable in-process.
    #[test]
    fn a_second_instance_lock_refuses_and_names_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        // A state directory that does not exist yet, as on a first boot.
        let path = dir.path().join("state").join("torrentd.lock");
        let first = InstanceLock::acquire(&path).expect("first lock");
        let pid = std::process::id().to_string();

        let err = InstanceLock::acquire(&path).expect_err("second lock must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("pid {pid}")),
            "names the holder: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "names the lock: {msg}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            pid,
            "the refused start must not overwrite the holder's pid",
        );

        // Released on drop, so a restart after a clean or failed exit is not
        // locked out.
        drop(first);
        InstanceLock::acquire(&path).expect("lock is free once the holder is gone");
    }

    /// Only a held lock refuses. A lock file left behind by a daemon that has
    /// exited — the normal state of a stopped host — is taken over, and its
    /// stale contents replaced.
    #[test]
    fn a_leftover_lock_file_does_not_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torrentd.lock");
        std::fs::write(&path, "4294967295 and then some trailing bytes\n").unwrap();
        let _lock = InstanceLock::acquire(&path).expect("unheld lock file");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            std::process::id().to_string(),
        );
    }

    /// A state directory that cannot be created refuses the start, naming
    /// the directory. A regular file standing where the directory belongs
    /// fails `create_dir_all` whoever runs the test, root included.
    #[test]
    fn a_state_directory_that_cannot_be_created_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("state");
        std::fs::write(&blocker, "not a directory").unwrap();
        let path = blocker.join("torrentd.lock");

        let err = InstanceLock::acquire(&path).expect_err("a file as the state dir");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("create the state directory {}", blocker.display())),
            "names the directory: {msg}"
        );
    }

    /// A lock file that cannot be opened refuses the start, naming the lock.
    /// A directory at the lock path cannot be opened for writing, whoever
    /// runs the test.
    #[test]
    fn a_lock_file_that_cannot_be_opened_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torrentd.lock");
        std::fs::create_dir(&path).unwrap();

        let err = InstanceLock::acquire(&path).expect_err("a directory as the lock file");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("open the single-instance lock {}", path.display())),
            "names the lock: {msg}"
        );
    }

    /// A pid that cannot be recorded costs only the pid: the start goes on
    /// and the lock is held. `/dev/full` opens, locks and refuses
    /// `ftruncate`, so the record fails after the lock is taken.
    #[test]
    fn a_pid_that_cannot_be_recorded_still_holds_the_lock() {
        let path = std::path::Path::new("/dev/full");
        let lock = InstanceLock::acquire(path).expect("an unrecordable pid is not fatal");

        // Probe with a bare `try_lock` rather than a second `acquire`: its
        // refusal reads the file, and `/dev/full` never reaches end of file.
        let probe = std::fs::File::open(path).unwrap();
        assert!(
            matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "the lock is held although the pid was not recorded",
        );
        drop(lock);
        probe.try_lock().expect("released on drop");
    }

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

    /// A teardown as [`join_teardowns`] takes one, boxed so two closures of
    /// different types can share one `Vec`.
    type BoxedTeardown = (ProfileId, String, Box<dyn FnOnce() + Send>);

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

    /// A `VpnManager` that writes each teardown into a log the whole teardown
    /// shares, so the order across sessions, tunnels and the kill switch is
    /// one sequence to assert on.
    #[derive(Clone, Debug)]
    struct RecordingVpn {
        log: Arc<std::sync::Mutex<Vec<String>>>,
        engines: Vec<Arc<torrentd_engine::MockEngine>>,
    }

    impl torrentd_engine::VpnManager for RecordingVpn {
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

        fn bring_down(&self, iface: &str) {
            let closed = self.engines.iter().all(|e| {
                e.calls()
                    .iter()
                    .any(|c| matches!(c, torrentd_engine::RecordedCall::Close))
            });
            self.log
                .lock()
                .expect("no panics holding this")
                .push(format!(
                    "tunnel {iface} down (every session closed: {closed})"
                ));
        }
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

    /// The VPN monitor runs through the boot scans, but its fence pauses what
    /// the state map holds, and nothing the scans add is there yet. What a
    /// scan added to a profile fenced mid-scan is paused by the scan: once,
    /// all of it, the moment the fence is seen, and each add after that as
    /// it lands. A profile left healthy keeps running.
    #[test]
    fn a_profile_fenced_mid_scan_has_what_the_scans_added_paused() {
        use torrentd_engine::RecordedCall;

        use crate::profile_registry::test_vpn_entry;

        let entry = |id: &str| {
            let engine = Arc::new(torrentd_engine::MockEngine::new());
            let config = test_vpn_entry(id, ProfileStatus::Active).config;
            let dyn_engine: Arc<dyn TorrentEngine> = engine.clone();
            (ProfileEntry::new(config, dyn_engine, None, None, 0), engine)
        };
        let (a_entry, a_engine) = entry("acct_a");
        let (b_entry, b_engine) = entry("acct_b");
        let profiles = ProfileRegistry::new(vec![a_entry, b_entry]);
        let metrics = PromSink::new();
        let (a, b) = (ProfileId::new("acct_a"), ProfileId::new("acct_b"));
        let handle = |engine: &torrentd_engine::MockEngine, n: u8| {
            engine.register_handle(libtorrent_safe::InfoHash([n; 20]))
        };
        let paused = |engine: &torrentd_engine::MockEngine| {
            engine
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    RecordedCall::PauseTorrent(h) => Some(h),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let fence = |id: &ProfileId| {
            profiles
                .resolve(id)
                .active()
                .unwrap()
                .update_health(|h| h.status = ProfileStatus::VpnDown);
        };

        let mut scan = ScanFence::default();
        let (a1, a2, a3) = (
            handle(&a_engine, 1),
            handle(&a_engine, 2),
            handle(&a_engine, 3),
        );
        let b1 = handle(&b_engine, 4);
        scan.added(&profiles, &metrics, &a, a1);
        scan.added(&profiles, &metrics, &a, a2);
        scan.added(&profiles, &metrics, &b, b1);
        assert!(paused(&a_engine).is_empty(), "nothing is fenced yet");

        // Fenced between two adds: the next add pauses everything so far.
        fence(&a);
        scan.added(&profiles, &metrics, &a, a3);
        assert_eq!(paused(&a_engine), vec![a1, a2, a3]);
        scan.enforce_all(&profiles, &metrics);
        assert_eq!(paused(&a_engine), vec![a1, a2, a3], "each is paused once");
        assert_eq!(
            profiles
                .resolve(&a)
                .active()
                .unwrap()
                .health()
                .paused_for_vpn,
            3
        );

        // Fenced after its own scan's last add: the sweep reaches it.
        assert!(paused(&b_engine).is_empty());
        fence(&b);
        scan.enforce_all(&profiles, &metrics);
        assert_eq!(paused(&b_engine), vec![b1]);
        let exported = String::from_utf8(metrics.render()).expect("utf-8");
        assert!(
            exported.contains("torrentd_profile_torrents_paused_vpn_down{profile_id=\"acct_a\"} 3"),
            "{exported}"
        );
    }
}

/// `build_profiles`, driven end to end with `MockVpn`, `MockForwarder` and
/// `MockEngine` — the safety rules per-profile construction guarantees, which
/// until it was extracted from `boot` held only by reading.
#[cfg(test)]
mod profile_construction_tests {
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::path::PathBuf;

    use torrentd_engine::MockEngine;
    use torrentd_engine::MockForwarder;
    use torrentd_engine::MockVpn;
    use torrentd_engine::PortForwardError;
    use torrentd_engine::Settings;

    use super::*;

    const TUNNEL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2));
    const OTHER_TUNNEL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 3));

    /// Top-level keys, with the state directory — where session state lives —
    /// under `dir`.
    fn cfg_with(dir: &Path, profiles: &[String]) -> Config {
        let body = format!(
            "default_save_path = \"/data/torrents\"\n\
             resume_dir = \"{d}/resume\"\n\
             torrent_dir = \"{d}/torrents\"\n\
             http_listen = \"127.0.0.1:8080\"\n\
             allow_unauthenticated = true\n\n{}",
            profiles.join("\n"),
            d = dir.display(),
        );
        toml::from_str(&body).expect("config parses")
    }

    fn host(id: &str, dht: bool) -> String {
        format!(
            "[[profile]]\nid = \"{id}\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\ndht = {dht}\n"
        )
    }

    /// A static-port WireGuard profile; `n` keeps identities distinct.
    fn vpn(id: &str, iface: &str, n: u8) -> String {
        format!(
            "[[profile]]\nid = \"{id}\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/{iface}.conf\"\nvpn_interface = \"{iface}\"\n\
             listen_port = {port}\npeer_fingerprint = \"-AA10{n:02x}-\"\n\
             user_agent = \"ua-{id}\"\n",
            port = 6890 + u16::from(n),
        )
    }

    fn natpmp(id: &str, iface: &str) -> String {
        format!(
            "[[profile]]\nid = \"{id}\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/{iface}.conf\"\nvpn_interface = \"{iface}\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1000-\"\n\
             user_agent = \"ua-{id}\"\n"
        )
    }

    /// Every session `build_profiles` asked for: the settings it would have
    /// been built with, and the session state it would have been restored
    /// from.
    type Built = Arc<std::sync::Mutex<Vec<(Settings, Option<Vec<u8>>)>>>;

    struct Outcome {
        up: Vec<ProfileEntry>,
        failed: Vec<FailedProfile>,
        built: Vec<(Settings, Option<Vec<u8>>)>,
        /// Still armed, as `boot` holds it until the rest of boot succeeds.
        cleanup: BootCleanup,
    }

    impl Outcome {
        fn up_ids(&self) -> Vec<&str> {
            self.up.iter().map(|e| e.id().as_str()).collect()
        }

        fn failed(&self, id: &str) -> &FailedProfile {
            self.failed
                .iter()
                .find(|f| f.config.id.as_str() == id)
                .unwrap_or_else(|| panic!("{id} is not reported failed: {:?}", self.failed))
        }
    }

    /// Run `build_profiles` over `cfg` with every seam mocked. The engine
    /// factory fails the call numbered `fail_engine_call` (zero-based), which
    /// is how a session construction failure is reached.
    async fn build(
        cfg: &Config,
        vpn: &MockVpn,
        forwarder: &MockForwarder,
        fail_engine_call: Option<usize>,
    ) -> Outcome {
        let vpn_for = vpn.clone();
        let mut cleanup = BootCleanup::with_vpn_factory(
            cfg.state_dir(),
            Arc::new(move |_t, _dir| {
                Arc::new(vpn_for.clone()) as Arc<dyn torrentd_engine::VpnManager>
            }),
        );
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let built: Built = Arc::default();
        let record = Arc::clone(&built);
        let mut calls = 0usize;
        let (up, failed) = build_profiles(
            cfg,
            &mut cleanup,
            forwarder,
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &crate::profile_state::Record::default(),
            move |settings: &Settings, state: Option<Vec<u8>>| {
                let n = calls;
                calls += 1;
                if Some(n) == fail_engine_call {
                    return Err("the session refused its settings");
                }
                record
                    .lock()
                    .expect("uncontended")
                    .push((settings.clone(), state));
                Ok(Arc::new(MockEngine::new()) as Arc<dyn TorrentEngine>)
            },
        )
        .await
        .expect("no shutdown was requested");
        let built = built.lock().expect("uncontended").clone();
        Outcome {
            up,
            failed,
            built,
            cleanup,
        }
    }

    /// Two accounts whose WireGuard configs name one server leave from one
    /// public address, whatever tunnel address each is given, and that is
    /// what a tracker sees (issue #171). The match ignores the port and the
    /// host's case; a profile on another server, a host profile and a config
    /// that cannot be read are not reported.
    #[test]
    fn two_vpn_profiles_whose_configs_name_one_endpoint_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[
                vpn("acct_a", "wg-a", 1),
                host("public", false),
                vpn("acct_b", "wg-b", 2),
                vpn("acct_c", "wg-c", 3),
                vpn("acct_d", "wg-d", 4),
            ],
        );
        let conf = |endpoint: &str| {
            format!(
                "[Interface]\nPrivateKey = k\nAddress = 10.2.0.2/32\n\n\
                 [Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n"
            )
        };
        let read = |path: &Path| match path.to_str() {
            Some("/etc/wireguard/wg-a.conf") => Ok(conf("NL-free-7.example.net:51820")),
            Some("/etc/wireguard/wg-b.conf") => Ok(conf("nl-free-7.example.net:443")),
            Some("/etc/wireguard/wg-c.conf") => Ok(conf("nl-free-8.example.net:51820")),
            _ => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        };
        assert_eq!(
            shared_endpoint_hosts(&cfg.profile, read),
            [SharedEndpoint {
                host: "nl-free-7.example.net".to_string(),
                profiles: vec![ProfileId::new("acct_a"), ProfileId::new("acct_b")],
            }],
        );

        let distinct = |path: &Path| Ok(conf(&format!("{}:51820", path.display())));
        assert!(shared_endpoint_hosts(&cfg.profile, distinct).is_empty());
    }

    #[tokio::test]
    async fn a_vpn_profile_whose_tunnel_fails_gets_no_session_and_the_others_come_up() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[vpn("acct_a", "wg-a", 1), host("public", false)],
        );
        // No address for wg-a: its bring-up fails the way the address poll does.
        let vpn = MockVpn::new();
        let out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(
            out.up_ids(),
            vec!["public"],
            "the host profile still came up"
        );
        assert!(
            out.failed("acct_a").reason.contains("VPN bring-up failed"),
            "reported failed, with the reason: {:?}",
            out.failed,
        );
        assert_eq!(
            out.built.len(),
            1,
            "Safety Rule 1: no session was ever constructed for the failed \
             profile — no bare-IP fallback",
        );
        assert_eq!(
            out.built[0].0.listen_interfaces.as_deref(),
            Some("0.0.0.0:6881"),
            "and the one session built is the host profile's",
        );
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-a".to_string()],
            "the half-up tunnel is lowered",
        );
    }

    #[tokio::test]
    async fn a_natpmp_failure_at_startup_disables_the_profile_and_lowers_its_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a")]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_err(PortForwardError::Gateway(2));

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert!(out.up.is_empty(), "no session on an unforwarded port");
        assert!(out.built.is_empty(), "none was even constructed");
        assert!(
            out.failed("acct_a")
                .reason
                .contains("NAT-PMP negotiation failed"),
            "got {:?}",
            out.failed,
        );
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-a".to_string()],
            "the tunnel raised for it is taken down with it",
        );
        let calls = forwarder.calls();
        assert_eq!(calls.len(), 1, "negotiated once, at startup");
        assert_eq!(
            calls[0].bind_ip, TUNNEL_IP,
            "negotiated from the tunnel address"
        );
        assert_eq!(
            calls[0].gateway,
            IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
            "against the default gateway",
        );
    }

    #[tokio::test]
    async fn a_negotiated_port_is_the_one_the_session_binds_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a")]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_ok_epoch(51413, 77);

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        assert_eq!(
            out.built[0].0.listen_interfaces.as_deref(),
            Some("wg-a:51413"),
        );
        let health = out.up[0].health();
        assert_eq!(health.forwarded_port, Some(51413));
        assert_eq!(health.forwarded_epoch, 77);
        assert_eq!(health.tunnel_ip, Some(TUNNEL_IP));
    }

    #[tokio::test]
    async fn an_earlier_profile_s_lease_is_renewed_before_the_next_bring_up() {
        // Two natpmp profiles. The first's 60-second lease starts at its
        // negotiation; the second's bring-up can take most of that, so the
        // first is renewed — asking to keep its port — before it starts.
        let dir = tempfile::tempdir().unwrap();
        let second = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg-b.conf\"\nvpn_interface = \"wg-b\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1001-\"\n\
             user_agent = \"ua-acct_b\"\n"
            .to_string();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a"), second]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_ok(51413); // acct_a negotiates
        forwarder.push_ok(51413); // acct_a renewed, same port
        forwarder.push_ok(40002); // acct_b negotiates

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert_eq!(out.up_ids(), vec!["acct_a", "acct_b"]);
        let calls = forwarder.calls();
        assert_eq!(calls.len(), 3, "negotiate a, renew a, negotiate b");
        assert_eq!((calls[0].bind_ip, calls[0].suggested_port), (TUNNEL_IP, 0));
        assert_eq!(
            (calls[1].bind_ip, calls[1].suggested_port),
            (TUNNEL_IP, 51413),
            "the renewal asks to keep the port the session listens on",
        );
        assert_eq!(
            (calls[2].bind_ip, calls[2].suggested_port),
            (OTHER_TUNNEL_IP, 0)
        );
        assert!(
            calls
                .iter()
                .all(|c| c.internal_port == PortMapRequest::INTERNAL_PORT),
            "every request names the same internal port",
        );
        assert_eq!(out.up[1].health().forwarded_port, Some(40002));
    }

    /// Two gateways, one port: the second natpmp profile is handed the port
    /// the first holds, or a port a static profile is configured with. Two
    /// profiles announcing one port are correlatable by a tracker operator
    /// (Safety Rule 8), so the second does not come up on it. At a9eb5a1
    /// nothing checked a gateway-assigned port against anything.
    #[tokio::test]
    async fn a_natpmp_port_another_profile_holds_disables_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let second = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg-b.conf\"\nvpn_interface = \"wg-b\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1001-\"\n\
             user_agent = \"ua-acct_b\"\n"
            .to_string();
        let cfg = cfg_with(
            dir.path(),
            &[natpmp("acct_a", "wg-a"), second, vpn("acct_s", "wg-s", 3)],
        );
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        vpn.set_ip("wg-s", IpAddr::V4(Ipv4Addr::new(10, 9, 0, 9)));
        let forwarder = MockForwarder::new();
        forwarder.push_ok(6893); // acct_a: acct_s's static port
        forwarder.push_ok(40002); // acct_b negotiates
        forwarder.push_ok(40002); // acct_b renewed before acct_s's bring-up

        let out = build(&cfg, &vpn, &forwarder, None).await;

        assert!(
            out.failed("acct_a").reason.contains("6893"),
            "a port a static profile is configured with, even one built later: {:?}",
            out.failed,
        );
        assert_eq!(out.up_ids(), vec!["acct_b", "acct_s"]);
        assert!(
            vpn.bring_down_calls().contains(&"wg-a".to_string()),
            "its tunnel is taken down with it",
        );

        // And a port an already-built profile holds.
        let dir = tempfile::tempdir().unwrap();
        let second = "[[profile]]\nid = \"acct_b\"\nnetwork = \"vpn\"\nvpn_type = \"wireguard\"\n\
             vpn_config = \"/etc/wireguard/wg-b.conf\"\nvpn_interface = \"wg-b\"\n\
             port_forward = \"natpmp\"\npeer_fingerprint = \"-BB1001-\"\n\
             user_agent = \"ua-acct_b\"\n"
            .to_string();
        let cfg = cfg_with(dir.path(), &[natpmp("acct_a", "wg-a"), second]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        let forwarder = MockForwarder::new();
        forwarder.push_ok(51413); // acct_a negotiates
        forwarder.push_ok(51413); // acct_a renewed
        forwarder.push_ok(51413); // acct_b handed the same port
        let out = build(&cfg, &vpn, &forwarder, None).await;
        assert_eq!(out.up_ids(), vec!["acct_a"]);
        assert!(
            out.failed("acct_b").reason.contains("51413"),
            "{:?}",
            out.failed
        );
    }

    #[tokio::test]
    async fn a_vpn_session_binds_only_the_tunnel_and_runs_no_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[vpn("acct_a", "wg-a", 1)]);
        // Session state on disk under this profile's name must not reach a
        // vpn session: its DHT routing table would announce the host.
        let state_path = cfg.session_state_path(&ProfileId::new("acct_a"));
        std::fs::write(&state_path, b"routing table").unwrap();
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);

        let out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        let (settings, state) = &out.built[0];
        assert_eq!(settings.enable_dht, Some(false));
        assert_eq!(settings.enable_lsd, Some(false));
        assert_eq!(settings.enable_upnp, Some(false));
        assert_eq!(settings.enable_natpmp, Some(false));
        assert_eq!(
            settings.listen_interfaces.as_deref(),
            Some("wg-a:6891"),
            "listening on the tunnel device, not its address: an address is bound to \
             the first interface whose network holds it, which can be a LAN's",
        );
        assert!(
            !settings
                .listen_interfaces
                .as_deref()
                .unwrap_or_default()
                .contains("0.0.0.0"),
            "never the wildcard",
        );
        assert_eq!(
            settings.outgoing_interfaces.as_deref(),
            Some("wg-a"),
            "outgoing connections are bound to the tunnel device (SO_BINDTODEVICE), \
             not only to its address, so where the kernel allows the device binding \
             a lost routing rule cannot send them out of the physical interface",
        );
        assert_eq!(settings.user_agent.as_deref(), Some("ua-acct_a"));
        assert_eq!(state, &None, "a vpn session restores no session state");
        assert!(
            vpn.bring_down_calls().is_empty(),
            "a tunnel that came up for a live session is left standing",
        );
    }

    #[tokio::test]
    async fn a_host_profile_with_dht_runs_it_and_restores_its_state_and_one_without_does_neither() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[host("with_dht", true), host("without", false)],
        );
        std::fs::create_dir_all(cfg.state_dir()).unwrap();
        for id in ["with_dht", "without"] {
            std::fs::write(cfg.session_state_path(&ProfileId::new(id)), id.as_bytes()).unwrap();
        }

        let out = build(&cfg, &MockVpn::new(), &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["with_dht", "without"]);
        let (with, with_state) = &out.built[0];
        assert_eq!(with.enable_dht, Some(true));
        assert_eq!(with_state.as_deref(), Some(&b"with_dht"[..]));
        let (without, without_state) = &out.built[1];
        assert_eq!(without.enable_dht, Some(false));
        assert_eq!(
            without_state, &None,
            "without DHT there is nothing worth restoring, even with a file there",
        );
    }

    #[tokio::test]
    async fn the_boot_guard_lowers_exactly_the_tunnels_raised_and_nothing_once_disarmed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[
                vpn("acct_a", "wg-a", 1),
                vpn("acct_b", "wg-b", 2),
                host("public", false),
            ],
        );
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);

        // Boot fails after the profiles: the guard is dropped armed.
        let out = build(&cfg, &vpn, &MockForwarder::new(), None).await;
        assert_eq!(out.up_ids(), vec!["acct_a", "acct_b", "public"]);
        assert!(vpn.bring_down_calls().is_empty());
        drop(out);
        let mut lowered = vpn.bring_down_calls();
        lowered.sort();
        assert_eq!(lowered, vec!["wg-a".to_string(), "wg-b".to_string()]);

        // Boot succeeds: the shutdown path owns the tunnels.
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        let mut out = build(&cfg, &vpn, &MockForwarder::new(), None).await;
        out.cleanup.disarm();
        drop(out);
        assert!(vpn.bring_down_calls().is_empty());
    }

    #[tokio::test]
    async fn a_profile_that_fails_after_its_tunnel_is_up_loses_it_even_when_boot_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[vpn("acct_a", "wg-a", 1), vpn("acct_b", "wg-b", 2)],
        );
        // Both tunnels come up on one address — every Proton WireGuard config
        // assigns 10.2.0.2/32 — so the second cannot be kept out of the
        // first's tunnel.
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", TUNNEL_IP);

        let mut out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        assert!(
            out.failed("acct_b")
                .reason
                .contains("also profile acct_a's"),
            "got {:?}",
            out.failed,
        );
        assert_eq!(out.built.len(), 1, "no session for the colliding profile");
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-b".to_string()],
            "lowered at once, not left for a guard that boot will disarm",
        );
        out.cleanup.disarm();
        drop(out);
        assert_eq!(
            vpn.bring_down_calls(),
            vec!["wg-b".to_string()],
            "and the surviving profile's tunnel stays up",
        );
    }

    /// Two tunnels on distinct IPv4 addresses that share a global IPv6
    /// address: the sessions send from it too, so the second is refused as
    /// for a shared IPv4 address. A tunnel whose IPv6 addresses cannot be
    /// read cannot be checked, and is refused as well.
    #[tokio::test]
    async fn a_tunnel_sharing_an_ipv6_address_or_unable_to_read_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[
                vpn("acct_a", "wg-a", 1),
                vpn("acct_b", "wg-b", 2),
                vpn("acct_c", "wg-c", 3),
            ],
        );
        let shared: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", OTHER_TUNNEL_IP);
        vpn.set_ip("wg-c", IpAddr::V4(Ipv4Addr::new(10, 3, 0, 2)));
        vpn.set_ipv6("wg-a", vec![shared]);
        vpn.set_ipv6("wg-b", vec!["2001:db8::9".parse().unwrap(), shared]);
        vpn.set_ipv6_unreadable("wg-c");

        let mut out = build(&cfg, &vpn, &MockForwarder::new(), None).await;

        assert_eq!(out.up_ids(), vec!["acct_a"]);
        let reason = &out.failed("acct_b").reason;
        assert!(
            reason.contains("tunnel address 2001:db8::2 is also profile acct_a's"),
            "{reason}"
        );
        let reason = &out.failed("acct_c").reason;
        assert!(
            reason.contains("could not read tunnel wg-c's IPv6 addresses")
                && reason.contains("no answer"),
            "{reason}"
        );
        let mut lowered = vpn.bring_down_calls();
        lowered.sort();
        assert_eq!(lowered, vec!["wg-b".to_string(), "wg-c".to_string()]);
        out.cleanup.disarm();
    }

    #[tokio::test]
    async fn a_session_that_will_not_build_lowers_its_tunnel_and_frees_the_address() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(
            dir.path(),
            &[vpn("acct_a", "wg-a", 1), vpn("acct_b", "wg-b", 2)],
        );
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        vpn.set_ip("wg-b", TUNNEL_IP);

        // acct_a's session is refused after its tunnel is up.
        let out = build(&cfg, &vpn, &MockForwarder::new(), Some(0)).await;

        assert!(
            out.failed("acct_a")
                .reason
                .contains("session construction failed"),
            "got {:?}",
            out.failed,
        );
        assert_eq!(vpn.bring_down_calls(), vec!["wg-a".to_string()]);
        assert_eq!(
            out.up_ids(),
            vec!["acct_b"],
            "a failed profile does not keep the address it no longer has a \
             tunnel on, so the next profile to come up on it is not refused",
        );
    }

    #[tokio::test]
    async fn a_shutdown_between_profiles_stops_the_bring_up() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[vpn("acct_a", "wg-a", 1)]);
        let vpn = MockVpn::new();
        vpn.set_ip("wg-a", TUNNEL_IP);
        let vpn_for = vpn.clone();
        let mut cleanup = BootCleanup::with_vpn_factory(
            PathBuf::from("/var/lib/torrentd"),
            Arc::new(move |_t, _dir| {
                Arc::new(vpn_for.clone()) as Arc<dyn torrentd_engine::VpnManager>
            }),
        );
        let (tx, mut boot_shutdown) = broadcast::channel(8);
        tx.send(ShutdownReason::Sigterm).unwrap();

        let r = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &crate::profile_state::Record::default(),
            |_: &Settings, _: Option<Vec<u8>>| -> Result<Arc<dyn TorrentEngine>, String> {
                panic!("no session is built after a shutdown was asked for")
            },
        )
        .await;

        assert!(r.is_err(), "the bring-up is abandoned");
        assert!(
            vpn.bring_up_calls().is_empty(),
            "no tunnel is raised after the shutdown",
        );
    }

    /// A profile left offline, read back from the state file a crash left,
    /// has its session paused before the session takes any other call, so no
    /// boot scan can give it a torrent that runs. The others are untouched.
    #[tokio::test]
    async fn a_profile_left_offline_boots_with_its_session_paused_first() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("public", false), host("acct_b", false)]);
        // What a previous run wrote before it was killed.
        let (states, _) = crate::profile_state::DesiredStates::load(cfg.profile_state_path());
        states
            .change(
                |r| {
                    r.set(
                        &ProfileId::new("acct_b"),
                        torrentd_engine::DesiredState::Offline,
                    )
                },
                |_| (),
            )
            .unwrap();
        drop(states);
        let (states, loaded) = crate::profile_state::DesiredStates::load(cfg.profile_state_path());
        assert_eq!(loaded, crate::profile_state::Loaded::Read);

        let mut cleanup = BootCleanup::new(cfg.state_dir());
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let engines: Arc<std::sync::Mutex<Vec<Arc<MockEngine>>>> = Arc::default();
        let made = Arc::clone(&engines);
        let (up, failed) = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &states.current(),
            move |_: &Settings, _: Option<Vec<u8>>| -> Result<Arc<dyn TorrentEngine>, String> {
                let engine = Arc::new(MockEngine::new());
                made.lock().unwrap().push(Arc::clone(&engine));
                Ok(engine)
            },
        )
        .await
        .unwrap();
        assert!(failed.is_empty());
        assert_eq!(up.len(), 2);
        let engines = engines.lock().unwrap();
        let (public, acct_b) = (&engines[0], &engines[1]);
        assert!(
            matches!(
                acct_b.calls().first(),
                Some(torrentd_engine::RecordedCall::PauseSession)
            ),
            "the offline profile's first call is the pause: {:?}",
            acct_b.calls(),
        );
        assert!(acct_b.session_paused().unwrap());
        assert!(!public.session_paused().unwrap());
        assert!(public.calls().is_empty(), "{:?}", public.calls());
    }

    /// The session pause leaves the DHT node running, so a host profile with
    /// DHT left offline starts with it stopped, its saved routing table still
    /// handed to the session for when it is set online.
    #[tokio::test]
    async fn a_dht_profile_left_offline_boots_with_its_dht_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("acct_b", true)]);
        std::fs::create_dir_all(cfg.state_dir()).unwrap();
        std::fs::write(cfg.session_state_path(&ProfileId::new("acct_b")), b"table").unwrap();
        let record = crate::profile_state::Record {
            offline_all: true,
            ..Default::default()
        };
        let mut cleanup = BootCleanup::new(cfg.state_dir());
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let built: Built = Arc::default();
        let seen = Arc::clone(&built);
        let (up, failed) = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &record,
            move |settings: &Settings,
                  state: Option<Vec<u8>>|
                  -> Result<Arc<dyn TorrentEngine>, String> {
                seen.lock().unwrap().push((settings.clone(), state));
                Ok(Arc::new(MockEngine::new()))
            },
        )
        .await
        .unwrap();
        assert!(failed.is_empty());
        assert_eq!(up.len(), 1);
        let built = built.lock().unwrap();
        let (settings, state) = &built[0];
        assert_eq!(settings.enable_dht, Some(false));
        assert_eq!(state.as_deref(), Some(&b"table"[..]));
    }

    /// A session that cannot be held offline gets no torrents: the profile
    /// is failed rather than run unpaused.
    #[tokio::test]
    async fn an_offline_profile_whose_session_will_not_pause_is_failed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("acct_b", false)]);
        let record = crate::profile_state::Record {
            offline_all: true,
            ..Default::default()
        };
        let mut cleanup = BootCleanup::new(cfg.state_dir());
        let (_tx, mut boot_shutdown) = broadcast::channel(8);
        let (up, failed) = build_profiles(
            &cfg,
            &mut cleanup,
            &MockForwarder::new(),
            &torrentd_engine::NoopSink,
            &mut boot_shutdown,
            &record,
            |_: &Settings, _: Option<Vec<u8>>| -> Result<Arc<dyn TorrentEngine>, String> {
                let engine = MockEngine::new();
                engine.inject_error("pause_session", torrentd_engine::EngineError::Shutdown);
                Ok(Arc::new(engine))
            },
        )
        .await
        .unwrap();
        assert!(up.is_empty());
        assert_eq!(failed.len(), 1);
        assert!(
            failed[0].reason.contains("could not be paused"),
            "{}",
            failed[0].reason
        );
    }

    /// Both boot scans hand the session an add that keeps the torrent in
    /// upload mode and clears every flag resume data could carry to lift it.
    #[test]
    fn both_boot_scans_forbid_downloading() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_with(dir.path(), &[host("public", true), vpn("a", "wg-a", 1)]);
        for p in &cfg.profile {
            let engine = MockEngine::new();
            engine
                .add_torrent(resume_scan_params(p, vec![1; 32], None))
                .unwrap();
            engine
                .add_torrent(torrent_dir_scan_params(p, vec![2; 32], "/data".into()))
                .unwrap();
            let adds: Vec<_> = engine
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    torrentd_engine::RecordedCall::AddTorrent(a) => Some(a),
                    _ => None,
                })
                .collect();
            assert_eq!(adds.len(), 2);
            for a in adds {
                assert!(a.forbids_downloading(), "{}: {a:?}", p.id);
            }
        }
    }
}
