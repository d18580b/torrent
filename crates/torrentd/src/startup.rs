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
/// the listen backlog until one closes.
///
/// Sized against the descriptor limit the daemon shares with libtorrent,
/// which is what `LimitNOFILE=65536` in `deploy/torrentd.service` is for:
/// each profile's `connections_limit` (10,000 in the sample config) and
/// `file_pool_size` draw on the same table. kynos' default of 10,000 would let
/// the API alone take a sixth of it, and every descriptor the API holds is one
/// a profile cannot open a peer or a file with. The API's own callers — an
/// operator or two, `torrentctl`, a Prometheus scrape, a reverse proxy's
/// pool — need a few dozen; 256 leaves room for a proxy that does not reuse
/// connections, at under 0.4% of the table.
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
/// to acknowledge before the connection is closed.
///
/// kynos leaves HTTP/2 keep-alive off, and HTTP/2 has no counterpart to
/// [`HTTP_HEADER_READ_TIMEOUT`]: a peer that sent the preface and then went
/// silent — crashed, partitioned, or never reading — would hold one of
/// [`HTTP_MAX_CONNECTIONS`] until the daemon stopped. With pings, such a peer
/// is dropped within 30 s.
///
/// This does not bound a peer that acknowledges pings and sends nothing
/// else, nor a plaintext connection that sends no byte at all: hyper-util
/// sniffs the protocol before either driver starts, with no timer, and kynos
/// exposes neither a first-byte deadline nor an HTTP/2 idle timeout. Both are
/// recorded in `docs/running.md` §7; a non-loopback `http_listen` belongs
/// behind a proxy that bounds them.
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
/// of the daemon.
///
/// Nothing else stops a second `torrentd` against the same config, and the
/// HTTP bind that eventually refuses one comes last. Before it, the second
/// process used to replace the running daemon's kill-switch table with one
/// naming only its own tunnels (`killswitch::enable` deletes the table before
/// loading its own), run the resume scan, and then — failing the bind — tear
/// down the table and the tunnels on its way out. The running daemon was left
/// seeding with no backstop, and nothing in it could notice.
///
/// Taken first in `boot`, so a second start refuses before any of that. The
/// lock belongs to the open file, not to the path: the kernel releases it
/// when this is dropped or when the process ends however it ends, SIGKILL
/// included, so a crash never leaves a stale lock to clear by hand. `std`
/// opens files close-on-exec, so no tunnel helper a boot spawns inherits it.
#[derive(Debug)]
struct InstanceLock {
    /// Never read. Holding the open file is the lock.
    _file: std::fs::File,
}

impl InstanceLock {
    /// Lock `path`, creating it and its directory where missing, or refuse
    /// naming the process that holds it.
    fn acquire(path: &std::path::Path) -> anyhow::Result<Self> {
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
    /// Every session boot built, closed before any tunnel goes. Dropping
    /// `boot`'s own handles does not destroy them once the port-forward
    /// monitor holds the registry, and a session outliving its tunnel is
    /// sockets bound to an address whose route is about to disappear.
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

    /// Bring one tunnel down and stop tracking it — for a profile that failed
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

    /// Bring a profile's tunnel up, recording it **before** the attempt.
    ///
    /// `bring_up` spawns the tunnel and only then polls up to 30 seconds for
    /// an address, so every failure after the spawn leaves something running:
    /// a WireGuard interface `wg-quick up` already created, or an
    /// `openvpn --daemon` that forked, exited 0, and is still retrying. Both
    /// outlive this process. Recording the tunnel only once an address had
    /// appeared left that one failure path — and only that one — with nothing
    /// tracking it: the failure teardown had nothing to remove, `Drop` had
    /// nothing to bring down, `ProfileRegistry::iter()` excludes failed profiles so the
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
    /// and on a runtime worker that is 30 seconds per profile during which
    /// nothing else — including the signal handler that is supposed to
    /// interrupt exactly this — gets to run on that thread.
    ///
    /// The manager comes from the same factory the teardown uses, so the
    /// object that raises a tunnel is the object that takes it down.
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
        // Sessions, then tunnels, then the kill switch, as on a clean
        // shutdown (`teardown_network`). The sessions go first because a
        // session left open while its tunnel goes keeps sockets bound to an
        // address whose route is disappearing; the switch goes last because
        // it is what confines the uid to the tunnels while they go, and
        // removing it first opened the host's own interface to anything
        // still bound for one.
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

/// Take both shutdown receivers `boot` needs, on one line.
///
/// `broadcast::Sender::subscribe()` sets the new receiver's cursor to the
/// channel's current tail, so a receiver created later provably cannot see a
/// send that already happened, and a send with no live receiver behind it is
/// discarded outright. `boot` used to subscribe the receiver that outlives
/// boot only after the resume and torrent-dir scans — 400-odd lines after the
/// signal listener was installed, and the whole of a single-session boot after
/// it. A SIGTERM in that window was consumed by `boot_shutdown`, which the
/// profile loop has already finished with, and the HTTP server's graceful
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
    /// Whether the nftables kill switch was installed and must be torn down on
    /// graceful shutdown.
    kill_switch_active: bool,
    log_handle: crate::tracing_init::LogReloadHandle,
    alert_loop: torrentd_engine::AlertLoopHandle,
    /// Registry entries no startup scan loaded; see `AppState::unloaded_at_boot`.
    unloaded_at_boot: std::collections::HashSet<libtorrent_safe::InfoHash>,
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
    // Refusals that are pure functions of the file, before any tunnel is
    // raised: among them a host profile beside `network_kill_switch`, whose
    // egress the ruleset would drop while it reported itself Active.
    cfg.check_boot_rules().map_err(refused)?;
    // Where a VPN manager keeps state a *later* process has to find — see
    // `vpn::for_type`. Resolved once here so bring-up and teardown agree.
    let run_dir = cfg.state_dir();

    // One daemon per state directory, decided before anything with an effect
    // outside this process — see `InstanceLock` for what a second start used
    // to do to the running daemon's kill switch. Above the signal install
    // because nothing here needs tearing down yet: a SIGTERM that kills the
    // process while the lock is being taken leaves nothing behind.
    //
    // Declared before `cleanup` below, so on every failed boot the cleanup's
    // teardown runs, in reverse declaration order, while this is still held:
    // a new start cannot slip in between and have its fresh kill switch
    // removed by the teardown of the boot it replaced.
    let instance_lock = {
        let path = cfg.instance_lock_path();
        tokio::task::spawn_blocking(move || InstanceLock::acquire(&path))
            .await
            .context("single-instance lock")??
    };

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
    let shutdown_tx = channels.shutdown_tx.clone();
    // Both shutdown receivers, taken here rather than 400 lines apart — the
    // one the profile loop polls during bring-up, and the one that outlives boot
    // and the HTTP server's graceful shutdown waits on — and taken *before*
    // the listener that can send to them is installed. See
    // `boot_shutdown_receivers` for what subscribing the second one late
    // cost, and `boot_shutdown_receivers_before` for why the order is not two
    // adjacent statements here any more.
    let (mut boot_shutdown, shutdown_rx) =
        boot_shutdown_receivers_before(&shutdown_tx, || signals::run(channels.clone())).await;

    // Tunnel bring-up (up to 30 s a profile) and the resume and torrent-dir
    // scans (minutes at 100K torrents) can outrun any fixed
    // `TimeoutStartSec`. Ask systemd for more time while boot runs — dropped,
    // and so stopped, when `boot` returns — capped so a wedged boot still
    // meets the timeout eventually.
    let _extend_start = sd_notify::TimeoutExtender::start(BOOT_EXTEND_CAP);

    warn_if_descriptors_are_short(&cfg);

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
    // anywhere after the profile loop used to leave a host with live tunnels, an
    // nftables table confining a uid that no longer exists, and no daemon.
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

    // Resume store — rooted at the top-level `resume_dir` and partitioned by
    // profile id, except where a `[[profile]]` names its own directory. Those keys
    // were validated for uniqueness and then ignored, so files landed under
    // the derived path and only matched the configured one by coincidence.
    //
    // The alert loop's writes are batched onto the store's own thread, and a
    // write that fails there is counted as the handler used to count it. The
    // handler has already cleared the torrent's `needs_save_resume` by then,
    // and libtorrent its modified bit, so the hook also marks the file stale:
    // otherwise no `ONLY_IF_MODIFIED` save, the shutdown drain's included,
    // would ever rewrite it.
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

    // Reconcile it against the configured profiles before anything reads it.
    //
    // The import above carries a pre-profiles registry over verbatim, which
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
    let profile_registry =
        Arc::new(ProfileRegistry::new(profile_entries).with_failed(failed_profiles));
    let source: Arc<dyn AlertSource> = Arc::new(ProfileSource::new(source_entries));
    // Port-forward renewal monitor: keeps NAT-PMP leases alive, rebinds the
    // live session if the forwarded port changes, and reannounces. Started
    // here, the moment every profile is built, rather than from
    // `run_until_signal`: everything between the two — the kill switch, the
    // resume and `.torrent` scans, opening the pool — is time a 60-second
    // lease negotiated during bring-up spent unrenewed. It renews at once.
    // If boot fails below, the process exits and the task with it.
    // It returns at once when no live profile negotiates a port, which is
    // not a death, so it is supervised only where it has work.
    let pf = crate::port_forward_monitor::run(
        profile_registry.clone(),
        state.clone(),
        metrics.clone(),
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
            // (`Config::check_boot_rules`), so an operator's pre-flight run
            // refuses a config with no vpn profile, and the daemon refuses it
            // as it loads the config, exiting 78. This check stays because it reads
            // the profiles that actually came up: a config with one vpn
            // profile whose tunnel failed lands here too, and no config check
            // could have known.
            cfg.check_boot_rules().map_err(refused)?;
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
    // What the scans could not load, per profile, by the `source` label of
    // `boot_torrent_load_failures`. Exported as gauges once both have run:
    // these happen before any scrape can, so a counter would appear already
    // incremented and `increase()` would never see it move.
    let mut load_failures: std::collections::HashMap<ProfileId, BootLoadFailures> =
        std::collections::HashMap::new();

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
        let mut added_from_resume = 0usize;
        let engine = source
            .engine_for(&profile)
            .ok_or_else(|| anyhow::anyhow!("no engine for profile {}", profile))?;
        for (i, (ih, data)) in entries.into_iter().enumerate() {
            // A 100K-torrent scan runs for minutes; a SIGTERM during it is
            // answered now, while `BootCleanup` still owns the tunnels, not
            // after the scan has added everything only for the drain to save
            // it all again.
            if i % SCAN_SHUTDOWN_CHECK_EVERY == 0 && shutdown_requested(&mut boot_shutdown) {
                anyhow::bail!("shutdown requested during the resume scan");
            }
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
                    load_failures
                        .entry(profile.clone())
                        .or_default()
                        .torrent_read += 1;
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
            match engine.add_torrent(resume_scan_params(profile_cfg, data.into_inner(), torrent)) {
                Ok(_) => {
                    added_from_resume += 1;
                    loaded.insert(ih);
                }
                Err(e) => {
                    warn!(profile_id = %profile, infohash = %ih, error.cause = %e, "resume add failed");
                    load_failures.entry(profile.clone()).or_default().resume_add += 1;
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
            if i % SCAN_SHUTDOWN_CHECK_EVERY == 0 && shutdown_requested(&mut boot_shutdown) {
                anyhow::bail!("shutdown requested during the torrent-dir scan");
            }
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
            match engine.add_torrent(torrent_dir_scan_params(
                profile_cfg,
                bytes,
                scan_save_path.clone(),
            )) {
                Ok(_) => {
                    added += 1;
                    loaded.insert(ih);
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

    // Reconcile what the registry claims against what the scans actually
    // loaded.
    //
    // The boot check above catches the adjacent mistake — a registry naming an
    // id no `[[profile]]` declares — and refuses well. But an operator who
    // takes its own advice ("give one of the configured profiles the id the
    // registry names") and stops there boots successfully with every file
    // still at the old un-partitioned root: `resume scan complete
    // torrent_count=0` at `info`, `/healthz` 200, and `GET /v1/profiles`
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
        .filter(|ih| !loaded.contains(ih))
        .collect();

    // Managed pool. Opened before the alert loop so a bad index path fails
    // startup rather than surfacing as a 500 on the first API call.
    let pool = crate::pool_service::PoolService::open(&cfg).context("open pool index")?;
    if let Some(pool) = pool.as_ref() {
        pool.set_metrics(metrics.clone());
    }

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
        kill_switch_active,
        log_handle,
        alert_loop,
        unloaded_at_boot,
        instance_lock,
    })
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
/// session, and the others carry on. It still has to be *reported* as failed
/// — skipping it outright made it vanish from `/profiles`, so an operator
/// wondering why an account was quiet found no trace of it anywhere but the
/// startup log. Returned as `(up, failed)`; an empty `up` is the caller's to
/// refuse, since a daemon with no session has nothing to run.
///
/// Every piece of the outside world arrives as a parameter — the tunnel
/// managers through `cleanup`'s factory, NAT-PMP through `forwarder`, the
/// session through `make_engine` — so a test drives this whole loop with
/// `MockVpn`, `MockForwarder` and `MockEngine`. `boot` constructed each of
/// them inline, and the safety rules below were guaranteed only by reading.
///
/// A natpmp profile's lease starts running when its port is negotiated, and
/// every later profile's bring-up — up to 30 seconds for the tunnel and ~16
/// for the negotiation — used to pass before anything renewed it. So before
/// each bring-up the leases of the profiles already built are renewed here,
/// which bounds a lease's age at boot to one profile's bring-up;
/// `port_forward_monitor` takes over as soon as this returns.
///
/// `Err` only for a shutdown asked for between two profiles' bring-ups.
async fn build_profiles<F, E>(
    cfg: &Config,
    cleanup: &mut BootCleanup,
    forwarder: &dyn PortForwarder,
    metrics: &dyn MetricsSink,
    boot_shutdown: &mut broadcast::Receiver<ShutdownReason>,
    mut make_engine: F,
) -> anyhow::Result<(Vec<ProfileEntry>, Vec<FailedProfile>)>
where
    F: FnMut(&torrentd_engine::Settings, Option<Vec<u8>>) -> Result<Arc<dyn TorrentEngine>, E>,
    E: std::fmt::Display,
{
    let mut profile_entries: Vec<ProfileEntry> = Vec::new();
    let mut failed_profiles: Vec<FailedProfile> = Vec::new();

    // Which profile holds each tunnel address. A vpn session is bound by
    // address, listening and outgoing alike, so two tunnels that come up with
    // one address (every Proton WireGuard config assigns 10.2.0.2/32) leave
    // nothing — neither the bind nor a source-address routing rule — that can
    // keep one account's traffic out of the other's tunnel. Only known after
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
            crate::port_forward_monitor::refresh_during_boot(built, forwarder, metrics);
        }

        match build_profile(
            p,
            session_settings(cfg),
            &cfg.session_state_path(&p.id),
            cleanup,
            forwarder,
            &tunnel_owner,
            &mut make_engine,
        )
        .await
        {
            Ok(entry) => {
                // Recorded only once this profile's session is built: a
                // profile that fails a later step has its tunnel taken down,
                // and still owning the address then disabled a later profile
                // over a tunnel that no longer exists.
                if let Some(ip) = entry.health().tunnel_ip {
                    tunnel_owner.insert(ip, p.id.clone());
                }
                profile_entries.push(entry);
            }
            Err(failed) => failed_profiles.push(failed),
        }
    }
    Ok((profile_entries, failed_profiles))
}

/// Build one profile's session, or say why it has none.
///
/// Any tunnel this raised and then failed after is taken down before the
/// `Err` returns, so a failed profile leaves nothing standing whether or not
/// the boot around it goes on to succeed. A tunnel that came up for a profile
/// that succeeded stays tracked by `cleanup`, whose drop guard owns it until
/// `boot` disarms it.
async fn build_profile<F, E>(
    p: &ProfileConfig,
    mut settings: torrentd_engine::Settings,
    session_state_path: &std::path::Path,
    cleanup: &mut BootCleanup,
    forwarder: &dyn PortForwarder,
    tunnel_owner: &std::collections::HashMap<IpAddr, ProfileId>,
    make_engine: &mut F,
) -> Result<ProfileEntry, FailedProfile>
where
    F: FnMut(&torrentd_engine::Settings, Option<Vec<u8>>) -> Result<Arc<dyn TorrentEngine>, E>,
    E: std::fmt::Display,
{
    macro_rules! fail_profile {
        ($reason:expr) => {
            return Err(FailedProfile {
                config: p.clone(),
                reason: $reason,
            })
        };
    }

    // A bring-up or teardown task that does not join — a panic inside
    // `spawn_blocking`, or the runtime shutting down under it — fails **that
    // profile**, and the boot carries on with the rest. Every one of these
    // sites was a `?`, which aborted the whole boot: one profile's panicking
    // `wg-quick` wrapper took every other profile's tunnel down with it, on a
    // daemon whose entire purpose is to keep the remaining profiles seeding.
    // Failing the profile is what the surrounding code does with every other
    // per-profile failure, and a failed profile is still visible:
    // `ProfileRegistry::with_failed` keeps it in `/profiles` and `vpn_monitor`
    // emits its tunnel-down series.
    //
    // `boot` as a whole still fails when *no* profile comes up, which is the
    // check below its call to `build_profiles`.
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
            if let Some(owner) = tunnel_owner.get(&ip) {
                error!(
                    profile_id = %p.id,
                    tunnel_ip = %ip,
                    other_profile_id = %owner,
                    "tunnel came up with an address another profile's tunnel already has; \
                     profile disabled, since a session bound by address cannot be kept \
                     out of the other account's tunnel",
                );
                let reason = format!(
                    "tunnel address {ip} is also profile {owner}'s, so neither session can \
                     be kept out of the other's tunnel"
                );
                tear_down_or_warn!(iface);
                fail_profile!(reason);
            }

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

            settings.listen_interfaces = Some(torrentd_engine::bind_endpoint(ip, effective_port));
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

    match make_engine(&settings, session_state) {
        Ok(engine) => {
            info!(
                profile_id = %p.id,
                network = if p.is_vpn() { "vpn" } else { "host" },
                tunnel_ip = tunnel_ip.map(|i| i.to_string()).unwrap_or_default(),
                dht = p.dht_enabled(),
                "profile engine up",
            );
            Ok(ProfileEntry::new(
                p.clone(),
                engine,
                tunnel_ip,
                forwarded_port,
                forwarded_epoch,
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
            kill_switch_active,
            log_handle,
            alert_loop,
            unloaded_at_boot,
            // Bound, not `_`: it has to live to the end of this function,
            // past the teardown. See the field.
            instance_lock: _instance_lock,
        } = self;

        // VPN health monitor (multi-profile only). Spawned before AppState
        // consumes the registry/state/metrics. The port-forward monitor is
        // not here: `boot` starts it as soon as the profiles are built.
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

        // The kill switch was checked once, at install. Anything that flushes
        // the ruleset afterwards — an `nft flush ruleset` from a firewall
        // reload, another service replacing the tables — removed the backstop
        // with nothing noticing.
        if kill_switch_active {
            spawn_supervised(
                "kill_switch_watch",
                metrics.clone(),
                crate::vpn::killswitch::watch(metrics.clone(), shutdown_tx.subscribe()),
            );
        }

        // Long-running pool work and the shutdown latch it checks; the
        // teardown below waits for it before stopping the alert loop.
        let work: Arc<crate::app_state::WorkGate> = Arc::default();

        // Re-drive any plan a crash or a kill left mid-apply, before the API
        // can accept new ones. A half-applied reorganisation is exactly the
        // state an operator cannot reason about. Held in the work gate like an
        // API apply, and stopped between steps the same way.
        if let Some(pool) = pool.clone() {
            crate::pool_apply::spawn_resume_unfinished(
                pool,
                source.clone(),
                state.clone(),
                Arc::clone(&work),
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
            unloaded_at_boot: Arc::new(parking_lot::Mutex::new(unloaded_at_boot)),
            shutdown: shutdown_tx.clone(),
            work: Arc::clone(&work),
        };

        // What the daemon decided to believe, in the journal, once. Anything
        // in this set can claim to be any client, and the key is read only at
        // startup — so an operator who edits it and reloads is told the
        // change requires a restart, and the running value can differ from
        // the file indefinitely. Without this line there is no evidence
        // anywhere of which value the process is actually running.
        //
        // `trusted_proxies` is the parsed set in its effective form, which is
        // what the matcher uses: `::ffff:0:0/96` is logged as `0.0.0.0/0`,
        // because that is every IPv4 peer. `configured` is the text as
        // written, so the line still reads back against the file.
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
        // here — `teardown_network` below closes them.
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
/// 1. **Close every session.** Peer and tracker sockets are bound to a
///    tunnel's address; closing them first means nothing is left to send when
///    the tunnel goes. Dropping the sessions was left to `source` going out of
///    scope at the end of `run_until_signal`, after both steps below — and to
///    every other task holding a clone letting go of it, which nothing waited
///    for.
/// 2. **Bring the tunnels down**, link before rules (`wireguard::native`).
/// 3. **Remove the kill switch last.** It confines the daemon's uid to the
///    tunnels; removing it before they were down, as the teardown did, opened
///    the host's own interface to every socket still bound for one.
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

/// Put every tunnel teardown in flight at once, then join them.
///
/// Moving the bounded exit wait to `spawn_blocking` took it off the runtime's
/// workers and left the daemon's **wall-clock** stop time where it was:
/// awaiting each job before spawning the next is still up to
/// `TERM_GRACE + KILL_GRACE` — seven seconds — per OpenVPN profile, serialized,
/// which is the `7N` this series named as the thing it was avoiding. Each
/// tunnel is an independent interface and an independent process, so there is
/// nothing to serialise for, and every serialized second comes out of the
/// stop budget `deploy/torrentd.service`'s `TimeoutStopSec` bounds.
///
/// Spawning happens in one pass and the awaits in a second, so the jobs run
/// concurrently and the log still reads in profile order. A `JoinError` — the
/// job panicked, or the runtime is shutting down — is warned and skipped:
/// shutdown must not fail on a teardown, and the tunnels that did come down
/// are still worth reporting.
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

/// Read the persisted DHT/session-state blob, or `None` if absent/empty.
/// `s` as one POSIX shell word: single-quoted, with each `'` closed, escaped
/// and reopened. The registry refusal prints a command to paste, and a state
/// directory holding a space or a shell metacharacter must not break it.
fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

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
    if let Err(e) = save_session_state(&shutdown_report_path(state_dir), &bytes) {
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
                "failed to remove network kill switch; the daemon's uid stays \
                 confined to the tunnels until the table is removed \
                 (nft delete table inet torrentd_ks) or a kill-switch boot replaces it",
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
            "the previous run could not remove the network kill switch on its way out; a boot \
             with network_kill_switch replaces it, otherwise remove it with \
             `nft delete table inet torrentd_ks`",
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

    /// The exception to "record it before the attempt": an interface of that
    /// name that is already up and is **not** this profile's.
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

    /// `boot`'s only teardown keeps its bounded wait off the worker.
    ///
    /// `boot` had three call sites that reached a *synchronous* `take_down`
    /// instead — a static profile with no `listen_port`, an unparseable
    /// `port_forward_gateway`, and a NAT-PMP negotiation that failed, which
    /// is what an `openvpn` profile on a provider account without port
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
    /// wrapped once, and `bring_down` is called at exactly the three sites that
    /// document why they are not the helper — `Drop for BootCleanup`, which
    /// cannot await, the shutdown job builder in `run_until_signal`, which
    /// is outside `boot` entirely, and `vpn_cmd::teardown`, which lowers what
    /// `torrentd vpn check --bring-up` raised and runs before `main` has built
    /// a runtime or `boot` has a `BootCleanup` to track anything with.
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
        // direct `bring_down` outside the three documented sites is the same
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
            // three sites that document why they are not it: `Drop for
            // BootCleanup`, where `drop` cannot await, the shutdown job
            // builder in `run_until_signal`, which is outside `boot` entirely,
            // and `vpn_cmd::teardown`, the synchronous `vpn check --bring-up`
            // path that runs before any runtime exists and never enters `boot`.
            vec!["startup.rs: 3".to_string(), "vpn_cmd.rs: 1".to_string()],
            "every teardown in `boot` goes through `take_down_off_worker`; the \
             only other `bring_down` calls are the three that say why they are \
             not it. Found {direct:?} — a new one wants the helper, and a \
             fifth documented site wants this count and its comment moved \
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

    /// The graceful-shutdown drain does not scale with profile count.
    ///
    /// Moving the bounded exit wait onto `spawn_blocking` changed which
    /// thread waits, not how long the daemon takes to stop: awaiting each
    /// job before spawning the next left the wall-clock stop time at up to
    /// seven seconds per OpenVPN profile, serialized, which is the `7N` this
    /// series named as the thing it was avoiding, out of the stop budget
    /// `deploy/torrentd.service`'s `TimeoutStopSec` bounds.
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

    /// A failed boot's teardown keeps the same order between the two things
    /// it owns: tunnels first, then the kill switch.
    #[test]
    fn a_failed_boot_takes_its_tunnels_down_before_the_kill_switch() {
        let text = include_str!("startup.rs");
        let drop_impl = text
            .split("impl Drop for BootCleanup")
            .nth(1)
            .and_then(|s| s.split("\n}\n").next())
            .expect("BootCleanup has a Drop impl");
        let tunnels = drop_impl
            .find("bring_down")
            .expect("drop brings tunnels down");
        let switch = drop_impl
            .find("killswitch::disable")
            .expect("drop removes the kill switch");
        assert!(
            tunnels < switch,
            "tunnels must come down before the kill switch goes"
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
             reaches the profile loop's check",
        );
        assert!(
            matches!(shutdown_rx.try_recv(), Ok(ShutdownReason::Sigterm)),
            "and the receiver the HTTP server's graceful shutdown waits on",
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
            Some("10.2.0.2:51413"),
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
            Some("10.2.0.2:6891"),
            "bound to the tunnel endpoint",
        );
        assert!(
            !settings
                .listen_interfaces
                .as_deref()
                .unwrap_or_default()
                .contains("0.0.0.0"),
            "never the wildcard",
        );
        assert_eq!(settings.outgoing_interfaces.as_deref(), Some("10.2.0.2"));
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
