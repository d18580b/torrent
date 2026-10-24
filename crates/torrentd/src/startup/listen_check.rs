//! The check that every vpn session's listen sockets are held to its tunnel
//! device, at boot before the scans and in the alert loop after.

use std::sync::Arc;

use tokio::sync::broadcast;
use torrentd_engine::AlertSource;
use torrentd_engine::ProfileId;
use torrentd_engine::ProfileSource;
use torrentd_engine::ShutdownReason;
use tracing::error;
use tracing::warn;

use super::shutdown_requested;
use crate::profile_registry::ProfileRegistry;

/// How long the boot waits for every vpn session to report its listen
/// sockets before the scans add a torrent to any ([`check_listen_devices`]).
/// A session opens them as it starts, on libtorrent's network thread, so this
/// is a bound on a session that never reports, not a wait any boot expects
/// to come near.
pub(super) const LISTEN_CHECK_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// How often [`check_listen_devices`] looks for a listen outcome again.
const LISTEN_CHECK_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// Before the scans add a torrent: every vpn session's listen sockets, as its
/// `listen_succeeded` alerts report them, held to `check`
/// ([`listen_device_check`]), so no scan torrent announces from a socket on
/// the wrong device while the alert loop, which checks each socket as it
/// comes up, has not started yet.
///
/// Waits until each vpn session in `hold` has reported a listen outcome,
/// succeeded or failed. A host profile is not waited for. A session that
/// opens more sockets in the same pass (another socket type, the IPv6
/// endpoint) may report them after its first outcome; those are checked by
/// the scans' own holds through the same [`CheckedHold`]. The alerts stay
/// held for the alert loop, which dispatches them, and checks each again, as
/// before.
///
/// `Err` fails the boot: a socket `check` refuses (with any number of
/// sessions, as the alert loop treats it), a session that reports nothing
/// within `bound`, and a shutdown asked for meanwhile.
pub(super) async fn check_listen_devices(
    profiles: &ProfileRegistry,
    hold: &CheckedHold<'_>,
    bound: std::time::Duration,
    shutdown: &mut broadcast::Receiver<ShutdownReason>,
) -> anyhow::Result<()> {
    let mut waiting: Vec<ProfileId> = hold
        .source
        .profiles()
        .into_iter()
        .filter(|id| {
            profiles
                .resolve(id)
                .active()
                .is_some_and(|e| e.config.vpn_interface().is_some())
        })
        .collect();
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        waiting.retain(|id| !hold.hold(id));
        hold.verdict()?;
        if waiting.is_empty() {
            return Ok(());
        }
        if shutdown_requested(shutdown) {
            anyhow::bail!("shutdown requested during the listen device check");
        }
        if tokio::time::Instant::now() >= deadline {
            let named = waiting
                .iter()
                .map(ProfileId::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "vpn profile(s) {named} reported no listen outcome in the {}s the boot waited \
                 after bringing every profile up, so which device their sockets are held to \
                 could not be checked before any torrent was loaded",
                bound.as_secs(),
            );
        }
        tokio::time::sleep(LISTEN_CHECK_POLL).await;
    }
}

/// The boot's alert hold from [`check_listen_devices`] until the alert loop
/// starts: every alert a session posts is held for the loop, and each
/// `listen_succeeded` among them is held to `check` as it is taken, so a
/// socket reported after a session's first listen outcome is checked before
/// the scans go on giving that session torrents to announce.
pub(super) struct CheckedHold<'a> {
    source: &'a ProfileSource,
    check: torrentd_engine::alert_loop::ListenDeviceCheck,
    /// Each socket `check` refused, as `profile ID, ENDPOINT: CAUSE`.
    refused: parking_lot::Mutex<Vec<String>>,
}

impl<'a> CheckedHold<'a> {
    pub(super) fn new(
        source: &'a ProfileSource,
        check: torrentd_engine::alert_loop::ListenDeviceCheck,
    ) -> Self {
        Self {
            source,
            check,
            refused: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Hold `profile`'s alerts, checking each listen socket among them.
    /// Whether one of them was a listen outcome, succeeded or failed.
    pub(super) fn hold(&self, profile: &ProfileId) -> bool {
        let mut reported = false;
        self.source
            .hold_alerts_inspecting(profile, |alert| match alert {
                torrentd_engine::Alert::ListenSucceeded { endpoint, .. } => {
                    reported = true;
                    if let Err(cause) = (self.check)(profile, endpoint) {
                        error!(
                            profile_id = %profile,
                            endpoint = %endpoint,
                            error.kind = "listen_wrong_device",
                            error.cause = %cause,
                            "a listen socket is not held to the profile's tunnel device",
                        );
                        self.refused
                            .lock()
                            .push(format!("profile {profile}, {endpoint}: {cause}"));
                    }
                }
                torrentd_engine::Alert::ListenFailed { .. } => reported = true,
                _ => {}
            });
        reported
    }

    /// [`Self::hold`] on every session, as the scans hold at each batch and
    /// at the end of each profile's scan: a socket a vpn session reports
    /// while another profile's torrents are being loaded is checked there
    /// too, not only once the alert loop starts.
    pub(super) fn hold_all(&self) {
        for profile in self.source.profiles() {
            self.hold(&profile);
        }
    }

    /// `Err`, which fails the boot, once any socket a hold took was refused.
    pub(super) fn verdict(&self) -> anyhow::Result<()> {
        let refused = self.refused.lock();
        if refused.is_empty() {
            return Ok(());
        }
        anyhow::bail!(
            "a vpn session's listen socket is not held to its tunnel device, so its torrents \
             would announce from outside the tunnel; the boot stops before the alert loop \
             starts: {}",
            refused.join("; "),
        )
    }
}

/// The alert loop's
/// [`AlertLoopBuilder::listen_device_check`](torrentd_engine::AlertLoopBuilder::listen_device_check):
/// a vpn profile's listen sockets must each be held to its `vpn_interface`.
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
pub(super) fn listen_device_check(
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use torrentd_engine::AlertLoopBuilder;
    use torrentd_engine::SystemClock;
    use torrentd_engine::TorrentEngine;

    use super::*;
    use crate::profile_registry::ProfileStatus;
    use crate::sd_notify;
    use crate::startup::scan::between_scan_batches;

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

    fn listen_alert(succeeded: bool, endpoint: &str) -> torrentd_engine::Alert {
        use libtorrent_safe::alert::AlertHeader;
        use torrentd_engine::AlertKind;

        let hdr = |kind| AlertHeader {
            kind,
            infohash: None,
            handle: None,
            timestamp_us: 0,
        };
        if succeeded {
            torrentd_engine::Alert::ListenSucceeded {
                hdr: hdr(AlertKind::ListenSucceeded),
                endpoint: endpoint.into(),
            }
        } else {
            torrentd_engine::Alert::ListenFailed {
                hdr: hdr(AlertKind::ListenFailed),
                error_code: libc::EADDRINUSE,
                operation: "bind".into(),
                endpoint: endpoint.into(),
                iface: "wg-acct_a".into(),
                message: "address in use".into(),
            }
        }
    }

    /// The vpn session `acct_a` on `vpn` and the host session `public`, as
    /// `boot` hands them to [`check_listen_devices`].
    fn listen_check_source(
        vpn: &Arc<torrentd_engine::MockEngine>,
    ) -> (Arc<ProfileRegistry>, ProfileSource) {
        let profiles = device_check_registry(vpn.clone());
        let host = Arc::new(torrentd_engine::MockEngine::new());
        let source = ProfileSource::new(vec![
            (ProfileId::new("public"), host as Arc<dyn TorrentEngine>),
            (
                ProfileId::new("acct_a"),
                vpn.clone() as Arc<dyn TorrentEngine>,
            ),
        ]);
        (profiles, source)
    }

    /// Before the scans add anything, a vpn session's listen socket on
    /// another device fails the boot, as it stops the alert loop once that
    /// runs; one held to the tunnel passes, and its alert is still held for
    /// the loop. The host session, which reports nothing, is not waited for.
    #[tokio::test(start_paused = true)]
    async fn the_boot_checks_vpn_listen_sockets_before_the_scans_add_a_torrent() {
        let (_tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);

        let vpn = Arc::new(torrentd_engine::MockEngine::new());
        vpn.push_alert(listen_alert(true, "10.2.0.2:6881"));
        let (profiles, source) = listen_check_source(&vpn);
        let (asked, read) = scripted_sockets(Ok(vec![socket("udp", Some("eth0"))]));
        let check = listen_device_check_with(profiles.clone(), read);
        let err = check_listen_devices(
            &profiles,
            &CheckedHold::new(&source, check.clone()),
            LISTEN_CHECK_BOUND,
            &mut shutdown,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("not held to its tunnel device")
                && err.contains("profile acct_a, 10.2.0.2:6881")
                && err.contains("udp socket held to eth0"),
            "{err}"
        );
        assert_eq!(*asked.lock(), vec!["10.2.0.2:6881".parse().unwrap()]);

        let vpn = Arc::new(torrentd_engine::MockEngine::new());
        vpn.push_alert(listen_alert(true, "10.2.0.2:6881"));
        let (profiles, source) = listen_check_source(&vpn);
        let (_, read) = scripted_sockets(Ok(vec![socket("tcp", Some("wg-acct_a"))]));
        let check = listen_device_check_with(profiles.clone(), read);
        check_listen_devices(
            &profiles,
            &CheckedHold::new(&source, check.clone()),
            LISTEN_CHECK_BOUND,
            &mut shutdown,
        )
        .await
        .expect("a socket held to the tunnel passes");
        let held = source.drain();
        assert_eq!(held.len(), 1, "the alert is left for the alert loop");
        assert_eq!(held[0].0, ProfileId::new("acct_a"));
    }

    /// The check waits for a vpn session's first listen outcome: one that
    /// arrives later passes, a failed listen counts as an outcome (there is
    /// no socket to check, and the alert loop judges the failure), one that
    /// never arrives fails the boot at the bound, and so does a shutdown.
    #[tokio::test(start_paused = true)]
    async fn the_listen_device_check_waits_for_each_vpn_session_up_to_its_bound() {
        let (tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);
        let passing = || scripted_sockets(Ok(vec![socket("tcp", Some("wg-acct_a"))])).1;

        let vpn = Arc::new(torrentd_engine::MockEngine::new());
        let (profiles, source) = listen_check_source(&vpn);
        let check = listen_device_check_with(profiles.clone(), passing());
        let late = {
            let vpn = vpn.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                vpn.push_alert(listen_alert(true, "10.2.0.2:6881"));
            })
        };
        let started = tokio::time::Instant::now();
        check_listen_devices(
            &profiles,
            &CheckedHold::new(&source, check.clone()),
            LISTEN_CHECK_BOUND,
            &mut shutdown,
        )
        .await
        .expect("an outcome that comes later passes");
        assert!(started.elapsed() >= std::time::Duration::from_secs(2));
        late.await.unwrap();

        let vpn = Arc::new(torrentd_engine::MockEngine::new());
        vpn.push_alert(listen_alert(false, "10.2.0.2:6881"));
        let (profiles, source) = listen_check_source(&vpn);
        let check = listen_device_check_with(profiles.clone(), passing());
        check_listen_devices(
            &profiles,
            &CheckedHold::new(&source, check.clone()),
            LISTEN_CHECK_BOUND,
            &mut shutdown,
        )
        .await
        .expect("a failed listen is an outcome");

        let vpn = Arc::new(torrentd_engine::MockEngine::new());
        let (profiles, source) = listen_check_source(&vpn);
        let check = listen_device_check_with(profiles.clone(), passing());
        let started = tokio::time::Instant::now();
        let err = check_listen_devices(
            &profiles,
            &CheckedHold::new(&source, check.clone()),
            LISTEN_CHECK_BOUND,
            &mut shutdown,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("vpn profile(s) acct_a reported no listen outcome in the 30s"),
            "{err}"
        );
        assert!(started.elapsed() >= LISTEN_CHECK_BOUND);

        tx.send(ShutdownReason::Sigterm).unwrap();
        let err = check_listen_devices(
            &profiles,
            &CheckedHold::new(&source, check.clone()),
            LISTEN_CHECK_BOUND,
            &mut shutdown,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("shutdown requested during the listen device check"),
            "{err}"
        );
    }

    /// A socket a vpn session reports after its first listen outcome (here
    /// the IPv6 endpoint of the same pass) is checked by the scans' next
    /// batch hold: one on the wrong device stops the scan there, as it would
    /// have stopped the boot before the scans, and its alert is still held.
    /// The hold takes every session, so the socket is caught while the scan
    /// is loading the host profile's torrents, not only `acct_a`'s.
    #[tokio::test(start_paused = true)]
    async fn a_listen_socket_reported_during_the_scans_is_checked_at_their_next_batch() {
        let (_tx, mut shutdown) = broadcast::channel::<ShutdownReason>(1);
        let progress = sd_notify::Progress::new();

        let vpn = Arc::new(torrentd_engine::MockEngine::new());
        vpn.push_alert(listen_alert(true, "10.2.0.2:6881"));
        let (profiles, source) = listen_check_source(&vpn);
        let check = listen_device_check_with(profiles.clone(), |at: std::net::SocketAddr| {
            let device = if at.is_ipv6() { "eth0" } else { "wg-acct_a" };
            Ok(vec![socket("tcp", Some(device))])
        });
        let hold = CheckedHold::new(&source, check);
        check_listen_devices(&profiles, &hold, LISTEN_CHECK_BOUND, &mut shutdown)
            .await
            .expect("the first socket is on the tunnel");

        // The scan is on `public`'s torrents; `acct_a`'s were loaded first.
        vpn.push_alert(listen_alert(true, "[fd00::2]:6881"));
        let batch = || {
            hold.hold_all();
            hold.verdict()
        };
        between_scan_batches(1, "resume", &mut shutdown, &progress, batch)
            .await
            .expect("only a batch boundary holds");
        let err = between_scan_batches(256, "resume", &mut shutdown, &progress, batch)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not held to its tunnel device")
                && err.contains("profile acct_a, [fd00::2]:6881")
                && err.contains("held to eth0"),
            "{err}"
        );
        assert_eq!(source.drain().len(), 2, "both alerts are left for the loop");
    }
}
