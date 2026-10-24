//! `torrentd vpn check` — verify a profile's VPN configuration against the real
//! host, with no libtorrent session, no torrents and no tracker contact.
//!
//! Host prerequisites run first, so a missing `ip` or `nft` is not buried
//! behind a tunnel bring-up, then each profile's checks in the order `boot`
//! performs them.
//!
//! Observe-only by default: no host change, nothing deleted. A NAT-PMP
//! profile asks the gateway for a short mapping and lets it lapse, through
//! [`RealHost::probe_forwarder`], which issues no delete on any branch.
//! `--bring-up` raises tunnels, and lowers only what it raised, judged from
//! the interface: one present before the call is left alone.
//!
//! Exit status: `0` clean, `1` any failure, `2` nothing failed but a check
//! could not be performed — excluding one no invocation could settle
//! ([`Check::needs_capability`]). See [`Report::exit_code`].

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use torrentd_engine::PortForwardMode;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use torrentd_engine::ProfileConfig;
use torrentd_engine::VpnError;
use torrentd_engine::VpnManager;
use torrentd_engine::VpnType;

use crate::config::Config;
use crate::vpn;

/// How long an egress probe waits before calling the tunnel unusable.
const EGRESS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Fail,
    /// Correctly configured to not apply — a NAT-PMP check on a static profile,
    /// a handshake check on OpenVPN. Distinct from `Pass` so a summary cannot
    /// read as "everything was verified" when most of it was skipped.
    Skip,
    /// The check could not be performed. Not the same as failing: an absent
    /// `wg` binary says nothing about whether the tunnel is healthy, and
    /// reporting it as a failure would train an operator to ignore failures.
    Unknown,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
    /// Set on an `Unknown` that **no invocation of this command on this host
    /// could settle** — usually for want of `CAP_NET_ADMIN`, which the
    /// daemon's own user lacks. Reported, but it does not colour the exit
    /// status, or a healthy host run as that user would never exit 0.
    #[serde(skip_serializing_if = "is_false")]
    pub needs_capability: bool,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Pass,
            detail: detail.into(),
            needs_capability: false,
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Fail,
            detail: detail.into(),
            needs_capability: false,
        }
    }
    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Skip,
            detail: detail.into(),
            needs_capability: false,
        }
    }
    fn unknown(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Unknown,
            detail: detail.into(),
            needs_capability: false,
        }
    }
    /// An `Unknown` nothing this invocation could be given would settle —
    /// for want of a capability, or because the answer lies outside this
    /// process — which does not colour the exit status. See
    /// [`Check::needs_capability`].
    fn unknown_unsettleable(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            needs_capability: true,
            ..Self::unknown(name, detail)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ProfileReport {
    pub profile_id: String,
    pub vpn_type: &'static str,
    pub checks: Vec<Check>,
}

impl ProfileReport {
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Fail)
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub host: Vec<Check>,
    pub profiles: Vec<ProfileReport>,
}

/// Everything established was good — excluding a check nothing this
/// invocation could be given would settle, which is reported and does not
/// colour the status. See [`Check::needs_capability`].
pub const EXIT_OK: i32 = 0;
/// At least one check failed.
pub const EXIT_FAILED: i32 = 1;
/// Nothing failed, but at least one check could not be performed.
pub const EXIT_UNKNOWN: i32 = 2;

impl Report {
    pub fn failed(&self) -> bool {
        self.host.iter().any(|c| c.verdict == Verdict::Fail)
            || self.profiles.iter().any(ProfileReport::failed)
    }

    fn checks(&self) -> impl Iterator<Item = &Check> {
        self.host
            .iter()
            .chain(self.profiles.iter().flat_map(|s| &s.checks))
    }

    /// Whether any check could not be performed, excluding
    /// [`Check::needs_capability`] ones.
    pub fn incomplete(&self) -> bool {
        self.checks()
            .any(|c| c.verdict == Verdict::Unknown && !c.needs_capability)
    }

    /// Whether anything was left unsettled for want of a capability.
    pub fn capability_bound(&self) -> bool {
        self.checks().any(|c| c.needs_capability)
    }

    /// The exit status this report implies: an `Unknown` is not success,
    /// since the status is all a `mise` task or `ExecStartPre` reads. A `Skip`
    /// correctly did not apply, and does not colour it.
    pub fn exit_code(&self) -> i32 {
        if self.failed() {
            EXIT_FAILED
        } else if self.incomplete() {
            EXIT_UNKNOWN
        } else {
            EXIT_OK
        }
    }
}

/// `CAP_NET_ADMIN`'s bit in a capability mask (`linux/capability.h`).
const CAP_NET_ADMIN_BIT: u32 = 12;

/// Whether `CapEff` in a `/proc/<pid>/status` body carries `bit`.
///
/// `None` when the file carried no `CapEff` line or an unparseable one, which
/// the caller reads as "do not classify anything from this".
fn cap_eff_has(status: &str, bit: u32) -> Option<bool> {
    let rest = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))?
        .trim();
    let mask = u64::from_str_radix(rest, 16).ok()?;
    Some(mask & (1u64 << bit) != 0)
}

/// Whether this process holds `CAP_NET_ADMIN`, which `nft --check` and
/// `wg show … latest-handshakes` both need, read from `/proc/self/status`.
/// `true` when the mask cannot be read, so a genuine rejection stays a
/// failure.
fn has_cap_net_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| cap_eff_has(&s, CAP_NET_ADMIN_BIT))
        .unwrap_or(true)
}

/// The host-touching operations a profile's checks perform, behind a trait so the
/// branch structure around them is testable without a tunnel or a gateway.
///
/// Two of those branches are the reason this exists rather than being inlined:
/// whether `--bring-up` tears an interface down, and whether the NAT-PMP
/// negotiation releases what it mapped. Both are decisions about somebody
/// else's live daemon, and a decision that can only be exercised on a host
/// with a real tunnel is a decision nothing can hold in place.
pub trait CheckHost {
    /// Whether the kernel already has this interface.
    ///
    /// Deliberately not `first_ipv4`: an interface that exists with no address
    /// is still an interface this command did not create, and tearing it down
    /// is still somebody else's outage.
    fn interface_exists(&self, iface: &str) -> bool;

    /// The address the daemon would bind every socket in this profile to,
    /// and the one `killswitch::enable` pairs the profile's interface with.
    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr>;

    /// The link's global IPv6 addresses, which `killswitch::enable` also
    /// pairs with the interface; none where they cannot be read, as there.
    fn tunnel_ipv6(&self, iface: &str) -> Vec<std::net::Ipv6Addr>;

    /// The tunnel manager for a profile's VPN type.
    fn manager(&self, t: VpnType, run_dir: &Path) -> Arc<dyn VpnManager>;

    /// A NAT-PMP client with startup's retransmit budget that deletes nothing,
    /// not even inside `map` ([`RealHost::probe_forwarder`]).
    fn forwarder(&self) -> Arc<dyn PortForwarder>;

    /// Read a sysctl, or `None` if it could not be read.
    ///
    /// Behind the trait because `conf/<iface>/rp_filter` only exists once the
    /// interface does, so *when* it is read decides what it says — and
    /// `--bring-up` exists precisely to make an interface that was not there.
    fn read_sysctl(&self, path: &str) -> Option<String>;

    /// Whether an executable answers `probe_arg` with a zero status.
    fn tool_available(&self, bin: &str, probe_arg: &str) -> bool;

    /// Stat the profile's tunnel config, or say why it could not be.
    fn profile_metadata(&self, path: &Path) -> std::io::Result<()>;

    /// [`vpn::wireguard_handshake_age`], with its reason reduced to the string
    /// that type already publishes.
    ///
    /// Behind the trait so [`judge_handshake`]'s fresh and stale arms are
    /// reachable through [`profile_checks`] without a live tunnel, and so a profile's
    /// checks reach the host through this seam and nothing else.
    fn handshake_age(&self, iface: &str) -> Result<Option<Duration>, &'static str>;

    /// This process's effective uid, or why it could not be read.
    fn current_uid(&self) -> Result<u32, String>;

    /// Whether this process holds `CAP_NET_ADMIN`.
    fn has_cap_net_admin(&self) -> bool;

    /// Dry-run a ruleset through `nft --check --file -`.
    ///
    /// Behind the trait because the two classes its stderr distinguishes —
    /// a parse rejection and a netlink cache failure — are what
    /// [`judge_nft_check`] classifies on, and a test that shells out to the
    /// real `nft` asserts whatever this machine happens to answer.
    fn nft_check(&self, ruleset: &str) -> std::io::Result<std::process::Output>;

    /// Whether `iface` is a WireGuard device: `Some(false)` is a positive
    /// reading that it is not one, and `None` means neither read answered.
    ///
    /// Behind the trait for the same reason as the rest, and separate from
    /// the handshake probe because it is the one question `wg show` cannot
    /// answer: `wg` refuses a non-WireGuard interface and an interface it
    /// lacks the capability to read with the same error.
    fn wireguard_device(&self, iface: &str) -> Option<bool>;

    /// The WireGuard link `iface`'s listen port and peer endpoints — the
    /// probe `killswitch::enable` reads each tunnel's transport exemption
    /// from.
    fn transport(&self, iface: &str) -> std::io::Result<vpn::killswitch::Transport>;

    /// Where the kernel would route a packet from `src` to `dest`, judged
    /// against `iface` — the health monitor's route probe.
    fn route_probe(
        &self,
        iface: &str,
        src: IpAddr,
        dest: IpAddr,
    ) -> Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>;
}

/// `CheckHost` against the actual machine.
#[derive(Debug, Clone, Copy)]
pub struct RealHost;

impl RealHost {
    /// The NAT-PMP client this command negotiates with.
    ///
    /// Named rather than inlined so the one property that matters about it —
    /// that it deletes nothing — is assertable without a gateway.
    pub fn probe_forwarder() -> vpn::NatpmpForwarder {
        vpn::NatpmpForwarder::for_probe()
    }
}

impl CheckHost for RealHost {
    fn interface_exists(&self, iface: &str) -> bool {
        vpn::link_standing(iface)
    }

    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr> {
        vpn::first_ipv4(iface)
    }

    fn tunnel_ipv6(&self, iface: &str) -> Vec<std::net::Ipv6Addr> {
        vpn::killswitch::tunnel_ipv6(iface)
    }

    fn manager(&self, t: VpnType, run_dir: &Path) -> Arc<dyn VpnManager> {
        vpn::for_type(t, run_dir)
    }

    fn forwarder(&self) -> Arc<dyn PortForwarder> {
        Arc::new(Self::probe_forwarder())
    }

    fn read_sysctl(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn tool_available(&self, bin: &str, probe_arg: &str) -> bool {
        vpn::exec::available(bin, probe_arg)
    }

    fn profile_metadata(&self, path: &Path) -> std::io::Result<()> {
        std::fs::metadata(path).map(|_| ())
    }

    fn handshake_age(&self, iface: &str) -> Result<Option<Duration>, &'static str> {
        vpn::wireguard_handshake_age(iface).map_err(|why| why.as_str())
    }

    fn current_uid(&self) -> Result<u32, String> {
        vpn::killswitch::current_uid().map_err(|e| e.to_string())
    }

    fn has_cap_net_admin(&self) -> bool {
        has_cap_net_admin()
    }

    fn nft_check(&self, ruleset: &str) -> std::io::Result<std::process::Output> {
        vpn::killswitch::check(ruleset)
    }

    fn wireguard_device(&self, iface: &str) -> Option<bool> {
        // `ip -d link show` needs no capability, and it reads the link type
        // from this process's namespace — the one `wg` and the managers see.
        // It used to be preceded by `/sys/class/net/<iface>/uevent`, which is
        // the namespace sysfs was mounted in. Not answering is `None`, which
        // leaves the handshake verdict exactly where it was.
        let name = vpn::exec::iface(iface).ok()?;
        let out = vpn::exec::run(
            "ip",
            &["-d", "link", "show", "dev", name],
            None,
            vpn::exec::QUICK,
        )
        .ok()?;
        if !out.status.success() {
            return None;
        }
        link_type_is_wireguard(&String::from_utf8_lossy(&out.stdout))
    }

    fn transport(&self, iface: &str) -> std::io::Result<vpn::killswitch::Transport> {
        vpn::killswitch::transport(iface)
    }

    fn route_probe(
        &self,
        iface: &str,
        src: IpAddr,
        dest: IpAddr,
    ) -> Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable> {
        vpn::route::probe(iface, src, dest)
    }
}

/// Read `ip -d link show <iface>`'s output for whether the link is WireGuard.
///
/// Matched on bare words, not substrings: an interface *named* `wireguard` or
/// `tun` prints as `wireguard:` or `tun:` and must not answer this itself.
///
/// A `tun` link is `None`, not `Some(false)`: `wireguard-go`, the userspace
/// implementation `wg-quick` falls back to without the kernel module, is a
/// `tun` device, so its link type separates nothing and only the handshake
/// probe can say what is behind it.
fn link_type_is_wireguard(ip_detail: &str) -> Option<bool> {
    let has = |word: &str| ip_detail.split_whitespace().any(|t| t == word);
    if has("wireguard") {
        Some(true)
    } else if has("tun") {
        None
    } else {
        Some(false)
    }
}

/// The effective reverse-path filter for one interface.
///
/// The kernel applies `max(conf/all/rp_filter, conf/<iface>/rp_filter)` to
/// source validation on an interface, so `conf/all` alone answers the question
/// in neither direction. A host with `all = 0` and `default = 1` gives every
/// freshly created WireGuard interface `rp_filter = 1` by inheritance and drops
/// every reply to a tunnel-bound socket — which is exactly the symptom this
/// check exists to catch — while `conf/all` reads clean. The converse misfires
/// too: `all = 1` with every interface at `2` is loose and healthy.
///
/// Each argument is the raw file contents, or `None` if the file could not be
/// read. An unparseable value is `unknown`: the previous `Some(v) => pass` arm
/// passed anything that was not the literal `"1"`, including nonsense.
fn judge_rp_filter(iface: &str, all: Option<&str>, per_iface: Option<&str>) -> Check {
    fn mode(v: u8) -> &'static str {
        match v {
            0 => "off",
            1 => "strict",
            _ => "loose",
        }
    }
    let read = |what: &str, raw: Option<&str>| -> Result<u8, String> {
        match raw {
            None => Err(format!("could not read {what}")),
            Some(s) => s
                .trim()
                .parse::<u8>()
                .map_err(|e| format!("{what} is {s:?}, which is not a number: {e}")),
        }
    };
    let all_path = "net.ipv4.conf.all.rp_filter";
    let iface_path = format!("net.ipv4.conf.{iface}.rp_filter");
    let (a, i) = match (read(all_path, all), read(&iface_path, per_iface)) {
        (Ok(a), Ok(i)) => (a, i),
        (Err(e), _) | (_, Err(e)) => {
            return Check::unknown(
                "rp_filter",
                format!("{e}; the kernel takes max({all_path}, {iface_path}) for {iface}"),
            )
        }
    };
    let effective = a.max(i);
    let detail = format!(
        "{iface}: {all_path} = {a}, {iface_path} = {i}, effective {effective} ({})",
        mode(effective)
    );
    if effective == 1 {
        Check::fail(
            "rp_filter",
            format!(
                "{detail}: replies to sockets bound to {iface} are dropped by the kernel. \
                 Set both to 2."
            ),
        )
    } else {
        Check::pass("rp_filter", detail)
    }
}

/// The uid the kill-switch ruleset would confine.
///
/// `as_uid` is what the operator asked about; `invoker` is this process,
/// which under `sudo … --bring-up` is routinely not the daemon's uid. The
/// config carries no uid, so a subject the invoker is not is unestablished —
/// except `0`, which `killswitch::enable` refuses whoever asks: a failure.
fn judge_kill_switch_uid(as_uid: Option<u32>, invoker: Result<u32, String>) -> Check {
    let subject = match (as_uid, invoker.as_ref()) {
        (Some(u), _) => u,
        (None, Ok(u)) => *u,
        (None, Err(e)) => {
            return Check::unknown(
                "kill_switch_uid",
                format!("could not read this process's uid ({e}), and --as-uid was not given"),
            )
        }
    };
    let named = as_uid.is_some();
    if subject == 0 {
        let whose = if named && invoker.as_ref().ok() != Some(&subject) {
            "--as-uid names uid 0"
        } else {
            "running as uid 0"
        };
        return Check::fail(
            "kill_switch_uid",
            format!(
                "{whose}: the kill-switch ruleset confines the daemon's uid to loopback and \
                 its tunnels, which as root would drop every root-owned process's traffic on \
                 this host. `killswitch::enable` refuses uid 0 whoever asks, so the boot \
                 aborts installing the kill switch"
            ),
        );
    }
    if invoker.as_ref().ok() != Some(&subject) {
        let who = match invoker.as_ref() {
            Ok(i) => format!("this process is uid {i}"),
            Err(e) => format!("this process's own uid could not be read: {e}"),
        };
        // Not counted against the status, and for the same reason the
        // capability-bound unknowns are not: nothing this invocation can be
        // told settles it. `--as-uid` names a uid the invoker is not *by
        // definition*, and this process cannot observe which user the daemon
        // runs as, so the mismatch is the expected answer on the one
        // privileged invocation the documentation describes rather than a
        // sign of anything. Leaving it to colour the status left
        // `vpn check` on a `network_kill_switch = true` host with no route to
        // 0 by any argument combination — under `sudo` the subject is 0 and
        // fails, `--as-uid 0` fails, and `--as-uid <daemon uid>` cost 2 —
        // which is the trap the three-valued status exists to prevent.
        return Check::unknown_unsettleable(
            "kill_switch_uid",
            format!(
                "asked about uid {subject}, but {who}, so whether that uid is the one the \
                 daemon runs as was not established — and nothing this command can be given \
                 would establish it. The ruleset below is still rendered and dry-run for uid \
                 {subject}"
            ),
        );
    }
    Check::pass("kill_switch_uid", format!("running as uid {subject}"))
}

/// The uid `kill_switch_ruleset` renders and dry-runs for, whatever
/// `kill_switch_uid` concluded: whether the ruleset parses does not depend on
/// who asks.
fn ruleset_subject(as_uid: Option<u32>, invoker: Result<u32, String>) -> Option<u32> {
    as_uid.or_else(|| invoker.ok())
}

/// The verdict `nft --check --file -` implies for a rendered ruleset.
///
/// Classified on **what `nft` reported**, not on who asked: nftables parses
/// before it touches netlink, so a parse diagnostic is a rejection of the
/// ruleset even from an unprivileged shell, and a lone netlink error is the
/// capability. `privileged` ([`has_cap_net_admin`]) only corroborates.
/// Whether nft's stderr is a **rejection of the ruleset**.
///
/// nftables prefixes every netlink failure with `netlink:`. Any other `Error:`
/// line came out of the parser or the rule evaluator, both of which run before
/// netlink is touched and need no capability at all — so it is a rejection
/// whatever mask the invoker holds. An unprivileged run against a ruleset that
/// does not parse prints *both* lines, which is why this is asked first.
fn nft_rejected_the_ruleset(stderr: &str) -> bool {
    stderr
        .lines()
        .map(str::trim)
        .any(|l| l.contains("Error:") && !l.starts_with("netlink:"))
}

/// Whether nft's stderr says it could not reach the kernel.
fn nft_reported_netlink_failure(stderr: &str) -> bool {
    stderr.lines().map(str::trim).any(|l| {
        l.starts_with("netlink:")
            || l.contains("Operation not permitted")
            || l.contains("Permission denied")
    })
}

fn judge_nft_check(
    outcome: std::io::Result<std::process::Output>,
    privileged: bool,
    uid: u32,
    ruleset: &str,
) -> Check {
    // Boot builds this interface list from the profiles whose tunnel actually
    // came up, not from every configured profile. Without a live registry this
    // check cannot know that set; naming the discrepancy is honest, and
    // guessing at it would not be.
    let caveat = "interfaces listed are the configured profiles this run checks; boot lists \
                  every profile whose tunnel came up";
    match outcome {
        Err(e) => Check::unknown(
            "kill_switch_ruleset",
            format!("could not run `nft --check --file -`: {e}. {caveat}\n{ruleset}"),
        ),
        Ok(o) if o.status.success() => Check::pass(
            "kill_switch_ruleset",
            format!("`nft --check` accepted this ruleset for uid {uid}. {caveat}\n{ruleset}"),
        ),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if nft_reported_netlink_failure(&err) && !nft_rejected_the_ruleset(&err) {
                let mask = if privileged {
                    "this process does hold CAP_NET_ADMIN, so the refusal is not a plain \
                     capability gap"
                } else {
                    "this process does not hold CAP_NET_ADMIN, which is what nft needs to \
                     reach the kernel"
                };
                Check::unknown_unsettleable(
                    "kill_switch_ruleset",
                    format!(
                        "the ruleset for uid {uid} parses, but `nft --check` could not \
                         validate it against this kernel ({err}); {mask}. {caveat}"
                    ),
                )
            } else {
                Check::fail(
                    "kill_switch_ruleset",
                    format!(
                        "`nft --check` rejected the ruleset boot would install, so the boot \
                         would abort installing it: {err}. {caveat}"
                    ),
                )
            }
        }
    }
}

/// The verdict a WireGuard handshake probe implies.
///
/// `probe` is [`vpn::wireguard_handshake_age`]'s result with its reason
/// reduced to the string that type already publishes. `privileged` is whether
/// this process holds `CAP_NET_ADMIN`, which is what `wg show <iface>
/// latest-handshakes` needs.
///
/// `is_wireguard_device` ([`CheckHost::wireguard_device`]) settles a refused
/// probe, which means either "not a WireGuard interface" or "no permission":
/// a positive reading that it is not one is a `fail` about the
/// configuration. A probe that answered needs no such reading; a userspace
/// tunnel is a `tun` device with no wireguard link type.
fn judge_handshake(
    iface: &str,
    probe: Result<Option<Duration>, &str>,
    max: Duration,
    privileged: bool,
    is_wireguard_device: Option<bool>,
) -> Check {
    if probe.is_err() && is_wireguard_device == Some(false) {
        return Check::fail(
            "handshake",
            format!(
                "{iface} is not a WireGuard device: the kernel reports no wireguard link \
                 type for it, so `wg show {iface} latest-handshakes` can never answer and \
                 the daemon's health monitor would fall back to IP presence alone for this \
                 profile. Point vpn_interface at the profile's own tunnel"
            ),
        );
    }
    match probe {
        Ok(Some(age)) if age <= max => Check::pass(
            "handshake",
            format!(
                "last handshake {}s ago (threshold {}s)",
                age.as_secs(),
                max.as_secs()
            ),
        ),
        Ok(Some(age)) => Check::fail(
            "handshake",
            format!(
                "last handshake {}s ago, over the {}s threshold: the daemon would fence this \
                 profile",
                age.as_secs(),
                max.as_secs()
            ),
        ),
        Ok(None) => Check::unknown(
            "handshake",
            "no peer has handshaked yet; the tunnel may still be coming up",
        ),
        Err("refused") if !privileged => {
            // What was established, and nothing more. The old text finished
            // "the daemon has it and would run this probe", which is a
            // prediction about a process this command never looked at — and
            // it was printed verbatim for an interface `wg` would refuse the
            // daemon too.
            let corroboration = match is_wireguard_device {
                Some(true) => format!(
                    " {iface} is a WireGuard device, so the missing capability accounts for \
                     the refusal on its own."
                ),
                _ => format!(
                    " Whether {iface} is a WireGuard device could not be read either, so the \
                     refusal has two possible causes and this run separated neither."
                ),
            };
            Check::unknown_unsettleable(
                "handshake",
                format!(
                    "`wg show {iface} latest-handshakes` was refused and this process does \
                     not hold CAP_NET_ADMIN, which it needs.{corroboration} Run as a user \
                     that holds that capability to settle it"
                ),
            )
        }
        Err(why) => Check::unknown(
            "handshake",
            format!("probe unavailable ({why}); the daemon would run on IP presence alone"),
        ),
    }
}

/// Checks that are about the host, not any one profile.
///
/// `iproute2` and `nftables` are host-wide; `rp_filter` is per interface and
/// lives in [`profile_checks`]. Every host touch goes through `host`, so the
/// classification here is testable without the real `ip` and `nft`.
fn host_checks(
    cfg: &Config,
    as_uid: Option<u32>,
    only: Option<&str>,
    host: &dyn CheckHost,
) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(if host.tool_available("ip", "-V") {
        Check::pass("iproute2", "`ip` is available")
    } else {
        Check::fail(
            "iproute2",
            "`ip` is not executable; every tunnel IP lookup in the daemon shells out to it",
        )
    });

    if cfg.network_kill_switch {
        out.push(if host.tool_available("nft", "--version") {
            Check::pass("nftables", "`nft` is available")
        } else {
            Check::fail(
                "nftables",
                "network_kill_switch = true but `nft` is not executable",
            )
        });

        let invoker = host.current_uid();
        out.push(judge_kill_switch_uid(as_uid, invoker.clone()));

        // The ruleset boot would install, dry-run rather than asserted.
        // Rendering a string established only that a string was formatted: on
        // a host where `nft` is present but the invoker lacks CAP_NET_ADMIN,
        // or where `nft -f` would reject the table, `pass` was printed and the
        // boot then aborted at `killswitch::enable`. `pass` sits in the same
        // four-valued vocabulary as the rest, and it was the only verdict this
        // check could ever produce.
        //
        // Rendered for whatever uid the operator named, whatever the check
        // above concluded about it. See `ruleset_subject`.
        out.push(match ruleset_subject(as_uid, invoker) {
            None => Check::unknown(
                "kill_switch_ruleset",
                "no uid was named and this process's own could not be read, so there is \
                 nothing to render a ruleset for; see kill_switch_uid",
            ),
            Some(uid) => {
                // `--profile` scopes the ruleset too, so an excluded profile's
                // interface cannot decide this run.
                let tunnels: Vec<String> = cfg
                    .profile
                    .iter()
                    .filter(|p| only.is_none_or(|id| p.id.as_str() == id))
                    .filter_map(|p| p.vpn_interface().map(str::to_string))
                    .collect();
                // The script boot hands to `nft -f` — `killswitch::install_script`,
                // the same renderer `killswitch::enable` calls — over the
                // tunnel addresses and transports that can be read now.
                // Boot reads each one off the live link and refuses to
                // install without it; a link that is not up yet has neither
                // to read, so what is missing is named rather than guessed at.
                let (ruleset, unread) = boot_install_script(uid, &tunnels, host);
                // A name the renderer refuses is the same boot abort as a
                // ruleset `nft` rejects, reported before any `nft` runs.
                let verdict = match ruleset {
                    Ok(ruleset) => judge_nft_check(
                        host.nft_check(&ruleset),
                        host.has_cap_net_admin(),
                        uid,
                        &ruleset,
                    ),
                    Err(e) => Check::fail("kill_switch_ruleset", e.to_string()),
                };
                note_unread(verdict, &unread)
            }
        });
    } else {
        out.push(Check::skip("kill_switch", "network_kill_switch = false"));
    }

    out
}

/// What [`boot_install_script`] could not read off the live links.
#[derive(Debug, Default)]
struct Unread {
    /// Tunnels with no address to pair their interface with, which the
    /// dry-run therefore carries no accept for.
    addresses: Vec<String>,
    /// Tunnels with no listen port or peer endpoint, whose transport the
    /// dry-run therefore does not exempt.
    ports: Vec<String>,
}

/// The kill-switch script boot would install for `uid` over `tunnels`: each
/// tunnel whose address `host` can read accepted from that address on its
/// own interface, the transport exemption for every tunnel whose listen port
/// `host` can read, and the tunnels it could read neither for.
///
/// Rendered by [`vpn::killswitch::install_script`], which is what
/// `killswitch::enable` renders with: for the same uid, tunnels, addresses
/// and ports the two are the same bytes. They used to differ — this command
/// dry-ran the bare table with no transport exemption and no replace, which
/// is not the script boot installs.
///
/// Every interface name is checked as the renderer would check it, including
/// a tunnel left out for want of an address: a name `nft` cannot parse fails
/// boot whether or not its link is up.
fn boot_install_script(
    uid: u32,
    tunnels: &[String],
    host: &dyn CheckHost,
) -> (std::io::Result<String>, Unread) {
    let mut unread = Unread::default();
    if let Err(e) = vpn::killswitch::check_interface_names(tunnels.iter().map(String::as_str)) {
        return (Err(e), unread);
    }
    let mut paired = Vec::new();
    let mut transports = Vec::new();
    for iface in tunnels {
        match host.first_ipv4(iface) {
            Ok(addr) => paired.push(
                vpn::killswitch::Tunnel::new(iface.as_str(), addr).with_v6(host.tunnel_ipv6(iface)),
            ),
            Err(_) => unread.addresses.push(iface.clone()),
        }
        match host.transport(iface) {
            Ok(t) => transports.push(t),
            Err(_) => unread.ports.push(iface.clone()),
        }
    }
    (
        vpn::killswitch::install_script(uid, &paired, &transports),
        unread,
    )
}

/// Say which tunnel addresses and transport exemptions the dry-run could not
/// include.
///
/// Not a verdict of its own: the ruleset's syntax and its acceptance by this
/// kernel do not depend on an address or a port number, so the dry-run still
/// establishes what it establishes. What boot would do differently is
/// stated: it reads both off the live link and refuses the install if it
/// cannot.
fn note_unread(mut verdict: Check, unread: &Unread) -> Check {
    if !unread.addresses.is_empty() {
        verdict.detail.push_str(&format!(
            "\nno tunnel address could be read for {} (not up?), so this dry-run accepts \
             nothing on it; boot pairs each tunnel's interface with the address read off \
             the live link and refuses to install the kill switch without it",
            unread.addresses.join(", "),
        ));
    }
    if !unread.ports.is_empty() {
        verdict.detail.push_str(&format!(
            "\nno listen port and peer endpoint could be read for {} (not up?), so this \
             dry-run carries no \
             transport exemption for it; boot reads each one off the live link and refuses \
             to install the kill switch without it",
            unread.ports.join(", "),
        ));
    }
    verdict
}

/// Prove that a socket **bound to the tunnel address** can send and receive.
///
/// What tells a tunnel that exists from one that works. A source-bound UDP
/// DNS query, since `std::net` cannot set a TCP connection's source address
/// and every resolver answers DNS.
fn egress_probe(src: IpAddr, dest: SocketAddr) -> Check {
    let sock = match std::net::UdpSocket::bind(SocketAddr::new(src, 0)) {
        Ok(s) => s,
        Err(e) => {
            return Check::fail(
                "egress",
                format!(
                    "cannot bind a UDP socket to the tunnel address {src}: {e}. Every socket \
                     in this profile would fail the same way."
                ),
            )
        }
    };
    if let Err(e) = sock.set_read_timeout(Some(EGRESS_TIMEOUT)) {
        return Check::unknown("egress", format!("could not set a read timeout: {e}"));
    }
    if let Err(e) = sock.connect(dest) {
        return Check::fail("egress", format!("cannot reach {dest} from {src}: {e}"));
    }

    // Minimal DNS query: header + QNAME + QTYPE(A) + QCLASS(IN).
    const TXID: u16 = 0x7d0e;
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&TXID.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // 1 question
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answer/authority/additional
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    if let Err(e) = sock.send(&q) {
        return Check::fail("egress", format!("send from {src} to {dest} failed: {e}"));
    }
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        Ok(n) if n >= 2 && buf[0..2] == TXID.to_be_bytes() => Check::pass(
            "egress",
            format!("{src} -> {dest} round trip succeeded ({n} bytes)"),
        ),
        Ok(n) => Check::unknown(
            "egress",
            format!("{n} bytes came back from {dest} but not our query; treat as inconclusive"),
        ),
        // What the probe establishes is that this destination did not answer a
        // DNS query in time. "The tunnel carries nothing" is one reading of
        // that and not the only one — the argument is a bare socket address
        // that nothing validates as a resolver — and this is the branch that
        // carries the exit code, so it states both rather than handing the
        // operator the alarming one. The non-matching-reply branch above
        // already reports itself this way.
        Err(e) => Check::fail(
            "egress",
            format!(
                "no reply from {} port {} within {}s on a socket bound to {src}: {e}. Two \
                 readings: {} may not answer DNS on port {}, or the tunnel is not carrying \
                 traffic.",
                dest.ip(),
                dest.port(),
                EGRESS_TIMEOUT.as_secs(),
                dest.ip(),
                dest.port(),
            ),
        ),
    }
}

/// Check one **vpn** profile.
///
/// The three assertions below hold because [`profile_reports`] filters the
/// selection on [`ProfileConfig::is_vpn`] and routes a host profile to
/// [`no_tunnel_report`] instead. They were reachable before that filter
/// existed.
fn profile_checks(
    cfg: &Config,
    profile: &ProfileConfig,
    bring_up: bool,
    egress: Option<SocketAddr>,
    host: &dyn CheckHost,
) -> ProfileReport {
    let mut checks = Vec::new();
    let iface = profile
        .vpn_interface()
        .expect("only vpn profiles reach profile_checks");
    let vpn_config = match &profile.network {
        torrentd_engine::ProfileNetwork::Vpn { vpn_config, .. } => vpn_config.clone(),
        torrentd_engine::ProfileNetwork::Host { .. } => {
            unreachable!("filtered by profile_reports")
        }
    };
    let vpn_type = profile
        .vpn_type()
        .expect("only vpn profiles reach profile_checks");

    // 1. The tunnel config the daemon would raise the link from / hand to
    //    openvpn.
    checks.push(match host.profile_metadata(&vpn_config) {
        Ok(_) => Check::pass(
            "vpn_config",
            format!("{} is readable", vpn_config.display()),
        ),
        Err(e) => Check::fail("vpn_config", format!("{}: {e}", vpn_config.display())),
    });

    // 2. The tools that profile's type needs.
    match vpn_type {
        VpnType::Wireguard => {
            // No `wg-quick` line: the daemon raises every link with `ip` and
            // `wg` itself and never runs it.
            checks.push(if host.tool_available("wg", "--version") {
                Check::pass("wireguard_tools", "`wg` is available")
            } else {
                Check::fail(
                    "wireguard_tools",
                    "`wg` is not executable: the daemon cannot raise the link, and the \
                     handshake half of the health monitor cannot run",
                )
            });
        }
        VpnType::Openvpn => {
            checks.push(if host.tool_available("openvpn", "--version") {
                Check::pass("openvpn", "`openvpn` is available")
            } else {
                Check::fail("openvpn", "`openvpn` is not executable")
            });
        }
    }

    // 3. Optionally raise the tunnel, as boot would. An interface already
    //    there (usually a running daemon's) is checked and never lowered.
    //    Whether this command raised it is read from the interface, re-probed
    //    after `bring_up`, not from its result: an `Err` can leave one behind,
    //    and adoption returns `Ok` for one that already stood.
    let manager = host.manager(vpn_type, &cfg.state_dir());
    let existed_before = bring_up && host.interface_exists(iface);
    let mut raised_here = false;
    if bring_up {
        if existed_before {
            checks.push(Check::skip(
                "bring_up",
                format!(
                    "{iface} already exists — not raised by this command, and it will not be \
                     taken down. Every check below runs against it as it stands."
                ),
            ));
        } else {
            let outcome = manager.bring_up(&profile.vpn_tunnel().expect("vpn profile"));
            raised_here = host.interface_exists(iface);
            match outcome {
                Ok(ip) => {
                    checks.push(Check::pass("bring_up", format!("tunnel came up on {ip}")));
                }
                Err(e) => {
                    // The caveat below belongs to the manager in hand.
                    // `openvpn --daemon` forks and exits 0 before its own
                    // address poll, so a failure there can leave a process
                    // standing that this command cannot see to stop;
                    // `wg-quick up` leaves no surviving process, and printing
                    // openvpn's mechanism for a WireGuard profile sent the
                    // operator looking for an orphan that cannot exist — on
                    // the one failure path where the report's precision is
                    // the point.
                    let aftermath = if raised_here {
                        format!(
                            "; {iface} is there even so, so this command raised it and is \
                             lowering it again"
                        )
                    } else if matches!(e, VpnError::RoutingFailed { .. }) {
                        // The tunnel did appear; the bring-up lowered it
                        // itself. Nothing is missing, and nothing was
                        // left running for want of a pid.
                        String::new()
                    } else {
                        match vpn_type {
                            VpnType::Openvpn => format!(
                                "; no {iface} appeared, but openvpn daemonises (it forks and \
                                 exits 0 before its own address poll) so it may have left a \
                                 process running that this command cannot see to stop"
                            ),
                            VpnType::Wireguard => format!(
                                "; no {iface} appeared, and raising a WireGuard link leaves \
                                 no process behind, so there is nothing running for this \
                                 command to have missed"
                            ),
                        }
                    };
                    checks.push(Check::fail("bring_up", format!("{e}{aftermath}")));
                    if raised_here {
                        checks.push(teardown(host, manager.as_ref(), iface));
                    }
                    return ProfileReport {
                        profile_id: profile.id.as_str().to_string(),
                        vpn_type: vpn_type_str(vpn_type),
                        checks,
                    };
                }
            }
        }
    }

    // 3b. rp_filter, for this profile's interface, after the bring-up step.
    //
    //     Strict reverse-path filtering drops the replies to a source-bound
    //     socket, so a multi-profile daemon looks like a tunnel that connects and
    //     carries no traffic. docs/running.md calls for 2 (loose). Judged per
    //     interface, because that is how the kernel judges it — and therefore
    //     judged *here* rather than in `host_checks`, because a per-profile
    //     property in the unscoped host block ignores `--profile`, and because
    //     `/proc/sys/net/ipv4/conf/<iface>/rp_filter` does not exist until the
    //     interface does. Reading it before `--bring-up` raised the tunnel
    //     reported `unknown` for the one interface the run was about.
    let all = host.read_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter");
    let per = host.read_sysctl(&format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter"));
    checks.push(judge_rp_filter(iface, all.as_deref(), per.as_deref()));

    // 4. The address the daemon would bind every socket in this profile to.
    let tunnel_ip = match host.first_ipv4(iface) {
        Ok(v4) => {
            checks.push(Check::pass("tunnel_ip", format!("{iface} has {v4}")));
            Some(IpAddr::V4(v4))
        }
        Err(e) => {
            checks.push(Check::fail(
                "tunnel_ip",
                format!(
                    "{iface} has no IPv4 address: {e}{}",
                    if bring_up {
                        ""
                    } else {
                        " (re-run with --bring-up to raise it)"
                    }
                ),
            ));
            None
        }
    };

    // 4b. The route the health monitor probes every poll: where a packet
    //     from each of the tunnel's addresses to the internet would go.
    let (route_check, route) = judge_routes(host, iface, tunnel_ip);
    checks.push(route_check);

    // 5. Handshake liveness — the same probe and the same threshold the health
    //    monitor applies every 30 seconds.
    let max = Duration::from_secs(cfg.vpn_handshake_max_age_secs);
    let handshake_probe = match vpn_type {
        VpnType::Wireguard => {
            let probe = host.handshake_age(iface);
            checks.push(judge_handshake(
                iface,
                probe,
                max,
                host.has_cap_net_admin(),
                host.wireguard_device(iface),
            ));
            Some(probe)
        }
        VpnType::Openvpn => {
            checks.push(Check::skip(
                "handshake",
                "no cheap liveness probe for openvpn",
            ));
            None
        }
    };

    // 5b. The health monitor's own verdict on what was just observed, from
    //     the function the monitor itself calls. The session the monitor would
    //     compare against is bound to the address the tunnel has now, and no
    //     torrent has been waiting on this tunnel, so a WireGuard link that has
    //     not handshaked yet is still inside its threshold (the `handshake`
    //     line above reports it).
    if let Some(ip) = tunnel_ip {
        let observation = crate::vpn_monitor::Observation {
            current: crate::vpn_monitor::Address::Held(ip),
            expected: Some(ip),
            route: route.and_then(Result::ok),
            handshake: match handshake_probe {
                Some(Ok(Some(age))) => crate::vpn_monitor::Handshake::Age(age),
                Some(Ok(None)) => crate::vpn_monitor::Handshake::Never,
                Some(Err(_)) | None => crate::vpn_monitor::Handshake::NoSignal,
            },
            unanswered_for: Duration::ZERO,
        };
        checks.push(match crate::vpn_monitor::evaluate(&observation, max) {
            Ok(()) => Check::pass(
                "health",
                "the daemon's health monitor would keep this profile up on these observations",
            ),
            Err(reason) => Check::fail(
                "health",
                format!(
                    "the daemon's health monitor would fence this profile ({})",
                    reason.as_str()
                ),
            ),
        });
    }

    // 6. Port forwarding, against the real gateway.
    //
    //    The mapping is left to expire, never deleted: NAT-PMP's delete is a
    //    wildcard that would remove the running daemon's forwards too, hence
    //    `RealHost::probe_forwarder`. Whether the gateway coalesces this
    //    request with the daemon's mapping is gateway behaviour, untested.
    match profile.port_forward() {
        PortForwardMode::Static => {
            checks.push(Check::skip(
                "port_forward",
                format!("static listen_port {:?}", profile.listen_port()),
            ));
        }
        PortForwardMode::Natpmp => match (
            tunnel_ip,
            profile.port_forward_gateway_or_default().parse::<IpAddr>(),
        ) {
            (Some(bind_ip), Ok(gateway)) => {
                let lease = crate::port_forward_monitor::LEASE_SECS;
                let req = PortMapRequest {
                    gateway,
                    bind_ip,
                    internal_port: PortMapRequest::INTERNAL_PORT,
                    // No preference: the check holds no port to keep.
                    suggested_port: 0,
                    // The daemon's own lease. `LEASE_SECS` is public so both
                    // paths agree; re-deriving it here would silently move the
                    // pre-flight out of step with the daemon the first time
                    // anyone changed it.
                    lifetime_secs: lease,
                };
                match host.forwarder().map(&req) {
                    Ok(m) => {
                        checks.push(Check::pass(
                            "port_forward",
                            format!(
                                "gateway {gateway} offered port {}; its {lease}s lease is left \
                                 to expire, not deleted",
                                m.port,
                            ),
                        ));
                    }
                    Err(e) => checks.push(Check::fail(
                        "port_forward",
                        format!("NAT-PMP against {gateway} failed: {e}"),
                    )),
                }
            }
            (None, _) => checks.push(Check::skip(
                "port_forward",
                "skipped: no tunnel address to negotiate from",
            )),
            (_, Err(e)) => checks.push(Check::fail(
                "port_forward",
                format!("port_forward_gateway is not an IP address: {e}"),
            )),
        },
    }

    // 7. Optional reachability probe, reported either way once asked for. A
    //    reply does not prove the tunnel carried it, so the route to the
    //    destination is asserted first; a destination of the other address
    //    family is said to be one before `ip` is asked.
    if let Some(dest) = egress {
        let mismatch = tunnel_ip.filter(|src| src.is_ipv4() != dest.ip().is_ipv4());
        let route_check = match mismatch {
            Some(src) => Check::fail(
                "egress_route",
                format!(
                    "{dest} is not of the address family of {iface}'s address {src}, so no \
                     socket bound to the tunnel address can reach it; give --egress a \
                     destination of {src}'s family"
                ),
            ),
            None => {
                let route = tunnel_ip.map(|src| host.route_probe(iface, src, dest.ip()));
                judge_route("egress_route", iface, tunnel_ip, dest.ip(), route)
            }
        };
        let routed = route_check.verdict == Verdict::Pass;
        let route_unknown = route_check.verdict == Verdict::Unknown;
        checks.push(route_check);
        checks.push(match tunnel_ip {
            Some(src) if routed => egress_probe(src, dest),
            Some(src) if mismatch.is_some() => Check::skip(
                "egress",
                format!(
                    "{dest} was not probed: it cannot be reached from {src} (see egress_route)"
                ),
            ),
            Some(_) if route_unknown => Check::skip(
                "egress",
                format!(
                    "{dest} was not probed: its route could not be asked (see egress_route), \
                     so a reply would not show the tunnel carries traffic"
                ),
            ),
            Some(_) => Check::skip(
                "egress",
                format!(
                    "{dest} was not probed: its route does not leave by {iface} (see \
                     egress_route), so a reply would not show the tunnel carries traffic"
                ),
            ),
            None => Check::skip(
                "egress",
                format!("{iface} has no address to send from, so {dest} was not probed"),
            ),
        });
    }

    // 8. Lower what step 3 was observed to have raised — absent before the
    //    call, present after it. An interface that was already there is left
    //    exactly as it was found, and produces no `bring_down` line at all.
    if raised_here {
        checks.push(teardown(host, manager.as_ref(), iface));
    }

    ProfileReport {
        profile_id: profile.id.as_str().to_string(),
        vpn_type: vpn_type_str(vpn_type),
        checks,
    }
}

/// The health monitor's route probe (`vpn_monitor::route_probe`), asked the
/// way it asks it, and the `route` line it implies, with the answer the
/// `health` line judges.
///
/// From the IPv4 tunnel address `src` toward `PROBE_DEST`, then — only while
/// every answer so far is "by the tunnel" — from each global IPv6 address on
/// `iface` toward `PROBE_DEST_V6`. The first answer that is not "by the
/// tunnel" is the answer, as it is for the monitor; with none, the IPv4 one.
/// IPv6 addresses that cannot be read are none, which leaves the IPv4
/// answer, as the monitor keeps it.
fn judge_routes(
    host: &dyn CheckHost,
    iface: &str,
    src: Option<IpAddr>,
) -> (
    Check,
    Option<Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>>,
) {
    let Some(v4) = src else {
        let dest = IpAddr::V4(vpn::route::PROBE_DEST);
        return (judge_route("route", iface, None, dest, None), None);
    };
    let via = Ok(vpn::route::RouteProbe::ViaTunnel);
    let ask = |from: IpAddr| {
        let dest = vpn::route::probe_dest(from);
        (from, dest, host.route_probe(iface, from, dest))
    };
    let mut answer = ask(v4);
    let mut by_tunnel = Vec::new();
    if answer.2 == via {
        for from in host.tunnel_ipv6(iface) {
            by_tunnel.push(answer);
            answer = ask(IpAddr::V6(from));
            if answer.2 != via {
                break;
            }
        }
    }
    let (from, dest, r) = answer;
    if r != via {
        return (
            judge_route("route", iface, Some(from), dest, Some(r.clone())),
            Some(r),
        );
    }
    by_tunnel.push((from, dest, r));
    let pairs: Vec<String> = by_tunnel
        .iter()
        .map(|(from, dest, _)| format!("from {from} to {dest}"))
        .collect();
    (
        Check::pass(
            "route",
            format!("a packet {} leaves by {iface}", pairs.join(" and ")),
        ),
        Some(via),
    )
}

/// The verdict a route probe implies: a route from the tunnel address to
/// `dest` that leaves by `iface` passes, any other route fails, and a probe
/// that could not run is `unknown`. With no tunnel address there is nothing to
/// ask about, which the `tunnel_ip` line already fails.
fn judge_route(
    name: &'static str,
    iface: &str,
    src: Option<IpAddr>,
    dest: IpAddr,
    probe: Option<Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>>,
) -> Check {
    match (src, probe) {
        (Some(src), Some(Ok(vpn::route::RouteProbe::ViaTunnel))) => Check::pass(
            name,
            format!("a packet from {src} to {dest} leaves by {iface}"),
        ),
        (Some(src), Some(Ok(vpn::route::RouteProbe::Elsewhere(why)))) => Check::fail(
            name,
            format!(
                "a packet from {src} to {dest} does not leave by {iface} ({why}): the \
                 source-address rule for the tunnel is missing or outranked, and the daemon's \
                 health monitor fences a profile in this state"
            ),
        ),
        (Some(_), Some(Err(why))) => Check::unknown(
            name,
            format!("`ip route get` could not run ({})", why.as_str()),
        ),
        _ => Check::skip(name, format!("{iface} has no address to route from")),
    }
}

/// Lower an interface this command raised, and report whether it went down.
///
/// `VpnManager::bring_down` swallows its errors, so the address is looked at
/// afterwards and a host left changed is said to be. A direct call: `vpn
/// check` runs before any tokio runtime exists.
fn teardown(host: &dyn CheckHost, manager: &dyn VpnManager, iface: &str) -> Check {
    manager.bring_down(iface);
    match host.first_ipv4(iface) {
        Err(_) => Check::pass(
            "bring_down",
            format!("{iface} no longer has an address; the host is as it was found"),
        ),
        Ok(ip) => Check::fail(
            "bring_down",
            format!(
                "{iface} still has {ip} after bring_down: this command raised the tunnel and \
                 could not lower it again, so the host has been left changed"
            ),
        ),
    }
}

fn vpn_type_str(t: VpnType) -> &'static str {
    match t {
        VpnType::Wireguard => "wireguard",
        VpnType::Openvpn => "openvpn",
    }
}

/// Select the profiles `only` names and report on each.
///
/// A profile with no tunnel gets a `skip` line: dropped, a host-only
/// deployment would print nothing and read as all clear, and
/// [`profile_checks`] takes vpn profiles only.
fn profile_reports(
    cfg: &Config,
    only: Option<&str>,
    bring_up: bool,
    egress: Option<SocketAddr>,
    host: &dyn CheckHost,
) -> anyhow::Result<Vec<ProfileReport>> {
    if cfg.profile.is_empty() {
        anyhow::bail!(
            "no [[profile]] entries are configured, so there is no VPN to check. \
             A daemon with no [[profile]] table cannot start either; see \
             deploy/torrentd.sample.toml."
        );
    }
    let selected: Vec<&ProfileConfig> = cfg
        .profile
        .iter()
        .filter(|s| only.is_none_or(|id| s.id.as_str() == id))
        .collect();
    if selected.is_empty() {
        anyhow::bail!("no profile matches {:?}", only.unwrap_or_default());
    }

    Ok(selected
        .into_iter()
        .map(|s| {
            if s.is_vpn() {
                profile_checks(cfg, s, bring_up, egress, host)
            } else {
                no_tunnel_report(s)
            }
        })
        .collect())
}

/// The report for a profile that has no tunnel to check.
fn no_tunnel_report(profile: &ProfileConfig) -> ProfileReport {
    ProfileReport {
        profile_id: profile.id.as_str().to_string(),
        vpn_type: "none",
        checks: vec![Check::skip(
            "tunnel",
            format!(
                "profile {:?} is network = \"host\" and reaches the network over the \
                 machine's own interfaces, so it has no tunnel to check",
                profile.id.as_str(),
            ),
        )],
    }
}

/// Run the checks, print them, and return the exit status they imply — `0`
/// clean, `1` for any failure, `2` for "nothing failed, but something could not
/// be checked". Usable as a pre-flight step in a unit or a CI job, which is why
/// `2` exists: those consumers read the status and not the report.
pub fn check(
    cfg: &Config,
    only: Option<&str>,
    json: bool,
    bring_up: bool,
    egress: Option<SocketAddr>,
    as_uid: Option<u32>,
) -> anyhow::Result<i32> {
    let host = RealHost;
    let report = Report {
        host: host_checks(cfg, as_uid, only, &host),
        profiles: profile_reports(cfg, only, bring_up, egress, &host)?,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human(&report);
    }

    let code = report.exit_code();
    match code {
        EXIT_FAILED => eprintln!("one or more VPN checks failed"),
        EXIT_UNKNOWN => eprintln!(
            "nothing failed, but one or more checks could not be performed; \
             exiting {EXIT_UNKNOWN}"
        ),
        _ => {}
    }
    Ok(code)
}

/// The four-character marker in front of a check.
///
/// `?cap` rather than `?   ` for an `Unknown` nothing this invocation can be
/// given would settle: it is the one `Unknown` that does not colour the exit
/// status, so the rendering has to distinguish it too, or a reader
/// reconciling a `0` against a column of `?` has nothing to go on. A missing
/// capability is the common reason and the one the marker is named for; the
/// footnote states the class, and each line states its own cause.
fn symbol(c: &Check) -> &'static str {
    match c.verdict {
        Verdict::Pass => "ok  ",
        Verdict::Fail => "FAIL",
        Verdict::Skip => "skip",
        Verdict::Unknown if c.needs_capability => "?cap",
        Verdict::Unknown => "?   ",
    }
}

fn print_human(report: &Report) {
    println!("host");
    for c in &report.host {
        println!("  [{}] {:<20} {}", symbol(c), c.name, c.detail);
    }
    for s in &report.profiles {
        println!("\nprofile {} ({})", s.profile_id, s.vpn_type);
        for c in &s.checks {
            println!("  [{}] {:<20} {}", symbol(c), c.name, c.detail);
        }
    }
    if report.capability_bound() {
        println!(
            "\n[?cap] marks a check nothing this invocation could be given would settle — \
             usually for want of CAP_NET_ADMIN, which the daemon holds and this shell does \
             not; each line says which. It is not counted against the exit status, because \
             no argument to this command would change it, so the status says nothing about \
             it either way."
        );
    }
}

#[cfg(test)]
mod tests;
