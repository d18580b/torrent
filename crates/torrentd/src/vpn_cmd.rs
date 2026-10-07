//! `torrentd vpn check` — verify a profile's VPN configuration against the real
//! host, with no libtorrent session, no torrents and no tracker contact.
//!
//! Every other way of exercising this code needs a fully configured daemon: a
//! pool, a torrent library, real payload, and an operator watching `/profiles` for
//! thirty seconds to see whether the health monitor fences anything. That
//! conflates two independent things — "does my VPN configuration work" and
//! "does my seeding setup work" — and it is the first of those that has to be
//! true before the second is worth testing.
//!
//! Host prerequisites run first, then each profile's checks in the order `boot`
//! performs them. The host block is deliberately *not* in boot's order: boot
//! installs the kill switch last, after every profile is up, and burying a
//! missing `iproute2` or `nft` behind a thirty-second tunnel bring-up would
//! cost an operator the thing this command is for.
//!
//! Observe-only by default, stated precisely: the default path makes **no
//! host change** and **deletes nothing**. It reads interfaces, reads `wg`
//! output, reads sysctls, and — for a NAT-PMP profile — asks the gateway for a
//! mapping with the daemon's own short lease and lets that lease lapse. Its
//! one interaction with a running daemon is that NAT-PMP request, sent from
//! the same client identity the daemon uses; whether a gateway coalesces it
//! with the mapping the daemon already holds or answers with a second one is
//! gateway-dependent, and nothing here tests it. What is guaranteed is that no
//! delete is issued on any branch — including the one inside
//! `NatpmpForwarder::map` where the gateway answers UDP on a different port
//! from TCP, which is why the check negotiates with
//! [`RealHost::probe_forwarder`] and not with the client startup uses.
//!
//! `--bring-up` opts into raising tunnels, which is the one thing here that
//! changes the machine. It lowers again **only** what it raised, and it takes
//! that from the interface rather than from the flag it set on the way in: an
//! interface absent before the call and present after was raised here, and
//! anything else — an interface that already existed, usually a running
//! daemon's — is reported, checked, and left alone.
//!
//! The exit status carries three values, because a `mise` task or a systemd
//! `ExecStartPre` reads the status and never the report: `0` clean, `1` for any
//! failure, `2` for "nothing failed, but at least one check could not be
//! performed". A check that could not be performed *because this invocation
//! lacks `CAP_NET_ADMIN`* is excluded from the third, and rendered `?cap`:
//! see [`Check::needs_capability`]. See [`Report::exit_code`].

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
    /// could settle** — usually because it lacks a capability — as distinct
    /// from one a different input, privilege or configuration would answer.
    ///
    /// They are not the same thing and collapsing them made `unknown` the
    /// normal outcome rather than the exceptional one. `docs/running.md`
    /// recommends running this as the daemon's user, which is a user without
    /// `CAP_NET_ADMIN`: `wg show … latest-handshakes` is refused and `nft
    /// --check` cannot initialise its netlink cache, so a host where *nothing
    /// is wrong* exited 2, and raising privileges only moves the problem to
    /// `kill_switch_uid`. A status that is never 0 on the supported
    /// deployment trains both consumers this command has — the `mise` task and
    /// a systemd `ExecStartPre` — to accept 2, which is what the three-valued
    /// status was introduced to prevent.
    ///
    /// So this one does not colour the exit status. It is still reported, in
    /// both renderings, because an operator has to know it did not run.
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
    /// An `Unknown` this invocation could not settle for want of a
    /// capability, which does not colour the exit status. See
    /// [`Check::needs_capability`].
    fn unknown_without_capability(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            needs_capability: true,
            ..Self::unknown(name, detail)
        }
    }

    /// An `Unknown` **nothing this process can be told would settle**, which
    /// is the same non-colouring class for the same reason. See
    /// [`Check::needs_capability`].
    ///
    /// The capability-bound ones are the common route into it. This is the
    /// other: an answer that depends on a fact outside this process
    /// altogether, where no argument, privilege or configuration change
    /// available to this invocation produces one.
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

    /// Whether any check could not be performed at all.
    ///
    /// An `Unknown` that names a capability this invocation does not have is
    /// excluded: see [`Check::needs_capability`]. It is reported and it does
    /// not colour the status, because on the deployment this repository ships
    /// it is the expected answer rather than a sign of anything.
    pub fn incomplete(&self) -> bool {
        self.checks()
            .any(|c| c.verdict == Verdict::Unknown && !c.needs_capability)
    }

    /// Whether anything was left unsettled for want of a capability.
    pub fn capability_bound(&self) -> bool {
        self.checks().any(|c| c.needs_capability)
    }

    /// The exit status this report implies.
    ///
    /// The four-valued verdict exists so a green summary cannot quietly mean
    /// "mostly not checked" — but the exit status is the only part of this
    /// report a `mise` task or a systemd `ExecStartPre` ever sees, and
    /// collapsing `unknown` into success asserted in one byte exactly what the
    /// four values were introduced to avoid. A run where `rp_filter` is
    /// unreadable, `wg-quick --help` exits non-zero and `wg show` is refused
    /// for want of permission established nothing about the handshake half and
    /// exited 0.
    ///
    /// `Skip` is not `Unknown`: a NAT-PMP check on a static profile did not fail
    /// to happen, it correctly did not apply, and it does not colour the
    /// status.
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

/// Whether this process holds `CAP_NET_ADMIN`.
///
/// Both checks that go `unknown` off-privilege need exactly this capability:
/// `nft --check` validates against the live kernel through netlink, and `wg
/// show <iface> latest-handshakes` reads peer state over generic netlink.
/// Asking the kernel whether we hold it is a structural test; the alternative
/// in use was substring-matching nftables' stderr, which puts the difference
/// between exit 1 and exit 2 on that project's error wording — a build,
/// locale or version with different text reported "nft --check rejected the
/// ruleset boot would install" when nothing about the ruleset was
/// established, and the converse downgraded a real rejection.
///
/// Read from `/proc/self/status`, the file `killswitch::current_uid` already
/// reads, so this needs no new dependency.
///
/// When the mask cannot be read this answers `true`: the fallbacks below are
/// what then decide, and assuming the capability keeps a genuine rejection a
/// failure rather than quietly excusing it.
fn has_cap_net_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| cap_eff_has(&s, CAP_NET_ADMIN_BIT))
        .unwrap_or(true)
}

/// Whether `bin` can be executed at all.
fn tool_available(bin: &str, probe_arg: &str) -> bool {
    vpn::exec::available(bin, probe_arg)
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

    /// The address the daemon would bind every socket in this profile to.
    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr>;

    /// The tunnel manager for a profile's VPN type.
    fn manager(&self, t: VpnType, run_dir: &Path) -> Arc<dyn VpnManager>;

    /// A NAT-PMP client with startup's retransmit budget that deletes nothing.
    ///
    /// The return type is the whole port-forward surface these checks can
    /// reach, and `PortForwarder` carries `map` and nothing else, so no
    /// release is expressible *here*. That is necessary and it is not
    /// sufficient: `NatpmpForwarder::map` contains its own wildcard delete on
    /// the branch where the gateway answers UDP on a different port from TCP,
    /// so narrowing the parameter's type constrained the call site while the
    /// object behind it could still destroy the daemon's forward. The client
    /// [`RealHost::probe_forwarder`] hands back is the variant that cannot.
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

    /// The UDP port the WireGuard link `iface` listens on — the probe
    /// `killswitch::enable` reads each tunnel's transport exemption from.
    fn listen_port(&self, iface: &str) -> std::io::Result<u16>;

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
        // Asked of `ip`, from this process's network namespace — the view
        // the tunnel managers act on — and not of `/sys/class/net`, which
        // shows the namespace sysfs was mounted in. A probe that could not be
        // answered reads as present: that is the answer that never lowers an
        // interface this command did not raise.
        vpn::link_exists(iface).unwrap_or(true)
    }

    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr> {
        vpn::first_ipv4(iface)
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
        tool_available(bin, probe_arg)
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

    fn listen_port(&self, iface: &str) -> std::io::Result<u16> {
        vpn::killswitch::listen_port(iface)
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
/// `as_uid` is what the operator asked about; `invoker` is this process. The
/// packaged unit runs the daemon as `User=torrentd` while `--bring-up` all but
/// requires root, so the invoking uid is routinely not the daemon's:
/// `sudo torrentd … vpn check --bring-up` used to emit `kill_switch_uid
/// running as uid 0` as its *first* line and exit 1, for a failure the daemon
/// would never hit. The reverse held too — an ordinary uid checking a host
/// whose service user is misconfigured as root passed.
///
/// The config carries no uid, so for any subject but `0` and any invoker but
/// that subject, this reports what it is: a property of the invoker, not of
/// the daemon, and therefore unestablished.
///
/// Uid `0` is the exception, and it is `fail` whoever is asking.
/// `killswitch::enable` refuses uid 0 *unconditionally* — it does not consult
/// the invoker, the config or the host — so "the daemon runs as root" settles
/// "the boot aborts at the kill switch" on its own. Reporting that `unknown`
/// wrote the answer into the detail string and then withheld it from the
/// verdict: the report said the boot aborts while the status byte said nothing
/// was established. The reason an unmatched subject is `unknown` is that this
/// process cannot observe the daemon's uid; when the operator names it, that
/// uncertainty is gone, and for `0` the answer does not depend on the observer
/// at all.
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

/// The uid `kill_switch_ruleset` renders and dry-runs for.
///
/// Deliberately **not** conditioned on what `kill_switch_uid` concluded. Those
/// two checks were coupled — any `Unknown` from the uid check suppressed the
/// ruleset entirely — and `--as-uid` names a uid the invoker is not *by
/// definition*, so the one invocation the flag exists for turned both checks
/// to `unknown` and never ran `nft --check` at all. Since `--bring-up` needs
/// root, that left `vpn check --bring-up` on a `network_kill_switch = true`
/// host with no route to exit 0 by any argument combination.
///
/// The dry-run establishes something real about the named uid either way: the
/// ruleset boot would install for *that* uid either parses and validates
/// against this kernel or it does not, and neither answer depends on who is
/// asking.
fn ruleset_subject(as_uid: Option<u32>, invoker: Result<u32, String>) -> Option<u32> {
    as_uid.or_else(|| invoker.ok())
}

/// The verdict `nft --check --file -` implies for a rendered ruleset.
///
/// Classified on **what `nft` reported**, not on who asked. nftables parses
/// its input before it touches netlink, so the two failures are distinguishable
/// from an unprivileged shell: a ruleset this build cannot parse prints a
/// parser diagnostic and no netlink error, while one that parses prints
/// `netlink: Error: cache initialization failed: Operation not permitted` and
/// nothing else. A parse diagnostic is therefore a **rejection of the
/// ruleset** whatever the invoker's capability mask says — the boot would
/// abort at `killswitch::enable` on exactly that input.
///
/// Classifying on the mask instead short-circuited every failure on the one
/// invocation `docs/running.md` recommends — an operator shell, which does not
/// hold `CAP_NET_ADMIN` — into the capability class, which
/// [`Report::incomplete`] excludes from the status. A configuration whose kill
/// switch cannot install exited `0`.
///
/// `privileged` is whether this process holds `CAP_NET_ADMIN`; see
/// [`has_cap_net_admin`]. It is kept as corroboration in the detail text, not
/// as the discriminator.
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
    let caveat = "interfaces listed are the configured profiles; boot lists only the profiles \
                  whose tunnel came up";
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
                Check::unknown_without_capability(
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
/// `is_wireguard_device` is [`CheckHost::wireguard_device`]'s reading, and it
/// is what settles the one thing the probe cannot. `ProbeUnavailable::Refused`
/// is documented at `vpn/wireguard.rs` as meaning *either* "not a WireGuard
/// interface" *or* "no permission", and privilege is the one axis that cannot
/// separate them: `wg show lo` and `wg show <nonexistent>` return the same
/// refusal. Resolving it by privilege alone gave a wireguard profile pointed at
/// a non-WireGuard interface — a configuration `ProfileConfig::validate_set`
/// accepts, since it constrains only that the interface equals the tunnel
/// config's file stem — an all-clear `0` and a message asserting the daemon would be
/// fine. A capability-free read of the link type says otherwise, and that is a
/// `fail` about the configuration rather than an `unknown` about this shell.
///
/// That reading only settles a probe that did **not** answer. A probe that
/// returned a handshake (or none yet) is `wg` itself reading a WireGuard
/// implementation behind `iface`, which is stronger evidence than the link
/// type: a userspace tunnel (`wireguard-go`, which `wg-quick` falls back to
/// without the kernel module) is a `tun` device and carries no wireguard link
/// type at all.
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
            Check::unknown_without_capability(
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
/// `iproute2` and `nftables` are here because they genuinely are host-wide: a
/// missing binary is missing for every profile, and neither answer changes with
/// `--profile`. `rp_filter` is **not** here, even though it reads a sysctl:
/// `conf/<iface>/rp_filter` is per profile by construction, so judging it here
/// scoped a check to interfaces the operator had excluded — a run narrowed to
/// one healthy profile exited 2 because of another profile's interface — and ran it
/// before `--bring-up` had raised anything, so the sysctl for the interface
/// the command was about to create did not exist yet. It also put two checks
/// named `rp_filter` in the same `host` array, which the `--json` contract
/// cannot express to a consumer keying by name. It lives in
/// [`profile_checks`] instead.
///
/// Every host touch goes through `host` for the same reason [`profile_checks`]'s
/// do: the classification this function performs — which `nft --check` failure
/// is a rejection of the ruleset, and whether an excluded profile's interface
/// may decide a scoped run — is branch logic, and a test that shells out to the
/// real `ip` and `nft` asserts whatever the machine it runs on happens to
/// answer.
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
                let tunnels: Vec<String> = cfg
                    .profile
                    .iter()
                    .filter_map(|p| p.vpn_interface().map(str::to_string))
                    .collect();
                // The script boot hands to `nft -f` — `killswitch::install_script`,
                // the same renderer `killswitch::enable` calls — over the
                // listen ports that can be read now. Boot reads each one off
                // the live link and refuses to install without it; a link
                // that is not up yet has no port to read, so its exemption is
                // named as missing rather than guessed at.
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
                let verdict = note_unread_ports(verdict, &unread);
                attribute_ruleset_rejection(verdict, cfg, only, uid, host)
            }
        });
    } else {
        out.push(Check::skip("kill_switch", "network_kill_switch = false"));
    }

    out
}

/// The kill-switch script boot would install for `uid` over `tunnels`, with
/// the transport exemption for every tunnel whose listen port `host` can read,
/// and the tunnels whose port it could not.
///
/// Rendered by [`vpn::killswitch::install_script`], which is what
/// `killswitch::enable` renders with: for the same uid, tunnels and ports the
/// two are the same bytes. They used to differ — this command dry-ran the bare
/// table with no transport exemption and no replace, which is not the script
/// boot installs.
fn boot_install_script(
    uid: u32,
    tunnels: &[String],
    host: &dyn CheckHost,
) -> (std::io::Result<String>, Vec<String>) {
    let mut ports = Vec::new();
    let mut unread = Vec::new();
    for iface in tunnels {
        match host.listen_port(iface) {
            Ok(p) => ports.push(p),
            Err(_) => unread.push(iface.clone()),
        }
    }
    (
        vpn::killswitch::install_script(uid, tunnels, &ports),
        unread,
    )
}

/// Say which transport exemptions the dry-run could not include.
///
/// Not a verdict of its own: the ruleset's syntax and its acceptance by this
/// kernel do not depend on a port number, so the dry-run still establishes
/// what it establishes. What boot would do differently is stated: it reads
/// the port off the live link and refuses the install if it cannot.
fn note_unread_ports(mut verdict: Check, unread: &[String]) -> Check {
    if !unread.is_empty() {
        verdict.detail.push_str(&format!(
            "\nno listen port could be read for {} (not up?), so this dry-run carries no \
             transport exemption for it; boot reads each one off the live link and refuses \
             to install the kill switch without it",
            unread.join(", "),
        ));
    }
    verdict
}

/// Keep an excluded profile's interface out of a scoped run's exit status.
///
/// The kill-switch table is host-wide — boot installs it whole — so the
/// rendered ruleset lists every configured vpn profile's interface, and the
/// caveat in the detail already says so. That justifies *listing* them. It
/// does not justify letting one decide the verdict of a run the operator
/// narrowed with `--profile`: `cli.rs` says "Check only this profile." and
/// `docs/running.md` "Check one profile instead of every configured profile",
/// and a rejection caused by an interface belonging to a profile that was
/// excluded is a `fail` and an exit `1` for a profile nobody asked about.
///
/// Attribution is by re-rendering: the same ruleset for the selected profile's
/// interfaces alone, dry-run the same way. If that parses while the full one
/// did not, the rejection is the excluded profiles' and this run reports it
/// without colouring the status. If it fails too, the selected profile owns it
/// and the verdict stands. A host profile has no interface in the table, so an
/// excluded host profile can own no part of a rejection. Nothing here reads nft's message for interface
/// names — every name is in it, including the ones that are fine.
fn attribute_ruleset_rejection(
    verdict: Check,
    cfg: &Config,
    only: Option<&str>,
    uid: u32,
    host: &dyn CheckHost,
) -> Check {
    // Only a `Fail` can colour a scoped run; the rest are already
    // non-colouring and are left exactly as they are.
    if verdict.verdict != Verdict::Fail {
        return verdict;
    }
    let Some(id) = only else {
        return verdict;
    };
    let (kept, excluded): (Vec<&ProfileConfig>, Vec<&ProfileConfig>) = cfg
        .profile
        .iter()
        .filter(|p| p.vpn_interface().is_some())
        .partition(|p| p.id.as_str() == id);
    if excluded.is_empty() {
        return verdict;
    }
    let scoped: Vec<String> = kept
        .iter()
        .filter_map(|p| p.vpn_interface().map(str::to_string))
        .collect();
    // The selected profile's own name cannot be rendered: it owns the
    // rejection, and the verdict stands.
    let Ok(scoped_ruleset) = boot_install_script(uid, &scoped, host).0 else {
        return verdict;
    };
    let scoped_parses = match host.nft_check(&scoped_ruleset) {
        Ok(o) => {
            o.status.success() || !nft_rejected_the_ruleset(&String::from_utf8_lossy(&o.stderr))
        }
        // The probe that would attribute it did not run, so nothing is
        // attributed and the rejection keeps the status it had.
        Err(_) => return verdict,
    };
    if !scoped_parses {
        return verdict;
    }
    let names: Vec<String> = excluded
        .iter()
        .filter_map(|p| {
            p.vpn_interface()
                .map(|iface| format!("{iface} (profile {})", p.id.as_str()))
        })
        .collect();
    Check::skip(
        "kill_switch_ruleset",
        format!(
            "{} — but the ruleset for profile {id}'s interfaces alone is accepted, so the \
             rejection belongs to {}, which --profile {id} excluded. It is reported and it \
             does not decide this run's status; re-run without --profile to have it do so",
            verdict.detail,
            names.join(", "),
        ),
    )
}

/// Prove that a socket **bound to the tunnel address** can send and receive.
///
/// This is the check that distinguishes a tunnel which exists from a tunnel
/// which works, and it is the same question the daemon asks implicitly of
/// every profile: `outgoing_interfaces` is pinned to the tunnel, so if traffic
/// cannot leave from that source address the profile connects to no peers and
/// announces to no tracker, while looking perfectly healthy to the IP-presence
/// check.
///
/// A source-bound UDP round trip is used rather than a TCP connect because
/// `std::net` offers no way to set the source address on an outbound TCP
/// connection — `TcpStream::connect` picks it from the routing table, which
/// would test the default route and not the tunnel at all. `UdpSocket::bind`
/// followed by `connect` does bind the source, which is exactly how
/// `vpn::natpmp` talks to the gateway.
///
/// The payload is a DNS query because every resolver answers one and the reply
/// is trivially identifiable, not because the daemon resolves anything this
/// way.
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

    // 3. Optionally raise the tunnel, exactly as boot would — but only if it
    //    is not already there.
    //
    //    `wg-quick up` refuses an interface that already exists, and the
    //    adoption path in `vpn::wireguard` then matches the tunnel config's public
    //    key and returns the address anyway. So a running daemon's tunnel used
    //    to be reported as "came up" having been created by nothing, and the
    //    unconditional teardown below then ran the same `wg-quick down` the
    //    daemon's own shutdown uses. The profile went down, `vpn_monitor` fenced
    //    it within 30s, and nothing re-raised it: a diagnostic command took a
    //    live seeding profile out until someone restarted the daemon.
    //
    //    An interface that was already there is adopted for every remaining
    //    check and never lowered. That also leaves the flag useful for the
    //    case it exists for — a crash-orphaned interface is still raised and
    //    still checked.
    //
    //    Which of the two happened is taken from the **interface**, re-probed
    //    after `bring_up` returns, and not from the arm it returned on. Both
    //    arms lie in one direction each. `bring_up` can return `Err` having
    //    already started something: `OpenvpnManager` runs `openvpn --daemon`,
    //    which forks and exits 0, and then times out in its own address poll;
    //    `WireguardManager` runs `wg-quick up`, which succeeds, and then times
    //    out the same way. Returning early on `Err` without looking left a
    //    process or an interface this command created standing, unreported and
    //    permanent — a re-run then sees the interface and reports `skip`. And
    //    `Ok` is not evidence of a raise, because the adoption path returns
    //    `Ok` for an interface `wg-quick up` refused.
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
    //     from the tunnel address to the internet would go.
    let route =
        tunnel_ip.map(|src| host.route_probe(iface, src, IpAddr::V4(vpn::route::PROBE_DEST)));
    checks.push(judge_route(
        "route",
        iface,
        tunnel_ip,
        IpAddr::V4(vpn::route::PROBE_DEST),
        route.clone(),
    ));

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
            current: Some(ip),
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
    //    The mapping is left to expire rather than deleted. NAT-PMP's delete
    //    is the RFC 6886 §3.4 wildcard form — internal port 0, lifetime 0 —
    //    and it cannot be narrowed: it removes *every* mapping held by the
    //    requesting address, which over a tunnel the daemon is already using
    //    means that daemon's live TCP and UDP forwards. The daemon does not
    //    notice for up to a renewal interval, during which no new inbound peer
    //    can connect; if the gateway then hands back a different port the
    //    renewal churns the listen sockets and leaves a stale port advertised
    //    to trackers until the next reannounce.
    //
    //    Removing the release from this call site was necessary and it was not
    //    sufficient: `NatpmpForwarder::map` issues the same wildcard delete
    //    itself when the gateway answers UDP on a different port from TCP. So
    //    the client here is `RealHost::probe_forwarder`, the variant that
    //    deletes on no branch at all; the property has to hold for the object
    //    called, not for the type of the parameter it arrives as.
    //
    //    Asking for the same short lease the daemon asks for costs nothing.
    //    What it does at a live gateway is *not* claimed here: this is the
    //    same NAT-PMP client identity, so the gateway may coalesce the request
    //    with the mapping the daemon already holds, or it may hand out a
    //    second one. Which of those happens is gateway behaviour that nothing
    //    in this repository tests.
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

    // 7. Optional reachability probe. A check the operator explicitly asked
    //    for reports a verdict either way: omitting the line and the JSON key
    //    when there is no address to bind to is the silent green the
    //    four-valued vocabulary exists to prevent.
    //
    //    A reply proves something left and came back; it does not prove it
    //    left by the tunnel. A source-bound socket whose rule is gone is
    //    routed by the main table, out of the physical interface with the
    //    tunnel's address as its source, and on a host where that still gets
    //    an answer the round trip passed. So the route to the probe's own
    //    destination is asserted first, and the round trip is a pass only
    //    over a route that leaves by the tunnel.
    //
    //    A destination of the other address family is said to be one before
    //    anything is asked of `ip`: `ip route get <v6> from <v4>` fails, and
    //    that failure read as a missing or outranked tunnel rule.
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
/// `VpnManager::bring_down` returns `()` and, per its own contract, swallows
/// its errors to the log — so reporting a pass straight after calling it
/// reported the one host mutation this command advertises without ever looking
/// at it. `wg-quick down` can fail: the interface is busy, the tunnel config moved,
/// `wg-quick` is not on this uid's PATH. Look at the address instead, and say
/// plainly when the host has been left changed.
///
/// This is a direct `bring_down` rather than `startup`'s
/// `take_down_off_worker`, and `boot_has_exactly_one_teardown_shape` counts it
/// as a documented site for that reason: `vpn check` is dispatched from `main`
/// before the tokio runtime is built, so there is no worker to keep free and
/// nothing to `spawn_blocking` onto, and the interface was raised by this
/// command, not recorded by a `boot`'s `BootCleanup`. Blocking here is the
/// command doing its job.
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
/// A profile with no tunnel gets a `skip` line rather than being dropped or
/// being handed to [`profile_checks`]. Dropping it would make a bare
/// `vpn check` on a host-only deployment print nothing and exit 0, which reads
/// as "checked, all clear" on a machine that has no tunnel at all —
/// `README.md` and `cli.rs` both document the bare invocation as every
/// configured profile. Handing it over is what the command did before: the
/// selection filtered on id alone, so `profile_checks`'s
/// `expect("only vpn profiles reach profile_checks")` was reachable from the
/// shipped sample config, and a documented pre-flight exited 101 — outside the
/// 0/1/2 contract `cli.rs` publishes. The `skip` follows the precedent the
/// `--egress` check already sets: report that it did not apply, and do not
/// colour the exit status.
///
/// Split out of [`check`] so the selection is reachable without a real host.
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
mod tests {
    use std::sync::Mutex;

    use torrentd_engine::MockForwarder;
    use torrentd_engine::MockVpn;

    use super::*;

    /// A `CheckHost` with no host behind it: every answer is scripted, and the
    /// tunnel manager and NAT-PMP client are the engine's recording doubles,
    /// so what the checks *did* to them is assertable.
    #[derive(Debug)]
    struct FakeHost {
        existing: Vec<String>,
        /// Scripted answers for `interface_exists`, consumed in call order,
        /// for the case where the interface changes under the command — which
        /// is the whole of what `--bring-up` does. Empty means "answer from
        /// `existing`".
        exists_seq: Mutex<Vec<bool>>,
        addrs: Mutex<Vec<(String, Option<Ipv4Addr>)>>,
        sysctls: Mutex<Vec<(String, String)>>,
        /// Every host interaction, in the order it happened, so *when* a
        /// sysctl was read relative to the raise is assertable. Shared with
        /// [`RecordingVpn`] so the raise lands in the same sequence.
        events: Arc<Mutex<Vec<String>>>,
        vpn: MockVpn,
        fwd: MockForwarder,
        /// Binaries `tool_available` should answer `false` for. Everything
        /// else is present, which is the ordinary host.
        missing_tools: Vec<String>,
        /// What `current_uid` answers.
        uid: Result<u32, String>,
        /// What `has_cap_net_admin` answers. `false` is the invocation
        /// `docs/running.md` recommends.
        privileged: bool,
        /// Scripted `nft --check` outcomes as `(exit code, stderr)`, consumed
        /// in call order. Empty means "accepted".
        nft: Mutex<Vec<(i32, String)>>,
        /// Scripted `wireguard_device` answers. An interface not listed reads
        /// as `None`, which is "neither read answered".
        wg_devices: Vec<(String, bool)>,
        /// What `handshake_age` answers for every interface. Defaults to a
        /// refusal, which is what an unprivileged `wg show` returns.
        handshake: Result<Option<Duration>, &'static str>,
        /// Scripted `listen_port` answers. An interface not listed has no
        /// port to read, which is a link that is not up.
        ports: Vec<(String, u16)>,
        /// What `route_probe` answers for every lookup. Defaults to a route by
        /// the tunnel, which is the healthy host.
        route: Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>,
    }

    impl FakeHost {
        fn new() -> Self {
            Self {
                existing: Vec::new(),
                exists_seq: Mutex::new(Vec::new()),
                addrs: Mutex::new(Vec::new()),
                sysctls: Mutex::new(Vec::new()),
                events: Arc::new(Mutex::new(Vec::new())),
                vpn: MockVpn::new(),
                fwd: MockForwarder::new(),
                missing_tools: Vec::new(),
                uid: Ok(2000),
                privileged: false,
                nft: Mutex::new(Vec::new()),
                wg_devices: Vec::new(),
                handshake: Err("refused"),
                ports: Vec::new(),
                route: Ok(vpn::route::RouteProbe::ViaTunnel),
            }
        }

        /// Script the listen port `iface`'s link reports.
        fn with_listen_port(mut self, iface: &str, port: u16) -> Self {
            self.ports.push((iface.to_string(), port));
            self
        }

        /// Script what every route lookup answers.
        fn with_route(
            mut self,
            route: Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable>,
        ) -> Self {
            self.route = route;
            self
        }

        /// Script what the `wg show <iface> latest-handshakes` probe answers.
        fn with_handshake(mut self, probe: Result<Option<Duration>, &'static str>) -> Self {
            self.handshake = probe;
            self
        }

        /// `bin` is not executable on this host.
        fn with_missing_tool(mut self, bin: &str) -> Self {
            self.missing_tools.push(bin.to_string());
            self
        }

        /// This process's effective uid, as `current_uid` reports it.
        fn with_uid(mut self, uid: u32) -> Self {
            self.uid = Ok(uid);
            self
        }

        /// Script `nft --check`, call by call, as `(exit code, stderr)`.
        fn with_nft(self, seq: impl IntoIterator<Item = (i32, &'static str)>) -> Self {
            *self.nft.lock().unwrap() = seq.into_iter().map(|(c, e)| (c, e.to_string())).collect();
            self
        }

        /// Script what the capability-free link-type read says about `iface`.
        fn with_wireguard_device(mut self, iface: &str, is_wg: bool) -> Self {
            self.wg_devices.push((iface.to_string(), is_wg));
            self
        }

        /// `iface` is already present on the host before the command runs.
        fn with_existing(mut self, iface: &str) -> Self {
            self.existing.push(iface.to_string());
            self
        }

        /// Script `interface_exists` call by call.
        fn with_exists_seq(self, seq: impl IntoIterator<Item = bool>) -> Self {
            *self.exists_seq.lock().unwrap() = seq.into_iter().collect();
            self
        }

        /// Script a sysctl's contents. Anything not scripted reads as absent,
        /// which is what `/proc/sys/net/ipv4/conf/<iface>/rp_filter` does for
        /// an interface that is not there.
        fn with_sysctl(self, path: &str, value: &str) -> Self {
            self.sysctls
                .lock()
                .unwrap()
                .push((path.to_string(), value.to_string()));
            self
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        fn record(&self, what: String) {
            self.events.lock().unwrap().push(what);
        }

        /// Script what `first_ipv4(iface)` returns, call by call, so the
        /// address can change across the run the way a real bring-up or
        /// teardown changes it.
        fn with_addrs(
            self,
            seq: impl IntoIterator<Item = (&'static str, Option<Ipv4Addr>)>,
        ) -> Self {
            *self.addrs.lock().unwrap() =
                seq.into_iter().map(|(i, a)| (i.to_string(), a)).collect();
            self
        }
    }

    impl CheckHost for FakeHost {
        fn interface_exists(&self, iface: &str) -> bool {
            self.record(format!("interface_exists {iface}"));
            let mut g = self.exists_seq.lock().unwrap();
            if g.is_empty() {
                self.existing.iter().any(|i| i == iface)
            } else {
                g.remove(0)
            }
        }

        fn read_sysctl(&self, path: &str) -> Option<String> {
            self.record(format!("read_sysctl {path}"));
            self.sysctls
                .lock()
                .unwrap()
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, v)| v.clone())
        }

        fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr> {
            let mut g = self.addrs.lock().unwrap();
            let next = if g.is_empty() {
                None
            } else {
                Some(g.remove(0))
            };
            match next {
                Some((_, Some(ip))) => Ok(ip),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no IPv4 address on {iface}"),
                )),
            }
        }

        fn manager(&self, _t: VpnType, _run_dir: &Path) -> Arc<dyn VpnManager> {
            Arc::new(RecordingVpn {
                inner: self.vpn.clone(),
                events: self.events.clone(),
            })
        }

        fn forwarder(&self) -> Arc<dyn PortForwarder> {
            Arc::new(self.fwd.clone())
        }

        fn tool_available(&self, bin: &str, probe_arg: &str) -> bool {
            self.record(format!("tool_available {bin} {probe_arg}"));
            !self.missing_tools.iter().any(|b| b == bin)
        }

        fn profile_metadata(&self, path: &Path) -> std::io::Result<()> {
            self.record(format!("profile_metadata {}", path.display()));
            Ok(())
        }

        fn handshake_age(&self, iface: &str) -> Result<Option<Duration>, &'static str> {
            self.record(format!("handshake_age {iface}"));
            self.handshake
        }

        fn current_uid(&self) -> Result<u32, String> {
            self.uid.clone()
        }

        fn has_cap_net_admin(&self) -> bool {
            self.privileged
        }

        fn nft_check(&self, ruleset: &str) -> std::io::Result<std::process::Output> {
            self.record(format!("nft_check {ruleset}"));
            let mut g = self.nft.lock().unwrap();
            if g.is_empty() {
                return Ok(nft_out(0, ""));
            }
            let (code, stderr) = g.remove(0);
            Ok(nft_out(code, &stderr))
        }

        fn wireguard_device(&self, iface: &str) -> Option<bool> {
            self.record(format!("wireguard_device {iface}"));
            self.wg_devices
                .iter()
                .find(|(i, _)| i == iface)
                .map(|(_, v)| *v)
        }

        fn listen_port(&self, iface: &str) -> std::io::Result<u16> {
            self.record(format!("listen_port {iface}"));
            self.ports
                .iter()
                .find(|(i, _)| i == iface)
                .map(|(_, p)| *p)
                .ok_or_else(|| std::io::Error::other(format!("{iface} is not up")))
        }

        fn route_probe(
            &self,
            iface: &str,
            src: IpAddr,
            dest: IpAddr,
        ) -> Result<vpn::route::RouteProbe, vpn::route::RouteProbeUnavailable> {
            self.record(format!("route_probe {iface} {src} {dest}"));
            self.route.clone()
        }
    }

    /// Build a finished `nft --check` `Output` with `code` and `stderr`.
    fn nft_out(code: i32, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// `MockVpn` with its calls recorded into `FakeHost`'s event log, so the
    /// order of a raise against a host read is assertable. `MockVpn` keeps its
    /// own `bring_up_calls`/`bring_down_calls` — those answer *whether*; this
    /// answers *when*.
    #[derive(Debug)]
    struct RecordingVpn {
        inner: MockVpn,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl VpnManager for RecordingVpn {
        fn bring_up(
            &self,
            tunnel: &torrentd_engine::VpnTunnel,
        ) -> Result<IpAddr, torrentd_engine::VpnError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("bring_up {}", tunnel.interface));
            self.inner.bring_up(tunnel)
        }

        fn current_ip(&self, iface: &str) -> Result<IpAddr, torrentd_engine::VpnError> {
            self.inner.current_ip(iface)
        }

        fn bring_down(&self, iface: &str) {
            self.events
                .lock()
                .unwrap()
                .push(format!("bring_down {iface}"));
            self.inner.bring_down(iface);
        }
    }

    /// A config with one WireGuard `vpn` profile, built from TOML so a
    /// required field added to `ProfileConfig` breaks this rather than letting
    /// it exercise a shape the daemon never parses.
    fn cfg_with_profile(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"

[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_a"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_a"
{extra}
"#
        ))
        .expect("test config parses")
    }

    /// A config holding whatever `tables` spells out.
    ///
    /// [`cfg_with_profile`] interpolates its argument *inside* the one
    /// `[[profile]]` table it builds, so it can express neither a second
    /// profile nor a host profile — which is why a 41-test suite was green
    /// while the binary panicked on the shipped sample, and the sample ships
    /// exactly one profile, `network = "host"`.
    fn cfg_with_tables(tables: &str) -> Config {
        toml::from_str(&format!(
            r#"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"
{tables}
"#
        ))
        .expect("test config parses")
    }

    /// The shipped sample's shape: one profile, `network = "host"`.
    const HOST_TABLE: &str = r#"
[[profile]]
id                = "public"
network           = "host"
listen_interfaces = "0.0.0.0:6882,[::]:6882"
"#;

    const VPN_TABLE: &str = r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
"#;

    /// The same profile with a gateway-assigned port.
    ///
    /// Written out rather than appended to [`cfg_with_profile`], which sets a
    /// static `listen_port`: a `listen_port` under `port_forward = "natpmp"`
    /// is refused now, because the gateway assigns the port at runtime and
    /// nothing binds the configured one.
    fn cfg_with_natpmp_profile(extra: &str) -> Config {
        cfg_with_tables(&format!(
            r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
port_forward         = "natpmp"
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_a"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_a"
{extra}
"#
        ))
    }

    /// `cfg_with_profile`'s config with a second vpn profile, so `--profile`
    /// has something to exclude and the kill-switch table has more than one
    /// interface in it.
    fn cfg_with_two_profiles() -> Config {
        let mut cfg = cfg_with_profile("");
        cfg.network_kill_switch = true;
        let mut b = cfg_with_tables(
            r#"
[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-b.conf"
vpn_interface        = "wg-acct-b"
listen_port          = 6882
peer_fingerprint = "-BB1000-"
user_agent           = "Transmission/4.0.5"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_b"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_b"
"#,
        );
        cfg.profile.push(b.profile.remove(0));
        cfg
    }

    fn find<'a>(checks: &'a [Check], name: &str) -> Option<&'a Check> {
        checks.iter().find(|c| c.name == name)
    }

    #[test]
    fn a_host_profile_is_skipped_rather_than_handed_to_profile_checks() {
        // F14. `check()` filtered the selection by id alone and mapped
        // `profile_checks` over every survivor, and `profile_checks` opens
        // with `.expect("only vpn profiles reach profile_checks")`. On the
        // shipped sample — one `network = "host"` profile — the documented
        // bare invocation panicked and exited 101, outside the 0/1/2 contract
        // `cli.rs` publishes.
        let cfg = cfg_with_tables(HOST_TABLE);
        let host = FakeHost::new();

        let reports = profile_reports(&cfg, None, false, None, &host)
            .expect("a host-only config is a legal config to check");

        assert_eq!(reports.len(), 1, "the profile is reported, not dropped");
        assert_eq!(reports[0].profile_id, "public");
        assert_eq!(reports[0].vpn_type, "none");
        let tunnel = find(&reports[0].checks, "tunnel")
            .expect("a host profile still gets a line, or the run reads as `checked, all clear`");
        assert_eq!(tunnel.verdict, Verdict::Skip, "detail: {}", tunnel.detail);
        assert!(
            tunnel.detail.contains("public") && tunnel.detail.contains("no tunnel"),
            "the operator has to be told why it was skipped: {}",
            tunnel.detail,
        );

        // A `skip` does not colour the status: the command exits 0 rather
        // than 101.
        let report = Report {
            host: Vec::new(),
            profiles: reports,
        };
        assert_eq!(report.exit_code(), EXIT_OK);
        assert!(!report.incomplete(), "a skip is not an unknown");
    }

    #[test]
    fn scoping_to_a_host_profile_by_id_is_skipped_too() {
        // `--profile public` on a mixed config. The id filter is what used to
        // select the panicking profile on its own.
        let cfg = cfg_with_tables(&format!("{VPN_TABLE}{HOST_TABLE}"));
        let host = FakeHost::new();

        let reports = profile_reports(&cfg, Some("public"), false, None, &host)
            .expect("naming a host profile is not a usage error");

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].profile_id, "public");
        assert_eq!(
            find(&reports[0].checks, "tunnel").unwrap().verdict,
            Verdict::Skip
        );
    }

    #[test]
    fn a_mixed_config_checks_the_tunnel_and_skips_the_host() {
        // The bare invocation on a config that has both. Every profile is
        // reported, in configured order, and only the tunnelled one is
        // actually probed.
        let cfg = cfg_with_tables(&format!("{VPN_TABLE}{HOST_TABLE}"));
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

        let reports = profile_reports(&cfg, None, false, None, &host)
            .expect("a mixed config is legal and --check-config calls it OK");

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].profile_id, "acct_a");
        assert!(
            find(&reports[0].checks, "tunnel_ip").is_some(),
            "the vpn profile is still fully checked",
        );
        assert_eq!(reports[1].profile_id, "public");
        assert_eq!(reports[1].checks.len(), 1, "a host profile gets one line");
        assert_eq!(reports[1].checks[0].verdict, Verdict::Skip);
    }

    #[test]
    fn bring_up_never_lowers_an_interface_it_did_not_raise() {
        // F1. The daemon is up and seeding on wg-acct-a. `--bring-up` finds
        // the interface already there, so it must adopt it: report the
        // bring-up as `skip`, run the remaining checks, and issue no teardown
        // at all. A `bring_down` recorded here is a live profile fenced until
        // someone restarts the daemon.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        assert!(
            host.vpn.bring_down_calls().is_empty(),
            "an adopted interface must never be brought down, got {:?}",
            host.vpn.bring_down_calls(),
        );
        assert!(
            host.vpn.bring_up_calls().is_empty(),
            "an existing interface must not be handed to bring_up either",
        );
        assert!(
            find(&r.checks, "bring_down").is_none(),
            "an adopted interface produces no bring_down line",
        );
        let bu = find(&r.checks, "bring_up").expect("a bring_up line is still reported");
        assert_eq!(bu.verdict, Verdict::Skip, "detail: {}", bu.detail);
        assert!(
            bu.detail.contains("wg-acct-a") && bu.detail.contains("already exists"),
            "the operator has to be told why it was skipped: {}",
            bu.detail,
        );
        // Adoption is not an early return: the rest of the profile is still
        // checked against the interface as it stands.
        assert!(find(&r.checks, "tunnel_ip").is_some());
    }

    #[test]
    fn bring_up_raises_and_lowers_an_interface_that_was_not_there() {
        // The complement of the above, and the case the flag exists for: a
        // crash-orphaned or never-raised interface is raised, checked, and put
        // back the way it was found.
        //
        // Absent on the probe before the call, present on the re-probe after
        // it: that pair, and not the arm `bring_up` returned on, is what makes
        // it this command's to lower.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", None),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        assert_eq!(host.vpn.bring_up_calls(), vec!["wg-acct-a"]);
        assert_eq!(host.vpn.bring_down_calls(), vec!["wg-acct-a"]);
        assert_eq!(
            find(&r.checks, "bring_up").map(|c| c.verdict),
            Some(Verdict::Pass),
        );
    }

    #[test]
    fn without_bring_up_no_tunnel_is_touched_either_way() {
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

        assert!(host.vpn.bring_up_calls().is_empty());
        assert!(host.vpn.bring_down_calls().is_empty());
        assert!(find(&r.checks, "bring_up").is_none());
        assert!(find(&r.checks, "bring_down").is_none());
    }

    #[test]
    fn a_bring_down_that_left_the_tunnel_up_is_reported_as_a_failure() {
        // F7. `bring_down` returns `()` and logs its errors away, so "tunnel
        // taken back down" was printed whether or not the tunnel went down.
        // Here the address is still there on the second lookup — `wg-quick
        // down` failed — and the operator has to be told the host was left
        // changed, on the one mutation this command advertises.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        assert_eq!(host.vpn.bring_down_calls(), vec!["wg-acct-a"]);
        let bd = find(&r.checks, "bring_down").expect("a bring_down line");
        assert_eq!(bd.verdict, Verdict::Fail, "detail: {}", bd.detail);
        assert!(
            bd.detail.contains("10.2.0.2"),
            "the address that is still there names the problem: {}",
            bd.detail,
        );
        assert!(r.failed(), "and it has to reach the exit status");
    }

    #[test]
    fn a_bring_down_that_worked_is_reported_only_once_the_address_is_gone() {
        let cfg = cfg_with_profile("");
        let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", None),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        assert_eq!(
            find(&r.checks, "bring_down").map(|c| c.verdict),
            Some(Verdict::Pass),
        );
    }

    #[test]
    fn the_default_path_leaves_its_mapping_to_expire_rather_than_deleting_it() {
        // F2. The flagless path is the one documented as observe-only, and it
        // used to finish by issuing NAT-PMP's wildcard delete from the tunnel
        // address — which removes every mapping that address holds, i.e. the
        // running daemon's live TCP and UDP forwards.
        //
        // Two things hold that shut. `PortForwarder` is the whole surface the
        // call site can reach and it has no delete, so a release cannot be
        // reintroduced through this parameter at all. And the reported
        // contract, asserted below, is that the lease is left to lapse: the
        // previous wording said the mapping had been "released again", so this
        // assertion fails against the behaviour it replaced.
        let cfg = cfg_with_natpmp_profile("port_forward_gateway = \"10.2.0.1\"");
        let host = FakeHost::new().with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        host.fwd.push_ok(51413);

        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

        assert_eq!(
            host.fwd.call_count(),
            1,
            "exactly one negotiation, and nothing after it",
        );
        let req = host.fwd.calls()[0];
        assert_eq!(
            req.lifetime_secs,
            crate::port_forward_monitor::LEASE_SECS,
            "the pre-flight must ask for the daemon's lease, not a second copy of it",
        );
        assert_eq!(req.bind_ip, IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        assert_eq!(
            req.internal_port,
            PortMapRequest::INTERNAL_PORT,
            "the pre-flight must send the daemon's internal port",
        );
        assert_eq!(
            req.suggested_port, 0,
            "the pre-flight holds no port, so it must suggest none",
        );

        let pf = find(&r.checks, "port_forward").expect("a port_forward line");
        assert_eq!(pf.verdict, Verdict::Pass, "detail: {}", pf.detail);
        assert!(
            pf.detail.contains("left to expire"),
            "the operator is told the mapping is left alone: {}",
            pf.detail,
        );
        assert!(
            !pf.detail.contains("released"),
            "a released mapping is the daemon's mapping: {}",
            pf.detail,
        );
    }

    #[test]
    fn a_natpmp_profile_with_no_tunnel_address_negotiates_nothing() {
        // The gateway is only reachable through the tunnel, so with no tunnel
        // address there is nothing to negotiate from and nothing to report but
        // a skip. Checked here because it is the arm that keeps the mapping
        // call off a host that has no tunnel at all.
        let cfg = cfg_with_natpmp_profile("");
        let host = FakeHost::new();

        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

        assert_eq!(host.fwd.call_count(), 0);
        assert_eq!(
            find(&r.checks, "port_forward").map(|c| c.verdict),
            Some(Verdict::Skip),
        );
    }

    #[test]
    fn a_report_fails_when_any_check_fails() {
        let r = Report {
            host: vec![Check::pass("a", "")],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![Check::pass("b", ""), Check::fail("c", "")],
            }],
        };
        assert!(r.failed());
    }

    /// Answer one UDP datagram on loopback with `reply`, and hand back the
    /// address to aim at. The same shape `vpn::natpmp`'s tests use for the
    /// NAT-PMP gateway.
    fn loopback_responder(reply: Vec<u8>) -> SocketAddr {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a responder");
        let addr = sock.local_addr().expect("responder address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((_, from)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&reply, from);
            }
        });
        addr
    }

    #[test]
    fn an_egress_probe_passes_only_on_a_reply_to_its_own_query() {
        // The transaction id is the whole of what makes the reply ours. A
        // responder that echoes it is a round trip; one that does not is
        // something else on the wire, and the verdict says so rather than
        // claiming the tunnel works.
        let ours = loopback_responder(vec![0x7d, 0x0e, 0x81, 0x80]);
        let c = egress_probe(IpAddr::V4(Ipv4Addr::LOCALHOST), ours);
        assert_eq!(c.verdict, Verdict::Pass, "detail: {}", c.detail);

        let someone_else = loopback_responder(vec![0xff, 0xff, 0x81, 0x80]);
        let c = egress_probe(IpAddr::V4(Ipv4Addr::LOCALHOST), someone_else);
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(c.detail.contains("inconclusive"), "detail: {}", c.detail);
    }

    #[test]
    fn an_egress_probe_that_cannot_bind_the_source_fails_with_the_address() {
        // Every socket in the profile is source-bound to the tunnel address, so
        // an address that cannot be bound is the whole profile failing, not just
        // this probe.
        let unbindable = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let c = egress_probe(unbindable, "127.0.0.1:53".parse().unwrap());
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
        assert!(c.detail.contains("203.0.113.7"), "detail: {}", c.detail);
    }

    #[test]
    fn an_egress_timeout_states_both_readings_and_names_the_port() {
        // F9. The probe establishes that this destination did not answer a DNS
        // query in time. It used to report "The tunnel has an address but is
        // not carrying traffic." — one reading of several, asserted as the
        // cause, on the branch that carries the exit code.
        //
        // A responder that accepts the datagram and never answers is the
        // timeout, without waiting for one: bind a socket, aim at it, and let
        // the read time out. Kept off the default 10s by overriding nothing —
        // instead the discriminator documented in the probe itself is used, a
        // destination that refuses the datagram outright.
        let closed = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let a = s.local_addr().unwrap();
            drop(s);
            a
        };
        let c = egress_probe(IpAddr::V4(Ipv4Addr::LOCALHOST), closed);
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
        assert!(
            c.detail.contains("Two readings"),
            "the operator is handed both: {}",
            c.detail,
        );
        assert!(
            c.detail.contains(&closed.port().to_string()),
            "the port is named: {}",
            c.detail,
        );
        assert!(
            !c.detail
                .contains("has an address but is not carrying traffic"),
            "the single asserted cause is gone: {}",
            c.detail,
        );
    }

    #[test]
    fn an_egress_check_that_was_asked_for_and_could_not_run_says_so() {
        // D7. `--egress` used to produce no line in the human report and no
        // key in the JSON when the profile had no tunnel address — a check the
        // operator explicitly asked for, silently absent.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new();

        let r = profile_checks(
            &cfg,
            &cfg.profile[0],
            false,
            Some("1.1.1.1:53".parse().unwrap()),
            &host,
        );

        let e = find(&r.checks, "egress").expect("an egress line even with no address");
        assert_eq!(e.verdict, Verdict::Skip, "detail: {}", e.detail);
        assert!(
            e.detail.contains("1.1.1.1:53") && e.detail.contains("wg-acct-a"),
            "detail: {}",
            e.detail,
        );
    }

    #[test]
    fn no_egress_flag_means_no_egress_line() {
        let cfg = cfg_with_profile("");
        let host = FakeHost::new();
        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
        assert!(find(&r.checks, "egress").is_none());
    }

    #[test]
    fn rp_filter_is_judged_on_the_pair_the_kernel_actually_uses() {
        // F4. The kernel takes max(conf/all, conf/<iface>) for source
        // validation on an interface. `conf/all` alone gets both directions
        // wrong, and this host demonstrates the first of them directly: it
        // reads all = 0 with every interface at 2.
        //
        // all = 0, default = 1 — the interface inherits strict at creation, so
        // every reply to a tunnel-bound socket is dropped while conf/all reads
        // clean. This used to print `[ok  ] rp_filter … = 0`.
        let c = judge_rp_filter("wg-acct-a", Some("0"), Some("1"));
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
        assert!(c.detail.contains("effective 1"), "detail: {}", c.detail);
        assert!(
            c.detail.contains("wg-acct-a"),
            "the operator has to see which interface binds: {}",
            c.detail,
        );

        // The converse: all = 1 with the interface at 2 is loose and healthy,
        // and used to FAIL and take the exit code with it.
        let c = judge_rp_filter("wg-acct-a", Some("1"), Some("2"));
        assert_eq!(c.verdict, Verdict::Pass, "detail: {}", c.detail);
        assert!(c.detail.contains("effective 2"), "detail: {}", c.detail);

        // Both loose, the documented configuration.
        assert_eq!(
            judge_rp_filter("wg-acct-a", Some("2"), Some("2")).verdict,
            Verdict::Pass,
        );
        // Both strict.
        assert_eq!(
            judge_rp_filter("wg-acct-a", Some("1"), Some("1")).verdict,
            Verdict::Fail,
        );
    }

    #[test]
    fn an_rp_filter_value_that_cannot_be_read_or_parsed_is_not_a_pass() {
        // The old `Some(v) => pass` arm passed anything that was not the
        // literal "1", nonsense included, and an interface whose sysctl is
        // absent says nothing about the interface either way.
        for (all, iface) in [
            (None, Some("2")),
            (Some("2"), None),
            (Some("banana"), Some("2")),
            (Some("2"), Some("")),
        ] {
            let c = judge_rp_filter("wg-acct-a", all, iface);
            assert_eq!(
                c.verdict,
                Verdict::Unknown,
                "all={all:?} iface={iface:?} gave {}",
                c.detail,
            );
        }
    }

    #[test]
    fn the_kill_switch_uid_checks_do_not_pass_judgement_on_the_wrong_process() {
        // F3. The packaged unit runs the daemon as `User=torrentd`, and
        // `--bring-up` all but requires root, so `sudo torrentd … vpn check
        // --bring-up` measured uid 0 and emitted `[FAIL] kill_switch_uid` as
        // its first line — a failure the daemon would never hit, on a check
        // whose own module doc promises the first failure here is the first
        // failure the daemon would hit.
        let c = judge_kill_switch_uid(Some(998), Ok(0));
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(
            c.detail.contains("998") && c.detail.contains("uid 0"),
            "both uids are named: {}",
            c.detail,
        );
    }

    #[test]
    fn an_excluded_profile_s_interface_does_not_decide_a_scoped_run() {
        // C52 / F4, reopened. `rp_filter` moved into the profile when the
        // same finding was first repaired, and `kill_switch_ruleset` kept
        // building its interface list from every configured profile, ignoring
        // `--profile`. A rejection caused by an interface belonging to a
        // profile the operator excluded was a `fail` and an exit 1 for a
        // profile that was not being checked, against a flag whose help says
        // "Check only this profile."
        //
        // The table is still rendered whole, because boot installs it whole
        // and the caveat says so. What changes is the verdict.
        let cfg = cfg_with_two_profiles();
        let host = FakeHost::new()
            // The full table is rejected; the selected profile's alone is not.
            .with_nft([
                (
                    1,
                    "/dev/stdin:5:39-39: Error: syntax error, unexpected string",
                ),
                (0, ""),
            ]);

        let checks = host_checks(&cfg, Some(2000), Some("acct_a"), &host);
        let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is still reported");

        assert_ne!(
            c.verdict,
            Verdict::Fail,
            "an excluded profile's interface does not colour a scoped run: {}",
            c.detail,
        );
        assert!(
            c.detail.contains("wg-acct-b") && c.detail.contains("acct_b"),
            "the offending interface and the profile it belongs to are both named: {}",
            c.detail,
        );
        assert!(
            c.detail.contains("syntax error"),
            "nft's own words still reach the operator: {}",
            c.detail,
        );
        let report = Report {
            host: checks,
            profiles: Vec::new(),
        };
        assert_eq!(
            report.exit_code(),
            EXIT_OK,
            "a run scoped to a healthy profile is clean",
        );

        // The complement: when the rejection survives scoping, it is the
        // selected profile's and it still decides the run.
        let host = FakeHost::new().with_nft([
            (
                1,
                "/dev/stdin:5:39-39: Error: syntax error, unexpected string",
            ),
            (
                1,
                "/dev/stdin:4:39-39: Error: syntax error, unexpected string",
            ),
        ]);
        let checks = host_checks(&cfg, Some(2000), Some("acct_a"), &host);
        let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is still reported");
        assert_eq!(
            c.verdict,
            Verdict::Fail,
            "a rejection the selected profile owns still fails: {}",
            c.detail,
        );

        // And an unscoped run is untouched: nothing was excluded, so there is
        // nothing to attribute elsewhere.
        let host = FakeHost::new().with_nft([(
            1,
            "/dev/stdin:5:39-39: Error: syntax error, unexpected string",
        )]);
        let checks = host_checks(&cfg, Some(2000), None, &host);
        let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is still reported");
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
    }

    #[test]
    fn a_uid_mismatch_is_reported_without_colouring_the_exit_status() {
        // F11, reopened. `--as-uid` names a uid the invoker is not *by
        // definition* — that is the whole reason the flag exists — and this
        // process cannot observe which user the daemon runs as. So the
        // mismatch is unsettleable by any argument, privilege or
        // configuration this invocation could be given, which is the same
        // class as the capability-bound unknowns and is excluded from the
        // status for the same reason.
        //
        // Leaving it to colour the status meant every combination of the one
        // documented privileged invocation landed on 1 or 2: under `sudo`
        // with no `--as-uid` the subject is 0 and fails, `--as-uid 0` fails,
        // and `--as-uid <daemon uid>` cost 2. A status nobody can get a 0
        // from trains both consumers to accept 2, which is what the
        // three-valued status was introduced to prevent.
        let c = judge_kill_switch_uid(Some(998), Ok(2000));
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(
            c.needs_capability,
            "an unknown nothing can settle does not colour the status: {}",
            c.detail,
        );
        assert!(
            c.detail.contains("998") && c.detail.contains("2000"),
            "both uids are named: {}",
            c.detail,
        );

        // Through the report: this is the invocation `docs/running.md`
        // describes, and it has to be able to reach 0.
        let report = Report {
            host: vec![
                Check::pass("iproute2", "`ip` is available"),
                Check::pass("nftables", "`nft` is available"),
                judge_kill_switch_uid(Some(998), Ok(2000)),
            ],
            profiles: Vec::new(),
        };
        assert_eq!(
            report.exit_code(),
            EXIT_OK,
            "--as-uid from a uid that is not the subject is the expected case, not a fault",
        );

        // The uid check still answers where the answer does not depend on the
        // observer: uid 0 fails whoever asks.
        assert_eq!(
            judge_kill_switch_uid(Some(0), Ok(2000)).verdict,
            Verdict::Fail,
            "the non-colouring class does not swallow a decidable failure",
        );
    }

    #[test]
    fn a_named_uid_of_zero_is_a_failure_whoever_is_asking() {
        // `killswitch::enable` refuses uid 0 *unconditionally* — it consults
        // neither the invoker nor the config — so "the daemon runs as root"
        // settles "the boot aborts at the kill switch" on its own, and the
        // answer does not depend on who is observing. Reporting it `unknown`
        // wrote that fact into the detail string and then withheld it from the
        // verdict: the report said the boot aborts while the status byte said
        // nothing was established.
        let c = judge_kill_switch_uid(Some(0), Ok(1000));
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
        assert!(
            c.detail.contains("refuses uid 0 whoever asks"),
            "the reason it is decidable without the invoker is stated: {}",
            c.detail,
        );
        assert!(
            c.detail.contains("--as-uid"),
            "and which of the two uids is being judged: {}",
            c.detail,
        );
        // It has to reach the exit status, not just the report.
        let r = Report {
            host: vec![c],
            profiles: vec![],
        };
        assert_eq!(r.exit_code(), EXIT_FAILED);

        // Every other route to subject 0 is the same failure.
        assert_eq!(judge_kill_switch_uid(Some(0), Ok(0)).verdict, Verdict::Fail);
        assert_eq!(judge_kill_switch_uid(None, Ok(0)).verdict, Verdict::Fail);
        assert_eq!(
            judge_kill_switch_uid(Some(0), Err("no Uid line".into())).verdict,
            Verdict::Fail,
        );
    }

    #[test]
    fn an_unsettled_uid_check_no_longer_suppresses_the_ruleset_dry_run() {
        // F11. `--as-uid` names a uid the invoker is not, by definition — that
        // is the flag's entire purpose. Coupling the ruleset's existence to
        // the uid check's verdict therefore turned *both* kill-switch checks
        // to `unknown` on the one invocation the flag exists for, so `nft
        // --check` never ran on it. With `--bring-up` needing root, that left
        // `vpn check --bring-up` on a `network_kill_switch = true` host with
        // no route to exit 0 by any argument combination.
        //
        // The uid check is still honestly `unknown` — this process cannot
        // observe the daemon's uid — and the dry-run still happens, because
        // whether the ruleset for uid 998 parses and validates against this
        // kernel does not depend on who asks.
        let uid = judge_kill_switch_uid(Some(998), Ok(2000));
        assert_eq!(uid.verdict, Verdict::Unknown, "detail: {}", uid.detail);
        assert_eq!(
            ruleset_subject(Some(998), Ok(2000)),
            Some(998),
            "the ruleset is rendered for the uid the operator named",
        );
        assert!(
            uid.detail.contains("still rendered and dry-run"),
            "and the operator is told the two are decoupled: {}",
            uid.detail,
        );

        // No uid named: this process's own, as before.
        assert_eq!(ruleset_subject(None, Ok(2000)), Some(2000));
        // Nothing to render for at all is the only `None`.
        assert_eq!(ruleset_subject(None, Err("no Uid line".into())), None);
        // And an unreadable invoker does not stop a named uid being judged.
        assert_eq!(
            ruleset_subject(Some(998), Err("no Uid line".into())),
            Some(998)
        );
    }

    #[test]
    fn the_kill_switch_uid_check_still_judges_the_uid_it_is_actually_running_as() {
        assert_eq!(judge_kill_switch_uid(None, Ok(1000)).verdict, Verdict::Pass);
        assert_eq!(
            judge_kill_switch_uid(Some(1000), Ok(1000)).verdict,
            Verdict::Pass,
        );
        // uid 0 for real is still the outage `killswitch::enable` refuses.
        assert_eq!(judge_kill_switch_uid(None, Ok(0)).verdict, Verdict::Fail);
        assert_eq!(judge_kill_switch_uid(Some(0), Ok(0)).verdict, Verdict::Fail);
        // Nothing to judge at all.
        assert_eq!(
            judge_kill_switch_uid(None, Err("no Uid line".into())).verdict,
            Verdict::Unknown,
        );
    }

    #[test]
    fn a_check_that_could_not_be_performed_does_not_exit_zero() {
        // F6. The report distinguishes four verdicts so a green cannot quietly
        // mean "mostly not checked", but the exit status is the only part of
        // it a mise task or a systemd ExecStartPre reads. A run that
        // established nothing about the handshake half used to exit 0.
        let r = Report {
            host: vec![Check::pass("iproute2", ""), Check::unknown("rp_filter", "")],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![
                    Check::pass("tunnel_ip", ""),
                    Check::unknown("handshake", ""),
                ],
            }],
        };
        assert!(!r.failed(), "nothing failed");
        assert!(r.incomplete());
        assert_eq!(r.exit_code(), EXIT_UNKNOWN);
    }

    #[test]
    fn an_unknown_inside_a_profile_alone_is_enough_to_colour_the_status() {
        // The host half can be entirely clean and the profile half entirely
        // unestablished; `Report::failed` only ever looked at `Fail`, so the
        // profile half has to be reached explicitly.
        let r = Report {
            host: vec![Check::pass("iproute2", "")],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![Check::unknown("handshake", "")],
            }],
        };
        assert_eq!(r.exit_code(), EXIT_UNKNOWN);
    }

    #[test]
    fn a_failure_outranks_an_unknown_in_the_exit_status() {
        let r = Report {
            host: vec![Check::unknown("rp_filter", "")],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![Check::fail("tunnel_ip", "")],
            }],
        };
        assert_eq!(r.exit_code(), EXIT_FAILED);
    }

    #[test]
    fn a_skip_is_not_an_unknown_and_exits_clean() {
        // A NAT-PMP check on a static profile did not fail to happen; it
        // correctly did not apply. Colouring the status for it would make
        // every static deployment exit 2 forever.
        let r = Report {
            host: vec![Check::pass("iproute2", ""), Check::skip("kill_switch", "")],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![
                    Check::pass("tunnel_ip", ""),
                    Check::skip("port_forward", ""),
                ],
            }],
        };
        assert!(!r.incomplete());
        assert_eq!(r.exit_code(), EXIT_OK);
    }

    #[test]
    fn a_host_side_failure_alone_fails_the_report() {
        // The left side of `Report::failed`'s `||`, which nothing reached.
        let r = Report {
            host: vec![Check::fail("iproute2", "")],
            profiles: vec![],
        };
        assert!(r.failed());
        assert_eq!(r.exit_code(), EXIT_FAILED);
    }

    #[test]
    fn unknown_and_skip_are_not_failures() {
        // An absent `wg` says nothing about whether the tunnel is healthy, and
        // reporting it as a failure would train an operator to ignore them.
        let r = Report {
            host: vec![Check::unknown("a", "")],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "openvpn",
                checks: vec![Check::skip("b", ""), Check::unknown("c", "")],
            }],
        };
        assert!(!r.failed());
    }

    #[test]
    fn the_json_report_keeps_the_shape_its_consumers_parse() {
        // C7/C8. `--json` is a contract: the four verdicts are lowercase
        // strings, and the report is `host` plus `profiles`, each profile carrying
        // `profile_id`, `vpn_type` and `checks` of `name`/`verdict`/`detail`.
        // Nothing here is enforced by the type system — `#[serde(rename_all)]`
        // is one attribute away from renaming every verdict at once.
        let r = Report {
            host: vec![Check::pass("iproute2", "`ip` is available")],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![
                    Check::fail("tunnel_ip", "no address"),
                    Check::skip("port_forward", "static"),
                    Check::unknown("handshake", "probe unavailable"),
                ],
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();

        assert_eq!(v["host"][0]["name"], "iproute2");
        assert_eq!(v["host"][0]["verdict"], "pass");
        assert_eq!(v["host"][0]["detail"], "`ip` is available");
        assert_eq!(v["profiles"][0]["profile_id"], "acct_a");
        assert_eq!(v["profiles"][0]["vpn_type"], "wireguard");
        assert_eq!(v["profiles"][0]["checks"][0]["verdict"], "fail");
        assert_eq!(v["profiles"][0]["checks"][1]["verdict"], "skip");
        assert_eq!(v["profiles"][0]["checks"][2]["verdict"], "unknown");
    }

    #[test]
    fn every_verdict_serialises_to_its_documented_lowercase_name() {
        for (verdict, expected) in [
            (Verdict::Pass, "pass"),
            (Verdict::Fail, "fail"),
            (Verdict::Skip, "skip"),
            (Verdict::Unknown, "unknown"),
        ] {
            assert_eq!(serde_json::to_value(verdict).unwrap(), expected);
        }
    }

    #[test]
    fn a_config_with_no_profiles_is_refused_with_an_explanation() {
        // C38. A config with no `[[profile]]` table has no tunnel to check, so
        // an empty report would read as a clean bill of health. Such a config
        // cannot start a daemon either, and the refusal says so.
        let cfg: Config = toml::from_str(
            r#"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"
"#,
        )
        .unwrap();

        let e = check(&cfg, None, false, false, None, None).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("[[profile]]"), "got {msg}");
        assert!(msg.contains("cannot start"), "got {msg}");
    }

    #[test]
    fn a_profile_filter_that_matches_nothing_is_refused_rather_than_reported_clean() {
        // C39. `--profile typo` used to be indistinguishable from "every profile
        // passed": no profiles selected, no failures, exit 0.
        let cfg = cfg_with_profile("");
        let e = check(&cfg, Some("acct_b"), false, false, None, None).unwrap_err();
        assert!(format!("{e:#}").contains("acct_b"), "got {e:#}");
    }

    #[test]
    fn a_missing_tool_is_reported_rather_than_panicking() {
        assert!(!tool_available(
            "torrentd-definitely-not-a-binary",
            "--version"
        ));
    }

    #[test]
    fn the_client_the_check_negotiates_with_cannot_delete_on_any_branch() {
        // F2, reopened. Removing the release from the call site and narrowing
        // the trait to `map` made a release inexpressible *through the
        // parameter*; it did not make one impossible, because
        // `NatpmpForwarder::map` issues the RFC 6886 wildcard delete itself
        // when the gateway answers UDP on a different port from TCP. The
        // socket that delete goes out on is bound to the tunnel address — the
        // running daemon's NAT-PMP identity — so the flagless, documented-as-
        // safe path could still destroy the daemon's live UDP forward.
        //
        // The property therefore has to hold for the object the command
        // calls. `natpmp.rs` asserts the branch behaviour against a loopback
        // gateway; this asserts that the check picks that client.
        assert!(
            !RealHost::probe_forwarder().deletes_divergent_udp(),
            "the pre-flight must negotiate with a client that deletes nothing",
        );
        // And that it is still the one-shot budget, not the renewal one: the
        // check asks startup's question and deserves startup's retransmits.
        assert!(
            RealHost::probe_forwarder().deletes_divergent_udp()
                != vpn::NatpmpForwarder::for_startup().deletes_divergent_udp(),
            "the daemon's own client is unchanged and still tidies its orphan",
        );
    }

    #[test]
    fn rp_filter_is_judged_for_the_profile_and_only_after_it_has_been_raised() {
        // F4, reopened. `conf/<iface>/rp_filter` is per profile by construction,
        // so judging it in the unscoped host block ignored `--profile` — a run
        // narrowed to one healthy profile exited 2 because of an interface the
        // operator had excluded — and ran it before `--bring-up` had raised
        // anything, so the sysctl for the interface the command was about to
        // create did not exist and the check reported `unknown` about the one
        // interface the run was for.
        //
        // The kernel is modelled honestly here: the per-interface sysctl is
        // scripted, and the assertion is on the *order* of the read against
        // the raise, so moving the read back into `host_checks` fails this
        // rather than merely relocating a passing test.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_exists_seq([false, true])
            .with_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
            .with_sysctl("/proc/sys/net/ipv4/conf/wg-acct-a/rp_filter", "2")
            .with_addrs([
                ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
                ("wg-acct-a", None),
            ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        let rp = find(&r.checks, "rp_filter").expect("the profile carries its own rp_filter line");
        assert_eq!(rp.verdict, Verdict::Pass, "detail: {}", rp.detail);
        assert!(
            rp.detail.contains("wg-acct-a") && rp.detail.contains("effective 2"),
            "the interface that binds is named: {}",
            rp.detail,
        );

        let events = host.events();
        let raised = events
            .iter()
            .position(|e| e == "bring_up wg-acct-a")
            .expect("the interface was raised");
        let read = events
            .iter()
            .position(|e| e == "read_sysctl /proc/sys/net/ipv4/conf/wg-acct-a/rp_filter")
            .expect("its rp_filter was read");
        assert!(
            raised < read,
            "the sysctl has to be read after the raise, or it reads as absent for the one \
             interface the run is about: {events:?}",
        );
    }

    #[test]
    fn the_host_block_carries_no_per_profile_check_and_no_duplicate_name() {
        // The other half of the same finding: a per-profile sysctl in the
        // unscoped host block emitted one `Check` per configured interface,
        // all named `rp_filter`, so `host[]` in the `--json` contract carried
        // duplicate `name` values and a consumer keying by name silently kept
        // one of them.
        //
        // Run against a `CheckHost` double rather than the real `ip` and
        // `nft`: what this asserts is the shape of the block, which must not
        // depend on what happens to be installed on the machine running it.
        let cfg = cfg_with_profile("");
        let host = host_checks(&cfg, None, None, &FakeHost::new());
        assert!(
            find(&host, "rp_filter").is_none(),
            "rp_filter is per profile and belongs to the profile: {:?}",
            host.iter().map(|c| c.name).collect::<Vec<_>>(),
        );
        let mut names: Vec<&str> = host.iter().map(|c| c.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "a consumer keying host[] by name has to get every check: {names:?}",
        );
    }

    #[test]
    fn the_host_block_is_built_from_the_check_host_and_not_from_this_machine() {
        // D34. `host_checks` was the one unit outside the `CheckHost` seam, so
        // its only test shelled out to the real `ip` and `nft` and asserted
        // whatever the machine answered — which is no constraint at all on the
        // two classifications this block now performs.
        //
        // Every host touch is scripted here, and the block's names and
        // verdicts follow the script rather than the host.
        let mut cfg = cfg_with_profile("");
        cfg.network_kill_switch = true;
        let host = FakeHost::new().with_uid(998).with_nft([(
            1,
            "netlink: Error: cache initialization failed: Operation not permitted",
        )]);

        let checks = host_checks(&cfg, None, None, &host);

        let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            vec![
                "iproute2",
                "nftables",
                "kill_switch_uid",
                "kill_switch_ruleset"
            ],
            "the host block's shape is the contract `host[]` publishes",
        );
        assert!(
            !names.contains(&"rp_filter"),
            "no per-profile check belongs in the unscoped host block: {names:?}",
        );

        // The scripted uid is the one judged, and the scripted `nft` outcome
        // is the one classified — neither came from this machine.
        let uid = find(&checks, "kill_switch_uid").expect("the uid check is reported");
        assert_eq!(uid.verdict, Verdict::Pass, "detail: {}", uid.detail);
        assert!(uid.detail.contains("998"), "detail: {}", uid.detail);
        let ruleset = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
        assert_eq!(
            ruleset.verdict,
            Verdict::Unknown,
            "detail: {}",
            ruleset.detail
        );
        assert!(ruleset.needs_capability, "detail: {}", ruleset.detail);

        // And the calls went through the seam rather than round it.
        let events = host.events();
        assert!(
            events.iter().any(|e| e.starts_with("tool_available ip"))
                && events.iter().any(|e| e.starts_with("nft_check")),
            "host_checks reaches the host only through CheckHost: {events:?}",
        );
    }

    /// #33: a name the renderer refuses is a `fail` naming it, reached before
    /// any `nft` runs — not a ruleset handed to `nft` to reject with a line
    /// number in stdin. Parsed without `Config::validate`, which would refuse
    /// the name first, so this reaches the renderer's own guard.
    #[test]
    fn an_unrenderable_interface_fails_the_ruleset_check_without_nft() {
        let mut cfg = cfg_with_tables(
            r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg}x.conf"
vpn_interface        = "wg}x"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"
"#,
        );
        cfg.network_kill_switch = true;
        let host = FakeHost::new().with_uid(998).with_nft([(0, "")]);

        let checks = host_checks(&cfg, None, None, &host);

        let ruleset = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
        assert_eq!(ruleset.verdict, Verdict::Fail, "detail: {}", ruleset.detail);
        assert!(
            ruleset.detail.contains("\"wg}x\""),
            "detail: {}",
            ruleset.detail
        );
        assert!(
            !host.events().iter().any(|e| e.starts_with("nft_check")),
            "nothing unparseable is handed to nft: {:?}",
            host.events(),
        );
    }

    /// #33 under `--profile`: a render refusal goes through
    /// `attribute_ruleset_rejection` like an `nft` rejection does. When the
    /// selected profile's own name is the one refused, the scoped render is
    /// refused too and the `fail` stands. When only an excluded profile's name
    /// is refused, the scoped ruleset renders and parses, and the verdict is
    /// downgraded to `skip` naming the excluded profile.
    #[test]
    fn a_render_refusal_is_attributed_to_the_profile_whose_name_was_refused() {
        let mut cfg = cfg_with_tables(
            r#"
[[profile]]
id                   = "acct_a"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg-acct-a.conf"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint = "-AA1000-"
user_agent           = "qBittorrent/5.0.3"

[[profile]]
id                   = "acct_b"
network              = "vpn"
vpn_type             = "wireguard"
vpn_config           = "/etc/wireguard/wg}x.conf"
vpn_interface        = "wg}x"
listen_port          = 6882
peer_fingerprint = "-BB1000-"
user_agent           = "Transmission/4.0.5"
"#,
        );
        cfg.network_kill_switch = true;

        // The selected profile owns the refused name: the scoped render is
        // refused as well, so the early return keeps the `fail`, and no
        // ruleset of any kind reaches nft.
        let host = FakeHost::new();
        let checks = host_checks(&cfg, Some(2000), Some("acct_b"), &host);
        let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
        assert!(c.detail.contains("\"wg}x\""), "detail: {}", c.detail);
        assert!(
            !host.events().iter().any(|e| e.starts_with("nft_check")),
            "a refused scoped render hands nothing to nft: {:?}",
            host.events(),
        );
        let report = Report {
            host: checks,
            profiles: Vec::new(),
        };
        assert_ne!(
            report.exit_code(),
            EXIT_OK,
            "the selected profile's refusal decides the run"
        );

        // Only an excluded profile's name is refused: the selected profile's
        // ruleset renders and parses, so the refusal is reported against the
        // excluded profile without deciding the run.
        let host = FakeHost::new().with_nft([(0, "")]);
        let checks = host_checks(&cfg, Some(2000), Some("acct_a"), &host);
        let c = find(&checks, "kill_switch_ruleset").expect("the ruleset check is reported");
        assert_eq!(c.verdict, Verdict::Skip, "detail: {}", c.detail);
        assert!(
            c.detail.contains("\"wg}x\"") && c.detail.contains("wg}x (profile acct_b)"),
            "the refused name and the excluded profile that owns it are both named: {}",
            c.detail,
        );
        let nft_calls: Vec<String> = host
            .events()
            .into_iter()
            .filter(|e| e.starts_with("nft_check"))
            .collect();
        assert_eq!(
            nft_calls.len(),
            1,
            "only the scoped ruleset is dry-run: {nft_calls:?}"
        );
        assert!(
            nft_calls[0].contains("wg-acct-a") && !nft_calls[0].contains("wg}x"),
            "the dry-run ruleset holds the selected profile's interface alone: {nft_calls:?}",
        );
        let report = Report {
            host: checks,
            profiles: Vec::new(),
        };
        assert_eq!(
            report.exit_code(),
            EXIT_OK,
            "an excluded profile's refusal does not colour a scoped run"
        );
    }

    #[test]
    fn a_bring_up_that_failed_after_raising_the_interface_lowers_it_again() {
        // F1(A), reopened. `bring_up` can return `Err` having already started
        // something: `OpenvpnManager` runs `openvpn --daemon`, which forks and
        // exits 0, and then times out in its own address poll; `wg-quick up`
        // succeeds and the IPv4 poll times out the same way. Returning on the
        // `Err` arm before `raised_here` was set left an interface — and, for
        // openvpn, a process writing its pid file where the daemon's teardown
        // reads it — standing forever, with nothing in the report about it.
        // Re-running then found the interface present and reported `skip`, so
        // the leak was permanent.
        //
        // Absent before, present after, so it is this command's to lower,
        // whatever arm `bring_up` came back on.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_exists_seq([false, true])
            .with_addrs([("wg-acct-a", None)]);
        // No `set_ip`, so MockVpn::bring_up returns BringUpTimeout — the exact
        // error both real managers produce after they have already started
        // something.

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        let bu = find(&r.checks, "bring_up").expect("a bring_up line");
        assert_eq!(bu.verdict, Verdict::Fail, "detail: {}", bu.detail);
        assert!(
            bu.detail.contains("lowering it again"),
            "the operator is told what is being done about it: {}",
            bu.detail,
        );
        assert_eq!(
            host.vpn.bring_down_calls(),
            vec!["wg-acct-a"],
            "an interface this command raised is lowered even when the raise reported failure",
        );
        assert!(
            find(&r.checks, "bring_down").is_some(),
            "and the teardown is reported, not assumed",
        );
    }

    #[test]
    fn a_bring_up_that_failed_and_left_nothing_standing_says_what_it_cannot_see() {
        // The complement: nothing appeared, so there is nothing to lower and
        // no teardown is issued. What the report says it cannot see depends on
        // the manager that was asked.
        //
        // F17. The caveat was unconditional, so a WireGuard profile's failure
        // was explained with openvpn's daemonising and the operator was sent
        // looking for an orphaned process that cannot exist. `openvpn
        // --daemon` forks and exits 0 before its own address poll and can
        // leave one; `wg-quick up` cannot.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new().with_exists_seq([false, false]);

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        assert!(host.vpn.bring_down_calls().is_empty());
        assert!(find(&r.checks, "bring_down").is_none());
        let bu = find(&r.checks, "bring_up").expect("a bring_up line");
        assert_eq!(bu.verdict, Verdict::Fail, "detail: {}", bu.detail);
        assert!(
            !bu.detail.contains("may have left a process running"),
            "wg-quick leaves no process, so the report must not suggest one: {}",
            bu.detail,
        );
        assert!(
            bu.detail.contains("leaves no process behind"),
            "the operator is told what was and was not left standing: {}",
            bu.detail,
        );

        // The openvpn profile, where the caveat is true and belongs.
        let mut cfg = cfg_with_profile("");
        match &mut cfg.profile[0].network {
            torrentd_engine::ProfileNetwork::Vpn { vpn_type, .. } => {
                *vpn_type = VpnType::Openvpn;
            }
            torrentd_engine::ProfileNetwork::Host { .. } => unreachable!("a vpn profile"),
        }
        let host = FakeHost::new().with_exists_seq([false, false]);

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        let bu = find(&r.checks, "bring_up").expect("a bring_up line");
        assert_eq!(bu.verdict, Verdict::Fail, "detail: {}", bu.detail);
        assert!(
            bu.detail.contains("may have left a process running")
                && bu.detail.contains("openvpn daemonises"),
            "the one thing it cannot observe is named, for the manager that can do it: {}",
            bu.detail,
        );
    }

    /// A tunnel whose routing could not be installed did come up, and the
    /// bring-up has already lowered it. For OpenVPN the report said "no tun
    /// appeared … may have left a process running", which is wrong on both
    /// counts; WireGuard reports the same `RoutingFailed`
    /// (`vpn::wireguard`'s `raise_failed`), so it reads the same.
    #[test]
    fn a_tunnel_lowered_for_want_of_routing_is_reported_as_having_come_up() {
        for kind in [VpnType::Openvpn, VpnType::Wireguard] {
            let mut cfg = cfg_with_profile("");
            match &mut cfg.profile[0].network {
                torrentd_engine::ProfileNetwork::Vpn { vpn_type, .. } => {
                    *vpn_type = kind;
                }
                torrentd_engine::ProfileNetwork::Host { .. } => unreachable!("a vpn profile"),
            }
            let host = FakeHost::new().with_exists_seq([false, false]);
            host.vpn.set_unroutable("wg-acct-a");

            let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

            let bu = find(&r.checks, "bring_up").expect("a bring_up line");
            assert_eq!(bu.verdict, Verdict::Fail, "{kind:?} detail: {}", bu.detail);
            assert!(
                bu.detail.contains("came up") && bu.detail.contains("taken down again"),
                "{kind:?}: the tunnel appeared and is gone: {}",
                bu.detail,
            );
            assert!(
                !bu.detail.contains("no wg-acct-a appeared")
                    && !bu.detail.contains("may have left a process running"),
                "{kind:?}: {}",
                bu.detail,
            );
            assert!(host.vpn.bring_down_calls().is_empty());
        }
    }

    #[test]
    fn a_successful_bring_up_that_adopted_rather_than_created_is_not_lowered() {
        // F1(B)'s shape from the other side: `Ok` is not evidence of a raise,
        // because `wg-quick up` refuses an interface that already exists and
        // the adoption path returns `Ok(ip)` for it. The re-probe is what
        // decides, so an interface that is *not* there after the call is not
        // lowered on the strength of an `Ok`.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_exists_seq([false, false])
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = profile_checks(&cfg, &cfg.profile[0], true, None, &host);

        assert_eq!(
            find(&r.checks, "bring_up").map(|c| c.verdict),
            Some(Verdict::Pass),
        );
        assert!(
            host.vpn.bring_down_calls().is_empty(),
            "nothing was observed to appear, so nothing is torn down: {:?}",
            host.vpn.bring_down_calls(),
        );
    }

    #[test]
    fn a_check_blocked_by_a_missing_capability_does_not_colour_the_exit_status() {
        // F6, reopened. `unknown` was the *normal* outcome of every invocation
        // the documentation recommends: run as the daemon's user, as
        // docs/running.md says to, and `wg show … latest-handshakes` is
        // refused and `nft --check` cannot initialise its netlink cache, so a
        // host where nothing is wrong exited 2. Raising privileges does not
        // help — it moves the problem to kill_switch_uid. A status that is
        // never 0 on the supported deployment trains its two consumers to
        // accept 2, which is what the three-valued status existed to prevent.
        let r = Report {
            host: vec![
                Check::pass("iproute2", ""),
                Check::unknown_without_capability("kill_switch_ruleset", ""),
            ],
            profiles: vec![ProfileReport {
                profile_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![
                    Check::pass("tunnel_ip", ""),
                    Check::unknown_without_capability("handshake", ""),
                ],
            }],
        };
        assert!(!r.failed());
        assert!(
            !r.incomplete(),
            "a capability this shell does not have is not something that could not be checked",
        );
        assert!(r.capability_bound(), "but it is still reported as such");
        assert_eq!(r.exit_code(), EXIT_OK);

        // A plain `Unknown` is untouched: an unreadable sysctl still means
        // nothing was established, and still exits 2.
        let r = Report {
            host: vec![
                Check::unknown_without_capability("kill_switch_ruleset", ""),
                Check::unknown("rp_filter", ""),
            ],
            profiles: vec![],
        };
        assert_eq!(r.exit_code(), EXIT_UNKNOWN);

        // And a real failure still outranks both.
        let r = Report {
            host: vec![
                Check::unknown_without_capability("handshake", ""),
                Check::fail("iproute2", ""),
            ],
            profiles: vec![],
        };
        assert_eq!(r.exit_code(), EXIT_FAILED);
    }

    #[test]
    fn a_capability_bound_check_is_marked_in_both_renderings() {
        // It does not colour the status, so the renderings are the only place
        // an operator can learn it did not run. The JSON field is optional and
        // absent on every other check, so a consumer that does not know about
        // it sees exactly what it saw before.
        let blocked = Check::unknown_without_capability("handshake", "no CAP_NET_ADMIN");
        assert_eq!(symbol(&blocked), "?cap");
        assert_eq!(symbol(&Check::unknown("rp_filter", "")), "?   ");
        assert_eq!(symbol(&Check::pass("iproute2", "")), "ok  ");

        let v = serde_json::to_value(&blocked).unwrap();
        assert_eq!(
            v["verdict"], "unknown",
            "the four verdict names do not change"
        );
        assert_eq!(v["needs_capability"], true);
        let ordinary = serde_json::to_value(Check::unknown("rp_filter", "")).unwrap();
        assert!(
            ordinary.get("needs_capability").is_none(),
            "the field is absent rather than false on every other check: {ordinary}",
        );
    }

    /// Build a `std::process::Output` for a finished `nft --check`.
    fn nft_output(code: i32, stderr: &str) -> std::io::Result<std::process::Output> {
        use std::os::unix::process::ExitStatusExt;
        Ok(std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    #[test]
    fn nft_check_is_classified_by_what_nft_reported_not_by_who_asked() {
        // F13, reopened. This test used to assert the opposite — that the
        // capability mask classifies before the error text does — and that
        // premise is refuted by execution: as an unprivileged uid with an
        // empty `CapEff`, an invalid ruleset prints a parser diagnostic and a
        // valid one prints only `netlink: Error: cache initialization failed`.
        // nftables parses before it touches netlink, so the two classes are
        // distinguishable without the capability.
        //
        // Classifying on the mask made `!privileged` short-circuit every
        // failure into the capability class on the one invocation
        // `docs/running.md` recommends, and since that class does not colour
        // the status, a configuration whose boot would abort at
        // `killswitch::enable` exited 0.
        //
        // Unprivileged, and nft reports it could not reach the kernel — in a
        // wording this code has never seen. Capability-bound: the ruleset
        // parsed.
        let c = judge_nft_check(
            nft_output(1, "netlink: konnte Cache nicht initialisieren"),
            false,
            998,
            "table inet torrentd {}",
        );
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(c.needs_capability, "detail: {}", c.detail);

        // Unprivileged, and nft rejected the ruleset. This is the arm the
        // removed behaviour got wrong, and it is what the command actually
        // sees: an unprivileged run against a ruleset that does not parse
        // prints the parser's diagnostic *and* the netlink one, because nft
        // carries on to the kernel after reporting the parse failure.
        let c = judge_nft_check(
            nft_output(
                1,
                "/dev/stdin:5:39-39: Error: syntax error, unexpected string, expecting \
                 comma or '}'\n\t\tmeta skuid 2000 oifname { \"lo\", \"wg\"x\" } accept\n\t\t \
                 ^\nnetlink: Error: cache initialization failed: Operation not permitted",
            ),
            false,
            2000,
            "table inet torrentd {}",
        );
        assert_eq!(
            c.verdict,
            Verdict::Fail,
            "a ruleset nft will not parse is a rejection whoever asked: {}",
            c.detail,
        );
        assert!(
            !c.needs_capability,
            "a rejection is not an unknown, so it colours the status: {}",
            c.detail,
        );
        assert!(
            c.detail.contains("syntax error"),
            "nft's own words reach the operator: {}",
            c.detail,
        );

        // Privileged and rejected: a real failure, and it keeps the exit code.
        let c = judge_nft_check(
            nft_output(1, "Error: syntax error, unexpected newline"),
            true,
            998,
            "table inet torrentd {}",
        );
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
        assert!(
            c.detail.contains("syntax error"),
            "nft's own words reach the operator: {}",
            c.detail,
        );

        // Privileged and nft still could not reach the kernel: the mask is
        // corroboration, not the discriminator, so what nft reported decides
        // this one too.
        let c = judge_nft_check(
            nft_output(
                1,
                "netlink: Error: cache initialization failed: Operation not permitted",
            ),
            true,
            998,
            "table inet torrentd {}",
        );
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(c.needs_capability);

        // Accepted.
        let c = judge_nft_check(nft_output(0, ""), true, 998, "table inet torrentd {}");
        assert_eq!(c.verdict, Verdict::Pass, "detail: {}", c.detail);
        assert!(
            c.detail.contains("998") && c.detail.contains("boot lists only"),
            "the uid judged and the interface-list caveat are both stated: {}",
            c.detail,
        );

        // `nft` could not be spawned at all: unknown, and *not* capability-
        // bound, because a missing binary is a real gap on a kill-switch host.
        let c = judge_nft_check(
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no nft")),
            false,
            998,
            "table inet torrentd {}",
        );
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(!c.needs_capability, "detail: {}", c.detail);
    }

    #[test]
    fn the_capability_mask_is_read_from_the_kernel_not_guessed() {
        // CAP_NET_ADMIN is bit 12. The two masks below are a real `CapEff` for
        // a process that has it and one that does not.
        let has = "Name:\tnft\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n";
        let hasnt = "Name:\tnft\nUid:\t998\t998\t998\t998\nCapEff:\t0000000000000000\n";
        assert_eq!(cap_eff_has(has, CAP_NET_ADMIN_BIT), Some(true));
        assert_eq!(cap_eff_has(hasnt, CAP_NET_ADMIN_BIT), Some(false));
        // Exactly bit 12 and nothing adjacent.
        assert_eq!(cap_eff_has("CapEff:\t0000000000001000\n", 12), Some(true));
        assert_eq!(cap_eff_has("CapEff:\t0000000000000800\n", 12), Some(false));
        // No line, or one that cannot be parsed, classifies nothing.
        assert_eq!(cap_eff_has("Uid:\t0\t0\t0\t0\n", CAP_NET_ADMIN_BIT), None);
        assert_eq!(
            cap_eff_has("CapEff:\tnot-a-mask\n", CAP_NET_ADMIN_BIT),
            None
        );
    }

    #[test]
    fn a_handshake_probe_refused_for_want_of_a_capability_is_told_apart_from_one_that_failed() {
        let max = Duration::from_secs(180);

        // Refused without CAP_NET_ADMIN on an interface the kernel confirms
        // *is* a WireGuard device: the capability the daemon has and this
        // shell does not. Reported, and not counted against the status.
        let c = judge_handshake("wg-acct-a", Err("refused"), max, false, Some(true));
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(c.needs_capability, "detail: {}", c.detail);
        assert!(
            c.detail.contains("CAP_NET_ADMIN"),
            "the operator is told what would settle it: {}",
            c.detail,
        );
        assert!(
            !c.detail.contains("would run this probe"),
            "the report does not predict what a process it never looked at would do: {}",
            c.detail,
        );

        // Refused *with* the capability is a real gap — `wg` cannot read it —
        // and still colours the status.
        let c = judge_handshake("wg-acct-a", Err("refused"), max, true, Some(true));
        assert_eq!(c.verdict, Verdict::Unknown);
        assert!(!c.needs_capability, "detail: {}", c.detail);

        // A missing `wg` is not a capability problem at any privilege.
        for privileged in [true, false] {
            let c = judge_handshake("wg-acct-a", Err("no_tool"), max, privileged, Some(true));
            assert_eq!(c.verdict, Verdict::Unknown);
            assert!(!c.needs_capability, "detail: {}", c.detail);
        }

        // And the verdicts that do not turn on privilege at all.
        assert_eq!(
            judge_handshake(
                "wg-acct-a",
                Ok(Some(Duration::from_secs(30))),
                max,
                false,
                Some(true),
            )
            .verdict,
            Verdict::Pass,
        );
        assert_eq!(
            judge_handshake(
                "wg-acct-a",
                Ok(Some(Duration::from_secs(300))),
                max,
                true,
                Some(true),
            )
            .verdict,
            Verdict::Fail,
        );
        let c = judge_handshake("wg-acct-a", Ok(None), max, true, Some(true));
        assert_eq!(c.verdict, Verdict::Unknown);
        assert!(
            !c.needs_capability,
            "a tunnel still coming up is not a permission problem"
        );

        // C30's missing arm. The link type could not be read at all, so the
        // refusal has two causes and the report says so rather than picking
        // one.
        let c = judge_handshake("wg-acct-a", Err("refused"), max, false, None);
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(c.needs_capability, "detail: {}", c.detail);
        assert!(
            c.detail.contains("could not be read"),
            "an unread link type is disclosed, not assumed: {}",
            c.detail,
        );
    }

    #[test]
    fn a_wireguard_profile_pointed_at_a_device_that_is_not_wireguard_fails() {
        // F14. `ProbeUnavailable::Refused` means *either* "not a WireGuard
        // interface" *or* "no permission", and privilege is the one axis that
        // cannot separate them — `wg show lo` and `wg show <nonexistent>`
        // return the same refusal on this host. Resolving it by privilege gave
        // a wireguard profile pointed at `lo` — a config `validate_set`
        // accepts, because it constrains only that the interface equals the
        // tunnel config's file stem — an all-clear `0` and a line asserting
        // the daemon would be fine.
        //
        // A capability-free read of the link type settles it, and a
        // misconfigured profile is a `fail` about the configuration.
        let c = judge_handshake(
            "lo",
            Err("refused"),
            Duration::from_secs(180),
            false,
            Some(false),
        );
        assert_eq!(c.verdict, Verdict::Fail, "detail: {}", c.detail);
        assert!(!c.needs_capability, "detail: {}", c.detail);
        assert!(
            c.detail.contains("lo"),
            "the offending interface is named: {}",
            c.detail,
        );

        // And through the whole profile: the verdict has to reach the report
        // and the exit status, not just the judge.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_wireguard_device("wg-acct-a", false)
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(127, 0, 0, 1)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
        let hs = find(&r.checks, "handshake").expect("the handshake line is still reported");
        assert_eq!(hs.verdict, Verdict::Fail, "detail: {}", hs.detail);
        let report = Report {
            host: Vec::new(),
            profiles: vec![r],
        };
        assert_eq!(
            report.exit_code(),
            EXIT_FAILED,
            "a profile whose handshake can never answer is not a clean run",
        );
    }

    #[test]
    fn a_handshake_that_answered_outranks_the_link_type() {
        // A userspace WireGuard tunnel (`wireguard-go`, `wg-quick`'s fallback
        // without the kernel module) is a `tun` device: no DEVTYPE, and
        // `ip -d link` says `tun`. `wg show` still answers for it, and an
        // answer is `wg` itself reading WireGuard behind the interface.
        let max = Duration::from_secs(180);
        let fresh = judge_handshake(
            "wg-acct-a",
            Ok(Some(Duration::from_secs(30))),
            max,
            true,
            Some(false),
        );
        assert_eq!(fresh.verdict, Verdict::Pass, "detail: {}", fresh.detail);
        let stale = judge_handshake(
            "wg-acct-a",
            Ok(Some(Duration::from_secs(300))),
            max,
            true,
            Some(false),
        );
        assert_eq!(stale.verdict, Verdict::Fail, "detail: {}", stale.detail);
        assert!(
            !stale.detail.contains("not a WireGuard device"),
            "a stale handshake is not a misconfigured interface: {}",
            stale.detail,
        );
        let pending = judge_handshake("wg-acct-a", Ok(None), max, true, Some(false));
        assert_eq!(
            pending.verdict,
            Verdict::Unknown,
            "detail: {}",
            pending.detail
        );

        // And through the whole profile, to the exit status.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_wireguard_device("wg-acct-a", false)
            .with_handshake(Ok(Some(Duration::from_secs(30))))
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(127, 0, 0, 1)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
        let hs = find(&r.checks, "handshake").expect("the handshake line is reported");
        assert_eq!(hs.verdict, Verdict::Pass, "detail: {}", hs.detail);
    }

    #[test]
    fn a_tun_link_is_not_read_as_proof_that_the_interface_is_not_wireguard() {
        let kernel = "7: wg-acct-a: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420\n    \
                      link/none  promiscuity 0\n    wireguard addrgenmode none";
        assert_eq!(link_type_is_wireguard(kernel), Some(true));
        let userspace = "7: wg-acct-a: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420\n    \
                         link/none  promiscuity 0\n    tun type tun pi off vnet_hdr off";
        assert_eq!(link_type_is_wireguard(userspace), None);
        let loopback = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    \
                        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00";
        assert_eq!(link_type_is_wireguard(loopback), Some(false));
        // An interface merely *named* after either type answers nothing.
        assert_eq!(
            link_type_is_wireguard("4: tun: <UP> mtu 1500\n    link/ether 00:11:22:33:44:55"),
            Some(false),
        );
        assert_eq!(
            link_type_is_wireguard("4: wireguard: <UP> mtu 1500\n    link/ether 00:11:22:33:44:55"),
            Some(false),
        );
    }

    #[test]
    fn a_profile_s_checks_reach_the_host_only_through_the_check_host() {
        // C1. Decision 32 put `host_checks` behind `CheckHost`; the per-tunnel
        // checks still stat'ed the tunnel config, ran the tool probes and the
        // handshake probe against this machine directly. Every one is scripted
        // here, and the verdicts follow the script.
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_missing_tool("wg")
            .with_handshake(Ok(Some(Duration::from_secs(10_000))))
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(127, 0, 0, 1)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);

        let config = find(&r.checks, "vpn_config").expect("the vpn_config line is reported");
        assert_eq!(config.verdict, Verdict::Pass, "detail: {}", config.detail);
        let wg = find(&r.checks, "wireguard_tools").expect("the wg line is reported");
        assert_eq!(wg.verdict, Verdict::Fail, "detail: {}", wg.detail);
        assert!(
            find(&r.checks, "wg_quick").is_none(),
            "the daemon never runs wg-quick, so its presence is not checked",
        );
        let hs = find(&r.checks, "handshake").expect("the handshake line is reported");
        assert_eq!(hs.verdict, Verdict::Fail, "detail: {}", hs.detail);
        assert!(hs.detail.contains("10000s"), "detail: {}", hs.detail);

        let events = host.events();
        for expected in [
            "profile_metadata /etc/wireguard/wg-acct-a.conf",
            "tool_available wg --version",
            "handshake_age wg-acct-a",
            "route_probe wg-acct-a 127.0.0.1 1.1.1.1",
        ] {
            assert!(
                events.iter().any(|e| e == expected),
                "{expected} went through the seam: {events:?}",
            );
        }
        assert!(
            !events.iter().any(|e| e.contains("wg-quick")),
            "nothing asks for wg-quick: {events:?}",
        );
    }

    /// The acceptance test for sharing the ruleset: the script `vpn check`
    /// dry-runs is byte-for-byte the script `killswitch::enable` hands to
    /// `nft -f` for the same uid, tunnels and listen ports. At a9eb5a1 the
    /// check rendered the bare table — no transport exemption, no replace —
    /// which is not what boot installs.
    #[test]
    fn the_kill_switch_ruleset_renders_identically_in_vpn_check_and_at_boot() {
        let cfg = cfg_with_two_profiles();
        let host = FakeHost::new()
            .with_listen_port("wg-acct-a", 51820)
            .with_listen_port("wg-acct-b", 40001);
        host_checks(&cfg, Some(998), None, &host);
        let dry_run: Vec<String> = host
            .events()
            .into_iter()
            .filter_map(|e| e.strip_prefix("nft_check ").map(str::to_string))
            .collect();
        assert_eq!(dry_run.len(), 1, "{dry_run:?}");

        let installed = std::cell::RefCell::new(String::new());
        let tunnels: Vec<String> = cfg
            .profile
            .iter()
            .filter_map(|p| p.vpn_interface().map(str::to_string))
            .collect();
        vpn::killswitch::enable_for_uid(
            998,
            &tunnels,
            |iface| {
                Ok(match iface {
                    "wg-acct-a" => 51820,
                    _ => 40001,
                })
            },
            |script| {
                *installed.borrow_mut() = script.to_string();
                Ok(())
            },
        )
        .expect("the boot path installs");
        assert_eq!(dry_run[0], *installed.borrow());
    }

    /// The route the monitor probes is reported, and a route that leaves by
    /// another device fails both the route line and the monitor's verdict.
    #[test]
    fn a_route_that_does_not_leave_by_the_tunnel_fails_the_route_and_the_health_verdict() {
        let cfg = cfg_with_profile("");
        let host = FakeHost::new()
            .with_handshake(Ok(Some(Duration::from_secs(5))))
            .with_route(Ok(vpn::route::RouteProbe::Elsewhere(
                "leaves by eth0".to_string(),
            )))
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &host);
        let route = find(&r.checks, "route").expect("the route line is reported");
        assert_eq!(route.verdict, Verdict::Fail, "detail: {}", route.detail);
        let health = find(&r.checks, "health").expect("the monitor's verdict is reported");
        assert_eq!(health.verdict, Verdict::Fail, "detail: {}", health.detail);
        assert!(
            health.detail.contains("route_mismatch"),
            "{}",
            health.detail
        );

        let healthy = FakeHost::new()
            .with_handshake(Ok(Some(Duration::from_secs(5))))
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, None, &healthy);
        let health = find(&r.checks, "health").expect("the monitor's verdict is reported");
        assert_eq!(health.verdict, Verdict::Pass, "detail: {}", health.detail);
    }

    /// `--egress` asserts the route before it trusts a reply: a round trip
    /// that went out of the physical interface is not evidence the tunnel
    /// carries traffic, so it is not attempted.
    #[test]
    fn egress_asserts_the_route_to_its_destination_before_the_round_trip() {
        let cfg = cfg_with_profile("");
        let dest: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let host = FakeHost::new()
            .with_route(Ok(vpn::route::RouteProbe::Elsewhere(
                "leaves by eth0".to_string(),
            )))
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, Some(dest), &host);
        let route = find(&r.checks, "egress_route").expect("the egress route is asserted");
        assert_eq!(route.verdict, Verdict::Fail, "detail: {}", route.detail);
        let egress = find(&r.checks, "egress").expect("the egress line is still reported");
        assert_eq!(egress.verdict, Verdict::Skip, "detail: {}", egress.detail);
        assert!(
            host.events()
                .iter()
                .any(|e| e == "route_probe wg-acct-a 10.2.0.2 192.0.2.53"),
            "the route is asked for the probe's own destination: {:?}",
            host.events(),
        );
    }

    /// A route probe that could not run says nothing about where the route
    /// goes, and the skipped round trip says so instead of claiming the route
    /// does not leave by the tunnel.
    #[test]
    fn an_egress_route_that_could_not_be_asked_is_not_called_a_wrong_route() {
        let cfg = cfg_with_profile("");
        let dest: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let host = FakeHost::new()
            .with_route(Err(vpn::route::RouteProbeUnavailable::NoTool))
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, Some(dest), &host);
        let route = find(&r.checks, "egress_route").expect("the egress route line");
        assert_eq!(route.verdict, Verdict::Unknown, "detail: {}", route.detail);
        let egress = find(&r.checks, "egress").expect("the egress line");
        assert_eq!(egress.verdict, Verdict::Skip, "detail: {}", egress.detail);
        assert!(
            egress.detail.contains("could not be asked")
                && !egress.detail.contains("does not leave by"),
            "detail: {}",
            egress.detail,
        );
    }

    /// An IPv6 `--egress` destination from an IPv4 tunnel address is a family
    /// mismatch, and is reported as one. `ip route get <v6> from <v4>` fails,
    /// and that failure was reported as a missing or outranked tunnel rule.
    #[test]
    fn an_egress_destination_of_the_other_family_is_reported_as_such() {
        let cfg = cfg_with_profile("");
        let dest: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
        let host = FakeHost::new()
            .with_route(Ok(vpn::route::RouteProbe::Elsewhere(
                "RTNETLINK answers: Invalid argument".to_string(),
            )))
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        let r = profile_checks(&cfg, &cfg.profile[0], false, Some(dest), &host);
        let route = find(&r.checks, "egress_route").expect("the egress route line");
        assert_eq!(route.verdict, Verdict::Fail, "detail: {}", route.detail);
        assert!(
            route.detail.contains("address family") && !route.detail.contains("outranked"),
            "detail: {}",
            route.detail,
        );
        assert!(
            !host.events().iter().any(|e| e.ends_with("2001:db8::53")),
            "no route is asked across families: {:?}",
            host.events(),
        );
        let egress = find(&r.checks, "egress").expect("the egress line");
        assert_eq!(egress.verdict, Verdict::Skip, "detail: {}", egress.detail);
    }
}
