//! `torrentd vpn check` — verify a slot's VPN configuration against the real
//! host, with no libtorrent session, no torrents and no tracker contact.
//!
//! Every other way of exercising this code needs a fully configured daemon: a
//! pool, a torrent library, real payload, and an operator watching `/slots` for
//! thirty seconds to see whether the health monitor fences anything. That
//! conflates two independent things — "does my VPN configuration work" and
//! "does my seeding setup work" — and it is the first of those that has to be
//! true before the second is worth testing.
//!
//! Host prerequisites run first, then each slot's checks in the order `boot`
//! performs them. The host block is deliberately *not* in boot's order: boot
//! installs the kill switch last, after every slot is up, and burying a
//! missing `iproute2` or `nft` behind a thirty-second tunnel bring-up would
//! cost an operator the thing this command is for.
//!
//! Observe-only by default, stated precisely: the default path makes **no
//! host change** and **deletes nothing**. It reads interfaces, reads `wg`
//! output, reads sysctls, and — for a NAT-PMP slot — asks the gateway for a
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
use torrentd_engine::SlotConfig;
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
    /// Correctly configured to not apply — a NAT-PMP check on a static slot,
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
    /// Set on an `Unknown` that could not be performed **because this
    /// invocation lacks a capability**, as distinct from one that could not be
    /// performed at all.
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
}

#[derive(Debug, Serialize)]
pub struct SlotReport {
    pub slot_id: String,
    pub vpn_type: &'static str,
    pub checks: Vec<Check>,
}

impl SlotReport {
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Fail)
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub host: Vec<Check>,
    pub slots: Vec<SlotReport>,
}

/// Everything was established, and everything established was good.
pub const EXIT_OK: i32 = 0;
/// At least one check failed.
pub const EXIT_FAILED: i32 = 1;
/// Nothing failed, but at least one check could not be performed.
pub const EXIT_UNKNOWN: i32 = 2;

impl Report {
    pub fn failed(&self) -> bool {
        self.host.iter().any(|c| c.verdict == Verdict::Fail)
            || self.slots.iter().any(SlotReport::failed)
    }

    fn checks(&self) -> impl Iterator<Item = &Check> {
        self.host
            .iter()
            .chain(self.slots.iter().flat_map(|s| &s.checks))
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
    /// `Skip` is not `Unknown`: a NAT-PMP check on a static slot did not fail
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
    std::process::Command::new(bin)
        .arg(probe_arg)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The host-touching operations a slot's checks perform, behind a trait so the
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

    /// The address the daemon would bind every socket in this slot to.
    fn first_ipv4(&self, iface: &str) -> std::io::Result<Ipv4Addr>;

    /// The tunnel manager for a slot's VPN type.
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
        // The kernel's own list. `ip link show` would answer the same question
        // through a subprocess whose absence we already report separately.
        Path::new("/sys/class/net").join(iface).exists()
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
        return Check::unknown(
            "kill_switch_uid",
            format!(
                "asked about uid {subject}, but {who}, so whether that uid is the one the \
                 daemon runs as was not established. The ruleset below is still rendered and \
                 dry-run for uid {subject}"
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
/// `privileged` is whether this process holds `CAP_NET_ADMIN`; see
/// [`has_cap_net_admin`]. Without it `nft` cannot initialise its netlink cache
/// and so establishes nothing about the ruleset, which is `unknown` bounded by
/// a capability rather than a rejection. The stderr substrings stay as a
/// fallback for the case where the capability mask could not be read.
fn judge_nft_check(
    outcome: std::io::Result<std::process::Output>,
    privileged: bool,
    uid: u32,
    ruleset: &str,
) -> Check {
    // Boot builds this interface list from the slots whose tunnel actually
    // came up, not from every configured slot. Without a live registry this
    // check cannot know that set; naming the discrepancy is honest, and
    // guessing at it would not be.
    let caveat = "interfaces listed are the configured slots; boot lists only the slots \
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
            let refused_for_want_of_capability = !privileged
                || err.contains("Operation not permitted")
                || err.contains("Permission denied");
            if refused_for_want_of_capability {
                Check::unknown_without_capability(
                    "kill_switch_ruleset",
                    format!(
                        "`nft --check` needs CAP_NET_ADMIN and did not get it ({err}), so the \
                         ruleset for uid {uid} was not validated. {caveat}"
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
/// latest-handshakes` needs: refused *without* it establishes nothing about
/// this host and is bounded by the capability, while refused *with* it is a
/// real gap — the interface is not a WireGuard interface, or `wg` cannot read
/// it for some other reason.
fn judge_handshake(
    probe: Result<Option<Duration>, &str>,
    max: Duration,
    privileged: bool,
) -> Check {
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
                 slot",
                age.as_secs(),
                max.as_secs()
            ),
        ),
        Ok(None) => Check::unknown(
            "handshake",
            "no peer has handshaked yet; the tunnel may still be coming up",
        ),
        Err("refused") if !privileged => Check::unknown_without_capability(
            "handshake",
            "`wg show <iface> latest-handshakes` was refused and this process does not hold \
             CAP_NET_ADMIN, which it needs; the daemon has it and would run this probe. Run \
             as the daemon's user with that capability to settle it",
        ),
        Err(why) => Check::unknown(
            "handshake",
            format!("probe unavailable ({why}); the daemon would run on IP presence alone"),
        ),
    }
}

/// Dry-run a ruleset through `nft --check --file -`: nftables parses it and
/// validates it against the live kernel, and installs nothing.
fn nft_check(ruleset: &str) -> std::io::Result<std::process::Output> {
    use std::io::Write;
    let mut child = std::process::Command::new("nft")
        .args(["--check", "--file", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("nft stdin unavailable"))?
        .write_all(ruleset.as_bytes())?;
    child.wait_with_output()
}

/// Checks that are about the host, not any one slot.
///
/// `iproute2` and `nftables` are here because they genuinely are host-wide: a
/// missing binary is missing for every slot, and neither answer changes with
/// `--slot`. `rp_filter` is **not** here, even though it reads a sysctl:
/// `conf/<iface>/rp_filter` is per slot by construction, so judging it here
/// scoped a check to interfaces the operator had excluded — a run narrowed to
/// one healthy slot exited 2 because of another slot's interface — and ran it
/// before `--bring-up` had raised anything, so the sysctl for the interface
/// the command was about to create did not exist yet. It also put two checks
/// named `rp_filter` in the same `host` array, which the `--json` contract
/// cannot express to a consumer keying by name. It lives in
/// [`slot_checks`] instead.
fn host_checks(cfg: &Config, as_uid: Option<u32>) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(if tool_available("ip", "-V") {
        Check::pass("iproute2", "`ip` is available")
    } else {
        Check::fail(
            "iproute2",
            "`ip` is not executable; every tunnel IP lookup in the daemon shells out to it",
        )
    });

    if cfg.network_kill_switch {
        out.push(if vpn::killswitch::nft_available() {
            Check::pass("nftables", "`nft` is available")
        } else {
            Check::fail(
                "nftables",
                "network_kill_switch = true but `nft` is not executable",
            )
        });

        let invoker = vpn::killswitch::current_uid().map_err(|e| e.to_string());
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
                let tunnels: Vec<String> =
                    cfg.slot.iter().map(|s| s.vpn_interface.clone()).collect();
                let ruleset = vpn::killswitch::render_ruleset(uid, &tunnels);
                judge_nft_check(nft_check(&ruleset), has_cap_net_admin(), uid, &ruleset)
            }
        });
    } else {
        out.push(Check::skip("kill_switch", "network_kill_switch = false"));
    }

    out
}

/// Prove that a socket **bound to the tunnel address** can send and receive.
///
/// This is the check that distinguishes a tunnel which exists from a tunnel
/// which works, and it is the same question the daemon asks implicitly of
/// every slot: `outgoing_interfaces` is pinned to the tunnel IP, so if traffic
/// cannot leave from that source address the slot connects to no peers and
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
                     in this slot would fail the same way."
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

fn slot_checks(
    cfg: &Config,
    slot: &SlotConfig,
    bring_up: bool,
    egress: Option<SocketAddr>,
    host: &dyn CheckHost,
) -> SlotReport {
    let mut checks = Vec::new();
    let iface = slot.vpn_interface.as_str();

    // 1. The profile the daemon would hand to wg-quick / openvpn.
    checks.push(match std::fs::metadata(&slot.vpn_profile) {
        Ok(_) => Check::pass(
            "profile",
            format!("{} is readable", slot.vpn_profile.display()),
        ),
        Err(e) => Check::fail("profile", format!("{}: {e}", slot.vpn_profile.display())),
    });

    // 2. The tools that slot's type needs.
    match slot.vpn_type {
        VpnType::Wireguard => {
            checks.push(if tool_available("wg", "--version") {
                Check::pass("wireguard_tools", "`wg` is available")
            } else {
                Check::fail(
                    "wireguard_tools",
                    "`wg` is not executable: the handshake half of the health monitor \
                     cannot run, and the daemon would fall back to IP presence alone",
                )
            });
            checks.push(if tool_available("wg-quick", "--help") {
                Check::pass("wg_quick", "`wg-quick` is available")
            } else {
                Check::unknown("wg_quick", "`wg-quick --help` did not exit cleanly")
            });
        }
        VpnType::Openvpn => {
            checks.push(if tool_available("openvpn", "--version") {
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
    //    adoption path in `vpn::wireguard` then matches the profile's public
    //    key and returns the address anyway. So a running daemon's tunnel used
    //    to be reported as "came up" having been created by nothing, and the
    //    unconditional teardown below then ran the same `wg-quick down` the
    //    daemon's own shutdown uses. The slot went down, `vpn_monitor` fenced
    //    it within 30s, and nothing re-raised it: a diagnostic command took a
    //    live seeding slot out until someone restarted the daemon.
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
    let manager = host.manager(slot.vpn_type, &cfg.state_dir());
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
            let outcome = manager.bring_up(&slot.vpn_profile());
            raised_here = host.interface_exists(iface);
            match outcome {
                Ok(ip) => {
                    checks.push(Check::pass("bring_up", format!("tunnel came up on {ip}")));
                }
                Err(e) => {
                    let aftermath = if raised_here {
                        format!(
                            "; {iface} is there even so, so this command raised it and is \
                             lowering it again"
                        )
                    } else {
                        format!(
                            "; no {iface} appeared, but a manager that daemonises (openvpn \
                             forks and exits 0 before its own address poll) may have left a \
                             process running that this command cannot see to stop"
                        )
                    };
                    checks.push(Check::fail("bring_up", format!("{e}{aftermath}")));
                    if raised_here {
                        checks.push(teardown(host, manager.as_ref(), iface));
                    }
                    return SlotReport {
                        slot_id: slot.id.as_str().to_string(),
                        vpn_type: vpn_type_str(slot.vpn_type),
                        checks,
                    };
                }
            }
        }
    }

    // 3b. rp_filter, for this slot's interface, after the bring-up step.
    //
    //     Strict reverse-path filtering drops the replies to a source-bound
    //     socket, so a multi-slot daemon looks like a tunnel that connects and
    //     carries no traffic. docs/running.md calls for 2 (loose). Judged per
    //     interface, because that is how the kernel judges it — and therefore
    //     judged *here* rather than in `host_checks`, because a per-slot
    //     property in the unscoped host block ignores `--slot`, and because
    //     `/proc/sys/net/ipv4/conf/<iface>/rp_filter` does not exist until the
    //     interface does. Reading it before `--bring-up` raised the tunnel
    //     reported `unknown` for the one interface the run was about.
    let all = host.read_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter");
    let per = host.read_sysctl(&format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter"));
    checks.push(judge_rp_filter(iface, all.as_deref(), per.as_deref()));

    // 4. The address the daemon would bind every socket in this slot to.
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

    // 5. Handshake liveness — the same probe and the same threshold the health
    //    monitor applies every 30 seconds.
    match slot.vpn_type {
        VpnType::Wireguard => {
            let max = Duration::from_secs(cfg.vpn_handshake_max_age_secs);
            let probe = vpn::wireguard_handshake_age(iface).map_err(|why| why.as_str());
            checks.push(judge_handshake(probe, max, has_cap_net_admin()));
        }
        VpnType::Openvpn => {
            checks.push(Check::skip(
                "handshake",
                "no cheap liveness probe for openvpn",
            ));
        }
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
    match slot.port_forward {
        PortForwardMode::Static => {
            checks.push(Check::skip(
                "port_forward",
                format!("static listen_port {:?}", slot.listen_port),
            ));
        }
        PortForwardMode::Natpmp => match (
            tunnel_ip,
            slot.port_forward_gateway_or_default().parse::<IpAddr>(),
        ) {
            (Some(bind_ip), Ok(gateway)) => {
                let lease = crate::port_forward_monitor::LEASE_SECS;
                let req = PortMapRequest {
                    gateway,
                    bind_ip,
                    internal_port: 0,
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
    if let Some(dest) = egress {
        checks.push(match tunnel_ip {
            Some(src) => egress_probe(src, dest),
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

    SlotReport {
        slot_id: slot.id.as_str().to_string(),
        vpn_type: vpn_type_str(slot.vpn_type),
        checks,
    }
}

/// Lower an interface this command raised, and report whether it went down.
///
/// `VpnManager::bring_down` returns `()` and, per its own contract, swallows
/// its errors to the log — so reporting a pass straight after calling it
/// reported the one host mutation this command advertises without ever looking
/// at it. `wg-quick down` can fail: the interface is busy, the profile moved,
/// `wg-quick` is not on this uid's PATH. Look at the address instead, and say
/// plainly when the host has been left changed.
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
    if cfg.slot.is_empty() {
        anyhow::bail!(
            "no [[slot]] entries are configured, so there is no VPN to check. \
             Single-session mode does not use a tunnel."
        );
    }
    let selected: Vec<&SlotConfig> = cfg
        .slot
        .iter()
        .filter(|s| only.is_none_or(|id| s.id.as_str() == id))
        .collect();
    if selected.is_empty() {
        anyhow::bail!("no slot matches {:?}", only.unwrap_or_default());
    }

    let host = RealHost;
    let report = Report {
        host: host_checks(cfg, as_uid),
        slots: selected
            .into_iter()
            .map(|s| slot_checks(cfg, s, bring_up, egress, &host))
            .collect(),
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
/// `?cap` rather than `?   ` for an `Unknown` this invocation could not settle
/// for want of a capability: it is the one `Unknown` that does not colour the
/// exit status, so the rendering has to distinguish it too, or a reader
/// reconciling a `0` against a column of `?` has nothing to go on.
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
    for s in &report.slots {
        println!("\nslot {} ({})", s.slot_id, s.vpn_type);
        for c in &s.checks {
            println!("  [{}] {:<20} {}", symbol(c), c.name, c.detail);
        }
    }
    if report.capability_bound() {
        println!(
            "\n[?cap] marks a check this invocation could not perform for want of \
             CAP_NET_ADMIN. It is not counted against the exit status — the daemon has the \
             capability and this shell does not — so the status says nothing about it either \
             way."
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
            }
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
            profile: &torrentd_engine::VpnProfile,
        ) -> Result<IpAddr, torrentd_engine::VpnError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("bring_up {}", profile.interface));
            self.inner.bring_up(profile)
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

    /// A multi-slot config with one WireGuard slot, built from TOML so a
    /// required field added to `SlotConfig` breaks this rather than letting it
    /// exercise a shape the daemon never parses.
    fn cfg_with_slot(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"
listen_interfaces = "0.0.0.0:6881"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"

[[slot]]
id                   = "acct_a"
vpn_profile          = "/etc/wireguard/wg-acct-a.conf"
vpn_type             = "wireguard"
vpn_interface        = "wg-acct-a"
listen_port          = 6881
peer_fingerprint_hex = "a1b2c3d4e5f60718"
user_agent           = "qBittorrent/5.0.3"
resume_dir           = "/tmp/torrentd-test/state/resume/acct_a"
torrent_dir          = "/tmp/torrentd-test/torrents/acct_a"
{extra}
"#
        ))
        .expect("test config parses")
    }

    fn find<'a>(checks: &'a [Check], name: &str) -> Option<&'a Check> {
        checks.iter().find(|c| c.name == name)
    }

    #[test]
    fn bring_up_never_lowers_an_interface_it_did_not_raise() {
        // F1. The daemon is up and seeding on wg-acct-a. `--bring-up` finds
        // the interface already there, so it must adopt it: report the
        // bring-up as `skip`, run the remaining checks, and issue no teardown
        // at all. A `bring_down` recorded here is a live slot fenced until
        // someone restarts the daemon.
        let cfg = cfg_with_slot("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

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
        // Adoption is not an early return: the rest of the slot is still
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
        let cfg = cfg_with_slot("");
        let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", None),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

        assert_eq!(host.vpn.bring_up_calls(), vec!["wg-acct-a"]);
        assert_eq!(host.vpn.bring_down_calls(), vec!["wg-acct-a"]);
        assert_eq!(
            find(&r.checks, "bring_up").map(|c| c.verdict),
            Some(Verdict::Pass),
        );
    }

    #[test]
    fn without_bring_up_no_tunnel_is_touched_either_way() {
        let cfg = cfg_with_slot("");
        let host = FakeHost::new()
            .with_existing("wg-acct-a")
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);

        let r = slot_checks(&cfg, &cfg.slot[0], false, None, &host);

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
        let cfg = cfg_with_slot("");
        let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

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
        let cfg = cfg_with_slot("");
        let host = FakeHost::new().with_exists_seq([false, true]).with_addrs([
            ("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2))),
            ("wg-acct-a", None),
        ]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

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
        let cfg = cfg_with_slot("port_forward = \"natpmp\"\nport_forward_gateway = \"10.2.0.1\"");
        let host = FakeHost::new().with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        host.fwd.push_ok(51413);

        let r = slot_checks(&cfg, &cfg.slot[0], false, None, &host);

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
    fn a_natpmp_slot_with_no_tunnel_address_negotiates_nothing() {
        // The gateway is only reachable through the tunnel, so with no tunnel
        // address there is nothing to negotiate from and nothing to report but
        // a skip. Checked here because it is the arm that keeps the mapping
        // call off a host that has no tunnel at all.
        let cfg = cfg_with_slot("port_forward = \"natpmp\"");
        let host = FakeHost::new();

        let r = slot_checks(&cfg, &cfg.slot[0], false, None, &host);

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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
        // Every socket in the slot is source-bound to the tunnel address, so
        // an address that cannot be bound is the whole slot failing, not just
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
        // key in the JSON when the slot had no tunnel address — a check the
        // operator explicitly asked for, silently absent.
        let cfg = cfg_with_slot("");
        let host = FakeHost::new();

        let r = slot_checks(
            &cfg,
            &cfg.slot[0],
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
        let cfg = cfg_with_slot("");
        let host = FakeHost::new();
        let r = slot_checks(&cfg, &cfg.slot[0], false, None, &host);
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
            slots: vec![],
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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
    fn an_unknown_inside_a_slot_alone_is_enough_to_colour_the_status() {
        // The host half can be entirely clean and the slot half entirely
        // unestablished; `Report::failed` only ever looked at `Fail`, so the
        // slot half has to be reached explicitly.
        let r = Report {
            host: vec![Check::pass("iproute2", "")],
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
                vpn_type: "wireguard",
                checks: vec![Check::fail("tunnel_ip", "")],
            }],
        };
        assert_eq!(r.exit_code(), EXIT_FAILED);
    }

    #[test]
    fn a_skip_is_not_an_unknown_and_exits_clean() {
        // A NAT-PMP check on a static slot did not fail to happen; it
        // correctly did not apply. Colouring the status for it would make
        // every static deployment exit 2 forever.
        let r = Report {
            host: vec![Check::pass("iproute2", ""), Check::skip("kill_switch", "")],
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
            slots: vec![],
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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
                vpn_type: "openvpn",
                checks: vec![Check::skip("b", ""), Check::unknown("c", "")],
            }],
        };
        assert!(!r.failed());
    }

    #[test]
    fn the_json_report_keeps_the_shape_its_consumers_parse() {
        // C7/C8. `--json` is a contract: the four verdicts are lowercase
        // strings, and the report is `host` plus `slots`, each slot carrying
        // `slot_id`, `vpn_type` and `checks` of `name`/`verdict`/`detail`.
        // Nothing here is enforced by the type system — `#[serde(rename_all)]`
        // is one attribute away from renaming every verdict at once.
        let r = Report {
            host: vec![Check::pass("iproute2", "`ip` is available")],
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
        assert_eq!(v["slots"][0]["slot_id"], "acct_a");
        assert_eq!(v["slots"][0]["vpn_type"], "wireguard");
        assert_eq!(v["slots"][0]["checks"][0]["verdict"], "fail");
        assert_eq!(v["slots"][0]["checks"][1]["verdict"], "skip");
        assert_eq!(v["slots"][0]["checks"][2]["verdict"], "unknown");
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
    fn a_single_session_config_is_refused_with_an_explanation() {
        // C38. Single-session mode uses no tunnel, so there is nothing to
        // check and an empty report would read as a clean bill of health.
        let cfg: Config = toml::from_str(
            r#"
listen_interfaces = "0.0.0.0:6881"
default_save_path = "/tmp/torrentd-test/data"
resume_dir = "/tmp/torrentd-test/state/resume"
torrent_dir = "/tmp/torrentd-test/torrents"
http_listen = "127.0.0.1:8080"
"#,
        )
        .unwrap();

        let e = check(&cfg, None, false, false, None, None).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("[[slot]]"), "got {msg}");
        assert!(msg.contains("Single-session"), "got {msg}");
    }

    #[test]
    fn a_slot_filter_that_matches_nothing_is_refused_rather_than_reported_clean() {
        // C39. `--slot typo` used to be indistinguishable from "every slot
        // passed": no slots selected, no failures, exit 0.
        let cfg = cfg_with_slot("");
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
    fn rp_filter_is_judged_for_the_slot_and_only_after_it_has_been_raised() {
        // F4, reopened. `conf/<iface>/rp_filter` is per slot by construction,
        // so judging it in the unscoped host block ignored `--slot` — a run
        // narrowed to one healthy slot exited 2 because of an interface the
        // operator had excluded — and ran it before `--bring-up` had raised
        // anything, so the sysctl for the interface the command was about to
        // create did not exist and the check reported `unknown` about the one
        // interface the run was for.
        //
        // The kernel is modelled honestly here: the per-interface sysctl is
        // scripted, and the assertion is on the *order* of the read against
        // the raise, so moving the read back into `host_checks` fails this
        // rather than merely relocating a passing test.
        let cfg = cfg_with_slot("");
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

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

        let rp = find(&r.checks, "rp_filter").expect("the slot carries its own rp_filter line");
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
    fn the_host_block_carries_no_per_slot_check_and_no_duplicate_name() {
        // The other half of the same finding: a per-slot sysctl in the
        // unscoped host block emitted one `Check` per configured interface,
        // all named `rp_filter`, so `host[]` in the `--json` contract carried
        // duplicate `name` values and a consumer keying by name silently kept
        // one of them.
        let cfg = cfg_with_slot("");
        let host = host_checks(&cfg, None);
        assert!(
            find(&host, "rp_filter").is_none(),
            "rp_filter is per slot and belongs to the slot: {:?}",
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
        let cfg = cfg_with_slot("");
        let host = FakeHost::new()
            .with_exists_seq([false, true])
            .with_addrs([("wg-acct-a", None)]);
        // No `set_ip`, so MockVpn::bring_up returns BringUpTimeout — the exact
        // error both real managers produce after they have already started
        // something.

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

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
        // no teardown is issued. The report still says what the command was
        // unable to establish, because a manager that daemonises can have left
        // a process behind that no interface probe can see.
        let cfg = cfg_with_slot("");
        let host = FakeHost::new().with_exists_seq([false, false]);

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

        assert!(host.vpn.bring_down_calls().is_empty());
        assert!(find(&r.checks, "bring_down").is_none());
        let bu = find(&r.checks, "bring_up").expect("a bring_up line");
        assert_eq!(bu.verdict, Verdict::Fail, "detail: {}", bu.detail);
        assert!(
            bu.detail.contains("may have left a process running"),
            "the one thing it cannot observe is named: {}",
            bu.detail,
        );
    }

    #[test]
    fn a_successful_bring_up_that_adopted_rather_than_created_is_not_lowered() {
        // F1(B)'s shape from the other side: `Ok` is not evidence of a raise,
        // because `wg-quick up` refuses an interface that already exists and
        // the adoption path returns `Ok(ip)` for it. The re-probe is what
        // decides, so an interface that is *not* there after the call is not
        // lowered on the strength of an `Ok`.
        let cfg = cfg_with_slot("");
        let host = FakeHost::new()
            .with_exists_seq([false, false])
            .with_addrs([("wg-acct-a", Some(Ipv4Addr::new(10, 2, 0, 2)))]);
        host.vpn
            .set_ip("wg-acct-a", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));

        let r = slot_checks(&cfg, &cfg.slot[0], true, None, &host);

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
            slots: vec![SlotReport {
                slot_id: "acct_a".into(),
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
            slots: vec![],
        };
        assert_eq!(r.exit_code(), EXIT_UNKNOWN);

        // And a real failure still outranks both.
        let r = Report {
            host: vec![
                Check::unknown_without_capability("handshake", ""),
                Check::fail("iproute2", ""),
            ],
            slots: vec![],
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
    fn nft_check_is_classified_by_the_capability_before_the_error_text() {
        // F13. The difference between exit 1 and exit 2 rested on nftables'
        // error wording: `err.contains("Operation not permitted")`. A build,
        // locale or version whose message differs reported "`nft --check`
        // rejected the ruleset boot would install" — asserting the boot would
        // abort when nothing about the ruleset had been established — and the
        // converse downgraded a genuine rejection whose text happened to carry
        // the phrase.
        //
        // Unprivileged, with a message this code has never seen: still
        // capability-bound, because without CAP_NET_ADMIN `nft` cannot reach
        // the kernel to validate anything.
        let c = judge_nft_check(
            nft_output(1, "netlink: konnte Cache nicht initialisieren"),
            false,
            998,
            "table inet torrentd {}",
        );
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(c.needs_capability, "detail: {}", c.detail);

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

        // The substring stays as a fallback for the case where the capability
        // mask could not be read at all and `privileged` defaulted to true.
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

        // Refused without CAP_NET_ADMIN: the capability the daemon has and
        // this shell does not. Reported, and not counted against the status.
        let c = judge_handshake(Err("refused"), max, false);
        assert_eq!(c.verdict, Verdict::Unknown, "detail: {}", c.detail);
        assert!(c.needs_capability, "detail: {}", c.detail);
        assert!(
            c.detail.contains("CAP_NET_ADMIN"),
            "the operator is told what would settle it: {}",
            c.detail,
        );

        // Refused *with* the capability is a real gap — not a WireGuard
        // interface, or `wg` cannot read it — and still colours the status.
        let c = judge_handshake(Err("refused"), max, true);
        assert_eq!(c.verdict, Verdict::Unknown);
        assert!(!c.needs_capability, "detail: {}", c.detail);

        // A missing `wg` is not a capability problem at any privilege.
        for privileged in [true, false] {
            let c = judge_handshake(Err("no_tool"), max, privileged);
            assert_eq!(c.verdict, Verdict::Unknown);
            assert!(!c.needs_capability, "detail: {}", c.detail);
        }

        // And the verdicts that do not turn on privilege at all.
        assert_eq!(
            judge_handshake(Ok(Some(Duration::from_secs(30))), max, false).verdict,
            Verdict::Pass,
        );
        assert_eq!(
            judge_handshake(Ok(Some(Duration::from_secs(300))), max, true).verdict,
            Verdict::Fail,
        );
        let c = judge_handshake(Ok(None), max, true);
        assert_eq!(c.verdict, Verdict::Unknown);
        assert!(
            !c.needs_capability,
            "a tunnel still coming up is not a permission problem"
        );
    }
}
