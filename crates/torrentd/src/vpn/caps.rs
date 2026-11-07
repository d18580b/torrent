//! This process's capabilities, and how `CAP_NET_ADMIN` reaches the tools the
//! VPN subsystem runs.
//!
//! The one reader of `/proc/self/status`'s capability sets. `net-cleanup`,
//! `vpn check`, `--check-config` and the daemon's boot all ask it.
//!
//! Every `ip`, `wg`, `nft` and `openvpn` the daemon runs needs
//! `CAP_NET_ADMIN`, and an `execve` keeps a capability only through the
//! ambient set (or a file capability on the tool, which no distribution
//! ships). A daemon can hold `CAP_NET_ADMIN` in one of two ways:
//!
//! - **systemd's `AmbientCapabilities=CAP_NET_ADMIN`.** The capability is
//!   ambient from the start, every child inherits it, and nothing here changes
//!   anything.
//! - **A file capability on the binary** (`cap_net_admin+p`, as
//!   `deploy/Containerfile` sets it), granted where the container's bounding
//!   set holds `NET_ADMIN`. `execve` clears the ambient set on a binary with a
//!   file capability, so the capability is permitted and no more.
//!   [`prepare_children`] raises it to effective and inheritable once, at
//!   boot, before any thread starts, and arms [`raise_ambient_in_child`],
//!   which `vpn::exec` installs as the `pre_exec` hook of every tool it runs.
//!   The ambient raise happens in the forked child only, so every tool
//!   `vpn::exec` runs gets the capability (`ip`, `wg`, `nft`, `openvpn`, and
//!   the `kill` that signals an `openvpn`, which does not need it) and no
//!   other child of the daemon does.
//!
//! Capability sets are per thread, and a thread starts with its creator's:
//! [`prepare_children`] runs on the main thread before the runtime, the
//! logger or libtorrent start one, so every later thread carries what it set.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// `CAP_NET_ADMIN`'s bit in the capability sets (`linux/capability.h`).
pub const CAP_NET_ADMIN: u32 = 12;

/// One process's four capability sets, as `/proc/<pid>/status` prints them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapSets {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub ambient: u64,
}

impl CapSets {
    /// The sets in a `/proc/<pid>/status` body, or `None` where a line is
    /// missing or not a hex mask.
    pub fn parse(status: &str) -> Option<Self> {
        let mask = |prefix: &str| -> Option<u64> {
            let hex = status.lines().find_map(|l| l.strip_prefix(prefix))?.trim();
            u64::from_str_radix(hex, 16).ok()
        };
        Some(Self {
            inheritable: mask("CapInh:")?,
            permitted: mask("CapPrm:")?,
            effective: mask("CapEff:")?,
            ambient: mask("CapAmb:")?,
        })
    }

    /// This process's sets, or `None` where `/proc/self/status` could not be
    /// read or parsed.
    ///
    /// The file reports the thread that reads it (the thread-group leader's
    /// view under `/proc/self`), which is the same as every thread's here:
    /// nothing changes them after [`prepare_children`].
    pub fn current() -> Option<Self> {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| Self::parse(&s))
    }

    pub fn permits(&self, cap: u32) -> bool {
        self.permitted & bit(cap) != 0
    }

    pub fn has_effective(&self, cap: u32) -> bool {
        self.effective & bit(cap) != 0
    }

    pub fn has_ambient(&self, cap: u32) -> bool {
        self.ambient & bit(cap) != 0
    }
}

fn bit(cap: u32) -> u64 {
    1u64 << cap
}

/// Whether this process holds `CAP_NET_ADMIN` effective, or `None` where its
/// status could not be read.
pub fn holds_net_admin() -> Option<bool> {
    CapSets::current().map(|c| c.has_effective(CAP_NET_ADMIN))
}

/// Set once by [`prepare_children`] when the tools `vpn::exec` runs need the
/// ambient raise; read by `vpn::exec` before every spawn.
static RAISE_AMBIENT: AtomicBool = AtomicBool::new(false);

/// Whether `vpn::exec` installs [`raise_ambient_in_child`] on the tools it
/// runs.
pub(crate) fn ambient_raise_armed() -> bool {
    RAISE_AMBIENT.load(Ordering::Relaxed)
}

/// What [`prepare_children`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// `CAP_NET_ADMIN` is not permitted: there is nothing to pass on.
    NotPermitted,
    /// It is already ambient (systemd's `AmbientCapabilities=`), or this
    /// process is root, whose children get every capability by the root rule:
    /// the children have it without any help, and nothing was changed.
    AlreadyInherited,
    /// It was permitted only, and is now effective and inheritable here and
    /// raised to ambient in each child `vpn::exec` spawns.
    RaisedForTools,
    /// The sets could not be read, or `capset` refused; the tools run
    /// without the capability unless they already had it.
    Failed(String),
}

impl std::fmt::Display for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotPermitted => "CAP_NET_ADMIN is not permitted to this process",
            Self::AlreadyInherited => {
                "CAP_NET_ADMIN is ambient (or this process is root), so every tool inherits it"
            }
            Self::RaisedForTools => {
                "CAP_NET_ADMIN came from the binary's file capability; raised to effective and \
                 inheritable, and to ambient in each ip, wg, nft, openvpn and kill the daemon runs"
            }
            Self::Failed(why) => return write!(f, "CAP_NET_ADMIN could not be prepared: {why}"),
        })
    }
}

/// Make `CAP_NET_ADMIN`, where it is permitted, reach the tools `vpn::exec`
/// runs. See the module documentation for the two shapes it handles.
///
/// Call once, from the main thread, before any other thread starts: the
/// sets it changes are the calling thread's, and only threads created after
/// it inherit them.
pub fn prepare_children() -> Prepared {
    let Some(sets) = CapSets::current() else {
        return Prepared::Failed("/proc/self/status could not be read".into());
    };
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let plan = plan(&sets, euid);
    if plan != Prepared::RaisedForTools {
        return plan;
    }
    match raise_effective_and_inheritable(CAP_NET_ADMIN) {
        Ok(()) => {
            RAISE_AMBIENT.store(true, Ordering::Relaxed);
            Prepared::RaisedForTools
        }
        Err(e) => Prepared::Failed(format!("capset: {e}")),
    }
}

/// What [`prepare_children`] does for a process holding `sets` as `euid`,
/// before it does it.
fn plan(sets: &CapSets, euid: u32) -> Prepared {
    if !sets.permits(CAP_NET_ADMIN) {
        Prepared::NotPermitted
    } else if euid == 0 || sets.has_ambient(CAP_NET_ADMIN) {
        Prepared::AlreadyInherited
    } else {
        Prepared::RaisedForTools
    }
}

/// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per set.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Add `cap`, which must be permitted, to this thread's effective and
/// inheritable sets, leaving everything else as it is.
fn raise_effective_and_inheritable(cap: u32) -> io::Result<()> {
    let mut header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: `header` and `data` are live, and `data` holds the two
    // elements version 3 reads and writes.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let word = (cap / 32) as usize;
    let mask = 1u32 << (cap % 32);
    data[word].effective |= mask;
    data[word].inheritable |= mask;
    // SAFETY: as above; `capset` only reads them.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The `pre_exec` hook `vpn::exec` installs while [`ambient_raise_armed`]:
/// raise `CAP_NET_ADMIN` to the forked child's ambient set, so the tool it
/// becomes keeps it across `execve`.
///
/// Runs between `fork` and `execve`, so it makes one system call and
/// allocates nothing. A refusal fails the spawn with the kernel's error,
/// rather than running a tool that would fail later for want of the
/// capability with a message that does not say so.
pub(crate) fn raise_ambient_in_child() -> io::Result<()> {
    // SAFETY: `prctl` with these integer arguments touches no memory.
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
            CAP_NET_ADMIN as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What [`holds_net_admin`] reads from a status body.
    fn net_admin_effective(status: &str) -> Option<bool> {
        CapSets::parse(status).map(|c| c.has_effective(CAP_NET_ADMIN))
    }

    /// A status body with the four sets given, as the kernel prints them.
    fn status(inh: u64, prm: u64, eff: u64, amb: u64) -> String {
        format!(
            "Name:\ttorrentd\nUid:\t1000\t1000\t1000\t1000\nCapInh:\t{inh:016x}\n\
             CapPrm:\t{prm:016x}\nCapEff:\t{eff:016x}\nCapBnd:\t000001ffffffffff\n\
             CapAmb:\t{amb:016x}\n"
        )
    }

    #[test]
    fn the_four_sets_are_read_from_a_status_body() {
        let sets = CapSets::parse(&status(0, 0x1000, 0, 0)).unwrap();
        assert!(sets.permits(CAP_NET_ADMIN));
        assert!(!sets.has_effective(CAP_NET_ADMIN));
        assert!(!sets.has_ambient(CAP_NET_ADMIN));
        // Root's full set, and the unit's `CapabilityBoundingSet=CAP_NET_ADMIN`.
        assert_eq!(
            net_admin_effective(
                "CapInh:\t0\nCapPrm:\t1ff\nCapEff:\t000001ffffffffff\nCapAmb:\t0\n"
            ),
            Some(true)
        );
        assert_eq!(
            net_admin_effective(&status(0x1000, 0x1000, 0x1000, 0x1000)),
            Some(true)
        );
        // The packaged unit's default, `CapabilityBoundingSet=` empty.
        assert_eq!(net_admin_effective(&status(0, 0, 0, 0)), Some(false));
        // Exactly bit 12: CAP_NET_RAW (13) and CAP_NET_BROADCAST (11) are not it.
        assert_eq!(net_admin_effective(&status(0, 0, 0x2000, 0)), Some(false));
        assert_eq!(net_admin_effective(&status(0, 0, 0x0800, 0)), Some(false));
        // Nothing to read is not a reading.
        assert_eq!(net_admin_effective("Name:\ttorrentd\n"), None);
        assert_eq!(
            net_admin_effective(
                &status(0, 0, 0, 0).replace("CapEff:\t0000000000000000", "CapEff:\tnot-hex")
            ),
            None
        );
    }

    /// Only the file-capability shape is changed. The systemd shape, where
    /// the capability is ambient already, and root are left exactly as they
    /// are; without the capability there is nothing to raise.
    #[test]
    fn only_a_permitted_but_not_ambient_capability_is_raised_for_the_tools() {
        let file_cap = CapSets::parse(&status(0, 0x1000, 0, 0)).unwrap();
        assert_eq!(plan(&file_cap, 1000), Prepared::RaisedForTools);
        // The same after a raise that did not reach ambient: still needed.
        let raised = CapSets::parse(&status(0x1000, 0x1000, 0x1000, 0)).unwrap();
        assert_eq!(plan(&raised, 1000), Prepared::RaisedForTools);

        let systemd = CapSets::parse(&status(0x1000, 0x1000, 0x1000, 0x1000)).unwrap();
        assert_eq!(plan(&systemd, 1000), Prepared::AlreadyInherited);
        let root = CapSets::parse(&status(0, 0x1ff_ffff_ffff, 0x1ff_ffff_ffff, 0)).unwrap();
        assert_eq!(plan(&root, 0), Prepared::AlreadyInherited);

        let none = CapSets::parse(&status(0, 0, 0, 0)).unwrap();
        assert_eq!(plan(&none, 1000), Prepared::NotPermitted);
        assert_eq!(plan(&none, 0), Prepared::NotPermitted);
    }

    /// This process's own sets are readable, and agree with the effective
    /// reading the other callers use.
    #[test]
    fn this_process_s_sets_are_readable() {
        let sets = CapSets::current().expect("/proc/self/status has the four sets");
        assert_eq!(holds_net_admin(), Some(sets.has_effective(CAP_NET_ADMIN)));
    }
}
