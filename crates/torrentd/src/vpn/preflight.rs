//! What a VPN deployment needs from the host, checked before any profile
//! comes up.
//!
//! Each requirement used to surface only as the failure of whatever first
//! needed it: `ip link add` refused for want of `CAP_NET_ADMIN`, or for want
//! of the WireGuard module; `nft -f` refused after every tunnel was already
//! up; `openvpn` exiting on a missing `/dev/net/tun`. In a container that is
//! a restart loop whose cause is a line deep in each attempt. Here each one
//! is asked once, without changing anything, and named:
//!
//! - [`Requirement::NetAdmin`]: `CAP_NET_ADMIN` permitted to this process,
//!   for any vpn profile or `network_kill_switch = true`. Without it the
//!   daemon exits 78, the configuration's status, since no restart grants it.
//! - [`Requirement::WireguardKernel`]: the kernel's WireGuard support, for a
//!   WireGuard profile, read as whether the `wireguard` generic-netlink
//!   family is registered. Asking may make the kernel load the module, as
//!   `ip link add … type wireguard` would; it creates no link.
//! - [`Requirement::Nft`]: `nft list tables` runs, for the kill switch. It
//!   runs through `vpn::exec`, so it also proves the capability reaches the
//!   tools and not only the daemon.
//! - [`Requirement::TunDevice`]: `/dev/net/tun`, for an OpenVPN profile.
//!
//! The daemon's boot, `--check-config` and `vpn check` all judge with
//! [`run`], so the three report the same verdicts.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt;

use torrentd_engine::ProfileConfig;
use torrentd_engine::VpnType;

use super::caps::CapSets;
use super::caps::CAP_NET_ADMIN;
use super::exec;

/// One thing a VPN deployment needs from the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    NetAdmin,
    WireguardKernel,
    Nft,
    TunDevice,
}

impl Requirement {
    /// The name every report uses: the boot's log line, `--check-config`'s
    /// output, `vpn check`'s check, and a failed profile's reason.
    pub fn name(self) -> &'static str {
        match self {
            Self::NetAdmin => "cap_net_admin",
            Self::WireguardKernel => "wireguard_kernel",
            Self::Nft => "nft_runs",
            Self::TunDevice => "tun_device",
        }
    }
}

/// What asking about one requirement established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finding {
    Met,
    Missing,
    /// Not asked, because asking needs `CAP_NET_ADMIN`, which this process
    /// does not hold. Not a finding about the host.
    NeedsCapability,
    /// Asked, and the host did not answer.
    Unknown,
}

/// One requirement's verdict, and what it rests on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub requirement: Requirement,
    pub finding: Finding,
    pub detail: String,
}

impl Outcome {
    fn new(requirement: Requirement, finding: Finding, detail: impl Into<String>) -> Self {
        Self {
            requirement,
            finding,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "preflight {}: {}", self.requirement.name(), self.detail)
    }
}

/// Which requirements a configuration has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Needs {
    pub net_admin: bool,
    pub wireguard: bool,
    pub nft: bool,
    pub tun: bool,
}

impl Needs {
    /// What `profiles`, with the kill switch on or off, need.
    pub fn of<'a>(
        profiles: impl IntoIterator<Item = &'a ProfileConfig>,
        kill_switch: bool,
    ) -> Self {
        let mut needs = Self {
            net_admin: kill_switch,
            nft: kill_switch,
            ..Self::default()
        };
        for p in profiles {
            match p.vpn_type() {
                Some(VpnType::Wireguard) => {
                    needs.net_admin = true;
                    needs.wireguard = true;
                }
                Some(VpnType::Openvpn) => {
                    needs.net_admin = true;
                    needs.tun = true;
                }
                None => {}
            }
        }
        needs
    }
}

/// The host, as the preflight asks it.
pub trait Probe {
    /// This process's capability sets, or `None` where they cannot be read.
    fn cap_sets(&self) -> Option<CapSets>;
    /// Whether the kernel registers the `wireguard` generic-netlink family.
    fn wireguard_family(&self) -> io::Result<bool>;
    /// `nft list tables`, run as the kill switch runs `nft`.
    fn nft_runs(&self) -> io::Result<()>;
    /// Whether `/dev/net/tun` is a character device.
    fn tun_device(&self) -> io::Result<bool>;
}

/// [`Probe`] against this machine.
#[derive(Debug, Clone, Copy)]
pub struct Host;

impl Probe for Host {
    fn cap_sets(&self) -> Option<CapSets> {
        CapSets::current()
    }

    fn wireguard_family(&self) -> io::Result<bool> {
        genl_family_exists("wireguard")
    }

    fn nft_runs(&self) -> io::Result<()> {
        exec::run_ok("nft", &["list", "tables"], None, exec::QUICK).map(|_| ())
    }

    fn tun_device(&self) -> io::Result<bool> {
        std::fs::metadata("/dev/net/tun").map(|m| m.file_type().is_char_device())
    }
}

/// The refusal for a process without `CAP_NET_ADMIN` that `needs` it, naming
/// both ways to grant it.
pub fn net_admin_missing() -> String {
    "this process does not hold CAP_NET_ADMIN in its permitted set, and a vpn profile or \
     network_kill_switch = true needs it: raising a tunnel and installing the kill switch both \
     do. Grant it one of two ways. Under systemd, AmbientCapabilities=CAP_NET_ADMIN and \
     CapabilityBoundingSet=CAP_NET_ADMIN in the unit (deploy/torrentd.service). In a container, \
     run the image, whose torrentd carries the file capability cap_net_admin+p, with NET_ADMIN \
     added to the container's capabilities and privilege escalation allowed: in Kubernetes the \
     pod securityContext `runAsUser: 1000`, `capabilities: {drop: [ALL], add: [NET_ADMIN]}` and \
     `allowPrivilegeEscalation: true` (docs/running.md, \"In a container\")"
        .to_string()
}

/// Judge every requirement `needs` names, in the order a boot meets them.
pub fn run(needs: &Needs, probe: &dyn Probe) -> Vec<Outcome> {
    let mut out = Vec::new();
    let sets = probe.cap_sets();
    // Whether the tools could be given the capability: unknown counts as
    // yes, so an unreadable status does not hide a real `nft` failure.
    let permitted = sets.is_none_or(|s| s.permits(CAP_NET_ADMIN));
    if needs.net_admin {
        out.push(match sets {
            None => Outcome::new(
                Requirement::NetAdmin,
                Finding::Unknown,
                "/proc/self/status could not be read for this process's capabilities",
            ),
            Some(s) if !s.permits(CAP_NET_ADMIN) => {
                Outcome::new(Requirement::NetAdmin, Finding::Missing, net_admin_missing())
            }
            Some(s) if s.has_ambient(CAP_NET_ADMIN) => Outcome::new(
                Requirement::NetAdmin,
                Finding::Met,
                "CAP_NET_ADMIN is permitted and ambient, so every tool inherits it",
            ),
            Some(_) => Outcome::new(
                Requirement::NetAdmin,
                Finding::Met,
                "CAP_NET_ADMIN is permitted; the tools the daemon runs (ip, wg, nft, openvpn) \
                 get it as ambient, and nothing else it runs does",
            ),
        });
    }
    if needs.wireguard {
        out.push(match probe.wireguard_family() {
            Ok(true) => Outcome::new(
                Requirement::WireguardKernel,
                Finding::Met,
                "the kernel has WireGuard: its `wireguard` generic-netlink family is registered",
            ),
            Ok(false) => Outcome::new(
                Requirement::WireguardKernel,
                Finding::Missing,
                "the kernel has no WireGuard support: its `wireguard` generic-netlink family is \
                 not registered and could not be loaded, so `ip link add … type wireguard` would \
                 fail. Load the module on the host (`modprobe wireguard`); a container cannot \
                 load one itself",
            ),
            Err(e) => Outcome::new(
                Requirement::WireguardKernel,
                Finding::Unknown,
                format!("could not ask the kernel for its `wireguard` generic-netlink family: {e}"),
            ),
        });
    }
    if needs.nft {
        out.push(if !permitted {
            Outcome::new(
                Requirement::Nft,
                Finding::NeedsCapability,
                "`nft list tables` was not run: it needs CAP_NET_ADMIN, which this process does \
                 not hold",
            )
        } else {
            match probe.nft_runs() {
                Ok(()) => Outcome::new(Requirement::Nft, Finding::Met, "`nft list tables` runs"),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Outcome::new(
                    Requirement::Nft,
                    Finding::Missing,
                    format!(
                        "network_kill_switch = true but `nft` is not installed ({e}); install \
                         nftables"
                    ),
                ),
                Err(e) => Outcome::new(
                    Requirement::Nft,
                    Finding::Missing,
                    format!(
                        "network_kill_switch = true but `nft` does not run ({e}), so the kill \
                         switch cannot be installed and the boot would abort after raising \
                         every tunnel"
                    ),
                ),
            }
        });
    }
    if needs.tun {
        out.push(match probe.tun_device() {
            Ok(true) => Outcome::new(
                Requirement::TunDevice,
                Finding::Met,
                "/dev/net/tun is a character device",
            ),
            Ok(false) => Outcome::new(
                Requirement::TunDevice,
                Finding::Missing,
                "/dev/net/tun exists but is not a character device, so openvpn cannot open a \
                 tunnel on it",
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Outcome::new(
                Requirement::TunDevice,
                Finding::Missing,
                "/dev/net/tun does not exist, and openvpn opens it for every tunnel. Load the \
                 `tun` module on the host; in a container, pass the host's /dev/net/tun in \
                 (compose `devices: [/dev/net/tun]`)",
            ),
            Err(e) => Outcome::new(
                Requirement::TunDevice,
                Finding::Unknown,
                format!("could not stat /dev/net/tun: {e}"),
            ),
        });
    }
    out
}

/// The outcome for `requirement` in `outcomes`, if it was judged missing.
pub fn missing(outcomes: &[Outcome], requirement: Requirement) -> Option<&Outcome> {
    outcomes
        .iter()
        .find(|o| o.requirement == requirement && o.finding == Finding::Missing)
}

/// Why `profile` cannot come up given `outcomes`, or `None` where nothing
/// the preflight found stops it. The reason is the failed profile's.
pub fn refusal_for(outcomes: &[Outcome], profile: &ProfileConfig) -> Option<String> {
    let requirement = match profile.vpn_type()? {
        VpnType::Wireguard => Requirement::WireguardKernel,
        VpnType::Openvpn => Requirement::TunDevice,
    };
    missing(outcomes, requirement).map(ToString::to_string)
}

/// The `CTRL_CMD_GETFAMILY` request for `name`, as bytes in host order.
fn getfamily_request(name: &str, seq: u32) -> Vec<u8> {
    const NLMSG_HDRLEN: usize = 16;
    const GENL_HDRLEN: usize = 4;
    const NLA_HDRLEN: usize = 4;
    let attr_len = NLA_HDRLEN + name.len() + 1;
    let padded = (attr_len + 3) & !3;
    let total = NLMSG_HDRLEN + GENL_HDRLEN + padded;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&(libc::GENL_ID_CTRL as u16).to_ne_bytes());
    buf.extend_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.push(libc::CTRL_CMD_GETFAMILY as u8);
    buf.push(1); // the controller's version
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    buf.extend_from_slice(&(libc::CTRL_ATTR_FAMILY_NAME as u16).to_ne_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.resize(total, 0);
    buf
}

/// Read the kernel's answer to [`getfamily_request`]: the family's
/// description is `true`, `ENOENT` is `false`, and anything else an error.
fn getfamily_reply(buf: &[u8]) -> io::Result<bool> {
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "a truncated netlink reply");
    let u16_at = |at: usize| -> io::Result<u16> {
        Ok(u16::from_ne_bytes(
            buf.get(at..at + 2)
                .ok_or_else(malformed)?
                .try_into()
                .unwrap(),
        ))
    };
    let kind = i32::from(u16_at(4)?);
    if kind == libc::GENL_ID_CTRL {
        return Ok(true);
    }
    if kind == libc::NLMSG_ERROR {
        let errno = -i32::from_ne_bytes(buf.get(16..20).ok_or_else(malformed)?.try_into().unwrap());
        return match errno {
            libc::ENOENT => Ok(false),
            0 => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the kernel acknowledged the lookup without describing the family",
            )),
            e => Err(io::Error::from_raw_os_error(e)),
        };
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("an unexpected netlink reply of type {kind}"),
    ))
}

/// Whether the kernel registers the generic-netlink family `name`. Needs no
/// capability.
fn genl_family_exists(name: &str) -> io::Result<bool> {
    // SAFETY: plain integer arguments.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_GENERIC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    // SAFETY: `timeout` is a live `timeval` of the size passed.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let request = getfamily_request(name, 1);
    // SAFETY: an all-zero `sockaddr_nl` is valid; with the family set it
    // addresses the kernel.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: `request` and `kernel` are live for the call, with the lengths
    // passed.
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&raw const kernel).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut reply = [0u8; 8192];
    // SAFETY: `reply` is live and as long as the length passed.
    let got = unsafe { libc::recv(fd.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    getfamily_reply(&reply[..got as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host whose every answer is scripted.
    struct Scripted {
        sets: Option<CapSets>,
        wireguard: fn() -> io::Result<bool>,
        nft: fn() -> io::Result<()>,
        tun: fn() -> io::Result<bool>,
    }

    impl Scripted {
        /// The healthy file-capability host: everything there.
        fn healthy() -> Self {
            Self {
                sets: Some(CapSets {
                    permitted: 1 << CAP_NET_ADMIN,
                    ..CapSets::default()
                }),
                wireguard: || Ok(true),
                nft: || Ok(()),
                tun: || Ok(true),
            }
        }
    }

    impl Probe for Scripted {
        fn cap_sets(&self) -> Option<CapSets> {
            self.sets
        }
        fn wireguard_family(&self) -> io::Result<bool> {
            (self.wireguard)()
        }
        fn nft_runs(&self) -> io::Result<()> {
            (self.nft)()
        }
        fn tun_device(&self) -> io::Result<bool> {
            (self.tun)()
        }
    }

    const ALL: Needs = Needs {
        net_admin: true,
        wireguard: true,
        nft: true,
        tun: true,
    };

    fn finding(outcomes: &[Outcome], r: Requirement) -> Option<Finding> {
        outcomes
            .iter()
            .find(|o| o.requirement == r)
            .map(|o| o.finding)
    }

    /// A config with no tunnel and no kill switch needs nothing, and nothing
    /// is asked: a host-only deployment probes nothing.
    #[test]
    fn only_what_the_configuration_needs_is_asked() {
        let panics = Scripted {
            sets: None,
            wireguard: || panic!("asked about WireGuard"),
            nft: || panic!("ran nft"),
            tun: || panic!("asked about tun"),
        };
        assert!(run(&Needs::default(), &panics).is_empty());

        let ks = Needs {
            net_admin: true,
            nft: true,
            ..Needs::default()
        };
        let out = run(&ks, &Scripted::healthy());
        let names: Vec<_> = out.iter().map(|o| o.requirement.name()).collect();
        assert_eq!(names, ["cap_net_admin", "nft_runs"]);
    }

    #[test]
    fn a_healthy_host_meets_every_requirement() {
        let out = run(&ALL, &Scripted::healthy());
        assert_eq!(out.len(), 4);
        assert!(out.iter().all(|o| o.finding == Finding::Met), "{out:#?}");
    }

    /// Without the capability: the refusal names both fixes, and `nft` is
    /// not run, since it would fail for that reason alone and say nothing
    /// about the host.
    #[test]
    fn without_the_capability_it_is_missing_and_nft_is_not_judged() {
        let host = Scripted {
            sets: Some(CapSets::default()),
            nft: || panic!("ran nft without the capability"),
            ..Scripted::healthy()
        };
        let out = run(&ALL, &host);
        let cap = missing(&out, Requirement::NetAdmin).expect("missing");
        for needle in [
            "CAP_NET_ADMIN",
            "AmbientCapabilities=CAP_NET_ADMIN",
            "securityContext",
            "allowPrivilegeEscalation: true",
            "drop: [ALL], add: [NET_ADMIN]",
        ] {
            assert!(cap.detail.contains(needle), "{needle}: {}", cap.detail);
        }
        assert_eq!(
            finding(&out, Requirement::Nft),
            Some(Finding::NeedsCapability)
        );
    }

    #[test]
    fn each_missing_facility_is_named() {
        let host = Scripted {
            wireguard: || Ok(false),
            nft: || {
                Err(io::Error::other(
                    "`nft list tables` exited 1: netlink: Error",
                ))
            },
            tun: || Err(io::Error::from(io::ErrorKind::NotFound)),
            ..Scripted::healthy()
        };
        let out = run(&ALL, &host);
        assert_eq!(finding(&out, Requirement::NetAdmin), Some(Finding::Met));
        for r in [
            Requirement::WireguardKernel,
            Requirement::Nft,
            Requirement::TunDevice,
        ] {
            let o = missing(&out, r).unwrap_or_else(|| panic!("{r:?}: {out:#?}"));
            assert!(o
                .to_string()
                .starts_with(&format!("preflight {}: ", r.name())));
        }
        assert!(missing(&out, Requirement::Nft)
            .unwrap()
            .detail
            .contains("netlink: Error"));
        assert!(missing(&out, Requirement::TunDevice)
            .unwrap()
            .detail
            .contains("/dev/net/tun"));

        let absent = Scripted {
            nft: || Err(io::Error::from(io::ErrorKind::NotFound)),
            ..Scripted::healthy()
        };
        assert!(missing(&run(&ALL, &absent), Requirement::Nft)
            .unwrap()
            .detail
            .contains("not installed"));
    }

    /// A host that does not answer is not a host that lacks the facility.
    #[test]
    fn a_host_that_does_not_answer_is_unknown_not_missing() {
        let host = Scripted {
            sets: None,
            wireguard: || Err(io::Error::from(io::ErrorKind::TimedOut)),
            tun: || Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            ..Scripted::healthy()
        };
        let out = run(&ALL, &host);
        assert_eq!(finding(&out, Requirement::NetAdmin), Some(Finding::Unknown));
        assert_eq!(
            finding(&out, Requirement::WireguardKernel),
            Some(Finding::Unknown)
        );
        assert_eq!(
            finding(&out, Requirement::TunDevice),
            Some(Finding::Unknown)
        );
        // Unknown capabilities still let `nft` be judged on its own answer.
        assert_eq!(finding(&out, Requirement::Nft), Some(Finding::Met));
    }

    #[test]
    fn the_request_is_a_getfamily_for_the_name() {
        let req = getfamily_request("wireguard", 7);
        // 16 header + 4 genl + (4 + "wireguard\0" = 14, padded to 16).
        assert_eq!(req.len(), 36);
        assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), 36);
        assert_eq!(
            i32::from(u16::from_ne_bytes(req[4..6].try_into().unwrap())),
            libc::GENL_ID_CTRL
        );
        assert_eq!(u32::from_ne_bytes(req[8..12].try_into().unwrap()), 7);
        assert_eq!(i32::from(req[16]), libc::CTRL_CMD_GETFAMILY);
        assert_eq!(u16::from_ne_bytes(req[20..22].try_into().unwrap()), 14);
        assert_eq!(&req[24..34], b"wireguard\0");
    }

    #[test]
    fn the_reply_reads_as_present_absent_or_an_error() {
        let reply = |kind: i32, errno: i32| {
            let mut b = vec![0u8; 36];
            b[4..6].copy_from_slice(&(kind as u16).to_ne_bytes());
            b[16..20].copy_from_slice(&(-errno).to_ne_bytes());
            b
        };
        assert!(getfamily_reply(&reply(libc::GENL_ID_CTRL, 0)).unwrap());
        assert!(!getfamily_reply(&reply(libc::NLMSG_ERROR, libc::ENOENT)).unwrap());
        let e = getfamily_reply(&reply(libc::NLMSG_ERROR, libc::EPERM)).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EPERM));
        assert!(getfamily_reply(&reply(libc::NLMSG_ERROR, 0)).is_err());
        assert!(getfamily_reply(&reply(42, 0)).is_err());
        assert!(getfamily_reply(&[0u8; 3]).is_err());
    }

    /// The generic-netlink controller describes itself on every kernel, so
    /// the lookup is reachable without a WireGuard module or a capability.
    #[test]
    fn the_kernel_answers_a_lookup_of_its_own_controller() {
        assert!(genl_family_exists("nlctrl").expect("the kernel answers"));
    }
}
