//! CLI argument parsing.

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

#[derive(Debug, Parser)]
#[command(
    name = "torrentd",
    version,
    about = "Headless petabyte-scale torrent seeding daemon",
    long_about = "Setup and operation: docs/running.md. Annotated config: deploy/torrentd.sample.toml."
)]
pub struct Cli {
    /// Path to the daemon's TOML configuration file.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,

    /// Validate the config file and exit. Useful for systemd
    /// `ExecStartPre=/usr/bin/torrentd --config /etc/torrentd/torrentd.toml --check-config`.
    ///
    /// Checks everything decidable from the file itself, including the boot
    /// refusals for `network_kill_switch = true` with no `network = "vpn"`
    /// profile or with any `network = "host"` one. It does NOT read the state directory, so the one boot check
    /// that does — the assignment registry naming a profile no `[[profile]]`
    /// table declares — still happens at startup and can still fail there. A
    /// config check that touched disk state would fail on a host whose state
    /// directory is not yet provisioned, which is the pre-flight case this
    /// flag exists for.
    ///
    /// Of the host, it probes one thing: that `nft` runs, when
    /// `network_kill_switch = true`. It does not check VPN prerequisites —
    /// that profile files are readable, that `ip`, `wg`, `wg-quick` or
    /// `openvpn` are installed, or which uid the daemon runs as. Run
    /// `torrentd --config <path> vpn check` for those. That command is kept
    /// out of this flag on purpose: its checks can come back "could not be
    /// checked" for want of a capability, and as `ExecStartPre=` that would
    /// refuse to start a daemon nothing is known to be wrong with.
    #[arg(long, verbatim_doc_comment)]
    pub check_config: bool,

    /// Optional subcommand. Omit it to run the daemon.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect and maintain the managed-pool index.
    Pool {
        #[command(subcommand)]
        cmd: PoolCmd,
    },
    /// Hash a password for the `[auth] password_hash` config key.
    HashPassword,
    /// Verify VPN configuration against the real host, without seeding.
    Vpn {
        #[command(subcommand)]
        cmd: VpnCmd,
    },
    /// Generate an API token and the hash to record in the config.
    NewToken {
        /// Label for the token, so a leaked one is identifiable from logs.
        #[arg(long)]
        name: String,
        /// One or more of: read, write, metrics.
        #[arg(long, value_delimiter = ',', default_value = "read")]
        scopes: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum VpnCmd {
    /// Run every VPN pre-flight check the daemon would depend on, and report
    /// each one separately.
    ///
    /// Observe-only unless `--bring-up` is given: it reads interfaces, `wg`
    /// state and sysctls, makes no host change, and deletes nothing. A NAT-PMP
    /// profile's mapping is negotiated with the same short lease the daemon
    /// uses and left to expire — NAT-PMP's delete removes every mapping the
    /// tunnel address holds, which would include a running daemon's, so the
    /// client used here issues none on any branch. No libtorrent session is
    /// constructed and no tracker is contacted, so this is safe to run against
    /// real credentials. Against a live daemon its one interaction is that
    /// NAT-PMP request, from the same client identity the daemon uses; whether
    /// a gateway coalesces it with the daemon's existing mapping or answers
    /// with a second one is gateway-dependent and is not tested here.
    ///
    /// Exit status: 0 when every check passed, 1 when any check failed, and 2
    /// when nothing failed but at least one check could not be performed. A
    /// check that nothing this invocation could be given would settle is
    /// reported `?cap` and does not raise the status to 2 — usually for want
    /// of CAP_NET_ADMIN, which the daemon holds and an operator shell usually
    /// does not, and also for the `kill_switch_uid` mismatch, which no
    /// argument or privilege resolves. Counting either would make 2 the normal
    /// answer on a healthy host. A caller that treats only 0 as success gets
    /// the strict reading; one that accepts 0 and 2 gets "nothing is known to
    /// be broken".
    Check {
        /// Check only this profile. Default: every configured profile.
        #[arg(long, value_name = "ID")]
        profile: Option<String>,
        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,
        /// Raise a tunnel that is not already up, check it, and lower again
        /// only what this command raised. An interface that was already there
        /// belongs to something else — usually a running daemon — and is
        /// checked and left alone. This is the only option here that modifies
        /// the host.
        ///
        /// Needs root: `wg-quick` re-execs itself under `sudo` when it is not
        /// uid 0, so on a TTY-less invocation with no askpass helper it
        /// prompts for a password it cannot read and the bring-up fails. Run
        /// it under `sudo`, or from something already running as root. Every
        /// other flag here works unprivileged.
        ///
        /// Because it modifies the host, this is also the one `vpn check`
        /// invocation that is NOT exempt from the authentication-posture
        /// check: it takes the daemon's full validation, so a configuration
        /// the daemon refuses to start from cannot be used to bring a tunnel
        /// up either. Observe-only `vpn check` keeps the exemption and still
        /// runs against a config the daemon refuses, which is the pre-flight
        /// it exists for.
        #[arg(long, verbatim_doc_comment)]
        bring_up: bool,
        /// Prove the tunnel carries traffic: send a DNS query from a socket
        /// bound to the tunnel address and require a reply, e.g. `1.1.1.1:53`.
        /// Without this the check confirms the tunnel has an address, not that
        /// anything can leave through it.
        #[arg(long, value_name = "IP:PORT")]
        egress: Option<std::net::SocketAddr>,
        /// Judge the kill-switch checks against this uid rather than this
        /// process's own. The daemon runs as its own user (the packaged unit
        /// uses `User=torrentd`) while `--bring-up` needs root, so the uid
        /// running this check is routinely not the uid the ruleset would
        /// confine.
        ///
        /// The ruleset is rendered and dry-run through `nft --check` for the
        /// uid given, whoever is invoking. The `kill_switch_uid` line itself
        /// reports `unknown` when the invoker is not that uid — this process
        /// cannot observe the daemon's uid — except for uid 0, which fails
        /// whoever asks, because the kill switch refuses to install for root
        /// unconditionally.
        #[arg(long, value_name = "UID")]
        as_uid: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PoolCmd {
    /// Walk the managed roots, read the torrent library, and match them.
    Scan,
    /// Summarise the existing index without touching the filesystem.
    Status,
    /// Re-stat claimed files and report what changed since the last scan.
    Check,
    /// Show bytes on disk that no torrent in the library claims.
    Orphans {
        /// Maximum entries to list per root.
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
}
