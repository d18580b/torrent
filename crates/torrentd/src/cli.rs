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
    #[arg(long)]
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
    /// Observe-only unless `--bring-up` is given: it reads interfaces and `wg`
    /// state, and a NAT-PMP slot's mapping is negotiated with the same short
    /// lease the daemon uses and then left to expire rather than deleted —
    /// NAT-PMP's delete removes every mapping the tunnel address holds, which
    /// would include a running daemon's. No libtorrent session is constructed
    /// and no tracker is contacted, so this is safe to run against real
    /// credentials, and safe to run while the daemon is up.
    Check {
        /// Check only this slot. Default: every configured slot.
        #[arg(long, value_name = "ID")]
        slot: Option<String>,
        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,
        /// Raise each tunnel before checking it and lower it afterwards. This
        /// is the only option here that modifies the host.
        #[arg(long)]
        bring_up: bool,
        /// Prove the tunnel carries traffic: send a DNS query from a socket
        /// bound to the tunnel address and require a reply, e.g. `1.1.1.1:53`.
        /// Without this the check confirms the tunnel has an address, not that
        /// anything can leave through it.
        #[arg(long, value_name = "IP:PORT")]
        egress: Option<std::net::SocketAddr>,
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
