//! CLI argument parsing.

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

#[derive(Debug, Parser)]
#[command(
    name = "seederd",
    version,
    about = "Headless petabyte-scale torrent seeding daemon",
    long_about = "See PRD.md and the sample config in deploy/seederd.sample.toml."
)]
pub struct Cli {
    /// Path to the daemon's TOML configuration file.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,

    /// Validate the config file and exit. Useful for systemd
    /// `ExecStartPre=/usr/bin/seederd --config /etc/seederd/seederd.toml --check-config`.
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
