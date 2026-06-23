//! CLI argument parsing.

use std::path::PathBuf;

use clap::Parser;

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
}
