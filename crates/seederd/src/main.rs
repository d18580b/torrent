//! `seederd` — headless petabyte-scale torrent seeding daemon.
//!
//! See PRD.md for the full spec. This binary wires together the
//! seederd-engine layer (TorrentEngine, alert loop, registry) with
//! configuration, signals, an axum HTTP control plane, and the VPN /
//! netlink integration. The CLI takes one argument: `--config <path>`.

#![deny(unsafe_op_in_unsafe_fn)]

mod app_state;
mod cli;
mod config;
mod http;
mod metrics_sink;
mod port_forward_monitor;
mod reload;
mod signals;
mod slot_registry;
mod startup;
mod tracing_init;
mod vpn;
mod vpn_monitor;

use anyhow::Context;
use clap::Parser;
use tracing::error;
use tracing::info;

use crate::cli::Cli;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = config::Config::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    if cli.check_config {
        // The kill switch shells out to `nft`; fail the pre-flight check now
        // rather than aborting startup later (systemd ExecStartPre).
        if cfg.network_kill_switch && !vpn::killswitch::nft_available() {
            anyhow::bail!("network_kill_switch = true but the `nft` binary is not available");
        }
        eprintln!("config OK");
        return Ok(());
    }

    let log_handle = tracing_init::init(cfg.log_level);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("seederd-tokio")
        .build()
        .context("build tokio runtime")?;

    runtime.block_on(async move {
        match startup::boot(cfg, log_handle).await {
            Ok(handle) => {
                let exit_code = handle.run_until_signal().await;
                std::process::exit(exit_code);
            }
            Err(e) => {
                error!(error.cause = %e, "startup failed");
                std::process::exit(70); // EX_SOFTWARE
            }
        }
    });

    // unreachable
    info!("seederd: clean exit");
    Ok(())
}
