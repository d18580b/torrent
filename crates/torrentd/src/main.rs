//! `torrentd` — headless petabyte-scale torrent seeding daemon.
//!
//! This binary wires together the
//! torrentd-engine layer (TorrentEngine, alert loop, registry) with
//! configuration, signals, an axum HTTP control plane, and the VPN /
//! netlink integration. The CLI takes one argument: `--config <path>`.

#![deny(unsafe_op_in_unsafe_fn)]

// Linux-only, stated as a compile error rather than left to chance. The crate
// already fails to build elsewhere, because `sd_notify` uses
// `std::os::linux::net::SocketAddrExt` — but that surfaces as an opaque
// unresolved-import error deep in a dependency rather than as the answer to
// "does this run on my Mac?".
#[cfg(not(target_os = "linux"))]
compile_error!(
    "torrentd is Linux-only: it depends on sd_notify, netlink-style interface \
     lookups, and nftables. There is no macOS or Windows port."
);

mod app_state;
mod auth;
mod cli;
mod config;
mod http;
mod metrics_sink;
mod pool_apply;
mod pool_cmd;
mod pool_service;
mod port_forward_monitor;
mod profile_registry;
mod reload;
mod sd_notify;
mod signals;
mod startup;
mod tracing_init;
mod vpn;
mod vpn_cmd;
mod vpn_monitor;

use anyhow::Context;
use clap::Parser;
use tracing::error;
use tracing::info;

use crate::cli::Cli;
use crate::cli::Command;
use crate::cli::PoolCmd;

/// Read a password twice from the terminal and print its Argon2id hash.
///
/// Read from stdin rather than taken as an argument so the password never
/// reaches the shell history or the process table.
fn hash_password_cmd() -> anyhow::Result<()> {
    use std::io::BufRead;
    use std::io::Write;

    eprint!("password: ");
    std::io::stderr().flush()?;
    let mut first = String::new();
    std::io::stdin().lock().read_line(&mut first)?;
    let first = first.trim_end_matches(['\n', '\r']).to_string();
    if first.is_empty() {
        anyhow::bail!("empty password");
    }

    // Only prompt twice when a human is typing; a piped password has already
    // been decided elsewhere and there is nothing to confirm against.
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        eprint!("confirm : ");
        std::io::stderr().flush()?;
        let mut again = String::new();
        std::io::stdin().lock().read_line(&mut again)?;
        if again.trim_end_matches(['\n', '\r']) != first {
            anyhow::bail!("passwords do not match");
        }
    }

    println!("{}", auth::hash_password(&first)?);
    eprintln!("\nAdd to your config:\n\n[auth]\npassword_hash = \"<the line above>\"");
    Ok(())
}

/// Print a fresh API token and the config stanza that accepts it.
fn new_token_cmd(name: &str, scopes: &[String]) -> anyhow::Result<()> {
    for s in scopes {
        if !matches!(s.as_str(), "read" | "write" | "metrics") {
            anyhow::bail!("unknown scope {s:?}; expected read, write, or metrics");
        }
    }
    let (token, digest) = auth::generate_token();
    // The token itself goes to stdout and is never stored: only its hash lands
    // in the config, so a leaked config cannot be replayed as a credential.
    println!("{token}");
    eprintln!(
        "\nAdd to your config (the token above is shown once and not stored):\n\n\
         [[auth.token]]\nname   = \"{name}\"\nsha256 = \"{digest}\"\nscopes = [{}]",
        scopes
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );
    Ok(())
}

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

    // Subcommands are operator tools, not the daemon: they run to completion
    // on this thread and never construct a session.
    if let Some(command) = cli.command {
        tracing_init::init(cfg.log_level);
        return match command {
            Command::Pool { cmd } => match cmd {
                PoolCmd::Scan => pool_cmd::scan(&cfg),
                PoolCmd::Status => pool_cmd::status(&cfg),
                PoolCmd::Check => pool_cmd::check(&cfg),
                PoolCmd::Orphans { limit } => pool_cmd::orphans(&cfg, limit),
            },
            Command::Vpn { cmd } => match cmd {
                cli::VpnCmd::Check {
                    profile,
                    json,
                    bring_up,
                    egress,
                } => vpn_cmd::check(&cfg, profile.as_deref(), json, bring_up, egress),
            },
            Command::HashPassword => hash_password_cmd(),
            Command::NewToken { name, scopes } => new_token_cmd(&name, &scopes),
        };
    }

    let log_handle = tracing_init::init(cfg.log_level);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("torrentd-tokio")
        .build()
        .context("build tokio runtime")?;

    runtime.block_on(async move {
        match startup::boot(cfg, cli.config, log_handle).await {
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
    info!("torrentd: clean exit");
    Ok(())
}
