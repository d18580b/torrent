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

/// What `--check-config` establishes beyond the file parsing and validating.
///
/// `deploy/torrentd.service` runs it as `ExecStartPre`, so every refusal
/// reproduced here is one that lands before `ExecStart` rather than under
/// `Restart=on-failure`. Split out of `main` so the wiring is reachable from a
/// test: `main` parses the CLI and has no other seam.
///
/// The one boot refusal deliberately *not* here is the registry cross-check,
/// which reads `profile_assignments.json` from the state directory. A config
/// check that touched disk state would fail on a host where that directory is
/// not yet provisioned, which is the pre-flight case this flag exists for. The
/// flag's own help text says so.
fn check_config(cfg: &config::Config) -> anyhow::Result<()> {
    // Refusals that are pure functions of the config file.
    cfg.check_boot_rules()?;
    // The kill switch shells out to `nft`; fail the pre-flight check now
    // rather than aborting startup later.
    if cfg.network_kill_switch && !vpn::killswitch::nft_available() {
        anyhow::bail!("network_kill_switch = true but the `nft` binary is not available");
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = config::Config::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    if cli.check_config {
        check_config(&cfg)?;
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
                // The only subcommand with more than two outcomes: it exits 2
                // when nothing failed but something could not be checked, so
                // it hands back a status rather than a `Result<()>` whose
                // `Err` could only ever mean 1.
                cli::VpnCmd::Check {
                    profile,
                    json,
                    bring_up,
                    egress,
                    as_uid,
                } => {
                    let code =
                        vpn_cmd::check(&cfg, profile.as_deref(), json, bring_up, egress, as_uid)?;
                    std::process::exit(code);
                }
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
                // `{:#}` rather than `{}`. `{}` Displays the outermost context
                // alone, so a chain like `load assignment registry: <the
                // registry's own message naming the file, the id and the
                // remedy>` reached the operator as four words with nothing
                // actionable in them — under `Restart=on-failure`, where the
                // log line is the only thing they get. Every `.context(...)`
                // on the way up is written to be read; this is what prints it.
                error!(error.cause = %format_args!("{e:#}"), "startup failed");
                std::process::exit(70); // EX_SOFTWARE
            }
        }
    });

    // unreachable
    info!("torrentd: clean exit");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOP: &str = r#"
default_save_path = "/data/torrents"
resume_dir = "/var/lib/torrentd/resume"
torrent_dir = "/var/lib/torrentd/torrents"
http_listen = "127.0.0.1:8080"
"#;

    fn cfg_from(body: &str) -> config::Config {
        toml::from_str(body).expect("test config parses")
    }

    #[test]
    fn check_config_reproduces_the_kill_switch_boot_refusal() {
        // `deploy/torrentd.service` runs `--check-config` as its
        // `ExecStartPre`. `boot` refuses this configuration, and the
        // pre-flight used to green-light it — so the failure landed at
        // `ExecStart` under `Restart=on-failure` instead of before it.
        let cfg = cfg_from(&format!(
            "{TOP}network_kill_switch = true\n\n[[profile]]\nid = \"public\"\n\
             network = \"host\"\nlisten_interfaces = \"0.0.0.0:6881\"\n"
        ));
        let msg = format!("{:#}", check_config(&cfg).unwrap_err());
        assert!(
            msg.contains("network_kill_switch") && msg.contains("vpn"),
            "got: {msg}",
        );
    }

    #[test]
    fn check_config_passes_a_configuration_the_daemon_would_boot() {
        let cfg = cfg_from(&format!(
            "{TOP}\n[[profile]]\nid = \"public\"\nnetwork = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\n"
        ));
        check_config(&cfg).unwrap();
    }
}
