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

/// The subcommand's name as an operator typed it, for error messages.
fn subcommand_name(command: &Command) -> &'static str {
    match command {
        Command::Pool { cmd } => match cmd {
            PoolCmd::Scan => "pool scan",
            PoolCmd::Status => "pool status",
            PoolCmd::Check => "pool check",
            PoolCmd::Orphans { .. } => "pool orphans",
        },
        Command::Vpn { cmd } => match cmd {
            cli::VpnCmd::Check { .. } => "vpn check",
        },
        Command::HashPassword => "hash-password",
        Command::NewToken { .. } => "new-token",
    }
}

/// Refuse `--check-config` given together with a subcommand.
///
/// The two ask for different validations. `--check-config` answers "would the
/// daemon start from this file", so it takes the full check including the
/// authentication posture; an operator subcommand takes everything but that
/// posture, because it constructs no session and binds nothing. One invocation
/// cannot satisfy both, and `load_config` resolves the tie by keying the
/// exemption on `cli.command.is_some() && !cli.check_config` — so the flag won
/// and the subcommand was **silently discarded**. `--check-config
/// hash-password` validated as the daemon, printed `config OK`, exited 0 and
/// never hashed anything.
///
/// Running the subcommand after the check is not available: it would have to
/// satisfy both validations at once, and a `hash-password` refused by the very
/// config the refusal sends an operator to it to fix is the thing the
/// exemption exists to prevent.
fn check_config_with_subcommand(cli: &Cli) -> Option<String> {
    if !cli.check_config {
        return None;
    }
    let name = subcommand_name(cli.command.as_ref()?);
    Some(format!(
        "--check-config was given together with the `{name}` subcommand, and they ask for \
         different things. --check-config answers \"would the daemon start from this file\", \
         which includes the authentication posture; `{name}` is an operator tool, which is \
         exempt from that check precisely so it still runs against a config the daemon \
         refuses. One invocation cannot be both, and this one used to validate as the daemon \
         and then discard `{name}` without running it. Run one or the other."
    ))
}

/// Whether this subcommand qualifies for the operator-tool exemption.
///
/// An **allow-list**, matched exhaustively over [`Command`] with no wildcard
/// arm. The exemption is from a *security* check, so a subcommand added later
/// must not inherit it by default: this does not compile until whoever adds
/// one classifies it. It was a negated `matches!` naming the single exception,
/// which is the opposite polarity and is not checked by anything.
///
/// The rule to classify by: **a subcommand is exempt unless it changes host
/// network state.** The exemption is justified on the ground that these
/// subcommands "construct no session and bind nothing", so a check about
/// serving is judging something they do not do. `pool scan` writes the pool
/// index, which is a file on this host and not a tunnel, so that ground still
/// holds for it. `vpn check --bring-up` raises a real WireGuard tunnel, so it
/// does not: a configuration the daemon refuses to start from should not be
/// usable to mutate the host, and `--bring-up` takes the daemon's full check.
/// Plain `vpn check` is observe-only and keeps the exemption — it is exactly
/// the pre-flight an operator runs against the config they are trying to fix.
fn is_exempt_operator_tool(command: &Command) -> bool {
    match command {
        // Reads the torrent library and writes the pool index: files under
        // paths this config already names, and no network state.
        Command::Pool { cmd } => match cmd {
            PoolCmd::Scan | PoolCmd::Status | PoolCmd::Check | PoolCmd::Orphans { .. } => true,
        },
        // Derive a hash, mint a token, print it. Neither reads nor writes
        // anything outside this process.
        Command::HashPassword | Command::NewToken { .. } => true,
        Command::Vpn { cmd } => match cmd {
            // The one arm that changes host network state. Everything else
            // `vpn check` does is reading interfaces, `wg` state and sysctls.
            cli::VpnCmd::Check { bring_up, .. } => !*bring_up,
        },
    }
}

/// Load the config with the validation this invocation actually needs.
///
/// The daemon and `--check-config` get the full check, authentication posture
/// included: one is about to serve, and the other exists to answer "would it".
/// An operator subcommand gets everything but the posture — it constructs no
/// session and binds nothing, and holding it to a check about serving is what
/// made `hash-password` unreachable from the very configs the refusal sends an
/// operator to it to fix. `vpn check --bring-up` is excluded from that, per
/// [`is_exempt_operator_tool`].
fn load_config(cli: &Cli) -> anyhow::Result<config::Config> {
    let is_operator_tool =
        cli.command.as_ref().is_some_and(is_exempt_operator_tool) && !cli.check_config;
    let loaded = if is_operator_tool {
        config::Config::load_for_operator_tool(&cli.config)
    } else {
        config::Config::load(&cli.config)
    };
    loaded.with_context(|| format!("failed to load config from {}", cli.config.display()))
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

    // Exit 2, the usage-error status, rather than 1: nothing about the
    // configuration is wrong, the invocation is.
    if let Some(msg) = check_config_with_subcommand(&cli) {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }

    let cfg = load_config(&cli)?;

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
                error!(error.cause = %e, "startup failed");
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

    /// The config an existing non-loopback deployment is holding on upgrade:
    /// no `[auth]`, no opt-out, and a bind it cannot move — a container
    /// publishes `127.0.0.1:8080:8080` to a daemon bound `0.0.0.0` inside the
    /// namespace, so a loopback bind there is a dead port.
    fn non_loopback_without_auth(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("torrentd.toml");
        std::fs::write(
            &p,
            "default_save_path = \"/data/torrents\"\n\
             resume_dir = \"/var/lib/torrentd/resume\"\n\
             torrent_dir = \"/var/lib/torrentd/torrents\"\n\
             http_listen = \"0.0.0.0:8080\"\n\
             \n\
             [[profile]]\n\
             id = \"public\"\n\
             network = \"host\"\n\
             listen_interfaces = \"0.0.0.0:6881\"\n",
        )
        .unwrap();
        p
    }

    #[test]
    fn hash_password_runs_from_the_config_the_refusal_sends_you_to_fix() {
        // The property: the way out of the refusal has to be reachable from
        // the configuration being refused. `hash-password` constructs no
        // session and binds nothing, so the posture check must not stand in
        // front of it — otherwise the only documented migration has no first
        // step for any deployment whose bind is not loopback.
        let dir = tempfile::tempdir().unwrap();
        let p = non_loopback_without_auth(dir.path());

        for argv in [
            vec!["torrentd", "--config", p.to_str().unwrap(), "hash-password"],
            vec![
                "torrentd",
                "--config",
                p.to_str().unwrap(),
                "new-token",
                "--name",
                "ci",
            ],
        ] {
            let cli = Cli::parse_from(argv.clone());
            assert!(
                load_config(&cli).is_ok(),
                "{argv:?} must load: it serves nothing",
            );
        }
    }

    #[test]
    fn bringing_a_tunnel_up_is_not_exempt_but_checking_one_is() {
        // The property: the operator-tool exemption is justified on
        // "they construct no session and bind nothing". `vpn check
        // --bring-up` raises a real WireGuard tunnel on the host, so it is
        // held to the daemon's full check — a configuration the daemon
        // refuses to start from must not be usable to mutate the host.
        //
        // Plain `vpn check` keeps the exemption, because the pre-flight has
        // to work on exactly the config an operator is trying to fix. Both
        // arms are pinned: dropping either one is the whole of this change.
        let dir = tempfile::tempdir().unwrap();
        let p = non_loopback_without_auth(dir.path());
        let path = p.to_str().unwrap();

        let cli = Cli::parse_from(["torrentd", "--config", path, "vpn", "check", "--bring-up"]);
        let msg = format!(
            "{:#}",
            load_config(&cli).expect_err("--bring-up mutates the host and is not exempt"),
        );
        assert!(
            msg.contains("allow_unauthenticated"),
            "the refusal must be the posture one; got: {msg}",
        );

        let cli = Cli::parse_from(["torrentd", "--config", path, "vpn", "check"]);
        assert!(
            load_config(&cli).is_ok(),
            "observe-only `vpn check` keeps the exemption",
        );
    }

    #[test]
    fn check_config_beside_a_subcommand_is_refused_naming_both() {
        // The property: an invocation that asks for two incompatible
        // validations is refused rather than silently resolved in favour of
        // one. `load_config` keys the operator-tool exemption on
        // `cli.command.is_some() && !cli.check_config`, so the flag won and
        // the subcommand was dropped: `--check-config hash-password`
        // validated as the daemon, printed `config OK`, exited 0 and never
        // hashed anything. A flag that swallows the subcommand beside it is
        // worse than either behaviour it was choosing between.
        //
        // The message must name both, because the operator has to know which
        // half to drop.
        for (argv, sub) in [
            (
                vec!["torrentd", "-c", "x", "--check-config", "hash-password"],
                "hash-password",
            ),
            (
                vec![
                    "torrentd",
                    "-c",
                    "x",
                    "--check-config",
                    "new-token",
                    "--name",
                    "ci",
                ],
                "new-token",
            ),
            (
                vec!["torrentd", "-c", "x", "--check-config", "pool", "status"],
                "pool status",
            ),
            (
                vec!["torrentd", "-c", "x", "--check-config", "vpn", "check"],
                "vpn check",
            ),
        ] {
            let cli = Cli::parse_from(argv.clone());
            let msg = check_config_with_subcommand(&cli)
                .unwrap_or_else(|| panic!("{argv:?} must be refused"));
            assert!(
                msg.contains("--check-config") && msg.contains(sub),
                "the refusal must name both halves; got: {msg}",
            );
        }

        // Neither alone is affected: the daemon, the bare pre-flight, and an
        // operator subcommand on its own all still run.
        for argv in [
            vec!["torrentd", "-c", "x"],
            vec!["torrentd", "-c", "x", "--check-config"],
            vec!["torrentd", "-c", "x", "hash-password"],
            vec!["torrentd", "-c", "x", "vpn", "check", "--bring-up"],
        ] {
            let cli = Cli::parse_from(argv.clone());
            assert!(
                check_config_with_subcommand(&cli).is_none(),
                "{argv:?} asks for one validation and must not be refused",
            );
        }
    }

    #[test]
    fn the_daemon_and_check_config_still_get_the_posture_check() {
        // The exemption is for subcommands only. Widening it to the daemon
        // would remove the refusal this whole change exists to make, and
        // widening it to `--check-config` would make the pre-flight answer a
        // different question from the startup it is a pre-flight for.
        let dir = tempfile::tempdir().unwrap();
        let p = non_loopback_without_auth(dir.path());

        for argv in [
            vec!["torrentd", "--config", p.to_str().unwrap()],
            vec![
                "torrentd",
                "--config",
                p.to_str().unwrap(),
                "--check-config",
            ],
        ] {
            let cli = Cli::parse_from(argv.clone());
            let msg = format!("{:#}", load_config(&cli).unwrap_err());
            assert!(
                msg.contains("allow_unauthenticated"),
                "{argv:?} must be refused; got: {msg}",
            );
        }
    }

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
