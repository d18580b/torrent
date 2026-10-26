//! `torrentctl`: a terminal client for torrentd's `/v1` API.
//!
//! It talks to the daemon only through a client spargen generates from the
//! committed OpenAPI document, so it exercises the same contract any other
//! client would. Everything but the command line and the terminal lives in
//! the library (`lib.rs`).

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use color_eyre::eyre::WrapErr as _;
use torrentctl::api;
use torrentctl::app;
use torrentctl::config;
use torrentctl::runtime;
use torrentctl::theme;

/// A terminal client for torrentd.
#[derive(Debug, Parser)]
#[command(name = "torrentctl", version, about)]
struct Cli {
    /// The daemon's base URL, or `unix:/path` for its socket [env: TORRENTCTL_URL]
    /// [default: unix:/run/torrentd/api.sock when it exists, else http://127.0.0.1:8080].
    #[arg(long, value_name = "URL")]
    url: Option<String>,
    /// A bearer token (`tdp_…`). Prefer --token-file or TORRENTCTL_TOKEN: a
    /// token on the command line is visible in the process list.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
    /// A file holding a bearer token. It must have no group or other
    /// permission bits (0600 or 0400); a relative path is from the current
    /// directory.
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
    /// The config file [default: $XDG_CONFIG_HOME/torrentctl/config.toml].
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

/// How long the exit waits for the runtime's blocking threads once the loop
/// has finished, before leaving them behind.
const EXIT_TIMEOUT: Duration = Duration::from_millis(500);

fn main() -> color_eyre::Result<std::process::ExitCode> {
    color_eyre::install()?;
    let cli = Cli::parse();
    let cfg = config::resolve(config::Overrides {
        url: cli.url,
        token: cli.token,
        token_file: cli.token_file,
        config: cli.config,
    })?;
    let _log = init_logging();

    // Without a token, present a placeholder. The generated client sends no
    // request whose document-declared credential is missing, but a daemon
    // with authentication disabled admits any request; one with `[auth]`
    // answers the placeholder with a 401, which is what shows the password
    // prompt. An unknown token is not a failed login, so this spends nothing
    // from the daemon's password throttle.
    let token = cfg.token.as_deref().unwrap_or(api::ANONYMOUS);
    let api = api::Api::new(&cfg.url, Some(token)).map_err(|e| color_eyre::eyre::eyre!(e))?;
    let model = app::Model::new(api, theme::Theme::new(theme::Depth::detect()));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .wrap_err("start the async runtime")?;
    // `ratatui::init` puts the terminal in raw mode on the alternate screen
    // and installs a panic hook that restores it first. A panic on a
    // background task ends `run` with `Model::fatal` set.
    let mut terminal = ratatui::init();
    // However the loop ends, a session token minted from the password is
    // revoked before `run` returns (or resumes a panic in the loop),
    // including after a background task's panic.
    let looped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(runtime::run(model, &mut terminal))
    }));
    // A panic in the loop has handed the terminal back already, through the
    // hook `ratatui::init` installed, and printed its report.
    if looped.is_ok() {
        ratatui::restore();
    }
    // Dropping the runtime would wait for every blocking thread, and one
    // stuck resolving the daemon's host name (reqwest resolves on blocking
    // threads) returns only when getaddrinfo gives up: over a dead tunnel,
    // not soon. The loop has finished, so nothing on the runtime is needed
    // any more: wait briefly, then leave such a thread behind. `run` has put
    // the SIGINT and SIGTERM dispositions back, so Ctrl-C ends even this
    // wait, and left SIGHUP ignored, so a hangup's repeat does not cut off
    // the notice and the log flush below.
    runtime.shutdown_timeout(EXIT_TIMEOUT);
    let ended = looped.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    // Printed only now: on the alternate screen it would vanish with it.
    if let Some(notice) = &ended.model.exit_notice {
        eprintln!("{notice}");
    }
    ended.result.wrap_err("the terminal failed")?;
    exit_code(ended.model.fatal.as_deref(), ended.signal)
}

/// The exit status once the terminal is the user's again. A signal that
/// ended the loop decides it: 128 plus the signal's number, as a shell
/// reports a process the signal killed, not a clean exit. That holds even
/// when a background task then panicked while a minted token was being
/// revoked; the panic's reason is still printed. A panic alone fails with
/// its reason through color_eyre.
fn exit_code(
    fatal: Option<&str>,
    signal: Option<&str>,
) -> color_eyre::Result<std::process::ExitCode> {
    match (signal, fatal) {
        (Some(signal), fatal) => {
            if let Some(what) = fatal {
                eprintln!("torrentctl stopped: {what}");
            }
            Ok(runtime::signal_exit_status(signal).into())
        }
        (None, Some(what)) => color_eyre::eyre::bail!("torrentctl stopped: {what}"),
        (None, None) => Ok(std::process::ExitCode::SUCCESS),
    }
}

/// Log to a file in the XDG state directory, never to the terminal the UI
/// owns. Returns the guard that flushes it.
fn init_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use etcetera::BaseStrategy as _;
    let dir = etcetera::choose_base_strategy()
        .ok()?
        .state_dir()?
        .join("torrentctl");
    std::fs::create_dir_all(&dir).ok()?;
    let (writer, guard) =
        tracing_appender::non_blocking(tracing_appender::rolling::never(dir, "torrentctl.log"));
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("TORRENTCTL_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    Some(guard)
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::exit_code;
    use super::runtime::signal_exit_status;

    #[test]
    fn a_signal_decides_the_exit_status_even_after_a_panic() {
        let status = ExitCode::from(signal_exit_status("SIGTERM"));
        assert_eq!(exit_code(None, Some("SIGTERM")).unwrap(), status);
        assert_eq!(
            exit_code(Some("a request panicked: x"), Some("SIGTERM")).unwrap(),
            status
        );
    }

    #[test]
    fn a_panic_alone_fails_with_its_reason() {
        let err = exit_code(Some("a request panicked: x"), None).unwrap_err();
        assert_eq!(err.to_string(), "torrentctl stopped: a request panicked: x");
        assert_eq!(exit_code(None, None).unwrap(), ExitCode::SUCCESS);
    }
}
