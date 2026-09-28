//! `torrentctl`: a terminal client for torrentd's `/v1` API.
//!
//! It talks to the daemon only through a client spargen generates from the
//! committed OpenAPI document, so it exercises the same contract any other
//! client would.

mod api;
mod app;
mod config;
mod fmt;
mod runtime;
mod screens;
#[cfg(test)]
mod testing;
mod theme;
mod ui;

use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::WrapErr as _;

/// A terminal client for torrentd.
#[derive(Debug, Parser)]
#[command(name = "torrentctl", version, about)]
struct Cli {
    /// The daemon's base URL [env: TORRENTCTL_URL] [default: http://127.0.0.1:8080].
    #[arg(long, value_name = "URL")]
    url: Option<String>,
    /// A bearer token (`tdp_…`). Prefer --token-file or TORRENTCTL_TOKEN: a
    /// token on the command line is visible in the process list.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
    /// A file holding a bearer token; it must be mode 0600.
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
    /// The config file [default: $XDG_CONFIG_HOME/torrentctl/config.toml].
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

fn main() -> color_eyre::Result<()> {
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
    // and installs a panic hook that restores it first.
    let mut terminal = ratatui::init();
    let result = runtime.block_on(runtime::run(model, &mut terminal));
    ratatui::restore();
    result.wrap_err("the terminal failed")
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
