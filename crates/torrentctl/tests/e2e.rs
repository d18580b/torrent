//! The generated client, and the `App` built on it, against a real daemon.
//!
//! `#[ignore]`d where it spawns `torrentd` with a live libtorrent session.
//! Run those with `mise run test-torrentctl`, which builds the daemon first;
//! set `TORRENTD_BIN` to use another binary.
//!
//! The generated-client tests are the other half of the contract test
//! `torrentd`'s own router tests are: those hold the handlers to the
//! document, this holds a client generated from the document — by a
//! different tool — to the handlers. The `App` tests drive what the
//! operator runs: the model, its effects spawned by the runtime, and the
//! rendered screen. Every test daemon gets its own HTTP and peer ports,
//! since the tests run in parallel.

use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyModifiers;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;
use tokio::sync::watch;
use torrentctl::api::Api;
use torrentctl::app;
use torrentctl::app::Live;
use torrentctl::app::Model;
use torrentctl::app::Msg;
use torrentctl::app::Session;
use torrentctl::app::Tab;
use torrentctl::runtime;
use torrentctl::theme::Depth;
use torrentctl::theme::Theme;

#[allow(clippy::all, clippy::pedantic, dead_code, unused, unreachable_patterns)]
mod api {
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}

use api::types;

const PROFILE: &str = "e2e";
const PASSWORD: &str = "correct-horse-battery";
const HTTP: &str = "127.0.0.1:18191";
const LISTEN_PORT: u16 = 16991;
/// The socket test's peer port. The tests run in parallel, and a daemon
/// whose only session cannot bind its listen socket exits.
const SOCKET_TEST_LISTEN_PORT: u16 = 16992;
/// The `App` test's daemon.
const APP_HTTP: &str = "127.0.0.1:18192";
const APP_LISTEN_PORT: u16 = 16993;
/// The event-stream reconnect test's daemon.
const STREAM_HTTP: &str = "127.0.0.1:18193";
const STREAM_LISTEN_PORT: u16 = 16994;
/// The session-loss test's daemon.
const RESTART_HTTP: &str = "127.0.0.1:18194";
const RESTART_LISTEN_PORT: u16 = 16995;
const MAGNET_HEX: &str = "0505050505050505050505050505050505050505";
/// How long the `App` is given to reach each state it is driven to.
const STEP: Duration = Duration::from_secs(30);

fn torrentd() -> PathBuf {
    std::env::var_os("TORRENTD_BIN").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/torrentd"),
        PathBuf::from,
    )
}

fn config(dir: &Path, auth: Option<&str>) -> PathBuf {
    config_listening(dir, auth, &format!("\"{HTTP}\""), LISTEN_PORT)
}

/// [`config`], with `listen` as the TOML value of `http_listen` and whatever
/// keys follow it, and the profile's peer socket on `port`.
fn config_listening(dir: &Path, auth: Option<&str>, listen: &str, port: u16) -> PathBuf {
    for sub in ["data", "resume", "torrents"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let access = match auth {
        Some(hash) => format!("[auth]\npassword_hash = \"{hash}\"\n"),
        None => "allow_unauthenticated = true\n".to_owned(),
    };
    let path = dir.join("cfg.toml");
    std::fs::write(
        &path,
        format!(
            "default_save_path = \"{d}/data\"\n\
             resume_dir = \"{d}/resume\"\n\
             torrent_dir = \"{d}/torrents\"\n\
             http_listen = {listen}\n\
             log_level = \"warn\"\n\
             enable_lsd = false\n\
             {access}\n\
             [[profile]]\n\
             id = \"{PROFILE}\"\n\
             network = \"host\"\n\
             listen_interfaces = \"127.0.0.1:{port}\"\n\
             dht = false\n",
            d = dir.display()
        ),
    )
    .unwrap();
    path
}

/// The Argon2id hash of [`PASSWORD`], from the daemon's own `hash-password`.
fn password_hash(dir: &Path) -> String {
    let cfg = config(dir, None);
    let mut child = Command::new(torrentd())
        .arg("--config")
        .arg(&cfg)
        .arg("hash-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run torrentd hash-password (build it first: cargo build -p torrentd)");
    writeln!(child.stdin.take().unwrap(), "{PASSWORD}").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "hash-password failed");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.0.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.0.kill();
    }
}

async fn start(dir: &Path) -> (Daemon, String) {
    let (daemon, base, _) = start_on(dir, Some(&password_hash(dir)), HTTP, LISTEN_PORT).await;
    (daemon, base)
}

/// A ready daemon on `http`, with the password whose hash is `auth` or
/// authentication disabled, and its peer socket on `port`; with its base
/// URL and its config file, to start it again from.
async fn start_on(
    dir: &Path,
    auth: Option<&str>,
    http: &str,
    port: u16,
) -> (Daemon, String, PathBuf) {
    let cfg = config_listening(dir, auth, &format!("\"{http}\""), port);
    let daemon = spawn(&cfg);
    let base = format!("http://{http}");
    wait_ready(&api::Client::new(&base).unwrap()).await;
    (daemon, base, cfg)
}

fn spawn(cfg: &Path) -> Daemon {
    let child = Command::new(torrentd())
        .arg("--config")
        .arg(cfg)
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn torrentd");
    Daemon(child)
}

async fn wait_ready(client: &api::Client) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(ok) = client.get_health().await {
            if ok.into_inner().ok {
                break;
            }
        }
        assert!(Instant::now() < deadline, "the daemon did not become ready");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A generated client that connects to the unix socket at `path`.
fn socket_client(path: &Path) -> api::Client {
    let http = reqwest::Client::builder()
        .unix_socket(path)
        .build()
        .unwrap();
    api::Client::with_client(http, "http://localhost").unwrap()
}

#[tokio::test]
#[ignore = "spawns torrentd; run with `mise run test-torrentctl`"]
async fn a_daemon_on_a_unix_socket_serves_the_api_there_with_the_configured_mode() {
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let hash = password_hash(dir.path());
    let sock = dir.path().join("api.sock");
    let cfg = config_listening(
        dir.path(),
        Some(&hash),
        &format!("\"unix:{}\"\nhttp_socket_mode = 0o600", sock.display()),
        SOCKET_TEST_LISTEN_PORT,
    );
    let daemon = spawn(&cfg);
    let anonymous = socket_client(&sock);
    wait_ready(&anonymous).await;

    let meta = std::fs::symlink_metadata(&sock).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    // A login: the request body reaches the handler, and the throttle's
    // reading of the peer address holds for a socket peer.
    let grant = anonymous
        .create_session(&types::CreateSession {
            password: PASSWORD.to_owned(),
        })
        .await
        .expect("sign in over the socket")
        .into_inner();
    let client = socket_client(&sock).with_credential(
        "bearer",
        api::Credential::Bearer(api::SecretString::from(grant.token)),
    );
    let server = client.get_server().await.unwrap().into_inner();
    assert_eq!(server.api_version, "1");

    // A streamed response is delivered as it is written.
    let mut events = client.stream_events().await.expect("open /v1/events");
    let first = tokio::time::timeout(Duration::from_secs(15), events.next())
        .await
        .expect("a tick within 15s")
        .expect("the stream stays open")
        .expect("a well-formed event");
    assert!(matches!(first.kind, types::ServerEventkind::Tick));
    drop(events);

    drop(daemon);
    assert!(!sock.exists(), "a stopped daemon removes its socket");
}

#[tokio::test]
#[ignore = "spawns torrentd; run with `mise run test-torrentctl`"]
async fn the_generated_client_drives_a_real_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let (_daemon, base) = start(dir.path()).await;

    // Unauthenticated: every guarded operation is refused, and the error is
    // a typed documented one.
    let anonymous = api::Client::new(&base).unwrap();
    let err = anonymous.get_status().await.unwrap_err();
    assert!(
        matches!(err, api::Error::RequestConstruction(_)),
        "no credential registered: refused before sending, {err:?}"
    );

    // The password buys a session token.
    let grant = anonymous
        .create_session(&types::CreateSession {
            password: PASSWORD.to_owned(),
        })
        .await
        .expect("sign in")
        .into_inner();
    assert!(grant.token.starts_with("tds_"), "{}", grant.token);
    let client = api::Client::new(&base).unwrap().with_credential(
        "bearer",
        api::Credential::Bearer(api::SecretString::from(grant.token.clone())),
    );

    let server = client.get_server().await.unwrap().into_inner();
    assert_eq!(server.api_version, "1");
    assert!(!server.pool.configured);
    let me = client.get_current_session().await.unwrap().into_inner();
    assert!(matches!(me.kind, types::PrincipalKind::Session));

    let profiles = client.list_profiles().await.unwrap().into_inner();
    assert_eq!(profiles.items[0].profile_id, PROFILE);

    // Add a magnet and find it again.
    let added = client
        .add_torrent(&types::AddTorrentRequest {
            profile_id: PROFILE.to_owned(),
            save_path: None,
            source: types::TorrentSource::TorrentSourceVariant0(Box::new(
                types::TorrentSourceVariant0 {
                    kind: types::TorrentSourceVariant0kind::Magnet,
                    uri: format!("magnet:?xt=urn:btih:{MAGNET_HEX}&dn=e2e"),
                },
            )),
        })
        .await
        .expect("add a magnet")
        .into_inner();
    assert_eq!(added.infohash, MAGNET_HEX);
    let page = client
        .list_torrents(api::ListTorrentsParams {
            profile_id: Some(PROFILE.to_owned()),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(page.items.iter().any(|t| t.infohash == MAGNET_HEX));
    assert!(page.next_cursor.is_none());

    // A duplicate is a documented 409, carried as a problem document.
    let err = client
        .add_torrent(&types::AddTorrentRequest {
            profile_id: PROFILE.to_owned(),
            save_path: None,
            source: types::TorrentSource::TorrentSourceVariant0(Box::new(
                types::TorrentSourceVariant0 {
                    kind: types::TorrentSourceVariant0kind::Magnet,
                    uri: format!("magnet:?xt=urn:btih:{MAGNET_HEX}"),
                },
            )),
        })
        .await
        .unwrap_err();
    match err {
        api::Error::Api(response) => {
            assert_eq!(response.status().as_u16(), 409);
            assert!(matches!(
                response.into_inner(),
                api::AddTorrentError::Status409(_)
            ));
        }
        other => panic!("expected the documented 409, got {other:?}"),
    }

    // The event stream delivers a typed tick.
    let mut events = client.stream_events().await.expect("open /v1/events");
    let first = tokio::time::timeout(Duration::from_secs(15), events.next())
        .await
        .expect("a tick within 15s")
        .expect("the stream stays open")
        .expect("a well-formed event");
    assert!(matches!(first.kind, types::ServerEventkind::Tick));
    assert_eq!(first.fingerprint.len(), 16);

    // Revoking the session ends it.
    client.delete_current_session().await.expect("sign out");
    let err = client.get_status().await.unwrap_err();
    match err {
        api::Error::Api(response) => assert_eq!(response.status().as_u16(), 401),
        other => panic!("a revoked token is a 401, got {other:?}"),
    }
}

/// The `App` as `runtime::run` drives it, with keys typed by the test
/// instead of read from a terminal: each message goes through
/// `app::update`, and the effects it returns are spawned by
/// `runtime::spawn`, whose messages come back on `rx`.
struct Driver {
    model: Model,
    tx: mpsc::UnboundedSender<Msg>,
    rx: mpsc::UnboundedReceiver<Msg>,
}

impl Driver {
    /// A model on `api`, asking the daemon who it is, as the loop's start
    /// does.
    fn start(api: Api) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        runtime::spawn(&tx, vec![app::check_session(&api)]);
        Self {
            model: Model::new(api, Theme::new(Depth::Mono)),
            tx,
            rx,
        }
    }

    fn send(&mut self, msg: Msg) {
        let effects = app::update(&mut self.model, msg);
        runtime::spawn(&self.tx, effects);
    }

    fn key(&mut self, code: KeyCode) {
        self.send(Msg::Key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    fn type_text(&mut self, text: &str) {
        for c in text.chars() {
            self.key(KeyCode::Char(c));
        }
    }

    /// Apply the effects' messages until `done` holds, failing after
    /// [`STEP`] with what was on screen.
    async fn until(&mut self, what: &str, done: impl Fn(&Model) -> bool) {
        let deadline = tokio::time::Instant::now() + STEP;
        while !done(&self.model) {
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(msg)) => self.send(msg),
                Ok(None) => unreachable!("the driver holds a sender"),
                Err(_) => panic!("{what}: not within {STEP:?}\n{}", self.screen()),
            }
        }
    }

    /// The screen at 160x48, one line per row, trailing spaces trimmed.
    fn screen(&self) -> String {
        let mut terminal = Terminal::new(TestBackend::new(160, 48)).unwrap();
        terminal
            .draw(|frame| torrentctl::ui::view(&self.model, frame))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            let line: String = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}

/// Wait for `follow_events` to report `wanted`, skipping change
/// notifications and other states on the way.
async fn live(rx: &mut mpsc::UnboundedReceiver<Msg>, within: Duration, wanted: fn(&Live) -> bool) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Msg::LiveChanged(state))) if wanted(&state) => return,
            Ok(Some(_)) => {}
            Ok(None) => panic!("follow_events stopped"),
            Err(_) => panic!("the event stream did not reach the state within {within:?}"),
        }
    }
}

#[tokio::test]
#[ignore = "spawns torrentd; run with `mise run test-torrentctl`"]
async fn app_against_daemon_logs_in_lists_and_quits() {
    let dir = tempfile::tempdir().unwrap();
    let hash = password_hash(dir.path());
    let (_daemon, base, _) = start_on(dir.path(), Some(&hash), APP_HTTP, APP_LISTEN_PORT).await;

    // No token: the placeholder `main` presents, which the daemon refuses,
    // so the password prompt is what comes up.
    let mut app = Driver::start(Api::new(&base, Some(torrentctl::api::ANONYMOUS)).unwrap());
    app.until("the sign-in prompt", |m| {
        matches!(m.session, Session::SignedOut)
    })
    .await;
    assert!(app.screen().contains("password"), "{}", app.screen());

    app.type_text(PASSWORD);
    app.key(KeyCode::Enter);
    app.until("signed in", |m| {
        matches!(m.session, Session::SignedIn { .. })
    })
    .await;
    assert!(app.model.minted, "the token came from the password");
    let minted = app.model.api.clone();

    // Add a magnet through the palette's `add`, into the one profile.
    app.key(KeyCode::Char(':'));
    app.type_text("add");
    app.key(KeyCode::Enter);
    assert_eq!(app.model.tab, Tab::Torrents);
    app.until("the profiles in the add dialog", |m| {
        !m.torrents.profiles_loading && !m.torrents.profiles.is_empty()
    })
    .await;
    app.type_text(&format!("magnet:?xt=urn:btih:{MAGNET_HEX}&dn=e2e"));
    app.key(KeyCode::Down);
    app.key(KeyCode::Right);
    assert_eq!(
        app.model
            .torrents
            .add
            .as_ref()
            .and_then(|d| d.profile.as_deref()),
        Some(PROFILE)
    );
    app.key(KeyCode::Enter);
    app.until("the added magnet listed", |m| {
        m.torrents.add.is_none()
            && !m.torrents.list.loading
            && m.torrents
                .list
                .items
                .iter()
                .any(|t| t.infohash == MAGNET_HEX)
    })
    .await;
    let screen = app.screen();
    let short = &MAGNET_HEX[..12];
    let row = screen
        .lines()
        .find(|line| line.contains(short) && line.contains(PROFILE) && !line.contains("added"))
        .unwrap_or_else(|| panic!("a list row for {short} in {PROFILE}:\n{screen}"));
    assert!(row.contains(short), "{row}");
    assert!(
        screen.contains(&format!("· {short} to {PROFILE}")),
        "the success toast:\n{screen}"
    );

    // `q` revokes the minted token before leaving.
    app.key(KeyCode::Char('q'));
    assert!(
        app.model.quitting && !app.model.quit,
        "waits for the revocation"
    );
    app.until("quit", |m| m.quit).await;
    let refused = torrentctl::api::call(minted.client.get_current_session())
        .await
        .expect_err("a revoked token is refused");
    assert_eq!(refused.status, Some(401), "{refused:?}");
}

#[tokio::test]
#[ignore = "spawns torrentd; run with `mise run test-torrentctl`"]
async fn follow_events_reconnects_after_daemon_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, base, cfg) = start_on(dir.path(), None, STREAM_HTTP, STREAM_LISTEN_PORT).await;
    let api = Api::new(&base, Some(torrentctl::api::ANONYMOUS)).unwrap();
    let (api_tx, api_rx) = watch::channel(api);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let follower = tokio::spawn(runtime::follow_events(api_rx, tx));

    live(&mut rx, Duration::from_secs(15), |l| *l == Live::Streaming).await;
    drop(daemon);
    live(&mut rx, Duration::from_secs(15), |l| {
        matches!(l, Live::Reconnecting { .. })
    })
    .await;

    // The same port again: the stream comes back on its own, within the
    // backoff (1s, doubling, at most 30s, never under the daemon's 5s retry).
    let _daemon = spawn(&cfg);
    live(&mut rx, Duration::from_secs(60), |l| *l == Live::Streaming).await;

    drop(api_tx);
    follower.abort();
}

#[tokio::test]
#[ignore = "spawns torrentd; run with `mise run test-torrentctl`"]
async fn a_session_does_not_survive_a_daemon_restart() {
    let dir = tempfile::tempdir().unwrap();
    let hash = password_hash(dir.path());
    let (daemon, base, cfg) =
        start_on(dir.path(), Some(&hash), RESTART_HTTP, RESTART_LISTEN_PORT).await;
    let grant = api::Client::new(&base)
        .unwrap()
        .create_session(&types::CreateSession {
            password: PASSWORD.to_owned(),
        })
        .await
        .expect("sign in")
        .into_inner();
    let client = api::Client::new(&base).unwrap().with_credential(
        "bearer",
        api::Credential::Bearer(api::SecretString::from(grant.token)),
    );
    client
        .get_current_session()
        .await
        .expect("the session works before the restart");

    // Sessions live in the daemon's memory only.
    drop(daemon);
    let _daemon = spawn(&cfg);
    wait_ready(&api::Client::new(&base).unwrap()).await;
    match client.get_current_session().await.unwrap_err() {
        api::Error::Api(response) => assert_eq!(response.status().as_u16(), 401),
        other => panic!("a session from before the restart is a 401, got {other:?}"),
    }
}

/// A panic inside the loop hands the terminal back: run under a pty, the
/// binary enters the alternate screen, leaves it ahead of the panic report,
/// shows the cursor again, and leaves the pty out of raw mode. Needs no
/// daemon, so it is not ignored.
#[test]
fn a_panic_hands_the_terminal_back() {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::os::fd::FromRawFd as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::process::CommandExt as _;

    let (master, slave) = {
        let mut master = -1;
        let mut slave = -1;
        let size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty writes two descriptors it opened into the
        // pointers it is given; the name and termios are optional.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: both descriptors were just opened and are owned here.
        unsafe {
            (
                std::fs::File::from(OwnedFd::from_raw_fd(master)),
                OwnedFd::from_raw_fd(slave),
            )
        }
    };

    let home = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_torrentctl"));
    command
        .args(["--url", "http://127.0.0.1:9"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("TERM", "xterm-256color")
        .env("RUST_BACKTRACE", "0")
        .env(torrentctl::runtime::PANIC_AFTER_DRAW, "1")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe calls between fork and exec: a new
    // session, with the pty on stdin as its controlling terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("run torrentctl");
    // The child holds the only copies of the pty's other end now.
    drop(command);

    // Read on a thread until the child closes its end (Linux reports that as
    // EIO), so a binary that neither panics nor exits fails the test at a
    // deadline instead of hanging it.
    let mut reader = master.try_clone().unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];
        let result = loop {
            match reader.read(&mut buf) {
                Ok(0) => break Ok(output),
                Ok(n) => output.extend_from_slice(&buf[..n]),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break Ok(output),
                Err(e) => break Err(e),
            }
        };
        let _ = done.send(result);
    });
    let output = match finished.recv_timeout(STEP) {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => panic!("read the pty ({}): {e}", master.as_raw_fd()),
        Err(_) => {
            // Killing the child closes its end, which ends the reader too.
            let _ = child.kill();
            let _ = child.wait();
            panic!("torrentctl neither panicked nor exited within {STEP:?}");
        }
    };
    let status = child.wait().unwrap();
    let output = String::from_utf8_lossy(&output);
    assert!(!status.success(), "a panic is a failure exit: {output:?}");

    const ENTER_ALTERNATE: &str = "\x1b[?1049h";
    const LEAVE_ALTERNATE: &str = "\x1b[?1049l";
    const SHOW_CURSOR: &str = "\x1b[?25h";
    let entered = output
        .find(ENTER_ALTERNATE)
        .unwrap_or_else(|| panic!("never entered the alternate screen: {output:?}"));
    let left = output[entered..]
        .find(LEAVE_ALTERNATE)
        .map(|at| entered + at)
        .unwrap_or_else(|| panic!("never left the alternate screen: {output:?}"));
    let report = output
        .find("TORRENTCTL_TEST_PANIC is set")
        .unwrap_or_else(|| panic!("no panic report: {output:?}"));
    assert!(
        left < report,
        "the alternate screen is left before the report prints, so it stays \
         on the operator's screen: {output:?}"
    );
    // The cursor comes back as the unwinding drops the terminal, after the
    // report.
    assert!(
        output[entered..].contains(SHOW_CURSOR),
        "the cursor is shown again: {output:?}"
    );
    // And the pty is out of raw mode: line editing and echo are back.
    // SAFETY: `termios` is plain data, filled in by tcgetattr on a
    // descriptor this test owns.
    let lflag = unsafe {
        let mut termios: libc::termios = std::mem::zeroed();
        assert_eq!(
            libc::tcgetattr(master.as_raw_fd(), &mut termios),
            0,
            "tcgetattr: {}",
            std::io::Error::last_os_error()
        );
        termios.c_lflag
    };
    assert_ne!(lflag & libc::ICANON, 0, "canonical mode restored");
    assert_ne!(lflag & libc::ECHO, 0, "echo restored");
}

/// A token no request could carry stops the binary before it takes the
/// terminal, with a message naming where the token came from — rather than
/// a UI reporting an unreachable daemon every few seconds. Needs no daemon
/// and no terminal, so it is not ignored.
#[test]
fn a_malformed_token_is_refused_before_the_terminal_is_taken() {
    const TOKEN: &str = "tdp_bad\u{1}token";
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_torrentctl"))
        .args(["--url", "http://127.0.0.1:9"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("TERM", "xterm-256color")
        .env("TORRENTCTL_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .output()
        .expect("run torrentctl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("the token from TORRENTCTL_TOKEN is not valid"),
        "{stderr}"
    );
    assert!(!stderr.contains(TOKEN), "the token never prints: {stderr}");
    assert!(
        !stdout.contains("\x1b[?1049h"),
        "the alternate screen is never entered: {stdout:?}"
    );
}
