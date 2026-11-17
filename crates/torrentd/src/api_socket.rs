//! The control API on a unix socket: `http_listen = "unix:/path"`.
//!
//! kynos' listeners are TCP only, so this module owns the accept loop and
//! hands each accepted stream to [`Server::serve_io`], which serves it as a
//! TCP connection is served: HTTP/1.1 or HTTP/2 (h2c) told apart from the
//! first bytes, under the TCP server's protocol settings
//! ([`crate::startup::http_server`]), with request bodies streamed to the
//! route, which authorizes the request and then reads its body under its own
//! cap and deadline.
//!
//! What `serve_io` leaves to the caller stays here: at most
//! `max_connections` open at once, and a bounded drain on shutdown. Every
//! request reaches the router from [`SOCKET_PEER`], an address no socket
//! connects from, so no `trusted_proxies` entry admits a forwarding header
//! sent over the socket. Who called is logged by uid and pid (`SO_PEERCRED`)
//! on the connection's span instead.
//!
//! [`Server::serve_io`]: kynos::server::Server::serve_io

use std::net::SocketAddr;
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kynos::router::service::Service;
use tokio::sync::broadcast;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use torrentd_engine::ShutdownReason;
use tracing::debug;
use tracing::info;
use tracing::warn;
use tracing::Instrument as _;

/// The peer address every request over the socket carries: unspecified, so
/// it names no host and matches no `trusted_proxies` entry.
pub const SOCKET_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// A bound API socket. Dropping it closes the listener and removes the socket
/// file.
#[derive(Debug)]
pub struct ApiSocket {
    listener: tokio::net::UnixListener,
    file: SocketFile,
}

impl ApiSocket {
    /// The socket's path.
    pub fn path(&self) -> &Path {
        &self.file.path
    }
}

/// The socket file a bind created. Dropping it removes the file, if the file
/// at its path is still that one: a later run that replaced it keeps its own.
#[derive(Debug)]
struct SocketFile {
    path: PathBuf,
    /// `(st_dev, st_ino)` of the file.
    id: (u64, u64),
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let ours = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == self.id);
        if ours {
            if let Err(e) = std::fs::remove_file(&self.path) {
                warn!(path = %self.path.display(), error.cause = %e, "remove the API socket");
            }
        }
    }
}

/// Bind the API socket at `path` with permission bits `mode` and, when
/// given, group `group` (a name or a number).
///
/// A socket file already at `path` that nothing answers on is a previous
/// run's, and is replaced. One that answers belongs to a running process, and
/// anything at `path` that is not a socket is somebody's file: both refuse.
///
/// The socket is bound in a private staging directory beside `path` (see
/// [`staging_paths`]), given its mode and group, and only then renamed into
/// place, so the configured path never names a socket with any other
/// permissions. The directory is mode `0700` whatever the umask, so while the
/// socket still has the umask's permissions only the daemon's own user can
/// connect to it, and no connection another user queued then is accepted
/// after the rename. Must run inside a tokio runtime.
pub fn bind(path: &Path, mode: u32, group: Option<&str>) -> anyhow::Result<ApiSocket> {
    use std::os::unix::fs::DirBuilderExt as _;

    use anyhow::Context as _;

    let gid = group.map(resolve_group).transpose()?;
    clear_stale(path)?;

    let (staging, temp) = staging_paths(path, std::process::id())
        .with_context(|| format!("{} names no file", path.display()))?;
    // A leftover from a run of this pid that died between bind and rename.
    // ignore-result: usually there is none; one that stays fails the mkdir
    // or bind below, which reports it.
    let _ = std::fs::remove_file(&temp);
    // ignore-result: as above.
    let _ = std::fs::remove_dir(&staging);

    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .with_context(|| format!("create the staging directory {}", staging.display()))?;
    let placed = (|| -> anyhow::Result<(tokio::net::UnixListener, std::fs::Metadata)> {
        let listener = tokio::net::UnixListener::bind(&temp)
            .with_context(|| format!("bind the API socket at {}", temp.display()))?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} {}", temp.display()))?;
        if let Some(gid) = gid {
            std::os::unix::fs::chown(&temp, None, Some(gid))
                .with_context(|| format!("chgrp {gid} {}", temp.display()))?;
        }
        std::fs::rename(&temp, path)
            .with_context(|| format!("rename {} to {}", temp.display(), path.display()))?;
        let meta =
            std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        Ok((listener, meta))
    })();
    // ignore-result: after the rename there is no temp to remove, and a
    // failure before it is the error `placed` carries.
    let _ = std::fs::remove_file(&temp);
    if let Err(e) = std::fs::remove_dir(&staging) {
        warn!(path = %staging.display(), error.cause = %e, "remove the API socket's staging directory");
    }
    let (listener, meta) = placed?;
    Ok(ApiSocket {
        listener,
        file: SocketFile {
            path: path.to_owned(),
            id: (meta.dev(), meta.ino()),
        },
    })
}

/// Where a socket at `path` is bound before it is renamed into place, by the
/// process with id `pid`: a directory `.<name>.<pid>` beside it, and the
/// socket `s` inside that. `None` when `path` names no file.
///
/// The staged socket's path is longer than `path`, by at most 14 bytes for
/// any pid, so configuration validation holds `path` to the length this
/// returns for the longest pid, not to `path`'s own.
pub fn staging_paths(path: &Path, pid: u32) -> Option<(PathBuf, PathBuf)> {
    let mut dir_name = std::ffi::OsString::from(".");
    dir_name.push(path.file_name()?);
    dir_name.push(format!(".{pid}"));
    let dir = path.with_file_name(dir_name);
    let socket = dir.join("s");
    Some((dir, socket))
}

/// Remove a socket at `path` that no process answers on; refuse one that
/// does, and anything that is not a socket.
fn clear_stale(path: &Path) -> anyhow::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow::anyhow!(e).context(format!("stat {}", path.display()))),
    };
    if !meta.file_type().is_socket() {
        anyhow::bail!(
            "{} exists and is not a socket; the daemon replaces only a socket a previous run \
             left behind. Move the file, or point http_listen at another path.",
            path.display()
        );
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => anyhow::bail!(
            "{} is a socket another process is serving on; is a second daemon running with \
             this http_listen?",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)
                .map_err(|e| anyhow::anyhow!(e).context(format!("remove {}", path.display())))?;
            info!(path = %path.display(), "removed the API socket a previous run left behind");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(e).context(format!(
            "connect to the socket already at {} to tell whether it is in use",
            path.display()
        ))),
    }
}

/// The gid `group` names: a number as is, a name through the system's group
/// database.
fn resolve_group(group: &str) -> anyhow::Result<u32> {
    if let Ok(gid) = group.parse::<u32>() {
        return Ok(gid);
    }
    let name = std::ffi::CString::new(group)
        .map_err(|_| anyhow::anyhow!("http_socket_group {group:?} contains a NUL byte"))?;
    let mut buf = vec![0_u8; 1024];
    loop {
        // SAFETY: an all-zero `group` is a valid value of the plain C struct,
        // which `getgrnam_r` only writes.
        let mut entry: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local of the type the call
        // expects, and `buf.len()` is the length of the buffer passed.
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &raw mut entry,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 4, 0);
            continue;
        }
        if rc != 0 {
            return Err(anyhow::anyhow!(std::io::Error::from_raw_os_error(rc))
                .context(format!("look up http_socket_group {group:?}")));
        }
        if result.is_null() {
            anyhow::bail!("http_socket_group {group:?} names no group on this host");
        }
        return Ok(entry.gr_gid);
    }
}

/// Limits the socket server keeps; the TCP server's, passed in from startup.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_connections: usize,
    /// How long a connection may take to send a request head: its first one
    /// from accept, under either protocol, and each later HTTP/1 one.
    pub header_read_timeout: Duration,
    pub drain_timeout: Duration,
}

/// The longest wait between two accepts that failed.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Serve `app` on `socket` until a shutdown arrives on `shutdown_rx`, then
/// run `on_shutdown`, stop accepting, and wait up to `limits.drain_timeout`
/// for the open connections to end before cutting off the rest.
///
/// `serve_io` has no graceful shutdown of its own, so a connection is not
/// asked to close: one with a request in flight ends once its client closes
/// it, as a `Connection: close` request does once it is answered, and an
/// idle one ends at its client's close, its next head's
/// `header_read_timeout`, or the HTTP/2 idle timeout, whichever comes first.
///
/// A failing accept is retried after a doubling backoff rather than ending
/// the server: running out of descriptors passes as connections close, and
/// stopping the daemon for it tears down every session to fix it.
pub async fn serve(
    socket: ApiSocket,
    app: Service<crate::http::ctx::AppCtx>,
    mut shutdown_rx: broadcast::Receiver<ShutdownReason>,
    on_shutdown: impl FnOnce(),
    limits: Limits,
) {
    let server = crate::startup::http_server(app).http1(
        kynos::server::protocol::http1::Http1Config::default()
            .header_read_timeout(Some(limits.header_read_timeout)),
    );
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut connections = JoinSet::new();
    let mut backoff = Duration::from_millis(10);

    loop {
        while connections.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            _ = shutdown_rx.recv() => break,
            permit = Arc::clone(&permits).acquire_owned() => {
                permit.expect("the semaphore is never closed")
            }
        };
        let accepted = tokio::select! {
            biased;
            _ = shutdown_rx.recv() => break,
            accepted = socket.listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _)) => {
                backoff = Duration::from_millis(10);
                let cred = stream.peer_cred().ok();
                let span = tracing::info_span!(
                    "api_socket",
                    peer.uid = cred.map(|c| c.uid()),
                    peer.pid = cred.and_then(|c| c.pid()),
                );
                let connection = match server.serve_io(stream, SOCKET_PEER) {
                    Ok(connection) => connection,
                    Err(e) => {
                        // Only a refused configuration fails here, and the
                        // server's is fixed at build time: unreachable unless
                        // `http_server` sets a value kynos refuses.
                        warn!(error.cause = %e, "the API socket's server configuration was refused");
                        continue;
                    }
                };
                connections.spawn(
                    async move {
                        let _permit = permit;
                        if let Err(e) = connection.await {
                            debug!(error.cause = %e, "API socket connection ended with an error");
                        }
                    }
                    .instrument(span),
                );
            }
            Err(e) => {
                drop(permit);
                warn!(
                    path = %socket.path().display(),
                    error.cause = %e,
                    retry_in_ms = backoff.as_millis(),
                    "accept on the API socket failed; retrying after a backoff",
                );
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    () = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
            }
        }
    }

    on_shutdown();
    // Closed before the drain, so a client connecting now is refused at once
    // rather than queued on a listener nothing accepts from.
    drop(socket);
    let drained = tokio::time::timeout(limits.drain_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        warn!(
            timeout_secs = limits.drain_timeout.as_secs(),
            open = connections.len(),
            "API socket drain timed out; the connections still open were cut off",
        );
        connections.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::http::v1::MAX_ADD_BODY_BYTES;
    use crate::http::v1::MAX_BODY_BYTES;

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    /// What a bind left in `dir` beside the socket: a staging directory or
    /// a socket in it, which a bind must never leave.
    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect()
    }

    /// A gid this process is not a member of, so chgrp to it fails; `None`
    /// as root, which may chgrp to anything.
    fn foreign_gid() -> Option<u32> {
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return None;
        }
        // SAFETY: called with a zero size, `getgroups` only counts.
        let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        let mut groups = vec![0; usize::try_from(n).unwrap()];
        // SAFETY: `groups` holds `n` entries.
        let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
        groups.truncate(usize::try_from(n).unwrap());
        // SAFETY: `getgid` has no preconditions.
        groups.push(unsafe { libc::getgid() });
        (1..).find(|gid| !groups.contains(gid))
    }

    #[tokio::test]
    async fn a_bind_that_fails_after_binding_leaves_no_socket_and_no_staging_directory() {
        let Some(gid) = foreign_gid() else {
            // CI runs as a non-root user, so there the skip is a failure.
            assert!(
                std::env::var_os("CI").is_none(),
                "root may chgrp to any gid, so this case cannot be built: \
                 CI must run the tests as a non-root user"
            );
            eprintln!("skipped: root may chgrp to any gid");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let msg = format!(
            "{:#}",
            bind(&path, 0o660, Some(&gid.to_string())).unwrap_err()
        );
        assert!(msg.contains(&format!("chgrp {gid}")), "got: {msg}");
        assert!(!path.exists(), "nothing was renamed into place");
        assert!(
            leftovers(dir.path()).is_empty(),
            "{:?}",
            leftovers(dir.path())
        );
        // The next bind is not in the way of anything the failed one left.
        drop(bind(&path, 0o600, None).unwrap());
    }

    #[tokio::test]
    async fn dropping_a_socket_keeps_a_file_that_replaced_it_at_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let socket = bind(&path, 0o600, None).unwrap();
        // Another process removed the socket and bound its own there.
        std::fs::remove_file(&path).unwrap();
        let other = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(socket);
        assert!(
            std::fs::symlink_metadata(&path).is_ok(),
            "the other socket is not this one's to remove"
        );
        assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
        drop(other);
    }

    #[test]
    fn a_staging_path_is_a_private_directory_beside_the_socket() {
        let (dir, socket) = staging_paths(Path::new("/run/torrentd/api.sock"), 4242).unwrap();
        assert_eq!(dir, Path::new("/run/torrentd/.api.sock.4242"));
        assert_eq!(socket, Path::new("/run/torrentd/.api.sock.4242/s"));
        assert!(staging_paths(Path::new("/"), 1).is_none());
    }

    #[tokio::test]
    async fn the_socket_is_created_with_the_configured_mode_and_group_and_removed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        // The process's own gid, by number: the one group a test may chgrp to.
        // SAFETY: `getgid` has no preconditions.
        let gid = unsafe { libc::getgid() };
        for mode in [0o660, 0o600] {
            let socket = bind(&path, mode, Some(&gid.to_string())).unwrap();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            assert!(meta.file_type().is_socket());
            assert_eq!(mode_of(&path), mode, "{mode:o}");
            assert_eq!(meta.gid(), gid);
            assert_eq!(socket.path(), path);
            assert!(
                leftovers(dir.path()).is_empty(),
                "{:?}",
                leftovers(dir.path())
            );
            drop(socket);
            assert!(!path.exists(), "dropping the socket removes its file");
        }
    }

    #[tokio::test]
    async fn a_stale_socket_is_replaced_and_a_live_socket_or_other_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");

        // A socket nothing listens on: what a killed daemon leaves.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let live = bind(&path, 0o600, None).unwrap();

        let msg = format!("{:#}", bind(&path, 0o600, None).unwrap_err());
        assert!(msg.contains("another process is serving"), "got: {msg}");
        assert!(path.exists(), "the live socket is left alone");
        drop(live);

        std::fs::write(&path, "not a socket").unwrap();
        let msg = format!("{:#}", bind(&path, 0o600, None).unwrap_err());
        assert!(msg.contains("not a socket"), "got: {msg}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a socket");
    }

    #[test]
    fn a_group_is_resolved_by_number_or_name_and_an_unknown_one_is_refused() {
        assert_eq!(resolve_group("4242").unwrap(), 4242);
        assert_eq!(resolve_group("root").unwrap(), 0);
        let msg = format!(
            "{:#}",
            resolve_group("torrentd-no-such-group-332").unwrap_err()
        );
        assert!(msg.contains("names no group"), "got: {msg}");
    }

    /// One HTTP/1.1 exchange on `path`, the response read to its end.
    async fn exchange(path: &Path, request: &str) -> String {
        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    /// A socket server over the test router, running.
    struct Running {
        _dir: tempfile::TempDir,
        path: PathBuf,
        tx: broadcast::Sender<ShutdownReason>,
        server: tokio::task::JoinHandle<()>,
        hook_rx: tokio::sync::oneshot::Receiver<()>,
    }

    fn start(limits: Limits) -> Running {
        start_with(limits, crate::app_state::build_test_state(None))
    }

    fn start_with(limits: Limits, state: crate::app_state::AppState) -> Running {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let socket = bind(&path, 0o600, None).unwrap();
        let openapi = crate::http::OpenApiJson(Arc::new(bytes::Bytes::from(
            crate::http::document_json().unwrap(),
        )));
        let app = crate::http::service(state, openapi).unwrap();
        let (tx, rx) = broadcast::channel(1);
        let (hook_tx, hook_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve(
            socket,
            app,
            rx,
            move || {
                let _ = hook_tx.send(());
            },
            limits,
        ));
        Running {
            _dir: dir,
            path,
            tx,
            server,
            hook_rx,
        }
    }

    const LIMITS: Limits = Limits {
        max_connections: 4,
        header_read_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(5),
    };

    /// A request head for `POST /v1/sessions` with a declared `length`.
    fn login_head(length: usize) -> String {
        format!(
            "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {length}\r\n\r\n"
        )
    }

    /// Each route holds its body to its own cap, as over TCP: 64 KiB
    /// everywhere but the add-torrent route, refused from the declared
    /// length before a byte of it is read.
    #[tokio::test]
    async fn a_body_over_its_routes_cap_is_refused_from_the_head_except_when_adding_a_torrent() {
        let Running {
            _dir,
            path,
            tx,
            server,
            ..
        } = start(LIMITS);

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            exchange(&path, &login_head(MAX_BODY_BYTES + 1)),
        )
        .await
        .expect("refused at once");
        assert!(response.starts_with("HTTP/1.1 413"), "got: {response:.300}");
        assert!(
            response.contains("application/problem+json"),
            "got: {response:.600}"
        );

        // The same size to the add route is read whole and reaches it.
        let body = format!("{{{}", " ".repeat(MAX_BODY_BYTES));
        let response = exchange(
            &path,
            &format!(
                "POST /v1/torrents HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 4"), "got: {response:.300}");
        assert!(
            !response.starts_with("HTTP/1.1 413"),
            "got: {response:.300}"
        );

        tx.send(ShutdownReason::Sigterm).unwrap();
        server.await.unwrap();
    }

    /// A request that is refused is refused before its body is read: with
    /// `[auth]` on, an add-torrent request with no credential that declares
    /// its whole cap and sends none of it is answered `401` at once, so the
    /// socket holds no body for a caller that is not signed in.
    #[tokio::test]
    async fn an_unauthenticated_body_is_refused_without_being_read() {
        let mut state = crate::app_state::build_test_state(None);
        state.auth = Some(crate::auth::Auth::new(crate::auth::AuthConfig {
            password_hash: crate::auth::hash_password("correct-horse-battery").unwrap(),
            session_ttl_secs: 3600,
            token: Vec::new(),
        }));
        let Running {
            _dir,
            path,
            tx,
            server,
            ..
        } = start_with(LIMITS, state);

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            exchange(
                &path,
                &format!(
                    "POST /v1/torrents HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
                     Content-Type: application/json\r\nContent-Length: {MAX_ADD_BODY_BYTES}\r\n\r\n"
                ),
            ),
        )
        .await
        .expect("refused at once");
        assert!(response.starts_with("HTTP/1.1 401"), "got: {response:.300}");

        tx.send(ShutdownReason::Sigterm).unwrap();
        server.await.unwrap();
    }

    /// HTTP/2 with prior knowledge (h2c) is served on the socket, as on TCP:
    /// the server answers the client preface with its own SETTINGS frame.
    #[tokio::test]
    async fn http2_is_served_on_the_socket() {
        let Running {
            _dir,
            path,
            tx,
            server,
            ..
        } = start(LIMITS);

        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        // The client connection preface, then an empty SETTINGS frame:
        // length 0, type 0x4, no flags, stream 0.
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .unwrap();
        let mut frame_head = [0_u8; 9];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut frame_head))
            .await
            .expect("the server answered the preface")
            .unwrap();
        assert_eq!(frame_head[3], 0x4, "a SETTINGS frame: {frame_head:?}");
        assert_eq!(&frame_head[5..], [0; 4], "on stream 0: {frame_head:?}");
        drop(stream);

        tx.send(ShutdownReason::Sigterm).unwrap();
        server.await.unwrap();
    }

    /// Past `max_connections`, a connection waits unaccepted until one closes.
    #[tokio::test]
    async fn a_connection_past_the_cap_is_served_only_once_another_closes() {
        let Running {
            _dir,
            path,
            tx,
            server,
            ..
        } = start(Limits {
            max_connections: 1,
            ..LIMITS
        });
        let get = "GET /v1/openapi.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

        // Holds the one permit: a connection with a request half sent.
        let mut first = tokio::net::UnixStream::connect(&path).await.unwrap();
        first
            .write_all(b"GET /v1/openapi.json HTTP/1.1\r\n")
            .await
            .unwrap();
        let second = tokio::spawn({
            let path = path.clone();
            async move { exchange(&path, get).await }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !second.is_finished(),
            "the second connection was served past the cap"
        );

        drop(first);
        let response = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("served once the first closed")
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response:.200}");

        tx.send(ShutdownReason::Sigterm).unwrap();
        server.await.unwrap();
    }

    /// A connection that never finishes its request head is closed after
    /// `header_read_timeout`, which frees its permit.
    #[tokio::test]
    async fn a_request_head_that_never_completes_is_cut_off() {
        let Running {
            _dir,
            path,
            tx,
            server,
            ..
        } = start(Limits {
            max_connections: 1,
            header_read_timeout: Duration::from_millis(200),
            ..LIMITS
        });
        let mut stalled = tokio::net::UnixStream::connect(&path).await.unwrap();
        stalled
            .write_all(b"GET /v1/openapi.json HTTP/1.1\r\n")
            .await
            .unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stalled.read_to_end(&mut rest))
            .await
            .expect("the daemon closed the stalled connection")
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&rest).starts_with("HTTP/1.1 200"),
            "a half-sent head is never served"
        );

        // Its permit is free again.
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            exchange(
                &path,
                "GET /v1/openapi.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            ),
        )
        .await
        .expect("served after the cut-off");
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response:.200}");

        tx.send(ShutdownReason::Sigterm).unwrap();
        server.await.unwrap();
    }

    /// A shutdown that arrives while a request is in flight lets it finish
    /// and answers it before the server stops.
    #[tokio::test]
    async fn a_shutdown_drains_a_request_in_flight() {
        let Running {
            path,
            tx,
            mut server,
            hook_rx,
            _dir,
        } = start(LIMITS);

        // A login whose body has not all arrived: the request is in the
        // route's body read when the shutdown comes.
        let body = "{\"password\":\"not-the-password\"}";
        let (head, tail) = body.split_at(5);
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream
            .write_all(format!("{}{head}", login_head(body.len())).as_bytes())
            .await
            .unwrap();
        // Long enough for the connection to be accepted and its head read.
        tokio::time::sleep(Duration::from_millis(300)).await;

        tx.send(ShutdownReason::Sigterm).unwrap();
        hook_rx.await.expect("the shutdown hook ran");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut server)
                .await
                .is_err(),
            "the server waits for the request in flight"
        );

        stream.write_all(tail.as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            stream.read_to_string(&mut response),
        )
        .await
        .expect("the request in flight is answered")
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 "), "got: {response:.300}");
        assert!(
            !response.starts_with("HTTP/1.1 5") && !response.starts_with("HTTP/1.1 408"),
            "the router answered it, not a cut-off: {response:.300}"
        );
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the server stops once it is drained")
            .unwrap();
    }

    #[tokio::test]
    async fn a_request_over_the_socket_is_served_and_a_shutdown_removes_the_file() {
        let Running {
            path,
            tx,
            server,
            hook_rx,
            _dir,
        } = start(LIMITS);

        let response = exchange(
            &path,
            "GET /v1/openapi.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response:.200}");
        assert!(response.contains("\"openapi\""), "the document is the body");

        // A request with a body reaches the router with that body: a JSON
        // body the route cannot parse is the route's own refusal, not the
        // socket's.
        let body = "{";
        let response = exchange(
            &path,
            &format!(
                "POST /v1/torrents HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 4"), "got: {response:.300}");
        assert!(
            !response.starts_with("HTTP/1.1 408") && !response.starts_with("HTTP/1.1 413"),
            "got: {response:.300}"
        );

        // A declared length over the cap is refused without its body being
        // sent at all: the exchange would otherwise wait out the deadline.
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            exchange(
                &path,
                &format!(
                    "POST /v1/torrents HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
                     Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    MAX_ADD_BODY_BYTES + 1
                ),
            ),
        )
        .await
        .expect("refused at once");
        assert!(response.starts_with("HTTP/1.1 413"), "got: {response:.300}");
        assert!(
            response.contains("application/problem+json"),
            "got: {response:.300}"
        );

        tx.send(ShutdownReason::Sigterm).unwrap();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the server stops on a shutdown")
            .unwrap();
        hook_rx.await.expect("the shutdown hook ran");
        assert!(!path.exists(), "the socket file is removed on shutdown");
    }
}
