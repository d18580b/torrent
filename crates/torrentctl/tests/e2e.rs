//! The generated client against a real daemon.
//!
//! `#[ignore]`d: it spawns `torrentd` with a live libtorrent session. Run it
//! with `mise run test-torrentctl`, which builds the daemon first; set
//! `TORRENTD_BIN` to use another binary.
//!
//! This is the other half of the contract test `torrentd`'s own router tests
//! are: those hold the handlers to the document, this holds a client
//! generated from the document — by a different tool — to the handlers.

use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

#[allow(clippy::all, clippy::pedantic, dead_code, unused, unreachable_patterns)]
mod api {
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}

use api::types;

const PROFILE: &str = "e2e";
const PASSWORD: &str = "correct-horse-battery";
const HTTP: &str = "127.0.0.1:18191";
const LISTEN_PORT: u16 = 16991;
const MAGNET_HEX: &str = "0505050505050505050505050505050505050505";

fn torrentd() -> PathBuf {
    std::env::var_os("TORRENTD_BIN").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/torrentd"),
        PathBuf::from,
    )
}

fn config(dir: &Path, auth: Option<&str>) -> PathBuf {
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
             http_listen = \"{HTTP}\"\n\
             log_level = \"warn\"\n\
             enable_lsd = false\n\
             {access}\n\
             [[profile]]\n\
             id = \"{PROFILE}\"\n\
             network = \"host\"\n\
             listen_interfaces = \"127.0.0.1:{LISTEN_PORT}\"\n\
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
    let hash = password_hash(dir);
    let cfg = config(dir, Some(&hash));
    let child = Command::new(torrentd())
        .arg("--config")
        .arg(&cfg)
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn torrentd");
    let daemon = Daemon(child);
    let base = format!("http://{HTTP}");
    let client = api::Client::new(&base).unwrap();
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
    (daemon, base)
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
