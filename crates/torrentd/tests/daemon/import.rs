//! Importing a qBittorrent `BT_backup` directory.

use super::*;

/// `POST path` with the JSON `body`, as [`http`] does, waiting up to
/// `timeout` for the answer.
fn post_within(addr: &str, path: &str, body: &str, timeout: Duration) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(timeout)).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("POST {path} on {addr}: {e}"));
    let resp = String::from_utf8_lossy(&buf);
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

/// Issue #430's acceptance: a qBittorrent `BT_backup` imports through the
/// real daemon and real libtorrent, each torrent the way its pair says.
///
/// Every case the generator knows, twice. One adoption takes them all:
///
/// - complete, renamed through `mapped_files`, and with a save path that is
///   not UTF-8: the fast path, the previous client's resume data handed to
///   libtorrent in seed mode, `adopted` at once and seeding without a check;
///   the renamed one at the name libtorrent learns from that resume data;
/// - incomplete, and with its sidecar cut off halfway: the verify queue,
///   hashed, then seeding and `adopted`;
/// - `NoSubfolder`: refused, since libtorrent cannot be told about a layout
///   only qBittorrent recorded, and never loaded;
/// - an orphan sidecar: never indexed, and refused as not in the library.
///
/// `torrentd_checks_started_total{source="adoption"}` counts the verify
/// queue's checks only, so it ends at the verified torrents' number. Each
/// adopted torrent's session holds it at the base the pool matched, and the
/// resume data libtorrent writes at the graceful stop records it in upload
/// mode — the daemon never downloads — and in seed mode for the fast path
/// alone.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_bt_backup_directory_imports_fast_path_and_verify_mixed() {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use bt_backup::Case;
    use torrentd_pool::adopt::refusal;

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let backup = p.join("BT_backup");
    let root = p.join("pool");
    let generated = bt_backup::generate(&backup, &root, 2 * Case::ALL.len(), |b| {
        use sha1::Digest;
        sha1::Sha1::digest(b).into()
    });
    let of = |cases: &[Case]| -> BTreeSet<String> {
        generated
            .iter()
            .filter(|g| cases.contains(&g.case))
            .map(|g| g.infohash.clone())
            .collect()
    };
    let fast = of(&[Case::Complete, Case::Renamed, Case::NonUtf8SavePath]);
    let verify = of(&[Case::Incomplete, Case::TruncatedSidecar]);

    let addr = &free_http();
    let cfg = write_config(p, free_port(), addr);
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!(
        "\n[pool]\nroots = [\"{}\"]\nlibrary_dir = \"{}\"\n",
        root.display(),
        backup.display()
    ));
    std::fs::write(&cfg, text).unwrap();
    let log = DaemonLog::new(p);
    let child = Running(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .stdout(log.stdio())
            .stderr(log.stdio())
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy(addr);

    let (code, body) = http(addr, "POST", "/v1/pool/scan", None);
    assert_eq!(code, 200, "{body}");
    for g in &generated {
        let expected = (g.case != Case::OrphanSidecar).then(|| "matched".to_owned());
        assert_eq!(pool_state(addr, &g.infohash), expected, "{g:?}");
    }

    let all: Vec<String> = generated
        .iter()
        .map(|g| format!("\"{}\"", g.infohash))
        .collect();
    // Answered once every torrent is added or queued, which runs past
    // `http`'s five-second read timeout for this many.
    let (code, body) = post_within(
        addr,
        "/v1/pool/adoptions",
        &format!(
            "{{\"profile_id\":\"{PROFILE}\",\"selector\":{{\"kind\":\"infohashes\",\
             \"infohashes\":[{}]}}}}",
            all.join(",")
        ),
        Duration::from_secs(120),
    );
    assert_eq!(code, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let set = |key: &str| -> BTreeSet<String> {
        v[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|ih| ih.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(set("fast_path"), fast, "{body}");
    assert_eq!(set("queued_for_verification"), verify, "{body}");
    let refused: BTreeMap<String, String> = v["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["infohash"].as_str().unwrap().to_owned(),
                r["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected_refused: BTreeMap<String, String> = generated
        .iter()
        .filter_map(|g| match g.case {
            Case::NoSubfolder => Some((g.infohash.clone(), refusal::LAYOUT_NOT_IN_RESUME)),
            Case::OrphanSidecar => Some((g.infohash.clone(), refusal::NOT_IN_LIBRARY)),
            _ => None,
        })
        .map(|(ih, r)| (ih, r.to_owned()))
        .collect();
    assert_eq!(refused, expected_refused, "{body}");

    // The fast path records the adoption as it adds, before any check could
    // have run.
    for ih in &fast {
        assert_eq!(pool_state(addr, ih).as_deref(), Some("adopted"), "{ih}");
    }

    let adopted: Vec<&bt_backup::Generated> = generated
        .iter()
        .filter(|g| fast.contains(&g.infohash) || verify.contains(&g.infohash))
        .collect();
    for g in &adopted {
        let ih = &g.infohash;
        if let Err(last) = settled_in(addr, ih, Duration::from_secs(60), |phase, _| {
            phase == "seeding"
        }) {
            panic!("{g:?} never reached seeding; last seen {last:?}");
        }
        poll(
            &format!("{ih} to be recorded adopted"),
            Duration::from_secs(30),
            || (pool_state(addr, ih).as_deref() == Some("adopted")).then_some(()),
        );

        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        assert_eq!(code, 200, "{body}");
        let t: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            t["session"]["name"].as_str(),
            Some(g.name.as_str()),
            "{g:?}"
        );
        assert_eq!(
            t["session"]["save_path"]
                .as_str()
                .map(std::path::PathBuf::from),
            Some(root.join(&g.base_rel)),
            "{g:?}"
        );
        // The paths libtorrent opens, which for the renamed torrent are the
        // ones only its resume data names.
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}/files"), None);
        assert_eq!(code, 200, "{body}");
        let files: serde_json::Value = serde_json::from_str(&body).unwrap();
        let paths: Vec<&str> = files["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, g.file_paths, "{g:?}");
    }

    // Refused, and so never handed to a session.
    for ih in &of(&[Case::NoSubfolder]) {
        assert_eq!(pool_state(addr, ih).as_deref(), Some("matched"), "{ih}");
        let (code, body) = http(addr, "GET", &format!("/v1/torrents/{ih}"), None);
        assert_eq!(code, 404, "{ih}: {body}");
    }

    // One check per verified torrent, and none for the fast path.
    assert_eq!(
        metric(addr, "torrentd_checks_started_total{source=\"adoption\"}"),
        verify.len() as f64,
    );

    child.stop();

    for g in &adopted {
        let resume = p
            .join("resume")
            .join(PROFILE)
            .join(format!("{}.resume", g.infohash));
        let bytes = std::fs::read(&resume)
            .unwrap_or_else(|e| panic!("{g:?}: no resume file at the graceful stop: {e}"));
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"11:upload_modei1e"), "{g:?} is not in upload mode");
        let seed_mode: &[u8] = if fast.contains(&g.infohash) {
            b"9:seed_modei1e"
        } else {
            b"9:seed_modei0e"
        };
        assert!(
            has(seed_mode),
            "{g:?}: expected {}",
            String::from_utf8_lossy(seed_mode)
        );
    }
}
