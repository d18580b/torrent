//! Boot refusals, config loading, and reloads.

use super::*;

/// The upgrade every pre-profiles deployment takes.
///
/// A single-session deployment's `slot_assignments.json` maps every info-hash
/// to `default`. The operator writes a `[[profile]]` table with some other id
/// and starts the daemon. The registry migration carries those entries over
/// verbatim, and nothing reconciles them: the per-profile resume and torrent
/// scans never look at the old un-partitioned paths, so nothing loads; the
/// registry says every one of those info-hashes is taken, so re-adding answers
/// 409; and `DELETE` cannot clear an entry whose profile has no session
/// either. The daemon serves `/healthz` 200 throughout, seeding nothing.
///
/// Without the reconciliation this test fails by timing out on a daemon that
/// came up perfectly happy.
#[test]
#[ignore = "spawns the real daemon; run with --ignored"]
fn a_migrated_registry_naming_an_unconfigured_profile_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), &free_http());

    // The pre-profiles registry, under its pre-profiles name. `write_config`
    // puts `resume_dir` at `p/resume`, so the state dir is `p`.
    std::fs::write(
        p.join("slot_assignments.json"),
        br#"{"0101010101010101010101010101010101010101":"default",
             "0202020202020202020202020202020202020202":"default"}"#,
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    let exited = wait_exit(&mut child, Duration::from_secs(30));
    // The refusal is a tracing ERROR, which this daemon writes to stdout as
    // JSON; read both streams so the assertions below do not depend on which.
    let mut err = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut err)
        .unwrap();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut err)
        .unwrap();

    let exited = exited.unwrap_or_else(|| {
        panic!("the daemon started against a registry it cannot serve; stderr: {err}")
    });
    assert_eq!(
        exited.code(),
        Some(78),
        "a refusal no restart can fix exits EX_CONFIG, which the unit does not restart; \
         stderr: {err}"
    );

    // The refusal has to be actionable: it names the id it does not recognise,
    // the ids it does, and both ways out.
    assert!(err.contains("default"), "must name the unknown id: {err}");
    assert!(
        err.contains(PROFILE),
        "must name the configured profiles: {err}"
    );
    assert!(
        err.contains("[[profile]]"),
        "must say what declares a profile: {err}"
    );
    assert!(
        err.contains("registry.db"),
        "must name the database to edit: {err}"
    );
    assert!(
        err.contains("DELETE FROM assignment WHERE profile_id IN ('default')"),
        "and the statement that clears those rows: {err}"
    );

    // And it must not have been a silent success followed by a crash: nothing
    // should have been loaded.
    assert!(
        !p.join(format!("session_state-{PROFILE}.dat")).exists(),
        "the daemon got far enough to persist session state"
    );
}

/// A resume file and a torrent-dir `.torrent` the boot scans cannot read are
/// skipped, the daemon comes up anyway, and boot exports each under its own
/// `source` of `boot_torrent_load_failures`. A directory stands where each
/// file goes, which no uid can read as a file.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn unreadable_scan_files_are_exported_by_source_at_boot() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    let ih = "ab".repeat(20);
    std::fs::create_dir_all(p.join("resume").join(PROFILE).join(format!("{ih}.resume"))).unwrap();
    std::fs::create_dir_all(
        p.join("torrents")
            .join(PROFILE)
            .join(format!("{ih}.torrent")),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .spawn()
        .expect("spawn daemon");
    wait_healthy(addr);

    let (code, metrics) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200);
    for source in ["resume_file", "torrent_file"] {
        assert!(
            metrics.lines().any(|l| {
                l.starts_with("torrentd_boot_torrent_load_failures{")
                    && l.contains(&format!("profile_id=\"{PROFILE}\""))
                    && l.contains(&format!("source=\"{source}\""))
                    && l.ends_with(" 1")
            }),
            "boot_torrent_load_failures{{source={source}}} should read 1:\n{metrics}"
        );
    }

    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
}

/// A config that does not load exits 78 (`EX_CONFIG`), from the daemon and
/// from `--check-config` alike, which is what `RestartPreventExitStatus=78`
/// reads to leave the unit stopped.
#[test]
#[ignore = "spawns the real daemon; run with --ignored"]
fn a_config_that_fails_to_load_exits_ex_config() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), &free_http());
    let text = std::fs::read_to_string(&cfg).unwrap();
    // Out of `shutdown_drain_secs`'s `1..=3600`: parses, then fails validation.
    std::fs::write(&cfg, format!("shutdown_drain_secs = 0\n{text}")).unwrap();

    for check in [false, true] {
        let (code, out) = run_to_exit(&cfg, check, None);
        assert_eq!(code, 78, "--check-config: {check}; output: {out}");
        assert!(
            out.contains("shutdown_drain_secs"),
            "the refusal names the key: {out}"
        );
    }

    let (code, out) = run_to_exit(&p.join("missing.toml"), false, None);
    assert_eq!(code, 78, "a config file that is not there: {out}");

    // An operator subcommand is not the daemon: `vpn check` documents only
    // 0/1/2, and a config it cannot load is its 1.
    let out = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .args(["vpn", "check"])
        .output()
        .expect("spawn torrentd vpn check");
    assert_eq!(
        out.status.code(),
        Some(1),
        "vpn check on a config that fails to load; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `--check-config`'s host probe (`nft` present under
/// `network_kill_switch = true`) exits 78 when it fails, and so does the
/// daemon, which makes the same probe itself before it raises anything. `nft`
/// is made absent by running with a `PATH` holding nothing.
#[test]
#[ignore = "spawns the real daemon; run with --ignored"]
fn a_kill_switch_with_no_nft_exits_ex_config() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    for sub in ["data", "resume", "torrents", "empty-path"] {
        std::fs::create_dir_all(p.join(sub)).unwrap();
    }
    let cfg = p.join("cfg.toml");
    std::fs::write(
        &cfg,
        format!(
            "default_save_path = \"{d}/data\"\n\
             resume_dir = \"{d}/resume\"\n\
             torrent_dir = \"{d}/torrents\"\n\
             http_listen = \"{http}\"\n\
             log_level = \"warn\"\n\
             allow_unauthenticated = true\n\
             network_kill_switch = true\n\
             \n\
             [[profile]]\n\
             id = \"acct_a\"\n\
             network = \"vpn\"\n\
             vpn_type = \"wireguard\"\n\
             vpn_config = \"{d}/wg0.conf\"\n\
             vpn_interface = \"wg-nonft\"\n\
             listen_port = {listen_port}\n\
             peer_fingerprint = \"-AA1000-\"\n\
             user_agent = \"ua-a\"\n\
             allowed_tracker_domains = [\"t.example\"]\n",
            d = p.display(),
            http = free_http(),
            listen_port = free_port(),
        ),
    )
    .unwrap();

    for check in [true, false] {
        let (code, out) = run_to_exit(&cfg, check, Some(&p.join("empty-path")));
        assert_eq!(code, 78, "--check-config: {check}; output: {out}");
        assert!(out.contains("nft"), "the refusal names `nft`: {out}");
    }
}

/// The reconciliation warning on an import boot names the database to edit,
/// not only the file the entries came from.
///
/// A registry that survives the boot check — every id it names is configured —
/// can still claim torrents no scan loaded, which is the silent total outage
/// that warning exists to catch. On this one boot the entries were imported
/// from the pre-rename `slot_assignments.json`, and editing that file changes
/// nothing: the daemon imports it into `registry.db` on the same boot, renames
/// it, and reads only the database from here on. Naming the old file alone sent them to the
/// wrong one.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn the_reconciliation_warning_names_both_registry_files() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);

    // Assignments for the profile that *is* configured, so the boot check
    // passes and the reconciliation below is reached — and no resume file for
    // either, so the scan loads none of them.
    std::fs::write(
        p.join("slot_assignments.json"),
        format!(
            "{{\"0101010101010101010101010101010101010101\":\"{PROFILE}\",
               \"0202020202020202020202020202020202020202\":\"{PROFILE}\"}}"
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    wait_healthy(addr);
    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .unwrap();

    let warning = out
        .lines()
        .find(|l| l.contains("the assignment registry claims more torrents"))
        .unwrap_or_else(|| panic!("the reconciliation warning did not fire; output: {out}"));

    assert!(
        warning.contains("\"registry_path\":\"") && warning.contains("registry.db"),
        "must name the database the operator edits from here on: {warning}",
    );
    assert!(
        warning.contains("\"registry_read_from\":\"")
            && warning.contains("slot_assignments.json.imported"),
        "and the file these entries were imported from, where it now is: {warning}",
    );

    // The import happened once: the JSON is moved aside and a second boot
    // reads the database alone, still holding both entries — which is why
    // the same warning fires again, counting the same two.
    assert!(!p.join("slot_assignments.json").exists());
    assert!(p.join("slot_assignments.json.imported").exists());
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    wait_healthy(addr);
    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .unwrap();
    let warning = out
        .lines()
        .find(|l| l.contains("the assignment registry claims more torrents"))
        .unwrap_or_else(|| panic!("the second boot lost the imported entries; output: {out}"));
    assert!(
        warning.contains("\"registry_torrents\":2"),
        "both entries survive into the second boot: {warning}",
    );
}

/// A non-reloadable edit is reported on every reload until a restart takes
/// it, not only on the first.
///
/// The reload pump used to record the whole new file as the running config
/// after each reload, so the second reload of the same edit answered
/// `SIGHUP: config unchanged` about a `file_pool_size` the daemon was still
/// not running.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_non_reloadable_change_is_reported_on_the_second_reload_too() {
    const WARNING: &str = "non-reloadable field requires daemon restart";
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    // Killed if an assertion below panics, rather than left running and
    // holding the test runner's stderr open.
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn daemon"),
    );
    // The daemon logs JSON lines to stdout; a reader thread keeps the pipe
    // drained and hands each line over as it arrives.
    let (tx, lines) = std::sync::mpsc::channel::<String>();
    let stdout = child.0.stdout.take().expect("piped stdout");
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    wait_healthy(addr);

    // A top-level key, so it goes above the `[[profile]]` table.
    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        body.replace(
            "enable_lsd = false\n",
            "enable_lsd = false\nfile_pool_size = 2000\n",
        ),
    )
    .unwrap();

    // Wait for the next reload's verdict: the restart warning naming the key,
    // or `config unchanged`.
    let verdict = |seen: &mut Vec<String>| -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match lines.recv_timeout(left) {
                Ok(line) => {
                    seen.push(line.clone());
                    if (line.contains(WARNING) && line.contains("file_pool_size"))
                        || line.contains("SIGHUP: config unchanged")
                    {
                        return line;
                    }
                }
                Err(_) => panic!("no reload verdict within 10s; output:\n{}", seen.join("\n")),
            }
        }
    };
    let mut seen = Vec::new();
    for reload in ["first", "second"] {
        let (code, body) = http(addr, "POST", "/v1/config/reload", None);
        assert!((200..300).contains(&code), "reload trigger: {code} {body}");
        let line = verdict(&mut seen);
        assert!(
            line.contains(WARNING),
            "the {reload} reload must still report the restart it needs: {line}",
        );
    }

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}

/// A real `SIGHUP`, not `POST /v1/config/reload`, reaches the reload pump,
/// and a `connections_limit` edit is applied to the profile's live libtorrent
/// session: `SIGHUP: settings applied` is logged only once that session's
/// `apply_settings` has returned, and nothing is counted as a failed reload.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_sighup_applies_connections_limit_to_the_live_session() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    // `settings applied` is an info line.
    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        body.replace("log_level = \"warn\"\n", "log_level = \"info\"\n"),
    )
    .unwrap();
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(&cfg)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn daemon"),
    );
    let (tx, lines) = std::sync::mpsc::channel::<String>();
    let stdout = child.0.stdout.take().expect("piped stdout");
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    wait_healthy(addr);

    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        body.replace(
            "enable_lsd = false\n",
            "enable_lsd = false\nconnections_limit = 321\n",
        ),
    )
    .unwrap();
    Command::new("kill")
        .args(["-HUP", &child.0.id().to_string()])
        .status()
        .expect("send SIGHUP");

    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let applied = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(line) = lines.recv_timeout(left) else {
            panic!("no reload verdict within 10s; output:\n{}", seen.join("\n"));
        };
        seen.push(line.clone());
        if line.contains("SIGHUP: settings applied")
            || line.contains("SIGHUP: apply_settings failed")
            || line.contains("SIGHUP: config unchanged")
            || line.contains("connections_limit refused")
        {
            break line;
        }
    };
    assert!(
        seen.iter().any(|l| l.contains("received SIGHUP")),
        "the signal, not the HTTP trigger, started this reload: {}",
        seen.join("\n"),
    );
    assert!(
        applied.contains("SIGHUP: settings applied")
            && applied.contains(&format!("\"profile_id\":\"{PROFILE}\"")),
        "the edit reached the profile's session: {applied}",
    );
    assert_eq!(
        metric(
            addr,
            "torrentd_config_reload_failures_total{stage=\"apply_settings\"}"
        ),
        0.0,
    );

    sigterm(&child.0);
    assert_exits_zero(&mut child.0, Duration::from_secs(30));
}
