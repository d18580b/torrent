//! What the HTTP listener serves: allowed hosts, and the metrics present from
//! boot.

use super::*;

#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn a_configured_allowed_host_is_answered_and_another_is_refused() {
    // The router tests set the allowlist on the state they build; this holds
    // the path from the config file to the running daemon's gate.
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let cfg = write_config(p, free_port(), addr);
    let body = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        format!("allowed_hosts = [\"torrentd.example.com\"]\n{body}"),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_torrentd"))
        .arg("--config")
        .arg(&cfg)
        .spawn()
        .expect("spawn daemon");

    wait_healthy(addr);

    for host in ["torrentd.example.com", "torrentd.example.com:8443"] {
        let (code, body) = http_as(addr, "GET", "/v1/torrents", None, host);
        assert_eq!(code, 200, "GET with Host {host}: {body}");
        let (code, body) = http_as(addr, "POST", "/v1/torrents/pause-all", None, host);
        assert!(
            (200..300).contains(&code),
            "POST with Host {host}: {code} {body}"
        );
    }
    let (code, body) = http_as(addr, "GET", "/v1/torrents", None, "attacker.example");
    assert_eq!(code, 403, "a Host not in allowed_hosts: {body}");

    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
}

/// Point a kubelet-style config directory at a new version of the file, the
/// way kubelet updates a mounted ConfigMap: write `..<to>/torrentd.toml`,
/// point `..data_tmp` at it, rename that over `..data`, remove `..<from>`.
fn kubelet_swap(dir: &std::path::Path, from: &str, to: &str, body: &str) {
    std::fs::create_dir(dir.join(to)).unwrap();
    std::fs::write(dir.join(to).join("torrentd.toml"), body).unwrap();
    std::os::unix::fs::symlink(to, dir.join("..data_tmp")).unwrap();
    std::fs::rename(dir.join("..data_tmp"), dir.join("..data")).unwrap();
    std::fs::remove_dir_all(dir.join(from)).unwrap();
}

/// `config_watch` on a directory laid out as kubelet mounts a ConfigMap:
/// each `..data` swap reloads with no signal and no API call, through the
/// reload `SIGHUP` runs. A file that does not parse is counted as that
/// reload's failure; a restart-only key changed raises
/// `config_restart_pending` for that key; and the file swapped back clears
/// it.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn config_watch_reloads_on_a_kubelet_symlink_swap_and_reports_a_pending_restart() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let base = std::fs::read_to_string(write_config(p, free_port(), addr)).unwrap();
    let body = format!("config_watch = true\n{base}");
    let conf = p.join("conf");
    std::fs::create_dir_all(conf.join("..v1")).unwrap();
    std::fs::write(conf.join("..v1/torrentd.toml"), &body).unwrap();
    std::os::unix::fs::symlink("..v1", conf.join("..data")).unwrap();
    std::os::unix::fs::symlink("..data/torrentd.toml", conf.join("torrentd.toml")).unwrap();
    let daemon = Running(
        Command::new(env!("CARGO_BIN_EXE_torrentd"))
            .arg("--config")
            .arg(conf.join("torrentd.toml"))
            .spawn()
            .expect("spawn daemon"),
    );
    wait_healthy(addr);

    let pending = "torrentd_config_restart_pending{key=\"shutdown_drain_secs\"}";
    let load_failures = "torrentd_config_reload_failures_total{stage=\"load\"}";
    let (_, metrics) = http(addr, "GET", "/metrics", None);
    assert!(
        metrics.lines().any(|l| l == format!("{pending} 0")),
        "seeded at boot:\n{metrics}"
    );

    // A file that does not parse: the reload runs, fails, and is counted.
    kubelet_swap(&conf, "..v1", "..v2", "this is = = not toml");
    poll(
        "the watched reload to fail at load",
        Duration::from_secs(15),
        || (metric(addr, load_failures) == 1.0).then_some(()),
    );

    // A restart-only key changed: reported as pending, by name.
    kubelet_swap(
        &conf,
        "..v2",
        "..v3",
        &format!("shutdown_drain_secs = 61\n{body}"),
    );
    poll(
        "shutdown_drain_secs pending a restart",
        Duration::from_secs(15),
        || (metric(addr, pending) == 1.0).then_some(()),
    );
    assert_eq!(
        metric(addr, "torrentd_config_restart_pending{key=\"auth\"}"),
        0.0,
        "only the key that changed is pending"
    );

    // The file swapped back to what the daemon runs clears it.
    kubelet_swap(&conf, "..v3", "..v4", &body);
    poll(
        "the pending restart to clear",
        Duration::from_secs(15),
        || (metric(addr, pending) == 0.0).then_some(()),
    );
    assert_eq!(metric(addr, load_failures), 1.0, "no further failure");

    daemon.stop();
}

/// The rows of `deploy/metrics.md` a host-profile daemon with no pool and no
/// kill switch must export from its first scrape: `(name, labels column)`.
fn series_present_from_boot() -> Vec<(String, String)> {
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/metrics.md"),
    )
    .expect("read deploy/metrics.md");
    doc.lines()
        .filter(|l| l.starts_with("| `torrentd_"))
        .filter_map(|l| {
            let cells: Vec<&str> = l.split(" | ").collect();
            let name = cells[0]
                .trim_start_matches("| ")
                .trim_matches('`')
                .to_string();
            let (labels, instances, present) = (cells[2], cells[3], cells[4]);
            let applies = matches!(instances, "daemon" | "each profile")
                && matches!(
                    present,
                    "from boot, at 0" | "from boot: always" | "from boot: live profiles"
                );
            applies.then(|| (name, labels.to_string()))
        })
        .collect()
}

/// The values a labels column lists, as `label="value"` matchers.
fn listed_values(labels: &str) -> Vec<String> {
    labels
        .split("; ")
        .filter_map(|part| part.split_once(": "))
        .flat_map(|(name, values)| {
            let name = name.trim_matches('`').to_string();
            values
                .split(", ")
                .map(move |v| format!("{name}=\"{}\"", v.trim_matches('`')))
        })
        .collect()
}

/// Everything an alert rule reads has to exist before the condition it
/// watches first happens, or `increase()` never sees that first event. So the
/// very first scrape of a fresh daemon must already hold every series the
/// reference table says is there from boot, for this profile and for every
/// listed label value. Then a reload that cannot parse its config is counted.
#[test]
#[ignore = "spawns the real daemon + libtorrent; run with --ignored"]
fn the_first_scrape_holds_every_series_present_from_boot() {
    let addr = free_http();
    let addr = addr.as_str();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let mut child = spawn_daemon(p, free_port(), addr);
    wait_healthy(addr);

    let (code, metrics) = http(addr, "GET", "/metrics", None);
    assert_eq!(code, 200);
    let expected = series_present_from_boot();
    assert!(expected.len() > 30, "parsed too few rows: {expected:?}");
    let mut missing = Vec::new();
    for (name, labels) in &expected {
        if !metrics.contains(&format!("# TYPE {name} ")) {
            missing.push(name.clone());
            continue;
        }
        // `task_up` lists every task there is; only the ones this config
        // starts exist.
        if name == "torrentd_task_up" {
            continue;
        }
        // `profile_boot_failed` is one series per profile, its `reason` the
        // failure's class or `none`; a profile that came up holds only
        // `none`, at 0.
        if name == "torrentd_profile_boot_failed" {
            let series = format!("{name}{{profile_id=\"test\",reason=\"none\"}} 0");
            if !metrics.lines().any(|l| l == series) {
                missing.push(series);
            }
            continue;
        }
        // A histogram's series are its `_bucket`, `_sum` and `_count`; its
        // `_count` stands for the row.
        for value in listed_values(labels) {
            let found = metrics.lines().any(|l| {
                (l.starts_with(&format!("{name}{{")) || l.starts_with(&format!("{name}_count{{")))
                    && l.contains(&value)
                    && (!labels.contains("profile_id") || l.contains("profile_id=\"test\""))
            });
            if !found {
                missing.push(format!("{name}{{{value}}}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "absent from the first scrape: {missing:?}\n\n{metrics}"
    );
    for task in ["vpn_monitor", "reload"] {
        assert!(
            metrics.contains(&format!("torrentd_task_up{{task=\"{task}\"}} 1")),
            "{task} is supervised from boot:\n{metrics}"
        );
    }

    // A reload that cannot parse the file keeps the old settings and says so
    // in a series an alert can read, not only in the journal.
    std::fs::write(p.join("cfg.toml"), "this is = = not toml").unwrap();
    let (code, body) = http(addr, "POST", "/v1/config/reload", None);
    assert!((200..300).contains(&code), "reload trigger: {code} {body}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, metrics) = http(addr, "GET", "/metrics", None);
        if metrics.contains("torrentd_config_reload_failures_total{stage=\"load\"} 1") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the failed reload was not counted:\n{metrics}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    sigterm(&child);
    assert_exits_zero(&mut child, Duration::from_secs(30));
    // A clean exit still writes the report the next boot re-exports, and it
    // says nothing was left behind. This daemon has no kill switch, so
    // `kill_switch_removal_failed` is false with nothing to remove: the
    // removal itself is asserted with the switch on, and the table checked
    // gone, in tests/vpn_netns_e2e.rs.
    let report = std::fs::read_to_string(p.join("last_shutdown.json")).expect("shutdown report");
    assert!(report.contains("\"unsaved_resumes\":0"), "{report}");
    assert!(
        report.contains("\"kill_switch_removal_failed\":false"),
        "{report}"
    );
}
