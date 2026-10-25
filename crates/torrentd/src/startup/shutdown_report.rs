//! What a run's exit leaves for the next boot to report, and the kill
//! switch's removal on the way out.

use torrentd_engine::batch_writer::write_atomic;
use torrentd_engine::MetricsSink;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::metrics_sink::PromSink;

/// What a run's exit left behind that no scrape of that run could see.
///
/// Both halves happen as the process is leaving: a metric set there is gone
/// before anything scrapes it, so an alert on it could never fire. The exiting
/// run writes this file and the next boot re-exports it as the
/// `last_shutdown_*` gauges, then deletes it — a run that dies without
/// writing one leaves the next boot reporting zero rather than a stale value
/// from an older exit.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct ShutdownReport {
    /// Resume saves the shutdown drain's deadline left unsaved.
    pub(super) unsaved_resumes: u64,
    /// The kill switch could not be removed on the way out.
    pub(super) kill_switch_removal_failed: bool,
}

/// `<state_dir>/last_shutdown.json`.
fn shutdown_report_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join("last_shutdown.json")
}

/// Persist `report` for the next boot. A failure is logged and otherwise
/// ignored: the process is exiting, and the journal line is all that is left.
pub(super) fn write_shutdown_report(state_dir: &std::path::Path, report: &ShutdownReport) {
    let bytes = serde_json::to_vec(report).expect("a plain struct serializes");
    if let Err(e) = write_atomic(&shutdown_report_path(state_dir), &bytes) {
        warn!(
            path = %shutdown_report_path(state_dir).display(),
            error.cause = %e,
            "could not persist the shutdown report; the next boot will report zero",
        );
    }
}

/// Read and delete the previous run's report. Absent, unreadable or
/// malformed all read as the default, the last two with a warning.
pub(super) fn take_shutdown_report(state_dir: &std::path::Path) -> ShutdownReport {
    let path = shutdown_report_path(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ShutdownReport::default(),
        Err(e) => {
            warn!(path = %path.display(), error.cause = %e, "could not read the shutdown report");
            return ShutdownReport::default();
        }
    };
    let report = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        warn!(path = %path.display(), error.cause = %e, "malformed shutdown report; ignoring it");
        ShutdownReport::default()
    });
    if let Err(e) = std::fs::remove_file(&path) {
        warn!(path = %path.display(), error.cause = %e, "could not remove the shutdown report");
    }
    report
}

/// Record the outcome of removing the kill switch on a clean shutdown.
///
/// On success `kill_switch_active` drops to 0. On failure it stays 1, because
/// the table is still installed and still confines the uid, and the report
/// carries the failure to the next boot.
pub(super) fn finish_kill_switch_removal(
    outcome: std::io::Result<()>,
    metrics: &PromSink,
    report: &mut ShutdownReport,
) {
    match outcome {
        Ok(()) => {
            info!("network kill switch removed");
            metrics.set_gauge("kill_switch_active", 0.0, &[]);
        }
        Err(e) => {
            error!(
                error.cause = %e,
                table = %crate::vpn::killswitch::own_table_name(),
                "failed to remove network kill switch; the daemon's uid stays \
                 confined to the tunnels until the table is removed \
                 (nft delete table inet <table>) or a kill-switch boot replaces it",
            );
            report.kill_switch_removal_failed = true;
        }
    }
}

/// Record the outcome of removing the kill switch after a failed boot. The
/// process is on its way out, so a failure goes to the report the next boot
/// reads.
pub(super) fn finish_boot_kill_switch_removal(
    run_dir: &std::path::Path,
    outcome: std::io::Result<()>,
) {
    match outcome {
        Ok(()) => info!("boot failed: network kill switch removed"),
        Err(e) => {
            warn!(error.cause = %e, "boot failed: could not remove kill switch");
            write_shutdown_report(
                run_dir,
                &ShutdownReport {
                    unsaved_resumes: 0,
                    kill_switch_removal_failed: true,
                },
            );
        }
    }
}

/// What a boot with `network_kill_switch = false` found of an earlier run's
/// kill-switch table. See [`remove_stale_kill_switch`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum StaleKillSwitch {
    /// `nft` is not installed, so no table can exist and none was asked for.
    NoNft,
    /// No table was there.
    Absent,
    /// A table was there and is gone.
    Removed,
    /// The tables could not be listed, or the one listed would not delete.
    Failed,
}

/// Remove a kill-switch table this boot did not install and will not use.
///
/// The table outlives an unclean exit (`kill -9`, an OOM kill, a panic
/// abort), and with the kill switch now off it keeps dropping every packet
/// the daemon's uid sends outside a tunnel: tracker requests time out and
/// host profiles go dark with nothing in the log to say why. Neither outcome
/// stops the boot. The operator asked for no kill switch, and a table that
/// could not be removed is reported with the command that removes it.
///
/// A listing that fails is logged at `info` rather than `warn`: without
/// `CAP_NET_ADMIN`, which a host-only deployment does not hold, it fails on
/// every boot, and such a daemon could not have installed a table either.
///
/// Only this uid's table is this boot's to remove
/// ([`crate::vpn::killswitch::remove_table`]): another uid's is another
/// daemon's kill switch, in force in the same network namespace.
pub(super) fn remove_stale_kill_switch(
    nft_available: bool,
    table: &str,
    remove: impl FnOnce() -> std::io::Result<bool>,
) -> StaleKillSwitch {
    if !nft_available {
        return StaleKillSwitch::NoNft;
    }
    match remove() {
        Ok(false) => StaleKillSwitch::Absent,
        Ok(true) => {
            warn!(
                table,
                "removed a stale network kill-switch table left by an earlier run that did not \
                 exit cleanly; with network_kill_switch = false it would have dropped this \
                 daemon's traffic outside the tunnels",
            );
            StaleKillSwitch::Removed
        }
        Err(e) => {
            info!(
                table,
                error.cause = %e,
                "could not check for, or remove, a network kill-switch table left by an earlier \
                 run. If one is installed it drops this daemon's traffic outside the tunnels; \
                 remove it with `nft delete table inet <table>`",
            );
            StaleKillSwitch::Failed
        }
    }
}

/// Export the previous run's [`ShutdownReport`] and warn about what it holds.
pub(super) fn export_shutdown_report(metrics: &PromSink, report: &ShutdownReport) {
    if report.unsaved_resumes > 0 {
        warn!(
            pending_resume_count = report.unsaved_resumes,
            "the previous run's shutdown left resume data unsaved; those torrents resumed from \
             older state",
        );
    }
    if report.kill_switch_removal_failed {
        warn!(
            table = %crate::vpn::killswitch::own_table_name(),
            "the previous run could not remove the network kill switch on its way out; a boot \
             with network_kill_switch replaces it and one without removes it, or remove it with \
             `nft delete table inet <table>`",
        );
    }
    metrics.set_gauge(
        "last_shutdown_unsaved_resumes",
        report.unsaved_resumes as f64,
        &[],
    );
    metrics.set_gauge(
        "last_shutdown_kill_switch_removal_failed",
        if report.kill_switch_removal_failed {
            1.0
        } else {
            0.0
        },
        &[],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::test_support::failed;

    fn rendered(metrics: &PromSink) -> String {
        String::from_utf8(metrics.render()).unwrap()
    }

    #[test]
    fn a_written_report_is_read_back_once_and_then_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let report = ShutdownReport {
            unsaved_resumes: 3,
            kill_switch_removal_failed: true,
        };
        write_shutdown_report(dir.path(), &report);
        assert_eq!(take_shutdown_report(dir.path()), report);
        assert!(
            !shutdown_report_path(dir.path()).exists(),
            "the report is deleted once read"
        );
        // A second boot, with no exit in between that wrote one, reports zero.
        assert_eq!(take_shutdown_report(dir.path()), ShutdownReport::default());
    }

    #[test]
    fn a_malformed_report_reads_as_zero_and_is_still_deleted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(shutdown_report_path(dir.path()), b"{not json").unwrap();
        assert_eq!(take_shutdown_report(dir.path()), ShutdownReport::default());
        assert!(!shutdown_report_path(dir.path()).exists());
    }

    #[test]
    fn a_non_zero_report_is_exported_as_non_zero_gauges() {
        let metrics = PromSink::new();
        export_shutdown_report(
            &metrics,
            &ShutdownReport {
                unsaved_resumes: 7,
                kill_switch_removal_failed: true,
            },
        );
        let text = rendered(&metrics);
        assert!(
            text.contains("torrentd_last_shutdown_unsaved_resumes 7"),
            "{text}"
        );
        assert!(
            text.contains("torrentd_last_shutdown_kill_switch_removal_failed 1"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_kill_switch_removal_leaves_it_active_and_reports_it() {
        let metrics = PromSink::new();
        metrics.set_gauge("kill_switch_active", 1.0, &[]);
        let mut report = ShutdownReport::default();
        finish_kill_switch_removal(failed(), &metrics, &mut report);
        assert!(report.kill_switch_removal_failed);
        let text = rendered(&metrics);
        assert!(text.contains("torrentd_kill_switch_active 1"), "{text}");
    }

    #[test]
    fn a_removed_kill_switch_reads_inactive_and_reports_nothing() {
        let metrics = PromSink::new();
        metrics.set_gauge("kill_switch_active", 1.0, &[]);
        let mut report = ShutdownReport::default();
        finish_kill_switch_removal(Ok(()), &metrics, &mut report);
        assert!(!report.kill_switch_removal_failed);
        let text = rendered(&metrics);
        assert!(text.contains("torrentd_kill_switch_active 0"), "{text}");
    }

    #[test]
    fn a_failed_boot_that_cannot_remove_the_kill_switch_leaves_a_report() {
        let dir = tempfile::tempdir().unwrap();
        finish_boot_kill_switch_removal(dir.path(), failed());
        assert_eq!(
            take_shutdown_report(dir.path()),
            ShutdownReport {
                unsaved_resumes: 0,
                kill_switch_removal_failed: true,
            }
        );

        finish_boot_kill_switch_removal(dir.path(), Ok(()));
        assert!(
            !shutdown_report_path(dir.path()).exists(),
            "a removal that worked writes no report"
        );
    }

    /// An unclean exit left the table, and the operator
    /// turned the kill switch off. The boot removes it and says so, and
    /// neither a failure nor a host without `nft` stops the boot.
    #[test]
    fn a_boot_with_the_kill_switch_off_removes_a_stale_table() {
        const T: &str = "torrentd_ks_998";
        assert_eq!(
            remove_stale_kill_switch(true, T, || Ok(true)),
            StaleKillSwitch::Removed
        );
        assert_eq!(
            remove_stale_kill_switch(true, T, || Ok(false)),
            StaleKillSwitch::Absent
        );
        assert_eq!(
            remove_stale_kill_switch(true, T, || failed().map(|()| true)),
            StaleKillSwitch::Failed
        );
        assert_eq!(
            remove_stale_kill_switch(false, T, || panic!("no nft, so nothing is asked of it")),
            StaleKillSwitch::NoNft
        );
    }

    /// #168: an OpenVPN daemon with the kill switch off boots beside a
    /// WireGuard daemon whose kill switch is in force under another uid. Its
    /// boot finds that table listed and leaves it standing; only its own uid's
    /// stale table is removed.
    #[test]
    fn a_boot_with_the_kill_switch_off_leaves_another_daemons_table() {
        let others = || Ok("table inet torrentd_ks_998\n".to_string());
        assert_eq!(
            remove_stale_kill_switch(true, "torrentd_ks_1000", || {
                crate::vpn::killswitch::disable_with(
                    1000,
                    others,
                    |_| panic!("no legacy table is listed"),
                    |name| panic!("{name} is the other daemon's kill switch, and stays"),
                )
            }),
            StaleKillSwitch::Absent
        );

        let deleted = std::cell::RefCell::new(Vec::new());
        assert_eq!(
            remove_stale_kill_switch(true, "torrentd_ks_1000", || {
                crate::vpn::killswitch::disable_with(
                    1000,
                    || Ok("table inet torrentd_ks_998\ntable inet torrentd_ks_1000\n".into()),
                    |_| panic!("no legacy table is listed"),
                    |name| {
                        deleted.borrow_mut().push(name.to_string());
                        Ok(())
                    },
                )
            }),
            StaleKillSwitch::Removed
        );
        assert_eq!(*deleted.borrow(), ["torrentd_ks_1000"]);
    }
}
