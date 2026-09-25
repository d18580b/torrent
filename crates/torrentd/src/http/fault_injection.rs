//! Fault injection for the alert drill: `POST /api/fault`.
//!
//! Compiled only with `--features fault-injection`, which is off by default
//! and which no release image enables. `deploy/drill/run.sh` builds an image
//! with it and uses this endpoint to reach the faults that have no trigger
//! outside the process, then asserts each one's alert arrives.
//!
//! Every session in this build is a real libtorrent session with a
//! [`MockEngine`] layered over it ([`FaultEngine`]): everything the daemon
//! does still goes to libtorrent, so the faults the drill injects from outside
//! stay real, and the mock adds what libtorrent cannot be asked for — a queued
//! alert, a stalled `pop_alerts`, a panicking `apply_settings`.
//!
//! Faults, and the alert each is for:
//!
//! | `fault`                | what happens                                         | alert                        |
//! |------------------------|------------------------------------------------------|------------------------------|
//! | `alert_queue_overflow` | an `alerts_dropped_alert` is queued                  | `TorrentdAlertQueueOverflow` |
//! | `portmap_error`        | a `portmap_error_alert` is queued                    | `TorrentdSessionErrors`      |
//! | `performance_warning`  | a `performance_alert` is queued                      | `TorrentdPerformanceWarning` |
//! | `torrent_error`        | a `torrent_error_alert` is queued                    | `TorrentdTorrentErrors`      |
//! | `file_error`           | a `file_error_alert` is queued                       | `TorrentdDiskErrors`         |
//! | `save_resume_failed`   | a `save_resume_data_failed_alert` is queued          | `TorrentdResumeSaveFailures` |
//! | `save_resume`          | a `save_resume_data_alert` is queued; the resume store writes it, which fails where the drill has blocked the path | `TorrentdResumeWriteErrors` |
//! | `stall_alert_loop`     | the alert loop's next drain blocks for `secs`        | `TorrentdAlertLoopStalled`   |
//! | `panic_apply_settings` | the profile's next `apply_settings` panics; a reload that changes a setting makes the reload task make that call | `TorrentdTaskDown` |
//! | `metrics_label_mismatch` | a sample is emitted with a label set its series does not have, and the exporter drops it | `TorrentdMetricsDropped` |
//! | `kill_switch_gone`     | `kill_switch_active` 1, `kill_switch_table_present` 0 | `TorrentdKillSwitchGone`     |
//! | `fence_pause_failed`   | `profile_fence_pause_errors_total` +1                 | `TorrentdFencePauseFailed`   |
//! | `store_write_failed`   | `store_write_errors_total{store}` +1                  | `TorrentdStoreWriteFailed`   |
//! | `pool_plan_failed`     | `pool_plan_failures_total{kind}` +1                   | `TorrentdPoolPlanFailed`     |
//!
//! The last four write the series the code that owns them writes, through the
//! daemon's own sink, because what they stand for — an nftables table, a
//! tunnel to fence, a store or a pool plan that fails to write — needs a host
//! the drill does not have. They prove the path from that series to the
//! webhook, not the code that moves it; that code has unit tests.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use libtorrent_safe::alert::AlertHeader;
use libtorrent_safe::AddParams;
use libtorrent_safe::Alert;
use libtorrent_safe::AlertKind;
use libtorrent_safe::InfoHash;
use libtorrent_safe::MoveFlags;
use libtorrent_safe::ResumeData;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::Settings;
use libtorrent_safe::TorrentHandle;
use serde::Deserialize;
use serde_json::json;
use serde_json::Value;
use torrentd_engine::EngineError;
use torrentd_engine::MetricsSink;
use torrentd_engine::MockEngine;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentEngine;

use crate::app_state::AppState;

/// The longest stall accepted. Long enough for `TorrentdAlertLoopStalled`
/// (15 s, held for a minute) with room for scrape and evaluation; bounded so
/// a typo cannot wedge the daemon past any drill's deadline.
pub const MAX_STALL_SECS: u64 = 600;

/// The info-hash a per-torrent fault names when the request gives none.
const DEFAULT_INFOHASH: InfoHash = InfoHash([0xfa; 20]);

/// Every [`FaultEngine`] this process built, for the endpoint to find a
/// profile's by identity. Only this build has one, and it lives as long as the
/// process does, like the sessions in it.
static ENGINES: Mutex<Vec<Arc<FaultEngine>>> = Mutex::new(Vec::new());

/// A real session with a [`MockEngine`] layered over it.
///
/// Every operation goes to `inner`. `pop_alerts` drains the mock first, so a
/// queued alert is dispatched like one libtorrent posted and an armed stall
/// blocks the loop that drains it; `apply_settings` passes through the mock
/// first, so an armed panic or error happens before libtorrent is called.
#[derive(Debug)]
pub struct FaultEngine {
    inner: Arc<dyn TorrentEngine>,
    faults: MockEngine,
}

impl FaultEngine {
    /// Layer a mock over `inner`, and record it for the endpoint.
    pub fn wrap(inner: Arc<dyn TorrentEngine>) -> Arc<dyn TorrentEngine> {
        let engine = Arc::new(FaultEngine {
            inner,
            faults: MockEngine::new().without_recording(),
        });
        ENGINES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(engine.clone());
        engine
    }

    /// The fault engine `engine` is, if it is one.
    fn find(engine: &Arc<dyn TorrentEngine>) -> Option<Arc<FaultEngine>> {
        ENGINES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .find(|f| std::ptr::addr_eq(Arc::as_ptr(f), Arc::as_ptr(engine)))
            .cloned()
    }
}

impl TorrentEngine for FaultEngine {
    fn add_torrent(&self, params: AddParams) -> Result<TorrentHandle, EngineError> {
        self.inner.add_torrent(params)
    }
    fn remove_torrent(&self, h: TorrentHandle, delete_files: bool) -> Result<(), EngineError> {
        self.inner.remove_torrent(h, delete_files)
    }
    fn pause_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.inner.pause_torrent(h)
    }
    fn resume_torrent(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.inner.resume_torrent(h)
    }
    fn save_resume_data(&self, h: TorrentHandle, flags: ResumeFlags) -> Result<(), EngineError> {
        self.inner.save_resume_data(h, flags)
    }
    fn pop_alerts(&self) -> Vec<Alert> {
        let mut alerts = self.faults.pop_alerts();
        alerts.extend(self.inner.pop_alerts());
        alerts
    }
    fn post_updates(&self) {
        self.inner.post_updates()
    }
    fn post_stats(&self) {
        self.inner.post_stats()
    }
    fn set_upload_limit(&self, h: TorrentHandle, bytes_per_sec: i32) -> Result<(), EngineError> {
        self.inner.set_upload_limit(h, bytes_per_sec)
    }
    fn set_file_priority(
        &self,
        h: TorrentHandle,
        file_idx: i32,
        priority: u8,
    ) -> Result<(), EngineError> {
        self.inner.set_file_priority(h, file_idx, priority)
    }
    fn force_recheck(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.inner.force_recheck(h)
    }
    fn force_reannounce(&self, h: TorrentHandle) -> Result<(), EngineError> {
        self.inner.force_reannounce(h)
    }
    fn move_storage(
        &self,
        h: TorrentHandle,
        new_path: &str,
        flags: MoveFlags,
    ) -> Result<(), EngineError> {
        self.inner.move_storage(h, new_path, flags)
    }
    fn apply_settings(&self, settings: &Settings) -> Result<(), EngineError> {
        self.faults.apply_settings(settings)?;
        self.inner.apply_settings(settings)
    }
    fn session_state(&self) -> Result<Vec<u8>, EngineError> {
        self.inner.session_state()
    }
}

/// A request to `POST /api/fault`. See the module docs for what each does.
#[derive(Debug, Deserialize)]
#[serde(tag = "fault", rename_all = "snake_case")]
pub enum Fault {
    AlertQueueOverflow {
        profile_id: String,
    },
    PortmapError {
        profile_id: String,
    },
    PerformanceWarning {
        profile_id: String,
    },
    TorrentError {
        profile_id: String,
        #[serde(default)]
        infohash: Option<String>,
    },
    FileError {
        profile_id: String,
        #[serde(default)]
        infohash: Option<String>,
    },
    SaveResumeFailed {
        profile_id: String,
        #[serde(default)]
        infohash: Option<String>,
    },
    SaveResume {
        profile_id: String,
        #[serde(default)]
        infohash: Option<String>,
    },
    StallAlertLoop {
        profile_id: String,
        secs: u64,
    },
    PanicApplySettings {
        profile_id: String,
    },
    MetricsLabelMismatch,
    KillSwitchGone,
    FencePauseFailed {
        profile_id: String,
    },
    StoreWriteFailed {
        store: String,
    },
    PoolPlanFailed {
        kind: String,
    },
}

type Refusal = (StatusCode, Json<Value>);

fn refuse(status: StatusCode, message: impl std::fmt::Display) -> Refusal {
    (status, Json(json!({ "error": message.to_string() })))
}

/// `POST /api/fault`: inject one fault. 204 once it is in place — a queued
/// alert is dispatched by the alert loop's next drain, not by the time this
/// returns.
pub async fn inject(
    State(state): State<AppState>,
    Json(fault): Json<Fault>,
) -> Result<StatusCode, Refusal> {
    tracing::warn!(fault = ?fault, "fault-injection build: injecting a fault");
    apply(&state, fault)?;
    Ok(StatusCode::NO_CONTENT)
}

fn apply(state: &AppState, fault: Fault) -> Result<(), Refusal> {
    let metrics = &state.metrics;
    match fault {
        Fault::AlertQueueOverflow { profile_id } => {
            let alert = Alert::AlertsDropped {
                hdr: header(AlertKind::AlertsDropped, None),
                bits: [1, 0],
            };
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::PortmapError { profile_id } => {
            let alert = warning(AlertKind::PortmapError, 0);
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::PerformanceWarning { profile_id } => {
            let alert = warning(AlertKind::Performance, 1);
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::TorrentError {
            profile_id,
            infohash,
        } => {
            let alert = Alert::TorrentError {
                hdr: header(AlertKind::TorrentError, Some(infohash_of(infohash)?)),
                error_code: 5,
                filename: String::new(),
                message: INJECTED.to_string(),
            };
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::FileError {
            profile_id,
            infohash,
        } => {
            let alert = Alert::FileError {
                hdr: header(AlertKind::FileError, Some(infohash_of(infohash)?)),
                error_code: 5,
                filename: String::new(),
                operation: "read".to_string(),
                message: INJECTED.to_string(),
            };
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::SaveResumeFailed {
            profile_id,
            infohash,
        } => {
            let alert = Alert::SaveResumeDataFailed {
                hdr: header(
                    AlertKind::SaveResumeDataFailed,
                    Some(infohash_of(infohash)?),
                ),
                error_code: 5,
                not_modified: false,
                message: INJECTED.to_string(),
            };
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::SaveResume {
            profile_id,
            infohash,
        } => {
            let alert = Alert::SaveResumeData {
                hdr: header(AlertKind::SaveResumeData, Some(infohash_of(infohash)?)),
                data: ResumeData::new(Vec::new()),
            };
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::StallAlertLoop { profile_id, secs } => {
            if secs == 0 || secs > MAX_STALL_SECS {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    format!("secs must be between 1 and {MAX_STALL_SECS}"),
                ));
            }
            engine(state, &profile_id)?
                .faults
                .stall_next_pop(Duration::from_secs(secs));
        }
        Fault::PanicApplySettings { profile_id } => {
            engine(state, &profile_id)?
                .faults
                .inject_panic("apply_settings");
        }
        Fault::MetricsLabelMismatch => {
            // Seeded at boot with its `store` label, so a sample without one
            // is exactly the mismatch the exporter counts and drops.
            metrics.inc_counter("store_write_errors_total", &[]);
        }
        Fault::KillSwitchGone => {
            metrics.set_gauge("kill_switch_active", 1.0, &[]);
            metrics.set_gauge("kill_switch_table_present", 0.0, &[]);
        }
        Fault::FencePauseFailed { profile_id } => {
            engine(state, &profile_id)?;
            metrics.inc_counter(
                "profile_fence_pause_errors_total",
                &[("profile_id", profile_id.as_str())],
            );
        }
        Fault::StoreWriteFailed { store } => {
            let store = catalogued_value("store_write_errors_total", &store)?;
            metrics.inc_counter("store_write_errors_total", &[("store", store)]);
        }
        Fault::PoolPlanFailed { kind } => {
            let kind = catalogued_value("pool_plan_failures_total", &kind)?;
            metrics.inc_counter("pool_plan_failures_total", &[("kind", kind)]);
        }
    }
    Ok(())
}

const INJECTED: &str = "injected by the fault-injection build";

fn header(kind: AlertKind, infohash: Option<InfoHash>) -> AlertHeader {
    AlertHeader {
        kind,
        infohash,
        handle: None,
        timestamp_us: 0,
    }
}

fn warning(kind: AlertKind, warning_code: i32) -> Alert {
    Alert::Warning {
        hdr: header(kind, None),
        error_code: 5,
        warning_code,
        message: INJECTED.to_string(),
    }
}

fn infohash_of(hex: Option<String>) -> Result<InfoHash, Refusal> {
    match hex {
        None => Ok(DEFAULT_INFOHASH),
        Some(hex) => InfoHash::from_hex(&hex).ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                format!("{hex:?} is not a 40-character hex info-hash"),
            )
        }),
    }
}

/// The fault engine of a live profile.
fn engine(state: &AppState, profile_id: &str) -> Result<Arc<FaultEngine>, Refusal> {
    let Some(engine) = state.source.engine_for(&ProfileId::new(profile_id)) else {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            format!("no live profile {profile_id:?}"),
        ));
    };
    FaultEngine::find(&engine).ok_or_else(|| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("profile {profile_id:?} has no fault engine"),
        )
    })
}

/// `value` as one of the catalogued values of `series`' label, so an injected
/// sample is one the real code could have written.
fn catalogued_value(series: &str, value: &str) -> Result<&'static str, Refusal> {
    let values = crate::metrics_sink::catalogued(series)
        .and_then(|s| s.label)
        .map(|(_, values)| values)
        .unwrap_or_default();
    values.iter().copied().find(|v| *v == value).ok_or_else(|| {
        refuse(
            StatusCode::BAD_REQUEST,
            format!("{value:?} is not one of {values:?}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped() -> (Arc<dyn TorrentEngine>, Arc<MockEngine>) {
        let inner = Arc::new(MockEngine::new());
        let engine = FaultEngine::wrap(inner.clone());
        (engine, inner)
    }

    #[test]
    fn a_wrapped_engine_is_found_by_identity_and_nothing_else_is() {
        let (engine, inner) = wrapped();
        assert!(FaultEngine::find(&engine).is_some());
        let other: Arc<dyn TorrentEngine> = inner;
        assert!(FaultEngine::find(&other).is_none());
    }

    #[test]
    fn queued_alerts_come_out_ahead_of_the_session_s() {
        let (engine, inner) = wrapped();
        let fault = FaultEngine::find(&engine).unwrap();
        inner.push_alert(warning(AlertKind::UdpError, 0));
        fault.faults.push_alert(warning(AlertKind::PortmapError, 0));
        let kinds: Vec<AlertKind> = engine.pop_alerts().iter().map(Alert::kind).collect();
        assert_eq!(kinds, vec![AlertKind::PortmapError, AlertKind::UdpError]);
    }

    #[test]
    fn an_armed_panic_fires_before_the_session_is_touched() {
        let (engine, inner) = wrapped();
        FaultEngine::find(&engine)
            .unwrap()
            .faults
            .inject_panic("apply_settings");
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.apply_settings(&Settings::default())
        }));
        assert!(panicked.is_err());
        assert!(inner.calls().is_empty());
        assert!(engine.apply_settings(&Settings::default()).is_ok());
        assert_eq!(inner.calls().len(), 1);
    }

    #[test]
    fn every_fault_name_parses() {
        for body in [
            r#"{"fault":"alert_queue_overflow","profile_id":"p"}"#,
            r#"{"fault":"portmap_error","profile_id":"p"}"#,
            r#"{"fault":"performance_warning","profile_id":"p"}"#,
            r#"{"fault":"torrent_error","profile_id":"p"}"#,
            r#"{"fault":"file_error","profile_id":"p","infohash":"00"}"#,
            r#"{"fault":"save_resume_failed","profile_id":"p"}"#,
            r#"{"fault":"save_resume","profile_id":"p"}"#,
            r#"{"fault":"stall_alert_loop","profile_id":"p","secs":1}"#,
            r#"{"fault":"panic_apply_settings","profile_id":"p"}"#,
            r#"{"fault":"metrics_label_mismatch"}"#,
            r#"{"fault":"kill_switch_gone"}"#,
            r#"{"fault":"fence_pause_failed","profile_id":"p"}"#,
            r#"{"fault":"store_write_failed","store":"registry"}"#,
            r#"{"fault":"pool_plan_failed","kind":"step_failed"}"#,
        ] {
            serde_json::from_str::<Fault>(body).unwrap_or_else(|e| panic!("{body}: {e}"));
        }
    }

    #[test]
    fn an_uncatalogued_label_value_is_refused() {
        assert_eq!(
            catalogued_value("store_write_errors_total", "registry").unwrap(),
            "registry"
        );
        let (status, _) = catalogued_value("store_write_errors_total", "nope").unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(infohash_of(Some("zz".into())).is_err());
        assert_eq!(infohash_of(None).unwrap(), DEFAULT_INFOHASH);
    }
}
