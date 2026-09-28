//! Fault injection for the alert drill: `POST /v1/faults`.
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
use std::sync::Weak;
use std::time::Duration;

use kynos::prelude::*;
use kynos::security::auth::Scoped;
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
use torrentd_engine::EngineError;
use torrentd_engine::MetricsSink;
use torrentd_engine::MockEngine;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentDetails;
use torrentd_engine::TorrentEngine;
use torrentd_engine::TorrentFile;
use torrentd_engine::TrackerEntry;

use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Write;
use crate::http::v1::common::internal;
use crate::http::v1::common::InfoHashHex;
use crate::http::v1::Testing;
use crate::http::validate::from_invalid;
use crate::http::validate::Invalid;

/// The longest stall accepted. Long enough for `TorrentdAlertLoopStalled`
/// (15 s, held for a minute) with room for scrape and evaluation; bounded so
/// a typo cannot wedge the daemon past any drill's deadline.
pub const MAX_STALL_SECS: u64 = 600;

/// The info-hash a per-torrent fault names when the request gives none.
const DEFAULT_INFOHASH: InfoHash = InfoHash([0xfa; 20]);

/// Every [`FaultEngine`] this process built, for the endpoint to find a
/// profile's by identity. Weak, so a session is still dropped when the daemon
/// drops it at shutdown rather than outliving it here.
static ENGINES: Mutex<Vec<Weak<FaultEngine>>> = Mutex::new(Vec::new());

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
        let mut engines = ENGINES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        engines.retain(|e| e.strong_count() > 0);
        engines.push(Arc::downgrade(&engine));
        engine
    }

    /// The fault engine `engine` is, if it is one.
    fn find(engine: &Arc<dyn TorrentEngine>) -> Option<Arc<FaultEngine>> {
        ENGINES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .find(|f| std::ptr::addr_eq(Arc::as_ptr(f), Arc::as_ptr(engine)))
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
    fn torrent_details(&self, h: TorrentHandle) -> Result<TorrentDetails, EngineError> {
        self.inner.torrent_details(h)
    }
    fn torrent_files(&self, h: TorrentHandle) -> Result<Option<Vec<TorrentFile>>, EngineError> {
        self.inner.torrent_files(h)
    }
    fn torrent_trackers(&self, h: TorrentHandle) -> Result<Vec<TrackerEntry>, EngineError> {
        self.inner.torrent_trackers(h)
    }
}

/// One fault to inject, named by `fault`. The module docs of
/// `http/fault_injection.rs` say what each does and which alert it is for.
#[derive(Debug, Deserialize, Schema)]
#[serde(tag = "fault", rename_all = "snake_case", deny_unknown_fields)]
pub enum Fault {
    /// Queue an `alerts_dropped_alert` on the profile's session.
    AlertQueueOverflow {
        /// The live profile whose session gets the alert.
        profile_id: String,
    },
    /// Queue a `portmap_error_alert` on the profile's session.
    PortmapError {
        /// The live profile whose session gets the alert.
        profile_id: String,
    },
    /// Queue a `performance_alert` on the profile's session.
    PerformanceWarning {
        /// The live profile whose session gets the alert.
        profile_id: String,
    },
    /// Queue a `torrent_error_alert` on the profile's session.
    TorrentError {
        /// The live profile whose session gets the alert.
        profile_id: String,
        /// The torrent the alert names; a fixed placeholder when absent.
        #[serde(default)]
        infohash: Option<InfoHashHex>,
    },
    /// Queue a `file_error_alert` on the profile's session.
    FileError {
        /// The live profile whose session gets the alert.
        profile_id: String,
        /// The torrent the alert names; a fixed placeholder when absent.
        #[serde(default)]
        infohash: Option<InfoHashHex>,
    },
    /// Queue a `save_resume_data_failed_alert` on the profile's session.
    SaveResumeFailed {
        /// The live profile whose session gets the alert.
        profile_id: String,
        /// The torrent the alert names; a fixed placeholder when absent.
        #[serde(default)]
        infohash: Option<InfoHashHex>,
    },
    /// Queue a `save_resume_data_alert`, which the resume store then writes.
    SaveResume {
        /// The live profile whose session gets the alert.
        profile_id: String,
        /// The torrent the alert names; a fixed placeholder when absent.
        #[serde(default)]
        infohash: Option<InfoHashHex>,
    },
    /// Block the profile's next alert drain.
    StallAlertLoop {
        /// The live profile whose alert drain stalls.
        profile_id: String,
        /// How long the drain blocks, in seconds: 1 to 600.
        #[schema(minimum = 1, maximum = 600)]
        secs: u64,
    },
    /// Make the profile's next `apply_settings` panic.
    PanicApplySettings {
        /// The live profile whose session panics.
        profile_id: String,
    },
    // The two field-less faults are empty struct variants, not unit ones:
    // serde ignores `deny_unknown_fields` on a unit variant of an internally
    // tagged enum, so `{"fault":"kill_switch_gone","x":1}` would be accepted
    // against a schema that refuses it.
    /// Emit a sample with a label set its series does not have.
    MetricsLabelMismatch {},
    /// Report the kill switch active and its nftables table gone.
    KillSwitchGone {},
    /// Count a failed pause while fencing the profile.
    FencePauseFailed {
        /// The live profile the failure is counted against.
        profile_id: String,
    },
    /// Count a failed write to a store.
    StoreWriteFailed {
        /// One of the `store` label values `store_write_errors_total` has.
        store: String,
    },
    /// Count a failed pool plan.
    PoolPlanFailed {
        /// One of the `kind` label values `pool_plan_failures_total` has.
        kind: String,
    },
}

/// Why a fault was not injected.
#[derive(Debug, thiserror::Error, ApiError)]
#[problem(base = "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#")]
pub enum FaultError {
    /// A value is outside what the fault accepts.
    #[error("{summary}")]
    #[problem(status = 422, title = "The request is invalid")]
    ValidationFailed {
        summary: String,
        /// Every violated constraint.
        #[problem(extension)]
        errors: serde_json::Value,
    },
    /// No live profile has this id.
    #[error("no live profile {0:?}")]
    #[problem(status = 404, title = "Profile not found")]
    ProfileNotFound(String),
    /// The profile's session is not a fault engine.
    #[error("{detail}")]
    #[problem(status = 500, title = "Internal error")]
    Internal { detail: String },
}
from_invalid!(FaultError);

fn invalid(pointer: &str, detail: String) -> FaultError {
    let mut invalid = Invalid::new();
    invalid.push(pointer, detail);
    invalid.into()
}

/// Inject a fault for the alert drill.
///
/// Present only in a `fault-injection` build. `204` once the fault is in
/// place: a queued alert is dispatched by the alert loop's next drain, not by
/// the time this returns.
#[kynos::post("/faults", tag = Testing)]
pub async fn inject_fault(
    _caller: Scoped<Bearer, Write>,
    Inject(state): Inject<Arc<AppState>>,
    Json(fault): Json<Fault>,
) -> Result<NoContent, FaultError> {
    tracing::warn!(fault = ?fault, "fault-injection build: injecting a fault");
    apply(&state, fault)?;
    Ok(NoContent)
}

fn apply(state: &AppState, fault: Fault) -> Result<(), FaultError> {
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
                hdr: header(AlertKind::TorrentError, Some(infohash_of(infohash))),
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
                hdr: header(AlertKind::FileError, Some(infohash_of(infohash))),
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
                hdr: header(AlertKind::SaveResumeDataFailed, Some(infohash_of(infohash))),
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
                hdr: header(AlertKind::SaveResumeData, Some(infohash_of(infohash))),
                data: ResumeData::new(Vec::new()),
            };
            engine(state, &profile_id)?.faults.push_alert(alert);
        }
        Fault::StallAlertLoop { profile_id, secs } => {
            if secs == 0 || secs > MAX_STALL_SECS {
                return Err(invalid(
                    "/secs",
                    format!("must be between 1 and {MAX_STALL_SECS}"),
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
        Fault::MetricsLabelMismatch {} => {
            // Seeded at boot with its `store` label, so a sample without one
            // is exactly the mismatch the exporter counts and drops.
            metrics.inc_counter("store_write_errors_total", &[]);
        }
        Fault::KillSwitchGone {} => {
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
            let store = catalogued_value("store_write_errors_total", "/store", &store)?;
            metrics.inc_counter("store_write_errors_total", &[("store", store)]);
        }
        Fault::PoolPlanFailed { kind } => {
            let kind = catalogued_value("pool_plan_failures_total", "/kind", &kind)?;
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

fn infohash_of(infohash: Option<InfoHashHex>) -> InfoHash {
    infohash.map_or(DEFAULT_INFOHASH, InfoHashHex::get)
}

/// The fault engine of a live profile.
fn engine(state: &AppState, profile_id: &str) -> Result<Arc<FaultEngine>, FaultError> {
    let Some(engine) = state.source.engine_for(&ProfileId::new(profile_id)) else {
        return Err(FaultError::ProfileNotFound(profile_id.to_owned()));
    };
    FaultEngine::find(&engine).ok_or_else(|| FaultError::Internal {
        detail: internal(
            "injecting a fault",
            format!("profile {profile_id:?} has no fault engine"),
        ),
    })
}

/// `value` as one of the catalogued values of `series`' label, so an injected
/// sample is one the real code could have written.
fn catalogued_value(series: &str, pointer: &str, value: &str) -> Result<&'static str, FaultError> {
    let values = crate::metrics_sink::catalogued(series)
        .and_then(|s| s.label)
        .map(|(_, values)| values)
        .unwrap_or_default();
    values
        .iter()
        .copied()
        .find(|v| *v == value)
        .ok_or_else(|| invalid(pointer, format!("{value:?} is not one of {values:?}")))
}

/// Mount `POST /v1/faults` on `$group`.
macro_rules! fault_routes {
    ($group:expr) => {
        $group.mount(kynos::routes![crate::http::fault_injection::inject_fault])
    };
}
pub(crate) use fault_routes;

/// Every declared response of `POST /v1/faults`, through the router.
#[cfg(test)]
pub(crate) async fn scenarios(cov: &Arc<crate::http::tests::support::Coverage>) {
    use serde_json::json;

    use crate::http::tests::support::assert_problem;
    use crate::http::tests::support::Harness;

    let engine = FaultEngine::wrap(Arc::new(MockEngine::new()));
    let source_engine = Arc::clone(&engine);
    let h = Harness::authed(cov, move |s| {
        s.source = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            source_engine,
        )]));
    });
    let write = h.tokens.write.clone();
    let post = |body: serde_json::Value| h.send("POST", "/v1/faults", Some(&write), Some(body));

    // A queued fault reaches the profile's next drain.
    post(json!({"fault": "portmap_error", "profile_id": "p"}))
        .await
        .assert_status(kynos::http::StatusCode::NO_CONTENT);
    let kinds: Vec<AlertKind> = engine.pop_alerts().iter().map(Alert::kind).collect();
    assert_eq!(kinds, vec![AlertKind::PortmapError]);

    // A value outside what the fault accepts says where.
    let resp = post(json!({"fault": "stall_alert_loop", "profile_id": "p", "secs": 0})).await;
    assert_problem(&resp, 422, "validation-failed");
    let body: serde_json::Value = resp.json();
    assert_eq!(body["errors"][0]["pointer"], "/secs");
    let resp = post(json!({"fault": "store_write_failed", "store": "nope"})).await;
    assert_problem(&resp, 422, "validation-failed");

    // An unknown profile is not found.
    let resp = post(json!({"fault": "portmap_error", "profile_id": "nope"})).await;
    assert_problem(&resp, 404, "profile-not-found");

    // An unknown fault, or a malformed infohash, is refused as unparseable —
    // the drill's probe for a fault-injection build relies on the 422.
    let resp = post(json!({"fault": "none"})).await;
    assert_eq!(resp.status().as_u16(), 422);
    let resp = post(json!({"fault": "file_error", "profile_id": "p", "infohash": "00"})).await;
    assert_eq!(resp.status().as_u16(), 422);
    h.send_with(
        "POST",
        "/v1/faults",
        Some(&write),
        None,
        &[("content-type", "application/json")],
    )
    .await
    .assert_status(kynos::http::StatusCode::BAD_REQUEST);
    h.send_with(
        "POST",
        "/v1/faults",
        Some(&write),
        None,
        &[("content-type", "text/plain")],
    )
    .await
    .assert_status(kynos::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let huge = "x".repeat(crate::http::v1::MAX_BODY_BYTES + 1);
    let resp = post(json!({"fault": "portmap_error", "profile_id": huge})).await;
    assert_eq!(resp.status().as_u16(), 413);

    // `write` is needed.
    let resp = h
        .send(
            "POST",
            "/v1/faults",
            None,
            Some(json!({"fault": "kill_switch_gone"})),
        )
        .await;
    assert_eq!(resp.status().as_u16(), 401);
    let read = h.tokens.read.clone();
    let resp = h
        .send(
            "POST",
            "/v1/faults",
            Some(&read),
            Some(json!({"fault": "kill_switch_gone"})),
        )
        .await;
    assert_problem(&resp, 403, "insufficient-scope");
    h.assert_conformance();

    // A profile whose session is not a fault engine is the daemon's fault.
    let plain = Harness::authed(cov, |_| {});
    let resp = plain
        .send(
            "POST",
            "/v1/faults",
            Some(&plain.tokens.write.clone()),
            Some(json!({"fault": "portmap_error", "profile_id": "p"})),
        )
        .await;
    assert_problem(&resp, 500, "internal");
    plain.assert_conformance();
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
    fn the_registry_does_not_keep_a_dropped_session_alive() {
        let (engine, inner) = wrapped();
        drop(engine);
        assert_eq!(Arc::strong_count(&inner), 1);
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

    const IH: &str = "fafafafafafafafafafafafafafafafafafafafa";

    #[test]
    fn every_fault_name_parses() {
        for body in [
            r#"{"fault":"alert_queue_overflow","profile_id":"p"}"#,
            r#"{"fault":"portmap_error","profile_id":"p"}"#,
            r#"{"fault":"performance_warning","profile_id":"p"}"#,
            r#"{"fault":"torrent_error","profile_id":"p"}"#,
            r#"{"fault":"file_error","profile_id":"p","infohash":"0101010101010101010101010101010101010101"}"#,
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
    fn a_fault_is_a_closed_request() {
        for body in [
            // Not an infohash: refused where it is parsed, before anything
            // is queued.
            r#"{"fault":"file_error","profile_id":"p","infohash":"00"}"#,
            r#"{"fault":"portmap_error","profile_id":"p","extra":1}"#,
            r#"{"fault":"kill_switch_gone","profile_id":"p"}"#,
            r#"{"fault":"none"}"#,
        ] {
            assert!(serde_json::from_str::<Fault>(body).is_err(), "{body}");
        }
    }

    #[test]
    fn an_uncatalogued_label_value_is_refused() {
        assert_eq!(
            catalogued_value("store_write_errors_total", "/store", "registry").unwrap(),
            "registry"
        );
        let err = catalogued_value("store_write_errors_total", "/store", "nope").unwrap_err();
        assert!(
            matches!(err, FaultError::ValidationFailed { .. }),
            "{err:?}"
        );
        assert_eq!(infohash_of(None), DEFAULT_INFOHASH);
        assert_eq!(infohash_of(Some(IH.parse().unwrap())), DEFAULT_INFOHASH);
    }

    /// A state whose one live profile, `p`, is a fault engine.
    fn state_with_fault_engine() -> (AppState, Arc<dyn TorrentEngine>) {
        let (engine, _inner) = wrapped();
        let mut state = crate::app_state::build_test_state(None);
        state.source = Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            Arc::clone(&engine),
        )]));
        (state, engine)
    }

    fn stall(profile_id: &str, secs: u64) -> Fault {
        Fault::StallAlertLoop {
            profile_id: profile_id.to_string(),
            secs,
        }
    }

    #[test]
    fn a_stall_outside_one_to_max_secs_is_refused_before_anything_is_armed() {
        let (state, engine) = state_with_fault_engine();
        for secs in [0, MAX_STALL_SECS + 1] {
            let err = apply(&state, stall("p", secs)).unwrap_err();
            assert!(
                matches!(err, FaultError::ValidationFailed { .. }),
                "secs = {secs}"
            );
        }
        // Nothing was armed: the next drain returns at once.
        let started = std::time::Instant::now();
        engine.pop_alerts();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(apply(&state, stall("p", MAX_STALL_SECS)).is_ok());
    }

    #[tokio::test]
    async fn faults_behave_as_documented() {
        scenarios(&crate::http::tests::support::Coverage::new()).await;
    }
}
