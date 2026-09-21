//! `GET /healthz` — readiness probe for systemd / load balancers.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use torrentd_engine::heartbeat_age;

use crate::app_state::AppState;

/// How stale the alert loop's heartbeat may get before the daemon reports
/// unready.
///
/// The loop stamps it at the top of every iteration and sleeps at most 100ms
/// when idle, so anything approaching this is pathological. Kept well under the
/// unit's `WatchdogSec=60s` so a probe notices first, and above the worst-case
/// dispatch of one full `alert_queue_size` batch.
const MAX_HEARTBEAT_AGE: std::time::Duration = std::time::Duration::from_secs(15);

pub async fn healthz(State(s): State<AppState>) -> impl IntoResponse {
    let n_slots = s.source.slots().len();
    if n_slots == 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"ok": false, "reason": "no_sessions"})),
        )
            .into_response();
    }

    // A live session count alone isn't readiness: if the alert loop has wedged
    // or died, the state map silently freezes and the daemon stops persisting
    // resume data while still answering every other endpoint.
    let age = heartbeat_age(&s.alert_heartbeat);
    if age > MAX_HEARTBEAT_AGE {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "reason": "alert_loop_stalled",
                "heartbeat_age_secs": age.as_secs(),
            })),
        )
            .into_response();
    }

    // A fenced slot is a slot whose tunnel the monitor found unhealthy — or
    // one whose tunnel never came up at boot: its torrents are paused (or
    // were never loaded), it will not resume without an operator, and it is
    // seeding nothing. A daemon in which *every* slot is in that state is not
    // healthy by any definition an operator would recognise, and reporting
    // `{"ok":true}` for it meant the probe was green through exactly the
    // incident it exists to catch.
    //
    // Some-but-not-all fenced stays 200: the remaining slots are still
    // serving, and taking the daemon out of rotation would stop them too. The
    // count is reported either way, and `torrentd_slot_vpn_tunnel_up` is the
    // per-slot signal to alert on.
    //
    // `slots` counts **configured** slots in both responses — the registry's
    // live entries *plus* the slots whose tunnel never came up — and a slot
    // that failed at boot is counted as fenced, because it has no session at
    // all. `slots_fenced` is counted over the same set, so the two read as a
    // coherent fraction whose denominator does not move during an incident.
    //
    // Counting the registry's live entries alone was the same number as the
    // alert source's live sessions, so `slots` shrank exactly when the probe
    // was being read: three configured slots with one tunnel down at boot
    // answered `{"ok":true,"slots":2,"slots_fenced":0}`, and a dashboard
    // reading the documented meaning saw a fully healthy daemon with a third
    // of the operator's accounts dark. Single-session mode has no registry,
    // and there its one session is the configured set.
    //
    // Computed once. It walks the registry twice per call, and the previous
    // shape called it twice and then shadowed the first binding.
    let (fenced, slots) = s.fenced_slots().unwrap_or((0, n_slots));
    if slots > 0 && fenced == slots {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "reason": "all_slots_fenced",
                "slots": slots,
                "slots_fenced": fenced,
                "heartbeat_age_secs": age.as_secs(),
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "slots": slots,
            "slots_fenced": fenced,
            "heartbeat_age_secs": age.as_secs(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use axum::extract::State;
    use axum::response::IntoResponse;

    use super::*;
    use crate::app_state::build_test_state;

    fn millis_ago(d: std::time::Duration) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        now.saturating_sub(d.as_millis() as u64)
    }

    /// The probe's *body*, not just its status. A load balancer reads the
    /// status; the operator's dashboard and runbook read these keys.
    async fn body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("healthz bodies are small");
        serde_json::from_slice(&bytes).expect("healthz answers JSON")
    }

    #[tokio::test]
    async fn fresh_heartbeat_is_ok() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_daemon_with_every_slot_fenced_is_unready() {
        use std::sync::Arc;

        use torrentd_engine::SlotStatus;

        use crate::slot_registry::test_entry;
        use crate::slot_registry::SlotRegistry;

        let reg = Arc::new(SlotRegistry::new(vec![
            test_entry("a", SlotStatus::VpnDown),
            test_entry("b", SlotStatus::VpnDown),
        ]));
        let s = build_test_state(Some(reg));
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let b = body(resp).await;
        assert_eq!(b["reason"], "all_slots_fenced");
        assert_eq!(b["slots"], 2, "configured slots");
        assert_eq!(b["slots_fenced"], 2);
    }

    #[tokio::test]
    async fn one_healthy_slot_keeps_the_daemon_in_rotation() {
        use std::sync::Arc;

        use torrentd_engine::SlotStatus;

        use crate::slot_registry::test_entry;
        use crate::slot_registry::test_failed_slot;
        use crate::slot_registry::SlotRegistry;

        // Three slots configured, and `c`'s tunnel failed at boot, so it
        // never got a session at all. The registry holds two entries and one
        // failed slot: `iter()` walks the entries, which is the same set the
        // alert source reports as live sessions.
        let reg = Arc::new(
            SlotRegistry::new(vec![
                test_entry("a", SlotStatus::VpnDown),
                test_entry("b", SlotStatus::Active),
            ])
            .with_failed(vec![test_failed_slot("c")]),
        );
        let s = build_test_state(Some(reg));
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        // `slots` is the configured count in *both* responses, so `fenced /
        // slots` is a fraction of one denominator wherever it is read. The
        // fixture has a failed slot precisely so the two readings differ:
        // counting live entries answers 1/2 -- which is what shipped -- and
        // the documented meaning answers 2/3, with the dark account visible.
        let b = body(resp).await;
        assert_eq!(b["ok"], true);
        assert_eq!(b["slots"], 3, "configured slots, not live sessions");
        assert_eq!(
            b["slots_fenced"], 2,
            "a slot with no session is worse off than a fenced one, not better",
        );
    }

    /// The 503 threshold reads the same denominator: one live slot fenced and
    /// one that never came up is *every* configured slot out of service, and
    /// a load balancer that keeps sending traffic to it has nowhere for the
    /// traffic to go.
    #[tokio::test]
    async fn a_fenced_slot_beside_a_slot_that_never_came_up_is_unready() {
        use std::sync::Arc;

        use torrentd_engine::SlotStatus;

        use crate::slot_registry::test_entry;
        use crate::slot_registry::test_failed_slot;
        use crate::slot_registry::SlotRegistry;

        let reg = Arc::new(
            SlotRegistry::new(vec![test_entry("a", SlotStatus::VpnDown)])
                .with_failed(vec![test_failed_slot("b")]),
        );
        let s = build_test_state(Some(reg));
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let b = body(resp).await;
        assert_eq!(b["reason"], "all_slots_fenced");
        assert_eq!(b["slots"], 2);
        assert_eq!(b["slots_fenced"], 2);
    }

    #[tokio::test]
    async fn a_healthy_single_session_reports_its_one_slot_unfenced() {
        // No registry here, so `fenced_slots()` is `None` and the response
        // falls back to the session count — single-session mode has no
        // tunnel to lose, and its one session *is* the configured set.
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body(resp).await;
        assert_eq!(b["slots"], 1);
        assert_eq!(b["slots_fenced"], 0);
    }

    #[tokio::test]
    async fn stalled_alert_loop_is_unready() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(MAX_HEARTBEAT_AGE * 2), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
