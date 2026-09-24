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

/// Readiness.
///
/// `profiles` is the **live** count — sessions that came up — and
/// `profiles_failed` is how many configured profiles never got one. They are
/// reported separately because a payload that only ever showed the live count
/// gave no hint an account was missing: two configured vpn profiles with one
/// tunnel down answered `{"ok":true,"profiles":1,"profiles_fenced":0}`, and
/// `all_profiles_fenced` could not fire for a startup failure because a failed
/// profile is not in the total it compares against.
///
/// A daemon running **no** live session answers 503 whatever the reason —
/// `profiles == 0` is not ready by any definition an operator would recognise,
/// and it is the state a total bring-up failure produces. Some-but-not-all
/// failed stays 200: the profiles that did come up are serving, and taking the
/// daemon out of rotation would stop them too. `profiles_failed` and
/// `torrentd_profile_vpn_tunnel_up` are what to alert on for that.
pub async fn healthz(State(s): State<AppState>) -> impl IntoResponse {
    let n_profiles = s.source.profiles().len();
    let n_failed = s.profiles.failed().len();
    if n_profiles == 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "reason": "no_sessions",
                "profiles": 0,
                "profiles_failed": n_failed,
            })),
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
                "profiles": n_profiles,
                "profiles_failed": n_failed,
                "heartbeat_age_secs": age.as_secs(),
            })),
        )
            .into_response();
    }

    // A fenced profile is a profile whose tunnel the monitor found unhealthy: its
    // torrents are paused, it will not resume without an operator, and it is
    // seeding nothing. A daemon in which *every* profile is in that state is not
    // healthy by any definition an operator would recognise, and reporting
    // `{"ok":true}` for it meant the probe was green through exactly the
    // incident it exists to catch.
    //
    // Some-but-not-all fenced stays 200: the remaining profiles are still
    // serving, and taking the daemon out of rotation would stop them too. The
    // count is reported either way, and `torrentd_profile_vpn_tunnel_up` is the
    // per-profile signal to alert on.
    let (fenced, total) = s.fenced_profiles();
    if total > 0 && fenced == total {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "reason": "all_profiles_fenced",
                "profiles": total,
                "profiles_fenced": fenced,
                "profiles_failed": n_failed,
                "heartbeat_age_secs": age.as_secs(),
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "profiles": n_profiles,
            "profiles_fenced": fenced,
            "profiles_failed": n_failed,
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

    #[tokio::test]
    async fn fresh_heartbeat_is_ok() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn body_of(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn a_profile_that_failed_to_come_up_is_counted_in_the_payload() {
        // `profiles` is the live count and always was. Reporting only that
        // gave a two-account deployment with one tunnel down
        // `{"ok":true,"profiles":1,"profiles_fenced":0}` — nothing in the
        // payload hinting an account was missing, and `all_profiles_fenced`
        // could not fire for it either, because a failed profile is not in
        // the total that check compares against.
        use std::sync::Arc;

        use torrentd_engine::ProfileStatus;

        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;

        let reg = Arc::new(
            ProfileRegistry::new(vec![test_entry("a", ProfileStatus::Active)]).with_failed(vec![
                test_failed_profile("b", "wg-b did not come up within 30s"),
            ]),
        );
        let s = build_test_state_with_sessions(Some(reg), &["a"]);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);

        let resp = healthz(State(s)).await.into_response();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "one account is still serving"
        );
        let body = body_of(resp).await;
        assert_eq!(body["profiles"], 1, "the live count, as documented");
        assert_eq!(body["profiles_failed"], 1, "body: {body}");
    }

    #[tokio::test]
    async fn a_daemon_whose_every_profile_failed_to_come_up_is_unready() {
        // A readiness probe on a daemon running zero sessions must not answer
        // ready. This is the state a total bring-up failure produces, and it
        // is not reachable through `all_profiles_fenced`.
        use std::sync::Arc;

        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;

        let reg = Arc::new(
            ProfileRegistry::new(vec![])
                .with_failed(vec![test_failed_profile("a", "wg-a did not come up")]),
        );
        let s = build_test_state_with_sessions(Some(reg), &[]);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);

        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_of(resp).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["profiles_failed"], 1, "body: {body}");
    }

    #[tokio::test]
    async fn a_daemon_with_every_profile_fenced_is_unready() {
        use std::sync::Arc;

        use torrentd_engine::ProfileStatus;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let reg = Arc::new(ProfileRegistry::new(vec![
            test_entry("a", ProfileStatus::VpnDown),
            test_entry("b", ProfileStatus::VpnDown),
        ]));
        let s = build_test_state(Some(reg));
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_host_profile_can_never_fence_the_daemon() {
        // A host profile has no tunnel, so it is never `VpnDown`. A daemon of
        // host profiles alone must therefore never report all-fenced.
        use std::sync::Arc;

        use crate::profile_registry::test_host_entry;
        use crate::profile_registry::ProfileRegistry;

        let reg = Arc::new(ProfileRegistry::new(vec![
            test_host_entry("a"),
            test_host_entry("b"),
        ]));
        let s = build_test_state(Some(reg));
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn one_healthy_profile_keeps_the_daemon_in_rotation() {
        use std::sync::Arc;

        use torrentd_engine::ProfileStatus;

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;

        let reg = Arc::new(ProfileRegistry::new(vec![
            test_entry("a", ProfileStatus::VpnDown),
            test_entry("b", ProfileStatus::Active),
        ]));
        let s = build_test_state(Some(reg));
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let resp = healthz(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
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
