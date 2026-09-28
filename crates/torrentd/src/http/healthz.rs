//! `GET /healthz` — readiness probe for systemd / load balancers.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::Reply;
use serde::Serialize;
use torrentd_engine::heartbeat_age;

use crate::app_state::AppState;
use crate::http::v1::Operations;

/// How stale the alert loop's heartbeat may get before the daemon reports
/// unready.
///
/// The loop stamps it at the top of every iteration and sleeps at most 100ms
/// when idle, so anything approaching this is pathological. Kept well under the
/// unit's `WatchdogSec=60s` so a probe notices first, and above the worst-case
/// dispatch of one full `alert_queue_size` batch.
const MAX_HEARTBEAT_AGE: std::time::Duration = std::time::Duration::from_secs(15);

/// The daemon's readiness, and the counts behind it.
#[derive(Debug, Schema, Serialize)]
pub struct HealthReport {
    /// Whether the daemon is ready. `true` exactly when the status is 200.
    pub ok: bool,
    /// Why the daemon is unready; `null` when it is ready.
    pub reason: Option<HealthReason>,
    /// Profiles with a live session.
    pub profiles: u32,
    /// Live profiles whose VPN tunnel the monitor fenced.
    pub profiles_fenced: u32,
    /// Configured profiles that never came up.
    pub profiles_failed: u32,
    /// Seconds since the alert loop last stamped its heartbeat; `null` when
    /// there is no live session to run one.
    pub heartbeat_age_secs: Option<u64>,
}

/// Why the daemon reports unready.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthReason {
    /// No profile has a live session.
    NoSessions,
    /// The alert loop has not run for longer than fifteen seconds.
    AlertLoopStalled,
    /// Every live profile is fenced: nothing is seeding.
    AllProfilesFenced,
}

/// The two answers `/healthz` gives, with one body shape between them.
#[derive(Reply)]
pub enum Health {
    #[reply(status = 200, description = "The daemon is ready.")]
    Ready(HealthReport),
    #[reply(
        status = 503,
        description = "The daemon is unready; `reason` says why. Take it out of rotation."
    )]
    Unready(HealthReport),
}

/// Readiness.
///
/// `profiles` is the **live** count — sessions that came up — and
/// `profiles_failed` is how many configured profiles never got one. They are
/// reported separately because a payload that only ever showed the live count
/// gave no hint an account was missing.
///
/// A daemon running **no** live session answers 503 whatever the reason — it
/// is the state a total bring-up failure produces. Some-but-not-all failed
/// stays 200: the profiles that did come up are serving, and taking the
/// daemon out of rotation would stop them too. `profiles_failed` and
/// `torrentd_profile_vpn_tunnel_up` are what to alert on for that. The route is
/// unauthenticated: a probe that needs a credential is a probe that breaks
/// during the incident it exists to detect.
#[kynos::get("/healthz", tag = Operations)]
pub async fn get_health(Inject(s): Inject<Arc<AppState>>) -> Health {
    let report = evaluate(&s);
    if report.ok {
        Health::Ready(report)
    } else {
        Health::Unready(report)
    }
}

fn evaluate(s: &AppState) -> HealthReport {
    let count = crate::http::v1::server::count;
    let n_profiles = s.source.profiles().len();
    let n_failed = count(s.profiles.failed().len());
    if n_profiles == 0 {
        return HealthReport {
            ok: false,
            reason: Some(HealthReason::NoSessions),
            profiles: 0,
            profiles_fenced: 0,
            profiles_failed: n_failed,
            heartbeat_age_secs: None,
        };
    }

    // A live session count alone isn't readiness: if the alert loop has wedged
    // or died, the state map silently freezes and the daemon stops persisting
    // resume data while still answering every other endpoint.
    let age = heartbeat_age(&s.alert_heartbeat);
    let (fenced, total) = s.fenced_profiles();
    if age > MAX_HEARTBEAT_AGE {
        return HealthReport {
            ok: false,
            reason: Some(HealthReason::AlertLoopStalled),
            profiles: count(n_profiles),
            profiles_fenced: count(fenced),
            profiles_failed: n_failed,
            heartbeat_age_secs: Some(age.as_secs()),
        };
    }

    // A fenced profile is a profile whose tunnel the monitor found unhealthy:
    // its torrents are paused, it will not resume without an operator, and it
    // is seeding nothing. A daemon in which *every* profile is in that state
    // is not healthy by any definition an operator would recognise.
    //
    // Some-but-not-all fenced stays 200: the remaining profiles are still
    // serving, and taking the daemon out of rotation would stop them too.
    //
    // A profile whose tunnel never came up at boot is not in this fraction —
    // it has no session to fence — and is reported as `profiles_failed`
    // instead. Failed profiles serve nothing, so "every live profile fenced"
    // is "every configured profile out of service".
    if total > 0 && fenced == total {
        return HealthReport {
            ok: false,
            reason: Some(HealthReason::AllProfilesFenced),
            profiles: count(total),
            profiles_fenced: count(fenced),
            profiles_failed: n_failed,
            heartbeat_age_secs: Some(age.as_secs()),
        };
    }

    HealthReport {
        ok: true,
        reason: None,
        profiles: count(n_profiles),
        profiles_fenced: count(fenced),
        profiles_failed: n_failed,
        heartbeat_age_secs: Some(age.as_secs()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::app_state::build_test_state;

    fn millis_ago(d: std::time::Duration) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        now.saturating_sub(d.as_millis() as u64)
    }

    #[test]
    fn fresh_heartbeat_is_ok() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        assert_eq!(probe(&s).0, 200);
    }

    /// The status `/healthz` would answer, and the body as JSON.
    fn probe(s: &AppState) -> (u16, serde_json::Value) {
        let report = evaluate(s);
        let status = if report.ok { 200 } else { 503 };
        (status, serde_json::to_value(&report).unwrap())
    }

    #[test]
    fn a_profile_that_failed_to_come_up_is_counted_in_the_payload() {
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

        let (status, body) = probe(&s);
        assert_eq!(status, 200, "one account is still serving");
        assert_eq!(body["profiles"], 1, "the live count, as documented");
        assert_eq!(body["profiles_failed"], 1, "body: {body}");
    }

    #[test]
    fn a_daemon_whose_every_profile_failed_to_come_up_is_unready() {
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

        let (status, body) = probe(&s);
        assert_eq!(status, 503);
        assert_eq!(body["ok"], false);
        assert_eq!(body["profiles_failed"], 1, "body: {body}");
    }

    #[test]
    fn a_daemon_with_every_profile_fenced_is_unready() {
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
        let (status, body) = probe(&s);
        assert_eq!(status, 503);
        let b = body;
        assert_eq!(b["reason"], "all_profiles_fenced");
        assert_eq!(b["profiles"], 2);
        assert_eq!(b["profiles_fenced"], 2);
    }

    #[test]
    fn a_host_profile_can_never_fence_the_daemon() {
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
        let (status, _) = probe(&s);
        assert_eq!(status, 200);
    }

    #[test]
    fn one_healthy_profile_keeps_the_daemon_in_rotation() {
        use std::sync::Arc;

        use torrentd_engine::ProfileStatus;

        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;

        // Three profiles configured, and `c`'s tunnel failed at boot, so it
        // never got a session at all. The fixture has a failed profile so the
        // dark account has to be visible in the body, not only in the status.
        let reg = Arc::new(
            ProfileRegistry::new(vec![
                test_entry("a", ProfileStatus::VpnDown),
                test_entry("b", ProfileStatus::Active),
            ])
            .with_failed(vec![test_failed_profile("c", "wg-c did not come up")]),
        );
        let s = build_test_state_with_sessions(Some(reg), &["a", "b"]);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let (status, body) = probe(&s);
        assert_eq!(status, 200);
        let b = body;
        assert_eq!(b["ok"], true);
        assert_eq!(b["profiles"], 2, "the live count, as documented");
        assert_eq!(b["profiles_fenced"], 1);
        assert_eq!(b["profiles_failed"], 1, "the dark account is visible");
    }

    /// One live profile fenced and one that never came up is *every*
    /// configured profile out of service, and a load balancer that keeps
    /// sending traffic to it has nowhere for the traffic to go.
    #[test]
    fn a_fenced_profile_beside_a_profile_that_never_came_up_is_unready() {
        use std::sync::Arc;

        use torrentd_engine::ProfileStatus;

        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;

        let reg = Arc::new(
            ProfileRegistry::new(vec![test_entry("a", ProfileStatus::VpnDown)])
                .with_failed(vec![test_failed_profile("b", "wg-b did not come up")]),
        );
        let s = build_test_state_with_sessions(Some(reg), &["a"]);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let (status, body) = probe(&s);
        assert_eq!(status, 503);
        let b = body;
        assert_eq!(b["reason"], "all_profiles_fenced");
        assert_eq!(b["profiles_fenced"], 1);
        assert_eq!(b["profiles_failed"], 1);
    }

    #[test]
    fn a_healthy_single_session_reports_its_one_profile_unfenced() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let (status, body) = probe(&s);
        assert_eq!(status, 200);
        let b = body;
        assert_eq!(b["profiles"], 1);
        assert_eq!(b["profiles_fenced"], 0);
        assert_eq!(b["profiles_failed"], 0);
    }

    #[test]
    fn stalled_alert_loop_is_unready() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(MAX_HEARTBEAT_AGE * 2), Ordering::Relaxed);
        let (status, _) = probe(&s);
        assert_eq!(status, 503);
    }
}
