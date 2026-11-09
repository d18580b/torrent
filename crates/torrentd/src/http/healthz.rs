//! The probes: `GET /livez` (is the process wedged?), `GET /readyz` (should
//! it take traffic?), and `GET /healthz`, the readiness probe under the name
//! it had before the two were split, kept for the scripts and the container
//! `HEALTHCHECK` that already use it.
//!
//! Liveness and readiness are different questions. A fenced profile is held
//! out of service on purpose until an operator lifts the fence, so a probe
//! that restarts the process for it - Kubernetes' `livenessProbe` - undoes
//! the fence. `/livez` therefore fails only for what a restart fixes.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::Reply;
use serde::Serialize;
use torrentd_engine::heartbeat_age;

use crate::app_state::AppState;
use crate::http::v1::Operations;

/// How stale the alert loop's heartbeat may get before the daemon reports
/// itself wedged and unready.
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
    /// Whether the kill switch lets the daemon's DNS out to
    /// `kill_switch_dns_servers` outside the tunnels, so every tracker
    /// hostname it looks up is visible to those resolvers. Never a reason to
    /// be unready: the operator chose it.
    pub kill_switch_dns_exempt: bool,
}

/// Why the daemon reports unready.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthReason {
    /// The boot has not finished: a torrent it loaded has not yet reached
    /// the state map, and ten minutes have not passed since.
    Starting,
    /// No profile has a live session.
    NoSessions,
    /// The alert loop has not run for longer than fifteen seconds.
    AlertLoopStalled,
    /// Every live profile is fenced: nothing is seeding.
    AllProfilesFenced,
}

/// The two answers `/readyz` and `/healthz` give, with one body shape
/// between them.
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

/// Whether the process is wedged, and the readings behind it.
#[derive(Debug, Schema, Serialize)]
pub struct LivenessReport {
    /// Whether the process is live. `true` exactly when the status is 200.
    pub ok: bool,
    /// The check that failed; `null` when live.
    pub failed: Option<LivenessCheck>,
    /// Seconds since the alert loop last stamped its heartbeat; `null` when
    /// there is no live session to run one.
    pub heartbeat_age_secs: Option<u64>,
    /// Batch writer threads - the ones that write resume data - that have
    /// died by a panic in this process.
    pub batch_writer_deaths: u64,
}

/// The check `/livez` failed.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LivenessCheck {
    /// The alert loop has not run for longer than fifteen seconds.
    AlertLoopStalled,
    /// A batch writer thread died: resume data no longer reaches the disk.
    BatchWriterDead,
    /// The runtime's tick, stamped twice a second, is older than two
    /// seconds: its scheduler or timer is starved.
    RuntimeStalled,
}

/// The two answers `/livez` gives, with one body shape between them.
#[derive(Reply)]
pub enum Liveness {
    #[reply(status = 200, description = "The process is live.")]
    Live(LivenessReport),
    #[reply(
        status = 503,
        description = "The process is wedged; `failed` names the check. Restart it."
    )]
    Wedged(LivenessReport),
}

/// How often the supervised task `runtime_tick` stamps
/// [`AppState::runtime_tick`].
const RUNTIME_TICK_PERIOD: std::time::Duration = std::time::Duration::from_millis(500);

/// How stale the runtime's tick stamp may get before `/livez` calls the
/// runtime stalled: four periods.
const MAX_RUNTIME_TICK_AGE: std::time::Duration = std::time::Duration::from_secs(2);

/// Stamp `stamp` with the time every [`RUNTIME_TICK_PERIOD`], forever. Run as
/// the supervised task `runtime_tick`.
///
/// Each stamp needs the runtime's timer to fire and a worker to poll this
/// task, so a starved scheduler or a timer that stopped firing lets it go
/// stale. `/livez` only reads it: a handler that runs on a free worker does
/// not refresh it, and so reports a stall on the others.
pub(crate) async fn run_runtime_tick(stamp: Arc<std::sync::atomic::AtomicU64>) {
    let mut every = tokio::time::interval(RUNTIME_TICK_PERIOD);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        stamp.store(now, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Liveness.
///
/// 503 only for what a restart fixes: the alert loop's heartbeat older than
/// fifteen seconds, a batch writer thread dead, or the runtime's tick - a
/// task stamping the time twice a second - older than two seconds. Never for
/// a fenced, offline, failed or missing profile: those are `/readyz`'s, and
/// a fence in particular holds until an operator lifts it, which a restart
/// would undo. A runtime wedged hard enough not to run this handler at all
/// gives no answer, which a probe's own timeout counts as a failure.
/// Unauthenticated, as every probe is.
#[kynos::get("/livez", tag = Operations)]
pub async fn get_live(Inject(s): Inject<Arc<AppState>>) -> Liveness {
    let report = evaluate_live(&s, torrentd_engine::batch_writer::writer_deaths());
    if report.ok {
        Liveness::Live(report)
    } else {
        Liveness::Wedged(report)
    }
}

/// The liveness of `s`, given the process's batch writer deaths.
fn evaluate_live(s: &AppState, writer_deaths: u64) -> LivenessReport {
    // With no live session there is no alert loop to judge; no session is a
    // readiness answer, and a restart does not bring a tunnel up.
    let age = (!s.source.profiles().is_empty()).then(|| heartbeat_age(&s.alert_heartbeat));
    let failed = if age.is_some_and(|a| a > MAX_HEARTBEAT_AGE) {
        Some(LivenessCheck::AlertLoopStalled)
    } else if writer_deaths > 0 {
        Some(LivenessCheck::BatchWriterDead)
    } else if heartbeat_age(&s.runtime_tick) > MAX_RUNTIME_TICK_AGE {
        Some(LivenessCheck::RuntimeStalled)
    } else {
        None
    };
    LivenessReport {
        ok: failed.is_none(),
        failed,
        heartbeat_age_secs: age.map(|a| a.as_secs()),
        batch_writer_deaths: writer_deaths,
    }
}

/// Readiness.
///
/// 503 `starting` until the boot has finished: the API is up and every
/// torrent the boot loaded has reached the state map, or ten minutes have
/// passed since the API state was built. A startup probe reads that.
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
#[kynos::get("/readyz", tag = Operations)]
pub async fn get_ready(Inject(s): Inject<Arc<AppState>>) -> Health {
    readiness(&s)
}

/// Readiness, under its original name.
///
/// The same answer as `GET /readyz`, kept so the scripts, the container
/// `HEALTHCHECK` and the probes already pointed at it keep working.
#[kynos::get("/healthz", tag = Operations)]
pub async fn get_health(Inject(s): Inject<Arc<AppState>>) -> Health {
    readiness(&s)
}

fn readiness(s: &AppState) -> Health {
    let report = evaluate(s);
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
    if s.boot.is_starting(&s.state) {
        let (fenced, _) = s.fenced_profiles();
        return HealthReport {
            ok: false,
            reason: Some(HealthReason::Starting),
            profiles: count(n_profiles),
            profiles_fenced: count(fenced),
            profiles_failed: n_failed,
            heartbeat_age_secs: (n_profiles > 0)
                .then(|| heartbeat_age(&s.alert_heartbeat).as_secs()),
            kill_switch_dns_exempt: s.kill_switch_dns_exempt,
        };
    }
    if n_profiles == 0 {
        return HealthReport {
            ok: false,
            reason: Some(HealthReason::NoSessions),
            profiles: 0,
            profiles_fenced: 0,
            profiles_failed: n_failed,
            heartbeat_age_secs: None,
            kill_switch_dns_exempt: s.kill_switch_dns_exempt,
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
            kill_switch_dns_exempt: s.kill_switch_dns_exempt,
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
            kill_switch_dns_exempt: s.kill_switch_dns_exempt,
        };
    }

    HealthReport {
        ok: true,
        reason: None,
        profiles: count(n_profiles),
        profiles_fenced: count(fenced),
        profiles_failed: n_failed,
        heartbeat_age_secs: Some(age.as_secs()),
        kill_switch_dns_exempt: s.kill_switch_dns_exempt,
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

        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;
        use crate::profile_registry::ProfileStatus;

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

        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;
        use crate::profile_registry::ProfileStatus;

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

        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;
        use crate::profile_registry::ProfileStatus;

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

        use crate::app_state::build_test_state_with_sessions;
        use crate::profile_registry::test_entry;
        use crate::profile_registry::test_failed_profile;
        use crate::profile_registry::ProfileRegistry;
        use crate::profile_registry::ProfileStatus;

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

    /// `docs/running.md` §9 tells an operator what a `/healthz` answer holds,
    /// and an alert or probe is written from it. A doc that names a key this
    /// report does not have, as one once named `all_profiles_fenced`, gives a
    /// check that never fires. Every name it gives must be a key of the
    /// serialised report or a `reason` value, and it must name every profile
    /// count and every reason the report has.
    #[test]
    fn the_running_docs_healthz_section_names_real_report_keys() {
        let doc = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/running.md"
        ))
        .unwrap();
        let start = doc
            .find("`profiles` is the number of **live** sessions")
            .expect("running.md no longer describes the /healthz report");
        let note = &doc[start..];
        let note = &note[..note
            .find("Confirm settings actually applied")
            .expect("running.md's /healthz section no longer ends where it did")];

        let report = serde_json::to_value(HealthReport {
            ok: true,
            reason: None,
            profiles: 0,
            profiles_fenced: 0,
            profiles_failed: 0,
            heartbeat_age_secs: None,
            kill_switch_dns_exempt: false,
        })
        .unwrap();
        let keys: Vec<&str> = report
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let reasons: Vec<String> = [
            HealthReason::Starting,
            HealthReason::NoSessions,
            HealthReason::AlertLoopStalled,
            HealthReason::AllProfilesFenced,
        ]
        .iter()
        .map(|r| {
            serde_json::to_value(r)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();

        let is_ident =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_');
        let spans: Vec<&str> = note.split('`').skip(1).step_by(2).collect();
        for span in &spans {
            // `.reason == "x"` or `"x"`: the quoted value must be a reason.
            for quoted in span.split('"').skip(1).step_by(2) {
                assert!(
                    reasons.iter().any(|r| r == quoted),
                    "the note quotes {quoted:?}, which is not a `reason` value: {reasons:?}"
                );
            }
            // `.field == …`: the field must be a key.
            if let Some(field) = span.strip_prefix('.') {
                let field = field
                    .split(|c: char| !(c.is_ascii_lowercase() || c == '_'))
                    .next()
                    .unwrap();
                assert!(
                    keys.contains(&field),
                    "the note checks `.{field}`, which is not a key: {keys:?}"
                );
            }
            if is_ident(span) {
                assert!(
                    keys.contains(span) || reasons.iter().any(|r| r == span),
                    "the note names `{span}`, which is neither a key nor a `reason` value: \
                     {keys:?} {reasons:?}"
                );
            }
        }
        for key in keys.iter().filter(|k| k.starts_with("profiles")) {
            assert!(
                spans.contains(key),
                "the note does not name the report's `{key}`: {note}"
            );
        }
        for reason in &reasons {
            assert!(
                spans.contains(&reason.as_str()),
                "the note does not name the `reason` value `{reason}`: {note}"
            );
        }
    }

    /// The DNS carve-out is in the body, ready or not, and never makes the
    /// daemon unready: it is a cost the operator chose, reported so a probe
    /// or a person reading it sees the lookups leave outside the tunnels.
    #[test]
    fn the_dns_carve_out_is_reported_and_never_unready() {
        let mut s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        assert_eq!(probe(&s).1["kill_switch_dns_exempt"], false);
        s.kill_switch_dns_exempt = true;
        let (status, body) = probe(&s);
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(body["kill_switch_dns_exempt"], true);
        s.alert_heartbeat
            .store(millis_ago(MAX_HEARTBEAT_AGE * 2), Ordering::Relaxed);
        let (status, body) = probe(&s);
        assert_eq!(status, 503);
        assert_eq!(body["kill_switch_dns_exempt"], true, "unready too");
    }

    #[test]
    fn stalled_alert_loop_is_unready() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(MAX_HEARTBEAT_AGE * 2), Ordering::Relaxed);
        let (status, _) = probe(&s);
        assert_eq!(status, 503);
    }

    /// The status `/livez` would answer for `s` with no writer dead, and the
    /// body as JSON.
    fn live(s: &AppState) -> (u16, serde_json::Value) {
        live_with(s, 0)
    }

    fn live_with(s: &AppState, deaths: u64) -> (u16, serde_json::Value) {
        let report = evaluate_live(s, deaths);
        let status = if report.ok { 200 } else { 503 };
        (status, serde_json::to_value(&report).unwrap())
    }

    /// A fence is held until an operator lifts it: every profile fenced
    /// takes the daemon out of rotation and never restarts it.
    #[test]
    fn a_daemon_with_every_profile_fenced_is_live_and_unready() {
        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;
        use crate::profile_registry::ProfileStatus;

        let reg = Arc::new(ProfileRegistry::new(vec![
            test_entry("a", ProfileStatus::VpnDown),
            test_entry("b", ProfileStatus::VpnDown),
        ]));
        let s = build_test_state(Some(reg));
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let (status, body) = live(&s);
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(body["failed"], serde_json::Value::Null);
        let (status, body) = probe(&s);
        assert_eq!(status, 503);
        assert_eq!(body["reason"], "all_profiles_fenced");
    }

    /// No live session, and so no alert loop to judge, is a readiness
    /// answer: a restart brings no tunnel up.
    #[test]
    fn a_daemon_with_no_session_is_live_and_unready() {
        let s = crate::app_state::build_test_state_with_sessions(None, &[]);
        s.alert_heartbeat.store(0, Ordering::Relaxed);
        let (status, body) = live(&s);
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(body["heartbeat_age_secs"], serde_json::Value::Null);
        assert_eq!(probe(&s).1["reason"], "no_sessions");
    }

    #[test]
    fn a_stalled_alert_loop_is_wedged_and_unready() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(MAX_HEARTBEAT_AGE * 2), Ordering::Relaxed);
        let (status, body) = live(&s);
        assert_eq!(status, 503);
        assert_eq!(body["failed"], "alert_loop_stalled");
        assert!(body["heartbeat_age_secs"].as_u64().unwrap() >= 30, "{body}");
        let (status, body) = probe(&s);
        assert_eq!(status, 503);
        assert_eq!(body["reason"], "alert_loop_stalled");
    }

    /// A dead batch writer and a stale runtime tick each fail liveness,
    /// naming themselves; neither moves readiness.
    #[test]
    fn a_dead_batch_writer_or_a_stalled_runtime_is_wedged() {
        let s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        let (status, body) = live_with(&s, 1);
        assert_eq!(status, 503);
        assert_eq!(body["failed"], "batch_writer_dead");
        assert_eq!(body["batch_writer_deaths"], 1);
        s.runtime_tick
            .store(millis_ago(MAX_RUNTIME_TICK_AGE * 2), Ordering::Relaxed);
        let (status, body) = live_with(&s, 0);
        assert_eq!(status, 503);
        assert_eq!(body["failed"], "runtime_stalled");
        assert_eq!(probe(&s).0, 200);
    }

    /// The tick task stamps a stale stamp fresh as soon as the runtime
    /// polls it, so a running runtime is live by it.
    #[tokio::test]
    async fn the_runtime_tick_refreshes_a_stale_stamp() {
        let s = build_test_state(None);
        s.runtime_tick
            .store(millis_ago(MAX_RUNTIME_TICK_AGE * 2), Ordering::Relaxed);
        assert_eq!(live(&s).1["failed"], "runtime_stalled");
        let ran = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            run_runtime_tick(Arc::clone(&s.runtime_tick)),
        )
        .await;
        assert!(ran.is_err(), "the tick runs until stopped");
        assert!(heartbeat_age(&s.runtime_tick) < RUNTIME_TICK_PERIOD);
        assert_eq!(live(&s).1["failed"], serde_json::Value::Null);
    }

    /// Until the boot is done, readiness is `starting` whatever else holds;
    /// liveness does not wait for it.
    #[test]
    fn a_daemon_still_starting_is_live_and_unready() {
        let mut s = build_test_state(None);
        s.alert_heartbeat
            .store(millis_ago(std::time::Duration::ZERO), Ordering::Relaxed);
        s.boot = Arc::new(crate::app_state::BootProgress::new(
            vec![libtorrent_safe::InfoHash([9; 20])],
            std::time::Duration::from_secs(600),
        ));
        assert_eq!(live(&s).0, 200);
        let (status, body) = probe(&s);
        assert_eq!(status, 503);
        assert_eq!(body["reason"], "starting");
        assert_eq!(body["profiles"], 1);
        s.boot.mark_serving();
        assert_eq!(
            probe(&s).1["reason"],
            "starting",
            "the torrent is not loaded"
        );
    }
}
