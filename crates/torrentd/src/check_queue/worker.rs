//! The check queue's worker: each tick retires what finished, records
//! adoptions' and re-hashes' verdicts in the pool index, and admits up to the
//! limit; and the boot's restore of the adoptions `pool.db` held waiting.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use torrentd_engine::AddParams;
use torrentd_engine::AlertSource;
use torrentd_engine::MetricsSink;
use torrentd_engine::ProfileId;
use torrentd_engine::StateMap;
use torrentd_engine::TorrentPhase;
use torrentd_engine::TrackerRefusal;
use torrentd_pool::AdoptionState;
use torrentd_pool::PoolStore;
use tracing::debug;
use tracing::info;
use tracing::warn;

use super::CheckSource;
use super::HeldAdd;
use super::PendingVerify;
use super::Recheck;
use super::VerifyQueue;
use super::ADMIT_INTERVAL;
use super::CHECK_SETTLE;
use super::RECHECK_EXPIRY;
use super::VERIFY_SETTLE;
use crate::pool_service::now_secs;
use crate::pool_service::off_worker;
use crate::pool_service::PoolService;
use crate::profile_registry::ProfileStatus;
use crate::registry::AssignmentRegistry;

/// Drive the verify queue: retire finished verifications, admit new ones.
///
/// Completion is observed from the shared state map rather than by subscribing
/// to alerts, so the queue needs no coupling to the alert loop and cannot wedge
/// if an alert is ever dropped under load.
///
/// Runs whether or not `[pool]` is configured: `pool` is `None` without it,
/// and then the queue holds no adoptions and records no verdicts.
#[allow(clippy::too_many_arguments)]
pub async fn run_verify_queue(
    queue: Arc<VerifyQueue>,
    pool: Option<Arc<PoolService>>,
    source: Arc<dyn AlertSource>,
    state: Arc<StateMap>,
    metrics: Arc<crate::metrics_sink::PromSink>,
    profiles: Arc<crate::profile_registry::ProfileRegistry>,
    registry: Arc<AssignmentRegistry>,
    mut shutdown: tokio::sync::broadcast::Receiver<torrentd_engine::ShutdownReason>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ADMIT_INTERVAL) => {}
            _ = shutdown.recv() => {
                info!(target: "torrentd::pool", "verify queue shutting down");
                return;
            }
        }

        let q = &*queue;
        verify_tick(
            q,
            pool.as_deref(),
            &source,
            &state,
            &metrics,
            &profiles,
            &registry,
        );

        metrics.set_gauge("check_queue_depth", q.depth() as f64, &[]);
        metrics.set_gauge("checks_in_flight", q.in_flight() as f64, &[]);
        if pool.is_none() {
            continue;
        }
        metrics.set_gauge("pool_verify_queue_depth", q.depth() as f64, &[]);
        metrics.set_gauge("pool_verify_in_flight", q.in_flight() as f64, &[]);
        // Counters take the increment since the last tick; the queue holds the
        // running total, and `set_gauge` on a `_total` name is not a counter.
        let (done, failed) = q.take_export_deltas();
        if done > 0 {
            metrics.add_counter("pool_verify_completed_total", done, &[]);
        }
        if failed > 0 {
            metrics.add_counter("pool_verify_failed_total", failed, &[]);
        }
    }
}

/// One tick of [`run_verify_queue`]: retire what finished, then admit up to
/// the limit.
///
/// The pool's steps - recording adoptions' and re-hashes' verdicts, and
/// admitting adoptions - write the pool index, on the writer a scan holds for
/// its whole run. They run only where the tick takes the writer without
/// waiting, and hold it to the end of the tick; where a scan holds it they
/// wait for a tick that finds it free, keeping their slots and their places
/// meanwhile. The rest - freeing ended checks' slots, starting re-hashes and
/// held adds - never touches the index, and goes on while a scan runs:
/// waiting on the writer here stalled every check the daemon starts until the
/// scan committed.
pub(super) fn verify_tick(
    q: &VerifyQueue,
    pool: Option<&PoolService>,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    metrics: &Arc<crate::metrics_sink::PromSink>,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
) {
    let writer = pool.and_then(|pool| {
        let store = pool.try_lock_writer();
        if store.is_none() {
            debug!(
                target: "torrentd::pool",
                "the pool index writer is held, most likely by a scan; adoptions' admission \
                 and verdicts wait for it, re-hashes and held adds go on",
            );
        }
        store.map(|store| (pool, store))
    });
    let indexed = writer.as_ref().map(|(pool, store)| (*pool, &**store));

    // 1) Retire anything that finished hashing.
    if let Some((pool, store)) = indexed {
        retire_in_flight(pool, Writer::Held(store), &**source, state, profiles);
    }
    // 1a) Free the slots of checks that have ended.
    retire_checking(q, state, RECHECK_EXPIRY);
    // 1b) Retire re-hashes of loaded torrents, once a check that finished
    //     after the request is in. One that finished before it is the
    //     previous check, and says nothing about this one.
    if let Some((pool, store)) = indexed {
        retire_rechecks(pool, Writer::Held(store), &**source, state, profiles);
    }

    // 2) Admit up to the limit, every kind together.
    admit(q, indexed, source, state, metrics, profiles, registry);
}

/// One verify-queue tick's slot accounting and admission, as
/// [`run_verify_queue`] makes it, for tests that drive the queue through the
/// HTTP API.
#[cfg(test)]
pub(crate) fn admit_tick_for_tests(
    q: &VerifyQueue,
    pool: Option<&PoolService>,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
) {
    let metrics = Arc::new(crate::metrics_sink::PromSink::new());
    let writer = pool.and_then(|pool| pool.try_lock_writer().map(|store| (pool, store)));
    retire_checking(q, state, RECHECK_EXPIRY);
    admit(
        q,
        writer.as_ref().map(|(pool, store)| (*pool, &**store)),
        source,
        state,
        &metrics,
        profiles,
        registry,
    );
}

/// What one admission attempt did.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum Admission {
    /// The item took a slot.
    Admitted,
    /// The item took no slot, and was dropped or put back; try the next.
    Skipped,
    /// Nothing more of this kind is admitted this tick.
    Stop,
}

/// Fill the free slots, taking waiting adoptions, re-hashes and held adds in
/// turn, so a backlog of any one cannot starve the others. Adoptions only
/// where `[pool]` is configured and `pool` carries its writer, taken by the
/// caller: admitting or dropping one writes the pool index.
pub(super) fn admit(
    q: &VerifyQueue,
    pool: Option<(&PoolService, &PoolStore)>,
    source: &Arc<dyn AlertSource>,
    state: &StateMap,
    metrics: &Arc<crate::metrics_sink::PromSink>,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
) {
    const ADOPTIONS: usize = 0;
    const RECHECKS: usize = 1;
    const ADDS: usize = 2;
    let _admitting = q.admit_lock.lock();
    // Which kinds may still admit this tick.
    let mut open = [pool.is_some(), true, true];
    // One pass at most over the adoptions, re-hashes and adds waiting when
    // the tick began: one held for a profile off the network goes to the
    // back, and would otherwise be met again in the same tick.
    let mut budget = [
        q.pending.len(),
        q.pending_rechecks.len(),
        q.pending_adds.len(),
    ];
    let mut next = ADOPTIONS;
    // Profiles whose held re-hashes and adds this tick has logged already:
    // one line per profile per tick, not one per torrent it holds.
    let mut held_logged = std::collections::HashSet::new();
    // The same for held adoptions, whose line is their own.
    let mut adoptions_held_logged = std::collections::HashSet::new();
    while open.iter().any(|o| *o) && q.in_flight() < q.limit {
        let kind = (next..next + 3).map(|k| k % 3).find(|k| open[*k]);
        let Some(kind) = kind else { break };
        if budget[kind] == 0 {
            open[kind] = false;
            continue;
        }
        budget[kind] = budget[kind].saturating_sub(1);
        let admission = match (kind, pool) {
            (ADOPTIONS, Some((pool, store))) => admit_adoption(
                pool,
                store,
                source,
                metrics,
                profiles,
                registry,
                &mut adoptions_held_logged,
            ),
            (RECHECKS, _) => admit_recheck(
                q,
                &**source,
                state,
                metrics.as_ref(),
                profiles,
                &mut held_logged,
            ),
            (ADDS, _) => admit_held_add(
                q,
                &**source,
                state,
                metrics.as_ref(),
                profiles,
                registry,
                &mut held_logged,
            ),
            _ => Admission::Stop,
        };
        match admission {
            Admission::Admitted => next = (kind + 1) % 3,
            Admission::Skipped => next = kind,
            Admission::Stop => open[kind] = false,
        }
    }
}

/// Ask libtorrent to re-check `handle`, marking a torrent in `DiskError`
/// `Checking` first.
///
/// A check that fails fast posts its `file_error` before any status update
/// reports `checking`. The file-error handler reads a `file_error` on a
/// torrent still in `DiskError` with no libtorrent error as one more failed
/// peer read and leaves `has_error` clear, so the error-and-pause the failed
/// check caused would go unrecorded, and a disk-error retry due before the
/// next update would re-check a torrent paused for the error, which cannot
/// check, and then retire with it paused. Marked before the call, not after:
/// the alert loop runs on its own thread, so the alert can beat a mark made
/// once the call returns. The disk-error retry marks its own re-checks, on
/// the alert loop's thread.
///
/// Where the call fails, no check starts, and the mark is taken back unless
/// something has moved the torrent on since: left in place, it would hold
/// the retry back, which waits out a check, and the next update reporting
/// the torrent seeding would map `Checking` to `Seeding` and drop the
/// `DiskError` it still has.
pub(crate) fn force_recheck_marking_checking(
    engine: &dyn torrentd_engine::TorrentEngine,
    state: &StateMap,
    handle: libtorrent_safe::TorrentHandle,
) -> Result<(), torrentd_engine::EngineError> {
    let mut marked = false;
    state.update(&handle.infohash, |s| {
        if s.phase == TorrentPhase::DiskError {
            s.phase = TorrentPhase::Checking;
            marked = true;
        }
    });
    let outcome = engine.force_recheck(handle);
    if outcome.is_err() && marked {
        state.update(&handle.infohash, |s| {
            if s.phase == TorrentPhase::Checking {
                s.phase = TorrentPhase::DiskError;
            }
        });
    }
    outcome
}

/// Start the re-hash at the head of the queue.
///
/// The request checked each torrent when it was queued, but the queue can
/// wait for hours, so the checks are made again here: a torrent no longer
/// loaded, paused, or without metadata is dropped, since libtorrent would not
/// hash it and it would hold a slot for nothing. One whose profile went off
/// the network is put back, as an adoption is held, because a re-hash puts
/// the torrent back on the network once it ends. So is one whose torrent a
/// paced set-online holds paused until its batch comes
/// ([`crate::profile_state::PacedHolds`]), and one paused that a fence's lift
/// has yet to resume ([`crate::profile_registry::ProfileEntry::resume_pending`]):
/// neither is paused for good. A torrent the operator resumes by hand is no
/// longer held, so its re-hash starts. The hold is logged once per profile per
/// tick: `held_logged` names the profiles already logged.
///
/// Every re-hash dropped here is counted in `pool_recheck_dropped_total` by
/// why, since `POST /v1/pool/verifications` answered that it started, and
/// `POST /v1/torrents/{infohash}/recheck` that it was accepted.
pub(super) fn admit_recheck(
    q: &VerifyQueue,
    source: &dyn AlertSource,
    state: &StateMap,
    metrics: &dyn MetricsSink,
    profiles: &crate::profile_registry::ProfileRegistry,
    held_logged: &mut std::collections::HashSet<ProfileId>,
) -> Admission {
    let dropped = |reason: &str| {
        metrics.inc_counter("pool_recheck_dropped_total", &[("reason", reason)]);
    };
    let Some(r) = q.pending_rechecks.lock().pop_front() else {
        return Admission::Stop;
    };
    let Some(st) = libtorrent_safe::InfoHash::from_hex(&r.infohash).and_then(|h| state.get(&h))
    else {
        info!(
            target: "torrentd::pool",
            infohash = %r.infohash,
            "a torrent queued for a re-hash is no longer loaded; dropping the re-hash",
        );
        dropped("not_loaded");
        return Admission::Skipped;
    };
    let fenced = profiles
        .resolve(&st.profile_id)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if fenced || profiles.held_offline(&st.profile_id) {
        if held_logged.insert(st.profile_id.clone()) {
            warn!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %r.infohash,
                reason = if fenced { "vpn_down" } else { "offline" },
                "re-hash held: profile is off the network",
            );
        }
        q.pending_rechecks.lock().push_back(r);
        return Admission::Skipped;
    }
    // A paced set-online pauses each running torrent until its batch, and
    // holds it meanwhile: it is paused by the daemon, not the operator, and
    // runs again once its batch comes, so its re-hash waits for that. The
    // hold is read whatever the phase: right after the set-online the phase
    // still reads as running until the next state update, since the
    // session's pause never set the torrent's own flag. One the operator
    // resumes by hand is released from its hold by that resume.
    if profiles.holds().holds(&st.profile_id, &st.handle.infohash) {
        if held_logged.insert(st.profile_id.clone()) {
            info!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %r.infohash,
                reason = "paced_resume",
                "re-hash held: the profile's paced resume has not reached the torrent yet",
            );
        }
        q.pending_rechecks.lock().push_back(r);
        return Admission::Skipped;
    }
    // A fence's lift marks the profile active, then resumes what the fence
    // paused a batch at a time, holding nothing in `PacedHolds`: a torrent it
    // has not reached yet reads as paused in an active profile, paused by
    // the daemon and not the operator, so its re-hash waits for its batch.
    // Read only while it reads as paused: one the run has resumed is hashed
    // at once. One the operator pauses while the run goes is left out of it,
    // and its re-hash is dropped below.
    if st.phase == TorrentPhase::Paused
        && profiles
            .resolve(&st.profile_id)
            .active()
            .is_some_and(|e| e.resume_pending(&st.handle.infohash))
    {
        if held_logged.insert(st.profile_id.clone()) {
            info!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %r.infohash,
                reason = "fence_lift",
                "re-hash held: the lift of the profile's fence has not resumed the torrent yet",
            );
        }
        q.pending_rechecks.lock().push_back(r);
        return Admission::Skipped;
    }
    let unhashable = match st.phase {
        TorrentPhase::Paused => Some(("paused", "it was paused while it waited")),
        TorrentPhase::AwaitingMetadata => {
            Some(("no_metadata", "it has no metadata to hash against"))
        }
        _ => None,
    };
    if let Some((reason, why)) = unhashable {
        warn!(
            target: "torrentd::pool",
            infohash = %r.infohash,
            reason = why,
            "re-hash dropped: libtorrent would not hash it",
        );
        dropped(reason);
        return Admission::Skipped;
    }
    let Some(engine) = source.engine_for(&st.profile_id) else {
        warn!(
            target: "torrentd::pool",
            profile_id = %st.profile_id,
            infohash = %r.infohash,
            "no engine for profile; dropping the re-hash",
        );
        dropped("no_engine");
        return Admission::Skipped;
    };
    // Marked before it is asked for, so the check it starts finishes after
    // the mark.
    q.checking
        .lock()
        .push((r.clone(), std::time::Instant::now()));
    if let Err(e) = force_recheck_marking_checking(engine.as_ref(), state, st.handle) {
        q.checking.lock().retain(|(c, _)| c.infohash != r.infohash);
        warn!(
            target: "torrentd::pool",
            infohash = %r.infohash,
            error.cause = %e,
            "re-hash failed to start; dropping it",
        );
        dropped("start_failed");
        return Admission::Skipped;
    }
    info!(target: "torrentd::pool", infohash = %r.infohash, "re-hashing");
    q.count_start(CheckSource::Recheck);
    Admission::Admitted
}

/// Resume the held `.torrent` add at the head of the queue, which starts its
/// first check.
///
/// One no longer loaded is dropped with its entry in the record of held
/// adds. One whose profile is off the network is put back, as a re-hash is
/// held: resuming it would put it on the network. One that fails to resume
/// is put back to try again, never dropped, since dropped it would stay
/// paused for good.
///
/// Its entry in the record stays until its check ends ([`retire_checking`]),
/// so a restart before then holds it again; its resume data is saved at once,
/// so a restart after then loads it running.
pub(super) fn admit_held_add(
    q: &VerifyQueue,
    source: &dyn AlertSource,
    state: &StateMap,
    metrics: &dyn MetricsSink,
    profiles: &crate::profile_registry::ProfileRegistry,
    registry: &AssignmentRegistry,
    held_logged: &mut std::collections::HashSet<ProfileId>,
) -> Admission {
    let Some(add) = q.pending_adds.lock().pop_front() else {
        return Admission::Stop;
    };
    let put_back = |add: HeldAdd| q.pending_adds.lock().push_back(add);
    let Some(st) = state.get(&add.infohash) else {
        // Still claimed for its profile: its add alert has not been handled
        // yet, or a `DELETE` is removing it and releases the claim once it
        // has. Unclaimed, it was removed.
        if registry.lookup(&add.infohash).as_ref() == Some(&add.profile) {
            put_back(add);
            return Admission::Skipped;
        }
        info!(
            target: "torrentd::pool",
            infohash = %add.infohash,
            "a .torrent held for its first check is no longer loaded; forgetting it",
        );
        q.release_hold(&add.profile, add.infohash);
        return Admission::Skipped;
    };
    let fenced = profiles
        .resolve(&st.profile_id)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if fenced || profiles.held_offline(&st.profile_id) {
        if held_logged.insert(st.profile_id.clone()) {
            warn!(
                target: "torrentd::pool",
                profile_id = %st.profile_id,
                infohash = %add.infohash,
                reason = if fenced { "vpn_down" } else { "offline" },
                "first check of a .torrent held: profile is off the network",
            );
        }
        put_back(add);
        return Admission::Skipped;
    }
    let Some(engine) = source.engine_for(&st.profile_id) else {
        put_back(add);
        return Admission::Skipped;
    };
    // Marked before the resume, so the check it starts ends after the mark.
    let hex = add.infohash.to_hex();
    q.checking.lock().push((
        Recheck {
            infohash: hex.clone(),
            record: false,
            source: add.source,
            held_by: Some(add.profile.clone()),
        },
        std::time::Instant::now(),
    ));
    // Resumed whatever the phase reads: a torrent added paused reads `idle`
    // until its first status update, and resuming one something else
    // resumed already changes nothing.
    let resumed = crate::fence::resume_unless_fenced(
        profiles,
        &st.profile_id,
        engine.as_ref(),
        st.handle,
        metrics,
    );
    if !matches!(resumed, Ok(crate::fence::SingleResume::Resumed)) {
        q.checking.lock().retain(|(r, _)| r.infohash != hex);
        warn!(
            target: "torrentd::pool",
            infohash = %add.infohash,
            outcome = ?resumed,
            "could not resume a .torrent held for its first check; trying again later",
        );
        put_back(add);
        return Admission::Skipped;
    }
    state.queue_resume_save_now(add.infohash);
    info!(
        target: "torrentd::pool",
        infohash = %add.infohash,
        source = add.source.as_str(),
        "first check of a .torrent started",
    );
    q.count_start(add.source);
    Admission::Admitted
}

/// Add the adoption at the head of the queue to its session, to verify.
///
/// One whose profile is fenced or set offline goes to the back and is
/// skipped, as a held re-hash or add is: the adoptions behind it, into
/// profiles still on the network, are admitted this tick rather than wait
/// for the fence to lift. The hold is logged once per profile per tick:
/// `held_logged` names the profiles already logged.
pub(super) fn admit_adoption(
    pool: &PoolService,
    store: &PoolStore,
    source: &Arc<dyn AlertSource>,
    metrics: &Arc<crate::metrics_sink::PromSink>,
    profiles: &Arc<crate::profile_registry::ProfileRegistry>,
    registry: &Arc<AssignmentRegistry>,
    held_logged: &mut std::collections::HashSet<ProfileId>,
) -> Admission {
    let q = pool.verify_queue();
    let Some(item) = q.pending.lock().pop_front() else {
        return Admission::Stop;
    };
    // `POST /v1/pool/adoptions` checks the profile's tunnel before queueing,
    // but the queue drains over minutes or hours and the tunnel can
    // drop in between. Admitting then would add torrents to a fenced
    // profile — the one thing fencing exists to prevent. Put it back and
    // wait for the operator. A profile the operator set offline is
    // held the same way: adoptions into it are refused, and what was
    // queued before it went offline waits for it to come back.
    let fenced = profiles
        .resolve(&item.profile)
        .active()
        .is_some_and(|e| e.health().status == ProfileStatus::VpnDown);
    if fenced || profiles.held_offline(&item.profile) {
        if held_logged.insert(item.profile.clone()) {
            warn!(
                target: "torrentd::pool",
                profile_id = %item.profile,
                infohash = %item.infohash,
                reason = if fenced { "vpn_down" } else { "offline" },
                "verify held: profile is off the network",
            );
        }
        q.pending.lock().push_back(item);
        return Admission::Skipped;
    }
    let Some(engine) = source.engine_for(&item.profile) else {
        warn!(target: "torrentd::pool", profile_id = %item.profile, "no engine for profile; dropping verify");
        release_dropped_claim(pool, Writer::Held(store), registry, &item);
        return Admission::Skipped;
    };
    let bytes = match torrentd_pool::scan::read_capped(&item.torrent_path) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                target: "torrentd::pool",
                path = %item.torrent_path.display(),
                error.cause = %e,
                "cannot read .torrent; dropping verify",
            );
            q.failed.fetch_add(1, Ordering::Relaxed);
            release_dropped_claim(pool, Writer::Held(store), registry, &item);
            return Admission::Skipped;
        }
    };
    // No SEED_MODE: that is what makes libtorrent hash the payload
    // against the piece hashes before it will seed. The no-download
    // invariant rides along regardless — see `torrentd_engine::policy`.
    let Some(profile_cfg) = profiles.config(&item.profile) else {
        warn!(
            target: "torrentd::pool",
            profile_id = %item.profile,
            "verify queue holds an item for a profile that is not live; dropping",
        );
        q.failed.fetch_add(1, Ordering::Relaxed);
        release_dropped_claim(pool, Writer::Held(store), registry, &item);
        return Admission::Skipped;
    };
    let params = verify_add_params(
        profile_cfg,
        bytes.clone(),
        item.save_path.to_string_lossy().into_owned(),
        item.trackers.clone(),
    );
    // The adopt checked this `.torrent` before queueing it; these are
    // the bytes read now, which are what the session gets, with the
    // trackers the adopt read.
    if verify_guard(metrics.as_ref(), profile_cfg, &item, &params).is_err() {
        q.failed.fetch_add(1, Ordering::Relaxed);
        release_dropped_claim(pool, Writer::Held(store), registry, &item);
        return Admission::Skipped;
    }
    match engine.add_torrent(params) {
        Ok(handle) => {
            // The tunnel was up when this was admitted above, and
            // can have dropped since.
            crate::fence::hold_if_fenced(
                profiles,
                pool.kill_switch(),
                &item.profile,
                engine.as_ref(),
                handle,
                metrics.as_ref(),
            );
            // The bytes the session was given, so a restart re-adds
            // the torrent with its metadata, at the path it was
            // given.
            pool.persist_torrent(
                &item.profile,
                &item.infohash,
                &bytes,
                &item.save_path.to_string_lossy(),
            );
            // A session holds it now, and a restart loads it from
            // the `.torrent` just written. Its persisted entry stays
            // until its verdict is recorded, so that restart waits
            // for the boot's check and records it.
            q.track_in_flight(item.infohash.clone());
            q.count_start(CheckSource::Adoption);
            info!(
                target: "torrentd::pool",
                infohash = %item.infohash,
                save_path = %item.save_path.display(),
                "verifying before seeding",
            );
            Admission::Admitted
        }
        Err(e) => {
            q.failed.fetch_add(1, Ordering::Relaxed);
            warn!(target: "torrentd::pool", infohash = %item.infohash, error.cause = %e, "verify add failed");
            release_dropped_claim(pool, Writer::Held(store), registry, &item);
            Admission::Skipped
        }
    }
}

/// Record the verdict of every in-flight torrent whose hashing is over, and
/// stop waiting on one removed while it hashed.
///
/// A removed torrent leaves the state map, and with no entry its outcome
/// reads as still waiting; it is told apart from one whose add has not
/// landed yet by having been seen there before. Its persisted entry goes
/// with it, so a later restart does not wait on a re-add of the info-hash
/// as though it were this adoption.
///
/// The finished entries are taken off the list under its lock, and their
/// store writes made only after it is released: a write waits out a running
/// scan, and the lock held through that wait blocked every reader of the
/// list with it.
pub(super) fn retire_in_flight(
    pool: &PoolService,
    writer: Writer<'_>,
    source: &dyn AlertSource,
    state: &StateMap,
    profiles: &crate::profile_registry::ProfileRegistry,
) {
    enum Retired {
        Forget(String),
        Record(libtorrent_safe::InfoHash, String, VerifyOutcome),
    }
    let mut retired = Vec::new();
    pool.verify_queue().in_flight.lock().retain_mut(|f| {
        let Some(hash) = libtorrent_safe::InfoHash::from_hex(&f.infohash) else {
            retired.push(Retired::Forget(f.infohash.clone()));
            return false;
        };
        let entry = state.get(&hash);
        match (entry.is_some(), f.seen) {
            (true, _) => f.seen = true,
            (false, true) => {
                info!(
                    target: "torrentd::pool",
                    infohash = %f.infohash,
                    "a torrent was removed while it was being verified; forgetting it",
                );
                retired.push(Retired::Forget(f.infohash.clone()));
                return false;
            }
            (false, false) => {}
        }
        let outcome = verify_outcome(entry.as_ref(), VERIFY_SETTLE);
        if outcome == VerifyOutcome::Waiting {
            return true;
        }
        retired.push(Retired::Record(hash, f.infohash.clone(), outcome));
        false
    });
    for r in retired {
        match r {
            Retired::Forget(ih) => pool.forget_queued(writer, &ih),
            Retired::Record(hash, ih, outcome) => {
                record_verify_outcome(pool, writer, source, state, profiles, &hash, &ih, outcome);
            }
        }
    }
}

/// Free the slot of every started check that has ended, handing the re-hashes
/// whose verdict is recorded to [`retire_rechecks`], and releasing the held
/// adds' entries in the record of held adds.
///
/// A check has ended once one finished after it started. One paused while it
/// checked keeps its slot, as a paused adoption does: libtorrent goes on with
/// the check once the torrent is resumed (a fence lifting, resume-all, a
/// disk-error retry), and a slot freed at the pause would let that check run
/// beside `limit` others. Except one whose check failed on a disk error
/// ([`error_paused`]): that check is over, with no `torrent_checked`, and
/// what resumes it is the disk-error retry, which takes a slot of its own
/// first. Held, its slot would stay taken until `expiry`, and a few rechecks
/// of torrents on a failing disk would stall every adoption and re-hash for a
/// day. Its verdict, where one is recorded, is still waited for, without a
/// slot. A disk-error retry's slot is not freed this way before
/// [`CHECK_SETTLE`]: it is taken while the torrent still reads error-paused,
/// and stays so until the status update after the retry's resume. A check not known to start ([`CheckSource::always_checks`]) frees its
/// slot once the torrent shows none running past [`CHECK_SETTLE`]. One removed
/// has nothing left to hash. One older than `expiry` ([`RECHECK_EXPIRY`] in
/// the worker) lost its check, and is forgotten rather than hold a slot for
/// the life of the process.
pub(super) fn retire_checking(q: &VerifyQueue, state: &StateMap, expiry: Duration) {
    let mut ended = Vec::new();
    // Held adds whose check is over, or gone with their torrent: their
    // entries in the record of held adds are released after the lock.
    let mut released = Vec::new();
    q.checking.lock().retain(|(r, started)| {
        let hash = libtorrent_safe::InfoHash::from_hex(&r.infohash);
        let mut free = || {
            if let (Some(profile), Some(hash)) = (&r.held_by, hash) {
                released.push((profile.clone(), hash));
            }
            false
        };
        let Some(st) = hash.and_then(|h| state.get(&h)) else {
            return free();
        };
        // A disk-error retry takes its slot on a torrent that reads
        // error-paused, and its resume clears the error only in the status
        // update after it: read before a few of those have come, the error
        // is the one the retry is clearing, not its check failing.
        let error_ended = error_paused(&st)
            && (r.source != CheckSource::DiskErrorRetry || started.elapsed() >= CHECK_SETTLE);
        if st.checked_at.is_some_and(|t| t > *started) || error_ended {
            if r.record {
                ended.push((r.infohash.clone(), *started));
            }
            return free();
        }
        // A check not known to start that shows none running after a few
        // status updates started none, or ended with no `torrent_checked`
        // the state map kept.
        if !r.source.always_checks()
            && started.elapsed() >= CHECK_SETTLE
            && !matches!(st.phase, TorrentPhase::Checking | TorrentPhase::Paused)
        {
            return free();
        }
        if started.elapsed() >= expiry {
            warn!(
                target: "torrentd::pool",
                infohash = %r.infohash,
                source = r.source.as_str(),
                "a check never reported ending; freeing its slot",
            );
            return free();
        }
        true
    });
    for (ih, started) in ended {
        q.await_recheck_verdict(ih, started);
    }
    q.flush_ended_holds(released);
}

/// Whether libtorrent has error-paused a torrent whose re-hash started, as a
/// check that fails on a disk error leaves it.
///
/// The `file_error` records `DiskError` with the error at once, and the next
/// status update reports the torrent `Paused` with the error. Neither can be
/// left over from before the start: the start moves a torrent in `DiskError`
/// to `Checking` ([`force_recheck_marking_checking`]), a paused torrent's
/// re-hash is never started, and a status update sets the phase and the error
/// together. A torrent paused without an error is not one: its check goes on
/// once it is resumed.
pub(super) fn error_paused(st: &torrentd_engine::TorrentState) -> bool {
    st.has_error && matches!(st.phase, TorrentPhase::DiskError | TorrentPhase::Paused)
}

/// Record the outcome of every re-hash of a loaded torrent whose check
/// finished after the request, and forget those removed or given up on.
///
/// As in [`retire_in_flight`], the store writes are made after the list's
/// lock is released.
pub(super) fn retire_rechecks(
    pool: &PoolService,
    writer: Writer<'_>,
    source: &dyn AlertSource,
    state: &StateMap,
    profiles: &crate::profile_registry::ProfileRegistry,
) {
    let mut finished = Vec::new();
    pool.verify_queue().rechecks.lock().retain(|(ih, started)| {
        let Some(hash) = libtorrent_safe::InfoHash::from_hex(ih) else {
            return false;
        };
        let entry = state.get(&hash);
        let Some(st) = entry.as_ref() else {
            // Removed while checking: nothing left to record.
            return false;
        };
        match recheck_step(
            recheck_outcome(st, *started, VERIFY_SETTLE),
            started.elapsed(),
        ) {
            RecheckStep::Hold => true,
            RecheckStep::Forget => false,
            RecheckStep::Record(outcome) => {
                finished.push((hash, ih.clone(), outcome));
                false
            }
        }
    });
    for (hash, ih, outcome) in finished {
        record_verify_outcome(pool, writer, source, state, profiles, &hash, &ih, outcome);
    }
}

/// Hold the bytes the verify worker is about to add to the account-isolation
/// guard.
///
/// A refusal is logged, and a guard refusal (`NotAllowed`, `ForeignAccount`
/// or `NoTrackers`) is counted in
/// `profile_assignment_registry_errors_total`, where `POST /v1/torrents`, both
/// boot scans and the adoption's enqueue count theirs. Bytes whose trackers
/// cannot be read are a failed verify, not an isolation refusal.
pub(super) fn verify_guard(
    metrics: &dyn MetricsSink,
    profile: &torrentd_engine::ProfileConfig,
    item: &PendingVerify,
    params: &AddParams,
) -> Result<(), TrackerRefusal> {
    let refusal = match torrentd_engine::check_trackers(profile, params) {
        Ok(()) => return Ok(()),
        Err(refusal) => refusal,
    };
    warn!(
        target: "torrentd::pool",
        profile_id = %item.profile,
        infohash = %item.infohash,
        error.cause = %refusal,
        "verify dropped: refused by the profile's tracker guard",
    );
    if refusal.is_guard_refusal() {
        metrics.inc_counter(
            "profile_assignment_registry_errors_total",
            &[("profile_id", item.profile.as_str())],
        );
    }
    Err(refusal)
}

/// Release the registry claim of a verify item the worker is dropping.
///
/// `POST /v1/pool/adoptions` claims the info-hash before it queues the item, and
/// releases the claim itself only when `execute_adopt` fails synchronously. An
/// item dropped here never reaches a session, so no `AddTorrent` alert will
/// ever give it a state-map entry, and it is not in `unloaded_at_boot` either:
/// a claim left behind made `DELETE` answer 409 "still being added" and refused
/// every re-add or re-adopt until a restart. The claim is released only while
/// it still names the item's profile, so a claim someone else has since taken
/// is left alone.
///
/// A claim naming the item's profile is the enqueue's own: the adoption queues
/// an item only when its `assign` inserted the row, and every other runtime
/// claimant - `POST /v1/torrents` and another adoption - refuses an info-hash
/// that is already assigned, to this profile as to any other, rather than
/// sharing the claim. Nobody else can therefore hold one under the same
/// profile while the item waits, and releasing it cannot strand a torrent
/// another add loaded.
///
/// The pool index's owner record the enqueue wrote goes too, while it still
/// names the item's profile. Left behind, it made adoption into any other
/// profile refuse the torrent, and `DELETE` could not clear it: with no
/// registry entry it answers not found.
///
/// Its entry in the persisted verify queue goes in every case, so a restart
/// does not queue it again.
pub(super) fn release_dropped_claim(
    pool: &PoolService,
    writer: Writer<'_>,
    registry: &AssignmentRegistry,
    item: &PendingVerify,
) {
    pool.forget_queued(writer, &item.infohash);
    if item.owner_recorded {
        let cleared = writer.with(pool, |s| match s.profile_of(&item.infohash) {
            Ok(Some(owner)) if owner == item.profile.as_str() => {
                s.set_profile(&item.infohash, None)
            }
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        });
        if let Err(e) = cleared {
            pool.note_store_error("set_profile", &e);
        }
    }
    let Some(ih) = libtorrent_safe::InfoHash::from_hex(&item.infohash) else {
        return;
    };
    if registry.lookup(&ih).as_ref() != Some(&item.profile) {
        return;
    }
    if let Err(e) = registry.remove(&ih) {
        warn!(
            target: "torrentd::pool",
            infohash = %item.infohash,
            profile_id = %item.profile,
            error.cause = %e,
            "could not release the registry claim of a dropped verify",
        );
    }
}

/// Write a finished verification into the pool index.
///
/// `Verified` records `adopted` with no drift — the one thing that clears
/// drift. `Failed` records `drifted` and **pauses** the torrent: under forced
/// upload mode it would otherwise sit in its session announcing a payload the
/// piece hashes just rejected, and an operator reading `drifted` would find it
/// still on the network. It is left out of every paced resume in its profile
/// first ([`crate::profile_registry::ProfileEntry::exclude_from_resumes`]), so
/// no lift resumes it after.
///
/// Either verdict forgets the info-hash's persisted verify-queue entry: an
/// adoption keeps it until here, so a restart before the verdict is recorded
/// waits for the boot's check rather than lose it.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_verify_outcome(
    pool: &PoolService,
    writer: Writer<'_>,
    source: &dyn AlertSource,
    state: &StateMap,
    profiles: &crate::profile_registry::ProfileRegistry,
    hash: &libtorrent_safe::InfoHash,
    ih: &str,
    outcome: VerifyOutcome,
) {
    let q = pool.verify_queue();
    let (state_to_record, verified_at, drift_at, note) = match outcome {
        VerifyOutcome::Waiting => return,
        VerifyOutcome::Verified => {
            q.completed.fetch_add(1, Ordering::Relaxed);
            info!(target: "torrentd::pool", infohash = %ih, "verified and seeding");
            (AdoptionState::Adopted, Some(now_secs()), None, None)
        }
        VerifyOutcome::Failed(reason) => {
            q.failed.fetch_add(1, Ordering::Relaxed);
            warn!(
                target: "torrentd::pool",
                infohash = %ih,
                reason = reason,
                "verification did not leave the torrent seeding; pausing it",
            );
            if let Some(st) = state.get(hash) {
                // Readied as the operator's pause readies one: a paced
                // resume running in the profile, or a kill-switch fence's
                // lift, would otherwise resume it, and a paced set-online's
                // hold would load it unpaused at the next boot.
                let entry = profiles.resolve(&st.profile_id).active();
                let before = entry.map(|e| e.prepare_pause(st.handle));
                let paused = source
                    .engine_for(&st.profile_id)
                    .map(|e| e.pause_torrent(st.handle));
                if matches!(paused, Some(Ok(()))) {
                    // Saved now: a crash before the next sweep would bring
                    // the torrent back unpaused, announcing a payload its
                    // piece hashes just rejected.
                    state.queue_resume_save_now(*hash);
                } else {
                    // Its flag did not change, so the note goes back.
                    if let (Some(e), Some(before)) = (entry, before) {
                        e.restore_noted(st.handle, before);
                    }
                    warn!(
                        target: "torrentd::pool",
                        infohash = %ih,
                        "could not pause a torrent whose verification failed",
                    );
                }
            }
            (AdoptionState::Drifted, None, Some(now_secs()), Some(reason))
        }
    };
    let written = writer.with(pool, |s| {
        let base = s.adoption_base(ih).ok().flatten();
        s.set_adoption(
            ih,
            state_to_record,
            base.as_ref().map(|(r, _)| *r),
            base.as_ref().map(|(_, b)| b.as_str()),
            verified_at,
            drift_at,
            note,
        )
    });
    if let Err(e) = written {
        pool.note_store_error("set_adoption", &e);
    }
    pool.forget_queued(writer, ih);
}

/// What the verify queue should do with one in-flight torrent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum VerifyOutcome {
    /// Still hashing, or not in the state map yet.
    Waiting,
    Verified,
    Failed(&'static str),
}

/// What pool adoption hands a session to verify a payload before seeding it:
/// the `.torrent`, announcing to the previous client's `trackers` in place of
/// its own where that client kept any.
pub(crate) fn verify_add_params(
    profile: &torrentd_engine::ProfileConfig,
    bytes: Vec<u8>,
    save_path: String,
    trackers: Vec<Vec<String>>,
) -> AddParams {
    AddParams::File {
        bytes,
        save_path,
        flags: torrentd_engine::verify_flags(profile),
        trackers,
    }
}

/// Decide an in-flight torrent's fate from its state-map entry alone.
///
/// Pure so the wedge this guards against is testable without a session. The
/// `checked_at` arm is the load-bearing one: a torrent whose payload fails its
/// check is moved to libtorrent's `downloading` state, which maps to
/// `Incomplete`, so it never becomes `Errored` and never becomes `Seeding`.
/// Waiting for either therefore waits forever, and a handful of corrupt
/// torrents would hold every verify slot and wedge adoption for the whole
/// pool.
pub(super) fn verify_outcome(
    entry: Option<&torrentd_engine::TorrentState>,
    settle: Duration,
) -> VerifyOutcome {
    let Some(st) = entry else {
        return VerifyOutcome::Waiting;
    };
    if st.phase == TorrentPhase::Seeding {
        return VerifyOutcome::Verified;
    }
    if st.phase == TorrentPhase::Errored {
        return VerifyOutcome::Failed("libtorrent reported an unrecoverable error");
    }
    // Hashing is over and it still is not seeding, so the payload does not
    // match the piece hashes. `torrent_finished` can trail `torrent_checked`
    // into the next drain batch, so give the healthy case time to land first.
    match st.checked_at {
        Some(t) if t.elapsed() >= settle => {
            VerifyOutcome::Failed("payload failed verification against the piece hashes")
        }
        _ => VerifyOutcome::Waiting,
    }
}

/// Decide a re-hash of a loaded torrent requested at `started`, or `None`
/// while no check has finished since the request.
///
/// Stricter than [`verify_outcome`] in one way: the torrent was loaded, and
/// usually `Seeding`, before the re-hash, and `torrent_checked_alert` only
/// stamps `checked_at` — the phase carrying the check's verdict lands with
/// the next state update, up to an update interval later. Until a phase
/// report has landed since the check, `phase` is the one from before it, and
/// reading its `Seeding` as a pass would record `adopted`, clear drift and
/// leave seeding a payload that just failed. So nothing is decided until a
/// phase report has been seen since the check.
pub(super) fn recheck_outcome(
    st: &torrentd_engine::TorrentState,
    started: std::time::Instant,
    settle: Duration,
) -> Option<VerifyOutcome> {
    if st.checked_at.is_none_or(|t| t <= started) {
        return None;
    }
    if !st.phase_since_check {
        return Some(VerifyOutcome::Waiting);
    }
    Some(verify_outcome(Some(st), settle))
}

/// What the verify queue does with one re-hash entry on a tick.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum RecheckStep {
    /// No verdict yet, and still inside [`RECHECK_EXPIRY`].
    Hold,
    /// No verdict past [`RECHECK_EXPIRY`]: dropped without recording one.
    Forget,
    /// A verdict to record.
    Record(VerifyOutcome),
}

/// Decide a re-hash entry from its [`recheck_outcome`] and its age.
///
/// Both undecided cases share the expiry: no check since the request
/// (`None`), and a check whose phase report has not landed (`Waiting`). A
/// phase report that never arrives would otherwise hold the entry for the
/// life of the process.
pub(super) fn recheck_step(outcome: Option<VerifyOutcome>, age: Duration) -> RecheckStep {
    match outcome {
        None | Some(VerifyOutcome::Waiting) if age < RECHECK_EXPIRY => RecheckStep::Hold,
        None | Some(VerifyOutcome::Waiting) => RecheckStep::Forget,
        Some(outcome) => RecheckStep::Record(outcome),
    }
}

impl PoolService {
    /// Forget `infohash`'s entry in the persisted verify queue: the queue
    /// recorded its verdict, dropped it, or saw its torrent removed while it
    /// was hashing. An entry the queue has added to a session is kept until
    /// then, so a restart while it hashes still records the verdict.
    pub(super) fn forget_queued(&self, writer: Writer<'_>, infohash: &str) {
        if let Err(e) = writer.with(self, |s| s.dequeue_verify(infohash)) {
            self.note_store_error("dequeue_verify", &e);
        }
    }

    /// Queue again every adoption `pool.db` holds as waiting for
    /// verification, once the boot scans have run. Returns the info-hashes
    /// queued.
    ///
    /// An adoption claims its info-hash in the registry before it queues the
    /// torrent, so a crash with items still waiting used to leave each claim
    /// with nothing behind it. An entry is queued again only while its claim
    /// still names its profile and no scan loaded it:
    ///
    /// - one `loaded` names was added to a session before the restart, and is
    ///   back from its `.torrent` or resume file with its verdict not yet
    ///   recorded; the boot hashes it again, so it goes back in flight and
    ///   the worker records that check's verdict, pausing a failure, as it
    ///   would have without the restart. Its entry stays until then.
    /// - one whose claim is gone, or names another profile, is dropped as the
    ///   worker drops an item: its owner record goes too, while it still
    ///   names the entry's profile, and a claim someone else holds is left
    ///   alone.
    pub fn restore_verify_queue(
        &self,
        registry: &AssignmentRegistry,
        loaded: &std::collections::HashSet<libtorrent_safe::InfoHash>,
    ) -> Vec<libtorrent_safe::InfoHash> {
        let rows = match self.with_store(|s| s.verify_queue()) {
            Ok(rows) => rows,
            Err(e) => {
                warn!(
                    target: "torrentd::pool",
                    op = "verify_queue",
                    error.cause = %e,
                    "could not read the persisted verify queue; the adoptions it held keep \
                     their registry claims with nothing to load them",
                );
                return Vec::new();
            }
        };
        let mut queued = Vec::new();
        for row in rows {
            let item = PendingVerify::from_row(row);
            let Some(ih) = libtorrent_safe::InfoHash::from_hex(&item.infohash) else {
                self.forget_queued(Writer::Wait, &item.infohash);
                continue;
            };
            if loaded.contains(&ih) {
                info!(
                    target: "torrentd::pool",
                    infohash = %item.infohash,
                    profile_id = %item.profile,
                    "an adoption was added before the restart and is loaded; \
                     waiting for its verification",
                );
                self.verify.track_in_flight(item.infohash);
                continue;
            }
            if registry.lookup(&ih).as_ref() != Some(&item.profile) {
                warn!(
                    target: "torrentd::pool",
                    infohash = %item.infohash,
                    profile_id = %item.profile,
                    "a queued adoption's registry claim no longer names its profile; \
                     dropping it",
                );
                release_dropped_claim(self, Writer::Wait, registry, &item);
                continue;
            }
            queued.push(ih);
            self.verify.enqueue(item);
        }
        if !queued.is_empty() {
            info!(
                target: "torrentd::pool",
                count = queued.len(),
                "queued the adoptions left waiting for verification again",
            );
        }
        queued
    }
}

/// How a verify-queue step that records something in the pool index reaches
/// its writer.
#[derive(Clone, Copy)]
pub(super) enum Writer<'a> {
    /// Take the writer for each write, waiting out whoever holds it, a
    /// running scan included: the boot's restore of the queue.
    Wait,
    /// The writer the verify tick took, which it takes only where nobody
    /// holds it, so none of its steps waits on a scan.
    Held(&'a PoolStore),
}

impl Writer<'_> {
    fn with<T>(self, pool: &PoolService, f: impl FnOnce(&PoolStore) -> T) -> T {
        match self {
            Writer::Wait => pool.with_store(f),
            Writer::Held(store) => off_worker(|| f(store)),
        }
    }
}
