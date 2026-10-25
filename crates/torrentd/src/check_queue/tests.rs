//! Verdicts, drops and the boot's restore of the check queue's adoptions and
//! re-hashes.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use torrentd_engine::InfoHash;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentPhase;
use torrentd_engine::TorrentState;

use super::worker::verify_outcome;
use super::worker::VerifyOutcome;
use crate::pool_service::tests::owner_of;
use crate::pool_service::tests::pending;
use crate::pool_service::tests::pool_with;
use crate::profile_registry::ProfileStatus;

pub(super) const SETTLE: Duration = Duration::from_secs(5);

fn st(phase: TorrentPhase, checked_ago: Option<Duration>) -> TorrentState {
    let now = Instant::now();
    let mut s = TorrentState::newly_added(
        TorrentHandle {
            id: 1,
            infohash: InfoHash([0x11; 20]),
        },
        ProfileId::new("p"),
        now,
    );
    s.phase = phase;
    s.checked_at = checked_ago.map(|d| now - d);
    s
}

#[test]
fn a_torrent_still_hashing_keeps_its_profile() {
    let s = st(TorrentPhase::Checking, None);
    assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Waiting);
}

#[test]
fn a_torrent_absent_from_the_state_map_keeps_its_profile() {
    assert_eq!(verify_outcome(None, SETTLE), VerifyOutcome::Waiting);
}

#[test]
fn a_seeding_torrent_retires_as_verified() {
    let s = st(TorrentPhase::Seeding, Some(Duration::from_secs(60)));
    assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Verified);
}

/// The wedge this fix exists for. A torrent whose payload fails hashing is
/// left in libtorrent's `downloading` state — `Incomplete` now, `Checking`
/// before that phase existed — so it is neither `Seeding` nor `Errored`,
/// and before the `checked_at` arm it held a verify slot forever. Four of
/// these were enough to stop the whole pool adopting.
#[test]
fn a_torrent_that_failed_hashing_does_not_hold_its_verify_slot_forever() {
    for phase in [TorrentPhase::Incomplete, TorrentPhase::Checking] {
        let s = st(phase, Some(Duration::from_secs(60)));
        assert_eq!(
            verify_outcome(Some(&s), SETTLE),
            VerifyOutcome::Failed("payload failed verification against the piece hashes"),
        );
    }
}

/// `torrent_checked` and `torrent_finished` can arrive in different drain
/// batches, so a tick landing between them must not condemn a healthy
/// torrent.
#[test]
fn a_just_checked_torrent_is_given_time_to_report_seeding() {
    let s = st(TorrentPhase::Checking, Some(Duration::from_millis(10)));
    assert_eq!(verify_outcome(Some(&s), SETTLE), VerifyOutcome::Waiting);
}

/// A re-hash of a torrent that was seeding: `torrent_checked` stamps
/// `checked_at`, and the `Seeding` still in `phase` is from before the
/// check. Read as the verdict, it records a payload that just failed as
/// verified.
#[test]
fn a_recheck_does_not_take_the_phase_from_before_the_check_as_its_verdict() {
    let started = Instant::now() - Duration::from_secs(120);
    let mut s = st(TorrentPhase::Seeding, Some(Duration::from_secs(60)));
    s.phase_since_check = false;
    assert_eq!(
        super::worker::recheck_outcome(&s, started, SETTLE),
        Some(VerifyOutcome::Waiting),
    );
    // The report carrying the verdict lands.
    s.phase = TorrentPhase::Incomplete;
    s.phase_since_check = true;
    assert_eq!(
        super::worker::recheck_outcome(&s, started, SETTLE),
        Some(VerifyOutcome::Failed(
            "payload failed verification against the piece hashes"
        )),
    );
    s.phase = TorrentPhase::Seeding;
    assert_eq!(
        super::worker::recheck_outcome(&s, started, SETTLE),
        Some(VerifyOutcome::Verified),
    );
}

/// A check that finished before the request is the previous one.
#[test]
fn a_recheck_ignores_a_check_from_before_the_request() {
    let mut s = st(TorrentPhase::Seeding, Some(Duration::from_secs(60)));
    s.phase_since_check = true;
    let started = Instant::now() - Duration::from_secs(30);
    assert_eq!(super::worker::recheck_outcome(&s, started, SETTLE), None);
}

/// A re-hash whose phase report never lands falls to the same expiry as
/// one that was never checked, instead of being held forever.
#[test]
fn an_undecided_recheck_is_forgotten_after_the_expiry() {
    use super::worker::recheck_step;
    use super::worker::RecheckStep;
    use super::RECHECK_EXPIRY;

    let young = RECHECK_EXPIRY - Duration::from_secs(1);
    for undecided in [None, Some(VerifyOutcome::Waiting)] {
        assert_eq!(recheck_step(undecided, young), RecheckStep::Hold);
        assert_eq!(recheck_step(undecided, RECHECK_EXPIRY), RecheckStep::Forget);
    }
    // A verdict is recorded whatever its age.
    assert_eq!(
        recheck_step(Some(VerifyOutcome::Verified), RECHECK_EXPIRY),
        RecheckStep::Record(VerifyOutcome::Verified),
    );
}

/// The enqueue writes the pool index's owner before the worker runs, so a
/// drop has to take it back: left behind, it refused adoption into every
/// other profile, and `DELETE` (with no registry entry) answered not
/// found.
#[test]
fn a_dropped_verify_clears_the_index_owner_its_enqueue_recorded() {
    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let ih = InfoHash([0x55; 20]);
    let pool = pool_with(dir.path(), ih, None);
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    let reg = crate::registry::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    reg.assign(ih, ProfileId::new("p")).unwrap();

    crate::pool_service::enqueue_verify(
        &pool,
        &profiles,
        &ih.to_hex(),
        dir.path().join("t.torrent"),
        dir.path().join("payload"),
        None,
        ProfileId::new("p"),
        false,
    )
    .unwrap();
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));
    let item = pool.verify_queue().pop_pending().unwrap();
    assert!(item.owner_recorded);

    super::worker::release_dropped_claim(&pool, super::worker::Writer::Wait, &reg, &item);
    assert_eq!(owner_of(&pool, ih), None);
    assert_eq!(reg.lookup(&ih), None);
}

/// An adoption claims its info-hash before it is queued, so the queue is
/// kept in `pool.db` and a restart queues again what was still waiting:
/// held in memory only, a crash left each claim with nothing to load it.
/// What the queue recorded a verdict for or dropped before the restart is
/// not queued again, nor is one whose claim no longer names its profile.
/// An entry whose torrent a scan loaded was added and is still hashing:
/// it goes back in flight, its entry kept, so its verdict is recorded.
#[test]
fn a_restart_queues_again_the_adoptions_still_waiting() {
    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let waiting = InfoHash([0x61; 20]);
    let loaded = InfoHash([0x62; 20]);
    let reassigned = InfoHash([0x63; 20]);
    let dropped = InfoHash([0x64; 20]);
    let admitted = InfoHash([0x65; 20]);
    let pool = pool_with(dir.path(), reassigned, None);
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    let reg = crate::registry::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    let trackers = vec![vec!["http://tracker.example/announce".to_owned()]];
    let resume = dir.path().join("t.fastresume");
    std::fs::write(
        &resume,
        "d8:trackersll31:http://tracker.example/announceeee",
    )
    .unwrap();
    for ih in [waiting, loaded, reassigned, dropped, admitted] {
        reg.assign(ih, ProfileId::new("p")).unwrap();
        crate::pool_service::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            dir.path().join("t.torrent"),
            dir.path().join("payload"),
            Some(&resume),
            ProfileId::new("p"),
            false,
        )
        .unwrap();
    }
    assert_eq!(owner_of(&pool, reassigned).as_deref(), Some("p"));
    // Before the crash the worker dropped one and recorded another's
    // verdict.
    super::worker::release_dropped_claim(
        &pool,
        super::worker::Writer::Wait,
        &reg,
        &pending(dropped, "p"),
    );
    pool.forget_queued(super::worker::Writer::Wait, &admitted.to_hex());
    // Since then, `reassigned`'s claim went to another profile.
    reg.remove(&reassigned).unwrap();
    reg.assign(reassigned, ProfileId::new("other")).unwrap();
    drop(pool);

    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = crate::pool_service::PoolService::open(&cfg)
        .unwrap()
        .unwrap();
    let scanned: std::collections::HashSet<_> = [loaded, admitted].into();
    assert_eq!(pool.restore_verify_queue(&reg, &scanned), [waiting]);

    assert_eq!(pool.verify_queue().depth(), 1);
    let item = pool.verify_queue().pop_pending().unwrap();
    assert_eq!(item.infohash, waiting.to_hex());
    assert_eq!(item.profile, ProfileId::new("p"));
    assert_eq!(item.torrent_path, dir.path().join("t.torrent"));
    assert_eq!(item.save_path, dir.path().join("payload"));
    assert_eq!(item.trackers, trackers);
    // The reassigned entry was dropped as the worker drops one: its owner
    // record goes, and the other profile's claim stays.
    assert_eq!(owner_of(&pool, reassigned), None);
    assert_eq!(reg.lookup(&reassigned), Some(ProfileId::new("other")));
    // The loaded adoption is waited on for the boot's check; the one
    // whose verdict was recorded is not.
    assert!(pool.verify_queue().is_in_flight(&loaded.to_hex()));
    assert!(!pool.verify_queue().is_in_flight(&admitted.to_hex()));
    assert_eq!(pool.verify_queue().in_flight(), 1);
    // The waiting adoption and the loaded one are still kept, so a second
    // restart before the queue adds the first, or records the second's
    // verdict, does the same again.
    let kept: Vec<_> = pool
        .with_store(|s| s.verify_queue().unwrap())
        .into_iter()
        .map(|r| r.infohash)
        .collect();
    assert_eq!(kept, [waiting.to_hex(), loaded.to_hex()]);
}

/// A finished verification whose store write waits out a scan does not
/// hold the queue's lists while it waits: `GET /v1/pool` and the event
/// stream read `depth()` and `in_flight()` on runtime workers, and a
/// reader blocked behind the scan pinned its worker until the scan
/// committed. Here the writer is held from another thread, an in-flight
/// torrent and a re-hash both finish, and one verify tick runs; a task
/// must read the queue's counts while that tick is still waiting, and
/// the verdicts land once the writer is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verdict_waiting_on_the_writer_does_not_block_the_queue_readers() {
    use std::sync::mpsc;
    use std::sync::Arc;

    use torrentd_engine::AlertSource;
    use torrentd_engine::MockEngine;
    use torrentd_engine::StateMap;
    use torrentd_pool::AdoptionState;

    let dir = tempfile::tempdir().unwrap();
    let adopted = InfoHash([0x81; 20]);
    let rehashed = InfoHash([0x82; 20]);
    let pool = Arc::new(pool_with(dir.path(), adopted, Some("p")));
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn AlertSource> = Arc::new(torrentd_engine::ProfileSource::new(vec![(
        ProfileId::new("p"),
        engine as Arc<dyn torrentd_engine::TorrentEngine>,
    )]));
    let state = Arc::new(StateMap::new());

    pool.verify_queue().track_in_flight(adopted.to_hex());
    pool.verify_queue()
        .await_recheck_verdict(rehashed.to_hex(), std::time::Instant::now());
    assert_eq!(pool.verify_queue().in_flight(), 1);
    // The adoption's check fails, and the re-hash, finishing after it was
    // asked for, passes: each verdict is a store write.
    std::thread::sleep(Duration::from_millis(10));
    state.insert(adopted, st(TorrentPhase::Incomplete, Some(SETTLE)));
    let mut seeding = st(TorrentPhase::Seeding, Some(Duration::ZERO));
    seeding.phase_since_check = true;
    state.insert(rehashed, seeding);

    // A scan holds the writer until told to stop.
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder = {
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            let _store = pool.hold_writer_for_tests();
            held_tx.send(()).unwrap();
            // Released when told, or when the test fails and drops the
            // sender.
            let _ = release_rx.recv();
        })
    };
    held_rx.recv().unwrap();

    // The verify tick's two retirements, each waiting on the writer to
    // record its verdict.
    let profiles = Arc::new(crate::profile_registry::ProfileRegistry::new(vec![]));
    let retire = |f: fn(
        &crate::pool_service::PoolService,
        super::worker::Writer<'_>,
        &dyn AlertSource,
        &StateMap,
        &crate::profile_registry::ProfileRegistry,
    )| {
        let (pool, source, state, profiles) = (
            Arc::clone(&pool),
            Arc::clone(&source),
            Arc::clone(&state),
            Arc::clone(&profiles),
        );
        std::thread::spawn(move || {
            f(
                &pool,
                super::worker::Writer::Wait,
                &*source,
                &state,
                &profiles,
            )
        })
    };
    let in_flight = retire(super::worker::retire_in_flight);
    let rechecks = retire(super::worker::retire_rechecks);

    // A reader on a runtime worker sees both finished entries gone while
    // their verdicts are still waiting, rather than waiting with them.
    let reader = {
        let pool = Arc::clone(&pool);
        let rehashed = rehashed.to_hex();
        tokio::spawn(async move {
            let q = pool.verify_queue();
            while q.in_flight() != 0 || q.tracks_recheck(&rehashed) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            q.depth()
        })
    };
    let read = tokio::time::timeout(Duration::from_secs(5), reader).await;
    assert!(
        matches!(read, Ok(Ok(0))),
        "a queue reader blocked behind the writer: {read:?}",
    );
    assert!(!in_flight.is_finished() && !rechecks.is_finished());

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    in_flight.join().unwrap();
    rechecks.join().unwrap();
    let got = pool
        .with_store(|s| s.adoption_state(&adopted.to_hex()))
        .unwrap();
    assert_eq!(got, Some(AdoptionState::Drifted));
    assert_eq!(pool.verify_queue().failed(), 1);
    assert_eq!(pool.verify_queue().completed(), 1);
}

/// The in-flight half of a restart mid-verify: a loaded adoption put
/// back in flight has its failed check recorded as a fresh adoption's
/// is, paused and `drifted`, and its persisted entry goes with the
/// verdict. One removed while it hashed is forgotten, entry and all,
/// without a verdict.
#[test]
fn a_restored_in_flight_adoption_records_its_verdict_and_a_removed_one_is_forgotten() {
    use std::sync::Arc;

    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::StateMap;
    use torrentd_pool::AdoptionState;

    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let checked = InfoHash([0x71; 20]);
    let removed = InfoHash([0x72; 20]);
    let pool = pool_with(dir.path(), checked, None);
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    let reg = crate::registry::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    for ih in [checked, removed] {
        reg.assign(ih, ProfileId::new("p")).unwrap();
        crate::pool_service::enqueue_verify(
            &pool,
            &profiles,
            &ih.to_hex(),
            dir.path().join("t.torrent"),
            dir.path().join("payload"),
            None,
            ProfileId::new("p"),
            false,
        )
        .unwrap();
    }
    drop(pool);

    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = crate::pool_service::PoolService::open(&cfg)
        .unwrap()
        .unwrap();
    let scanned: std::collections::HashSet<_> = [checked, removed].into();
    assert!(pool.restore_verify_queue(&reg, &scanned).is_empty());
    assert_eq!(pool.verify_queue().in_flight(), 2);

    let engine = Arc::new(MockEngine::new());
    let source = torrentd_engine::ProfileSource::new(vec![(
        ProfileId::new("p"),
        engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
    )]);
    let state = StateMap::new();
    // Both are in their sessions, still hashing.
    state.insert(checked, st(TorrentPhase::Checking, None));
    state.insert(removed, st(TorrentPhase::Checking, None));
    super::worker::retire_in_flight(
        &pool,
        super::worker::Writer::Wait,
        &source,
        &state,
        &profiles,
    );
    assert_eq!(pool.verify_queue().in_flight(), 2);

    // One finishes its check without seeding; the other is removed.
    state.insert(checked, st(TorrentPhase::Incomplete, Some(SETTLE)));
    state.remove(&removed, &ProfileId::new("p"), None);
    super::worker::retire_in_flight(
        &pool,
        super::worker::Writer::Wait,
        &source,
        &state,
        &profiles,
    );

    assert_eq!(pool.verify_queue().in_flight(), 0);
    assert!(engine
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
    let got = pool
        .with_store(|s| s.adoption_state(&checked.to_hex()))
        .unwrap();
    assert_eq!(got, Some(AdoptionState::Drifted));
    assert!(pool.with_store(|s| s.verify_queue().unwrap()).is_empty());
}

/// An adoption whose `torrent_checked_alert` was dropped never gets
/// `checked_at`, and one whose check failed then sits in `Incomplete`, which
/// [`verify_outcome`] reads as still waiting: it held its verify slot for the
/// life of the process. Shown that way past the settle, it is recorded
/// failed - paused, `drifted`, counted - and its slot is freed.
#[test]
fn an_adoption_whose_checked_alert_was_lost_frees_its_slot_as_failed() {
    use std::sync::Arc;

    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::StateMap;
    use torrentd_pool::AdoptionState;

    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let hash = InfoHash([0x73; 20]);
    let pool = pool_with(dir.path(), hash, None);
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    let engine = Arc::new(MockEngine::new());
    let source = torrentd_engine::ProfileSource::new(vec![(
        ProfileId::new("p"),
        engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
    )]);
    let state = StateMap::new();
    let q = pool.verify_queue();
    q.track_in_flight(hash.to_hex());
    let retire = || {
        super::worker::retire_in_flight(
            &pool,
            super::worker::Writer::Wait,
            &source,
            &state,
            &profiles,
        );
    };

    // Hashing, or held paused: it keeps its slot however long that lasts,
    // past the expiry too.
    for phase in [TorrentPhase::Checking, TorrentPhase::Paused] {
        state.insert(hash, st(phase, None));
        retire();
        q.age_in_flight(super::RECHECK_EXPIRY);
        retire();
        assert!(q.is_in_flight(&hash.to_hex()));
    }

    // The check ends failed and its alert is lost. Just seen, it is given
    // the settle.
    state.insert(hash, st(TorrentPhase::Incomplete, None));
    retire();
    assert!(q.is_in_flight(&hash.to_hex()));
    assert_eq!(q.failed(), 0);

    q.age_in_flight(SETTLE);
    retire();
    assert_eq!(q.in_flight(), 0);
    assert_eq!(q.failed(), 1);
    assert!(engine
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
    let got = pool
        .with_store(|s| s.adoption_state(&hash.to_hex()))
        .unwrap();
    assert_eq!(got, Some(AdoptionState::Drifted));
}

/// Issue 650: a disk read error during an adoption's check leaves the
/// torrent paused with an error. That check is over with no verdict, yet
/// read as held paused it reset the expiry every tick and kept its verify
/// slot for the life of the process, and `max_concurrent_verify` of them
/// stalled every check behind them. Through the worker's tick: one paused
/// without an error still waits past the expiry, holding its slot, while
/// one paused on an error is recorded failed with its reason, freeing the
/// slot for the check queued behind it.
#[test]
fn an_error_paused_adoption_is_failed_and_frees_its_slot() {
    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::StateMap;
    use torrentd_pool::AdoptionState;

    use super::worker::ERROR_PAUSED_REASON;
    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let adopting = InfoHash([0x65; 20]);
    let mut pool = pool_with(dir.path(), adopting, Some("p"));
    pool.verify = Arc::new(super::VerifyQueue::new(1));
    let engine = Arc::new(MockEngine::new());
    let source: Arc<dyn torrentd_engine::AlertSource> =
        Arc::new(torrentd_engine::ProfileSource::new(vec![(
            ProfileId::new("p"),
            engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
        )]));
    let profiles = Arc::new(ProfileRegistry::new(vec![test_entry(
        "p",
        ProfileStatus::Active,
    )]));
    let registry = Arc::new(crate::registry::AssignmentRegistry::new_empty(
        dir.path().join("reg.json"),
    ));
    let metrics = Arc::new(crate::metrics_sink::PromSink::new());
    let state = StateMap::new();
    let q = pool.verify_queue();

    // The adoption holds the only slot; a re-hash waits behind it.
    q.track_in_flight(adopting.to_hex());
    let queued = InfoHash([0x66; 20]);
    let mut loaded = TorrentState::newly_added(
        TorrentHandle {
            id: 2,
            infohash: queued,
        },
        ProfileId::new("p"),
        Instant::now(),
    );
    loaded.phase = TorrentPhase::Seeding;
    state.insert(queued, loaded);
    q.enqueue_recheck(queued.to_hex(), false);
    let tick = || {
        super::worker::verify_tick(
            q,
            Some(&pool),
            &source,
            &state,
            &metrics,
            &profiles,
            &registry,
        );
    };
    let rechecked = || {
        engine
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::ForceRecheck(h) if h.infohash == queued))
    };

    // Held paused without an error, as behind the held-add queue: it keeps
    // waiting past the expiry, and the re-hash with it.
    state.insert(adopting, st(TorrentPhase::Paused, None));
    tick();
    q.age_in_flight(super::RECHECK_EXPIRY);
    tick();
    assert!(q.is_in_flight(&adopting.to_hex()));
    assert_eq!(q.failed(), 0);
    assert!(
        !rechecked(),
        "the paused adoption still holds the only slot"
    );

    // Its check fails on a disk read error, which pauses it with the error.
    let mut errored = st(TorrentPhase::Paused, None);
    errored.has_error = true;
    state.insert(adopting, errored);
    tick();
    assert!(!q.is_in_flight(&adopting.to_hex()));
    assert_eq!(q.failed(), 1);
    assert!(engine
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
    let drifted = pool
        .with_store(|s| s.torrents_page(None, Some(AdoptionState::Drifted), 10))
        .unwrap();
    assert_eq!(drifted.len(), 1);
    assert_eq!(drifted[0].torrent.infohash, adopting.to_hex());
    assert_eq!(drifted[0].note.as_deref(), Some(ERROR_PAUSED_REASON));
    assert!(rechecked(), "the freed slot went to the queued re-hash");
}

/// The decision behind the test above, and its backstop: a finished check's
/// phase shown unstamped is failed only once held for the settle, any other
/// phase between resets it, and one showing neither a running nor a held
/// check past the expiry is failed, while one showing either never is.
#[test]
fn an_adoption_with_no_verdict_is_failed_after_the_settle_or_the_expiry() {
    use super::worker::lost_check_outcome;
    use super::RECHECK_EXPIRY;

    let young = Duration::from_secs(1);
    for phase in [TorrentPhase::Incomplete, TorrentPhase::Idle] {
        let s = st(phase, None);
        let mut since = None;
        let mut waiting = Instant::now() - young;
        assert_eq!(
            lost_check_outcome(Some(&s), &mut since, &mut waiting, SETTLE, RECHECK_EXPIRY),
            VerifyOutcome::Waiting,
        );
        assert!(since.is_some());
        since = since.map(|t| t - SETTLE);
        assert!(matches!(
            lost_check_outcome(Some(&s), &mut since, &mut waiting, SETTLE, RECHECK_EXPIRY),
            VerifyOutcome::Failed(_),
        ));
    }

    // A healthy check passing through: `Seeding` would be decided by
    // `verify_outcome`, so any phase still undecided here resets the clock.
    for phase in [
        TorrentPhase::Checking,
        TorrentPhase::Paused,
        TorrentPhase::DiskError,
    ] {
        let mut since = Some(Instant::now() - SETTLE);
        let mut waiting = Instant::now() - young;
        assert_eq!(
            lost_check_outcome(
                Some(&st(phase, None)),
                &mut since,
                &mut waiting,
                SETTLE,
                RECHECK_EXPIRY,
            ),
            VerifyOutcome::Waiting,
        );
        assert_eq!(since, None);
    }

    // A stamped check is `verify_outcome`'s to decide, not this.
    let mut since = None;
    let mut waiting = Instant::now() - young;
    assert_eq!(
        lost_check_outcome(
            Some(&st(TorrentPhase::Incomplete, Some(Duration::ZERO))),
            &mut since,
            &mut waiting,
            SETTLE,
            RECHECK_EXPIRY,
        ),
        VerifyOutcome::Waiting,
    );

    // A running or held check is never expired, however long it has waited:
    // a multi-terabyte hash past a day, or an adoption held paused behind the
    // held-add queue. Showing either restarts the clock.
    for phase in [TorrentPhase::Checking, TorrentPhase::Paused] {
        let mut since = None;
        let mut waiting = Instant::now() - RECHECK_EXPIRY - young;
        assert_eq!(
            lost_check_outcome(
                Some(&st(phase, None)),
                &mut since,
                &mut waiting,
                SETTLE,
                RECHECK_EXPIRY,
            ),
            VerifyOutcome::Waiting,
        );
        assert!(waiting.elapsed() < young);
    }

    // Paused on an error, as a disk read error during the check leaves it,
    // the check is over: failed at once, however young.
    for phase in [TorrentPhase::Paused, TorrentPhase::DiskError] {
        let mut s = st(phase, None);
        s.has_error = true;
        let mut since = None;
        let mut waiting = Instant::now();
        assert_eq!(
            lost_check_outcome(Some(&s), &mut since, &mut waiting, SETTLE, RECHECK_EXPIRY),
            VerifyOutcome::Failed(super::worker::ERROR_PAUSED_REASON),
        );
    }

    // Past the expiry showing neither: never in the state map, or stuck in
    // a phase no check leads to.
    let stuck = st(TorrentPhase::DiskError, None);
    for entry in [Some(&stuck), None] {
        let mut since = None;
        let mut waiting = Instant::now() - (RECHECK_EXPIRY - young);
        assert_eq!(
            lost_check_outcome(entry, &mut since, &mut waiting, SETTLE, RECHECK_EXPIRY),
            VerifyOutcome::Waiting,
        );
        waiting -= young;
        assert_eq!(
            lost_check_outcome(entry, &mut since, &mut waiting, SETTLE, RECHECK_EXPIRY),
            VerifyOutcome::Failed("no verification verdict within the check expiry"),
        );
    }
}

/// An owner record the enqueue did not write, or that names another
/// profile by the time of the drop, is not the drop's to clear.
#[test]
fn a_dropped_verify_leaves_an_index_owner_it_did_not_record() {
    use crate::profile_registry::test_entry;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let ih = InfoHash([0x66; 20]);
    let reg = crate::registry::AssignmentRegistry::new_empty(dir.path().join("reg.json"));

    // Already this profile's before the adopt: the enqueue records nothing.
    let pool = pool_with(dir.path(), ih, Some("p"));
    let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
    crate::pool_service::enqueue_verify(
        &pool,
        &profiles,
        &ih.to_hex(),
        dir.path().join("t.torrent"),
        dir.path().join("payload"),
        None,
        ProfileId::new("p"),
        false,
    )
    .unwrap();
    let item = pool.verify_queue().pop_pending().unwrap();
    assert!(!item.owner_recorded);
    super::worker::release_dropped_claim(&pool, super::worker::Writer::Wait, &reg, &item);
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("p"));

    // Recorded, but another profile's by now.
    pool.with_store(|s| s.set_profile(&ih.to_hex(), Some("other")).unwrap());
    let item = super::PendingVerify {
        owner_recorded: true,
        ..pending(ih, "p")
    };
    super::worker::release_dropped_claim(&pool, super::worker::Writer::Wait, &reg, &item);
    assert_eq!(owner_of(&pool, ih).as_deref(), Some("other"));
}

/// The verify worker counts a foreign `.torrent` as an isolation refusal,
/// as every add path does, and bytes it cannot read as a failed verify
/// only.
#[test]
fn the_verify_worker_counts_only_a_foreign_torrent_as_an_isolation_refusal() {
    let mut profile = crate::profile_registry::test_entry("acct", ProfileStatus::Active).config;
    profile.allowed_tracker_domains = vec!["allowed.example".to_owned()];
    let metrics = crate::metrics_sink::PromSink::new();
    let item = pending(InfoHash([0x44; 20]), "acct");
    let file = |announce: &str| {
        let mut t = format!(
            "d8:announce{}:{announce}4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:",
            announce.len()
        )
        .into_bytes();
        t.extend_from_slice(&[0u8; 20]);
        t.extend_from_slice(b"ee");
        super::worker::verify_add_params(&profile, t, "/p".into(), Vec::new())
    };
    let counted = || {
        let text = String::from_utf8(metrics.render()).unwrap();
        text.lines()
            .find(|l| l.contains("profile_assignment_registry_errors_total{profile_id=\"acct\"}"))
            .map(str::to_owned)
    };

    super::worker::verify_guard(
        &metrics,
        &profile,
        &item,
        &file("http://tracker.allowed.example/announce"),
    )
    .unwrap();
    assert!(matches!(
        super::worker::verify_guard(
            &metrics,
            &profile,
            &item,
            &super::worker::verify_add_params(
                &profile,
                b"not bencode".to_vec(),
                "/p".into(),
                Vec::new()
            ),
        ),
        Err(torrentd_engine::TrackerRefusal::Unreadable(_))
    ));
    assert!(
        counted().is_none_or(|l| l.ends_with(" 0")),
        "{:?}",
        counted()
    );
    assert!(matches!(
        super::worker::verify_guard(
            &metrics,
            &profile,
            &item,
            &file("http://tracker.foreign.example/announce"),
        ),
        Err(torrentd_engine::TrackerRefusal::NotAllowed)
    ));
    assert!(
        counted().is_some_and(|l| l.ends_with(" 1")),
        "{:?}",
        counted()
    );
}

/// Issue 113: a `.torrent` qBittorrent wrote without trackers is added on
/// the verify path with the ones its `.fastresume` kept, and held to the
/// allow-list on those; with neither, the refusal says there is no
/// tracker, and is counted as the guard's.
#[test]
fn the_verify_path_announces_to_the_fastresumes_trackers() {
    let dir = tempfile::tempdir().unwrap();
    let mut profile = crate::profile_registry::test_entry("acct", ProfileStatus::Active).config;
    profile.allowed_tracker_domains = vec!["allowed.example".to_owned()];
    let metrics = crate::metrics_sink::PromSink::new();
    let item = pending(InfoHash([0x45; 20]), "acct");
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    let resume = |trackers: &str| {
        let p = dir.path().join("t.fastresume");
        std::fs::write(&p, format!("d8:trackers{trackers}e")).unwrap();
        crate::pool_service::previous_trackers(Some(&p))
    };

    let kept = resume("ll39:http://tracker.allowed.example/announceee");
    assert_eq!(
        kept,
        vec![vec!["http://tracker.allowed.example/announce".to_owned()]]
    );
    let params = super::worker::verify_add_params(&profile, bare.clone(), "/p".into(), kept);
    super::worker::verify_guard(&metrics, &profile, &item, &params).unwrap();
    let foreign = resume("ll39:http://tracker.foreign.example/announceee");
    assert!(matches!(
        super::worker::verify_guard(
            &metrics,
            &profile,
            &item,
            &super::worker::verify_add_params(&profile, bare.clone(), "/p".into(), foreign),
        ),
        Err(torrentd_engine::TrackerRefusal::NotAllowed)
    ));

    // No `.fastresume`, or one with no trackers: none to announce to.
    assert!(crate::pool_service::previous_trackers(None).is_empty());
    // Nor does a sidecar that cannot be parsed, or read.
    assert!(resume("ll39:http://tracker.allowed.example/announce").is_empty());
    assert!(
        crate::pool_service::previous_trackers(Some(&dir.path().join("gone.fastresume")))
            .is_empty()
    );
    let none = resume("le");
    assert!(none.is_empty());
    let refusal = super::worker::verify_guard(
        &metrics,
        &profile,
        &item,
        &super::worker::verify_add_params(&profile, bare, "/p".into(), none),
    )
    .unwrap_err();
    assert!(matches!(
        refusal,
        torrentd_engine::TrackerRefusal::NoTrackers
    ));
    let adopt = crate::pool_service::tracker_refusal(&refusal);
    assert!(adopt.isolation);
    assert!(adopt.reason.contains("no tracker"), "{}", adopt.reason);
    assert!(!adopt.reason.contains("outside"), "{}", adopt.reason);
    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(
            text.lines()
                .any(|l| l
                    .ends_with("profile_assignment_registry_errors_total{profile_id=\"acct\"} 2")),
            "{text}"
        );
}

/// Issue 166: an adoption onto account B's profile, bound to B's passkey,
/// is refused when the previous client's resume trackers carry account
/// A's — on the verify path, which adds the bare `.torrent` with those
/// trackers, and on the resume fast path, which hands the resume data
/// itself — though A's tracker is on B's domain list. The refusal names
/// the binding and is counted as the guard's.
#[test]
fn an_adoption_carrying_another_accounts_passkey_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut profile = crate::profile_registry::test_entry("acct", ProfileStatus::Active).config;
    profile.allowed_tracker_domains = vec!["allowed.example".to_owned()];
    profile.allowed_tracker_urls = vec!["http://tracker.allowed.example/PASS-B/".to_owned()];
    let metrics = crate::metrics_sink::PromSink::new();
    let item = pending(InfoHash([0x46; 20]), "acct");
    let mut bare = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    bare.extend_from_slice(&[0u8; 20]);
    bare.extend_from_slice(b"ee");
    let resume = |passkey: &str| {
        let url = format!("http://tracker.allowed.example/{passkey}/announce");
        let p = dir.path().join("t.fastresume");
        std::fs::write(&p, format!("d8:trackersll{}:{url}eee", url.len())).unwrap();
        crate::pool_service::previous_trackers(Some(&p))
    };

    let verify =
        |trackers| super::worker::verify_add_params(&profile, bare.clone(), "/p".into(), trackers);
    super::worker::verify_guard(&metrics, &profile, &item, &verify(resume("PASS-B"))).unwrap();
    let refusal = super::worker::verify_guard(&metrics, &profile, &item, &verify(resume("PASS-A")))
        .unwrap_err();
    assert!(matches!(
        refusal,
        torrentd_engine::TrackerRefusal::ForeignAccount
    ));
    let adopt = crate::pool_service::tracker_refusal(&refusal);
    assert!(adopt.isolation);
    assert!(
        adopt.reason.contains("allowed_tracker_urls"),
        "{}",
        adopt.reason
    );

    // The fast path: libtorrent resume data whose own `trackers` list is
    // A's, in front of a bare `.torrent`.
    let ih = libtorrent_safe::info_hash_from_torrent(&bare).unwrap();
    let url = "http://tracker.allowed.example/PASS-A/announce";
    let mut data =
        b"d11:file-format22:libtorrent resume file12:file-versioni1e9:info-hash20:".to_vec();
    data.extend_from_slice(&ih.0);
    data.extend_from_slice(format!("8:trackersll{}:{url}eee", url.len()).as_bytes());
    let params =
        crate::pool_service::adoption_resume_params(&profile, data, Some(bare), "/p".into());
    assert!(matches!(
        torrentd_engine::check_trackers(&profile, &params),
        Err(torrentd_engine::TrackerRefusal::ForeignAccount)
    ));

    let text = String::from_utf8(metrics.render()).unwrap();
    assert!(
            text.lines()
                .any(|l| l
                    .ends_with("profile_assignment_registry_errors_total{profile_id=\"acct\"} 1")),
            "{text}"
        );
}

/// A verify item the worker drops never reaches a session, so its claim
/// must go with it: left behind, `DELETE` answered 409 and every re-adopt
/// was refused until a restart.
#[test]
fn a_dropped_verify_releases_its_registry_claim() {
    let dir = tempfile::tempdir().unwrap();
    let reg = crate::registry::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    let ih = InfoHash([0x22; 20]);
    reg.assign(ih, ProfileId::new("p")).unwrap();
    let pool = pool_with(dir.path(), ih, None);
    super::worker::release_dropped_claim(
        &pool,
        super::worker::Writer::Wait,
        &reg,
        &pending(ih, "p"),
    );
    assert_eq!(reg.lookup(&ih), None);
}

/// A claim that no longer names the item's profile is not the item's to
/// release.
#[test]
fn a_dropped_verify_leaves_another_profiles_claim() {
    let dir = tempfile::tempdir().unwrap();
    let reg = crate::registry::AssignmentRegistry::new_empty(dir.path().join("reg.json"));
    let ih = InfoHash([0x33; 20]);
    reg.assign(ih, ProfileId::new("other")).unwrap();
    let pool = pool_with(dir.path(), ih, None);
    super::worker::release_dropped_claim(
        &pool,
        super::worker::Writer::Wait,
        &reg,
        &pending(ih, "p"),
    );
    assert_eq!(reg.lookup(&ih), Some(ProfileId::new("other")));
}

#[test]
fn an_errored_torrent_retires_as_failed() {
    let s = st(TorrentPhase::Errored, None);
    assert!(matches!(
        verify_outcome(Some(&s), SETTLE),
        VerifyOutcome::Failed(_),
    ));
}

/// A failed verification records `drifted` and pauses the torrent; a
/// passed one is the only thing that clears drift.
#[test]
fn a_failed_verify_pauses_the_torrent_and_a_passed_one_clears_drift() {
    use std::sync::Arc;

    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::StateMap;
    use torrentd_pool::AdoptionState;

    let dir = tempfile::tempdir().unwrap();
    let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
    let pool = crate::pool_service::PoolService::open(&cfg)
        .unwrap()
        .unwrap();
    let engine = Arc::new(MockEngine::new());
    let source = torrentd_engine::ProfileSource::new(vec![(
        ProfileId::new("p"),
        engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
    )]);
    let state = StateMap::new();
    let hash = InfoHash([0x11; 20]);
    state.insert(hash, st(TorrentPhase::Incomplete, Some(SETTLE)));
    let ih = hash.to_hex();
    pool.with_store(|s| {
        s.upsert_torrent(
            &torrentd_pool::PoolTorrent {
                infohash: ih.clone(),
                infohash_v1: None,
                infohash_v2: None,
                name: "T".into(),
                total_size: 1,
                num_files: 1,
                source_path: dir.path().join("t.torrent"),
                fastresume_path: None,
                declared_save_path: None,
                category: None,
                tags: vec![],
                profile: None,
            },
            0,
        )
    })
    .unwrap();

    let profiles = crate::profile_registry::ProfileRegistry::new(vec![]);
    super::worker::record_verify_outcome(
        &pool,
        super::worker::Writer::Wait,
        &source,
        &state,
        &profiles,
        &hash,
        &ih,
        VerifyOutcome::Failed("bad"),
    );
    assert!(engine
        .calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::PauseTorrent(_))));
    // The pause is saved at once, not left for the 30-minute sweep.
    assert_eq!(
        state.dispatch_resume_saves(10),
        vec![(hash, torrentd_engine::ResumeFlags::empty())],
    );
    let (got, drift) = pool
        .with_store(|s| {
            Ok::<_, torrentd_pool::PoolError>((s.adoption_state(&ih)?, s.drift_at(&ih)?))
        })
        .unwrap();
    assert_eq!(got, Some(AdoptionState::Drifted));
    assert!(drift.is_some());

    super::worker::record_verify_outcome(
        &pool,
        super::worker::Writer::Wait,
        &source,
        &state,
        &profiles,
        &hash,
        &ih,
        VerifyOutcome::Verified,
    );
    let (got, drift) = pool
        .with_store(|s| {
            Ok::<_, torrentd_pool::PoolError>((s.adoption_state(&ih)?, s.drift_at(&ih)?))
        })
        .unwrap();
    assert_eq!(got, Some(AdoptionState::Adopted));
    assert_eq!(drift, None);
}

/// A failed verification leaves the torrent out of every paced resume in
/// its profile before pausing it, as the operator's pause does: a lift
/// still running does not resume it, a kill-switch fence that takes the
/// run back does not record it, and a gate opened before the failure,
/// as a kill-switch fence opens one, refuses it to that fence's lift.
/// Set offline instead, the profile holds the rest of the run for the
/// next set-online, and not it.
#[test]
fn a_failed_verify_leaves_the_torrent_out_of_every_paced_resume() {
    use std::collections::HashSet;
    use std::sync::Arc;

    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::StateMap;

    use crate::profile_registry::test_host_entry;
    use crate::profile_registry::Gated;
    use crate::profile_registry::NoTorrents;
    use crate::profile_registry::ProfileRegistry;
    use crate::profile_state::DesiredState;

    let failed = TorrentHandle {
        id: 1,
        infohash: InfoHash([0x11; 20]),
    };
    let other = TorrentHandle {
        id: 2,
        infohash: InfoHash([0x22; 20]),
    };
    let id = ProfileId::new("p");
    let verify = |profiles: &ProfileRegistry| {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = crate::pool_service::PoolService::open(&cfg)
            .unwrap()
            .unwrap();
        let engine = Arc::new(MockEngine::new());
        let source = torrentd_engine::ProfileSource::new(vec![(
            id.clone(),
            engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
        )]);
        let state = StateMap::new();
        state.insert(failed.infohash, st(TorrentPhase::Incomplete, Some(SETTLE)));
        super::worker::record_verify_outcome(
            &pool,
            super::worker::Writer::Wait,
            &source,
            &state,
            profiles,
            &failed.infohash,
            &failed.infohash.to_hex(),
            VerifyOutcome::Failed("bad"),
        );
        assert!(engine
            .calls()
            .iter()
            .any(|c| matches!(c, RecordedCall::PauseTorrent(h) if *h == failed)));
    };

    // A lift run open, and a fence's gate standing.
    let profiles = ProfileRegistry::new(vec![test_host_entry("p")]);
    let entry = profiles.resolve(&id).active().unwrap();
    let fence_gate = entry.open_gate();
    let run = entry.begin_resume(vec![failed, other]);
    verify(&profiles);
    assert_eq!(run.gate().resume(failed, || ()), Err(Gated::Excluded));
    assert_eq!(fence_gate.resume(failed, || ()), Err(Gated::Excluded));
    assert_eq!(fence_gate.resume(other, || ()), Ok(()));
    assert_eq!(entry.take_resume(), Some(vec![other]));

    // A lift run open, then a set-offline: what it holds for the next
    // set-online is the rest of the run.
    let profiles = ProfileRegistry::new(vec![test_host_entry("p")]);
    let entry = profiles.resolve(&id).active().unwrap();
    let run = entry.begin_resume(vec![failed, other]);
    verify(&profiles);
    profiles
        .change_states(
            |rec| rec.set(&id, DesiredState::Offline),
            &crate::metrics_sink::PromSink::new(),
            &NoTorrents,
        )
        .unwrap();
    assert!(run.cancelled());
    assert_eq!(
        profiles.holds().held(&id),
        HashSet::from([other.infohash]),
        "the failed torrent is not held to be resumed",
    );
}

/// Issue #410: a kill-switch fence that lands after a failed
/// verification's pause, before a state update reports it, reads the
/// torrent as paused, as it reads the operator's pause, so its lift
/// leaves it paused and resumes only the rest. Where the engine refused
/// the pause the torrent still runs, and the lift resumes it with the
/// rest.
#[tokio::test(start_paused = true)]
async fn a_kill_switch_lift_just_after_a_failed_verify_leaves_the_torrent_paused() {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    use torrentd_engine::MockEngine;
    use torrentd_engine::RecordedCall;
    use torrentd_engine::StateMap;

    use crate::fence::KillSwitchFence;
    use crate::profile_registry::ProfileEntry;
    use crate::profile_registry::ProfileRegistry;
    use crate::vpn::killswitch::Fence;
    use crate::vpn::route::RouteProbe;
    use crate::vpn_monitor::TunnelProbes;

    let failed = TorrentHandle {
        id: 1,
        infohash: InfoHash([0x11; 20]),
    };
    let other = TorrentHandle {
        id: 2,
        infohash: InfoHash([0x22; 20]),
    };
    let bound = Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
    let loaded = |state: &StateMap, h: TorrentHandle, phase: TorrentPhase| {
        let mut s = TorrentState::newly_added(h, ProfileId::new("p"), Instant::now());
        s.phase = phase;
        state.insert(h.infohash, s);
    };
    // Verifies `failed` to a failure, then fences the profile, lets the
    // fence's pauses reach the state map, and lifts it with the tunnel
    // healthy: what the lift resumed.
    let fence_after_failed_verify = |refuse_pause: bool| async move {
        let id = ProfileId::new("p");
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::minimal_for_tests(dir.path(), false);
        let pool = crate::pool_service::PoolService::open(&cfg)
            .unwrap()
            .unwrap();
        let engine = Arc::new(MockEngine::new());
        let entry = ProfileEntry::new(
            crate::profile_registry::test_vpn_entry("p", ProfileStatus::Active).config,
            engine.clone(),
            bound,
            None,
            0,
        );
        let profiles = Arc::new(ProfileRegistry::new(vec![entry]));
        let source = torrentd_engine::ProfileSource::new(vec![(
            id.clone(),
            engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
        )]);
        let state = Arc::new(StateMap::new());
        for h in [failed, other] {
            loaded(&state, h, TorrentPhase::Seeding);
        }
        let fence = KillSwitchFence::new(
            profiles.clone(),
            state.clone(),
            Arc::new(crate::metrics_sink::PromSink::new()),
            Arc::new(move |_, _| TunnelProbes {
                ip: Ok(bound),
                route: Some(Ok(RouteProbe::ViaTunnel)),
                handshake: Some(Ok(None)),
            }),
        );
        if refuse_pause {
            engine.inject_error("pause_torrent", torrentd_engine::EngineError::Shutdown);
        }
        super::worker::record_verify_outcome(
            &pool,
            super::worker::Writer::Wait,
            &source,
            &state,
            &profiles,
            &failed.infohash,
            &failed.infohash.to_hex(),
            VerifyOutcome::Failed("bad"),
        );
        // No state update since: the state map still reads it seeding.
        fence.fence_all();
        for h in [failed, other] {
            loaded(&state, h, TorrentPhase::Paused);
        }
        fence.lift();
        for _ in 0..100_000 {
            if !profiles.iter().any(|e| e.is_resuming()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!profiles.iter().any(|e| e.is_resuming()), "the lift ends");
        let mut resumed: Vec<u64> = engine
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                RecordedCall::ResumeTorrent(h) => Some(h.id),
                _ => None,
            })
            .collect();
        resumed.sort_unstable();
        resumed
    };

    assert_eq!(
        fence_after_failed_verify(false).await,
        [other.id],
        "the failed torrent stays paused",
    );
    assert_eq!(
        fence_after_failed_verify(true).await,
        [failed.id, other.id],
        "a refused pause left it running, and the lift resumes it",
    );
}
