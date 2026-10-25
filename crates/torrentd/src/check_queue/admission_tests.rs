//! Admission: the shared limit, the turn every kind of check takes, and what
//! holds or drops a waiting check.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use torrentd_engine::InfoHash;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentHandle;
use torrentd_engine::TorrentPhase;
use torrentd_engine::TorrentState;

use super::tests::SETTLE;
use crate::pool_service::tests::owner_of;
use crate::pool_service::tests::padded_past_the_cap;
use crate::pool_service::tests::pending;
use crate::pool_service::tests::pool_with;
use crate::profile_registry::ProfileStatus;

/// What the verify worker needs besides the pool: a session for `p`, a
/// registry with `p` live and `down` fenced, and the state map.
struct Worker {
    engine: std::sync::Arc<torrentd_engine::MockEngine>,
    source: std::sync::Arc<dyn torrentd_engine::AlertSource>,
    state: torrentd_engine::StateMap,
    metrics: std::sync::Arc<crate::metrics_sink::PromSink>,
    profiles: std::sync::Arc<crate::profile_registry::ProfileRegistry>,
    registry: std::sync::Arc<crate::registry::AssignmentRegistry>,
}

impl Worker {
    fn new(dir: &std::path::Path) -> Self {
        use std::sync::Arc;

        use crate::profile_registry::test_entry;

        let engine = Arc::new(torrentd_engine::MockEngine::new());
        Self {
            source: Arc::new(torrentd_engine::ProfileSource::new(vec![(
                ProfileId::new("p"),
                engine.clone() as Arc<dyn torrentd_engine::TorrentEngine>,
            )])),
            engine,
            state: torrentd_engine::StateMap::new(),
            metrics: Arc::new(crate::metrics_sink::PromSink::new()),
            profiles: Arc::new(crate::profile_registry::ProfileRegistry::new(vec![
                test_entry("p", ProfileStatus::Active),
                test_entry("down", ProfileStatus::VpnDown),
            ])),
            registry: Arc::new(crate::registry::AssignmentRegistry::new_empty(
                dir.join("reg.json"),
            )),
        }
    }

    /// Load `ih` into `profile`'s session in `phase`.
    fn load(&self, ih: InfoHash, id: u64, profile: &str, phase: TorrentPhase) {
        let mut st = TorrentState::newly_added(
            TorrentHandle { id, infohash: ih },
            ProfileId::new(profile),
            Instant::now(),
        );
        st.phase = phase;
        self.state.insert(ih, st);
    }

    /// One verify tick's slot accounting and admission.
    fn tick(&self, pool: &crate::pool_service::PoolService) {
        super::worker::retire_checking(pool.verify_queue(), &self.state, super::RECHECK_EXPIRY);
        let store = pool.lock_writer();
        super::worker::admit(
            pool.verify_queue(),
            Some((pool, &store)),
            &self.source,
            &self.state,
            &self.metrics,
            &self.profiles,
            &self.registry,
        );
    }

    /// Every torrent the session was asked to re-hash, in order.
    fn rechecked(&self) -> Vec<InfoHash> {
        self.engine
            .calls()
            .iter()
            .filter_map(|c| match c {
                torrentd_engine::RecordedCall::ForceRecheck(h) => Some(h.infohash),
                _ => None,
            })
            .collect()
    }

    /// The session reports `ih`'s check over, as `torrent_checked` does.
    fn finish_check(&self, ih: InfoHash) {
        // After the re-hash's start mark, on any clock resolution.
        std::thread::sleep(Duration::from_millis(2));
        let mut st = self.state.get(&ih).unwrap();
        st.checked_at = Some(Instant::now());
        self.state.insert(ih, st);
    }
}

/// A one-file `.torrent` named `name`, written to `dir`, and the info-hash
/// its session keys it by, which admission holds the queued item to.
fn library_torrent(dir: &std::path::Path, name: &str) -> (std::path::PathBuf, InfoHash) {
    let mut t = format!(
        "d4:infod6:lengthi1e4:name{}:{name}12:piece lengthi16384e6:pieces20:",
        name.len()
    )
    .into_bytes();
    t.extend_from_slice(&[0u8; 20]);
    t.extend_from_slice(b"ee");
    let path = dir.join(format!("{name}.torrent"));
    std::fs::write(&path, &t).unwrap();
    (path, libtorrent_safe::info_hash_from_torrent(&t).unwrap())
}

/// `POST /v1/pool/verifications` naming 50 torrents with
/// `max_concurrent_verify = 4` never has more than 4 checking at once,
/// counting an adoption's verification against the same limit, and
/// `in_flight()` - `pool_verify_in_flight` - counts the re-hashes. Before
/// the re-hashes went through the queue, all 50 started at once.
#[test]
fn rechecks_share_the_verify_limit_with_adoptions() {
    use std::collections::HashSet;

    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let hashes: Vec<InfoHash> = (0..50u8)
        .map(|i| {
            let mut b = [0xC0; 20];
            b[19] = i;
            InfoHash(b)
        })
        .collect();
    for (i, ih) in hashes.iter().enumerate() {
        w.load(*ih, i as u64 + 1, "p", TorrentPhase::Seeding);
        pool.verify_queue().enqueue_recheck(ih.to_hex(), false);
    }
    // Asked for twice, queued once.
    pool.verify_queue()
        .enqueue_recheck(hashes[0].to_hex(), false);
    assert_eq!(pool.verify_queue().depth(), 50);
    // An adoption verifying holds one of the four slots.
    pool.verify_queue().track_in_flight("ab".repeat(20));
    let mut adoptions = 1;

    let mut finished = HashSet::new();
    let mut peaks = [0usize; 2];
    for tick in 0..200 {
        if tick == 10 {
            pool.verify_queue().forget_in_flight();
            adoptions = 0;
        }
        w.tick(&pool);
        let started = w.rechecked();
        let checking = started.iter().filter(|h| !finished.contains(*h)).count();
        assert!(
            checking + adoptions <= 4,
            "tick {tick}: {checking} re-hashes and {adoptions} adoptions in flight",
        );
        assert_eq!(pool.verify_queue().in_flight(), checking + adoptions);
        assert_eq!(pool.verify_queue().depth(), 50 - started.len());
        peaks[adoptions] = peaks[adoptions].max(checking);
        if started.len() == 50 && checking == 0 {
            break;
        }
        // The session finishes the oldest check still running.
        if let Some(ih) = started.iter().find(|h| !finished.contains(*h)) {
            w.finish_check(*ih);
            finished.insert(*ih);
        }
    }
    let started = w.rechecked();
    assert_eq!(started, hashes, "every torrent re-hashed once, in order");
    assert_eq!(finished.len(), 50);
    // The limit is reached, not merely respected: 4 slots, less the
    // adoption's while it held one.
    assert_eq!(peaks, [4, 3]);
    assert_eq!(pool.verify_queue().in_flight(), 0);
}

/// The worker checks a waiting re-hash again when it starts it: one
/// whose profile is fenced is held, and one no longer loaded, paused, or
/// without metadata is dropped, none of them taking a slot. One paused
/// while it checks keeps its slot until the check ends, and its verdict
/// is waited for.
#[test]
fn a_rechecks_admission_holds_or_drops_what_libtorrent_would_not_hash() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let [fenced, gone, paused, magnet, ok] =
        [0xD1, 0xD2, 0xD3, 0xD4, 0xD5].map(|b| InfoHash([b; 20]));
    w.load(fenced, 1, "down", TorrentPhase::Seeding);
    w.load(paused, 3, "p", TorrentPhase::Paused);
    w.load(magnet, 4, "p", TorrentPhase::AwaitingMetadata);
    w.load(ok, 5, "p", TorrentPhase::Seeding);
    let q = pool.verify_queue();
    for ih in [fenced, gone, paused, magnet, ok] {
        q.enqueue_recheck(ih.to_hex(), true);
    }

    w.tick(&pool);
    assert_eq!(w.rechecked(), [ok]);
    assert_eq!(q.in_flight(), 1);
    assert_eq!(q.depth(), 1, "the fenced profile's re-hash waits");
    assert!(q.tracks_recheck(&fenced.to_hex()));
    for dropped in [gone, paused, magnet] {
        assert!(!q.tracks_recheck(&dropped.to_hex()));
    }
    for reason in ["not_loaded", "paused", "no_metadata"] {
        assert_eq!(rechecks_dropped(&w, reason), 1, "{reason}: counted");
    }
    // Still fenced on the next tick: held again, not started.
    w.tick(&pool);
    assert_eq!(w.rechecked(), [ok]);
    assert_eq!(q.depth(), 1);

    // Paused mid-check: libtorrent goes on with the check once the
    // torrent is resumed, so the slot stays taken until it ends.
    let mut st = w.state.get(&ok).unwrap();
    st.phase = TorrentPhase::Paused;
    w.state.insert(ok, st);
    w.tick(&pool);
    assert_eq!(q.in_flight(), 1, "a paused check keeps its slot");
    // Resumed, and the check it went on with ends: the slot is free, and
    // the verdict awaited.
    let mut st = w.state.get(&ok).unwrap();
    st.phase = TorrentPhase::Seeding;
    w.state.insert(ok, st);
    w.finish_check(ok);
    w.tick(&pool);
    assert_eq!(q.in_flight(), 0);
    assert!(q.tracks_recheck(&ok.to_hex()));
}

/// A re-hash whose check fails on a disk error frees its slot at once,
/// whether the `file_error` (`DiskError` with the error) or the status
/// update after it (`Paused` with the error) is what the tick reads: the
/// check ended with no `torrent_checked`, and held, the slot would stay
/// taken for a day. A recorded re-hash's verdict is still waited for, and
/// the slots go to the re-hashes behind them.
#[test]
fn a_rehash_whose_check_fails_on_a_disk_error_frees_its_slot() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(2));
    let w = Worker::new(dir.path());
    let [disk_error, error_paused, next_a, next_b] =
        [0xE1, 0xE2, 0xE3, 0xE4].map(|b| InfoHash([b; 20]));
    for (i, ih) in [disk_error, error_paused, next_a, next_b]
        .into_iter()
        .enumerate()
    {
        w.load(ih, i as u64 + 1, "p", TorrentPhase::Seeding);
    }
    let q = pool.verify_queue();
    q.enqueue_recheck(disk_error.to_hex(), true);
    q.enqueue_recheck(error_paused.to_hex(), false);
    q.enqueue_recheck(next_a.to_hex(), false);
    q.enqueue_recheck(next_b.to_hex(), false);

    w.tick(&pool);
    assert_eq!(w.rechecked(), [disk_error, error_paused]);
    assert_eq!(q.in_flight(), 2);

    for (ih, phase) in [
        (disk_error, TorrentPhase::DiskError),
        (error_paused, TorrentPhase::Paused),
    ] {
        let mut st = w.state.get(&ih).unwrap();
        st.phase = phase;
        st.has_error = true;
        w.state.insert(ih, st);
    }
    w.tick(&pool);
    assert_eq!(
        w.rechecked(),
        [disk_error, error_paused, next_a, next_b],
        "the error-paused checks' slots went to the re-hashes behind them",
    );
    assert_eq!(q.in_flight(), 2);
    assert!(
        q.tracks_recheck(&disk_error.to_hex()),
        "a recorded re-hash still waits for its verdict",
    );
    assert!(!q.tracks_recheck(&error_paused.to_hex()));
}

/// A re-hash whose torrent a paced set-online holds paused until its
/// batch waits for it rather than being dropped as paused, and starts
/// once the pace has resumed and released the torrent.
#[test]
fn a_rehash_waits_while_a_paced_set_online_holds_its_torrent() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let held = InfoHash([0xD6; 20]);
    let id = ProfileId::new("p");
    w.load(held, 1, "p", TorrentPhase::Paused);
    w.profiles.holds().hold(&id, [held]).unwrap();
    let q = pool.verify_queue();
    q.enqueue_recheck(held.to_hex(), true);

    w.tick(&pool);
    assert!(w.rechecked().is_empty());
    assert_eq!(q.depth(), 1, "held by the pace: it waits");
    assert!(q.tracks_recheck(&held.to_hex()));

    // Its batch comes: resumed, then released.
    let mut st = w.state.get(&held).unwrap();
    st.phase = TorrentPhase::Seeding;
    w.state.insert(held, st);
    w.profiles.holds().release(&id, [held]).unwrap();
    w.tick(&pool);
    assert_eq!(w.rechecked(), [held]);
}

/// Right after a set-online the held torrent's phase still reads as
/// running: the session's pause never set its own flag, and the state
/// update reporting it paused has not come yet. Its re-hash waits all the
/// same, rather than starting on a torrent the pace has just paused.
#[test]
fn a_rehash_waits_for_a_held_torrent_whose_phase_still_reads_running() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let held = InfoHash([0xD7; 20]);
    let id = ProfileId::new("p");
    w.load(held, 1, "p", TorrentPhase::Seeding);
    w.profiles.holds().hold(&id, [held]).unwrap();
    let q = pool.verify_queue();
    q.enqueue_recheck(held.to_hex(), true);

    let mut logged = std::collections::HashSet::new();
    assert_eq!(
        super::worker::admit_recheck(
            q,
            &*w.source,
            &w.state,
            &*w.metrics,
            &w.profiles,
            &mut logged
        ),
        super::worker::Admission::Skipped,
    );
    assert!(logged.contains(&id), "the hold was logged");
    assert!(w.rechecked().is_empty(), "no check started");
    assert_eq!(q.depth(), 1, "held by the pace: it waits");
    assert_eq!(q.in_flight(), 0, "and holds no slot");
}

/// How many re-hashes the queue dropped for `reason`, as `/metrics`
/// renders it.
fn rechecks_dropped(w: &Worker, reason: &str) -> u64 {
    let text = String::from_utf8(w.metrics.render()).unwrap();
    let series = format!("torrentd_pool_recheck_dropped_total{{reason=\"{reason}\"}} ");
    text.lines()
        .find_map(|l| l.strip_prefix(&series))
        .map_or(0, |v| v.parse().unwrap())
}

/// The kill-switch watch lifts its fence: it records the lift's run with
/// `begin_resume`, marks the profile active, and the run resumes the
/// torrents a batch at a time (`KillSwitchFence::lift`). A
/// re-hash that reaches a torrent the run has not resumed yet waits for
/// it rather than being dropped as paused, and starts once it is resumed.
#[test]
fn a_rehash_waits_while_a_kill_switch_lift_has_not_resumed_its_torrent() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let id = ProfileId::new("p");
    let ih = InfoHash([0xE1; 20]);
    w.load(ih, 1, "p", TorrentPhase::Paused);
    let entry = w.profiles.resolve(&id).active().unwrap();
    let run = entry.begin_resume(vec![w.state.get(&ih).unwrap().handle]);
    let q = pool.verify_queue();
    q.enqueue_recheck(ih.to_hex(), true);

    w.tick(&pool);
    assert!(w.rechecked().is_empty(), "no check on a paused torrent");
    assert_eq!(q.depth(), 1, "the lift has yet to resume it: it waits");
    assert!(q.tracks_recheck(&ih.to_hex()));
    assert_eq!(rechecks_dropped(&w, "paused"), 0);

    // Its batch comes, and the run ends.
    let mut st = w.state.get(&ih).unwrap();
    st.phase = TorrentPhase::Seeding;
    w.state.insert(ih, st.clone());
    entry.end_resume(&run, &[st.handle]);
    w.tick(&pool);
    assert_eq!(w.rechecked(), [ih]);
}

/// The operator sets a fenced profile online: the fence is lifted and
/// every torrent in the profile is resumed by a paced run, as
/// `lift_fence` does. A re-hash held while the profile was fenced is
/// still held between the lift and the run reaching its torrent, then
/// starts.
#[test]
fn a_rehash_waits_while_a_set_online_lift_has_not_resumed_its_torrent() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let id = ProfileId::new("p");
    let entry = w.profiles.resolve(&id).active().unwrap();
    entry.update_health(|h| h.status = ProfileStatus::VpnDown);
    let ih = InfoHash([0xE2; 20]);
    w.load(ih, 1, "p", TorrentPhase::Paused);
    let q = pool.verify_queue();
    q.enqueue_recheck(ih.to_hex(), true);

    w.tick(&pool);
    assert_eq!(q.depth(), 1, "fenced: it waits");

    // Set online: the run is recorded, then the profile marked active,
    // then its torrents resumed a batch at a time. A tick between the
    // two steps finds it still fenced.
    let run = entry.begin_resume(w.state.handles_for_profile(&id));
    w.tick(&pool);
    assert_eq!(q.depth(), 1, "run recorded, still fenced: it waits");
    entry.update_health(|h| h.status = ProfileStatus::Active);
    w.tick(&pool);
    assert!(w.rechecked().is_empty());
    assert_eq!(q.depth(), 1, "the lift has yet to resume it: it waits");
    assert_eq!(rechecks_dropped(&w, "paused"), 0);

    let mut st = w.state.get(&ih).unwrap();
    st.phase = TorrentPhase::Seeding;
    w.state.insert(ih, st.clone());
    entry.end_resume(&run, &[st.handle]);
    w.tick(&pool);
    assert_eq!(w.rechecked(), [ih]);
}

/// A torrent the operator pauses while a lift's run goes is left out of
/// the run, so it is paused for good: its re-hash is dropped, and the
/// drop is counted. The rest of the run's torrents still wait.
#[test]
fn a_rehash_of_a_torrent_paused_out_of_a_lift_is_dropped_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let id = ProfileId::new("p");
    let (paused, waiting) = (InfoHash([0xE3; 20]), InfoHash([0xE4; 20]));
    w.load(paused, 1, "p", TorrentPhase::Paused);
    w.load(waiting, 2, "p", TorrentPhase::Paused);
    let entry = w.profiles.resolve(&id).active().unwrap();
    let _run = entry.begin_resume(w.state.handles_for_profile(&id));
    entry.exclude_from_resumes(w.state.get(&paused).unwrap().handle);
    let q = pool.verify_queue();
    for ih in [paused, waiting] {
        q.enqueue_recheck(ih.to_hex(), true);
    }

    w.tick(&pool);
    assert!(w.rechecked().is_empty());
    assert!(!q.tracks_recheck(&paused.to_hex()), "the operator's pause");
    assert!(q.tracks_recheck(&waiting.to_hex()), "the lift's to resume");
    assert_eq!(q.depth(), 1);
    assert_eq!(rechecks_dropped(&w, "paused"), 1);
}

/// A re-hash paused while it checks holds its slot, so with
/// `max_concurrent_verify = 1` the next waits for it: a pause and resume
/// cannot put a second check beside it.
#[test]
fn a_rehash_paused_mid_check_keeps_its_slot() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(1));
    let w = Worker::new(dir.path());
    let [first, second] = [0xE1, 0xE2].map(|b| InfoHash([b; 20]));
    w.load(first, 1, "p", TorrentPhase::Seeding);
    w.load(second, 2, "p", TorrentPhase::Seeding);
    let q = pool.verify_queue();
    q.enqueue_recheck(first.to_hex(), false);
    q.enqueue_recheck(second.to_hex(), false);

    w.tick(&pool);
    assert_eq!(w.rechecked(), [first]);
    let mut st = w.state.get(&first).unwrap();
    st.phase = TorrentPhase::Paused;
    w.state.insert(first, st);
    for _ in 0..3 {
        w.tick(&pool);
    }
    assert_eq!(
        w.rechecked(),
        [first],
        "the second waits for the paused check"
    );
    assert_eq!((q.in_flight(), q.depth()), (1, 1));

    w.finish_check(first);
    w.tick(&pool);
    assert_eq!(w.rechecked(), [first, second]);
    assert_eq!((q.in_flight(), q.depth()), (1, 0));
}

/// Issue #383: a slot taken outside the queue's own admission, as the
/// disk-error retry takes one, counts against the same limit: none is
/// handed out past it, or while an admission pass holds the queue, and
/// one whose check never started is given back. A check not known to
/// start frees its slot once the torrent shows none running.
#[test]
fn a_disk_error_retry_takes_a_slot_in_the_shared_limit() {
    use super::CheckSource::DiskErrorRetry;

    let q = super::VerifyQueue::new(2);
    let (a, b, c) = (InfoHash([1; 20]), InfoHash([2; 20]), InfoHash([3; 20]));
    assert!(q.try_take(a, DiskErrorRetry));
    assert!(q.try_take(a, DiskErrorRetry), "one torrent holds one slot");
    assert!(q.try_take(b, DiskErrorRetry));
    assert_eq!(q.in_flight(), 2);
    assert!(!q.try_take(c, DiskErrorRetry), "past the limit");
    q.release_slot(&a);
    {
        let _admitting = q.admit_lock.lock();
        assert!(
            !q.try_take(c, DiskErrorRetry),
            "never waits on an admission"
        );
    }
    assert!(q.try_take(c, DiskErrorRetry));
    assert_eq!(q.in_flight(), 2);

    // `b` resumed with no check (its error was not a check's), `c` is
    // checking: past the settle, `b` alone frees its slot.
    let state = torrentd_engine::StateMap::new();
    for (ih, phase) in [(b, TorrentPhase::Seeding), (c, TorrentPhase::Checking)] {
        let mut st = TorrentState::newly_added(
            TorrentHandle {
                id: 1,
                infohash: ih,
            },
            ProfileId::new("p"),
            Instant::now(),
        );
        st.phase = phase;
        state.insert(ih, st);
    }
    super::worker::retire_checking(&q, &state, super::RECHECK_EXPIRY);
    assert_eq!(q.in_flight(), 2, "not before the settle");
    assert_eq!(
        q.age_checks(super::CHECK_SETTLE),
        [DiskErrorRetry, DiskErrorRetry]
    );
    super::worker::retire_checking(&q, &state, super::RECHECK_EXPIRY);
    assert_eq!(q.in_flight(), 1);
    assert!(q.try_take(a, DiskErrorRetry));
}

/// The disk-error retry takes its slot on an error-paused torrent and
/// resumes it, and the queue's next tick, before any status update has
/// cleared the error, still reads it error-paused. That is the error the
/// retry is clearing, not its check failing: the slot stays taken, so the
/// check `clear_error` starts runs inside the limit. Past the settle a
/// torrent still error-paused frees it.
#[test]
fn a_disk_error_retry_keeps_its_slot_while_the_torrent_still_reads_error_paused() {
    use super::CheckSource::DiskErrorRetry;

    let q = super::VerifyQueue::new(1);
    let ih = InfoHash([4; 20]);
    let state = torrentd_engine::StateMap::new();
    let mut st = TorrentState::newly_added(
        TorrentHandle {
            id: 1,
            infohash: ih,
        },
        ProfileId::new("p"),
        Instant::now(),
    );
    st.phase = TorrentPhase::Paused;
    st.has_error = true;
    state.insert(ih, st);

    assert!(q.try_take(ih, DiskErrorRetry));
    super::worker::retire_checking(&q, &state, super::RECHECK_EXPIRY);
    assert_eq!(
        q.in_flight(),
        1,
        "the retry's resume has not been reported yet"
    );
    assert!(!q.try_take(InfoHash([5; 20]), DiskErrorRetry));

    assert_eq!(q.age_checks(super::CHECK_SETTLE), [DiskErrorRetry]);
    super::worker::retire_checking(&q, &state, super::RECHECK_EXPIRY);
    assert_eq!(q.in_flight(), 0, "still error-paused past the settle");
}

/// A started re-hash whose torrent is removed frees its slot with no
/// verdict left to await, and one whose check never reports its end
/// frees it once the expiry passes, and not before.
#[test]
fn a_rehash_frees_its_slot_when_removed_or_expired() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let [removed, silent] = [0xF1, 0xF2].map(|b| InfoHash([b; 20]));
    w.load(removed, 1, "p", TorrentPhase::Seeding);
    w.load(silent, 2, "p", TorrentPhase::Seeding);
    let q = pool.verify_queue();
    q.enqueue_recheck(removed.to_hex(), true);
    q.enqueue_recheck(silent.to_hex(), true);
    w.tick(&pool);
    assert_eq!(w.rechecked(), [removed, silent]);
    assert_eq!(q.in_flight(), 2);

    w.state.remove(&removed, &ProfileId::new("p"), None);
    super::worker::retire_checking(q, &w.state, super::RECHECK_EXPIRY);
    assert_eq!(q.in_flight(), 1, "the removed torrent's slot is free");
    assert!(
        !q.tracks_recheck(&removed.to_hex()),
        "nothing left to record"
    );

    // Inside the expiry, the silent check keeps its slot.
    super::worker::retire_checking(q, &w.state, Duration::from_secs(3600));
    assert_eq!(q.in_flight(), 1);
    // Past it, the slot is freed and the re-hash forgotten.
    std::thread::sleep(Duration::from_millis(2));
    super::worker::retire_checking(q, &w.state, Duration::from_millis(1));
    assert_eq!(q.in_flight(), 0);
    assert!(!q.tracks_recheck(&silent.to_hex()));
}

/// With adoptions and re-hashes both waiting, the worker admits them in
/// turn, so neither backlog starves the other: each free slot goes to
/// the other kind than the last one admitted.
#[test]
fn adoptions_and_rehashes_waiting_together_are_admitted_in_turn() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();
    for name in ["a", "b", "c"] {
        let (path, ih) = library_torrent(dir.path(), name);
        q.enqueue(super::PendingVerify {
            torrent_path: path,
            save_path: dir.path().to_path_buf(),
            ..pending(ih, "p")
        });
    }
    let rehashes = [0xB0, 0xB1, 0xB2].map(|b| InfoHash([b; 20]));
    for (i, ih) in rehashes.iter().enumerate() {
        w.load(*ih, i as u64 + 1, "p", TorrentPhase::Seeding);
        q.enqueue_recheck(ih.to_hex(), false);
    }
    let order = || {
        w.engine
            .calls()
            .iter()
            .filter_map(|c| match c {
                torrentd_engine::RecordedCall::AddTorrent(_) => Some('A'),
                torrentd_engine::RecordedCall::ForceRecheck(_) => Some('R'),
                _ => None,
            })
            .collect::<String>()
    };

    w.tick(&pool);
    assert_eq!(order(), "ARAR", "the four slots split between the kinds");
    assert_eq!((q.in_flight(), q.depth()), (4, 2));

    // Every slot frees: the rest go in turn too.
    q.forget_in_flight();
    for ih in &rehashes[..2] {
        w.finish_check(*ih);
    }
    w.tick(&pool);
    assert_eq!(order(), "ARARAR");
    assert_eq!(q.depth(), 0);
}

/// Issue #454: a scan holds the pool index's writer for its whole run,
/// and the verify tick used to wait on it to record a verdict or admit
/// an adoption, stalling every re-hash and held add the daemon starts
/// until the scan committed. With the writer held, a tick now returns at
/// once having started the waiting re-hash, leaving the adoption queued
/// and the finished one in flight; the tick after the writer is free
/// records the verdict and admits the adoption.
#[test]
fn a_verify_tick_does_not_wait_on_a_scan_holding_the_writer() {
    use std::sync::mpsc;

    use torrentd_engine::RecordedCall;
    use torrentd_pool::AdoptionState;

    let dir = tempfile::tempdir().unwrap();
    let checked = InfoHash([0xE0; 20]);
    let mut pool = pool_with(dir.path(), checked, Some("p"));
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();

    // An adoption whose check has failed, its verdict to record.
    q.track_in_flight(checked.to_hex());
    w.load(checked, 1, "p", TorrentPhase::Incomplete);
    let mut done = w.state.get(&checked).unwrap();
    done.checked_at = Some(Instant::now() - SETTLE);
    w.state.insert(checked, done);
    // A re-hash waiting for a slot.
    let rehash = InfoHash([0xE1; 20]);
    w.load(rehash, 2, "p", TorrentPhase::Seeding);
    q.enqueue_recheck(rehash.to_hex(), false);
    // An adoption waiting for a slot.
    let (path, waiting) = library_torrent(dir.path(), "w");
    q.enqueue(super::PendingVerify {
        torrent_path: path,
        save_path: dir.path().to_path_buf(),
        ..pending(waiting, "p")
    });
    let calls = || w.engine.calls();
    let tick = || {
        super::worker::verify_tick(
            q,
            Some(&pool),
            &w.source,
            &w.state,
            &w.metrics,
            &w.profiles,
            &w.registry,
        );
    };

    std::thread::scope(|s| {
        // A scan holds the writer until told to stop.
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let pool = &pool;
        let holder = s.spawn(move || {
            let _store = pool.hold_writer_for_tests();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        held_rx.recv().unwrap();
        let (ticked_tx, ticked_rx) = mpsc::channel();
        let ticker = s.spawn(move || {
            tick();
            let _ = ticked_tx.send(());
        });
        let ticked = ticked_rx.recv_timeout(Duration::from_secs(5));
        // What the tick did while the writer was held, read before it is
        // released.
        let during = calls();
        let in_flight = q.in_flight();
        let depth = q.depth();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        ticker.join().unwrap();
        assert!(ticked.is_ok(), "the tick waited on the writer");
        assert!(
            during
                .iter()
                .any(|c| matches!(c, RecordedCall::ForceRecheck(h) if h.infohash == rehash)),
            "the re-hash starts while the writer is held: {during:?}",
        );
        assert!(
            !during.iter().any(|c| matches!(
                c,
                RecordedCall::AddTorrent(_) | RecordedCall::PauseTorrent(_)
            )),
            "no adoption is admitted and no verdict recorded: {during:?}",
        );
        // The finished adoption and the re-hash hold slots; the waiting
        // adoption is still queued.
        assert_eq!((in_flight, depth), (2, 1));
    });
    assert_eq!(
        pool.with_store(|s| s.adoption_state(&checked.to_hex()).unwrap()),
        None,
        "nothing recorded yet",
    );

    // The writer free: the verdict lands and the adoption starts.
    tick();
    assert_eq!(
        pool.with_store(|s| s.adoption_state(&checked.to_hex()).unwrap()),
        Some(AdoptionState::Drifted),
    );
    assert!(calls()
        .iter()
        .any(|c| matches!(c, RecordedCall::AddTorrent(_))));
    assert_eq!(q.depth(), 0);
}

/// Issue #454: an adoption at the head of the queue whose profile is
/// fenced is held at the back, and the adoptions behind it, into a
/// profile still on the network, are admitted the same tick rather than
/// wait for the fence to lift.
#[test]
fn a_fenced_adoption_at_the_head_does_not_hold_back_the_ones_behind_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();
    let mut fenced = None;
    for (i, profile) in ["down", "p", "p"].into_iter().enumerate() {
        let (path, ih) = library_torrent(dir.path(), &i.to_string());
        fenced.get_or_insert(ih);
        q.enqueue(super::PendingVerify {
            torrent_path: path,
            save_path: dir.path().to_path_buf(),
            ..pending(ih, profile)
        });
    }
    let adds = || {
        w.engine
            .calls()
            .iter()
            .filter(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_)))
            .count()
    };

    w.tick(&pool);
    assert_eq!(adds(), 2, "both adoptions into `p` start");
    assert_eq!((q.in_flight(), q.depth()), (2, 1));
    let held: Vec<String> = q
        .pending
        .lock()
        .iter()
        .map(|v| v.infohash.clone())
        .collect();
    assert_eq!(
        held,
        [fenced.unwrap().to_hex()],
        "the fenced one waits, queued once"
    );

    // Still fenced on the next tick: held again, and nothing else added.
    w.tick(&pool);
    assert_eq!(adds(), 2);
    assert_eq!(q.depth(), 1);
}

/// Adoptions held for a fenced profile log the hold once per profile per
/// tick, not once per adoption, while each stays queued and none is
/// added to a session.
#[test]
fn adoptions_held_for_a_fenced_profile_log_once_per_tick() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();
    for i in 0..20u8 {
        q.enqueue(pending(InfoHash([0xE0 + i; 20]), "down"));
    }
    let store = pool.lock_writer();
    let mut logged = std::collections::HashSet::new();
    for _ in 0..20 {
        assert_eq!(
            super::worker::admit_adoption(
                &pool,
                &store,
                &w.source,
                &w.metrics,
                &w.profiles,
                &w.registry,
                &mut logged,
            ),
            super::worker::Admission::Skipped,
        );
    }
    assert_eq!(
        logged.into_iter().collect::<Vec<_>>(),
        [ProfileId::new("down")],
        "one profile, logged once",
    );
    assert_eq!(q.depth(), 20, "every held adoption stays queued");
    assert!(!w
        .engine
        .calls()
        .iter()
        .any(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_))));
}

/// Issue #543: an adoption whose `.torrent` has grown past the library
/// read cap since it was queued is not read whole: it is dropped as a
/// failed verify, as an unreadable one is, and nothing is added.
#[test]
fn an_adoption_whose_torrent_is_past_the_cap_is_dropped_unread() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();
    let mut t = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi16384e6:pieces20:".to_vec();
    t.extend_from_slice(&[0u8; 20]);
    t.extend_from_slice(b"ee");
    let path = dir.path().join("big.torrent");
    std::fs::write(&path, padded_past_the_cap(&t)).unwrap();
    q.enqueue(super::PendingVerify {
        torrent_path: path,
        save_path: dir.path().to_path_buf(),
        ..pending(InfoHash([0xD3; 20]), "p")
    });

    w.tick(&pool);
    assert!(!w
        .engine
        .calls()
        .iter()
        .any(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_))));
    assert_eq!((q.failed(), q.depth(), q.in_flight()), (1, 0, 0));
}

/// Issue #612: an adoption whose library `.torrent` was replaced by another
/// torrent's after it was queued is dropped at admission as a failed verify,
/// its registry claim released. Before, the other torrent was added under
/// this one's claim and persisted as its `.torrent`.
#[test]
fn an_adoption_whose_library_torrent_was_replaced_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (path, queued) = library_torrent(dir.path(), "a");
    let mut pool = pool_with(dir.path(), queued, None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    w.registry.assign(queued, ProfileId::new("p")).unwrap();
    let q = pool.verify_queue();
    q.enqueue(super::PendingVerify {
        torrent_path: path.clone(),
        save_path: dir.path().to_path_buf(),
        ..pending(queued, "p")
    });
    // The library file now holds another torrent.
    let (other_path, other) = library_torrent(dir.path(), "b");
    assert_ne!(other, queued);
    std::fs::rename(other_path, &path).unwrap();

    w.tick(&pool);
    assert!(!w
        .engine
        .calls()
        .iter()
        .any(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_))));
    assert_eq!((q.failed(), q.depth(), q.in_flight()), (1, 0, 0));
    assert_eq!(w.registry.lookup(&queued), None, "the claim is released");
}

/// Issue #651: a boot whose persisted adoption queue names a profile with no
/// session holds that profile's items, row, owner record and registry claim
/// intact, and admits them once the profile has an engine. Before, each was
/// dropped as though its profile were gone. An item whose profile no
/// `[[profile]]` declares any more is still dropped.
#[test]
fn a_boot_holds_the_queued_adoptions_of_a_profile_without_a_session() {
    use crate::profile_registry::test_entry;
    use crate::profile_registry::test_failed_profile;
    use crate::profile_registry::ProfileRegistry;

    let dir = tempfile::tempdir().unwrap();
    let w = Worker::new(dir.path());
    let torrents: Vec<_> = [("a", "p"), ("b", "f"), ("c", "gone")]
        .into_iter()
        .map(|(name, profile)| {
            let (path, ih) = library_torrent(dir.path(), name);
            (path, ih, profile)
        })
        .collect();
    let mut pool = pool_with(dir.path(), torrents[0].1, None);
    // The run before the restart: every profile up, each adoption claimed,
    // recorded as its profile's, and queued in `pool.db`.
    let before = ProfileRegistry::new(
        ["p", "f", "gone"]
            .into_iter()
            .map(|id| test_entry(id, ProfileStatus::Active))
            .collect(),
    );
    for (path, ih, profile) in &torrents {
        pool.with_store(|s| {
            s.upsert_torrent(
                &torrentd_pool::PoolTorrent {
                    infohash: ih.to_hex(),
                    infohash_v1: None,
                    infohash_v2: None,
                    name: "t".into(),
                    total_size: 1,
                    num_files: 1,
                    source_path: path.clone(),
                    fastresume_path: None,
                    declared_save_path: None,
                    category: None,
                    tags: vec![],
                    profile: None,
                },
                0,
            )
            .unwrap();
        });
        w.registry.assign(*ih, ProfileId::new(*profile)).unwrap();
        crate::pool_service::enqueue_verify(
            &pool,
            &before,
            &ih.to_hex(),
            path.clone(),
            dir.path().to_path_buf(),
            None,
            ProfileId::new(*profile),
            false,
        )
        .unwrap();
    }
    // The restart: the in-memory queue is gone, `p` is up but its session
    // not yet reachable, `f`'s tunnel failed, and `gone` left the config.
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let ihs: Vec<InfoHash> = torrents.iter().map(|t| t.1).collect();
    assert_eq!(
        pool.restore_verify_queue(&w.registry, &Default::default()),
        ihs
    );
    let booted = Arc::new(
        ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)])
            .with_failed(vec![test_failed_profile("f", "tunnel failed")]),
    );
    let no_engine: Arc<dyn torrentd_engine::AlertSource> =
        Arc::new(torrentd_engine::ProfileSource::new(Vec::new()));
    let tick = |source: &Arc<dyn torrentd_engine::AlertSource>| {
        let store = pool.lock_writer();
        super::worker::admit(
            pool.verify_queue(),
            Some((&pool, &store)),
            source,
            &w.state,
            &w.metrics,
            &booted,
            &w.registry,
        );
    };
    let adds = || {
        w.engine
            .calls()
            .iter()
            .filter(|c| matches!(c, torrentd_engine::RecordedCall::AddTorrent(_)))
            .count()
    };
    let rows = || -> Vec<String> {
        pool.with_store(|s| s.verify_queue().unwrap())
            .into_iter()
            .map(|r| r.infohash)
            .collect()
    };
    let intact = |ih: InfoHash, profile: &str| {
        assert!(rows().contains(&ih.to_hex()), "{profile}'s row stays");
        assert_eq!(owner_of(&pool, ih).as_deref(), Some(profile));
        assert_eq!(w.registry.lookup(&ih), Some(ProfileId::new(profile)));
    };

    for _ in 0..2 {
        tick(&no_engine);
        assert_eq!(adds(), 0);
        assert_eq!(pool.verify_queue().depth(), 2, "`p` and `f` wait");
        intact(ihs[0], "p");
        intact(ihs[1], "f");
    }
    // The undeclared profile's item went the first tick, with its records.
    assert!(!rows().contains(&ihs[2].to_hex()));
    assert_eq!(owner_of(&pool, ihs[2]), None);
    assert_eq!(w.registry.lookup(&ihs[2]), None);

    // `p`'s engine appears: its adoption is admitted, and `f`'s still waits.
    tick(&w.source);
    assert_eq!(adds(), 1);
    assert_eq!(pool.verify_queue().in_flight(), 1);
    assert_eq!(pool.verify_queue().depth(), 1);
    intact(ihs[1], "f");
}

/// Re-hashes held for a fenced profile log the hold once per profile per
/// tick, not once per re-hash, while each stays queued.
#[test]
fn rehashes_held_for_a_fenced_profile_log_once_per_tick() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();
    for i in 0..20u8 {
        let ih = InfoHash([0x90 + i; 20]);
        w.load(ih, u64::from(i) + 1, "down", TorrentPhase::Seeding);
        q.enqueue_recheck(ih.to_hex(), false);
    }
    let mut logged = std::collections::HashSet::new();
    for _ in 0..20 {
        assert_eq!(
            super::worker::admit_recheck(
                q,
                &*w.source,
                &w.state,
                &*w.metrics,
                &w.profiles,
                &mut logged
            ),
            super::worker::Admission::Skipped,
        );
    }
    assert_eq!(logged.len(), 1, "one profile, logged once");
    assert_eq!(q.depth(), 20, "every held re-hash stays queued");
    assert!(w.rechecked().is_empty());
}

/// A re-hash of a torrent in `DiskError` marks it `Checking` before
/// libtorrent is asked to check it, so a check that fails before any
/// status update is recorded as the error-and-pause it is rather than as
/// a failed peer read.
#[test]
fn a_rehash_marks_a_disk_error_torrent_checking_before_it_starts() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();
    let ih = InfoHash([0xC0; 20]);
    w.load(ih, 1, "p", TorrentPhase::DiskError);
    q.enqueue_recheck(ih.to_hex(), false);

    let held = w.engine.hold_next("force_recheck");
    let admitted = std::thread::scope(|s| {
        let admit = s.spawn(|| {
            let mut logged = std::collections::HashSet::new();
            super::worker::admit_recheck(
                q,
                &*w.source,
                &w.state,
                &*w.metrics,
                &w.profiles,
                &mut logged,
            )
        });
        held.wait_entered();
        assert_eq!(
            w.state.get(&ih).unwrap().phase,
            TorrentPhase::Checking,
            "marked while libtorrent is still being asked",
        );
        held.release();
        admit.join().unwrap()
    });
    assert_eq!(admitted, super::worker::Admission::Admitted);
    assert_eq!(w.state.get(&ih).unwrap().phase, TorrentPhase::Checking);
    assert_eq!(w.rechecked(), [ih]);
}

/// A re-hash that fails to start takes the `Checking` mark back: no check
/// runs, and the torrent is still in `DiskError`.
#[test]
fn a_rehash_that_fails_to_start_leaves_disk_error_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = pool_with(dir.path(), InfoHash([0x01; 20]), None);
    pool.verify = Arc::new(super::VerifyQueue::new(4));
    let w = Worker::new(dir.path());
    let q = pool.verify_queue();
    let ih = InfoHash([0xC1; 20]);
    w.load(ih, 1, "p", TorrentPhase::DiskError);
    q.enqueue_recheck(ih.to_hex(), false);
    w.engine
        .inject_error("force_recheck", torrentd_engine::EngineError::Shutdown);

    let mut logged = std::collections::HashSet::new();
    assert_eq!(
        super::worker::admit_recheck(
            q,
            &*w.source,
            &w.state,
            &*w.metrics,
            &w.profiles,
            &mut logged
        ),
        super::worker::Admission::Skipped,
    );
    assert_eq!(w.state.get(&ih).unwrap().phase, TorrentPhase::DiskError);
    assert_eq!(q.in_flight(), 0);
}
