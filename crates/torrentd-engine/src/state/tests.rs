use super::*;

fn ih(byte: u8) -> InfoHash {
    InfoHash([byte; 20])
}
fn handle(id: u64, byte: u8) -> TorrentHandle {
    TorrentHandle {
        id,
        infohash: ih(byte),
    }
}

#[test]
fn retries_due_returns_only_expired() {
    let m = StateMap::new();
    let now = Instant::now();
    let h1 = handle(1, 1);
    let h2 = handle(2, 2);
    let mut s1 = TorrentState::newly_added(h1, ProfileId::new("p"), now);
    s1.retry = Some(RetryState {
        next_attempt: now - Duration::from_secs(1),
        attempts: 1,
    });
    let mut s2 = TorrentState::newly_added(h2, ProfileId::new("p"), now);
    s2.retry = Some(RetryState {
        next_attempt: now + Duration::from_secs(60),
        attempts: 1,
    });
    m.insert(s1.handle.infohash, s1);
    m.insert(s2.handle.infohash, s2);
    let due = m.retries_due(now);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0], h1);
}

#[test]
fn a_settle_for_a_torrent_nobody_asked_about_changes_nothing() {
    // The global counter this replaced was decremented by any settle, so
    // a stray one for torrent B released the drain while torrent A's save
    // was still outstanding.
    let m = StateMap::new();
    assert!(m.queue_resume_save(ih(1), ResumeFlags::empty()));
    assert_eq!(m.dispatch_resume_saves(10).len(), 1);
    assert!(!m.note_resume_settled(&ih(2)));
    assert_eq!(m.pending_resume_count(), 1);
    assert!(m.note_resume_settled(&ih(1)));
    assert_eq!(m.pending_resume_count(), 0);
}

#[test]
fn one_torrent_is_asked_for_once_however_often_it_is_queued() {
    let m = StateMap::new();
    assert!(m.queue_resume_save(ih(1), ResumeFlags::empty()));
    assert!(!m.queue_resume_save(ih(1), ResumeFlags::empty()));
    assert_eq!(m.dispatch_resume_saves(10).len(), 1);
    // In flight counts as asked for, too.
    assert!(!m.queue_resume_save(ih(1), ResumeFlags::empty()));
    assert_eq!(m.pending_resume_count(), 1);
}

#[test]
fn a_later_only_if_modified_request_keeps_a_queued_unconditional_save() {
    // The shutdown drain asks `ONLY_IF_MODIFIED` for every torrent; one
    // still waiting on its first save has no file for "not modified" to
    // leave in place.
    let m = StateMap::new();
    assert!(m.queue_resume_save(ih(1), ResumeFlags::empty()));
    assert!(!m.queue_resume_save(ih(1), ResumeFlags::ONLY_IF_MODIFIED));
    assert_eq!(
        m.dispatch_resume_saves(10),
        vec![(ih(1), ResumeFlags::empty())]
    );
}

#[test]
fn a_save_now_is_unconditional_and_raises_a_queued_sweep_save() {
    let m = StateMap::new();
    m.queue_resume_save_now(ih(1));
    assert!(m.queue_resume_save(ih(2), ResumeFlags::ONLY_IF_MODIFIED));
    m.queue_resume_save_now(ih(2));
    assert_eq!(
        m.dispatch_resume_saves(10),
        vec![(ih(1), ResumeFlags::empty()), (ih(2), ResumeFlags::empty())],
        "one request each, both unconditional",
    );
}

#[test]
fn a_save_now_during_an_in_flight_save_asks_once_more_when_it_settles() {
    // The answer on its way may have been taken before the change.
    let m = StateMap::new();
    assert!(m.queue_resume_save(ih(1), ResumeFlags::ONLY_IF_MODIFIED));
    assert_eq!(m.dispatch_resume_saves(10).len(), 1);
    m.queue_resume_save_now(ih(1));
    m.queue_resume_save_now(ih(1));
    assert_eq!(m.dispatch_resume_saves(10), vec![], "not doubled in flight");
    assert!(m.note_resume_settled(&ih(1)));
    assert_eq!(m.pending_resume_count(), 1);
    assert_eq!(
        m.dispatch_resume_saves(10),
        vec![(ih(1), ResumeFlags::empty())]
    );
    assert!(m.note_resume_settled(&ih(1)));
    assert_eq!(m.pending_resume_count(), 0, "asked again once, not forever");
}

#[test]
fn a_lost_save_that_changed_in_flight_is_asked_for_unconditionally() {
    let m = StateMap::new();
    assert!(m.queue_resume_save(ih(1), ResumeFlags::ONLY_IF_MODIFIED));
    m.dispatch_resume_saves(10);
    m.queue_resume_save_now(ih(1));
    assert_eq!(
        m.requeue_in_flight_resume_saves(&ProfileId::new("p"), ResumeFlags::ONLY_IF_MODIFIED),
        1
    );
    assert_eq!(
        m.dispatch_resume_saves(10),
        vec![(ih(1), ResumeFlags::empty())]
    );
    assert!(m.note_resume_settled(&ih(1)));
    assert_eq!(
        m.pending_resume_count(),
        0,
        "the re-ask answered the change"
    );
}

#[test]
fn dispatch_never_puts_more_than_the_cap_in_flight() {
    let m = StateMap::new();
    for b in 0..10 {
        m.queue_resume_save(ih(b), ResumeFlags::empty());
    }
    assert_eq!(m.dispatch_resume_saves(4).len(), 4);
    assert_eq!(
        m.dispatch_resume_saves(4).len(),
        0,
        "the cap is already full"
    );
    m.note_resume_settled(&ih(0));
    m.note_resume_settled(&ih(1));
    assert_eq!(
        m.dispatch_resume_saves(4).len(),
        2,
        "topped up as saves settle"
    );
    assert_eq!(m.resume_saves_in_flight(), 4);
    assert_eq!(m.pending_resume_count(), 8);
}

#[test]
fn lost_saves_are_asked_for_again_first_with_the_new_flags() {
    let m = StateMap::new();
    for b in 0..3 {
        m.queue_resume_save(ih(b), ResumeFlags::ONLY_IF_MODIFIED);
    }
    m.dispatch_resume_saves(2);
    assert_eq!(
        m.requeue_in_flight_resume_saves(&ProfileId::new("p"), ResumeFlags::empty()),
        2
    );
    assert_eq!(m.resume_saves_in_flight(), 0);
    assert_eq!(m.pending_resume_count(), 3);
    let again = m.dispatch_resume_saves(2);
    let mut got: Vec<u8> = again.iter().map(|(h, _)| h.0[0]).collect();
    got.sort();
    assert_eq!(got, vec![0, 1], "the lost ones go ahead of the queue");
    assert!(again.iter().all(|(_, f)| f.is_empty()));
}

#[test]
fn an_overflow_requeues_only_the_saves_in_flight_to_its_own_profile() {
    let m = StateMap::new();
    let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
    let now = Instant::now();
    // 1 and 2 are p's, 3 is q's, 4 is no longer tracked by anyone.
    assert!(m.track_added(handle(1, 1), &p, true, now));
    assert!(m.track_added(handle(2, 2), &p, true, now));
    assert!(m.track_added(handle(3, 3), &q, true, now));
    for b in 1..=4 {
        m.queue_resume_save(ih(b), ResumeFlags::ONLY_IF_MODIFIED);
    }
    assert_eq!(m.dispatch_resume_saves(10).len(), 4);
    assert_eq!(
        m.requeue_in_flight_resume_saves(&p, ResumeFlags::empty()),
        3
    );
    assert_eq!(m.resume_saves_in_flight(), 1, "q's answer is still owed");
    let mut again: Vec<u8> = m
        .dispatch_resume_saves(10)
        .into_iter()
        .map(|(h, _)| h.0[0])
        .collect();
    again.sort();
    assert_eq!(again, vec![1, 2, 4]);
    // q's own answer settles its save, once.
    assert!(m.note_resume_settled(&ih(3)));
    assert!(!m.note_resume_settled(&ih(3)));
}

/// One removal and one add leave the length as it was; the generation
/// moves on each, and not on a call that changes nothing.
#[test]
fn the_generation_moves_on_every_entry_change_and_only_then() {
    let m = StateMap::new();
    let now = Instant::now();
    let p = ProfileId::new("p");
    let (a, b) = (handle(1, 1), handle(2, 2));
    let g0 = m.generation();
    m.insert(a.infohash, TorrentState::newly_added(a, p.clone(), now));
    let g1 = m.generation();
    assert!(g1 > g0);
    assert!(!m.track_added(a, &p, true, now), "already tracked");
    assert!(m.remove(&a.infohash, &ProfileId::new("q"), None).is_none());
    assert!(m.remove(&b.infohash, &p, None).is_none());
    m.update(&a.infohash, |s| s.retry = None);
    assert_eq!(m.generation(), g1, "a no-op moved the generation");

    assert!(m.remove(&a.infohash, &p, Some(a)).is_some());
    assert!(m.track_added(b, &p, true, now));
    assert_eq!(m.len(), 1);
    assert_eq!(m.generation(), g1 + 2, "a swap left the generation");
    // The same info-hash under another handle is another torrent.
    assert!(m.track_added(handle(3, 2), &p, true, now));
    assert_eq!(m.generation(), g1 + 3);
}

/// Before its first state update, a torrent reads as what its add
/// implies: a magnet as fetching its metadata, one with metadata as
/// checking. Never `Idle`, which says it has been checked.
#[test]
fn a_tracked_add_starts_in_the_phase_its_metadata_implies() {
    let m = StateMap::new();
    let now = Instant::now();
    let p = ProfileId::new("p");
    let (magnet, file) = (handle(1, 1), handle(2, 2));
    assert!(m.track_added(magnet, &p, false, now));
    assert!(m.track_added(file, &p, true, now));
    assert_eq!(
        m.get(&magnet.infohash).unwrap().phase,
        TorrentPhase::AwaitingMetadata
    );
    assert_eq!(m.get(&file.infohash).unwrap().phase, TorrentPhase::Checking);

    // A second report of the same torrent keeps what the entry gathered.
    m.update(&file.infohash, |s| s.phase = TorrentPhase::Seeding);
    assert!(!m.track_added(file, &p, false, now));
    assert_eq!(m.get(&file.infohash).unwrap().phase, TorrentPhase::Seeding);
    assert!(m.tracks(file, &p));
    assert!(!m.tracks(file, &ProfileId::new("q")));
    assert!(
        !m.tracks(handle(3, 2), &p),
        "another torrent under the info-hash"
    );
}

#[test]
fn a_rearmed_retry_fires_at_its_new_deadline_only() {
    let m = StateMap::new();
    let now = Instant::now();
    let h = handle(1, 1);
    let mut s = TorrentState::newly_added(h, ProfileId::new("p"), now);
    s.retry = Some(RetryState {
        next_attempt: now,
        attempts: 1,
    });
    m.insert(h.infohash, s);
    // Re-armed further out before it came due: the old entry is stale.
    m.update(&h.infohash, |s| {
        s.retry = Some(RetryState {
            next_attempt: now + Duration::from_secs(60),
            attempts: 2,
        })
    });
    assert!(m.retries_due(now).is_empty(), "the stale deadline fired");
    assert_eq!(
        m.retries_due(now + Duration::from_secs(60)),
        vec![h],
        "the live deadline did not"
    );
    assert_eq!(m.retry_schedule_len(), 0, "popped entries are gone");
}

#[test]
fn a_retired_or_removed_retry_never_fires() {
    let m = StateMap::new();
    let now = Instant::now();
    for (id, b) in [(1, 1u8), (2, 2)] {
        let h = handle(id, b);
        let mut s = TorrentState::newly_added(h, ProfileId::new("p"), now);
        s.retry = Some(RetryState::first(now));
        m.insert(h.infohash, s);
    }
    m.update(&ih(1), |s| s.retry = None);
    assert!(m.remove(&ih(2), &ProfileId::new("p"), None).is_some());
    assert!(m.retries_due(now + RetryState::MAX_DELAY).is_empty());
}

#[test]
fn a_remove_leaves_an_entry_another_profile_or_torrent_holds() {
    let m = StateMap::new();
    let now = Instant::now();
    let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
    let old = handle(1, 1);
    let new = handle(2, 1);
    m.insert(ih(1), TorrentState::newly_added(new, q.clone(), now));
    assert!(m.remove(&ih(1), &p, None).is_none(), "q's entry, not p's");
    assert!(
        m.remove(&ih(1), &q, Some(old)).is_none(),
        "not that torrent"
    );
    assert_eq!(m.get(&ih(1)).map(|s| s.handle), Some(new));
    assert!(m.remove(&ih(1), &q, Some(new)).is_some());
    assert!(!m.contains(&ih(1)));
}

#[test]
fn a_removal_settles_with_whether_its_profile_added_the_infohash_again() {
    let m = StateMap::new();
    let now = Instant::now();
    let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
    let old = handle(1, 1);
    m.insert(ih(1), TorrentState::newly_added(old, p.clone(), now));
    m.begin_removal(&p, old);
    // Another profile's add is not this removal's re-add.
    m.note_readded(&q, &ih(1));
    let mut seen = None;
    let settled = m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(false));
    assert_eq!(
        settled,
        RemovalSettled {
            entry_released: true,
            readded: false,
        }
    );

    m.insert(ih(1), TorrentState::newly_added(old, p.clone(), now));
    m.begin_removal(&p, old);
    m.note_readded(&p, &ih(1));
    let settled = m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(true));
    assert!(settled.readded);
    // Consumed: a later removal of the re-added torrent deletes.
    m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(false));
}

#[test]
fn a_reconciled_removal_settles_only_a_recorded_torrent_and_keeps_its_record() {
    let m = StateMap::new();
    let now = Instant::now();
    let p = ProfileId::new("p");
    let (old, new) = (handle(1, 1), handle(2, 1));
    m.insert(ih(1), TorrentState::newly_added(old, p.clone(), now));
    // Nobody asked for its removal: left alone, nothing deleted.
    assert_eq!(m.reconcile_removal(&p, old, |_| panic!("deleted")), None);
    assert!(m.contains(&ih(1)));

    m.begin_removal(&p, old);
    // Not that torrent.
    assert_eq!(m.reconcile_removal(&p, new, |_| panic!("deleted")), None);
    let mut seen = None;
    let settled = m.reconcile_removal(&p, old, |readded| seen = Some(readded));
    assert_eq!(seen, Some(false));
    assert_eq!(
        settled,
        Some(RemovalSettled {
            entry_released: true,
            readded: false,
        })
    );
    assert!(!m.contains(&ih(1)));
    // Once settled, a second reconcile finds no entry and runs nothing.
    assert_eq!(m.reconcile_removal(&p, old, |_| panic!("deleted")), None);

    // The alert was only late: the profile re-added the info-hash, and
    // the alert then settles by the kept record, leaving the new entry
    // and its files.
    m.note_readded(&p, &ih(1));
    m.insert(ih(1), TorrentState::newly_added(new, p.clone(), now));
    let settled = m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(true));
    assert!(!settled.entry_released);
    assert_eq!(m.get(&ih(1)).map(|s| s.handle), Some(new));
}

#[test]
fn an_abandoned_removal_is_forgotten_once_every_request_for_it_was_refused() {
    let m = StateMap::new();
    let p = ProfileId::new("p");
    let old = handle(1, 1);
    let mut seen = None;

    m.begin_removal(&p, old);
    m.abandon_removal(&p, old);
    m.note_readded(&p, &ih(1));
    m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(false), "nothing pending to mark");

    m.begin_removal(&p, old);
    m.note_readded(&p, &ih(1));
    // A second request for the same torrent, refused, keeps the mark.
    m.begin_removal(&p, old);
    m.abandon_removal(&p, old);
    m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(true));

    // Two requests alongside each other: the first's is accepted, the
    // second's refused once the torrent is gone. The refusal leaves the
    // record the first's alert is owed, unmarked, for a re-add to mark.
    m.begin_removal(&p, old);
    m.begin_removal(&p, old);
    m.abandon_removal(&p, old);
    m.note_readded(&p, &ih(1));
    m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(true), "the accepted request's record survives");

    // Every request refused: no alert is owed, and the record goes.
    m.begin_removal(&p, old);
    m.begin_removal(&p, old);
    m.abandon_removal(&p, old);
    m.abandon_removal(&p, old);
    m.note_readded(&p, &ih(1));
    m.settle_removal(&p, &ih(1), |readded| seen = Some(readded));
    assert_eq!(seen, Some(false), "nothing pending to mark");
}

#[test]
fn an_update_that_leaves_the_retry_alone_schedules_nothing() {
    let m = StateMap::new();
    let now = Instant::now();
    let h = handle(1, 1);
    let mut s = TorrentState::newly_added(h, ProfileId::new("p"), now);
    s.retry = Some(RetryState::first(now));
    m.insert(h.infohash, s);
    for _ in 0..100 {
        m.update(&h.infohash, |s| s.num_peers += 1);
    }
    assert_eq!(m.retry_schedule_len(), 1);
}

#[test]
fn retry_backoff_doubles_to_cap() {
    assert_eq!(RetryState::delay_for_attempt(1), Duration::from_secs(60));
    assert_eq!(RetryState::delay_for_attempt(2), Duration::from_secs(120));
    assert_eq!(RetryState::delay_for_attempt(3), Duration::from_secs(240));
    assert_eq!(RetryState::delay_for_attempt(7), RetryState::MAX_DELAY);
    assert_eq!(RetryState::delay_for_attempt(20), RetryState::MAX_DELAY);
}
