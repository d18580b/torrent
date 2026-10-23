//! `AlertsDropped` handler: if libtorrent's alert queue overflowed, count
//! the overflow and log how many alert types were lost. Indicates the alert
//! loop is falling behind.
//!
//! When the lost types include the resume-data answers, every save in flight
//! to the profile's session is asked for again: libtorrent reports which
//! *types* it dropped and never which torrents, so any of them may be one
//! whose answer is gone, and a save nobody answers holds the shutdown drain
//! open until its deadline. Another profile's session has a queue of its own,
//! and its saves stay in flight.
//!
//! When they include `add_torrent_alert`, the session's torrents are compared
//! against the state map and every one it is missing is tracked, since the
//! map learns of a torrent from that alert.
//!
//! When they include `torrent_removed_alert`, every entry of the profile's
//! whose torrent the daemon asked to remove and the session no longer holds
//! is settled as that alert would have settled it, since only that alert
//! drops a torrent from the map. Its tombstone is left for that alert, which
//! may be only late, or for the next boot.
//!
//! When they include `state_update_alert`, every tracked torrent's status is
//! read from the session and folded into the state map, since libtorrent
//! never posts a paused or idle torrent's lost update again.

use std::collections::HashSet;

use libtorrent_safe::Alert;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::TorrentHandle;
use tracing::error;
use tracing::warn;

use crate::handlers::add;
use crate::handlers::state_update;
use crate::handlers::HandlerCtx;

/// `save_resume_data_alert::alert_type` and
/// `save_resume_data_failed_alert::alert_type` in libtorrent 2.0
/// (`include/libtorrent/alert_types.hpp`). The shim copies libtorrent's
/// `dropped_alerts` bitset bit for bit, so bit *n* of the pair is alert type
/// *n*.
///
/// The shim `static_assert`s each of these five numbers against libtorrent's
/// own `alert_type` (`shim_alerts.cpp`, beside the `alerts_dropped`
/// translation), so a libtorrent that renumbers one fails the build.
const SAVE_RESUME_DATA_TYPE: u32 = 37;
const SAVE_RESUME_DATA_FAILED_TYPE: u32 = 38;
/// `add_torrent_alert::alert_type` in libtorrent 2.0.
const ADD_TORRENT_TYPE: u32 = 67;
/// `torrent_removed_alert::alert_type` in libtorrent 2.0. Critical priority
/// only raises the queue limit it is held to, so it can be dropped too.
const TORRENT_REMOVED_TYPE: u32 = 4;
/// `state_update_alert::alert_type` in libtorrent 2.0.
const STATE_UPDATE_TYPE: u32 = 68;

/// Whether alert type `ty` is set in a `dropped_alerts` bitset.
fn dropped(bits: &[u64; 2], ty: u32) -> bool {
    let (word, bit) = ((ty / 64) as usize, ty % 64);
    bits.get(word).is_some_and(|w| w & (1u64 << bit) != 0)
}

pub fn handle(alert: &Alert, ctx: &mut HandlerCtx<'_>) {
    let Alert::AlertsDropped { bits, .. } = alert else {
        unreachable!("dropped::handle called with non-dropped alert");
    };
    let _enter = ctx.span.enter();
    let total = bits[0].count_ones() + bits[1].count_ones();
    warn!(
        target: "torrentd_engine::handler::dropped",
        bits_lo = bits[0],
        bits_hi = bits[1],
        kinds = total,
        "libtorrent alert queue overflowed; alerts dropped",
    );
    if dropped(bits, SAVE_RESUME_DATA_TYPE) || dropped(bits, SAVE_RESUME_DATA_FAILED_TYPE) {
        // Without `ONLY_IF_MODIFIED`: producing the lost answer cleared
        // libtorrent's modified bit, so asking conditionally would be told
        // "not modified" about data that was never written.
        let requeued = ctx
            .state
            .requeue_in_flight_resume_saves(&ctx.profile_id, ResumeFlags::empty());
        warn!(
            target: "torrentd_engine::handler::dropped",
            torrent_count = requeued,
            "resume-data answers were among the dropped alerts; asking again for every save in \
             flight to this profile's session",
        );
        // Under the profile whose queue overflowed, like every other counter
        // this loop emits: that is the session falling behind.
        ctx.metrics.add_counter(
            "resume_saves_requeued_total",
            requeued as u64,
            &[("profile_id", ctx.profile_id.as_str())],
        );
    }
    let (adds, removals) = (
        dropped(bits, ADD_TORRENT_TYPE),
        dropped(bits, TORRENT_REMOVED_TYPE),
    );
    if adds || removals {
        reconcile_session(ctx, adds, removals);
    }
    // After the adds: a torrent tracked from its lost add alert above was in
    // the same lost updates, so it is refreshed too.
    if dropped(bits, STATE_UPDATE_TYPE) {
        refresh_statuses(ctx);
    }
    // One per overflow. libtorrent reports *which alert types* it dropped, as
    // a bitset, and never how many alerts; this used to add the bitset's
    // popcount to `alerts_dropped_total`, which is a count of neither. The
    // number of overflow events is what the alert can honestly rest on, and
    // the series is named for that.
    ctx.metrics.inc_counter(
        "alert_queue_overflows_total",
        &[("profile_id", ctx.profile_id.as_str())],
    );
}

/// Read every torrent's status from the session and fold it into the state
/// map as a `state_update_alert` would, for an overflow that dropped one.
///
/// libtorrent posts a torrent in a `state_update_alert` only when its status
/// changed since the last post, and forgets the change once it has posted it
/// (`session_impl::post_torrent_updates`). A torrent that is transferring
/// changes every tick and recovers by itself; one that was paused, or seeds
/// with no peers, is never posted again, and its entry would keep the phase,
/// `needs_save_resume` and error state it had before the overflow until a
/// restart. Every torrent is refreshed, since libtorrent names the lost types
/// and never the torrents.
///
/// Only an entry this profile tracks under the same handle is refreshed: a
/// status of a torrent the map does not track, or tracks under another
/// handle, describes nothing the map holds.
fn refresh_statuses(ctx: &HandlerCtx<'_>) {
    let statuses = match ctx.engine.torrent_statuses() {
        Ok(statuses) => statuses,
        Err(e) => {
            error!(
                target: "torrentd_engine::handler::dropped",
                op = "torrent_statuses",
                error.cause = %e,
                "state updates were among the dropped alerts and the session's torrent statuses \
                 could not be read; paused or idle torrents keep the phase they had before the \
                 overflow until their status changes again",
            );
            return;
        }
    };
    let mut refreshed = 0u64;
    for s in &statuses {
        let tracked = ctx
            .state
            .get(&s.handle.infohash)
            .is_some_and(|st| st.handle == s.handle && st.profile_id == ctx.profile_id);
        if tracked {
            state_update::apply(s, ctx);
            refreshed += 1;
        }
    }
    warn!(
        target: "torrentd_engine::handler::dropped",
        torrent_count = refreshed,
        "state updates were among the dropped alerts; refreshed every tracked torrent's status \
         from the session",
    );
    // Under the profile whose queue overflowed, like the other counters here.
    ctx.metrics.add_counter(
        "statuses_refreshed_total",
        refreshed,
        &[("profile_id", ctx.profile_id.as_str())],
    );
}

/// Compare the session's torrents with the state map, for an overflow that
/// dropped `add_torrent_alert`s (`adds`) or `torrent_removed_alert`s
/// (`removals`). libtorrent names the lost types and never the torrents, so
/// the whole session is compared.
///
/// Removals first: an entry the session no longer holds is settled
/// ([`reconcile_removals`]) before a torrent re-added under its info-hash
/// takes the map's place for it, which would leave the removal unsettled.
///
/// A torrent enters the map from its add alert, so one whose alert was lost
/// would seed with nothing tracking it: no fence pauses it, no sweep or drain
/// saves it, and `DELETE` refuses it. Each torrent the session holds that the
/// map is missing gets what its alert would have given it (`add::track`). An
/// add alert that was not lost and is still queued finds its torrent tracked
/// and keeps the entry.
fn reconcile_session(ctx: &HandlerCtx<'_>, adds: bool, removals: bool) {
    // The profile's entries as they stood before the session was listed. A
    // torrent the boot scan adds meanwhile is in the session before it is in
    // the map, so an entry taken from a later look could be one the listing
    // missed, and would read as removed.
    let entries = if removals {
        ctx.state.handles_for_profile(&ctx.profile_id)
    } else {
        Vec::new()
    };
    let held = match ctx.engine.torrents() {
        Ok(held) => held,
        Err(e) => {
            error!(
                target: "torrentd_engine::handler::dropped",
                op = "torrents",
                error.cause = %e,
                adds,
                removals,
                "add-torrent or torrent-removed alerts were dropped and the session's torrents \
                 could not be listed; torrents whose add alert was lost stay untracked, and ones \
                 whose removal alert was lost stay in the state map",
            );
            return;
        }
    };
    if removals {
        reconcile_removals(ctx, entries, &held);
    }
    if !adds {
        return;
    }
    let mut recovered = 0u64;
    for h in held {
        // Only the missing: a tracked torrent's add was handled, or seeded by
        // the boot scan, and re-asking its save and hold for every torrent in
        // a 100K session would cost a store lookup each.
        if !ctx.state.tracks(h, &ctx.profile_id) && add::track(h, ctx) {
            recovered += 1;
        }
    }
    warn!(
        target: "torrentd_engine::handler::dropped",
        torrent_count = recovered,
        "add-torrent alerts were among the dropped alerts; tracked the session's torrents the \
         state map was missing",
    );
}

/// Settle every one of `entries`, the profile's state-map entries, that the
/// session no longer holds (`held`) and whose removal the daemon asked for,
/// as its lost `torrent_removed_alert` would have: drop the entry, delete
/// the stores' files a re-add does not own, and settle a resume save in
/// flight for it.
///
/// The tombstone `DELETE` left standing is kept, not settled. The session no
/// longer holding the torrent does not mean its alert was lost: it may be only
/// late, and a resume save libtorrent queued before the removal can still
/// write the resume file before it. Cleared here, a crash in that window, or
/// that alert lost to a second overflow, would leave a resume file with no
/// tombstone, and the next boot would load the torrent again. The alert, the
/// torrent's last, settles it where it comes, and the boot where it does not.
///
/// Without this a lost alert leaves the entry until a restart, and the
/// overlap guards of `DELETE ?delete_files=true` and of a pool delete plan,
/// which read the map, refuse every request on the host for a torrent they
/// cannot read from its session.
///
/// An entry the session no longer holds and whose removal nobody asked for
/// is left, and counted in the log: only `DELETE` removes a torrent from a
/// session, so it is not a lost removal, and deleting its files would be.
fn reconcile_removals(ctx: &HandlerCtx<'_>, entries: Vec<TorrentHandle>, held: &[TorrentHandle]) {
    let held: HashSet<_> = held.iter().copied().collect();
    let (mut settled, mut unrecorded) = (0u64, 0u64);
    for h in entries.into_iter().filter(|h| !held.contains(h)) {
        let outcome = ctx.state.reconcile_removal(&ctx.profile_id, h, |readded| {
            add::settle_removed_files(ctx, &h.infohash, readded, add::Tombstone::Keep);
        });
        match outcome {
            Some(s) => {
                // As the alert's handler does: a save in flight for the
                // removed torrent is never answered with its info-hash.
                if s.entry_released {
                    ctx.state.note_resume_settled(&h.infohash);
                }
                settled += 1;
            }
            // Its entry went meanwhile, or no removal of it was recorded.
            None if ctx.state.get(&h.infohash).is_some_and(|st| st.handle == h) => {
                unrecorded += 1;
            }
            None => {}
        }
    }
    warn!(
        target: "torrentd_engine::handler::dropped",
        torrent_count = settled,
        unrecorded_count = unrecorded,
        "torrent-removed alerts were among the dropped alerts; settled the removals of the \
         torrents the session no longer holds",
    );
    // Under the profile whose queue overflowed, like the other counters here.
    ctx.metrics.add_counter(
        "removals_reconciled_total",
        settled,
        &[("profile_id", ctx.profile_id.as_str())],
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use libtorrent_safe::InfoHash;

    use super::*;
    use crate::clock::MockClock;
    use crate::engine::EngineError;
    use crate::engine::TorrentEngine;
    use crate::metrics::RecordingSink;
    use crate::mock::MockEngine;
    use crate::profile::ProfileId;
    use crate::resume_store::MemoryResumeStore;
    use crate::resume_store::ResumeStore;
    use crate::state::StateMap;
    use crate::torrent_store::MemoryTorrentStore;
    use crate::torrent_store::TorrentStore;

    fn overflow(bits: [u64; 2]) -> Alert {
        Alert::AlertsDropped {
            hdr: AlertHeader {
                kind: AlertKind::AlertsDropped,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            bits,
        }
    }

    fn run(state: &StateMap, metrics: &RecordingSink, bits: [u64; 2]) {
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut ctx = HandlerCtx {
            state,
            resume: &resume,
            torrents: &torrents,
            metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        handle(&overflow(bits), &mut ctx);
    }

    fn in_flight(state: &StateMap, n: u8) {
        for b in 0..n {
            state.queue_resume_save(InfoHash([b; 20]), ResumeFlags::ONLY_IF_MODIFIED);
        }
        state.dispatch_resume_saves(usize::MAX);
    }

    #[test]
    fn a_dropped_resume_answer_puts_every_save_in_flight_back_on_the_queue() {
        for ty in [SAVE_RESUME_DATA_TYPE, SAVE_RESUME_DATA_FAILED_TYPE] {
            let state = StateMap::new();
            let metrics = RecordingSink::new();
            in_flight(&state, 3);
            run(&state, &metrics, [1u64 << ty, 0]);
            assert_eq!(state.resume_saves_in_flight(), 0, "type {ty}");
            assert_eq!(state.pending_resume_count(), 3, "none forgotten");
            // Asked again unconditionally: the lost answer cleared
            // libtorrent's modified bit.
            let again = state.dispatch_resume_saves(usize::MAX);
            assert!(again.iter().all(|(_, f)| f.is_empty()));
            // Counted, under the profile whose queue overflowed.
            let requeued: Vec<_> = metrics
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    crate::metrics::MetricCall::AddCounter {
                        name,
                        value,
                        labels,
                    } if name == "resume_saves_requeued_total" => Some((value, labels)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                requeued,
                vec![(3, vec![("profile_id".to_string(), "p".to_string())])],
                "type {ty}",
            );
        }
    }

    #[test]
    fn a_dropped_resume_answer_leaves_another_profiles_saves_in_flight() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let now = std::time::Instant::now();
        let (p, q) = (ProfileId::new("p"), ProfileId::new("q"));
        for (b, profile) in [(1u8, &p), (2, &q), (3, &q)] {
            let h = TorrentHandle {
                id: u64::from(b),
                infohash: InfoHash([b; 20]),
            };
            assert!(state.track_added(h, profile, true, now));
            state.queue_resume_save(h.infohash, ResumeFlags::ONLY_IF_MODIFIED);
        }
        state.dispatch_resume_saves(usize::MAX);
        // `run` handles the overflow in profile `p`.
        run(&state, &metrics, [1u64 << SAVE_RESUME_DATA_TYPE, 0]);
        assert_eq!(state.resume_saves_in_flight(), 2, "q's two are still owed");
        assert_eq!(
            state.dispatch_resume_saves(usize::MAX),
            vec![(InfoHash([1; 20]), ResumeFlags::empty())],
        );
        assert_eq!(metrics.count_for("resume_saves_requeued_total"), 1);
    }

    #[test]
    fn an_overflow_that_spared_the_resume_answers_leaves_saves_in_flight() {
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        in_flight(&state, 3);
        // Every other type set, both words.
        let mut bits = [u64::MAX, u64::MAX];
        bits[0] &= !(1u64 << SAVE_RESUME_DATA_TYPE);
        bits[0] &= !(1u64 << SAVE_RESUME_DATA_FAILED_TYPE);
        run(&state, &metrics, bits);
        assert_eq!(state.resume_saves_in_flight(), 3);
        assert_eq!(metrics.count_for("resume_saves_requeued_total"), 0);
    }

    /// Handle an overflow with `bits` against `engine`, in profile `p`.
    fn run_on(
        engine: Arc<dyn TorrentEngine>,
        state: &StateMap,
        metrics: &RecordingSink,
        bits: [u64; 2],
    ) {
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let clock = MockClock::new();
        let mut ctx = HandlerCtx {
            state,
            resume: &resume,
            torrents: &torrents,
            metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        handle(&overflow(bits), &mut ctx);
    }

    const ADD_DROPPED: [u64; 2] = [0, 1u64 << (ADD_TORRENT_TYPE - 64)];

    #[test]
    fn dropped_add_alerts_track_every_torrent_the_session_holds_and_the_map_lacks() {
        use crate::state::TorrentPhase;

        let mock = Arc::new(MockEngine::new());
        let (a, b, c) = (
            mock.register_handle(InfoHash([1; 20])),
            mock.register_handle(InfoHash([2; 20])),
            mock.register_handle(InfoHash([3; 20])),
        );
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let p = ProfileId::new("p");
        // `a`'s alert was handled, and its entry has moved on since.
        assert!(state.track_added(a, &p, true, std::time::Instant::now()));
        state.update(&a.infohash, |st| st.phase = TorrentPhase::Seeding);

        run_on(mock.clone(), &state, &metrics, ADD_DROPPED);

        for h in [a, b, c] {
            let st = state.get(&h.infohash).expect("tracked");
            assert_eq!((st.handle, &st.profile_id), (h, &p));
        }
        assert_eq!(state.get(&a.infohash).unwrap().phase, TorrentPhase::Seeding);
        assert_eq!(state.handles_for_profile(&p).len(), 3, "all fenceable");
        // The recovered ones get the first save their alert would have queued.
        let mut saved: Vec<_> = state
            .dispatch_resume_saves(usize::MAX)
            .into_iter()
            .map(|(ih, _)| ih)
            .collect();
        saved.sort_by_key(|ih| ih.0);
        assert_eq!(saved, vec![b.infohash, c.infohash]);
    }

    #[test]
    fn an_overflow_that_spared_the_add_alerts_does_not_list_the_session() {
        let mock = Arc::new(MockEngine::new());
        let h = mock.register_handle(InfoHash([4; 20]));
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let mut bits = [u64::MAX, u64::MAX];
        bits[1] &= !ADD_DROPPED[1];
        bits[0] &= !REMOVED_DROPPED[0];
        run_on(mock, &state, &metrics, bits);
        assert!(!state.contains(&h.infohash));
    }

    const REMOVED_DROPPED: [u64; 2] = [1u64 << TORRENT_REMOVED_TYPE, 0];

    /// Handle an overflow with `bits` against `engine`, in profile `p`, with
    /// the stores the caller reads afterwards.
    fn run_with(
        engine: Arc<dyn TorrentEngine>,
        state: &StateMap,
        resume: &MemoryResumeStore,
        torrents: &MemoryTorrentStore,
        metrics: &RecordingSink,
        bits: [u64; 2],
    ) {
        run_alert(engine, state, resume, torrents, metrics, &overflow(bits));
    }

    /// Handle `alert`, an overflow or an add-side alert, as [`run_with`] does.
    fn run_alert(
        engine: Arc<dyn TorrentEngine>,
        state: &StateMap,
        resume: &MemoryResumeStore,
        torrents: &MemoryTorrentStore,
        metrics: &RecordingSink,
        alert: &Alert,
    ) {
        let clock = MockClock::new();
        let mut ctx = HandlerCtx {
            state,
            resume,
            torrents,
            metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        match alert {
            Alert::AlertsDropped { .. } => handle(alert, &mut ctx),
            _ => add::handle(alert, &mut ctx),
        }
    }

    /// `p` tracks `ih`, holds its files and the tombstone `DELETE` leaves
    /// standing, and `DELETE` has removed it from the session.
    fn removed_by_delete(
        mock: &MockEngine,
        state: &StateMap,
        resume: &MemoryResumeStore,
        torrents: &MemoryTorrentStore,
        ih: InfoHash,
    ) -> TorrentHandle {
        let p = ProfileId::new("p");
        let h = mock.register_handle(ih);
        assert!(state.track_added(h, &p, true, std::time::Instant::now()));
        resume.write(&p, &ih, b"old-resume").unwrap();
        torrents.write(&p, &ih, b"old-torrent").unwrap();
        resume.write_tombstone(&p, &ih).unwrap();
        state.begin_removal(&p, h);
        mock.remove_torrent(h, false).unwrap();
        h
    }

    fn reconciled(metrics: &RecordingSink) -> Vec<(u64, Vec<(String, String)>)> {
        metrics
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                crate::metrics::MetricCall::AddCounter {
                    name,
                    value,
                    labels,
                } if name == "removals_reconciled_total" => Some((value, labels)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_dropped_removal_alert_is_settled_from_the_session() {
        let mock = Arc::new(MockEngine::new());
        let (state, resume, torrents) = (
            StateMap::new(),
            MemoryResumeStore::new(),
            MemoryTorrentStore::new(),
        );
        let metrics = RecordingSink::new();
        let p = ProfileId::new("p");
        let ih = InfoHash([6; 20]);
        // A save in flight when it went, which will never be answered with
        // its info-hash.
        state.queue_resume_save(ih, ResumeFlags::empty());
        state.dispatch_resume_saves(usize::MAX);
        removed_by_delete(&mock, &state, &resume, &torrents, ih);
        // Still held, and tracked: untouched.
        let kept = mock.register_handle(InfoHash([7; 20]));
        assert!(state.track_added(kept, &p, true, std::time::Instant::now()));

        run_with(
            mock.clone(),
            &state,
            &resume,
            &torrents,
            &metrics,
            REMOVED_DROPPED,
        );

        assert!(!state.contains(&ih), "the removed torrent's entry is gone");
        assert!(state.contains(&kept.infohash));
        assert!(resume.snapshot(&p).is_empty());
        assert!(torrents.load_all(&p).unwrap().is_empty());
        // Kept: the alert may be only late, with a resume save still to land
        // before it, and it or the next boot settles the tombstone.
        assert_eq!(resume.tombstones(&p).unwrap(), vec![ih], "kept");
        assert_eq!(state.resume_saves_in_flight(), 0);
        assert_eq!(
            reconciled(&metrics),
            vec![(1, vec![("profile_id".to_string(), "p".to_string())])],
        );
        // A second overflow finds nothing left to settle.
        run_with(
            mock.clone(),
            &state,
            &resume,
            &torrents,
            &metrics,
            REMOVED_DROPPED,
        );
        assert_eq!(metrics.count_for("removals_reconciled_total"), 1);

        // The alert was only late: a resume save queued before the removal
        // lands, and then the alert, the torrent's last, deletes what it
        // wrote and settles the tombstone.
        resume.write(&p, &ih, b"late-resume").unwrap();
        let removed = Alert::TorrentRemoved {
            hdr: AlertHeader {
                kind: AlertKind::TorrentRemoved,
                infohash: Some(ih),
                handle: None,
                timestamp_us: 0,
            },
        };
        run_alert(mock, &state, &resume, &torrents, &metrics, &removed);
        assert!(resume.snapshot(&p).is_empty());
        assert!(resume.tombstones(&p).unwrap().is_empty(), "settled");
        assert!(
            state.get(&kept.infohash).is_some(),
            "only the removed torrent"
        );
    }

    #[test]
    fn a_dropped_removal_alert_keeps_a_torrent_re_added_under_its_infohash() {
        let p = ProfileId::new("p");
        let ih = InfoHash([8; 20]);
        // The re-add's own add alert handled, or lost in the same overflow.
        for (bits, readd_tracked) in [
            (REMOVED_DROPPED, true),
            ([REMOVED_DROPPED[0], ADD_DROPPED[1]], false),
        ] {
            let mock = Arc::new(MockEngine::new());
            let (state, resume, torrents) = (
                StateMap::new(),
                MemoryResumeStore::new(),
                MemoryTorrentStore::new(),
            );
            let metrics = RecordingSink::new();
            let old = removed_by_delete(&mock, &state, &resume, &torrents, ih);
            // The same profile adds it again: a new handle, and its files.
            state.note_readded(&p, &ih);
            let new = mock.register_handle(ih);
            assert_ne!(new, old);
            torrents.write(&p, &ih, b"new-torrent").unwrap();
            if readd_tracked {
                assert!(state.track_added(new, &p, true, std::time::Instant::now()));
            }

            run_with(mock, &state, &resume, &torrents, &metrics, bits);

            let st = state.get(&ih).expect("the re-add's entry");
            assert_eq!((st.handle, &st.profile_id), (new, &p), "{bits:?}");
            assert_eq!(
                torrents.load_all(&p).unwrap(),
                vec![(ih, b"new-torrent".to_vec())],
                "{bits:?}",
            );
            // Settled only where the removed torrent's entry was still there.
            let settled = u64::from(!readd_tracked);
            assert_eq!(
                metrics.count_for("removals_reconciled_total"),
                settled,
                "{bits:?}",
            );
            // Left for the alert or the boot, which spends it on the re-add.
            assert_eq!(resume.tombstones(&p).unwrap(), vec![ih], "{bits:?}");
        }
    }

    #[test]
    fn an_entry_the_session_lost_without_a_recorded_removal_is_left() {
        let mock = Arc::new(MockEngine::new());
        let (state, resume, torrents) = (
            StateMap::new(),
            MemoryResumeStore::new(),
            MemoryTorrentStore::new(),
        );
        let metrics = RecordingSink::new();
        let p = ProfileId::new("p");
        let ih = InfoHash([9; 20]);
        let h = mock.register_handle(ih);
        assert!(state.track_added(h, &p, true, std::time::Instant::now()));
        torrents.write(&p, &ih, b"torrent").unwrap();
        mock.remove_torrent(h, false).unwrap();

        run_with(mock, &state, &resume, &torrents, &metrics, REMOVED_DROPPED);

        assert!(state.contains(&ih));
        assert_eq!(torrents.load_all(&p).unwrap().len(), 1);
        assert_eq!(metrics.count_for("removals_reconciled_total"), 0);
    }

    #[test]
    fn a_session_that_cannot_be_listed_leaves_the_map_as_it_was() {
        let mock = Arc::new(MockEngine::new());
        let h = mock.register_handle(InfoHash([5; 20]));
        mock.inject_error("torrents", EngineError::Shutdown);
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        run_on(mock, &state, &metrics, ADD_DROPPED);
        assert!(!state.contains(&h.infohash));
        // The overflow is still counted.
        assert_eq!(metrics.count_for("alert_queue_overflows_total"), 1);
    }

    const STATE_UPDATE_DROPPED: [u64; 2] = [0, 1u64 << (STATE_UPDATE_TYPE - 64)];

    /// A paused seed's status, as libtorrent reports it: still `seeding`,
    /// with the paused flag set.
    fn paused_status(h: TorrentHandle) -> libtorrent_safe::alert::TorrentStatusView {
        libtorrent_safe::alert::TorrentStatusView {
            handle: h,
            state: 5,
            flags: libtorrent_safe::TorrentFlags::PAUSED.bits(),
            total_uploaded: 0,
            total_payload_uploaded: 0,
            upload_rate: 0,
            download_rate: 0,
            num_peers: 0,
            num_seeds: 0,
            num_connections: 0,
            progress: 1.0,
            has_metadata: true,
            needs_save_resume: true,
            is_finished: true,
            is_seeding: false,
            has_error: false,
        }
    }

    #[test]
    fn a_dropped_state_update_refreshes_every_tracked_torrent_from_the_session() {
        use crate::state::TorrentPhase;

        let mock = Arc::new(MockEngine::new());
        let p = ProfileId::new("p");
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        // Two seeds the map last saw seeding, which were paused since, with
        // the update that said so lost.
        let (a, b) = (
            mock.register_handle(InfoHash([10; 20])),
            mock.register_handle(InfoHash([11; 20])),
        );
        for h in [a, b] {
            assert!(state.track_added(h, &p, true, std::time::Instant::now()));
            state.update(&h.infohash, |st| {
                st.phase = TorrentPhase::Seeding;
                st.is_seeding = true;
                st.needs_save_resume = false;
            });
            mock.set_torrent_status(paused_status(h));
        }
        // Held by the session and not tracked: its status describes nothing
        // the map holds, and is not counted.
        let untracked = mock.register_handle(InfoHash([12; 20]));
        mock.set_torrent_status(paused_status(untracked));

        run_on(mock.clone(), &state, &metrics, STATE_UPDATE_DROPPED);

        for h in [a, b] {
            let st = state.get(&h.infohash).expect("tracked");
            assert_eq!(st.phase, TorrentPhase::Paused);
            assert!(st.needs_save_resume, "the sweep saves it");
            assert!(!st.is_seeding);
        }
        assert!(!state.contains(&untracked.infohash));
        let refreshed: Vec<_> = metrics
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                crate::metrics::MetricCall::AddCounter {
                    name,
                    value,
                    labels,
                } if name == "statuses_refreshed_total" => Some((value, labels)),
                _ => None,
            })
            .collect();
        assert_eq!(
            refreshed,
            vec![(2, vec![("profile_id".to_string(), "p".to_string())])],
        );
    }

    /// The map's entry for `h` as a seed the map last saw seeding, under
    /// `profile`.
    fn seeding_entry(state: &StateMap, h: TorrentHandle, profile: &ProfileId) {
        use crate::state::TorrentPhase;

        assert!(state.track_added(h, profile, true, std::time::Instant::now()));
        state.update(&h.infohash, |st| {
            st.phase = TorrentPhase::Seeding;
            st.is_seeding = true;
            st.needs_save_resume = false;
        });
    }

    /// The entry [`seeding_entry`] left for `h` is unchanged, under `h` and
    /// `profile`, and no status was counted as refreshed.
    fn left_as_it_was(
        state: &StateMap,
        metrics: &RecordingSink,
        h: TorrentHandle,
        profile: &ProfileId,
    ) {
        use crate::state::TorrentPhase;

        let st = state.get(&h.infohash).expect("still tracked");
        assert_eq!((st.handle, &st.profile_id), (h, profile));
        assert_eq!(st.phase, TorrentPhase::Seeding);
        assert!(st.is_seeding);
        assert!(!st.needs_save_resume);
        assert_eq!(metrics.count_for("statuses_refreshed_total"), 0);
    }

    #[test]
    fn a_status_under_another_handle_than_the_entry_is_not_applied() {
        let mock = Arc::new(MockEngine::new());
        let p = ProfileId::new("p");
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        let ih = InfoHash([15; 20]);
        // The map tracks the torrent under a handle the session has since
        // replaced with another for the same info-hash.
        let old = mock.register_handle(ih);
        seeding_entry(&state, old, &p);
        mock.remove_torrent(old, false).unwrap();
        let new = mock.register_handle(ih);
        assert_ne!(new, old);
        mock.set_torrent_status(paused_status(new));

        run_on(mock, &state, &metrics, STATE_UPDATE_DROPPED);

        left_as_it_was(&state, &metrics, old, &p);
    }

    #[test]
    fn a_status_whose_entry_another_profile_tracks_is_not_applied() {
        let mock = Arc::new(MockEngine::new());
        let q = ProfileId::new("q");
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        // Same handle, but the entry is another profile's, not the one whose
        // queue overflowed.
        let h = mock.register_handle(InfoHash([16; 20]));
        seeding_entry(&state, h, &q);
        mock.set_torrent_status(paused_status(h));

        run_on(mock, &state, &metrics, STATE_UPDATE_DROPPED);

        left_as_it_was(&state, &metrics, h, &q);
    }

    #[test]
    fn an_overflow_that_spared_the_state_updates_reads_no_status() {
        use crate::state::TorrentPhase;

        let mock = Arc::new(MockEngine::new());
        let h = mock.register_handle(InfoHash([13; 20]));
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        assert!(state.track_added(h, &ProfileId::new("p"), true, std::time::Instant::now()));
        state.update(&h.infohash, |st| st.phase = TorrentPhase::Seeding);
        mock.set_torrent_status(paused_status(h));
        let mut bits = [u64::MAX, u64::MAX];
        bits[1] &= !STATE_UPDATE_DROPPED[1];
        run_on(mock, &state, &metrics, bits);
        assert_eq!(state.get(&h.infohash).unwrap().phase, TorrentPhase::Seeding);
        assert_eq!(metrics.count_for("statuses_refreshed_total"), 0);
    }

    #[test]
    fn statuses_that_cannot_be_read_leave_the_map_as_it_was() {
        use crate::state::TorrentPhase;

        let mock = Arc::new(MockEngine::new());
        let h = mock.register_handle(InfoHash([14; 20]));
        let state = StateMap::new();
        let metrics = RecordingSink::new();
        assert!(state.track_added(h, &ProfileId::new("p"), true, std::time::Instant::now()));
        state.update(&h.infohash, |st| st.phase = TorrentPhase::Seeding);
        mock.set_torrent_status(paused_status(h));
        mock.inject_error("torrent_statuses", EngineError::Shutdown);
        run_on(mock, &state, &metrics, STATE_UPDATE_DROPPED);
        assert_eq!(state.get(&h.infohash).unwrap().phase, TorrentPhase::Seeding);
        assert_eq!(metrics.count_for("statuses_refreshed_total"), 0);
        assert_eq!(metrics.count_for("alert_queue_overflows_total"), 1);
    }

    #[test]
    fn one_overflow_counts_once_however_many_types_it_dropped() {
        let state = StateMap::new();
        let resume = MemoryResumeStore::new();
        let torrents = MemoryTorrentStore::new();
        let metrics = RecordingSink::new();
        let clock = MockClock::new();
        let engine: Arc<dyn TorrentEngine> = Arc::new(MockEngine::new());
        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: ProfileId::new("p"),
            span: tracing::info_span!("test"),
        };
        let alert = Alert::AlertsDropped {
            hdr: AlertHeader {
                kind: AlertKind::AlertsDropped,
                infohash: None,
                handle: None,
                timestamp_us: 0,
            },
            bits: [0b1011, 1],
        };
        handle(&alert, &mut ctx);
        assert_eq!(metrics.count_for("alert_queue_overflows_total"), 1);
        assert_eq!(metrics.count_for("alerts_dropped_total"), 0);
    }
}
