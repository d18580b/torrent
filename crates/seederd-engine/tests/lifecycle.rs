//! Layer 3 integration scenarios (PRD Validation §Layer 3) — deterministic,
//! single-session, real libtorrent + real disk, no network.
//!
//! Each test drives a real `libtorrent_safe::Session` and asserts on the raw
//! alert stream the daemon's handlers consume (the handler→`StateMap` phase
//! mapping itself is unit-tested in `handlers/state_update.rs`). They are
//! `#[ignore]`d because they build/run libtorrent and touch the disk; run with:
//!
//!   cargo test -p seederd-engine --test lifecycle -- --ignored
//!
//! Coverage:
//!   - resume round-trip: SEED_MODE seed → save_resume_data → reload skips
//!     re-verification (no `hash_failed`, seeds immediately).
//!   - verification & corruption: a full-check add seeds when on-disk bytes
//!     match the piece hashes and never seeds when they don't.
//!   - alert-queue overflow: a tiny `alert_queue_size` flooded without draining
//!     surfaces `alerts_dropped` and keeps draining cleanly (no hang/panic).

mod support;

use std::time::Duration;

use libtorrent_safe::{AddParams, Alert, ResumeFlags, Session, TorrentFlags};

const PIECE_LEN: usize = 32 * 1024;
const FILE_LEN: usize = 256 * 1024; // 8 pieces

#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn resume_round_trip_skips_reverify() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    let data = support::payload(1, FILE_LEN);
    std::fs::write(dir.path().join("seed-A"), &data).unwrap();
    let torrent = support::single_file_torrent("seed-A", &data, PIECE_LEN);

    // --- session 1: seed in SEED_MODE, then capture resume data ---
    let blob = {
        let s1 = Session::new(&support::local_seed_settings()).unwrap();
        let h = s1
            .add_torrent(AddParams::File {
                bytes: torrent.clone(),
                save_path: save.clone(),
                flags: TorrentFlags::SEED_MODE,
            })
            .unwrap();
        assert!(
            support::wait_for_seeding(&s1, h, Duration::from_secs(15)),
            "a SEED_MODE torrent with present payload should reach seeding"
        );
        s1.save_resume_data(h, ResumeFlags::SAVE_INFO_DICT).unwrap();
        support::pump_until(&s1, Duration::from_secs(15), |a| match a {
            Alert::SaveResumeData { data, .. } => Some(data.as_bytes().to_vec()),
            Alert::SaveResumeDataFailed { message, .. } => {
                panic!("save_resume_data failed: {message}")
            }
            _ => None,
        })
        .expect("a save_resume_data alert should arrive")
    };
    assert!(!blob.is_empty(), "resume blob should be non-empty");

    // --- session 2: reload purely from resume; it must NOT re-verify ---
    let s2 = Session::new(&support::local_seed_settings()).unwrap();
    let h2 = s2.add_torrent(AddParams::Resume { bytes: blob }).unwrap();
    let mut saw_hash_failed = false;
    let seeded = support::pump_until(&s2, Duration::from_secs(15), |a| match a {
        Alert::HashFailed { .. } => {
            saw_hash_failed = true;
            None
        }
        Alert::StateUpdate { statuses, .. } => statuses
            .iter()
            .find(|s| s.handle.infohash == h2.infohash && s.is_seeding)
            .map(|_| ()),
        _ => None,
    })
    .is_some();

    assert!(
        !saw_hash_failed,
        "resume must skip re-verification: no hash_failed expected"
    );
    assert!(seeded, "the resumed torrent should be seeding");
}

#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn full_check_verifies_and_rejects_corrupt_payload() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    // Piece hashes are computed over the *correct* payload.
    let correct = support::payload(2, FILE_LEN);
    let torrent = support::single_file_torrent("seed-B", &correct, PIECE_LEN);

    // (a) On-disk bytes match the hashes → full check passes → seeding.
    {
        std::fs::write(dir.path().join("seed-B"), &correct).unwrap();
        let s = Session::new(&support::local_seed_settings()).unwrap();
        let h = s
            .add_torrent(AddParams::File {
                bytes: torrent.clone(),
                save_path: save.clone(),
                flags: TorrentFlags::default(), // no SEED_MODE → libtorrent checks files
            })
            .unwrap();
        assert!(
            support::wait_for_seeding(&s, h, Duration::from_secs(20)),
            "matching payload must verify and seed"
        );
    }

    // (b) Same torrent, corrupt bytes of the same length → check fails → the
    //     torrent never seeds (a seeding daemon must not serve bad data).
    {
        let corrupt = support::payload(0xFF, FILE_LEN);
        assert_ne!(correct, corrupt);
        std::fs::write(dir.path().join("seed-B"), &corrupt).unwrap();
        let s = Session::new(&support::local_seed_settings()).unwrap();
        let h = s
            .add_torrent(AddParams::File {
                bytes: torrent,
                save_path: save,
                flags: TorrentFlags::default(),
            })
            .unwrap();
        let status = support::settle_status(&s, h, Duration::from_secs(4));
        let status = status.expect("expected at least one state update for the torrent");
        assert!(
            !status.is_seeding && status.progress < 1.0,
            "corrupt payload must fail verification and not seed (is_seeding={}, progress={})",
            status.is_seeding,
            status.progress
        );
    }
}

#[test]
#[ignore = "real libtorrent; run with --ignored"]
fn alert_queue_overflow_surfaces_drop_and_keeps_draining() {
    // Tiny alert queue: flooding adds without draining forces libtorrent to drop
    // alerts and post an alerts_dropped_alert.
    let mut settings = support::local_seed_settings();
    settings.alert_queue_size = Some(4);
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();

    let session = Session::new(&settings).unwrap();

    // Add many distinct SEED_MODE torrents WITHOUT draining alerts in between.
    // SEED_MODE + no peers means no disk access, so missing payload is fine.
    let payload = support::payload(7, 64);
    for i in 0..3000 {
        let torrent = support::single_file_torrent(&format!("ov-{i}"), &payload, 64);
        let _ = session.add_torrent(AddParams::File {
            bytes: torrent,
            save_path: save.clone(),
            flags: TorrentFlags::SEED_MODE,
        });
    }

    // Now drain: we must observe an AlertsDropped, and draining must terminate
    // cleanly without panicking.
    let saw_dropped = support::pump_until(&session, Duration::from_secs(10), |a| match a {
        Alert::AlertsDropped { .. } => Some(()),
        _ => None,
    })
    .is_some();
    assert!(
        saw_dropped,
        "flooding a size-4 alert queue should surface an alerts_dropped alert"
    );

    // Drain whatever remains; the session stays responsive (no hang/panic).
    let _ = session.drain_alerts();
}
