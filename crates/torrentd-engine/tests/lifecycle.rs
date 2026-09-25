//! Layer 3 integration scenarios — deterministic,
//! single-session, real libtorrent + real disk, no network.
//!
//! Each test drives a real `libtorrent_safe::Session` and asserts on the raw
//! alert stream the daemon's handlers consume (the handler→`StateMap` phase
//! mapping itself is unit-tested in `handlers/state_update.rs`). They are
//! `#[ignore]`d because they build/run libtorrent and touch the disk; run with:
//!
//!   cargo test -p torrentd-engine --test lifecycle -- --ignored
//!
//! Coverage:
//!   - resume round-trip: SEED_MODE seed → save_resume_data → reload skips
//!     re-verification (no `hash_failed`, seeds immediately).
//!   - resume WITHOUT the info dict (the daemon's actual save flags): proves
//!     metadata is lost and re-attaching the stored `.torrent` restores it.
//!   - a resume add that clears flags still reports status (update_subscribe
//!     must survive the clear mask).
//!   - verification & corruption: a full-check add seeds when on-disk bytes
//!     match the piece hashes and never seeds when they don't.
//!   - alert-queue overflow: a tiny `alert_queue_size` flooded without draining
//!     surfaces `alerts_dropped` and keeps draining cleanly (no hang/panic).
//!   - the no-download invariant: `UPLOAD_MODE` survives a real session, holds
//!     for a magnet (which `SEED_MODE` cannot cover at all), and holds through
//!     the verification failure that drops `SEED_MODE`.
//!   - disk-error recovery: an unreadable payload leaves the torrent paused
//!     with a libtorrent error (not newly in upload mode), and `resume()`
//!     clears both and seeds, with `UPLOAD_MODE` untouched.

mod support;

use std::time::Duration;

use libtorrent_safe::AddParams;
use libtorrent_safe::Alert;
use libtorrent_safe::ResumeFlags;
use libtorrent_safe::Session;
use libtorrent_safe::TorrentFlags;

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
    let h2 = s2.add_torrent(AddParams::resume(blob)).unwrap();
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

/// The production resume path, which the round-trip test above does not cover
/// because it passes `SAVE_INFO_DICT` explicitly.
///
/// `write_resume_data` emits the info dict only when `save_resume_data` was
/// called with that flag (`vendor/libtorrent/src/torrent.cpp` gates
/// `ret.ti = m_torrent_file` on it), and the daemon's periodic and shutdown
/// saves both omit it — deliberately, since embedding a full piece-hash table
/// in every resume file costs gigabytes across a large inventory. So resume
/// data alone cannot reconstruct the torrent, and the fix is to hand
/// `add_torrent` the `.torrent` the daemon already keeps on disk.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn resume_without_info_dict_needs_the_torrent_file() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    let data = support::payload(3, FILE_LEN);
    std::fs::write(dir.path().join("seed-C"), &data).unwrap();
    let torrent = support::single_file_torrent("seed-C", &data, PIECE_LEN);

    // Save resume data exactly as the daemon does: no SAVE_INFO_DICT.
    let blob = {
        let s1 = Session::new(&support::local_seed_settings()).unwrap();
        let h = s1
            .add_torrent(AddParams::File {
                bytes: torrent.clone(),
                save_path: save.clone(),
                flags: TorrentFlags::SEED_MODE,
            })
            .unwrap();
        assert!(support::wait_for_seeding(&s1, h, Duration::from_secs(15)));
        s1.save_resume_data(h, ResumeFlags::empty()).unwrap();
        support::pump_until(&s1, Duration::from_secs(15), |a| match a {
            Alert::SaveResumeData { data, .. } => Some(data.as_bytes().to_vec()),
            Alert::SaveResumeDataFailed { message, .. } => {
                panic!("save_resume_data failed: {message}")
            }
            _ => None,
        })
        .expect("a save_resume_data alert should arrive")
    };

    // (a) Resume alone: no metadata, so the torrent cannot seed. With DHT, PEX
    //     and LSD disabled — a private profile's configuration — there is nowhere
    //     to fetch it from, and it would sit idle forever.
    {
        let s2 = Session::new(&support::local_seed_settings()).unwrap();
        let h2 = s2.add_torrent(AddParams::resume(blob.clone())).unwrap();
        let st = support::settle_status(&s2, h2, Duration::from_secs(3))
            .expect("a state update should arrive");
        assert!(
            !st.has_metadata,
            "resume data saved without SAVE_INFO_DICT must not carry metadata",
        );
        assert!(!st.is_seeding, "a torrent with no metadata cannot seed");
    }

    // (b) Same resume data plus the stored .torrent: metadata restored, seeding
    //     again, and still no re-verification.
    {
        let s3 = Session::new(&support::local_seed_settings()).unwrap();
        let h3 = s3
            .add_torrent(AddParams::Resume {
                bytes: blob,
                torrent: Some(torrent),
                save_path: None,
                flags_set: TorrentFlags::empty(),
                flags_clear: TorrentFlags::empty(),
            })
            .unwrap();
        let mut saw_hash_failed = false;
        let seeded = support::pump_until(&s3, Duration::from_secs(15), |a| match a {
            Alert::HashFailed { .. } => {
                saw_hash_failed = true;
                None
            }
            Alert::StateUpdate { statuses, .. } => statuses
                .iter()
                .find(|s| s.handle.infohash == h3.infohash && s.is_seeding)
                .map(|_| ()),
            _ => None,
        })
        .is_some();
        assert!(!saw_hash_failed, "re-attaching metadata must not re-verify");
        assert!(seeded, "resume + .torrent should seed");
    }
}

/// A resume add that clears a flag must not also unsubscribe the torrent from
/// status updates.
///
/// `flags_clear` is translated bit-for-bit, but an earlier version routed it
/// through the same helper that prepends the session defaults — so clearing
/// `PAUSED` also cleared `update_subscribe`. The torrent then seeded perfectly
/// while never appearing in another `state_update_alert`, leaving the daemon
/// reporting zero progress and zero upload for it forever. Nothing short of
/// asserting on the alert stream catches that: the torrent is genuinely fine,
/// only invisible.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn a_resume_add_that_clears_flags_still_reports_status() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    let data = support::payload(9, FILE_LEN);
    std::fs::write(dir.path().join("seed-D"), &data).unwrap();
    let torrent = support::single_file_torrent("seed-D", &data, PIECE_LEN);

    let blob = {
        let s1 = Session::new(&support::local_seed_settings()).unwrap();
        let h = s1
            .add_torrent(AddParams::File {
                bytes: torrent.clone(),
                save_path: save.clone(),
                flags: TorrentFlags::SEED_MODE,
            })
            .unwrap();
        assert!(support::wait_for_seeding(&s1, h, Duration::from_secs(15)));
        s1.save_resume_data(h, ResumeFlags::empty()).unwrap();
        support::pump_until(&s1, Duration::from_secs(15), |a| match a {
            Alert::SaveResumeData { data, .. } => Some(data.as_bytes().to_vec()),
            _ => None,
        })
        .expect("resume data")
    };

    let s2 = Session::new(&support::local_seed_settings()).unwrap();
    let h2 = s2
        .add_torrent(AddParams::Resume {
            bytes: blob,
            torrent: Some(torrent),
            save_path: Some(save),
            flags_set: TorrentFlags::SEED_MODE,
            // The clear that used to take update_subscribe down with it.
            flags_clear: TorrentFlags::PAUSED,
        })
        .unwrap();

    let seeding = support::pump_until(&s2, Duration::from_secs(15), |a| match a {
        Alert::StateUpdate { statuses, .. } => statuses
            .iter()
            .find(|s| s.handle.infohash == h2.infohash && s.is_seeding && s.progress >= 1.0)
            .map(|_| ()),
        _ => None,
    });
    assert!(
        seeding.is_some(),
        "the torrent must keep reporting status after a flag clear",
    );
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

// ---------------------------------------------------------------------------
// The no-download invariant
// ---------------------------------------------------------------------------

/// `torrentd_engine::policy` asserts `UPLOAD_MODE` on every add path. This
/// proves the claim it rests on: that libtorrent honours and *keeps* the flag,
/// rather than treating it the way it treats `SEED_MODE`.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn upload_mode_survives_a_failed_verification() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    let good = support::payload(1, FILE_LEN);
    let torrent = support::single_file_torrent("seed-A", &good, PIECE_LEN);
    // Same length, different bytes: every piece hash fails.
    std::fs::write(dir.path().join("seed-A"), support::payload(2, FILE_LEN)).unwrap();

    let s = Session::new(&support::local_seed_settings()).unwrap();
    // The pool's verify path exactly: no SEED_MODE, so libtorrent hashes.
    let h = s
        .add_torrent(AddParams::File {
            bytes: torrent,
            save_path: save,
            flags: TorrentFlags::UPLOAD_MODE,
        })
        .unwrap();

    let last = support::settle_status(&s, h, Duration::from_secs(10))
        .expect("the torrent should report status");
    let flags = TorrentFlags::from_bits_truncate(last.flags);

    assert!(
        flags.contains(TorrentFlags::UPLOAD_MODE),
        "upload_mode must survive the hash failure that drops seed_mode; flags={flags:?}",
    );
    assert!(
        !last.is_seeding,
        "a torrent whose every piece failed must not seed",
    );
    assert_eq!(
        last.download_rate, 0,
        "a torrent in upload_mode must never request a piece",
    );
}

/// The case `SEED_MODE` cannot cover: libtorrent documents it as a no-op for a
/// torrent added without metadata, so a magnet add was previously unguarded and
/// would fetch the whole payload once metadata arrived. `UPLOAD_MODE` is not
/// conditioned on metadata.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn a_magnet_add_carries_upload_mode_without_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let s = Session::new(&support::local_seed_settings()).unwrap();
    let h = s
        .add_torrent(AddParams::Magnet {
            uri: "magnet:?xt=urn:btih:0101010101010101010101010101010101010101".into(),
            save_path: dir.path().to_str().unwrap().to_string(),
            flags: TorrentFlags::SEED_MODE | TorrentFlags::UPLOAD_MODE,
        })
        .unwrap();

    let last = support::settle_status(&s, h, Duration::from_secs(5))
        .expect("the torrent should report status");
    let flags = TorrentFlags::from_bits_truncate(last.flags);

    assert!(
        !flags.contains(TorrentFlags::SEED_MODE),
        "libtorrent ignores seed_mode without metadata — if this ever fails, \
         the reasoning in torrentd_engine::policy needs revisiting; flags={flags:?}",
    );
    assert!(
        flags.contains(TorrentFlags::UPLOAD_MODE),
        "upload_mode is what actually holds for a magnet; flags={flags:?}",
    );
    assert_eq!(last.download_rate, 0);
}

/// What the disk-error retry actually recovers, on a real session.
///
/// A payload the daemon cannot read fails the check with a disk error that is
/// not end-of-file or a missing file, and libtorrent answers it with a
/// `file_error_alert`, an error on the torrent, and a pause — not with upload
/// mode, which the torrent carried from the add. `resume()` clears the error
/// and the pause, re-checks, and the torrent seeds; upload mode is untouched
/// throughout. The retry timer keys on exactly that error bit.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn resume_clears_the_error_a_disk_failure_left_and_keeps_upload_mode() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    let data = support::payload(4, FILE_LEN);
    let file = dir.path().join("seed-D");
    std::fs::write(&file, &data).unwrap();
    let torrent = support::single_file_torrent("seed-D", &data, PIECE_LEN);

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&file).is_ok() {
        // Root reads through mode 000; there is no read failure to observe.
        eprintln!("skipped: this user can read a mode-000 file");
        return;
    }

    let s = Session::new(&support::local_seed_settings()).unwrap();
    // The pool's verify path: no SEED_MODE, so libtorrent reads to hash.
    let h = s
        .add_torrent(AddParams::File {
            bytes: torrent,
            save_path: save,
            flags: TorrentFlags::UPLOAD_MODE,
        })
        .unwrap();

    let mut saw_file_error = false;
    let failed = support::pump_until(&s, Duration::from_secs(15), |a| match a {
        Alert::FileError { hdr, .. } if hdr.infohash == Some(h.infohash) => {
            saw_file_error = true;
            None
        }
        Alert::StateUpdate { statuses, .. } if saw_file_error => statuses
            .iter()
            .find(|st| st.handle.infohash == h.infohash && st.has_error)
            .cloned(),
        _ => None,
    })
    .expect("an unreadable payload should raise file_error and leave an error on the torrent");
    let flags = TorrentFlags::from_bits_truncate(failed.flags);
    assert!(
        flags.contains(TorrentFlags::PAUSED),
        "libtorrent pauses a torrent on a read-class disk error; flags={flags:?}",
    );
    assert!(
        flags.contains(TorrentFlags::UPLOAD_MODE),
        "upload_mode is the add-time policy, not the disk error's doing; flags={flags:?}",
    );

    // The storage comes back; the retry's resume() is what recovers the torrent.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    s.resume_torrent(h).unwrap();

    let recovered = support::pump_until(&s, Duration::from_secs(20), |a| match a {
        Alert::StateUpdate { statuses, .. } => statuses
            .iter()
            .find(|st| st.handle.infohash == h.infohash && st.is_seeding)
            .cloned(),
        _ => None,
    })
    .expect("resume() should clear the error, re-check, and seed");
    let flags = TorrentFlags::from_bits_truncate(recovered.flags);
    assert!(!recovered.has_error, "resume() clears libtorrent's error");
    assert!(!flags.contains(TorrentFlags::PAUSED), "flags={flags:?}");
    assert!(
        flags.contains(TorrentFlags::UPLOAD_MODE),
        "resume() never clears upload_mode; flags={flags:?}",
    );
}
