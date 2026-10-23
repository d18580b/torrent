//! Layer 3 integration scenarios — deterministic, real libtorrent + real
//! disk, no network beyond loopback. Every scenario but the willing-seeder one
//! runs a single session.
//!
//! Each test drives a real `libtorrent_safe::Session` and asserts on the raw
//! alert stream the daemon's handlers consume (the handler→`StateMap` phase
//! mapping itself is unit-tested in `handlers/state_update.rs`). They are
//! `#[ignore]`d because they build/run libtorrent and touch the disk; run with:
//!
//!   cargo test -p torrentd-engine --test lifecycle -- --ignored
//!
//! Coverage:
//!   - resume round-trip: SEED_MODE seed → save_resume_data → corrupt a piece
//!     on disk → reload skips re-verification (still seeds at 1.0, no
//!     `hash_failed`), while a forced check does find the corruption.
//!   - resume WITHOUT the info dict (the daemon's actual save flags): proves
//!     metadata is lost and re-attaching the stored `.torrent` restores it.
//!   - a resume add that clears flags still reports status (update_subscribe
//!     must survive the clear mask).
//!   - verification & corruption: a full-check add seeds when on-disk bytes
//!     match the piece hashes and never seeds when they don't.
//!   - bounded drains: a bounded drain leaves the rest queued, and
//!     `RealEngine::pop_alerts` returns at most `MAX_ALERTS_PER_POP`.
//!   - alert-queue overflow: a tiny `alert_queue_size` flooded without draining
//!     surfaces `alerts_dropped` and keeps draining cleanly (no hang/panic).
//!   - the no-download invariant: `UPLOAD_MODE` survives a real session, holds
//!     for a magnet (which `SEED_MODE` cannot cover at all), and holds through
//!     the verification failure that drops `SEED_MODE`; and, the one scenario
//!     here with a second session, a half-written torrent added on each of the
//!     six add paths takes zero payload bytes from a loopback seeder it stays
//!     connected to.
//!   - a magnet on a DHT-enabled host profile reaches the session with DHT,
//!     PEX and LSD disabled while it has no metadata, sheds them once its
//!     metadata shows it public, and keeps them when it shows it private.
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
                trackers: Vec::new(),
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

    // --- between sessions: corrupt the first piece in place ---
    // The same length and modification time, so nothing but a hash check can
    // tell. A reload that re-verified would find the piece bad and never
    // reach 1.0; one that trusts its resume data seeds as before. The absence
    // of `hash_failed` alone cannot tell the two apart: a check that passes
    // posts none either.
    let file = dir.path().join("seed-A");
    let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    let mut corrupt = data.clone();
    for b in &mut corrupt[..PIECE_LEN] {
        *b ^= 0xff;
    }
    std::fs::write(&file, &corrupt).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

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
            .map(|s| s.progress),
        _ => None,
    });

    assert!(
        !saw_hash_failed,
        "resume must skip re-verification: no hash_failed expected"
    );
    assert_eq!(
        seeded,
        Some(1.0),
        "the resumed torrent should seed whole over a piece it never re-read",
    );

    // The corruption is real: a forced check finds it. Without this, a
    // corruption the check could not see would make the assertions above
    // hold whether or not the reload re-verified.
    s2.force_recheck(h2).unwrap();
    let (mut checked, mut last) = (false, None);
    let found = support::pump_until(&s2, Duration::from_secs(15), |a| {
        match a {
            Alert::TorrentChecked { .. } => checked = true,
            Alert::StateUpdate { statuses, .. } => {
                if let Some(s) = statuses.iter().find(|s| s.handle.infohash == h2.infohash) {
                    last = Some((s.progress, s.is_seeding));
                }
            }
            _ => {}
        }
        (checked && last.is_some_and(|(p, seeding)| p < 1.0 && !seeding)).then_some(())
    });
    assert!(
        found.is_some(),
        "a full check of the corrupted payload should drop it below 1.0 \
         (checked: {checked}, last progress and seeding: {last:?})",
    );
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
                trackers: Vec::new(),
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
                trackers: Vec::new(),
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
                trackers: Vec::new(),
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
                trackers: Vec::new(),
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

/// A bounded drain returns at most its bound and leaves the rest queued, so
/// the engine can release the session lock between batches without losing an
/// alert.
#[test]
#[ignore = "real libtorrent; run with --ignored"]
fn a_bounded_drain_leaves_the_rest_queued() {
    let dir = tempfile::tempdir().unwrap();
    let s = Session::new(&support::local_seed_settings()).unwrap();
    for i in 0..20u8 {
        s.add_torrent(AddParams::Magnet {
            uri: format!("magnet:?xt=urn:btih:{}", hex::encode([i + 1; 20])),
            save_path: dir.path().to_str().unwrap().to_string(),
            flags: TorrentFlags::PAUSED | TorrentFlags::UPLOAD_MODE,
        })
        .unwrap();
    }
    let first = s.drain_alerts_up_to(5);
    assert_eq!(first.len(), 5);
    let mut added = first
        .iter()
        .filter(|a| matches!(a, Alert::AddTorrent { .. }))
        .count();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while added < 20 && std::time::Instant::now() < deadline {
        added += s
            .drain_alerts_up_to(5)
            .iter()
            .filter(|a| matches!(a, Alert::AddTorrent { .. }))
            .count();
    }
    assert_eq!(added, 20, "every add_torrent_alert arrives across batches");
}

/// `RealEngine::pop_alerts` converts at most `MAX_ALERTS_PER_POP` alerts per
/// call, and the rest arrive on the next pops.
#[test]
#[ignore = "real libtorrent; run with --ignored"]
fn the_engine_pops_at_most_its_cap_per_call() {
    use torrentd_engine::real::MAX_ALERTS_PER_POP;
    use torrentd_engine::RealEngine;
    use torrentd_engine::TorrentEngine;

    let count = MAX_ALERTS_PER_POP + 100;
    let mut settings = support::local_seed_settings();
    settings.alert_queue_size = Some(10_000);
    let dir = tempfile::tempdir().unwrap();
    let engine = RealEngine::new(&settings).unwrap();
    for i in 0..count {
        let mut ih = [0u8; 20];
        ih[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        engine
            .add_torrent(AddParams::Magnet {
                uri: format!("magnet:?xt=urn:btih:{}", hex::encode(ih)),
                save_path: dir.path().to_str().unwrap().to_string(),
                flags: TorrentFlags::PAUSED | TorrentFlags::UPLOAD_MODE,
            })
            .unwrap();
    }
    // Every add posted its `add_torrent_alert` before returning, so more
    // than the cap is queued now.
    let first = engine.pop_alerts();
    assert_eq!(first.len(), MAX_ALERTS_PER_POP);
    let mut added = first
        .iter()
        .filter(|a| matches!(a, Alert::AddTorrent { .. }))
        .count();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while added < count && std::time::Instant::now() < deadline {
        let batch = engine.pop_alerts();
        assert!(batch.len() <= MAX_ALERTS_PER_POP, "{}", batch.len());
        added += batch
            .iter()
            .filter(|a| matches!(a, Alert::AddTorrent { .. }))
            .count();
    }
    assert_eq!(added, count, "every add_torrent_alert arrives across pops");
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
            trackers: Vec::new(),
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

/// Resume data written by another client carries `auto_managed=1`
/// (qBittorrent and Deluge both write it), and libtorrent takes an
/// auto-managed torrent out of upload mode once `optimistic_disk_retry` has
/// passed (`torrent::second_tick`). The shim clears the flag on every add
/// whatever the caller asks for, so upload mode outlasts the retry window.
///
/// The caller here clears nothing on purpose: the guard must not depend on
/// every add path remembering to ask for it.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn resume_data_carrying_auto_managed_cannot_lift_upload_mode() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    // No payload on disk: the torrent is incomplete, so out of upload mode it
    // would be downloading.
    let torrent = support::single_file_torrent("absent", &support::payload(9, FILE_LEN), PIECE_LEN);
    let mut settings = support::local_seed_settings();
    settings.optimistic_disk_retry = Some(1);

    let blob = {
        let s1 = Session::new(&settings).unwrap();
        let h = s1
            .add_torrent(AddParams::File {
                bytes: torrent,
                save_path: save,
                flags: TorrentFlags::UPLOAD_MODE,
                trackers: Vec::new(),
            })
            .unwrap();
        support::settle_status(&s1, h, Duration::from_secs(2))
            .expect("the torrent should report status");
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
    // Rewrite the flag as another client's resume data would carry it.
    let (off, on) = (b"12:auto_managedi0e", b"12:auto_managedi1e");
    let at = blob
        .windows(off.len())
        .position(|w| w == off)
        .expect("resume data records auto_managed");
    let mut foreign = blob.clone();
    foreign[at..at + on.len()].copy_from_slice(on);

    let s2 = Session::new(&settings).unwrap();
    let h = s2
        .add_torrent(AddParams::Resume {
            bytes: foreign,
            torrent: None,
            save_path: None,
            flags_set: TorrentFlags::empty(),
            flags_clear: TorrentFlags::empty(),
        })
        .unwrap();
    // Several retry windows and second_ticks.
    let last = support::settle_status(&s2, h, Duration::from_secs(4))
        .expect("the torrent should report status");
    let flags = TorrentFlags::from_bits_truncate(last.flags);
    assert!(
        !flags.contains(TorrentFlags::AUTO_MANAGED),
        "auto_managed from resume data must be cleared; flags={flags:?}",
    );
    assert!(
        flags.contains(TorrentFlags::UPLOAD_MODE),
        "upload_mode must outlast optimistic_disk_retry; flags={flags:?}",
    );
    assert!(
        !last.is_seeding && last.progress < 1.0,
        "the payload is absent"
    );
    assert_eq!(
        last.download_rate, 0,
        "a torrent in upload_mode never requests a piece"
    );
}

/// The no-download invariant against a peer that has every piece and would
/// serve it, on every path the daemon adds a torrent by.
///
/// The tests above read `download_rate` off a torrent that has no peer, so
/// nothing could have been downloaded whatever the flags said. Here session A
/// seeds six complete payloads on loopback. Six daemon-side sessions each hold
/// one of them half-written — the first half correct, the rest zeroes — added
/// the way one add path adds it, with the flags that path composes, and each
/// is connected to A. For ten seconds after every connection is up (and after
/// the recheck, on the recheck path), each must take zero payload bytes and
/// leave its file exactly as it was, while A still lists it as a peer and it
/// still sees A as a seed.
///
/// Both sides set `close_redundant_connections` false. With libtorrent's
/// default, a torrent in upload mode tells its peers it is upload-only and a
/// seed hangs up on it at once; the torrent would then take nothing because it
/// had no peer, which is the vacuous pass this test exists to replace.
#[test]
#[ignore = "real libtorrent + disk + loopback peers; run with --ignored"]
fn an_upload_mode_torrent_never_takes_a_piece_from_a_willing_seeder() {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::time::Instant;

    use libtorrent_safe::alert::TorrentStatusView;
    use libtorrent_safe::TorrentHandle;
    use torrentd_engine::policy::magnet_flags;
    use torrentd_engine::resume_flags_clear;
    use torrentd_engine::resume_flags_set;
    use torrentd_engine::resume_flags_set_without_metadata;
    use torrentd_engine::seed_flags;
    use torrentd_engine::verify_flags;
    use torrentd_engine::ProfileConfig;
    use torrentd_engine::ProfileId;
    use torrentd_engine::ProfileNetwork;

    /// libtorrent's `torrent_status::state_t` values for a torrent hashing
    /// its payload: it turns peers away until it is done.
    const CHECKING_FILES: u32 = 1;
    const CHECKING_RESUME_DATA: u32 = 7;
    const PATHS: [&str; 6] = [
        ".torrent",
        "magnet",
        "resume",
        "resume + .torrent",
        "adoption fast path",
        "force recheck",
    ];
    const RECHECK: usize = 5;
    const ADOPTION: usize = 4;

    let mut settings = support::local_seed_settings();
    settings.close_redundant_connections = Some(false);
    let profile = ProfileConfig {
        id: ProfileId::new("public"),
        network: ProfileNetwork::Host {
            listen_interfaces: "127.0.0.1:0".into(),
            dht: false,
        },
        peer_fingerprint: None,
        user_agent: None,
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    };

    // One payload per path, so each of A's torrents has exactly one peer and
    // A's peer count names the path it belongs to.
    let names: Vec<String> = (0..PATHS.len()).map(|i| format!("willing-{i}")).collect();
    let payloads: Vec<Vec<u8>> = (0..PATHS.len())
        .map(|i| support::payload(0x50 + i as u8, FILE_LEN))
        .collect();
    let torrents: Vec<Vec<u8>> = (0..PATHS.len())
        .map(|i| support::single_file_torrent(&names[i], &payloads[i], PIECE_LEN))
        .collect();
    let half_written = |i: usize| {
        let mut b = payloads[i][..FILE_LEN / 2].to_vec();
        b.resize(FILE_LEN, 0);
        b
    };

    // --- A: the willing seeder, every payload complete and verified ---
    let seed_dir = tempfile::tempdir().unwrap();
    let a = Session::new(&settings).unwrap();
    let mut a_torrents = Vec::new();
    for i in 0..PATHS.len() {
        std::fs::write(seed_dir.path().join(&names[i]), &payloads[i]).unwrap();
        a_torrents.push(
            a.add_torrent(AddParams::File {
                bytes: torrents[i].clone(),
                save_path: seed_dir.path().to_str().unwrap().to_string(),
                flags: verify_flags(&profile),
                trackers: Vec::new(),
            })
            .unwrap(),
        );
    }
    let mut port = None;
    let mut a_seeding = vec![false; PATHS.len()];
    support::pump_until(&a, Duration::from_secs(20), |alert| {
        match alert {
            Alert::ListenSucceeded { endpoint, .. } => {
                port = port.or_else(|| {
                    endpoint
                        .rsplit_once(':')
                        .and_then(|(_, p)| p.parse::<u16>().ok())
                        .filter(|p| *p != 0)
                });
            }
            Alert::StateUpdate { statuses, .. } => {
                for st in statuses {
                    if let Some(i) = a_torrents.iter().position(|h| h.id == st.handle.id) {
                        a_seeding[i] |= st.is_seeding;
                    }
                }
            }
            _ => {}
        }
        (port.is_some() && a_seeding.iter().all(|s| *s)).then_some(())
    })
    .unwrap_or_else(|| panic!("A seeds every payload and listens: {a_seeding:?} {port:?}"));
    let seeder = SocketAddr::from((Ipv4Addr::LOCALHOST, port.unwrap()));

    // Resume data for a half-written payload, as this daemon saves it (no
    // info dict) or with it. The directory it was saved from, which the
    // resume data names, keeps the half-written file for the add.
    let saved_resume = |i: usize, flags: ResumeFlags| {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(&names[i]), half_written(i)).unwrap();
        let s = Session::new(&settings).unwrap();
        let h = s
            .add_torrent(AddParams::File {
                bytes: torrents[i].clone(),
                save_path: dir.path().to_str().unwrap().to_string(),
                flags: verify_flags(&profile),
                trackers: Vec::new(),
            })
            .unwrap();
        support::pump_until(&s, Duration::from_secs(15), |alert| match alert {
            Alert::TorrentChecked { hdr } if hdr.infohash == Some(h.infohash) => Some(()),
            _ => None,
        })
        .expect("the half-written payload is checked");
        s.save_resume_data(h, flags).unwrap();
        let blob = support::pump_until(&s, Duration::from_secs(15), |alert| match alert {
            Alert::SaveResumeData { data, .. } => Some(data.as_bytes().to_vec()),
            Alert::SaveResumeDataFailed { message, .. } => {
                panic!("save_resume_data failed: {message}")
            }
            _ => None,
        })
        .expect("a save_resume_data alert should arrive");
        (dir, blob)
    };

    // --- the daemon side: one session per add path ---
    struct Leecher {
        path: &'static str,
        session: Session,
        h: TorrentHandle,
        file: std::path::PathBuf,
        written: Vec<u8>,
        last: Option<TorrentStatusView>,
        dialled: Option<Instant>,
        _dir: tempfile::TempDir,
    }
    let mut leechers = Vec::new();
    for (i, path) in PATHS.iter().enumerate() {
        let (dir, params) = match i {
            0 | RECHECK => {
                let dir = tempfile::tempdir().unwrap();
                std::fs::write(dir.path().join(&names[i]), half_written(i)).unwrap();
                let params = AddParams::File {
                    bytes: torrents[i].clone(),
                    save_path: dir.path().to_str().unwrap().to_string(),
                    flags: verify_flags(&profile),
                    trackers: Vec::new(),
                };
                (dir, params)
            }
            1 => {
                let dir = tempfile::tempdir().unwrap();
                std::fs::write(dir.path().join(&names[i]), half_written(i)).unwrap();
                let ih = libtorrent_safe::info_hash_from_torrent(&torrents[i]).unwrap();
                let params = AddParams::Magnet {
                    uri: format!("magnet:?xt=urn:btih:{}", ih.to_hex()),
                    save_path: dir.path().to_str().unwrap().to_string(),
                    flags: magnet_flags(&profile),
                };
                (dir, params)
            }
            // The startup resume reload, from resume data that carries its
            // metadata and has no `.torrent` beside it.
            2 => {
                let (dir, blob) = saved_resume(i, ResumeFlags::SAVE_INFO_DICT);
                let params = AddParams::Resume {
                    bytes: blob,
                    torrent: None,
                    save_path: None,
                    flags_set: resume_flags_set_without_metadata(&profile),
                    flags_clear: resume_flags_clear(),
                };
                (dir, params)
            }
            // The startup resume reload as the daemon's own saves need it.
            3 => {
                let (dir, blob) = saved_resume(i, ResumeFlags::empty());
                let params = AddParams::Resume {
                    bytes: blob,
                    torrent: Some(torrents[i].clone()),
                    save_path: None,
                    flags_set: resume_flags_set(&profile),
                    flags_clear: resume_flags_clear(),
                };
                (dir, params)
            }
            // Pool adoption's fast path: another client's resume data, which
            // carries `auto_managed=1`, seeded straight away.
            ADOPTION => {
                let (dir, mut blob) = saved_resume(i, ResumeFlags::empty());
                let (off, on) = (b"12:auto_managedi0e", b"12:auto_managedi1e");
                let at = blob
                    .windows(off.len())
                    .position(|w| w == off)
                    .expect("resume data records auto_managed");
                blob[at..at + on.len()].copy_from_slice(on);
                let params = AddParams::Resume {
                    bytes: blob,
                    torrent: Some(torrents[i].clone()),
                    save_path: Some(dir.path().to_str().unwrap().to_string()),
                    flags_set: seed_flags(&profile),
                    flags_clear: TorrentFlags::PAUSED | resume_flags_clear(),
                };
                (dir, params)
            }
            _ => unreachable!(),
        };
        let session = Session::new(&settings).unwrap();
        let h = session.add_torrent(params).unwrap();
        let file = dir.path().join(&names[i]);
        let written = std::fs::read(&file).unwrap();
        assert_eq!(written, half_written(i), "{path}");
        leechers.push(Leecher {
            path,
            session,
            h,
            file,
            written,
            last: None,
            dialled: None,
            _dir: dir,
        });
    }

    // One round: read every status, and dial A again from any torrent that
    // is not checking and has lost it. Returns whether the recheck path
    // reported a finished check this round.
    //
    // Liveness is read fresh from each session with `torrent_statuses`, not
    // from `post_torrent_updates`: libtorrent posts a state update only for
    // a torrent it marked changed, and a peer hanging up does not mark one,
    // so a seeder lost mid-dwell would go unnoticed and never be redialled.
    let mut a_peers = vec![0i32; PATHS.len()];
    let round = |leechers: &mut Vec<Leecher>, a_peers: &mut Vec<i32>| {
        let mut checked = false;
        a.drain_alerts();
        for st in a.torrent_statuses().unwrap() {
            if let Some(i) = a_torrents.iter().position(|h| h.id == st.handle.id) {
                a_peers[i] = st.num_peers;
            }
        }
        for (i, l) in leechers.iter_mut().enumerate() {
            for alert in l.session.drain_alerts() {
                if i == RECHECK && matches!(alert, Alert::TorrentChecked { .. }) {
                    checked = true;
                }
            }
            l.last = l
                .session
                .torrent_statuses()
                .unwrap()
                .into_iter()
                .find(|st| st.handle.id == l.h.id);
            let checking = l
                .last
                .as_ref()
                .is_none_or(|st| matches!(st.state, CHECKING_FILES | CHECKING_RESUME_DATA));
            let lost = l.last.as_ref().is_none_or(|st| st.num_seeds == 0);
            if !checking
                && lost
                && l.dialled
                    .is_none_or(|t| t.elapsed() > Duration::from_secs(1))
            {
                l.session.connect_peer(l.h, seeder).unwrap();
                l.dialled = Some(Instant::now());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        checked
    };
    let connected = |leechers: &Vec<Leecher>, a_peers: &Vec<i32>| {
        leechers
            .iter()
            .zip(a_peers)
            .all(|(l, peers)| *peers >= 1 && l.last.as_ref().is_some_and(|st| st.num_seeds >= 1))
    };
    let describe = |leechers: &Vec<Leecher>, a_peers: &Vec<i32>| {
        leechers
            .iter()
            .zip(a_peers)
            .map(|(l, peers)| {
                let st = l.last.as_ref();
                format!(
                    "{}: A lists {peers} peer(s), it sees {:?} seed(s), state {:?}",
                    l.path,
                    st.map(|s| s.num_seeds),
                    st.map(|s| s.state),
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    while !connected(&leechers, &a_peers) {
        assert!(
            Instant::now() < deadline,
            "every path connects to A: {}",
            describe(&leechers, &a_peers),
        );
        round(&mut leechers, &mut a_peers);
    }

    // The recheck runs with the seeder connected. It drops every peer, so
    // the round above dials A again once the check is done; the dwell starts
    // once it has, so the recheck path gets its ten seconds connected too.
    leechers[RECHECK]
        .session
        .force_recheck(leechers[RECHECK].h)
        .unwrap();
    let mut rechecked = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !(rechecked && connected(&leechers, &a_peers)) {
        assert!(
            Instant::now() < deadline,
            "the recheck finishes (finished: {rechecked}) and every path is connected to A: {}",
            describe(&leechers, &a_peers),
        );
        rechecked |= round(&mut leechers, &mut a_peers);
    }
    let dwell = Instant::now() + Duration::from_secs(10);
    while Instant::now() < dwell {
        round(&mut leechers, &mut a_peers);
    }
    let untouched = |leechers: &Vec<Leecher>| {
        for l in leechers {
            assert_eq!(
                l.session.total_payload_download(l.h).unwrap(),
                0,
                "{}: took payload from the seeder",
                l.path,
            );
            assert!(
                std::fs::read(&l.file).unwrap() == l.written,
                "{}: the payload on disk changed",
                l.path,
            );
        }
    };
    untouched(&leechers);
    // Ten seconds on, every path is connected to A again, or still, and has
    // still taken nothing.
    let deadline = Instant::now() + Duration::from_secs(20);
    while !connected(&leechers, &a_peers) {
        assert!(
            Instant::now() < deadline,
            "every path is still connected to A: {}",
            describe(&leechers, &a_peers),
        );
        round(&mut leechers, &mut a_peers);
    }
    untouched(&leechers);

    for (i, l) in leechers.iter().enumerate() {
        let st = l.last.as_ref().unwrap();
        let flags = TorrentFlags::from_bits_truncate(st.flags);
        assert!(
            flags.contains(TorrentFlags::UPLOAD_MODE),
            "{}: flags={flags:?}",
            l.path
        );
        // Every path but adoption's `SEED_MODE` add knows it lacks half the
        // payload, and A has it: a torrent that would download, would here.
        if i != ADOPTION {
            assert!(
                st.has_metadata && !st.is_seeding && st.progress < 1.0,
                "{}: has_metadata={} is_seeding={} progress={}",
                l.path,
                st.has_metadata,
                st.is_seeding,
                st.progress,
            );
        }
    }
}

/// A magnet on a DHT-enabled host profile, before its metadata arrives.
///
/// A host profile trusts a torrent's own `private` bit, and a magnet has none
/// until its metadata is fetched; libtorrent announces a torrent without valid
/// metadata on the DHT regardless. So the flags the policy composes for a
/// magnet must reach the session with DHT, PEX and LSD disabled, and stay
/// there while the torrent has no metadata.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn a_magnet_on_a_dht_host_profile_carries_the_discovery_guards() {
    use torrentd_engine::policy::magnet_flags;
    use torrentd_engine::ProfileConfig;
    use torrentd_engine::ProfileId;
    use torrentd_engine::ProfileNetwork;

    let profile = ProfileConfig {
        id: ProfileId::new("public"),
        network: ProfileNetwork::Host {
            listen_interfaces: "127.0.0.1:0".into(),
            dht: true,
        },
        peer_fingerprint: None,
        user_agent: None,
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec!["tracker.example".into()],
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let s = Session::new(&support::local_seed_settings()).unwrap();
    let h = s
        .add_torrent(AddParams::Magnet {
            uri: "magnet:?xt=urn:btih:0202020202020202020202020202020202020202\
                  &tr=https%3A%2F%2Ftracker.example%2Fannounce"
                .into(),
            save_path: dir.path().to_str().unwrap().to_string(),
            flags: magnet_flags(&profile),
        })
        .unwrap();

    let last = support::settle_status(&s, h, Duration::from_secs(5))
        .expect("the torrent should report status");
    assert!(!last.has_metadata, "no peer can have supplied metadata");
    assert!(
        TorrentFlags::from_bits_truncate(last.flags).contains(TorrentFlags::UPLOAD_MODE),
        "flags={:?}",
        last.flags,
    );

    // The status view does not report the discovery bits; the resume data
    // libtorrent writes does, and it is also what carries them across a
    // restart.
    s.save_resume_data(h, ResumeFlags::empty()).unwrap();
    let blob = support::pump_until(&s, Duration::from_secs(15), |a| match a {
        Alert::SaveResumeData { data, .. } => Some(data.as_bytes().to_vec()),
        Alert::SaveResumeDataFailed { message, .. } => {
            panic!("save_resume_data failed: {message}")
        }
        _ => None,
    })
    .expect("a save_resume_data alert should arrive");
    let has = |needle: &[u8]| blob.windows(needle.len()).any(|w| w == needle);
    for key in [
        &b"11:disable_dhti1e"[..],
        b"11:disable_pexi1e",
        b"11:disable_lsdi1e",
    ] {
        assert!(
            has(key),
            "{} missing from the resume data",
            String::from_utf8_lossy(key),
        );
    }
}

/// A magnet on a DHT-enabled host profile sheds its discovery guards once its
/// metadata shows it public, and keeps them when it shows it private.
///
/// Real session, real resume data: the `metadata_received` handler is handed
/// the alert a peer's metadata would raise, for a real magnet handle, and the
/// resume data libtorrent then writes says whether DHT, PEX and LSD are off.
/// The alert is constructed rather than fetched from a peer: this layer has
/// one session and no network, and a libtorrent seed never serves a private
/// torrent's metadata, so the private case could not be fetched at all.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn public_magnet_metadata_lifts_the_discovery_guards_and_private_keeps_them() {
    use std::sync::Arc;

    use libtorrent_safe::alert::AlertHeader;
    use libtorrent_safe::AlertKind;
    use torrentd_engine::handlers::metadata;
    use torrentd_engine::handlers::HandlerCtx;
    use torrentd_engine::policy::magnet_flags;
    use torrentd_engine::policy::public_magnet_lift;
    use torrentd_engine::MemoryResumeStore;
    use torrentd_engine::MemoryTorrentStore;
    use torrentd_engine::MockClock;
    use torrentd_engine::NoopSink;
    use torrentd_engine::ProfileConfig;
    use torrentd_engine::ProfileId;
    use torrentd_engine::ProfileNetwork;
    use torrentd_engine::RealEngine;
    use torrentd_engine::StateMap;
    use torrentd_engine::TorrentEngine;

    let profile = ProfileConfig {
        id: ProfileId::new("public"),
        network: ProfileNetwork::Host {
            listen_interfaces: "127.0.0.1:0".into(),
            dht: true,
        },
        peer_fingerprint: None,
        user_agent: None,
        resume_dir: None,
        torrent_dir: None,
        allowed_tracker_domains: vec![],
        allowed_tracker_urls: vec![],
        upload_rate_limit: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let engine: Arc<dyn TorrentEngine> =
        Arc::new(RealEngine::new(&support::local_seed_settings()).unwrap());
    let state = StateMap::new();
    let resume = MemoryResumeStore::new();
    let torrents = MemoryTorrentStore::new();
    let metrics = NoopSink;
    let clock = MockClock::new();

    // The discovery bits as the resume data libtorrent writes for `h` holds
    // them, each `Some(off)`.
    let discovery_in_resume = |h| {
        engine.save_resume_data(h, ResumeFlags::empty()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let blob = loop {
            assert!(std::time::Instant::now() < deadline, "no resume data");
            let found = engine.pop_alerts().into_iter().find_map(|a| match a {
                Alert::SaveResumeData { hdr, data } if hdr.infohash == Some(h.infohash) => {
                    Some(data.as_bytes().to_vec())
                }
                Alert::SaveResumeDataFailed { message, .. } => {
                    panic!("save_resume_data failed: {message}")
                }
                _ => None,
            });
            if let Some(b) = found {
                break b;
            }
            std::thread::sleep(Duration::from_millis(40));
        };
        let has = |needle: &[u8]| blob.windows(needle.len()).any(|w| w == needle);
        ["dht", "pex", "lsd"].map(|k| {
            let on = has(format!("11:disable_{k}i0e").as_bytes());
            let off = has(format!("11:disable_{k}i1e").as_bytes());
            assert!(on != off, "disable_{k} should be in the resume data once");
            off
        })
    };

    for (byte, info, kept) in [
        (0x31u8, &b"d6:lengthi5e4:name1:ae"[..], false),
        (0x32, b"d6:lengthi5e4:name1:a7:privatei1ee", true),
    ] {
        let hex = format!("{byte:02x}").repeat(20);
        let h = engine
            .add_torrent(AddParams::Magnet {
                uri: format!("magnet:?xt=urn:btih:{hex}"),
                save_path: dir.path().to_str().unwrap().to_string(),
                flags: magnet_flags(&profile),
            })
            .unwrap();
        assert_eq!(discovery_in_resume(h), [true; 3], "added guarded");

        let mut ctx = HandlerCtx {
            state: &state,
            resume: &resume,
            torrents: &torrents,
            metrics: &metrics,
            clock: &clock,
            engine: &engine,
            profile_fenced: None,
            fence_hold: None,
            profile_id: profile.id.clone(),
            span: tracing::info_span!("test"),
        };
        let alert = Alert::MetadataReceived {
            hdr: AlertHeader {
                kind: AlertKind::MetadataReceived,
                infohash: Some(h.infohash),
                handle: Some(h),
                timestamp_us: 0,
            },
            info_section: info.to_vec(),
        };
        metadata::handle(&alert, &mut ctx, public_magnet_lift(&profile));

        assert_eq!(
            discovery_in_resume(h),
            [kept; 3],
            "private={kept}: the guards should be {}",
            if kept { "kept" } else { "lifted" },
        );
        // A public magnet's save is queued so the lift reaches its resume
        // file; a private one queues nothing.
        let queued: Vec<_> = state
            .dispatch_resume_saves(usize::MAX)
            .into_iter()
            .map(|(ih, _)| ih)
            .collect();
        let want = if kept { vec![] } else { vec![h.infohash] };
        assert_eq!(queued, want);
        for ih in queued {
            state.note_resume_settled(&ih);
        }
    }

    // Nothing but the discovery guards can be cleared.
    let h = engine.torrents().unwrap()[0];
    assert!(engine.unset_flags(h, TorrentFlags::UPLOAD_MODE).is_err());
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
            trackers: Vec::new(),
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

/// The HTTP API's per-torrent queries, through `RealEngine` against a real
/// session: details, files and trackers for a seeded torrent with metadata,
/// the metadata-less shape of a magnet, and `TorrentNotFound` once removed.
#[test]
#[ignore = "real libtorrent + disk; run with --ignored"]
fn engine_queries_report_details_files_and_trackers() {
    use torrentd_engine::EngineError;
    use torrentd_engine::RealEngine;
    use torrentd_engine::TorrentEngine;

    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_str().unwrap().to_string();
    let data = support::payload(7, FILE_LEN);
    std::fs::write(dir.path().join("query-A"), &data).unwrap();
    // Prepend an announce URL to the generated torrent: `announce` sorts
    // before `info`, so the result is still a canonical bencoded dict. The
    // port is closed; the torrent never needs the tracker to answer.
    let tracker = "http://127.0.0.1:1/announce";
    let plain = support::single_file_torrent("query-A", &data, PIECE_LEN);
    let mut torrent = format!("d8:announce{}:{tracker}", tracker.len()).into_bytes();
    torrent.extend_from_slice(&plain[1..]);

    let engine = RealEngine::new(&support::local_seed_settings()).unwrap();
    let h = engine
        .add_torrent(AddParams::File {
            bytes: torrent,
            save_path: save.clone(),
            flags: TorrentFlags::SEED_MODE,
            trackers: Vec::new(),
        })
        .unwrap();
    engine.set_upload_limit(h, 123_456).unwrap();

    let d = engine.torrent_details(h).unwrap();
    assert_eq!(d.name.as_deref(), Some("query-A"));
    assert!(d.has_metadata);
    assert_eq!(d.total_size, Some(FILE_LEN as u64));
    assert_eq!(d.save_path, save);
    assert_eq!(d.upload_limit, Some(123_456));
    assert!(d.added_at.is_some_and(|t| t > 1_600_000_000), "{d:?}");

    let files = engine.torrent_files(h).unwrap().expect("metadata present");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].index, 0);
    assert_eq!(files[0].path, "query-A");
    assert_eq!(files[0].size, FILE_LEN as u64);
    assert_eq!(files[0].priority, 4, "libtorrent's default priority");
    // SEED_MODE assumes every piece, so a seed reports the whole file.
    let mut downloaded = files[0].downloaded;
    for _ in 0..100 {
        if downloaded == FILE_LEN as u64 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        downloaded = engine.torrent_files(h).unwrap().unwrap()[0].downloaded;
    }
    assert_eq!(downloaded, FILE_LEN as u64);

    let trackers = engine.torrent_trackers(h).unwrap();
    assert_eq!(trackers.len(), 1);
    assert_eq!(trackers[0].url, tracker);
    assert_eq!(trackers[0].tier, 0);
    assert!(!trackers[0].verified);

    // A magnet has no metadata: details say so and there is no file list.
    let m = engine
        .add_torrent(AddParams::Magnet {
            uri: "magnet:?xt=urn:btih:0505050505050505050505050505050505050505&dn=pending".into(),
            save_path: save.clone(),
            flags: TorrentFlags::PAUSED | TorrentFlags::UPLOAD_MODE,
        })
        .unwrap();
    let md = engine.torrent_details(m).unwrap();
    assert!(!md.has_metadata);
    assert_eq!(md.total_size, None);
    assert_eq!(md.name.as_deref(), Some("pending"));
    assert_eq!(md.upload_limit, None, "unlimited by default");
    assert_eq!(engine.torrent_files(m).unwrap(), None);

    // Once removed, every query is TorrentNotFound rather than a shim error.
    engine.remove_torrent(h, false).unwrap();
    for err in [
        engine.torrent_details(h).map(|_| ()).unwrap_err(),
        engine.torrent_files(h).map(|_| ()).unwrap_err(),
        engine.torrent_trackers(h).map(|_| ()).unwrap_err(),
    ] {
        assert!(
            matches!(
                err,
                EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(ih)) if ih == h.infohash
            ),
            "{err:?}"
        );
    }
}
