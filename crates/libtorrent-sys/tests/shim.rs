//! Layer 2 shim FFI tests.
//!
//! Run with: `cargo test -p libtorrent-sys --features shim-tests`
//!
//! The assertions cover struct marshalling, exception isolation, null-handle
//! safety, and buffer ownership against a real (but non-listening) libtorrent
//! session. AddressSanitizer instrumentation is a follow-up (see build.rs for
//! why instrumenting only the shim doesn't link on this toolchain).

#![cfg(all(feature = "shim-tests", feature = "bundled"))]
#![allow(non_upper_case_globals)]

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use libtorrent_sys::*;

const NO_NET: &str = r#"{"enable_dht":false,"enable_lsd":false,"enable_upnp":false,"enable_natpmp":false,"listen_interfaces":"127.0.0.1:0"}"#;

fn make_session() -> *mut lt_session {
    let settings = CString::new(NO_NET).unwrap();
    let mut err = [0 as c_char; 512];
    let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
    assert!(!s.is_null(), "session create failed");
    s
}

#[test]
fn exception_isolation_bad_torrent_returns_null() {
    let s = make_session();
    let garbage = b"this is not a bencoded torrent";
    let save = CString::new("/tmp").unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_file(
            s,
            garbage.as_ptr(),
            garbage.len(),
            save.as_ptr(),
            0,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(
        h, 0,
        "a bad .torrent must return the null handle, not unwind"
    );
    assert_ne!(err[0], 0, "err_out should describe the parse failure");
    unsafe { lt_session_destroy(s) };
}

#[test]
fn null_and_unknown_handle_ops_are_safe() {
    let s = make_session();
    // 0 is the null sentinel; a large id is simply unknown. Neither crashes.
    assert_eq!(unsafe { lt_torrent_pause(s, 0) }, LT_ERR);
    assert_eq!(unsafe { lt_torrent_resume(s, 0) }, LT_ERR);
    assert_eq!(unsafe { lt_remove_torrent(s, 0, 0) }, LT_ERR);
    assert_eq!(
        unsafe { lt_torrent_set_upload_limit(s, 999_999, 100) },
        LT_ERR
    );
    assert_eq!(unsafe { lt_torrent_force_reannounce(s, 0) }, LT_ERR);
    assert_eq!(unsafe { lt_torrent_force_reannounce(s, 999_999) }, LT_ERR);
    assert_eq!(unsafe { lt_torrent_pause(ptr::null_mut(), 1) }, LT_ERR);
    assert_eq!(
        unsafe { lt_torrent_force_reannounce(ptr::null_mut(), 1) },
        LT_ERR
    );
    unsafe { lt_session_destroy(s) };
}

#[test]
fn save_state_buffer_ownership_roundtrip() {
    let s = make_session();
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_session_save_state(s, &mut buf, &mut len, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32);
    assert!(
        !buf.is_null() && len > 0,
        "expected a non-empty state buffer"
    );
    // ASan verifies this frees exactly what the shim malloc'd (no double-free
    // / no leak). Reloading the same blob must round-trip.
    let rc2 = unsafe { lt_session_load_state(s, buf, len, err.as_mut_ptr(), 512) };
    assert_eq!(rc2, LT_OK as i32);
    unsafe { lt_buf_free(buf) };
    unsafe { lt_session_destroy(s) };
}

#[test]
fn magnet_info_hash_marshals_20_bytes() {
    let uri = CString::new("magnet:?xt=urn:btih:0101010101010101010101010101010101010101").unwrap();
    let mut out = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_magnet_info_hash(uri.as_ptr(), out.as_mut_ptr(), err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32);
    assert_eq!(out, [0x01u8; 20]);
}

#[test]
fn torrent_info_hash_bad_buffer_errors_cleanly() {
    let garbage = b"nope";
    let mut out = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_info_hash(
            garbage.as_ptr(),
            garbage.len(),
            out.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(rc, LT_ERR);
    assert_ne!(err[0], 0);
}

#[test]
fn add_magnet_marshals_add_torrent_alert_union() {
    let s = make_session();
    let uri = CString::new(
        "magnet:?xt=urn:btih:0202020202020202020202020202020202020202&dn=marshal-test",
    )
    .unwrap();
    let save = CString::new("/tmp").unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_magnet(
            s,
            uri.as_ptr(),
            save.as_ptr(),
            LT_TF_SEED_MODE,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "magnet add returned null");
    assert_eq!(ih, [0x02u8; 20]);

    // The add_torrent_alert must marshal through the union with the same
    // infohash and a valid handle. Drain (and free) until we see it.
    let mut found = false;
    for _ in 0..100 {
        let mut u: lt_alert_union = unsafe { std::mem::zeroed() };
        if unsafe { lt_pop_alert(s, &mut u) } == 1 {
            if u.kind == lt_alert_kind_LT_ALERT_ADD_TORRENT {
                assert_eq!(u.infohash, [0x02u8; 20]);
                assert_ne!(u.handle, 0);
                found = true;
            }
            // Free any heap payload (ASan checks ownership).
            unsafe { lt_alert_payload_free(&mut u) };
        } else {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if found {
            break;
        }
    }
    assert!(found, "expected an add_torrent_alert for the magnet");
    unsafe { lt_session_destroy(s) };
}

// ---------------------------------------------------------------------------
// lt_torrent_metadata — the pool library scanner's parser
// ---------------------------------------------------------------------------

/// Fixtures come from the pinned `vendor/libtorrent` test corpus, and the
/// expected hashes below are the constants libtorrent's own
/// `test_torrent_info.cpp` asserts against. Hand-rolling a valid v2 torrent
/// would mean reimplementing the 16 KiB-leaf merkle construction in the test,
/// which is exactly the computation under test.
fn vendored_torrent(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/libtorrent/test/test_torrents")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn parse_meta(bytes: &[u8]) -> lt_torrent_meta {
    let mut meta: lt_torrent_meta = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_metadata(
            bytes.as_ptr(),
            bytes.len(),
            &mut meta,
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_metadata failed");
    meta
}

fn meta_file_path(f: &lt_torrent_meta_file) -> String {
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(f.path.as_ptr() as *const u8, f.path.len()) };
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul]).into_owned()
}

#[test]
fn metadata_reads_v2_root_hashes_and_both_infohashes() {
    // v2.torrent is a v1+v2 hybrid: one 64 KiB file. Both the v2 info-hash and
    // the per-file merkle root are asserted against libtorrent's own expected
    // values, so a regression in our struct marshalling shows up as a mismatch
    // rather than a plausible-looking wrong hash.
    let bytes = vendored_torrent("v2.torrent");
    let mut meta = parse_meta(&bytes);

    assert_eq!(meta.num_files, 1);
    assert_eq!(meta.has_v1, 1, "v2.torrent is a hybrid");
    assert_eq!(meta.has_v2, 1);

    let files = unsafe { std::slice::from_raw_parts(meta.files, meta.num_files) };
    assert_eq!(meta_file_path(&files[0]), "test64K");
    assert_eq!(files[0].size, 65536);
    assert_eq!(files[0].has_pieces_root, 1);
    assert_eq!(
        hex_of(&files[0].pieces_root),
        "60aae9c7b428f87e0713e88229e18f0adf12cd7b22a0dd8a92bb2485eb7af242",
    );
    assert_eq!(
        hex_of(&meta.infohash_v2),
        "597b180c1a170a585dfc5e85d834d69013ceda174b8f357d5bb1a0ca509faf0a",
    );

    unsafe { lt_torrent_meta_free(&mut meta) };
    // Freeing twice must be safe — the daemon frees on every early return path.
    unsafe { lt_torrent_meta_free(&mut meta) };
}

#[test]
fn metadata_on_a_v1_only_torrent_has_no_per_file_roots() {
    // v1 pieces span file boundaries, so there is no per-file digest to report.
    // The pool matcher relies on this to decide when it must fall back to
    // (path, size) matching instead of content-addressed matching.
    let bytes = vendored_torrent("base.torrent");
    let mut meta = parse_meta(&bytes);

    assert_eq!(meta.has_v1, 1);
    assert_eq!(meta.has_v2, 0, "base.torrent is v1-only");
    assert_eq!(meta.infohash_v2, [0u8; 32], "v2 hash must be zeroed");

    let files = unsafe { std::slice::from_raw_parts(meta.files, meta.num_files) };
    assert!(
        files.iter().all(|f| f.has_pieces_root == 0),
        "a v1-only torrent must report no per-file merkle roots",
    );

    unsafe { lt_torrent_meta_free(&mut meta) };
}

#[test]
fn metadata_reports_every_file_of_a_multi_file_torrent() {
    let bytes = vendored_torrent("v2_multiple_files.torrent");
    let mut meta = parse_meta(&bytes);

    assert!(meta.num_files > 1, "fixture should be multi-file");
    let files = unsafe { std::slice::from_raw_parts(meta.files, meta.num_files) };
    assert_eq!(files.len(), meta.num_files);
    // Sizes must be populated and paths non-empty for every entry; a partially
    // filled array would silently corrupt the pool index.
    assert!(files.iter().all(|f| !meta_file_path(f).is_empty()));
    assert_eq!(
        meta.total_size,
        files.iter().map(|f| f.size).sum::<u64>(),
        "total_size should equal the sum of the file list",
    );

    unsafe { lt_torrent_meta_free(&mut meta) };
}

#[test]
fn metadata_rejects_garbage_without_unwinding() {
    let garbage = b"d4:infoNOT-BENCODE";
    let mut meta: lt_torrent_meta = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_metadata(
            garbage.as_ptr(),
            garbage.len(),
            &mut meta,
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(rc, LT_ERR, "malformed input must return LT_ERR");
    assert_ne!(err[0], 0, "err_out should describe the parse failure");
    assert!(meta.files.is_null(), "no allocation should leak on failure");

    // Null args must not dereference.
    assert_eq!(
        unsafe { lt_torrent_metadata(ptr::null(), 0, &mut meta, err.as_mut_ptr(), 512) },
        LT_ERR,
    );
    unsafe { lt_torrent_meta_free(ptr::null_mut()) };
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Per-torrent queries: lt_torrent_details / _files / _trackers
// ---------------------------------------------------------------------------

const TRACKERS: [&str; 3] = [
    "http://127.0.0.1:1/announce",
    "http://127.0.0.1:2/announce",
    "http://127.0.0.1:3/tier1",
];

/// A v1 multi-file `.torrent` with two tracker tiers (two URLs in tier 0, one
/// in tier 1). The piece hashes are filler: every test adds it paused, so
/// libtorrent never checks or serves the payload.
fn multi_file_tracker_torrent() -> Vec<u8> {
    const PIECE_LEN: u64 = 16 * 1024;
    let files: [(&str, &str, u64); 3] = [
        ("docs", "readme.txt", 1000),
        ("docs", "notes.txt", 20_000),
        ("data", "blob.bin", 40_000),
    ];
    let total: u64 = files.iter().map(|f| f.2).sum();
    let num_pieces = total.div_ceil(PIECE_LEN) as usize;

    let bstr = |s: &str| format!("{}:{s}", s.len());
    let mut out = Vec::new();
    // Top-level keys in bencode byte order: announce < announce-list < info.
    out.extend_from_slice(b"d");
    out.extend_from_slice(format!("8:announce{}", bstr(TRACKERS[0])).as_bytes());
    out.extend_from_slice(
        format!(
            "13:announce-listll{}{}el{}ee",
            bstr(TRACKERS[0]),
            bstr(TRACKERS[1]),
            bstr(TRACKERS[2])
        )
        .as_bytes(),
    );
    // Info-dict keys: files < name < piece length < pieces.
    out.extend_from_slice(b"4:infod5:filesl");
    for (dir, name, len) in files {
        out.extend_from_slice(
            format!("d6:lengthi{len}e4:pathl{}{}ee", bstr(dir), bstr(name)).as_bytes(),
        );
    }
    out.extend_from_slice(b"e");
    out.extend_from_slice(format!("4:name{}", bstr("multi-root")).as_bytes());
    out.extend_from_slice(format!("12:piece lengthi{PIECE_LEN}e").as_bytes());
    out.extend_from_slice(format!("6:pieces{}:", num_pieces * 20).as_bytes());
    out.extend(std::iter::repeat_n(0xAB_u8, num_pieces * 20));
    out.extend_from_slice(b"ee");
    out
}

fn add_file(s: *mut lt_session, bytes: &[u8]) -> lt_handle {
    let save = CString::new("/tmp").unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_file(
            s,
            bytes.as_ptr(),
            bytes.len(),
            save.as_ptr(),
            LT_TF_PAUSED,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "add .torrent failed: {}", c_buf(&err));
    h
}

fn add_magnet(s: *mut lt_session, uri: &str) -> lt_handle {
    let uri = CString::new(uri).unwrap();
    let save = CString::new("/tmp").unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_magnet(
            s,
            uri.as_ptr(),
            save.as_ptr(),
            LT_TF_PAUSED,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "add magnet failed: {}", c_buf(&err));
    h
}

fn c_buf(buf: &[c_char]) -> String {
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul]).into_owned()
}

fn details(s: *mut lt_session, h: lt_handle) -> lt_torrent_details {
    let mut d: lt_torrent_details = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_torrent_details(s, h, &mut d, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_details: {}", c_buf(&err));
    d
}

#[test]
fn details_without_metadata_report_the_magnet_name_and_no_size() {
    let s = make_session();
    let h = add_magnet(
        s,
        "magnet:?xt=urn:btih:0303030303030303030303030303030303030303&dn=pending-name",
    );
    let d = details(s, h);
    assert_eq!(d.has_metadata, 0);
    assert_eq!(d.total_size, 0, "no metadata, no size");
    assert_eq!(
        c_buf(&d.name),
        "pending-name",
        "dn= is the name until metadata"
    );
    assert_eq!(c_buf(&d.save_path), "/tmp");
    assert_eq!(d.upload_limit, 0, "a fresh torrent is unlimited");
    assert!(d.added_time > 1_600_000_000, "added_time is unix seconds");
    unsafe { lt_session_destroy(s) };
}

#[test]
fn details_with_metadata_report_size_name_and_upload_limit() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    let d = details(s, h);
    assert_eq!(d.has_metadata, 1);
    assert_eq!(d.total_size, 61_000);
    assert_eq!(c_buf(&d.name), "multi-root");

    assert_eq!(
        unsafe { lt_torrent_set_upload_limit(s, h, 50_000) },
        LT_OK as i32
    );
    assert_eq!(details(s, h).upload_limit, 50_000);
    // libtorrent spells "unlimited" as -1 or 0; the shim always says 0.
    assert_eq!(
        unsafe { lt_torrent_set_upload_limit(s, h, -1) },
        LT_OK as i32
    );
    assert_eq!(details(s, h).upload_limit, 0);
    unsafe { lt_session_destroy(s) };
}

#[test]
fn files_list_every_file_with_size_progress_and_priority() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    assert_eq!(
        unsafe { lt_torrent_set_file_priority(s, h, 2, 7) },
        LT_OK as i32
    );

    // libtorrent applies a file priority through the disk thread and only
    // updates what get_file_priorities() reports once that completes, so poll
    // briefly. Every iteration frees what the previous one was handed.
    let mut got = Vec::new();
    for _ in 0..100 {
        let mut list: lt_torrent_file_list = unsafe { std::mem::zeroed() };
        let mut err = [0 as c_char; 512];
        let rc = unsafe { lt_torrent_files(s, h, &mut list, err.as_mut_ptr(), 512) };
        assert_eq!(rc, LT_OK as i32, "lt_torrent_files: {}", c_buf(&err));
        assert_eq!(list.has_metadata, 1);
        assert_eq!(list.num_files, 3);
        let files = unsafe { std::slice::from_raw_parts(list.files, list.num_files) };
        got = files
            .iter()
            .map(|f| (c_buf(&f.path), f.size, f.downloaded, f.priority))
            .collect::<Vec<(String, u64, u64, u8)>>();
        unsafe { lt_torrent_file_list_free(&mut list) };
        assert!(list.files.is_null() && list.num_files == 0);
        // Idempotent, and safe on null.
        unsafe { lt_torrent_file_list_free(&mut list) };
        if got[2].3 == 7 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        got,
        vec![
            ("multi-root/docs/readme.txt".to_string(), 1000, 0, 4),
            ("multi-root/docs/notes.txt".to_string(), 20_000, 0, 4),
            ("multi-root/data/blob.bin".to_string(), 40_000, 0, 7),
        ],
    );

    unsafe { lt_torrent_file_list_free(ptr::null_mut()) };
    unsafe { lt_session_destroy(s) };
}

#[test]
fn files_without_metadata_is_ok_and_empty() {
    let s = make_session();
    let h = add_magnet(
        s,
        "magnet:?xt=urn:btih:0404040404040404040404040404040404040404",
    );
    let mut list: lt_torrent_file_list = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_torrent_files(s, h, &mut list, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_files: {}", c_buf(&err));
    assert_eq!(list.has_metadata, 0);
    assert_eq!(list.num_files, 0);
    assert!(list.files.is_null());
    unsafe { lt_torrent_file_list_free(&mut list) };
    unsafe { lt_session_destroy(s) };
}

#[test]
fn trackers_report_every_url_with_its_tier() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());

    let mut list: lt_tracker_list = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_torrent_trackers(s, h, &mut list, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_trackers: {}", c_buf(&err));
    let entries = unsafe { std::slice::from_raw_parts(list.entries, list.num_entries) };
    let got: Vec<(String, u8)> = entries.iter().map(|e| (c_buf(&e.url), e.tier)).collect();
    // Tier order is fixed; libtorrent shuffles URLs within a tier (BEP 12).
    let tiers: Vec<u8> = got.iter().map(|g| g.1).collect();
    assert_eq!(tiers, vec![0, 0, 1]);
    let mut sorted = got.clone();
    sorted.sort();
    let mut want = vec![
        (TRACKERS[0].to_string(), 0),
        (TRACKERS[1].to_string(), 0),
        (TRACKERS[2].to_string(), 1),
    ];
    want.sort();
    assert_eq!(sorted, want);
    // A paused torrent has never announced: nothing to report yet.
    for e in entries {
        assert_eq!(e.updating, 0);
        assert_eq!(e.fails, 0);
        assert_eq!(e.next_announce, 0);
        assert_eq!(e.scrape_complete, -1);
        assert_eq!(e.scrape_incomplete, -1);
        assert_eq!(c_buf(&e.message), "");
        assert_eq!(c_buf(&e.last_error), "");
    }

    unsafe { lt_tracker_list_free(&mut list) };
    assert!(list.entries.is_null() && list.num_entries == 0);
    unsafe { lt_tracker_list_free(&mut list) };
    unsafe { lt_tracker_list_free(ptr::null_mut()) };
    unsafe { lt_session_destroy(s) };
}

#[test]
fn trackers_fold_a_failed_announce_into_fails_error_and_next_announce() {
    // Every tracker URL points at a closed loopback port (HTTP ones, so the
    // announce fails at once with "connection refused" rather than waiting out
    // a UDP timeout), so once the torrent runs libtorrent records the failure
    // and schedules a retry. That exercises the endpoint aggregation end to
    // end.
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    assert_eq!(unsafe { lt_torrent_resume(s, h) }, LT_OK as i32);

    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut failed = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        let mut list: lt_tracker_list = unsafe { std::mem::zeroed() };
        let mut err = [0 as c_char; 512];
        let rc = unsafe { lt_torrent_trackers(s, h, &mut list, err.as_mut_ptr(), 512) };
        assert_eq!(rc, LT_OK as i32, "lt_torrent_trackers: {}", c_buf(&err));
        let entries = unsafe { std::slice::from_raw_parts(list.entries, list.num_entries) };
        failed = entries.iter().find(|e| e.fails > 0).map(|e| {
            (
                c_buf(&e.url),
                c_buf(&e.last_error),
                e.next_announce,
                e.updating,
            )
        });
        unsafe { lt_tracker_list_free(&mut list) };
        if failed.is_some() {
            break;
        }
        // Drain alerts so the session's queue does not fill while we wait.
        let mut u: lt_alert_union = unsafe { std::mem::zeroed() };
        while unsafe { lt_pop_alert(s, &mut u) } == 1 {
            unsafe { lt_alert_payload_free(&mut u) };
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let (url, last_error, next_announce, _updating) =
        failed.expect("an announce to a closed port should fail within 30s");
    assert!(TRACKERS.contains(&url.as_str()), "unexpected url {url}");
    assert!(
        !last_error.is_empty(),
        "a failed announce carries its error"
    );
    assert!(
        next_announce >= started,
        "a failed tracker is scheduled for a retry, in unix seconds: {next_announce}"
    );
    unsafe { lt_session_destroy(s) };
}

#[test]
fn queries_on_unknown_or_removed_handles_fail_with_the_marker() {
    let s = make_session();
    let marker = std::str::from_utf8(LT_ERR_UNKNOWN_HANDLE_MSG)
        .unwrap()
        .trim_end_matches('\0')
        .to_string();
    let removed = add_file(s, &multi_file_tracker_torrent());
    assert_eq!(unsafe { lt_remove_torrent(s, removed, 0) }, LT_OK as i32);

    for h in [0, 999_999, removed] {
        let mut err = [0 as c_char; 512];
        let mut d: lt_torrent_details = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { lt_torrent_details(s, h, &mut d, err.as_mut_ptr(), 512) },
            LT_ERR
        );
        assert_eq!(c_buf(&err), marker);

        let mut err = [0 as c_char; 512];
        let mut files: lt_torrent_file_list = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { lt_torrent_files(s, h, &mut files, err.as_mut_ptr(), 512) },
            LT_ERR
        );
        assert_eq!(c_buf(&err), marker);
        assert!(files.files.is_null(), "no allocation on failure");

        let mut err = [0 as c_char; 512];
        let mut trackers: lt_tracker_list = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { lt_torrent_trackers(s, h, &mut trackers, err.as_mut_ptr(), 512) },
            LT_ERR
        );
        assert_eq!(c_buf(&err), marker);
        assert!(trackers.entries.is_null(), "no allocation on failure");
    }

    // Null session / out pointers must not dereference.
    let mut err = [0 as c_char; 512];
    assert_eq!(
        unsafe { lt_torrent_details(ptr::null_mut(), 1, ptr::null_mut(), err.as_mut_ptr(), 512,) },
        LT_ERR
    );
    assert_eq!(
        unsafe { lt_torrent_files(s, 1, ptr::null_mut(), err.as_mut_ptr(), 512) },
        LT_ERR
    );
    assert_eq!(
        unsafe { lt_torrent_trackers(s, 1, ptr::null_mut(), err.as_mut_ptr(), 512) },
        LT_ERR
    );
    unsafe { lt_session_destroy(s) };
}

// ---------------------------------------------------------------------------
// Add-time flags, handle ids, settings bounds
// ---------------------------------------------------------------------------

/// Pop alerts until `f` returns `Some`, freeing every payload, for up to ~5s.
fn wait_for<T>(s: *mut lt_session, mut f: impl FnMut(&lt_alert_union) -> Option<T>) -> Option<T> {
    for _ in 0..250 {
        let mut u: lt_alert_union = unsafe { std::mem::zeroed() };
        if unsafe { lt_pop_alert(s, &mut u) } == 1 {
            let got = f(&u);
            unsafe { lt_alert_payload_free(&mut u) };
            if got.is_some() {
                return got;
            }
        } else {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    None
}

/// The flags a state update reports for `h`, asking for one until it does.
fn status_flags(s: *mut lt_session, h: lt_handle) -> u32 {
    for _ in 0..20 {
        unsafe { lt_post_torrent_updates(s) };
        let flags = wait_for(s, |u| {
            if u.kind != lt_alert_kind_LT_ALERT_STATE_UPDATE {
                return None;
            }
            let su = unsafe { u.payload.state_update };
            if su.statuses.is_null() {
                return None;
            }
            let views = unsafe { std::slice::from_raw_parts(su.statuses, su.count) };
            views.iter().find(|v| v.handle == h).map(|v| v.flags)
        });
        if let Some(flags) = flags {
            return flags;
        }
    }
    panic!("no state update reported handle {h}");
}

/// Whatever the caller passes, every add leaves the torrent in upload mode
/// with none of the flags that could lift it.
#[test]
fn every_add_forces_upload_mode_and_clears_the_forbidden_flags() {
    let s = make_session();
    let forbidden = LT_TF_AUTO_MANAGED
        | LT_TF_SHARE_MODE
        | LT_TF_SUPER_SEEDING
        | LT_TF_SEQUENTIAL_DOWNLOAD
        | LT_TF_STOP_WHEN_READY;
    let bytes = multi_file_tracker_torrent();
    let save = CString::new("/tmp").unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_file(
            s,
            bytes.as_ptr(),
            bytes.len(),
            save.as_ptr(),
            LT_TF_PAUSED | forbidden,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "add failed: {}", c_buf(&err));
    let flags = status_flags(s, h);
    assert_ne!(flags & LT_TF_UPLOAD_MODE, 0, "flags={flags:#x}");
    assert_eq!(flags & forbidden, 0, "flags={flags:#x}");

    let uri = CString::new("magnet:?xt=urn:btih:0303030303030303030303030303030303030303").unwrap();
    let m = unsafe {
        lt_add_torrent_magnet(
            s,
            uri.as_ptr(),
            save.as_ptr(),
            LT_TF_PAUSED | forbidden,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(m, 0, "magnet add failed: {}", c_buf(&err));
    let flags = status_flags(s, m);
    assert_ne!(flags & LT_TF_UPLOAD_MODE, 0, "flags={flags:#x}");
    assert_eq!(flags & forbidden, 0, "flags={flags:#x}");
    unsafe { lt_session_destroy(s) };
}

/// Remove a torrent, let the alerts it posted before the removal drain, and
/// add the same info-hash again: the new id addresses the new torrent. It
/// used to resolve to the removed one, which a late alert had re-registered,
/// so every operation on the re-added torrent failed.
#[test]
fn a_re_added_info_hash_gets_a_live_handle() {
    let s = make_session();
    let bytes = multi_file_tracker_torrent();
    let first = add_file(s, &bytes);
    assert_eq!(unsafe { lt_remove_torrent(s, first, 0) }, LT_OK as i32);
    // Drain straight away, while the removed torrent still exists: its
    // add_torrent_alert is translated after the removal, then its
    // torrent_removed_alert.
    let removed = wait_for(s, |u| {
        (u.kind == lt_alert_kind_LT_ALERT_TORRENT_REMOVED).then_some(())
    });
    assert!(removed.is_some(), "no torrent_removed_alert");
    // Let libtorrent finish tearing the first torrent down.
    std::thread::sleep(std::time::Duration::from_millis(300));

    let again = add_file(s, &bytes);
    assert_eq!(
        unsafe { lt_save_resume_data(s, again, 0) },
        LT_OK as i32,
        "the re-added torrent's id addresses a live torrent"
    );
    let saved = wait_for(s, |u| match u.kind {
        k if k == lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA => Some(true),
        k if k == lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA_FAILED => Some(false),
        _ => None,
    });
    assert_eq!(
        saved,
        Some(true),
        "save_resume_data succeeds on the re-added torrent"
    );
    let mut d: lt_torrent_details = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    assert_eq!(
        unsafe { lt_torrent_details(s, again, &mut d, err.as_mut_ptr(), 512) },
        LT_OK as i32,
        "{}",
        c_buf(&err)
    );
    unsafe { lt_session_destroy(s) };
}

/// An integer setting outside `int` is refused, not narrowed into some other
/// value and applied.
#[test]
fn an_out_of_range_integer_setting_is_refused() {
    for json in [
        r#"{"connections_limit":4294967297}"#,
        r#"{"connections_limit":-2147483649}"#,
        r#"{"connections_limit":99999999999999999999999}"#,
    ] {
        let settings = CString::new(json).unwrap();
        let mut err = [0 as c_char; 512];
        let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
        assert!(s.is_null(), "{json} was accepted");
        assert!(
            c_buf(&err).contains("out of range"),
            "{json}: {}",
            c_buf(&err)
        );
    }
    let s = make_session();
    let settings = CString::new(r#"{"connections_limit":4294967297}"#).unwrap();
    let mut err = [0 as c_char; 512];
    assert_eq!(
        unsafe { lt_session_apply_settings(s, settings.as_ptr(), err.as_mut_ptr(), 512) },
        LT_ERR
    );
    assert!(c_buf(&err).contains("out of range"), "{}", c_buf(&err));
    unsafe { lt_session_destroy(s) };
}
