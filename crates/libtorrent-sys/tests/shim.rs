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
