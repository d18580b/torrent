//! Layer 2 shim FFI tests.
//!
//! Run with: `cargo test -p libtorrent-sys --features shim-tests`
//!
//! The assertions cover struct marshalling, exception isolation, null-handle
//! safety, and buffer ownership against a real libtorrent session listening
//! on loopback only. Ownership is checked by what the tests can observe — a
//! buffer readable for its whole length, released through the shim's own
//! free — and not by a sanitizer: AddressSanitizer instrumentation is a
//! follow-up (see build.rs for why instrumenting only the shim doesn't link on
//! this toolchain), so a double free or a leak goes undetected here.

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
            std::ptr::null(),
            std::ptr::null(),
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
    assert_eq!(
        unsafe { lt_torrent_unset_flags(s, 999_999, LT_TF_DISABLE_DHT) },
        LT_ERR
    );
    assert_eq!(
        unsafe { lt_torrent_unset_flags(ptr::null_mut(), 1, LT_TF_DISABLE_DHT) },
        LT_ERR
    );
    assert_eq!(unsafe { lt_torrent_force_recheck(s, 0) }, LT_ERR);
    assert_eq!(unsafe { lt_torrent_force_recheck(s, 999_999) }, LT_ERR);
    assert_eq!(
        unsafe { lt_torrent_force_recheck(ptr::null_mut(), 1) },
        LT_ERR
    );
    let ip = CString::new("127.0.0.1").unwrap();
    assert_eq!(
        unsafe { lt_test_connect_peer(s, 999_999, ip.as_ptr(), 1) },
        LT_ERR
    );
    assert_eq!(
        unsafe { lt_test_connect_peer(ptr::null_mut(), 1, ip.as_ptr(), 1) },
        LT_ERR
    );
    let mut downloaded = 7u64;
    assert_eq!(
        unsafe { lt_test_total_payload_download(s, 999_999, &mut downloaded) },
        LT_ERR
    );
    assert_eq!(
        unsafe { lt_test_total_payload_download(ptr::null_mut(), 1, &mut downloaded) },
        LT_ERR
    );
    assert_eq!(downloaded, 7, "a refused read leaves *out alone");
    unsafe { lt_session_destroy(s) };
}

/// The test-only peer API on a live torrent: a fresh torrent has taken no
/// payload, a numeric address is accepted, and anything else is refused.
#[test]
fn the_test_peer_api_reads_zero_and_refuses_a_bad_address() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    let mut downloaded = u64::MAX;
    assert_eq!(
        unsafe { lt_test_total_payload_download(s, h, &mut downloaded) },
        LT_OK as i32
    );
    assert_eq!(downloaded, 0);
    for ok in ["127.0.0.1", "::1"] {
        let ip = CString::new(ok).unwrap();
        assert_eq!(
            unsafe { lt_test_connect_peer(s, h, ip.as_ptr(), 1) },
            LT_OK as i32,
            "{ok}"
        );
    }
    for bad in ["localhost", "", "127.0.0.1:1"] {
        let ip = CString::new(bad).unwrap();
        assert_eq!(
            unsafe { lt_test_connect_peer(s, h, ip.as_ptr(), 1) },
            LT_ERR,
            "{bad:?}"
        );
    }
    assert_eq!(
        unsafe { lt_test_connect_peer(s, h, ptr::null(), 1) },
        LT_ERR
    );
    unsafe { lt_session_destroy(s) };
}

/// A fresh session has dropped no alert in translation, a null one reads 0,
/// and an ordinary drain leaves the count where it was.
#[test]
fn translate_errors_starts_at_zero() {
    assert_eq!(unsafe { lt_alert_translate_errors(ptr::null_mut()) }, 0);
    let s = make_session();
    assert_eq!(unsafe { lt_alert_translate_errors(s) }, 0);
    let _h = add_file(s, &multi_file_tracker_torrent());
    let added = wait_for(s, |u| {
        (u.kind == lt_alert_kind_LT_ALERT_ADD_TORRENT).then_some(())
    });
    assert!(added.is_some(), "no add_torrent_alert");
    assert_eq!(unsafe { lt_alert_translate_errors(s) }, 0);
    unsafe { lt_session_destroy(s) };
}

/// `lt_torrent_unset_flags` clears the discovery guards and refuses every
/// other bit, upload mode first among them, without touching the torrent.
#[test]
fn unset_flags_clears_only_the_discovery_guards() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    let guards = LT_TF_DISABLE_PEX | LT_TF_DISABLE_DHT | LT_TF_DISABLE_LSD;
    assert_eq!(
        unsafe { lt_torrent_unset_flags(s, h, guards) },
        LT_OK as i32
    );
    assert_eq!(unsafe { lt_torrent_unset_flags(s, h, 0) }, LT_OK as i32);
    for refused in [
        LT_TF_UPLOAD_MODE,
        LT_TF_PAUSED,
        LT_TF_SEED_MODE,
        LT_TF_DISABLE_DHT | LT_TF_UPLOAD_MODE,
    ] {
        assert_eq!(
            unsafe { lt_torrent_unset_flags(s, h, refused) },
            LT_ERR,
            "bits {refused:#x} must be refused",
        );
    }
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
    // The buffer is the caller's: readable for its whole length, and what it
    // holds is the bencoded dict lt_session_create_with_state reads back.
    let state = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    assert_eq!(
        (state[0], state[len - 1]),
        (b'd', b'e'),
        "state is a bencoded dict: {}",
        String::from_utf8_lossy(&state)
    );
    let restored = create_with_state(Some(&state)).expect("the saved state is accepted");
    unsafe { lt_session_destroy(restored) };
    // Released through the shim's own free, never Rust's allocator. Nothing
    // here detects a double free or a leak: the shim is not built under a
    // sanitizer (see the module comment).
    unsafe { lt_buf_free(buf) };
    unsafe { lt_session_destroy(s) };
}

/// `lt_session_create_with_state` on `state` (None: a null buffer), with the
/// no-network settings. `Err` carries err_out.
fn create_with_state(state: Option<&[u8]>) -> Result<*mut lt_session, String> {
    let settings = CString::new(NO_NET).unwrap();
    let (ptr, len) = state.map_or((ptr::null(), 0), |b| (b.as_ptr(), b.len()));
    let mut err = [0 as c_char; 512];
    let s =
        unsafe { lt_session_create_with_state(settings.as_ptr(), ptr, len, err.as_mut_ptr(), 512) };
    if s.is_null() {
        Err(c_buf(&err))
    } else {
        Ok(s)
    }
}

/// The state a session saves, copied out and freed.
fn saved_state(s: *mut lt_session) -> Vec<u8> {
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_session_save_state(s, &mut buf, &mut len, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "{}", c_buf(&err));
    let state = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    unsafe { lt_buf_free(buf) };
    state
}

/// A session restored from saved state saves state of its own again, and a
/// blob that is not bencode is refused with a reason, not unwound across the
/// boundary or turned into a session with whatever the parse left.
#[test]
fn create_with_state_round_trips_and_refuses_garbage() {
    let first = make_session();
    let state = saved_state(first);
    unsafe { lt_session_destroy(first) };

    let restored = create_with_state(Some(&state)).expect("saved state is accepted");
    let again = saved_state(restored);
    assert!(
        again.starts_with(b"d") && again.ends_with(b"e"),
        "{}",
        String::from_utf8_lossy(&again)
    );
    unsafe { lt_session_destroy(restored) };

    // A null buffer is lt_session_create.
    let plain = create_with_state(None).expect("no state is a fresh session");
    unsafe { lt_session_destroy(plain) };

    let truncated = &state[..state.len() / 2];
    for garbage in [&b"this is not bencode"[..], truncated] {
        let err = create_with_state(Some(garbage)).expect_err("garbage state must be refused");
        assert!(!err.is_empty(), "err_out names the parse failure");
    }
}

#[test]
fn magnet_info_hashes_marshal_v1_and_v2() {
    let mut err = [0 as c_char; 512];

    let uri = CString::new("magnet:?xt=urn:btih:0101010101010101010101010101010101010101").unwrap();
    let mut out: lt_info_hashes = unsafe { std::mem::zeroed() };
    let rc = unsafe { lt_magnet_info_hashes(uri.as_ptr(), &mut out, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32);
    assert_eq!((out.has_v1, out.has_v2), (1, 0));
    assert_eq!(out.v1, [0x01u8; 20]);
    assert_eq!(out.v2, [0u8; 32], "v2 hash must be zeroed");

    // A hybrid magnet names both: btih and a btmh multihash (0x1220 prefix).
    let uri = CString::new(format!(
        "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}",
        "02".repeat(20),
        "03".repeat(32)
    ))
    .unwrap();
    let rc = unsafe { lt_magnet_info_hashes(uri.as_ptr(), &mut out, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32);
    assert_eq!((out.has_v1, out.has_v2), (1, 1));
    assert_eq!(out.v1, [0x02u8; 20]);
    assert_eq!(out.v2, [0x03u8; 32]);
}

#[test]
fn torrent_info_hashes_report_both_hashes_of_a_hybrid() {
    let bytes = vendored_torrent("v2.torrent");
    let mut out: lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_info_hashes(bytes.as_ptr(), bytes.len(), &mut out, err.as_mut_ptr(), 512)
    };
    assert_eq!(rc, LT_OK as i32);
    assert_eq!((out.has_v1, out.has_v2), (1, 1), "v2.torrent is a hybrid");
    assert_eq!(
        hex_of(&out.v2),
        "597b180c1a170a585dfc5e85d834d69013ceda174b8f357d5bb1a0ca509faf0a",
    );
    assert_ne!(out.v1, [0u8; 20]);
}

/// A hybrid `.torrent` is keyed by its v1 hash, not libtorrent's
/// `get_best()` (the truncated v2 one): the key a btih-only magnet for the
/// same torrent has, and the one it keeps once its metadata arrives.
#[test]
fn a_hybrid_file_add_reports_its_v1_hash() {
    let bytes = vendored_torrent("v2.torrent");
    let mut hashes: lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_info_hashes(
            bytes.as_ptr(),
            bytes.len(),
            &mut hashes,
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(rc, LT_OK as i32);

    let s = make_session();
    let save = CString::new("/tmp").unwrap();
    let mut ih = [0u8; 20];
    let h = unsafe {
        lt_add_torrent_file(
            s,
            bytes.as_ptr(),
            bytes.len(),
            save.as_ptr(),
            LT_TF_PAUSED,
            std::ptr::null(),
            std::ptr::null(),
            0,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "add .torrent failed: {}", c_buf(&err));
    assert_eq!(ih, hashes.v1, "the add reports the v1 hash");
    unsafe { lt_session_destroy(s) };
}

/// `lt_add_info_hashes` reports the hashes the resume add keys the torrent
/// by: with a hybrid `.torrent` attached to v2-only resume data, the add
/// keys it by the `.torrent`'s v1 hash, not the truncated v2 hash the resume
/// data alone names; without the `.torrent`, the truncated v2 hash, and no
/// metadata. A `.torrent` naming another torrent than the resume data is
/// refused, as the add refuses it.
#[test]
fn add_info_hashes_report_the_key_the_resume_add_gives() {
    // In the repository rather than the vendor corpus, so the test runs
    // without the submodules.
    let torrent = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../torrentd-pool/tests/fixtures/v2_hybrid.torrent"),
    )
    .expect("read the hybrid fixture");
    let mut hashes: lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_info_hashes(
            torrent.as_ptr(),
            torrent.len(),
            &mut hashes,
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(rc, LT_OK as i32, "{}", c_buf(&err));
    let mut resume = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
    resume.extend_from_slice(b"10:info-hash232:");
    resume.extend_from_slice(&hashes.v2);
    resume.extend_from_slice(b"9:save_path4:/tmpe");

    let read = |resume: &[u8], torrent: &[u8]| {
        let mut out: lt_info_hashes = unsafe { std::mem::zeroed() };
        let mut has_metadata = -1;
        let mut err = [0 as c_char; 512];
        let rc = unsafe {
            lt_add_info_hashes(
                ptr::null(),
                if torrent.is_empty() {
                    ptr::null()
                } else {
                    torrent.as_ptr()
                },
                torrent.len(),
                resume.as_ptr(),
                resume.len(),
                &mut out,
                &mut has_metadata,
                err.as_mut_ptr(),
                512,
            )
        };
        (rc, out, has_metadata, c_buf(&err))
    };

    let (rc, out, has_metadata, err_text) = read(&resume, &torrent);
    assert_eq!(rc, LT_OK as i32, "{err_text}");
    assert_eq!(has_metadata, 1);
    assert_eq!((out.has_v1, out.has_v2), (1, 1));
    assert_eq!((out.v1, out.v2), (hashes.v1, hashes.v2));

    let (rc, out, has_metadata, err_text) = read(&resume, &[]);
    assert_eq!(rc, LT_OK as i32, "{err_text}");
    assert_eq!(has_metadata, 0);
    assert_eq!((out.has_v1, out.has_v2), (0, 1));
    assert_eq!(out.v1, [0u8; 20], "v1 hash must be zeroed");

    // The add itself keys it by the attached `.torrent`'s v1 hash.
    let s = make_session();
    let mut ih = [0u8; 20];
    let h = unsafe {
        lt_add_torrent_resume_ex(
            s,
            resume.as_ptr(),
            resume.len(),
            torrent.as_ptr(),
            torrent.len(),
            ptr::null(),
            0,
            0,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "resume add failed: {}", c_buf(&err));
    assert_eq!(ih, hashes.v1, "the resume add reports the v1 hash");
    unsafe { lt_session_destroy(s) };

    // Resume data naming another torrent than the `.torrent` attached to it.
    let mut other = b"d11:file-format22:libtorrent resume file12:file-versioni1e".to_vec();
    other.extend_from_slice(b"9:info-hash20:");
    other.extend_from_slice(&[0x05u8; 20]);
    other.extend_from_slice(b"9:save_path4:/tmpe");
    let (rc, out, has_metadata, err_text) = read(&other, &torrent);
    assert_eq!(rc, LT_ERR, "a mismatched .torrent must be refused");
    assert!(!err_text.is_empty());
    assert_eq!((out.has_v1, out.has_v2, has_metadata), (0, 0, 0));
}

#[test]
fn torrent_info_hashes_bad_buffer_errors_cleanly() {
    let garbage = b"nope";
    let mut out: lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_info_hashes(
            garbage.as_ptr(),
            garbage.len(),
            &mut out,
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

/// A shim string returned as a pointer and a length. The NUL after the
/// `len` bytes is part of the contract, so it is asserted here too.
fn sized_c_str(ptr: *const c_char, len: usize) -> String {
    assert!(!ptr.is_null(), "a returned string must not be null");
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(ptr as *const u8, len + 1) };
    assert_eq!(bytes[len], 0, "a returned string must be NUL-terminated");
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn meta_file_path(f: &lt_torrent_meta_file) -> String {
    sized_c_str(f.path, f.path_len)
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
    assert_eq!(sized_c_str(meta.name, meta.name_len), "test64K");
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
    assert!(meta.strings.is_null() && meta.name.is_null() && meta.files.is_null());
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
fn metadata_flags_padding_files() {
    // pad_file.torrent carries a BEP 47 padding entry with a non-zero size,
    // which never exists on disk; the pool matcher skips it by this flag.
    let bytes = vendored_torrent("pad_file.torrent");
    let mut meta = parse_meta(&bytes);
    let files = unsafe { std::slice::from_raw_parts(meta.files, meta.num_files) };
    let pads: Vec<_> = files.iter().filter(|f| f.pad_file == 1).collect();
    assert!(
        !pads.is_empty(),
        "the fixture's padding entry must be flagged"
    );
    assert!(
        pads.iter().all(|f| f.size > 0),
        "padding files carry a size"
    );
    assert!(
        files.iter().any(|f| f.pad_file == 0),
        "real files must not be flagged",
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
    assert!(
        meta.strings.is_null(),
        "no allocation should leak on failure"
    );

    // Null args must not dereference.
    assert_eq!(
        unsafe { lt_torrent_metadata(ptr::null(), 0, &mut meta, err.as_mut_ptr(), 512) },
        LT_ERR,
    );
    unsafe { lt_torrent_meta_free(ptr::null_mut()) };
}

/// A v1 multi-file `.torrent` declaring `count` one-byte files at the top
/// level. The piece hashes are filler: only the parse is under test.
fn v1_torrent_with_files(count: usize) -> Vec<u8> {
    const PIECE_LEN: usize = 16 * 1024;
    let num_pieces = count.div_ceil(PIECE_LEN);
    let mut out = Vec::with_capacity(count * 32 + 1024);
    out.extend_from_slice(b"d4:infod5:filesl");
    for i in 0..count {
        let name = format!("f{i}");
        out.extend_from_slice(format!("d6:lengthi1e4:pathl{}:{name}ee", name.len()).as_bytes());
    }
    out.extend_from_slice(b"e4:name4:many");
    out.extend_from_slice(format!("12:piece lengthi{PIECE_LEN}e").as_bytes());
    out.extend_from_slice(format!("6:pieces{}:", num_pieces * 20).as_bytes());
    out.extend(std::iter::repeat_n(0xAB_u8, num_pieces * 20));
    out.extend_from_slice(b"ee");
    out
}

#[test]
fn metadata_refuses_more_than_the_file_cap_and_leaves_out_owning_nothing() {
    let count = LT_MAX_TORRENT_FILES as usize + 1;
    let bytes = v1_torrent_with_files(count);
    // Non-null sentinels: the refusal must overwrite them, not leave a
    // caller holding pointers it would free.
    let mut meta: lt_torrent_meta = unsafe { std::mem::zeroed() };
    meta.files = ptr::dangling_mut();
    meta.strings = ptr::dangling_mut();
    meta.name = ptr::dangling();
    meta.num_files = 7;
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
    assert_eq!(rc, LT_ERR, "a manifest over the file cap must be refused");
    assert!(
        c_buf(&err).contains("implausible number of files"),
        "the refusal should be the file-cap one, got {:?}",
        c_buf(&err),
    );
    assert!(meta.files.is_null(), "a refusal must leave files null");
    assert!(meta.strings.is_null(), "a refusal must leave strings null");
    assert!(meta.name.is_null(), "a refusal must leave name null");
    assert_eq!(meta.num_files, 0);
    // Freeing the zeroed result is a no-op, as every caller's error path does.
    unsafe { lt_torrent_meta_free(&mut meta) };

    // The cap itself is accepted, so the refusal above is the count check
    // and not libtorrent failing to parse a manifest this large.
    let mut at_cap = parse_meta(&v1_torrent_with_files(count - 1));
    assert_eq!(at_cap.num_files, count - 1);
    unsafe { lt_torrent_meta_free(&mut at_cap) };
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
    add_file_at(s, bytes, "/tmp")
}

/// Added paused, so libtorrent creates nothing under `save_path`.
fn add_file_at(s: *mut lt_session, bytes: &[u8], save_path: &str) -> lt_handle {
    let save = CString::new(save_path).unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_file(
            s,
            bytes.as_ptr(),
            bytes.len(),
            save.as_ptr(),
            LT_TF_PAUSED,
            std::ptr::null(),
            std::ptr::null(),
            0,
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

/// `lt_torrent_details`, copied out and freed.
struct Details {
    name: String,
    save_path: String,
    total_size: u64,
    added_time: i64,
    upload_limit: u32,
    has_metadata: u8,
}

fn details(s: *mut lt_session, h: lt_handle) -> Details {
    let mut d: lt_torrent_details = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_torrent_details(s, h, &mut d, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_details: {}", c_buf(&err));
    let out = Details {
        name: sized_c_str(d.name, d.name_len),
        save_path: sized_c_str(d.save_path, d.save_path_len),
        total_size: d.total_size,
        added_time: d.added_time,
        upload_limit: d.upload_limit,
        has_metadata: d.has_metadata,
    };
    unsafe { lt_torrent_details_free(&mut d) };
    assert!(d.strings.is_null() && d.name.is_null() && d.save_path.is_null());
    // Idempotent, and safe on null.
    unsafe { lt_torrent_details_free(&mut d) };
    unsafe { lt_torrent_details_free(ptr::null_mut()) };
    out
}

/// A v1 single-root `.torrent` whose one file sits under directories deep
/// enough to push its torrent-relative path past the 1 023 bytes the shim's
/// fixed path buffers used to hold. Every component stays under the 255-byte
/// file-name limit, so the path is one a filesystem can hold.
fn long_path_torrent() -> (Vec<u8>, String) {
    let dirs: Vec<String> = (0..6).map(|i| format!("{i}{}", "d".repeat(199))).collect();
    let bstr = |s: &str| format!("{}:{s}", s.len());
    let mut path = String::new();
    for d in &dirs {
        path.push_str(&bstr(d));
    }
    path.push_str(&bstr("leaf.bin"));
    let mut out = Vec::new();
    out.extend_from_slice(b"d4:infod5:filesl");
    out.extend_from_slice(format!("d6:lengthi1000e4:pathl{path}ee").as_bytes());
    out.extend_from_slice(b"e");
    out.extend_from_slice(format!("4:name{}", bstr("long-root")).as_bytes());
    out.extend_from_slice(b"12:piece lengthi16384e");
    out.extend_from_slice(b"6:pieces20:");
    out.extend(std::iter::repeat_n(0xAB_u8, 20));
    out.extend_from_slice(b"ee");
    let rel = format!("long-root/{}/leaf.bin", dirs.join("/"));
    (out, rel)
}

#[test]
fn files_and_details_return_paths_past_the_old_buffer_whole() {
    let (bytes, rel) = long_path_torrent();
    assert!(rel.len() > 1_023, "the path must outgrow the old buffer");
    // Never created: the torrent is added paused.
    let deep = format!("/tmp/{}", vec!["s".repeat(200); 6].join("/"));
    assert!(
        deep.len() > 1_023,
        "the save path must outgrow the old buffer"
    );
    let s = make_session();
    let h = add_file_at(s, &bytes, &deep);

    let mut list: lt_torrent_file_list = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_torrent_files(s, h, 0, usize::MAX, &mut list, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_files: {}", c_buf(&err));
    assert_eq!(list.num_files, 1);
    let f = unsafe { &*list.files };
    assert_eq!(f.path_len, rel.len());
    assert_eq!(sized_c_str(f.path, f.path_len), rel);
    unsafe { lt_torrent_file_list_free(&mut list) };
    assert!(list.files.is_null() && list.strings.is_null());

    let d = details(s, h);
    assert_eq!(d.save_path, deep);
    assert_eq!(d.name, "long-root");
    unsafe { lt_session_destroy(s) };
}

#[test]
fn storage_moved_reports_a_destination_past_the_old_buffer_whole() {
    // The relocation step records this path as the torrent's base and its
    // boot-scan save path, so a cut one would name another directory.
    let base = std::env::temp_dir().join(format!("lt-shim-long-move-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let dst = base.join(vec!["m".repeat(200); 6].join("/"));
    let dst = dst.to_str().unwrap().to_owned();
    assert!(
        dst.len() > 1_023,
        "the destination must outgrow the old buffer"
    );

    let (bytes, _) = long_path_torrent();
    let s = make_session();
    let h = add_file_at(s, &bytes, src.to_str().unwrap());
    let want = CString::new(dst.clone()).unwrap();
    let rc = unsafe { lt_torrent_move_storage(s, h, want.as_ptr(), LT_MOVE_DONT_REPLACE) };
    assert_eq!(rc, LT_OK as i32);

    let moved = wait_for(s, |u| {
        if u.kind == lt_alert_kind_LT_ALERT_STORAGE_MOVED_FAILED {
            let p = unsafe { &u.payload.storage_moved_failed };
            panic!("move failed: {}", c_buf(&p.message));
        }
        (u.kind == lt_alert_kind_LT_ALERT_STORAGE_MOVED && u.handle == h).then(|| {
            let p = unsafe { &u.payload.storage_moved };
            (p.path_len, sized_c_str(p.path, p.path_len))
        })
    });
    assert_eq!(moved, Some((dst.len(), dst.clone())));
    // The session serves from the whole path too.
    assert_eq!(details(s, h).save_path, dst);
    unsafe { lt_session_destroy(s) };
    let _ = std::fs::remove_dir_all(&base);
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
    assert_eq!(d.name, "pending-name", "dn= is the name until metadata");
    assert_eq!(d.save_path, "/tmp");
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
    assert_eq!(d.name, "multi-root");

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
        let rc = unsafe { lt_torrent_files(s, h, 0, usize::MAX, &mut list, err.as_mut_ptr(), 512) };
        assert_eq!(rc, LT_OK as i32, "lt_torrent_files: {}", c_buf(&err));
        assert_eq!(list.has_metadata, 1);
        assert_eq!(list.num_files, 3);
        let files = unsafe { std::slice::from_raw_parts(list.files, list.num_files) };
        got = files
            .iter()
            .map(|f| {
                (
                    sized_c_str(f.path, f.path_len),
                    f.size,
                    f.downloaded,
                    f.priority,
                )
            })
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
fn files_page_copies_only_the_requested_range_and_reports_the_total() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    // (start, limit) -> (first_index, paths)
    let page = |start: usize, limit: usize| {
        let mut list: lt_torrent_file_list = unsafe { std::mem::zeroed() };
        let mut err = [0 as c_char; 512];
        let rc = unsafe { lt_torrent_files(s, h, start, limit, &mut list, err.as_mut_ptr(), 512) };
        assert_eq!(rc, LT_OK as i32, "lt_torrent_files: {}", c_buf(&err));
        assert_eq!(list.has_metadata, 1);
        assert_eq!(
            list.total_files, 3,
            "the whole torrent's count, whatever the page"
        );
        let paths: Vec<String> = if list.num_files == 0 {
            assert!(list.files.is_null(), "an empty page allocates nothing");
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(list.files, list.num_files) }
                .iter()
                .map(|f| sized_c_str(f.path, f.path_len))
                .collect()
        };
        let first = list.first_index;
        unsafe { lt_torrent_file_list_free(&mut list) };
        (first, paths)
    };
    assert_eq!(
        page(1, 1),
        (1, vec!["multi-root/docs/notes.txt".to_string()])
    );
    assert_eq!(
        page(1, 100),
        (
            1,
            vec![
                "multi-root/docs/notes.txt".to_string(),
                "multi-root/data/blob.bin".to_string()
            ]
        )
    );
    // A count alone, and a start at or past the end: empty, not an error.
    assert_eq!(page(0, 0), (0, vec![]));
    assert_eq!(page(3, 10), (3, vec![]));
    assert_eq!(page(usize::MAX, usize::MAX), (3, vec![]));
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
    let rc = unsafe { lt_torrent_files(s, h, 0, usize::MAX, &mut list, err.as_mut_ptr(), 512) };
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

/// `lt_torrent_statuses` reports every torrent the session holds, under the
/// handle it was added with, paused or not, and owns nothing on an empty
/// session or a refused call.
#[test]
fn statuses_report_every_torrent_under_its_handle() {
    let s = make_session();
    let mut list: lt_status_list = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];

    let rc = unsafe { lt_torrent_statuses(s, &mut list, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_statuses: {}", c_buf(&err));
    assert!(list.statuses.is_null() && list.count == 0, "empty session");

    let h = add_file(s, &multi_file_tracker_torrent());
    let rc = unsafe { lt_torrent_statuses(s, &mut list, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_statuses: {}", c_buf(&err));
    let views = unsafe { std::slice::from_raw_parts(list.statuses, list.count) };
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].handle, h);
    assert_ne!(views[0].infohash, [0u8; 20]);
    assert_ne!(views[0].flags & LT_TF_PAUSED, 0, "added paused");

    unsafe { lt_status_list_free(&mut list) };
    assert!(list.statuses.is_null() && list.count == 0);
    unsafe { lt_status_list_free(&mut list) };
    unsafe { lt_status_list_free(ptr::null_mut()) };

    assert_eq!(
        unsafe { lt_torrent_statuses(ptr::null_mut(), &mut list, err.as_mut_ptr(), 512) },
        LT_ERR
    );
    assert_eq!(
        unsafe { lt_torrent_statuses(s, ptr::null_mut(), err.as_mut_ptr(), 512) },
        LT_ERR
    );
    unsafe { lt_session_destroy(s) };
}

/// A tracker error carries the category its code belongs to: an announce to
/// a closed loopback port is refused with an `errno`, in the system category,
/// and was not cancelled.
#[test]
fn a_refused_announce_reports_a_system_category_error_not_an_abort() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    assert_eq!(unsafe { lt_torrent_resume(s, h) }, LT_OK as i32);
    assert_eq!(unsafe { lt_torrent_force_reannounce(s, h) }, LT_OK as i32);

    let got = wait_for(s, |u| {
        if u.kind != lt_alert_kind_LT_ALERT_TRACKER_ERROR {
            return None;
        }
        let e = unsafe { u.payload.tracker_error };
        Some((e.error_code, e.error_category, e.aborted))
    });
    let (code, category, aborted) = got.expect("no tracker_error alert");
    assert_ne!(code, 0);
    assert_eq!(
        category as u32, lt_error_category_LT_ERROR_CATEGORY_SYSTEM,
        "code {code}"
    );
    assert_eq!(aborted, 0, "a refused announce is not a cancelled one");
    unsafe { lt_session_destroy(s) };
}

/// Add [`multi_file_tracker_torrent`] with `url` as its only tracker, start
/// it, and return the first tracker error's code, category and abort flag.
fn first_tracker_error_announcing_to(url: &str) -> (i32, i32, u8) {
    let s = make_session();
    let bytes = multi_file_tracker_torrent();
    let url = CString::new(url).unwrap();
    let ptrs = [url.as_ptr()];
    let tiers = [0i32];
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
            ptrs.as_ptr(),
            tiers.as_ptr(),
            ptrs.len(),
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "add .torrent failed: {}", c_buf(&err));
    assert_eq!(unsafe { lt_torrent_resume(s, h) }, LT_OK as i32);
    assert_eq!(unsafe { lt_torrent_force_reannounce(s, h) }, LT_OK as i32);
    let got = wait_for(s, |u| {
        if u.kind != lt_alert_kind_LT_ALERT_TRACKER_ERROR {
            return None;
        }
        let e = unsafe { u.payload.tracker_error };
        Some((e.error_code, e.error_category, e.aborted))
    });
    unsafe { lt_session_destroy(s) };
    got.expect("no tracker_error alert")
}

/// A tracker URL whose scheme libtorrent has no connection for fails with
/// `errors::unsupported_url_protocol`, in the libtorrent category.
#[test]
fn an_unsupported_tracker_scheme_reports_a_libtorrent_category_error() {
    let (code, category, aborted) = first_tracker_error_announcing_to("gopher://127.0.0.1:1/");
    assert_eq!(
        category as u32, lt_error_category_LT_ERROR_CATEGORY_LIBTORRENT,
        "code {code}"
    );
    assert_ne!(code, 0);
    assert_eq!(aborted, 0);
}

/// An HTTP tracker that answers with a non-200 status fails with that status,
/// in the HTTP category.
#[test]
fn an_http_tracker_status_reports_an_http_category_error() {
    use std::io::Read;
    use std::io::Write;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf);
        let _ = conn.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    });
    let (code, category, aborted) =
        first_tracker_error_announcing_to(&format!("http://127.0.0.1:{port}/announce"));
    server.join().unwrap();
    assert_eq!(
        category as u32, lt_error_category_LT_ERROR_CATEGORY_HTTP,
        "code {code}"
    );
    assert_eq!(code, 404);
    assert_eq!(aborted, 0);
}

/// Trackers given with a `.torrent` add replace its announce list, tiers
/// kept, the way a resume file's `trackers` list does.
#[test]
fn a_file_add_announces_to_the_trackers_given_in_place_of_its_own() {
    let s = make_session();
    let bytes = multi_file_tracker_torrent();
    let urls = [
        CString::new("http://a.override.example:9/announce").unwrap(),
        CString::new("").unwrap(),
        CString::new("http://b.override.example:10/announce").unwrap(),
    ];
    let ptrs: Vec<*const c_char> = urls.iter().map(|c| c.as_ptr()).collect();
    let tiers = [0i32, 0, 1];
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
            ptrs.as_ptr(),
            tiers.as_ptr(),
            ptrs.len(),
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "add .torrent failed: {}", c_buf(&err));

    let mut list: lt_tracker_list = unsafe { std::mem::zeroed() };
    let rc = unsafe { lt_torrent_trackers(s, h, &mut list, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_trackers: {}", c_buf(&err));
    let entries = unsafe { std::slice::from_raw_parts(list.entries, list.num_entries) };
    let got: Vec<(String, u8)> = entries.iter().map(|e| (c_buf(&e.url), e.tier)).collect();
    // None of the `.torrent`'s own, and the empty URL is skipped.
    assert_eq!(
        got,
        vec![
            ("http://a.override.example:9/announce".to_string(), 0),
            ("http://b.override.example:10/announce".to_string(), 1),
        ]
    );
    unsafe { lt_tracker_list_free(&mut list) };

    // The guard reads the same list: the override's domain admits it, and
    // the `.torrent`'s own (all on 127.0.0.1) no longer count.
    let overrides = CString::new("override.example").unwrap();
    let own = CString::new("127.0.0.1").unwrap();
    let mut allowed = |csv: &CString, n: usize| unsafe {
        lt_add_trackers_allowed(
            ptr::null(),
            bytes.as_ptr(),
            bytes.len(),
            ptrs.as_ptr(),
            tiers.as_ptr(),
            n,
            ptr::null(),
            0,
            csv.as_ptr(),
            ptr::null(),
            0,
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(allowed(&overrides, ptrs.len()), 1);
    assert_eq!(allowed(&own, ptrs.len()), 0);
    // None given: the `.torrent`'s own.
    assert_eq!(allowed(&own, 0), 1);
    assert_eq!(allowed(&overrides, 0), 0);
    unsafe { lt_session_destroy(s) };
}

/// A source announcing to nothing is told apart from one announcing
/// somewhere it may not.
#[test]
fn the_tracker_guard_reports_no_trackers_on_its_own() {
    let uri = CString::new("magnet:?xt=urn:btih:0404040404040404040404040404040404040404").unwrap();
    let domains = CString::new("example.com").unwrap();
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_add_trackers_allowed(
            uri.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            domains.as_ptr(),
            ptr::null(),
            0,
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(rc, LT_NO_TRACKERS as i32, "{}", c_buf(&err));
}

/// With an account binding, a tracker on an allowed host under another
/// account's passkey is told apart from a foreign tracker.
#[test]
fn the_tracker_guard_holds_a_tracker_to_the_account_prefixes() {
    let enc = |u: &str| {
        u.replace(':', "%3A")
            .replace('/', "%2F")
            .replace('?', "%3F")
    };
    let magnet = |tr: &str| {
        CString::new(format!(
            "magnet:?xt=urn:btih:0505050505050505050505050505050505050505&tr={}",
            enc(tr)
        ))
        .unwrap()
    };
    let domains = CString::new("tracker.example").unwrap();
    let prefix = CString::new("https://tracker.example/PASS-A/").unwrap();
    let prefixes = [prefix.as_ptr()];
    let mut err = [0 as c_char; 512];
    let mut verdict = |uri: &CString, n: usize| unsafe {
        lt_add_trackers_allowed(
            uri.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            domains.as_ptr(),
            prefixes.as_ptr(),
            n,
            err.as_mut_ptr(),
            512,
        )
    };
    let ours = magnet("https://tracker.example/PASS-A/announce");
    let theirs = magnet("https://tracker.example/PASS-B/announce");
    let foreign = magnet("https://other.example/PASS-A/announce");
    assert_eq!(verdict(&ours, 1), 1);
    assert_eq!(verdict(&theirs, 1), LT_TRACKER_ACCOUNT_MISMATCH as i32);
    assert_eq!(verdict(&foreign, 1), 0);
    // No binding: the host alone decides.
    assert_eq!(verdict(&theirs, 0), 1);
}

#[test]
fn an_announce_url_prefix_matches_at_a_boundary_only() {
    let has = |url: &str, prefix: &str| {
        let (u, p) = (CString::new(url).unwrap(), CString::new(prefix).unwrap());
        unsafe { lt_announce_url_has_prefix(u.as_ptr(), p.as_ptr()) == 1 }
    };
    let q = "https://t.example/announce.php?passkey=abc";
    assert!(has(q, q));
    assert!(has("https://t.example/announce.php?passkey=abc&x=1", q));
    assert!(!has("https://t.example/announce.php?passkey=abcd", q));
    // Scheme and authority case-insensitively, the rest exactly.
    assert!(has("HTTPS://T.Example/announce.php?passkey=abc", q));
    assert!(!has("https://t.example/announce.php?passkey=ABC", q));
    let p = "https://t.example/abc/";
    assert!(has("https://t.example/abc/announce", p));
    assert!(!has("https://t.example:443/abc/announce", p));
    assert!(!has("https://t.example.evil/abc/announce", p));
    assert!(!has("https://t.example@evil.example/abc/", p));
    assert!(!has("http://t.example/abc/announce", p));
    // A prefix with no path, or no scheme, matches nothing.
    assert!(!has("https://t.example/abc", "https://t.example"));
    assert!(!has("https://t.example/abc", "t.example/abc"));
    assert!(!has("https://t.example/abc", "https:///abc"));
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
                e.working,
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
    let (url, last_error, next_announce, working) =
        failed.expect("an announce to a closed port should fail within 30s");
    assert!(TRACKERS.contains(&url.as_str()), "unexpected url {url}");
    assert_eq!(working, 0, "no endpoint of a refused tracker works");
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
        assert!(d.strings.is_null(), "no allocation on failure");

        let mut err = [0 as c_char; 512];
        let mut files: lt_torrent_file_list = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { lt_torrent_files(s, h, 0, usize::MAX, &mut files, err.as_mut_ptr(), 512) },
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
        unsafe { lt_torrent_files(s, 1, 0, usize::MAX, ptr::null_mut(), err.as_mut_ptr(), 512) },
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
            std::ptr::null(),
            std::ptr::null(),
            0,
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
    unsafe { lt_torrent_details_free(&mut d) };
    unsafe { lt_session_destroy(s) };
}

/// Remove a torrent and add the same info-hash again before a single alert is
/// popped, then drain. The removed torrent's `add_torrent_alert` is translated
/// while the re-added entry is stored (a non-add registration, which keeps the
/// live entry), and its `torrent_removed_alert` names a torrent that is no
/// longer the stored one (which leaves the entry alone). The new id must
/// survive both.
#[test]
fn a_removal_drained_after_the_re_add_leaves_the_new_id_live() {
    let s = make_session();
    let bytes = multi_file_tracker_torrent();
    let first = add_file(s, &bytes);
    assert_eq!(unsafe { lt_remove_torrent(s, first, 0) }, LT_OK as i32);
    let again = add_file(s, &bytes);
    assert_ne!(again, first, "the re-add is registered under a fresh id");

    // Drain until the removal's alert has been translated, then whatever
    // follows it, so every alert either torrent posted has been through the
    // registry before the new id is used.
    let removed = wait_for(s, |u| {
        (u.kind == lt_alert_kind_LT_ALERT_TORRENT_REMOVED).then_some(())
    });
    assert!(removed.is_some(), "no torrent_removed_alert");
    let _ = wait_for(s, |_| None::<()>);

    let mut d: lt_torrent_details = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    assert_eq!(
        unsafe { lt_torrent_details(s, again, &mut d, err.as_mut_ptr(), 512) },
        LT_OK as i32,
        "the re-added id still resolves: {}",
        c_buf(&err)
    );
    unsafe { lt_torrent_details_free(&mut d) };
    assert_eq!(
        unsafe { lt_save_resume_data(s, again, 0) },
        LT_OK as i32,
        "the re-added id addresses a live torrent"
    );
    let saved = wait_for(s, |u| match u.kind {
        k if k == lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA => Some(true),
        k if k == lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA_FAILED => Some(false),
        _ => None,
    });
    assert_eq!(saved, Some(true), "save_resume_data succeeds on the re-add");
    unsafe { lt_session_destroy(s) };
}

/// Resume data for `ih` that says `auto_managed`, `share_mode`,
/// `super_seeding`, `sequential_download` and `stop_when_ready`, and not
/// `upload_mode`: everything another client's resume data could carry to take
/// a torrent out of upload mode.
fn resume_lifting_upload_mode(ih: &[u8; 20]) -> Vec<u8> {
    let mut resume = Vec::new();
    resume.extend_from_slice(b"d12:auto_managedi1e");
    resume.extend_from_slice(b"11:file-format22:libtorrent resume file");
    resume.extend_from_slice(b"12:file-versioni1e");
    resume.extend_from_slice(b"9:info-hash20:");
    resume.extend_from_slice(ih);
    resume.extend_from_slice(b"6:pausedi1e");
    resume.extend_from_slice(b"9:save_path4:/tmp");
    resume.extend_from_slice(b"19:sequential_downloadi1e");
    resume.extend_from_slice(b"10:share_modei1e");
    resume.extend_from_slice(b"15:stop_when_readyi1e");
    resume.extend_from_slice(b"13:super_seedingi1e");
    resume.extend_from_slice(b"11:upload_modei0e");
    resume.extend_from_slice(b"e");
    resume
}

/// `lt_add_torrent_resume_ex` with no overrides forces upload mode over
/// [`resume_lifting_upload_mode`]: alone, and with the `.torrent` the daemon
/// keeps beside resume data saved without its info dict.
#[test]
fn a_plain_resume_add_forces_upload_mode_over_the_resume_data() {
    let s = make_session();
    let torrent = multi_file_tracker_torrent();
    let mut hashes: lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    assert_eq!(
        unsafe {
            lt_torrent_info_hashes(
                torrent.as_ptr(),
                torrent.len(),
                &mut hashes,
                err.as_mut_ptr(),
                512,
            )
        },
        LT_OK as i32,
        "{}",
        c_buf(&err)
    );
    let forbidden = LT_TF_AUTO_MANAGED
        | LT_TF_SHARE_MODE
        | LT_TF_SUPER_SEEDING
        | LT_TF_SEQUENTIAL_DOWNLOAD
        | LT_TF_STOP_WHEN_READY;

    for (ih, torrent) in [([0x0Au8; 20], None), (hashes.v1, Some(&torrent[..]))] {
        let resume = resume_lifting_upload_mode(&ih);
        let (t_ptr, t_len) = torrent.map_or((ptr::null(), 0), |t| (t.as_ptr(), t.len()));
        let mut ih_out = [0u8; 20];
        let h = unsafe {
            lt_add_torrent_resume_ex(
                s,
                resume.as_ptr(),
                resume.len(),
                t_ptr,
                t_len,
                ptr::null(),
                0,
                0,
                ih_out.as_mut_ptr(),
                err.as_mut_ptr(),
                512,
            )
        };
        assert_ne!(h, 0, "resume add failed: {}", c_buf(&err));
        assert_eq!(ih_out, ih);
        if torrent.is_some() {
            assert_eq!(details(s, h).has_metadata, 1, "the .torrent was attached");
        }

        let flags = status_flags(s, h);
        assert_ne!(flags & LT_TF_UPLOAD_MODE, 0, "flags={flags:#x}");
        assert_eq!(flags & forbidden, 0, "flags={flags:#x}");
    }
    unsafe { lt_session_destroy(s) };
}

/// `force_recheck` drops seed mode — libtorrent re-learns which pieces it
/// has — and leaves upload mode where every add put it.
#[test]
fn recheck_keeps_upload_mode() {
    // libtorrent holds seed mode only for a running torrent whose payload is
    // on disk, so the single file exists at its full length and the add is
    // not paused (the torrent names no tracker, and the session dials no
    // peer). Its piece hash is filler: the recheck fails it, which is beside
    // the point.
    const LEN: usize = 1000;
    let dir = std::env::temp_dir().join(format!("shim-recheck-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload"), [0x5A_u8; LEN]).unwrap();
    let mut bytes =
        format!("d4:infod6:lengthi{LEN}e4:name7:payload12:piece lengthi16384e6:pieces20:")
            .into_bytes();
    bytes.extend_from_slice(&[0xAB; 20]);
    bytes.extend_from_slice(b"ee");

    let s = make_session();
    let save = CString::new(dir.to_str().unwrap()).unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_file(
            s,
            bytes.as_ptr(),
            bytes.len(),
            save.as_ptr(),
            LT_TF_SEED_MODE,
            std::ptr::null(),
            std::ptr::null(),
            0,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "add failed: {}", c_buf(&err));
    let before = status_flags(s, h);
    assert_eq!(
        before & (LT_TF_SEED_MODE | LT_TF_UPLOAD_MODE),
        LT_TF_SEED_MODE | LT_TF_UPLOAD_MODE,
        "flags={before:#x}"
    );

    assert_eq!(unsafe { lt_torrent_force_recheck(s, h) }, LT_OK as i32);
    let mut after = before;
    for _ in 0..50 {
        after = status_flags(s, h);
        if after & LT_TF_SEED_MODE == 0 {
            break;
        }
    }
    assert_eq!(
        after & LT_TF_SEED_MODE,
        0,
        "the recheck ran; flags={after:#x}"
    );
    assert_ne!(after & LT_TF_UPLOAD_MODE, 0, "flags={after:#x}");
    unsafe { lt_session_destroy(s) };
    let _ = std::fs::remove_dir_all(&dir);
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

// ---------------------------------------------------------------------------
// Web seeds
// ---------------------------------------------------------------------------

const URL_SEED_HOST: &str = "urlseed.invalid";
const HTTP_SEED_HOST: &str = "httpseed.invalid";
const MAGNET_SEED_HOST: &str = "magnetseed.invalid";

/// `multi_file_tracker_torrent` with a `url-list` and an `httpseeds` entry,
/// each on a host under no tracker domain.
fn web_seeded_torrent() -> Vec<u8> {
    let plain = multi_file_tracker_torrent();
    let info = plain
        .windows(7)
        .position(|w| w == b"4:infod")
        .expect("info key");
    let http = format!("http://{HTTP_SEED_HOST}/seed");
    let url = format!("http://{URL_SEED_HOST}/files/");
    let mut out = plain[..info].to_vec();
    // Top-level keys in bencode byte order: httpseeds < info < url-list.
    out.extend_from_slice(format!("9:httpseedsl{}:{http}e", http.len()).as_bytes());
    out.extend_from_slice(&plain[info..plain.len() - 1]);
    out.extend_from_slice(format!("8:url-listl{}:{url}e", url.len()).as_bytes());
    out.extend_from_slice(b"e");
    out
}

/// The resume data `h` saves now: what the torrent holds, web seeds included,
/// since libtorrent writes every web seed the torrent has into `url-list` and
/// `httpseeds`.
fn saved_resume(s: *mut lt_session, h: lt_handle) -> Vec<u8> {
    assert_eq!(unsafe { lt_save_resume_data(s, h, 0) }, LT_OK as i32);
    wait_for(s, |u| match u.kind {
        k if k == lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA => {
            let r = unsafe { u.payload.save_resume };
            Some(Ok(
                unsafe { std::slice::from_raw_parts(r.buf, r.len) }.to_vec()
            ))
        }
        k if k == lt_alert_kind_LT_ALERT_SAVE_RESUME_DATA_FAILED => Some(Err(())),
        _ => None,
    })
    .expect("no save_resume_data alert")
    .expect("save_resume_data failed")
}

fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

fn assert_no_web_seeds(resume: &[u8]) {
    for host in [URL_SEED_HOST, HTTP_SEED_HOST, MAGNET_SEED_HOST] {
        assert!(
            !holds(resume, host),
            "the torrent kept a web seed on {host}: {}",
            String::from_utf8_lossy(resume)
        );
    }
}

fn add_resume(s: *mut lt_session, resume: &[u8], torrent: &[u8]) -> lt_handle {
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_resume_ex(
            s,
            resume.as_ptr(),
            resume.len(),
            torrent.as_ptr(),
            torrent.len(),
            ptr::null(),
            LT_TF_PAUSED,
            0,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_ne!(h, 0, "resume add failed: {}", c_buf(&err));
    h
}

/// Hand-built resume data for `ih`, with a `url-list` and an `httpseeds`
/// entry when `seeds` is set and neither key otherwise.
fn resume_for(ih: &[u8; 20], seeds: bool) -> Vec<u8> {
    let http = format!("http://{HTTP_SEED_HOST}/resume");
    let url = format!("http://{URL_SEED_HOST}/resume/");
    let mut resume = Vec::new();
    resume.extend_from_slice(b"d11:file-format22:libtorrent resume file");
    resume.extend_from_slice(b"12:file-versioni1e");
    if seeds {
        resume.extend_from_slice(format!("9:httpseedsl{}:{http}e", http.len()).as_bytes());
    }
    resume.extend_from_slice(b"9:info-hash20:");
    resume.extend_from_slice(ih);
    resume.extend_from_slice(b"9:save_path4:/tmp");
    if seeds {
        resume.extend_from_slice(format!("8:url-listl{}:{url}e", url.len()).as_bytes());
    }
    resume.extend_from_slice(b"e");
    resume
}

/// A `.torrent`'s `url-list` and `httpseeds` never reach the torrent, and the
/// resume data it saves records it with none.
#[test]
fn a_file_add_drops_the_torrent_s_web_seeds() {
    let bytes = web_seeded_torrent();
    // The fixture does carry them, so their absence below is the add's doing.
    assert!(holds(&bytes, URL_SEED_HOST) && holds(&bytes, HTTP_SEED_HOST));
    let s = make_session();
    let h = add_file(s, &bytes);
    assert_no_web_seeds(&saved_resume(s, h));
    unsafe { lt_session_destroy(s) };
}

/// A magnet's `ws=` never reaches the torrent.
#[test]
fn a_magnet_add_drops_its_ws_web_seed() {
    let s = make_session();
    let h = add_magnet(
        s,
        &format!(
            "magnet:?xt=urn:btih:0606060606060606060606060606060606060606\
             &ws=http%3A%2F%2F{MAGNET_SEED_HOST}%2Ffile"
        ),
    );
    assert_no_web_seeds(&saved_resume(s, h));
    unsafe { lt_session_destroy(s) };
}

/// A resume add drops the web seeds in the resume data's own `url-list` and
/// `httpseeds`, and those of the `.torrent` attached to resume data that has
/// neither key, which libtorrent would otherwise load from the metadata.
#[test]
fn a_resume_add_drops_web_seeds_from_the_resume_data_and_the_torrent() {
    let bytes = web_seeded_torrent();
    let mut hashes: lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    assert_eq!(
        unsafe {
            lt_torrent_info_hashes(
                bytes.as_ptr(),
                bytes.len(),
                &mut hashes,
                err.as_mut_ptr(),
                512,
            )
        },
        LT_OK as i32,
        "{}",
        c_buf(&err)
    );
    assert_eq!(hashes.has_v1, 1, "the web-seeded torrent is v1");
    let ih = hashes.v1;
    for seeds in [true, false] {
        let s = make_session();
        let h = add_resume(s, &resume_for(&ih, seeds), &bytes);
        assert_no_web_seeds(&saved_resume(s, h));
        unsafe { lt_session_destroy(s) };
    }
}

/// What a web-seeded `.torrent` add saves comes back through a resume add, in
/// a session of its own, still without a web seed.
#[test]
fn web_seeds_stay_dropped_across_a_resume_round_trip() {
    let bytes = web_seeded_torrent();
    let s = make_session();
    let h = add_file(s, &bytes);
    let first = saved_resume(s, h);
    unsafe { lt_session_destroy(s) };

    let s = make_session();
    let h = add_resume(s, &first, &bytes);
    assert_no_web_seeds(&saved_resume(s, h));
    unsafe { lt_session_destroy(s) };
}

// ---------------------------------------------------------------------------
// Session pause
// ---------------------------------------------------------------------------

/// Whether any of `h`'s trackers has recorded a failed announce, draining the
/// alert queue so it does not fill while a test polls.
fn an_announce_failed(s: *mut lt_session, h: lt_handle) -> bool {
    let mut list: lt_tracker_list = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe { lt_torrent_trackers(s, h, &mut list, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32, "lt_torrent_trackers: {}", c_buf(&err));
    let entries = unsafe { std::slice::from_raw_parts(list.entries, list.num_entries) };
    let failed = entries.iter().any(|e| e.fails > 0);
    unsafe { lt_tracker_list_free(&mut list) };
    let mut u: lt_alert_union = unsafe { std::mem::zeroed() };
    while unsafe { lt_pop_alert(s, &mut u) } == 1 {
        unsafe { lt_alert_payload_free(&mut u) };
    }
    failed
}

#[test]
fn session_pause_calls_are_null_safe() {
    assert_eq!(unsafe { lt_session_pause(ptr::null_mut()) }, LT_ERR);
    assert_eq!(unsafe { lt_session_resume(ptr::null_mut()) }, LT_ERR);
    assert_eq!(unsafe { lt_session_is_paused(ptr::null_mut()) }, LT_ERR);
}

/// A paused session holds a torrent added after the pause, and resumed by its
/// own handle, off the network: its trackers, all on closed loopback ports,
/// are never asked. Resuming the session lets the same torrent announce, and
/// that announce fails at once, so its absence before is the pause's doing.
#[test]
fn a_paused_session_keeps_a_later_add_from_announcing_until_it_resumes() {
    let s = make_session();
    assert_eq!(unsafe { lt_session_is_paused(s) }, 0);
    assert_eq!(unsafe { lt_session_pause(s) }, LT_OK as i32);
    assert_eq!(unsafe { lt_session_pause(s) }, LT_OK as i32, "idempotent");
    assert_eq!(unsafe { lt_session_is_paused(s) }, 1);

    let h = add_file(s, &multi_file_tracker_torrent());
    assert_eq!(unsafe { lt_torrent_resume(s, h) }, LT_OK as i32);
    // The torrent's own flag is clear: the session's pause is what holds it.
    assert_eq!(status_flags(s, h) & LT_TF_PAUSED, 0);

    let quiet_until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < quiet_until {
        assert!(
            !an_announce_failed(s, h),
            "a torrent in a paused session announced"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    assert_eq!(unsafe { lt_session_resume(s) }, LT_OK as i32);
    assert_eq!(unsafe { lt_session_is_paused(s) }, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut announced = false;
    while std::time::Instant::now() < deadline {
        if an_announce_failed(s, h) {
            announced = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(announced, "the resumed session never announced the torrent");
    unsafe { lt_session_destroy(s) };
}

// ---------------------------------------------------------------------------
// Boundary hardening: lengths, the handle registry, move flags, settings
// ---------------------------------------------------------------------------

/// The v1 infohash of `bytes`, read through the shim.
fn v1_hash(bytes: &[u8]) -> [u8; 20] {
    let mut hashes: lt_info_hashes = unsafe { std::mem::zeroed() };
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_info_hashes(
            bytes.as_ptr(),
            bytes.len(),
            &mut hashes,
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(rc, LT_OK as i32, "{}", c_buf(&err));
    hashes.v1
}

/// Every entry point that hands a caller's `.torrent` buffer to libtorrent
/// refuses a length past `INT_MAX`. The length used is the real one plus
/// 2^32, which a narrowing cast to `int` turns back into the real one: the
/// shim used to parse the buffer and report success. The buffer itself is
/// the real length, so neither behaviour reads past it.
#[test]
fn a_buffer_length_past_int_max_is_refused() {
    let bytes = multi_file_tracker_torrent();
    let len = bytes.len() + (1usize << 32);
    let resume = resume_for(&v1_hash(&bytes), false);
    let assert_refused = |what: &str, err: &[c_char]| {
        assert!(c_buf(err).contains("INT_MAX"), "{what}: {}", c_buf(err));
    };

    let mut err = [0 as c_char; 512];
    let mut hashes: lt_info_hashes = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { lt_torrent_info_hashes(bytes.as_ptr(), len, &mut hashes, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_ERR, "lt_torrent_info_hashes");
    assert_refused("lt_torrent_info_hashes", &err);

    let mut err = [0 as c_char; 512];
    let mut meta: lt_torrent_meta = unsafe { std::mem::zeroed() };
    let rc = unsafe { lt_torrent_metadata(bytes.as_ptr(), len, &mut meta, err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_ERR, "lt_torrent_metadata");
    assert_refused("lt_torrent_metadata", &err);

    // Each source read with and without resume data, which take separate
    // branches in the shim.
    for resume in [None, Some(&resume)] {
        let (rp, rl) = resume.map_or((ptr::null(), 0), |r| (r.as_ptr(), r.len()));
        let mut err = [0 as c_char; 512];
        let mut out: lt_info_hashes = unsafe { std::mem::zeroed() };
        let mut has_metadata = 0;
        let rc = unsafe {
            lt_add_info_hashes(
                ptr::null(),
                bytes.as_ptr(),
                len,
                rp,
                rl,
                &mut out,
                &mut has_metadata,
                err.as_mut_ptr(),
                512,
            )
        };
        assert_eq!(
            rc,
            LT_ERR,
            "lt_add_info_hashes, resume {}",
            resume.is_some()
        );
        assert_refused("lt_add_info_hashes", &err);

        let csv = CString::new("127.0.0.1").unwrap();
        let mut err = [0 as c_char; 512];
        let rc = unsafe {
            lt_add_trackers_allowed(
                ptr::null(),
                bytes.as_ptr(),
                len,
                ptr::null(),
                ptr::null(),
                0,
                rp,
                rl,
                csv.as_ptr(),
                ptr::null(),
                0,
                err.as_mut_ptr(),
                512,
            )
        };
        assert_eq!(
            rc,
            LT_ERR,
            "lt_add_trackers_allowed, resume {}",
            resume.is_some()
        );
        assert_refused("lt_add_trackers_allowed", &err);
    }

    let s = make_session();
    let save = CString::new("/tmp").unwrap();
    let mut ih = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_file(
            s,
            bytes.as_ptr(),
            len,
            save.as_ptr(),
            LT_TF_PAUSED,
            ptr::null(),
            ptr::null(),
            0,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(h, 0, "lt_add_torrent_file");
    assert_refused("lt_add_torrent_file", &err);

    let mut err = [0 as c_char; 512];
    let h = unsafe {
        lt_add_torrent_resume_ex(
            s,
            resume.as_ptr(),
            resume.len(),
            bytes.as_ptr(),
            len,
            ptr::null(),
            LT_TF_PAUSED,
            0,
            ih.as_mut_ptr(),
            err.as_mut_ptr(),
            512,
        )
    };
    assert_eq!(h, 0, "lt_add_torrent_resume_ex");
    assert_refused("lt_add_torrent_resume_ex", &err);
    unsafe { lt_session_destroy(s) };
}

/// Pop and free every alert until the queue has stayed empty for 100ms.
fn drain(s: *mut lt_session) {
    let mut idle = 0;
    while idle < 5 {
        let mut u: lt_alert_union = unsafe { std::mem::zeroed() };
        if unsafe { lt_pop_alert(s, &mut u) } == 1 {
            unsafe { lt_alert_payload_free(&mut u) };
            idle = 0;
        } else {
            idle += 1;
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

/// After `lt_remove_torrent`, alerts the torrent posted before the removal
/// are still queued, and the torrent object outlives the call for a moment,
/// so they can be translated while its handle is still valid. None of them
/// may register the removed torrent again: each reports no handle, where each
/// used to register it under a fresh id, the stale-handle state the issue
/// names. (`add_torrent_alert` alone still registers; it is drained first
/// here, so every alert counted below is a non-add one.)
///
/// Whether the torrent is still alive when its queued alerts are translated
/// is a race this test does not control, so the scenario repeats until it has
/// seen at least one such alert, and every one it saw must carry no handle.
#[test]
fn alerts_translated_after_a_removal_do_not_register_the_removed_torrent() {
    let bytes = multi_file_tracker_torrent();
    let ih = v1_hash(&bytes);
    let mut late = Vec::new();
    for _ in 0..20 {
        let s = make_session();
        let h = add_file(s, &bytes);
        // The add's own alerts, including add_torrent_alert, go first.
        drain(s);
        // Resumed, the torrent announces to closed loopback ports; the
        // failures queue up unpopped.
        assert_eq!(unsafe { lt_torrent_resume(s, h) }, LT_OK as i32);
        unsafe { lt_post_torrent_updates(s) };
        std::thread::sleep(std::time::Duration::from_millis(300));

        assert_eq!(unsafe { lt_remove_torrent(s, h, 0) }, LT_OK as i32);
        // Every alert naming the torrent up to its torrent_removed_alert.
        let removed = wait_for(s, |u| {
            if u.kind == lt_alert_kind_LT_ALERT_TORRENT_REMOVED {
                return Some(());
            }
            if u.infohash == ih {
                late.push((u.kind, u.handle));
            }
            None
        });
        assert!(removed.is_some(), "no torrent_removed_alert");
        unsafe { lt_session_destroy(s) };
        if !late.is_empty() {
            break;
        }
    }
    assert!(
        !late.is_empty(),
        "no alert was translated while the removed torrent still existed, so nothing was tested"
    );
    assert!(
        late.iter().all(|&(_, handle)| handle == 0),
        "an alert translated after the removal registered the removed torrent: {late:?}"
    );
}

/// A move-storage flag outside the `LT_MOVE_*` constants is refused, where it
/// used to fall through to `always_replace_files`, the one choice that
/// overwrites files at the destination.
#[test]
fn an_unknown_move_flag_is_refused() {
    let s = make_session();
    let h = add_file(s, &multi_file_tracker_torrent());
    let dest = std::env::temp_dir().join(format!("shim-move-flags-{}", std::process::id()));
    let dest_c = CString::new(dest.to_str().unwrap()).unwrap();
    for flags in [3, 0x100, u32::MAX] {
        assert_eq!(
            unsafe { lt_torrent_move_storage(s, h, dest_c.as_ptr(), flags) },
            LT_ERR,
            "move flags {flags:#x}"
        );
    }
    unsafe { lt_session_destroy(s) };
    let _ = std::fs::remove_dir_all(&dest);
}

/// The settings object is the whole input: anything but whitespace after its
/// closing brace is refused, on create and on apply, where it used to be
/// ignored.
#[test]
fn settings_with_trailing_bytes_are_refused() {
    for json in [
        r#"{"enable_dht":false} x"#,
        r#"{"enable_dht":false}}"#,
        r#"{"enable_dht":false},"#,
        r#"{}{"enable_dht":true}"#,
    ] {
        let settings = CString::new(json).unwrap();
        let mut err = [0 as c_char; 512];
        let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
        assert!(s.is_null(), "{json} was accepted");
        assert!(c_buf(&err).contains("trailing"), "{json}: {}", c_buf(&err));
    }

    let settings = CString::new(format!("{NO_NET} \n\t")).unwrap();
    let mut err = [0 as c_char; 512];
    let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
    assert!(!s.is_null(), "trailing whitespace refused: {}", c_buf(&err));
    let settings = CString::new(r#"{"enable_dht":false} x"#).unwrap();
    let mut err = [0 as c_char; 512];
    assert_eq!(
        unsafe { lt_session_apply_settings(s, settings.as_ptr(), err.as_mut_ptr(), 512) },
        LT_ERR
    );
    assert!(c_buf(&err).contains("trailing"), "{}", c_buf(&err));
    unsafe { lt_session_destroy(s) };
}

/// A settings string may spell characters as `\uXXXX`, including a surrogate
/// pair, and they decode to their UTF-8 bytes. A lone surrogate, `\u0000`, a
/// short escape and a non-hex digit are refused.
#[test]
fn a_settings_string_decodes_unicode_escapes() {
    // `127.0.0.1:0` with escapes: the session listens only if they decode to
    // exactly those bytes.
    let json = r#"{"enable_dht":false,"enable_lsd":false,"enable_upnp":false,"enable_natpmp":false,"listen_interfaces":"127.0.0.1:0","user_agent":"café € 😀"}"#;
    let settings = CString::new(json).unwrap();
    let mut err = [0 as c_char; 512];
    let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
    assert!(!s.is_null(), "escapes refused: {}", c_buf(&err));
    let listened = wait_for(s, |u| match u.kind {
        k if k == lt_alert_kind_LT_ALERT_LISTEN_SUCCEEDED => Some(true),
        k if k == lt_alert_kind_LT_ALERT_LISTEN_FAILED => Some(false),
        _ => None,
    });
    assert_eq!(listened, Some(true), "the escaped listen interface");
    assert!(
        holds(&saved_state(s), "caf\u{e9} \u{20ac} \u{1F600}"),
        "the escaped user agent decodes to its UTF-8 bytes"
    );
    unsafe { lt_session_destroy(s) };

    for bad in [
        r#"{"user_agent":"\ud83d"}"#,
        r#"{"user_agent":"\ud83dx"}"#,
        r#"{"user_agent":"\ud83dA"}"#,
        r#"{"user_agent":"\ude00"}"#,
        r#"{"user_agent":"a\u0000b"}"#,
        r#"{"user_agent":"\u12"}"#,
        r#"{"user_agent":"\u12g4"}"#,
    ] {
        let settings = CString::new(bad).unwrap();
        let mut err = [0 as c_char; 512];
        let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
        assert!(s.is_null(), "{bad} was accepted");
        assert!(!c_buf(&err).is_empty(), "{bad}: no reason given");
    }
}
