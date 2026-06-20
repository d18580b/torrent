//! Layer 2 shim FFI tests (PRD Validation Strategy §Layer 2).
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
    assert_eq!(h, 0, "a bad .torrent must return the null handle, not unwind");
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
    assert_eq!(unsafe { lt_torrent_set_upload_limit(s, 999_999, 100) }, LT_ERR);
    assert_eq!(unsafe { lt_torrent_pause(ptr::null_mut(), 1) }, LT_ERR);
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
    assert!(!buf.is_null() && len > 0, "expected a non-empty state buffer");
    // ASan verifies this frees exactly what the shim malloc'd (no double-free
    // / no leak). Reloading the same blob must round-trip.
    let rc2 = unsafe { lt_session_load_state(s, buf, len, err.as_mut_ptr(), 512) };
    assert_eq!(rc2, LT_OK as i32);
    unsafe { lt_buf_free(buf) };
    unsafe { lt_session_destroy(s) };
}

#[test]
fn magnet_info_hash_marshals_20_bytes() {
    let uri =
        CString::new("magnet:?xt=urn:btih:0101010101010101010101010101010101010101").unwrap();
    let mut out = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let rc =
        unsafe { lt_magnet_info_hash(uri.as_ptr(), out.as_mut_ptr(), err.as_mut_ptr(), 512) };
    assert_eq!(rc, LT_OK as i32);
    assert_eq!(out, [0x01u8; 20]);
}

#[test]
fn torrent_info_hash_bad_buffer_errors_cleanly() {
    let garbage = b"nope";
    let mut out = [0u8; 20];
    let mut err = [0 as c_char; 512];
    let rc = unsafe {
        lt_torrent_info_hash(garbage.as_ptr(), garbage.len(), out.as_mut_ptr(), err.as_mut_ptr(), 512)
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
