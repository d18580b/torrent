//! Session lifecycle, null and unknown handles, saved state, and the
//! info-hashes of a `.torrent`, a magnet and an add.

use super::*;

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
    assert_eq!(
        unsafe { lt_torrent_enforce_no_download(s, 999_999) },
        LT_ERR
    );
    assert_eq!(
        unsafe { lt_torrent_enforce_no_download(ptr::null_mut(), 1) },
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
pub(crate) fn saved_state(s: *mut lt_session) -> Vec<u8> {
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
            // Free any heap payload. Nothing here checks it was freed; the
            // ASan run does (see the module comment).
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
