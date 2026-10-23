//! Boundary hardening: lengths, the handle registry, move flags, settings.

use super::*;

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
/// The same holds for the state update queued before the removal: its alert
/// names no torrent at the top level, so it is read entry by entry, and every
/// status entry for the removed torrent must carry no handle either.
///
/// Whether the torrent is still alive when its queued alerts are translated
/// is a race this test does not control, so the scenario repeats until it has
/// seen at least one such alert and one such status entry, and every one it
/// saw must carry no handle.
#[test]
fn alerts_translated_after_a_removal_do_not_register_the_removed_torrent() {
    let bytes = multi_file_tracker_torrent();
    let ih = v1_hash(&bytes);
    let mut late = Vec::new();
    let mut late_states = Vec::new();
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
            if u.kind == lt_alert_kind_LT_ALERT_STATE_UPDATE {
                let su = unsafe { u.payload.state_update };
                if !su.statuses.is_null() {
                    let views = unsafe { std::slice::from_raw_parts(su.statuses, su.count) };
                    late_states.extend(views.iter().filter(|v| v.infohash == ih).map(|v| v.handle));
                }
            } else if u.infohash == ih {
                late.push((u.kind, u.handle));
            }
            None
        });
        assert!(removed.is_some(), "no torrent_removed_alert");
        unsafe { lt_session_destroy(s) };
        if !late.is_empty() && !late_states.is_empty() {
            break;
        }
    }
    // The state view first: once it registers the torrent, every later alert
    // resolves to that id too, so its failure would show up as theirs.
    assert!(
        !late_states.is_empty(),
        "no state update was translated while the removed torrent still existed, so nothing was tested"
    );
    assert!(
        late_states.iter().all(|&handle| handle == 0),
        "a state update translated after the removal registered the removed torrent: {late_states:?}"
    );
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

/// A JSON `\u` escape followed by `hex`, assembled at run time so the source
/// holds no escape a tool or reader could decode in place.
fn u_esc(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

/// A settings string may spell characters as `\uXXXX`, including a surrogate
/// pair, and they decode to their UTF-8 bytes. A lone surrogate, `\u0000`, a
/// short escape and a non-hex digit are refused.
#[test]
fn a_settings_string_decodes_unicode_escapes() {
    // `127.0.0.1:0` with escapes: the session listens only if they decode to
    // exactly those bytes.
    let listen = format!(
        "{}{}{}.0.0.1{}0",
        u_esc("0031"),
        u_esc("0032"),
        u_esc("0037"),
        u_esc("003A")
    );
    // U+00E9, U+20AC, and U+1F600 as a surrogate pair.
    let agent = format!(
        "caf{} {} {}{}",
        u_esc("00e9"),
        u_esc("20ac"),
        u_esc("d83d"),
        u_esc("de00")
    );
    let json = format!(
        r#"{{"enable_dht":false,"enable_lsd":false,"enable_upnp":false,"enable_natpmp":false,"listen_interfaces":"{listen}","user_agent":"{agent}"}}"#
    );
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

    for value in [
        u_esc("d83d"),
        format!("{}x", u_esc("d83d")),
        format!("{}{}", u_esc("d83d"), u_esc("0041")),
        u_esc("de00"),
        format!("a{}b", u_esc("0000")),
        u_esc("12"),
        u_esc("12g4"),
    ] {
        let bad = format!(r#"{{"user_agent":"{value}"}}"#);
        let settings = CString::new(bad.as_str()).unwrap();
        let mut err = [0 as c_char; 512];
        let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), 512) };
        assert!(s.is_null(), "{bad} was accepted");
        assert!(!c_buf(&err).is_empty(), "{bad}: no reason given");
    }
}

/// A reason cut to fit `err_out` is cut on a character boundary: it never
/// ends in the lead byte of a character it cut in half.
#[test]
fn a_reason_cut_to_fit_err_out_keeps_whole_characters() {
    // The reason is "unknown setting: " (17 bytes) and then the key, whose
    // characters are two bytes each.
    let settings = CString::new(r#"{"ééé":1}"#).unwrap();
    let reason = |err_len: usize| {
        let mut err = vec![0x7f as c_char; err_len];
        let s = unsafe { lt_session_create(settings.as_ptr(), err.as_mut_ptr(), err_len as i32) };
        assert!(s.is_null(), "an unknown setting was accepted");
        let bytes: Vec<u8> = err.iter().map(|c| *c as u8).collect();
        let nul = bytes.iter().position(|b| *b == 0).expect("NUL-terminated");
        String::from_utf8(bytes[..nul].to_vec()).expect("whole UTF-8")
    };
    // Room for 18 bytes ends inside the first character, which is dropped.
    assert_eq!(reason(19), "unknown setting: ");
    // Room for 19 ends after it, which is kept.
    assert_eq!(reason(20), "unknown setting: é");
}
