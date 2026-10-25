//! Add-time flags, handle ids, settings bounds.

use super::*;

/// Pop alerts until `f` returns `Some`, freeing every payload, for up to ~5s.
pub(crate) fn wait_for<T>(
    s: *mut lt_session,
    mut f: impl FnMut(&lt_alert_union) -> Option<T>,
) -> Option<T> {
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
pub(crate) fn status_flags(s: *mut lt_session, h: lt_handle) -> u32 {
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

    // Re-asserting the invariant on a live torrent keeps it, and touches
    // nothing outside it: a torrent resumed just before is not paused again.
    // (The resume is also what makes the next state update report it:
    // libtorrent reports only torrents whose status changed.)
    for t in [h, m] {
        assert_eq!(unsafe { lt_torrent_resume(s, t) }, LT_OK as i32);
        assert_eq!(
            unsafe { lt_torrent_enforce_no_download(s, t) },
            LT_OK as i32
        );
        let flags = status_flags(s, t);
        assert_ne!(flags & LT_TF_UPLOAD_MODE, 0, "flags={flags:#x}");
        assert_eq!(flags & forbidden, 0, "flags={flags:#x}");
        assert_eq!(flags & LT_TF_PAUSED, 0, "flags={flags:#x}");
    }
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
