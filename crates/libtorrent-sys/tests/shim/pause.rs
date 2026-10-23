//! Session pause.

use super::*;

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
