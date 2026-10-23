//! Per-torrent queries: lt_torrent_details / _files / _trackers.

use super::*;

const TRACKERS: [&str; 3] = [
    "http://127.0.0.1:1/announce",
    "http://127.0.0.1:2/announce",
    "http://127.0.0.1:3/tier1",
];

/// A v1 multi-file `.torrent` with two tracker tiers (two URLs in tier 0, one
/// in tier 1). The piece hashes are filler: every test adds it paused, so
/// libtorrent never checks or serves the payload.
pub(crate) fn multi_file_tracker_torrent() -> Vec<u8> {
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

pub(crate) fn add_file(s: *mut lt_session, bytes: &[u8]) -> lt_handle {
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

pub(crate) fn add_magnet(s: *mut lt_session, uri: &str) -> lt_handle {
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

pub(crate) fn c_buf(buf: &[c_char]) -> String {
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul]).into_owned()
}

/// `lt_torrent_details`, copied out and freed.
pub(crate) struct Details {
    pub(crate) name: String,
    pub(crate) save_path: String,
    pub(crate) total_size: u64,
    pub(crate) added_time: i64,
    pub(crate) upload_limit: u32,
    pub(crate) has_metadata: u8,
}

pub(crate) fn details(s: *mut lt_session, h: lt_handle) -> Details {
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
    let e = first_tracker_error_alert(url);
    (e.error_code, e.error_category, e.aborted)
}

/// [`first_tracker_error_announcing_to`]'s alert, whole.
fn first_tracker_error_alert(url: &str) -> lt_alert_tracker_error {
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
        Some(unsafe { u.payload.tracker_error })
    });
    unsafe { lt_session_destroy(s) };
    got.expect("no tracker_error alert")
}

/// A tracker URL longer than the alert's buffer is cut on a character
/// boundary: the alert names the tracker by a prefix of its URL that is whole
/// UTF-8, never one ending in the lead byte of a character it cut in half.
#[test]
fn a_tracker_url_cut_to_fit_its_alert_keeps_whole_characters() {
    // 20 ASCII bytes, then two-byte characters: the buffer's last byte for
    // text, LT_PATH_MAX - 1, falls on the second byte of one.
    let url = format!("http://127.0.0.1:1/a{}", "é".repeat(LT_PATH_MAX as usize));
    let e = first_tracker_error_alert(&url);
    let bytes: Vec<u8> = e
        .tracker_url
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    let got = std::str::from_utf8(&bytes).expect("the cut URL is whole UTF-8");
    assert!(url.starts_with(got), "{got:?} is not a prefix of the URL");
    assert_eq!(
        got.len(),
        LT_PATH_MAX as usize - 2,
        "cut at the start of the character the buffer's end splits"
    );
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
