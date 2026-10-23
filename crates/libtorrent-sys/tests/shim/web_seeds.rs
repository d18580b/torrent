//! Web seeds.

use super::*;

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

pub(crate) fn holds(haystack: &[u8], needle: &str) -> bool {
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
pub(crate) fn resume_for(ih: &[u8; 20], seeds: bool) -> Vec<u8> {
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
