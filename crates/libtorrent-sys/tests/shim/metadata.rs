//! lt_torrent_metadata — the pool library scanner's parser.

use super::*;

/// Fixtures come from the pinned `vendor/libtorrent` test corpus, and the
/// expected hashes below are the constants libtorrent's own
/// `test_torrent_info.cpp` asserts against. Hand-rolling a valid v2 torrent
/// would mean reimplementing the 16 KiB-leaf merkle construction in the test,
/// which is exactly the computation under test.
pub(crate) fn vendored_torrent(name: &str) -> Vec<u8> {
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
pub(crate) fn sized_c_str(ptr: *const c_char, len: usize) -> String {
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

pub(crate) fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
