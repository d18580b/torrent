//! A generated qBittorrent `BT_backup`: `<infohash>.torrent` and
//! `<infohash>.fastresume` pairs, with each torrent's payload written under a
//! managed root where the pair says it is.
//!
//! Shared by the pool's tests (`tests/pool.rs`) and the daemon's
//! (`crates/torrentd/tests/daemon.rs`, through `#[path]`), so the import both
//! layers are held to is the same one. Every torrent is two files under one
//! 16 KiB piece, so its single piece hash is the SHA-1 of both files' bytes
//! end to end; the caller supplies the hash function, because the pool crate
//! has no SHA-1 of its own and never hashes payload.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

/// What the previous client left for one torrent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Case {
    /// A sidecar marking every piece had, its `qBt-savePath` naming where the
    /// payload is.
    Complete,
    /// A sidecar marking the piece missing.
    Incomplete,
    /// Complete, with the first file renamed through `mapped_files`, and on
    /// disk only under that name.
    Renamed,
    /// Complete, with `qBt-contentLayout` `NoSubfolder`: the files sit in
    /// the save path without the torrent's top directory, which only
    /// qBittorrent's own key records.
    NoSubfolder,
    /// A complete sidecar cut off halfway, as an interrupted copy leaves it.
    /// None of it parses, so its save path is lost too and the payload is
    /// found by the torrent's name under the root.
    TruncatedSidecar,
    /// Complete, with a save path that is not UTF-8 in both `qBt-savePath`
    /// and `save_path`; the payload is found by the torrent's name instead.
    NonUtf8SavePath,
    /// A `.fastresume` whose `.torrent` is gone. Nothing indexes it.
    OrphanSidecar,
}

impl Case {
    pub const ALL: [Case; 7] = [
        Case::Complete,
        Case::Incomplete,
        Case::Renamed,
        Case::NoSubfolder,
        Case::TruncatedSidecar,
        Case::NonUtf8SavePath,
        Case::OrphanSidecar,
    ];
}

/// One generated pair.
#[derive(Clone, Debug)]
pub struct Generated {
    pub case: Case,
    pub infohash: String,
    pub name: String,
    /// Where the torrent's paths are relative to, under the root: the save
    /// path adoption hands libtorrent. Empty is the root itself.
    pub base_rel: String,
    /// Each file's path relative to `base_rel` as libtorrent opens it, which
    /// for [`Case::Renamed`] is the name it was renamed to.
    pub file_paths: Vec<String>,
}

/// The piece length every generated torrent declares; each one is smaller.
pub const PIECE_LENGTH: usize = 16384;

/// Write `count` pairs into `backup`, cycling through [`Case::ALL`], and each
/// torrent's payload under `root`. `sha1` hashes the payload for the
/// `.torrent`'s piece hash.
pub fn generate(
    backup: &Path,
    root: &Path,
    count: usize,
    sha1: fn(&[u8]) -> [u8; 20],
) -> Vec<Generated> {
    std::fs::create_dir_all(backup).unwrap();
    std::fs::create_dir_all(root).unwrap();
    (0..count)
        .map(|i| one(backup, root, i, Case::ALL[i % Case::ALL.len()], sha1))
        .collect()
}

fn one(backup: &Path, root: &Path, i: usize, case: Case, sha1: fn(&[u8]) -> [u8; 20]) -> Generated {
    let name = format!("bt-{i:04}");
    // Distinct sizes and bytes per torrent, so no two share a payload or an
    // info-hash, and the size anchor cannot cross from one to another.
    let a: Vec<u8> = (0..100 + i % 97).map(|n| (n + i) as u8).collect();
    let b: Vec<u8> = (0..50 + i).map(|n| (n * 7 + i) as u8).collect();
    assert!(a.len() + b.len() <= PIECE_LENGTH, "one piece per torrent");
    let mut payload = a.clone();
    payload.extend_from_slice(&b);
    let torrent = metainfo(
        &name,
        &[("a.bin", a.len()), ("b.bin", b.len())],
        sha1(&payload),
    );
    let ih = libtorrent_safe::info_hash_from_torrent(&torrent).unwrap();

    let torrent_paths = [format!("{name}/a.bin"), format!("{name}/b.bin")];
    let (base_rel, file_paths) = match case {
        Case::Complete | Case::Incomplete | Case::OrphanSidecar => {
            (format!("s{i:04}"), torrent_paths.to_vec())
        }
        Case::Renamed => (
            format!("s{i:04}"),
            vec![format!("{name}/renamed-a.bin"), torrent_paths[1].clone()],
        ),
        Case::NoSubfolder => (format!("s{i:04}"), vec!["a.bin".into(), "b.bin".into()]),
        Case::TruncatedSidecar | Case::NonUtf8SavePath => (String::new(), torrent_paths.to_vec()),
    };
    let save_dir = root.join(&base_rel);

    let mut resume: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    resume.insert("file-format", bstr(b"libtorrent resume file"));
    resume.insert("file-version", b"i1e".to_vec());
    resume.insert("info-hash", bstr(&ih.0));
    let had = !matches!(case, Case::Incomplete);
    resume.insert("pieces", bstr(&[u8::from(had)]));
    let save = save_dir.to_string_lossy().into_owned();
    resume.insert("qBt-savePath", bstr(save.as_bytes()));
    resume.insert("save_path", bstr(save.as_bytes()));
    resume.insert("qBt-category", bstr(b"imported"));
    match case {
        Case::Renamed => {
            let mut l = b"l".to_vec();
            l.extend_from_slice(&bstr(file_paths[0].as_bytes()));
            l.extend_from_slice(&bstr(b""));
            l.push(b'e');
            resume.insert("mapped_files", l);
        }
        Case::NoSubfolder => {
            resume.insert("qBt-contentLayout", bstr(b"NoSubfolder"));
        }
        Case::NonUtf8SavePath => {
            let mut p = root.to_string_lossy().into_owned().into_bytes();
            p.extend_from_slice(b"/\xff\xfe-latin1-\xe9");
            resume.insert("qBt-savePath", bstr(&p));
            resume.insert("save_path", bstr(&p));
        }
        _ => {}
    }
    let mut fr = b"d".to_vec();
    for (k, v) in &resume {
        fr.extend_from_slice(&bstr(k.as_bytes()));
        fr.extend_from_slice(v);
    }
    fr.push(b'e');
    if case == Case::TruncatedSidecar {
        fr.truncate(fr.len() / 2);
    }

    let stem = backup.join(ih.to_hex());
    std::fs::write(stem.with_extension("fastresume"), &fr).unwrap();
    if case != Case::OrphanSidecar {
        std::fs::write(stem.with_extension("torrent"), &torrent).unwrap();
        for (rel, bytes) in file_paths.iter().zip([&a, &b]) {
            let p: PathBuf = save_dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, bytes).unwrap();
        }
    }

    Generated {
        case,
        infohash: ih.to_hex(),
        name,
        base_rel,
        file_paths,
    }
}

/// A multi-file `.torrent` named `name` over `files`, in one piece hashing to
/// `piece`.
fn metainfo(name: &str, files: &[(&str, usize)], piece: [u8; 20]) -> Vec<u8> {
    let mut t = b"d4:infod5:filesl".to_vec();
    for (path, len) in files {
        t.extend_from_slice(format!("d6:lengthi{len}e4:pathl").as_bytes());
        t.extend_from_slice(&bstr(path.as_bytes()));
        t.extend_from_slice(b"ee");
    }
    t.extend_from_slice(b"e4:name");
    t.extend_from_slice(&bstr(name.as_bytes()));
    t.extend_from_slice(format!("12:piece lengthi{PIECE_LENGTH}e6:pieces20:").as_bytes());
    t.extend_from_slice(&piece);
    t.extend_from_slice(b"ee");
    t
}

/// A bencoded byte string.
fn bstr(b: &[u8]) -> Vec<u8> {
    let mut v = format!("{}:", b.len()).into_bytes();
    v.extend_from_slice(b);
    v
}
