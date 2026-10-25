//! A torrent's files and their priorities.

use super::*;

pub(super) async fn files(h: &Harness, e: &Engines) {
    let loaded = handle(&e.p, LOADED);
    let list = format!("/v1/torrents/{}/files", hex(LOADED));
    let priority = |i: u32| format!("/v1/torrents/{}/files/{i}/priority", hex(LOADED));

    // A magnet still fetching its metadata has no files.
    let resp = h.read(&list).await;
    assert_problem(&resp, 409, "metadata-pending");
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 409, "metadata-pending");

    let all: Vec<TorrentFile> = (0..12).map(|i| file(i, &format!("d/f{i}"))).collect();
    e.p.set_torrent_files(loaded, Some(all));
    let page: Value = h.read(&format!("{list}?limit=5")).await.json();
    assert_eq!(page["items"].as_array().unwrap().len(), 5);
    assert_eq!(
        page["items"][0],
        json!({"index": 0, "path": "d/f0", "size": 100, "downloaded": 50, "priority": 4})
    );
    // Index 10 sorts after 9, not after 1.
    let mut seen: Vec<u64> = Vec::new();
    let mut cursor = None::<String>;
    loop {
        let path = match &cursor {
            Some(c) => format!("{list}?limit=5&cursor={c}"),
            None => format!("{list}?limit=5"),
        };
        let page: Value = h.read(&path).await.json();
        seen.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["index"].as_u64().unwrap()),
        );
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen, (0..12).collect::<Vec<u64>>());
    let resp = h.read(&format!("{list}?cursor=nope!")).await;
    assert_problem(&resp, 400, "invalid-cursor");
    let torrents_cursor = crate::http::page::encode("torrents", &hex(LOADED));
    let resp = h.read(&format!("{list}?cursor={torrents_cursor}")).await;
    assert_problem(&resp, 400, "invalid-cursor");
    // Another torrent's files cursor, and a key no file index could be.
    for (listing, key) in [
        (format!("files:{}", hex(ADDING)), "0000000001"),
        (format!("files:{}", hex(LOADED)), "zzz"),
    ] {
        let cursor = crate::http::page::encode(&listing, key);
        let resp = h.read(&format!("{list}?cursor={cursor}")).await;
        assert_problem(&resp, 400, "invalid-cursor");
    }
    let resp = h.read(&format!("{list}?limit=0")).await;
    assert_problem(&resp, 422, "validation-failed");
    assert_eq!(errors_at(&resp), ["#/query/limit"]);
    let resp = h.read(&format!("/v1/torrents/{}/files", hex(ADDING))).await;
    assert_problem(&resp, 404, "torrent-not-found");
    e.p.inject_error("torrent_files", injected("torrent_files"));
    let resp = h.read(&list).await;
    assert_problem(&resp, 500, "internal");
    e.p.inject_error(
        "torrent_files",
        EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(LOADED)),
    );
    let resp = h.read(&list).await;
    assert_problem(&resp, 404, "torrent-not-found");

    // Priorities.
    h.write_json("PUT", &priority(11), json!({"priority": 7}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(last_call_was(
        &e.p,
        &RecordedCall::SetFilePriority {
            handle: loaded,
            file_idx: 11,
            priority: 7
        }
    ));
    let resp = h
        .write_json("PUT", &priority(12), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 404, "file-not-found");
    let resp = h
        .write_json("PUT", &priority(u32::MAX), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 404, "file-not-found");
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 8}))
        .await;
    assert_problem(&resp, 422, "validation-failed");
    assert_eq!(errors_at(&resp), ["/priority"]);
    for body in [
        json!({"priority": 256}),
        json!({"priority": 1, "x": 1}),
        json!({}),
    ] {
        let resp = h.write_json("PUT", &priority(0), body.clone()).await;
        assert_eq!(resp.status().as_u16(), 422, "{body}");
    }
    let resp = h
        .write_json(
            "PUT",
            &format!("/v1/torrents/{}/files/0/priority", hex(ADDING)),
            json!({"priority": 1}),
        )
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
    e.p.inject_error("set_file_priority", injected("set_file_priority"));
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 500, "internal");
    // Removed from its session between the count and the set.
    e.p.inject_error(
        "set_file_priority",
        EngineError::Safe(libtorrent_safe::Error::TorrentNotFound(LOADED)),
    );
    let resp = h
        .write_json("PUT", &priority(0), json!({"priority": 1}))
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
    body_framework_rejections(h, "PUT", &priority(0), crate::http::v1::REQUEST_DEADLINE).await;

    // A page of the largest torrent the shim admits copies that page out of
    // the session, not the whole list: every engine call and the alert loop
    // wait on the session lock while it copies.
    const LARGE: u32 = 250_000;
    let large: Vec<TorrentFile> = (0..LARGE).map(|i| file(i, &format!("d/f{i}"))).collect();
    e.p.set_torrent_files(loaded, Some(large));
    let mid = crate::http::page::encode(&format!("files:{}", hex(LOADED)), &file_key(124_999));
    let page: Value = h.read(&format!("{list}?cursor={mid}")).await.json();
    let indices: Vec<u64> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["index"].as_u64().unwrap())
        .collect();
    assert_eq!(indices, (125_000..125_100).collect::<Vec<u64>>());
    assert!(page["next_cursor"].is_string());
    // Every earlier call in this fixture read at most a dozen files.
    assert_eq!(e.p.largest_files_copy(), 100, "copied past the page");
    // The priority route reads the count alone.
    h.write_json("PUT", &priority(LARGE - 1), json!({"priority": 1}))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_problem(
        &h.write_json("PUT", &priority(LARGE), json!({"priority": 1}))
            .await,
        404,
        "file-not-found",
    );
    assert_eq!(e.p.largest_files_copy(), 100);
    // The last page has no cursor, and a cursor past every file, which a
    // ten-digit key can name, is an empty last page.
    let last = crate::http::page::encode(&format!("files:{}", hex(LOADED)), &file_key(LARGE - 3));
    let page: Value = h.read(&format!("{list}?cursor={last}")).await.json();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert!(page["next_cursor"].is_null());
    let past = crate::http::page::encode(&format!("files:{}", hex(LOADED)), "9999999999");
    let page: Value = h.read(&format!("{list}?cursor={past}")).await.json();
    assert_eq!(page["items"], json!([]));
    assert!(page["next_cursor"].is_null());
}

/// A file listing's cursor key, as the handler spells it.
fn file_key(index: u32) -> String {
    format!("{index:010}")
}
