//! A torrent's trackers.

use super::*;

pub(super) async fn trackers(h: &Harness, e: &Engines) {
    let loaded = handle(&e.p, LOADED);
    let path = format!("/v1/torrents/{}/trackers", hex(LOADED));
    let entry = |url: String, tier: u8| TrackerEntry {
        url,
        tier,
        verified: false,
        updating: false,
        working: false,
        fails: 0,
        message: None,
        last_error: None,
        next_announce: None,
        scrape_complete: None,
        scrape_incomplete: None,
    };
    e.p.set_torrent_trackers(
        loaded,
        vec![
            TrackerEntry {
                verified: true,
                message: Some(format!(
                    "moved to https://new.example/announce?passkey={PASSKEY}"
                )),
                next_announce: Some(1_700_000_000),
                scrape_complete: Some(12),
                scrape_incomplete: Some(3),
                ..entry(
                    format!("https://user:{PASSKEY}@t.example:8443/{PASSKEY}/announce?passkey={PASSKEY}"),
                    0,
                )
            },
            TrackerEntry {
                fails: 2,
                last_error: Some("connection refused".into()),
                message: Some("ignored while there is an error".into()),
                ..entry("udp://backup.example:6969/announce".into(), 1)
            },
            entry("http://idle.example/announce".into(), 2),
        ],
    );
    let resp = h.read(&path).await;
    resp.assert_status(StatusCode::OK);
    assert!(
        !resp.text().contains(PASSKEY),
        "a passkey left the daemon: {}",
        resp.text()
    );
    let list: Value = resp.json();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["tier"], 0);
    assert_eq!(items[0]["host"], "t.example:8443");
    assert!(
        items[0]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://t.example:8443/[redacted:"),
        "{}",
        items[0]["url"]
    );
    assert_eq!(items[0]["status"], "working");
    assert!(items[0]["message"]
        .as_str()
        .unwrap()
        .contains("https://new.example/[redacted:"));
    assert_eq!(items[0]["next_announce_at"], "2023-11-14T22:13:20Z");
    assert_eq!(items[0]["seeds"], 12);
    assert_eq!(items[0]["peers"], 3);
    assert_eq!(items[1]["url"], "udp://backup.example:6969/announce");
    assert_eq!(items[1]["status"], "error");
    assert_eq!(items[1]["message"], "connection refused");
    assert_eq!(items[2]["status"], "not_contacted");
    assert_eq!(items[2]["message"], Value::Null);
    assert_eq!(items[2]["seeds"], Value::Null);

    // A magnet has its trackers before its metadata: no metadata-pending.
    let fenced = handle(&e.f, FENCED);
    e.f.set_torrent_trackers(fenced, vec![entry("http://t.example/a".into(), 0)]);
    let list: Value = h
        .read(&format!("/v1/torrents/{}/trackers", hex(FENCED)))
        .await
        .json();
    assert_eq!(list["items"].as_array().unwrap().len(), 1);

    let resp = h
        .read(&format!("/v1/torrents/{}/trackers", hex(ADDING)))
        .await;
    assert_problem(&resp, 404, "torrent-not-found");
    e.p.inject_error("torrent_trackers", injected("torrent_trackers"));
    let resp = h.read(&path).await;
    assert_problem(&resp, 500, "internal");
}
