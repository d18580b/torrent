//! Trackers: `GET /v1/torrents/{infohash}/trackers`.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::security::auth::Scoped;
use serde::Serialize;
use torrentd_engine::TorrentEngine;

use super::is_gone;
use super::loaded;
use super::model::TorrentPath;
use super::Lookup;
use crate::app_state::AppState;
use crate::http::security::Bearer;
use crate::http::security::Read;
use crate::http::v1::common::blocking;
use crate::http::v1::common::internal;
use crate::http::v1::Torrents;

/// Where a tracker stands.
///
/// Derived in this order: `working` when the last announce over any of the
/// daemon's listen endpoints succeeded, whatever the others report; otherwise
/// `error` when the last announce failed (an error text is present, or
/// announces have failed and none has ever succeeded); otherwise `updating`
/// while an announce is in flight; otherwise `working` once the tracker has
/// answered an announce; otherwise `not_contacted`.
#[derive(Clone, Copy, Debug, Schema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrackerStatus {
    /// No announce has reached the tracker yet.
    NotContacted,
    /// An announce is in flight.
    Updating,
    /// The tracker has answered an announce.
    Working,
    /// The last announce failed; `message` says why.
    Error,
}

impl TrackerStatus {
    fn of(t: &torrentd_engine::TrackerEntry) -> Self {
        // One endpoint announcing successfully is the tracker working, even
        // while another fails: the torrent is announced. `fails` is the worst
        // endpoint's count, so it cannot say otherwise.
        if t.working {
            Self::Working
        } else if t.last_error.is_some() || (t.fails > 0 && !t.verified) {
            Self::Error
        } else if t.updating {
            Self::Updating
        } else if t.verified {
            Self::Working
        } else {
            Self::NotContacted
        }
    }
}

/// One tracker of a torrent.
#[derive(Debug, Schema, Serialize)]
pub struct Tracker {
    /// The tier; lower tiers are tried first.
    pub tier: u8,
    /// The tracker's host, with its port when the URL names one. Empty when
    /// the URL could not be parsed.
    pub host: String,
    /// The announce URL, shown only as far as it is known to carry no
    /// credential: unchanged when it is a scheme, a plain host and port, and
    /// a conventional path (`/announce`, `/scrape`, …) with no query;
    /// otherwise `scheme://host/[redacted:<hash>]`, or the bare marker when
    /// it does not parse. The hash tells two trackers apart without showing
    /// either. The raw URL is never returned.
    pub url: String,
    /// Where the tracker stands.
    pub status: TrackerStatus,
    /// The last announce's error when it failed, else the tracker's last
    /// status message; `null` when there is neither. Every `scheme://` URL in
    /// it is shown by the same rule as `url`, and a `://` with no scheme is
    /// hidden whole; everything else is the tracker's own text, returned as
    /// it is.
    pub message: Option<String>,
    /// When the next announce is due; `null` when none is scheduled.
    pub next_announce_at: Option<jiff::Timestamp>,
    /// Seeds, as the tracker last reported; `null` when unknown.
    pub seeds: Option<u32>,
    /// Peers that are not seeds, as the tracker last reported; `null` when
    /// unknown.
    pub peers: Option<u32>,
}

impl From<torrentd_engine::TrackerEntry> for Tracker {
    fn from(t: torrentd_engine::TrackerEntry) -> Self {
        let status = TrackerStatus::of(&t);
        let message = t.last_error.or(t.message).map(|m| display_message(&m));
        let shown = crate::redact::display_announce_url(&t.url);
        Self {
            tier: t.tier,
            host: shown.host,
            url: shown.url,
            status,
            message,
            next_announce_at: t
                .next_announce
                .and_then(|secs| jiff::Timestamp::from_second(secs).ok()),
            seeds: t.scrape_complete,
            peers: t.scrape_incomplete,
        }
    }
}

/// A torrent's trackers.
#[derive(Debug, Schema, Serialize)]
pub struct TrackerList {
    /// The trackers, tier by tier, in the order they are tried.
    pub items: Vec<Tracker>,
}

torrent_error! {
    /// Why a torrent's trackers could not be listed.
    pub enum ListTrackersError {
        /// No loaded torrent has this infohash.
        #[error("no loaded torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
        /// The session could not be asked.
        #[error("{detail}")]
        #[problem(status = 500, title = "Internal error")]
        Internal { detail: String },
    }
}
from_lookup!(ListTrackersError);

/// List a torrent's trackers.
///
/// Tier by tier, with each tracker's announce state, last message, next
/// announce and scrape counts. A magnet has its trackers before its metadata,
/// so this answers for one still fetching it. Announce URLs are redacted:
/// a passkey never leaves the daemon.
#[kynos::get("/torrents/{infohash}/trackers", tag = Torrents)]
pub async fn list_torrent_trackers(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Json<TrackerList>, ListTrackersError> {
    let (st, engine) = loaded(&s, p.infohash.get())?;
    let trackers = match blocking(move || engine.torrent_trackers(st.handle)).await {
        Ok(trackers) => trackers,
        Err(e) if is_gone(&e) => return Err(ListTrackersError::TorrentNotFound),
        Err(e) => {
            return Err(ListTrackersError::Internal {
                detail: internal("listing the torrent's trackers", e),
            })
        }
    };
    Ok(Json(TrackerList {
        items: trackers.into_iter().map(Tracker::from).collect(),
    }))
}

/// A tracker's free-text message as the API shows it.
///
/// Every `scheme://` URL in it is shown by the rule a tracker's `url` is, so
/// a passkey a tracker echoes back in one is never returned. A URL starts at
/// its scheme — the ASCII scheme characters right before `://` — and a `://`
/// with none before it is hidden whole. It ends where the log's redactor
/// ends one — whitespace, a quote, `<`/`>`, or prose punctuation and an
/// unopened closing bracket at its end — so what surrounds it survives. A
/// backslash, which ends one in the log because log lines are JSON, does not
/// end one here: a message is not JSON, and cutting there would show what
/// follows it. Everything outside a URL, including text glued to
/// the front of a scheme, is the tracker's own words and is returned as it
/// is.
fn display_message(message: &str) -> String {
    use crate::redact::display_announce_url;
    use crate::redact::is_scheme_char;
    use crate::redact::is_url_terminator;
    use crate::redact::trim_trailing_punctuation;

    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(sep) = rest.find("://") {
        // Back up over the scheme: a run of ASCII scheme characters, so the
        // index lands on a character boundary whatever precedes it.
        let start = rest[..sep].trim_end_matches(is_scheme_char).len();
        let end = rest[sep..]
            .find(|c| c != '\\' && is_url_terminator(c))
            .map_or(rest.len(), |i| sep + i);
        let url = trim_trailing_punctuation(&rest[start..end]);
        out.push_str(&rest[..start]);
        // A scheme that is empty or does not start with a letter is not one
        // `display_announce_url` reads, so the run shows only as its marker.
        out.push_str(&display_announce_url(url).url);
        rest = &rest[start + url.len()..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker(verified: bool, updating: bool, fails: u32, err: Option<&str>) -> TrackerStatus {
        tracker_with(false, verified, updating, fails, err)
    }

    fn tracker_with(
        working: bool,
        verified: bool,
        updating: bool,
        fails: u32,
        err: Option<&str>,
    ) -> TrackerStatus {
        TrackerStatus::of(&torrentd_engine::TrackerEntry {
            url: "http://t/a".into(),
            tier: 0,
            verified,
            updating,
            working,
            fails,
            message: None,
            last_error: err.map(str::to_owned),
            next_announce: None,
            scrape_complete: None,
            scrape_incomplete: None,
        })
    }

    #[test]
    fn tracker_status_follows_the_documented_order() {
        assert_eq!(tracker(false, false, 0, None), TrackerStatus::NotContacted);
        assert_eq!(tracker(false, true, 0, None), TrackerStatus::Updating);
        assert_eq!(tracker(true, false, 0, None), TrackerStatus::Working);
        assert_eq!(tracker(true, true, 0, None), TrackerStatus::Updating);
        // An error text wins over everything, even a tracker that once worked.
        assert_eq!(
            tracker(true, true, 1, Some("refused")),
            TrackerStatus::Error
        );
        // Failures without an error text: an error only if it never worked.
        assert_eq!(tracker(false, false, 2, None), TrackerStatus::Error);
        assert_eq!(tracker(true, false, 2, None), TrackerStatus::Working);
    }

    /// One endpoint announcing and another failing is a working tracker. The
    /// failing endpoint's count is the `fails` the entry carries, and its
    /// error the text, so without `working` this read as `error`.
    #[test]
    fn a_tracker_with_one_working_and_one_failing_endpoint_is_working() {
        assert_eq!(
            tracker_with(true, true, false, 3, Some("refused")),
            TrackerStatus::Working
        );
        assert_eq!(
            tracker_with(true, false, true, 3, None),
            TrackerStatus::Working
        );
        assert_eq!(
            tracker_with(false, true, false, 3, Some("refused")),
            TrackerStatus::Error
        );
    }

    #[test]
    fn a_tracker_message_never_carries_a_url_the_url_field_would_hide() {
        let shown =
            display_message("unregistered (see https://t.example/announce?pk=abc123), retry later");
        assert!(!shown.contains("abc123"), "{shown}");
        assert!(
            shown.starts_with("unregistered (see https://t.example/[redacted:"),
            "{shown}"
        );
        assert!(shown.ends_with("), retry later"), "{shown}");
        // Brackets and angle quotes the URL sits in survive, and nothing is
        // doubled or dropped around the marker.
        let shown = display_message(
            "[https://u:SECRET5@t.example/announce] <https://t.example/announce?pk=S>",
        );
        assert!(
            !shown.contains("SECRET5") && !shown.contains("pk=S"),
            "{shown}"
        );
        assert!(
            shown.starts_with("[https://t.example/[redacted:"),
            "{shown}"
        );
        assert!(shown.contains("] <https://t.example/[redacted:"), "{shown}");
        assert!(shown.ends_with("]>"), "{shown}");
        // The marker is the one the url field shows for the same URL.
        let raw = "https://t.example/announce?pk=abc123";
        assert!(
            display_message(raw) == crate::redact::display_announce_url(raw).url,
            "{}",
            display_message(raw)
        );
        // Non-ASCII right before a scheme, or as the scheme: no panic, and
        // nothing leaks.
        for text in [
            "→https://t.example/announce?pk=S",
            "é://x?pk=S",
            "voir«https://u:p@t.example/announce?pk=S»",
            "ü🙂https://t.example/announce?pk=S",
        ] {
            let shown = display_message(text);
            assert!(!shown.contains("pk=S") && !shown.contains("u:p"), "{shown}");
        }
        assert!(display_message("→https://t.example/announce?pk=S")
            .starts_with("→https://t.example/[redacted:"));
        // `://` at either end, doubled colons, and a scheme that starts with
        // a digit: never a panic, never the passkey.
        for text in [
            "://",
            "://SECRET",
            "x ://",
            "x::://y/?passkey=SECRET",
            "1https://t.example/announce?passkey=SECRET",
            "://://://SECRET",
            "https://t.example/announce\\?passkey=SECRET",
        ] {
            let shown = display_message(text);
            assert!(!shown.contains("SECRET"), "{text} -> {shown}");
        }
        // A `://` with no scheme is hidden whole.
        let shown = display_message("bad ://t.example/announce?passkey=SECRET end");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(
            shown.starts_with("bad [redacted:") && shown.ends_with(" end"),
            "{shown}"
        );
        assert_eq!(
            display_message("torrent not registered"),
            "torrent not registered"
        );
        let plain = display_message("moved to udp://t.example:6969/announce");
        assert_eq!(plain, "moved to udp://t.example:6969/announce");
    }
}
