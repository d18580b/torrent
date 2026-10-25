//! Listing and reading: `GET /v1/torrents` and `GET /v1/torrents/{infohash}`.

use std::sync::Arc;

use kynos::prelude::*;
use kynos::security::auth::Scoped;
use libtorrent_safe::InfoHash;
use torrentd_engine::ProfileId;
use torrentd_engine::TorrentDetails;
use torrentd_engine::TorrentEngine;
use tracing::warn;

use super::model::Torrent;
use super::model::TorrentPage;
use super::model::TorrentPath;
use super::model::TorrentPhase;
use super::model::TorrentSummary;
use crate::app_state::AppState;
use crate::http::page::paginate;
use crate::http::page::PageLimit;
use crate::http::page::PageRequest;
use crate::http::security::Bearer;
use crate::http::security::Read;
use crate::http::v1::common::blocking;
use crate::http::v1::Torrents;
use crate::http::validate::from_invalid;
use crate::http::validate::Invalid;

/// The listing name torrent cursors are bound to.
const TORRENTS_LISTING: &str = "torrents";

/// Which torrents to list, and which page.
#[derive(Schema, QueryParams)]
pub struct ListTorrentsQuery {
    /// Only the torrents assigned to this profile. A profile that failed to
    /// come up is still listed; an id no profile declares is
    /// `404 profile-not-found`, not an empty page.
    pub profile_id: Option<String>,
    /// Only the torrents in this phase.
    pub phase: Option<TorrentPhase>,
    /// Resume after the page this cursor ended.
    pub cursor: Option<String>,
    /// Torrents per page, 1 to 1000; 100 when absent.
    pub limit: Option<PageLimit>,
}

torrent_error! {
    /// Why the torrents could not be listed.
    pub enum ListTorrentsError {
        /// The cursor is not one this listing issued.
        #[error("the cursor is not one this listing issued; start again without it")]
        #[problem(status = 400, title = "Invalid cursor")]
        InvalidCursor,
        /// No profile with this `profile_id` is configured.
        #[error("unknown profile_id")]
        #[problem(status = 404, title = "Profile not found")]
        ProfileNotFound,
        /// A query parameter is out of range.
        #[error("{summary}")]
        #[problem(status = 422, title = "The request is invalid")]
        ValidationFailed {
            summary: String,
            #[problem(extension)]
            errors: serde_json::Value,
        },
    }
}
from_invalid!(ListTorrentsError);

/// List torrents.
///
/// Every torrent the daemon holds an assignment for, loaded or not, ordered
/// by infohash and paged with `cursor`. Filter by `profile_id` and `phase`.
/// Rates, totals and phase come from the state the alert loop keeps, so a
/// page costs no call into libtorrent. Each item is a `TorrentSummary`; what
/// only a session can answer — name, size, save path, upload limit — is on
/// `GET /v1/torrents/{infohash}`.
#[kynos::get("/torrents", tag = Torrents)]
pub async fn list_torrents(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Query(q): Query<ListTorrentsQuery>,
) -> Result<Json<TorrentPage>, ListTorrentsError> {
    let mut invalid = Invalid::new();
    let page = PageRequest::parse(
        TORRENTS_LISTING,
        q.cursor.as_deref(),
        q.limit.map(PageLimit::get),
        crate::http::validate::is_infohash_hex,
        &mut invalid,
    )
    .map_err(|_| ListTorrentsError::InvalidCursor)?;
    invalid.finish()?;

    let profile_id = match q.profile_id {
        Some(id) => {
            let profile_id = ProfileId::new(id);
            // A failed profile's assignments are listed: this reads the
            // registry, not an engine.
            if matches!(
                s.profiles.resolve(&profile_id),
                crate::profile_registry::Resolution::Unknown
            ) {
                return Err(ListTorrentsError::ProfileNotFound);
            }
            Some(profile_id)
        }
        None => None,
    };
    // `is_infohash_hex` admitted the cursor's key, so it decodes.
    let after = page.after.as_deref().and_then(InfoHash::from_hex);
    let rows = first_after(
        s.registry.as_ref(),
        after,
        page.limit.saturating_add(1),
        |ih, p| {
            profile_id.as_ref().is_none_or(|want| p == want)
                && q.phase
                    .is_none_or(|phase| TorrentPhase::of(s.state.get(ih).as_ref()) == phase)
        },
    );

    let (rows, next_cursor) = paginate(TORRENTS_LISTING, rows, |(ih, _)| ih.to_hex(), &page);
    Ok(Json(TorrentPage {
        items: rows
            .iter()
            .map(|(ih, profile)| TorrentSummary::build(&s, ih, profile))
            .collect(),
        next_cursor,
    }))
}

/// The `take` smallest assignments by infohash that sort after `after` and
/// that `keep` admits, in ascending order.
///
/// One pass over the registry holding at most `take` entries, rather than a
/// copy of all of it sorted for every page: at a hundred thousand torrents
/// that was a hundred thousand clones and an `n log n` sort to answer a page
/// of a hundred. The caller asks for one more than a page, so the page
/// knows whether another follows.
fn first_after(
    registry: &crate::registry::AssignmentRegistry,
    after: Option<InfoHash>,
    take: usize,
    mut keep: impl FnMut(&InfoHash, &ProfileId) -> bool,
) -> Vec<(InfoHash, ProfileId)> {
    use std::collections::BinaryHeap;

    /// Ordered by infohash alone, so the heap's top is the largest kept.
    struct ByInfohash(InfoHash, ProfileId);
    impl PartialEq for ByInfohash {
        fn eq(&self, other: &Self) -> bool {
            self.0 .0 == other.0 .0
        }
    }
    impl Eq for ByInfohash {}
    impl PartialOrd for ByInfohash {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for ByInfohash {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0 .0.cmp(&other.0 .0)
        }
    }

    if take == 0 {
        return Vec::new();
    }
    let mut kept: BinaryHeap<ByInfohash> = BinaryHeap::with_capacity(take.min(1024) + 1);
    registry.for_each(|ih, p| {
        if after.is_some_and(|a| ih.0 <= a.0) {
            return;
        }
        // Already full of smaller ones: this cannot make the page.
        if kept.len() == take && kept.peek().is_some_and(|top| ih.0 >= top.0 .0) {
            return;
        }
        if !keep(ih, p) {
            return;
        }
        kept.push(ByInfohash(*ih, p.clone()));
        if kept.len() > take {
            kept.pop();
        }
    });
    kept.into_sorted_vec()
        .into_iter()
        .map(|ByInfohash(ih, p)| (ih, p))
        .collect()
}

torrent_error! {
    /// Why a torrent could not be read.
    pub enum GetTorrentError {
        /// No torrent with this infohash is assigned to any profile.
        #[error("no torrent with this infohash")]
        #[problem(status = 404, title = "Torrent not found")]
        TorrentNotFound,
    }
}

/// Read one torrent.
///
/// Everything the listing reports, plus what only its session can answer:
/// `name`, `total_size`, `save_path`, `upload_limit_bytes_per_sec` and
/// `added_at`. Those are `null` when no session holds the torrent (its profile
/// failed to come up, or the boot left it unloaded), or when the session
/// could not be asked; the rest is still reported.
#[kynos::get("/torrents/{infohash}", tag = Torrents)]
pub async fn get_torrent(
    _caller: Scoped<Bearer, Read>,
    Inject(s): Inject<Arc<AppState>>,
    Path(p): Path<TorrentPath>,
) -> Result<Json<Torrent>, GetTorrentError> {
    let ih = p.infohash.get();
    let profile = s
        .registry
        .lookup(&ih)
        .ok_or(GetTorrentError::TorrentNotFound)?;
    let details = match s.state.get(&ih) {
        Some(st) => details_of(&s, &profile, st.handle).await,
        None => None,
    };
    Ok(Json(Torrent::build(&s, &ih, &profile, details)))
}

/// The session's details for a loaded torrent, or `None` if it cannot be
/// asked. A torrent is still worth reporting without them.
async fn details_of(
    s: &AppState,
    profile: &ProfileId,
    handle: torrentd_engine::TorrentHandle,
) -> Option<TorrentDetails> {
    let engine = s.source.engine_for(profile)?;
    blocking(move || engine.torrent_details(handle))
        .await
        .inspect_err(|e| {
            warn!(
                target: "torrentd::http",
                infohash = %handle.infohash,
                error.cause = %e,
                "could not read a torrent's details from its session",
            );
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_the_smallest_kept_infohashes_after_the_cursor() {
        // Against the obvious implementation this replaced: copy, filter,
        // sort, skip, take.
        let dir = tempfile::tempdir().unwrap();
        let reg = crate::registry::AssignmentRegistry::new_empty(dir.path().join("r.json"));
        let mut all = Vec::new();
        for n in 0..60u8 {
            // Scrambled, so insertion order says nothing about sort order.
            let ih = InfoHash([n.wrapping_mul(37).wrapping_add(11); 20]);
            let p = ProfileId::new(if n % 3 == 0 { "a" } else { "b" });
            reg.assign(ih, p.clone()).unwrap();
            all.push((ih, p));
        }
        all.sort_by_key(|(ih, _)| ih.0);
        let want_b = ProfileId::new("b");
        for after in [None, Some(all[0].0), Some(all[29].0), Some(all[59].0)] {
            for take in [0, 1, 7, 60, 100] {
                let naive: Vec<_> = all
                    .iter()
                    .filter(|(ih, p)| after.is_none_or(|a| ih.0 > a.0) && *p == want_b)
                    .take(take)
                    .cloned()
                    .collect();
                let got = first_after(&reg, after, take, |_, p| *p == want_b);
                assert_eq!(
                    got.iter().map(|(ih, _)| ih.0).collect::<Vec<_>>(),
                    naive.iter().map(|(ih, _)| ih.0).collect::<Vec<_>>(),
                    "after {:?}, take {take}",
                    after.map(|a| a.to_hex()),
                );
            }
        }
    }
}
