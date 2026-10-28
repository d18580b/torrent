//! What can be done to one torrent or to all of them: which actions go at
//! once and which ask first, the requests they send, and what they report.

use super::list::selected_summary;
use super::Msg;
use super::Pending;
use super::State;
use crate::api::types;
use crate::api::Api;
use crate::fmt;
use crate::screens::contract::Ctx;
use crate::screens::contract::Effect;
use crate::screens::contract::Toast;
use crate::screens::contract::ToastKind;
use crate::ui::widgets::Confirm;

/// Something done to one torrent, or to all of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Pause,
    Resume,
    Recheck,
    Reannounce,
    Remove,
    /// Remove, and delete the payload.
    RemoveFiles,
    PauseAll,
    ResumeAll,
}

impl Action {
    pub(super) fn doing(self) -> &'static str {
        match self {
            Action::Pause => "pausing",
            Action::Resume => "resuming",
            Action::Recheck => "rechecking",
            Action::Reannounce => "reannouncing",
            Action::Remove => "removing",
            Action::RemoveFiles => "removing with files",
            Action::PauseAll => "pausing every torrent",
            Action::ResumeAll => "resuming every torrent",
        }
    }
}
/// Start `action`: at once for what is harmless and undoable, behind a
/// confirmation for what removes anything or touches every torrent.
pub(super) fn act(state: &mut State, action: Action, ctx: &Ctx<'_>) -> Vec<Effect> {
    match action {
        Action::PauseAll => {
            state.confirm = Some((
                Confirm::new(
                    "Pause every torrent",
                    "Pause every torrent of every live profile? They stop announcing and serving \
                     peers until resumed.",
                ),
                Pending::PauseAll,
            ));
            return Vec::new();
        }
        Action::ResumeAll => {
            state.confirm = Some((
                Confirm::new(
                    "Resume every torrent",
                    "Resume every torrent? Fenced (vpn_down) and failed profiles are skipped.",
                ),
                Pending::ResumeAll,
            ));
            return Vec::new();
        }
        _ => {}
    }
    let target = match &state.detail {
        Some(detail) => Some((detail.hash.clone(), detail.name().map(str::to_owned))),
        None => selected_summary(state).map(|s| (s.infohash.clone(), None)),
    };
    let Some((hash, name)) = target else {
        return Vec::new();
    };
    let what = match name {
        Some(name) => format!("{name} ({})", fmt::short_hash(&hash)),
        None => fmt::short_hash(&hash).to_owned(),
    };
    match action {
        Action::Remove => {
            state.confirm = Some((
                Confirm::new(
                    "Remove torrent",
                    format!("Remove {what}? The daemon forgets it; its payload stays on disk."),
                ),
                Pending::Act(action, hash),
            ));
            Vec::new()
        }
        Action::RemoveFiles if !ctx.pool_mutations_allowed() => vec![Effect::toast(Toast::info(
            "deleting files needs [pool] allow_mutations in the daemon's config; `d` removes and \
             keeps them",
        ))],
        Action::RemoveFiles => {
            state.confirm = Some((
                Confirm::new(
                    "Remove torrent and delete files",
                    format!(
                        "Remove {what} and move its payload to the pool's trash? The daemon \
                         forgets it; the files can be restored from .torrentd-trash."
                    ),
                )
                .typed("delete"),
                Pending::Act(action, hash),
            ));
            Vec::new()
        }
        _ => vec![perform(ctx.api, action, hash)],
    }
}

/// The request `action` sends for the torrent `hash`, answering with what
/// it did.
pub(super) fn perform(api: &Api, action: Action, hash: String) -> Effect {
    let api = api.clone();
    Effect::new(async move {
        let client = &api.client;
        let h = hash.clone();
        let result = match action {
            Action::Pause => crate::api::call(client.pause_torrent(h)).await,
            Action::Resume => crate::api::call(client.resume_torrent(h)).await,
            Action::Recheck => crate::api::call(client.recheck_torrent(h)).await,
            Action::Reannounce => crate::api::call(client.reannounce_torrent(h)).await,
            Action::Remove => crate::api::call(client.delete_torrent(h, None)).await,
            Action::RemoveFiles => {
                // The typed confirmation the operator gave is what the
                // daemon's `confirm` stands for: name the torrent again.
                let params = crate::api::generated::DeleteTorrentParams {
                    delete_files: Some(true),
                    confirm: Some(h.clone()),
                };
                crate::api::call(client.delete_torrent(h, params)).await
            }
            // Never reach here: every torrent goes through `bulk`.
            Action::PauseAll | Action::ResumeAll => Ok(()),
        };
        crate::app::Msg::Torrents(Msg::Acted {
            action,
            hash,
            result,
        })
    })
}

/// Pause or resume every torrent.
pub(super) fn bulk(api: &Api, pause: bool) -> Effect {
    let api = api.clone();
    Effect::new(async move {
        let result = if pause {
            crate::api::call(api.client.pause_all_torrents()).await
        } else {
            // Unbounded: the daemon resumes 100 torrents a second, and
            // answers once the last is.
            crate::api::call_unbounded(api.client.resume_all_torrents()).await
        };
        crate::app::Msg::Torrents(Msg::Bulk { pause, result })
    })
}

/// What a pause-all or resume-all did, with what it did not reach.
pub(super) fn bulk_toast(pause: bool, outcome: &types::BulkOutcome) -> Toast {
    let verb = if pause { "paused" } else { "resumed" };
    let mut text = format!("{verb} {} torrents", fmt::count(outcome.torrent_count));
    if outcome.failed_count > 0 {
        text.push_str(&format!(
            "; {} failed and are still {}",
            fmt::count(outcome.failed_count),
            if pause { "running" } else { "paused" }
        ));
    }
    for skipped in &outcome.skipped_profiles {
        text.push_str(&format!(
            "; skipped {} ({}: {})",
            skipped.profile_id, skipped.reason, skipped.detail
        ));
    }
    let kind = if outcome.failed_count > 0 {
        ToastKind::Error
    } else if outcome.skipped_profiles.is_empty() {
        ToastKind::Success
    } else {
        ToastKind::Info
    };
    Toast {
        kind,
        text,
        request_id: None,
    }
}
