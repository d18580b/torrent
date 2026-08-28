//! `GET /api/events` — a Server-Sent Events stream of change notifications.
//!
//! The client needs to know *when* to refetch, not what changed. Pushing the
//! deltas themselves would mean serialising per-torrent state on every tick,
//! which at a hundred thousand torrents is exactly the cost the state map was
//! designed to avoid; a bare tick lets the client refetch only the panels it
//! has mounted.
//!
//! SSE rather than a WebSocket because the traffic is one-directional and SSE
//! reconnects on its own, so a dropped connection needs no client logic beyond
//! the polling fallback that already exists.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::Event;
use axum::response::sse::KeepAlive;
use axum::response::sse::Sse;
use futures_util::stream::Stream;
use seederd_engine::heartbeat_age;

use crate::app_state::AppState;

/// How often to consider emitting a tick. Matches the alert loop's own
/// `post_torrent_updates` cadence: emitting faster cannot surface anything
/// newer.
const TICK: Duration = Duration::from_secs(1);

/// Minimum gap between ticks actually sent when nothing is changing, so an idle
/// pool costs one message a second per client rather than a busy loop.
const IDLE_TICK: Duration = Duration::from_secs(10);

pub async fn events(
    State(s): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let mut last_fingerprint = u64::MAX;
        let mut last_emit = std::time::Instant::now() - IDLE_TICK;

        loop {
            tokio::time::sleep(TICK).await;

            // A cheap summary of the things a client would re-render for.
            // Comparing it avoids waking every browser once a second for a
            // pool that is not doing anything.
            let fp = fingerprint(&s);
            let idle_due = last_emit.elapsed() >= IDLE_TICK;
            if fp == last_fingerprint && !idle_due {
                continue;
            }
            last_fingerprint = fp;
            last_emit = std::time::Instant::now();

            yield Ok(Event::default().event("tick").data(fp.to_string()));
        }
    };

    Sse::new(stream).keep_alive(
        // Proxies drop idle connections; the comment frames keep them open
        // without the client having to reconnect.
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// Collapse the state a client renders into one number.
///
/// Deliberately coarse: it needs to change when something visible changes, not
/// to describe what. Torrent count, aggregate rates and the alert-loop
/// heartbeat between them cover adds, removals, rate changes and the loop
/// stalling.
fn fingerprint(s: &AppState) -> u64 {
    let mut acc: u64 = 1469598103934665603;
    let mut mix = |v: u64| {
        acc ^= v;
        acc = acc.wrapping_mul(1099511628211);
    };

    mix(s.registry.len() as u64);
    mix(s.state.len() as u64);
    mix(s.state.pending_resume_count());

    let mut up = 0i64;
    let mut seeding = 0u64;
    s.registry.for_each(|ih, _| {
        if let Some(st) = s.state.get(ih) {
            up += st.upload_rate;
            if st.is_seeding {
                seeding += 1;
            }
        }
    });
    mix(up as u64);
    mix(seeding);

    if let Some(pool) = &s.pool {
        mix(pool.verify_queue().depth() as u64);
        mix(pool.verify_queue().in_flight() as u64);
        mix(pool.verify_queue().completed());
    }

    // Coarse enough not to churn, fine enough that a stalled loop shows up.
    mix(heartbeat_age(&s.alert_heartbeat).as_secs());
    acc
}
