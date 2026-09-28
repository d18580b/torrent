//! The loop: draw, wait for a key, a tick, a change notification or an
//! effect's result, apply it, spawn what it asks for, repeat.

use std::time::Duration;

use crossterm::event::Event;
use crossterm::event::EventStream;
use crossterm::event::KeyEventKind;
use futures_util::StreamExt as _;
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::api::Api;
use crate::app;
use crate::app::Effect;
use crate::app::Live;
use crate::app::Model;
use crate::app::Msg;

/// How often the UI redraws without input: spinners and toast expiry.
const TICK: Duration = Duration::from_millis(250);

/// Run until the user quits.
pub async fn run(mut model: Model, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    // The event stream follows whichever credential is in use: a sign-in or
    // a sign-out changes it.
    let (api_tx, api_rx) = watch::channel(model.api.clone());
    tokio::spawn(follow_events(api_rx, tx.clone()));

    spawn(&tx, vec![app::check_session(&model.api)]);
    let mut keys = EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while !model.quit {
        terminal.draw(|frame| crate::ui::view(&model, frame))?;
        let msg = tokio::select! {
            event = keys.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => Msg::Key(key),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e),
                None => break,
            },
            _ = tick.tick() => Msg::Tick,
            Some(msg) = rx.recv() => msg,
        };
        let effects = app::update(&mut model, msg);
        // A sign-in replaces the credential; the stream follows it.
        api_tx.send_if_modified(|current| {
            let changed = current.epoch != model.api.epoch;
            if changed {
                *current = model.api.clone();
            }
            changed
        });
        spawn(&tx, effects);
    }
    Ok(())
}

fn spawn(tx: &mpsc::UnboundedSender<Msg>, effects: Vec<Effect>) {
    for effect in effects {
        let tx = tx.clone();
        tokio::spawn(async move {
            let msg = effect.0.await;
            let _ = tx.send(msg);
        });
    }
}

/// Keep `GET /v1/events` open, turning each event into [`Msg::Changed`] and
/// reporting whether the stream is up. Reconnects with backoff, and at once
/// when the credential changes.
async fn follow_events(mut api_rx: watch::Receiver<Api>, tx: mpsc::UnboundedSender<Msg>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let api = api_rx.borrow_and_update().clone();
        // A refused credential stays refused: asking again only counts
        // against it on the daemon. Wait for another one instead.
        let mut refused = false;
        let reason = match api.client.stream_events().await {
            Ok(mut stream) => {
                let _ = tx.send(Msg::LiveChanged(Live::Streaming));
                backoff = Duration::from_secs(1);
                loop {
                    tokio::select! {
                        item = stream.next() => match item {
                            Some(Ok(_event)) => {
                                let _ = tx.send(Msg::Changed);
                            }
                            Some(Err(e)) => break format!("stream error: {e}"),
                            None => break "the daemon closed the stream".to_owned(),
                        },
                        changed = api_rx.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            break "credential changed".to_owned();
                        }
                    }
                }
            }
            Err(e) => {
                let failure = crate::api::Failure::from(e);
                refused = matches!(failure.status, Some(401 | 403));
                failure.message()
            }
        };
        if tx
            .send(Msg::LiveChanged(Live::Reconnecting {
                reason: reason.clone(),
            }))
            .is_err()
        {
            return;
        }
        tracing::debug!(target: "torrentctl::events", reason, "event stream down");
        let wait = if refused { Duration::MAX } else { backoff };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            changed = api_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
