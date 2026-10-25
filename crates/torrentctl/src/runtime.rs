//! The loop: draw, wait for a key, a tick, a change notification or an
//! effect's result, apply it, spawn what it asks for, repeat.
//!
//! However the loop ends — a quit, a draw or input error, the end of the
//! input, a panic, or SIGHUP, SIGINT or SIGTERM — a session token this
//! client minted is revoked before it returns ([`finish`]).

use std::panic::AssertUnwindSafe;
use std::time::Duration;

use crossterm::event::Event;
use crossterm::event::EventStream;
use crossterm::event::KeyEventKind;
use futures_util::FutureExt as _;
use futures_util::Stream;
use futures_util::StreamExt as _;
use ratatui::DefaultTerminal;
use tokio::signal::unix::signal;
use tokio::signal::unix::Signal;
use tokio::signal::unix::SignalKind;
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

/// Set in the environment, the loop panics right after its first draw: how
/// `tests/e2e.rs` proves, under a pty, that a panic hands the terminal back
/// (the alternate screen left, the cursor shown) rather than leaving it raw.
pub const PANIC_AFTER_DRAW: &str = "TORRENTCTL_TEST_PANIC";

/// How long [`finish`] may take after an exit the user did not ask for: long
/// enough for a revocation to answer or reach [`app::REVOKE_TIMEOUT`], short
/// enough that a SIGTERM is not answered with a SIGKILL first.
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

/// How the loop ended: the model as it was left (its
/// [`Model::exit_notice`] is what to tell the user once the terminal is
/// theirs again), and whether the terminal failed.
pub struct Ended {
    pub model: Model,
    pub result: std::io::Result<()>,
}

/// SIGHUP (the terminal went away), SIGINT and SIGTERM, caught so that they
/// end the loop through [`finish`] rather than kill the process with a
/// minted token still live. Installed once, before the loop starts: from
/// then on these signals no longer terminate the process by themselves.
pub struct Signals {
    hangup: Signal,
    interrupt: Signal,
    terminate: Signal,
}

impl Signals {
    pub fn install() -> std::io::Result<Self> {
        Ok(Self {
            hangup: signal(SignalKind::hangup())?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// The name of the next signal to arrive.
    async fn recv(&mut self) -> &'static str {
        tokio::select! {
            _ = self.hangup.recv() => "SIGHUP",
            _ = self.interrupt.recv() => "SIGINT",
            _ = self.terminate.recv() => "SIGTERM",
        }
    }
}

/// Run on the terminal until the user quits or the loop otherwise ends.
pub async fn run(model: Model, terminal: &mut DefaultTerminal) -> Ended {
    let signals = match Signals::install() {
        Ok(signals) => signals,
        Err(e) => {
            return Ended {
                model,
                result: Err(e),
            };
        }
    };
    run_with(
        model,
        |model| {
            terminal
                .draw(|frame| crate::ui::view(model, frame))
                .map(drop)
        },
        EventStream::new(),
        signals,
    )
    .await
}

/// [`run`], drawing with `draw` and reading terminal events from `keys`.
/// Whatever ends the loop, a session token the model minted is revoked
/// before this returns; a panic in the loop is resumed once it has been.
pub async fn run_with<K>(
    mut model: Model,
    draw: impl FnMut(&Model) -> std::io::Result<()>,
    keys: K,
    mut signals: Signals,
) -> Ended
where
    K: Stream<Item = std::io::Result<Event>> + Unpin,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    // The event stream follows whichever credential is in use: a sign-in or
    // a sign-out changes it.
    let (api_tx, api_rx) = watch::channel(model.api.clone());
    tokio::spawn(follow_events(api_rx, tx.clone()));
    spawn(&tx, vec![app::check_session(&model.api)]);

    let looped = AssertUnwindSafe(drive(
        &mut model,
        draw,
        keys,
        &mut signals,
        &tx,
        &mut rx,
        &api_tx,
    ))
    .catch_unwind()
    .await;
    if !model.quit {
        finish(&mut model, &tx, &mut rx, &mut signals).await;
    }
    match looped {
        Ok(result) => Ended { model, result },
        Err(panic) => {
            // The panic hook has handed the terminal back already, so this
            // stays on the operator's screen.
            if let Some(notice) = &model.exit_notice {
                eprintln!("{notice}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}

/// The loop itself: until the model quits, the input ends or fails, a draw
/// fails, or a signal arrives.
async fn drive<K>(
    model: &mut Model,
    mut draw: impl FnMut(&Model) -> std::io::Result<()>,
    mut keys: K,
    signals: &mut Signals,
    tx: &mpsc::UnboundedSender<Msg>,
    rx: &mut mpsc::UnboundedReceiver<Msg>,
    api_tx: &watch::Sender<Api>,
) -> std::io::Result<()>
where
    K: Stream<Item = std::io::Result<Event>> + Unpin,
{
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while !model.quit {
        draw(model)?;
        if std::env::var_os(PANIC_AFTER_DRAW).is_some() {
            panic!("{PANIC_AFTER_DRAW} is set");
        }
        let msg = tokio::select! {
            event = keys.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => Msg::Key(key),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e),
                None => {
                    tracing::info!(target: "torrentctl::runtime", "the terminal input ended");
                    return Ok(());
                }
            },
            name = signals.recv() => {
                tracing::info!(target: "torrentctl::runtime", signal = name, "signalled to leave");
                return Ok(());
            }
            _ = tick.tick() => Msg::Tick,
            Some(msg) = rx.recv() => msg,
        };
        let effects = app::update(model, msg);
        // A sign-in replaces the credential; the stream follows it.
        api_tx.send_if_modified(|current| {
            let changed = current.epoch != model.api.epoch;
            if changed {
                *current = model.api.clone();
            }
            changed
        });
        spawn(tx, effects);
    }
    Ok(())
}

/// Finish an exit the user did not ask for as a quit would: revoke a minted
/// token, or wait for an in-flight sign-in to answer and revoke what it
/// mints — without drawing, since the terminal may be gone. Bounded by
/// [`FINISH_TIMEOUT`]; a second signal leaves at once.
async fn finish(
    model: &mut Model,
    tx: &mpsc::UnboundedSender<Msg>,
    rx: &mut mpsc::UnboundedReceiver<Msg>,
    signals: &mut Signals,
) {
    // A quit already under way has its revocation in flight: wait for it
    // rather than quit a second time, which would leave at once.
    if !model.quitting {
        let effects = app::update(model, Msg::Quit);
        spawn(tx, effects);
    }
    let deadline = tokio::time::Instant::now() + FINISH_TIMEOUT;
    while !model.quit {
        let msg = tokio::select! {
            Some(msg) = rx.recv() => msg,
            () = tokio::time::sleep_until(deadline) => {
                tracing::warn!(target: "torrentctl::runtime", "the session token was not revoked within {FINISH_TIMEOUT:?}");
                model.exit_notice.get_or_insert_with(|| {
                    format!(
                        "torrentctl: the session token was not revoked within {}s; it stays \
                         valid on the daemon until it expires",
                        FINISH_TIMEOUT.as_secs()
                    )
                });
                return;
            }
            name = signals.recv() => {
                tracing::warn!(target: "torrentctl::runtime", signal = name, "signalled again: leaving without revoking");
                return;
            }
        };
        let effects = app::update(model, msg);
        spawn(tx, effects);
    }
}

/// Run each effect on its own task, sending its message to `tx`.
pub fn spawn(tx: &mpsc::UnboundedSender<Msg>, effects: Vec<Effect>) {
    for effect in effects {
        let tx = tx.clone();
        tokio::spawn(async move {
            let msg = effect.0.await;
            let _ = tx.send(msg);
        });
    }
}

/// How long the event stream may go without an event before it is taken
/// for dead. The daemon sends a tick at least every ten seconds, so three
/// missed ones mean a wedged daemon or a stalled connection — which, left
/// alone, would read "live" for ever while nothing arrives. Opening the
/// stream is held to the same bound.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How [`follow_events`] paces itself: [`Timing::DAEMON`], or shorter in a
/// test that watches it on the real clock.
#[derive(Clone, Copy, Debug)]
struct Timing {
    /// See [`IDLE_TIMEOUT`].
    idle: Duration,
    /// The first wait before reconnecting, doubled after each failed attempt.
    first_backoff: Duration,
    /// The longest the backoff grows to.
    max_backoff: Duration,
}

impl Timing {
    const DAEMON: Self = Self {
        idle: IDLE_TIMEOUT,
        first_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(30),
    };
}

/// Why the stream went down, and what that means for the wait before the
/// next attempt.
enum Down {
    /// The stream failed or was refused; wait before trying again.
    Failed { reason: String, refused: bool },
    /// The credential changed: the old stream belongs to a credential no
    /// longer in use, so open one with the new one at once.
    CredentialChanged,
    /// The UI is gone.
    Closed,
}

/// Keep `GET /v1/events` open, turning each event into [`Msg::Changed`] with
/// its fingerprint (the model decides whether it is news) and reporting
/// whether the stream is up: [`Live::Streaming`] once an event has arrived,
/// [`Live::Reconnecting`] when it fails or falls silent for
/// [`IDLE_TIMEOUT`]. Reconnects with backoff, never sooner than the
/// daemon's own `retry`, and at once when the credential changes.
pub async fn follow_events(api_rx: watch::Receiver<Api>, tx: mpsc::UnboundedSender<Msg>) {
    follow_events_paced(api_rx, tx, Timing::DAEMON).await;
}

async fn follow_events_paced(
    mut api_rx: watch::Receiver<Api>,
    tx: mpsc::UnboundedSender<Msg>,
    timing: Timing,
) {
    let mut backoff = timing.first_backoff;
    // The daemon's SSE `retry`, from the last stream that carried one: the
    // floor of every wait, since reconnecting sooner is what it asked not to
    // happen.
    let mut server_retry = Duration::ZERO;
    loop {
        let api = api_rx.borrow_and_update().clone();
        let down = tokio::select! {
            down = follow_once(&api, &tx, timing, &mut backoff, &mut server_retry) => down,
            changed = api_rx.changed() => match changed {
                Ok(()) => Down::CredentialChanged,
                Err(_) => Down::Closed,
            },
        };
        let (reason, wait) = match down {
            Down::Closed => return,
            Down::CredentialChanged => {
                backoff = timing.first_backoff;
                ("credential changed".to_owned(), None)
            }
            // A refused credential stays refused: asking again only counts
            // against it on the daemon. Wait for another one instead.
            Down::Failed { reason, refused } => (
                reason,
                Some(if refused {
                    Duration::MAX
                } else {
                    backoff.max(server_retry)
                }),
            ),
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
        let Some(wait) = wait else {
            continue;
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                backoff = (backoff * 2).min(timing.max_backoff);
            }
            changed = api_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                backoff = timing.first_backoff;
            }
        }
    }
}

/// Open the stream with `api` and follow it until it fails, is refused, or
/// falls silent for `timing.idle`.
async fn follow_once(
    api: &Api,
    tx: &mpsc::UnboundedSender<Msg>,
    timing: Timing,
    backoff: &mut Duration,
    server_retry: &mut Duration,
) -> Down {
    let idle = timing.idle;
    let mut stream = match tokio::time::timeout(idle, api.client.stream_events()).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let failure = crate::api::Failure::from(e);
            return Down::Failed {
                refused: matches!(failure.status, Some(401 | 403)),
                reason: failure.message(),
            };
        }
        Err(_) => {
            return Down::Failed {
                reason: format!("the daemon did not open the stream within {idle:?}"),
                refused: false,
            };
        }
    };
    let mut streaming = false;
    loop {
        let item = tokio::time::timeout(idle, stream.next()).await;
        if let Some(retry) = stream.reconnect_delay() {
            *server_retry = retry;
        }
        let event = match item {
            Ok(Some(Ok(event))) => event,
            Ok(Some(Err(e))) => {
                return Down::Failed {
                    reason: format!("stream error: {e}"),
                    refused: false,
                };
            }
            Ok(None) => {
                return Down::Failed {
                    reason: "the daemon closed the stream".to_owned(),
                    refused: false,
                };
            }
            Err(_) => {
                return Down::Failed {
                    reason: format!("no event from the daemon for {idle:?}"),
                    refused: false,
                };
            }
        };
        // Live only once something has arrived: an open stream that never
        // delivers is not one.
        if !streaming {
            streaming = true;
            *backoff = timing.first_backoff;
            if tx.send(Msg::LiveChanged(Live::Streaming)).is_err() {
                return Down::Closed;
            }
        }
        if tx.send(Msg::Changed(event.fingerprint)).is_err() {
            return Down::Closed;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::Instant;

    use super::*;
    use crate::testing::EventServer;

    /// The daemon's pacing scaled down to run on the real clock: a paused
    /// one advances past a deadline while a loopback socket still has bytes
    /// in flight, which is the very race these tests time.
    const FAST: Timing = Timing {
        idle: Duration::from_millis(400),
        first_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_secs(30),
    };

    /// Longer than anything here waits for, so a test that fails says so
    /// rather than hanging.
    const PATIENCE: Duration = Duration::from_secs(20);

    /// Slack for a loaded machine on an upper bound.
    const SLACK: Duration = Duration::from_millis(900);

    /// `follow_events` paced by `timing` on `token` against `server`, with
    /// what it sends.
    fn follow(
        server: &EventServer,
        token: &str,
        timing: Timing,
    ) -> (watch::Sender<Api>, mpsc::UnboundedReceiver<Msg>) {
        let api = Api::new(&server.url, Some(token)).expect("a valid URL");
        let (api_tx, api_rx) = watch::channel(api);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(follow_events_paced(api_rx, tx, timing));
        (api_tx, rx)
    }

    async fn next(rx: &mut mpsc::UnboundedReceiver<Msg>) -> Msg {
        tokio::time::timeout(PATIENCE, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("follow_events sent nothing within {PATIENCE:?}"))
            .expect("follow_events is running")
    }

    async fn next_live(rx: &mut mpsc::UnboundedReceiver<Msg>) -> Live {
        match next(rx).await {
            Msg::LiveChanged(live) => live,
            other => panic!("expected a stream state, got {other:?}"),
        }
    }

    async fn next_changed(rx: &mut mpsc::UnboundedReceiver<Msg>) -> String {
        match next(rx).await {
            Msg::Changed(fingerprint) => fingerprint,
            other => panic!("expected a tick, got {other:?}"),
        }
    }

    fn reason(live: Live) -> String {
        match live {
            Live::Reconnecting { reason } => reason,
            other => panic!("expected the stream down, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_stream_that_falls_silent_is_down_after_the_idle_timeout() {
        let mut server = EventServer::start().await;
        let (_api_tx, mut rx) = follow(&server, "tdp_a", FAST);
        let mut stream = server.next(PATIENCE).await;
        stream.open().await;
        // Taken before the tick is sent, so the follower's wait for the next
        // one cannot have started earlier.
        let last_tick = Instant::now();
        stream.tick("00000000000000aa", "").await;
        assert_eq!(next_live(&mut rx).await, Live::Streaming);
        assert_eq!(next_changed(&mut rx).await, "00000000000000aa");

        // The connection stays open and says nothing: a wedged daemon.
        let reason = reason(next_live(&mut rx).await);
        let silent = last_tick.elapsed();
        assert!(reason.contains("no event"), "{reason}");
        assert!(
            silent >= FAST.idle && silent < FAST.idle + SLACK,
            "down after {silent:?} of silence"
        );
        server.next(PATIENCE).await;
        drop(stream);
    }

    #[tokio::test]
    async fn the_stream_is_live_only_once_an_event_arrives() {
        let mut server = EventServer::start().await;
        let (_api_tx, mut rx) = follow(&server, "tdp_a", FAST);
        let mut silent = server.next(PATIENCE).await;
        silent.open().await;
        // Opened, but nothing ever arrives: never live.
        let reason = reason(next_live(&mut rx).await);
        assert!(reason.contains("no event"), "{reason}");
        drop(silent);

        let mut stream = server.next(PATIENCE).await;
        stream.open().await;
        stream.tick("00000000000000bb", "").await;
        assert_eq!(next_live(&mut rx).await, Live::Streaming);
        assert_eq!(next_changed(&mut rx).await, "00000000000000bb");
    }

    #[tokio::test]
    async fn reconnects_wait_at_least_the_servers_retry() {
        let mut server = EventServer::start().await;
        let (_api_tx, mut rx) = follow(&server, "tdp_a", FAST);
        let mut stream = server.next(PATIENCE).await;
        stream.open().await;
        // The daemon sends its `retry` with its first tick.
        stream.tick("00000000000000aa", "retry: 1000\n").await;
        assert_eq!(next_live(&mut rx).await, Live::Streaming);
        next_changed(&mut rx).await;

        drop(stream);
        let dropped = Instant::now();
        reason(next_live(&mut rx).await);
        let refused = server.next(PATIENCE).await;
        let waited = refused.at - dropped;
        assert!(
            waited >= Duration::from_secs(1),
            "reconnected after {waited:?}, sooner than the daemon's retry"
        );

        // A failed attempt carries no `retry` of its own; the last one the
        // daemon sent still holds over the 100ms backoff.
        let at = refused.at;
        refused.refuse("503 Service Unavailable").await;
        reason(next_live(&mut rx).await);
        let again = server.next(PATIENCE).await;
        let waited = again.at - at;
        assert!(
            waited >= Duration::from_secs(1),
            "retried after {waited:?}, sooner than the daemon's retry"
        );
    }

    #[tokio::test]
    async fn a_new_credential_reconnects_at_once_with_it() {
        let mut server = EventServer::start().await;
        // A backoff long enough that waiting it out cannot pass for "at once".
        let slow = Timing {
            first_backoff: Duration::from_secs(10),
            ..FAST
        };
        let (api_tx, mut rx) = follow(&server, "tdp_a", slow);
        let mut stream = server.next(PATIENCE).await;
        assert_eq!(stream.bearer.as_deref(), Some("tdp_a"));
        stream.open().await;
        stream.tick("00000000000000aa", "retry: 5000\n").await;
        assert_eq!(next_live(&mut rx).await, Live::Streaming);
        next_changed(&mut rx).await;

        let next_api = api_tx.borrow().with_token("tds_b").expect("a valid URL");
        api_tx.send(next_api).expect("follow_events is running");
        let changed = Instant::now();
        assert_eq!(reason(next_live(&mut rx).await), "credential changed");
        let reopened = server.next(PATIENCE).await;
        assert_eq!(reopened.bearer.as_deref(), Some("tds_b"));
        let waited = reopened.at - changed;
        assert!(waited < SLACK, "reconnected after {waited:?}, not at once");
        drop(stream);
    }

    /// A daemon that takes the request and never sends a response head is
    /// down after the idle timeout, not the request timeout.
    #[tokio::test]
    async fn a_stream_that_never_opens_is_down_after_the_idle_timeout() {
        let mut server = EventServer::start().await;
        let (_api_tx, mut rx) = follow(&server, "tdp_a", FAST);
        let wedged = server.next(PATIENCE).await;
        let reason = reason(next_live(&mut rx).await);
        let waited = wedged.at.elapsed();
        assert!(reason.contains("did not open the stream"), "{reason}");
        assert!(
            waited < FAST.idle + SLACK,
            "down after {waited:?} without a response"
        );
        server.next(PATIENCE).await;
        drop(wedged);
    }

    #[tokio::test]
    async fn a_new_credential_during_a_wait_reconnects_at_once_from_the_first_backoff() {
        let mut server = EventServer::start().await;
        // Long enough that the doubled backoff is told apart from the first.
        let paced = Timing {
            first_backoff: Duration::from_secs(1),
            ..FAST
        };
        let (api_tx, mut rx) = follow(&server, "tdp_a", paced);
        // Two refusals in a row: the second wait is the doubled backoff, 2s.
        for _ in 0..2 {
            let refused = server.next(PATIENCE).await;
            refused.refuse("503 Service Unavailable").await;
            reason(next_live(&mut rx).await);
        }

        // A new credential arrives during that wait.
        let next_api = api_tx.borrow().with_token("tds_b").expect("a valid URL");
        api_tx.send(next_api).expect("follow_events is running");
        let changed = Instant::now();
        let reopened = server.next(PATIENCE).await;
        assert_eq!(reopened.bearer.as_deref(), Some("tds_b"));
        let waited = reopened.at - changed;
        assert!(waited < SLACK, "reconnected after {waited:?}, not at once");

        // Refused again, it waits the first backoff, not the doubled one.
        let at = reopened.at;
        reopened.refuse("503 Service Unavailable").await;
        reason(next_live(&mut rx).await);
        let again = server.next(PATIENCE).await;
        let waited = again.at - at;
        assert!(
            waited >= paced.first_backoff && waited < 2 * paced.first_backoff,
            "retried after {waited:?}: the backoff was not reset"
        );
    }
}
