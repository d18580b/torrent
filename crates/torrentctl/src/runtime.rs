//! The loop: draw, wait for a key, a tick, a change notification or an
//! effect's result, apply it, spawn what it asks for, repeat.
//!
//! However the loop ends — a quit, a draw or input error, the end of the
//! input, a panic, or SIGHUP, SIGINT or SIGTERM — a session token this
//! client minted is revoked before it returns ([`finish`]).

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use crossterm::event::Event;
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

/// Set in the environment, the loop spawns an effect that panics right after
/// its first draw: how `tests/e2e.rs` proves that a panic on a background
/// task stops the loop and exits, rather than leaving it drawing over a
/// terminal the panic hook already restored.
pub const PANIC_IN_TASK: &str = "TORRENTCTL_TEST_PANIC_IN_TASK";

/// Set in the environment, the loop parks a blocking thread for good right
/// after its first draw, then quits: how `tests/e2e.rs` proves that the
/// process still exits within its bound when a blocking thread never
/// returns, as one stuck in a name resolution that never answers does.
pub const STALL_BLOCKING: &str = "TORRENTCTL_TEST_STALL_BLOCKING";

/// How long [`finish`] may take after an exit the user did not ask for: long
/// enough for a revocation to answer or reach [`app::REVOKE_TIMEOUT`], short
/// enough that a SIGTERM is not answered with a SIGKILL first.
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long after the signal that ended the loop the same signal again is
/// taken for a repeat of it rather than a second ask to leave at once. When a
/// terminal closes, the foreground job usually gets two SIGHUPs within
/// milliseconds: the one the shell resends to its jobs, and the one the
/// kernel sends to the foreground group when the shell exits.
pub const REPEAT_GRACE: Duration = Duration::from_secs(1);

/// How long [`finish`], once its work is done, waits for a SIGHUP after the
/// loop ended on its own — a draw or input error, or the end of the input.
/// A terminal that hangs up fails the draw or the read with EIO in the same
/// instant the kernel sends the SIGHUP, and either can reach the loop
/// first; without the wait, an exit with no token to revoke would leave
/// before the SIGHUP was seen and report a terminal failure, not a hangup.
pub const HANGUP_GRACE: Duration = Duration::from_millis(500);

/// How the loop ended: the model as it was left (its
/// [`Model::exit_notice`] is what to tell the user once the terminal is
/// theirs again, and its [`Model::fatal`] says a background task panicked),
/// whether the terminal failed, and the signal that ended it, if one did.
pub struct Ended {
    pub model: Model,
    pub result: std::io::Result<()>,
    pub signal: Option<&'static str>,
}

/// The exit status a process ended by `signal` reports by convention:
/// 128 plus the signal's number, as a shell reports one the signal killed.
pub fn signal_exit_status(signal: &str) -> u8 {
    let kind = match signal {
        "SIGHUP" => SignalKind::hangup(),
        "SIGINT" => SignalKind::interrupt(),
        _ => SignalKind::terminate(),
    };
    128 + u8::try_from(kind.as_raw_value()).expect("a signal number below 128")
}

/// SIGHUP (the terminal went away), SIGINT and SIGTERM, caught so that they
/// end the loop through [`finish`] rather than kill the process with a
/// minted token still live. Installed once, before the loop starts: while
/// it lives these signals no longer terminate the process by themselves.
///
/// Dropping it puts back the dispositions SIGINT and SIGTERM had before
/// [`Signals::install`] — the default, or the ignore a non-interactive
/// shell set — because tokio never removes a handler it installed. Without
/// that, a process whose loop has finished but whose exit is still waiting
/// (on a blocking thread stuck in name resolution, say) would answer Ctrl-C
/// and SIGTERM with nothing. SIGHUP is left ignored instead, until the
/// process exits: a hangup's repeat (see [`REPEAT_GRACE`]) can land after
/// the loop, and under the default it would kill the process before `main`
/// has printed the exit notice and flushed the log. The exit after the loop
/// is bounded, so ignoring it costs nothing. Tokio installs its handler once
/// per process, so a second `install` after a drop catches nothing: install
/// it once.
pub struct Signals {
    hangup: Signal,
    interrupt: Signal,
    terminate: Signal,
    /// Each signal with the disposition dropping this gives it.
    after: [(libc::c_int, libc::sigaction); 3],
}

impl Signals {
    pub fn install() -> std::io::Result<Self> {
        let current = |number| {
            // SAFETY: `sigaction` is plain data, for which all zeroes is a
            // valid value.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: a null new action only reads the current one into
            // `old`, which outlives the call.
            match unsafe { libc::sigaction(number, std::ptr::null(), &mut old) } {
                0 => Ok((number, old)),
                _ => Err(std::io::Error::last_os_error()),
            }
        };
        // SAFETY: `sigaction` is plain data, for which all zeroes is a valid
        // value: no flags, an empty mask.
        let mut ignore: libc::sigaction = unsafe { std::mem::zeroed() };
        ignore.sa_sigaction = libc::SIG_IGN;
        // Read before tokio replaces them.
        let after = [
            (libc::SIGHUP, ignore),
            current(libc::SIGINT)?,
            current(libc::SIGTERM)?,
        ];
        Ok(Self {
            hangup: signal(SignalKind::hangup())?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            after,
        })
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        for (number, action) in &self.after {
            // SAFETY: installs an ignore, or an action `sigaction` itself
            // reported for this signal; a null out-pointer discards the
            // current one.
            let rc = unsafe { libc::sigaction(*number, action, std::ptr::null_mut()) };
            if rc != 0 {
                tracing::warn!(
                    target: "torrentctl::runtime",
                    signal = *number,
                    error = %std::io::Error::last_os_error(),
                    "could not restore the signal's disposition"
                );
            }
        }
    }
}

/// The name of each signal as it arrives.
impl Stream for Signals {
    type Item = &'static str;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<&'static str>> {
        let this = self.get_mut();
        for (signal, name) in [
            (&mut this.hangup, "SIGHUP"),
            (&mut this.interrupt, "SIGINT"),
            (&mut this.terminate, "SIGTERM"),
        ] {
            if let std::task::Poll::Ready(Some(())) = signal.poll_recv(cx) {
                return std::task::Poll::Ready(Some(name));
            }
        }
        std::task::Poll::Pending
    }
}

/// How long the input thread waits on the terminal at a time before it
/// checks for a resize, which arrives as SIGWINCH rather than as input.
const INPUT_WAIT: Duration = Duration::from_millis(50);

/// How long [`run`] waits, once the loop has ended, for the input thread to
/// stop. It stops at once unless it is inside crossterm's read on a hung-up
/// terminal, which it never leaves (see [`input`]); then it is left behind,
/// and the terminal it would have read from is gone anyway.
const INPUT_STOP_TIMEOUT: Duration = Duration::from_millis(200);

/// Run on the terminal until the user quits or the loop otherwise ends.
///
/// Returns only once the input thread has stopped (or [`INPUT_STOP_TIMEOUT`]
/// has passed), so that nothing reads the terminal while, or after, it is
/// handed back: what the user types from then on is the shell's.
pub async fn run(model: Model, terminal: &mut DefaultTerminal) -> Ended {
    let started = Signals::install().and_then(|signals| Ok((signals, input()?)));
    let (signals, (keys, reader)) = match started {
        Ok(started) => started,
        Err(e) => {
            return Ended {
                model,
                result: Err(e),
                signal: None,
            };
        }
    };
    // The loop drops `keys` as it ends, which stops the reader before
    // `finish` waits on a revocation: keys typed meanwhile stay in the tty.
    let ended = run_with(
        model,
        |model| {
            terminal
                .draw(|frame| crate::ui::view(model, frame))
                .map(drop)
        },
        keys,
        signals,
    )
    .await;
    reader.stopped().await;
    ended
}

/// Terminal events, read by the input thread [`input`] starts. Dropping it
/// stops the thread: the receiver closes first, then the stop pipe's write
/// end, whose closing wakes the thread wherever it waits.
struct Keys {
    rx: mpsc::UnboundedReceiver<std::io::Result<Event>>,
    _stop: std::io::PipeWriter,
}

impl Stream for Keys {
    type Item = std::io::Result<Event>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx)
    }
}

/// The input thread, for [`run`] to wait on once [`Keys`] is dropped.
struct Reader {
    /// Closes as the thread returns.
    stopped: tokio::sync::oneshot::Receiver<()>,
}

impl Reader {
    /// Wait up to [`INPUT_STOP_TIMEOUT`] for the thread to return.
    async fn stopped(self) {
        if tokio::time::timeout(INPUT_STOP_TIMEOUT, self.stopped)
            .await
            .is_err()
        {
            tracing::warn!(
                target: "torrentctl::runtime",
                "the input thread did not stop within {INPUT_STOP_TIMEOUT:?}; leaving it behind"
            );
        }
    }
}

/// Terminal events, read on a thread of their own until the [`Keys`] this
/// returns is dropped.
///
/// Not crossterm's `EventStream`, which reads crossterm's event source on
/// the task that awaits it: once the terminal hangs up, that source spins
/// inside the read for good, because its read loop takes the end of file a
/// hung-up tty answers (and any error but `WouldBlock`) as a reason to read
/// again (crossterm 0.29, `event/source/unix/mio.rs`). On the loop's task
/// that starves everything else on it: the SIGHUP is never seen, and the
/// process spins at full CPU with its terminal gone. On a thread, the spin
/// is confined there and ends with the process, and the loop still sees the
/// SIGHUP, or the next draw's EIO.
///
/// Nor a thread blocked in `crossterm::event::read`, which cannot be told to
/// stop: after the loop it would read one more batch — what the user typed
/// for the shell once the client had quit — and drop it. Instead the thread
/// waits in poll(2) on the terminal and a stop pipe together, and calls into
/// crossterm only once the terminal has input (or every [`INPUT_WAIT`], for
/// a resize), and only while [`Keys`] is alive. Crossterm reads all the
/// input there is when it reads, so the terminal is left unread from the
/// moment the loop ends.
fn input() -> std::io::Result<(Keys, Reader)> {
    use std::io::IsTerminal as _;

    // The descriptor crossterm reads events from: stdin where it is a
    // terminal, the controlling terminal otherwise.
    let tty = if std::io::stdin().is_terminal() {
        None
    } else {
        Some(std::fs::File::open("/dev/tty")?)
    };
    let (stop_rx, stop_tx) = std::io::pipe()?;
    let (tx, rx) = mpsc::unbounded_channel();
    let (stopped_tx, stopped) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("torrentctl-input".to_owned())
        .spawn(move || {
            use std::os::fd::AsRawFd as _;
            let fd = tty
                .as_ref()
                .map_or(libc::STDIN_FILENO, std::fs::File::as_raw_fd);
            read_events(fd, &stop_rx, &tx);
            drop(stopped_tx);
        })?;
    Ok((Keys { rx, _stop: stop_tx }, Reader { stopped }))
}

/// The input thread's loop: wait for input on `tty`, or for `stop` to
/// close, or for [`INPUT_WAIT`] to pass; then, while `tx`'s receiver is
/// open, send every event crossterm has. Returns once the receiver has
/// closed, or after sending an error.
fn read_events(
    tty: std::os::fd::RawFd,
    stop: &std::io::PipeReader,
    tx: &mpsc::UnboundedSender<std::io::Result<Event>>,
) {
    use std::os::fd::AsRawFd as _;
    let millis = libc::c_int::try_from(INPUT_WAIT.as_millis()).expect("a short wait");
    loop {
        let mut fds = [
            libc::pollfd {
                fd: tty,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll(2) only reads and writes `fds`, which outlives the
        // call, and waits at most `millis`; a descriptor that has closed
        // is reported in `revents`, not misused.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                let _ = tx.send(Err(e));
                return;
            }
        }
        // Checked before every call into crossterm, which reads all the
        // input there is: the loop has ended, and what is typed now is not
        // the client's.
        while !tx.is_closed() {
            match crossterm::event::poll(Duration::ZERO) {
                Ok(false) => break,
                Ok(true) => {}
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            }
            let event = crossterm::event::read();
            let failed = event.is_err();
            if tx.send(event).is_err() || failed {
                return;
            }
        }
        if tx.is_closed() {
            return;
        }
    }
}

/// [`run`], drawing with `draw`, reading terminal events from `keys` and
/// the names of signals to leave on from `signals` ([`Signals`]).
/// Whatever ends the loop, a session token the model minted is revoked
/// before this returns; a panic in the loop is resumed once it has been.
/// That includes a panic on a background task ([`Msg::Fatal`]): the loop
/// stops drawing at once, and [`finish`] revokes the token without drawing.
pub async fn run_with<K, S>(
    model: Model,
    draw: impl FnMut(&Model) -> std::io::Result<()>,
    keys: K,
    signals: S,
) -> Ended
where
    K: Stream<Item = std::io::Result<Event>> + Unpin,
    S: Stream<Item = &'static str> + Unpin,
{
    run_spawning(model, draw, keys, signals, Vec::new()).await
}

/// [`run_with`], spawning `first` alongside the first session check: how a
/// test puts a background task's panic on the runtime.
async fn run_spawning<K, S>(
    mut model: Model,
    draw: impl FnMut(&Model) -> std::io::Result<()>,
    keys: K,
    mut signals: S,
    mut first: Vec<Effect>,
) -> Ended
where
    K: Stream<Item = std::io::Result<Event>> + Unpin,
    S: Stream<Item = &'static str> + Unpin,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    // The event stream follows whichever credential is in use: a sign-in or
    // a sign-out changes it.
    let (api_tx, api_rx) = watch::channel(model.api.clone());
    spawn_task(&tx, "the event stream", follow_events(api_rx, tx.clone()));
    first.push(app::check_session(&model.api));
    spawn(&tx, first);

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
    let mut signal = match &looped {
        Ok(Ok(signal)) => *signal,
        _ => None,
    };
    if !model.quit {
        // The terminal, not a panic, is what ended the loop.
        let terminal_ended = matches!(looped, Ok(Ok(None) | Err(_))) && model.fatal.is_none();
        signal = finish(
            &mut model,
            &tx,
            &mut rx,
            &mut signals,
            signal,
            terminal_ended,
        )
        .await;
    }
    match looped {
        Ok(result) => Ended {
            model,
            result: result.map(drop),
            signal,
        },
        Err(panic) => {
            // The panic hook has handed the terminal back already, so this
            // stays on the operator's screen.
            if let Some(notice) = &model.exit_notice {
                notify(notice);
            }
            std::panic::resume_unwind(panic)
        }
    }
}

/// The loop itself: until the model quits, the input ends or fails, a draw
/// fails, or a signal arrives; returns the signal's name in that last case.
async fn drive<K, S>(
    model: &mut Model,
    mut draw: impl FnMut(&Model) -> std::io::Result<()>,
    mut keys: K,
    signals: &mut S,
    tx: &mpsc::UnboundedSender<Msg>,
    rx: &mut mpsc::UnboundedReceiver<Msg>,
    api_tx: &watch::Sender<Api>,
) -> std::io::Result<Option<&'static str>>
where
    K: Stream<Item = std::io::Result<Event>> + Unpin,
    S: Stream<Item = &'static str> + Unpin,
{
    let mut panic_in_task = std::env::var_os(PANIC_IN_TASK).is_some();
    let mut stall_blocking = std::env::var_os(STALL_BLOCKING).is_some();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // A background task's panic stops the drawing at once: the panic hook
    // has handed the terminal back. The exit it started finishes in
    // [`finish`].
    while !model.quit && model.fatal.is_none() {
        draw(model)?;
        if std::env::var_os(PANIC_AFTER_DRAW).is_some() {
            panic!("{PANIC_AFTER_DRAW} is set");
        }
        if std::mem::take(&mut panic_in_task) {
            spawn(
                tx,
                vec![Effect::new(async { panic!("{PANIC_IN_TASK} is set") })],
            );
        }
        if std::mem::take(&mut stall_blocking) {
            drop(tokio::task::spawn_blocking(|| loop {
                std::thread::park();
            }));
            spawn(tx, app::update(model, Msg::Quit));
            continue;
        }
        let msg = tokio::select! {
            event = keys.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => Msg::Key(key),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e),
                None => {
                    tracing::info!(target: "torrentctl::runtime", "the terminal input ended");
                    return Ok(None);
                }
            },
            Some(name) = signals.next() => {
                tracing::info!(target: "torrentctl::runtime", signal = name, "signalled to leave");
                return Ok(Some(name));
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
    Ok(None)
}

/// Finish an exit the user did not ask for as a quit would: revoke a minted
/// token, or wait for an in-flight sign-in to answer and revoke what it
/// mints — without drawing, since the terminal may be gone. Bounded by
/// [`FINISH_TIMEOUT`]. A second signal leaves at once, unless it is the
/// `cause` (the signal that ended the loop) again within [`REPEAT_GRACE`],
/// which is a repeat of it. Where no signal ended the loop, the first
/// SIGHUP is taken for its cause — the hangup behind a draw or input error
/// — and only a signal after that is a second ask. Where the terminal ended
/// the loop (`terminal_ended`) and no SIGHUP has come by the time the rest
/// is done, waits up to [`HANGUP_GRACE`] for one. Returns the cause: the
/// signal that ended the loop, or that hangup, so that the exit status says
/// the terminal went away whichever of the two the loop saw first.
async fn finish<S>(
    model: &mut Model,
    tx: &mpsc::UnboundedSender<Msg>,
    rx: &mut mpsc::UnboundedReceiver<Msg>,
    signals: &mut S,
    cause: Option<&'static str>,
    terminal_ended: bool,
) -> Option<&'static str>
where
    S: Stream<Item = &'static str> + Unpin,
{
    // A quit already under way has its revocation in flight: wait for it
    // rather than quit a second time, which would leave at once.
    if !model.quitting {
        let effects = app::update(model, Msg::Quit);
        spawn(tx, effects);
    }
    let started = tokio::time::Instant::now();
    let deadline = started + FINISH_TIMEOUT;
    // When `cause` last arrived, for telling a repeat of it from a second ask.
    let mut repeat_from = started;
    let mut cause = cause;
    // Whether a session token is known to exist: one in use that this client
    // minted, or one a sign-in answered with while quitting, whose
    // revocation is in flight.
    let mut token = model.minted;
    while !model.quit {
        let msg = tokio::select! {
            Some(msg) = rx.recv() => msg,
            () = tokio::time::sleep_until(deadline) => {
                let secs = FINISH_TIMEOUT.as_secs();
                let notice = if token || model.minted {
                    tracing::warn!(target: "torrentctl::runtime", "the session token was not revoked within {FINISH_TIMEOUT:?}");
                    format!(
                        "torrentctl: the session token was not revoked within {secs}s; it \
                         stays valid on the daemon until it expires"
                    )
                } else {
                    tracing::warn!(target: "torrentctl::runtime", "the sign-in did not answer within {FINISH_TIMEOUT:?}");
                    format!(
                        "torrentctl: the sign-in had not answered within {secs}s; if the \
                         daemon mints a session token for it, that token stays valid on the \
                         daemon until it expires"
                    )
                };
                model.exit_notice.get_or_insert(notice);
                return cause;
            }
            Some(name) = signals.next() => {
                if cause.is_none() && name == "SIGHUP" {
                    // The loop ended on its own — a draw or input error, the
                    // end of the input, a panic — and a hangup follows: the
                    // terminal going away is what ended it (a draw on a
                    // closed tty fails with EIO before the SIGHUP lands), so
                    // this is the same exit, not a second ask.
                    tracing::debug!(target: "torrentctl::runtime", signal = name, "a hangup after the loop ended: the same exit");
                    cause = Some(name);
                    repeat_from = tokio::time::Instant::now();
                    continue;
                }
                if Some(name) == cause && repeat_from.elapsed() < REPEAT_GRACE {
                    tracing::debug!(target: "torrentctl::runtime", signal = name, "the same signal again at once: a repeat, not a second ask");
                    continue;
                }
                tracing::warn!(target: "torrentctl::runtime", signal = name, "signalled again: leaving without revoking");
                return cause;
            }
        };
        if matches!(msg, Msg::Login(crate::screens::login::Msg::Answered(Ok(_)))) {
            token = true;
        }
        let effects = app::update(model, msg);
        spawn(tx, effects);
    }
    if cause.is_none() && terminal_ended {
        if let Ok(Some("SIGHUP")) = tokio::time::timeout(HANGUP_GRACE, signals.next()).await {
            tracing::debug!(target: "torrentctl::runtime", "a hangup after the loop ended: the same exit");
            return Some("SIGHUP");
        }
    }
    cause
}

/// Write `line` and a newline to stderr, as `eprintln!` would, ignoring a
/// failure. Once the terminal has hung up, stderr answers EIO, and
/// `eprintln!` panics on that (std forgives only EBADF); a panic there,
/// during the exit, aborts the process before the log is flushed.
pub fn notify(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// Run each effect on its own task, sending its message to `tx`. An effect
/// that panics sends [`Msg::Fatal`] instead.
pub fn spawn(tx: &mpsc::UnboundedSender<Msg>, effects: Vec<Effect>) {
    for effect in effects {
        let reply = tx.clone();
        spawn_task(tx, "a request", async move {
            let _ = reply.send(effect.0.await);
        });
    }
}

/// Run `task` on its own task, sending [`Msg::Fatal`] to `tx` if it panics.
///
/// Tokio would otherwise swallow the panic into a join handle nobody awaits,
/// after the panic hook has already restored the terminal: the loop would
/// keep drawing over the normal screen with raw mode off, or, for the event
/// stream, live updates would stop without a word.
fn spawn_task(
    tx: &mpsc::UnboundedSender<Msg>,
    what: &'static str,
    task: impl Future<Output = ()> + Send + 'static,
) {
    let tx = tx.clone();
    tokio::spawn(async move {
        // Nothing the task touched is observed after a panic: the loop
        // stops on the message this sends.
        if let Err(payload) = AssertUnwindSafe(task).catch_unwind().await {
            let said = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("a non-string payload");
            let _ = tx.send(Msg::Fatal(format!("{what} panicked: {said}")));
        }
    });
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
                // `v1` may add event kinds; one this build does not know is
                // not a broken stream, and the stream goes on after it.
                if let Some(kind) = unknown_kind(&e) {
                    tracing::debug!(
                        target: "torrentctl::events",
                        kind,
                        "ignored an event of a kind this build does not know"
                    );
                    continue;
                }
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

/// The `kind` of an event that failed to decode only because this build
/// does not know its kind: a JSON object whose `kind` is a string that is
/// not a [`ServerEventkind`](crate::api::types::ServerEventkind). Anything
/// else that fails to decode, a known kind included, is `None`: a stream
/// sending that is broken.
fn unknown_kind<E>(e: &crate::api::generated::Error<E>) -> Option<String> {
    let crate::api::generated::Error::Decode { body, .. } = e else {
        return None;
    };
    let event: serde_json::Value = serde_json::from_slice(body).ok()?;
    let kind = event.as_object()?.get("kind")?;
    let known = serde_json::from_value::<crate::api::types::ServerEventkind>(kind.clone()).is_ok();
    match kind {
        serde_json::Value::String(kind) if !known => Some(kind.clone()),
        _ => None,
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

    fn fatal(msg: Msg) -> String {
        match msg {
            Msg::Fatal(what) => what,
            other => panic!("expected a fatal message, got {other:?}"),
        }
    }

    const REVOKE: &str = "DELETE /v1/sessions/current";

    /// A model holding `tds_minted`, minted from the password, aimed at
    /// `daemon`.
    fn minted(daemon: &crate::testing::Recorder) -> Model {
        let api = daemon.api().with_token("tds_minted").expect("a valid URL");
        let mut model = Model::new(api, crate::testing::theme());
        model.minted = true;
        model
    }

    /// Terminal input that never arrives.
    fn no_input() -> futures_util::stream::Pending<std::io::Result<Event>> {
        futures_util::stream::pending()
    }

    /// Signals that never arrive.
    fn no_signals() -> futures_util::stream::Pending<&'static str> {
        futures_util::stream::pending()
    }

    fn revoked(daemon: &crate::testing::Recorder) -> bool {
        daemon.requests().contains(&crate::testing::Request {
            line: REVOKE.to_owned(),
            bearer: Some("tds_minted".to_owned()),
        })
    }

    async fn bounded(run: impl std::future::Future<Output = Ended>) -> Ended {
        tokio::time::timeout(PATIENCE, run)
            .await
            .unwrap_or_else(|_| panic!("run_with did not return within {PATIENCE:?}"))
    }

    #[tokio::test]
    async fn the_end_of_the_input_revokes_a_minted_token() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let ended = bounded(run_with(
            minted(&daemon),
            |_| Ok(()),
            futures_util::stream::empty(),
            no_signals(),
        ))
        .await;
        assert!(ended.result.is_ok());
        assert!(ended.model.quit);
        assert_eq!(ended.signal, None);
        assert!(revoked(&daemon), "{:?}", daemon.requests());
        assert_eq!(ended.model.exit_notice, None, "revoked: nothing to say");
    }

    #[tokio::test]
    async fn an_input_or_draw_error_revokes_a_minted_token_and_is_returned() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let ended = bounded(run_with(
            minted(&daemon),
            |_| Ok(()),
            futures_util::stream::iter([Err(std::io::Error::other("the tty is gone"))]),
            no_signals(),
        ))
        .await;
        let error = ended.result.expect_err("the input error");
        assert_eq!(error.to_string(), "the tty is gone");
        assert!(revoked(&daemon), "input: {:?}", daemon.requests());

        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let ended = bounded(run_with(
            minted(&daemon),
            |_| Err(std::io::Error::other("cannot draw")),
            no_input(),
            no_signals(),
        ))
        .await;
        let error = ended.result.expect_err("the draw error");
        assert_eq!(error.to_string(), "cannot draw");
        assert!(revoked(&daemon), "draw: {:?}", daemon.requests());
        assert_eq!(ended.signal, None, "no hangup within the grace");
    }

    /// A draw error with no token to revoke, and the SIGHUP behind it
    /// landing only once the loop has ended: the hangup is still what the
    /// exit reports, not a terminal failure.
    #[tokio::test]
    async fn a_hangup_landing_just_after_a_draw_error_is_the_exits_cause() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let model = Model::new(daemon.api(), crate::testing::theme());
        let signals = futures_util::stream::once(async {
            tokio::time::sleep(HANGUP_GRACE / 5).await;
            "SIGHUP"
        });
        let ended = bounded(run_with(
            model,
            |_| Err(std::io::Error::other("EIO")),
            no_input(),
            Box::pin(signals),
        ))
        .await;
        assert_eq!(ended.signal, Some("SIGHUP"));
        assert!(ended.result.is_err(), "the draw error is kept");
        assert!(ended.model.quit);
    }

    #[tokio::test]
    async fn a_signal_revokes_a_minted_token() {
        for name in ["SIGHUP", "SIGINT", "SIGTERM"] {
            let daemon = crate::testing::Recorder::start("204 No Content", "");
            let ended = bounded(run_with(
                minted(&daemon),
                |_| Ok(()),
                no_input(),
                futures_util::stream::iter([name]),
            ))
            .await;
            assert!(ended.result.is_ok(), "{name}");
            assert_eq!(ended.signal, Some(name));
            assert!(ended.model.quit, "{name}");
            assert!(revoked(&daemon), "{name}: {:?}", daemon.requests());
        }
    }

    /// After a password sign-in, a background task's panic stops the loop
    /// and the token is still revoked before `run_with` returns.
    #[tokio::test]
    async fn a_background_panic_revokes_a_minted_token() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let ended = bounded(run_spawning(
            minted(&daemon),
            |_| Ok(()),
            no_input(),
            no_signals(),
            vec![Effect::new(async { panic!("effect blew up") })],
        ))
        .await;
        assert!(ended.result.is_ok());
        assert_eq!(
            ended.model.fatal.as_deref(),
            Some("a request panicked: effect blew up")
        );
        assert!(ended.model.quit, "the revocation completed");
        assert!(revoked(&daemon), "{:?}", daemon.requests());
        assert_eq!(ended.model.exit_notice, None, "revoked: nothing to say");
    }

    /// A draw on a closed terminal fails before the hangup's SIGHUP lands:
    /// that SIGHUP, and the kernel's repeat of it, are the same exit, and
    /// the token is still revoked.
    #[tokio::test]
    async fn a_hangup_after_a_draw_error_still_revokes() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let ended = bounded(run_with(
            minted(&daemon),
            |_| Err(std::io::Error::other("EIO")),
            no_input(),
            futures_util::stream::iter(["SIGHUP", "SIGHUP"]),
        ))
        .await;
        assert_eq!(ended.result.expect_err("the draw error").to_string(), "EIO");
        assert!(ended.model.quit, "the revocation completed");
        assert!(revoked(&daemon), "{:?}", daemon.requests());
    }

    /// After a draw error and its hangup, a distinct signal, or the hangup
    /// again once [`REPEAT_GRACE`] has passed, is a second ask: it leaves
    /// without waiting for the revocation.
    #[tokio::test]
    async fn a_second_ask_after_a_draw_error_and_its_hangup_leaves_without_waiting() {
        let wedged = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", wedged.local_addr().expect("an address"));
        let model = || {
            let api = Api::new(&url, Some("tds_minted")).expect("a valid URL");
            let mut model = Model::new(api, crate::testing::theme());
            model.minted = true;
            model
        };
        let draw = |_: &Model| Err(std::io::Error::other("EIO"));

        let started = Instant::now();
        let ended = bounded(run_with(
            model(),
            draw,
            no_input(),
            futures_util::stream::iter(["SIGHUP", "SIGINT"]),
        ))
        .await;
        assert!(
            started.elapsed() < crate::app::REVOKE_TIMEOUT,
            "left after {:?}",
            started.elapsed()
        );
        assert!(ended.model.quitting && !ended.model.quit);

        let signals = futures_util::stream::once(async { "SIGHUP" }).chain(
            futures_util::stream::once(async {
                tokio::time::sleep(REPEAT_GRACE + Duration::from_millis(200)).await;
                "SIGHUP"
            }),
        );
        let started = Instant::now();
        let ended = bounded(run_with(model(), draw, no_input(), Box::pin(signals))).await;
        let left = started.elapsed();
        assert!(
            left >= REPEAT_GRACE && left < crate::app::REVOKE_TIMEOUT,
            "left after {left:?}"
        );
        assert!(ended.model.quitting && !ended.model.quit);
        drop(wedged);
    }

    #[tokio::test]
    async fn an_effect_that_panics_sends_a_fatal_message() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn(
            &tx,
            vec![
                Effect::new(async { panic!("effect blew up") }),
                Effect::new(async { panic!("{} blew up", "formatted") }),
                Effect::now(Msg::Tick),
            ],
        );
        let mut said = Vec::new();
        for _ in 0..3 {
            match next(&mut rx).await {
                Msg::Tick => {}
                msg => said.push(fatal(msg)),
            }
        }
        said.sort();
        assert_eq!(
            said,
            [
                "a request panicked: effect blew up",
                "a request panicked: formatted blew up",
            ]
        );
    }

    #[tokio::test]
    async fn a_task_that_panics_sends_a_fatal_message_naming_it() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn_task(&tx, "the event stream", async {
            std::panic::panic_any(7_u8);
        });
        assert_eq!(
            fatal(next(&mut rx).await),
            "the event stream panicked: a non-string payload"
        );
    }

    #[tokio::test]
    async fn a_panic_in_the_loop_revokes_a_minted_token_then_resumes() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let panicked = AssertUnwindSafe(run_with(
            minted(&daemon),
            |_| panic!("the draw panicked"),
            no_input(),
            no_signals(),
        ))
        .catch_unwind()
        .await;
        let panic = panicked.err().expect("the panic is resumed");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"the draw panicked"));
        assert!(revoked(&daemon), "{:?}", daemon.requests());
    }

    /// A daemon that takes connections and never answers: the revocation
    /// is still waiting when the second signal arrives.
    #[tokio::test]
    async fn a_second_signal_leaves_without_waiting_for_the_revocation() {
        let wedged = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", wedged.local_addr().expect("an address"));
        let api = Api::new(&url, Some("tds_minted")).expect("a valid URL");
        let mut model = Model::new(api, crate::testing::theme());
        model.minted = true;
        let started = Instant::now();
        let ended = bounded(run_with(
            model,
            |_| Ok(()),
            no_input(),
            futures_util::stream::iter(["SIGHUP", "SIGTERM"]),
        ))
        .await;
        assert!(
            started.elapsed() < crate::app::REVOKE_TIMEOUT,
            "left after {:?}",
            started.elapsed()
        );
        assert!(ended.model.quitting && !ended.model.quit);
        assert_eq!(
            ended.signal,
            Some("SIGHUP"),
            "the signal that ended the loop"
        );
        drop(wedged);
    }

    /// A closing terminal sends the foreground job SIGHUP twice at once (the
    /// shell's and the kernel's): the repeat is not a second ask, and the
    /// revocation still happens.
    #[tokio::test]
    async fn a_repeat_of_the_signal_that_ended_the_loop_still_revokes() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let ended = bounded(run_with(
            minted(&daemon),
            |_| Ok(()),
            no_input(),
            futures_util::stream::iter(["SIGHUP", "SIGHUP"]),
        ))
        .await;
        assert!(ended.model.quit, "the revocation completed");
        assert!(revoked(&daemon), "{:?}", daemon.requests());
        assert_eq!(ended.signal, Some("SIGHUP"));
    }

    /// The same signal once [`REPEAT_GRACE`] has passed is a second ask: it
    /// leaves without waiting for the revocation.
    #[tokio::test]
    async fn the_same_signal_after_the_grace_leaves_without_waiting() {
        let wedged = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", wedged.local_addr().expect("an address"));
        let api = Api::new(&url, Some("tds_minted")).expect("a valid URL");
        let mut model = Model::new(api, crate::testing::theme());
        model.minted = true;
        let signals = futures_util::stream::once(async { "SIGTERM" }).chain(
            futures_util::stream::once(async {
                tokio::time::sleep(REPEAT_GRACE + Duration::from_millis(200)).await;
                "SIGTERM"
            }),
        );
        let started = Instant::now();
        let ended = bounded(run_with(model, |_| Ok(()), no_input(), Box::pin(signals))).await;
        let left = started.elapsed();
        assert!(
            left >= REPEAT_GRACE && left < crate::app::REVOKE_TIMEOUT,
            "left after {left:?}"
        );
        assert!(ended.model.quitting && !ended.model.quit);
        drop(wedged);
    }

    /// A sign-in the daemon never answers holds the exit for
    /// [`FINISH_TIMEOUT`], and the notice says no token is known to exist.
    #[tokio::test]
    async fn an_unanswered_sign_in_gives_up_after_the_finish_timeout() {
        let wedged = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", wedged.local_addr().expect("an address"));
        let api = Api::new(&url, Some(crate::api::ANONYMOUS)).expect("a valid URL");
        let mut model = Model::new(api, crate::testing::theme());
        model.login.busy = true;
        let started = Instant::now();
        let ended = bounded(run_with(
            model,
            |_| Ok(()),
            no_input(),
            futures_util::stream::iter(["SIGTERM"]),
        ))
        .await;
        let left = started.elapsed();
        assert!(
            left >= FINISH_TIMEOUT && left < FINISH_TIMEOUT + SLACK,
            "left after {left:?}"
        );
        let notice = ended.model.exit_notice.expect("a notice");
        assert!(
            notice.contains("sign-in had not answered within 5s"),
            "{notice}"
        );
        assert!(!notice.contains("was not revoked"), "{notice}");
        drop(wedged);
    }

    #[test]
    fn a_signalled_exit_reports_128_plus_the_signal_number() {
        assert_eq!(signal_exit_status("SIGHUP"), 129);
        assert_eq!(signal_exit_status("SIGINT"), 130);
        assert_eq!(signal_exit_status("SIGTERM"), 143);
    }

    /// A quit already waiting on its revocation is not quit a second time
    /// by a signal, which would leave at once: the revocation completes.
    #[tokio::test]
    async fn a_signal_during_a_quit_waits_for_its_revocation() {
        let daemon = crate::testing::Recorder::start("204 No Content", "");
        let (keys_tx, mut keys_rx) = mpsc::unbounded_channel();
        let (signal_tx, mut signal_rx) = mpsc::unbounded_channel();
        let keys = futures_util::stream::poll_fn(move |cx| keys_rx.poll_recv(cx));
        let signals = futures_util::stream::poll_fn(move |cx| signal_rx.poll_recv(cx));
        let run = tokio::spawn(run_with(
            minted(&daemon),
            move |model| {
                // Signalled on the draw after the quit was taken, while its
                // revocation is in flight.
                if model.quitting && !model.quit {
                    let _ = signal_tx.send("SIGTERM");
                }
                Ok(())
            },
            keys,
            signals,
        ));
        let q = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('q'),
            crossterm::event::KeyModifiers::NONE,
        );
        keys_tx.send(Ok(Event::Key(q))).expect("running");
        let ended = bounded(async { run.await.expect("no panic") }).await;
        assert!(ended.model.quit, "the revocation completed");
        let revocations = daemon.lines().iter().filter(|l| *l == REVOKE).count();
        assert_eq!(revocations, 1, "{:?}", daemon.requests());
        assert!(revoked(&daemon));
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

    /// `v1` may add event kinds: one this build does not know neither
    /// brings the stream up nor takes it down, and what follows it arrives.
    #[tokio::test]
    async fn an_unknown_event_kind_is_ignored_and_the_stream_stays_live() {
        let mut server = EventServer::start().await;
        let (_api_tx, mut rx) = follow(&server, "tdp_a", FAST);
        let mut stream = server.next(PATIENCE).await;
        stream.open().await;
        stream
            .event("rename", r#"{"kind":"rename","to":"x"}"#)
            .await;
        stream.tick("00000000000000aa", "").await;
        assert_eq!(next_live(&mut rx).await, Live::Streaming);
        assert_eq!(next_changed(&mut rx).await, "00000000000000aa");

        stream.event("rename", r#"{"kind":"rename"}"#).await;
        stream.tick("00000000000000bb", "").await;
        assert_eq!(next_changed(&mut rx).await, "00000000000000bb");
        drop(stream);
    }

    /// A known kind that does not decode is a broken stream, not a new kind.
    #[tokio::test]
    async fn a_malformed_tick_still_takes_the_stream_down() {
        let mut server = EventServer::start().await;
        let (_api_tx, mut rx) = follow(&server, "tdp_a", FAST);
        let mut stream = server.next(PATIENCE).await;
        stream.open().await;
        stream.tick("00000000000000aa", "").await;
        assert_eq!(next_live(&mut rx).await, Live::Streaming);
        next_changed(&mut rx).await;

        stream.event("tick", r#"{"kind":"tick"}"#).await;
        let reason = reason(next_live(&mut rx).await);
        assert!(reason.contains("stream error"), "{reason}");
        server.next(PATIENCE).await;
        drop(stream);
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

    /// The handler each of the three signals has now.
    fn handlers() -> [libc::sighandler_t; 3] {
        [libc::SIGHUP, libc::SIGINT, libc::SIGTERM].map(|number| {
            // SAFETY: `sigaction` is plain data, for which all zeroes is a
            // valid value.
            let mut now: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: a null new action only reads the current one.
            let rc = unsafe { libc::sigaction(number, std::ptr::null(), &mut now) };
            assert_eq!(rc, 0, "sigaction: {}", std::io::Error::last_os_error());
            now.sa_sigaction
        })
    }

    /// Dropping the handlers puts back what SIGINT and SIGTERM did before,
    /// so a process whose loop has finished dies of Ctrl-C or SIGTERM again
    /// while its exit waits. SIGINT starts ignored here, as a non-interactive
    /// shell leaves it for a background job, and is ignored again after, not
    /// turned into the default. SIGHUP starts at the default and is ignored
    /// after, so a hangup's repeat landing during the exit does not kill the
    /// process before the notice and the log are out. The only test in this
    /// binary that installs them: tokio installs its handler once per
    /// process.
    #[tokio::test]
    async fn dropping_the_signal_handlers_restores_interrupt_and_terminate_and_ignores_hangup() {
        // SAFETY: setting a signal to its default or to be ignored; no
        // handler runs.
        let hangup = unsafe { libc::signal(libc::SIGHUP, libc::SIG_DFL) };
        assert_ne!(hangup, libc::SIG_ERR);
        // SAFETY: as above.
        let interrupt = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
        assert_ne!(interrupt, libc::SIG_ERR);
        let before = handlers();
        assert_eq!(before[..2], [libc::SIG_DFL, libc::SIG_IGN]);

        let signals = Signals::install().expect("install the signal handlers");
        let installed = handlers();
        for ((now, was), name) in installed
            .iter()
            .zip(before)
            .zip(["SIGHUP", "SIGINT", "SIGTERM"])
        {
            assert_ne!(*now, was, "{name} has tokio's handler");
        }
        drop(signals);
        assert_eq!(handlers(), [libc::SIG_IGN, before[1], before[2]]);

        // SAFETY: puts back the actions SIGHUP and SIGINT had before this
        // test.
        unsafe {
            libc::signal(libc::SIGHUP, hangup);
            libc::signal(libc::SIGINT, interrupt);
        }
    }
}
