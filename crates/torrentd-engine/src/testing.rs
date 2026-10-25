//! Helpers for tests that assert on the tracing events code emits.

use tracing::subscriber::NoSubscriber;
use tracing::Dispatch;
use tracing::Subscriber;

/// Runs `f` with `subscriber` as this thread's default, so the events `f`
/// emits reach it even when a parallel test registered the same callsites
/// first, apart from the narrow window described below.
///
/// `tracing::subscriber::with_default` alone is not enough for a test that
/// counts or reads events. While a single dispatcher is registered
/// process-wide, tracing-core registers a new callsite by asking only the
/// registering thread's default. A parallel test thread with no subscriber
/// that reaches a `warn!` first caches its interest as never, and this
/// thread's subscriber then sees nothing from it. Holding a second live
/// dispatcher for `f`'s duration makes every registration ask each live
/// dispatcher, `subscriber` included. Creating it, and `subscriber`'s
/// dispatcher after it, also rebuilds the interest of every callsite already
/// registered, so one cached as never before this call is corrected too.
///
/// One window remains. tracing-core adds a callsite to its registry only
/// after computing its interest, so a thread with no subscriber that starts
/// registering a callsite just before `_pin` is created can still compute
/// that interest from its own default alone, miss the rebuild, and leave
/// never cached. This narrows the race to that registration instant rather
/// than closing it.
pub fn with_subscriber<S, T>(subscriber: S, f: impl FnOnce() -> T) -> T
where
    S: Subscriber + Send + Sync + 'static,
{
    let _pin = Dispatch::new(NoSubscriber::default());
    tracing::subscriber::with_default(subscriber, f)
}

/// Keeps `subscriber` as this thread's default, and the second dispatcher
/// [`with_subscriber`] pins alive, until it is dropped.
#[must_use = "the subscriber is this thread's default only while the guard lives"]
#[derive(Debug)]
pub struct SubscriberGuard {
    // Fields drop in declaration order: the default is restored before the
    // pinned dispatcher goes, as it is in `with_subscriber`.
    _default: tracing::subscriber::DefaultGuard,
    _pin: Dispatch,
}

/// The guard-returning counterpart of [`with_subscriber`], for a test that
/// must hold `subscriber` across an `.await` or over code a closure cannot
/// wrap. `subscriber` stays this thread's default until the returned guard
/// is dropped, with the same protection and the same remaining window that
/// [`with_subscriber`] describes.
pub fn set_subscriber<S>(subscriber: S) -> SubscriberGuard
where
    S: Subscriber + Send + Sync + 'static,
{
    let pin = Dispatch::new(NoSubscriber::default());
    SubscriberGuard {
        _default: tracing::subscriber::set_default(subscriber),
        _pin: pin,
    }
}
