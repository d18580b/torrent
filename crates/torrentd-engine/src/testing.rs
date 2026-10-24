//! Helpers for tests that assert on the tracing events code emits.

use tracing::subscriber::NoSubscriber;
use tracing::Dispatch;
use tracing::Subscriber;

/// Runs `f` with `subscriber` as this thread's default, so the events `f`
/// emits reach it however parallel tests touched the same callsites first.
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
pub fn with_subscriber<S, T>(subscriber: S, f: impl FnOnce() -> T) -> T
where
    S: Subscriber + Send + Sync + 'static,
{
    let _pin = Dispatch::new(NoSubscriber::default());
    tracing::subscriber::with_default(subscriber, f)
}
