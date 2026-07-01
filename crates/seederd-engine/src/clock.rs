//! Time + sleep abstraction.
//!
//! Used by the alert loop's tick scheduler, the retry timer, and the
//! resume save scheduler. Every place that would otherwise call
//! `Instant::now()` or `thread::sleep()` goes through this trait so unit
//! tests advance time deterministically via `MockClock`.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;

pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> Instant;
    /// Synchronously sleep for `d`. The default `SystemClock` impl uses
    /// `std::thread::sleep`; tests use `MockClock` which records the
    /// requested duration and advances the simulated clock.
    fn sleep(&self, d: Duration);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d)
    }
}

/// Deterministic clock for unit tests. `now()` returns the current
/// simulated time. `sleep(d)` advances the simulated clock by `d` and
/// returns immediately.
#[derive(Debug, Clone)]
pub struct MockClock {
    inner: Arc<Mutex<MockClockInner>>,
}

#[derive(Debug)]
struct MockClockInner {
    now: Instant,
    sleeps: Vec<Duration>,
}

impl MockClock {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockClockInner {
                now: Instant::now(),
                sleeps: Vec::new(),
            })),
        }
    }

    /// Advance the clock by `d` without recording a sleep. Used to set up
    /// scenarios.
    pub fn advance(&self, d: Duration) {
        self.inner.lock().now += d;
    }

    /// Snapshot of every `Clock::sleep(d)` call observed.
    pub fn observed_sleeps(&self) -> Vec<Duration> {
        self.inner.lock().sleeps.clone()
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MockClock {
    fn now(&self) -> Instant {
        self.inner.lock().now
    }

    fn sleep(&self, d: Duration) {
        let mut g = self.inner.lock();
        g.sleeps.push(d);
        g.now += d;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_advance_records() {
        let c = MockClock::new();
        let t0 = c.now();
        c.sleep(Duration::from_secs(60));
        c.sleep(Duration::from_secs(30));
        assert_eq!(c.now() - t0, Duration::from_secs(90));
        assert_eq!(c.observed_sleeps().len(), 2);
    }
}
