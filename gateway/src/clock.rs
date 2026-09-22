//! Injectable clock: monotonic time for expiry decisions (immune to wall-clock
//! adjustments) + absolute Unix ms for wire-visible deadlines.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Monotonic instant for internal deadline/expiry comparison.
    fn mono(&self) -> Instant;
    /// Absolute Unix epoch milliseconds — the wire deadline representation.
    fn unix_ms(&self) -> u64;
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn mono(&self) -> Instant {
        Instant::now()
    }
    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Deterministic manual clock for tests. `advance` moves both faces together.
/// `Clone` shares the same underlying time — the core holds one copy, the
/// test holds another, and advances are visible to both.
#[derive(Clone)]
pub struct TestClock {
    inner: std::sync::Arc<TestClockInner>,
}

struct TestClockInner {
    base: Instant,
    elapsed: Mutex<Duration>,
    base_unix_ms: u64,
}

impl TestClock {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(TestClockInner {
                base: Instant::now(),
                elapsed: Mutex::new(Duration::ZERO),
                base_unix_ms: 1_800_000_000_000,
            }),
        }
    }
    pub fn advance(&self, d: Duration) {
        *self.inner.elapsed.lock().unwrap() += d;
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    fn mono(&self) -> Instant {
        self.inner.base + *self.inner.elapsed.lock().unwrap()
    }
    fn unix_ms(&self) -> u64 {
        self.inner.base_unix_ms + self.inner.elapsed.lock().unwrap().as_millis() as u64
    }
}
