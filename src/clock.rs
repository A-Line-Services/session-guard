//! Time source used for every expiry, rotation and cookie `Max-Age` decision.

use std::sync::{Arc, Mutex, PoisonError};

use time::{OffsetDateTime, PrimitiveDateTime};

/// A source of the current time.
///
/// The guard never calls [`OffsetDateTime::now_utc`] directly, so tests (and simulations) can drive time with
/// [`ManualClock`]. Any `Fn() -> OffsetDateTime` closure is also a clock.
pub trait Clock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> OffsetDateTime;
}

/// The system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

impl<F> Clock for F
where
    F: Fn() -> OffsetDateTime + Send + Sync + 'static,
{
    fn now(&self) -> OffsetDateTime {
        self()
    }
}

/// A clock that only moves when told to. Clones share the same time.
#[derive(Clone, Debug)]
pub struct ManualClock {
    now: Arc<Mutex<OffsetDateTime>>,
}

impl ManualClock {
    /// A clock frozen at `start`.
    pub fn new(start: OffsetDateTime) -> Self {
        Self {
            now: Arc::new(Mutex::new(start)),
        }
    }

    /// Jumps to `instant` (may move backwards).
    pub fn set(&self, instant: OffsetDateTime) {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner) = instant;
    }

    /// Moves forward by `by`. Saturates instead of overflowing.
    pub fn advance(&self, by: std::time::Duration) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        let delta = time::Duration::try_from(by).unwrap_or(time::Duration::MAX);
        *now = now.checked_add(delta).unwrap_or(PrimitiveDateTime::MAX.assume_utc());
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new(OffsetDateTime::now_utc())
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn manual_clock_advances_and_is_shared_between_clones() {
        let start = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let clock = ManualClock::new(start);
        let other = clock.clone();
        clock.advance(Duration::from_secs(90));
        assert_eq!(other.now(), start + time::Duration::seconds(90));
        other.set(start);
        assert_eq!(clock.now(), start);
    }

    #[test]
    fn manual_clock_saturates() {
        let clock = ManualClock::new(PrimitiveDateTime::MAX.assume_utc() - time::Duration::seconds(1));
        clock.advance(Duration::from_secs(u64::MAX));
        assert_eq!(clock.now(), PrimitiveDateTime::MAX.assume_utc());
    }

    #[test]
    fn closures_are_clocks() {
        let fixed = OffsetDateTime::from_unix_timestamp(42).unwrap();
        let clock = move || fixed;
        assert_eq!(Clock::now(&clock), fixed);
    }
}
