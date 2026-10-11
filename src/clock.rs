//! Time source used for every expiry, rotation and cookie `Max-Age` decision.

use std::sync::{Arc, Mutex, PoisonError};

use chrono::{DateTime, Utc};

/// A source of the current time.
///
/// The guard never calls [`Utc::now`] directly, so tests (and simulations) can drive time with
/// [`ManualClock`]. Any `Fn() -> DateTime<Utc>` closure is also a clock.
pub trait Clock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> DateTime<Utc>;
}

/// The system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

impl<F> Clock for F
where
    F: Fn() -> DateTime<Utc> + Send + Sync + 'static,
{
    fn now(&self) -> DateTime<Utc> {
        self()
    }
}

/// A clock that only moves when told to. Clones share the same time.
#[derive(Clone, Debug)]
pub struct ManualClock {
    now: Arc<Mutex<DateTime<Utc>>>,
}

impl ManualClock {
    /// A clock frozen at `start`.
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            now: Arc::new(Mutex::new(start)),
        }
    }

    /// Jumps to `instant` (may move backwards).
    pub fn set(&self, instant: DateTime<Utc>) {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner) = instant;
    }

    /// Moves forward by `by`. Saturates instead of overflowing.
    pub fn advance(&self, by: std::time::Duration) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        let delta = chrono::TimeDelta::from_std(by).unwrap_or(chrono::TimeDelta::MAX);
        *now = now.checked_add_signed(delta).unwrap_or(DateTime::<Utc>::MAX_UTC);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new(Utc::now())
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn manual_clock_advances_and_is_shared_between_clones() {
        let start = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let clock = ManualClock::new(start);
        let other = clock.clone();
        clock.advance(Duration::from_secs(90));
        assert_eq!(other.now(), start + chrono::TimeDelta::seconds(90));
        other.set(start);
        assert_eq!(clock.now(), start);
    }

    #[test]
    fn manual_clock_saturates() {
        let clock = ManualClock::new(DateTime::<Utc>::MAX_UTC - chrono::TimeDelta::seconds(1));
        clock.advance(Duration::from_secs(u64::MAX));
        assert_eq!(clock.now(), DateTime::<Utc>::MAX_UTC);
    }

    #[test]
    fn closures_are_clocks() {
        let fixed = DateTime::from_timestamp(42, 0).unwrap();
        let clock = move || fixed;
        assert_eq!(Clock::now(&clock), fixed);
    }
}
