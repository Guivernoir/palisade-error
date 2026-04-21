//! Constant-time and timing-normalization helpers.
//!
//! This module centralizes the crate's timing behavior so higher-level code
//! no longer depends on a runtime-specific crate for delay handling.

use std::thread;
use std::time::{Duration, Instant};

const SPIN_THRESHOLD: Duration = Duration::from_micros(50);

/// Return the deadline that preserves a minimum elapsed duration from `start`.
#[inline]
pub(crate) fn deadline_from(start: Instant, minimum: Duration) -> Instant {
    start.checked_add(minimum).unwrap_or(start)
}

/// Spin until at least `floor` has elapsed from `start`.
#[inline(never)]
pub(crate) fn enforce_floor(start: Instant, floor: Duration) {
    spin_until(deadline_from(start, floor));
}

/// Block the current thread until `deadline`.
#[inline]
pub(crate) fn sleep_until(deadline: Instant) {
    park_until(deadline);
}

/// Await until `deadline` without a runtime dependency.
///
/// This future is allocation-free but blocks the current executor thread.
#[inline]
pub(crate) async fn sleep_until_async(deadline: Instant) {
    sleep_until(deadline);
}

#[inline]
fn park_until(deadline: Instant) {
    let now = Instant::now();
    if deadline <= now {
        return;
    }

    let remaining = deadline.duration_since(now);
    if remaining > SPIN_THRESHOLD {
        thread::sleep(remaining - SPIN_THRESHOLD);
    }

    spin_until(deadline);
}

#[inline]
fn spin_until(deadline: Instant) {
    while Instant::now() < deadline {
        std::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::{deadline_from, enforce_floor, sleep_until};
    use std::time::{Duration, Instant};

    #[test]
    fn deadline_from_uses_start_time() {
        let start = Instant::now();
        let deadline = deadline_from(start, Duration::from_millis(5));
        assert!(deadline >= start);
    }

    #[test]
    fn enforce_floor_waits_long_enough() {
        let start = Instant::now();
        enforce_floor(start, Duration::from_millis(1));
        assert!(start.elapsed() >= Duration::from_millis(1));
    }

    #[test]
    fn sleep_until_returns_when_deadline_passes() {
        let start = Instant::now();
        sleep_until(deadline_from(start, Duration::from_millis(1)));
        assert!(start.elapsed() >= Duration::from_millis(1));
    }
}
