//! Constant-time and timing-normalization helpers.
//!
//! This module centralizes the crate's timing behavior so higher-level code
//! no longer depends on a runtime-specific crate for delay handling.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
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

/// Await until `deadline` without requiring a specific async runtime.
#[inline]
pub(crate) async fn sleep_until_async(deadline: Instant) {
    Delay::new(deadline).await;
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

struct DelayState {
    started: AtomicBool,
    ready: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl DelayState {
    fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    fn with_waker<T>(&self, f: impl FnOnce(&mut Option<Waker>) -> T) -> T {
        match self.waker.lock() {
            Ok(mut guard) => f(&mut guard),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }
}

struct Delay {
    deadline: Instant,
    state: Arc<DelayState>,
}

impl Delay {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            state: Arc::new(DelayState::new()),
        }
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.deadline || self.state.ready.load(Ordering::Acquire) {
            self.state.ready.store(true, Ordering::Release);
            return Poll::Ready(());
        }

        self.state.with_waker(|slot| match slot {
            Some(current) if current.will_wake(cx.waker()) => {}
            _ => *slot = Some(cx.waker().clone()),
        });

        if !self.state.started.swap(true, Ordering::AcqRel) {
            let state = Arc::clone(&self.state);
            let deadline = self.deadline;
            thread::spawn(move || {
                park_until(deadline);
                state.ready.store(true, Ordering::Release);
                state.with_waker(|slot| {
                    if let Some(waker) = slot.take() {
                        waker.wake();
                    }
                });
            });
        }

        if self.state.ready.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
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
