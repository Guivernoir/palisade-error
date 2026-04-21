use palisade_errors::AgentError;
use std::time::{Duration, Instant};

fn main() {
    let started = Instant::now();
    let err = AgentError::new(
        103,
        "Invalid credentials",
        "username lookup failed during authentication flow",
        "alice@example.invalid",
    )
    .with_timing_normalization(Duration::from_millis(25));

    println!("{err}");
    println!("elapsed: {:?}", started.elapsed());
}
