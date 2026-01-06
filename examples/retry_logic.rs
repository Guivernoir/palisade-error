//! Retry Logic Example
//!
//! Demonstrates how to implement retry logic using the retryable error flag
//! and exponential backoff strategies.
//!
//! Run with: cargo run --example retry_logic

use palisade_errors::{AgentError, definitions, Result};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

fn main() {
    println!("=== Retry Logic Example ===\n");

    // Example 1: Simple retry with linear backoff
    println!("1. Simple Retry with Linear Backoff:");
    simple_retry_example();
    println!();

    // Example 2: Exponential backoff
    println!("2. Exponential Backoff:");
    exponential_backoff_example();
    println!();

    // Example 3: Retry only retryable errors
    println!("3. Selective Retry (only retryable errors):");
    selective_retry_example();
    println!();

    // Example 4: Retry with timeout
    println!("4. Retry with Total Timeout:");
    retry_with_timeout_example();
}

/// Simulated service that fails a few times then succeeds
struct UnstableService {
    attempts: Arc<Mutex<u32>>,
    fail_count: u32,
}

impl UnstableService {
    fn new(fail_count: u32) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(0)),
            fail_count,
        }
    }

    fn call(&self) -> Result<String> {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        let current_attempt = *attempts;

        if current_attempt <= self.fail_count {
            println!("   Attempt {}: Failed (transient)", current_attempt);
            Err(
                AgentError::telemetry(
                    definitions::TEL_CHANNEL_CLOSED,
                    "collect_telemetry",
                    "Service temporarily unavailable"
                )
                .with_retry()
                .with_metadata("attempt", &current_attempt.to_string())
            )
        } else {
            println!("   Attempt {}: Success!", current_attempt);
            Ok(format!("Success after {} attempts", current_attempt))
        }
    }

    fn call_permanent_failure(&self) -> Result<String> {
        println!("   Attempt: Failed (permanent)");
        Err(
            AgentError::config(
                definitions::CFG_VALIDATION_FAILED,
                "validate_config",
                "Invalid configuration"
            )
            // Note: no .with_retry() - this is permanent
        )
    }
}

/// Simple retry with linear backoff
fn simple_retry_example() {
    let service = UnstableService::new(2); // Fail 2 times, then succeed
    
    let max_attempts = 5;
    let backoff = Duration::from_millis(100);

    for attempt in 1..=max_attempts {
        match service.call() {
            Ok(result) => {
                println!("   ✓ {}", result);
                return;
            }
            Err(e) if e.is_retryable() && attempt < max_attempts => {
                println!("   Retrying in {:?}...", backoff);
                std::thread::sleep(backoff);
            }
            Err(e) => {
                println!("   ✗ Max retries exceeded: {}", e);
                return;
            }
        }
    }
}

/// Exponential backoff retry strategy
fn exponential_backoff_example() {
    let service = UnstableService::new(3); // Fail 3 times
    
    let max_attempts = 5;
    let initial_backoff = Duration::from_millis(50);
    let max_backoff = Duration::from_secs(2);

    for attempt in 1..=max_attempts {
        match service.call() {
            Ok(result) => {
                println!("   ✓ {}", result);
                return;
            }
            Err(e) if e.is_retryable() && attempt < max_attempts => {
                // Calculate exponential backoff: 50ms, 100ms, 200ms, 400ms, ...
                let backoff = initial_backoff * 2_u32.pow(attempt - 1);
                let backoff = backoff.min(max_backoff);
                
                println!("   Retrying in {:?}...", backoff);
                std::thread::sleep(backoff);
            }
            Err(e) => {
                println!("   ✗ Max retries exceeded: {}", e);
                return;
            }
        }
    }
}

/// Only retry errors that are marked as retryable
fn selective_retry_example() {
    // This service returns a permanent error
    let service = UnstableService::new(0);
    
    let max_attempts = 5;

    println!("   Testing with permanent error:");
    for attempt in 1..=max_attempts {
        match service.call_permanent_failure() {
            Ok(result) => {
                println!("   ✓ {}", result);
                return;
            }
            Err(e) if e.is_retryable() && attempt < max_attempts => {
                println!("   Error is retryable, retrying...");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                println!("   ✗ Error is not retryable, aborting immediately");
                println!("   External: {}", e);
                return;
            }
        }
    }
}

/// Retry with a total timeout constraint
fn retry_with_timeout_example() {
    let service = UnstableService::new(10); // Will fail many times
    
    let max_duration = Duration::from_secs(1);
    let backoff = Duration::from_millis(100);
    let start = Instant::now();
    
    let mut attempt = 0;

    loop {
        attempt += 1;
        
        // Check if we've exceeded total timeout
        if start.elapsed() > max_duration {
            println!("   ✗ Total timeout exceeded after {} attempts", attempt);
            return;
        }

        match service.call() {
            Ok(result) => {
                println!("   ✓ {}", result);
                println!("   Total time: {:?}", start.elapsed());
                return;
            }
            Err(e) if e.is_retryable() => {
                let remaining = max_duration.saturating_sub(start.elapsed());
                
                if remaining < backoff {
                    println!("   ✗ Not enough time for another retry");
                    println!("   External: {}", e);
                    return;
                }
                
                println!("   Retrying ({}s remaining)...", remaining.as_secs_f32());
                std::thread::sleep(backoff);
            }
            Err(e) => {
                println!("   ✗ Permanent error: {}", e);
                return;
            }
        }
    }
}

/// Helper function: Retry with exponential backoff (reusable)
pub fn retry_with_exponential_backoff<F, T>(
    mut operation: F,
    max_attempts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    let mut last_error = None;

    for attempt in 1..=max_attempts {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) if e.is_retryable() && attempt < max_attempts => {
                let backoff = initial_backoff * 2_u32.pow(attempt - 1);
                let backoff = backoff.min(max_backoff);
                std::thread::sleep(backoff);
                last_error = Some(e);
            }
            Err(e) => return Err(e),
        }
    }

    Err(last_error.unwrap())
}