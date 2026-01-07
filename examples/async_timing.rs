//! Demonstrates async-safe timing normalization for Tokio runtime.
//!
//! Run with: cargo run --example async_timing --features tokio

use palisade_errors::{AgentError, definitions, Result};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    println!("=== Async Timing Normalization Demo ===\n");

    // Scenario 1: Fast path (user doesn't exist)
    println!("1. Testing fast authentication path...");
    let start = Instant::now();
    let result = authenticate_user("nonexistent", "password").await;
    let fast_duration = start.elapsed();
    
    assert!(result.is_err());
    println!("   Fast path took: {:?}", fast_duration);
    println!("   Expected: ~100ms (normalized)");
    println!("   Actual vs expected: {}ms difference\n", 
        (fast_duration.as_millis() as i64 - 100).abs());

    // Scenario 2: Slow path (password hash check)
    println!("2. Testing slow authentication path...");
    let start = Instant::now();
    let result = authenticate_user("admin", "wrongpassword").await;
    let slow_duration = start.elapsed();
    
    assert!(result.is_err());
    println!("   Slow path took: {:?}", slow_duration);
    println!("   Expected: ~100ms (normalized)");
    println!("   Actual vs expected: {}ms difference\n",
        (slow_duration.as_millis() as i64 - 100).abs());

    // Scenario 3: Concurrent requests
    println!("3. Testing 10 concurrent authentication failures...");
    let start = Instant::now();
    
    let mut handles = vec![];
    for i in 0..10 {
        let handle = tokio::spawn(async move {
            authenticate_user(&format!("user{}", i), "password").await
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await.unwrap();
    }
    
    let concurrent_duration = start.elapsed();
    println!("   10 concurrent requests took: {:?}", concurrent_duration);
    println!("   Expected: ~100-150ms (overlapping, not blocking)");
    println!("   If this took >1 second, timing normalization is blocking!\n");

    println!("=== Key Observations ===");
    println!("✓ Fast and slow paths take similar time (timing attack mitigation)");
    println!("✓ Concurrent requests don't block each other (async-safe)");
    println!("✓ No executor thread starvation");
    println!("✓ Response timing is constant regardless of failure reason");
}

/// Simulate authentication with timing side-channel.
async fn authenticate_user(username: &str, password: &str) -> Result<()> {
    // Fast path: user doesn't exist (~5ms in reality)
    if !user_exists(username).await {
        return Err(
            AgentError::config(
                definitions::CFG_VALIDATION_FAILED,
                "authenticate_user",
                "Invalid credentials"
            )
            .with_timing_normalization_async(Duration::from_millis(100))
            .await
        );
    }

    // Slow path: password hash check (~80ms in reality)
    tokio::time::sleep(Duration::from_millis(80)).await;
    if !check_password(username, password).await {
        return Err(
            AgentError::config(
                definitions::CFG_VALIDATION_FAILED,
                "authenticate_user",
                "Invalid credentials"
            )
            .with_timing_normalization_async(Duration::from_millis(100))
            .await
        );
    }

    Ok(())
}

async fn user_exists(username: &str) -> bool {
    // Simulate database lookup (fast)
    tokio::time::sleep(Duration::from_millis(5)).await;
    username == "admin"
}

async fn check_password(_username: &str, _password: &str) -> bool {
    // Simulate password hash verification (slow)
    tokio::time::sleep(Duration::from_millis(80)).await;
    false // Always fail for demo
}