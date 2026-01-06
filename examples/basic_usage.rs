//! Basic usage example for palisade_errors
//!
//! Run with: cargo run --example basic_usage

use palisade_errors::{AgentError, definitions, Result};

fn validate_threshold(value: f64) -> Result<()> {
    if value < 0.0 || value > 100.0 {
        return Err(AgentError::config(
            definitions::CFG_INVALID_VALUE,
            "validate_threshold",
            "Threshold must be between 0 and 100"
        ));
    }
    Ok(())
}

fn process_config(threshold: f64, retries: u32) -> Result<()> {
    validate_threshold(threshold)?;
    
    if retries == 0 {
        return Err(AgentError::config(
            definitions::CFG_INVALID_VALUE,
            "process_config",
            "Retry count cannot be zero"
        ).with_retry());
    }
    
    Ok(())
}

fn main() {
    println!("=== Palisade Errors: Basic Usage ===\n");
    
    // Example 1: Valid input
    println!("1. Valid configuration:");
    match process_config(50.0, 3) {
        Ok(_) => println!("   ✓ Configuration valid\n"),
        Err(e) => println!("   ✗ Error: {}\n", e),
    }
    
    // Example 2: Invalid threshold
    println!("2. Invalid threshold:");
    match process_config(150.0, 3) {
        Ok(_) => println!("   ✓ Configuration valid"),
        Err(e) => {
            // External display - safe for untrusted viewers
            println!("   ✗ External: {}", e);
            
            // Internal logging - full context for forensics
            print!("   ℹ Internal: ");
            e.with_internal_log(|log| {
                let mut buffer = String::new();
                log.write_to(&mut buffer).unwrap();
                println!("{}", buffer);
            });
            println!();
        }
    }
    
    // Example 3: Retryable error
    println!("3. Retryable error:");
    match process_config(75.0, 0) {
        Ok(_) => println!("   ✓ Configuration valid"),
        Err(e) => {
            println!("   ✗ External: {}", e);
            println!("   ℹ Retryable: {}", e.is_retryable());
            
            // Access structured fields
            let log = e.internal_log();
            println!("   ℹ Error code: {}", log.code());
            println!("   ℹ Operation: {}", log.operation());
            println!("   ℹ Details: {}", log.details());
            println!();
        }
    }
    
    // Example 4: Error with metadata
    println!("4. Error with metadata:");
    let err = AgentError::telemetry(
        definitions::TEL_EVENT_LOST,
        "collect_metrics",
        "Event buffer full"
    )
    .with_retry()
    .with_metadata("event_id", "evt-12345")
    .with_metadata("correlation_id", "corr-67890");
    
    println!("   ✗ External: {}", err);
    
    err.with_internal_log(|log| {
        let mut buffer = String::new();
        log.write_to(&mut buffer).unwrap();
        println!("   ℹ Internal: {}", buffer);
    });
    
    println!("\n=== Key Observations ===");
    println!("• External errors show only: category, permanence, and code");
    println!("• Internal logs contain: operation, details, and metadata");
    println!("• Sensitive data is never exposed externally");
    println!("• Error codes enable tracking without information disclosure");
}