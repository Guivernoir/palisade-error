//! Basic Error Handling Example
//!
//! Demonstrates fundamental error handling patterns with the Palisade error system.
//!
//! Run with: cargo run --example basic_errors

use palisade_errors::{AgentError, definitions, config_err, Result};

fn main() {
    println!("=== Basic Error Handling Example ===\n");

    // Example 1: Simple error creation
    simple_error_example();

    // Example 2: Error with retry
    retryable_error_example();

    // Example 3: Error with metadata
    error_with_metadata_example();

    // Example 4: Error propagation
    error_propagation_example();
}

/// Example 1: Creating a simple error
fn simple_error_example() {
    println!("1. Simple Error Creation:");
    
    let err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "parse_config",
        "Invalid configuration format"
    );

    // External display (safe for logs visible to attackers)
    println!("   External: {}", err);
    
    // Internal logging (full context for forensics)
    err.with_internal_log(|log| {
        let mut buffer = String::new();
        log.write_to(&mut buffer).unwrap();
        println!("   Internal: {}", buffer);
    });
    
    println!();
}

/// Example 2: Retryable errors for transient failures
fn retryable_error_example() {
    println!("2. Retryable Error:");
    
    let err = AgentError::telemetry(
        definitions::TEL_CHANNEL_CLOSED,
        "collect_telemetry",
        "Event channel temporarily unavailable"
    ).with_retry();

    println!("   External: {}", err);
    println!("   Is retryable: {}", err.is_retryable());
    println!();
}

/// Example 3: Adding tracking metadata
fn error_with_metadata_example() {
    println!("3. Error with Metadata:");
    
    let err = AgentError::deployment(
        definitions::DCP_DEPLOY_FAILED,
        "deploy_honeypot",
        "Failed to deploy deception artifact"
    )
    .with_metadata("artifact_id", "hp_001")
    .with_metadata("target_path", "/opt/honeypots/web")
    .with_metadata("deployment_id", "deploy_20240115_001");

    println!("   External: {}", err);
    
    err.with_internal_log(|log| {
        println!("   Metadata count: {}", log.metadata().len());
        for (key, _) in log.metadata() {
            println!("     - {}", key);
        }
    });
    
    println!();
}

/// Example 4: Error propagation through call stack
fn error_propagation_example() {
    println!("4. Error Propagation:");
    
    fn level_3() -> Result<()> {
        Err(config_err!(
            definitions::CFG_VALIDATION_FAILED,
            "validate_threshold",
            "Threshold value out of range"
        ))
    }

    fn level_2() -> Result<()> {
        level_3()?;
        Ok(())
    }

    fn level_1() -> Result<()> {
        level_2()?;
        Ok(())
    }

    match level_1() {
        Ok(_) => println!("   Success"),
        Err(e) => {
            println!("   Caught error at top level:");
            println!("   External: {}", e);
            
            e.with_internal_log(|log| {
                println!("   Operation: {}", log.operation());
                println!("   Details: {}", log.details());
            });
        }
    }
    
    println!();
}