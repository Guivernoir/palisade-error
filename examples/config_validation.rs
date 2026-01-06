//! Configuration Validation Example
//!
//! Demonstrates error handling in configuration parsing and validation,
//! a common use case in security systems.
//!
//! Run with: cargo run --example config_validation

use palisade_errors::{AgentError, definitions, config_err, Result};
use std::collections::HashMap;

fn main() {
    println!("=== Configuration Validation Example ===\n");

    // Example 1: Single field validation
    println!("1. Single Field Validation:");
    match validate_threshold(150.0) {
        Ok(val) => println!("   Valid threshold: {}", val),
        Err(e) => println!("   Error: {}", e),
    }
    println!();

    // Example 2: Multiple field validation
    println!("2. Multiple Field Validation:");
    let config = HashMap::from([
        ("threshold".to_string(), "85.5".to_string()),
        ("timeout".to_string(), "30".to_string()),
        ("max_retries".to_string(), "3".to_string()),
    ]);
    match validate_config(&config) {
        Ok(_) => println!("   Configuration valid"),
        Err(e) => {
            println!("   Configuration invalid:");
            println!("   External: {}", e);
            e.with_internal_log(|log| {
                let mut buffer = String::new();
                log.write_to(&mut buffer).unwrap();
                println!("   Internal: {}", buffer);
            });
        }
    }
    println!();

    // Example 3: Collecting multiple validation errors
    println!("3. Collecting Multiple Errors:");
    let bad_config = HashMap::from([
        ("threshold".to_string(), "150.0".to_string()), // Too high
        ("timeout".to_string(), "0".to_string()),       // Zero
        ("max_retries".to_string(), "-1".to_string()),  // Negative
    ]);
    let errors = validate_all_fields(&bad_config);
    println!("   Found {} validation errors:", errors.len());
    for (i, err) in errors.iter().enumerate() {
        println!("   {}. {}", i + 1, err);
    }
    println!();

    // Example 4: Sensitive configuration data
    println!("4. Handling Sensitive Data:");
    match load_credentials("/etc/secrets/api_key.conf") {
        Ok(_) => println!("   Credentials loaded"),
        Err(e) => {
            println!("   External: {}", e);
            // Notice that the path doesn't appear in external display
        }
    }
}

/// Validate a threshold value (must be 0-100)
fn validate_threshold(value: f64) -> Result<f64> {
    if value < 0.0 || value > 100.0 {
        return Err(config_err!(
            definitions::CFG_INVALID_VALUE,
            "validate_threshold",
            "Threshold must be between 0.0 and 100.0, got {}",
            value
        ));
    }
    Ok(value)
}

/// Validate timeout value (must be positive)
fn validate_timeout(value: u64) -> Result<u64> {
    if value == 0 {
        return Err(config_err!(
            definitions::CFG_INVALID_VALUE,
            "validate_timeout",
            "Timeout must be greater than 0"
        ));
    }
    Ok(value)
}

/// Validate max retries (must be positive)
fn validate_max_retries(value: i32) -> Result<i32> {
    if value < 0 {
        return Err(config_err!(
            definitions::CFG_INVALID_VALUE,
            "validate_max_retries",
            "Max retries cannot be negative"
        ));
    }
    Ok(value)
}

/// Validate entire configuration (short-circuit on first error)
fn validate_config(config: &HashMap<String, String>) -> Result<()> {
    // Parse and validate threshold
    let threshold: f64 = config
        .get("threshold")
        .ok_or_else(|| config_err!(
            definitions::CFG_MISSING_REQUIRED,
            "validate_config",
            "Missing required field: threshold"
        ))?
        .parse()
        .map_err(|_| config_err!(
            definitions::CFG_PARSE_FAILED,
            "parse_threshold",
            "Invalid threshold value format"
        ))?;
    
    validate_threshold(threshold)?;

    // Parse and validate timeout
    let timeout: u64 = config
        .get("timeout")
        .ok_or_else(|| config_err!(
            definitions::CFG_MISSING_REQUIRED,
            "validate_config",
            "Missing required field: timeout"
        ))?
        .parse()
        .map_err(|_| config_err!(
            definitions::CFG_PARSE_FAILED,
            "parse_timeout",
            "Invalid timeout value format"
        ))?;
    
    validate_timeout(timeout)?;

    // Parse and validate max_retries
    let max_retries: i32 = config
        .get("max_retries")
        .ok_or_else(|| config_err!(
            definitions::CFG_MISSING_REQUIRED,
            "validate_config",
            "Missing required field: max_retries"
        ))?
        .parse()
        .map_err(|_| config_err!(
            definitions::CFG_PARSE_FAILED,
            "parse_max_retries",
            "Invalid max_retries value format"
        ))?;
    
    validate_max_retries(max_retries)?;

    Ok(())
}

/// Validate all fields and collect errors (don't short-circuit)
fn validate_all_fields(config: &HashMap<String, String>) -> Vec<AgentError> {
    let mut errors = Vec::new();

    // Validate threshold
    if let Some(threshold_str) = config.get("threshold") {
        if let Ok(threshold) = threshold_str.parse::<f64>() {
            if let Err(e) = validate_threshold(threshold) {
                errors.push(e.with_metadata("field", "threshold"));
            }
        } else {
            errors.push(
                config_err!(
                    definitions::CFG_PARSE_FAILED,
                    "parse_threshold",
                    "Invalid threshold format"
                )
                .with_metadata("field", "threshold")
            );
        }
    } else {
        errors.push(
            config_err!(
                definitions::CFG_MISSING_REQUIRED,
                "validate_config",
                "Missing required field"
            )
            .with_metadata("field", "threshold")
        );
    }

    // Validate timeout
    if let Some(timeout_str) = config.get("timeout") {
        if let Ok(timeout) = timeout_str.parse::<u64>() {
            if let Err(e) = validate_timeout(timeout) {
                errors.push(e.with_metadata("field", "timeout"));
            }
        } else {
            errors.push(
                config_err!(
                    definitions::CFG_PARSE_FAILED,
                    "parse_timeout",
                    "Invalid timeout format"
                )
                .with_metadata("field", "timeout")
            );
        }
    }

    // Validate max_retries
    if let Some(retries_str) = config.get("max_retries") {
        if let Ok(retries) = retries_str.parse::<i32>() {
            if let Err(e) = validate_max_retries(retries) {
                errors.push(e.with_metadata("field", "max_retries"));
            }
        } else {
            errors.push(
                config_err!(
                    definitions::CFG_PARSE_FAILED,
                    "parse_max_retries",
                    "Invalid max_retries format"
                )
                .with_metadata("field", "max_retries")
            );
        }
    }

    errors
}

/// Load credentials from a file (demonstrates sensitive path handling)
fn load_credentials(path: &str) -> Result<String> {
    use std::fs;
    
    fs::read_to_string(path).map_err(|e| {
        AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "load_credentials",
            path, // Path is kept separate as sensitive data
            e
        )
    })
}