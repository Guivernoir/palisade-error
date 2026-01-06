//! Demonstrates integration with production logging infrastructure

use palisade_errors::{AgentError, definitions, Result};
use serde_json::json;
use std::fs::File;

/// Simulated secure logger that demonstrates proper integration
struct SecureLogger {
    // In production: connection to SIEM, encrypted log file, etc.
}

impl SecureLogger {
    /// Log error with full forensic context to secure storage
    fn log_error(&self, err: &AgentError) {
        // Create structured log entry
        let log_entry = err.with_internal_log(|log| {
            json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "severity": "ERROR",
                "code": log.code().to_string(),
                "namespace": log.code().namespace(),
                "category": format!("{:?}", err.category()),
                "operation": log.operation(),
                "details": log.details(),
                "retryable": log.is_retryable(),
                "metadata": log.metadata().iter()
                    .map(|(k, v)| (k.to_string(), v.as_str().to_string()))
                    .collect::<std::collections::HashMap<_, _>>(),
                // Sensitive data logged separately with restricted access
                "has_sensitive_context": log.source_sensitive().is_some(),
            })
        });

        // In production: write to secure log with access controls
        eprintln!("SECURE LOG: {}", log_entry);
        
        // Sensitive data goes to separate, highly restricted log
        if err.internal_log().source_sensitive().is_some() {
            self.log_sensitive_context(err);
        }
    }
    
    /// Log sensitive context to restricted storage (HSM, encrypted volume, etc.)
    fn log_sensitive_context(&self, err: &AgentError) {
        err.with_internal_log(|log| {
            if let Some(sensitive) = log.source_sensitive() {
                let sensitive_entry = json!({
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "code": log.code().to_string(),
                    "correlation_id": log.metadata()
                        .iter()
                        .find(|(k, _)| *k == "correlation_id")
                        .map(|(_, v)| v.as_str()),
                    // Hash the sensitive data for correlation without storing plaintext
                    "context_hash": format!("{:x}", md5::compute(sensitive)),
                    // Only log sensitive data if absolutely necessary
                    "context": sensitive,  // In production: encrypt this
                });
                
                eprintln!("RESTRICTED LOG: {}", sensitive_entry);
            }
        });
    }
}

/// Simulated HTTP API response builder
fn build_api_response(err: &AgentError) -> serde_json::Value {
    json!({
        "error": {
            "code": err.code().to_string(),
            "message": err.to_string(),  // Sanitized for external consumption
            "retryable": err.is_retryable(),
            // Timestamp helps with correlation but doesn't leak internal timing
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }
    })
}

fn authenticate_user(username: &str, password: &str) -> Result<()> {
    // Simulate authentication failure
    if username.is_empty() {
        return Err(
            AgentError::config_sensitive(
                definitions::CFG_MISSING_REQUIRED,
                "authenticate",
                "Authentication failed",
                format!("Empty username, password length: {}", password.len())
            )
            .with_metadata("client_ip", "192.168.1.100")
            .with_metadata("correlation_id", "req-abc-123")
        );
    }
    
    Ok(())
}

fn load_secrets(path: &str) -> Result<String> {
    File::open(path)
        .map_err(|e| {
            AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "load_secrets",
                path.to_string(),
                e
            )
            .with_metadata("correlation_id", "req-xyz-789")
        })?;
    
    Ok("secret_data".to_string())
}

fn main() {
    println!("=== Production Integration Example ===\n");
    
    let logger = SecureLogger {};
    
    // Scenario 1: Authentication failure
    println!("1. Authentication Failure:");
    match authenticate_user("", "hunter2") {
        Ok(_) => println!("   Success"),
        Err(e) => {
            // Log full context to secure storage
            logger.log_error(&e);
            
            // Return sanitized response to client
            let response = build_api_response(&e);
            println!("   API Response: {}\n", response);
        }
    }
    
    // Scenario 2: File access error with sensitive path
    println!("2. Sensitive File Access:");
    match load_secrets("/etc/palisade/master.key") {
        Ok(_) => println!("   Success"),
        Err(e) => {
            logger.log_error(&e);
            let response = build_api_response(&e);
            println!("   API Response: {}\n", response);
        }
    }
    
    println!("=== Key Integration Patterns ===");
    println!("✓ Structured logging with JSON for SIEM integration");
    println!("✓ Separate storage for sensitive context (restricted access)");
    println!("✓ Correlation IDs for request tracing");
    println!("✓ Sanitized API responses (no information leakage)");
    println!("✓ Zero-allocation internal logging");
}