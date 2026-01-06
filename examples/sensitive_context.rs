//! Example demonstrating sensitive context handling
//!
//! Run with: cargo run --example sensitive_context

use palisade_errors::{AgentError, definitions, Result};
use std::fs::File;
use std::io;

fn load_config_file(path: &str) -> Result<String> {
    // Simulate file reading
    Err(AgentError::from_io_path(
        definitions::IO_READ_FAILED,
        "load_config_file",
        path,
        io::Error::new(io::ErrorKind::PermissionDenied, "access denied")
    ))
}

fn validate_credentials(username: &str, token: &str) -> Result<()> {
    if username.is_empty() {
        return Err(AgentError::config_sensitive(
            definitions::CFG_MISSING_REQUIRED,
            "validate_credentials",
            "Username is required",
            &format!("Empty username for token: {}", &token[..8.min(token.len())])
        ));
    }
    
    if token.len() < 32 {
        return Err(AgentError::config_sensitive(
            definitions::CFG_INVALID_VALUE,
            "validate_credentials",
            "Token must be at least 32 characters",
            &format!("Token length: {} for user: {}", token.len(), username)
        ));
    }
    
    Ok(())
}

fn main() {
    println!("=== Palisade Errors: Sensitive Context ===\n");
    
    // Example 1: File path handling
    println!("1. File I/O with sensitive path:");
    let secret_path = "/etc/palisade/secrets.toml";
    match load_config_file(secret_path) {
        Ok(_) => println!("   ✓ File loaded"),
        Err(e) => {
            // External display - NO PATH VISIBLE
            println!("   ✗ External: {}", e);
            println!("   ℹ Code: {}", e.code());
            
            // Internal logging - path is separate from error kind
            let log = e.internal_log();
            println!("   ℹ Internal source (error kind): {:?}", log.source_internal());
            println!("   ℹ Sensitive source (path): {:?}", log.source_sensitive());
            println!();
        }
    }
    
    // Example 2: Credentials with sensitive data
    println!("2. Credential validation:");
    match validate_credentials("", "short_token") {
        Ok(_) => println!("   ✓ Credentials valid"),
        Err(e) => {
            // External display - NO CREDENTIALS VISIBLE
            println!("   ✗ External: {}", e);
            
            // Internal logging shows details
            let log = e.internal_log();
            println!("   ℹ Operation: {}", log.operation());
            println!("   ℹ Details: {}", log.details());
            if let Some(sensitive) = log.source_sensitive() {
                println!("   ℹ Sensitive context: {}", sensitive);
            }
            println!();
        }
    }
    
    // Example 3: Proper credential handling
    println!("3. Another credential error:");
    match validate_credentials("admin", "tooshort") {
        Ok(_) => println!("   ✓ Credentials valid"),
        Err(e) => {
            println!("   ✗ External: {}", e);
            
            // Zero-allocation internal logging
            print!("   ℹ Internal: ");
            e.with_internal_log(|log| {
                let mut buffer = String::new();
                log.write_to(&mut buffer).unwrap();
                println!("{}", buffer);
            });
            println!();
        }
    }
    
    println!("=== Security Properties Demonstrated ===");
    println!("• File paths never appear in external errors");
    println!("• Error kinds and paths stored separately");
    println!("• Credentials and tokens never in Display output");
    println!("• All context zeroized when error is dropped");
    println!("• Internal logs available for forensics");
    
    #[cfg(feature = "trusted_debug")]
    {
        println!("\n=== Trusted Debug Mode (Feature Enabled) ===");
        let err = AgentError::config_sensitive(
            definitions::CFG_INVALID_VALUE,
            "test",
            "test error",
            "secret_data_here"
        );
        
        let log = err.internal_log();
        println!("Full debug output:\n{}", log.format_for_trusted_debug());
        println!("\n⚠️  Only use trusted_debug in secure environments!");
    }
    
    #[cfg(not(feature = "trusted_debug"))]
    {
        println!("\n💡 Enable 'trusted_debug' feature to see full debug output");
        println!("   cargo run --example sensitive_context --features trusted_debug");
    }
}