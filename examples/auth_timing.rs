//! Authentication with Timing Protection Example
//!
//! Demonstrates how to use timing normalization to prevent timing side-channel
//! attacks that could be used for user enumeration or other reconnaissance.
//!
//! Run with: cargo run --example auth_timing

use palisade_errors::{AgentError, definitions, Result};
use std::time::{Duration, Instant};
use std::collections::HashMap;

// Simulated user database
struct UserDatabase {
    users: HashMap<String, String>, // username -> password_hash
}

impl UserDatabase {
    fn new() -> Self {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "hash_of_alices_password".to_string());
        users.insert("bob".to_string(), "hash_of_bobs_password".to_string());
        Self { users }
    }

    fn user_exists(&self, username: &str) -> bool {
        self.users.contains_key(username)
    }

    fn verify_password(&self, username: &str, password_hash: &str) -> bool {
        // In real code, this would do constant-time comparison
        self.users.get(username)
            .map(|stored_hash| stored_hash == password_hash)
            .unwrap_or(false)
    }
}

fn main() {
    println!("=== Authentication Timing Protection Example ===\n");

    let db = UserDatabase::new();

    // Example 1: Without timing protection (VULNERABLE)
    println!("1. WITHOUT Timing Protection (Vulnerable):");
    demonstrate_timing_attack(&db);
    println!();

    // Example 2: With timing protection (SECURE)
    println!("2. WITH Timing Protection (Secure):");
    demonstrate_timing_protection(&db);
    println!();

    // Example 3: Real authentication flow
    println!("3. Real Authentication Flow:");
    test_authentication(&db);
}

/// Vulnerable authentication (different timing for different failures)
fn authenticate_vulnerable(db: &UserDatabase, username: &str, password: &str) -> Result<()> {
    // Fast path: user doesn't exist (returns immediately)
    if !db.user_exists(username) {
        return Err(AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "authenticate",
            "Invalid credentials"
        ));
    }

    // Slow path: verify password (simulated expensive operation)
    std::thread::sleep(Duration::from_millis(50)); // Simulate password hashing
    
    let password_hash = format!("hash_of_{}", password);
    if !db.verify_password(username, &password_hash) {
        return Err(AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "authenticate",
            "Invalid credentials"
        ));
    }

    Ok(())
}

/// Secure authentication (constant timing regardless of failure reason)
fn authenticate_secure(db: &UserDatabase, username: &str, password: &str) -> Result<()> {
    const AUTH_TIMEOUT: Duration = Duration::from_millis(100);
    
    // Fast path: user doesn't exist
    if !db.user_exists(username) {
        return Err(
            AgentError::config(
                definitions::CFG_VALIDATION_FAILED,
                "authenticate",
                "Invalid credentials"
            )
            .with_timing_normalization(AUTH_TIMEOUT)
        );
    }

    // Slow path: verify password
    std::thread::sleep(Duration::from_millis(50)); // Simulate password hashing
    
    let password_hash = format!("hash_of_{}", password);
    if !db.verify_password(username, &password_hash) {
        return Err(
            AgentError::config(
                definitions::CFG_VALIDATION_FAILED,
                "authenticate",
                "Invalid credentials"
            )
            .with_timing_normalization(AUTH_TIMEOUT)
        );
    }

    Ok(())
}

/// Demonstrate how timing attack works
fn demonstrate_timing_attack(db: &UserDatabase) {
    // Try authenticating with non-existent user
    let start1 = Instant::now();
    let _ = authenticate_vulnerable(db, "nonexistent", "password");
    let time1 = start1.elapsed();
    
    // Try authenticating with existing user but wrong password
    let start2 = Instant::now();
    let _ = authenticate_vulnerable(db, "alice", "wrong_password");
    let time2 = start2.elapsed();

    println!("   Time for non-existent user: {:?}", time1);
    println!("   Time for wrong password:     {:?}", time2);
    println!("   Difference: {:?}", time2.saturating_sub(time1));
    println!("   ⚠️  Attacker can detect if username exists!");
}

/// Demonstrate timing protection
fn demonstrate_timing_protection(db: &UserDatabase) {
    // Try authenticating with non-existent user
    let start1 = Instant::now();
    let _ = authenticate_secure(db, "nonexistent", "password");
    let time1 = start1.elapsed();
    
    // Try authenticating with existing user but wrong password
    let start2 = Instant::now();
    let _ = authenticate_secure(db, "alice", "wrong_password");
    let time2 = start2.elapsed();

    println!("   Time for non-existent user: {:?}", time1);
    println!("   Time for wrong password:     {:?}", time2);
    
    let diff = if time1 > time2 {
        time1 - time2
    } else {
        time2 - time1
    };
    
    println!("   Difference: {:?}", diff);
    println!("   ✓ Both take similar time - timing attack prevented!");
}

/// Test real authentication scenarios
fn test_authentication(db: &UserDatabase) {
    let test_cases = vec![
        ("alice", "alices_password", "Valid user, correct password"),
        ("alice", "wrong_password", "Valid user, wrong password"),
        ("nonexistent", "any_password", "Non-existent user"),
        ("bob", "bobs_password", "Valid user, correct password"),
    ];

    for (username, password, description) in test_cases {
        print!("   {} ... ", description);
        match authenticate_secure(db, username, password) {
            Ok(_) => println!("✓ Success"),
            Err(e) => {
                println!("✗ Failed");
                println!("      External message: {}", e);
                // Notice: All failures show the same message externally
            }
        }
    }
}