//! Demonstrates bounded forensic logging with ring buffer.
//!
//! Run with: cargo run --example ring_buffer_demo

use palisade_errors::{AgentError, definitions};
use palisade_errors::ring_buffer::RingBufferLogger;
use std::time::Instant;

fn main() {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║     RING BUFFER FORENSIC LOGGER DEMO                  ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // Configuration
    let max_entries = 100;
    let max_entry_bytes = 2048;
    let logger = RingBufferLogger::new(max_entries, max_entry_bytes);

    println!("Configuration:");
    println!("  • Max entries: {}", max_entries);
    println!("  • Max entry size: {} bytes", max_entry_bytes);
    println!("  • Max memory: {} KB\n", (max_entries * max_entry_bytes) / 1024);

    // Scenario 1: Normal logging
    println!("=== Scenario 1: Normal Operation ===");
    for i in 0..10 {
        let err = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "validate_input",
            format!("Validation failed for input #{}", i)
        )
        .with_metadata("request_id", format!("req-{}", i));

        logger.log(&err, &format!("192.168.1.{}", 100 + i));
    }
    println!("✓ Logged 10 normal errors");
    println!("  Buffer: {}/{} entries", logger.len(), logger.capacity());
    println!("  Memory: {} KB\n", logger.memory_usage_bytes() / 1024);

    // Scenario 2: Attack burst (should trigger evictions)
    println!("=== Scenario 2: Attack Burst (500 errors) ===");
    let start = Instant::now();
    
    for i in 0..500 {
        let err = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "authenticate",
            format!("Auth failed: attempt #{} with long payload: {}", i, "X".repeat(100))
        )
        .with_metadata("campaign_id", "bruteforce_2024")
        .with_metadata("attempt", i.to_string());

        logger.log(&err, &format!("192.168.1.{}", i % 256));
    }
    
    let duration = start.elapsed();
    println!("✓ Logged 500 errors in {:?}", duration);
    println!("  Buffer: {}/{} entries (oldest evicted)", logger.len(), logger.capacity());
    println!("  Memory: {} KB", logger.memory_usage_bytes() / 1024);
    println!("  Evictions: {}", logger.eviction_count());
    println!("  Throughput: {:.0} errors/sec\n", 500.0 / duration.as_secs_f64());

    // Scenario 3: DoS attempt with huge payloads
    println!("=== Scenario 3: DoS Attempt (Huge Payloads) ===");
    for i in 0..10 {
        let huge_payload = "A".repeat(100_000); // 100KB payload
        let err = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "process_request",
            format!("DoS attempt: {}", huge_payload)
        );

        logger.log(&err, "192.168.1.99");
    }
    println!("✓ Survived 10 errors with 100KB payloads each");
    println!("  Buffer: {}/{} entries", logger.len(), logger.capacity());
    println!("  Memory: {} KB (truncation prevented explosion)\n", 
        logger.memory_usage_bytes() / 1024);

    // Analysis: Recent entries
    println!("=== Recent Entries (Last 5) ===");
    let recent = logger.get_recent(5);
    for (idx, entry) in recent.iter().enumerate() {
        println!("  [{}] {} - {} ({}B)",
            idx + 1,
            entry.code,
            &entry.operation,
            entry.size_bytes
        );
        if entry.details.len() > 50 {
            println!("      Details: {}...", &entry.details[..50]);
        } else {
            println!("      Details: {}", entry.details);
        }
    }
    println!();

    // Analysis: Filter by source IP
    println!("=== Attack Pattern Analysis ===");
    let from_attacker = logger.get_filtered(|e| e.source_ip.starts_with("192.168.1.99"));
    println!("  Errors from 192.168.1.99: {}", from_attacker.len());
    
    let bruteforce_campaign = logger.get_filtered(|e| {
        e.metadata.iter().any(|(k, v)| k == &"campaign_id" && v == "bruteforce_2024")
    });
    println!("  Errors in bruteforce campaign: {}", bruteforce_campaign.len());
    
    // Calculate error rate
    if let (Some(oldest), Some(newest)) = (logger.get_all().last(), logger.get_all().first()) {
        let time_span = newest.timestamp - oldest.timestamp;
        if time_span > 0 {
            let rate = logger.len() as f64 / time_span as f64;
            println!("  Current error rate: {:.1} errors/sec", rate);
        }
    }
    println!();

    // Memory efficiency
    println!("=== Memory Efficiency ===");
    let avg_entry_size = if logger.len() > 0 {
        logger.memory_usage_bytes() / logger.len()
    } else {
        0
    };
    println!("  Average entry size: {} bytes", avg_entry_size);
    println!("  Memory utilization: {:.1}%", 
        (logger.memory_usage_bytes() as f64 / (max_entries * max_entry_bytes) as f64) * 100.0);
    println!("  Buffer utilization: {:.1}%",
        (logger.len() as f64 / logger.capacity() as f64) * 100.0);
    println!();

    println!("╔════════════════════════════════════════════════════════╗");
    println!("║     KEY PROPERTIES DEMONSTRATED                        ║");
    println!("╚════════════════════════════════════════════════════════╝");
    println!("✓ Bounded memory: {} KB maximum", (max_entries * max_entry_bytes) / 1024);
    println!("✓ DoS resistant: Truncation + eviction prevents exhaustion");
    println!("✓ High throughput: Handles burst attacks efficiently");
    println!("✓ Pattern analysis: Filter and correlation capabilities");
    println!("✓ FIFO eviction: Retains most recent attack data");
    println!("✓ Predictable performance: O(1) insertion and eviction");
}