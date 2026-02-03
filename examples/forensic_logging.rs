use palisade_errors::{
    AgentError, definitions, 
    ring_buffer::RingBufferLogger
};
use std::thread;
use std::time::Duration;

fn main() {
    println!("--- Forensic Ring Buffer Example ---\n");

    // Initialize a small buffer for demonstration
    // Max 10 entries, Max 128 bytes per entry
    let logger = RingBufferLogger::new(10, 128);

    println!("1. Simulating massive brute force attack (50 requests)...");
    
    for i in 1..=50 {
        // Simulate an attack from changing IPs
        let ip = format!("192.168.1.{}", i);
        
        let err = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "auth_check",
            format!("Invalid password provided for user 'admin' (Attempt {})", i)
        );

        // Log to ring buffer
        logger.log(&err, &ip);
        
        // Simulate tiny network delay
        if i % 10 == 0 { thread::sleep(Duration::from_millis(5)); }
    }

    println!("2. Attack finished. Analyzing buffer state.");
    println!("   Total Evictions (Dropped logs): {}", logger.eviction_count());
    println!("   Current Buffer Size: {}", logger.len());
    println!("   Buffer Capacity:     {}", logger.capacity());

    println!("\n3. Dumping remaining forensic data (Last 10 events):");
    println!("{:<10} | {:<15} | {}", "Time", "Source IP", "Details");
    println!("{:-<10}-|-{:-<15}-|-{:-<20}", "", "", "");

    let recent_logs = logger.get_recent(10);
    
    for entry in recent_logs {
        println!(
            "{:<10} | {:<15} | {}", 
            entry.timestamp % 10000, // Just show last digits of timestamp
            entry.source_ip, 
            entry.details
        );
    }

    println!("\nNotice that attempts 1-40 are gone. Only the most recent forensic data remains.");
}