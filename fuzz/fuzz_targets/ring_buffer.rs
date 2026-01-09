#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions, ring_buffer::RingBufferLogger};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    
    // Parse fuzzer input
    let capacity = ((data[0] as usize) % 100) + 1; // 1-100
    let max_entry = ((data[1] as usize) % 2048) + 256; // 256-2304
    let num_ops = ((data[2] as usize) % 50) + 1; // 1-50 operations
    let remaining = &data[3..];
    
    let logger = RingBufferLogger::new(capacity, max_entry);
    
    // Perform random operations
    for i in 0..num_ops {
        let idx = i * remaining.len() / num_ops;
        if idx >= remaining.len() {
            break;
        }
        
        let op_type = remaining[idx] % 4;
        
        match op_type {
            0 => {
                // Log an error
                let detail = if idx + 100 < remaining.len() {
                    String::from_utf8_lossy(&remaining[idx..idx + 100])
                } else {
                    String::from_utf8_lossy(&remaining[idx..])
                };
                
                let err = AgentError::config(
                    definitions::CFG_PARSE_FAILED,
                    "fuzz",
                    detail.to_string()
                );
                logger.log(&err, "192.168.1.1");
            }
            1 => {
                // Get recent
                let _ = logger.get_recent(5);
            }
            2 => {
                // Get all
                let _ = logger.get_all();
            }
            3 => {
                // Get filtered
                let _ = logger.get_filtered(|_| true);
            }
            _ => unreachable!(),
        }
    }
    
    // Verify invariants
    assert!(logger.len() <= logger.capacity());
    assert!(logger.memory_usage_bytes() <= capacity * max_entry);
});