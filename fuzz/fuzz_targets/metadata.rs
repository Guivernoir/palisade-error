#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    
    // Split data into count and values
    let count = (data[0] % 16) as usize; // Max 15 metadata entries
    let remaining = &data[1..];
    
    let mut err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "operation",
        "details"
    );
    
    // Add metadata entries with arbitrary data
    for i in 0..count {
        let start = (i * remaining.len() / (count + 1)).min(remaining.len());
        let end = ((i + 1) * remaining.len() / (count + 1)).min(remaining.len());
        
        if start < end {
            let value = String::from_utf8_lossy(&remaining[start..end]);
            err = err.with_metadata("fuzzy_key", value.to_string());
        }
    }
    
    // Test that we can still log it
    let log = err.internal_log();
    let mut buffer = String::new();
    let _ = log.write_to(&mut buffer);
    
    // Should not panic
    let _ = format!("{}", err);
});