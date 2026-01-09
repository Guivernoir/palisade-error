#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions};

fuzz_target!(|data: &[u8]| {
    // Convert to string, allowing invalid UTF-8 to test boundaries
    let s = String::from_utf8_lossy(data);
    
    // Create error with potentially huge string
    let err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "fuzz_operation",
        s.to_string()
    );
    
    // Test internal logging (must truncate correctly)
    let log = err.internal_log();
    let mut buffer = String::new();
    let result = log.write_to(&mut buffer);
    
    // Should never panic, always produce valid output
    assert!(result.is_ok());
    
    // Output should be valid UTF-8
    assert!(std::str::from_utf8(buffer.as_bytes()).is_ok());
    
    // Output should be bounded (max field = 1024 + indicator)
    assert!(buffer.len() < 10000, "Truncation failed: {} bytes", buffer.len());
});