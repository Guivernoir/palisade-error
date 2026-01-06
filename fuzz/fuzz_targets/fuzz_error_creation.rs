#![no_main]

//! Fuzz target for basic error creation
//!
//! Tests that creating errors with arbitrary strings never:
//! - Panics
//! - Leaks memory
//! - Exposes sensitive data in external display
//!
//! Run with: cargo fuzz run fuzz_error_creation

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions};

fuzz_target!(|data: &[u8]| {
    // Only process valid UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        // Limit input size to prevent OOM
        let truncated = &s[..s.len().min(10_000)];
        
        // Test each error constructor type
        let errors = vec![
            AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "fuzz_op",
                truncated
            ),
            AgentError::deployment(
                definitions::DCP_DEPLOY_FAILED,
                "fuzz_op",
                truncated
            ),
            AgentError::telemetry(
                definitions::TEL_INIT_FAILED,
                "fuzz_op",
                truncated
            ),
            AgentError::correlation(
                definitions::COR_RULE_EVAL_FAILED,
                "fuzz_op",
                truncated
            ),
            AgentError::response(
                definitions::RSP_EXEC_FAILED,
                "fuzz_op",
                truncated
            ),
            AgentError::logging(
                definitions::LOG_WRITE_FAILED,
                "fuzz_op",
                truncated
            ),
            AgentError::platform(
                definitions::PLT_SYSCALL_FAILED,
                "fuzz_op",
                truncated
            ),
            AgentError::io_operation(
                definitions::IO_READ_FAILED,
                "fuzz_op",
                truncated
            ),
        ];

        for err in errors {
            // These operations should never panic
            let _ = format!("{}", err);
            let _ = format!("{:?}", err);
            
            // Test with retry flag
            let with_retry = err.with_retry();
            assert!(with_retry.is_retryable());
            
            // Verify details don't appear in external display
            let displayed = format!("{}", with_retry);
            assert!(!displayed.contains(truncated), 
                "Input leaked into external display: {}", displayed);
            assert!(!displayed.contains("fuzz_op"),
                "Operation name leaked into external display: {}", displayed);
        }
    }
});