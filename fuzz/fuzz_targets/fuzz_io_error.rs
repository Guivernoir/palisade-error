#![no_main]

//! Fuzz target for I/O error path handling
//!
//! Tests that file path handling never:
//! - Panics on arbitrary paths
//! - Leaks paths in external display
//! - Breaks on unicode paths
//! - Has issues with path separators
//!
//! Run with: cargo fuzz run fuzz_io_error

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions};
use std::io;

fuzz_target!(|data: &[u8]| {
    if let Ok(path_str) = std::str::from_utf8(data) {
        // Limit path length to prevent OOM
        let path = &path_str[..path_str.len().min(4096)];
        
        // Test different I/O error kinds
        let error_kinds = vec![
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::AlreadyExists,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::InvalidData,
            io::ErrorKind::TimedOut,
            io::ErrorKind::WriteZero,
            io::ErrorKind::Interrupted,
            io::ErrorKind::UnexpectedEof,
        ];

        for error_kind in error_kinds {
            let io_error = io::Error::from(error_kind);
            
            let err = AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "read_file",
                path,
                io_error
            );

            // External display should NOT contain path
            let displayed = format!("{}", err);
            
            // Check that path doesn't leak (handle common substrings)
            if path.len() > 3 {
                // Don't check very short paths as they might coincidentally appear
                assert!(!displayed.contains(path),
                    "Path leaked in external display: {}", path);
            }
            
            // Common path components should not leak
            let path_components = vec!["/etc/", "/home/", "/var/", "C:\\", "secret", "password"];
            for component in path_components {
                if path.contains(component) {
                    assert!(!displayed.contains(component),
                        "Path component '{}' leaked from path: {}", component, path);
                }
            }

            // Operation name should not leak
            assert!(!displayed.contains("read_file"),
                "Operation name leaked in external display");

            // Internal log SHOULD contain path
            err.with_internal_log(|log| {
                // Should have sensitive source (the path)
                assert!(log.source_sensitive().is_some(),
                    "Path not stored in sensitive source");
                
                // Should have internal source (error kind)
                assert!(log.source_internal().is_some(),
                    "Error kind not stored in internal source");

                let mut buffer = String::new();
                log.write_to(&mut buffer).expect("write_to failed");

                // Verify path appears in internal log (if not too long)
                if path.len() <= 1024 {
                    assert!(buffer.contains(path) || buffer.contains("sensitive="),
                        "Path not in internal log");
                }

                // Verify output is valid UTF-8
                assert!(std::str::from_utf8(buffer.as_bytes()).is_ok(),
                    "Internal log contains invalid UTF-8");
            });

            // Test Debug output
            let debug = format!("{:?}", err);
            assert!(std::str::from_utf8(debug.as_bytes()).is_ok(),
                "Debug output contains invalid UTF-8");
            
            // Path should be redacted in debug
            if path.len() > 3 {
                assert!(!debug.contains(path) || debug.contains("REDACTED"),
                    "Path leaked in Debug output without redaction");
            }
        }

        // Test with various path formats
        let test_paths = vec![
            path,
            &format!("/tmp/{}", path),
            &format!("C:\\Users\\{}", path),
            &format!("../../../{}", path),
            &format!("~/{}", path),
        ];

        for test_path in test_paths {
            let err = AgentError::from_io_path(
                definitions::IO_WRITE_FAILED,
                "write_file",
                test_path,
                io::Error::from(io::ErrorKind::PermissionDenied)
            );

            let displayed = format!("{}", err);
            
            // None of the path variants should leak
            if test_path.len() > 3 {
                assert!(!displayed.contains(test_path),
                    "Test path leaked: {}", test_path);
            }
        }
    }
});