#![no_main]

//! Fuzz target for metadata handling
//!
//! Tests that adding arbitrary metadata never:
//! - Panics
//! - Leaks in external display
//! - Causes memory issues
//! - Breaks internal logging
//!
//! Run with: cargo fuzz run fuzz_metadata

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions};
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

#[derive(Debug)]
struct MetadataInput<'a> {
    values: Vec<&'a str>,
}

impl<'a> Arbitrary<'a> for MetadataInput<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let count = u.int_in_range(0..=10)?; // 0-10 metadata entries
        let mut values = Vec::new();
        
        for _ in 0..count {
            if let Ok(s) = u.arbitrary::<&str>() {
                values.push(s);
            }
        }
        
        Ok(Self { values })
    }
}

fuzz_target!(|input: MetadataInput| {
    let mut err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "test_operation",
        "test details"
    );

    // Add all metadata entries
    let metadata_keys = vec![
        "key1", "key2", "key3", "key4", "key5",
        "key6", "key7", "key8", "key9", "key10",
    ];

    for (i, value) in input.values.iter().enumerate() {
        if i < metadata_keys.len() {
            // Limit value size to prevent OOM
            let truncated = &value[..value.len().min(1000)];
            err = err.with_metadata(metadata_keys[i], truncated);
        }
    }

    // Test external display - metadata should NOT leak
    let displayed = format!("{}", err);
    for value in &input.values {
        assert!(!displayed.contains(*value),
            "Metadata value leaked in external display");
    }
    for key in &metadata_keys[..input.values.len()] {
        assert!(!displayed.contains(key),
            "Metadata key leaked in external display");
    }

    // Test internal logging - metadata SHOULD appear
    err.with_internal_log(|log| {
        let metadata = log.metadata();
        assert_eq!(metadata.len(), input.values.len().min(10));

        let mut buffer = String::new();
        log.write_to(&mut buffer).expect("write_to failed");

        // Verify buffer is reasonable size
        assert!(buffer.len() < 20_000,
            "Internal log with metadata too large: {} bytes", buffer.len());

        // Metadata should appear in internal log
        for key in &metadata_keys[..input.values.len()] {
            assert!(buffer.contains(key),
                "Metadata key '{}' not in internal log", key);
        }
    });

    // Test Debug output
    let debug = format!("{:?}", err);
    assert!(std::str::from_utf8(debug.as_bytes()).is_ok());

    // Test that error can be dropped without issues
    drop(err);
});