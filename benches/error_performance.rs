// benches/error_performance.rs
//! Benchmarks for palisade_errors performance characteristics
//! 
//! Critical for honeypot deployment where error rates can spike during attacks.
//! Target: <100ns for error creation, <1μs for logging

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use palisade_errors::{AgentError, definitions};
use std::io;

// ============================================================================
// ERROR CREATION BENCHMARKS
// ============================================================================

fn bench_error_creation_simple(c: &mut Criterion) {
    c.bench_function("create_simple_error", |b| {
        b.iter(|| {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "details"
            ))
        })
    });
}

fn bench_error_creation_with_string(c: &mut Criterion) {
    c.bench_function("create_error_dynamic_string", |b| {
        b.iter(|| {
            let dynamic_detail = format!("Error at line {}", 42);
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                dynamic_detail
            ))
        })
    });
}

fn bench_error_creation_sensitive(c: &mut Criterion) {
    c.bench_function("create_error_with_sensitive", |b| {
        b.iter(|| {
            black_box(AgentError::config_sensitive(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "details",
                "/etc/passwd"
            ))
        })
    });
}

fn bench_error_creation_io_split(c: &mut Criterion) {
    c.bench_function("create_error_io_split_source", |b| {
        b.iter(|| {
            let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
            black_box(AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "read_file",
                "/secret/path",
                io_err
            ))
        })
    });
}

// ============================================================================
// METADATA BENCHMARKS
// ============================================================================

fn bench_metadata_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata");
    
    // Pre-allocate strings to avoid measuring allocation
    let values: Vec<String> = (0..8).map(|i| format!("value_{}", i)).collect();
    
    for count in [1, 2, 4, 8] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                let mut err = AgentError::config(
                    definitions::CFG_PARSE_FAILED,
                    "operation",
                    "details"
                );
                
                for i in 0..count {
                    // Clone the string to avoid lifetime issues
                    err = err.with_metadata("key", values[i].clone());
                }
                
                black_box(err)
            })
        });
    }
    
    group.finish();
}

// ============================================================================
// LOGGING BENCHMARKS
// ============================================================================

fn bench_internal_log_access(c: &mut Criterion) {
    let err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "operation",
        "details"
    );
    
    c.bench_function("internal_log_access", |b| {
        b.iter(|| {
            // Benchmark creating the log and extracting owned data
            let log = err.internal_log();
            let code = log.code();
            let operation = log.operation().to_string();
            let details = log.details().to_string();
            black_box((code, operation, details))
        })
    });
}

fn bench_internal_log_write(c: &mut Criterion) {
    let err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "operation",
        "details"
    )
    .with_metadata("correlation_id", "abc-123")
    .with_metadata("session_id", "xyz-789");
    
    c.bench_function("internal_log_write_to", |b| {
        b.iter(|| {
            let log = err.internal_log();
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            black_box(buffer)
        })
    });
}

fn bench_internal_log_with_sensitive(c: &mut Criterion) {
    let err = AgentError::config_sensitive(
        definitions::CFG_PARSE_FAILED,
        "operation",
        "details",
        "/secret/path/to/file"
    );
    
    c.bench_function("internal_log_with_sensitive", |b| {
        b.iter(|| {
            let log = err.internal_log();
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            black_box(buffer)
        })
    });
}

fn bench_callback_logging(c: &mut Criterion) {
    let err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "operation",
        "details"
    );
    
    c.bench_function("callback_logging_pattern", |b| {
        b.iter(|| {
            // Use callback pattern - return owned data
            err.with_internal_log(|log| {
                let code = log.code();
                let operation = log.operation().to_string();
                black_box((code, operation))
            })
        })
    });
}

// ============================================================================
// DISPLAY FORMATTING BENCHMARKS
// ============================================================================

fn bench_external_display(c: &mut Criterion) {
    let err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "operation",
        "details"
    );
    
    c.bench_function("external_display_format", |b| {
        b.iter(|| {
            black_box(format!("{}", err))
        })
    });
}

fn bench_debug_format(c: &mut Criterion) {
    let err = AgentError::config(
        definitions::CFG_PARSE_FAILED,
        "operation",
        "details"
    );
    
    c.bench_function("debug_format", |b| {
        b.iter(|| {
            black_box(format!("{:?}", err))
        })
    });
}

// ============================================================================
// REALISTIC HONEYPOT SCENARIOS
// ============================================================================

fn bench_honeypot_auth_failure(c: &mut Criterion) {
    c.bench_function("honeypot_auth_failure", |b| {
        b.iter(|| {
            let err = AgentError::config_sensitive(
                definitions::CFG_VALIDATION_FAILED,
                "ssh_authenticate",
                "Authentication failed",
                "username=root password=hunter2"
            )
            .with_metadata("source_ip", "192.168.1.100")
            .with_metadata("auth_method", "password")
            .with_retry();
            
            // Simulate logging
            let log = err.internal_log();
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            
            // Simulate external response
            let response = format!("{}", err);
            
            black_box((buffer, response))
        })
    });
}

fn bench_honeypot_path_traversal(c: &mut Criterion) {
    c.bench_function("honeypot_path_traversal", |b| {
        b.iter(|| {
            let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
            let err = AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "serve_file",
                "../../etc/passwd",
                io_err
            )
            .with_metadata("source_ip", "192.168.1.101")
            .with_metadata("request_path", "../../etc/passwd")
            .with_metadata("method", "GET");
            
            let log = err.internal_log();
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            
            black_box(buffer)
        })
    });
}

fn bench_honeypot_rate_limit(c: &mut Criterion) {
    c.bench_function("honeypot_rate_limit", |b| {
        b.iter(|| {
            let err = AgentError::response(
                definitions::RSP_RATE_LIMITED,
                "handle_request",
                "Rate limit exceeded"
            )
            .with_retry()
            .with_metadata("source_ip", "192.168.1.103")
            .with_metadata("request_count", "150")
            .with_metadata("window", "60s");
            
            let response = format!("{}", err);
            black_box(response)
        })
    });
}

// ============================================================================
// ATTACK BURST SIMULATION
// ============================================================================

fn bench_attack_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("attack_burst");
    
    // Simulate burst of errors during coordinated attack
    for burst_size in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(burst_size),
            &burst_size,
            |b, &size| {
                // Pre-allocate attempt strings
                let attempts: Vec<String> = (0..size)
                    .map(|i| format!("attempt_{}", i))
                    .collect();
                let attempt_nums: Vec<String> = (0..size)
                    .map(|i| i.to_string())
                    .collect();
                
                b.iter(|| {
                    let mut logs = Vec::with_capacity(size);
                    
                    for i in 0..size {
                        let err = AgentError::config_sensitive(
                            definitions::CFG_VALIDATION_FAILED,
                            "authenticate",
                            "Failed",
                            attempts[i].clone()
                        )
                        .with_metadata("attempt", attempt_nums[i].clone());
                        
                        let log = err.internal_log();
                        let mut buffer = String::new();
                        log.write_to(&mut buffer).unwrap();
                        logs.push(buffer);
                    }
                    
                    black_box(logs)
                })
            }
        );
    }
    
    group.finish();
}

// ============================================================================
// MEMORY ALLOCATION PROFILING
// ============================================================================

fn bench_zero_allocation_path(c: &mut Criterion) {
    c.bench_function("zero_allocation_static_strings", |b| {
        b.iter(|| {
            // This path should not allocate - using static strings only
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "static_operation",  // &'static str
                "static details"     // &'static str
            );
            
            // Extract owned data to benchmark properly
            let log = err.internal_log();
            let operation = log.operation().to_string();
            let details = log.details().to_string();
            black_box((operation, details))
        })
    });
}

fn bench_allocation_heavy_path(c: &mut Criterion) {
    c.bench_function("allocation_heavy_dynamic_strings", |b| {
        b.iter(|| {
            // This allocates - dynamic strings
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                format!("operation_{}", 42),
                format!("details_{}", 123)
            );
            
            // Extract owned data
            let log = err.internal_log();
            let operation = log.operation().to_string();
            let details = log.details().to_string();
            black_box((operation, details))
        })
    });
}

// ============================================================================
// BENCHMARK GROUPS
// ============================================================================

criterion_group!(
    creation_benches,
    bench_error_creation_simple,
    bench_error_creation_with_string,
    bench_error_creation_sensitive,
    bench_error_creation_io_split,
);

criterion_group!(
    metadata_benches,
    bench_metadata_addition,
);

criterion_group!(
    logging_benches,
    bench_internal_log_access,
    bench_internal_log_write,
    bench_internal_log_with_sensitive,
    bench_callback_logging,
);

criterion_group!(
    display_benches,
    bench_external_display,
    bench_debug_format,
);

criterion_group!(
    honeypot_benches,
    bench_honeypot_auth_failure,
    bench_honeypot_path_traversal,
    bench_honeypot_rate_limit,
    bench_attack_burst,
);

criterion_group!(
    allocation_benches,
    bench_zero_allocation_path,
    bench_allocation_heavy_path,
);

criterion_main!(
    creation_benches,
    metadata_benches,
    logging_benches,
    display_benches,
    honeypot_benches,
    allocation_benches,
);