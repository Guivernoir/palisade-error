// benches/error_performance.rs
//! Comprehensive benchmarks for palisade_errors performance characteristics
//! 
//! Validates all performance claims made in documentation and tests edge cases.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use palisade_errors::{AgentError, definitions};
use std::io;
use std::time::Duration;

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

fn bench_error_creation_all_constructors(c: &mut Criterion) {
    let mut group = c.benchmark_group("error_constructors");
    
    group.bench_function("config", |b| {
        b.iter(|| black_box(AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")))
    });
    
    group.bench_function("deployment", |b| {
        b.iter(|| black_box(AgentError::deployment(definitions::DCP_DEPLOY_FAILED, "op", "details")))
    });
    
    group.bench_function("telemetry", |b| {
        b.iter(|| black_box(AgentError::telemetry(definitions::TEL_INIT_FAILED, "op", "details")))
    });
    
    group.bench_function("correlation", |b| {
        b.iter(|| black_box(AgentError::correlation(definitions::COR_RULE_EVAL_FAILED, "op", "details")))
    });
    
    group.bench_function("response", |b| {
        b.iter(|| black_box(AgentError::response(definitions::RSP_EXEC_FAILED, "op", "details")))
    });
    
    group.bench_function("logging", |b| {
        b.iter(|| black_box(AgentError::logging(definitions::LOG_WRITE_FAILED, "op", "details")))
    });
    
    group.bench_function("platform", |b| {
        b.iter(|| black_box(AgentError::platform(definitions::PLT_UNSUPPORTED, "op", "details")))
    });
    
    group.bench_function("io_operation", |b| {
        b.iter(|| black_box(AgentError::io_operation(definitions::IO_READ_FAILED, "op", "details")))
    });
    
    group.finish();
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
                    err = err.with_metadata("key", values[i].clone());
                }
                
                black_box(err)
            })
        });
    }
    
    group.finish();
}

fn bench_metadata_access_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_access");
    
    for count in [0, 1, 4, 8] {
        let mut err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
        for i in 0..count {
            err = err.with_metadata("key", format!("value_{}", i));
        }
        
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, _| {
                b.iter(|| {
                    let log = err.internal_log();
                    let metadata = log.metadata();
                    black_box(metadata.len())
                })
            }
        );
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
            err.with_internal_log(|log| {
                let code = log.code();
                let operation = log.operation().to_string();
                black_box((code, operation))
            })
        })
    });
}

fn bench_log_truncation(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_truncation");
    
    for size in [100, 1024, 5000, 10000] {
        let huge_details = "A".repeat(size);
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "operation",
            huge_details
        );
        
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    let log = err.internal_log();
                    let mut buffer = String::new();
                    log.write_to(&mut buffer).unwrap();
                    black_box(buffer)
                })
            }
        );
    }
    
    group.finish();
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

fn bench_error_code_display(c: &mut Criterion) {
    c.bench_function("error_code_to_string", |b| {
        b.iter(|| {
            black_box(definitions::CFG_PARSE_FAILED.to_string())
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
            
            let log = err.internal_log();
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            
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
    
    for burst_size in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(burst_size),
            &burst_size,
            |b, &size| {
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
// TIMING NORMALIZATION BENCHMARKS
// ============================================================================

fn bench_timing_normalization_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_normalization");
    
    // Fast error (should add delay)
    group.bench_function("fast_error_with_norm", |b| {
        b.iter(|| {
            let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
            black_box(err.with_timing_normalization(Duration::from_millis(10)))
        })
    });
    
    // Already slow error (should skip delay)
    group.bench_function("slow_error_with_norm", |b| {
        b.iter(|| {
            let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
            std::thread::sleep(Duration::from_millis(15));
            black_box(err.with_timing_normalization(Duration::from_millis(10)))
        })
    });
    
    group.finish();
}

fn bench_timing_normalization_precision(c: &mut Criterion) {
    c.bench_function("timing_norm_measurement_overhead", |b| {
        b.iter(|| {
            let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
            let age = err.age();
            black_box(age)
        })
    });
}

// ============================================================================
// OBFUSCATION BENCHMARKS
// ============================================================================

#[cfg(feature = "obfuscate-codes")]
fn bench_obfuscation_overhead(c: &mut Criterion) {
    use palisade_errors::obfuscation;
    
    let mut group = c.benchmark_group("obfuscation");
    
    // Salt initialization
    group.bench_function("init_session_salt", |b| {
        b.iter(|| {
            black_box(obfuscation::init_session_salt(12345))
        })
    });
    
    // Code obfuscation
    obfuscation::init_session_salt(5);
    group.bench_function("obfuscate_code", |b| {
        b.iter(|| {
            black_box(obfuscation::obfuscate_code(definitions::CFG_PARSE_FAILED))
        })
    });
    
    // Random salt generation
    group.bench_function("generate_random_salt", |b| {
        b.iter(|| {
            black_box(obfuscation::generate_random_salt())
        })
    });
    
    // Full error creation with obfuscation
    group.bench_function("error_with_obfuscation", |b| {
        b.iter(|| {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_obfuscation()
            )
        })
    });
    
    group.finish();
}

#[cfg(not(feature = "obfuscate-codes"))]
fn bench_obfuscation_overhead(_c: &mut Criterion) {
    // No-op when feature is disabled
}

// ============================================================================
// RING BUFFER BENCHMARKS
// ============================================================================

fn bench_ring_buffer_single_threaded(c: &mut Criterion) {
    use palisade_errors::ring_buffer::RingBufferLogger;
    
    let mut group = c.benchmark_group("ring_buffer_single");
    
    for capacity in [100, 1000, 10000] {
        let logger = RingBufferLogger::new(capacity, 2048);
        
        group.bench_with_input(
            BenchmarkId::from_parameter(capacity),
            &capacity,
            |b, _| {
                b.iter(|| {
                    let err = AgentError::config(
                        definitions::CFG_PARSE_FAILED,
                        "operation",
                        "test error details"
                    );
                    logger.log(&err, "192.168.1.100");
                })
            }
        );
    }
    
    group.finish();
}

fn bench_ring_buffer_concurrent(c: &mut Criterion) {
    use palisade_errors::ring_buffer::RingBufferLogger;
    
    let mut group = c.benchmark_group("ring_buffer_concurrent");
    
    for thread_count in [2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(thread_count),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    let logger = RingBufferLogger::new(1000, 2048);
                    let handles: Vec<_> = (0..threads).map(|i| {
                        let logger = logger.clone();
                        std::thread::spawn(move || {
                            for j in 0..250 {
                                let err = AgentError::config(
                                    definitions::CFG_PARSE_FAILED,
                                    "op",
                                    format!("thread {} error {}", i, j)
                                );
                                logger.log(&err, &format!("192.168.1.{}", i));
                            }
                        })
                    }).collect();
                    
                    for handle in handles {
                        handle.join().unwrap();
                    }
                    
                    black_box(logger)
                })
            }
        );
    }
    
    group.finish();
}

fn bench_ring_buffer_eviction(c: &mut Criterion) {
    use palisade_errors::ring_buffer::RingBufferLogger;
    
    c.bench_function("ring_buffer_with_eviction", |b| {
        let logger = RingBufferLogger::new(100, 2048);
        
        b.iter(|| {
            // Log 200 errors, causing 100 evictions
            for i in 0..200 {
                let err = AgentError::config(
                    definitions::CFG_PARSE_FAILED,
                    "op",
                    format!("error {}", i)
                );
                logger.log(&err, "192.168.1.1");
            }
            black_box(&logger)
        });
    });
}

fn bench_ring_buffer_queries(c: &mut Criterion) {
    use palisade_errors::ring_buffer::RingBufferLogger;
    
    let mut group = c.benchmark_group("ring_buffer_queries");
    
    let logger = RingBufferLogger::new(1000, 2048);
    
    // Populate buffer
    for i in 0..500 {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "op",
            format!("error {}", i)
        )
        .with_metadata("type", if i % 2 == 0 { "typeA" } else { "typeB" });
        logger.log(&err, &format!("192.168.1.{}", i % 256));
    }
    
    group.bench_function("get_recent_10", |b| {
        b.iter(|| {
            black_box(logger.get_recent(10))
        })
    });
    
    group.bench_function("get_all", |b| {
        b.iter(|| {
            black_box(logger.get_all())
        })
    });
    
    group.bench_function("get_filtered", |b| {
        b.iter(|| {
            black_box(logger.get_filtered(|e| e.source_ip.starts_with("192.168.1.1")))
        })
    });
    
    group.finish();
}

// ============================================================================
// MEMORY ALLOCATION PROFILING
// ============================================================================

fn bench_zero_allocation_path(c: &mut Criterion) {
    c.bench_function("zero_allocation_static_strings", |b| {
        b.iter(|| {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "static_operation",
                "static details"
            );
            
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
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                format!("operation_{}", 42),
                format!("details_{}", 123)
            );
            
            let log = err.internal_log();
            let operation = log.operation().to_string();
            let details = log.details().to_string();
            black_box((operation, details))
        })
    });
}

// ============================================================================
// EDGE CASES AND STRESS TESTS
// ============================================================================

fn bench_unicode_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("unicode");
    
    group.bench_function("ascii", |b| {
        b.iter(|| {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "simple ascii details"
            ))
        })
    });
    
    group.bench_function("emoji", |b| {
        b.iter(|| {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "Error with emoji 🔥💥🚨"
            ))
        })
    });
    
    group.bench_function("mixed_scripts", |b| {
        b.iter(|| {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "Mixed: English, Русский, 中文, العربية"
            ))
        })
    });
    
    group.finish();
}

fn bench_method_chaining(c: &mut Criterion) {
    let mut group = c.benchmark_group("method_chaining");
    
    group.bench_function("no_chaining", |b| {
        b.iter(|| {
            black_box(AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details"))
        })
    });
    
    group.bench_function("with_retry", |b| {
        b.iter(|| {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_retry()
            )
        })
    });
    
    group.bench_function("with_metadata_x5", |b| {
        b.iter(|| {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_metadata("k1", "v1")
                    .with_metadata("k2", "v2")
                    .with_metadata("k3", "v3")
                    .with_metadata("k4", "v4")
                    .with_metadata("k5", "v5")
            )
        })
    });
    
    group.bench_function("full_chain", |b| {
        b.iter(|| {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_retry()
                    .with_metadata("k1", "v1")
                    .with_metadata("k2", "v2")
                    .with_metadata("k3", "v3")
            )
        })
    });
    
    group.finish();
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
    bench_error_creation_all_constructors,
);

criterion_group!(
    metadata_benches,
    bench_metadata_addition,
    bench_metadata_access_cost,
);

criterion_group!(
    logging_benches,
    bench_internal_log_access,
    bench_internal_log_write,
    bench_internal_log_with_sensitive,
    bench_callback_logging,
    bench_log_truncation,
);

criterion_group!(
    display_benches,
    bench_external_display,
    bench_debug_format,
    bench_error_code_display,
);

criterion_group!(
    honeypot_benches,
    bench_honeypot_auth_failure,
    bench_honeypot_path_traversal,
    bench_honeypot_rate_limit,
    bench_attack_burst,
);

criterion_group!(
    timing_benches,
    bench_timing_normalization_overhead,
    bench_timing_normalization_precision,
);

criterion_group!(
    obfuscation_benches,
    bench_obfuscation_overhead,
);

criterion_group!(
    ring_buffer_benches,
    bench_ring_buffer_single_threaded,
    bench_ring_buffer_concurrent,
    bench_ring_buffer_eviction,
    bench_ring_buffer_queries,
);

criterion_group!(
    allocation_benches,
    bench_zero_allocation_path,
    bench_allocation_heavy_path,
);

criterion_group!(
    edge_case_benches,
    bench_unicode_handling,
    bench_method_chaining,
);

criterion_main!(
    creation_benches,
    metadata_benches,
    logging_benches,
    display_benches,
    honeypot_benches,
    timing_benches,
    obfuscation_benches,
    ring_buffer_benches,
    allocation_benches,
    edge_case_benches,
);