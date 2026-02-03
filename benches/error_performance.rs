// benches/error_performance.rs
//! Comprehensive benchmarks for palisade_errors performance characteristics
//! 
//! Validates all performance claims made in documentation and tests edge cases.
//! Now with PRECISE per-allocation tracking.
//!
//! Results are automatically saved to: benchmark_memory_results.txt

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Bencher, Criterion, measurement::WallTime};
use palisade_errors::{AgentError, definitions};
use std::io;
use std::time::Duration;

// ============================================================================
// Precise Allocation Tracking with stats_alloc
// ============================================================================

use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;
use std::fs::OpenOptions;
use std::io::Write;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Memory statistics for a single benchmark iteration
#[derive(Debug, Clone, Copy)]
struct MemStats {
    /// Total bytes allocated during operation
    allocated: usize,
    /// Total bytes deallocated during operation
    deallocated: usize,
    /// Net memory change (allocated - deallocated)
    net: isize,
    /// Number of allocation calls
    alloc_count: usize,
    /// Number of deallocation calls
    dealloc_count: usize,
}

/// Combined benchmark results (memory + timing)
#[derive(Debug, Clone)]
struct BenchResults {
    mem: MemStats,
    /// Median time in nanoseconds
    time_ns: Option<f64>,
}

impl MemStats {
    fn zero() -> Self {
        Self {
            allocated: 0,
            deallocated: 0,
            net: 0,
            alloc_count: 0,
            dealloc_count: 0,
        }
    }

    fn from_region(start: &stats_alloc::Stats, end: &stats_alloc::Stats) -> Self {
        let allocated = end.bytes_allocated.saturating_sub(start.bytes_allocated);
        let deallocated = end.bytes_deallocated.saturating_sub(start.bytes_deallocated);
        let alloc_count = end.allocations.saturating_sub(start.allocations);
        let dealloc_count = end.deallocations.saturating_sub(start.deallocations);
        
        Self {
            allocated,
            deallocated,
            net: allocated as isize - deallocated as isize,
            alloc_count,
            dealloc_count,
        }
    }

    fn median(stats: &[MemStats]) -> Self {
        if stats.is_empty() {
            return Self::zero();
        }

        let mut allocated: Vec<usize> = stats.iter().map(|s| s.allocated).collect();
        let mut deallocated: Vec<usize> = stats.iter().map(|s| s.deallocated).collect();
        let mut net: Vec<isize> = stats.iter().map(|s| s.net).collect();
        let mut alloc_count: Vec<usize> = stats.iter().map(|s| s.alloc_count).collect();
        let mut dealloc_count: Vec<usize> = stats.iter().map(|s| s.dealloc_count).collect();

        allocated.sort_unstable();
        deallocated.sort_unstable();
        net.sort_unstable();
        alloc_count.sort_unstable();
        dealloc_count.sort_unstable();

        let mid = stats.len() / 2;

        Self {
            allocated: allocated[mid],
            deallocated: deallocated[mid],
            net: net[mid],
            alloc_count: alloc_count[mid],
            dealloc_count: dealloc_count[mid],
        }
    }

    fn print(&self, label: &str) {
        let output = format!(
            "\n┌─ Memory: {} ─────────────────────────────────\n\
             │ Allocated:     {:>8} bytes  ({} allocs)\n\
             │ Deallocated:   {:>8} bytes  ({} deallocs)\n\
             │ Net Change:    {:>8} bytes\n\
             │ Avg per alloc: {:>8} bytes\n\
             └────────────────────────────────────────────────────────",
            label,
            self.allocated, 
            self.alloc_count,
            self.deallocated, 
            self.dealloc_count,
            self.net.abs(),
            if self.alloc_count > 0 { self.allocated / self.alloc_count } else { 0 }
        );
        
        println!("{}", output);
    }

    fn print_with_timing(&self, label: &str, time_ns: f64) {
        let output = format!(
            "\n┌─ Results: {} ─────────────────────────────────\n\
             │ Time:          {:>8.2} ns\n\
             │ Allocated:     {:>8} bytes  ({} allocs)\n\
             │ Deallocated:   {:>8} bytes  ({} deallocs)\n\
             │ Net Change:    {:>8} bytes\n\
             │ Avg per alloc: {:>8} bytes\n\
             └────────────────────────────────────────────────────────",
            label,
            time_ns,
            self.allocated, 
            self.alloc_count,
            self.deallocated, 
            self.dealloc_count,
            self.net.abs(),
            if self.alloc_count > 0 { self.allocated / self.alloc_count } else { 0 }
        );
        
        println!("{}", output);
        
        // Write to file with timing data
        Self::append_to_file(label, self, Some(time_ns));
    }

    fn append_to_file(label: &str, stats: &MemStats, time_ns: Option<f64>) {
        let filename = "benchmark_memory_results.txt";
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)
            .expect("Failed to open benchmark results file");
        
        // Write header with timestamp if file is empty/new
        let is_new_file = file.metadata()
            .map(|m| m.len() == 0)
            .unwrap_or(true);
            
        if is_new_file {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            writeln!(file, "════════════════════════════════════════════════════════════════════════════════════════════════").ok();
            writeln!(file, "Benchmark Results (Memory + Timing) - Unix timestamp: {}", now).ok();
            writeln!(file, "════════════════════════════════════════════════════════════════════════════════════════════════\n").ok();
        }
        
        // Format timing data
        let timing_str = if let Some(ns) = time_ns {
            if ns < 1_000.0 {
                format!("{:>8.2} ns", ns)
            } else if ns < 1_000_000.0 {
                format!("{:>8.2} µs", ns / 1_000.0)
            } else if ns < 1_000_000_000.0 {
                format!("{:>8.2} ms", ns / 1_000_000.0)
            } else {
                format!("{:>8.2} s", ns / 1_000_000_000.0)
            }
        } else {
            "  N/A      ".to_string()
        };
        
        writeln!(file, 
            "{:<50} │ Time: {} │ Alloc: {:>8} B ({:>3} calls) │ Dealloc: {:>8} B ({:>3} calls) │ Net: {:>8} B",
            label,
            timing_str,
            stats.allocated,
            stats.alloc_count,
            stats.deallocated,
            stats.dealloc_count,
            stats.net.abs()
        ).ok();
    }
}

// Thread-local storage for memory stats collection
thread_local! {
    static MEM_STATS: std::cell::RefCell<Vec<MemStats>> = std::cell::RefCell::new(Vec::new());
    static TIMING_STATS: std::cell::RefCell<Vec<f64>> = std::cell::RefCell::new(Vec::new());
}

/// Benchmark helper that measures BOTH time (via criterion) AND memory (via stats_alloc)
fn bench_with_mem<F>(b: &mut Bencher<'_>, label: &str, mut f: F)
where
    F: FnMut(),
{
    // Clear previous stats
    MEM_STATS.with(|stats| stats.borrow_mut().clear());
    TIMING_STATS.with(|stats| stats.borrow_mut().clear());

    b.iter(|| {
        let region = Region::new(&GLOBAL);
        let start = region.change();
        let time_start = std::time::Instant::now();
        
        f();
        
        let elapsed = time_start.elapsed();
        let end = region.change();
        let mem_stat = MemStats::from_region(&start, &end);
        
        MEM_STATS.with(|stats| stats.borrow_mut().push(mem_stat));
        TIMING_STATS.with(|stats| stats.borrow_mut().push(elapsed.as_nanos() as f64));
        
        black_box(mem_stat);
    });

    // Calculate and print MEDIAN memory + timing stats after benchmark completes
    MEM_STATS.with(|mem_stats| {
        TIMING_STATS.with(|time_stats| {
            let mem_stats = mem_stats.borrow();
            let mut time_stats = time_stats.borrow_mut();
            
            if !mem_stats.is_empty() && !time_stats.is_empty() {
                let median_mem = MemStats::median(&mem_stats);
                
                // Calculate median time
                time_stats.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let median_time = time_stats[time_stats.len() / 2];
                
                median_mem.print_with_timing(label, median_time);
            }
        });
    });
}

// ============================================================================
// ERROR CREATION BENCHMARKS
// ============================================================================

fn bench_error_creation_simple(c: &mut Criterion) {
    c.bench_function("create_simple_error", |b| {
        bench_with_mem(b, "Simple Error Creation", || {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "details"
            ));
        })
    });
}

fn bench_error_creation_with_string(c: &mut Criterion) {
    c.bench_function("create_error_dynamic_string", |b| {
        bench_with_mem(b, "Dynamic String Error", || {
            let dynamic_detail = format!("Error at line {}", 42);
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                dynamic_detail
            ));
        })
    });
}

fn bench_error_creation_sensitive(c: &mut Criterion) {
    c.bench_function("create_error_with_sensitive", |b| {
        bench_with_mem(b, "Error with Sensitive Data", || {
            black_box(AgentError::config_sensitive(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "details",
                "/etc/passwd"
            ));
        })
    });
}

fn bench_error_creation_io_split(c: &mut Criterion) {
    c.bench_function("create_error_io_split_source", |b| {
        bench_with_mem(b, "I/O Error with Split Source", || {
            let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
            black_box(AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "read_file",
                "/secret/path",
                io_err
            ));
        })
    });
}

fn bench_error_creation_all_constructors(c: &mut Criterion) {
    let mut group = c.benchmark_group("error_constructors");
    
    group.bench_function("config", |b| {
        bench_with_mem(b, "Config Constructor", || { 
            black_box(AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")); 
        })
    });
    
    group.bench_function("deployment", |b| {
        bench_with_mem(b, "Deployment Constructor", || { 
            black_box(AgentError::deployment(definitions::DCP_DEPLOY_FAILED, "op", "details")); 
        })
    });
    
    group.bench_function("telemetry", |b| {
        bench_with_mem(b, "Telemetry Constructor", || { 
            black_box(AgentError::telemetry(definitions::TEL_INIT_FAILED, "op", "details")); 
        })
    });
    
    group.bench_function("correlation", |b| {
        bench_with_mem(b, "Correlation Constructor", || { 
            black_box(AgentError::correlation(definitions::COR_RULE_EVAL_FAILED, "op", "details")); 
        })
    });
    
    group.bench_function("response", |b| {
        bench_with_mem(b, "Response Constructor", || { 
            black_box(AgentError::response(definitions::RSP_EXEC_FAILED, "op", "details")); 
        })
    });
    
    group.bench_function("logging", |b| {
        bench_with_mem(b, "Logging Constructor", || { 
            black_box(AgentError::logging(definitions::LOG_WRITE_FAILED, "op", "details")); 
        })
    });
    
    group.bench_function("platform", |b| {
        bench_with_mem(b, "Platform Constructor", || { 
            black_box(AgentError::platform(definitions::PLT_UNSUPPORTED, "op", "details")); 
        })
    });
    
    group.bench_function("io_operation", |b| {
        bench_with_mem(b, "I/O Operation Constructor", || { 
            black_box(AgentError::io_operation(definitions::IO_READ_FAILED, "op", "details")); 
        })
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
            bench_with_mem(b, &format!("Add {} Metadata Fields", count), || {
                let mut err = AgentError::config(
                    definitions::CFG_PARSE_FAILED,
                    "operation",
                    "details"
                );
                
                for i in 0..count {
                    err = err.with_metadata("key", values[i].clone());
                }
                
                black_box(err);
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
                bench_with_mem(b, &format!("Access {} Metadata Fields", count), || {
                    let log = err.internal_log();
                    let metadata = log.metadata();
                    black_box(metadata.len());
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
        bench_with_mem(b, "Internal Log Access", || {
            let log = err.internal_log();
            let code = log.code().to_string();
            let operation = log.operation().to_string();
            let details = log.details().to_string();
            black_box((code, operation, details));
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
        bench_with_mem(b, "Internal Log Write", || {
            let log = err.internal_log();
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            black_box(buffer);
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
        bench_with_mem(b, "Log with Sensitive Data", || {
            let log = err.internal_log();
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            black_box(buffer);
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
        bench_with_mem(b, "Callback Logging", || {
            err.with_internal_log(|log| {
                let code = log.code().to_string();
                let operation = log.operation().to_string();
                black_box((code, operation));
            }); // Note: The lambda passed to with_internal_log returns the value, but we need the outer closure to return ()
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
                bench_with_mem(b, &format!("Truncate {} chars", size), || {
                    let log = err.internal_log();
                    let mut buffer = String::new();
                    log.write_to(&mut buffer).unwrap();
                    black_box(buffer);
                })
            }
        );
    }
    
    group.finish();
}

// ============================================================================
// MEMORY TRACKING BENCHMARKS
// ============================================================================

fn bench_memory_error_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_tracking");
    group.bench_function("mem_error_creation_batch", |b| {
        bench_with_mem(b, "Batch Create 1000 Errors", || {
            for _ in 0..1000 {
                let _err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
            }
        })
    });
    group.finish();
}

fn bench_memory_internal_log_batch(c: &mut Criterion) {
    let err = AgentError::config(definitions::CFG_PARSE_FAILED, "operation", "details")
        .with_metadata("k1", "v1")
        .with_metadata("k2", "v2");
    let mut group = c.benchmark_group("memory_tracking");
    group.bench_function("mem_internal_log_batch", |b| {
        bench_with_mem(b, "Batch Log 1000 Errors", || {
            for _ in 0..1000 {
                err.with_internal_log(|log| {
                    let mut buffer = String::new();
                    log.write_to(&mut buffer).unwrap();
                    black_box(buffer);
                });
            }
        })
    });
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
        bench_with_mem(b, "External Display Format", || {
            black_box(format!("{}", err));
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
        bench_with_mem(b, "Debug Format", || {
            black_box(format!("{:?}", err));
        })
    });
}

fn bench_error_code_display(c: &mut Criterion) {
    c.bench_function("error_code_to_string", |b| {
        bench_with_mem(b, "Error Code To String", || {
            black_box(definitions::CFG_PARSE_FAILED.to_string());
        })
    });
}

// ============================================================================
// REALISTIC HONEYPOT SCENARIOS
// ============================================================================

fn bench_honeypot_auth_failure(c: &mut Criterion) {
    c.bench_function("honeypot_auth_failure", |b| {
        bench_with_mem(b, "Honeypot Auth Failure", || {
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
            
            black_box((buffer, response));
        })
    });
}

fn bench_honeypot_path_traversal(c: &mut Criterion) {
    c.bench_function("honeypot_path_traversal", |b| {
        bench_with_mem(b, "Honeypot Path Traversal", || {
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
            
            black_box(buffer);
        })
    });
}

fn bench_honeypot_rate_limit(c: &mut Criterion) {
    c.bench_function("honeypot_rate_limit", |b| {
        bench_with_mem(b, "Honeypot Rate Limit", || {
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
            black_box(response);
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
                
                bench_with_mem(b, &format!("Attack Burst {}", size), || {
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
                    
                    black_box(logs);
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
        bench_with_mem(b, "Fast Error With Norm", || {
            let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
            black_box(err.with_timing_normalization(Duration::from_millis(10)));
        })
    });
    
    // Already slow error (should skip delay)
    group.bench_function("slow_error_with_norm", |b| {
        bench_with_mem(b, "Slow Error With Norm", || {
            let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
            std::thread::sleep(Duration::from_millis(15));
            black_box(err.with_timing_normalization(Duration::from_millis(10)));
        })
    });
    
    group.finish();
}

fn bench_timing_normalization_precision(c: &mut Criterion) {
    c.bench_function("timing_norm_measurement_overhead", |b| {
        bench_with_mem(b, "Timing Norm Measurement Overhead", || {
            let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
            let age = err.age();
            black_box(age);
        })
    });
}

// ============================================================================
// OBFUSCATION BENCHMARKS
// ============================================================================

fn bench_obfuscation_overhead(c: &mut Criterion) {
    use palisade_errors::obfuscation;
    
    let mut group = c.benchmark_group("obfuscation");
    
    // Salt initialization
    group.bench_function("init_session_salt", |b| {
        bench_with_mem(b, "Init Session Salt", || {
            black_box(obfuscation::init_session_salt(12345));
        })
    });
    
    // Code obfuscation
    obfuscation::init_session_salt(5);
    group.bench_function("obfuscate_code", |b| {
        bench_with_mem(b, "Obfuscate Code", || {
            black_box(obfuscation::obfuscate_code(&definitions::CFG_PARSE_FAILED));
        })
    });
    
    // Random salt generation
    group.bench_function("generate_random_salt", |b| {
        bench_with_mem(b, "Generate Random Salt", || {
            black_box(obfuscation::generate_random_salt());
        })
    });
    
    // Full error creation (obfuscation always applied)
    group.bench_function("error_with_obfuscation", |b| {
        bench_with_mem(b, "Error With Obfuscation", || {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
            );
        })
    });
    
    group.finish();
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
                bench_with_mem(b, &format!("Ring Buffer {} entries", capacity), || {
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
                bench_with_mem(b, &format!("{} threads", threads), || {
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
                    
                    black_box(logger);
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
        
        bench_with_mem(b, "Ring Buffer With Eviction", || {
            // Log 200 errors, causing 100 evictions
            for i in 0..200 {
                let err = AgentError::config(
                    definitions::CFG_PARSE_FAILED,
                    "op",
                    format!("error {}", i)
                );
                logger.log(&err, "192.168.1.1");
            }
            black_box(&logger);
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
        bench_with_mem(b, "Get Recent 10", || {
            black_box(logger.get_recent(10));
        })
    });
    
    group.bench_function("get_all", |b| {
        bench_with_mem(b, "Get All", || {
            black_box(logger.get_all());
        })
    });
    
    group.bench_function("get_filtered", |b| {
        bench_with_mem(b, "Get Filtered", || {
            black_box(logger.get_filtered(|e| e.source_ip.starts_with("192.168.1.1")));
        })
    });
    
    group.finish();
}

// ============================================================================
// MEMORY ALLOCATION PROFILING
// ============================================================================

fn bench_zero_allocation_path(c: &mut Criterion) {
    c.bench_function("zero_allocation_static_strings", |b| {
        bench_with_mem(b, "Zero Allocation Static Strings", || {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "static_operation",
                "static details"
            );
            
            let log = err.internal_log();
            let operation = log.operation().to_string();
            let details = log.details().to_string();
            black_box((operation, details));
        })
    });
}

fn bench_allocation_heavy_path(c: &mut Criterion) {
    c.bench_function("allocation_heavy_dynamic_strings", |b| {
        bench_with_mem(b, "Allocation Heavy Dynamic Strings", || {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                format!("operation_{}", 42),
                format!("details_{}", 123)
            );
            
            let log = err.internal_log();
            let operation = log.operation().to_string();
            let details = log.details().to_string();
            black_box((operation, details));
        })
    });
}

// ============================================================================
// EDGE CASES AND STRESS TESTS
// ============================================================================

fn bench_unicode_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("unicode");
    
    group.bench_function("ascii", |b| {
        bench_with_mem(b, "Ascii", || {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "simple ascii details"
            ));
        })
    });
    
    group.bench_function("emoji", |b| {
        bench_with_mem(b, "Emoji", || {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "Error with emoji 🔥💥🚨"
            ));
        })
    });
    
    group.bench_function("mixed_scripts", |b| {
        bench_with_mem(b, "Mixed Scripts", || {
            black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "Mixed: English, Русский, 中文, العربية"
            ));
        })
    });
    
    group.finish();
}

fn bench_method_chaining(c: &mut Criterion) {
    let mut group = c.benchmark_group("method_chaining");
    
    group.bench_function("no_chaining", |b| {
        bench_with_mem(b, "No Chaining", || {
            black_box(AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details"));
        })
    });
    
    group.bench_function("with_retry", |b| {
        bench_with_mem(b, "With Retry", || {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_retry()
            );
        })
    });
    
    group.bench_function("with_metadata_x5", |b| {
        bench_with_mem(b, "With Metadata X5", || {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_metadata("k1", "v1")
                    .with_metadata("k2", "v2")
                    .with_metadata("k3", "v3")
                    .with_metadata("k4", "v4")
                    .with_metadata("k5", "v5")
            );
        })
    });
    
    group.bench_function("full_chain", |b| {
        bench_with_mem(b, "Full Chain", || {
            black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_retry()
                    .with_metadata("k1", "v1")
                    .with_metadata("k2", "v2")
                    .with_metadata("k3", "v3")
            );
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
    memory_benches,
    bench_memory_error_creation,
    bench_memory_internal_log_batch,
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
    memory_benches,
    edge_case_benches,
);