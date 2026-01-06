//! Logging Integration Example
//!
//! Demonstrates how to integrate Palisade errors with logging systems,
//! showing both external (sanitized) and internal (detailed) logging patterns.
//!
//! Run with: cargo run --example logging_integration

use palisade_errors::{AgentError, definitions, config_err, Result};
use std::fs;
use std::io::Write;

fn main() {
    println!("=== Logging Integration Example ===\n");

    // Example 1: Simple logging
    println!("1. Basic Logging:");
    basic_logging_example();
    println!();

    // Example 2: Structured logging
    println!("2. Structured Logging:");
    structured_logging_example();
    println!();

    // Example 3: External vs Internal logs
    println!("3. External vs Internal Logging:");
    dual_logging_example();
    println!();

    // Example 4: Log aggregation
    println!("4. Log Aggregation Pattern:");
    log_aggregation_example();
}

/// Simple logger that writes to stdout
struct SimpleLogger;

impl SimpleLogger {
    fn log_error_external(&self, err: &AgentError) {
        // This would go to external-facing logs
        println!("   [EXTERNAL] {}", err);
    }

    fn log_error_internal(&self, err: &AgentError) {
        // This would go to internal forensic logs
        err.with_internal_log(|log| {
            let mut buffer = String::new();
            log.write_to(&mut buffer).unwrap();
            println!("   [INTERNAL] {}", buffer);
        });
    }
}

/// Structured logger that outputs JSON-like format
struct StructuredLogger;

impl StructuredLogger {
    fn log_error(&self, err: &AgentError) {
        err.with_internal_log(|log| {
            println!("   {{");
            println!("     \"code\": \"{}\",", log.code());
            println!("     \"category\": \"{}\",", log.code().category().display_name());
            println!("     \"operation\": \"{}\",", log.operation());
            println!("     \"details\": \"{}\",", log.details());
            println!("     \"retryable\": {},", log.is_retryable());
            
            if let Some(source_internal) = log.source_internal() {
                println!("     \"source_internal\": \"{}\",", source_internal);
            }
            
            if let Some(source_sensitive) = log.source_sensitive() {
                // In production, you might hash or redact this
                println!("     \"source_sensitive\": \"<HASH:{}>\",", 
                    simple_hash(source_sensitive));
            }
            
            if !log.metadata().is_empty() {
                println!("     \"metadata\": {{");
                for (i, (key, value)) in log.metadata().iter().enumerate() {
                    let comma = if i < log.metadata().len() - 1 { "," } else { "" };
                    println!("       \"{}\": \"{}\"{}",key, value.as_str(), comma);
                }
                println!("     }}");
            }
            
            println!("   }}");
        });
    }
}

/// Simple hash function for demonstration
fn simple_hash(s: &str) -> String {
    format!("{:x}", s.len() * 31 + s.as_bytes().iter().sum::<u8>() as usize)
}

/// Example 1: Basic logging pattern
fn basic_logging_example() {
    let logger = SimpleLogger;
    
    let err = config_err!(
        definitions::CFG_PARSE_FAILED,
        "parse_yaml",
        "Invalid YAML syntax at line 42"
    );

    logger.log_error_external(&err);
    logger.log_error_internal(&err);
}

/// Example 2: Structured logging for log aggregation systems
fn structured_logging_example() {
    let logger = StructuredLogger;
    
    let err = AgentError::deployment(
        definitions::DCP_DEPLOY_FAILED,
        "deploy_honeypot",
        "Failed to create deception artifact"
    )
    .with_metadata("artifact_id", "hp_web_001")
    .with_metadata("deployment_id", "deploy_20240115_123")
    .with_retry();

    logger.log_error(&err);
}

/// Example 3: Demonstrating dual logging (external + internal)
fn dual_logging_example() {
    fn load_config(path: &str) -> Result<String> {
        fs::read_to_string(path).map_err(|e| {
            AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "load_config",
                path,
                e
            )
        })
    }

    let logger = SimpleLogger;
    
    match load_config("/nonexistent/config.yaml") {
        Ok(_) => println!("   Config loaded"),
        Err(e) => {
            // Log externally (sanitized - safe for untrusted viewers)
            logger.log_error_external(&e);
            
            // Log internally (full context - only in secure log system)
            logger.log_error_internal(&e);
            
            println!("\n   Notice: External log reveals NO path information!");
            println!("           Internal log contains full path for forensics.");
        }
    }
}

/// Example 4: Log aggregation pattern
fn log_aggregation_example() {
    struct LogAggregator {
        errors: Vec<String>,
    }

    impl LogAggregator {
        fn new() -> Self {
            Self { errors: Vec::new() }
        }

        fn add_error(&mut self, err: &AgentError) {
            err.with_internal_log(|log| {
                let mut buffer = String::new();
                log.write_to(&mut buffer).unwrap();
                self.errors.push(buffer);
            });
        }

        fn flush_to_file(&self, path: &str) -> std::io::Result<()> {
            let mut file = fs::File::create(path)?;
            for error in &self.errors {
                writeln!(file, "{}", error)?;
            }
            Ok(())
        }

        fn print_summary(&self) {
            println!("   Collected {} errors", self.errors.len());
            for (i, error) in self.errors.iter().enumerate() {
                println!("   {}. {}", i + 1, error.lines().next().unwrap_or(""));
            }
        }
    }

    let mut aggregator = LogAggregator::new();

    // Simulate multiple operations that produce errors
    let errors = vec![
        config_err!(
            definitions::CFG_PARSE_FAILED,
            "parse_config",
            "Invalid syntax"
        ),
        AgentError::telemetry(
            definitions::TEL_CHANNEL_CLOSED,
            "collect_events",
            "Channel closed"
        ).with_retry(),
        AgentError::response(
            definitions::RSP_RATE_LIMITED,
            "execute_response",
            "Rate limit exceeded"
        ).with_retry(),
    ];

    for err in &errors {
        aggregator.add_error(err);
    }

    aggregator.print_summary();

    // In production, you would:
    // aggregator.flush_to_file("/var/log/agent/errors.log").unwrap();
}

/// Bonus: Rate-limited error logging
struct RateLimitedLogger {
    last_log_time: std::time::Instant,
    min_interval: std::time::Duration,
}

impl RateLimitedLogger {
    fn new(min_interval: std::time::Duration) -> Self {
        Self {
            last_log_time: std::time::Instant::now() - min_interval,
            min_interval,
        }
    }

    fn should_log(&mut self) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_log_time) >= self.min_interval {
            self.last_log_time = now;
            true
        } else {
            false
        }
    }

    fn log_error(&mut self, err: &AgentError) {
        if self.should_log() {
            err.with_internal_log(|log| {
                let mut buffer = String::new();
                log.write_to(&mut buffer).unwrap();
                println!("   [LOGGED] {}", buffer);
            });
        } else {
            println!("   [DROPPED] Error dropped due to rate limiting");
        }
    }
}