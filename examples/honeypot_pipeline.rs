// examples/honeypot_pipeline.rs
//! Demonstrates error handling pipeline for Palisade honeypot system
//!
//! Run with: cargo run --example honeypot_pipeline

use palisade_errors::{AgentError, definitions, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// ATTACK CORRELATION ENGINE
// ============================================================================

/// Correlates errors to detect attack patterns
struct AttackCorrelator {
    /// Maps source IP to error patterns
    error_patterns: Arc<Mutex<HashMap<String, Vec<ErrorPattern>>>>,
    /// Tracks attack campaigns by correlation ID
    campaigns: Arc<Mutex<HashMap<String, AttackCampaign>>>,
}

#[derive(Debug, Clone)]
struct ErrorPattern {
    code: String,
    timestamp: u64,
    operation: String,
    category: String,
}

#[derive(Debug)]
struct AttackCampaign {
    source_ip: String,
    start_time: u64,
    error_count: usize,
    error_codes: Vec<String>,
    techniques: Vec<AttackTechnique>,
}

#[derive(Debug)]
enum AttackTechnique {
    PathTraversal,
    SqlInjection,
    CommandInjection,
    CredentialStuffing,
    Reconnaissance,
    DosAttempt,
}

impl AttackCorrelator {
    fn new() -> Self {
        Self {
            error_patterns: Arc::new(Mutex::new(HashMap::new())),
            campaigns: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process an error and update attack correlation
    fn process_error(&self, err: &AgentError, source_ip: &str, correlation_id: &str) {
        let pattern = err.with_internal_log(|log| {
            ErrorPattern {
                code: log.code().to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                operation: log.operation().to_string(),
                category: format!("{:?}", err.category()),
            }
        });

        // Update error patterns for source IP
        {
            let mut patterns = self.error_patterns.lock().unwrap();
            patterns
                .entry(source_ip.to_string())
                .or_insert_with(Vec::new)
                .push(pattern.clone());
        }

        // Update or create attack campaign
        {
            let mut campaigns = self.campaigns.lock().unwrap();
            let campaign = campaigns
                .entry(correlation_id.to_string())
                .or_insert_with(|| AttackCampaign {
                    source_ip: source_ip.to_string(),
                    start_time: pattern.timestamp,
                    error_count: 0,
                    error_codes: Vec::new(),
                    techniques: Vec::new(),
                });

            campaign.error_count += 1;
            campaign.error_codes.push(pattern.code.clone());

            // Detect attack techniques based on error patterns
            if pattern.code.contains("IO") {
                if !campaign.techniques.iter().any(|t| matches!(t, AttackTechnique::PathTraversal)) {
                    campaign.techniques.push(AttackTechnique::PathTraversal);
                }
            }
            if pattern.operation.contains("auth") {
                if !campaign.techniques.iter().any(|t| matches!(t, AttackTechnique::CredentialStuffing)) {
                    campaign.techniques.push(AttackTechnique::CredentialStuffing);
                }
            }
        }

        // Check if this looks like a coordinated attack
        self.detect_attack_campaign(source_ip);
    }

    /// Detect if error patterns indicate active attack campaign
    fn detect_attack_campaign(&self, source_ip: &str) {
        let patterns = self.error_patterns.lock().unwrap();
        if let Some(errors) = patterns.get(source_ip) {
            let recent_errors = errors.iter()
                .filter(|e| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    now - e.timestamp < 60 // Last 60 seconds
                })
                .count();

            if recent_errors > 10 {
                println!("⚠️  ALERT: Potential attack campaign from {}", source_ip);
                println!("   {} errors in last 60 seconds", recent_errors);
            }
        }
    }

    /// Generate attack intelligence report
    fn generate_report(&self) -> String {
        let campaigns = self.campaigns.lock().unwrap();
        let mut report = String::from("=== PALISADE ATTACK INTELLIGENCE REPORT ===\n\n");

        for (campaign_id, campaign) in campaigns.iter() {
            report.push_str(&format!(
                "Campaign: {}\n\
                 Source: {}\n\
                 Duration: {} seconds\n\
                 Error Count: {}\n\
                 Techniques: {:?}\n\
                 Error Codes: {}\n\n",
                campaign_id,
                campaign.source_ip,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() - campaign.start_time,
                campaign.error_count,
                campaign.techniques,
                campaign.error_codes.join(", ")
            ));
        }

        report
    }
}

// ============================================================================
// FORENSIC LOGGER
// ============================================================================

/// Multi-tier logging for honeypot forensics
struct ForensicLogger {
    /// High-volume operational log (sanitized, high-speed)
    operational_log: Arc<Mutex<Vec<String>>>,
    /// Detailed forensic log (full context, encrypted)
    forensic_log: Arc<Mutex<Vec<String>>>,
    /// Restricted access log (sensitive data only)
    sensitive_log: Arc<Mutex<Vec<String>>>,
}

impl ForensicLogger {
    fn new() -> Self {
        Self {
            operational_log: Arc::new(Mutex::new(Vec::new())),
            forensic_log: Arc::new(Mutex::new(Vec::new())),
            sensitive_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Log error with appropriate tier separation
    fn log(&self, err: &AgentError, context: &LogContext) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Tier 1: Operational log (external-safe message + metadata)
        {
            let mut ops = self.operational_log.lock().unwrap();
            ops.push(format!(
                "[{}] {} source_ip={} correlation_id={} retryable={}",
                timestamp,
                err, // Uses Display - sanitized
                context.source_ip,
                context.correlation_id,
                err.is_retryable()
            ));
        }

        // Tier 2: Forensic log (full internal context)
        err.with_internal_log(|log| {
            let mut forensic = self.forensic_log.lock().unwrap();
            let mut entry = format!(
                "[{}] [{}] operation='{}' details='{}' source_ip={} user_agent='{}'",
                timestamp,
                log.code(),
                log.operation(),
                log.details(),
                context.source_ip,
                context.user_agent
            );

            // Include internal source if present
            if let Some(internal) = log.source_internal() {
                entry.push_str(&format!(" source_internal='{}'", internal));
            }

            // Add all metadata
            for (key, value) in log.metadata() {
                entry.push_str(&format!(" {}='{}'", key, value.as_str()));
            }

            forensic.push(entry);
        });

        // Tier 3: Sensitive log (paths, credentials, PII)
        err.with_internal_log(|log| {
            if let Some(sensitive) = log.source_sensitive() {
                let mut sensitive_log = self.sensitive_log.lock().unwrap();
                // In production: encrypt this before writing
                sensitive_log.push(format!(
                    "[{}] [{}] correlation_id={} SENSITIVE: {}",
                    timestamp,
                    log.code(),
                    context.correlation_id,
                    sensitive
                ));
            }
        });
    }

    /// Dump logs for analysis
    fn dump_logs(&self) {
        println!("\n=== OPERATIONAL LOG (Public-Safe) ===");
        let ops = self.operational_log.lock().unwrap();
        for entry in ops.iter() {
            println!("{}", entry);
        }

        println!("\n=== FORENSIC LOG (Authenticated Access) ===");
        let forensic = self.forensic_log.lock().unwrap();
        for entry in forensic.iter() {
            println!("{}", entry);
        }

        println!("\n=== SENSITIVE LOG (Restricted Access) ===");
        let sensitive = self.sensitive_log.lock().unwrap();
        for entry in sensitive.iter() {
            println!("{}", entry);
        }
    }
}

// ============================================================================
// CONTEXT AND PIPELINE
// ============================================================================

#[derive(Clone)]
struct LogContext {
    source_ip: String,
    correlation_id: String,
    user_agent: String,
}

/// Main error processing pipeline for honeypot
struct ErrorPipeline {
    logger: Arc<ForensicLogger>,
    correlator: Arc<AttackCorrelator>,
}

impl ErrorPipeline {
    fn new() -> Self {
        Self {
            logger: Arc::new(ForensicLogger::new()),
            correlator: Arc::new(AttackCorrelator::new()),
        }
    }

    /// Process an error through the complete pipeline
    fn process(&self, err: AgentError, context: &LogContext) -> AgentError {
        // Log to forensic system
        self.logger.log(&err, context);

        // Update attack correlation
        self.correlator.process_error(&err, &context.source_ip, &context.correlation_id);

        // Return sanitized error for external response
        err
    }

    fn dump_state(&self) {
        self.logger.dump_logs();
        println!("\n{}", self.correlator.generate_report());
    }
}

// ============================================================================
// SIMULATED HONEYPOT OPERATIONS
// ============================================================================

fn simulate_ssh_bruteforce(pipeline: &ErrorPipeline, attacker_ip: &str) {
    println!("\n>>> Simulating SSH bruteforce from {}", attacker_ip);
    
    let passwords = ["admin", "password", "123456", "root", "admin123"];
    
    for (i, password) in passwords.iter().enumerate() {
        let context = LogContext {
            source_ip: attacker_ip.to_string(),
            correlation_id: format!("ssh-{}-{}", attacker_ip, i),
            user_agent: "OpenSSH_8.2p1".to_string(),
        };

        let err = AgentError::config_sensitive(
            definitions::CFG_VALIDATION_FAILED,
            "ssh_authenticate",
            "Authentication failed",
            format!("username=root password={}", password)
        )
        .with_metadata("auth_method", "password")
        .with_metadata("attempt", i.to_string());

        let sanitized = pipeline.process(err, &context);
        
        // What the attacker sees (sanitized)
        println!("  ← Response to attacker: {}", sanitized);
    }
}

fn simulate_path_traversal(pipeline: &ErrorPipeline, attacker_ip: &str) {
    println!("\n>>> Simulating path traversal attack from {}", attacker_ip);
    
    let paths = [
        "../../etc/passwd",
        "../../../etc/shadow",
        "....//....//etc/passwd",
        "/var/www/../../etc/passwd",
    ];

    for (i, path) in paths.iter().enumerate() {
        let context = LogContext {
            source_ip: attacker_ip.to_string(),
            correlation_id: format!("http-{}-{}", attacker_ip, i),
            user_agent: "Mozilla/5.0 (Attack Scanner)".to_string(),
        };

        let err = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "serve_file",
            path.to_string(),
            io::Error::new(io::ErrorKind::PermissionDenied, "denied")
        )
        .with_metadata("request_path", *path)
        .with_metadata("method", "GET");

        let sanitized = pipeline.process(err, &context);
        println!("  ← Response to attacker: {}", sanitized);
    }
}

fn simulate_sql_injection(pipeline: &ErrorPipeline, attacker_ip: &str) {
    println!("\n>>> Simulating SQL injection from {}", attacker_ip);
    
    let payloads = [
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT * FROM users --",
    ];

    for (i, payload) in payloads.iter().enumerate() {
        let context = LogContext {
            source_ip: attacker_ip.to_string(),
            correlation_id: format!("sql-{}-{}", attacker_ip, i),
            user_agent: "sqlmap/1.5".to_string(),
        };

        let err = AgentError::config_sensitive(
            definitions::CFG_VALIDATION_FAILED,
            "validate_input",
            "Invalid input format",
            format!("Detected SQL injection pattern: {}", payload)
        )
        .with_metadata("input_field", "username")
        .with_metadata("detection", "sql_injection");

        let sanitized = pipeline.process(err, &context);
        println!("  ← Response to attacker: {}", sanitized);
    }
}

fn simulate_dos_attempt(pipeline: &ErrorPipeline, attacker_ip: &str) {
    println!("\n>>> Simulating DoS attempt from {}", attacker_ip);
    
    for i in 0..15 {
        let context = LogContext {
            source_ip: attacker_ip.to_string(),
            correlation_id: format!("dos-{}", attacker_ip),
            user_agent: "flood-bot".to_string(),
        };

        let err = AgentError::response(
            definitions::RSP_RATE_LIMITED,
            "handle_request",
            "Rate limit exceeded"
        )
        .with_retry()
        .with_metadata("request_count", i.to_string())
        .with_metadata("window", "60s");

        let sanitized = pipeline.process(err, &context);
        
        if i < 3 || i > 12 {
            println!("  ← Response to attacker: {}", sanitized);
        } else if i == 3 {
            println!("  ... (9 more requests)");
        }
    }
}

// ============================================================================
// MAIN DEMONSTRATION
// ============================================================================

fn main() {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║     PALISADE HONEYPOT - ERROR PIPELINE DEMO           ║");
    println!("╚════════════════════════════════════════════════════════╝");

    let pipeline = ErrorPipeline::new();

    // Simulate various attack scenarios
    simulate_ssh_bruteforce(&pipeline, "192.168.1.100");
    simulate_path_traversal(&pipeline, "192.168.1.101");
    simulate_sql_injection(&pipeline, "192.168.1.102");
    simulate_dos_attempt(&pipeline, "192.168.1.103");

    // Dump complete forensic state
    println!("\n");
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║     FORENSIC ANALYSIS                                  ║");
    println!("╚════════════════════════════════════════════════════════╝");
    pipeline.dump_state();

    println!("\n");
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║     KEY OBSERVATIONS                                   ║");
    println!("╚════════════════════════════════════════════════════════╝");
    println!("✓ Attackers see only: category, permanence, error code");
    println!("✓ Forensic logs contain: operation, details, metadata");
    println!("✓ Sensitive data isolated: credentials, paths, payloads");
    println!("✓ Attack correlation: patterns detected across errors");
    println!("✓ Zero information disclosure: sanitized responses only");
    println!("✓ Complete audit trail: three-tier logging");
}