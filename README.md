# Palisade Errors

**Security-conscious error handling for high-assurance Rust applications.**

[![Crates.io](https://img.shields.io/crates/v/palisade-errors.svg)](https://crates.io/crates/palisade-errors)
[![Documentation](https://docs.rs/palisade-errors/badge.svg)](https://docs.rs/palisade-errors)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Palisade Errors is designed for systems where **information leakage is a security vulnerability**. Built as the foundational error handling layer for the **Palisade Honeypot System**, it enforces a strict separation between "what happened" (forensics) and "what the user sees" (sanitization), while guaranteeing that sensitive data in memory is zeroized immediately after use.

## 🎯 Design Philosophy

In a honeypot, every error is intelligence:

- **For attackers:** Errors reveal system architecture, validation logic, and attack surface
- **For defenders:** Errors provide forensic trails, attack correlation, and threat intelligence

Palisade Errors ensures attackers see only walls, while defenders see everything.

## 🚀 Key Features

- **Forensic Integrity:** Keep full stack traces, variable values, and internal state for your logs
- **Information Hiding:** External error messages (`Display`) are automatically sanitized to reveal only error codes and categories
- **Memory Safety:** All error context is wrapped in `ZeroizeOnDrop` types. Secrets are wiped from memory as soon as the error is dropped
- **DoS Protection:** Log outputs are strictly truncated to prevent memory exhaustion attacks via massive error messages
- **Zero-Allocation Paths:** Optimized for performance using `Cow<'static, str>` to handle string literals without heap allocation
- **Timing Attack Mitigation:** Optional constant-time error responses

## ⚡ Performance

Benchmarked on Dell Latitude E6410 (Intel Core i5 M560 @ 2.66GHz, circa 2010):

### Core Operations

| Operation                | Time  | Honeypot Capacity |
| ------------------------ | ----- | ----------------- |
| Simple error creation    | 209ns | 4.8M errors/sec   |
| Dynamic string error     | 253ns | 3.9M errors/sec   |
| Sensitive context error  | 224ns | 4.5M errors/sec   |
| I/O error (split source) | 359ns | 2.8M errors/sec   |

### Logging Performance

| Operation                | Time  | Throughput    |
| ------------------------ | ----- | ------------- |
| Internal log access      | 59ns  | 16.9M ops/sec |
| Log write to buffer      | 673ns | 1.5M ops/sec  |
| Callback logging pattern | 30ns  | 33.3M ops/sec |

### Honeypot Scenarios

| Scenario                     | Time   | Capacity |
| ---------------------------- | ------ | -------- |
| Auth failure (full pipeline) | 1.39μs | 719k/sec |
| Path traversal detection     | 1.23μs | 813k/sec |
| Rate limit response          | 540ns  | 1.9M/sec |

### Attack Burst Handling

| Burst Size | Time   | Bursts/sec |
| ---------- | ------ | ---------- |
| 10 errors  | 8.8μs  | 114k/sec   |
| 50 errors  | 45.7μs | 21.9k/sec  |
| 100 errors | 86.6μs | 11.5k/sec  |
| 500 errors | 446μs  | 2.2k/sec   |

### Metadata Performance

| Entries   | Time   | Impact          |
| --------- | ------ | --------------- |
| 1 entry   | 326ns  | Inline storage  |
| 2 entries | 404ns  | Inline storage  |
| 4 entries | 527ns  | Inline storage  |
| 8 entries | 1.17μs | Heap allocation |

**Typical honeypot load:** 1,000-5,000 errors/second during coordinated attacks

**Safety margin:** 140-800x on 15-year-old hardware

**CPU overhead at 5,000 errors/sec:** <0.7% (estimated 5ms CPU time)

On modern hardware (Ryzen 9, M-series), expect 3-5x better performance.

## 📖 Usage

### Basic Example

```rust
use palisade_errors::{AgentError, definitions, Result};

fn check_access(user: &str) -> Result<()> {
    if user == "admin" {
        return Ok(());
    }

    // This creates an error that logs the user input internally
    // but only shows "Configuration operation failed" externally.
    Err(AgentError::config(
        definitions::CFG_PERMISSION_DENIED,
        "check_access",
        format!("User '{}' denied", user)
    ))
}
```

**What the attacker sees:**

```
Configuration operation failed [permanent] (E-CFG-104)
```

**What your logs contain:**

```
[1704652800] [E-CFG-104] operation='check_access'
details="User 'attacker' denied" source_ip=192.168.1.100
```

### Handling Sensitive Data

When handling passwords, keys, file paths, or PII, use the `sensitive` constructors to ensure data is sequestered and zeroized:

```rust
use palisade_errors::{AgentError, definitions};

let err = AgentError::config_sensitive(
    definitions::CFG_INVALID_VALUE,
    "login_flow",          // Operation name
    "Password verification failed", // Generic details
    password_input         // SENSITIVE: Zeroized on drop, never shown in Display
);
```

**Security guarantee:** When `err` is dropped, `password_input` is zeroized in memory. Core dumps cannot recover it.

### Secure Logging

To access the internal details for your secure logs, use the `internal_log()` method. This returns a short-lived structure that prevents data retention:

```rust
// In your logging middleware
if let Err(e) = result {
    // Write full details to secure log file
    let mut log_buf = String::new();
    e.internal_log().write_to(&mut log_buf).unwrap();
    secure_logger.info(log_buf);

    // Return sanitized error to client
    return Err(e);
}
```

### Attack Correlation

Track attack patterns across errors:

```rust
let err = AgentError::config_sensitive(
    definitions::CFG_VALIDATION_FAILED,
    "ssh_authenticate",
    "Authentication failed",
    format!("username={} password={}", username, password)
)
.with_metadata("source_ip", attacker_ip)
.with_metadata("protocol", "ssh")
.with_metadata("campaign_id", detected_campaign);

// Process through correlation engine
correlator.track_error(&err, attacker_ip);
```

## 🎓 Examples

```bash
# Basic usage patterns
cargo run --example basic_usage

# Sensitive data handling
cargo run --example sensitive_context

# Complete honeypot pipeline (attack simulation)
cargo run --example honeypot_pipeline
```

The `honeypot_pipeline` example demonstrates:

- SSH bruteforce detection
- Path traversal logging
- SQL injection tracking
- DoS attempt correlation
- Multi-tier forensic logging
- Attack intelligence generation

## 🔧 Running Scripts

Convenient scripts are provided for comprehensive testing, benchmarking, and fuzzing:

### Test Suite

```bash
# Run all tests with multiple feature combinations
./run_all_tests.sh
```

This script runs:

- Standard unit tests with all feature combinations
- Property-based tests (proptest)
- All examples to verify compilation and execution
- Code quality checks (Clippy, formatting)
- Documentation build verification

### Benchmarking

```bash
# Run comprehensive performance benchmarks
./run_benchmarks.sh
```

Generates detailed performance reports in `target/criterion/report/index.html` covering:

- Error creation patterns
- Logging performance
- Honeypot scenarios
- Attack burst handling
- Metadata operations
- Timing normalization
- Ring buffer performance

### Fuzz Testing

**Note:** Fuzz testing requires Rust nightly toolchain. Install with:

```bash
rustup install nightly
```

```bash
# Run all fuzz targets for 60 seconds each (uses nightly automatically)
./run_fuzz.sh all 60

# Run specific fuzz target
./run_fuzz.sh truncation 300

# Available targets: error_context, truncation, metadata, ring_buffer
```

Fuzz testing targets:

- **truncation**: Validates log truncation with extreme input sizes
- **metadata**: Stress-tests metadata storage with random key-value pairs
- **ring_buffer**: Verifies concurrent ring buffer operations under load

## 🛡️ Security Properties

### 1. Zero Information Disclosure

All external errors use identical format regardless of failure reason:

```
{Category} operation failed [{permanence}] ({ERROR-CODE})
```

Attackers cannot distinguish between:

- Missing file vs permission denied
- Invalid password vs invalid username
- Configuration error vs system error

### 2. Memory Forensics Protection

**Threat:** Post-compromise memory dumps reveal sensitive data

**Mitigation:** Automatic zeroization via `ZeroizeOnDrop`

```rust
{
    let err = AgentError::config_sensitive(..., "password=Secret123");
    // Use error...
} // <- Memory zeroized here, unrecoverable
```

### 3. Timing Attack Resistance

**Threat:** Response timing reveals authentication logic paths

**Mitigation:** Optional timing normalization

```rust
fn authenticate(user: &str, pass: &str) -> Result<Session> {
    let result = check_credentials(user, pass);

    if let Err(e) = result {
        // All auth failures take exactly 100ms
        return Err(e.with_timing_normalization(Duration::from_millis(100)));
    }
    result
}
```

### 4. DoS Protection

**Threat:** Attacker triggers errors with massive payloads to exhaust memory

**Mitigation:** All log fields truncated to 1024 characters with clear indicators

### 5. Attack Attribution

**Threat:** Distributed attacks evade correlation

**Mitigation:** Metadata-based tracking across IPs, protocols, and time windows

## 🏗️ Architecture

```
Attacker Request
    ↓
Application Logic (fails)
    ↓
┌─────────────────────────────────────┐
│   AgentError (palisade_errors)      │
│                                      │
│  ┌────────────────────────────────┐ │
│  │ External (Display)             │ │──→ Sanitized response to attacker
│  │ "Configuration failed (E-101)" │ │    (zero information leakage)
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │ Internal (InternalLog)         │ │──→ Forensic logs
│  │ Full context + metadata        │ │    (complete audit trail)
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │ Sensitive (ZeroizeOnDrop)      │ │──→ Restricted access logs
│  │ Credentials, paths, PII        │ │    (encrypted, HSM-backed)
│  └────────────────────────────────┘ │
└─────────────────────────────────────┘
    ↓ (on drop)
Memory Zeroization
```

## 🔧 Integration

### Honeypot Service Example

```rust
impl HttpHoneypot {
    async fn handle_request(&self, req: HttpRequest, addr: SocketAddr) -> HttpResponse {
        let correlation_id = uuid::Uuid::new_v4().to_string();

        match self.process_request(&req).await {
            Ok(response) => response,
            Err(err) => {
                // Add tracking metadata
                let err = err
                    .with_metadata("source_ip", &addr.ip().to_string())
                    .with_metadata("correlation_id", &correlation_id)
                    .with_metadata("path", req.uri().path());

                // Log to forensic system
                self.logger.log_error(&err);

                // Update attack correlation
                self.correlator.process_error(&err, &addr.ip().to_string());

                // Return sanitized error
                HttpResponse::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(format!("{}", err)) // Sanitized via Display
                    .unwrap()
            }
        }
    }
}
```

### SIEM Integration

```rust
// Structured JSON for SIEM ingestion
err.with_internal_log(|log| {
    let event = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "severity": "ERROR",
        "code": log.code().to_string(),
        "namespace": log.code().namespace(),
        "category": format!("{:?}", err.category()),
        "operation": log.operation(),
        "details": log.details(),
        "metadata": log.metadata().iter()
            .map(|(k, v)| (k.to_string(), v.as_str().to_string()))
            .collect::<HashMap<_, _>>(),
    });

    siem.send_event(event);
});
```

## 📊 Benchmarking

```bash
# Run benchmarks
cargo bench

# View detailed HTML report
open target/criterion/report/index.html

# Specific benchmark groups
cargo bench creation_benches    # Error creation
cargo bench honeypot_benches    # Attack scenarios
cargo bench attack_burst        # Burst simulation
```

## 🧪 Testing

```bash
# All tests
cargo test

# Run comprehensive test suite
./run_all_tests.sh

# With coverage
cargo install cargo-tarpaulin
cargo tarpaulin --out Html --output-dir coverage/

# Memory leak verification
cargo install cargo-valgrind
cargo valgrind test --release

# Fuzz testing (requires cargo-fuzz)
./run_fuzz.sh all 60
```

**Test Coverage:**

- Unit tests for all error types and operations
- Property-based testing (proptest) for invariants
- Integration tests for honeypot scenarios
- Fuzz testing for robustness against malformed inputs
- Memory leak verification (expected: **zero leaks**)

**Fuzz Testing Targets:**

- Log truncation boundary conditions
- Metadata storage stress testing
- Ring buffer concurrent operations

## 🎯 Use Cases

- **Honeypot Systems:** Deception infrastructure (primary use case)
- **Security Agents:** EDR, intrusion detection, threat hunting
- **Authentication Services:** Credential validation, SSO, IAM
- **API Gateways:** Rate limiting, authorization, input validation
- **Cryptographic Services:** Key management, HSM integration
- **Compliance Systems:** Audit logging, PCI-DSS, HIPAA

Any system where error messages could aid an adversary.

## 📜 Features

- `default`: Standard error handling
- `trusted_debug`: Enable detailed debug output (⚠️ **debug builds only, never in production**)
- `external_signaling`: Reserved for future capabilities

## 🤝 Contributing

Contributions welcome! Areas of interest:

- Additional attack scenario examples
- Integration with logging frameworks
- Performance optimizations
- Security audits

## 📄 License

Licensed under Apache-2.0.

## ⚠️ Security Considerations

### This Library Does NOT Protect Against:

- **Application-level vulnerabilities:** SQL injection, XSS, etc. (layer above errors)
- **Network-level attacks:** DDoS, packet sniffing (layer below errors)
- **Side-channel attacks:** Cache timing, speculative execution (CPU-level)
- **Social engineering:** Phishing, pretexting (human layer)

### This Library DOES Protect Against:

- **Error message fingerprinting:** Attackers mapping your architecture
- **Information disclosure:** Leaking paths, credentials, internal state
- **Memory forensics:** Post-compromise credential recovery
- **Timing attacks:** Response time revealing logic paths (with normalization)
- **Attack evasion:** Distributed attacks escaping correlation

### Threat Model

We assume attackers:

- ✓ Have source code access
- ✓ Can trigger errors intentionally
- ✓ Collect error messages for analysis
- ✓ May compromise the system later (memory scraping)

We guarantee:

- ✓ External errors reveal only category + code
- ✓ Sensitive data zeroized on drop
- ✓ Log truncation prevents DoS
- ✓ Timing normalization available

### Defense in Depth

This library is ONE layer of security. Combine with:

- Input validation (prevent attacks)
- Rate limiting (slow attackers)
- Web Application Firewall (block patterns)
- Intrusion Detection (detect campaigns)
- Network segmentation (contain breaches)

## 🎖️ Status

**Current State:** Production-ready for honeypot deployment

**Performance:** Validated on hardware from 2010 to present

**Security:** Designed under adversarial threat model

**Testing:** Comprehensive test suite + benchmarks + examples

**Documentation:** Complete API docs + integration guides

---

**Built for the Palisade Honeypot System**

Where every error is a strategic deception.
