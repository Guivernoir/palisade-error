# Security Policy

## Threat Model

`palisade_errors` is designed to operate in hostile environments where attackers may have:

1. **Source Code Access:** Attackers know the internal error logic and can read this repository
2. **Trigger Capability:** Attackers can intentionally trigger errors to fingerprint the system
3. **Message Collection:** Attackers aggregate error messages to map internal architecture
4. **Memory Scraping:** Attackers may attempt to read process memory after a compromise (e.g., via core dumps or debugger attachment)
5. **Timing Analysis:** Attackers measure response times to infer code paths

This library is built for **honeypot systems** where EVERY error is intelligence that attackers will analyze.

### Design Guarantees

- **Sanitization:** The `Display` trait implementation NEVER leaks internal state, file paths, or variable values
- **Ephemerality:** Sensitive data is stored in `ZeroizeOnDrop` wrappers and cannot survive beyond the error's lifetime
- **DoS Resistance:** All log formatting is bounded. Unbounded string inputs are truncated before allocation
- **Timing Resistance:** Optional normalization prevents timing-based logic path fingerprinting
- **Memory Protection:** All context fields are zeroized on drop, including non-sensitive fields (defense in depth)

## What This Library Protects Against

### ✅ Information Disclosure via Error Messages

**Attack:** Attacker triggers errors to learn about system internals

**Example:**

```
# What attacker tries to do:
curl http://honeypot/../../etc/passwd

# What they get (external):
I/O operation failed [permanent] (E-IO-800)

# What they DON'T get:
❌ File path: /etc/passwd
❌ Error kind: PermissionDenied
❌ Operation: serve_file
❌ Internal state: authenticated=false
```

**Protection:** External errors use fixed format regardless of failure reason.

### ✅ Memory Forensics After Compromise

**Attack:** Attacker dumps memory after breach to recover credentials

**Example:**

```rust
// Attacker attempts SSH with password "SuperSecret123"
let err = AgentError::config_sensitive(
    definitions::CFG_VALIDATION_FAILED,
    "ssh_authenticate",
    "Authentication failed",
    "password=SuperSecret123"
);

// Use error in logging...

// When err drops, "SuperSecret123" is zeroized in memory
// Core dumps, debuggers, memory scanners: cannot recover it
```

**Protection:** `ZeroizeOnDrop` trait on all context fields.

### ✅ Timing-Based User Enumeration

**Attack:** Attacker measures response time to determine if username exists

**Example:**

```rust
fn authenticate(user: &str, pass: &str) -> Result<Session> {
    // Fast path: user doesn't exist (~10ms)
    if !user_exists(user) {
        return Err(
            AgentError::config(...)
                .with_timing_normalization(Duration::from_millis(100))
        );
    }

    // Slow path: password hash check (~90ms)
    if !check_password(user, pass) {
        return Err(
            AgentError::config(...)
                .with_timing_normalization(Duration::from_millis(100))
        );
    }

    Ok(create_session(user))
}

// Both error paths take exactly 100ms
// Attacker cannot distinguish via timing
```

**Protection:** Optional `with_timing_normalization()` method.

### ✅ DoS via Massive Error Messages

**Attack:** Attacker triggers errors with huge payloads to exhaust memory

**Example:**

```rust
// Attacker sends 1GB file path
let huge_path = "A".repeat(1_000_000_000);
let err = AgentError::from_io_path(
    definitions::IO_READ_FAILED,
    "serve_file",
    huge_path,  // Will be truncated
    io_err
);

// Internal log output: truncated to 1024 chars + "[TRUNCATED]"
// Memory usage: bounded
```

**Protection:** All log fields truncated to 1024 characters.

### ✅ Attack Pattern Correlation Evasion

**Attack:** Distributed botnet uses different IPs to evade detection

**Example:**

```rust
// Track errors across IPs via metadata
let err = AgentError::config(...)
    .with_metadata("source_ip", attacker_ip)
    .with_metadata("campaign_id", detected_campaign)
    .with_metadata("correlation_id", request_id);

// Correlation engine connects:
// - Same campaign_id from multiple IPs
// - Similar error patterns
// - Temporal clustering
// Result: Botnet detected despite IP diversity
```

**Protection:** Rich metadata for correlation engines.

## What This Library Does NOT Protect Against

### ❌ Application-Level Vulnerabilities

This library handles errors, it doesn't prevent them.

**Still vulnerable to:**

- SQL injection (validate inputs!)
- XSS (sanitize outputs!)
- Command injection (never shell out with user input!)
- Authentication bypass (implement proper authn/authz!)

**Mitigation:** Use this library to LOG these attacks without REVEALING details to attackers.

### ❌ Network-Level Attacks

Errors happen at application layer.

**Still vulnerable to:**

- DDoS (use rate limiting, CDN)
- Packet sniffing (use TLS)
- ARP spoofing (use network segmentation)

**Mitigation:** This library helps DETECT attacks via error correlation, not prevent them.

### ❌ CPU-Level Side Channels

**Still vulnerable to:**

- Spectre/Meltdown (CPU vulnerabilities)
- Cache timing attacks (requires constant-time crypto primitives)
- Branch prediction side channels

**Mitigation:** For cryptographic operations, use dedicated constant-time libraries (e.g., `subtle` crate).

### ❌ Social Engineering

**Still vulnerable to:**

- Phishing (humans are the weakness)
- Pretexting (attackers lying to users)
- Insider threats (trusted users going rogue)

**Mitigation:** This is a technical control, not a human control.

## Performance Validation

Benchmarked on Dell Latitude E6410 (Intel Core i5 M560 @ 2.66GHz, 2010-era hardware):

### Error Creation Performance

```
Simple error:              209 ns  (4.8M errors/sec)
Dynamic string:            253 ns  (3.9M errors/sec)
Sensitive context:         224 ns  (4.5M errors/sec)
I/O with split sources:    359 ns  (2.8M errors/sec)
```

### Constructor Performance by Category

```
Config error:              210 ns  (4.8M/sec)
Deployment error:          216 ns  (4.6M/sec)
Telemetry error:          214 ns  (4.7M/sec)
Correlation error:         245 ns  (4.1M/sec)
Response error:            218 ns  (4.6M/sec)
Logging error:             218 ns  (4.6M/sec)
Platform error:            218 ns  (4.6M/sec)
I/O operation:             220 ns  (4.5M/sec)
```

### Logging Performance

```
Log access:                 59 ns  (16.9M ops/sec)
Log write to buffer:       673 ns  (1.5M ops/sec)
Callback pattern:           30 ns  (33.3M ops/sec)
With sensitive data:       564 ns  (1.8M ops/sec)
```

### Metadata Operations

```
1 metadata entry:          326 ns  (3.1M ops/sec) - inline storage
2 metadata entries:        404 ns  (2.5M ops/sec) - inline storage
4 metadata entries:        527 ns  (1.9M ops/sec) - inline storage
8 metadata entries:      1,169 ns  (855k ops/sec) - heap allocation

Metadata access (any):   1.06 ns  (943M ops/sec)
```

### Log Truncation

```
100 chars:                 556 ns
1024 chars (limit):        859 ns
5000 chars (truncated):    915 ns
10000 chars (truncated):   908 ns
```

### Display & Formatting

```
External display format:   316 ns  (3.2M ops/sec)
Debug format:            1,087 ns  (920k ops/sec)
Error code to string:      124 ns  (8.1M ops/sec)
```

### Honeypot Scenarios

```
Auth failure (full):      1.39 µs  (719k/sec)
Path traversal:           1.23 µs  (813k/sec)
Rate limit response:       540 ns  (1.9M/sec)
```

### Attack Burst Handling

```
10 errors:               8.79 µs   (114k bursts/sec)
50 errors:               45.7 µs   (21.9k bursts/sec)
100 errors:              86.6 µs   (11.5k bursts/sec)
500 errors:               446 µs   (2.2k bursts/sec)
```

### Timing Normalization

```
Fast error with norm:    10.13 ms  (normalized to 10ms)
Slow error with norm:    15.15 ms  (normalized to 15ms)
Measurement overhead:      162 ns  (negligible)
```

### Obfuscation Feature (when enabled)

```
Initialize session salt:  352 ps  (2.8T ops/sec)
Obfuscate error code:      14 ns  (71.4M ops/sec)
Generate random salt:      72 ns  (13.9M ops/sec)
Error with obfuscation:   243 ns  (4.1M errors/sec)
```

### Ring Buffer Performance

```
Single-threaded (100):     421 ns
Single-threaded (1000):    428 ns
Single-threaded (10000):   464 ns

Concurrent (2 threads):    470 µs
Concurrent (4 threads):    781 µs
Concurrent (8 threads):  1,567 µs

With eviction (200):     99.8 µs
Get recent 10:          4.91 µs
Get all (200 entries):   256 µs
Get filtered:            120 µs
```

### Memory Allocation

```
Static strings:            170 ns  (zero allocation)
Dynamic strings:           239 ns  (heap allocation)
```

### Unicode Handling

```
ASCII text:                207 ns
Emoji:                     207 ns
Mixed scripts:             213 ns
```

### Method Chaining

```
No chaining:               210 ns
With retry context:        218 ns
With 5 metadata entries:   359 ns
Full chain:                277 ns
```

### Capacity Analysis

**Typical honeypot attack loads:**

- **Idle probing:** 1-10 errors/sec
- **Active scan:** 100-500 errors/sec
- **Coordinated attack:** 1,000-5,000 errors/sec
- **DDoS attempt:** 10,000+ errors/sec

**Library capacity on E6410 (worst case - auth failure scenario):**

- Single-threaded: 719,000 errors/sec
- **Safety margin:** 144x @ 5,000 errors/sec
- **CPU overhead:** <0.7% @ 5,000 errors/sec

**On modern hardware (Ryzen 9, M-series Apple Silicon):**

- Expected: 2-3M errors/sec (3-4x faster)
- **Safety margin:** 400-600x

**Conclusion:** Performance is NOT a bottleneck for honeypot deployments, even on 15-year-old hardware.

## Known Limitations

### 1. Timing Normalization is Coarse

**Issue:** `std::thread::sleep` has OS-dependent precision (1-15ms)

**Impact:** Cannot defend against sub-millisecond timing attacks

**Mitigation:**

- Use for authentication (100ms+ normalization)
- Don't rely on it for cryptographic timing
- Implement constant-time algorithms at application layer

**Alternative:** For crypto, use crates like `subtle` with hardware constant-time guarantees.

### 2. Zeroization is Best-Effort

**Issue:** Modern OSes use memory encryption, swap, compression

**Impact:** Zeroized memory might exist in:

- Encrypted swap files (attacker needs disk + key)
- CPU caches (L1/L2/L3)
- Hibernate files

**Mitigation:**

- Disable swap for sensitive processes
- Encrypt disk at rest
- Lock memory pages with `mlock()`
- This library provides defense-in-depth, not absolute guarantees

### 3. Error Codes are Deterministic

**Issue:** Error codes like `E-CFG-100` map to specific code paths

**Impact:** Sophisticated attackers can fingerprint the system

**Example:**

```
E-CFG-100 → Config parser, line 42
E-CFG-101 → Validator, missing field
E-CFG-102 → Validator, type mismatch
```

**Mitigation:**

- This is acceptable trade-off (debugging requires some signal)
- Error codes are still FAR better than detailed messages
- For ultra-paranoid deployments: randomize error IDs per session

### 4. SmallVec Spill for Heavy Metadata

**Issue:** More than 4 metadata entries triggers heap allocation

**Impact:** Performance degrades, potential for memory fragmentation

**Measured:**

- 1 entry: 326ns (inline storage)
- 2 entries: 404ns (inline storage)
- 4 entries: 527ns (inline storage)
- 8 entries: 1,169ns (heap allocation, 2.2x slower)

**Mitigation:**

- Keep critical paths to ≤4 metadata entries
- Not a concern for typical honeypot use (most errors have 2-3 metadata)
- Even with 8 entries, still processing 855k errors/sec

### 5. Async Contexts with Timing Normalization

**Issue:** `with_timing_normalization()` uses `std::thread::sleep`

**Impact:** Blocks executor threads in async contexts (Tokio, async-std)

**Mitigation:**

- Only use in synchronous code paths
- For async: implement timing normalization at application layer with `tokio::time::sleep()`
- Consider removing this feature if primarily async deployment

## Security Audit Checklist

Before deploying in production:

- [ ] **Information Disclosure Test**

  ```bash
  cargo test information_disclosure -- --nocapture
  # Verify no sensitive data in external errors
  ```

- [ ] **Memory Leak Verification**

  ```bash
  cargo install cargo-valgrind
  cargo valgrind test --release
  # Expected: "All heap blocks were freed -- no leaks are possible"
  ```

- [ ] **Fuzz Testing**

  ```bash
  # Requires Rust nightly toolchain
  rustup install nightly

  # Run all fuzz targets for 5 minutes each
  ./run_fuzz.sh all 300
  # Check fuzz/artifacts/ for any crashes
  ```

- [ ] **Timing Normalization Test**

  ```bash
  cargo test timing_normalization -- --nocapture
  # Verify consistent timing across code paths
  ```

- [ ] **Performance Under Load**

  ```bash
  cargo bench attack_burst
  # Verify acceptable performance at expected attack volumes
  ```

- [ ] **External Error Format Review**

  ```bash
  cargo run --example honeypot_pipeline | grep "Response to attacker"
  # Manually verify no information leakage
  ```

- [ ] **Forensic Log Completeness**

  ```bash
  cargo run --example honeypot_pipeline | grep "FORENSIC LOG"
  # Verify all necessary context captured
  ```

- [ ] **Comprehensive Test Suite**
  ```bash
  ./run_all_tests.sh
  # Run all tests, examples, and quality checks
  ```

## Deployment Best Practices

### 1. Multi-Tier Logging

```rust
struct HoneypotLogger {
    operational: syslog::Logger,      // Public-safe, high volume
    forensic: encrypted_log::Logger,  // Full context, encrypted
    sensitive: hsm_log::SecureLogger, // Restricted access, HSM-backed
}

impl HoneypotLogger {
    fn log_error(&self, err: &AgentError) {
        // Tier 1: Operational (external-safe)
        self.operational.log(format!("{}", err));

        // Tier 2: Forensic (full internal context)
        err.with_internal_log(|log| {
            self.forensic.log_structured(/* ... */);
        });

        // Tier 3: Sensitive (if present)
        err.with_internal_log(|log| {
            if let Some(sensitive) = log.source_sensitive() {
                self.sensitive.log(/* ... */);
            }
        });
    }
}
```

### 2. Access Controls

- **Operational logs:** Read-only for SOC analysts
- **Forensic logs:** Authenticated security team only
- **Sensitive logs:** Need-to-know basis, audit all access

### 3. Encryption at Rest

- Forensic logs: AES-256-GCM
- Sensitive logs: HSM-backed encryption
- Keys: Separate key management system

### 4. Retention Policies

- Operational: 30 days (compliance minimum)
- Forensic: 90 days (investigation window)
- Sensitive: 7 days then secure deletion (data minimization)

### 5. Alerting Thresholds

Monitor for:

- Error rate spikes (>1,000/sec from single IP)
- Unusual error codes (CORE errors = serious)
- Campaign patterns (same correlation_id from multiple IPs)
- Performance degradation (>5μs per error = investigate)

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in `palisade_errors`, please do **NOT** open a public issue.

### Private Disclosure

**Email:** `strukturaenterprise@gmail.com`

**Subject:** `[SECURITY] Vulnerability in palisade_errors`

### What to Include

1. **Description:** What's vulnerable and why
2. **Impact:** What could an attacker do with this
3. **Steps to Reproduce:** Ideally, a proof-of-concept
4. **Proposed Fix:** If you have ideas

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Fix Development:** Within 30 days (for critical issues)
- **Public Disclosure:** After fix is released

### Scope

**In scope:**

- Information disclosure via error messages
- Memory leaks that bypass zeroization
- DoS via unbounded allocations
- Timing side-channels in error handling
- Panic safety issues in Drop implementations

**Out of scope:**

- Vulnerabilities in example code (not production)
- Issues in dependencies (report to upstream)
- Theoretical attacks with no practical exploit
- Performance issues that don't affect security

## Security Hardening Recommendations

For maximum security posture:

1. **Compile with hardening flags:**

   ```toml
   [profile.release]
   opt-level = 3
   lto = true
   codegen-units = 1
   strip = true
   panic = "abort"
   ```

2. **Enable additional checks:**

   ```bash
   RUSTFLAGS="-Z sanitizer=address" cargo +nightly test
   RUSTFLAGS="-Z sanitizer=memory" cargo +nightly test
   ```

3. **Use security-focused allocator:**

   ```toml
   [dependencies]
   tikv-jemallocator = "0.5"
   ```

4. **Minimize attack surface:**

   ```toml
   [features]
   default = []  # No features by default
   ```

5. **Regular audits:**
   ```bash
   cargo audit
   cargo deny check
   cargo geiger
   ```

## License

This security policy is licensed under the same terms as the code: Apache-2.0.

---

**Last Updated:** January 9th, 2026
**Version:** 0.2.0  
**Contact:** strukturaenterprise@gmail.com
