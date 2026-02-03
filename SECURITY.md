# Security Policy

**Version:** 0.3.0  
**Last Updated:** February 3, 2026

## Threat Model

`palisade-errors` is designed to operate in hostile environments where attackers may have:

1. **Source Code Access:** Attackers know the internal error logic and can read this repository.
2. **Trigger Capability:** Attackers can intentionally trigger errors to fingerprint the system.
3. **Message Collection:** Attackers aggregate error messages to map internal architecture.
4. **Memory Scraping:** Attackers may attempt to read process memory after a compromise (e.g., via core dumps or debugger attachment).
5. **Timing Analysis:** Attackers measure response times to infer code paths.

This library is built for **honeypot systems** where EVERY error is intelligence that attackers will analyze.

### Design Guarantees

- **Sanitization:** The `Display` trait implementation NEVER leaks internal state, file paths, or variable values.
- **Ephemerality:** Sensitive data is stored in `ZeroizeOnDrop` wrappers and cannot survive beyond the error's lifetime.
- **DoS Resistance:** All log formatting is bounded. Unbounded string inputs are truncated before allocation.
- **Timing Resistance:** Optional normalization prevents timing-based logic path fingerprinting.
- **Memory Protection:** All context fields are zeroized on drop.

## Performance Validation

We validate security performance using high-fidelity benchmarks on constrained hardware to ensure security mechanisms (like timing normalization) do not introduce denial-of-service vectors or side-channels.

👉 **Please refer to [BENCH_AVG.md](BENCH_AVG.md) for detailed analysis of timing normalization, memory efficiency, and burst handling.**

## Error Code Governance

Strict governance of error codes and namespaces is critical to preventing information leakage through taxonomy drift.

👉 **Please refer to [ERROR_GOVERNANCE.md](ERROR_GOVERNANCE.md) for the security rules regarding namespace authorities, strict taxonomy features (`strict_taxonomy`), and severity enforcement (`strict_severity`).**

## What This Library Protects Against

### ✅ Information Disclosure via Error Messages

**Attack:** Attacker triggers errors to learn about system internals.

**Protection:** External errors use fixed format regardless of failure reason.
- **External:** `I/O operation failed [permanent] (E-IO-800)`
- **Hidden:** File paths, error kinds, internal state.

### ✅ Memory Forensics After Compromise

**Attack:** Attacker dumps memory after breach to recover credentials.

**Protection:** `ZeroizeOnDrop` trait on all context fields ensures sensitive data is wiped immediately after the error object goes out of scope.

### ✅ Timing-Based User Enumeration

**Attack:** Attacker measures response time to determine if username exists.

**Protection:** Optional `with_timing_normalization()` method allows developers to enforce consistent execution time for sensitive paths (e.g., authentication).

### ✅ DoS via Massive Error Messages

**Attack:** Attacker triggers errors with huge payloads to exhaust memory.

**Protection:** All log fields are strictly truncated to prevent unbounded allocation.

## What This Library Does NOT Protect Against

### ❌ Application-Level Vulnerabilities
This library handles errors; it doesn't prevent them. You must still validate inputs against SQL injection, XSS, and command injection.

### ❌ Network-Level Attacks
This library does not prevent DDoS or packet sniffing.

### ❌ CPU-Level Side Channels
While we provide timing normalization for application logic, we do not protect against micro-architectural attacks like Spectre or Meltdown.

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in `palisade_errors`, please do **NOT** open a public issue.

### Private Disclosure

**Email:** `strukturaenterprise@gmail.com`  
**Subject:** `[SECURITY] Vulnerability in palisade_errors`

### What to Include

1. **Description:** What's vulnerable and why.
2. **Impact:** What could an attacker do with this.
3. **Steps to Reproduce:** Ideally, a proof-of-concept.
4. **Proposed Fix:** If you have ideas.

### Scope

**In scope:**
- Information disclosure via error messages.
- Memory leaks that bypass zeroization.
- DoS via unbounded allocations.
- Timing side-channels in error handling logic.

**Out of scope:**
- Vulnerabilities in example code.
- Issues in upstream dependencies.
- Theoretical attacks without practical exploit paths.