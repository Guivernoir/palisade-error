# Palisade Errors

**Security-conscious error handling for high-assurance Rust applications.**

[![Crates.io](https://img.shields.io/crates/v/palisade-errors.svg)](https://crates.io/crates/palisade-errors)
[![Documentation](https://docs.rs/palisade-errors/badge.svg)](https://docs.rs/palisade-errors)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Palisade Errors is designed for systems where **information leakage is a security vulnerability**. Built as the foundational error handling layer for the **Palisade Honeypot System**, it enforces a strict separation between "what happened" (forensics) and "what the user sees" (sanitization), while guaranteeing that sensitive data in memory is zeroized immediately after use.

**Current Version:** 0.3.0  

## 🎯 Design Philosophy

In a honeypot, every error is intelligence:

- **For attackers:** Errors reveal system architecture, validation logic, and attack surface
- **For defenders:** Errors provide forensic trails, attack correlation, and threat intelligence

Palisade Errors ensures attackers see only walls, while defenders see everything.

## 🚀 Key Features

- **Forensic Integrity:** Keep full stack traces, variable values, and internal state for your logs.
- **Information Hiding:** External error messages (`Display`) are automatically sanitized to reveal only error codes and categories.
- **Memory Safety:** All error context is wrapped in `ZeroizeOnDrop` types. Secrets are wiped from memory as soon as the error is dropped.
- **DoS Protection:** Log outputs are strictly truncated to prevent memory exhaustion attacks.
- **Strict Taxonomy:** Optional feature flags to enforce rigid error categorization at compile time.
- **Timing Attack Mitigation:** Built-in normalization mechanisms to prevent side-channel leakage.

## ⚖️ Governance & Taxonomy

To maintain security boundaries in large-scale systems, this crate adheres to a strict governance contract regarding error namespaces, impact scores, and authority flags.

👉 **Please refer to [error-governance.md](error-governance.md) for the complete taxonomy rules, authority models, and strict-mode feature flags.**

## ⚡ Performance

This crate is architected for **zero-leak memory management** and **microsecond-level predictability**, even on legacy hardware.

👉 **For detailed benchmarks, timing normalization analysis, and hardware validation, see [bench_avg.md](bench_avg.md).**

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

Track attack patterns across errors using the metadata API:

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

## 🛡️ Security Features

* **Zero Information Disclosure:** Attackers cannot distinguish between missing files, permission errors, or logic failures based on the external message.
* **Memory Forensics Protection:** `ZeroizeOnDrop` implementation ensures sensitive strings are unrecoverable from RAM after use.
* **Timing Attack Resistance:** Optional timing normalization primitives.
* **DoS Protection:** Automatic log truncation limits.
* **Strict Taxonomy:** Compile-time enforcement of error categorization via `strict_taxonomy` feature.

See [SECURITY.md](SECURITY.md) for the full threat model.

## 📄 License

Licensed under Apache-2.0.

