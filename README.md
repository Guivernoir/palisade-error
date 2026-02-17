# Palisade Errors

**Security-conscious error handling for high-assurance Rust applications.**

[![Crates.io](https://img.shields.io/crates/v/palisade-errors.svg)](https://crates.io/crates/palisade-errors)
[![Documentation](https://docs.rs/palisade-errors/badge.svg)](https://docs.rs/palisade-errors)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Palisade Errors is designed for systems where **information leakage is a security vulnerability**. Built as the foundational error handling layer for the **Palisade Honeypot System**, it enforces a strict separation between "what happened" (forensics) and "what the adversary sees" (sanitization), while guaranteeing that sensitive data in memory is zeroized immediately after use.

**Current Version:** 1.0.1

---

## 🎯 Design Philosophy

In a honeypot, every error is intelligence:

- **For attackers:** Errors reveal system architecture, validation logic, and attack surface.
- **For defenders:** Errors provide forensic trails, attack correlation, and threat intelligence.

Palisade Errors ensures attackers see only walls, while defenders see everything.

---

## 🏗️ Architecture

The library is built around two complementary error models that share the same security philosophy:

### `AgentError` — The Operational Layer

The primary error type for day-to-day use. Wraps a subsystem error code, operation context, optional sensitive source, metadata tags, and a retryability flag. All construction automatically applies session-specific error code obfuscation and enforces a 1 µs constant-time floor to prevent timing side-channels.

### `DualContextError` — The Deception Layer

A newer, type-enforced dual-context model built for honeypot-specific scenarios. It holds two explicitly typed contexts that cannot be confused at compile time:

- **`PublicContext`** — what the adversary sees. Either a `Lie` (always available) or a `Truth` (gated behind the `external_signaling` feature flag).
- **`InternalContext`** — what SOC analysts see. Can be `Diagnostic`, `Sensitive`, or a tracked `Lie` (for log exfiltration scenarios).

Neither type implements `Display` in a leaking way. `InternalContext::Display` always emits `[INTERNAL CONTEXT REDACTED]`. You access internal content via explicit methods with deliberate API surface.

### `SocAccess` — Capability-Based Sensitive Access

Accessing `Sensitive`-classified internal context requires a `SocAccess` capability token:

```rust
let access = SocAccess::acquire();
if let Some(raw) = context.expose_sensitive(&access) {
    send_to_encrypted_soc_siem(raw);
}
```

This is not cryptographic. Its purpose is **organizational safety**: making sensitive data access grep-able, explicit, and impossible to call accidentally through a generic formatting path.

```
Attacker Request
    ↓
Application Logic (fails)
    ↓
┌─────────────────────────────────────────┐
│   AgentError / DualContextError         │
│                                         │
│  ┌────────────────────────────────────┐ │
│  │ External (Display / PublicContext) │ │──→ Sanitized/deceptive response
│  │ "Configuration failed (E-CFG-103)" │ │    (zero information leakage)
│  └────────────────────────────────────┘ │
│                                         │
│  ┌────────────────────────────────────┐ │
│  │ Internal (InternalLog / Internal   │ │──→ SOC forensic logs
│  │ Context) — Full diagnostic context │ │    (complete audit trail)
│  └────────────────────────────────────┘ │
│                                         │
│  ┌────────────────────────────────────┐ │
│  │ Sensitive (ZeroizeOnDrop +         │ │──→ Encrypted, access-controlled
│  │ volatile writes) — PII, creds,     │ │    restricted-access storage
│  │ paths, keys                        │ │    (requires SocAccess token)
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
    ↓ (on drop)
Best-effort Memory Zeroization
```

---

## 🚀 Key Features

- **Forensic Integrity:** Full stack traces, variable values, and internal state are preserved for your logs — but never reach the adversary.
- **Dual-Context Model:** `DualContextError` gives type-enforced separation of public lies from internal truth.
- **Capability-Based Access:** `SocAccess` prevents accidental sensitive data exposure through generic formatting paths.
- **Information Hiding:** `Display` on all error types is sanitized to reveal only error codes and categories.
- **Memory Safety:** Sensitive data lives in `ZeroizeOnDrop` wrappers. Owned strings receive volatile writes on drop to defeat LLVM dead-store elimination. Secrets are wiped from memory as soon as the error is dropped.
- **Always-On Obfuscation:** Session salts are applied at construction time. The same semantic error produces different codes across sessions, defeating fingerprinting.
- **DoS Protection:** Log outputs are strictly truncated. Convenience macros enforce `sanitized!()` wrapping for dynamic arguments.
- **Strict Taxonomy:** Feature flags enforce rigid error categorization at compile time.
- **Timing Attack Mitigation:** Built-in 1 µs constant-time floor at construction, plus `with_timing_normalization()` for sensitive operation windows.
- **Bounded Forensic Logging:** `RingBufferLogger` provides fixed-memory, DoS-proof forensic log storage.

---

## ⚙️ Feature Flags

| Flag | Default | Effect |
|---|---|---|
| `strict_taxonomy` | Off | Enforces namespace→category mappings at compile time. **Must be enabled in CI.** |
| `strict_severity` | Off | Restricts Breach-level impacts to namespaces with `can_breach` authority. Recommended for production. |
| `external_signaling` | Off | Enables `PublicContext::truth()` and `DualContextError::with_truth()`. Without this flag, **all external output must be deceptive** — enforced at compile time. |
| `trusted_debug` | Off | Enables `InternalLog::format_for_trusted_debug()`. Only activates in `debug_assertions` builds. |
| `tokio` / `async_std` | Off | Enables `AgentError::with_timing_normalization_async()` for non-blocking timing normalization. |

---

## 📖 Usage

### Basic `AgentError`

```rust
use palisade_errors::{AgentError, definitions, Result};

fn check_access(user: &str) -> Result<()> {
    if user == "admin" {
        return Ok(());
    }

    Err(AgentError::config(
        definitions::CFG_PERMISSION_DENIED,
        "check_access",
        format!("User '{}' denied", user)
    ))
}
```

**Adversary sees:**
```
Configuration operation failed [permanent] (E-CFG-107)
// Note: code is session-obfuscated — not E-CFG-104
```

**Your logs contain:**
```
[E-CFG-107] operation='check_access' details="User 'attacker' denied"
```

### Sensitive Data with `AgentError`

```rust
use palisade_errors::{AgentError, definitions};

let err = AgentError::config_sensitive(
    definitions::CFG_INVALID_VALUE,
    "login_flow",
    "Password verification failed",  // Generic details — visible in internal logs
    password_input                   // Sensitive: zeroized on drop, never in Display
);
```

### The Dual-Context Model

For maximum deception control, use `DualContextError` directly:

```rust
use palisade_errors::{DualContextError, OperationCategory};

// Adversary sees generic error. SOC sees SQL injection attempt.
let err = DualContextError::with_lie(
    "Permission denied",
    "Blocked SQL injection: UNION SELECT detected in parameter 'id'",
    OperationCategory::Detection,
);

// External category is also masked: Detection → "Routine Operation"
assert_eq!(err.external_category(), "Routine Operation");
```

**When even internal logs might be exfiltrated:**

```rust
let err = DualContextError::with_double_lie(
    "Service temporarily unavailable",
    "Routine maintenance window in progress",   // [LIE] prefix in SOC logs
    OperationCategory::System,
);
```

**Sensitive internal data:**

```rust
let err = DualContextError::with_lie_and_sensitive(
    "Resource not found",
    format!("Attempted access: /var/secrets/api_keys.txt by user {}", username),
    OperationCategory::IO,
);

// Normal logging — no sensitive data emitted
if let Some(payload) = err.internal().payload() {
    soc_logger.write(format!("{}", payload));
}

// Restricted access — requires SocAccess capability
let access = SocAccess::acquire();
if let Some(raw) = err.internal().expose_sensitive(&access) {
    send_to_encrypted_soc_siem(raw);
}
```

**When `external_signaling` is enabled**, you may emit truthful external messages for benign errors that improve the honeypot's authenticity:

```rust
// Only compiles with feature = "external_signaling"
let err = DualContextError::with_truth(
    "Invalid JSON format",
    "JSON parse error at line 42, column 15: expected closing brace",
    OperationCategory::Configuration,
);
```

Without the feature flag, `PublicContext::truth()` and `DualContextError::with_truth()` do not exist — compile-time enforcement of the deception-only policy.

### Building Errors with `ContextBuilder`

For complex error construction with a fluent API:

```rust
use palisade_errors::{ContextBuilder, OperationCategory};

let err = ContextBuilder::new()
    .public_lie("Operation failed")
    .internal_diagnostic("Database connection timeout after 30s")
    .category(OperationCategory::IO)
    .build();
```

### Secure Logging with `AgentError`

```rust
if let Err(e) = result {
    // Write full details to secure log
    let mut log_buf = String::new();
    e.internal_log().write_to(&mut log_buf).unwrap();
    secure_logger.info(log_buf);

    // Return sanitized error to caller
    return Err(e);
}
```

### Convenience Macros

Macros enforce compile-time safety: operation names and format strings **must be string literals**, and dynamic arguments **must be wrapped in `sanitized!()`**:

```rust
use palisade_errors::{config_err, definitions, sanitized};

let line_num = 42;

// ✓ Correct — literal format, sanitized dynamic argument
let err = config_err!(
    &definitions::CFG_PARSE_FAILED,
    "validate",
    "Invalid value at line {}",
    sanitized!(line_num)
);
```

```rust,compile_fail
// ✗ Compile error — operation must be a literal, not a runtime string
let err = config_err!(&definitions::CFG_PARSE_FAILED, user_input, "Failed");
```

`sanitized!()` truncates to 256 characters at UTF-8 boundaries and replaces control characters with `?` to prevent log injection.

### Attack Correlation with `AgentError`

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

correlator.track_error(&err, attacker_ip);
```

### Timing Attack Mitigation

```rust
use palisade_errors::{AgentError, definitions};
use std::time::Duration;

fn authenticate(user: &str, pass: &str) -> palisade_errors::Result<()> {
    if !user_exists(user) {
        return Err(
            AgentError::config(definitions::CFG_VALIDATION_FAILED, "auth", "Invalid credentials")
                .with_timing_normalization(Duration::from_millis(100))
        );
    }

    if !check_password(user, pass) {
        return Err(
            AgentError::config(definitions::CFG_VALIDATION_FAILED, "auth", "Invalid credentials")
                .with_timing_normalization(Duration::from_millis(100))
        );
    }

    Ok(())
}
```

Both paths take at least 100 ms, preventing user enumeration via response time. For async runtimes, use `with_timing_normalization_async()` (requires `tokio` or `async_std` feature).

### Bounded Forensic Logging

```rust
use palisade_errors::ring_buffer::RingBufferLogger;
use palisade_errors::{AgentError, definitions};

// Max 1000 entries, 2 KB per entry = 2 MB total memory ceiling
let logger = RingBufferLogger::new(1000, 2048);

let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
logger.log(&err, "192.168.1.100");

let recent = logger.get_recent(10);
for entry in recent {
    println!("[{}] {} — {}", entry.timestamp, entry.code, entry.operation);
}
```

Oldest entries are evicted FIFO. Concurrent reads are supported via `RwLock`. No unbounded growth regardless of attack volume.

### Error Code Obfuscation

Obfuscation is applied automatically at `AgentError` construction. You can also use it directly:

```rust
use palisade_errors::obfuscation;

// Per-session setup (call once per connection/session)
let salt = obfuscation::generate_random_salt();
obfuscation::init_session_salt(salt);

// Session 1: E-CFG-103, Session 2: E-CFG-106, Session 3: E-CFG-101
// Attacker cannot correlate codes across sessions.
```

---

## ⚖️ Governance & Taxonomy

Strict governance of error codes and namespaces is critical to preventing information leakage through taxonomy drift.

👉 **See [ERROR_GOVERNANCE.md](ERROR_GOVERNANCE.md) for the complete taxonomy rules, authority models, and feature flag requirements.**

## ⚡ Performance

This crate is architected for **zero-leak memory management** and **microsecond-level predictability**, even on legacy hardware.

👉 **See [BENCH_AVG.md](BENCH_AVG.md) for detailed benchmarks, timing normalization analysis, and hardware validation.**

---

## 🔄 License

Licensed under Apache-2.0.