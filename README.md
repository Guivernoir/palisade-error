# Palisade Errors

**Security-conscious error handling for high-assurance Rust applications.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Palisade Errors is designed for systems where **information leakage is a security vulnerability**. It enforces a strict separation between "what happened" (forensics) and "what the user sees" (sanitization), while guaranteeing that sensitive data in memory is zeroized immediately after use.

## 🚀 Key Features

- **Forensic Integrity:** Keep full stack traces, variable values, and internal state for your logs.
- **Information Hiding:** External error messages (`Display`) are automatically sanitized to reveal only error codes and categories.
- **Memory Safety:** All error context is wrapped in `ZeroizeOnDrop` types. Secrets are wiped from memory as soon as the error is dropped.
- **DoS Protection:** Log outputs are strictly truncated to prevent memory exhaustion attacks via massive error messages.
- **Zero-Allocation Paths:** Optimized for performance using `Cow<'static, str>` to handle string literals without heap allocation.
- **Timing Attack Mitigation:** Optional constant-time error responses.

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

### Handling Sensitive Data

When handling passwords, keys, or PII, use the `sensitive` constructors to ensure data is sequestered.

```rust
use palisade_errors::{AgentError, definitions};

let err = AgentError::config_sensitive(
    definitions::CFG_INVALID_VALUE,
    "login_flow",          // Operation name
    "Password verification failed", // Generic details
    password_input         // SENSITIVE: Zeroized on drop, never shown in Display
);

```

### Secure Logging

To access the internal details for your secure logs, use the `internal_log()` method. This returns a short-lived structure that prevents data retention.

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

## 🛡️ License

Licensed under Apache-2.0.
