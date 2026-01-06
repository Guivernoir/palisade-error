# Palisade Errors API Documentation

Comprehensive guide to the Palisade Errors API and architecture.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Types](#core-types)
- [Error Codes](#error-codes)
- [Creating Errors](#creating-errors)
- [Logging and Forensics](#logging-and-forensics)
- [Security Model](#security-model)
- [Advanced Patterns](#advanced-patterns)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         AgentError                          │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ ErrorCode  │  │ErrorContext  │  │ Retryable Flag   │   │
│  │ (E-XXX-YY) │  │ (Zeroized)   │  │                  │   │
│  └────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────┘
        │                    │                      │
        │                    │                      │
        ▼                    ▼                      ▼
   ┌─────────┐         ┌──────────┐         ┌──────────┐
   │Category │         │Operation │         │ Metadata │
   │System   │         │Details   │         │ Tracking │
   │Config   │         │Sources   │         │ IDs      │
   │IO       │         │Sensitive │         │          │
   └─────────┘         └──────────┘         └──────────┘
```

## Core Types

### `AgentError`

The main error type that provides:

- Structured error codes
- Automatic zeroization of context
- Dual display modes (internal/external)
- Metadata tracking

```rust
pub struct AgentError {
    code: ErrorCode,
    context: ErrorContext,
    retryable: bool,
}
```

### `ErrorCode`

Identifies errors without revealing implementation details:

```rust
pub struct ErrorCode {
    namespace: &'static str,  // e.g., "CFG", "IO", "CORE"
    code: u16,                // e.g., 100, 200, 300
    category: OperationCategory,
}
```

Format: `E-{namespace}-{code:03}` (e.g., `E-CFG-100`)

### `ErrorContext`

Internal context that is fully zeroized on drop:

```rust
pub struct ErrorContext {
    pub operation: ContextField,              // Operation name
    pub details: ContextField,                // Error details
    pub source_internal: Option<ContextField>, // Error kind
    pub source_sensitive: Option<ContextField>,// Paths, credentials
    pub metadata: Vec<(&'static str, ContextField)>,
}
```

### `ContextField`

Classifies data by sensitivity:

```rust
pub enum ContextField {
    Internal(String),   // Authenticated logs only
    Sensitive(String),  // Contains PII/secrets
}
```

All variants are zeroized on drop.

### `OperationCategory`

Broad categories for external display:

```rust
pub enum OperationCategory {
    Configuration,  // Config parsing/validation
    Deployment,     // Artifact management
    Monitoring,     // Event collection
    Analysis,       // Rule evaluation
    Response,       // Action execution
    Audit,          // Logging
    System,         // System operations
    IO,             // File/network I/O
}
```

### `InternalLog<'a>`

Structured log entry with explicit lifetime:

```rust
pub struct InternalLog<'a> {
    code: ErrorCode,
    operation: &'a str,
    details: &'a str,
    source_internal: Option<&'a str>,
    source_sensitive: Option<&'a str>,
    metadata: &'a [(&'static str, ContextField)],
    retryable: bool,
}
```

Cannot outlive the `AgentError` that created it.

## Error Codes

### Namespace Ranges

| Namespace | Range   | Purpose             |
| --------- | ------- | ------------------- |
| CORE      | 001-099 | Core system errors  |
| CFG       | 100-199 | Configuration       |
| DCP       | 200-299 | Deception artifacts |
| TEL       | 300-399 | Telemetry           |
| COR       | 400-499 | Correlation engine  |
| RSP       | 500-599 | Response execution  |
| LOG       | 600-699 | Logging subsystem   |
| PLT       | 700-799 | Platform operations |
| IO        | 800-899 | I/O operations      |

### Example Codes

```rust
use palisade_errors::codes;

// Configuration errors
codes::CFG_PARSE_FAILED       // E-CFG-100
codes::CFG_VALIDATION_FAILED  // E-CFG-101
codes::CFG_MISSING_REQUIRED   // E-CFG-102
codes::CFG_INVALID_VALUE      // E-CFG-103

// I/O errors
codes::IO_READ_FAILED         // E-IO-800
codes::IO_WRITE_FAILED        // E-IO-801
codes::IO_NOT_FOUND           // E-IO-804
```

## Creating Errors

### Basic Errors

```rust
use palisade_errors::{AgentError, codes};

// Simple error
let err = AgentError::config(
    codes::CFG_INVALID_VALUE,
    "validate_threshold",
    "Threshold must be between 0 and 100"
);
```

### Errors with Sensitive Context

```rust
// Sensitive information (paths, usernames)
let err = AgentError::config_sensitive(
    codes::CFG_PARSE_FAILED,
    "load_config",
    "Failed to parse configuration",
    "/etc/secret/config.toml"  // Stored separately
);
```

### I/O Errors with Split Sources

```rust
use std::fs::File;

let result = File::open(path).map_err(|e|
    AgentError::from_io_path(
        codes::IO_READ_FAILED,
        "load_file",
        path,  // Sensitive
        e      // Internal
    )
);
```

### Retryable Errors

```rust
let err = AgentError::telemetry(
    codes::TEL_WATCH_FAILED,
    "init_watcher",
    "inotify limit reached"
)
.with_retry();  // Mark as retryable

assert!(err.is_retryable());
```

### Errors with Metadata

```rust
let err = AgentError::correlation(
    codes::COR_BUFFER_OVERFLOW,
    "process_events",
    "Event buffer full"
)
.with_metadata("event_id", "evt-12345")
.with_metadata("correlation_id", "corr-67890")
.with_metadata("buffer_size", "1000");
```

### Using Convenience Macros

```rust
use palisade_errors::{config_err, io_err, codes};

// Format strings in macros
let line = 42;
let err = config_err!(
    codes::CFG_PARSE_FAILED,
    "parse_config",
    "Invalid value at line {}",
    line
);

// Different subsystems
let err = io_err!(
    codes::IO_WRITE_FAILED,
    "write_log",
    "Failed to write {} bytes",
    1024
);
```

Available macros:

- `config_err!`
- `config_err_sensitive!`
- `deployment_err!`
- `telemetry_err!`
- `correlation_err!`
- `response_err!`
- `logging_err!`
- `platform_err!`
- `io_err!`

## Logging and Forensics

### External Display (Sanitized)

```rust
let err = AgentError::config(
    codes::CFG_PARSE_FAILED,
    "parse_config",
    "Failed to parse TOML"
);

// Displays: "Configuration operation failed [permanent] (E-CFG-100)"
println!("{}", err);
```

### Internal Logging (Full Context)

```rust
// Pattern 1: Callback style (preferred)
err.with_internal_log(|log| {
    let mut buffer = String::new();
    log.write_to(&mut buffer).unwrap();
    eprintln!("{}", buffer);
});

// Pattern 2: Direct access
let log = err.internal_log();
println!("Code: {}", log.code());
println!("Operation: {}", log.operation());
println!("Details: {}", log.details());
```

### Zero-Allocation Logging

```rust
// Write directly to output without intermediate allocations
err.with_internal_log(|log| {
    let mut buffer = String::new();
    log.write_to(&mut buffer).unwrap();
    // Send buffer to logger
});
```

### Structured Field Access

```rust
let log = err.internal_log();

// Access individual fields
let code = log.code();
let operation = log.operation();
let details = log.details();
let retryable = log.is_retryable();

// Access sources
if let Some(internal) = log.source_internal() {
    println!("Error kind: {}", internal);
}

if let Some(sensitive) = log.source_sensitive() {
    // Handle with care - contains paths/credentials
    log_to_secure_system(sensitive);
}

// Access metadata
for (key, value) in log.metadata() {
    println!("{}: {}", key, value.as_str());
}
```

### Trusted Debug Output

Only available with `trusted_debug` feature:

```rust
#[cfg(feature = "trusted_debug")]
{
    let log = err.internal_log();
    let debug_str = log.format_for_trusted_debug();
    eprintln!("DEBUG: {}", debug_str);
}
```

⚠️ **Never use in production or untrusted environments!**

## Security Model

### Threat Model

We assume attackers can:

- Read source code
- Trigger errors deliberately
- Collect error messages for fingerprinting
- Perform post-compromise memory scraping
- Analyze timing and error patterns

### Defense Strategy

1. **External Sanitization**: Only category, permanence, and code visible
2. **Internal Forensics**: Full context for legitimate operators
3. **Automatic Zeroization**: All context zeroized on drop
4. **Lifetime Enforcement**: Log entries cannot outlive errors
5. **Split Storage**: Sensitive data separated from error kinds

### What's Protected

External display NEVER reveals:

- File paths
- Usernames or credentials
- Configuration values
- Internal architecture
- Validation logic
- Stack traces or memory addresses

### What's Exposed

External display provides:

- Operation category (broad domain)
- Error code (for tracking)
- Permanence (retry semantics)

Example:

```
Configuration operation failed [permanent] (E-CFG-103)
```

### Security Properties

- ✅ All context zeroized on drop
- ✅ No information leakage in Display
- ✅ Lifetime-bound log entries
- ✅ Explicit sensitivity marking
- ✅ Split error kind and path storage
- ✅ DoS protection (field truncation)
- ✅ Zero-allocation hot paths

## Advanced Patterns

### Error Propagation

```rust
fn inner_operation() -> Result<()> {
    Err(AgentError::config(
        codes::CFG_PARSE_FAILED,
        "parse_field",
        "Invalid syntax"
    ))
}

fn outer_operation() -> Result<()> {
    inner_operation().map_err(|e|
        e.with_metadata("caller", "outer_operation")
    )
}
```

### Conditional Retry

```rust
fn should_retry(err: &AgentError) -> bool {
    err.is_retryable() && matches!(
        err.category(),
        OperationCategory::Monitoring | OperationCategory::IO
    )
}

match operation() {
    Ok(val) => val,
    Err(e) if should_retry(&e) => {
        // Retry logic
    }
    Err(e) => return Err(e),
}
```

### Error Aggregation

```rust
struct ErrorSummary {
    count: usize,
    by_code: HashMap<String, usize>,
    retryable: usize,
}

fn summarize_errors(errors: &[AgentError]) -> ErrorSummary {
    let mut summary = ErrorSummary::default();

    for err in errors {
        summary.count += 1;
        *summary.by_code.entry(err.code().to_string())
            .or_insert(0) += 1;
        if err.is_retryable() {
            summary.retryable += 1;
        }
    }

    summary
}
```

### Custom Logging Integration

```rust
trait Logger {
    fn log_error(&self, log: &InternalLog);
}

struct JsonLogger;

impl Logger for JsonLogger {
    fn log_error(&self, log: &InternalLog) {
        let json = json!({
            "code": log.code().to_string(),
            "operation": log.operation(),
            "details": log.details(),
            "retryable": log.is_retryable(),
            "metadata": log.metadata().iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<HashMap<_, _>>(),
        });

        // Send to log aggregation system
        send_to_elk(&json);
    }
}

// Usage
let logger = JsonLogger;
err.with_internal_log(|log| logger.log_error(log));
```

### Testing Error Behavior

```rust
#[test]
fn test_no_information_leakage() {
    let err = AgentError::config_sensitive(
        codes::CFG_PARSE_FAILED,
        "parse_config",
        "Invalid syntax",
        "/secret/path/config.toml"
    );

    let external = err.to_string();

    // Verify no sensitive data in external display
    assert!(!external.contains("/secret"));
    assert!(!external.contains("config.toml"));
    assert!(!external.contains("parse_config"));

    // Verify code is present
    assert!(external.contains("E-CFG-100"));
}

#[test]
fn test_zeroization_on_drop() {
    let err = AgentError::config_sensitive(
        codes::CFG_PARSE_FAILED,
        "test",
        "test",
        "sensitive_data"
    );

    // err is dropped here, all memory zeroized
    drop(err);

    // Memory should be zeroed (enforced by ZeroizeOnDrop)
}
```

## Performance Considerations

- **Zero-allocation paths**: Use `write_to()` instead of `format_for_trusted_debug()`
- **Avoid cloning**: Use references and lifetimes
- **Metadata efficiency**: Add metadata before error propagation
- **Field truncation**: Automatic DoS protection (1024 char limit)

## Best Practices

1. **Always use appropriate error codes** - Don't reuse codes for different situations
2. **Mark sensitive data explicitly** - Use `config_sensitive()` or `from_io_path()`
3. **Add meaningful metadata** - Include correlation IDs and context
4. **Use callback logging** - Prevents accidental log retention
5. **Test security properties** - Verify no information leakage
6. **Handle retryable errors** - Check `is_retryable()` before retry logic
7. **Log internally, display externally** - Different audiences, different needs

## Migration Guide

### From `std::io::Error`

Before:

```rust
File::open(path)?
```

After:

```rust
File::open(path).map_err(|e|
    AgentError::from_io_path(
        codes::IO_READ_FAILED,
        "open_file",
        path,
        e
    )
)?
```

### From Custom Error Types

Before:

```rust
return Err(MyError::Config { path, reason });
```

After:

```rust
return Err(AgentError::config_sensitive(
    codes::CFG_PARSE_FAILED,
    "parse_config",
    reason,
    path
));
```

## Further Reading

- [README.md](README) - Quick start and overview
- [CONTRIBUTING.md](CONTRIBUTING) - Development guidelines
- [examples/](examples/) - Runnable examples
- [src/](src/) - Source code with inline documentation
