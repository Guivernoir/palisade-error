# Palisade Errors

Security-conscious error handling for Rust services that operate against adversarial, deceptive, or high-scrutiny external surfaces.

## Abstract

`palisade-errors` is a deliberately narrow error crate. Its public API is centered on a single type, `AgentError`, and its design prioritizes surface reduction, deterministic storage, redaction discipline, and bounded operational behavior over rich ecosystem interoperability.

The crate is intended for environments in which errors are not merely debugging artifacts but part of the observable attack surface. In that setting, the primary engineering question is not only "how do we represent failure?" but also "what does a hostile observer learn from the way failure is represented, timed, retained, and persisted?" Palisade Errors addresses that question with fixed-capacity payload handling, process-local code obfuscation, bounded in-memory forensics, timing normalization, and optional encrypted log persistence.

This crate should be evaluated as an operationally opinionated component, not as a general-purpose replacement for the broader Rust error ecosystem.

## Positioning

The crate is a good fit when the following properties matter:

- external error surfaces must reveal as little as possible
- public-path heap allocation should be avoided
- sensitive payload storage should be zeroized on overwrite and drop
- in-process forensic retention should remain memory-bounded
- log persistence should be explicit, optional, and hardened

It is a poor fit when the following priorities dominate:

- rich error chaining across many third-party libraries
- idiomatic derive-based integration with large application stacks
- backtrace-first diagnostics for developer-facing tools
- standardized cryptographic log formats

## Public Interface

The only named public type is `AgentError`. Supported entry points are inherent methods on that type:

- `AgentError::new(code, external, internal, sensitive)`
- `AgentError::with_timing_normalization(duration)`
- `AgentError::with_timing_normalization_async(duration)`
- `AgentError::log(path)` when `feature = "log"`

No public namespace types, context wrappers, ring-buffer types, or code-table primitives are exposed.

## Design Objectives

### 1. External Surface Discipline

`Display` emits only the external payload. `Debug` remains similarly constrained unless `trusted_debug` is enabled. This is the core redaction rule of the crate.

### 2. Bounded Public-Path Behavior

Payload text is stored inline in fixed-capacity buffers. The in-process forensic ring buffer is statically bounded. Optional encrypted log records are assembled in fixed-capacity buffers.

### 3. Sensitive Data Hygiene

Inline payload buffers and transient cryptographic buffers are explicitly zeroized on overwrite and drop. This reduces residual exposure after normal object lifetimes, while not claiming protection against kernel- or hardware-level compromise.

### 4. Stable Failure Semantics Under Observation

Public construction, formatting, and optional log persistence use crate-local timing normalization helpers. The current implementation enforces a minimum 50 us public-path floor where applicable.

### 5. Controlled Forensic Retention

Each `AgentError::new()` appends one record to a bounded in-process ring buffer. This preserves local forensic value without allowing unbounded memory growth under adversarial triggering.

## Security Model

The crate assumes an attacker may:

- trigger error paths repeatedly
- observe externally formatted errors
- compare timing across requests
- recover crash dumps or residual process memory after compromise
- exfiltrate persisted log files

The crate aims to reduce information leakage through formatting, storage, and persistence behavior. It does not claim to secure the surrounding application, eliminate pre-error side channels, or provide a standardized cryptographic audit-log protocol.

## Optional Logging

Encrypted file logging is disabled by default and available only behind `feature = "log"`.

```bash
cargo run --example encrypted_logging --features log
```

When enabled, `AgentError::log()` writes one record using the following layered structure:

- inner AES-256-GCM encryption
- outer SHA-512-derived masking stream
- HMAC-SHA512 over the final encrypted frame

The implementation is intentionally bounded and zeroizes transient buffers after use. It should be understood as defense in depth, not as a substitute for a standardized, externally audited secure logging scheme.

Operational constraints enforced by the current implementation:

- the log path must be absolute
- the log path must not be a symlink
- new Unix log files are created owner-private
- appends are followed by `sync_data()`
- payload text is sanitized before plaintext framing to prevent line and field injection

## Quick Start

```rust
use palisade_errors::AgentError;

fn validate_user(user: &str) -> Result<(), AgentError> {
    if user == "admin" {
        return Ok(());
    }

    Err(AgentError::new(
        103,
        "Invalid credentials",
        "username lookup failed during authentication flow",
        user,
    ))
}
```

By default, terminal formatting is intentionally minimal:

```rust
let err = AgentError::new(
    100,
    "Request could not be completed",
    "configuration parse failed near bootstrap file",
    "/srv/palisade/config/bootstrap.toml",
);

assert_eq!(format!("{err}"), "Request could not be completed");
assert!(!format!("{err:?}").contains("bootstrap.toml"));
```

## Feature Flags

- `log`: enables encrypted file logging
- `strict_severity`: enables stricter internal impact validation
- `trusted_debug`: allows `Debug` to expose code, external, internal, and sensitive payloads for trusted environments

## Operational Guidance

For production use, the crate should be treated as one layer in a broader control set. Recommended surrounding controls include:

- application-level rate limiting on attacker-reachable failure paths
- deliberate file placement and lifecycle management for encrypted logs
- explicit policies for key custody, live-memory access, and crash-dump handling
- routine validation on the target platform and workload, not only on developer workstations

## Verification Workflow

Local verification commands:

```bash
cargo fmt --all
cargo check --all-targets --all-features
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml
```

Short fuzzing runs:

```bash
cargo +nightly fuzz run agent_error_display -- -max_total_time=3
cargo +nightly fuzz run agent_error_timing -- -max_total_time=3
cargo +nightly fuzz run agent_error_log -- -max_total_time=3
```

Benchmark entry points:

```bash
cargo bench --bench performance
cargo bench --bench memory
cargo bench --bench performance --features log
cargo bench --bench memory --features log
```

Reports are written under `target/bench-results/`.

## Limitations

The current crate should be adopted with the following limits in mind:

- the encrypted log construction is custom and not externally audited
- `with_timing_normalization_async()` blocks the current executor thread
- the crate optimizes for surface reduction, not for ergonomic integration with common Rust error stacks
- borrowed static strings remain recoverable from the compiled binary
- the crate does not hide work performed before `AgentError` is created

## Related Documents

- [Security Policy](SECURITY.md)
- [Error Code Governance Contract](ERROR_GOVERNANCE.md)
- [Performance and Allocation Notes](BENCH_AVG.md)
- [Examples](examples/README.md)
