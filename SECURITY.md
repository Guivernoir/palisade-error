# Security Policy

## Abstract

This document defines the security posture, threat model, implemented controls, operational assumptions, and disclosure expectations for `palisade-errors`.

The crate is designed to reduce information leakage through error handling in hostile or deceptive environments. It is not a complete security boundary and should not be presented as one.

## Scope

This policy covers the crate's behavior in the following areas:

- public error construction and formatting
- fixed-capacity payload handling
- zeroization of inline and transient buffers
- timing normalization on public paths
- optional encrypted log persistence
- bounded in-process forensic retention

This policy does not cover the security of the surrounding application, operating system, deployment platform, or external log aggregation system.

## Threat Model

`palisade-errors` assumes attackers may:

1. trigger error paths repeatedly
2. observe externally formatted errors
3. compare response timing across requests
4. inspect crash dumps or residual memory after compromise
5. exfiltrate persisted log files

The crate is designed to reduce leakage under those conditions. It does not assume protection against kernel compromise, physical memory extraction, or hardware side-channel attacks.

## Security Objectives

The crate currently pursues the following objectives:

- minimize externally visible diagnostic detail
- keep the public path allocation-free
- zeroize sensitive inline and transient buffers where feasible
- constrain in-process forensic retention to a fixed bound
- persist logs only through an explicit opt-in feature
- reduce timing distinguishability across public error surfaces

## Implemented Controls

### External Formatting

- `Display` exposes only the external payload
- `Debug` exposes only the external payload unless `trusted_debug` is enabled
- unknown numeric codes collapse to a safe core fallback instead of panicking

### Memory and Allocation Discipline

- public payloads are stored in fixed-capacity inline buffers
- the default public path avoids heap allocation
- inline payload buffers are zeroized on overwrite and drop
- transient cryptographic buffers used by logging are explicitly zeroized

### Timing Behavior

- public construction, formatting, timing normalization, and optional log persistence use the crate-local `ct` module
- the current implementation enforces a minimum 50 us timing floor where applicable

Timing normalization should be understood as leakage reduction, not proof of constant-time execution under all compilers, CPUs, and schedulers.

### In-Process Forensics

- each `AgentError::new()` appends to a bounded ring buffer
- forensic retention is memory-bounded and overwrite-based
- the crate does not permit unbounded in-process error accumulation

## Logging Design

Encrypted file logging is disabled by default and available only behind `feature = "log"`.

When enabled, records are framed as:

- `len || outer_nonce || masked(inner_nonce || aes_gcm_ciphertext || tag) || mac`

The current construction uses:

- AES-256-GCM for the inner authenticated-encryption layer
- a SHA-512-derived masking stream for the outer layer
- HMAC-SHA512 over the final encrypted frame

Current hardening rules include:

- the log path must be absolute
- the log path must not be a symlink
- new Unix log files are created owner-private
- appends are followed by `sync_data()`
- control characters are sanitized before plaintext framing
- oversized records fail closed

## Residual Risks and Non-Goals

The crate does not guarantee the following:

- protection against kernel- or hardware-level memory disclosure
- secrecy of borrowed string literals compiled into the binary
- concealment of work performed before `AgentError` is constructed
- safety of persisted logs without surrounding operational controls
- compatibility with standardized secure-logging protocols

The current log construction is custom. It has test coverage and bounded behavior, but it should not be described as externally audited or standards-based cryptographic logging.

## Deployment Guidance

Production deployments should pair this crate with:

- rate limiting on attacker-reachable failure paths
- controlled crash-dump and core-dump policy
- explicit placement and retention policy for encrypted log files
- key-custody and live-memory access policy
- environment-specific validation of timing and performance assumptions

## Verification Expectations

Recommended release validation:

```bash
cargo fmt --all
cargo check --all-targets --all-features
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml
```

Recommended adversarial checks:

- fuzzing of display, timing, and log code paths
- benchmark validation on the target hardware class
- manual review of log-file placement and permission behavior on the deployment OS

## Disclosure

Please do not file public issues for potential security problems.

- Email: `strukturaenterprise@gmail.com`
- Subject: `[SECURITY] palisade-errors`

Include, when possible:

- affected version
- reproduction steps
- expected and observed behavior
- deployment assumptions relevant to the issue
