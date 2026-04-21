# Error Code Governance Contract

## Abstract

This document defines the stability and review rules for error identity, redaction, and public API scope in `palisade-errors`.

The intent of this contract is straightforward: error handling is part of the crate's security model. As a result, changes to code resolution, formatting, payload exposure, or allocation behavior must be treated as governed changes rather than ordinary refactors.

## Purpose

The governance model exists to preserve four invariants:

- callers interact with one stable public error type
- externally visible formatting remains tightly redacted
- internal error identity remains deterministic inside the crate
- public-path operational behavior stays bounded

## Public Contract

The supported public contract is intentionally small:

- downstream code constructs errors only through `AgentError::new(...)`
- timing normalization is available only through the two `AgentError` timing methods
- encrypted file logging is available only through `AgentError::log(...)` when `feature = "log"`

No error-code tables, namespace types, ring-buffer types, or context wrappers are part of the public API contract.

## Internal Identity Model

Error identity is represented internally through crate-private `ErrorCode` statics.

Each internal code carries:

- namespace
- numeric code
- operation category
- impact score

Callers supply only the numeric code. The crate resolves that number to an internal definition and then obfuscates it per process before it becomes part of an `AgentError`.

## Compatibility Rules

### Unknown Codes

Unknown numeric codes must never panic. They resolve to the safe core fallback:

- `CORE_INVALID_STATE` (`4`)

This behavior is part of the stability contract.

### Namespace Ownership

Namespaces remain crate-private and compile-time defined. Runtime namespace construction is not part of the supported contract.

### Feature Flags

Feature flags may tighten internal validation but do not expand the public API. The currently relevant governance-facing flags are:

- `strict_severity`
- `trusted_debug`
- `log`

## Redaction Rules

The formatting contract is fixed unless an intentional governance change is approved:

- `Display` may expose only the external payload
- `Debug` may expose only the external payload unless `trusted_debug` is enabled
- internal and sensitive payloads must not escape through default public formatting
- code, internal payload, and sensitive payload belong in explicit forensic paths, not in ordinary user-facing output

Any change that weakens these guarantees should be treated as a contract-level change.

## Storage and Allocation Rules

The expected public-path behavior is:

- fixed-capacity inline payload storage
- no public-path heap allocation in `new`, `Display`, `Debug`, timing normalization, or optional encrypted logging
- zeroization of inline payload buffers on overwrite and drop

Logging remains optional because it crosses an explicit filesystem boundary and therefore carries a different operational risk profile.

## Review-Required Changes

The following changes should trigger explicit design review:

- expanding the public surface beyond `AgentError`
- making `AgentError` `Clone` or `Copy`
- weakening redaction guarantees
- removing or materially reducing timing-floor enforcement from public methods
- reintroducing heap allocation into the default public path
- exposing internal code tables or namespace primitives publicly
- changing fallback behavior for unknown numeric codes
- replacing bounded storage with unbounded retention

## Release Checklist

Before a release that changes error semantics, reviewers should confirm:

- the public API surface is unchanged or intentionally versioned
- formatting tests still prove external-only default output
- allocation expectations still hold on the public path
- timing-floor behavior remains covered by tests and benchmarks
- optional logging rules remain explicit and documented
- unknown-code fallback behavior is unchanged unless intentionally revised

## Interpretation

When there is ambiguity between convenience and leakage resistance, this contract favors leakage resistance. When there is ambiguity between richer public diagnostics and a narrower stable surface, this contract favors a narrower stable surface.
