# Examples

## Abstract

The examples in this repository are intentionally small. Their purpose is to demonstrate the crate's operating model, not to serve as a full application framework.

## Example Set

- `basic_usage`: constructs and returns `AgentError` in a conventional application-style flow
- `timing_normalization`: demonstrates post-construction timing normalization
- `encrypted_logging`: demonstrates optional encrypted file persistence and therefore requires `feature = "log"`

## How to Run

```bash
cargo run --example basic_usage
cargo run --example timing_normalization
cargo run --example encrypted_logging --features log
```

## Reading the Examples

When evaluating the examples, focus on the following behaviors:

- the external payload is the default terminal-facing surface
- internal and sensitive payloads are retained for controlled forensic paths
- timing normalization is explicit rather than ambient
- encrypted log persistence is opt-in and feature-gated

For broader operational guidance, see the repository-level documents:

- [README](../README.md)
- [Security Policy](../SECURITY.md)
- [Error Code Governance Contract](../ERROR_GOVERNANCE.md)
