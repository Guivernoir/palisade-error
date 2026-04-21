# Performance and Allocation Notes

## Abstract

This repository does not keep fixed benchmark numbers under version control. Performance and allocation measurements are machine-dependent and sensitive to operating system, CPU model, clock behavior, compiler version, enabled features, and benchmark harness configuration.

Accordingly, the supported benchmark practice is to generate fresh local reports and interpret them against design expectations rather than against stale committed numbers.

## Evaluation Scope

The benchmark suite is intended to answer three practical questions:

- does the public path remain allocation-free
- do timing floors remain observable in the intended scenarios
- does enabling optional logging preserve bounded behavior

## Reproducible Commands

```bash
cargo bench --bench performance
cargo bench --bench memory

# Optional logging-path coverage
cargo bench --bench performance --features log
cargo bench --bench memory --features log
```

## Report Location

Generated reports are written to:

- `target/bench-results/performance.txt`
- `target/bench-results/memory.txt`

## Report Contents

Each report records, per scenario:

- iteration count
- average latency
- minimum latency
- maximum latency
- allocations per iteration
- deallocations per iteration
- reallocations per iteration
- bytes allocated per iteration
- bytes deallocated per iteration
- bytes reallocated per iteration
- configured timing floor in nanoseconds
- timing-floor check result as `true` or `false`

## Expected Invariants

The design intent of the current crate implies the following expectations:

- ordinary `AgentError` construction and formatting should report zero heap allocations per iteration
- timing-oriented scenarios should respect the configured public floor
- the `log` scenario should remain bounded in memory use even when encrypted persistence is enabled

If a benchmark run violates one of these expectations, the result should be treated as a regression candidate, not as background noise.

## Interpretation Guidance

Benchmark numbers should be compared only within a clearly defined context:

- same machine class
- same Rust toolchain
- same feature set
- same benchmark harness inputs

Cross-machine numbers can still be useful for rough capacity planning, but they are not a strong basis for release claims.

## Recommended Release Practice

For production-facing releases, benchmark reports should be regenerated on hardware that resembles the intended deployment class. At minimum, maintainers should verify:

- no unexpected allocations appear on the public path
- timing floors are still met under the tested workload
- enabling `log` does not introduce unbounded behavior
