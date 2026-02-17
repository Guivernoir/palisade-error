# Security Policy

**Version:** 1.0.0
**Last Updated:** February 17, 2026

---

## Threat Model

`palisade-errors` is designed to operate in hostile environments where attackers may have:

1. **Source Code Access:** Attackers know the internal error logic and can read this repository.
2. **Trigger Capability:** Attackers can intentionally trigger errors to fingerprint the system.
3. **Message Collection:** Attackers aggregate error messages to map internal architecture.
4. **Memory Scraping:** Attackers may attempt to read process memory after a compromise (e.g., via core dumps or debugger attachment).
5. **Timing Analysis:** Attackers measure response times to infer code paths.
6. **Log Exfiltration:** Sophisticated attackers may compromise log aggregation infrastructure.

This library is built for **honeypot systems** where EVERY error is intelligence that attackers will analyze.

---

## Core Security Architecture

### Two-Layer Error Model

The library provides two complementary error types that share the same security philosophy:

**`AgentError`** is the primary operational error type. It holds subsystem-specific context and wraps the legacy `InternalLog` access pattern. Obfuscation and constant-time enforcement are applied automatically at construction.

**`DualContextError`** is the newer deception-native error type. It uses distinct wrapper types for public and internal context — `PublicContext` and `InternalContext` — that cannot be confused at compile time. Each has its own `Display` implementation with deliberate information policies:

- `PublicContext::Display` renders only the intended external string (which may be a lie).
- `InternalContext::Display` always emits `[INTERNAL CONTEXT REDACTED]` regardless of content. Internal data is accessed via `payload()` or `expose_sensitive()` only.

### Design Guarantees

- **Sanitization:** `AgentError::Display` and `DualContextError::Display` never leak internal state, file paths, or variable values. External output format is fixed: `{Category} operation failed [{permanence}] ({ERROR-CODE})` for `AgentError`, or the public context string for `DualContextError`.
- **Type-Enforced Trust Boundaries:** No implicit conversion exists between `PublicContext` and `InternalContext`. The type system prevents accidental cross-boundary leakage at compile time.
- **Ephemerality:** Sensitive data lives in `ZeroizeOnDrop` wrappers. Secrets are wiped from memory when the error is dropped.
- **Volatile Write Protection:** `InternalContextField::Sensitive` variants receive `ptr::write_volatile` treatment in `Drop` to defeat LLVM dead-store elimination, followed by a `compiler_fence(SeqCst)` to prevent instruction reordering. This provides best-effort defense against compiler-level optimizations that could remove the clearing operation.
- **DoS Resistance:** All log formatting is bounded. `InternalLog` fields are truncated at 1024 characters. Convenience macro arguments must be wrapped in `sanitized!()` which truncates at 256 characters and neutralizes control characters.
- **Timing Resistance:** All `AgentError` construction enforces a 1 µs constant-time floor via spin loop. `with_timing_normalization()` and `with_timing_normalization_async()` extend this for sensitive operation windows.
- **Memory Protection:** All context fields are zeroized on drop. The `Drop` implementation on `AgentError` is marked `#[inline(never)]` and uses `catch_unwind` to ensure cleanup runs even during panics.
- **Error Code Obfuscation:** Session salts are applied at construction time. The same semantic error yields different codes across sessions, defeating fingerprint mapping.

---

## What This Library Protects Against

### ✅ Information Disclosure via Error Messages

**Attack:** Attacker triggers errors to learn about system internals.

**Protection:** External errors use a fixed format regardless of failure reason. Neither `AgentError::Display` nor `DualContextError::Display` can emit operation names, file paths, or internal state. `DualContextError` goes further: the adversary receives an explicitly crafted deceptive message.

- **External:** `I/O operation failed [permanent] (E-IO-805)`
- **Hidden:** File path, error kind, internal state, actual operation name.

### ✅ Deception Narrative Integrity

**Attack:** Attacker correlates error codes or messages across sessions to build an internal map.

**Protection:** Session-specific error code obfuscation applies a salt at construction time. The same logical error produces `E-CFG-103` in one session and `E-CFG-107` in another. Attacker cannot correlate codes without compromising the session salt.

The `DualContextError::with_double_lie()` constructor provides an additional layer for environments where even internal logs may be exfiltrated: both external and internal contexts contain intentionally false narratives, with the internal lie clearly marked `[LIE]` for SOC analyst awareness.

### ✅ Memory Forensics After Compromise

**Attack:** Attacker dumps memory after breach to recover credentials, paths, or session tokens.

**Protection:** Three-layer defense on sensitive data:

1. **High-level zeroization:** `zeroize` crate clears owned `String` buffers.
2. **Volatile writes:** `ptr::write_volatile` over the raw buffer bytes prevents LLVM from removing the clearing operation as a dead store.
3. **Compiler fence:** `compiler_fence(SeqCst)` ensures zeroization instructions complete before the drop chain continues.

**What this does NOT guarantee:**

- Hardware cache visibility — compiler fences do not flush CPU caches.
- Cross-thread guarantees — other threads may observe old values in their caches.
- Allocator-level security — memory may be reallocated before physical clearing.
- DMA or swap — OS/hardware may have copied data before zeroization.

For cryptographic key material requiring HSM-grade wiping, use platform-specific APIs (`mlock`, `SecureZeroMemory`) and dedicated secure allocators in addition to this library.

### ✅ Timing-Based User Enumeration

**Attack:** Attacker measures response time to determine if a username exists, a path is valid, or a permission check took a different code path.

**Protection:**

- All `AgentError` construction enforces a 1 µs constant-time floor via spin loop.
- `with_timing_normalization(Duration)` adds a deadline-based delay on the error path to equalize timing across divergent code paths.
- `with_timing_normalization_async(Duration).await` provides the same without blocking the executor thread (requires `tokio` or `async_std` feature).

Limitations: OS scheduling introduces 1–15 ms jitter. Network timing, cache behavior, and database queries are not covered. This is defense-in-depth, not a complete solution.

### ✅ DoS via Massive Error Messages

**Attack:** Attacker triggers errors with enormous payloads to exhaust memory during log formatting.

**Protection:**

- `InternalLog::write_to()` truncates all fields at 1024 bytes, appending `...[TRUNCATED]`. UTF-8 boundaries are respected; pathological inputs fall back to the truncation indicator only.
- `sanitized!()` macro truncates at 256 characters and neutralizes control characters before they enter the error context.
- `RingBufferLogger` provides a hard memory ceiling for forensic log storage. Total memory is bounded at construction time by `capacity × max_entry_bytes`. Oldest entries are evicted FIFO under any write volume.

### ✅ Accidental Sensitive Data Exposure

**Attack (internal):** Developer accidentally includes sensitive data in a public log path or formats an `InternalContext` into an HTTP response.

**Protection:**

- `InternalContext::Display` always returns `[INTERNAL CONTEXT REDACTED]`. It is impossible to accidentally emit internal context through `format!("{}", ctx)`.
- `Sensitive` variant of `InternalContext` requires a `SocAccess` capability token to access raw content. The token cannot be acquired accidentally — it requires explicit `SocAccess::acquire()` call.
- The `external_signaling` feature gate makes `PublicContext::truth()` unavailable by default. Without enabling the feature, the compiler rejects any attempt to emit truthful public messages, enforcing honeypot-first deception policy at compile time.

### ✅ Compile-Time Taxonomy Drift

**Attack (internal):** Developer creates an error code with a semantically wrong namespace/category pair, causing operational confusion or accidental information disclosure.

**Protection:** `ErrorCode::const_new()` validates namespace–category compatibility and impact authority at compile time. Violations are compile errors in const contexts. The `strict_taxonomy` feature tightens this to reject all permissive fallbacks in CI.

---

## Capability-Based Access Control

Sensitive internal context requires a `SocAccess` capability token:

```rust
let access = SocAccess::acquire();
if let Some(raw) = context.expose_sensitive(&access) {
    send_to_encrypted_soc_siem(raw);
}
```

This is **not cryptographic** — an attacker with code execution can trivially construct `SocAccess::acquire()`. The purpose is **organizational process safety**:

1. Forces explicit privilege acquisition (cannot call accidentally via generic trait).
2. Makes sensitive data access grep-able: `grep -r "SocAccess::acquire"` shows every access point.
3. Provides a clean integration point for future RBAC or audit hook systems.
4. Prevents `format!("{}", internal_context)` from leaking anything useful.

All calls to `SocAccess::acquire()` should be wrapped in audit logging at the application level.

---

## Performance Validation

Security mechanisms are validated using high-fidelity benchmarks on constrained hardware to ensure they do not introduce denial-of-service vectors or side-channels of their own.

👉 **See [BENCH_AVG.md](BENCH_AVG.md) for detailed analysis of timing normalization, memory efficiency, obfuscation overhead, and burst handling.**

---

## Error Code Governance

Strict governance of error codes and namespaces is critical to preventing information leakage through taxonomy drift.

👉 **See [ERROR_GOVERNANCE.md](ERROR_GOVERNANCE.md) for namespace authority models, strict taxonomy features, and CI requirements.**

---

## What This Library Does NOT Protect Against

### ❌ Application-Level Vulnerabilities

This library handles errors; it does not prevent them. You must still validate inputs against SQL injection, XSS, and command injection at the application layer.

### ❌ Network-Level Attacks

This library does not prevent DDoS or packet sniffing.

### ❌ CPU-Level Side Channels

While timing normalization addresses application logic paths, we do not protect against micro-architectural attacks such as Spectre or Meltdown.

### ❌ Allocator-Level Memory Persistence

Volatile writes and zeroization operate on the string buffer itself. Memory freed to the allocator may be held in allocator-internal structures before returning to the OS. For keys and credentials that require guaranteed physical clearing, use `mlock` and platform-specific secure allocators.

### ❌ Compiler-Enforced Secrets Across FFI Boundaries

Sensitive `Cow::Borrowed` values (static string references) are not zeroized — static strings live in the binary. Do not use `&'static str` for runtime secrets.

---

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in `palisade_errors`, please do **NOT** open a public issue.

### Private Disclosure

**Email:** `strukturaenterprise@gmail.com`
**Subject:** `[SECURITY] Vulnerability in palisade_errors`

### What to Include

1. **Description:** What is vulnerable and why.
2. **Impact:** What could an attacker do with this.
3. **Steps to Reproduce:** Ideally, a proof-of-concept.
4. **Proposed Fix:** If you have ideas.

### Scope

**In scope:**
- Information disclosure via error messages or internal context leakage.
- Memory leaks that bypass zeroization or volatile write protection.
- DoS via unbounded allocations.
- Timing side-channels in error handling logic.
- Bypasses of the `SocAccess` capability model.
- Taxonomy violations that reach external output.

**Out of scope:**
- Vulnerabilities in example code only.
- Issues in upstream dependencies.
- Theoretical attacks without practical exploit paths.
- Hardware-level attacks (Spectre, Meltdown, cache timing).