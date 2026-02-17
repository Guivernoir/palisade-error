# Error Code Governance Contract

**Version**: 1.1
**Status**: Active
**Last Updated**: 2026-02-17

This document defines the governance contract for the error code system and the dual-context deception model. Changes to governance rules require explicit review and version increment.

---

## Core Principles

### 1. Identity vs. Metadata (Immutable)

**Identity Layer** (frozen at compile time):
- `ErrorCode` — complete error specification
- `ErrorNamespace` — namespace classification

Both are **non-Copy, non-Clone, non-constructable at runtime**. The `ErrorNamespace` private field `_private: ()` enforces this at the type level.

**Metadata Layer** (Copy-enabled):
- `ImpactScore` — validated severity value (0–1000)
- `ErrorImpact` — impact level enum
- `OperationCategory` — operation classification

These are **Copy** for ergonomic use in defensive code. No governance risk from their duplication.

**Rule**: Identity types cannot be duplicated or moved after const initialization. All usage is by reference.

---

### 2. Dual-Context Deception Model

The library provides two complementary error types. Both obey the same external sanitization contract; they differ in how context is structured.

#### `AgentError` (Operational)

Uses a flat `ErrorContext` internally, exposed via the `InternalLog<'a>` accessor pattern. Context fields are zeroized on drop. The external `Display` format is:

```
{Category} operation failed [{permanence}] ({E-NS-CODE})
```

This format is fixed and cannot leak internal details.

#### `DualContextError` (Deception-Native)

Uses two explicitly typed context wrappers:

| Type | Purpose | Display Behavior |
|---|---|---|
| `PublicContext` | External-facing message | Renders the wrapped string directly |
| `InternalContext` | SOC-only diagnostic data | Always emits `[INTERNAL CONTEXT REDACTED]` |

These types cannot be confused at compile time. No implicit conversion between them exists.

#### `InternalContext` Classification

| Variant | Constructor | `payload()` | `expose_sensitive()` |
|---|---|---|---|
| `Diagnostic` | `InternalContext::diagnostic()` | `Some(Truth(_))` | `None` |
| `Sensitive` | `InternalContext::sensitive()` | `None` | `Some(&str)` (requires `SocAccess`) |
| `Lie` | `InternalContext::lie()` | `Some(Lie(_))` (prefixed `[LIE]`) | `None` |

**Sensitive** variants receive additional protection: `ptr::write_volatile` byte-by-byte clearing in `Drop`, followed by `compiler_fence(SeqCst)`, to defeat LLVM dead-store elimination.

#### `PublicContext` Classification

| Variant | Constructor | Availability |
|---|---|---|
| `Lie` | `PublicContext::lie()` | Always |
| `Truth` | `PublicContext::truth()` | Only with `external_signaling` feature |

Without `external_signaling`, the compiler rejects any attempt to construct `PublicContext::truth()`. This enforces deception-only external output at compile time rather than runtime policy.

#### `DualContextError` Constructor Invariants

| Constructor | Public | Internal | Invariant |
|---|---|---|---|
| `with_lie()` | `Lie` | `Diagnostic` | Default honeypot pattern |
| `with_lie_and_sensitive()` | `Lie` | `Sensitive` | Requires `SocAccess` for raw access |
| `with_truth()` | `Truth` | `Diagnostic` | Feature-gated. No internal lies when external is truthful. |
| `with_double_lie()` | `Lie` | `Lie` | For log-exfiltration scenarios. Internal marked `[LIE]`. |

---

### 3. Capability-Based Sensitive Access (`SocAccess`)

Access to `Sensitive`-classified `InternalContext` content requires a `SocAccess` capability token:

```rust
let access = SocAccess::acquire();
if let Some(raw) = context.expose_sensitive(&access) {
    send_to_encrypted_soc_siem(raw);
}
```

**Purpose:** Organizational safety, not cryptographic protection.

1. Makes sensitive data access grep-able across the entire codebase.
2. Prevents accidental exposure via generic `format!("{}", ctx)` — which always emits `[INTERNAL CONTEXT REDACTED]`.
3. Provides a clean integration point for future RBAC or audit hook systems.

**Rule:** All calls to `SocAccess::acquire()` should be wrapped in application-level audit logging.

---

### 4. Namespace Authority Model

Each namespace has **const authority flags** determining permitted operations:

```rust
pub const CORE: ErrorNamespace = ErrorNamespace::__internal_new("CORE", true);
//                                                                       ^^^^ can_breach flag
```

**Current Authority Mapping:**

| Namespace | `can_breach` | Rationale |
|---|---|---|
| CORE | `true` | Fundamental failures may indicate system compromise |
| CFG | `false` | Configuration errors do not reach Breach severity |
| DCP | `true` | Deception compromise = security breach by definition |
| TEL | `false` | Telemetry is low-risk |
| COR | `false` | Correlation engine is analytical |
| RSP | `false` | Response execution (may need elevation in future) |
| LOG | `false` | Logging is low-risk |
| PLT | `false` | Platform ops (may need elevation in future) |
| IO | `false` | File/network I/O is not directly breach-capable |

**Evolution Path:** Authority flags can be modified to reflect architectural changes without rewriting policy logic. When RSP gains command execution, set `can_breach = true`. No policy code changes required.

---

### 5. Taxonomy Enforcement Modes

#### Default Mode (Permissive)

CORE, CFG, COR, RSP, PLT accept any category. Allows operational flexibility during taxonomy stabilization.

#### Strict Taxonomy Mode (`feature = "strict_taxonomy"`)

All namespaces enforce explicit category mappings. Violations are compile-time errors in const contexts.

**Must be enabled in CI builds.**

#### Strict Severity Mode (`feature = "strict_severity"`)

Breach-level impacts (951–1000) restricted to namespaces with `can_breach = true`. Optional hardening feature. Recommended for production.

#### External Signaling Mode (`feature = "external_signaling"`)

Enables `PublicContext::truth()` and `DualContextError::with_truth()`. Without this feature, the compiler rejects any truthful external output. This enforces honeypot-first deception policy at compile time.

**Default: disabled.** Only enable if your deployment scenario requires occasional truthful external signals for authenticity.

---

### 6. Construction API Contract

**Two APIs, two guarantees:**

| API | Use Case | Failure Mode | Context |
|---|---|---|---|
| `const_new` | Const statics | Panic (compile error in const) | Programmer error |
| `checked_new` | Runtime construction | `Result<T, InternalErrorCodeViolation>` | Environment/config error |

**Rules:**
- Use `const_new` for error codes defined in source files.
- Use `checked_new` for error codes from config, plugins, or untrusted sources.
- Never use `const_new` with runtime values.
- When exposing `checked_new` errors externally, call `.to_public()` on the violation to strip taxonomy details.

---

## What is Allowed to Change

### ✅ Safe Changes (No Review Required)

1. **Adding new namespaces** — add const to `namespaces` module, set authority flags, update this document.
2. **Modifying authority flags** — change `can_breach` values, add new authority dimensions.
3. **Refining category policies** — adjust `category_policy` module; keep changes localized.
4. **Adding impact score ranges** — modify `ErrorImpact::from_score` boundaries; **must add corresponding boundary tests**.
5. **Adding `DualContextError` constructor variants** — new semantic patterns following the public/internal contract.
6. **Expanding `OperationCategory`** — new categories must include both `display_name()` and `deceptive_name()` implementations.

### ⚠️ Changes Requiring Review

1. **Changing identity semantics** — making identity types Copy/Clone, allowing runtime namespace construction, weakening governance guarantees.
2. **Breaking const initialization** — removing `const_new`, making validation non-const, breaking macro compatibility.
3. **Exposing internal violations externally** — removing `.to_public()` sanitization, making `InternalErrorCodeViolation` public API, leaking taxonomy details.
4. **Modifying `SocAccess`** — changing access control semantics, making it constructable without explicit call, or removing the capability token pattern.
5. **Enabling `external_signaling` by default** — changes the default deception policy.

### 🚫 Forbidden Changes

1. **Making `ErrorNamespace` constructable at runtime** — the `_private` field must remain; no public constructors allowed.
2. **Removing zero-allocation guarantees** — `Display` must write directly to formatter; no intermediate heap allocations in identity types.
3. **Weakening attacker observability control** — external error codes must remain `E-XXX-YYY` format; internal details must not leak to external contexts; `.to_public()` must remain taxonomy-sanitized.
4. **Removing volatile write protection on Sensitive drop** — the `ptr::write_volatile` loop and `compiler_fence` in `InternalContextField::drop()` must not be removed.
5. **Making `InternalContext::Display` emit actual content** — it must always return `[INTERNAL CONTEXT REDACTED]` regardless of variant.

---

## Security Boundaries

### Trust Boundary: Internal vs. External

**Internal Context** (authenticated SOC access):
- Full `InternalErrorCodeViolation` details
- Complete namespace and category information
- Impact scores and authority models
- `InternalContext::payload()` data
- `InternalContext::expose_sensitive()` data (requires `SocAccess`)
- `DualContextError::internal()` accessor

**External Context** (attacker-observable):
- Error code format: `E-XXX-YYY` only (obfuscated per session)
- Generic operation category name (honeypot categories masked as "Routine Operation")
- `DualContextError::external_message()` — the public lie or truth string
- No namespace restrictions revealed
- No authority model disclosed

**Enforcement:**
```rust
// WRONG — leaks taxonomy details
return Err(violation);

// RIGHT — sanitized for external consumption
return Err(violation.to_public().into());
```

```rust
// WRONG — InternalContext formatted via Display leaks nothing, but is misleading
let msg = format!("{}", err.internal());  // always "[INTERNAL CONTEXT REDACTED]"

// RIGHT — explicit accessor
if let Some(payload) = err.internal().payload() {
    soc_logger.write(format!("{}", payload));
}
```

---

## CI/CD Requirements

### Mandatory Checks

1. **Strict Taxonomy in CI:**
   ```bash
   cargo test --features strict_taxonomy
   cargo build --features strict_taxonomy
   ```
   All CI builds **must** enable `strict_taxonomy` to prevent namespace/category drift.

2. **Impact Boundary Tests** — all tests in the "Impact Boundary Tests" section must pass; adding impact levels requires corresponding boundary tests.

3. **Dual-Mode Testing:**
   ```bash
   cargo test                            # permissive mode
   cargo test --features strict_taxonomy # strict mode
   ```

4. **External Signaling Gate:**
   ```bash
   cargo test                                    # deception-only mode (default)
   cargo test --features external_signaling      # with truth constructors available
   ```
   Tests must verify that without the feature, `PublicContext::truth()` is unavailable.

### Optional Checks

1. **Strict Severity in Production:**
   ```bash
   cargo build --release --features strict_severity
   ```

2. **Full Security Surface:**
   ```bash
   cargo build --release --features strict_taxonomy,strict_severity
   ```

---

## Migration Guide

### From `AgentError` to `DualContextError`

For new honeypot-specific code, prefer `DualContextError` for explicit deception control:

```rust
// Old pattern
let err = AgentError::config(CFG_VALIDATION_FAILED, "auth", "Invalid credentials");

// New pattern — explicit deception, type-safe trust boundary
let err = DualContextError::with_lie(
    "Service unavailable",
    "Authentication failed: invalid credential hash for user_id=7429",
    OperationCategory::Configuration,
);
```

The `AgentError` pattern remains fully supported and is preferred when you do not need explicit deceptive narrative control.

### From Unrestricted to Strict Taxonomy

When enabling `strict_taxonomy`:

1. **Audit existing error codes:**
   ```bash
   grep -r "define_error_codes" src/
   ```

2. **Fix category mismatches per namespace:**
   - CORE → System only
   - CFG → Configuration only
   - COR → Analysis only
   - RSP → Response only
   - PLT → System / IO only
   - DCP → Deception / Detection / Containment / Deployment

3. **Test both modes:**
   ```bash
   cargo test                             # permissive
   cargo test --features strict_taxonomy  # strict
   ```

4. **Enable in CI:** Start with warnings, escalate to errors after cleanup.

---

## Architectural Evolution

### Adding Breach Authority to a Namespace

Example: RSP gains command execution capability.

**Steps:**

1. Update namespace definition:
   ```rust
   pub const RSP: ErrorNamespace = ErrorNamespace::__internal_new("RSP", true);
   //                                                                      ^^^^ was false
   ```

2. Update the Authority Mapping table in this document.

3. Audit existing RSP error codes with `impact >= 951`.

4. Add tests for new authority under `strict_severity`.

No policy code changes required — authority is flag-based.

### Adding a New Deception Scenario Constructor

When a new invariant pattern is needed on `DualContextError`:

1. Define the public/internal semantics.
2. Add a `pub fn` constructor to `DualContextError` that enforces those semantics via `PublicContext` and `InternalContext` types.
3. Document the invariant in the `DualContextError` rustdoc.
4. Update the Constructor Invariants table in this document.
5. Add integration tests covering both the happy path and boundary conditions.

---

## Audit Trail

| Date | Change | Rationale |
|---|---|---|
| 2026-02-03 | v1.0 — Initial governance contract | Freeze taxonomy before organizational scaling |
| 2026-02-17 | v1.1 — Add DualContextError, SocAccess, external_signaling, ContextBuilder, volatile write protection | Reflect dual-context architecture and updated security model |

---

## Appendix: Quick Reference

### Namespace → Category Mappings (Strict Mode)

| Namespace | Permitted Categories | Authority |
|---|---|---|
| CORE | System | Breach |
| CFG | Configuration | No Breach |
| DCP | Deception, Detection, Containment, Deployment | Breach |
| TEL | Audit, Monitoring, System | No Breach |
| COR | Analysis | No Breach |
| RSP | Response | No Breach |
| LOG | Audit, Monitoring, System | No Breach |
| PLT | System, IO | No Breach |
| IO | Any except Deception / Detection / Containment | No Breach |

### Impact Score Ranges

| Score | Level | Semantics |
|---|---|---|
| 0–50 | Noise | Internal noise, no operational impact |
| 51–150 | Flaw | Minor visual discrepancy in deception layer |
| 151–300 | Jitter | Performance issues perceptible as lag |
| 301–450 | Glitch | Emulated feature fails to respond correctly |
| 451–600 | Suspicion | Logic inconsistency may identify the trap |
| 601–750 | Leak | Information disclosure / fingerprinting |
| 751–850 | Collapse | Total failure of service emulation |
| 851–950 | Escalation | Unintended lateral or vertical access |
| 951–1000 | **Breach** | Sandbox breakout risk |

### Maximum Recommended Impact per Namespace

| Namespace | Max Impact | Notes |
|---|---|---|
| CORE | 850 | Escalation only; no Breach without `strict_severity` override |
| CFG | 300 | Configuration failures are non-critical |
| DCP | 1000 | Full Breach authorized |
| TEL | 600 | Monitoring data may leak internally |
| COR | 600 | Analysis errors may expose correlation logic |
| RSP | 600 | Response failures contain at Escalation |
| LOG | 300 | Logging failures are low-risk |
| PLT | 500 | Platform issues stay below Suspicion |
| IO | 300 | I/O errors are non-critical |

### Feature Flag Matrix

| Feature | Default | CI Required | Production Recommended |
|---|---|---|---|
| `strict_taxonomy` | Off | **Yes** | Yes |
| `strict_severity` | Off | No | Yes |
| `external_signaling` | Off | Test both states | No (honeypot default) |
| `trusted_debug` | Off | No | **Never** |
| `tokio` / `async_std` | Off | If used | If async runtime present |

---

**End of Governance Contract**

This document is the authoritative source for error code system policy and dual-context deception model governance. Deviations require explicit approval and version increment.