# Error Code Governance Contract

**Version**: 1.0  
**Status**: Frozen  
**Last Updated**: 2025-02-03

This document defines the immutable governance contract for the error code system. Changes to these rules require explicit review and versioning.

---

## Core Principles

### 1. Identity vs Metadata (Immutable)

**Identity Layer** (Frozen at compile time):
- `ErrorCode` - Complete error specification
- `ErrorNamespace` - Namespace classification
- Both are **non-Copy, non-Clone, non-constructable at runtime**

**Metadata Layer** (Copy-enabled):
- `ImpactScore` - Severity classification
- `ErrorImpact` - Impact level enum
- `OperationCategory` - Operation classification
- These are **Copy** for defensive programming convenience

**Rule**: Identity types cannot be duplicated or moved after const initialization. All usage is by reference.

---

### 2. Namespace Authority Model

Each namespace has **const authority flags** that determine permitted operations:

```rust
pub const CORE: ErrorNamespace = ErrorNamespace::__internal_new("CORE", true);
//                                                                name   ^^^ can_breach flag
```

**Current Authority Mapping**:
- **CORE**: `can_breach = true` (fundamental system failures)
- **CFG**: `can_breach = false` (configuration errors are not breaches)
- **DCP**: `can_breach = true` (deception compromise = security breach)
- **TEL**: `can_breach = false` (telemetry is low-risk)
- **COR**: `can_breach = false` (correlation engine is analytical)
- **RSP**: `can_breach = false` (response execution - may need elevation in future)
- **LOG**: `can_breach = false` (logging is low-risk)
- **PLT**: `can_breach = false` (platform ops - may need elevation in future)
- **IO**: `can_breach = false` (file/network I/O is not directly breach-capable)

**Evolution Path**: Authority flags can be modified to reflect architectural changes without rewriting policy logic. For example, if RSP gains command execution capabilities, its `can_breach` flag can be set to `true`.

---

### 3. Taxonomy Enforcement Modes

#### Default Mode (Permissive)
- CORE, CFG, COR, RSP, PLT accept any category
- Allows operational flexibility during taxonomy stabilization
- Use in development and early deployment

#### Strict Taxonomy Mode (`feature = "strict_taxonomy"`)
- All namespaces enforce explicit category mappings
- Prevents taxonomy drift and dumping-ground anti-patterns
- **MUST be enabled in CI builds**
- Violations are compile-time errors in const contexts

#### Strict Severity Mode (`feature = "strict_severity"`)
- Breach-level impacts (951-1000) restricted to namespaces with `can_breach = true`
- Prevents low-risk subsystems from critical classification
- Optional hardening feature
- Recommended for production deployments

---

### 4. Construction API Contract

**Two APIs, two guarantees**:

| API | Use Case | Failure Mode | Context |
|-----|----------|--------------|---------|
| `const_new` | Const statics | Panic (compile error in const) | Programmer error |
| `checked_new` | Runtime construction | `Result<T, E>` (never panics) | Environment error |

**Rule**: 
- Use `const_new` for error codes defined in source files
- Use `checked_new` for error codes from config, plugins, or untrusted sources
- Never use `const_new` with runtime values

---

## What is Allowed to Change

### ✅ Safe Changes (No Review Required)

1. **Adding new namespaces**
   - Add const to `namespaces` module
   - Set appropriate authority flags
   - Document in module-level comments

2. **Modifying authority flags**
   - Change `can_breach` values for namespaces
   - Add new authority dimensions if needed
   - Update this document

3. **Refining category policies**
   - Adjust category validation in `category_policy` module
   - Keep changes localized to policy functions

4. **Adding impact score ranges**
   - Modify `ErrorImpact::from_score` boundaries
   - Add new impact levels if needed
   - **MUST add corresponding boundary tests**

### ⚠️ Changes Requiring Review

1. **Changing identity semantics**
   - Making identity types Copy/Clone
   - Allowing runtime namespace construction
   - Weakening governance guarantees

2. **Breaking const initialization**
   - Removing `const_new`
   - Making validation non-const
   - Breaking macro compatibility

3. **Exposing internal violations externally**
   - Removing `.to_public()` sanitization
   - Making `InternalErrorCodeViolation` public API
   - Leaking taxonomy details across trust boundaries

### 🚫 Forbidden Changes

1. **Making `ErrorNamespace` constructable at runtime**
   - The `_private` field MUST remain
   - No public constructors allowed
   - Namespaces are compile-time only

2. **Removing zero-allocation guarantees**
   - Display must write directly to formatter
   - No intermediate heap allocations
   - Construction must be const-compatible

3. **Weakening attacker observability control**
   - External error codes MUST remain `E-XXX-YYY` format
   - Internal details MUST NOT leak to external contexts
   - `.to_public()` MUST remain taxonomy-sanitized

---

## Security Boundaries

### Trust Boundary: Internal vs External

**Internal Context** (authenticated SOC access):
- Full `InternalErrorCodeViolation` details
- Complete namespace and category information
- Impact scores and authority models
- Taxonomy policy details

**External Context** (attacker-observable):
- Error code format: `E-XXX-YYY` only
- Generic violation messages via `.to_public()`
- No namespace restrictions revealed
- No authority model disclosed

**Enforcement**:
```rust
// WRONG - leaks taxonomy
return Err(violation); 

// RIGHT - sanitized
return Err(violation.to_public().into());
```

---

## CI/CD Requirements

### Mandatory Checks

1. **Strict Taxonomy in CI**
   ```bash
   cargo test --features strict_taxonomy
   cargo build --features strict_taxonomy
   ```
   All CI builds MUST enable `strict_taxonomy` to prevent drift.

2. **Impact Boundary Tests**
   - All tests in "Impact Boundary Tests" section MUST pass
   - Adding impact levels requires corresponding boundary tests
   - Cross-boundary transition tests are mandatory

3. **Dual-Mode Testing**
   - Both permissive and strict modes MUST be tested
   - Tests MUST verify that strict mode actually rejects violations
   - Tests MUST verify that permissive mode actually allows flexibility

### Optional Checks

1. **Strict Severity in Production**
   ```bash
   cargo build --release --features strict_severity
   ```
   Recommended for production deployments.

---

## Migration Guide

### From Unrestricted to Strict Taxonomy

When enabling `strict_taxonomy`:

1. **Audit existing error codes**
   ```bash
   grep -r "define_error_code" | grep "CORE"
   ```

2. **Fix category mismatches**
   - CORE → System only
   - CFG → Configuration only
   - COR → Analysis only
   - RSP → Response only
   - PLT → System/IO only

3. **Test both modes**
   ```bash
   cargo test  # permissive
   cargo test --features strict_taxonomy  # strict
   ```

4. **Enable in CI gradually**
   - Start with warnings
   - Escalate to errors after cleanup

---

## Architectural Evolution

### Adding Breach Authority to a Namespace

Example: RSP gains command execution, needs Breach capability

**Steps**:
1. Update namespace definition:
   ```rust
   pub const RSP: ErrorNamespace = ErrorNamespace::__internal_new("RSP", true);
   //                                                                      ^^^^ was false
   ```

2. Update this document's authority mapping

3. Audit existing RSP error codes with impact >= 951

4. Add tests for new authority

**No policy code changes required** - authority is flag-based, not hardcoded.

---

## Audit Trail

| Date | Change | Rationale |
|------|--------|-----------|
| 2026-02-03 | Initial governance contract | Freeze taxonomy before organizational scaling |

---

## Appendix: Quick Reference

### Namespace → Category Mappings (Strict Mode)

| Namespace | Permitted Categories | Authority |
|-----------|---------------------|-----------|
| CORE | System | Breach |
| CFG | Configuration | No Breach |
| DCP | Deception, Detection, Containment, Deployment | Breach |
| TEL | Audit, Monitoring, System | No Breach |
| COR | Analysis | No Breach |
| RSP | Response | No Breach |
| LOG | Audit, Monitoring, System | No Breach |
| PLT | System, IO | No Breach |
| IO | Any except Deception/Detection/Containment | No Breach |

### Impact Score Ranges

| Score | Level | Semantics |
|-------|-------|-----------|
| 0-50 | Noise | Internal noise, no impact |
| 51-150 | Flaw | Minor visual discrepancy |
| 151-300 | Jitter | Performance issues |
| 301-450 | Glitch | Functional error |
| 451-600 | Suspicion | Logic inconsistency |
| 601-750 | Leak | Information disclosure |
| 751-850 | Collapse | Total failure of emulation |
| 851-950 | Escalation | Unintended access |
| 951-1000 | **Breach** | Sandbox breakout risk |

### Feature Flag Matrix

| Feature | Default | CI Required | Production Recommended |
|---------|---------|-------------|----------------------|
| `strict_taxonomy` | Off | **Yes** | Yes |
| `strict_severity` | Off | No | Yes |

---

**End of Governance Contract**

This document is the authoritative source for error code system policy. Deviations require explicit approval and versioning.