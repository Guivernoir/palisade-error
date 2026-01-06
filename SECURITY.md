# Security Policy

## Threat Model

### Assumptions

**Palisade Errors** is designed for security-sensitive systems where we assume attackers:

1. **Have source code access**: Open-source means adversaries know the implementation
2. **Can trigger errors intentionally**: Malformed inputs, permission errors, resource exhaustion
3. **Collect error outputs**: External error messages, timing, resource usage patterns
4. **May achieve post-compromise access**: Memory dumps, core files, swap space
5. **Use error patterns for fingerprinting**: Map internal architecture through error analysis

### Security Guarantees

✅ **What We Protect:**

- File paths never appear in external errors
- Usernames, credentials, tokens never in `Display` output
- Validation logic not revealed through error messages
- All context data cryptographically zeroized on drop
- Internal architecture not exposed through error categories

❌ **What We Don't Protect:**

- Timing side channels (errors may take different time to construct)
- Error code enumeration (attacker can trigger all codes)
- Memory access patterns (cache-timing attacks on error handling)
- Compiler optimizations that might skip zeroization (use `volatile` writes if needed)

### Threat Scenarios

#### Scenario 1: Reconnaissance via Error Messages

**Attack**: Send malformed configuration with path traversal

```
POST /api/config { "path": "../../../etc/passwd" }
```

**Without Palisade**:

```
Error: Failed to read '../../../etc/passwd': No such file or directory
```

☠️ Attacker learns: filesystem structure, path validation, error types

**With Palisade**:

```
Configuration operation failed [permanent] (E-CFG-103)
```

✅ Attacker learns: operation category, error is permanent

**Internal Log** (access-controlled):

```
[E-CFG-103] operation='load_config' details='Invalid path'
sensitive='../../../etc/passwd'
```

#### Scenario 2: Post-Compromise Memory Scraping

**Attack**: After gaining access, attacker dumps process memory searching for:

- API keys from past error contexts
- File paths revealing system topology
- Usernames and session IDs from validation errors

**Protection**: All `ErrorContext` fields implement `ZeroizeOnDrop`. When errors are dropped:

```rust
impl Drop for ErrorContext {
    fn drop(&mut self) {
        self.zeroize();  // Cryptographic overwrite
    }
}
```

Memory contents are overwritten with zeros before deallocation.

#### Scenario 3: Error Code Correlation Attack

**Attack**: Trigger errors across multiple endpoints, correlate error codes to map architecture

**Example Attack Flow**:

1. POST /api/deploy → E-DCP-200 (Deployment)
2. POST /api/config → E-CFG-100 (Configuration)
3. GET /api/metrics → E-TEL-302 (Telemetry)

**Result**: Attacker maps subsystems without gaining access

**Mitigation**: Error codes are intentionally namespace-based. We accept this tradeoff because:

- Operational benefits outweigh disclosure risk
- Codes enable tracking without revealing implementation
- Alternative (random codes) breaks debuggability

## Vulnerability Reporting

### Reporting Process

**DO NOT** open public GitHub issues for security vulnerabilities.

**Please report security issues to**: `strukturaenterprise@gmail.com`

Include:

1. **Vulnerability description**: What's the issue?
2. **Affected versions**: Which releases are impacted?
3. **Attack scenario**: How would an attacker exploit this?
4. **Proof of concept**: Code demonstrating the vulnerability
5. **Suggested mitigation**: If you have ideas for fixes

### Response Timeline

- **24 hours**: Initial response acknowledging receipt
- **72 hours**: Preliminary assessment of severity and impact
- **7 days**: Proposed fix or mitigation strategy
- **30 days**: Coordinated disclosure (or earlier if critical)

### Severity Classification

| Severity     | Description                                   | Example                                      |
| ------------ | --------------------------------------------- | -------------------------------------------- |
| **Critical** | Information disclosure of credentials/secrets | Sensitive data in `Display` output           |
| **High**     | Bypass of security boundaries                 | Zeroization not occurring                    |
| **Medium**   | Side-channel information leakage              | Timing attacks revealing internal state      |
| **Low**      | DoS via error handling                        | Memory exhaustion through unbounded metadata |

## Security Best Practices

### For Library Users

#### ✅ DO

```rust
// Keep internal logs in secure storage
err.with_internal_log(|log| {
    secure_audit_log.write(log);  // Access-controlled logging
});

// Use error codes for tracking
let code = err.code();
metrics.record_error(code.namespace(), code.code());

// Mark errors retryable appropriately
AgentError::telemetry(code, op, msg)
    .with_retry()  // Transient failures only
```

#### ❌ DON'T

```rust
// Never log errors to untrusted outputs
println!("{:?}", err);  // Even Debug is redacted, but still...

// Never store errors long-term
static LAST_ERROR: Mutex<Option<AgentError>> = ...;  // NO!

// Never serialize errors to external systems
serde_json::to_string(&err)  // We don't impl Serialize intentionally

// Never use format! on sensitive data
let msg = format!("Failed for {}", username);  // Use .with_sensitive()
```

### For Contributors

#### Code Review Checklist

Before accepting PRs, verify:

- [ ] No sensitive data in `Display` impl
- [ ] All new fields are zeroized on drop
- [ ] No `Clone` on types containing sensitive data (or explicit tracking)
- [ ] Lifetimes prevent escaped references to internal data
- [ ] No allocations that bypass zeroization
- [ ] Tests verify external output is sanitized
- [ ] Documentation warns about security implications

#### Testing Requirements

Security-sensitive changes must include:

```rust
#[test]
fn test_no_sensitive_leakage() {
    let err = AgentError::config_sensitive(
        codes::CFG_PARSE_FAILED,
        "test",
        "public details",
        "SECRET_VALUE"
    );

    let external = err.to_string();
    assert!(!external.contains("SECRET_VALUE"));
}

#[test]
fn test_zeroization_on_drop() {
    let err = create_error_with_sensitive("secret123");
    drop(err);
    // Memory inspection would show zeros (hard to test in Rust)
    // This is enforced by ZeroizeOnDrop derive
}
```

## Feature Flag Security

### `trusted_debug`

**⚠️ DANGER**: Exposes all sensitive context in debug output

**Safe for**:

- Local development with trusted data
- Secure CI/CD pipelines
- Controlled debugging sessions

**NEVER use in**:

- Production
- Shared development environments
- Automated systems with untrusted inputs
- Any system with external log aggregation

**Detection**:

```rust
#[cfg(feature = "trusted_debug")]
compile_error!("trusted_debug enabled in release build!");
```

Add this to your build.rs to prevent accidental production use.

### `external_signaling`

Currently reserved for future capabilities. When implemented:

- Allows selective field exposure in sanitized outputs
- Maintains security invariant: only explicitly public data escapes
- Requires careful review of what's marked `Public`

## Cryptographic Guarantees

### Zeroization

We use the [`zeroize`](https://crates.io/crates/zeroize) crate which provides:

- **Volatile writes**: Prevents compiler optimization from removing overwrites
- **Memory fencing**: Ensures zeroization completes before deallocation
- **Derived implementations**: Automatic recursive zeroization

**Limitations**:

- Doesn't protect against sophisticated physical attacks (DMA, cold boot)
- Doesn't clear CPU registers or caches
- Doesn't protect data in transit (network, IPC)

For defense-in-depth:

- Use encrypted swap/hibernation
- Enable memory protection features (ASLR, DEP)
- Use secure enclaves (SGX, SEV) for highest sensitivity

## Compliance Considerations

### GDPR (General Data Protection Regulation)

- ✅ **Right to erasure**: Zeroization supports data deletion requirements
- ✅ **Data minimization**: External errors contain minimal information
- ✅ **Purpose limitation**: Context separated by sensitivity level
- ⚠️ **Audit trail**: Internal logs must be properly secured

### SOC 2 / ISO 27001

- ✅ **Security logging**: Structured internal logs support audit requirements
- ✅ **Incident response**: Error codes enable tracking and correlation
- ✅ **Access control**: Internal/external separation enforces least privilege
- ⚠️ **Log retention**: Implement proper retention policies for internal logs

### PCI DSS (Payment Card Industry)

- ✅ **No cardholder data in errors**: Never pass PCI data to error constructors
- ✅ **Secure logging**: Internal logs can meet audit log requirements if properly secured
- ⚠️ **Requirement 10**: Ensure internal logs include required audit fields

## Known Limitations

### 1. Metadata Ordering

Metadata is stored in a `Vec` and order is preserved, but external iteration order is not guaranteed across versions. Don't rely on metadata order for security decisions.

### 2. Error Code Exhaustion

With 999 codes per namespace, it's possible (though unlikely) to exhaust codes in a large system. Plan namespace allocation carefully.

### 3. No Async Context Tracking

Error lifetimes don't track async context. Be cautious with:

```rust
let err = create_error();
let log = err.internal_log();
tokio::spawn(async move {
    // log is moved to async context
    // This compiles but is semantically questionable
});
```

### 4. Clone Creates Unzeroized Copies

`ErrorContext` derives `Clone`. Each clone creates a separate copy that must be dropped independently. In highly sensitive contexts, consider removing `Clone` or implementing a clone registry.

## Version Support

| Version | Supported | Notes                             |
| ------- | --------- | --------------------------------- |
| 0.1.x   | ✅ Yes    | Current release                   |
| < 0.1   | ❌ No     | Pre-release, not production-ready |

We will maintain security updates for the current major version only.

## Acknowledgments

This security policy was inspired by:

- [Ring's Security Policy](https://github.com/briansmith/ring/blob/main/SECURITY.md)
- [RustCrypto Security Practices](https://github.com/RustCrypto/meta/blob/master/SECURITY.md)
- OWASP Secure Coding Practices

## Contact

- **Security Email**: strukturaenterprise@gmail.com
- **PGP Key**: _(To be added)_
- **Response Time**: Within 24 hours for critical issues

---

**Remember**: Perfect security doesn't exist, but we can make attacks expensive enough that attackers move on to easier targets.
