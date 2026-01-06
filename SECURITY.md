# Security Policy

## Threat Model

`palisade_errors` is designed to operate in hostile environments where attackers may have:

1.  **Source Code Access:** Attackers know the internal error logic.
2.  **Trigger Capability:** Attackers can intentionally trigger errors to fingerprint the system.
3.  **Memory Scraping:** Attackers may attempt to read process memory after a compromise (e.g., via core dumps or debugger attachment).

### Design Guarantees

- **Sanitization:** The `Display` trait implementation NEVER leaks internal state, file paths, or variable values.
- **Ephemerality:** Sensitive data is stored in `ZeroizeOnDrop` wrappers.
- **DoS Resistance:** All log formatting is bounded. Unbounded string inputs are truncated before allocation.

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in `palisade_errors`, please do **NOT** open a public issue.

**Please email findings to:** `strukturaenterprise@gmail.com`

### What to include

- A description of the vulnerability.
- Steps to reproduce the issue (proof-of-concept code is appreciated).
- Potential impact of the vulnerability.

We will acknowledge receipt of your report within 48 hours and strive to provide a fix as rapidly as possible.
