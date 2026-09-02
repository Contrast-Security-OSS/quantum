<!-- Contrast Quantum Advisor Report -->

# Contrast Quantum Advisor
## Post-Quantum Cryptography Readiness Assessment

---

**Client:** Cargo-Crypto-contrast-cargo-cats-frontgateservice
**Report Date:** September 2, 2026
**Assessment Type:** Runtime Cryptographic Analysis & Quantum Risk Assessment

---

## Executive Summary

This assessment inventories every cryptographic algorithm actually observed running in production across your applications - algorithm strength, mode, invocation frequency, and the real call context behind each finding, captured by Contrast Security's runtime instrumentation rather than declared dependencies or static code scanning.

**1** application(s) use cryptography, calling **4** distinct algorithm(s), for **4** total findings analyzed.

> No algorithms were flagged as needing post-quantum remediation.

### Applications

| Application | Algorithms Used |
|-------------|------------------|
| Cargo-Crypto-contrast-cargo-cats-frontgateservice | `AES/GCM/NoPadding`, `MD5`, `SHA-1`, `SHA-256` |

### Algorithms

| Algorithm | Risk Level | Applications | Invocations |
|-----------|------------|---------------|-------------|
| `AES/GCM/NoPadding` | LOW | 1 | 124 |
| `MD5` | NOT_QUANTUM_ISSUE | 1 | 5 |
| `SHA-1` | NOT_QUANTUM_ISSUE | 1 | 1 |
| `SHA-256` | LOW | 1 | 868 |

- **0** algorithm(s) need post-quantum remediation (CRITICAL/HIGH/MEDIUM)
- **2** algorithm(s) are quantum-safe as-is (LOW)
- **2** algorithm(s) have classical (non-quantum) weaknesses to address separately

### Application Context

**Cargo-Crypto-contrast-cargo-cats-frontgateservice**

Based on its name, this is likely the front gateway service for the "cargo cats" application, probably handling incoming requests and routing them to backend services within that system. It appears to be an isolated or minimally instrumented component, since no connected applications or third-party libraries were observed, which may reflect limited runtime visibility rather than an actual lack of dependencies.


### Quantum Risk Overview

> ✅ **No critical quantum vulnerabilities detected**

### Code Source Summary

| Source Type | Count | Remediation Approach |
|-------------|-------|---------------------|
| 🏠 Custom Code | 4 | Direct code change by dev team |

---

## Detailed Findings

### 🟢 Low Priority (Quantum-Safe)

#### [LOW] Finding 1: No action needed for SHA-256 usage in Cargo-Crypto-contrast-cargo-cats-frontgateservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `SHA-256` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown, no stack trace provided` |
| **Remediation Owner** | N/A, no action required |
| **Frequency** | Low (868 invocations) |
| **Reachability** | 1 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, stack trace not provided, likely general data integrity or identifier hashing |
| **Data Lifetime** | unknown (insufficient stack trace detail to determine) |

**Description:** Application computes SHA-256 hashes, likely for integrity checks, data fingerprinting, or similar purposes.

**Quantum Threat Analysis:** SHA-256 is a symmetric primitive. Grover's algorithm provides at most a quadratic speedup against hash preimage/collision resistance, reducing effective security from 256 bits to roughly 128 bits, which remains well above the threshold considered secure. SHA-256 is not vulnerable to Shor's algorithm since it is not based on integer factorization or discrete logarithm problems.

**Recommendation:** No remediation needed for quantum resistance. SHA-256 remains quantum-safe at current and foreseeable quantum computing capabilities. Continue monitoring NIST guidance in case recommendations change.

**Remediation Plan:**
None required. If this SHA-256 usage is paired with an asymmetric algorithm elsewhere in the same workflow (e.g., signing a hash with RSA/ECDSA), that paired asymmetric operation is the actual quantum risk and should be evaluated separately, not this hash function itself.

---

#### [LOW] Finding 2: No action needed for AES/GCM usage in Cargo-Crypto-contrast-cargo-cats-frontgateservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `AES/GCM/NoPadding` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown, no stack trace provided to identify the originating package or class` |
| **Remediation Owner** | No remediation required, application team should confirm key size during a routine review |
| **Frequency** | Low (124 invocations) |
| **Reachability** | 1 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, no stack trace or entry point provided to identify what data is being encrypted |
| **Data Lifetime** | short-term |

**Description:** The application uses AES/GCM/NoPadding for authenticated symmetric encryption.

**Quantum Threat Analysis:** AES is symmetric crypto, so it's only affected by Grover's algorithm, which halves effective key strength. AES/GCM at 256-bit keys remains secure at roughly AES-128 equivalent strength post-quantum. This is quantum-safe by design as long as a 256-bit key is used.

**Recommendation:** No replacement needed. Confirm the key size configured for this AES/GCM usage is 256-bit rather than 128-bit, since 128-bit keys drop to roughly 64-bit equivalent strength under Grover's algorithm, which is inadequate for long-term protection.

**Remediation Plan:**
Verify the key generation code (e.g., KeyGenerator.getInstance("AES").init(256)) uses 256-bit keys. No stack trace was available for this instance, so the exact call site couldn't be confirmed. If this data has a long retention period, treat that as a separate finding requiring key-size verification, not a post-quantum migration issue.

---

### ⚪ Non-Quantum Issues

#### [NOT_QUANTUM_ISSUE] Finding 3: Replace SHA-1 in cargo-cats-frontgateservice (classical break, not quantum)

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `SHA-1` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown, no stack trace provided in this observation` |
| **Remediation Owner** | Application development team for cargo-cats-frontgateservice |
| **Frequency** | Very Low (1 invocations) |
| **Reachability** | 1 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, no stack trace available to determine what data is being hashed |
| **Data Lifetime** | short-term |

**Description:** Application computes a SHA-1 hash, purpose unclear due to missing stack trace and entry point details

**Quantum Threat Analysis:** SHA-1 is a symmetric/hash primitive. Grover's algorithm only provides a quadratic speedup against hash preimage attacks, so SHA-1's quantum-adjusted strength would still be roughly 80 bits if it were otherwise sound. The real problem is that SHA-1 is already classically broken via practical collision attacks (e.g., SHAttered), which have nothing to do with quantum computing.

**Recommendation:** Treat this as a standard cryptographic hygiene finding, not a post-quantum migration item. Replace SHA-1 with SHA-256 or SHA-3-256 for any integrity, signature, or fingerprinting use. If SHA-1 is being used for password hashing, switch to a dedicated password hashing function such as bcrypt, scrypt, or Argon2 instead of a general-purpose hash.

**Remediation Plan:**
This finding is missing its stack trace and entry point, so the exact call site and use case (checksum, signature digest, password hash, cache key, etc.) can't be confirmed. Pull the full observation details from Contrast to identify the calling code before making changes, since the fix differs depending on whether SHA-1 is used for integrity checking versus password storage.

---

#### [NOT_QUANTUM_ISSUE] Finding 4: Replace MD5 hashing in Cargo-Crypto-contrast-cargo-cats-frontgateservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `MD5` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown - stack trace not provided in this observation` |
| **Remediation Owner** | Application development team (assumed custom_code based on naming; verify actual call site once stack trace is available) |
| **Frequency** | Very Low (5 invocations) |
| **Reachability** | 1 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown - no stack trace context available to determine what data is being hashed |
| **Data Lifetime** | unknown |

**Description:** Application uses MD5 hashing, observed 5 times, with no stack trace or entry point provided to determine the specific purpose.

**Quantum Threat Analysis:** MD5 is classically broken (collision attacks are practical today) but this is not a quantum-specific vulnerability. Grover's algorithm would only provide a quadratic speedup against a preimage attack, and MD5 is already broken well beyond that by classical cryptanalysis. This should be tracked as a standard cryptographic weakness, not a post-quantum migration item.

**Recommendation:** Replace MD5 with SHA-256 or SHA-3 for any integrity, hashing, or fingerprinting use case. If MD5 is being used for password storage, replace it with a proper password hashing function (bcrypt, scrypt, or Argon2) instead. This is unrelated to quantum readiness and should be prioritized as a classical cryptographic hygiene fix.

**Remediation Plan:**
No stack trace or entry point was provided with this finding, so the exact call site and purpose (integrity check, password hashing, cache key, deduplication, etc.) can't be confirmed. Recommend re-pulling observation details (GET /observations/{id}/details) to get the stack trace before assigning to a team, since the fix differs significantly if this turns out to be password storage versus a non-security checksum use.

---

## Appendix A: Algorithm Risk Matrix

| Algorithm | Quantum Risk | Remediation Timeline |
|-----------|--------------|----------------------|
| `SHA-256` | 🟢 LOW | ✅ No action needed |
| `AES/GCM/NoPadding` | 🟢 LOW | ✅ No action needed |
| `SHA-1` | ⚪ NOT_QUANTUM_ISSUE | 🔧 Classical security fix |
| `MD5` | ⚪ NOT_QUANTUM_ISSUE | 🔧 Classical security fix |

---

## Appendix B: Methodology

### Quantum Threat Model

This assessment evaluates cryptographic algorithms against two primary quantum computing threats:

| Threat | Impact | Affected Algorithms |
|--------|--------|---------------------|
| **Shor's Algorithm** | Complete break of asymmetric crypto | RSA, ECDSA, ECDH, DH, DSA |
| **Grover's Algorithm** | Halves effective key length | AES, SHA (still safe at 256-bit) |

### Risk Classification Criteria

- **CRITICAL**: Asymmetric cryptography protecting long-term secrets, digital signatures, or stored data
- **HIGH**: Asymmetric cryptography for sensitive data with medium-term exposure
- **MEDIUM**: Asymmetric cryptography with forward secrecy mitigations
- **LOW**: Symmetric cryptography with sufficient key sizes (quantum-resistant)
- **NOT_QUANTUM_ISSUE**: Classical cryptographic weaknesses unrelated to quantum threats

### Data Sources

Cryptographic usage data collected via Contrast Security runtime instrumentation, providing:
- Actual algorithms in use (not just declared dependencies)
- Complete call stack context for usage classification
- Invocation frequency and code path reachability metrics

---

*Report generated by Contrast Quantum Advisor*
*Powered by Contrast Security Runtime Observability*
