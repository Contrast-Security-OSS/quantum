<!-- Contrast Quantum Advisor Report -->

# Contrast Quantum Advisor
## Post-Quantum Cryptography Readiness Assessment

---

**Client:** Contrast Crypto Inventory
**Report Date:** September 2, 2026
**Assessment Type:** Runtime Cryptographic Analysis & Quantum Risk Assessment

---

## Executive Summary

This assessment inventories every cryptographic algorithm actually observed running in production across your applications - algorithm strength, mode, invocation frequency, and the real call context behind each finding, captured by Contrast Security's runtime instrumentation rather than declared dependencies or static code scanning.

**2** application(s) use cryptography, calling **4** distinct algorithm(s), for **7** total findings analyzed.

> No algorithms were flagged as needing post-quantum remediation.

### Applications

| Application | Algorithms Used |
|-------------|------------------|
| Cargo-Crypto-contrast-cargo-cats-dataservice | `AES/GCM/NoPadding`, `MD5`, `SHA-256` |
| Cargo-Crypto-contrast-cargo-cats-frontgateservice | `AES/GCM/NoPadding`, `MD5`, `SHA-1`, `SHA-256` |

### Algorithms

| Algorithm | Risk Level | Applications | Invocations |
|-----------|------------|---------------|-------------|
| `AES/GCM/NoPadding` | LOW | 2 | 124 |
| `MD5` | UNKNOWN | 2 | 5 |
| `SHA-1` | NOT_QUANTUM_ISSUE | 1 | 1 |
| `SHA-256` | UNKNOWN | 2 | 868 |

- **0** algorithm(s) need post-quantum remediation (CRITICAL/HIGH/MEDIUM)
- **1** algorithm(s) are quantum-safe as-is (LOW)
- **1** algorithm(s) have classical (non-quantum) weaknesses to address separately

### Application Context

**Cargo-Crypto-contrast-cargo-cats-dataservice**

Based on its name, this is likely a data service component for an application called "Cargo Cats," probably handling data persistence or retrieval for that system. With no observed connections or third-party libraries, it may be a newly instrumented, isolated, or lightly-used service, so this description should be treated as a low-confidence guess rather than a confirmed architectural role.

**Cargo-Crypto-contrast-cargo-cats-frontgateservice**

Based on its name, this is most likely the front-facing API gateway for the "Cargo Cats" application suite, handling inbound traffic and routing requests toward backend services. Since no connected applications or third-party libraries were observed, its architecture graph data is likely incomplete or it operates in isolation from the instrumented environment.


### Quantum Risk Overview

> ✅ **No critical quantum vulnerabilities detected**

### Code Source Summary

| Source Type | Count | Remediation Approach |
|-------------|-------|---------------------|
| 🏠 Custom Code | 5 | Direct code change by dev team |
| ❓ Unknown | 2 | Requires investigation |

---

## Detailed Findings

### 🟢 Low Priority (Quantum-Safe)

#### [LOW] Finding 1: No action needed - SHA-256 usage in Cargo-Crypto-contrast-cargo-cats-frontgateservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `SHA-256` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown - stack trace not provided, cannot determine exact origin package` |
| **Remediation Owner** | No remediation owner needed at this time |
| **Frequency** | Low (868 invocations) |
| **Reachability** | 2 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, no stack trace or entry point provided to determine specific data being hashed |
| **Data Lifetime** | short-term |

**Description:** Application computes SHA-256 hashes, likely for integrity checks, checksums, or similar purposes.

**Quantum Threat Analysis:** SHA-256 is a symmetric hash function. Grover's algorithm only provides a quadratic speedup against hash functions, reducing SHA-256's effective security from 256 bits to roughly 128 bits, which remains well above the security margin considered safe against quantum attacks. This is not vulnerable to Shor's algorithm since it isn't asymmetric.

**Recommendation:** No remediation required. SHA-256 is quantum-resistant at current NIST security levels and does not need replacement as part of post-quantum migration planning.

**Remediation Plan:**
None required. If this hash is being used in a context involving digital signatures or key exchange elsewhere in the same code path, those adjacent mechanisms should be evaluated separately since they may carry quantum risk even though SHA-256 itself does not.

---

#### [LOW] Finding 2: No action needed for AES-GCM usage in Cargo-Crypto-contrast-cargo-cats-dataservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `AES/GCM/NoPadding` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-dataservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unable to determine, no stack trace provided` |
| **Remediation Owner** | N/A, no fix required for quantum resistance |
| **Frequency** | Low (124 invocations) |
| **Reachability** | 2 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, no stack trace or entry point provided to determine specific data type |
| **Data Lifetime** | unknown |

**Description:** The application uses AES/GCM/NoPadding for authenticated symmetric encryption, likely protecting data at rest or in transit.

**Quantum Threat Analysis:** AES-GCM is a symmetric algorithm. Grover's Algorithm only reduces its effective security by half, so AES-256-GCM remains at 128-bit security post-quantum, still considered secure. If this is AES-128-GCM, it would drop to an effective 64-bit security level, which is a concern independent of quantum computing and should be reviewed for key size.

**Recommendation:** Confirm the key size in use. If AES-256, no action is needed for quantum resistance. If AES-128, plan to upgrade to AES-256 to maintain long-term security margins, though this is a classical strength issue, not a quantum-specific one.

**Remediation Plan:**
No stack trace was provided in this instance, so the specific code location and key size could not be verified. Request the full stack trace and confirm the key length parameter passed to Cipher.getInstance or equivalent key generation call before closing this out.

---

#### [LOW] Finding 3: No action needed: AES/GCM authenticated encryption in Cargo-Crypto-contrast-cargo-cats-frontgateservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `AES/GCM/NoPadding` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown, no stack trace provided` |
| **Remediation Owner** | No remediation owner needed for this algorithm itself |
| **Frequency** | Low (124 invocations) |
| **Reachability** | 2 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, no stack trace provided, but AES-GCM is typically used for data-at-rest or payload encryption |
| **Data Lifetime** | long-term |

**Description:** Application uses AES/GCM/NoPadding for authenticated symmetric encryption, likely protecting data at rest or in transit payloads.

**Quantum Threat Analysis:** AES is a symmetric cipher, only vulnerable to Grover's algorithm, which merely halves effective key strength. AES-256/GCM remains secure against quantum attack. If the implementation uses AES-128, effective post-quantum strength drops to approximately 64 bits, which is a separate concern worth verifying.

**Recommendation:** No replacement required for the AES/GCM algorithm itself. Confirm the actual key size in use, if this is AES-128, plan an upgrade to AES-256 to maintain adequate post-quantum security margin. Also verify the key exchange or key management mechanism that provisions this AES key, since that mechanism (if asymmetric) is the actual quantum risk, not the AES-GCM operation itself.

**Remediation Plan:**
No stack trace or entry point was provided with this finding, so code source and key size could not be confirmed. Pull the actual observation details/stack trace from Contrast to identify the calling class and confirm key length. If key material is derived via RSA/ECDH key exchange upstream, that component should be evaluated separately for quantum risk under CRITICAL/HIGH criteria.

---

### ⚪ Non-Quantum Issues

#### [NOT_QUANTUM_ISSUE] Finding 4: Replace SHA-1 in Cargo-Crypto-contrast-cargo-cats-frontgateservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `SHA-1` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown, stack trace not provided` |
| **Remediation Owner** | Application development team (pending stack trace confirmation) |
| **Frequency** | Very Low (1 invocations) |
| **Reachability** | 1 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, no stack trace available to determine data type |
| **Data Lifetime** | short-term |

**Description:** Application computes a SHA-1 hash, purpose unclear due to missing stack trace and entry point data

**Quantum Threat Analysis:** SHA-1 is not a quantum-specific concern. Grover's algorithm only reduces effective security by a square-root factor, and SHA-1's 160-bit output would still nominally hit 80-bit quantum resistance, but SHA-1 is already classically broken via collision attacks (e.g., SHAttered) and should be replaced regardless of quantum considerations.

**Recommendation:** Replace SHA-1 with SHA-256 or better for any security-relevant use (integrity checks, digital signatures, certificate fingerprints). If SHA-1 is used only for non-security purposes (e.g., cache keys, checksums for deduplication), it may be acceptable to leave in place, but this should be confirmed by reviewing the actual call site.

**Remediation Plan:**
No stack trace or entry point was provided for this finding, so the exact code location and purpose of the SHA-1 call could not be determined. Re-run the observation with full stack trace capture enabled to identify the source package and calling class before assigning remediation ownership. Once located, swap MessageDigest.getInstance("SHA-1") for "SHA-256" and verify no downstream systems depend on the specific 160-bit output length or format.

---

#### [NOT_QUANTUM_ISSUE] Finding 5: Replace MD5 hashing in Cargo-Crypto-contrast-cargo-cats-frontgateservice

| Attribute | Value |
|-----------|-------|
| **Algorithm** | `MD5` |
| **Application** | Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Code Source** | 🏠 Custom Code |
| **Source Package** | `Unknown, no stack trace provided` |
| **Remediation Owner** | Application development team for Cargo-Crypto-contrast-cargo-cats-frontgateservice |
| **Frequency** | Very Low (5 invocations) |
| **Reachability** | 2 code path(s) invoke this algorithm |
| **Data Sensitivity** | Unknown, no stack trace or entry point provided to determine what data is being hashed |
| **Data Lifetime** | unknown |

**Description:** Application computes MD5 hashes, likely for checksums, cache keys, or similar non-cryptographic purposes.

**Quantum Threat Analysis:** MD5 is not a quantum vulnerability. It's classically broken due to well-known collision attacks (Grover's algorithm only affects hash preimage resistance by a square root factor, which is not the issue here). This is a legacy cryptographic weakness unrelated to post-quantum migration planning.

**Recommendation:** Treat this as a classical crypto hygiene finding rather than a quantum migration item. If MD5 is used for any security purpose (integrity checks, password handling, digital signatures), replace it with SHA-256 or SHA-3. If it's used for non-security purposes (cache keys, checksums for non-adversarial data), it may be lower priority but should still be documented as a known weak algorithm.

**Remediation Plan:**
No stack trace or entry point was provided in this observation, so the exact code location and usage context couldn't be determined. Recommend pulling the full stack trace from the CBOM evidence to confirm whether this is a security-relevant use case before prioritizing remediation. If used for signatures or authentication, escalate to CRITICAL under classical crypto risk, separate from this quantum-specific assessment.

---

## Appendix A: Algorithm Risk Matrix

| Algorithm | Quantum Risk | Remediation Timeline |
|-----------|--------------|----------------------|
| `AES/GCM/NoPadding` | 🟢 LOW | ✅ No action needed |
| `SHA-1` | ⚪ NOT_QUANTUM_ISSUE | 🔧 Classical security fix |
| `SHA-256` | ❓ UNKNOWN | Review |
| `MD5` | ❓ UNKNOWN | Review |

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
