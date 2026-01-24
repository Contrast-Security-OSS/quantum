#!/usr/bin/env python3
"""
quantum_advisor.py: AI-powered analysis of CBOM for quantum migration decisions.

Analyzes cryptographic usage patterns from a CBOM file and provides intelligent
recommendations on which algorithms need immediate replacement vs. which are
acceptable from a quantum threat perspective.

Usage:
    python quantum_advisor.py cbom.json
    python quantum_advisor.py cbom.json --verbose
    python quantum_advisor.py cbom.json --output report.md
"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Optional
from ai_client import AIClient, Colors, confirm_cost


# Quantum threat analysis prompt - focused on stack trace context analysis
ANALYSIS_PROMPT = """You are a cryptography security expert specializing in post-quantum cryptography migration.

Analyze this cryptographic algorithm usage from a CBOM (Cryptography Bill of Materials) and provide a risk assessment focused on QUANTUM THREATS ONLY.

## Quantum Threat Background

**Shor's Algorithm** breaks asymmetric crypto (RSA, ECDSA, ECDH, DH) completely - these MUST be replaced.
**Grover's Algorithm** halves symmetric crypto strength - AES-256 becomes AES-128 equivalent, still secure.

## Risk Categories (Quantum-specific)

**CRITICAL - Replace Immediately:**
- RSA, ECDSA, ECDH, DH used for long-term secrets or signatures
- Asymmetric crypto protecting data with >5 year confidentiality requirement
- Code signing, document signing with long validity
- "Harvest Now, Decrypt Later" vulnerable data

**HIGH - Replace Soon:**
- Asymmetric crypto in TLS for sensitive data (even with forward secrecy, metadata vulnerable)
- Key exchange for stored encrypted data

**MEDIUM - Plan Replacement:**
- Asymmetric crypto for ephemeral sessions with short-lived data
- TLS with forward secrecy for non-sensitive data

**LOW - Acceptable (Quantum Safe):**
- AES-256, AES-192 (Grover reduces to 128/96 bits - still secure)
- SHA-256, SHA-384, SHA-512 (quantum resistant at these sizes)
- AES-128 in GCM mode for TLS (ephemeral, forward secrecy protects)
- Symmetric crypto with sufficient key size

**NOT A QUANTUM ISSUE (but may have other problems):**
- MD5, SHA-1 - classically broken, but not a quantum-specific threat
- DES, 3DES - classically weak, not quantum-specific

## Stack Trace Context Clues

Look for these patterns in stack traces to determine usage context:

**Password Hashing (usually OK even with weak hash):**
- `PasswordEncoder`, `BCrypt`, `SCrypt`, `PBKDF2`
- `MessageDigestPasswordEncoder`, `DelegatingPasswordEncoder`

**TLS/SSL (check for forward secrecy):**
- `sun.security.ssl`, `SSLHandshake`, `SSLCipher`
- `HKDF`, `NewSessionTicket` = TLS 1.3 with forward secrecy (better)
- If ephemeral key exchange (ECDHE), lower risk

**Data Encryption at Rest (HIGH risk if asymmetric):**
- `Cipher.getInstance` outside TLS context
- Database encryption, file encryption
- Key wrapping operations

**Signatures (CRITICAL if long-lived):**
- `Signature.getInstance`, signing operations
- Code signing, document signing, certificate creation

## Your Analysis Task

For the algorithm provided:
1. Identify the usage context from stack traces
2. Determine data lifetime/sensitivity from context
3. Assess quantum-specific risk level
4. Provide specific recommendation

Output JSON with this structure:
```json
{
  "algorithm": "name",
  "quantum_risk": "CRITICAL|HIGH|MEDIUM|LOW|NOT_QUANTUM_ISSUE",
  "usage_context": "brief description of how it's being used",
  "data_lifetime": "ephemeral|short-term|long-term|unknown",
  "recommendation": "specific action to take",
  "reasoning": "why this risk level, citing stack trace evidence"
}
```
"""


@dataclass
class CryptoAsset:
    """Represents a cryptographic asset from the CBOM."""
    name: str
    bom_ref: str
    primitive: Optional[str]
    mode: Optional[str]
    key_size: Optional[int]
    quantum_level: int
    classical_level: int
    usage_count: int
    unique_locations: int
    occurrences: list
    applications: list


def parse_cbom(cbom_path: str) -> tuple[list[CryptoAsset], dict]:
    """Parse a CBOM file and extract crypto assets."""
    with open(cbom_path, 'r') as f:
        cbom = json.load(f)

    assets = []
    app_names = {}

    # First pass: collect app names
    for component in cbom.get('components', []):
        if component.get('type') == 'application':
            app_names[component.get('bom-ref')] = component.get('name')

    # Build dependency map (which apps use which crypto)
    crypto_to_apps = {}
    for dep in cbom.get('dependencies', []):
        app_ref = dep.get('ref')
        if app_ref in app_names:
            for crypto_ref in dep.get('dependsOn', []):
                if crypto_ref not in crypto_to_apps:
                    crypto_to_apps[crypto_ref] = []
                crypto_to_apps[crypto_ref].append(app_names[app_ref])

    # Second pass: extract crypto assets
    for component in cbom.get('components', []):
        if component.get('type') != 'cryptographic-asset':
            continue

        bom_ref = component.get('bom-ref', '')
        crypto_props = component.get('cryptoProperties', {})
        algo_props = crypto_props.get('algorithmProperties', {})

        # Extract properties
        props = {p['name']: p['value'] for p in component.get('properties', [])}

        # Extract occurrences with stack traces
        occurrences = []
        evidence = component.get('evidence', {})
        for occ in evidence.get('occurrences', []):
            occurrences.append({
                'location': occ.get('location', ''),
                'context': occ.get('additionalContext', '')
            })

        asset = CryptoAsset(
            name=component.get('name', ''),
            bom_ref=bom_ref,
            primitive=algo_props.get('primitive'),
            mode=algo_props.get('mode'),
            key_size=int(algo_props.get('parameterSetIdentifier', 0)) if algo_props.get('parameterSetIdentifier') else None,
            quantum_level=algo_props.get('nistQuantumSecurityLevel', 0),
            classical_level=algo_props.get('classicalSecurityLevel', 0),
            usage_count=int(props.get('contrast:usageCount', 0)),
            unique_locations=int(props.get('contrast:uniqueLocations', 0)),
            occurrences=occurrences,
            applications=crypto_to_apps.get(bom_ref, [])
        )
        assets.append(asset)

    return assets, cbom.get('metadata', {})


def format_asset_for_ai(asset: CryptoAsset) -> str:
    """Format a crypto asset for AI analysis."""
    lines = [
        f"Algorithm: {asset.name}",
        f"Primitive: {asset.primitive or 'unknown'}",
        f"Mode: {asset.mode or 'N/A'}",
        f"Key Size: {asset.key_size or 'unknown'}",
        f"NIST Quantum Level: {asset.quantum_level}",
        f"Classical Security: {asset.classical_level}",
        f"Usage Count: {asset.usage_count}",
        f"Unique Locations: {asset.unique_locations}",
        f"Applications: {', '.join(asset.applications) or 'unknown'}",
        "",
        "Stack Traces / Evidence:"
    ]

    for i, occ in enumerate(asset.occurrences, 1):
        lines.append(f"\n--- Occurrence {i} ---")
        lines.append(f"Location: {occ['location']}")
        if occ['context']:
            # Format stack trace more readably
            context = occ['context'].replace(' ', '\n  ')
            lines.append(f"Context:\n  {context}")

    return '\n'.join(lines)


def analyze_asset(client: AIClient, asset: CryptoAsset, verbose: bool = False) -> dict:
    """Analyze a single crypto asset using AI."""
    asset_text = format_asset_for_ai(asset)

    if verbose:
        print(f"\n{Colors.DIM}Analyzing {asset.name}...{Colors.NC}")

    response, usage = client.call(ANALYSIS_PROMPT, asset_text, max_tokens=2048)

    if verbose:
        client.log_call(asset.name, usage)

    # Parse JSON from response
    try:
        # Find JSON in response
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        if json_start >= 0 and json_end > json_start:
            result = json.loads(response[json_start:json_end])
            return result
    except json.JSONDecodeError:
        pass

    # Fallback if JSON parsing fails
    return {
        "algorithm": asset.name,
        "quantum_risk": "UNKNOWN",
        "usage_context": "Failed to parse AI response",
        "recommendation": response[:500],
        "reasoning": "AI response was not valid JSON"
    }


def generate_report(results: list[dict], metadata: dict) -> str:
    """Generate a markdown report from analysis results."""
    lines = [
        "# Quantum Cryptography Risk Assessment",
        "",
        f"Generated from CBOM: {metadata.get('component', {}).get('name', 'Unknown')}",
        f"Timestamp: {metadata.get('timestamp', 'Unknown')}",
        "",
        "## Executive Summary",
        ""
    ]

    # Count by risk level
    risk_counts = {}
    for r in results:
        level = r.get('quantum_risk', 'UNKNOWN')
        risk_counts[level] = risk_counts.get(level, 0) + 1

    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_QUANTUM_ISSUE', 'UNKNOWN']:
        if level in risk_counts:
            emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'NOT_QUANTUM_ISSUE': '⚪'}.get(level, '❓')
            lines.append(f"- {emoji} **{level}**: {risk_counts[level]} algorithm(s)")

    lines.extend(["", "## Detailed Findings", ""])

    # Group by risk level
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_QUANTUM_ISSUE']:
        level_results = [r for r in results if r.get('quantum_risk') == level]
        if not level_results:
            continue

        lines.append(f"### {level}")
        lines.append("")

        for r in level_results:
            lines.append(f"#### {r.get('algorithm', 'Unknown')}")
            lines.append("")
            lines.append(f"**Usage Context:** {r.get('usage_context', 'Unknown')}")
            lines.append("")
            lines.append(f"**Data Lifetime:** {r.get('data_lifetime', 'Unknown')}")
            lines.append("")
            lines.append(f"**Recommendation:** {r.get('recommendation', 'None')}")
            lines.append("")
            lines.append(f"**Reasoning:** {r.get('reasoning', 'None')}")
            lines.append("")

    lines.extend([
        "## Migration Priority",
        "",
        "Based on quantum threat analysis:",
        "",
        "1. **Immediate Action**: Replace all CRITICAL algorithms",
        "2. **Near-term**: Plan replacement for HIGH risk algorithms",
        "3. **Monitor**: Track MEDIUM risk for future migration",
        "4. **No Action Needed**: LOW risk algorithms are quantum-safe",
        "",
        "---",
        "*Analysis performed using AI-assisted quantum risk assessment*"
    ])

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='AI-powered quantum cryptography risk assessment from CBOM'
    )
    parser.add_argument('cbom', help='Path to CBOM JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output report file (markdown)')
    parser.add_argument('--json', help='Output raw JSON results')
    parser.add_argument('--no-confirm', action='store_true', help='Skip cost confirmation')

    args = parser.parse_args()

    # Parse CBOM
    print(f"\n{Colors.BLUE}Parsing CBOM...{Colors.NC}")
    try:
        assets, metadata = parse_cbom(args.cbom)
    except Exception as e:
        print(f"{Colors.RED}Error parsing CBOM: {e}{Colors.NC}")
        sys.exit(1)

    print(f"  Found {len(assets)} cryptographic assets")

    # Filter to assets worth analyzing
    # Include: quantum_level == 0, asymmetric primitives, OR verbose mode (all)
    if args.verbose:
        # Verbose mode: analyze ALL crypto for usage context
        vulnerable_assets = assets
    else:
        # Normal mode: quantum-vulnerable or asymmetric
        vulnerable_assets = [a for a in assets if
                            a.quantum_level == 0 or
                            a.primitive in ('pke', 'signature', 'kex', 'key-agree')]

    if not vulnerable_assets:
        print(f"\n{Colors.GREEN}No quantum-vulnerable algorithms found!{Colors.NC}")
        print("All cryptographic assets appear to be quantum-safe.")
        return

    print(f"  {len(vulnerable_assets)} assets to analyze")

    # Initialize AI client
    client = AIClient()

    # Estimate cost
    estimated_cost = client.estimate_cost(len(vulnerable_assets), avg_input_tokens=3000, avg_output_tokens=800)

    if not args.no_confirm and not confirm_cost(estimated_cost, len(vulnerable_assets)):
        print("Cancelled.")
        sys.exit(0)

    # Analyze each asset
    print(f"\n{Colors.BLUE}Analyzing algorithms...{Colors.NC}")
    results = []
    for asset in vulnerable_assets:
        try:
            result = analyze_asset(client, asset, args.verbose)
            results.append(result)
            # Print quick status
            risk = result.get('quantum_risk', 'UNKNOWN')
            color = {
                'CRITICAL': Colors.RED,
                'HIGH': Colors.YELLOW,
                'MEDIUM': Colors.YELLOW,
                'LOW': Colors.GREEN,
                'NOT_QUANTUM_ISSUE': Colors.DIM
            }.get(risk, Colors.NC)
            print(f"  {color}{asset.name}: {risk}{Colors.NC}")
        except Exception as e:
            print(f"  {Colors.RED}{asset.name}: Error - {e}{Colors.NC}")
            results.append({
                "algorithm": asset.name,
                "quantum_risk": "ERROR",
                "reasoning": str(e)
            })

    # Generate report
    report = generate_report(results, metadata)

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n{Colors.GREEN}Report written to {args.output}{Colors.NC}")
    else:
        print("\n" + "=" * 60)
        print(report)

    if args.json:
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Colors.GREEN}JSON results written to {args.json}{Colors.NC}")

    # Print AI usage summary
    client.print_summary()


if __name__ == '__main__':
    main()
