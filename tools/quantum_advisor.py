#!/usr/bin/env python3
"""
quantum_advisor.py: AI-powered analysis of CBOM for quantum migration decisions.

Analyzes each cryptographic usage instance from a CBOM file and provides
actionable remediation tasks based on quantum threat analysis.

Usage:
    python quantum_advisor.py cbom.json
    python quantum_advisor.py cbom.json --verbose
    python quantum_advisor.py cbom.json --output report.md
"""

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from ai_client import AIClient, Colors, confirm_cost


# Quantum threat analysis prompt - focused on individual occurrence analysis
ANALYSIS_PROMPT = """You are a cryptography security expert specializing in post-quantum cryptography migration.

Analyze this SINGLE cryptographic usage instance and provide a specific remediation recommendation.

## Quantum Threat Background

**Shor's Algorithm** breaks asymmetric crypto (RSA, ECDSA, ECDH, DH) completely - these MUST be replaced.
**Grover's Algorithm** halves symmetric crypto strength - AES-256 becomes AES-128 equivalent, still secure.

## Risk Levels (Quantum-specific)

**CRITICAL**: Must fix immediately
- Asymmetric crypto protecting long-term secrets, signatures, or stored data
- "Harvest Now, Decrypt Later" vulnerable

**HIGH**: Fix soon (within 6 months)
- Asymmetric crypto for sensitive but shorter-lived data
- VPN/tunnel key exchange

**MEDIUM**: Plan replacement (6-18 months)
- Asymmetric crypto with forward secrecy for ephemeral data
- TLS key exchange (ECDHE) - forward secrecy mitigates risk

**LOW**: No action needed
- Symmetric crypto with sufficient key size (AES-128+, SHA-256+)
- Quantum-safe by design

**NOT_QUANTUM_ISSUE**: Different problem
- MD5, SHA-1, DES, 3DES - classically broken, not quantum-specific

## Stack Trace Context Clues

**Password Hashing**: `PasswordEncoder`, `BCrypt`, `PBKDF2` → Usually OK
**TLS/SSL**: `sun.security.ssl`, `SSLHandshake`, `HKDF` → Check for forward secrecy
**Data at Rest**: `Cipher.getInstance` outside TLS, database/file encryption → HIGH risk if asymmetric
**Signatures**: `Signature.getInstance`, code signing, certificates → CRITICAL if long-lived

## Code Source Classification (IMPORTANT)

Analyze the stack trace to determine WHERE the crypto call originates:

**custom_code**: Application's own code (com.acme.*, com.company.*, etc.)
- Remediation: Direct code change by development team
- Timeline: Fastest to fix

**open_source_library**: Third-party OSS (org.apache.*, com.google.*, io.netty.*, etc.)
- Remediation: File issue/PR with maintainer, upgrade when fixed, or fork
- Timeline: Depends on maintainer responsiveness

**commercial_library**: Commercial/vendor libraries (com.oracle.*, com.ibm.*, database drivers)
- Remediation: Contact vendor support, request PQ update, plan for vendor timeline
- Timeline: May require contract leverage, could be slow

**framework**: Web/app frameworks (org.springframework.*, javax.*, jakarta.*)
- Remediation: Upgrade framework version when PQ support added, monitor releases
- Timeline: Major frameworks are actively working on PQ support

**jdk_runtime**: JDK/JRE internals (sun.security.*, java.security.*, javax.crypto.*)
- Remediation: Upgrade JDK when PQ algorithms available, or add BC provider
- Timeline: OpenJDK has PQ work in progress

## Your Task

Analyze this specific usage and return JSON:
```json
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|NOT_QUANTUM_ISSUE",
  "title": "Brief actionable title (e.g., 'Replace RSA document signing in acme-docs')",
  "application": "app name from stack trace",
  "usage_summary": "One sentence: what the crypto is doing",
  "data_sensitivity": "What kind of data is being protected",
  "data_lifetime": "ephemeral|short-term|long-term",
  "code_source": "custom_code|open_source_library|commercial_library|framework|jdk_runtime",
  "source_package": "The specific package/library where the crypto call originates (e.g., 'com.acme.auth', 'org.springframework.security', 'mysql-connector-java')",
  "remediation_owner": "Who needs to fix this (e.g., 'Development Team', 'Spring Security maintainers', 'Oracle/MySQL', 'OpenJDK')",
  "evidence": ["Key stack trace lines that informed the decision"],
  "quantum_threat": "Why this is/isn't vulnerable to quantum attacks",
  "recommendation": "Specific action to take",
  "migration_notes": "Technical notes for the developer doing the fix"
}
```
"""


@dataclass
class CryptoOccurrence:
    """Represents a single cryptographic usage instance."""
    algorithm: str
    primitive: Optional[str]
    mode: Optional[str]
    key_size: Optional[int]
    quantum_level: int
    location: str
    context: str
    application: str
    usage_count: int
    unique_locations: int


@dataclass
class AppMetadata:
    """Architecture/connection info for one application, from the Contrast graph."""
    name: str
    language: Optional[str] = None
    posture_score: Optional[float] = None
    posture_severity: Optional[str] = None
    open_issues_total: Optional[int] = None
    library_count: int = 0
    connected_applications: Optional[list] = None

    def __post_init__(self):
        if self.connected_applications is None:
            self.connected_applications = []


def get_frequency_label(usage_count: int) -> str:
    """Convert usage count to frequency label."""
    if usage_count >= 100000:
        return "Very High"
    elif usage_count >= 10000:
        return "High"
    elif usage_count >= 1000:
        return "Medium"
    elif usage_count >= 100:
        return "Low"
    else:
        return "Very Low"


def parse_cbom(cbom_path: str) -> tuple[list[CryptoOccurrence], dict, dict[str, AppMetadata]]:
    """Parse a CBOM file and extract individual crypto occurrences plus per-application metadata."""
    with open(cbom_path, 'r') as f:
        cbom = json.load(f)

    occurrences = []
    app_metadata: dict[str, AppMetadata] = {}

    for component in cbom.get('components', []):
        bom_ref = component.get('bom-ref', '')
        if component.get('type') == 'application' and bom_ref.startswith('app-'):
            props = {p['name']: p['value'] for p in component.get('properties', [])}
            name = component.get('name', bom_ref)
            connected = props.get('contrast:connectedApplications', '')
            app_metadata[name] = AppMetadata(
                name=name,
                language=props.get('contrast:language'),
                posture_score=float(props['contrast:postureScore']) if 'contrast:postureScore' in props else None,
                posture_severity=props.get('contrast:postureSeverity'),
                open_issues_total=int(props['contrast:openIssuesTotal']) if 'contrast:openIssuesTotal' in props else None,
                library_count=int(props.get('contrast:libraryCount', 0)),
                connected_applications=[c.strip() for c in connected.split(',') if c.strip()],
            )
            continue

        if component.get('type') != 'cryptographic-asset':
            continue

        crypto_props = component.get('cryptoProperties', {})
        algo_props = crypto_props.get('algorithmProperties', {})
        props = {p['name']: p['value'] for p in component.get('properties', [])}

        # Extract each occurrence as a separate item
        evidence = component.get('evidence', {})
        for occ in evidence.get('occurrences', []):
            context = occ.get('additionalContext', '')

            # Extract app name from context
            app_name = 'unknown'
            if 'App:' in context:
                app_line = context.split('Stack Trace:')[0] if 'Stack Trace:' in context else context
                app_name = app_line.replace('App:', '').strip()

            occurrence = CryptoOccurrence(
                algorithm=component.get('name', ''),
                primitive=algo_props.get('primitive'),
                mode=algo_props.get('mode'),
                key_size=int(algo_props.get('parameterSetIdentifier', 0)) if algo_props.get('parameterSetIdentifier') else None,
                quantum_level=algo_props.get('nistQuantumSecurityLevel', 0),
                location=occ.get('location', ''),
                context=context,
                application=app_name,
                usage_count=int(props.get('contrast:usageCount', 0)),
                unique_locations=int(props.get('contrast:uniqueLocations', 1))
            )
            occurrences.append(occurrence)

    return occurrences, cbom.get('metadata', {}), app_metadata


def format_occurrence_for_ai(occ: CryptoOccurrence) -> str:
    """Format a single occurrence for AI analysis."""
    # Format stack trace more readably
    stack_trace = ""
    if 'Stack Trace:' in occ.context:
        parts = occ.context.split('Stack Trace:')
        stack_trace = parts[1].strip() if len(parts) > 1 else ""
        # Convert space-separated to newline-separated
        stack_trace = stack_trace.replace(' ', '\n')

    lines = [
        f"Algorithm: {occ.algorithm}",
        f"Primitive: {occ.primitive or 'unknown'}",
        f"Mode: {occ.mode or 'N/A'}",
        f"Key Size: {occ.key_size or 'unknown'} bits",
        f"NIST Quantum Level: {occ.quantum_level}",
        f"Application: {occ.application}",
        f"Usage Count: {occ.usage_count}",
        f"Entry Point: {occ.location}",
        "",
        "Stack Trace:",
        stack_trace
    ]

    return '\n'.join(lines)


def extract_stack_trace(context: str) -> list[str]:
    """Extract stack trace frames from context string."""
    if 'Stack Trace:' not in context:
        return []

    parts = context.split('Stack Trace:')
    if len(parts) < 2:
        return []

    stack_text = parts[1].strip()
    # Split on spaces (frames are space-separated in CBOM)
    frames = [f.strip() for f in stack_text.split(' ') if f.strip()]
    return frames


APP_DESCRIPTION_PROMPT = """You are an application security analyst building context for a cryptography inventory report.

You are given metadata about ONE application: its name, language, which other applications it's connected to, \
and its third-party library footprint. You are NOT given its cryptographic findings - only its architecture.

Write a 2-3 sentence description of what this application/API most likely does, based on its name, language, \
and connections to other services. Be concrete about its likely role (e.g. "a front-line API gateway that routes \
requests to backend services", "a reporting service that generates documents for internal consumers").

Return JSON:
```json
{
  "description": "2-3 sentence description of what this application/API does"
}
```
"""


def format_app_for_ai(app: AppMetadata) -> str:
    lines = [
        f"Application: {app.name}",
        f"Language: {app.language or 'unknown'}",
        f"Connected Applications: {', '.join(app.connected_applications) if app.connected_applications else 'none observed'}",
        f"Third-Party Library Count: {app.library_count}",
    ]
    return '\n'.join(lines)


def generate_app_descriptions(client: AIClient, apps: dict[str, AppMetadata], verbose: bool = False) -> dict[str, str]:
    """Generate a one-time architectural description for each application, for report context."""
    descriptions = {}
    for name, app in apps.items():
        if verbose:
            print(f"\n{Colors.DIM}Describing application {name}...{Colors.NC}")

        response, usage = client.call(APP_DESCRIPTION_PROMPT, format_app_for_ai(app), max_tokens=400)

        if verbose:
            client.log_call(f"describe:{name}", usage)

        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                result = json.loads(response[json_start:json_end])
                descriptions[name] = result.get('description', '').strip()
                continue
        except json.JSONDecodeError:
            pass
        descriptions[name] = ''

    return descriptions


RISK_SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_QUANTUM_ISSUE', 'UNKNOWN', 'ERROR']


def _risk_rank(risk_level: str) -> int:
    return RISK_SEVERITY_ORDER.index(risk_level) if risk_level in RISK_SEVERITY_ORDER else len(RISK_SEVERITY_ORDER)


def enrich_bom(bom_path: str, descriptions: dict[str, str], results: list[dict]) -> tuple[int, int]:
    """Write the advisor's findings back into the CBOM itself:
    - application component descriptions (CycloneDX's standard Component.description)
    - quantum:* risk properties on each cryptographic-asset component, rolled up from
      the worst-risk occurrence analyzed for that algorithm (same property names
      quantum_enhance.py used to write, so this supersedes running that separately)

    This makes the CBOM self-describing for anyone who consumes the JSON directly,
    not just the markdown report. Returns (apps_described, algorithms_annotated)."""
    with open(bom_path, 'r') as f:
        bom = json.load(f)

    findings_by_algorithm: dict[str, list[dict]] = {}
    for r in results:
        findings_by_algorithm.setdefault(r.get('algorithm', ''), []).append(r)

    apps_described = 0
    algorithms_annotated = 0

    for component in bom.get('components', []):
        bom_ref = component.get('bom-ref', '')

        if component.get('type') == 'application' and bom_ref.startswith('app-'):
            description = descriptions.get(component.get('name', ''))
            if description:
                component['description'] = description
                apps_described += 1
            continue

        if component.get('type') != 'cryptographic-asset':
            continue

        findings = findings_by_algorithm.get(component.get('name', ''))
        if not findings:
            continue

        worst = min(findings, key=lambda r: _risk_rank(r.get('risk_level', 'UNKNOWN')))

        quantum_props = [
            ('quantum:riskLevel', worst.get('risk_level', 'UNKNOWN')),
            ('quantum:title', worst.get('title', '')),
            ('quantum:usageSummary', worst.get('usage_summary', '')),
            ('quantum:dataSensitivity', worst.get('data_sensitivity', '')),
            ('quantum:dataLifetime', worst.get('data_lifetime', '')),
            ('quantum:codeSource', worst.get('code_source', '')),
            ('quantum:sourcePackage', worst.get('source_package', '')),
            ('quantum:remediationOwner', worst.get('remediation_owner', '')),
            ('quantum:quantumThreat', worst.get('quantum_threat', '')),
            ('quantum:recommendation', worst.get('recommendation', '')),
            ('quantum:migrationNotes', worst.get('migration_notes', '')),
            ('quantum:findingsAnalyzed', str(len(findings))),
        ]

        # Drop any stale quantum:* properties from a previous run before re-adding,
        # so repeated runs don't accumulate duplicates.
        props = [p for p in component.get('properties', []) if not p.get('name', '').startswith('quantum:')]
        for name, value in quantum_props:
            if value:
                props.append({'name': name, 'value': str(value)})
        component['properties'] = props
        algorithms_annotated += 1

    if apps_described or algorithms_annotated:
        meta_props = [p for p in bom.get('metadata', {}).get('properties', [])
                      if not p.get('name', '').startswith('quantum:')]
        meta_props.append({'name': 'quantum:enhancedAt', 'value': datetime.now().isoformat()})
        meta_props.append({'name': 'quantum:enhancedBy', 'value': 'Contrast Quantum Advisor'})
        bom.setdefault('metadata', {})['properties'] = meta_props

        with open(bom_path, 'w') as f:
            json.dump(bom, f, indent=2)

    return apps_described, algorithms_annotated


def analyze_occurrence(client: AIClient, occ: CryptoOccurrence, verbose: bool = False) -> dict:
    """Analyze a single crypto occurrence using AI."""
    occ_text = format_occurrence_for_ai(occ)

    if verbose:
        print(f"\n{Colors.DIM}Analyzing {occ.algorithm} in {occ.application}...{Colors.NC}")

    response, usage = client.call(ANALYSIS_PROMPT, occ_text, max_tokens=1500)

    if verbose:
        client.log_call(f"{occ.algorithm}@{occ.application}", usage)

    # Extract real stack trace from CBOM data
    real_stack_trace = extract_stack_trace(occ.context)

    # Parse JSON from response
    try:
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        if json_start >= 0 and json_end > json_start:
            result = json.loads(response[json_start:json_end])
            result['algorithm'] = occ.algorithm
            result['raw_location'] = occ.location
            # Add frequency and reachability from CBOM data
            result['frequency'] = get_frequency_label(occ.usage_count)
            result['frequency_count'] = occ.usage_count
            result['reachability'] = occ.unique_locations
            # Override AI's evidence with real stack trace
            result['stack_trace'] = real_stack_trace
            return result
    except json.JSONDecodeError:
        pass

    return {
        "algorithm": occ.algorithm,
        "application": occ.application,
        "risk_level": "UNKNOWN",
        "title": f"Analyze {occ.algorithm} in {occ.application}",
        "usage_summary": "Failed to parse AI response",
        "recommendation": response[:500],
        "frequency": get_frequency_label(occ.usage_count),
        "frequency_count": occ.usage_count,
        "reachability": occ.unique_locations,
        "stack_trace": real_stack_trace
    }


def generate_html_report(markdown_content: str) -> str:
    """Wrap markdown content in an HTML template with styling."""
    # Escape backticks and quotes for JS embedding
    escaped_md = markdown_content.replace('\\', '\\\\').replace('`', '\\`').replace("'", "&#39;")

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contrast Quantum Advisor Report</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root {{
            --contrast-purple: #7B2D8E;
            --contrast-dark: #1a1a2e;
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #6c757d;
        }}

        * {{ box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 20px;
            line-height: 1.7;
            background: #f8f9fa;
            color: #333;
        }}

        #content {{
            background: white;
            padding: 50px 60px;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
        }}

        h1 {{
            color: var(--contrast-purple);
            font-size: 2.5em;
            margin-bottom: 5px;
            font-weight: 600;
        }}

        h1 + h2 {{
            color: #666;
            font-weight: 400;
            font-size: 1.3em;
            margin-top: 0;
            padding-bottom: 20px;
            border-bottom: 3px solid var(--contrast-purple);
        }}

        h2 {{
            color: var(--contrast-dark);
            margin-top: 40px;
            font-size: 1.6em;
        }}

        h3 {{
            color: var(--contrast-purple);
            font-size: 1.3em;
            margin-top: 35px;
            padding: 12px 15px;
            background: linear-gradient(135deg, #f8f4fa 0%, #fff 100%);
            border-left: 4px solid var(--contrast-purple);
            border-radius: 0 5px 5px 0;
        }}

        h4 {{
            color: #333;
            font-size: 1.05em;
            margin-top: 25px;
            padding: 15px;
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 15px 0 20px 0;
            font-size: 0.95em;
        }}

        th, td {{
            border: 1px solid #e0e0e0;
            padding: 12px 15px;
            text-align: left;
        }}

        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #555;
        }}

        tr:nth-child(even) {{ background: #fafafa; }}

        code {{
            background: #f4f4f4;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
            color: var(--contrast-purple);
        }}

        pre {{
            background: var(--contrast-dark);
            color: #e8e8e8;
            padding: 18px 20px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.85em;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        pre code {{
            background: none;
            color: inherit;
            padding: 0;
        }}

        blockquote {{
            margin: 25px 0;
            padding: 20px 25px;
            border-left: 4px solid var(--contrast-purple);
            background: linear-gradient(135deg, #fef9ff 0%, #fff 100%);
            border-radius: 0 8px 8px 0;
            font-size: 1.05em;
        }}

        blockquote p {{ margin: 0; }}

        hr {{
            border: none;
            border-top: 1px solid #e8e8e8;
            margin: 35px 0;
        }}

        strong {{ color: #222; }}

        ul, ol {{ margin: 15px 0; padding-left: 25px; }}
        li {{ margin: 8px 0; }}

        #content > p:last-of-type {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #888;
            font-size: 0.9em;
            text-align: center;
        }}

        @media print {{
            body {{ background: white; padding: 0; }}
            #content {{ box-shadow: none; padding: 30px; }}
            h4 {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div id="content"></div>
    <script>
        const markdown = `{escaped_md}`;
        document.getElementById('content').innerHTML = marked.parse(markdown);
    </script>
</body>
</html>'''


def generate_report(results: list[dict], metadata: dict, app_metadata: dict[str, AppMetadata],
                     app_descriptions: dict[str, str]) -> str:
    """Generate a professional task-oriented markdown report."""

    report_date = datetime.now().strftime("%B %d, %Y")
    source_name = metadata.get('component', {}).get('name', 'Unknown')

    # Collect algorithm data for charts
    algo_risks = {}
    for r in results:
        algo = r.get('algorithm', 'Unknown')
        level = r.get('risk_level', 'UNKNOWN')
        if algo not in algo_risks:
            algo_risks[algo] = level

    # Aggregate per-algorithm usage across all occurrences. frequency_count is the
    # algorithm's total invocation count (computed once, org-wide) - it's the same
    # value on every occurrence of that algorithm, so it's set once per algorithm
    # here, not summed across apps/occurrences (which would double-count it).
    algo_summary = {}
    for r in results:
        algo = r.get('algorithm', 'Unknown')
        agg = algo_summary.setdefault(algo, {
            'risk_level': r.get('risk_level', 'UNKNOWN'),
            'apps': set(),
            'usage_count': r.get('frequency_count', 0),
        })
        if r.get('application'):
            agg['apps'].add(r['application'])

    apps_in_report = sorted({r.get('application') for r in results if r.get('application')})
    algos_by_app = {}
    for r in results:
        if r.get('application'):
            algos_by_app.setdefault(r['application'], set()).add(r.get('algorithm', 'Unknown'))

    quantum_vulnerable_count = sum(1 for a in algo_summary.values() if a['risk_level'] in ('CRITICAL', 'HIGH', 'MEDIUM'))
    quantum_safe_count = sum(1 for a in algo_summary.values() if a['risk_level'] == 'LOW')
    classical_issue_count = sum(1 for a in algo_summary.values() if a['risk_level'] == 'NOT_QUANTUM_ISSUE')

    lines = [
        "<!-- Contrast Quantum Advisor Report -->",
        "",
        "# Contrast Quantum Advisor",
        "## Post-Quantum Cryptography Readiness Assessment",
        "",
        "---",
        "",
        f"**Client:** {source_name}",
        f"**Report Date:** {report_date}",
        f"**Assessment Type:** Runtime Cryptographic Analysis & Quantum Risk Assessment",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "This assessment inventories every cryptographic algorithm actually observed running in production "
        "across your applications - algorithm strength, mode, invocation frequency, and the real call context "
        "behind each finding, captured by Contrast Security's runtime instrumentation rather than declared "
        "dependencies or static code scanning.",
        "",
        f"**{len(apps_in_report)}** application(s) use cryptography, calling **{len(algo_summary)}** distinct "
        f"algorithm(s), for **{len(results)}** total findings analyzed.",
        "",
    ]

    if quantum_vulnerable_count > 0:
        lines.append(f"> **{quantum_vulnerable_count} of {len(algo_summary)} algorithms need post-quantum remediation** "
                    f"(CRITICAL/HIGH/MEDIUM risk).")
    else:
        lines.append("> No algorithms were flagged as needing post-quantum remediation.")

    lines.append("")
    lines.append("### Applications")
    lines.append("")
    lines.append("| Application | Algorithms Used |")
    lines.append("|-------------|------------------|")
    for app_name in apps_in_report:
        algos_used = ', '.join(f"`{a}`" for a in sorted(algos_by_app.get(app_name, [])))
        lines.append(f"| {app_name} | {algos_used} |")

    lines.append("")
    lines.append("### Algorithms")
    lines.append("")
    lines.append("| Algorithm | Risk Level | Applications | Invocations |")
    lines.append("|-----------|------------|---------------|-------------|")
    for algo, agg in sorted(algo_summary.items()):
        lines.append(f"| `{algo}` | {agg['risk_level']} | {len(agg['apps'])} | {agg['usage_count']:,} |")

    lines.append("")
    lines.append(f"- **{quantum_vulnerable_count}** algorithm(s) need post-quantum remediation (CRITICAL/HIGH/MEDIUM)")
    lines.append(f"- **{quantum_safe_count}** algorithm(s) are quantum-safe as-is (LOW)")
    lines.append(f"- **{classical_issue_count}** algorithm(s) have classical (non-quantum) weaknesses to address separately")
    lines.append("")

    # Application context - one entry per app with observed crypto usage, describing what it is
    # and what it's connected to (from the Contrast architecture graph)
    apps_with_findings = sorted({r.get('application') for r in results if r.get('application')} & set(app_metadata.keys()))
    if apps_with_findings:
        lines.append("### Application Context")
        lines.append("")
        for app_name in apps_with_findings:
            app = app_metadata.get(app_name)
            lines.append(f"**{app_name}**")
            if app:
                meta_bits = []
                if app.language:
                    meta_bits.append(f"Language: {app.language}")
                if app.posture_score is not None:
                    meta_bits.append(f"Posture Score: {app.posture_score} ({app.posture_severity})")
                if app.connected_applications:
                    meta_bits.append(f"Connects To: {', '.join(app.connected_applications)}")
                if meta_bits:
                    lines.append(" | ".join(meta_bits))
            description = app_descriptions.get(app_name)
            if description:
                lines.append("")
                lines.append(description)
            lines.append("")
        lines.append("")

    # Count by risk level
    risk_counts = {}
    for r in results:
        level = r.get('risk_level', 'UNKNOWN')
        risk_counts[level] = risk_counts.get(level, 0) + 1

    total = len(results)
    critical_count = risk_counts.get('CRITICAL', 0)
    high_count = risk_counts.get('HIGH', 0)
    medium_count = risk_counts.get('MEDIUM', 0)
    low_count = risk_counts.get('LOW', 0)
    other_count = risk_counts.get('NOT_QUANTUM_ISSUE', 0) + risk_counts.get('UNKNOWN', 0)
    action_needed = critical_count + high_count

    # Visual risk chart using ASCII/Unicode
    lines.append("### Quantum Risk Overview")
    lines.append("")

    if action_needed > 0:
        lines.append(f"> ⚠️ **{action_needed} of {total} findings require priority remediation** — "
                    f"{critical_count} critical, {high_count} high")
    else:
        lines.append("> ✅ **No critical quantum vulnerabilities detected**")

    lines.append("")

    # Risk distribution bar chart
    lines.append("```")
    lines.append("QUANTUM RISK DISTRIBUTION")
    lines.append("─" * 50)

    max_count = max(risk_counts.values()) if risk_counts else 1
    bar_width = 30

    for level, label, color in [
        ('CRITICAL', '🔴 CRITICAL ', '█'),
        ('HIGH', '🟠 HIGH     ', '█'),
        ('MEDIUM', '🟡 MEDIUM   ', '▓'),
        ('LOW', '🟢 LOW      ', '░'),
        ('NOT_QUANTUM_ISSUE', '⚪ OTHER    ', '·')
    ]:
        count = risk_counts.get(level, 0)
        if level == 'NOT_QUANTUM_ISSUE':
            count += risk_counts.get('UNKNOWN', 0)
        if count > 0:
            bar_len = int((count / max_count) * bar_width)
            bar = color * bar_len
            lines.append(f"{label} {bar} {count}")

    lines.append("─" * 50)
    lines.append(f"Total: {total} cryptographic operations analyzed")
    lines.append("```")
    lines.append("")

    # Remediation timeline
    lines.append("### Recommended Remediation Timeline")
    lines.append("")
    lines.append("```")
    lines.append("2024          2025          2026          2027          2028")
    lines.append("  │             │             │             │             │")
    lines.append("  ├─────────────┼─────────────┼─────────────┼─────────────┤")

    if critical_count > 0:
        lines.append("  │▓▓▓▓▓▓▓▓▓▓▓▓▓│             │             │             │ 🔴 CRITICAL: Replace NOW")
    if high_count > 0:
        lines.append("  │             │▓▓▓▓▓▓▓▓▓▓▓▓▓│             │             │ 🟠 HIGH: Complete by mid-2025")
    if medium_count > 0:
        lines.append("  │             │             │▓▓▓▓▓▓▓▓▓▓▓▓▓│             │ 🟡 MEDIUM: Plan for 2025-2026")
    if low_count > 0:
        lines.append("  │░░░░░░░░░░░░░│░░░░░░░░░░░░░│░░░░░░░░░░░░░│░░░░░░░░░░░░░│ 🟢 LOW: Monitor (quantum-safe)")

    lines.append("  └─────────────┴─────────────┴─────────────┴─────────────┘")
    lines.append("```")
    lines.append("")


    lines.append("")

    # Code Source Summary
    source_counts = {}
    for r in results:
        source = r.get('code_source', 'unknown')
        source_counts[source] = source_counts.get(source, 0) + 1

    lines.append("### Code Source Summary")
    lines.append("")
    lines.append("| Source Type | Count | Remediation Approach |")
    lines.append("|-------------|-------|---------------------|")

    source_info = {
        'custom_code': ('🏠 Custom Code', 'Direct code change by dev team'),
        'open_source_library': ('📦 Open Source Library', 'File issue/PR, upgrade when fixed'),
        'commercial_library': ('💼 Commercial Library', 'Contact vendor support'),
        'framework': ('🏗️ Framework', 'Upgrade framework version'),
        'jdk_runtime': ('☕ JDK/Runtime', 'Upgrade JDK or add PQ provider'),
        'unknown': ('❓ Unknown', 'Requires investigation')
    }

    for source in ['custom_code', 'open_source_library', 'commercial_library', 'framework', 'jdk_runtime', 'unknown']:
        if source in source_counts:
            label, approach = source_info.get(source, ('Unknown', 'TBD'))
            lines.append(f"| {label} | {source_counts[source]} | {approach} |")

    lines.append("")

    # Detailed findings by risk level
    lines.append("---")
    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("")

    task_num = 1
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_QUANTUM_ISSUE']:
        level_results = [r for r in results if r.get('risk_level') == level]
        if not level_results:
            continue

        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'NOT_QUANTUM_ISSUE': '⚪'}.get(level, '❓')
        level_title = {
            'CRITICAL': 'Critical Priority',
            'HIGH': 'High Priority',
            'MEDIUM': 'Medium Priority',
            'LOW': 'Low Priority (Quantum-Safe)',
            'NOT_QUANTUM_ISSUE': 'Non-Quantum Issues'
        }.get(level, level)

        lines.append(f"### {emoji} {level_title}")
        lines.append("")

        for r in level_results:
            title = r.get('title', 'Unknown')
            lines.append(f"#### [{level}] Finding {task_num}: {title}")
            lines.append("")

            # Metadata table
            freq = r.get('frequency', 'Unknown')
            freq_count = r.get('frequency_count', 0)
            reachability = r.get('reachability', 1)

            # Code source with emoji
            code_source = r.get('code_source', 'unknown')
            source_emoji = {
                'custom_code': '🏠',
                'open_source_library': '📦',
                'commercial_library': '💼',
                'framework': '🏗️',
                'jdk_runtime': '☕'
            }.get(code_source, '❓')
            source_label = {
                'custom_code': 'Custom Code',
                'open_source_library': 'Open Source Library',
                'commercial_library': 'Commercial Library',
                'framework': 'Framework',
                'jdk_runtime': 'JDK/Runtime'
            }.get(code_source, 'Unknown')

            lines.append("| Attribute | Value |")
            lines.append("|-----------|-------|")
            lines.append(f"| **Algorithm** | `{r.get('algorithm', 'Unknown')}` |")
            lines.append(f"| **Application** | {r.get('application', 'Unknown')} |")
            lines.append(f"| **Code Source** | {source_emoji} {source_label} |")
            lines.append(f"| **Source Package** | `{r.get('source_package', 'Unknown')}` |")
            lines.append(f"| **Remediation Owner** | {r.get('remediation_owner', 'Unknown')} |")
            lines.append(f"| **Frequency** | {freq} ({freq_count:,} invocations) |")
            lines.append(f"| **Reachability** | {reachability} code path(s) invoke this algorithm |")
            lines.append(f"| **Data Sensitivity** | {r.get('data_sensitivity', 'Unknown')} |")
            lines.append(f"| **Data Lifetime** | {r.get('data_lifetime', 'Unknown')} |")
            lines.append("")

            lines.append(f"**Description:** {r.get('usage_summary', 'Unknown')}")
            lines.append("")

            lines.append(f"**Quantum Threat Analysis:** {r.get('quantum_threat', 'Unknown')}")
            lines.append("")

            # Stack trace evidence
            stack_trace = r.get('stack_trace', [])
            if stack_trace:
                lines.append("**Stack Trace:**")
                lines.append("```")
                for frame in stack_trace:
                    lines.append(frame)
                lines.append("```")
                lines.append("")

            lines.append(f"**Recommendation:** {r.get('recommendation', 'None')}")
            lines.append("")

            if r.get('migration_notes'):
                notes = r.get('migration_notes')
                if isinstance(notes, list):
                    notes = '\n'.join(f"- {n}" for n in notes)
                lines.append("**Remediation Plan:**")
                lines.append(notes)
                lines.append("")

            lines.append("---")
            lines.append("")
            task_num += 1

    # Appendix
    lines.extend([
        "## Appendix A: Algorithm Risk Matrix",
        "",
    ])

    # Algorithm risk matrix table
    lines.append("| Algorithm | Quantum Risk | Remediation Timeline |")
    lines.append("|-----------|--------------|----------------------|")

    timeline_map = {
        'CRITICAL': '🚨 Immediate',
        'HIGH': '⏰ 6 months',
        'MEDIUM': '📅 6-18 months',
        'LOW': '✅ No action needed',
        'NOT_QUANTUM_ISSUE': '🔧 Classical security fix'
    }

    for algo, level in sorted(algo_risks.items(), key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_QUANTUM_ISSUE', 'UNKNOWN'].index(x[1]) if x[1] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_QUANTUM_ISSUE', 'UNKNOWN'] else 99):
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'NOT_QUANTUM_ISSUE': '⚪'}.get(level, '❓')
        timeline = timeline_map.get(level, 'Review')
        lines.append(f"| `{algo}` | {emoji} {level} | {timeline} |")

    lines.extend([
        "",
        "---",
        "",
        "## Appendix B: Methodology",
        "",
        "### Quantum Threat Model",
        "",
        "This assessment evaluates cryptographic algorithms against two primary quantum computing threats:",
        "",
        "| Threat | Impact | Affected Algorithms |",
        "|--------|--------|---------------------|",
        "| **Shor's Algorithm** | Complete break of asymmetric crypto | RSA, ECDSA, ECDH, DH, DSA |",
        "| **Grover's Algorithm** | Halves effective key length | AES, SHA (still safe at 256-bit) |",
        "",
        "### Risk Classification Criteria",
        "",
        "- **CRITICAL**: Asymmetric cryptography protecting long-term secrets, digital signatures, or stored data",
        "- **HIGH**: Asymmetric cryptography for sensitive data with medium-term exposure",
        "- **MEDIUM**: Asymmetric cryptography with forward secrecy mitigations",
        "- **LOW**: Symmetric cryptography with sufficient key sizes (quantum-resistant)",
        "- **NOT_QUANTUM_ISSUE**: Classical cryptographic weaknesses unrelated to quantum threats",
        "",
        "### Data Sources",
        "",
        "Cryptographic usage data collected via Contrast Security runtime instrumentation, providing:",
        "- Actual algorithms in use (not just declared dependencies)",
        "- Complete call stack context for usage classification",
        "- Invocation frequency and code path reachability metrics",
        "",
        "---",
        "",
        "*Report generated by Contrast Quantum Advisor*",
        "*Powered by Contrast Security Runtime Observability*",
    ])

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='AI-powered quantum cryptography remediation task generator'
    )
    parser.add_argument('cbom', help='Path to CBOM JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output report file (markdown)')
    parser.add_argument('--json', help='Output raw JSON results')
    parser.add_argument('--no-confirm', action='store_true', help='Skip cost confirmation')
    parser.add_argument('--filter', choices=['all', 'vulnerable', 'asymmetric'],
                       default='all', help='Filter which occurrences to analyze')

    args = parser.parse_args()

    # Parse CBOM
    print(f"\n{Colors.BLUE}Parsing CBOM...{Colors.NC}")
    try:
        occurrences, metadata, app_metadata = parse_cbom(args.cbom)
    except Exception as e:
        print(f"{Colors.RED}Error parsing CBOM: {e}{Colors.NC}")
        sys.exit(1)

    print(f"  Found {len(occurrences)} cryptographic usage instances")

    # Filter occurrences
    if args.filter == 'vulnerable':
        occurrences = [o for o in occurrences if o.quantum_level == 0]
        print(f"  Filtered to {len(occurrences)} quantum-vulnerable instances")
    elif args.filter == 'asymmetric':
        occurrences = [o for o in occurrences if o.primitive in ('pke', 'signature', 'kex', 'key-agree')]
        print(f"  Filtered to {len(occurrences)} asymmetric crypto instances")

    if not occurrences:
        print(f"\n{Colors.GREEN}No matching cryptographic usages found!{Colors.NC}")
        return

    # Initialize AI client
    client = AIClient()

    # Only describe applications that actually have a matching finding
    apps_in_scope = {name: app for name, app in app_metadata.items()
                      if name in {o.application for o in occurrences}}

    # Estimate cost (occurrence analysis + one description call per application)
    estimated_cost = client.estimate_cost(len(occurrences) + len(apps_in_scope),
                                           avg_input_tokens=1800, avg_output_tokens=550)

    if not args.no_confirm and not confirm_cost(estimated_cost, len(occurrences) + len(apps_in_scope)):
        print("Cancelled.")
        sys.exit(0)

    # Describe each application's likely role once, from its architecture graph context
    app_descriptions = {}
    if apps_in_scope:
        print(f"\n{Colors.BLUE}Describing {len(apps_in_scope)} applications...{Colors.NC}")
        app_descriptions = generate_app_descriptions(client, apps_in_scope, args.verbose)

    # Analyze each occurrence
    print(f"\n{Colors.BLUE}Analyzing {len(occurrences)} cryptographic usages...{Colors.NC}")
    results = []
    for occ in occurrences:
        try:
            result = analyze_occurrence(client, occ, args.verbose)
            results.append(result)

            # Print quick status
            risk = result.get('risk_level', 'UNKNOWN')
            title = result.get('title', f"{occ.algorithm} in {occ.application}")
            color = {
                'CRITICAL': Colors.RED,
                'HIGH': Colors.YELLOW,
                'MEDIUM': Colors.YELLOW,
                'LOW': Colors.GREEN,
                'NOT_QUANTUM_ISSUE': Colors.DIM
            }.get(risk, Colors.NC)
            print(f"  {color}[{risk}] {title}{Colors.NC}")
        except Exception as e:
            print(f"  {Colors.RED}Error analyzing {occ.algorithm} in {occ.application}: {e}{Colors.NC}")
            results.append({
                "algorithm": occ.algorithm,
                "application": occ.application,
                "risk_level": "ERROR",
                "title": f"{occ.algorithm} in {occ.application}",
                "recommendation": str(e)
            })

    # Write descriptions and quantum:* risk properties back into the CBOM itself
    apps_described, algorithms_annotated = enrich_bom(args.cbom, app_descriptions, results)
    if apps_described or algorithms_annotated:
        print(f"  Enriched {args.cbom}: {apps_described} application description(s), "
              f"{algorithms_annotated} algorithm(s) annotated with quantum:* properties")

    # Generate report
    report = generate_report(results, metadata, app_metadata, app_descriptions)

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n{Colors.GREEN}Report written to {args.output}{Colors.NC}")

        # Also generate HTML version
        html_output = args.output.replace('.md', '.html')
        html_report = generate_html_report(report)
        with open(html_output, 'w') as f:
            f.write(html_report)
        print(f"{Colors.GREEN}HTML report written to {html_output}{Colors.NC}")
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
