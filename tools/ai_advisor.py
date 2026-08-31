#!/usr/bin/env python3
"""
ai_advisor.py: AI-powered inventory report of AI-enabled applications from an AI-BOM.

Groups findings by application (not by risk level): for each app, describes what
the application appears to be based on its architecture/connection graph, then
lists how it uses AI (model, provider, and what each call appears to do, inferred
from the stack trace).

Usage:
    python ai_advisor.py aibom.json
    python ai_advisor.py aibom.json --verbose
    python ai_advisor.py aibom.json --output report.md
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional
from ai_client import AIClient, Colors, confirm_cost


ANALYSIS_PROMPT = """You are an application security and AI governance analyst building an inventory of \
AI-enabled applications from Contrast Security runtime observability data.

You are given metadata about ONE application (name, language, architecture/connection graph info) and a \
list of AI/LLM usage instances observed running in it, each with a model, provider, endpoint, and a real \
stack trace captured at runtime.

## Your Task

1. Write a 2-4 sentence description of what this application/API most likely does. Base this on its name, \
language, which other applications it's connected to, and its library footprint - not on the AI usage alone.
2. For EACH AI usage instance provided, write a 2-3 sentence description of what that specific call appears \
to be doing. Name the 2-4 key application/library methods on the call path immediately around the AI call \
(e.g. "AiController.openai calls AiService.chat, which invokes the OpenAI ChatCompletionService.create client") \
rather than describing the call in the abstract - the caller/callee names are what make this concrete. Ignore \
generic framework/container plumbing (servlet dispatch, filter chains, thread pool internals) further down the \
stack; focus on the application-level and client-library frames closest to the AI call itself. Be concrete about \
the apparent purpose (e.g. "generates a chat reply for the /chat endpoint", "summarizes an uploaded document").
3. Assess the overall AI usage risk level for this application.

## Risk Levels

**CRITICAL**: Sensitive/regulated data (PII, credentials, source code, health/financial records) likely sent \
to an unvetted third-party model, or an unknown model/provider in a production path with no oversight.
**HIGH**: Production cloud AI usage without an apparent governance process ("shadow AI").
**MEDIUM**: Approved-looking usage lacking monitoring, or non-production usage that could reach production unreviewed.
**LOW**: Local/self-hosted model with no external data egress, or clearly low-sensitivity usage.
**NOT_AI_RISK_ISSUE**: Benign, well-governed usage with no identifiable risk signal.

## Your Task - Output

Return JSON:
```json
{
  "application_description": "2-4 sentence description of what this app/API does",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|NOT_AI_RISK_ISSUE",
  "governance_concern": "shadow_ai|ungoverned_cloud_usage|data_exposure_risk|low_risk|none",
  "risk_rationale": "Why this risk level, considering the app's role and connections",
  "recommendation": "Specific action to take for this application's AI usage",
  "ai_usages": [
    {
      "model": "model name exactly as given",
      "usage_description": "2-3 sentences naming the key methods on the call path around the AI call"
    }
  ]
}
```

Include exactly one entry in "ai_usages" for each usage instance given below, in the same order.
"""


@dataclass
class AIUsageInstance:
    """A single AI/LLM usage instance within an application."""
    model: str
    provider: Optional[str]
    endpoint: Optional[str]
    host_category: str
    usage_count: int
    unique_locations: int
    stack_trace: list[str]
    route: Optional[str]


@dataclass
class AppInventoryEntry:
    """One application's AI usage inventory entry."""
    name: str
    language: Optional[str]
    posture_score: Optional[float]
    posture_severity: Optional[str]
    criticality: Optional[int]
    open_issues_total: Optional[int]
    server_count: int
    library_count: int
    connected_applications: list[str]
    ai_usages: list[AIUsageInstance] = field(default_factory=list)


def get_frequency_label(usage_count: int) -> str:
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


def extract_stack_trace(context: str) -> list[str]:
    if 'Stack Trace:' not in context:
        return []
    parts = context.split('Stack Trace:')
    if len(parts) < 2:
        return []
    stack_text = parts[1].strip()
    return [f.strip() for f in stack_text.split(' ') if f.strip()]


# Frame prefixes that are generic framework/container plumbing, not useful for
# describing what an AI call is doing - trimmed out before the frame limit applies.
_NOISY_FRAME_PREFIXES = (
    'java.base/', 'javax.servlet', 'jakarta.servlet',
    'org.springframework.web.servlet', 'org.springframework.web.filter',
    'org.apache.catalina', 'org.apache.tomcat', 'org.apache.coyote',
    'sun.reflect', 'jdk.internal.reflect',
)


def trim_stack_trace(frames: list[str], max_frames: int = 6) -> list[str]:
    """Keep just the application/client-library frames closest to the call site."""
    relevant = [f for f in frames if not f.startswith(_NOISY_FRAME_PREFIXES)]
    return relevant[:max_frames]


def extract_route(context: str) -> Optional[str]:
    if 'Route:' not in context:
        return None
    after = context.split('Route:', 1)[1]
    route = after.split('|')[0].split('\n')[0].strip()
    return route or None


def parse_aibom(aibom_path: str) -> tuple[list[AppInventoryEntry], dict]:
    """Parse an AI-BOM file into a per-application inventory."""
    with open(aibom_path, 'r') as f:
        aibom = json.load(f)

    app_components = {}
    model_components = {}
    for component in aibom.get('components', []):
        bom_ref = component.get('bom-ref', '')
        if component.get('type') == 'application' and bom_ref.startswith('app-'):
            app_components[bom_ref] = component
        elif component.get('type') == 'machine-learning-model':
            model_components[bom_ref] = component

    # Map app bom-ref -> list of model bom-refs it depends on
    app_to_models = {}
    for dep in aibom.get('dependencies', []):
        ref = dep.get('ref')
        if ref in app_components:
            app_to_models[ref] = list(dep.get('dependsOn', []))

    entries = []
    for app_ref, app_component in app_components.items():
        props = {p['name']: p['value'] for p in app_component.get('properties', [])}
        app_name = app_component.get('name', app_ref)

        connected = props.get('contrast:connectedApplications', '')
        connected_list = [c.strip() for c in connected.split(',') if c.strip()]

        entry = AppInventoryEntry(
            name=app_name,
            language=props.get('contrast:language'),
            posture_score=float(props['contrast:postureScore']) if 'contrast:postureScore' in props else None,
            posture_severity=props.get('contrast:postureSeverity'),
            criticality=int(props['contrast:criticality']) if 'contrast:criticality' in props else None,
            open_issues_total=int(props['contrast:openIssuesTotal']) if 'contrast:openIssuesTotal' in props else None,
            server_count=int(props.get('contrast:serverCount', 0)),
            library_count=int(props.get('contrast:libraryCount', 0)),
            connected_applications=connected_list,
        )

        for model_ref in app_to_models.get(app_ref, []):
            model_component = model_components.get(model_ref)
            if not model_component:
                continue
            model_props = {p['name']: p['value'] for p in model_component.get('properties', [])}
            model_name = model_component.get('name', model_ref)
            provider = model_component.get('publisher') or model_props.get('contrast:provider')

            evidence = model_component.get('evidence', {})
            for occ in evidence.get('occurrences', []):
                context = occ.get('additionalContext', '')
                # Only include occurrences that belong to this application
                if f"App: {app_name}" not in context:
                    continue
                entry.ai_usages.append(AIUsageInstance(
                    model=model_name,
                    provider=provider,
                    endpoint=model_props.get('contrast:endpoint'),
                    host_category=model_props.get('contrast:hostCategory', 'unknown'),
                    usage_count=int(model_props.get('contrast:usageCount', 0)),
                    unique_locations=int(model_props.get('contrast:uniqueLocations', 1)),
                    stack_trace=extract_stack_trace(context),
                    route=extract_route(context),
                ))

        if entry.ai_usages:
            entries.append(entry)

    return entries, aibom.get('metadata', {})


def format_app_for_ai(entry: AppInventoryEntry) -> str:
    lines = [
        f"Application: {entry.name}",
        f"Language: {entry.language or 'unknown'}",
        f"Connected Applications: {', '.join(entry.connected_applications) or 'none observed'}",
        f"Library Count: {entry.library_count}",
        f"Server Instances: {entry.server_count}",
        "",
        "AI Usage Instances:",
    ]
    for i, usage in enumerate(entry.ai_usages, 1):
        lines.append(f"\n--- Usage {i} ---")
        lines.append(f"Model: {usage.model}")
        lines.append(f"Provider: {usage.provider or 'unknown'}")
        lines.append(f"Endpoint: {usage.endpoint or 'unknown'} ({usage.host_category})")
        lines.append(f"Route: {usage.route or 'unknown'}")
        lines.append(f"Usage Count: {usage.usage_count}")
        lines.append("Stack Trace:")
        lines.append('\n'.join(usage.stack_trace) if usage.stack_trace else '(none captured)')

    return '\n'.join(lines)


def analyze_application(client: AIClient, entry: AppInventoryEntry, verbose: bool = False) -> dict:
    entry_text = format_app_for_ai(entry)

    if verbose:
        print(f"\n{Colors.DIM}Analyzing {entry.name} ({len(entry.ai_usages)} AI usage instances)...{Colors.NC}")

    response, usage = client.call(ANALYSIS_PROMPT, entry_text, max_tokens=2000)

    if verbose:
        client.log_call(entry.name, usage)

    try:
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        if json_start >= 0 and json_end > json_start:
            result = json.loads(response[json_start:json_end])
            result['application'] = entry.name
            return result
    except json.JSONDecodeError:
        pass

    return {
        "application": entry.name,
        "risk_level": "UNKNOWN",
        "application_description": "Failed to parse AI response",
        "recommendation": response[:500],
        "ai_usages": []
    }


def write_descriptions_to_bom(aibom_path: str, results: list[dict]) -> int:
    """Write generated application descriptions back into the AI-BOM's own application
    components (CycloneDX's standard Component.description field), so the BOM is
    self-describing for anyone who consumes the JSON directly. Returns the count written."""
    descriptions = {r.get('application'): r.get('application_description') for r in results if r.get('application')}

    with open(aibom_path, 'r') as f:
        aibom = json.load(f)

    written = 0
    for component in aibom.get('components', []):
        bom_ref = component.get('bom-ref', '')
        if component.get('type') != 'application' or not bom_ref.startswith('app-'):
            continue
        description = descriptions.get(component.get('name', ''))
        if description:
            component['description'] = description
            written += 1

    if written:
        with open(aibom_path, 'w') as f:
            json.dump(aibom, f, indent=2)

    return written


def generate_report(app_results: list[dict], entries: list[AppInventoryEntry], metadata: dict) -> str:
    """Generate a markdown inventory report, organized by application."""
    from datetime import datetime

    report_date = datetime.now().strftime("%B %d, %Y")
    source_name = metadata.get('component', {}).get('name', 'Unknown')

    entries_by_name = {e.name: e for e in entries}

    risk_counts = {}
    risk_by_app = {}
    for r in app_results:
        level = r.get('risk_level', 'UNKNOWN')
        risk_counts[level] = risk_counts.get(level, 0) + 1
        risk_by_app[r.get('application')] = level

    total_apps = len(app_results)
    total_usages = sum(len(e.ai_usages) for e in entries)
    critical_count = risk_counts.get('CRITICAL', 0)
    high_count = risk_counts.get('HIGH', 0)
    action_needed = critical_count + high_count

    # Aggregate model/provider usage across all applications. usage_count is the
    # model's total invocation count (computed once, org-wide, by AIBOMGenerator) -
    # it's the same value on every occurrence of that model, so it's set once per
    # model here, not summed across occurrences/apps (which would double-count it).
    model_summary = {}
    for e in entries:
        for u in e.ai_usages:
            key = (u.provider or 'unknown', u.model)
            agg = model_summary.setdefault(key, {'host_category': u.host_category, 'apps': set(), 'usage_count': u.usage_count})
            agg['apps'].add(e.name)

    cloud_models = sorted({k for k, v in model_summary.items() if v['host_category'] == 'cloud'})
    local_models = sorted({k for k, v in model_summary.items() if v['host_category'] == 'local'})

    lines = [
        "<!-- Contrast AI Advisor Report -->",
        "",
        "# Contrast AI Advisor",
        "## Inventory of AI-Enabled Applications",
        "",
        "---",
        "",
        f"**Client:** {source_name}",
        f"**Report Date:** {report_date}",
        f"**Assessment Type:** Runtime AI/LLM Usage Inventory & Governance Risk Assessment",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This report inventories every AI/LLM model and provider observed actually running in production "
        f"across your applications - the model, provider, destination endpoint, and real call stack behind "
        f"each usage, captured by Contrast Security's runtime instrumentation.",
        "",
        f"**{total_apps}** application(s) use AI, calling **{len(model_summary)}** distinct model(s) across "
        f"**{len({provider for provider, _ in model_summary})}** provider(s), for **{total_usages}** total usage instance(s).",
        "",
    ]

    if action_needed > 0:
        lines.append(f"> **{action_needed} of {total_apps} applications need priority review** "
                    f"({critical_count} critical, {high_count} high) for their AI usage.")
    else:
        lines.append("> No applications were flagged CRITICAL or HIGH risk for their AI usage.")

    lines.append("")
    lines.append("### Applications")
    lines.append("")
    lines.append("| Application | Risk Level | Models Used |")
    lines.append("|-------------|------------|--------------|")
    for e in entries:
        models_used = ', '.join(sorted({f"`{u.model}`" for u in e.ai_usages}))
        lines.append(f"| {e.name} | {risk_by_app.get(e.name, 'UNKNOWN')} | {models_used} |")

    lines.append("")
    lines.append("### Models & Providers")
    lines.append("")
    lines.append("| Provider | Model | Host Category | Applications | Invocations |")
    lines.append("|----------|-------|----------------|---------------|-------------|")
    for (provider, model), agg in sorted(model_summary.items()):
        lines.append(f"| {provider} | `{model}` | {agg['host_category']} | {len(agg['apps'])} | {agg['usage_count']:,} |")

    lines.append("")
    if cloud_models:
        lines.append(f"- **{len(cloud_models)}** model(s) called over the network to an external cloud provider "
                    f"(data leaves your infrastructure)")
    if local_models:
        lines.append(f"- **{len(local_models)}** model(s) self-hosted/local (no external data egress)")

    lines.append("")
    lines.append("| Risk Level | Applications |")
    lines.append("|------------|--------------|")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_AI_RISK_ISSUE', 'UNKNOWN']:
        if risk_counts.get(level):
            lines.append(f"| {level} | {risk_counts[level]} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Application Inventory")
    lines.append("")

    # Sort applications by risk severity, most severe first
    order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOT_AI_RISK_ISSUE', 'UNKNOWN']
    app_results_sorted = sorted(
        app_results,
        key=lambda r: order.index(r.get('risk_level', 'UNKNOWN')) if r.get('risk_level') in order else 99
    )

    for r in app_results_sorted:
        app_name = r.get('application', 'Unknown')
        entry = entries_by_name.get(app_name)
        risk_level = r.get('risk_level', 'UNKNOWN')

        lines.append(f"### {app_name}")
        lines.append("")
        lines.append(f"**Risk Level:** {risk_level}")
        lines.append("")

        if entry:
            meta_bits = []
            if entry.language:
                meta_bits.append(f"**Language:** {entry.language}")
            if entry.posture_score is not None:
                meta_bits.append(f"**Posture Score:** {entry.posture_score} ({entry.posture_severity})")
            if entry.open_issues_total is not None:
                meta_bits.append(f"**Open Issues:** {entry.open_issues_total}")
            if entry.connected_applications:
                meta_bits.append(f"**Connects To:** {', '.join(entry.connected_applications)}")
            if meta_bits:
                lines.append(" | ".join(meta_bits))
                lines.append("")

        lines.append(r.get('application_description', 'No description available.'))
        lines.append("")

        lines.append(f"**Risk Rationale:** {r.get('risk_rationale', 'Unknown')}")
        lines.append("")
        lines.append(f"**Recommendation:** {r.get('recommendation', 'None')}")
        lines.append("")

        lines.append("#### AI Usage")
        lines.append("")

        usage_descriptions = {u.get('model'): u.get('usage_description') for u in r.get('ai_usages', [])}

        if entry:
            for usage in entry.ai_usages:
                freq = get_frequency_label(usage.usage_count)
                lines.append(f"**Model:** `{usage.model}`" + (f" ({usage.provider})" if usage.provider else ""))
                lines.append("")
                lines.append("| Attribute | Value |")
                lines.append("|-----------|-------|")
                lines.append(f"| **Endpoint** | `{usage.endpoint or 'unknown'}` |")
                lines.append(f"| **Host Category** | {usage.host_category} |")
                lines.append(f"| **Route** | {usage.route or 'unknown'} |")
                lines.append(f"| **Frequency** | {freq} ({usage.usage_count:,} invocations) |")
                lines.append(f"| **Reachability** | {usage.unique_locations} code path(s) |")
                lines.append("")

                description = usage_descriptions.get(usage.model, "No description available.")
                lines.append(f"**What it's doing:** {description}")
                lines.append("")

                if usage.stack_trace:
                    lines.append("**Stack Trace:**")
                    lines.append("```")
                    for frame in usage.stack_trace:
                        lines.append(frame)
                    lines.append("```")
                    lines.append("")

        lines.append("---")
        lines.append("")

    lines.extend([
        "## Appendix: Methodology",
        "",
        "AI/LLM usage data collected via Contrast Security runtime instrumentation. Application descriptions "
        "and connection data are derived from the Contrast architecture graph (application, server, and "
        "library relationships); AI usage descriptions are inferred from the real stack trace captured at "
        "each call site.",
        "",
        "- **CRITICAL**: Likely sensitive/regulated data sent to an unvetted third-party model",
        "- **HIGH**: Production cloud AI usage without an apparent governance process",
        "- **MEDIUM**: Approved-looking usage lacking monitoring, or non-production usage that could reach production",
        "- **LOW**: Local/self-hosted usage or clearly low-sensitivity usage",
        "- **NOT_AI_RISK_ISSUE**: Benign, well-governed usage with no identifiable risk signal",
        "",
        "---",
        "",
        "*Report generated by Contrast AI Advisor*",
        "*Powered by Contrast Security Runtime Observability*",
    ])

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='AI-powered inventory of AI-enabled applications from an AI-BOM'
    )
    parser.add_argument('aibom', help='Path to AI-BOM JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output report file (markdown)')
    parser.add_argument('--json', help='Output raw JSON results')
    parser.add_argument('--no-confirm', action='store_true', help='Skip cost confirmation')

    args = parser.parse_args()

    print(f"\n{Colors.BLUE}Parsing AI-BOM...{Colors.NC}")
    try:
        entries, metadata = parse_aibom(args.aibom)
    except Exception as e:
        print(f"{Colors.RED}Error parsing AI-BOM: {e}{Colors.NC}")
        sys.exit(1)

    total_usages = sum(len(e.ai_usages) for e in entries)
    print(f"  Found {len(entries)} applications with {total_usages} AI usage instances")

    if not entries:
        print(f"\n{Colors.GREEN}No AI-enabled applications found!{Colors.NC}")
        return

    client = AIClient()

    estimated_cost = client.estimate_cost(len(entries), avg_input_tokens=2000, avg_output_tokens=800)

    if not args.no_confirm and not confirm_cost(estimated_cost, len(entries)):
        print("Cancelled.")
        sys.exit(0)

    print(f"\n{Colors.BLUE}Analyzing {len(entries)} applications...{Colors.NC}")
    results = []
    for entry in entries:
        try:
            result = analyze_application(client, entry, args.verbose)
            results.append(result)

            risk = result.get('risk_level', 'UNKNOWN')
            color = {
                'CRITICAL': Colors.RED,
                'HIGH': Colors.YELLOW,
                'MEDIUM': Colors.YELLOW,
                'LOW': Colors.GREEN,
                'NOT_AI_RISK_ISSUE': Colors.DIM
            }.get(risk, Colors.NC)
            print(f"  {color}[{risk}] {entry.name} ({len(entry.ai_usages)} usage(s)){Colors.NC}")
        except Exception as e:
            print(f"  {Colors.RED}Error analyzing {entry.name}: {e}{Colors.NC}")
            results.append({
                "application": entry.name,
                "risk_level": "ERROR",
                "application_description": str(e),
                "ai_usages": []
            })

    written = write_descriptions_to_bom(args.aibom, results)
    if written:
        print(f"  Wrote {written} application description(s) back into {args.aibom}")

    report = generate_report(results, entries, metadata)

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

    client.print_summary()


if __name__ == '__main__':
    main()
