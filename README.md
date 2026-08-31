# Quantum

Generate [CycloneDX](https://cyclonedx.org/) Bills of Materials from Contrast Security runtime observability data:

- **CBOM** ([Cryptography Bill of Materials](https://cyclonedx.org/capabilities/cbom/)) - every cryptographic algorithm actually observed running, for post-quantum migration planning
- **AI-BOM** (AI/LLM usage inventory) - every AI model and provider actually observed running, for AI governance and shadow-AI visibility

Both come with an AI-powered advisor report: **Quantum Advisor** (crypto risk) and **AI Advisor** (AI usage risk).

**Requirements:** Java 8+ and Maven to build; the `claude` CLI on your `PATH` and logged in, for the AI analysis. No Python, no separate API key, no AWS/Bedrock credentials. One jar, one command per BOM type.

## Why Contrast for This?

Contrast provides runtime observability that goes far beyond static code scanning or self-reported inventories:

- **Full-stack inventory** - Captures crypto and AI usage across your entire application stack at runtime, not just what's declared in source code or dependency manifests
- **Complete details** - Algorithm strength/mode/padding/OIDs for crypto; provider/model/endpoint for AI
- **Usage metrics** - How often each crypto algorithm or AI model is actually called in production
- **Full stack traces** - Understand the context: is this crypto protecting passwords, SSL/TLS, tokens? Is this AI call generating a chat reply, summarizing a document?
- **Multiple call paths** - See how many different code paths invoke each algorithm/model
- **Architecture context** - Each application component is enriched with its language, security posture, and what it's connected to (from the Contrast architecture graph), so the advisor reports can describe what an application actually is, not just what it uses
- **Application dependencies** - Which apps and APIs depend on each crypto algorithm or AI model

This runtime visibility is critical for post-quantum migration and AI governance planning - you need to know not just *what's* in use, but *how* it's being used and by *what*.

## Features

- Generates CycloneDX 1.6 compliant CBOM and AI-BOM in JSON format
- Fetches usage data from the Contrast `/observations` API (crypto algorithms and AI/LLM usage share this endpoint, filtered by rule type)
- Shows which applications use which algorithms/models
- Application components are enriched with `contrast:*` properties (language, posture score, criticality, open issues, connections) and a deep-link `externalReference` back to the Contrast Explorer UI, both pulled from the `contrast-graph` API
- Includes NIST quantum security levels for post-quantum migration planning, and cloud-vs-local host classification for AI usage
- Tracks usage counts and unique call locations per algorithm/model
- Full stack traces showing usage context
- Filters by application or environment (PRODUCTION, DEVELOPMENT, QA)
- `--analyze` runs the matching AI advisor after generation, which writes its generated application descriptions back into the BOM's `Component.description` field

## Quick Start

1. Create `contrast.properties` in your working directory:

```properties
contrast.url=https://your-instance.contrastsecurity.com/api/ns-ui/v1
contrast.org_id=your-org-id
contrast.auth_header=base64-encoded-email:service-key
contrast.api_key=your-api-key
```

2. Build and run:

```bash
mvn clean package

# CBOM
java -jar target/quantum-1.0-SNAPSHOT.jar cbom

# AI-BOM
java -jar target/quantum-1.0-SNAPSHOT.jar aibom
```

## Usage

A single jar with two subcommands, `cbom` and `aibom`, taking the same set of flags:

### CBOM (crypto)

```bash
# Generate CBOM for all apps
java -jar quantum.jar cbom

# List available applications
java -jar quantum.jar cbom --list

# Generate CBOM for specific app (by name or ID)
java -jar quantum.jar cbom --app "MyApp"
java -jar quantum.jar cbom --app 7136cb1b-f846-4c1d-bdd3-77b448cbd2fe

# Filter by environment
java -jar quantum.jar cbom --env PRODUCTION

# Combine filters
java -jar quantum.jar cbom --app "MyApp" --env PRODUCTION -o myapp-prod.json

# Use custom config file
java -jar quantum.jar cbom -c /path/to/config.properties

# Generate CBOM + AI-powered Quantum Advisor risk report
java -jar quantum.jar cbom --analyze
```

### AI-BOM (AI/LLM usage)

Same flags, `aibom` subcommand:

```bash
java -jar quantum.jar aibom
java -jar quantum.jar aibom --list
java -jar quantum.jar aibom --app "MyApp" --env PRODUCTION
java -jar quantum.jar aibom --analyze
```

### Re-running an advisor against an existing BOM

`cbom --analyze` / `aibom --analyze` already run the matching advisor automatically after generation. To re-run the advisor against a BOM you already have (without regenerating it), use the standalone subcommands:

```bash
# Crypto / post-quantum risk report
java -jar quantum.jar cbom-advisor cbom.json -o report.md

# AI usage inventory / governance risk report
java -jar quantum.jar aibom-advisor aibom.json -o report.md
```

Everything - BOM generation and AI analysis - runs in a single JVM process. The advisors shell out to the `claude` CLI already logged in to this shell (no separate API key or AWS/Bedrock credentials needed, and no Python required) - just make sure `claude` is on your `PATH` and authenticated.

## Output

### CBOM

- **Application components** with dependencies on crypto algorithms, enriched with `contrast:language`/`postureScore`/`connectedApplications`/etc. and a deep-link `externalReference`
- **Cryptographic asset components** with:
  - Algorithm properties (primitive, mode, padding)
  - OID (Object Identifier)
  - Classical security level
  - NIST quantum security level (0 = quantum vulnerable)
  - `contrast:usageCount` / `contrast:uniqueLocations`
  - Full stack traces showing usage context (passwords, SSL, etc.), deduplicated per-application

```
Contrast Crypto Inventory
├── app-frontend → SHA-256, AES/GCM
└── app-backend → SHA-256, MD5 (quantum vulnerable), RSA
```

### AI-BOM

- **Application components**, enriched the same way as the CBOM's
- **`machine-learning-model` components** (one per provider/model observed) with:
  - `contrast:provider` / `contrast:endpoint` / `contrast:hostCategory` (`cloud`, `local`, or `unknown`)
  - `contrast:usageCount` / `contrast:uniqueLocations`
  - Full stack traces, deduplicated per-application

```
Contrast AI Usage Inventory
├── app-aiservice → openai/gpt-4o (cloud)
└── app-reportservice → openai/smollm2:135m-tuned (local, via Ollama)
```

### Advisor reports

- **Quantum Advisor** - findings grouped by risk level (CRITICAL/HIGH/MEDIUM/LOW/NOT_QUANTUM_ISSUE), with an "Application Context" section describing each app from its architecture graph data
- **AI Advisor** - organized as an inventory of AI-enabled applications (one section per app, not per finding): an AI-generated description of what the app does, then each AI usage instance with model/provider/endpoint and a description of what that specific call is doing, inferred from the key methods around it in the stack trace

Both advisors write their generated application descriptions back into the source BOM's `Component.description` field, so the BOM itself stays self-describing even without the report. The Quantum Advisor also writes `quantum:*` risk properties (risk level, recommendation, code source, etc.) back onto each crypto algorithm component - this happens automatically as part of every run, no separate step needed.

## BOM Viewer

`tools/bom-viewer.html` is a standalone, offline browser tool for viewing a CBOM or AI-BOM: drag and drop (or click to browse for) a JSON file and it detects which kind of BOM it is and renders it accordingly - no server or build step required.

- **CBOM** - crypto algorithm components as readable cards, including any `quantum:*` risk properties the advisor wrote back
- **AI-BOM** - an application-by-application view (model, provider, endpoint, host category, stack trace) plus each app's `Component.description`, mirroring the AI Advisor report

```bash
open tools/bom-viewer.html
```

Two sample AI-BOM files are included to try it with:
- `sample-aibom.json` - real output from `AIBOMGenerator` against a live org (one model, both apps local/self-hosted)
- `test-aibom.json` - a hand-crafted fixture covering cases the sample doesn't: multiple providers (OpenAI/Anthropic/Ollama), both cloud and local host categories, and an app with multiple call sites for the same model

## Building

```bash
mvn clean package
```

Creates `target/quantum-1.0-SNAPSHOT.jar` (executable uber-jar; `Main` dispatches to `cbom`/`aibom` based on the first argument).

## Configuration

| Property | Description |
|----------|-------------|
| `contrast.url` | Contrast API base URL |
| `contrast.org_id` | Your organization ID |
| `contrast.auth_header` | Base64 encoded `email:service_key` |
| `contrast.api_key` | Your API key |

## Algorithm Analysis

The tool automatically parses algorithm strings straight from the JCA `Cipher`/`MessageDigest`/etc. constructor (e.g., `AES/GCM/NoPadding`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`, `PBEWithMD5AndDES`) and extracts:

- Algorithm family (AES, RSA, SHA, DES/3DES, PBE, etc.)
- Mode (GCM, CBC, ECB, CTR, etc.) - omitted for asymmetric algorithms, where a "mode" segment in the transformation string is a JCA naming artifact, not a real cryptographic mode
- Padding scheme
- Key size
- Cryptographic primitive type
- Security levels

### Quantum Vulnerability

Algorithms are classified by NIST quantum security level:
- **Level 0**: Quantum vulnerable (RSA, ECDSA, ECDH, etc.) - also used as a catch-all for classically-broken algorithms (MD5, SHA-1, DES) that the advisor then re-classifies as `NOT_QUANTUM_ISSUE`
- **Level 1-5**: Quantum resistant (AES-128+, SHA-256+, ML-KEM, ML-DSA, etc.)

## License

Copyright Contrast Security
