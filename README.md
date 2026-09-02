# Runtime Analyst

Runtime Analyst turns Contrast Security's runtime observability data into structured, standard reports, across three domains:

- **Crypto** - every cryptographic algorithm observed running in your applications, with NIST post-quantum vulnerability classification
- **AI** - every AI model and provider observed running, with cloud-vs-local classification for shadow-AI visibility
- **Blueprint (alpha)** - a map of how your applications connect and behave: assets, deployment zones, connections, and crypto/AI behaviors

For Crypto and AI, it produces both a [CycloneDX](https://cyclonedx.org/) Bill of Materials - **CBOM** and **AI-BOM** - and an AI-powered analysis report - **Quantum Advisor** and **AI Advisor** - that classifies findings, explains what each application actually does, and writes its analysis back into the BOM itself. Blueprint (alpha) produces only a draft CycloneDX 2.0 Architectural BOM + Bill of Behaviors; it doesn't have an analysis report yet.

It doesn't scan source code or dependency manifests - it reads what Contrast's agents observed actually running in your applications, with full stack traces, usage counts, and architecture context.

**Requirements:**

- A Contrast account with runtime data already flowing in from real-world applications and APIs - Contrast's agents must actually be deployed and observing traffic. Runtime Analyst only reports on what Contrast has observed; it has nothing to show against an account with no instrumented applications or no production/QA traffic.
- Java 17+ and Maven to build.
- The `claude` CLI on your `PATH` and logged in, for `--analyze`/the advisor reports - no separate API key, no AWS/Bedrock credentials, no Python.

One jar, one command per report type.

## Why Contrast for This?

Contrast provides runtime observability that goes far beyond static code scanning or self-reported inventories:

- **Full-stack inventory** - Captures crypto and AI usage across your entire application stack at runtime, not just what's declared in source code or dependency manifests
- **Complete details** - Algorithm strength/mode/padding/OIDs for crypto; provider/model/endpoint for AI
- **Usage metrics** - How often each crypto algorithm or AI model is actually called in production
- **Full stack traces** - Understand the context: is this crypto protecting passwords, SSL/TLS, tokens? Is this AI call generating a chat reply, summarizing a document?
- **Multiple call paths** - See how many different code paths invoke each algorithm/model
- **Architecture context** - Each application component is enriched with its language, security posture, and what it's connected to (from the Contrast architecture graph), so the advisor reports can describe what an application actually is, not just what it uses
- **Application dependencies** - Which apps and APIs depend on each crypto algorithm or AI model
- **Real connections, not guesses** - Blueprint's assets, zones, and flows come from the same architecture graph, so the map it draws is what Contrast actually saw talking to what, not an inferred or self-reported topology

This runtime visibility is critical for post-quantum migration and AI governance planning - you need to know not just *what's* in use, but *how* it's being used and by *what*.

## `--help`

```
$ java -jar runtime-analyst.jar

Runtime Analyst - Contrast Security Bill of Materials generator

Usage:
  java -jar runtime-analyst.jar auth [options]              Connect to Contrast and generate contrast.properties
  java -jar runtime-analyst.jar cbom [options]              Generate a Cryptography Bill of Materials
  java -jar runtime-analyst.jar aibom [options]             Generate an AI/LLM usage Bill of Materials
  java -jar runtime-analyst.jar blueprint [options]         Generate a CycloneDX Blueprint (ABOM + Bill of Behaviors)
  java -jar runtime-analyst.jar cbom-advisor <cbom.json>    Re-run the Quantum Advisor against an existing CBOM
  java -jar runtime-analyst.jar aibom-advisor <aibom.json>  Re-run the AI Advisor against an existing AI-BOM

`cbom --analyze` / `aibom --analyze` already run the matching advisor automatically after generation -
the standalone cbom-advisor/aibom-advisor commands are for re-running the advisor without regenerating the BOM.

Run with -h after a subcommand for its options, e.g.:
  java -jar runtime-analyst.jar cbom -h
  java -jar runtime-analyst.jar aibom -h
```

Every subcommand supports `-h`/`--help` for its own options - see [Examples](#examples) below for each one's full help text.

## Authentication

Every command except `auth` itself reads a `contrast.properties` file for credentials. If `cbom`, `aibom`, or `blueprint` don't find one (or the one named with `-c`), they run `auth` for you automatically first, then proceed with the command you actually asked for - so you never have to run `auth` yourself as a separate step. You can also set up `contrast.properties` ahead of time, two ways:

**Option 1 - `auth` (recommended):**

```bash
java -jar runtime-analyst.jar auth --host https://your-instance.contrastsecurity.com
```

This opens a real browser window and lets you log in exactly the way you normally would, including SSO/MFA - there's nothing to copy or paste. The window closes as soon as login completes; in the background, it reads your personal API key, service key, and organization ID directly off your account's **User Settings > Your Keys** page, verifies them with a real API call, and writes `contrast.properties` for you. Your session cookie is never read or stored - only the API key and service key that page shows you.

**Option 2 - create it by hand:**

```properties
contrast.url=https://your-instance.contrastsecurity.com/api/ns-ui/v1
contrast.org_id=your-org-id
contrast.auth_header=base64-encoded-email:service-key
contrast.api_key=your-api-key
```

Find these values yourself under **User Settings > Your Keys** in the Contrast UI. `contrast.auth_header` is the base64 encoding of `your-email:your-service-key` (not the service key alone).

Every command accepts `-c <path>` to point at a config file somewhere other than the working directory.

## Usage

```bash
mvn clean package   # build target/runtime-analyst-1.0.jar
```

A single jar, dispatched by subcommand:

| Subcommand | Purpose |
|---|---|
| `auth` | Log in via browser and generate `contrast.properties` |
| `cbom` | Generate a Cryptography Bill of Materials |
| `aibom` | Generate an AI/LLM usage Bill of Materials |
| `blueprint` (alpha) | Generate a draft CycloneDX 2.0 Architectural BOM + Bill of Behaviors |
| `cbom-advisor` | Re-run the Quantum Advisor against an existing CBOM file |
| `aibom-advisor` | Re-run the AI Advisor against an existing AI-BOM file |

`cbom`, `aibom`, and `blueprint` all share the same filter flags: `--app <id|name>`, `--env <PRODUCTION|DEVELOPMENT|QA>`, `--list` (list available applications and exit), `-o <file>` (output path), and `-c <config.properties>`. `cbom`/`aibom` additionally support `--analyze`, which runs the matching advisor automatically after generation.

## Examples

### `auth`

```
$ java -jar runtime-analyst.jar auth -h

Auth - connect runtime-analyst to your Contrast account

Opens a real browser window, lets you log in (including SSO/MFA) the way you normally
would, then reads your personal API key/service key/org id off User Settings > Your Keys
directly - no manual copy/paste into the terminal. The window closes as soon as login
completes; everything after that runs in a background headless browser.

Usage:
  java -jar runtime-analyst.jar auth [--host <url>] [-o <contrast.properties>]
```

```bash
# First-time setup against your instance
java -jar runtime-analyst.jar auth --host https://eval.contrastsecurity.com

# Write to a different config path
java -jar runtime-analyst.jar auth --host https://eval.contrastsecurity.com -o prod.properties
```

### `cbom`

```
$ java -jar runtime-analyst.jar cbom -h

CBOM Generator - Create CycloneDX CBOM from Contrast observations

Usage:
  java -jar runtime-analyst.jar cbom                    Generate CBOM for all apps
  java -jar runtime-analyst.jar cbom --app <id|name>    Filter by app (ID or name)
  java -jar runtime-analyst.jar cbom --env <tier>       Filter by environment (PRODUCTION, DEVELOPMENT, QA)
  java -jar runtime-analyst.jar cbom --list             List available applications with IDs
  java -jar runtime-analyst.jar cbom --analyze          Run Quantum Advisor AI analysis after CBOM generation
  java -jar runtime-analyst.jar cbom -o <file.json>     Specify output filename
  java -jar runtime-analyst.jar cbom -c <config.properties>  Use custom config file
```

```bash
java -jar runtime-analyst.jar cbom                                    # all apps -> cbom.json
java -jar runtime-analyst.jar cbom --list                             # list applications and their IDs
java -jar runtime-analyst.jar cbom --app "MyApp"                      # filter by app name
java -jar runtime-analyst.jar cbom --app 7136cb1b-f846-4c1d-bdd3-77b448cbd2fe   # ...or by ID
java -jar runtime-analyst.jar cbom --env PRODUCTION                   # only prod observations
java -jar runtime-analyst.jar cbom --app "MyApp" --env PRODUCTION -o myapp-prod.json
java -jar runtime-analyst.jar cbom -c prod.properties --list
java -jar runtime-analyst.jar cbom --analyze                          # + Quantum Advisor risk report
```

### `aibom`

```
$ java -jar runtime-analyst.jar aibom -h

AI-BOM Generator - Create CycloneDX AI-BOM from Contrast AI usage observations

Usage:
  java -jar runtime-analyst.jar aibom                   Generate AI-BOM for all apps
  java -jar runtime-analyst.jar aibom --app <id|name>   Filter by app (ID or name)
  java -jar runtime-analyst.jar aibom --env <tier>      Filter by environment (PRODUCTION, DEVELOPMENT, QA)
  java -jar runtime-analyst.jar aibom --list            List available applications with IDs
  java -jar runtime-analyst.jar aibom --analyze         Run AI Advisor analysis after AI-BOM generation
  java -jar runtime-analyst.jar aibom -o <file.json>    Specify output filename
  java -jar runtime-analyst.jar aibom -c <config.properties>  Use custom config file
```

```bash
java -jar runtime-analyst.jar aibom
java -jar runtime-analyst.jar aibom --list
java -jar runtime-analyst.jar aibom --app "MyApp" --env PRODUCTION
java -jar runtime-analyst.jar aibom --analyze                         # + AI Advisor governance report
```

### `blueprint` (alpha)

```
$ java -jar runtime-analyst.jar blueprint -h

Blueprint Generator - Create a CycloneDX Blueprint (ABOM + Bill of Behaviors) from Contrast data

Usage:
  java -jar runtime-analyst.jar blueprint                   Generate a Blueprint for all apps
  java -jar runtime-analyst.jar blueprint --app <id|name>   Filter by app (ID or name)
  java -jar runtime-analyst.jar blueprint --env <tier>      Filter by environment (PRODUCTION, DEVELOPMENT, QA)
  java -jar runtime-analyst.jar blueprint --list            List available applications with IDs
  java -jar runtime-analyst.jar blueprint -o <file.json>    Specify output filename
  java -jar runtime-analyst.jar blueprint -c <config.properties>  Use custom config file

Note: Blueprints are a CycloneDX draft (unreleased 2.0-dev branch, spec PR #652).
This command populates assets/zones/flows/behaviors from real Contrast data only -
it does not generate threats/controls/risks (TM-BOM), which would require fabricating
findings Contrast's telemetry cannot back.
```

```bash
java -jar runtime-analyst.jar blueprint
java -jar runtime-analyst.jar blueprint --app "MyApp" --env PRODUCTION
```

### `cbom-advisor` / `aibom-advisor`

Re-run an advisor against a BOM you already have, without regenerating it:

```
$ java -jar runtime-analyst.jar cbom-advisor
Usage: java -jar runtime-analyst.jar cbom-advisor <cbom.json> [-v] [-o report.md] [--json out.json] [--no-confirm] [--filter all|vulnerable|asymmetric]

$ java -jar runtime-analyst.jar aibom-advisor
Usage: java -jar runtime-analyst.jar aibom-advisor <aibom.json> [-v] [-o report.md] [--json out.json] [--no-confirm]
```

```bash
java -jar runtime-analyst.jar cbom-advisor cbom.json -o report.md
java -jar runtime-analyst.jar aibom-advisor aibom.json -o report.md
java -jar runtime-analyst.jar cbom-advisor cbom.json -v -o report.md --filter vulnerable
```

Everything - BOM generation and AI analysis - runs in a single JVM process. The advisors shell out to the `claude` CLI already logged in to this shell; no separate API key or AWS/Bedrock credentials needed, and no Python required.

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

### Blueprint (alpha)

A draft CycloneDX 2.0 document with a top-level `blueprints[]` array containing:

- **`assets[]`** - one per application (from the `contrast-graph` architecture graph) plus one per connection known only by name
- **`zones[]`** - one per deployment tier
- **`flows[]`** - architecture-graph connections between assets, deduplicated and modeled as bidirectional since the graph API doesn't preserve direction
- **`behaviors.instances[]`** - crypto/AI usage observations mapped onto the CycloneDX behavior taxonomy (e.g. `security:cryptography:encryptsData`, `ai:generative:processesPrompt`)

Deliberately does **not** generate threats, controls, or risks (TM-BOM) - the draft spec models those as a separate, sibling construct, and none of it can be derived from Contrast telemetry without an actual STRIDE-style analysis.

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

## Configuration Reference

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
