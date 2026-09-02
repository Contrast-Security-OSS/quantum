# Runtime Analyst

Runtime Analyst turns Contrast Security's runtime observability data into structured, standard reports. RA doesn't scan source code or dependency manifests - it reads what Contrast's agents observed actually running in your applications, with full stack traces, usage counts, and architecture context. This runtime visibility is critical for post-quantum migration and AI governance planning - you need to know not just *what's* in use, but *how* it's being used and by *what*.

- **Cryptography** - every cryptographic algorithm observed running in your apps/APIs, with NIST post-quantum vulnerability classification.  Produces a CBOM and an AI-powered analysis report.
- **AI** - every AI model and provider observed running, with cloud-vs-local classification for shadow-AI visibility. Produces a AIBOM and an AI-powered analysis report
- **Blueprint (alpha)** - a map of how your apps/APIs connect and behave: assets, deployment zones, connections, and crypto/AI behaviors
- **Threat Model** (coming soon) - TBD
- **Vulnerability Exclusion** - an analysis of library CVE exposure in your apps/APIs, based Contrast's runtime library-usage and CVE Shield/Protect data. Produces a VEX document and an AI-powered analysis report.

**Requirements:**

- A Contrast account with runtime data already flowing in from real-world applications and APIs - Contrast's agents must actually be deployed and observing traffic. Runtime Analyst only reports on what Contrast has observed; it has nothing to show against an account with no instrumented applications or no production/QA traffic.
- The `claude` CLI on your `PATH` and logged in, for `--analyze`/the advisor reports - no separate API key, no AWS/Bedrock credentials, no Python.

## Why Contrast?

Contrast provides runtime observability that goes far beyond static code scanning or self-reported inventories:

- **Full-stack inventory** - Captures crypto and AI usage across your entire application stack at runtime, not just what's declared in source code or dependency manifests
- **Complete details** - Algorithm strength/mode/padding/OIDs for crypto; provider/model/endpoint for AI
- **Usage metrics** - How often each crypto algorithm or AI model is actually called in production
- **Full stack traces** - Understand the context: is this crypto protecting passwords, SSL/TLS, tokens? Is this AI call generating a chat reply, summarizing a document?
- **Multiple call paths** - See how many different code paths invoke each algorithm/model
- **Architecture context** - Each application component is enriched with its language, security posture, and what it's connected to (from the Contrast architecture graph), so the advisor reports can describe what an application actually is, not just what it uses
- **Application dependencies** - Which apps and APIs depend on each crypto algorithm or AI model
- **Real connections, not guesses** - Blueprint's assets, zones, and flows come from the same architecture graph, so the map it draws is what Contrast actually saw talking to what, not an inferred or self-reported topology



## Authentication

Every command except `auth` itself reads a `contrast.properties` file for credentials. If `cbom`, `aibom`, `blueprint`, or `vex` don't find one (or the one named with `-c`), they run `auth` for you automatically first, then proceed with the command you actually asked for - so you never have to run `auth` yourself as a separate step. You can also set up `contrast.properties` ahead of time, two ways:

**Option 1 - `auth` (recommended):**

```bash
java -jar runtime-analyst.jar auth --host https://your-instance.contrastsecurity.com
```

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
| `vex` | Generate a CycloneDX VEX for an application's library CVEs |
| `cbom-advisor` | Re-run the Quantum Advisor against an existing CBOM file |
| `aibom-advisor` | Re-run the AI Advisor against an existing AI-BOM file |
| `vex-advisor` | Re-run the VEX Advisor against an existing VEX file |

`cbom`, `aibom`, `blueprint`, and `vex` all share `--app <id|name>`, `--env <PRODUCTION|DEVELOPMENT|QA>`, `--list` (list available applications and exit), `-o <file>` (output path), and `-c <config.properties>`. For `cbom`/`aibom`/`blueprint`, `--env` filters which observations are included. For `vex`, `--env` means something more specific: it scopes each claim to that one environment's CVE Shield/exposure status, instead of considering the application's dev/qa/prod combined (see the `vex` policy below) - `--env PRODUCTION` means "not seen/protected in production specifically," not "not seen somewhere across the app." `cbom`/`aibom`/`vex` additionally support `--analyze`, which runs the matching advisor automatically after generation. `vex` also has its own `--vex-accept-after-days <n>` (see below).

## Examples

### `auth`

```
$ java -jar runtime-analyst.jar auth -h

# First-time setup against your instance
$ java -jar runtime-analyst.jar auth --host https://eval.contrastsecurity.com

# Write to a different config path
$ java -jar runtime-analyst.jar auth --host https://eval.contrastsecurity.com -o prod.properties
```

### `cbom`

```
$ java -jar runtime-analyst.jar cbom -h

java -jar runtime-analyst.jar cbom                      # all apps -> cbom.json
java -jar runtime-analyst.jar cbom --list               # list applications and their IDs
java -jar runtime-analyst.jar cbom --app "MyApp"        # filter by app name
java -jar runtime-analyst.jar cbom --app 7136cb1b-f846-4c1d-bdd3-77b448cbd2fe
java -jar runtime-analyst.jar cbom --env PRODUCTION     # only prod observations
java -jar runtime-analyst.jar cbom --app "MyApp" --env PRODUCTION -o myapp-prod.json
java -jar runtime-analyst.jar cbom -c prod.properties --list
java -jar runtime-analyst.jar cbom --analyze            # + Quantum Advisor risk report
```



### `aibom`

```
$ java -jar runtime-analyst.jar aibom -h

java -jar runtime-analyst.jar aibom
java -jar runtime-analyst.jar aibom --list
java -jar runtime-analyst.jar aibom --app "MyApp" --env PRODUCTION
java -jar runtime-analyst.jar aibom --analyze         	# + AI Advisor governance report
```



### `blueprint` (alpha)

```
$ java -jar runtime-analyst.jar blueprint -h

java -jar runtime-analyst.jar blueprint
java -jar runtime-analyst.jar blueprint --app "MyApp" --env PRODUCTION
```



### `vex`

```
$ java -jar runtime-analyst.jar vex -h

java -jar runtime-analyst.jar vex --app "MyApp"                 # -> vex-MyApp.json, considers dev+qa+prod together
java -jar runtime-analyst.jar vex --app "MyApp" --env PRODUCTION  # scope every claim to production only
java -jar runtime-analyst.jar vex --list                        # list applications and their IDs
java -jar runtime-analyst.jar vex --app "MyApp" --vex-accept-after-days 60 -o vex.json
java -jar runtime-analyst.jar vex --app "MyApp" --analyze        # + VEX Advisor soundness review
```



By default a claim considers the application's dev/qa/prod environments together - "protected" means protected in at least one, "not seen" means not seen in any of them. `--env <tier>` narrows every claim to just that one environment instead, so `--env PRODUCTION` means "not seen/protected in production specifically," not "not seen somewhere in the app." An exclusion is generated when:

1. **Library never loaded at runtime in this application** (`classes_used == 0` for that app)
   → `not_affected` 
2. **Library loaded, but CVE Shield/Protect is actively mitigating it for this application** 
   → `not_affected` / `protected_at_runtime`.
3. **Library loaded, and this application's CVE status is `EXPOSED`/`EXPLOITED`** 
   → no VEX statement at all. This tool never suppresses a vulnerability it can't positively account for.
4. **Library loaded, but the CVE has never been observed executing in this application**
   → a statement is still generated, with the actual number of days recorded as the reason.

Every statement carries `contrast:*` properties (`classesUsed`/`classCount`, `daysObserved`, `acceptAfterDays`, `envFilter`, and the per-environment `devStatus`/`qaStatus`/`prodStatus`) so a reviewer can see the underlying evidence, not just the resulting state.



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

### VEX

A standard CycloneDX 1.6 document with a top-level `vulnerabilities[]` array, one entry per (application, library, CVE) with:

- `id` - the CVE identifier, `source` - NVD reference
- `description` - the CVE description, as reported by Contrast
- `ratings[]` - CVSS v3.1 score/severity/vector as reported by Contrast
- `advisories[]` - any reference URLs Contrast has on file for the CVE (omitted when there are none)
- `affects[].ref` - a best-effort `pkg:maven/...` purl for the affected library
- `affects[].versions[]` - the deployed version (`affected`) and, when Contrast has upgrade guidance for the library, the recommended fixed version (`unaffected`)
- `recommendation` - the remediation action: Contrast's own minimal-upgrade guidance for the library when available, falling back to "no newer release identified" when it isn't
- `analysis.state`/`analysis.justification`/`analysis.detail` - the VEX claim itself and why it was made (see the policy in the [`vex` examples](#vex) above)
- `analysis.response[]` - `update` when a fix version is known, `workaround_available` for `protected_at_runtime` claims (the active Shield/Protect control **is** the workaround), omitted otherwise
- `properties[]` - the underlying evidence (`contrast:classesUsed`/`classCount`, `contrast:daysObserved`, `contrast:acceptAfterDays`, `contrast:devStatus`/`qaStatus`/`prodStatus`, `contrast:latestVersion`) plus exploitability signals (`contrast:epssScore`/`epssPercentile`, `contrast:cisaKev` - CISA Known Exploited Vulnerabilities catalog membership)

All of the above is deterministic, pulled directly from Contrast's own CVE/library data - nothing here is AI-generated, since a VEX claim is an attestation and needs to stay auditable back to its source evidence. The EPSS/CISA KEV signals are new inputs to the **VEX Advisor**'s AI judgment (below), not to the claim itself.

```
Contrast VEX
└── SAML-PetClinic-Demo
    ├── CVE-2018-14721 (jackson-databind 2.8.8) → not_affected / code_not_reachable
    └── CVE-2022-22965 (spring-webmvc 4.3.9)    → not_affected (288 days, no observed execution)
```

Note: `PROTECTED_AT_RUNTIME` (CVE Shield/Protect actively mitigating) is implemented but not yet confirmed against a live example with that status - see the caveats in the `vex` command's own help/design notes before relying on it.

### Advisor reports

- **Quantum Advisor** - findings grouped by risk level (CRITICAL/HIGH/MEDIUM/LOW/NOT_QUANTUM_ISSUE), with an "Application Context" section describing each app from its architecture graph data
- **AI Advisor** - organized as an inventory of AI-enabled applications (one section per app, not per finding): an AI-generated description of what the app does, then each AI usage instance with model/provider/endpoint and a description of what that specific call is doing, inferred from the key methods around it in the stack trace
- **VEX Advisor** - not a second opinion on whether a CVE exists (Contrast's runtime data already establishes that), but a soundness check on whether each `not_affected`/`in_triage` claim is safe to rely on given the CVE's severity/exploitability. Flags claims that rest purely on "N days without observed execution" for a CRITICAL/HIGH-severity CVE in a heavily-loaded library as `needs_review`, while treating `code_not_reachable`/`protected_at_runtime` claims as structurally sound regardless of severity. Weighs each CVE's EPSS score/percentile and CISA KEV (Known Exploited Vulnerabilities catalog) status alongside CVSS severity - a duration-only claim on a KEV-listed or high-EPSS CVE is judged more harshly than the same claim on a CVE with no evidence of real-world exploitation. Organized one section per application, with a per-CVE table plus rationale for anything flagged.

Both the Quantum and AI Advisors write their generated application descriptions back into the source BOM's `Component.description` field, so the BOM itself stays self-describing even without the report. The Quantum Advisor also writes `quantum:*` risk properties (risk level, recommendation, code source, etc.) back onto each crypto algorithm component. The VEX Advisor writes `contrast:vexAdvisorAssessment` (`sound`/`needs_review`) and `contrast:vexAdvisorRationale` back onto each vulnerability's `properties[]`. All of this happens automatically as part of every `--analyze` run, no separate step needed.

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

## Sample Reports

`samples/` has one real, current output from each generator and its matching advisor report - useful as a reference for what each format actually looks like without running the tool yourself:

| CycloneDX document | Advisor report | Scoped to |
|---|---|---|
| `sample-cbom.json` | `sample-cbom-advisor.md` | `Cargo-Crypto-contrast-cargo-cats-frontgateservice` |
| `sample-aibom.json` | `sample-aibom-advisor.md` | `Robert-cargocats-aiservice` |
| `sample-blueprint.json` | *(no advisor - see the Blueprint section above)* | `Cargo-Crypto-contrast-cargo-cats-frontgateservice` |
| `sample-vex.json` | `sample-vex-advisor.md` | `SAML-PetClinic-Demo` |

Each is scoped with `--app` to one application rather than the whole org (smaller, more readable files, and a full-org VEX run makes one CVE-issues API call per application). They're deliberately *not* all the same app - in this org, crypto usage, AI usage, and vulnerable libraries happen to show up in three disjoint sets of applications, so no single app would produce non-empty output for all four generators. Each sample uses whichever app actually has real data for that report type.

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
