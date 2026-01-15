# Quantum CBOM Generator

Generate [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) (Cryptography Bill of Materials) from Contrast Security observability data.

## Why Contrast for Crypto Inventory?

Contrast provides runtime observability that goes far beyond static code scanning:

- **Full-stack inventory** - Captures crypto usage across your entire application stack at runtime, not just what's visible in source code
- **Complete algorithm details** - Strength, feedback mode, padding scheme, and OIDs for each algorithm
- **Usage metrics** - How often each crypto component is actually called in production
- **Full stack traces** - Understand the context: is this crypto used for passwords, SSL/TLS, tokens, or something else?
- **Multiple call paths** - See how many different code paths invoke each crypto component
- **Application dependencies** - Which apps and APIs depend on each crypto component

This runtime visibility is critical for post-quantum migration planning - you need to know not just *what* crypto you have, but *how* it's being used.

## Features

- Generates CycloneDX 1.6 compliant CBOM in JSON format
- Fetches cryptographic algorithm usage from Contrast API
- Shows which applications use which cryptographic algorithms
- Includes NIST quantum security levels for post-quantum migration planning
- Tracks usage counts and unique call locations per algorithm
- Full stack traces showing crypto usage context
- Filters by application or environment (PRODUCTION, DEVELOPMENT, QA)

## Quick Start

1. Create `contrast.properties` in your working directory:

```properties
contrast.url=https://your-instance.contrastsecurity.com/api/ns-ui/v1
contrast.org_id=your-org-id
contrast.auth_header=base64-encoded-email:service-key
contrast.api_key=your-api-key
```

2. Run:

```bash
java -jar quantum-1.0-SNAPSHOT.jar
```

## Usage

```bash
# Generate CBOM for all apps
java -jar quantum.jar

# List available applications
java -jar quantum.jar --list

# Generate CBOM for specific app (by name or ID)
java -jar quantum.jar --app "MyApp"
java -jar quantum.jar --app 7136cb1b-f846-4c1d-bdd3-77b448cbd2fe

# Filter by environment
java -jar quantum.jar --env PRODUCTION

# Combine filters
java -jar quantum.jar --app "MyApp" --env PRODUCTION -o myapp-prod.json

# Use custom config file
java -jar quantum.jar -c /path/to/config.properties
```

## Output

The generated CBOM includes:

- **Application components** with dependencies on crypto algorithms
- **Cryptographic asset components** with:
  - Algorithm properties (primitive, mode, padding)
  - OID (Object Identifier)
  - Classical security level
  - NIST quantum security level (0 = quantum vulnerable)
  - `contrast:usageCount` - total invocations at runtime
  - `contrast:uniqueLocations` - number of distinct call paths
  - Full stack traces showing usage context (passwords, SSL, etc.)

Example dependency structure:
```
Contrast Crypto Inventory
├── app-frontend → SHA-256, AES/GCM
└── app-backend → SHA-256, MD5 (quantum vulnerable), RSA
```

### CBOM Properties

| Property | Description |
|----------|-------------|
| `contrast:usageCount` | Total number of times this algorithm was invoked at runtime |
| `contrast:uniqueLocations` | Number of distinct code paths that use this algorithm |

These metrics help prioritize migration efforts - a crypto algorithm called millions of times across dozens of code paths needs more attention than one used once during startup.

## Building

```bash
mvn clean package
```

Creates `target/quantum-1.0-SNAPSHOT.jar` (executable uber-jar).

## Configuration

| Property | Description |
|----------|-------------|
| `contrast.url` | Contrast API base URL |
| `contrast.org_id` | Your organization ID |
| `contrast.auth_header` | Base64 encoded `email:service_key` |
| `contrast.api_key` | Your API key |

## Algorithm Analysis

The tool automatically parses algorithm strings (e.g., `AES/GCM/NoPadding`) and extracts:

- Algorithm family (AES, RSA, SHA, etc.)
- Mode (GCM, CBC, ECB, etc.)
- Padding scheme
- Key size
- Cryptographic primitive type
- Security levels

### Quantum Vulnerability

Algorithms are classified by NIST quantum security level:
- **Level 0**: Quantum vulnerable (RSA, ECDSA, ECDH, etc.)
- **Level 1-5**: Quantum resistant (AES-128+, SHA-256+, ML-KEM, ML-DSA, etc.)

## License

Copyright Contrast Security
