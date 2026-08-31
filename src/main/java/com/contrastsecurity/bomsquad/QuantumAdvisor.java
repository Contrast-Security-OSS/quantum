package com.contrastsecurity.bomsquad;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * AI-powered analysis of a CBOM for quantum migration decisions. Java port of the
 * former tools/quantum_advisor.py - analyzes each cryptographic usage instance and
 * writes back a markdown report plus quantum:* risk properties on the CBOM itself.
 *
 * Usage:
 *   java -jar bom-squad.jar cbom-advisor cbom.json [-v] [-o report.md] [--json out.json] [--no-confirm] [--filter all|vulnerable|asymmetric]
 */
public class QuantumAdvisor {

    private static final String[] RISK_SEVERITY_ORDER = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT_QUANTUM_ISSUE", "UNKNOWN", "ERROR"};

    private static final String ANALYSIS_PROMPT =
        "You are a cryptography security expert specializing in post-quantum cryptography migration.\n\n" +
        "Analyze this SINGLE cryptographic usage instance and provide a specific remediation recommendation.\n\n" +
        "## Quantum Threat Background\n\n" +
        "**Shor's Algorithm** breaks asymmetric crypto (RSA, ECDSA, ECDH, DH) completely - these MUST be replaced.\n" +
        "**Grover's Algorithm** halves symmetric crypto strength - AES-256 becomes AES-128 equivalent, still secure.\n\n" +
        "## Risk Levels (Quantum-specific)\n\n" +
        "**CRITICAL**: Must fix immediately\n" +
        "- Asymmetric crypto protecting long-term secrets, signatures, or stored data\n" +
        "- \"Harvest Now, Decrypt Later\" vulnerable\n\n" +
        "**HIGH**: Fix soon (within 6 months)\n" +
        "- Asymmetric crypto for sensitive but shorter-lived data\n" +
        "- VPN/tunnel key exchange\n\n" +
        "**MEDIUM**: Plan replacement (6-18 months)\n" +
        "- Asymmetric crypto with forward secrecy for ephemeral data\n" +
        "- TLS key exchange (ECDHE) - forward secrecy mitigates risk\n\n" +
        "**LOW**: No action needed\n" +
        "- Symmetric crypto with sufficient key size (AES-128+, SHA-256+)\n" +
        "- Quantum-safe by design\n\n" +
        "**NOT_QUANTUM_ISSUE**: Different problem\n" +
        "- MD5, SHA-1, DES, 3DES - classically broken, not quantum-specific\n\n" +
        "## Stack Trace Context Clues\n\n" +
        "**Password Hashing**: `PasswordEncoder`, `BCrypt`, `PBKDF2` -> Usually OK\n" +
        "**TLS/SSL**: `sun.security.ssl`, `SSLHandshake`, `HKDF` -> Check for forward secrecy\n" +
        "**Data at Rest**: `Cipher.getInstance` outside TLS, database/file encryption -> HIGH risk if asymmetric\n" +
        "**Signatures**: `Signature.getInstance`, code signing, certificates -> CRITICAL if long-lived\n\n" +
        "## Code Source Classification (IMPORTANT)\n\n" +
        "Analyze the stack trace to determine WHERE the crypto call originates:\n\n" +
        "**custom_code**: Application's own code (com.acme.*, com.company.*, etc.)\n" +
        "- Remediation: Direct code change by development team\n" +
        "- Timeline: Fastest to fix\n\n" +
        "**open_source_library**: Third-party OSS (org.apache.*, com.google.*, io.netty.*, etc.)\n" +
        "- Remediation: File issue/PR with maintainer, upgrade when fixed, or fork\n" +
        "- Timeline: Depends on maintainer responsiveness\n\n" +
        "**commercial_library**: Commercial/vendor libraries (com.oracle.*, com.ibm.*, database drivers)\n" +
        "- Remediation: Contact vendor support, request PQ update, plan for vendor timeline\n" +
        "- Timeline: May require contract leverage, could be slow\n\n" +
        "**framework**: Web/app frameworks (org.springframework.*, javax.*, jakarta.*)\n" +
        "- Remediation: Upgrade framework version when PQ support added, monitor releases\n" +
        "- Timeline: Major frameworks are actively working on PQ support\n\n" +
        "**jdk_runtime**: JDK/JRE internals (sun.security.*, java.security.*, javax.crypto.*)\n" +
        "- Remediation: Upgrade JDK when PQ algorithms available, or add BC provider\n" +
        "- Timeline: OpenJDK has PQ work in progress\n\n" +
        "## Your Task\n\n" +
        "Analyze this specific usage and return JSON:\n" +
        "```json\n" +
        "{\n" +
        "  \"risk_level\": \"CRITICAL|HIGH|MEDIUM|LOW|NOT_QUANTUM_ISSUE\",\n" +
        "  \"title\": \"Brief actionable title (e.g., 'Replace RSA document signing in acme-docs')\",\n" +
        "  \"application\": \"app name from stack trace\",\n" +
        "  \"usage_summary\": \"One sentence: what the crypto is doing\",\n" +
        "  \"data_sensitivity\": \"What kind of data is being protected\",\n" +
        "  \"data_lifetime\": \"ephemeral|short-term|long-term\",\n" +
        "  \"code_source\": \"custom_code|open_source_library|commercial_library|framework|jdk_runtime\",\n" +
        "  \"source_package\": \"The specific package/library where the crypto call originates\",\n" +
        "  \"remediation_owner\": \"Who needs to fix this\",\n" +
        "  \"quantum_threat\": \"Why this is/isn't vulnerable to quantum attacks\",\n" +
        "  \"recommendation\": \"Specific action to take\",\n" +
        "  \"migration_notes\": \"Technical notes for the developer doing the fix\"\n" +
        "}\n" +
        "```\n";

    private static final String APP_DESCRIPTION_PROMPT =
        "You are an application security analyst building context for a cryptography inventory report.\n\n" +
        "You are given metadata about ONE application: its name, language, which other applications it's connected to, " +
        "and its third-party library footprint. You are NOT given its cryptographic findings - only its architecture.\n\n" +
        "Write a 2-3 sentence description of what this application/API most likely does, based on its name, language, " +
        "and connections to other services. Be concrete about its likely role (e.g. \"a front-line API gateway that routes " +
        "requests to backend services\", \"a reporting service that generates documents for internal consumers\").\n\n" +
        "Return JSON:\n" +
        "```json\n" +
        "{\n" +
        "  \"description\": \"2-3 sentence description of what this application/API does\"\n" +
        "}\n" +
        "```\n";

    static class CryptoOccurrence {
        String algorithm;
        String primitive;
        String mode;
        Integer keySize;
        int quantumLevel;
        String location;
        String context;
        String application;
        int usageCount;
        int uniqueLocations;
    }

    static class AppMetadata {
        String name;
        String language;
        Double postureScore;
        String postureSeverity;
        Integer openIssuesTotal;
        int libraryCount;
        List<String> connectedApplications = new ArrayList<>();
    }

    static class ParsedCbom {
        List<CryptoOccurrence> occurrences = new ArrayList<>();
        JsonObject metadata;
        Map<String, AppMetadata> appMetadata = new LinkedHashMap<>();
    }

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) {
        String cbomPath = null;
        boolean verbose = false;
        String output = null;
        String jsonOut = null;
        boolean noConfirm = false;
        String filter = "all";

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("-v") || a.equals("--verbose")) verbose = true;
            else if ((a.equals("-o") || a.equals("--output")) && i + 1 < args.length) output = args[++i];
            else if (a.equals("--json") && i + 1 < args.length) jsonOut = args[++i];
            else if (a.equals("--no-confirm")) noConfirm = true;
            else if (a.equals("--filter") && i + 1 < args.length) filter = args[++i];
            else if (a.equals("-h") || a.equals("--help")) {
                System.out.println("Usage: java -jar bom-squad.jar cbom-advisor <cbom.json> [-v] [-o report.md] [--json out.json] [--no-confirm] [--filter all|vulnerable|asymmetric]");
                return;
            } else if (!a.startsWith("-")) {
                cbomPath = a;
            }
        }

        if (cbomPath == null) {
            System.err.println("Error: path to CBOM JSON file is required");
            System.exit(1);
        }

        try {
            new QuantumAdvisor().run(cbomPath, verbose, output, jsonOut, noConfirm, filter);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void run(String cbomPath, boolean verbose, String output, String jsonOut, boolean noConfirm, String filter) throws Exception {
        System.out.println("\nParsing CBOM...");
        ParsedCbom parsed = parseCbom(cbomPath);
        List<CryptoOccurrence> occurrences = parsed.occurrences;
        System.out.println("  Found " + occurrences.size() + " cryptographic usage instances");

        if (filter.equals("vulnerable")) {
            occurrences.removeIf(o -> o.quantumLevel != 0);
            System.out.println("  Filtered to " + occurrences.size() + " quantum-vulnerable instances");
        } else if (filter.equals("asymmetric")) {
            Set<String> asymmetric = new LinkedHashSet<>(Arrays.asList("pke", "signature", "kex", "key-agree"));
            occurrences.removeIf(o -> o.primitive == null || !asymmetric.contains(o.primitive));
            System.out.println("  Filtered to " + occurrences.size() + " asymmetric crypto instances");
        }

        if (occurrences.isEmpty()) {
            System.out.println("\nNo matching cryptographic usages found!");
            return;
        }

        ClaudeClient client = new ClaudeClient();

        Set<String> appsWithFindings = new LinkedHashSet<>();
        for (CryptoOccurrence o : occurrences) appsWithFindings.add(o.application);
        Map<String, AppMetadata> appsInScope = new LinkedHashMap<>();
        for (Map.Entry<String, AppMetadata> e : parsed.appMetadata.entrySet()) {
            if (appsWithFindings.contains(e.getKey())) appsInScope.put(e.getKey(), e.getValue());
        }

        double estimatedCost = client.estimateCost(occurrences.size() + appsInScope.size(), 1800, 550);
        if (!ClaudeClient.confirmCost(estimatedCost, occurrences.size() + appsInScope.size(), noConfirm)) {
            System.out.println("Cancelled.");
            return;
        }

        Map<String, String> appDescriptions = new LinkedHashMap<>();
        if (!appsInScope.isEmpty()) {
            System.out.println("\nDescribing " + appsInScope.size() + " applications...");
            appDescriptions = generateAppDescriptions(client, appsInScope, verbose);
        }

        System.out.println("\nAnalyzing " + occurrences.size() + " cryptographic usages...");
        List<JsonObject> results = new ArrayList<>();
        for (CryptoOccurrence occ : occurrences) {
            JsonObject result;
            try {
                result = analyzeOccurrence(client, occ, verbose);
            } catch (Exception e) {
                System.out.println("  Error analyzing " + occ.algorithm + " in " + occ.application + ": " + e.getMessage());
                result = new JsonObject();
                result.addProperty("algorithm", occ.algorithm);
                result.addProperty("application", occ.application);
                result.addProperty("risk_level", "ERROR");
                result.addProperty("title", occ.algorithm + " in " + occ.application);
                result.addProperty("recommendation", String.valueOf(e.getMessage()));
            }
            results.add(result);
            String risk = getString(result, "risk_level", "UNKNOWN");
            String title = getString(result, "title", occ.algorithm + " in " + occ.application);
            System.out.println("  [" + risk + "] " + title);
        }

        int[] enriched = enrichBom(cbomPath, appDescriptions, results);
        if (enriched[0] > 0 || enriched[1] > 0) {
            System.out.println("  Enriched " + cbomPath + ": " + enriched[0] + " application description(s), "
                + enriched[1] + " algorithm(s) annotated with quantum:* properties");
        }

        String report = generateReport(results, parsed.metadata, parsed.appMetadata, appDescriptions);

        if (output != null) {
            try (FileWriter w = new FileWriter(output)) {
                w.write(report);
            }
            System.out.println("\nReport written to " + output);
        } else {
            System.out.println("\n" + "=".repeat(60));
            System.out.println(report);
        }

        if (jsonOut != null) {
            JsonArray arr = new JsonArray();
            for (JsonObject r : results) arr.add(r);
            try (FileWriter w = new FileWriter(jsonOut)) {
                w.write(gson.toJson(arr));
            }
            System.out.println("\nJSON results written to " + jsonOut);
        }

        client.printSummary();
    }

    // ---- Parsing ----

    private ParsedCbom parseCbom(String path) throws IOException {
        ParsedCbom result = new ParsedCbom();
        JsonObject cbom;
        try (FileReader reader = new FileReader(path)) {
            cbom = gson.fromJson(reader, JsonObject.class);
        }
        result.metadata = cbom.has("metadata") ? cbom.getAsJsonObject("metadata") : new JsonObject();

        JsonArray components = cbom.has("components") ? cbom.getAsJsonArray("components") : new JsonArray();
        for (JsonElement el : components) {
            JsonObject component = el.getAsJsonObject();
            String bomRef = getString(component, "bom-ref", "");
            String type = getString(component, "type", "");

            if (type.equals("application") && bomRef.startsWith("app-")) {
                Map<String, String> props = properties(component);
                String name = getString(component, "name", bomRef);
                AppMetadata app = new AppMetadata();
                app.name = name;
                app.language = props.get("contrast:language");
                if (props.containsKey("contrast:postureScore")) app.postureScore = Double.parseDouble(props.get("contrast:postureScore"));
                app.postureSeverity = props.get("contrast:postureSeverity");
                if (props.containsKey("contrast:openIssuesTotal")) app.openIssuesTotal = Integer.parseInt(props.get("contrast:openIssuesTotal"));
                app.libraryCount = props.containsKey("contrast:libraryCount") ? Integer.parseInt(props.get("contrast:libraryCount")) : 0;
                String connected = props.getOrDefault("contrast:connectedApplications", "");
                for (String c : connected.split(",")) {
                    if (!c.trim().isEmpty()) app.connectedApplications.add(c.trim());
                }
                result.appMetadata.put(name, app);
                continue;
            }

            if (!type.equals("cryptographic-asset")) continue;

            JsonObject cryptoProps = component.has("cryptoProperties") ? component.getAsJsonObject("cryptoProperties") : new JsonObject();
            JsonObject algoProps = cryptoProps.has("algorithmProperties") ? cryptoProps.getAsJsonObject("algorithmProperties") : new JsonObject();
            Map<String, String> props = properties(component);

            JsonObject evidence = component.has("evidence") ? component.getAsJsonObject("evidence") : new JsonObject();
            JsonArray occArr = evidence.has("occurrences") ? evidence.getAsJsonArray("occurrences") : new JsonArray();
            for (JsonElement occEl : occArr) {
                JsonObject occ = occEl.getAsJsonObject();
                String context = getString(occ, "additionalContext", "");

                String appName = "unknown";
                if (context.contains("App:")) {
                    String appLine = context.contains("Stack Trace:") ? context.split("Stack Trace:")[0] : context;
                    appName = appLine.replace("App:", "").trim();
                }

                CryptoOccurrence occurrence = new CryptoOccurrence();
                occurrence.algorithm = getString(component, "name", "");
                occurrence.primitive = algoProps.has("primitive") ? algoProps.get("primitive").getAsString() : null;
                occurrence.mode = algoProps.has("mode") ? algoProps.get("mode").getAsString() : null;
                occurrence.quantumLevel = algoProps.has("nistQuantumSecurityLevel") ? algoProps.get("nistQuantumSecurityLevel").getAsInt() : 0;
                occurrence.location = getString(occ, "location", "");
                occurrence.context = context;
                occurrence.application = appName;
                occurrence.usageCount = props.containsKey("contrast:usageCount") ? Integer.parseInt(props.get("contrast:usageCount")) : 0;
                occurrence.uniqueLocations = props.containsKey("contrast:uniqueLocations") ? Integer.parseInt(props.get("contrast:uniqueLocations")) : 1;
                result.occurrences.add(occurrence);
            }
        }

        return result;
    }

    private Map<String, String> properties(JsonObject component) {
        Map<String, String> props = new LinkedHashMap<>();
        if (component.has("properties")) {
            for (JsonElement el : component.getAsJsonArray("properties")) {
                JsonObject p = el.getAsJsonObject();
                props.put(p.get("name").getAsString(), p.get("value").getAsString());
            }
        }
        return props;
    }

    private String getString(JsonObject obj, String key, String def) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : def;
    }

    // ---- AI analysis ----

    private String formatOccurrenceForAi(CryptoOccurrence occ) {
        String stackTrace = "";
        if (occ.context.contains("Stack Trace:")) {
            String[] parts = occ.context.split("Stack Trace:", 2);
            stackTrace = parts.length > 1 ? parts[1].trim().replace(" ", "\n") : "";
        }
        return "Algorithm: " + occ.algorithm + "\n" +
            "Primitive: " + (occ.primitive != null ? occ.primitive : "unknown") + "\n" +
            "Mode: " + (occ.mode != null ? occ.mode : "N/A") + "\n" +
            "NIST Quantum Level: " + occ.quantumLevel + "\n" +
            "Application: " + occ.application + "\n" +
            "Usage Count: " + occ.usageCount + "\n" +
            "Entry Point: " + occ.location + "\n\n" +
            "Stack Trace:\n" + stackTrace;
    }

    private List<String> extractStackTrace(String context) {
        List<String> frames = new ArrayList<>();
        if (!context.contains("Stack Trace:")) return frames;
        String[] parts = context.split("Stack Trace:", 2);
        if (parts.length < 2) return frames;
        for (String f : parts[1].trim().split(" ")) {
            if (!f.trim().isEmpty()) frames.add(f.trim());
        }
        return frames;
    }

    private String formatAppForAi(AppMetadata app) {
        String connected = app.connectedApplications.isEmpty() ? "none observed" : String.join(", ", app.connectedApplications);
        return "Application: " + app.name + "\n" +
            "Language: " + (app.language != null ? app.language : "unknown") + "\n" +
            "Connected Applications: " + connected + "\n" +
            "Third-Party Library Count: " + app.libraryCount;
    }

    private Map<String, String> generateAppDescriptions(ClaudeClient client, Map<String, AppMetadata> apps, boolean verbose) throws Exception {
        Map<String, String> descriptions = new LinkedHashMap<>();
        for (Map.Entry<String, AppMetadata> entry : apps.entrySet()) {
            if (verbose) System.out.println("  Describing application " + entry.getKey() + "...");
            String response = client.call(APP_DESCRIPTION_PROMPT, formatAppForAi(entry.getValue()), null);
            String description = "";
            JsonObject parsed = extractJson(response);
            if (parsed != null && parsed.has("description")) {
                description = parsed.get("description").getAsString().trim();
            }
            descriptions.put(entry.getKey(), description);
        }
        return descriptions;
    }

    private JsonObject analyzeOccurrence(ClaudeClient client, CryptoOccurrence occ, boolean verbose) throws Exception {
        if (verbose) System.out.println("  Analyzing " + occ.algorithm + " in " + occ.application + "...");
        String response = client.call(ANALYSIS_PROMPT, formatOccurrenceForAi(occ), null);
        List<String> realStackTrace = extractStackTrace(occ.context);

        JsonObject result = extractJson(response);
        if (result != null) {
            result.addProperty("algorithm", occ.algorithm);
            result.addProperty("raw_location", occ.location);
            result.addProperty("frequency", frequencyLabel(occ.usageCount));
            result.addProperty("frequency_count", occ.usageCount);
            result.addProperty("reachability", occ.uniqueLocations);
            JsonArray stackArr = new JsonArray();
            for (String f : realStackTrace) stackArr.add(f);
            result.add("stack_trace", stackArr);
            return result;
        }

        JsonObject fallback = new JsonObject();
        fallback.addProperty("algorithm", occ.algorithm);
        fallback.addProperty("application", occ.application);
        fallback.addProperty("risk_level", "UNKNOWN");
        fallback.addProperty("title", "Analyze " + occ.algorithm + " in " + occ.application);
        fallback.addProperty("usage_summary", "Failed to parse AI response");
        fallback.addProperty("recommendation", response.length() > 500 ? response.substring(0, 500) : response);
        fallback.addProperty("frequency", frequencyLabel(occ.usageCount));
        fallback.addProperty("frequency_count", occ.usageCount);
        fallback.addProperty("reachability", occ.uniqueLocations);
        return fallback;
    }

    private JsonObject extractJson(String response) {
        int start = response.indexOf('{');
        int end = response.lastIndexOf('}');
        if (start < 0 || end < start) return null;
        try {
            return gson.fromJson(response.substring(start, end + 1), JsonObject.class);
        } catch (Exception e) {
            return null;
        }
    }

    private String frequencyLabel(int usageCount) {
        if (usageCount >= 100000) return "Very High";
        if (usageCount >= 10000) return "High";
        if (usageCount >= 1000) return "Medium";
        if (usageCount >= 100) return "Low";
        return "Very Low";
    }

    // ---- Enrichment (write descriptions + quantum:* properties back into the CBOM) ----

    private int riskRank(String level) {
        for (int i = 0; i < RISK_SEVERITY_ORDER.length; i++) {
            if (RISK_SEVERITY_ORDER[i].equals(level)) return i;
        }
        return RISK_SEVERITY_ORDER.length;
    }

    private int[] enrichBom(String bomPath, Map<String, String> descriptions, List<JsonObject> results) throws IOException {
        JsonObject bom;
        try (FileReader reader = new FileReader(bomPath)) {
            bom = gson.fromJson(reader, JsonObject.class);
        }

        Map<String, List<JsonObject>> findingsByAlgorithm = new LinkedHashMap<>();
        for (JsonObject r : results) {
            String algo = getString(r, "algorithm", "");
            findingsByAlgorithm.computeIfAbsent(algo, k -> new ArrayList<>()).add(r);
        }

        int appsDescribed = 0;
        int algorithmsAnnotated = 0;

        JsonArray components = bom.has("components") ? bom.getAsJsonArray("components") : new JsonArray();
        for (JsonElement el : components) {
            JsonObject component = el.getAsJsonObject();
            String bomRef = getString(component, "bom-ref", "");
            String type = getString(component, "type", "");

            if (type.equals("application") && bomRef.startsWith("app-")) {
                String description = descriptions.get(getString(component, "name", ""));
                if (description != null && !description.isEmpty()) {
                    component.addProperty("description", description);
                    appsDescribed++;
                }
                continue;
            }

            if (!type.equals("cryptographic-asset")) continue;

            List<JsonObject> findings = findingsByAlgorithm.get(getString(component, "name", ""));
            if (findings == null || findings.isEmpty()) continue;

            JsonObject worst = findings.get(0);
            for (JsonObject f : findings) {
                if (riskRank(getString(f, "risk_level", "UNKNOWN")) < riskRank(getString(worst, "risk_level", "UNKNOWN"))) {
                    worst = f;
                }
            }

            JsonArray newProps = new JsonArray();
            if (component.has("properties")) {
                for (JsonElement pEl : component.getAsJsonArray("properties")) {
                    if (!pEl.getAsJsonObject().get("name").getAsString().startsWith("quantum:")) {
                        newProps.add(pEl);
                    }
                }
            }
            addPropIfPresent(newProps, "quantum:riskLevel", getString(worst, "risk_level", "UNKNOWN"));
            addPropIfPresent(newProps, "quantum:title", getString(worst, "title", ""));
            addPropIfPresent(newProps, "quantum:usageSummary", getString(worst, "usage_summary", ""));
            addPropIfPresent(newProps, "quantum:dataSensitivity", getString(worst, "data_sensitivity", ""));
            addPropIfPresent(newProps, "quantum:dataLifetime", getString(worst, "data_lifetime", ""));
            addPropIfPresent(newProps, "quantum:codeSource", getString(worst, "code_source", ""));
            addPropIfPresent(newProps, "quantum:sourcePackage", getString(worst, "source_package", ""));
            addPropIfPresent(newProps, "quantum:remediationOwner", getString(worst, "remediation_owner", ""));
            addPropIfPresent(newProps, "quantum:quantumThreat", getString(worst, "quantum_threat", ""));
            addPropIfPresent(newProps, "quantum:recommendation", getString(worst, "recommendation", ""));
            addPropIfPresent(newProps, "quantum:migrationNotes", getString(worst, "migration_notes", ""));
            addPropIfPresent(newProps, "quantum:findingsAnalyzed", String.valueOf(findings.size()));
            component.add("properties", newProps);
            algorithmsAnnotated++;
        }

        if (appsDescribed > 0 || algorithmsAnnotated > 0) {
            JsonObject metadata = bom.has("metadata") ? bom.getAsJsonObject("metadata") : new JsonObject();
            JsonArray metaProps = new JsonArray();
            if (metadata.has("properties")) {
                for (JsonElement pEl : metadata.getAsJsonArray("properties")) {
                    if (!pEl.getAsJsonObject().get("name").getAsString().startsWith("quantum:")) {
                        metaProps.add(pEl);
                    }
                }
            }
            JsonObject enhancedAt = new JsonObject();
            enhancedAt.addProperty("name", "quantum:enhancedAt");
            enhancedAt.addProperty("value", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metaProps.add(enhancedAt);
            JsonObject enhancedBy = new JsonObject();
            enhancedBy.addProperty("name", "quantum:enhancedBy");
            enhancedBy.addProperty("value", "Contrast Quantum Advisor");
            metaProps.add(enhancedBy);
            metadata.add("properties", metaProps);
            bom.add("metadata", metadata);

            try (FileWriter w = new FileWriter(bomPath)) {
                w.write(gson.toJson(bom));
            }
        }

        return new int[]{appsDescribed, algorithmsAnnotated};
    }

    private void addPropIfPresent(JsonArray props, String name, String value) {
        if (value != null && !value.isEmpty()) {
            JsonObject p = new JsonObject();
            p.addProperty("name", name);
            p.addProperty("value", value);
            props.add(p);
        }
    }

    // ---- Report generation ----

    private String generateReport(List<JsonObject> results, JsonObject metadata, Map<String, AppMetadata> appMetadata, Map<String, String> appDescriptions) {
        String reportDate = LocalDateTime.now().format(DateTimeFormatter.ofPattern("MMMM d, yyyy"));
        String sourceName = "Unknown";
        if (metadata.has("component") && metadata.getAsJsonObject("component").has("name")) {
            sourceName = metadata.getAsJsonObject("component").get("name").getAsString();
        }

        Map<String, String> algoRisks = new LinkedHashMap<>();
        for (JsonObject r : results) {
            String algo = getString(r, "algorithm", "Unknown");
            algoRisks.putIfAbsent(algo, getString(r, "risk_level", "UNKNOWN"));
        }

        Map<String, String> algoRiskLevel = new TreeMap<>();
        Map<String, Set<String>> algoApps = new TreeMap<>();
        Map<String, Integer> algoUsageCount = new TreeMap<>();
        for (JsonObject r : results) {
            String algo = getString(r, "algorithm", "Unknown");
            algoRiskLevel.putIfAbsent(algo, getString(r, "risk_level", "UNKNOWN"));
            algoApps.computeIfAbsent(algo, k -> new TreeSet<>());
            String app = getString(r, "application", null);
            if (app != null) algoApps.get(algo).add(app);
            algoUsageCount.putIfAbsent(algo, r.has("frequency_count") ? r.get("frequency_count").getAsInt() : 0);
        }

        Set<String> appsInReport = new TreeSet<>();
        Map<String, Set<String>> algosByApp = new TreeMap<>();
        for (JsonObject r : results) {
            String app = getString(r, "application", null);
            if (app != null) {
                appsInReport.add(app);
                algosByApp.computeIfAbsent(app, k -> new TreeSet<>()).add(getString(r, "algorithm", "Unknown"));
            }
        }

        int quantumVulnerable = 0, quantumSafe = 0, classicalIssue = 0;
        for (String level : algoRiskLevel.values()) {
            if (level.equals("CRITICAL") || level.equals("HIGH") || level.equals("MEDIUM")) quantumVulnerable++;
            else if (level.equals("LOW")) quantumSafe++;
            else if (level.equals("NOT_QUANTUM_ISSUE")) classicalIssue++;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<!-- Contrast Quantum Advisor Report -->\n\n");
        sb.append("# Contrast Quantum Advisor\n## Post-Quantum Cryptography Readiness Assessment\n\n---\n\n");
        sb.append("**Client:** ").append(sourceName).append("\n");
        sb.append("**Report Date:** ").append(reportDate).append("\n");
        sb.append("**Assessment Type:** Runtime Cryptographic Analysis & Quantum Risk Assessment\n\n---\n\n");
        sb.append("## Executive Summary\n\n");
        sb.append("This assessment inventories every cryptographic algorithm actually observed running in production ")
          .append("across your applications - algorithm strength, mode, invocation frequency, and the real call context ")
          .append("behind each finding, captured by Contrast Security's runtime instrumentation rather than declared ")
          .append("dependencies or static code scanning.\n\n");
        sb.append("**").append(appsInReport.size()).append("** application(s) use cryptography, calling **")
          .append(algoRiskLevel.size()).append("** distinct algorithm(s), for **").append(results.size())
          .append("** total findings analyzed.\n\n");

        if (quantumVulnerable > 0) {
            sb.append("> **").append(quantumVulnerable).append(" of ").append(algoRiskLevel.size())
              .append(" algorithms need post-quantum remediation** (CRITICAL/HIGH/MEDIUM risk).\n");
        } else {
            sb.append("> No algorithms were flagged as needing post-quantum remediation.\n");
        }

        sb.append("\n### Applications\n\n| Application | Algorithms Used |\n|-------------|------------------|\n");
        for (String app : appsInReport) {
            StringBuilder algos = new StringBuilder();
            for (String a : algosByApp.getOrDefault(app, new TreeSet<>())) {
                if (algos.length() > 0) algos.append(", ");
                algos.append('`').append(a).append('`');
            }
            sb.append("| ").append(app).append(" | ").append(algos).append(" |\n");
        }

        sb.append("\n### Algorithms\n\n| Algorithm | Risk Level | Applications | Invocations |\n|-----------|------------|---------------|-------------|\n");
        for (Map.Entry<String, String> e : algoRiskLevel.entrySet()) {
            String algo = e.getKey();
            sb.append("| `").append(algo).append("` | ").append(e.getValue()).append(" | ")
              .append(algoApps.getOrDefault(algo, new TreeSet<>()).size()).append(" | ")
              .append(String.format("%,d", algoUsageCount.getOrDefault(algo, 0))).append(" |\n");
        }

        sb.append("\n- **").append(quantumVulnerable).append("** algorithm(s) need post-quantum remediation (CRITICAL/HIGH/MEDIUM)\n");
        sb.append("- **").append(quantumSafe).append("** algorithm(s) are quantum-safe as-is (LOW)\n");
        sb.append("- **").append(classicalIssue).append("** algorithm(s) have classical (non-quantum) weaknesses to address separately\n\n");

        Set<String> appsWithFindings = new TreeSet<>(appsInReport);
        appsWithFindings.retainAll(appMetadata.keySet());
        if (!appsWithFindings.isEmpty()) {
            sb.append("### Application Context\n\n");
            for (String appName : appsWithFindings) {
                AppMetadata app = appMetadata.get(appName);
                sb.append("**").append(appName).append("**\n");
                List<String> metaBits = new ArrayList<>();
                if (app != null) {
                    if (app.language != null) metaBits.add("Language: " + app.language);
                    if (app.postureScore != null) metaBits.add("Posture Score: " + app.postureScore + " (" + app.postureSeverity + ")");
                    if (!app.connectedApplications.isEmpty()) metaBits.add("Connects To: " + String.join(", ", app.connectedApplications));
                }
                if (!metaBits.isEmpty()) sb.append(String.join(" | ", metaBits)).append("\n");
                String description = appDescriptions.get(appName);
                if (description != null && !description.isEmpty()) {
                    sb.append("\n").append(description).append("\n");
                }
                sb.append("\n");
            }
            sb.append("\n");
        }

        Map<String, Integer> riskCounts = new LinkedHashMap<>();
        for (JsonObject r : results) {
            String level = getString(r, "risk_level", "UNKNOWN");
            riskCounts.merge(level, 1, Integer::sum);
        }

        int total = results.size();
        int criticalCount = riskCounts.getOrDefault("CRITICAL", 0);
        int highCount = riskCounts.getOrDefault("HIGH", 0);
        int actionNeeded = criticalCount + highCount;

        sb.append("### Quantum Risk Overview\n\n");
        if (actionNeeded > 0) {
            sb.append("> ⚠️ **").append(actionNeeded).append(" of ").append(total)
              .append(" findings require priority remediation** — ").append(criticalCount).append(" critical, ")
              .append(highCount).append(" high\n\n");
        } else {
            sb.append("> ✅ **No critical quantum vulnerabilities detected**\n\n");
        }

        Map<String, String> sourceEmoji = new LinkedHashMap<>();
        sourceEmoji.put("custom_code", "🏠 Custom Code");
        sourceEmoji.put("open_source_library", "📦 Open Source Library");
        sourceEmoji.put("commercial_library", "💼 Commercial Library");
        sourceEmoji.put("framework", "🏗️ Framework");
        sourceEmoji.put("jdk_runtime", "☕ JDK/Runtime");
        sourceEmoji.put("unknown", "❓ Unknown");
        Map<String, String> sourceApproach = new LinkedHashMap<>();
        sourceApproach.put("custom_code", "Direct code change by dev team");
        sourceApproach.put("open_source_library", "File issue/PR, upgrade when fixed");
        sourceApproach.put("commercial_library", "Contact vendor support");
        sourceApproach.put("framework", "Upgrade framework version");
        sourceApproach.put("jdk_runtime", "Upgrade JDK or add PQ provider");
        sourceApproach.put("unknown", "Requires investigation");

        Map<String, Integer> sourceCounts = new LinkedHashMap<>();
        for (JsonObject r : results) {
            sourceCounts.merge(getString(r, "code_source", "unknown"), 1, Integer::sum);
        }
        sb.append("### Code Source Summary\n\n| Source Type | Count | Remediation Approach |\n|-------------|-------|---------------------|\n");
        for (String key : sourceEmoji.keySet()) {
            if (sourceCounts.containsKey(key)) {
                sb.append("| ").append(sourceEmoji.get(key)).append(" | ").append(sourceCounts.get(key))
                  .append(" | ").append(sourceApproach.get(key)).append(" |\n");
            }
        }
        sb.append("\n---\n\n## Detailed Findings\n\n");

        Map<String, String> levelEmoji = new LinkedHashMap<>();
        levelEmoji.put("CRITICAL", "🔴");
        levelEmoji.put("HIGH", "🟠");
        levelEmoji.put("MEDIUM", "🟡");
        levelEmoji.put("LOW", "🟢");
        levelEmoji.put("NOT_QUANTUM_ISSUE", "⚪");
        Map<String, String> levelTitle = new LinkedHashMap<>();
        levelTitle.put("CRITICAL", "Critical Priority");
        levelTitle.put("HIGH", "High Priority");
        levelTitle.put("MEDIUM", "Medium Priority");
        levelTitle.put("LOW", "Low Priority (Quantum-Safe)");
        levelTitle.put("NOT_QUANTUM_ISSUE", "Non-Quantum Issues");

        int taskNum = 1;
        for (String level : new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT_QUANTUM_ISSUE"}) {
            List<JsonObject> levelResults = new ArrayList<>();
            for (JsonObject r : results) {
                if (getString(r, "risk_level", "UNKNOWN").equals(level)) levelResults.add(r);
            }
            if (levelResults.isEmpty()) continue;

            sb.append("### ").append(levelEmoji.get(level)).append(" ").append(levelTitle.get(level)).append("\n\n");

            for (JsonObject r : levelResults) {
                String title = getString(r, "title", "Unknown");
                sb.append("#### [").append(level).append("] Finding ").append(taskNum).append(": ").append(title).append("\n\n");

                String freq = getString(r, "frequency", "Unknown");
                int freqCount = r.has("frequency_count") ? r.get("frequency_count").getAsInt() : 0;
                int reachability = r.has("reachability") ? r.get("reachability").getAsInt() : 1;
                String codeSource = getString(r, "code_source", "unknown");
                String srcLabel = sourceEmoji.getOrDefault(codeSource, "❓ Unknown");

                sb.append("| Attribute | Value |\n|-----------|-------|\n");
                sb.append("| **Algorithm** | `").append(getString(r, "algorithm", "Unknown")).append("` |\n");
                sb.append("| **Application** | ").append(getString(r, "application", "Unknown")).append(" |\n");
                sb.append("| **Code Source** | ").append(srcLabel).append(" |\n");
                sb.append("| **Source Package** | `").append(getString(r, "source_package", "Unknown")).append("` |\n");
                sb.append("| **Remediation Owner** | ").append(getString(r, "remediation_owner", "Unknown")).append(" |\n");
                sb.append("| **Frequency** | ").append(freq).append(" (").append(String.format("%,d", freqCount)).append(" invocations) |\n");
                sb.append("| **Reachability** | ").append(reachability).append(" code path(s) invoke this algorithm |\n");
                sb.append("| **Data Sensitivity** | ").append(getString(r, "data_sensitivity", "Unknown")).append(" |\n");
                sb.append("| **Data Lifetime** | ").append(getString(r, "data_lifetime", "Unknown")).append(" |\n\n");

                sb.append("**Description:** ").append(getString(r, "usage_summary", "Unknown")).append("\n\n");
                sb.append("**Quantum Threat Analysis:** ").append(getString(r, "quantum_threat", "Unknown")).append("\n\n");
                sb.append("**Recommendation:** ").append(getString(r, "recommendation", "None")).append("\n\n");

                if (r.has("migration_notes") && !r.get("migration_notes").isJsonNull()) {
                    sb.append("**Remediation Plan:**\n").append(r.get("migration_notes").getAsString()).append("\n\n");
                }

                sb.append("---\n\n");
                taskNum++;
            }
        }

        sb.append("## Appendix A: Algorithm Risk Matrix\n\n| Algorithm | Quantum Risk | Remediation Timeline |\n|-----------|--------------|----------------------|\n");
        Map<String, String> timelineMap = new LinkedHashMap<>();
        timelineMap.put("CRITICAL", "🚨 Immediate");
        timelineMap.put("HIGH", "⏰ 6 months");
        timelineMap.put("MEDIUM", "📅 6-18 months");
        timelineMap.put("LOW", "✅ No action needed");
        timelineMap.put("NOT_QUANTUM_ISSUE", "🔧 Classical security fix");

        List<Map.Entry<String, String>> sortedAlgos = new ArrayList<>(algoRisks.entrySet());
        List<String> order = Arrays.asList("CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT_QUANTUM_ISSUE", "UNKNOWN");
        sortedAlgos.sort(Comparator.comparingInt(e -> {
            int idx = order.indexOf(e.getValue());
            return idx < 0 ? 99 : idx;
        }));
        for (Map.Entry<String, String> e : sortedAlgos) {
            String emoji = levelEmoji.getOrDefault(e.getValue(), "❓");
            String timeline = timelineMap.getOrDefault(e.getValue(), "Review");
            sb.append("| `").append(e.getKey()).append("` | ").append(emoji).append(" ").append(e.getValue())
              .append(" | ").append(timeline).append(" |\n");
        }

        sb.append("\n---\n\n## Appendix B: Methodology\n\n### Quantum Threat Model\n\n");
        sb.append("This assessment evaluates cryptographic algorithms against two primary quantum computing threats:\n\n");
        sb.append("| Threat | Impact | Affected Algorithms |\n|--------|--------|---------------------|\n");
        sb.append("| **Shor's Algorithm** | Complete break of asymmetric crypto | RSA, ECDSA, ECDH, DH, DSA |\n");
        sb.append("| **Grover's Algorithm** | Halves effective key length | AES, SHA (still safe at 256-bit) |\n\n");
        sb.append("### Risk Classification Criteria\n\n");
        sb.append("- **CRITICAL**: Asymmetric cryptography protecting long-term secrets, digital signatures, or stored data\n");
        sb.append("- **HIGH**: Asymmetric cryptography for sensitive data with medium-term exposure\n");
        sb.append("- **MEDIUM**: Asymmetric cryptography with forward secrecy mitigations\n");
        sb.append("- **LOW**: Symmetric cryptography with sufficient key sizes (quantum-resistant)\n");
        sb.append("- **NOT_QUANTUM_ISSUE**: Classical cryptographic weaknesses unrelated to quantum threats\n\n");
        sb.append("### Data Sources\n\n");
        sb.append("Cryptographic usage data collected via Contrast Security runtime instrumentation, providing:\n");
        sb.append("- Actual algorithms in use (not just declared dependencies)\n");
        sb.append("- Complete call stack context for usage classification\n");
        sb.append("- Invocation frequency and code path reachability metrics\n\n---\n\n");
        sb.append("*Report generated by Contrast Quantum Advisor*\n*Powered by Contrast Security Runtime Observability*\n");

        return sb.toString();
    }
}
