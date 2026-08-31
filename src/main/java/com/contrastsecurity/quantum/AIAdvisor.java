package com.contrastsecurity.quantum;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
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
 * AI-powered inventory report of AI-enabled applications from an AI-BOM. Java port
 * of the former tools/ai_advisor.py - groups findings by application (not by risk
 * level): for each app, describes what it appears to be, then lists how it uses AI.
 *
 * Usage:
 *   java -jar quantum.jar aibom-advisor aibom.json [-v] [-o report.md] [--json out.json] [--no-confirm]
 */
public class AIAdvisor {

    private static final String ANALYSIS_PROMPT =
        "You are an application security and AI governance analyst building an inventory of " +
        "AI-enabled applications from Contrast Security runtime observability data.\n\n" +
        "You are given metadata about ONE application (name, language, architecture/connection graph info) and a " +
        "list of AI/LLM usage instances observed running in it, each with a model, provider, endpoint, and a real " +
        "stack trace captured at runtime.\n\n" +
        "## Your Task\n\n" +
        "1. Write a 2-4 sentence description of what this application/API most likely does. Base this on its name, " +
        "language, which other applications it's connected to, and its library footprint - not on the AI usage alone.\n" +
        "2. For EACH AI usage instance provided, write a 2-3 sentence description of what that specific call appears " +
        "to be doing. Name the 2-4 key application/library methods on the call path immediately around the AI call " +
        "(e.g. \"AiController.openai calls AiService.chat, which invokes the OpenAI ChatCompletionService.create client\") " +
        "rather than describing the call in the abstract - the caller/callee names are what make this concrete. Ignore " +
        "generic framework/container plumbing (servlet dispatch, filter chains, thread pool internals) further down the " +
        "stack; focus on the application-level and client-library frames closest to the AI call itself. Be concrete about " +
        "the apparent purpose (e.g. \"generates a chat reply for the /chat endpoint\", \"summarizes an uploaded document\").\n" +
        "3. Assess the overall AI usage risk level for this application.\n\n" +
        "## Risk Levels\n\n" +
        "**CRITICAL**: Sensitive/regulated data (PII, credentials, source code, health/financial records) likely sent " +
        "to an unvetted third-party model, or an unknown model/provider in a production path with no oversight.\n" +
        "**HIGH**: Production cloud AI usage without an apparent governance process (\"shadow AI\").\n" +
        "**MEDIUM**: Approved-looking usage lacking monitoring, or non-production usage that could reach production unreviewed.\n" +
        "**LOW**: Local/self-hosted model with no external data egress, or clearly low-sensitivity usage.\n" +
        "**NOT_AI_RISK_ISSUE**: Benign, well-governed usage with no identifiable risk signal.\n\n" +
        "## Your Task - Output\n\n" +
        "Return JSON:\n" +
        "```json\n" +
        "{\n" +
        "  \"application_description\": \"2-4 sentence description of what this app/API does\",\n" +
        "  \"risk_level\": \"CRITICAL|HIGH|MEDIUM|LOW|NOT_AI_RISK_ISSUE\",\n" +
        "  \"governance_concern\": \"shadow_ai|ungoverned_cloud_usage|data_exposure_risk|low_risk|none\",\n" +
        "  \"risk_rationale\": \"Why this risk level, considering the app's role and connections\",\n" +
        "  \"recommendation\": \"Specific action to take for this application's AI usage\",\n" +
        "  \"ai_usages\": [\n" +
        "    {\n" +
        "      \"model\": \"model name exactly as given\",\n" +
        "      \"usage_description\": \"2-3 sentences naming the key methods on the call path around the AI call\"\n" +
        "    }\n" +
        "  ]\n" +
        "}\n" +
        "```\n\n" +
        "Include exactly one entry in \"ai_usages\" for each usage instance given below, in the same order.\n";

    static class AIUsageInstance {
        String model;
        String provider;
        String endpoint;
        String hostCategory;
        int usageCount;
        int uniqueLocations;
        List<String> stackTrace = new ArrayList<>();
        String route;
    }

    static class AppInventoryEntry {
        String name;
        String language;
        Double postureScore;
        String postureSeverity;
        Integer criticality;
        Integer openIssuesTotal;
        int serverCount;
        int libraryCount;
        List<String> connectedApplications = new ArrayList<>();
        List<AIUsageInstance> aiUsages = new ArrayList<>();
    }

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) {
        String aibomPath = null;
        boolean verbose = false;
        String output = null;
        String jsonOut = null;
        boolean noConfirm = false;

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("-v") || a.equals("--verbose")) verbose = true;
            else if ((a.equals("-o") || a.equals("--output")) && i + 1 < args.length) output = args[++i];
            else if (a.equals("--json") && i + 1 < args.length) jsonOut = args[++i];
            else if (a.equals("--no-confirm")) noConfirm = true;
            else if (a.equals("-h") || a.equals("--help")) {
                System.out.println("Usage: java -jar quantum.jar aibom-advisor <aibom.json> [-v] [-o report.md] [--json out.json] [--no-confirm]");
                return;
            } else if (!a.startsWith("-")) {
                aibomPath = a;
            }
        }

        if (aibomPath == null) {
            System.err.println("Error: path to AI-BOM JSON file is required");
            System.exit(1);
        }

        try {
            new AIAdvisor().run(aibomPath, verbose, output, jsonOut, noConfirm);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void run(String aibomPath, boolean verbose, String output, String jsonOut, boolean noConfirm) throws Exception {
        System.out.println("\nParsing AI-BOM...");
        List<AppInventoryEntry> entries;
        JsonObject metadata;
        try {
            Object[] parsed = parseAibom(aibomPath);
            @SuppressWarnings("unchecked")
            List<AppInventoryEntry> e = (List<AppInventoryEntry>) parsed[0];
            entries = e;
            metadata = (JsonObject) parsed[1];
        } catch (Exception e) {
            System.err.println("Error parsing AI-BOM: " + e.getMessage());
            System.exit(1);
            return;
        }

        int totalUsages = 0;
        for (AppInventoryEntry e : entries) totalUsages += e.aiUsages.size();
        System.out.println("  Found " + entries.size() + " applications with " + totalUsages + " AI usage instances");

        if (entries.isEmpty()) {
            System.out.println("\nNo AI-enabled applications found!");
            return;
        }

        ClaudeClient client = new ClaudeClient();
        double estimatedCost = client.estimateCost(entries.size(), 2000, 800);
        if (!ClaudeClient.confirmCost(estimatedCost, entries.size(), noConfirm)) {
            System.out.println("Cancelled.");
            return;
        }

        System.out.println("\nAnalyzing " + entries.size() + " applications...");
        List<JsonObject> results = new ArrayList<>();
        for (AppInventoryEntry entry : entries) {
            JsonObject result;
            try {
                result = analyzeApplication(client, entry, verbose);
            } catch (Exception e) {
                System.out.println("  Error analyzing " + entry.name + ": " + e.getMessage());
                result = new JsonObject();
                result.addProperty("application", entry.name);
                result.addProperty("risk_level", "ERROR");
                result.addProperty("application_description", String.valueOf(e.getMessage()));
                result.add("ai_usages", new JsonArray());
            }
            results.add(result);
            String risk = getString(result, "risk_level", "UNKNOWN");
            System.out.println("  [" + risk + "] " + entry.name + " (" + entry.aiUsages.size() + " usage(s))");
        }

        int written = writeDescriptionsToBom(aibomPath, results);
        if (written > 0) {
            System.out.println("  Wrote " + written + " application description(s) back into " + aibomPath);
        }

        String report = generateReport(results, entries, metadata);

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

    private Object[] parseAibom(String path) throws IOException {
        JsonObject aibom;
        try (FileReader reader = new FileReader(path)) {
            aibom = gson.fromJson(reader, JsonObject.class);
        }

        Map<String, JsonObject> appComponents = new LinkedHashMap<>();
        Map<String, JsonObject> modelComponents = new LinkedHashMap<>();
        JsonArray components = aibom.has("components") ? aibom.getAsJsonArray("components") : new JsonArray();
        for (JsonElement el : components) {
            JsonObject c = el.getAsJsonObject();
            String bomRef = getString(c, "bom-ref", "");
            String type = getString(c, "type", "");
            if (type.equals("application") && bomRef.startsWith("app-")) {
                appComponents.put(bomRef, c);
            } else if (type.equals("machine-learning-model")) {
                modelComponents.put(bomRef, c);
            }
        }

        Map<String, List<String>> appToModels = new LinkedHashMap<>();
        JsonArray dependencies = aibom.has("dependencies") ? aibom.getAsJsonArray("dependencies") : new JsonArray();
        for (JsonElement el : dependencies) {
            JsonObject dep = el.getAsJsonObject();
            String ref = getString(dep, "ref", "");
            if (appComponents.containsKey(ref)) {
                List<String> modelRefs = new ArrayList<>();
                if (dep.has("dependsOn")) {
                    for (JsonElement m : dep.getAsJsonArray("dependsOn")) modelRefs.add(m.getAsString());
                }
                appToModels.put(ref, modelRefs);
            }
        }

        List<AppInventoryEntry> entries = new ArrayList<>();
        for (Map.Entry<String, JsonObject> appEntry : appComponents.entrySet()) {
            String appRef = appEntry.getKey();
            JsonObject appComponent = appEntry.getValue();
            Map<String, String> props = properties(appComponent);
            String appName = getString(appComponent, "name", appRef);

            AppInventoryEntry entry = new AppInventoryEntry();
            entry.name = appName;
            entry.language = props.get("contrast:language");
            if (props.containsKey("contrast:postureScore")) entry.postureScore = Double.parseDouble(props.get("contrast:postureScore"));
            entry.postureSeverity = props.get("contrast:postureSeverity");
            if (props.containsKey("contrast:criticality")) entry.criticality = Integer.parseInt(props.get("contrast:criticality"));
            if (props.containsKey("contrast:openIssuesTotal")) entry.openIssuesTotal = Integer.parseInt(props.get("contrast:openIssuesTotal"));
            entry.serverCount = props.containsKey("contrast:serverCount") ? Integer.parseInt(props.get("contrast:serverCount")) : 0;
            entry.libraryCount = props.containsKey("contrast:libraryCount") ? Integer.parseInt(props.get("contrast:libraryCount")) : 0;
            String connected = props.getOrDefault("contrast:connectedApplications", "");
            for (String c : connected.split(",")) {
                if (!c.trim().isEmpty()) entry.connectedApplications.add(c.trim());
            }

            for (String modelRef : appToModels.getOrDefault(appRef, new ArrayList<>())) {
                JsonObject modelComponent = modelComponents.get(modelRef);
                if (modelComponent == null) continue;
                Map<String, String> modelProps = properties(modelComponent);
                String modelName = getString(modelComponent, "name", modelRef);
                String provider = modelComponent.has("publisher") && !modelComponent.get("publisher").isJsonNull()
                    ? modelComponent.get("publisher").getAsString() : modelProps.get("contrast:provider");

                JsonObject evidence = modelComponent.has("evidence") ? modelComponent.getAsJsonObject("evidence") : new JsonObject();
                JsonArray occArr = evidence.has("occurrences") ? evidence.getAsJsonArray("occurrences") : new JsonArray();

                List<JsonObject> appOccurrences = new ArrayList<>();
                for (JsonElement occEl : occArr) {
                    JsonObject occ = occEl.getAsJsonObject();
                    String context = getString(occ, "additionalContext", "");
                    if (context.contains("App: " + appName)) appOccurrences.add(occ);
                }
                int appReachability = appOccurrences.size();

                for (JsonObject occ : appOccurrences) {
                    String context = getString(occ, "additionalContext", "");
                    AIUsageInstance usage = new AIUsageInstance();
                    usage.model = modelName;
                    usage.provider = provider;
                    usage.endpoint = modelProps.get("contrast:endpoint");
                    usage.hostCategory = modelProps.getOrDefault("contrast:hostCategory", "unknown");
                    usage.usageCount = modelProps.containsKey("contrast:usageCount") ? Integer.parseInt(modelProps.get("contrast:usageCount")) : 0;
                    usage.uniqueLocations = appReachability;
                    usage.stackTrace = extractStackTrace(context);
                    usage.route = extractRoute(context);
                    entry.aiUsages.add(usage);
                }
            }

            if (!entry.aiUsages.isEmpty()) entries.add(entry);
        }

        return new Object[]{entries, aibom.has("metadata") ? aibom.getAsJsonObject("metadata") : new JsonObject()};
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

    private String extractRoute(String context) {
        if (!context.contains("Route:")) return null;
        String after = context.split("Route:", 2)[1];
        String route = after.split("\\|")[0].split("\n")[0].trim();
        return route.isEmpty() ? null : route;
    }

    // ---- AI analysis ----

    private String formatAppForAi(AppInventoryEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append("Application: ").append(entry.name).append("\n");
        sb.append("Language: ").append(entry.language != null ? entry.language : "unknown").append("\n");
        String connected = entry.connectedApplications.isEmpty() ? "none observed" : String.join(", ", entry.connectedApplications);
        sb.append("Connected Applications: ").append(connected).append("\n");
        sb.append("Library Count: ").append(entry.libraryCount).append("\n");
        sb.append("Server Instances: ").append(entry.serverCount).append("\n\n");
        sb.append("AI Usage Instances:");

        int i = 1;
        for (AIUsageInstance usage : entry.aiUsages) {
            sb.append("\n\n--- Usage ").append(i++).append(" ---\n");
            sb.append("Model: ").append(usage.model).append("\n");
            sb.append("Provider: ").append(usage.provider != null ? usage.provider : "unknown").append("\n");
            sb.append("Endpoint: ").append(usage.endpoint != null ? usage.endpoint : "unknown").append(" (").append(usage.hostCategory).append(")\n");
            sb.append("Route: ").append(usage.route != null ? usage.route : "unknown").append("\n");
            sb.append("Usage Count: ").append(usage.usageCount).append("\n");
            sb.append("Stack Trace:\n");
            sb.append(usage.stackTrace.isEmpty() ? "(none captured)" : String.join("\n", usage.stackTrace));
        }

        return sb.toString();
    }

    private JsonObject analyzeApplication(ClaudeClient client, AppInventoryEntry entry, boolean verbose) throws Exception {
        String entryText = formatAppForAi(entry);
        if (verbose) System.out.println("  Analyzing " + entry.name + " (" + entry.aiUsages.size() + " AI usage instances)...");

        String response = client.call(ANALYSIS_PROMPT, entryText, null);

        int start = response.indexOf('{');
        int end = response.lastIndexOf('}');
        if (start >= 0 && end > start) {
            try {
                JsonObject result = gson.fromJson(response.substring(start, end + 1), JsonObject.class);
                result.addProperty("application", entry.name);
                return result;
            } catch (Exception ignored) {
                // fall through to fallback below
            }
        }

        JsonObject fallback = new JsonObject();
        fallback.addProperty("application", entry.name);
        fallback.addProperty("risk_level", "UNKNOWN");
        fallback.addProperty("application_description", "Failed to parse AI response");
        fallback.addProperty("recommendation", response.length() > 500 ? response.substring(0, 500) : response);
        fallback.add("ai_usages", new JsonArray());
        return fallback;
    }

    private int writeDescriptionsToBom(String aibomPath, List<JsonObject> results) throws IOException {
        Map<String, String> descriptions = new LinkedHashMap<>();
        for (JsonObject r : results) {
            String app = getString(r, "application", null);
            if (app != null) descriptions.put(app, getString(r, "application_description", null));
        }

        JsonObject aibom;
        try (FileReader reader = new FileReader(aibomPath)) {
            aibom = gson.fromJson(reader, JsonObject.class);
        }

        int written = 0;
        JsonArray components = aibom.has("components") ? aibom.getAsJsonArray("components") : new JsonArray();
        for (JsonElement el : components) {
            JsonObject c = el.getAsJsonObject();
            String bomRef = getString(c, "bom-ref", "");
            if (!getString(c, "type", "").equals("application") || !bomRef.startsWith("app-")) continue;
            String description = descriptions.get(getString(c, "name", ""));
            if (description != null && !description.isEmpty()) {
                c.addProperty("description", description);
                written++;
            }
        }

        if (written > 0) {
            try (FileWriter w = new FileWriter(aibomPath)) {
                w.write(gson.toJson(aibom));
            }
        }

        return written;
    }

    private String frequencyLabel(int usageCount) {
        if (usageCount >= 100000) return "Very High";
        if (usageCount >= 10000) return "High";
        if (usageCount >= 1000) return "Medium";
        if (usageCount >= 100) return "Low";
        return "Very Low";
    }

    // ---- Report generation ----

    private String generateReport(List<JsonObject> appResults, List<AppInventoryEntry> entries, JsonObject metadata) {
        String reportDate = LocalDateTime.now().format(DateTimeFormatter.ofPattern("MMMM d, yyyy"));
        String sourceName = "Unknown";
        if (metadata.has("component") && metadata.getAsJsonObject("component").has("name")) {
            sourceName = metadata.getAsJsonObject("component").get("name").getAsString();
        }

        Map<String, AppInventoryEntry> entriesByName = new LinkedHashMap<>();
        for (AppInventoryEntry e : entries) entriesByName.put(e.name, e);

        Map<String, Integer> riskCounts = new LinkedHashMap<>();
        Map<String, String> riskByApp = new LinkedHashMap<>();
        for (JsonObject r : appResults) {
            String level = getString(r, "risk_level", "UNKNOWN");
            riskCounts.merge(level, 1, Integer::sum);
            String app = getString(r, "application", null);
            if (app != null) riskByApp.put(app, level);
        }

        int totalApps = appResults.size();
        int totalUsages = 0;
        for (AppInventoryEntry e : entries) totalUsages += e.aiUsages.size();
        int criticalCount = riskCounts.getOrDefault("CRITICAL", 0);
        int highCount = riskCounts.getOrDefault("HIGH", 0);
        int actionNeeded = criticalCount + highCount;

        // Aggregate model/provider usage. usageCount is the model's total invocation
        // count (org-wide) - set once per model here, not summed across apps/usages.
        Map<String, String[]> modelKeyToProviderModel = new LinkedHashMap<>();
        Map<String, String> modelHostCategory = new LinkedHashMap<>();
        Map<String, Set<String>> modelApps = new TreeMap<>();
        Map<String, Integer> modelUsageCount = new LinkedHashMap<>();
        for (AppInventoryEntry e : entries) {
            for (AIUsageInstance u : e.aiUsages) {
                String provider = u.provider != null ? u.provider : "unknown";
                String key = provider + "::" + u.model;
                modelKeyToProviderModel.putIfAbsent(key, new String[]{provider, u.model});
                modelHostCategory.putIfAbsent(key, u.hostCategory);
                modelUsageCount.putIfAbsent(key, u.usageCount);
                modelApps.computeIfAbsent(key, k -> new TreeSet<>()).add(e.name);
            }
        }

        int cloudModels = 0, localModels = 0;
        for (String hc : modelHostCategory.values()) {
            if (hc.equals("cloud")) cloudModels++;
            else if (hc.equals("local")) localModels++;
        }
        Set<String> distinctProviders = new TreeSet<>();
        for (String[] pm : modelKeyToProviderModel.values()) distinctProviders.add(pm[0]);

        StringBuilder sb = new StringBuilder();
        sb.append("<!-- Contrast AI Advisor Report -->\n\n");
        sb.append("# Contrast AI Advisor\n## Inventory of AI-Enabled Applications\n\n---\n\n");
        sb.append("**Client:** ").append(sourceName).append("\n");
        sb.append("**Report Date:** ").append(reportDate).append("\n");
        sb.append("**Assessment Type:** Runtime AI/LLM Usage Inventory & Governance Risk Assessment\n\n---\n\n");
        sb.append("## Executive Summary\n\n");
        sb.append("This report inventories every AI/LLM model and provider observed actually running in production ")
          .append("across your applications - the model, provider, destination endpoint, and real call stack behind ")
          .append("each usage, captured by Contrast Security's runtime instrumentation.\n\n");
        sb.append("**").append(totalApps).append("** application(s) use AI, calling **")
          .append(modelKeyToProviderModel.size()).append("** distinct model(s) across **")
          .append(distinctProviders.size()).append("** provider(s), for **").append(totalUsages)
          .append("** total usage instance(s).\n\n");

        if (actionNeeded > 0) {
            sb.append("> **").append(actionNeeded).append(" of ").append(totalApps)
              .append(" applications need priority review** (").append(criticalCount).append(" critical, ")
              .append(highCount).append(" high) for their AI usage.\n");
        } else {
            sb.append("> No applications were flagged CRITICAL or HIGH risk for their AI usage.\n");
        }

        sb.append("\n### Applications\n\n| Application | Risk Level | Models Used |\n|-------------|------------|--------------|\n");
        for (AppInventoryEntry e : entries) {
            Set<String> models = new TreeSet<>();
            for (AIUsageInstance u : e.aiUsages) models.add("`" + u.model + "`");
            sb.append("| ").append(e.name).append(" | ").append(riskByApp.getOrDefault(e.name, "UNKNOWN"))
              .append(" | ").append(String.join(", ", models)).append(" |\n");
        }

        sb.append("\n### Models & Providers\n\n| Provider | Model | Host Category | Applications | Invocations |\n|----------|-------|----------------|---------------|-------------|\n");
        List<String> sortedKeys = new ArrayList<>(modelKeyToProviderModel.keySet());
        sortedKeys.sort(Comparator.naturalOrder());
        for (String key : sortedKeys) {
            String[] pm = modelKeyToProviderModel.get(key);
            sb.append("| ").append(pm[0]).append(" | `").append(pm[1]).append("` | ")
              .append(modelHostCategory.get(key)).append(" | ").append(modelApps.getOrDefault(key, new TreeSet<>()).size())
              .append(" | ").append(String.format("%,d", modelUsageCount.getOrDefault(key, 0))).append(" |\n");
        }

        sb.append("\n");
        if (cloudModels > 0) {
            sb.append("- **").append(cloudModels).append("** model(s) called over the network to an external cloud provider (data leaves your infrastructure)\n");
        }
        if (localModels > 0) {
            sb.append("- **").append(localModels).append("** model(s) self-hosted/local (no external data egress)\n");
        }

        sb.append("\n| Risk Level | Applications |\n|------------|--------------|\n");
        for (String level : new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT_AI_RISK_ISSUE", "UNKNOWN"}) {
            if (riskCounts.containsKey(level)) {
                sb.append("| ").append(level).append(" | ").append(riskCounts.get(level)).append(" |\n");
            }
        }

        sb.append("\n---\n\n## Application Inventory\n\n");

        List<String> order = java.util.Arrays.asList("CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT_AI_RISK_ISSUE", "UNKNOWN");
        List<JsonObject> sortedResults = new ArrayList<>(appResults);
        sortedResults.sort(Comparator.comparingInt(r -> {
            int idx = order.indexOf(getString(r, "risk_level", "UNKNOWN"));
            return idx < 0 ? 99 : idx;
        }));

        for (JsonObject r : sortedResults) {
            String appName = getString(r, "application", "Unknown");
            AppInventoryEntry entry = entriesByName.get(appName);
            String riskLevel = getString(r, "risk_level", "UNKNOWN");

            sb.append("### ").append(appName).append("\n\n**Risk Level:** ").append(riskLevel).append("\n\n");

            if (entry != null) {
                List<String> metaBits = new ArrayList<>();
                if (entry.language != null) metaBits.add("**Language:** " + entry.language);
                if (entry.postureScore != null) metaBits.add("**Posture Score:** " + entry.postureScore + " (" + entry.postureSeverity + ")");
                if (entry.openIssuesTotal != null) metaBits.add("**Open Issues:** " + entry.openIssuesTotal);
                if (!entry.connectedApplications.isEmpty()) metaBits.add("**Connects To:** " + String.join(", ", entry.connectedApplications));
                if (!metaBits.isEmpty()) sb.append(String.join(" | ", metaBits)).append("\n\n");
            }

            sb.append(getString(r, "application_description", "No description available.")).append("\n\n");
            sb.append("**Risk Rationale:** ").append(getString(r, "risk_rationale", "Unknown")).append("\n\n");
            sb.append("**Recommendation:** ").append(getString(r, "recommendation", "None")).append("\n\n");
            sb.append("#### AI Usage\n\n");

            Map<String, String> usageDescriptions = new LinkedHashMap<>();
            if (r.has("ai_usages")) {
                for (JsonElement uEl : r.getAsJsonArray("ai_usages")) {
                    JsonObject u = uEl.getAsJsonObject();
                    usageDescriptions.put(getString(u, "model", ""), getString(u, "usage_description", null));
                }
            }

            if (entry != null) {
                for (AIUsageInstance usage : entry.aiUsages) {
                    String freq = frequencyLabel(usage.usageCount);
                    sb.append("| Attribute | Value |\n|-----------|-------|\n");
                    sb.append("| **Model** | `").append(usage.model).append("` |\n");
                    sb.append("| **Provider** | ").append(usage.provider != null ? usage.provider : "unknown").append(" |\n");
                    sb.append("| **Endpoint** | `").append(usage.endpoint != null ? usage.endpoint : "unknown").append("` |\n");
                    sb.append("| **Host Category** | ").append(usage.hostCategory).append(" |\n");
                    sb.append("| **Route** | ").append(usage.route != null ? usage.route : "unknown").append(" |\n");
                    sb.append("| **Frequency (model-wide)** | ").append(freq).append(" (")
                      .append(String.format("%,d", usage.usageCount)).append(" invocations across all apps using this model) |\n");
                    sb.append("| **Reachability (this app)** | ").append(usage.uniqueLocations).append(" code path(s) in this application |\n\n");

                    String description = usageDescriptions.getOrDefault(usage.model, "No description available.");
                    sb.append("**What it's doing:** ").append(description).append("\n\n");
                }
            }

            sb.append("---\n\n");
        }

        sb.append("## Appendix: Methodology\n\n");
        sb.append("AI/LLM usage data collected via Contrast Security runtime instrumentation. Application descriptions ")
          .append("and connection data are derived from the Contrast architecture graph (application, server, and ")
          .append("library relationships); AI usage descriptions are inferred from the real stack trace captured at ")
          .append("each call site.\n\n");
        sb.append("- **CRITICAL**: Likely sensitive/regulated data sent to an unvetted third-party model\n");
        sb.append("- **HIGH**: Production cloud AI usage without an apparent governance process\n");
        sb.append("- **MEDIUM**: Approved-looking usage lacking monitoring, or non-production usage that could reach production\n");
        sb.append("- **LOW**: Local/self-hosted usage or clearly low-sensitivity usage\n");
        sb.append("- **NOT_AI_RISK_ISSUE**: Benign, well-governed usage with no identifiable risk signal\n\n---\n\n");
        sb.append("*Report generated by Contrast AI Advisor*\n*Powered by Contrast Security Runtime Observability*\n");

        return sb.toString();
    }
}
