package com.contrastsecurity.runtimeanalyst;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * AI-powered review of a CycloneDX VEX document produced by VEXGenerator - not a second
 * opinion on whether the CVE exists (Contrast's runtime data already establishes that),
 * but a sanity check on whether each "not_affected"/"in_triage" CLAIM is well-supported
 * given the CVE's severity/exploitability, or whether a human should look at it before
 * relying on it.
 *
 * Usage:
 *   java -jar runtime-analyst.jar vex-advisor vex.json [-v] [-o report.md] [--json out.json] [--no-confirm]
 */
public class VEXAdvisor {

    private static final String ANALYSIS_PROMPT =
        "You are an application security analyst reviewing a set of VEX (Vulnerability Exploitability eXchange) " +
        "claims that a tool generated automatically from Contrast Security runtime observability data, for ONE " +
        "application.\n\n" +
        "Each claim already has a CycloneDX analysis.state (not_affected or in_triage) and a justification/detail " +
        "explaining WHY the tool made that claim (e.g. the library's classes were never loaded at runtime, or the " +
        "vulnerable code path hasn't executed in N days of observation). Your job is NOT to re-derive the CVE - it " +
        "is to judge whether relying on each claim, as stated, is reasonable given the CVE's severity/exploitability, " +
        "or whether it's the kind of claim a human reviewer should double-check before trusting it.\n\n" +
        "You're also given whether Assess (the module that produces the runtime evidence every claim rests on) and " +
        "ADR (the classic HTTP-rule-based RASP module, formerly branded \"Protect\" - distinct from CVE Shield) " +
        "are enabled per environment for this application, and whether CVE Shield itself has any coverage for " +
        "each specific CVE at all (a per-CVE, product-level fact - not something that varies by environment). " +
        "Weigh all of this directly: a duration-based claim scoped " +
        "to an environment where Assess has no data or is disabled isn't weak evidence, it's NO evidence - flag " +
        "it regardless of severity. A claim where CVE Shield has no coverage for that CVE at all is weaker still " +
        "than one where Shield exists and simply hasn't fired - \"we haven't seen it\" means less when nothing " +
        "was capable of catching it in the first place. A claim in an environment where ADR is disabled has one " +
        "less active mitigating control as a backstop if the absence-of-execution reasoning turns out wrong, " +
        "which raises the stakes of getting it wrong.\n\n" +
        "## What makes a claim worth flagging for review\n\n" +
        "- Any duration-based claim scoped to an environment where Assess has no data or is disabled - there is no " +
        "runtime evidence behind it at all, regardless of the CVE's severity.\n" +
        "- A duration-based claim on a CRITICAL/HIGH severity CVE where CVE Shield has no coverage at all for that " +
        "CVE - there's no possibility of an active backstop catching an exploit attempt, so the claim rests " +
        "entirely on absence-of-execution.\n" +
        "- A `not_affected` claim justified only by \"N days without observed execution\" (not by code_not_reachable " +
        "or protected_at_runtime) on a CRITICAL/HIGH severity CVE, especially one with a high EPSS score or KEV " +
        "(known-exploited) status - absence of evidence is weaker evidence the more severe/exploitable the CVE is.\n" +
        "- An `in_triage` claim on a CRITICAL/HIGH severity CVE with very few days observed so far - not wrong, but " +
        "worth surfacing as still-open risk rather than letting it sit silently.\n" +
        "- Anything where the day count looks barely over the acceptance threshold rather than comfortably past it.\n\n" +
        "## What's normally fine as-is\n\n" +
        "- `code_not_reachable` (zero classes of the library ever loaded) - this is a structural fact, not a " +
        "probabilistic one, regardless of severity.\n" +
        "- `protected_at_runtime` (CVE Shield actively mitigating) - an active control, not an absence of " +
        "evidence.\n" +
        "- Low/medium severity CVEs accepted on duration alone - lower stakes if the absence-of-evidence reasoning " +
        "turns out wrong.\n\n" +
        "## Your Task - Output\n\n" +
        "Return JSON:\n" +
        "```json\n" +
        "{\n" +
        "  \"application_description\": \"2-3 sentence overview of this application's VEX posture - how many claims, \"\n" +
        "    + \"how sound they generally look\",\n" +
        "  \"risk_level\": \"CRITICAL|HIGH|MEDIUM|LOW|SOUND\",\n" +
        "  \"risk_rationale\": \"Why this level, referencing the specific claims that drove it\",\n" +
        "  \"recommendation\": \"Specific next action - e.g. which CVEs need a human look before relying on this VEX\",\n" +
        "  \"statements\": [\n" +
        "    {\n" +
        "      \"cve_id\": \"CVE ID exactly as given\",\n" +
        "      \"assessment\": \"sound|needs_review\",\n" +
        "      \"rationale\": \"1-2 sentences on why this specific claim is or isn't safe to rely on as-is\"\n" +
        "    }\n" +
        "  ]\n" +
        "}\n" +
        "```\n\n" +
        "Include exactly one entry in \"statements\" for each claim given below, keyed by its CVE ID.\n";

    static class VexStatement {
        String cveId;
        String purl;
        Double score;
        String severity;
        String state;
        String justification;
        String detail;
        String recommendation;
        Double epssScore;
        Double epssPercentile;
        Boolean cisaKev;
        Boolean shieldAvailable;
        long classesUsed;
        long classCount;
        long daysObserved;
        long acceptAfterDays;
    }

    static class AppEntry {
        String name;
        List<VexStatement> statements = new ArrayList<>();
        // "true"/"false"/"" (no agent ever seen in that environment) - see VEXGenerator.ModuleStatus
        String assessEnabledDev, assessEnabledQa, assessEnabledProd;
        String adrEnabledDev, adrEnabledQa, adrEnabledProd;
    }

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) {
        String vexPath = null;
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
                System.out.println("Usage: java -jar runtime-analyst.jar vex-advisor <vex.json> [-v] [-o report.md] [--json out.json] [--no-confirm]");
                return;
            } else if (!a.startsWith("-")) {
                vexPath = a;
            }
        }

        if (vexPath == null) {
            System.err.println("Error: path to VEX JSON file is required");
            System.exit(1);
        }

        try {
            new VEXAdvisor().run(vexPath, verbose, output, jsonOut, noConfirm);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void run(String vexPath, boolean verbose, String output, String jsonOut, boolean noConfirm) throws Exception {
        System.out.println("\nParsing VEX...");
        List<AppEntry> entries = parseVex(vexPath);

        int totalStatements = 0;
        for (AppEntry e : entries) totalStatements += e.statements.size();
        System.out.println("  Found " + entries.size() + " application(s) with " + totalStatements + " VEX statement(s)");

        if (entries.isEmpty()) {
            System.out.println("\nNo VEX statements found!");
            return;
        }

        ClaudeClient client = new ClaudeClient();
        double estimatedCost = client.estimateCost(entries.size(), 2000, 800);
        if (!ClaudeClient.confirmCost(estimatedCost, entries.size(), noConfirm)) {
            System.out.println("Cancelled.");
            return;
        }

        System.out.println("\nAnalyzing " + entries.size() + " application(s)...");
        List<JsonObject> results = new ArrayList<>();
        for (AppEntry entry : entries) {
            JsonObject result;
            try {
                result = analyzeApplication(client, entry, verbose);
            } catch (Exception e) {
                System.out.println("  Error analyzing " + entry.name + ": " + e.getMessage());
                result = new JsonObject();
                result.addProperty("application", entry.name);
                result.addProperty("risk_level", "ERROR");
                result.addProperty("application_description", String.valueOf(e.getMessage()));
                result.add("statements", new JsonArray());
            }
            results.add(result);
            String risk = getString(result, "risk_level", "UNKNOWN");
            System.out.println("  [" + risk + "] " + entry.name + " (" + entry.statements.size() + " statement(s))");
        }

        int written = writeAssessmentsToVex(vexPath, results);
        if (written > 0) {
            System.out.println("  Wrote " + written + " assessment(s) back into " + vexPath);
        }

        String report = generateReport(results, entries);

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

    private List<AppEntry> parseVex(String path) throws IOException {
        JsonObject vex;
        try (FileReader reader = new FileReader(path)) {
            vex = gson.fromJson(reader, JsonObject.class);
        }

        Map<String, AppEntry> byApp = new LinkedHashMap<>();
        JsonArray vulnerabilities = vex.has("vulnerabilities") ? vex.getAsJsonArray("vulnerabilities") : new JsonArray();

        for (JsonElement el : vulnerabilities) {
            JsonObject v = el.getAsJsonObject();
            Map<String, String> props = properties(v);
            String appName = props.getOrDefault("contrast:appName", "Unknown Application");

            VexStatement s = new VexStatement();
            s.cveId = getString(v, "id", "");
            if (v.has("affects") && v.getAsJsonArray("affects").size() > 0) {
                s.purl = getString(v.getAsJsonArray("affects").get(0).getAsJsonObject(), "ref", null);
            }
            if (v.has("ratings") && v.getAsJsonArray("ratings").size() > 0) {
                JsonObject rating = v.getAsJsonArray("ratings").get(0).getAsJsonObject();
                if (rating.has("score") && !rating.get("score").isJsonNull()) s.score = rating.get("score").getAsDouble();
                s.severity = getString(rating, "severity", null);
            }
            if (v.has("analysis")) {
                JsonObject analysis = v.getAsJsonObject("analysis");
                s.state = getString(analysis, "state", null);
                s.justification = getString(analysis, "justification", null);
                s.detail = getString(analysis, "detail", null);
            }
            s.recommendation = getString(v, "recommendation", null);
            s.classesUsed = parseLong(props.get("contrast:classesUsed"));
            s.classCount = parseLong(props.get("contrast:classCount"));
            s.daysObserved = parseLong(props.get("contrast:daysObserved"));
            s.acceptAfterDays = parseLong(props.get("contrast:acceptAfterDays"));
            s.epssScore = parseDouble(props.get("contrast:epssScore"));
            s.epssPercentile = parseDouble(props.get("contrast:epssPercentile"));
            String cisaProp = props.get("contrast:cisaKev");
            s.cisaKev = cisaProp != null ? Boolean.parseBoolean(cisaProp) : null;
            String shieldProp = props.get("contrast:shieldAvailable");
            s.shieldAvailable = shieldProp != null && !shieldProp.isEmpty() ? Boolean.parseBoolean(shieldProp) : null;

            byApp.computeIfAbsent(appName, k -> {
                AppEntry e = new AppEntry();
                e.name = k;
                return e;
            }).statements.add(s);
        }

        JsonArray components = vex.has("components") ? vex.getAsJsonArray("components") : new JsonArray();
        for (JsonElement el : components) {
            JsonObject c = el.getAsJsonObject();
            if (!"application".equals(getString(c, "type", null))) continue;
            String appName = getString(c, "name", null);
            AppEntry entry = appName != null ? byApp.get(appName) : null;
            if (entry == null) continue;
            Map<String, String> props = properties(c);
            entry.assessEnabledDev = props.get("contrast:assessEnabledDev");
            entry.assessEnabledQa = props.get("contrast:assessEnabledQa");
            entry.assessEnabledProd = props.get("contrast:assessEnabledProd");
            entry.adrEnabledDev = props.get("contrast:adrEnabledDev");
            entry.adrEnabledQa = props.get("contrast:adrEnabledQa");
            entry.adrEnabledProd = props.get("contrast:adrEnabledProd");
        }

        return new ArrayList<>(byApp.values());
    }

    private long parseLong(String s) {
        if (s == null || s.isEmpty()) return 0L;
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    /** "" (no agent ever seen) is distinct from "false" (agent seen, module explicitly disabled). */
    private String formatEnvFlags(String dev, String qa, String prod) {
        return "dev=" + envFlagLabel(dev) + ", qa=" + envFlagLabel(qa) + ", prod=" + envFlagLabel(prod);
    }

    private String envFlagLabel(String value) {
        if (value == null || value.isEmpty()) return "no data";
        return "true".equals(value) ? "enabled" : "disabled";
    }

    private Double parseDouble(String s) {
        if (s == null || s.isEmpty()) return null;
        try {
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return null;
        }
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

    private String formatAppForAi(AppEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append("Application: ").append(entry.name).append("\n\n");
        sb.append("Assess (the module that produces the runtime evidence behind every claim below) enabled: ")
          .append(formatEnvFlags(entry.assessEnabledDev, entry.assessEnabledQa, entry.assessEnabledProd)).append("\n");
        sb.append("ADR enabled (classic RASP module, formerly \"Protect\" - not CVE Shield): ")
          .append(formatEnvFlags(entry.adrEnabledDev, entry.adrEnabledQa, entry.adrEnabledProd)).append("\n\n");
        sb.append("VEX Claims:");

        for (VexStatement s : entry.statements) {
            sb.append("\n\n--- ").append(s.cveId).append(" ---\n");
            sb.append("Library: ").append(s.purl != null ? s.purl : "unknown").append("\n");
            sb.append("Severity: ").append(s.severity != null ? s.severity : "unknown")
              .append(s.score != null ? " (score " + s.score + ")" : "").append("\n");
            if (s.epssScore != null) {
                sb.append("EPSS: ").append(s.epssScore)
                  .append(s.epssPercentile != null ? " (percentile " + s.epssPercentile + ")" : "").append("\n");
            }
            if (s.cisaKev != null) {
                sb.append("CISA Known Exploited Vulnerabilities (KEV) catalog: ").append(s.cisaKev ? "YES" : "no").append("\n");
            }
            if (s.shieldAvailable != null) {
                sb.append("CVE Shield has coverage for this CVE at all (org-wide fact): ")
                  .append(s.shieldAvailable ? "YES" : "NO - no virtual patch coverage at all").append("\n");
            }
            sb.append("Claimed state: ").append(s.state).append("\n");
            if (s.justification != null) sb.append("Justification: ").append(s.justification).append("\n");
            sb.append("Detail: ").append(s.detail != null ? s.detail : "(none)").append("\n");
            if (s.recommendation != null) sb.append("Recommendation on record: ").append(s.recommendation).append("\n");
            sb.append("Classes used: ").append(s.classesUsed).append(" of ").append(s.classCount).append("\n");
            sb.append("Days observed: ").append(s.daysObserved).append(" (acceptance threshold: ").append(s.acceptAfterDays).append(")\n");
        }

        return sb.toString();
    }

    private JsonObject analyzeApplication(ClaudeClient client, AppEntry entry, boolean verbose) throws Exception {
        String entryText = formatAppForAi(entry);
        if (verbose) System.out.println("  Analyzing " + entry.name + " (" + entry.statements.size() + " VEX statements)...");

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
        fallback.add("statements", new JsonArray());
        return fallback;
    }

    private int writeAssessmentsToVex(String vexPath, List<JsonObject> results) throws IOException {
        Map<String, Map<String, JsonObject>> assessmentsByAppAndCve = new LinkedHashMap<>();
        for (JsonObject r : results) {
            String app = getString(r, "application", null);
            if (app == null || !r.has("statements")) continue;
            Map<String, JsonObject> byCve = new LinkedHashMap<>();
            for (JsonElement el : r.getAsJsonArray("statements")) {
                JsonObject s = el.getAsJsonObject();
                String cveId = getString(s, "cve_id", null);
                if (cveId != null) byCve.put(cveId, s);
            }
            assessmentsByAppAndCve.put(app, byCve);
        }

        JsonObject vex;
        try (FileReader reader = new FileReader(vexPath)) {
            vex = gson.fromJson(reader, JsonObject.class);
        }

        int written = 0;
        JsonArray vulnerabilities = vex.has("vulnerabilities") ? vex.getAsJsonArray("vulnerabilities") : new JsonArray();
        for (JsonElement el : vulnerabilities) {
            JsonObject v = el.getAsJsonObject();
            Map<String, String> props = properties(v);
            String appName = props.getOrDefault("contrast:appName", "Unknown Application");
            String cveId = getString(v, "id", null);

            Map<String, JsonObject> byCve = assessmentsByAppAndCve.get(appName);
            if (byCve == null || cveId == null || !byCve.containsKey(cveId)) continue;

            JsonObject assessment = byCve.get(cveId);
            JsonArray oldProperties = v.has("properties") ? v.getAsJsonArray("properties") : new JsonArray();
            JsonArray properties = new JsonArray();
            for (JsonElement propEl : oldProperties) {
                String name = getString(propEl.getAsJsonObject(), "name", "");
                if (!"contrast:vexAdvisorAssessment".equals(name) && !"contrast:vexAdvisorRationale".equals(name)) {
                    properties.add(propEl);
                }
            }
            properties.add(propertyJson("contrast:vexAdvisorAssessment", getString(assessment, "assessment", "unknown")));
            properties.add(propertyJson("contrast:vexAdvisorRationale", getString(assessment, "rationale", "")));
            v.add("properties", properties);
            written++;
        }

        if (written > 0) {
            try (FileWriter w = new FileWriter(vexPath)) {
                w.write(gson.toJson(vex));
            }
        }

        return written;
    }

    private JsonObject propertyJson(String name, String value) {
        JsonObject p = new JsonObject();
        p.addProperty("name", name);
        p.addProperty("value", value != null ? value : "");
        return p;
    }

    // ---- Report generation ----

    private String generateReport(List<JsonObject> appResults, List<AppEntry> entries) {
        String reportDate = LocalDateTime.now().format(DateTimeFormatter.ofPattern("MMMM d, yyyy"));

        Map<String, AppEntry> entriesByName = new LinkedHashMap<>();
        for (AppEntry e : entries) entriesByName.put(e.name, e);

        // One assessment lookup per (app, cve), built once - avoids re-deriving it per section below.
        Map<String, Map<String, JsonObject>> assessmentsByApp = new LinkedHashMap<>();
        for (JsonObject r : appResults) {
            String app = getString(r, "application", null);
            if (app == null || !r.has("statements")) continue;
            Map<String, JsonObject> byCve = new LinkedHashMap<>();
            for (JsonElement el : r.getAsJsonArray("statements")) {
                JsonObject s = el.getAsJsonObject();
                String cveId = getString(s, "cve_id", null);
                if (cveId != null) byCve.put(cveId, s);
            }
            assessmentsByApp.put(app, byCve);
        }

        Map<String, Integer> riskCounts = new LinkedHashMap<>();
        Map<String, String> riskByApp = new LinkedHashMap<>();
        for (JsonObject r : appResults) {
            String level = getString(r, "risk_level", "UNKNOWN");
            riskCounts.merge(level, 1, Integer::sum);
            String app = getString(r, "application", null);
            if (app != null) riskByApp.put(app, level);
        }

        int totalApps = appResults.size();
        int totalStatements = 0;
        for (AppEntry e : entries) totalStatements += e.statements.size();

        int needsReviewCount = 0;
        List<VexStatement> kevFlagged = new ArrayList<>();
        List<VexStatement> highEpssFlagged = new ArrayList<>();
        for (AppEntry entry : entries) {
            Map<String, JsonObject> byCve = assessmentsByApp.getOrDefault(entry.name, Map.of());
            for (VexStatement s : entry.statements) {
                JsonObject assessment = byCve.get(s.cveId);
                boolean flagged = assessment != null && "needs_review".equals(getString(assessment, "assessment", ""));
                if (flagged) {
                    needsReviewCount++;
                    if (Boolean.TRUE.equals(s.cisaKev)) kevFlagged.add(s);
                    else if (s.epssScore != null && s.epssScore >= 0.5) highEpssFlagged.add(s);
                }
            }
        }

        List<String> criticalOrHighApps = new ArrayList<>();
        for (JsonObject r : appResults) {
            String level = getString(r, "risk_level", "UNKNOWN");
            if ("CRITICAL".equals(level) || "HIGH".equals(level)) {
                criticalOrHighApps.add(getString(r, "application", "Unknown"));
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<!-- Contrast VEX Advisor Report -->\n\n");
        sb.append("# Contrast VEX Advisor\n## Review of Automatically-Generated VEX Claims\n\n---\n\n");
        sb.append("**Report Date:** ").append(reportDate).append("\n");
        sb.append("**Assessment Type:** VEX Claim Soundness Review\n\n---\n\n");
        sb.append("## Summary\n\n");
        sb.append("This report reviews VEX (Vulnerability Exploitability eXchange) claims generated from Contrast ")
          .append("Security runtime library-usage and CVE Shield data. It does not re-derive whether a CVE ")
          .append("exists - it judges whether each `not_affected`/`in_triage` claim is well-supported enough to rely ")
          .append("on as-is, or whether a human should look at it first.\n\n");
        sb.append("**Coverage:** ").append(totalApps).append(" application(s), ").append(totalStatements)
          .append(" VEX statement(s) reviewed.\n\n");

        sb.append("**Key Findings:**\n\n");
        if (needsReviewCount > 0) {
            sb.append("- **").append(needsReviewCount).append(" of ").append(totalStatements)
              .append(" claim(s) flagged for human review** before relying on them.\n");
        } else {
            sb.append("- No claims were flagged for review - all VEX statements look well-supported as generated.\n");
        }
        if (!kevFlagged.isEmpty()) {
            sb.append("- **").append(kevFlagged.size())
              .append(" flagged claim(s) are on CVEs in the CISA Known Exploited Vulnerabilities (KEV) catalog** - ")
              .append("actively exploited in the wild: ").append(formatCveList(kevFlagged, 6)).append(".\n");
        }
        if (!highEpssFlagged.isEmpty()) {
            sb.append("- **").append(highEpssFlagged.size())
              .append(" flagged claim(s) have an EPSS score ≥ 0.5** (50%+ predicted exploitation likelihood): ")
              .append(formatCveList(highEpssFlagged, 6)).append(".\n");
        }
        if (!criticalOrHighApps.isEmpty()) {
            sb.append("- Application(s) rated CRITICAL/HIGH risk: ").append(String.join(", ", criticalOrHighApps)).append(".\n");
        }
        sb.append("\n### Applications\n\n| Application | Risk Level | Statements |\n|-------------|------------|------------|\n");
        for (AppEntry e : entries) {
            sb.append("| ").append(e.name).append(" | ").append(riskByApp.getOrDefault(e.name, "UNKNOWN"))
              .append(" | ").append(e.statements.size()).append(" |\n");
        }

        sb.append("\n| Risk Level | Applications |\n|------------|--------------|\n");
        for (String level : new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "SOUND", "UNKNOWN"}) {
            if (riskCounts.containsKey(level)) {
                sb.append("| ").append(level).append(" | ").append(riskCounts.get(level)).append(" |\n");
            }
        }

        sb.append("\n### Legend\n\n");
        sb.append("**VEX** - `NA` = not_affected, `IT` = in_triage\n\n");
        sb.append("**Shield** - whether CVE Shield has a virtual patch for this specific CVE at all (a per-CVE, ")
          .append("product-level fact - coverage existing anywhere means it's available everywhere Shield is ")
          .append("enabled): `Yes` (Shield covers it, even if it hasn't fired), `No` (no Shield coverage for this ")
          .append("CVE at all - the claim rests entirely on absence-of-execution, with no possible active ")
          .append("backstop), `-` (unknown).\n\n");
        sb.append("**Rationale** - why the claim was made, with the day count for the three duration-based reasons:\n\n");
        sb.append("| Rationale | Meaning |\n|-----------|---------|\n");
        sb.append("| `Library Unused` | Library never loaded at runtime (0 classes) - structural, not time-based |\n");
        sb.append("| `CVE Shielded` | CVE Shield actively mitigating at runtime - an active control, not time-based |\n");
        sb.append("| `CVE Not Used Nd` | not_affected - library loaded, but zero observed executions of the vulnerable path in N days of runtime monitoring, past the acceptance threshold |\n");
        sb.append("| `CVE Watching Nd` | in_triage - zero observed executions in N days so far, still short of the acceptance threshold - may still graduate to `CVE Not Used` |\n");
        sb.append("| `No Shield Coverage Nd` | in_triage, permanently - CVE Shield has no coverage for this CVE here (Shield column is `No`), so elapsed time is never evidence of anything and this can never graduate, no matter how large Nd gets |\n\n");
        sb.append("Rows are sorted CISA KEV-listed first, then by EPSS score, then by CVSS score, so the claims worth ")
          .append("a second look surface at the top - see the Key Findings above for which specific CVEs those are.\n\n");
        sb.append("**Protection Status** (shown per app below) - Assess is the module that produces the runtime ")
          .append("evidence every claim in this report rests on; ADR (formerly branded \"Protect\") is the classic ")
          .append("HTTP-rule-based RASP module. Neither is CVE Shield - CVE Shield is a separate product that defends ")
          .append("specific CVEs via a microsandbox rather than HTTP rules. Its own coverage is the per-row **Shield** ")
          .append("column above - a per-CVE, product-level fact (coverage existing anywhere means it's available ")
          .append("everywhere Shield is enabled), not an app- or environment-scoped one.\n");

        sb.append("\n---\n\n## Application Detail\n\n");

        List<String> order = java.util.Arrays.asList("CRITICAL", "HIGH", "MEDIUM", "LOW", "SOUND", "UNKNOWN");
        List<JsonObject> sortedResults = new ArrayList<>(appResults);
        sortedResults.sort(Comparator.comparingInt(r -> {
            int idx = order.indexOf(getString(r, "risk_level", "UNKNOWN"));
            return idx < 0 ? 99 : idx;
        }));

        for (JsonObject r : sortedResults) {
            String appName = getString(r, "application", "Unknown");
            AppEntry entry = entriesByName.get(appName);
            String riskLevel = getString(r, "risk_level", "UNKNOWN");

            sb.append("### ").append(appName).append("\n\n**Risk Level:** ").append(riskLevel).append("\n\n");
            if (entry != null) {
                sb.append("**Protection Status:** Assess (runtime evidence): ")
                  .append(formatEnvFlags(entry.assessEnabledDev, entry.assessEnabledQa, entry.assessEnabledProd))
                  .append(" · ADR (classic RASP, formerly \"Protect\" - not CVE Shield): ")
                  .append(formatEnvFlags(entry.adrEnabledDev, entry.adrEnabledQa, entry.adrEnabledProd))
                  .append("\n\n");
            }
            sb.append(getString(r, "application_description", "No description available.")).append("\n\n");
            sb.append("**Risk Rationale:** ").append(getString(r, "risk_rationale", "Unknown")).append("\n\n");
            sb.append("**Recommendation:** ").append(getString(r, "recommendation", "None")).append("\n\n");

            if (entry != null) {
                List<VexStatement> statements = new ArrayList<>(entry.statements);
                statements.sort((a, b) -> {
                    boolean aKev = Boolean.TRUE.equals(a.cisaKev), bKev = Boolean.TRUE.equals(b.cisaKev);
                    if (aKev != bKev) return aKev ? -1 : 1;
                    double aEpss = a.epssScore != null ? a.epssScore : -1;
                    double bEpss = b.epssScore != null ? b.epssScore : -1;
                    if (aEpss != bEpss) return Double.compare(bEpss, aEpss);
                    double aScore = a.score != null ? a.score : -1;
                    double bScore = b.score != null ? b.score : -1;
                    return Double.compare(bScore, aScore);
                });

                sb.append("| CVE | Library | Score | VEX | Shield | Rationale |\n|-----|---------|-------|-----|--------|-----------|\n");
                for (VexStatement s : statements) {
                    sb.append("| ").append(s.cveId).append(" | ").append(plainLibrary(s.purl))
                      .append(" | ").append(s.score != null ? s.score : "-").append(" | ")
                      .append("in_triage".equals(s.state) ? "IT" : "NA").append(" | ")
                      .append(shieldLabel(s.shieldAvailable)).append(" | ")
                      .append(rationaleWord(s)).append(" |\n");
                }
                sb.append("\n");
            }

            sb.append("---\n\n");
        }

        sb.append("## Appendix: Methodology\n\n");
        sb.append("VEX claims were generated by `VEXGenerator` from Contrast runtime library class-usage data and ")
          .append("per-environment CVE Shield status - see `vex --help` for the exact decision policy. This ")
          .append("advisor does not change any claim; it only assesses whether relying on each claim as generated is ")
          .append("reasonable given the CVE's severity and exploitability - it doesn't offer a distinct action per ")
          .append("claim, since the real options (verify reachability, upgrade the library) are the same regardless of ")
          .append("severity. See the Legend above for how the VEX/Rationale columns are derived, and the Key Findings ")
          .append("above for which specific CVEs are CISA KEV-listed or high-EPSS.\n\n");
        sb.append("- **sound**: the claim's justification (structural fact or active control, or a duration comfortably ")
          .append("past the threshold on a low-stakes CVE) supports relying on it as-is\n");
        sb.append("- **needs_review**: the claim rests on absence-of-observed-execution for a severe/exploitable CVE, or ")
          .append("is otherwise borderline - a human should confirm before treating it as resolved\n\n---\n\n");
        sb.append("*Report generated by Contrast VEX Advisor*\n*Powered by Contrast Security Runtime Observability*\n");

        return sb.toString();
    }

    /**
     * Library Unused/CVE Shielded are structural. CVE Not Used/CVE Watching are duration-based and genuinely
     * still accumulating toward (or past) the acceptance threshold. No Shield Coverage is also in_triage, but
     * for a different reason - Shield has zero coverage for this CVE, so it stays in_triage forever regardless
     * of daysObserved; using "CVE Watching Nd" for that case would make a 288-day-old in_triage claim look like
     * a bug rather than the intended "can never graduate" state.
     */
    private String rationaleWord(VexStatement s) {
        if ("code_not_reachable".equals(s.justification)) return "Library Unused";
        if ("protected_at_runtime".equals(s.justification)) return "CVE Shielded";
        if ("in_triage".equals(s.state) && Boolean.FALSE.equals(s.shieldAvailable)) {
            return "No Shield Coverage " + s.daysObserved + "d";
        }
        if ("in_triage".equals(s.state)) return "CVE Watching " + s.daysObserved + "d";
        return "CVE Not Used " + s.daysObserved + "d";
    }

    /** Whether CVE Shield has any coverage for this CVE at all (org-wide fact) - "-" means unknown. */
    private String shieldLabel(Boolean shieldAvailable) {
        if (shieldAvailable == null) return "-";
        return shieldAvailable ? "Yes" : "No";
    }

    /** Strips a purl down to "artifact@version" - drops the "pkg:maven/<group>/" prefix for a narrow column. */
    private String plainLibrary(String purl) {
        if (purl == null) return "unknown";
        int lastSlash = purl.lastIndexOf('/');
        return lastSlash >= 0 ? purl.substring(lastSlash + 1) : purl;
    }

    private String formatCveList(List<VexStatement> statements, int max) {
        List<String> distinctCves = new ArrayList<>(new java.util.LinkedHashSet<>(
            statements.stream().map(s -> s.cveId).collect(java.util.stream.Collectors.toList())));
        StringBuilder sb = new StringBuilder();
        int shown = Math.min(distinctCves.size(), max);
        for (int i = 0; i < shown; i++) {
            if (i > 0) sb.append(", ");
            sb.append(distinctCves.get(i));
        }
        if (distinctCves.size() > max) {
            sb.append(" (+").append(distinctCves.size() - max).append(" more)");
        }
        return sb.toString();
    }

}
