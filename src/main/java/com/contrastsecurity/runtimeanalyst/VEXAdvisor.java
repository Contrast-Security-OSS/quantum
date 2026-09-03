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
 * Review of a CycloneDX VEX document produced by VEXGenerator - not a second opinion on whether the CVE
 * exists (Contrast's runtime data already establishes that), but a sanity check on whether each
 * "not_affected"/"in_triage" CLAIM is well-supported given the CVE's severity/exploitability, or whether a
 * human should look at it before relying on it.
 *
 * WHICH claims need review is decided deterministically (see needsReview()), not by an AI call - every input
 * (severity, CISA KEV, EPSS, Assess/ADR enablement, CVE Shield coverage) is already a plain fact sitting on the
 * VEX itself, so classifying it per-statement over an AI round-trip added cost and multi-minute latency
 * without adding judgment, and made the same VEX produce a different flagged count from run to run on
 * identical input - a liability for something meant to be relied on. The one AI call per app is used only for
 * the narrative (application_description/risk_level/risk_rationale/recommendation), synthesizing what the
 * already-decided facts mean in prose.
 *
 * Usage:
 *   java -jar runtime-analyst.jar vex-advisor vex.json [-v] [-o report.md] [--json out.json] [--no-confirm]
 */
public class VEXAdvisor {

    /**
     * Which VEX statements are worth a human's attention before being relied on. Deterministic, not an AI call -
     * every input here (state/justification, severity, CISA KEV, EPSS, Assess/ADR enablement) is already a plain
     * fact sitting on the statement or its app, so classifying it 235 times over an AI round-trip added latency
     * and cost without adding judgment: it also made the same VEX produce a different flagged count from run to
     * run (21, then 61, then 125, all on identical input), which is a liability for something meant to be relied
     * on. The AI's role is now the app-level narrative only - synthesizing what these facts mean in prose, not
     * deciding what the facts are.
     */
    private boolean needsReview(VexStatement s, AppEntry entry) {
        if (s.justification != null) return false; // code_not_reachable / protected_at_runtime - structural, always sound
        if ("in_triage".equals(s.state) && s.daysObserved < s.acceptAfterDays) return false; // genuinely still early
        boolean assessBlind = isAssessBlind(s, entry);
        boolean highSeverity = s.severity != null
            && ("critical".equalsIgnoreCase(s.severity) || "high".equalsIgnoreCase(s.severity));
        boolean kev = Boolean.TRUE.equals(s.cisaKev);
        boolean highEpss = s.epssScore != null && s.epssScore >= 0.5;
        return assessBlind || highSeverity || kev || highEpss;
    }

    /**
     * Whether Assess had no runtime data anywhere in the environment(s) this claim's evidence spans - a claim
     * scoped to ALL (dev/qa/prod combined, the default) is only "blind" if every one of the three lacks data;
     * one --env-scoped claim is blind only if that specific environment lacks data.
     */
    private boolean isAssessBlind(VexStatement s, AppEntry entry) {
        String scope = s.envFilter != null ? s.envFilter : "ALL";
        if ("DEVELOPMENT".equals(scope)) return !"true".equals(entry.assessEnabledDev);
        if ("QA".equals(scope)) return !"true".equals(entry.assessEnabledQa);
        if ("PRODUCTION".equals(scope)) return !"true".equals(entry.assessEnabledProd);
        return !"true".equals(entry.assessEnabledDev)
            && !"true".equals(entry.assessEnabledQa)
            && !"true".equals(entry.assessEnabledProd);
    }

    private static final String ANALYSIS_PROMPT =
        "You are an application security analyst writing a short narrative summary of a VEX (Vulnerability " +
        "Exploitability eXchange) claim set that a tool generated automatically from Contrast Security runtime " +
        "observability data, for ONE application. Which specific claims need review has ALREADY been decided " +
        "deterministically (rule: duration-based claims on a CRITICAL/HIGH severity, CISA KEV-listed, or " +
        "high-EPSS CVE, or where Assess itself had no runtime data to back the claim) - you're given that list, " +
        "not asked to re-derive it. Your job is to turn the given facts into a clear, specific narrative: what's " +
        "in this VEX, what's actually worth a second look and why, and what to do about it.\n\n" +
        "Return JSON:\n" +
        "```json\n" +
        "{\n" +
        "  \"application_description\": \"2-3 sentence overview of this application's VEX posture - how many \"\n" +
        "    + \"claims, how sound they generally look\",\n" +
        "  \"risk_level\": \"CRITICAL|HIGH|MEDIUM|LOW|SOUND\",\n" +
        "  \"risk_rationale\": \"Why this level, naming the specific flagged CVEs/libraries that drove it\",\n" +
        "  \"recommendation\": \"Specific next action - which CVEs need a human look first, and why those\"\n" +
        "}\n" +
        "```\n";

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
        String envFilter; // "ALL", "DEVELOPMENT", "QA", or "PRODUCTION" - which env(s) this claim's evidence spans
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
        double estimatedCost = client.estimateCost(entries.size(), 1000, 2500);
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
            }
            results.add(result);
            String risk = getString(result, "risk_level", "UNKNOWN");
            System.out.println("  [" + risk + "] " + entry.name + " (" + entry.statements.size() + " statement(s))");
        }

        int written = writeAssessmentsToVex(vexPath, entries);
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
            s.envFilter = props.getOrDefault("contrast:envFilter", "ALL");

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

        List<VexStatement> flagged = new ArrayList<>();
        int sound = 0;
        for (VexStatement s : entry.statements) {
            if (needsReview(s, entry)) flagged.add(s);
            else sound++;
        }

        sb.append("Total claims: ").append(entry.statements.size())
          .append(" (sound: ").append(sound).append(", flagged for review: ").append(flagged.size()).append(")\n\n");

        if (flagged.isEmpty()) {
            sb.append("No claims were flagged - every claim is either structural (library unused / CVE Shield ")
              .append("actively mitigating) or duration-based on a low/medium-severity, non-KEV, low-EPSS CVE ")
              .append("with real Assess data backing it.\n");
        } else {
            sb.append("Claims flagged for review (already decided deterministically - explain what's actually ")
              .append("going on with these in your narrative, don't just restate the reason tag):\n");
            for (VexStatement s : flagged) {
                sb.append("\n- ").append(s.cveId).append(" on ").append(s.purl != null ? s.purl : "unknown library")
                  .append(" (").append(s.severity != null ? s.severity : "unknown severity")
                  .append(s.score != null ? ", score " + s.score : "").append(")");
                List<String> tags = new ArrayList<>();
                if (isAssessBlind(s, entry)) tags.add("Assess has no data here");
                if (Boolean.TRUE.equals(s.cisaKev)) tags.add("CISA KEV");
                if (s.epssScore != null && s.epssScore >= 0.5) tags.add("EPSS " + s.epssScore);
                if (!tags.isEmpty()) sb.append(" [").append(String.join(", ", tags)).append("]");
                sb.append(" - ").append(s.state).append(", ").append(s.daysObserved).append(" days observed");
                if (s.recommendation != null) sb.append(". Recommendation on record: ").append(s.recommendation);
            }
            sb.append("\n");
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
        return fallback;
    }

    /** Short, deterministic explanation of why a statement was (or wasn't) flagged - see needsReview(). */
    private String reviewRationale(VexStatement s, AppEntry entry, boolean flagged) {
        if (!flagged) return "sound";
        List<String> reasons = new ArrayList<>();
        if (isAssessBlind(s, entry)) reasons.add("Assess has no runtime data in the environment(s) this claim covers");
        if (s.severity != null && ("critical".equalsIgnoreCase(s.severity) || "high".equalsIgnoreCase(s.severity))) {
            reasons.add(s.severity.toUpperCase() + " severity");
        }
        if (Boolean.TRUE.equals(s.cisaKev)) reasons.add("CISA KEV-listed");
        if (s.epssScore != null && s.epssScore >= 0.5) reasons.add("EPSS " + s.epssScore);
        return "Flagged: " + String.join(", ", reasons) + " - duration-based claim, not a structural guarantee.";
    }

    private int writeAssessmentsToVex(String vexPath, List<AppEntry> entries) throws IOException {
        Map<String, AppEntry> entriesByName = new LinkedHashMap<>();
        for (AppEntry e : entries) entriesByName.put(e.name, e);

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
            AppEntry entry = entriesByName.get(appName);
            if (entry == null || cveId == null) continue;
            VexStatement s = entry.statements.stream().filter(st -> cveId.equals(st.cveId)).findFirst().orElse(null);
            if (s == null) continue;

            boolean flagged = needsReview(s, entry);
            JsonArray oldProperties = v.has("properties") ? v.getAsJsonArray("properties") : new JsonArray();
            JsonArray properties = new JsonArray();
            for (JsonElement propEl : oldProperties) {
                String name = getString(propEl.getAsJsonObject(), "name", "");
                if (!"contrast:vexAdvisorAssessment".equals(name) && !"contrast:vexAdvisorRationale".equals(name)) {
                    properties.add(propEl);
                }
            }
            properties.add(propertyJson("contrast:vexAdvisorAssessment", flagged ? "needs_review" : "sound"));
            properties.add(propertyJson("contrast:vexAdvisorRationale", reviewRationale(s, entry, flagged)));
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
            for (VexStatement s : entry.statements) {
                if (needsReview(s, entry)) {
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
        sb.append("**Rationale** - why the claim was made, with the day count for the two duration-based reasons:\n\n");
        sb.append("| Rationale | Meaning |\n|-----------|---------|\n");
        sb.append("| `Library Unused` | Library never loaded at runtime (0 classes) - structural, not time-based |\n");
        sb.append("| `CVE Shielded` | CVE Shield actively mitigating at runtime - an active control, not time-based |\n");
        sb.append("| `CVE Not Used Nd` | not_affected - library loaded, but zero observed executions of the vulnerable path in N days of runtime monitoring, past the acceptance threshold |\n");
        sb.append("| `CVE Watching Nd` | in_triage - zero observed executions in N days so far, still short of the acceptance threshold - may still graduate to `CVE Not Used` |\n\n");
        sb.append("CVEs with no CVE Shield coverage at all never appear in this table - VEXGenerator excludes ")
          .append("them entirely rather than claiming `not_affected` or `in_triage` without a detector ever having ")
          .append("watched (see its console output for the excluded count).\n\n");
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
     * still accumulating toward (or past) the acceptance threshold. CVEs with no CVE Shield coverage at all
     * never reach this report - VEXGenerator excludes them entirely (see its decision-rule 3), since neither
     * not_affected nor in_triage is a claim it can support without a detector ever having watched.
     */
    private String rationaleWord(VexStatement s) {
        if ("code_not_reachable".equals(s.justification)) return "Library Unused";
        if ("protected_at_runtime".equals(s.justification)) return "CVE Shielded";
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
