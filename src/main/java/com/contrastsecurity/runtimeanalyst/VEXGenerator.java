package com.contrastsecurity.runtimeanalyst;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.cyclonedx.model.vulnerability.Vulnerability.Affect;
import org.cyclonedx.model.vulnerability.Vulnerability.Analysis;
import org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification;
import org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity;
import org.cyclonedx.model.vulnerability.Vulnerability.Source;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Generates a CycloneDX VEX (Vulnerability Exploitability eXchange) document for an
 * application's library vulnerabilities, using Contrast's runtime library-usage and
 * CVE Shield/Protect observation data to justify "not affected"/"in triage" claims
 * rather than fabricating them.
 *
 * Three data sources, all under the same contrast.properties credentials:
 *   - GET  /api/v4/organizations/{org}/applications                          app first/last seen
 *   - POST /Contrast/api/ng/{org}/libraries/filter                           per-library CVEs + runtime class-usage
 *   - GET  /api/ns-ui/v1/organizations/{org}/applications/{id}/cves/issues   per-CVE per-environment Shield/Protect status
 *
 * Decision rules (see CLAUDE.md discussion - these are policy, not spec):
 *   1. classes_used == 0 for the app+library -> not_affected / code_not_reachable, unconditional.
 *   2. classes_used > 0, CVE's env status is PROTECTING/BLOCKED -> not_affected / protected_at_runtime.
 *   3. classes_used > 0, CVE's env status is EXPOSED/EXPLOITED (or unrecognized) -> no VEX entry;
 *      never suppress a vulnerability we can't positively account for.
 *   4. classes_used > 0, CVE's env status is NOT_SEEN (or missing) in every environment observed:
 *        - days observed >= acceptAfterDays -> not_affected (no justification), detail explains the
 *          day count and threshold as an operational risk-acceptance, not a structural guarantee.
 *        - days observed <  acceptAfterDays -> in_triage, detail explains the day count so far.
 *
 * Usage:
 *   java -jar runtime-analyst.jar vex --app "MyApp"
 *   java -jar runtime-analyst.jar vex --list
 *   java -jar runtime-analyst.jar vex --app "MyApp" --vex-accept-after-days 30 -o vex.json
 */
public class VEXGenerator {

    private static final List<String> PROTECTED_STATUSES = List.of("PROTECTING", "BLOCKED");
    private static final List<String> NOT_SEEN_STATUSES = List.of("NOT_SEEN");

    private String baseUrl; // e.g. https://host/api/ns-ui/v1
    private String host;    // e.g. https://host
    private String orgId;
    private String authHeader;
    private String apiKey;
    private int acceptAfterDays = 30;
    private String envFilter; // DEVELOPMENT, QA, or PRODUCTION - null means consider all three

    private final Gson gson = new Gson();
    private final CloseableHttpClient httpClient = HttpClients.createDefault();

    public VEXGenerator(String configFile) throws IOException {
        loadConfig(configFile);
    }

    public void setAcceptAfterDays(int days) {
        this.acceptAfterDays = days;
    }

    public void setEnvFilter(String env) {
        this.envFilter = env;
    }

    private void loadConfig(String configFile) throws IOException {
        Properties props = new Properties();
        File f = configFile != null ? new File(configFile) : new File("contrast.properties");
        if (!f.exists()) {
            throw new IOException("Config file not found: " + f.getPath());
        }
        try (InputStream is = new FileInputStream(f)) {
            props.load(is);
        }
        baseUrl = props.getProperty("contrast.url");
        orgId = props.getProperty("contrast.org_id");
        authHeader = props.getProperty("contrast.auth_header");
        apiKey = props.getProperty("contrast.api_key");
        if (baseUrl == null || orgId == null || authHeader == null || apiKey == null) {
            throw new IOException("contrast.properties is missing one of: contrast.url, contrast.org_id, contrast.auth_header, contrast.api_key");
        }
        host = baseUrl.replaceAll("/api/.*", "");
    }

    public static void main(String[] args) {
        String appFilter = null;
        String envFilter = null;
        String outputFile = "vex.json";
        String configFile = null;
        boolean listOnly = false;
        boolean runAnalysis = false;
        int acceptAfterDays = 30;

        for (int i = 0; i < args.length; i++) {
            if ("--app".equals(args[i]) && i + 1 < args.length) {
                appFilter = args[++i];
            } else if ("--env".equals(args[i]) && i + 1 < args.length) {
                envFilter = args[++i].toUpperCase();
            } else if ("--list".equals(args[i])) {
                listOnly = true;
            } else if ("--analyze".equals(args[i])) {
                runAnalysis = true;
            } else if ("-o".equals(args[i]) && i + 1 < args.length) {
                outputFile = args[++i];
            } else if ("-c".equals(args[i]) && i + 1 < args.length) {
                configFile = args[++i];
            } else if ("--vex-accept-after-days".equals(args[i]) && i + 1 < args.length) {
                acceptAfterDays = Integer.parseInt(args[++i]);
            } else if ("--help".equals(args[i]) || "-h".equals(args[i])) {
                printUsage();
                return;
            }
        }

        try {
            VEXGenerator generator = new VEXGenerator(configFile);
            generator.setAcceptAfterDays(acceptAfterDays);
            generator.setEnvFilter(envFilter);

            List<AppInfo> apps = generator.fetchApplications();

            if (listOnly) {
                System.out.println("\nAvailable applications:");
                for (AppInfo app : apps) {
                    System.out.println("  " + app.name + "  (" + app.id + ")");
                }
                return;
            }

            List<AppInfo> targets = new ArrayList<>();
            if (appFilter == null) {
                targets.addAll(apps);
            } else {
                for (AppInfo app : apps) {
                    if (appFilter.equals(app.id) || appFilter.equalsIgnoreCase(app.name)) {
                        targets.add(app);
                    }
                }
                if (targets.isEmpty()) {
                    System.err.println("No application matched \"" + appFilter + "\". Use --list to see available applications.");
                    System.exit(1);
                }
            }

            Bom bom = generator.generateVEX(targets);

            if (appFilter != null && "vex.json".equals(outputFile)) {
                String safe = targets.get(0).name.replaceAll("[^a-zA-Z0-9-_]", "_");
                outputFile = "vex-" + safe + ".json";
            }

            generator.writeVEX(bom, outputFile);

            if (runAnalysis) {
                generator.runVEXAdvisor(outputFile);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("\nVEX Generator - Create a CycloneDX VEX from Contrast library-usage and CVE Shield data");
        System.out.println("\nUsage:");
        System.out.println("  java -jar runtime-analyst.jar vex --app <id|name>                Generate a VEX for one application");
        System.out.println("  java -jar runtime-analyst.jar vex                                Generate a VEX covering all applications");
        System.out.println("  java -jar runtime-analyst.jar vex --list                         List available applications with IDs");
        System.out.println("  java -jar runtime-analyst.jar vex --env <tier>                    Scope claims to one environment (DEVELOPMENT, QA, PRODUCTION) instead of this app's dev/qa/prod combined");
        System.out.println("  java -jar runtime-analyst.jar vex --vex-accept-after-days <n>     Days of no-observed-execution before treating a CVE as not_affected (default 30)");
        System.out.println("  java -jar runtime-analyst.jar vex --analyze                       Run VEX Advisor AI review after VEX generation");
        System.out.println("  java -jar runtime-analyst.jar vex -o <file.json>                  Specify output filename");
        System.out.println("  java -jar runtime-analyst.jar vex -c <config.properties>          Use custom config file");
    }

    /**
     * Run the VEX Advisor to sanity-check the generated claims, in-process (no Python required).
     */
    private void runVEXAdvisor(String vexFile) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Running VEX Advisor Review...");
        System.out.println("=".repeat(60));

        String advisorOutput = vexFile.replace(".json", "-advisor.md");
        VEXAdvisor.main(new String[]{vexFile, "--no-confirm", "-o", advisorOutput});
        System.out.println("\nVEX Advisor report written to: " + advisorOutput);
    }

    // ---- Data model ----

    static class AppInfo {
        String id;
        String name;
        long firstSeenTime;
        long lastSeenTime;
    }

    private static class CveIssue {
        String cveId;
        String libraryVersion;
        String dev;
        String qa;
        String prod;
    }

    // ---- Applications ----

    public List<AppInfo> fetchApplications() throws IOException {
        String url = host + "/api/v4/organizations/" + orgId + "/applications?size=500";
        HttpGet get = new HttpGet(url);
        get.setHeader("Authorization", authHeader);
        get.setHeader("API-Key", apiKey);
        get.setHeader("Accept", "application/json");

        HttpResponse response = httpClient.execute(get);
        int statusCode = response.getStatusLine().getStatusCode();
        String body = EntityUtils.toString(response.getEntity());
        if (statusCode != 200) {
            throw new IOException("Applications API returned status " + statusCode + ": " + body);
        }

        JsonObject json = gson.fromJson(body, JsonObject.class);
        List<AppInfo> apps = new ArrayList<>();
        for (JsonElement el : json.getAsJsonArray("content")) {
            JsonObject o = el.getAsJsonObject();
            AppInfo app = new AppInfo();
            app.id = getStringOrNull(o, "id");
            app.name = getStringOrNull(o, "name");
            app.firstSeenTime = parseIsoOrEpoch(o, "firstSeenTime");
            app.lastSeenTime = parseIsoOrEpoch(o, "lastSeenTime");
            apps.add(app);
        }
        return apps;
    }

    private long parseIsoOrEpoch(JsonObject o, String field) {
        if (!o.has(field) || o.get(field).isJsonNull()) {
            return 0L;
        }
        JsonElement el = o.get(field);
        if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isNumber()) {
            return el.getAsLong();
        }
        try {
            return java.time.Instant.parse(el.getAsString()).toEpochMilli();
        } catch (Exception e) {
            return 0L;
        }
    }

    // ---- CVE Shield / Protect status, per app ----

    private Map<String, CveIssue> fetchCveIssues(String appId) throws IOException {
        Map<String, CveIssue> issues = new HashMap<>();
        String cursor = "";
        boolean hasMore = true;

        while (hasMore) {
            String url = baseUrl + "/organizations/" + orgId + "/applications/" + appId
                + "/cves/issues?size=100&sort=cvssScore,desc&pagination=cursor&cursor=" + cursor;
            HttpGet get = new HttpGet(url);
            get.setHeader("Authorization", authHeader);
            get.setHeader("API-Key", apiKey);
            get.setHeader("Accept", "application/json");

            HttpResponse response = httpClient.execute(get);
            int statusCode = response.getStatusLine().getStatusCode();
            String body = EntityUtils.toString(response.getEntity());
            if (statusCode != 200) {
                throw new IOException("CVE issues API returned status " + statusCode + ": " + body);
            }

            JsonObject json = gson.fromJson(body, JsonObject.class);
            for (JsonElement el : json.getAsJsonArray("items")) {
                JsonObject o = el.getAsJsonObject();
                CveIssue issue = new CveIssue();
                issue.cveId = getStringOrNull(o, "cveId");
                issue.libraryVersion = getStringOrNull(o, "libraryVersion");
                issue.dev = getStringOrNull(o, "dev");
                issue.qa = getStringOrNull(o, "qa");
                issue.prod = getStringOrNull(o, "prod");
                issues.put(issue.cveId + "|" + issue.libraryVersion, issue);
            }

            hasMore = json.has("hasMore") && json.get("hasMore").getAsBoolean();
            cursor = json.has("cursor") && !json.get("cursor").isJsonNull() ? json.get("cursor").getAsString() : "";
            if (cursor.isEmpty()) {
                hasMore = false;
            }
        }
        return issues;
    }

    // ---- Libraries: CVEs + runtime class usage, per app ----

    private JsonArray fetchLibraries(String appId) throws IOException {
        JsonArray allLibraries = new JsonArray();
        int offset = 0;
        int limit = 50;
        int total = Integer.MAX_VALUE;

        while (offset < total) {
            String url = host + "/Contrast/api/ng/" + orgId
                + "/libraries/filter?expand=skip_links,apps,quickFilters,vulns,status,usage_counts"
                + "&offset=" + offset + "&limit=" + limit + "&sort=score";
            HttpPost post = new HttpPost(url);
            post.setHeader("Authorization", authHeader);
            post.setHeader("API-Key", apiKey);
            post.setHeader("Content-Type", "application/json");
            post.setHeader("Accept", "application/json");

            JsonObject requestBody = new JsonObject();
            requestBody.addProperty("q", "");
            requestBody.addProperty("quickFilter", "VULNERABLE");
            JsonArray appsArray = new JsonArray();
            appsArray.add(appId);
            requestBody.add("apps", appsArray);
            requestBody.add("servers", new JsonArray());
            requestBody.add("environments", new JsonArray());
            requestBody.add("grades", new JsonArray());
            requestBody.add("languages", new JsonArray());
            requestBody.add("licenses", new JsonArray());
            requestBody.add("status", new JsonArray());
            requestBody.add("severities", new JsonArray());
            requestBody.add("tags", new JsonArray());
            requestBody.addProperty("includeUnused", true);
            requestBody.addProperty("includeUsed", true);
            post.setEntity(new StringEntity(gson.toJson(requestBody)));

            HttpResponse response = httpClient.execute(post);
            int statusCode = response.getStatusLine().getStatusCode();
            String body = EntityUtils.toString(response.getEntity());
            if (statusCode != 200) {
                throw new IOException("Libraries API returned status " + statusCode + ": " + body);
            }

            JsonObject json = gson.fromJson(body, JsonObject.class);
            JsonArray page = json.getAsJsonArray("libraries");
            for (JsonElement el : page) {
                allLibraries.add(el);
            }
            total = json.has("count") ? json.get("count").getAsInt() : page.size();
            offset += limit;
            if (page.size() == 0) {
                break;
            }
        }
        return allLibraries;
    }

    // ---- VEX generation ----

    public Bom generateVEX(List<AppInfo> apps) throws IOException {
        Bom bom = new Bom();
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (AppInfo app : apps) {
            System.out.println("\nProcessing " + app.name + " (" + app.id + ")...");

            Map<String, CveIssue> cveIssues = fetchCveIssues(app.id);
            JsonArray libraries = fetchLibraries(app.id);
            System.out.println("  " + libraries.size() + " vulnerable libraries, " + cveIssues.size() + " CVE issue records");

            long daysObserved = (app.lastSeenTime > app.firstSeenTime)
                ? (app.lastSeenTime - app.firstSeenTime) / (1000L * 60 * 60 * 24)
                : 0L;

            for (JsonElement libEl : libraries) {
                JsonObject lib = libEl.getAsJsonObject();
                String group = getStringOrNull(lib, "group");
                String fileName = getStringOrNull(lib, "file_name");
                String fileVersion = getStringOrNull(lib, "file_version");
                String hash = getStringOrNull(lib, "hash");
                long classesUsed = lib.has("classes_used") ? lib.get("classes_used").getAsLong() : 0L;
                long classCount = lib.has("class_count") ? lib.get("class_count").getAsLong() : 0L;

                if (!lib.has("vulns")) {
                    continue;
                }

                for (JsonElement vulnEl : lib.getAsJsonArray("vulns")) {
                    JsonObject vuln = vulnEl.getAsJsonObject();
                    String cveId = getStringOrNull(vuln, "name");
                    if (cveId == null) {
                        continue;
                    }

                    Vulnerability v = buildVulnerability(
                        app, group, fileName, fileVersion, hash, classesUsed, classCount,
                        cveId, vuln, cveIssues.get(cveId + "|" + fileVersion), daysObserved);

                    if (v != null) {
                        vulnerabilities.add(v);
                    }
                }
            }
        }

        System.out.println("\nGenerated " + vulnerabilities.size() + " VEX statements.");
        bom.setVulnerabilities(vulnerabilities);

        if (apps.size() == 1) {
            Component appComponent = new Component();
            appComponent.setType(Component.Type.APPLICATION);
            appComponent.setName(apps.get(0).name);
            appComponent.setBomRef(sanitizeBomRef(apps.get(0).id));
            Metadata metadata = new Metadata();
            metadata.setComponent(appComponent);
            bom.setMetadata(metadata);
        }

        return bom;
    }

    /** Returns null when the CVE shouldn't get a VEX statement at all (exposed/exploited/unrecognized status). */
    private Vulnerability buildVulnerability(AppInfo app, String group, String fileName, String fileVersion,
            String hash, long classesUsed, long classCount, String cveId, JsonObject vuln,
            CveIssue issue, long daysObserved) {

        Vulnerability v = new Vulnerability();
        v.setBomRef(sanitizeBomRef(app.id + "-" + cveId + "-" + hash));
        v.setId(cveId);

        Source source = new Source();
        source.setName("NVD");
        source.setUrl("https://nvd.nist.gov/vuln/detail/" + cveId);
        v.setSource(source);

        Rating rating = new Rating();
        rating.setSource(source);
        if (vuln.has("cvss_3_severity_value")) {
            rating.setScore(vuln.get("cvss_3_severity_value").getAsDouble());
        }
        String severity = getStringOrNull(vuln, "cvss_3_severity_code");
        if (severity != null) {
            rating.setSeverity(Severity.fromString(severity.toLowerCase()));
        }
        rating.setMethod(Method.CVSSV31);
        String vector = getStringOrNull(vuln, "cvss_3_vector");
        if (vector != null) {
            rating.setVector(vector);
        }
        List<Rating> ratings = new ArrayList<>();
        ratings.add(rating);
        v.setRatings(ratings);

        String purl = "pkg:maven/" + (group != null ? group : "unknown") + "/" + artifactNameFrom(fileName) + "@" + fileVersion;
        Affect affect = new Affect();
        affect.setRef(purl);
        List<Affect> affects = new ArrayList<>();
        affects.add(affect);
        v.setAffects(affects);

        Analysis analysis = new Analysis();
        String detail;

        if (classesUsed == 0) {
            analysis.setState(State.NOT_AFFECTED);
            analysis.setJustification(Justification.CODE_NOT_REACHABLE);
            detail = "Library not observed executing at runtime in " + app.name + " - 0 of " + classCount
                + " classes loaded (Contrast runtime library-usage data).";
        } else if (issue != null && isProtected(issue)) {
            analysis.setState(State.NOT_AFFECTED);
            analysis.setJustification(Justification.PROTECTED_AT_RUNTIME);
            detail = "CVE Shield/Protect is actively mitigating this vulnerability at runtime in " + app.name
                + " (" + envScopeLabel() + ").";
        } else if (issue != null && isNotSeen(issue)) {
            detail = "Library loaded (" + classesUsed + " of " + classCount + " classes used) but this CVE's "
                + "vulnerable code path has not been observed executing in " + app.name + " (" + envScopeLabel()
                + ") in " + daysObserved + " days of runtime monitoring";
            if (daysObserved >= acceptAfterDays) {
                analysis.setState(State.NOT_AFFECTED);
                detail += " (policy threshold: " + acceptAfterDays + " days). Operational risk acceptance based on "
                    + "runtime observation, not a structural non-reachability guarantee.";
            } else {
                analysis.setState(State.IN_TRIAGE);
                detail += " (below the " + acceptAfterDays + "-day acceptance threshold).";
            }
        } else if (issue == null) {
            // Library confirmed used, but no matching per-CVE environment record found at all -
            // treat the same as "not seen" using the same duration logic, but flag the missing join.
            detail = "Library loaded (" + classesUsed + " of " + classCount + " classes used); no per-environment "
                + "CVE Shield/exposure record found for this CVE+version in " + app.name + ". Not observed "
                + "executing in " + daysObserved + " days of runtime monitoring for this application";
            if (daysObserved >= acceptAfterDays) {
                analysis.setState(State.NOT_AFFECTED);
                detail += " (policy threshold: " + acceptAfterDays + " days). Operational risk acceptance based on "
                    + "runtime observation, not a structural non-reachability guarantee.";
            } else {
                analysis.setState(State.IN_TRIAGE);
                detail += " (below the " + acceptAfterDays + "-day acceptance threshold).";
            }
        } else {
            // EXPOSED / EXPLOITED / any unrecognized status - never suppress.
            return null;
        }

        analysis.setDetail(detail);
        v.setAnalysis(analysis);

        List<Property> properties = new ArrayList<>();
        properties.add(property("contrast:appId", app.id));
        properties.add(property("contrast:appName", app.name));
        properties.add(property("contrast:classesUsed", String.valueOf(classesUsed)));
        properties.add(property("contrast:classCount", String.valueOf(classCount)));
        properties.add(property("contrast:daysObserved", String.valueOf(daysObserved)));
        properties.add(property("contrast:acceptAfterDays", String.valueOf(acceptAfterDays)));
        properties.add(property("contrast:envFilter", envFilter != null ? envFilter : "ALL"));
        if (issue != null) {
            properties.add(property("contrast:devStatus", issue.dev));
            properties.add(property("contrast:qaStatus", issue.qa));
            properties.add(property("contrast:prodStatus", issue.prod));
        }
        v.setProperties(properties);

        return v;
    }

    /**
     * With no --env filter, a claim considers all three of the app's own environments (dev/qa/prod).
     * With --env, it's scoped to just that one - e.g. --env PRODUCTION means "protected in production",
     * not "protected somewhere, possibly only in dev".
     */
    private List<String> statusesToConsider(CveIssue issue) {
        if (envFilter == null) {
            return java.util.Arrays.asList(issue.dev, issue.qa, issue.prod);
        }
        switch (envFilter) {
            case "DEVELOPMENT": return java.util.Arrays.asList(issue.dev);
            case "QA": return java.util.Arrays.asList(issue.qa);
            case "PRODUCTION": return java.util.Arrays.asList(issue.prod);
            default: return java.util.Arrays.asList(issue.dev, issue.qa, issue.prod);
        }
    }

    private String envScopeLabel() {
        return envFilter != null ? envFilter.toLowerCase() : "across its own dev/qa/prod environments";
    }

    private boolean isProtected(CveIssue issue) {
        for (String status : statusesToConsider(issue)) {
            if (isProtectedStatus(status)) return true;
        }
        return false;
    }

    private boolean isProtectedStatus(String status) {
        return status != null && PROTECTED_STATUSES.contains(status);
    }

    private boolean isNotSeen(CveIssue issue) {
        for (String status : statusesToConsider(issue)) {
            if (!isNotSeenOrNull(status)) return false;
        }
        return true;
    }

    private boolean isNotSeenOrNull(String status) {
        return status == null || NOT_SEEN_STATUSES.contains(status);
    }

    private String artifactNameFrom(String fileName) {
        if (fileName == null) {
            return "unknown";
        }
        // e.g. "spring-web-4.3.9.release.jar" -> "spring-web"; best-effort, not exact for all naming schemes.
        String withoutExt = fileName.replaceAll("\\.jar$", "");
        return withoutExt.replaceAll("-\\d.*$", "");
    }

    private Property property(String name, String value) {
        Property p = new Property();
        p.setName(name);
        p.setValue(value != null ? value : "");
        return p;
    }

    private String sanitizeBomRef(String input) {
        return input.toLowerCase()
            .replaceAll("[^a-z0-9-]", "-")
            .replaceAll("-+", "-")
            .replaceAll("^-|-$", "");
    }

    private String getStringOrNull(JsonObject obj, String field) {
        return obj.has(field) && !obj.get(field).isJsonNull() ? obj.get(field).getAsString() : null;
    }

    public void writeVEX(Bom bom, String filename) throws Exception {
        System.out.println("\nWriting VEX to " + filename);
        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
        String json = generator.toJsonString();
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(json);
        }
        System.out.println("  Done!");
    }
}
