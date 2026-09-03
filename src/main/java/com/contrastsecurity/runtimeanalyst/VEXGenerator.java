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
import org.cyclonedx.model.vulnerability.Vulnerability.Advisory;
import org.cyclonedx.model.vulnerability.Vulnerability.Affect;
import org.cyclonedx.model.vulnerability.Vulnerability.Analysis;
import org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification;
import org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response;
import org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method;
import org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity;
import org.cyclonedx.model.vulnerability.Vulnerability.Source;
import org.cyclonedx.model.vulnerability.Vulnerability.Version.Status;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Generates a CycloneDX VEX (Vulnerability Exploitability eXchange) document for an
 * application's library vulnerabilities, using Contrast's runtime library-usage and
 * CVE Shield observation data to justify "not affected"/"in triage" claims
 * rather than fabricating them.
 *
 * Five data sources, all under the same contrast.properties credentials:
 *   - GET  /api/v4/organizations/{org}/applications                          app first/last seen
 *   - POST /Contrast/api/ng/{org}/libraries/filter                           per-library CVEs + runtime class-usage
 *   - GET  /api/ns-ui/v1/organizations/{org}/applications/{id}/cves/issues   per-CVE per-environment CVE Shield status
 *   - GET  /Contrast/api/ng/{org}/applications/{id}/servers                  per-server Assess/ADR module enablement
 *   - GET  /api/ns-ui/v1/organizations/{org}/cves                            org-wide per-CVE Shield coverage (cveShieldExists)
 *
 * Decision rules (see CLAUDE.md discussion - these are policy, not spec):
 *   1. classes_used == 0 for the app+library -> not_affected / code_not_reachable, unconditional.
 *   2. classes_used > 0, CVE's env status is PROTECTING/BLOCKED -> not_affected / protected_at_runtime.
 *   3. classes_used > 0, CVE Shield has no coverage for this CVE at all (org-wide cveShieldExists is false -
 *      see shieldAvailability()) -> no VEX entry. Coverage is a per-CVE, product-level fact, not an
 *      app/environment-scoped one - if Shield covers a CVE anywhere, it covers it everywhere Shield/ADR is
 *      enabled. Without it, "not observed executing" isn't evidence of anything (there was never a detector
 *      watching), so neither not_affected nor in_triage is a claim this tool can support - in_triage would be
 *      just as wrong, since it implies evidence is accumulating toward a future resolution that nothing here
 *      could ever produce. This is the same "can't positively account for it" bucket as rule 5 below, just a
 *      different root cause (no detection capability, vs. confirmed exploitation) - excluded CVEs are counted
 *      in the run's own console output, not silently dropped.
 *   4. classes_used > 0, CVE's env status is NOT_SEEN (or missing) in every environment observed - Shield has
 *      coverage here (rule 3 didn't apply) and simply hasn't fired, so elapsed time is genuine evidence:
 *        - days observed >= acceptAfterDays -> not_affected (no justification), detail explains the
 *          day count and threshold as an operational risk-acceptance, not a structural guarantee.
 *        - days observed <  acceptAfterDays -> in_triage, detail explains the day count so far.
 *   5. classes_used > 0, CVE's env status is EXPOSED/EXPLOITED (or unrecognized) -> no VEX entry;
 *      never suppress a vulnerability we can't positively account for.
 *
 * Not factored into the decision rules above (deliberately - see ModuleStatus): whether Assess/ADR are
 * even enabled per environment. A "not seen" claim scoped to an environment where Assess itself isn't running
 * has no runtime evidence behind it at all, but rather than silently changing the claim, that fact is reported
 * as its own contrast:assessEnabled and contrast:adrEnabled property (per env) so a human (or the VEX
 * Advisor) can weigh it. ADR (formerly branded "Protect") is the classic HTTP-rule-based RASP module (the
 * API's `defend` flag) - a separate product from CVE Shield, which defends specific CVEs via a microsandbox.
 *
 * Usage:
 *   java -jar runtime-analyst.jar vex --app "MyApp"
 *   java -jar runtime-analyst.jar vex --list
 *   java -jar runtime-analyst.jar vex --app "MyApp" --vex-accept-after-days 30 -o vex.json
 */
public class VEXGenerator {

    private static final List<String> PROTECTED_STATUSES = List.of("PROTECTING", "BLOCKED");
    // NO_SHIELD is a real per-app-per-environment status value (confirmed by scanning every app in this org -
    // not documented alongside NOT_SEEN/PROTECTING/BLOCKED/etc). It belongs in the same duration-based branch
    // as NOT_SEEN below (absence-of-execution is still the applicable reasoning for reaching that branch at
    // all) - whether Shield actually has coverage for the CVE is a separate question, decided by the org-wide
    // cveShieldExists fact instead (see shieldAvailability()), not by this per-app status.
    private static final List<String> NOT_SEEN_STATUSES = List.of("NOT_SEEN", "NO_SHIELD");

    private String baseUrl; // e.g. https://host/api/ns-ui/v1
    private String host;    // e.g. https://host
    private String orgId;
    private String authHeader;
    private String apiKey;
    private int acceptAfterDays = 30;
    private String envFilter; // DEVELOPMENT, QA, or PRODUCTION - null means consider all three

    // Counts of CVEs deliberately excluded from the VEX (no statement generated) because this tool can't
    // positively account for them - tracked so the exclusion is visible in the run's own output, not silent.
    private int excludedNoShieldCoverage = 0;
    private int excludedExposedOrUnrecognized = 0;

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

    // ---- CVE Shield status, per app (per-CVE per-environment, from cves/issues) ----

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

    // ---- Assess/ADR module enablement, per app ----

    /**
     * `defend` is ADR (formerly branded "Protect"), the HTTP-rule-based RASP module - a different, older
     * product from CVE Shield, which defends specific CVEs via a microsandbox rather than HTTP rules. CVE
     * Shield's own coverage/status is NOT derived from this flag - see fetchCveShieldStatus below for that.
     */
    private static class ModuleStatus {
        Boolean assessEnabledDev, assessEnabledQa, assessEnabledProd;
        Boolean adrEnabledDev, adrEnabledQa, adrEnabledProd;
    }

    private ModuleStatus fetchModuleStatus(String appId) throws IOException {
        String url = host + "/Contrast/api/ng/" + orgId + "/applications/" + appId + "/servers";
        HttpGet get = new HttpGet(url);
        get.setHeader("Authorization", authHeader);
        get.setHeader("API-Key", apiKey);
        get.setHeader("Accept", "application/json");

        HttpResponse response = httpClient.execute(get);
        int statusCode = response.getStatusLine().getStatusCode();
        String body = EntityUtils.toString(response.getEntity());
        if (statusCode != 200) {
            throw new IOException("Servers API returned status " + statusCode + ": " + body);
        }

        ModuleStatus ps = new ModuleStatus();
        JsonObject json = gson.fromJson(body, JsonObject.class);
        if (!json.has("servers")) {
            return ps;
        }
        for (JsonElement el : json.getAsJsonArray("servers")) {
            JsonObject server = el.getAsJsonObject();
            String env = getStringOrNull(server, "environment");
            boolean assess = server.has("assess") && !server.get("assess").isJsonNull() && server.get("assess").getAsBoolean();
            boolean adr = server.has("defend") && !server.get("defend").isJsonNull() && server.get("defend").getAsBoolean();
            if ("DEVELOPMENT".equals(env)) {
                ps.assessEnabledDev = orTrue(ps.assessEnabledDev, assess);
                ps.adrEnabledDev = orTrue(ps.adrEnabledDev, adr);
            } else if ("QA".equals(env)) {
                ps.assessEnabledQa = orTrue(ps.assessEnabledQa, assess);
                ps.adrEnabledQa = orTrue(ps.adrEnabledQa, adr);
            } else if ("PRODUCTION".equals(env)) {
                ps.assessEnabledProd = orTrue(ps.assessEnabledProd, assess);
                ps.adrEnabledProd = orTrue(ps.adrEnabledProd, adr);
            }
        }
        return ps;
    }

    // ---- CVE Shield coverage, org-wide (not per app - fetched once per run) ----

    /**
     * Whether Contrast even HAS a CVE Shield virtual patch for a given CVE at all - a different fact from
     * whether it's actively catching that CVE for a specific app/environment (which is what the per-app
     * devStatus/qaStatus/prodStatus properties, from cves/issues, already report).
     */
    private Map<String, Boolean> fetchCveShieldStatus() throws IOException {
        Map<String, Boolean> cveShieldExists = new HashMap<>();
        String cursor = "";
        boolean hasMore = true;

        while (hasMore) {
            String url = baseUrl + "/organizations/" + orgId
                + "/cves?size=100&sort=maxCvssScore,desc&pagination=cursor&cursor=" + cursor
                + "&dateInterval%5BstartTime%5D=2000-01-01T00:00:00.000Z"
                + "&dateInterval%5BendTime%5D=" + java.time.Instant.now();
            HttpGet get = new HttpGet(url);
            get.setHeader("Authorization", authHeader);
            get.setHeader("API-Key", apiKey);
            get.setHeader("Accept", "application/json");

            HttpResponse response = httpClient.execute(get);
            int statusCode = response.getStatusLine().getStatusCode();
            String body = EntityUtils.toString(response.getEntity());
            if (statusCode != 200) {
                throw new IOException("CVEs API returned status " + statusCode + ": " + body);
            }

            JsonObject json = gson.fromJson(body, JsonObject.class);
            for (JsonElement el : json.getAsJsonArray("items")) {
                JsonObject item = el.getAsJsonObject();
                String cveId = item.has("cve") ? getStringOrNull(item.getAsJsonObject("cve"), "id") : null;
                if (cveId != null && item.has("cveShieldExists") && !item.get("cveShieldExists").isJsonNull()) {
                    cveShieldExists.put(cveId, item.get("cveShieldExists").getAsBoolean());
                }
            }

            hasMore = json.has("hasMore") && json.get("hasMore").getAsBoolean();
            cursor = json.has("cursor") && !json.get("cursor").isJsonNull() ? json.get("cursor").getAsString() : "";
            if (cursor.isEmpty()) {
                hasMore = false;
            }
        }
        return cveShieldExists;
    }

    /** Null (no server seen yet) stays null only if never set; otherwise ORs across multiple servers in the same env. */
    private Boolean orTrue(Boolean existing, boolean value) {
        return existing == null ? value : (existing || value);
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
        List<Component> appComponents = new ArrayList<>();

        System.out.println("\nFetching org-wide CVE Shield coverage...");
        Map<String, Boolean> cveShieldExists = fetchCveShieldStatus();
        System.out.println("  " + cveShieldExists.size() + " CVEs with known Shield coverage status");

        for (AppInfo app : apps) {
            System.out.println("\nProcessing " + app.name + " (" + app.id + ")...");

            Map<String, CveIssue> cveIssues = fetchCveIssues(app.id);
            JsonArray libraries = fetchLibraries(app.id);
            ModuleStatus protection = fetchModuleStatus(app.id);
            System.out.println("  " + libraries.size() + " vulnerable libraries, " + cveIssues.size() + " CVE issue records");
            appComponents.add(buildAppComponent(app, protection));

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
                JsonObject remediationGuidance = lib.has("remediationGuidance") && lib.get("remediationGuidance").isJsonObject()
                    ? lib.getAsJsonObject("remediationGuidance") : null;
                String latestVersion = getStringOrNull(lib, "latest_version");

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
                        cveId, vuln, cveIssues.get(cveId + "|" + fileVersion), daysObserved,
                        remediationGuidance, latestVersion, cveShieldExists.get(cveId));

                    if (v != null) {
                        vulnerabilities.add(v);
                    }
                }
            }
        }

        System.out.println("\nGenerated " + vulnerabilities.size() + " VEX statements.");
        if (excludedNoShieldCoverage > 0 || excludedExposedOrUnrecognized > 0) {
            System.out.println("Excluded " + (excludedNoShieldCoverage + excludedExposedOrUnrecognized)
                + " CVE(s) - no VEX statement generated, since this tool can't positively account for them:");
            if (excludedNoShieldCoverage > 0) {
                System.out.println("  " + excludedNoShieldCoverage + " have no CVE Shield coverage at all - "
                    + "absence-of-execution isn't evidence when nothing was ever watching");
            }
            if (excludedExposedOrUnrecognized > 0) {
                System.out.println("  " + excludedExposedOrUnrecognized + " are EXPOSED/EXPLOITED (or an "
                    + "unrecognized status) - genuinely affected, not a claim this tool makes");
            }
        }
        bom.setVulnerabilities(vulnerabilities);
        bom.setComponents(appComponents);

        if (apps.size() == 1) {
            Metadata metadata = new Metadata();
            metadata.setComponent(appComponents.get(0));
            bom.setMetadata(metadata);
        }

        return bom;
    }

    /** Carries Assess/ADR module-enablement facts (see ModuleStatus) - one per app, not repeated per statement. */
    private Component buildAppComponent(AppInfo app, ModuleStatus protection) {
        Component appComponent = new Component();
        appComponent.setType(Component.Type.APPLICATION);
        appComponent.setName(app.name);
        appComponent.setBomRef(sanitizeBomRef(app.id));

        List<Property> properties = new ArrayList<>();
        properties.add(property("contrast:assessEnabledDev", enabledLabel(protection.assessEnabledDev)));
        properties.add(property("contrast:assessEnabledQa", enabledLabel(protection.assessEnabledQa)));
        properties.add(property("contrast:assessEnabledProd", enabledLabel(protection.assessEnabledProd)));
        properties.add(property("contrast:adrEnabledDev", enabledLabel(protection.adrEnabledDev)));
        properties.add(property("contrast:adrEnabledQa", enabledLabel(protection.adrEnabledQa)));
        properties.add(property("contrast:adrEnabledProd", enabledLabel(protection.adrEnabledProd)));
        appComponent.setProperties(properties);
        return appComponent;
    }

    /** "" (no data) means no agent was ever seen reporting from that environment - not the same as "disabled". */
    private String enabledLabel(Boolean value) {
        return value == null ? "" : String.valueOf(value);
    }

    /** Returns null when the CVE shouldn't get a VEX statement at all (exposed/exploited/unrecognized status). */
    private Vulnerability buildVulnerability(AppInfo app, String group, String fileName, String fileVersion,
            String hash, long classesUsed, long classCount, String cveId, JsonObject vuln,
            CveIssue issue, long daysObserved, JsonObject remediationGuidance, String latestVersion,
            Boolean orgWideShieldExists) {

        Vulnerability v = new Vulnerability();
        v.setBomRef(sanitizeBomRef(app.id + "-" + cveId + "-" + hash));
        v.setId(cveId);

        String description = getStringOrNull(vuln, "description");
        if (description != null) {
            v.setDescription(description);
        }

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

        if (vuln.has("references") && vuln.getAsJsonArray("references").size() > 0) {
            List<Advisory> advisories = new ArrayList<>();
            for (JsonElement refEl : vuln.getAsJsonArray("references")) {
                String refUrl = refEl.isJsonPrimitive() ? refEl.getAsString() : getStringOrNull(refEl.getAsJsonObject(), "url");
                if (refUrl == null || refUrl.isEmpty()) {
                    continue;
                }
                Advisory advisory = new Advisory();
                advisory.setUrl(refUrl);
                advisories.add(advisory);
            }
            if (!advisories.isEmpty()) {
                v.setAdvisories(advisories);
            }
        }

        String purl = "pkg:maven/" + (group != null ? group : "unknown") + "/" + artifactNameFrom(fileName) + "@" + fileVersion;
        Affect affect = new Affect();
        affect.setRef(purl);

        // Contrast's own remediation guidance (minUpgrade = smallest version that clears this library's
        // vulnerabilities) is more actionable than the library's raw latest_version, which may be newer
        // than necessary or not actually address this CVE - prefer it when available.
        String minUpgradeVersion = remediationGuidance != null
            ? getStringOrNull(nestedObject(remediationGuidance, "minUpgrade"), "version") : null;
        String maxUpgradeVersion = remediationGuidance != null
            ? getStringOrNull(nestedObject(remediationGuidance, "maxUpgrade"), "version") : null;
        String recommendedVersion = minUpgradeVersion != null ? minUpgradeVersion : latestVersion;

        List<org.cyclonedx.model.vulnerability.Vulnerability.Version> versions = new ArrayList<>();
        org.cyclonedx.model.vulnerability.Vulnerability.Version affectedVersion =
            new org.cyclonedx.model.vulnerability.Vulnerability.Version();
        affectedVersion.setVersion(fileVersion);
        affectedVersion.setStatus(Status.AFFECTED);
        versions.add(affectedVersion);
        boolean fixAvailable = recommendedVersion != null && !recommendedVersion.equals(fileVersion);
        if (fixAvailable) {
            org.cyclonedx.model.vulnerability.Vulnerability.Version fixedVersion =
                new org.cyclonedx.model.vulnerability.Vulnerability.Version();
            fixedVersion.setVersion(recommendedVersion);
            fixedVersion.setStatus(Status.UNAFFECTED);
            versions.add(fixedVersion);
        }
        affect.setVersions(versions);

        List<Affect> affects = new ArrayList<>();
        affects.add(affect);
        v.setAffects(affects);

        String artifactName = artifactNameFrom(fileName);
        if (fixAvailable) {
            StringBuilder rec = new StringBuilder("Upgrade " + artifactName + " from " + fileVersion + " to "
                + recommendedVersion + " to remediate " + cveId + ".");
            if (maxUpgradeVersion != null && !maxUpgradeVersion.equals(recommendedVersion)) {
                rec.append(" Latest available release is ").append(maxUpgradeVersion).append(".");
            }
            v.setRecommendation(rec.toString());
        } else {
            v.setRecommendation("No newer release of " + artifactName + " is currently identified; monitor for a "
                + "fix and re-run VEX generation periodically.");
        }

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
            detail = "CVE Shield is actively mitigating this vulnerability at runtime in " + app.name
                + " (" + envScopeLabel() + ").";
        } else if (Boolean.FALSE.equals(shieldAvailability(orgWideShieldExists))) {
            // CVE Shield has no coverage for this CVE at all - there was never anything watching for an exploit
            // attempt, so "not observed executing" isn't evidence of anything, and neither not_affected nor
            // in_triage is a claim we can support. in_triage would be just as wrong: it implies evidence is
            // accumulating toward a future resolution, but nothing is running that could ever produce one. This
            // is the same "can't positively account for it" bucket as EXPOSED/EXPLOITED below - no VEX entry.
            excludedNoShieldCoverage++;
            return null;
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
            excludedExposedOrUnrecognized++;
            return null;
        }

        analysis.setDetail(detail);

        List<Response> responses = new ArrayList<>();
        if (analysis.getJustification() == Justification.PROTECTED_AT_RUNTIME) {
            // The active CVE Shield control is itself the mitigation in place.
            responses.add(Response.WORKAROUND_AVAILABLE);
        } else if (analysis.getJustification() != Justification.CODE_NOT_REACHABLE && fixAvailable) {
            responses.add(Response.UPDATE);
        }
        if (!responses.isEmpty()) {
            analysis.setResponses(responses);
        }

        v.setAnalysis(analysis);

        List<Property> properties = new ArrayList<>();
        properties.add(property("contrast:appId", app.id));
        properties.add(property("contrast:appName", app.name));
        properties.add(property("contrast:classesUsed", String.valueOf(classesUsed)));
        properties.add(property("contrast:classCount", String.valueOf(classCount)));
        properties.add(property("contrast:daysObserved", String.valueOf(daysObserved)));
        properties.add(property("contrast:acceptAfterDays", String.valueOf(acceptAfterDays)));
        properties.add(property("contrast:envFilter", envFilter != null ? envFilter : "ALL"));
        if (vuln.has("epss_score") && !vuln.get("epss_score").isJsonNull()) {
            properties.add(property("contrast:epssScore", String.valueOf(vuln.get("epss_score").getAsDouble())));
        }
        if (vuln.has("epss_percentile") && !vuln.get("epss_percentile").isJsonNull()) {
            properties.add(property("contrast:epssPercentile", String.valueOf(vuln.get("epss_percentile").getAsDouble())));
        }
        if (vuln.has("cisa") && !vuln.get("cisa").isJsonNull()) {
            properties.add(property("contrast:cisaKev", String.valueOf(vuln.get("cisa").getAsBoolean())));
        }
        Boolean shieldAvailable = shieldAvailability(orgWideShieldExists);
        if (shieldAvailable != null) {
            properties.add(property("contrast:shieldAvailable", String.valueOf(shieldAvailable)));
        }
        if (latestVersion != null) {
            properties.add(property("contrast:latestVersion", latestVersion));
        }
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

    /**
     * Whether CVE Shield could catch this CVE at all - this is a per-CVE, product-level fact (does Contrast
     * ship a virtual patch definition for it), NOT something that varies by app or environment: coverage
     * existing anywhere means it's available everywhere Shield/ADR is enabled. So this is just the org-wide
     * cveShieldExists flag from /cves, verbatim - no per-app inference. (An earlier version of this method
     * tried to infer availability from per-environment NO_SHIELD/NOT_SEEN status instead, which happened to
     * agree with the org-wide fact in every case checked so far, but was solving the wrong problem - it can't
     * distinguish "no coverage exists" from "this app's agent hasn't received the rule yet," and coverage
     * itself simply isn't an app/environment-scoped concept.)
     */
    private Boolean shieldAvailability(Boolean orgWideShieldExists) {
        return orgWideShieldExists;
    }

    private String artifactNameFrom(String fileName) {
        if (fileName == null) {
            return "unknown";
        }
        // e.g. "spring-web-4.3.9.release.jar" -> "spring-web"; best-effort, not exact for all naming schemes.
        String withoutExt = fileName.replaceAll("\\.jar$", "");
        return withoutExt.replaceAll("-\\d.*$", "");
    }

    private JsonObject nestedObject(JsonObject obj, String field) {
        return obj.has(field) && obj.get(field).isJsonObject() ? obj.getAsJsonObject(field) : null;
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
        return obj != null && obj.has(field) && !obj.get(field).isJsonNull() ? obj.get(field).getAsString() : null;
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
