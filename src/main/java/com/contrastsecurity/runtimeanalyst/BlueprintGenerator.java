package com.contrastsecurity.runtimeanalyst;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Generates a CycloneDX "Blueprint" (Architectural BOM + Bill of Behaviors) from Contrast
 * API data: the contrast-graph architecture/connection graph plus crypto-algorithm and
 * ai-usage observations, reclassified as entries from the CycloneDX behavior taxonomy.
 *
 * Blueprints are not yet part of a ratified CycloneDX release. As of this writing,
 * cyclonedx-core-java (and CycloneDX 1.7) have no model classes or schema for them - the
 * only draft schema is on the unreleased "2.0-dev" branch of CycloneDX/specification
 * (open PR https://github.com/CycloneDX/specification/pull/652,
 * schema/2.0/model/cyclonedx-blueprint-2.0.schema.json /
 * cyclonedx-behavior-2.0.schema.json / behavior-taxonomy.schema.json). This generator
 * hand-builds JSON matching that draft shape via Gson rather than typed model classes,
 * and will need to be revisited once the spec (and a library that supports it) lands.
 *
 * Only the parts of a Blueprint that Contrast's runtime data can actually back are
 * populated: assets (from the architecture graph), zones (from deployment tier), flows
 * (from architecture graph connections), and behavior instances (from crypto/AI usage
 * observations, mapped onto the CycloneDX behavior taxonomy). Threat modeling (TM-BOM) -
 * threats, scenarios, controls, risks - is a separate, sibling top-level construct in the
 * draft spec and is intentionally out of scope here: none of it can be derived from
 * Contrast telemetry without an actual STRIDE-style analysis, so generating it would mean
 * fabricating findings rather than reporting observed facts.
 *
 * Usage:
 *   java -jar runtime-analyst.jar blueprint                    # Fetch all apps, output blueprint.json
 *   java -jar runtime-analyst.jar blueprint --app "AppName"    # Fetch single app
 *   java -jar runtime-analyst.jar blueprint --list             # List available applications
 *   java -jar runtime-analyst.jar blueprint -o custom.json     # Custom output filename
 *   java -jar runtime-analyst.jar blueprint -c config.properties
 *
 * Config file (contrast.properties):
 *   contrast.url=https://your-instance.contrastsecurity.com/api/ns-ui/v1
 *   contrast.org_id=your-org-id
 *   contrast.auth_header=base64-encoded-credentials
 *   contrast.api_key=your-api-key
 */
public class BlueprintGenerator {

    private static final String CRYPTO_ALGORITHM_RULE_ID = "crypto-algorithm";
    private static final String AI_USAGE_RULE_ID = "ai-usage";

    private String baseUrl;
    private String orgId;
    private String authHeader;
    private String apiKey;
    private String envFilter; // PRODUCTION, DEVELOPMENT, QA, etc.

    private final Gson gson = new Gson();
    private final Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();

    public void setEnvFilter(String env) {
        this.envFilter = env;
    }

    public BlueprintGenerator(String configFile) throws IOException {
        loadConfig(configFile);
    }

    private void loadConfig(String configFile) throws IOException {
        Properties props = new Properties();

        File f;
        if (configFile != null) {
            f = new File(configFile);
            if (!f.exists()) {
                throw new IOException("Config file not found: " + configFile);
            }
        } else {
            f = new File("contrast.properties");
            if (!f.exists()) {
                throw new IOException("No contrast.properties found in current directory.\n" +
                    "Create one with:\n" +
                    "  contrast.url=https://your-instance.contrastsecurity.com/api/ns-ui/v1\n" +
                    "  contrast.org_id=your-org-id\n" +
                    "  contrast.auth_header=base64-encoded-credentials\n" +
                    "  contrast.api_key=your-api-key\n" +
                    "Or specify a config file with -c option.");
            }
        }

        InputStream is = new FileInputStream(f);
        try {
            props.load(is);
        } finally {
            is.close();
        }

        baseUrl = props.getProperty("contrast.url");
        orgId = props.getProperty("contrast.org_id");
        authHeader = props.getProperty("contrast.auth_header");
        apiKey = props.getProperty("contrast.api_key");

        if (baseUrl == null || orgId == null || authHeader == null || apiKey == null) {
            throw new IOException("Config file must contain: contrast.url, contrast.org_id, contrast.auth_header, contrast.api_key");
        }
    }

    public static void main(String[] args) {
        String appFilter = null;
        String envFilter = null;
        String outputFile = "blueprint.json";
        String configFile = null;
        boolean listOnly = false;

        for (int i = 0; i < args.length; i++) {
            if ("--app".equals(args[i]) && i + 1 < args.length) {
                appFilter = args[++i];
            } else if ("--env".equals(args[i]) && i + 1 < args.length) {
                envFilter = args[++i].toUpperCase();
            } else if ("--list".equals(args[i])) {
                listOnly = true;
            } else if ("-o".equals(args[i]) && i + 1 < args.length) {
                outputFile = args[++i];
            } else if ("-c".equals(args[i]) && i + 1 < args.length) {
                configFile = args[++i];
            } else if ("--help".equals(args[i]) || "-h".equals(args[i])) {
                printUsage();
                System.exit(0);
            }
        }

        try {
            BlueprintGenerator generator = new BlueprintGenerator(configFile);
            generator.setEnvFilter(envFilter);
            List<Observation> observations = generator.fetchObservations();

            if (listOnly) {
                generator.listApplications(observations);
            } else {
                BlueprintResult result = generator.generateBlueprint(observations, appFilter);

                if (appFilter != null && "blueprint.json".equals(outputFile)) {
                    String nameForFile = result.resolvedAppName != null ? result.resolvedAppName : appFilter;
                    String safeAppName = nameForFile.replaceAll("[^a-zA-Z0-9-_]", "_");
                    outputFile = "blueprint-" + safeAppName + ".json";
                }

                generator.writeBlueprint(result.document, outputFile);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("\nBlueprint Generator - Create a CycloneDX Blueprint (ABOM + Bill of Behaviors) from Contrast data");
        System.out.println("\nUsage:");
        System.out.println("  java -jar runtime-analyst.jar blueprint                   Generate a Blueprint for all apps");
        System.out.println("  java -jar runtime-analyst.jar blueprint --app <id|name>   Filter by app (ID or name)");
        System.out.println("  java -jar runtime-analyst.jar blueprint --env <tier>      Filter by environment (PRODUCTION, DEVELOPMENT, QA)");
        System.out.println("  java -jar runtime-analyst.jar blueprint --list            List available applications with IDs");
        System.out.println("  java -jar runtime-analyst.jar blueprint -o <file.json>    Specify output filename");
        System.out.println("  java -jar runtime-analyst.jar blueprint -c <config.properties>  Use custom config file");
        System.out.println("\nConfig file (contrast.properties):");
        System.out.println("  contrast.url=https://your-instance.contrastsecurity.com/api/ns-ui/v1");
        System.out.println("  contrast.org_id=your-org-id");
        System.out.println("  contrast.auth_header=base64-encoded-credentials");
        System.out.println("  contrast.api_key=your-api-key");
        System.out.println("\nNote: Blueprints are a CycloneDX draft (unreleased 2.0-dev branch, spec PR #652).");
        System.out.println("This command populates assets/zones/flows/behaviors from real Contrast data only -");
        System.out.println("it does not generate threats/controls/risks (TM-BOM), which would require fabricating");
        System.out.println("findings Contrast's telemetry cannot back.");
    }

    // Raw counts before dedup, keyed by "crypto:<algorithm>" or "ai:<provider>/<model>"
    private Map<String, Integer> rawCounts = new HashMap<>();

    // Application-level architecture/connection info from the Contrast graph, keyed by applicationId
    private Map<String, AppGraphInfo> appGraphInfo = new HashMap<>();

    public List<Observation> fetchObservations() throws IOException {
        System.out.println("\nFetching observations from Contrast API...");

        rawCounts.clear();

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            JsonArray observationList = fetchObservationsList(httpClient);
            System.out.println("  Found " + observationList.size() + " total observations");

            // Dedup key: kind + algorithm/model + applicationId + route (before fetching details)
            Map<String, Observation> uniqueObservations = new HashMap<>();
            Set<String> environmentsSeen = new HashSet<>();
            int skipped = 0;
            int irrelevant = 0;

            for (JsonElement element : observationList) {
                JsonObject obs = element.getAsJsonObject();

                String ruleId = getStringOrNull(obs, "ruleId");
                Observation observation;
                if (CRYPTO_ALGORITHM_RULE_ID.equals(ruleId)) {
                    observation = parseObservationFromList(obs);
                    observation.kind = "crypto";
                    observation.algorithm = getStringOrNull(obs, "attackValue");
                } else if (AI_USAGE_RULE_ID.equals(ruleId)) {
                    observation = parseObservationFromList(obs);
                    observation.kind = "ai";
                    AIUsageParser parser = new AIUsageParser(getStringOrNull(obs, "attackValue"), getStringOrNull(obs, "summary"));
                    observation.provider = parser.getProvider();
                    observation.model = parser.getModel();
                } else {
                    irrelevant++;
                    continue;
                }

                if (envFilter != null && !envFilter.equals(observation.environment)) {
                    skipped++;
                    continue;
                }

                if (observation.environment != null) {
                    environmentsSeen.add(observation.environment);
                }

                String rawKey = "crypto".equals(observation.kind)
                    ? "crypto:" + observation.algorithm
                    : "ai:" + observation.provider + "/" + observation.model;
                rawCounts.merge(rawKey, 1, Integer::sum);

                String dedupKey = rawKey + "|" + observation.applicationId + "|" + observation.route;
                if (!uniqueObservations.containsKey(dedupKey)) {
                    uniqueObservations.put(dedupKey, observation);
                }
            }

            System.out.println("  Filtered to " + (observationList.size() - irrelevant) + " crypto/AI-usage observations");
            if (skipped > 0) {
                System.out.println("  Filtered to " + (observationList.size() - irrelevant - skipped) + " (env: " + envFilter + ")");
            }
            System.out.println("  Deduplicated to " + uniqueObservations.size() + " unique observations");

            System.out.print("  Fetching details for unique observations");
            for (Observation observation : uniqueObservations.values()) {
                JsonObject details = fetchObservationDetails(httpClient, observation.id);
                addDetailsToObservation(observation, details);
                System.out.print('.');
            }
            System.out.println(" done");

            if (!environmentsSeen.isEmpty()) {
                System.out.println("\nFetching application architecture/connection graph...");
                try {
                    appGraphInfo = ApplicationGraphFetcher.fetch(httpClient, gson, baseUrl, orgId, authHeader, apiKey, environmentsSeen);
                    System.out.println("  Found graph data for " + appGraphInfo.size() + " applications");
                } catch (IOException e) {
                    System.out.println("  Skipping graph enrichment (" + e.getMessage() + ")");
                }
            }

            return new ArrayList<>(uniqueObservations.values());
        }
    }

    private JsonArray fetchObservationsList(CloseableHttpClient httpClient) throws IOException {
        String url = baseUrl + "/organizations/" + orgId + "/observations";
        HttpPost post = new HttpPost(url);

        post.setHeader("Authorization", authHeader);
        post.setHeader("API-Key", apiKey);
        post.setHeader("Content-Type", "application/json");
        post.setHeader("Accept", "application/json");

        String requestBody = "{"
            + "\"observationOrigins\":[\"OBSERVABILITY\"],"
            + "\"values\":[\"MLKEM\",\"ML-KEM\",\"ML-DSA\",\"FN-DSA\"],"
            + "\"excludeValues\":true,"
            + "\"pageable\":{"
            + "\"pageSize\":1000,"
            + "\"sort\":[{\"property\":\"EVENT_TIME\",\"direction\":\"desc\"}],"
            + "\"sortAfter\":[]"
            + "}"
            + "}";
        post.setEntity(new StringEntity(requestBody));

        HttpResponse response = httpClient.execute(post);
        int statusCode = response.getStatusLine().getStatusCode();
        String responseBody = EntityUtils.toString(response.getEntity());

        if (statusCode != 200) {
            throw new IOException("API returned status " + statusCode + ": " + responseBody);
        }

        JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
        if (jsonResponse == null || !jsonResponse.has("observations")) {
            throw new IOException("Invalid API response");
        }

        return jsonResponse.getAsJsonArray("observations");
    }

    private JsonObject fetchObservationDetails(CloseableHttpClient httpClient, String observationId) throws IOException {
        String url = baseUrl + "/organizations/" + orgId + "/observations/" + observationId + "/details";
        HttpGet get = new HttpGet(url);

        get.setHeader("Authorization", authHeader);
        get.setHeader("API-Key", apiKey);
        get.setHeader("Accept", "application/json");

        HttpResponse response = httpClient.execute(get);
        int statusCode = response.getStatusLine().getStatusCode();
        String responseBody = EntityUtils.toString(response.getEntity());

        if (statusCode != 200) {
            throw new IOException("API returned status " + statusCode + " for observation " + observationId);
        }

        return gson.fromJson(responseBody, JsonObject.class);
    }

    private Observation parseObservationFromList(JsonObject listItem) {
        Observation obs = new Observation();
        obs.id = getStringOrNull(listItem, "observationId");
        obs.eventTime = getStringOrNull(listItem, "detectedTime");
        obs.route = getStringOrNull(listItem, "httpRoute");
        obs.applicationId = getStringOrNull(listItem, "applicationId");
        obs.applicationName = getStringOrNull(listItem, "applicationName");
        obs.serverName = getStringOrNull(listItem, "serverName");
        obs.environment = getStringOrNull(listItem, "deploymentTier");
        return obs;
    }

    private void addDetailsToObservation(Observation obs, JsonObject details) {
        if (details.has("stackTrace") && !details.get("stackTrace").isJsonNull()) {
            JsonElement stackTraceElement = details.get("stackTrace");
            if (stackTraceElement.isJsonArray()) {
                JsonArray stackTrace = stackTraceElement.getAsJsonArray();
                StringBuilder sb = new StringBuilder();
                for (JsonElement frame : stackTrace) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(frame.getAsString());
                }
                obs.stackTrace = sb.toString();
            } else if (stackTraceElement.isJsonPrimitive()) {
                obs.stackTrace = stackTraceElement.getAsString();
            }
        }
    }

    private String getStringOrNull(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return null;
    }

    public void listApplications(List<Observation> observations) {
        Map<String, String> appIdToName = new HashMap<>();
        Map<String, Integer> appIdToCount = new HashMap<>();

        for (Observation obs : observations) {
            if (obs.applicationId != null && !obs.applicationId.isEmpty()) {
                appIdToName.put(obs.applicationId, obs.applicationName);
                appIdToCount.merge(obs.applicationId, 1, Integer::sum);
            }
        }

        System.out.println("\nAvailable applications:");
        System.out.println("  ID                                      Name                                                     Observations");
        System.out.println("  ---------------------------------------- -------------------------------------------------------- ------------");
        for (Map.Entry<String, String> entry : appIdToName.entrySet()) {
            String appId = entry.getKey();
            String appName = entry.getValue();
            int count = appIdToCount.get(appId);
            System.out.printf("  %-40s %-56s %d%n", appId, appName, count);
        }
    }

    static class BlueprintResult {
        JsonObject document;
        String resolvedAppName;
        BlueprintResult(JsonObject document, String resolvedAppName) {
            this.document = document;
            this.resolvedAppName = resolvedAppName;
        }
    }

    public BlueprintResult generateBlueprint(List<Observation> observations, String appFilter) {
        System.out.println("\nGenerating Blueprint" + (appFilter != null ? " for " + appFilter : " for all applications"));

        List<Observation> filtered = new ArrayList<>();
        String resolvedAppName = null;
        for (Observation obs : observations) {
            if (appFilter == null) {
                filtered.add(obs);
            } else if (appFilter.equals(obs.applicationId) || appFilter.equals(obs.applicationName)) {
                filtered.add(obs);
                if (resolvedAppName == null && obs.applicationName != null) {
                    resolvedAppName = obs.applicationName;
                }
            }
        }
        System.out.println("  Processing " + filtered.size() + " observations");

        // Group observations by app
        Map<String, List<Observation>> byApp = new HashMap<>();
        Map<String, String> appIdToName = new HashMap<>();
        Map<String, String> appIdToEnv = new HashMap<>();
        for (Observation obs : filtered) {
            String appKey = obs.applicationId != null ? obs.applicationId : obs.applicationName;
            if (appKey == null) continue;
            byApp.computeIfAbsent(appKey, k -> new ArrayList<>()).add(obs);
            appIdToName.put(appKey, obs.applicationName);
            if (obs.environment != null) {
                appIdToEnv.putIfAbsent(appKey, obs.environment);
            }
        }

        System.out.println("  Found " + byApp.size() + " applications");

        JsonObject doc = new JsonObject();
        doc.addProperty("$schema", "https://cyclonedx.org/schema/2.0/cyclonedx-2.0.schema.json");
        doc.addProperty("specFormat", "CycloneDX");
        doc.addProperty("specVersion", "2.0");
        doc.addProperty("serialNumber", "urn:uuid:" + UUID.randomUUID().toString());
        doc.addProperty("version", 1);

        JsonObject metadata = new JsonObject();
        metadata.addProperty("timestamp", new Date().toInstant().toString());
        doc.add("metadata", metadata);

        JsonArray blueprints = new JsonArray();
        JsonObject blueprint = new JsonObject();
        blueprint.addProperty("bom-ref", "blueprint-1");
        blueprint.addProperty("name", resolvedAppName != null ? "Blueprint - " + resolvedAppName
            : (appFilter != null ? "Blueprint - " + appFilter : "Contrast Architecture Blueprint"));
        blueprint.addProperty("description",
            "Generated from Contrast runtime observability data: application architecture/connections "
            + "(contrast-graph) and crypto/AI usage observations, mapped onto the CycloneDX behavior "
            + "taxonomy. Does not include threats, controls, or risks - see TM-BOM.");
        JsonArray modelTypes = new JsonArray();
        modelTypes.add("architecture");
        modelTypes.add("behavioral");
        blueprint.add("modelTypes", modelTypes);

        // --- Assets: one per known application, plus one per distinct connected entity we
        // only know by name (no architecture-graph node of our own for it). ---
        Map<String, String> appAssetRefs = new HashMap<>(); // appId -> asset bom-ref
        Map<String, String> nameToAssetRef = new HashMap<>(); // application/connection name -> asset bom-ref
        JsonArray assets = new JsonArray();

        for (Map.Entry<String, List<Observation>> entry : byApp.entrySet()) {
            String appId = entry.getKey();
            String appName = appIdToName.get(appId);
            String displayName = appName != null ? appName : appId;
            String assetRef = "asset-app-" + sanitizeBomRef(displayName);
            appAssetRefs.put(appId, assetRef);
            nameToAssetRef.put(displayName, assetRef);

            JsonObject asset = new JsonObject();
            asset.addProperty("bom-ref", assetRef);
            asset.addProperty("name", displayName);
            asset.addProperty("type", "system");

            AppGraphInfo graphInfo = appGraphInfo.get(appId);
            JsonArray assetProps = new JsonArray();
            if (graphInfo != null) {
                if (graphInfo.language != null) {
                    assetProps.add(property("contrast:language", graphInfo.language));
                }
                if (graphInfo.postureScore != null) {
                    assetProps.add(property("contrast:postureScore", String.valueOf(graphInfo.postureScore)));
                }
                if (graphInfo.postureSeverity != null) {
                    assetProps.add(property("contrast:postureSeverity", graphInfo.postureSeverity));
                }
                if (graphInfo.openIssuesTotal != null) {
                    assetProps.add(property("contrast:openIssuesTotal", String.valueOf(graphInfo.openIssuesTotal)));
                }
                assetProps.add(property("contrast:serverCount", String.valueOf(graphInfo.serverCount)));
                assetProps.add(property("contrast:libraryCount", String.valueOf(graphInfo.libraryCount)));

                if (graphInfo.criticality != null) {
                    JsonObject classification = new JsonObject();
                    classification.addProperty("criticality", mapCriticality(graphInfo.criticality));
                    asset.add("classification", classification);
                }
            }
            if (assetProps.size() > 0) {
                asset.add("properties", assetProps);
            }

            String env = appIdToEnv.get(appId);
            if (env != null) {
                asset.addProperty("zone", "zone-env-" + sanitizeBomRef(env));
            }

            assets.add(asset);
        }

        // External assets: connections whose target isn't one of our known applications
        // (resolved by applicationId first, falling back to name matching - the
        // contrast-graph display name for an app doesn't always match its /observations
        // applicationName, so name-only matching would otherwise fabricate duplicates of
        // apps we already have an asset for).
        int externalCounter = 0;
        for (AppGraphInfo graphInfo : appGraphInfo.values()) {
            for (String connectedName : graphInfo.connectedApplications) {
                if (resolveConnectedAssetRef(graphInfo, connectedName, appAssetRefs, nameToAssetRef) == null) {
                    String assetRef = "asset-external-" + sanitizeBomRef(connectedName);
                    nameToAssetRef.put(connectedName, assetRef);

                    JsonObject asset = new JsonObject();
                    asset.addProperty("bom-ref", assetRef);
                    asset.addProperty("name", connectedName);
                    asset.addProperty("type", "system");
                    asset.addProperty("description", "Known only as an architecture-graph connection target; no application-level data available.");
                    assets.add(asset);
                    externalCounter++;
                }
            }
        }
        blueprint.add("assets", assets);

        // --- Zones: one per deployment tier seen ---
        JsonArray zones = new JsonArray();
        Set<String> envsSeen = new HashSet<>(appIdToEnv.values());
        for (String env : envsSeen) {
            JsonObject zone = new JsonObject();
            zone.addProperty("bom-ref", "zone-env-" + sanitizeBomRef(env));
            zone.addProperty("name", env);
            zone.addProperty("type", "deployment");
            zones.add(zone);
        }
        blueprint.add("zones", zones);

        // --- Flows: architecture-graph connections between assets (direction is not
        // preserved by the graph API, so flows are modeled as bidirectional) ---
        JsonArray flows = new JsonArray();
        Set<String> seenPairs = new HashSet<>();
        int flowCounter = 0;
        for (Map.Entry<String, AppGraphInfo> entry : appGraphInfo.entrySet()) {
            String appId = entry.getKey();
            String sourceRef = appAssetRefs.get(appId);
            if (sourceRef == null) continue; // app filtered out / not in this blueprint

            for (String connectedName : entry.getValue().connectedApplications) {
                String destRef = resolveConnectedAssetRef(entry.getValue(), connectedName, appAssetRefs, nameToAssetRef);
                if (destRef == null || destRef.equals(sourceRef)) continue;

                String pairKey = sourceRef.compareTo(destRef) < 0 ? sourceRef + "|" + destRef : destRef + "|" + sourceRef;
                if (!seenPairs.add(pairKey)) continue;

                JsonObject flow = new JsonObject();
                flow.addProperty("bom-ref", "flow-" + (++flowCounter));
                flow.addProperty("name", appIdToName.getOrDefault(appId, appId) + " <-> " + connectedName);
                flow.addProperty("type", "data");
                flow.addProperty("source", sourceRef);
                flow.addProperty("destination", destRef);
                flow.addProperty("bidirectional", true);
                flows.add(flow);
            }
        }
        blueprint.add("flows", flows);

        // --- Behaviors: crypto/AI usage observations mapped onto the behavior taxonomy ---
        // TODO: the Behavior tab's richer per-route data (Contrast's ServiceResourceDto/
        // ActionType model - resources as addressable assets with per-resource actions like
        // AUTHN, STORAGE_QUERY, OUTBOUND_SERVICE_CALL) isn't reachable here. Its backend
        // (adr-contrastgraph-reader's BehaviorTabController, proxied via adr-explorer-aggregator)
        // has no API-Key-authenticated route in contrast-api-gateway - only UI session/XSRF auth
        // works today. Revisit once that gap is closed (see PROD-2415).
        JsonArray instances = new JsonArray();
        int behaviorCounter = 0;
        int unmapped = 0;
        for (Observation obs : filtered) {
            String appKey = obs.applicationId != null ? obs.applicationId : obs.applicationName;
            String actorRef = appKey != null ? appAssetRefs.get(appKey) : null;

            String tag = "crypto".equals(obs.kind) ? mapCryptoBehavior(obs.algorithm) : mapAiBehavior();
            if (tag == null) {
                unmapped++;
                continue;
            }

            JsonObject instance = new JsonObject();
            instance.addProperty("bom-ref", "behavior-" + (++behaviorCounter));
            instance.addProperty("behavior", tag);
            if (actorRef != null) {
                JsonArray actors = new JsonArray();
                actors.add(actorRef);
                instance.add("actors", actors);
            }
            instance.addProperty("trigger", obs.route != null ? "api-call" : "unknown");
            instances.add(instance);
        }
        if (unmapped > 0) {
            System.out.println("  " + unmapped + " observation(s) had no behavior-taxonomy mapping, skipped");
        }
        JsonObject behaviors = new JsonObject();
        behaviors.add("instances", instances);
        blueprint.add("behaviors", behaviors);

        blueprints.add(blueprint);
        doc.add("blueprints", blueprints);

        System.out.println("  Created " + assets.size() + " assets (" + externalCounter + " external), "
            + zones.size() + " zones, " + flows.size() + " flows, " + instances.size() + " behavior instances");

        return new BlueprintResult(doc, resolvedAppName);
    }

    /**
     * Maps a Contrast crypto-algorithm observation onto an entry in the CycloneDX behavior
     * taxonomy (behavior-taxonomy.schema.json, security:cryptography:* namespace), based on
     * the algorithm's cryptographic primitive. This is necessarily a coarse mapping: the
     * taxonomy distinguishes e.g. encrypt vs. decrypt, but a crypto-algorithm observation
     * doesn't tell us which direction was used, so a representative tag is chosen per primitive.
     */
    private String mapCryptoBehavior(String algorithm) {
        if (algorithm == null || algorithm.isEmpty()) return null;
        AlgorithmParser parser = new AlgorithmParser(algorithm);
        String primitive = parser.getPrimitive();
        if (primitive == null) return "security:cryptography:encryptsData";

        switch (primitive.toLowerCase()) {
            case "ae":
            case "block-cipher":
            case "stream-cipher":
            case "pke":
                return "security:cryptography:encryptsData";
            case "hash":
            case "xof":
                return "security:cryptography:hashesData";
            case "mac":
                return "security:cryptography:ensuresIntegrity";
            case "signature":
                return "security:cryptography:signsData";
            case "kex":
            case "key-agree":
            case "kem":
                return "security:cryptography:exchangesKey";
            case "kdf":
                return "security:cryptography:generatesKey";
            case "drbg":
                return "security:cryptography:generatesRandomValue";
            default:
                return "security:cryptography:encryptsData";
        }
    }

    /**
     * AI-usage observations don't distinguish inference/training/agent action types, so all
     * are mapped onto the taxonomy's general-purpose generative-AI-call entry.
     */
    private String mapAiBehavior() {
        return "ai:generative:processesPrompt";
    }

    /**
     * Resolves an architecture-graph connection name to the asset bom-ref it actually
     * refers to. Prefers resolving by applicationId (via AppGraphInfo.connectedApplicationIds)
     * when the connection target is itself a known Contrast application, since the
     * contrast-graph display name and the /observations applicationName for the same app
     * can differ; falls back to matching on the name string (for server/library clusters,
     * or apps outside this blueprint's filter).
     */
    private String resolveConnectedAssetRef(AppGraphInfo graphInfo, String connectedName,
            Map<String, String> appAssetRefs, Map<String, String> nameToAssetRef) {
        String connectedAppId = graphInfo.connectedApplicationIds.get(connectedName);
        if (connectedAppId != null) {
            String ref = appAssetRefs.get(connectedAppId);
            if (ref != null) return ref;
        }
        return nameToAssetRef.get(connectedName);
    }

    private String mapCriticality(int criticality) {
        if (criticality <= 1) return "minimal";
        if (criticality == 2) return "low";
        if (criticality == 3) return "moderate";
        if (criticality == 4) return "high";
        return "critical";
    }

    private JsonObject property(String name, String value) {
        JsonObject p = new JsonObject();
        p.addProperty("name", name);
        p.addProperty("value", value);
        return p;
    }

    private String sanitizeBomRef(String input) {
        return input.toLowerCase()
            .replaceAll("[^a-z0-9-]", "-")
            .replaceAll("-+", "-")
            .replaceAll("^-|-$", "");
    }

    public void writeBlueprint(JsonObject document, String filename) throws IOException {
        System.out.println("\nWriting Blueprint to " + filename);

        String json = prettyGson.toJson(document);
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(json);
        }

        System.out.println("  Done!");
        System.out.println("\n  Output: " + filename);
    }

    // Observation class for holding fetched data (crypto or AI usage)
    static class Observation {
        String id;
        String kind; // "crypto" or "ai"
        String algorithm; // crypto only
        String provider;  // ai only
        String model;     // ai only
        String eventTime;
        String route;
        String applicationId;
        String applicationName;
        String serverName;
        String environment;
        String stackTrace;
    }
}
