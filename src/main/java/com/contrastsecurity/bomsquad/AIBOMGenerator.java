package com.contrastsecurity.bomsquad;

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

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Property;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Generates a CycloneDX AI-BOM (AI/ML usage inventory) from Contrast API observations.
 *
 * Usage:
 *   java -jar bom-squad.jar aibom                # Fetch all apps, output aibom.json
 *   java -jar bom-squad.jar aibom --app "AppName" # Fetch single app
 *   java -jar bom-squad.jar aibom --list          # List available applications
 *   java -jar bom-squad.jar aibom -o custom.json  # Custom output filename
 *   java -jar bom-squad.jar aibom -c config.properties
 *
 * Config file (contrast.properties):
 *   contrast.url=https://your-instance.contrastsecurity.com/api/ns-ui/v1
 *   contrast.org_id=your-org-id
 *   contrast.auth_header=base64-encoded-credentials
 *   contrast.api_key=your-api-key
 */
public class AIBOMGenerator {

    private static final String AI_USAGE_RULE_ID = "ai-usage";

    private String baseUrl;
    private String orgId;
    private String authHeader;
    private String apiKey;
    private String envFilter; // PRODUCTION, DEVELOPMENT, QA, etc.

    private final Gson gson = new Gson();

    public void setEnvFilter(String env) {
        this.envFilter = env;
    }

    public AIBOMGenerator(String configFile) throws IOException {
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
        String outputFile = "aibom.json";
        String configFile = null;
        boolean listOnly = false;
        boolean runAnalysis = false;

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
            } else if ("--help".equals(args[i]) || "-h".equals(args[i])) {
                printUsage();
                System.exit(0);
            }
        }

        try {
            AIBOMGenerator generator = new AIBOMGenerator(configFile);
            generator.setEnvFilter(envFilter);
            List<Observation> observations = generator.fetchObservations();

            if (listOnly) {
                generator.listApplications(observations);
            } else {
                AIBOMResult result = generator.generateAIBOM(observations, appFilter);

                if (appFilter != null && "aibom.json".equals(outputFile)) {
                    String nameForFile = result.resolvedAppName != null ? result.resolvedAppName : appFilter;
                    String safeAppName = nameForFile.replaceAll("[^a-zA-Z0-9-_]", "_");
                    outputFile = "aibom-" + safeAppName + ".json";
                }

                generator.writeAIBOM(result.bom, outputFile);

                if (runAnalysis) {
                    generator.runAIAdvisor(outputFile);
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("\nAI-BOM Generator - Create CycloneDX AI-BOM from Contrast AI usage observations");
        System.out.println("\nUsage:");
        System.out.println("  java -jar bom-squad.jar aibom                   Generate AI-BOM for all apps");
        System.out.println("  java -jar bom-squad.jar aibom --app <id|name>   Filter by app (ID or name)");
        System.out.println("  java -jar bom-squad.jar aibom --env <tier>      Filter by environment (PRODUCTION, DEVELOPMENT, QA)");
        System.out.println("  java -jar bom-squad.jar aibom --list            List available applications with IDs");
        System.out.println("  java -jar bom-squad.jar aibom --analyze         Run AI Advisor analysis after AI-BOM generation");
        System.out.println("  java -jar bom-squad.jar aibom -o <file.json>    Specify output filename");
        System.out.println("  java -jar bom-squad.jar aibom -c <config.properties>  Use custom config file");
        System.out.println("\nConfig file (contrast.properties):");
        System.out.println("  contrast.url=https://eval.contrastsecurity.com/api/ns-ui/v1");
        System.out.println("  contrast.org_id=your-org-id");
        System.out.println("  contrast.auth_header=base64-encoded-credentials");
        System.out.println("  contrast.api_key=your-api-key");
    }

    /**
     * Run the AI Advisor to analyze the AI-BOM and generate an AI-usage risk
     * assessment report, in-process (no Python required).
     */
    private void runAIAdvisor(String aiBomFile) {
        System.out.println("\n" + "============================================================");
        System.out.println("Running AI Advisor Analysis...");
        System.out.println("============================================================");

        String advisorOutput = aiBomFile.replace(".json", "-advisor.md");

        AIAdvisor.main(new String[]{aiBomFile, "--no-confirm", "-o", advisorOutput});
        System.out.println("\nAI Advisor report written to: " + advisorOutput);
    }

    // Track raw counts per model (provider + model) before deduplication
    private Map<String, Integer> modelRawCounts = new HashMap<>();

    // Application-level architecture/connection info from the Contrast graph, keyed by applicationId
    private Map<String, AppGraphInfo> appGraphInfo = new HashMap<>();

    public List<Observation> fetchObservations() throws IOException {
        System.out.println("\nFetching AI usage observations from Contrast API...");

        modelRawCounts.clear();

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            JsonArray observationList = fetchObservationsList(httpClient);
            System.out.println("  Found " + observationList.size() + " total observations");

            // First pass: parse basic info, filter to AI usage, count, and deduplicate.
            // Dedup key: model + applicationId + route (before fetching details)
            Map<String, Observation> uniqueObservations = new HashMap<>();
            Set<String> environmentsSeen = new HashSet<>();
            int skipped = 0;
            int nonAi = 0;

            for (JsonElement element : observationList) {
                JsonObject obs = element.getAsJsonObject();

                // The observations endpoint returns all OBSERVABILITY data (crypto, AI usage, etc.)
                // so filter client-side to just the AI usage rule.
                String ruleId = getStringOrNull(obs, "ruleId");
                if (!AI_USAGE_RULE_ID.equals(ruleId)) {
                    nonAi++;
                    continue;
                }

                Observation observation = parseObservationFromList(obs);

                if (envFilter != null && !envFilter.equals(observation.environment)) {
                    skipped++;
                    continue;
                }

                if (observation.environment != null) {
                    environmentsSeen.add(observation.environment);
                }

                String modelKey = observation.provider + "/" + observation.model;
                modelRawCounts.merge(modelKey, 1, Integer::sum);

                String dedupKey = modelKey + "|" + observation.applicationId + "|" + observation.route;
                if (!uniqueObservations.containsKey(dedupKey)) {
                    uniqueObservations.put(dedupKey, observation);
                }
            }

            System.out.println("  Filtered to " + (observationList.size() - nonAi) + " AI usage observations");
            if (skipped > 0) {
                System.out.println("  Filtered to " + (observationList.size() - nonAi - skipped) + " (env: " + envFilter + ")");
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

    public int getRawCount(String provider, String model) {
        return modelRawCounts.getOrDefault(provider + "/" + model, 0);
    }

    private JsonArray fetchObservationsList(CloseableHttpClient httpClient) throws IOException {
        String url = baseUrl + "/organizations/" + orgId + "/observations";
        HttpPost post = new HttpPost(url);

        post.setHeader("Authorization", authHeader);
        post.setHeader("API-Key", apiKey);
        post.setHeader("Content-Type", "application/json");
        post.setHeader("Accept", "application/json");

        // Note: the observations API does not support filtering by ruleId/behaviorType
        // server-side, so we fetch everything and filter to AI usage client-side.
        String requestBody = "{"
            + "\"observationOrigins\":[\"OBSERVABILITY\"],"
            + "\"values\":[],"
            + "\"excludeValues\":false,"
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
        obs.attackValue = getStringOrNull(listItem, "attackValue");
        obs.eventTime = getStringOrNull(listItem, "detectedTime");
        obs.route = getStringOrNull(listItem, "httpRoute");
        obs.applicationId = getStringOrNull(listItem, "applicationId");
        obs.applicationName = getStringOrNull(listItem, "applicationName");
        obs.serverName = getStringOrNull(listItem, "serverName");
        obs.environment = getStringOrNull(listItem, "deploymentTier");

        // Parse provider/model from attackValue now; endpoint gets refined once we
        // have the details "summary" field.
        AIUsageParser parser = new AIUsageParser(obs.attackValue, null);
        obs.provider = parser.getProvider();
        obs.model = parser.getModel();
        obs.endpoint = parser.getEndpoint();
        obs.hostCategory = parser.getHostCategory();

        return obs;
    }

    private void addDetailsToObservation(Observation obs, JsonObject details) {
        String summary = getStringOrNull(details, "summary");
        obs.summary = summary;

        // Re-parse with the summary available - it carries the endpoint that the
        // attackValue alone doesn't.
        AIUsageParser parser = new AIUsageParser(obs.attackValue, summary);
        obs.provider = parser.getProvider();
        obs.model = parser.getModel();
        obs.endpoint = parser.getEndpoint();
        obs.hostCategory = parser.getHostCategory();

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

        if (obs.stackTrace != null && !obs.stackTrace.isEmpty()) {
            String[] frames = obs.stackTrace.split("\n");
            if (frames.length > 0) {
                obs.callee = frames[0].trim();
            }
            if (frames.length > 1) {
                obs.caller = frames[1].trim();
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

        System.out.println("\nApplications with AI usage:");
        System.out.println("  ID                                      Name                                                     Observations");
        System.out.println("  ---------------------------------------- -------------------------------------------------------- ------------");
        for (Map.Entry<String, String> entry : appIdToName.entrySet()) {
            String appId = entry.getKey();
            String appName = entry.getValue();
            int count = appIdToCount.get(appId);
            System.out.printf("  %-40s %-56s %d%n", appId, appName, count);
        }
    }

    static class AIBOMResult {
        Bom bom;
        String resolvedAppName;
        AIBOMResult(Bom bom, String resolvedAppName) {
            this.bom = bom;
            this.resolvedAppName = resolvedAppName;
        }
    }

    public AIBOMResult generateAIBOM(List<Observation> observations, String appFilter) {
        System.out.println("\nGenerating AI-BOM" + (appFilter != null ? " for " + appFilter : " for all applications"));

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

        final String bomAppName = resolvedAppName != null ? resolvedAppName : appFilter;

        // Group observations by app, then by model (provider + model)
        Map<String, Map<String, List<Observation>>> byAppThenModel = new HashMap<>();
        Map<String, String> appIdToName = new HashMap<>();
        Set<String> allModelKeys = new HashSet<>();

        for (Observation obs : filtered) {
            if (obs.model == null || obs.model.isEmpty()) {
                continue;
            }
            String appKey = obs.applicationId != null ? obs.applicationId : obs.applicationName;
            if (appKey == null) {
                continue;
            }
            String modelKey = (obs.provider != null ? obs.provider : "unknown") + "/" + obs.model;
            byAppThenModel
                .computeIfAbsent(appKey, k -> new HashMap<>())
                .computeIfAbsent(modelKey, k -> new ArrayList<>())
                .add(obs);
            appIdToName.put(appKey, obs.applicationName);
            allModelKeys.add(modelKey);
        }

        System.out.println("  Found " + byAppThenModel.size() + " applications");
        System.out.println("  Found " + allModelKeys.size() + " unique AI models");

        Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID().toString());
        bom.setVersion(1);

        Metadata metadata = new Metadata();
        metadata.setTimestamp(new Date());

        Component rootComponent = new Component();
        rootComponent.setType(Component.Type.APPLICATION);
        rootComponent.setName(bomAppName != null ? bomAppName : "Contrast AI Usage Inventory");
        rootComponent.setVersion("1.0");
        rootComponent.setBomRef(bomAppName != null ? sanitizeBomRef(bomAppName) : "contrast-ai-inventory");
        metadata.setComponent(rootComponent);
        bom.setMetadata(metadata);

        List<Component> components = new ArrayList<>();
        List<Dependency> dependencies = new ArrayList<>();

        Map<String, String> modelBomRefs = new HashMap<>();
        for (String modelKey : allModelKeys) {
            List<Observation> allOccurrences = new ArrayList<>();
            for (Map<String, List<Observation>> appModels : byAppThenModel.values()) {
                List<Observation> obs = appModels.get(modelKey);
                if (obs != null) {
                    allOccurrences.addAll(obs);
                }
            }

            int rawCount = allOccurrences.isEmpty() ? 0 : getRawCount(allOccurrences.get(0).provider, allOccurrences.get(0).model);
            if (rawCount == 0) rawCount = allOccurrences.size();

            Component modelComponent = createModelComponent(modelKey, allOccurrences, rawCount);
            components.add(modelComponent);
            modelBomRefs.put(modelKey, modelComponent.getBomRef());
        }

        List<String> appBomRefs = new ArrayList<>();
        for (Map.Entry<String, Map<String, List<Observation>>> appEntry : byAppThenModel.entrySet()) {
            String appId = appEntry.getKey();
            String appName = appIdToName.get(appId);
            Map<String, List<Observation>> appModels = appEntry.getValue();

            Component appComponent = new Component();
            appComponent.setType(Component.Type.APPLICATION);
            appComponent.setName(appName != null ? appName : appId);
            appComponent.setBomRef("app-" + sanitizeBomRef(appName != null ? appName : appId));

            AppGraphInfo graphInfo = appGraphInfo.get(appId);
            if (graphInfo != null) {
                List<Property> appProps = new ArrayList<>();
                if (graphInfo.language != null) {
                    appProps.add(property("contrast:language", graphInfo.language));
                }
                if (graphInfo.postureScore != null) {
                    appProps.add(property("contrast:postureScore", String.valueOf(graphInfo.postureScore)));
                }
                if (graphInfo.postureSeverity != null) {
                    appProps.add(property("contrast:postureSeverity", graphInfo.postureSeverity));
                }
                if (graphInfo.criticality != null) {
                    appProps.add(property("contrast:criticality", String.valueOf(graphInfo.criticality)));
                }
                if (graphInfo.openIssuesTotal != null) {
                    appProps.add(property("contrast:openIssuesTotal", String.valueOf(graphInfo.openIssuesTotal)));
                }
                appProps.add(property("contrast:serverCount", String.valueOf(graphInfo.serverCount)));
                appProps.add(property("contrast:libraryCount", String.valueOf(graphInfo.libraryCount)));
                if (!graphInfo.connectedApplications.isEmpty()) {
                    appProps.add(property("contrast:connectedApplications", String.join(", ", graphInfo.connectedApplications)));
                }
                appComponent.setProperties(appProps);

                if (graphInfo.nodeId != null) {
                    appComponent.addExternalReference(buildAppExternalReference(appId, graphInfo.nodeId));
                }
            }

            components.add(appComponent);
            appBomRefs.add(appComponent.getBomRef());

            Dependency appDep = new Dependency(appComponent.getBomRef());
            for (String modelKey : appModels.keySet()) {
                String modelRef = modelBomRefs.get(modelKey);
                if (modelRef != null) {
                    appDep.addDependency(new Dependency(modelRef));
                }
            }
            dependencies.add(appDep);
        }

        if (appFilter == null && appBomRefs.size() > 1) {
            Dependency rootDep = new Dependency(rootComponent.getBomRef());
            for (String appRef : appBomRefs) {
                rootDep.addDependency(new Dependency(appRef));
            }
            dependencies.add(rootDep);
        } else if (appBomRefs.size() == 1) {
            Dependency rootDep = new Dependency(rootComponent.getBomRef());
            for (String modelRef : modelBomRefs.values()) {
                rootDep.addDependency(new Dependency(modelRef));
            }
            dependencies.add(rootDep);
        }

        bom.setComponents(components);
        bom.setDependencies(dependencies);

        System.out.println("  Created " + components.size() + " components (" +
                          byAppThenModel.size() + " apps + " + allModelKeys.size() + " AI models)");
        return new AIBOMResult(bom, resolvedAppName);
    }

    private Component createModelComponent(String modelKey, List<Observation> occurrences, int rawCount) {
        Observation sample = occurrences.get(0);

        Component component = new Component();
        component.setType(Component.Type.MACHINE_LEARNING_MODEL);
        component.setName(sample.model != null ? sample.model : modelKey);
        if (sample.provider != null) {
            component.setPublisher(sample.provider);
        }
        component.setBomRef("ai-" + sanitizeBomRef(modelKey));

        List<Property> properties = new ArrayList<>();
        properties.add(property("contrast:usageCount", String.valueOf(rawCount)));
        properties.add(property("contrast:uniqueLocations", String.valueOf(occurrences.size())));
        if (sample.provider != null) {
            properties.add(property("contrast:provider", sample.provider));
        }

        // Prefer a real observed endpoint/host category if any occurrence has one
        String endpoint = null;
        String hostCategory = "unknown";
        for (Observation obs : occurrences) {
            if (obs.endpoint != null && !obs.endpoint.isEmpty()) {
                endpoint = obs.endpoint;
                hostCategory = obs.hostCategory;
                break;
            }
        }
        if (endpoint != null) {
            properties.add(property("contrast:endpoint", endpoint));
        }
        properties.add(property("contrast:hostCategory", hostCategory));

        component.setProperties(properties);

        Evidence evidence = new Evidence();
        List<Occurrence> evidenceOccurrences = new ArrayList<>();

        Set<String> seen = new HashSet<>();
        for (Observation obs : occurrences) {
            String key = (obs.applicationId != null ? obs.applicationId : "") + "|"
                + (obs.caller != null ? obs.caller : "") + "|" + (obs.route != null ? obs.route : "");
            if (seen.add(key)) {
                Occurrence occ = new Occurrence();
                occ.setLocation(obs.callee != null ? obs.callee : obs.caller);

                StringBuilder context = new StringBuilder();
                if (obs.applicationName != null && !obs.applicationName.isEmpty()) {
                    context.append("App: ").append(obs.applicationName);
                }
                if (obs.route != null && !obs.route.isEmpty()) {
                    if (context.length() > 0) context.append(" | ");
                    context.append("Route: ").append(obs.route);
                }
                if (obs.stackTrace != null && !obs.stackTrace.isEmpty()) {
                    if (context.length() > 0) context.append("\n");
                    context.append("Stack Trace:\n").append(obs.stackTrace);
                } else if (obs.caller != null && !obs.caller.isEmpty()) {
                    if (context.length() > 0) context.append(" | ");
                    context.append("Caller: ").append(obs.caller);
                }
                if (context.length() > 0) {
                    occ.setAdditionalContext(context.toString());
                }

                evidenceOccurrences.add(occ);
            }
        }

        if (!evidenceOccurrences.isEmpty()) {
            evidence.setOccurrences(evidenceOccurrences);
            component.setEvidence(evidence);
        }

        return component;
    }

    private Property property(String name, String value) {
        Property p = new Property();
        p.setName(name);
        p.setValue(value);
        return p;
    }

    private ExternalReference buildAppExternalReference(String appId, String graphNodeId) {
        String uiBaseUrl = baseUrl.replaceAll("/api/.*", "");
        String url = uiBaseUrl + "/Contrast/cs/index.html#/" + orgId
            + "/explorer?detailsId=" + graphNodeId + "&applicationId=" + appId;

        ExternalReference ref = new ExternalReference();
        ref.setType(ExternalReference.Type.RUNTIME_ANALYSIS_REPORT);
        ref.setUrl(url);
        ref.setComment("Contrast Application Explorer");
        return ref;
    }

    private String sanitizeBomRef(String input) {
        return input.toLowerCase()
            .replaceAll("[^a-z0-9-]", "-")
            .replaceAll("-+", "-")
            .replaceAll("^-|-$", "");
    }

    public void writeAIBOM(Bom bom, String filename) throws Exception {
        System.out.println("\nWriting AI-BOM to " + filename);

        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
        String json = generator.toJsonString();

        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(json);
        }

        System.out.println("  Done!");

        int cloudModels = 0;
        int localModels = 0;
        int unknownHost = 0;
        if (bom.getComponents() != null) {
            for (Component c : bom.getComponents()) {
                if (c.getType() != Component.Type.MACHINE_LEARNING_MODEL || c.getProperties() == null) {
                    continue;
                }
                for (Property p : c.getProperties()) {
                    if ("contrast:hostCategory".equals(p.getName())) {
                        if ("cloud".equals(p.getValue())) cloudModels++;
                        else if ("local".equals(p.getValue())) localModels++;
                        else unknownHost++;
                    }
                }
            }
        }

        System.out.println("\n  Summary:");
        System.out.println("    Total AI models: " + (cloudModels + localModels + unknownHost));
        System.out.println("    Cloud/external provider: " + cloudModels);
        System.out.println("    Local/self-hosted: " + localModels);
        System.out.println("    Unknown host: " + unknownHost);
        System.out.println("\n  Output: " + filename);
    }

    static class Observation {
        String id;
        String attackValue;
        String summary;
        String eventTime;
        String route;
        String applicationId;
        String applicationName;
        String serverName;
        String environment;
        String provider;
        String model;
        String endpoint;
        String hostCategory;
        String caller;
        String callee;
        String stackTrace;
    }
}
