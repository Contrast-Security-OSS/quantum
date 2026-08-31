package com.contrastsecurity.quantum;

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
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Property;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Generates CycloneDX CBOM (Cryptography Bill of Materials) from Contrast API.
 *
 * Usage:
 *   java -jar quantum.jar cbom                      # Fetch all apps, output cbom.json
 *   java -jar quantum.jar cbom --app "AppName"      # Fetch single app
 *   java -jar quantum.jar cbom --list               # List available apps
 *   java -jar quantum.jar cbom -o custom.json       # Custom output filename
 *   java -jar quantum.jar cbom -c config.properties # Use custom config file
 *
 * Config file (contrast.properties):
 *   contrast.url=https://eval.contrastsecurity.com/api/ns-ui/v1
 *   contrast.org_id=your-org-id
 *   contrast.auth_header=base64-encoded-credentials
 *   contrast.api_key=your-api-key
 */
public class CBOMGenerator {

    private static final String CRYPTO_ALGORITHM_RULE_ID = "crypto-algorithm";

    private String baseUrl;
    private String orgId;
    private String authHeader;
    private String apiKey;
    private String envFilter; // PRODUCTION, DEVELOPMENT, QA, etc.

    private final Gson gson = new Gson();

    public void setEnvFilter(String env) {
        this.envFilter = env;
    }

    public CBOMGenerator(String configFile) throws IOException {
        loadConfig(configFile);
    }

    private void loadConfig(String configFile) throws IOException {
        Properties props = new Properties();

        // Load from specified file or contrast.properties in current directory
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
        String outputFile = "cbom.json";
        String configFile = null;
        boolean listOnly = false;
        boolean runAnalysis = false;

        // Parse args
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
            CBOMGenerator generator = new CBOMGenerator(configFile);
            generator.setEnvFilter(envFilter);
            List<Observation> observations = generator.fetchObservations();

            if (listOnly) {
                generator.listApplications(observations);
            } else {
                CBOMResult result = generator.generateCBOM(observations, appFilter);

                // Auto-name output file using resolved app name
                if (appFilter != null && "cbom.json".equals(outputFile)) {
                    String nameForFile = result.resolvedAppName != null ? result.resolvedAppName : appFilter;
                    String safeAppName = nameForFile.replaceAll("[^a-zA-Z0-9-_]", "_");
                    outputFile = "cbom-" + safeAppName + ".json";
                }

                generator.writeCBOM(result.bom, outputFile);

                // Run Quantum Advisor analysis if requested
                if (runAnalysis) {
                    generator.runQuantumAdvisor(outputFile);
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("\nCBOM Generator - Create CycloneDX CBOM from Contrast observations");
        System.out.println("\nUsage:");
        System.out.println("  java -jar quantum.jar cbom                    Generate CBOM for all apps");
        System.out.println("  java -jar quantum.jar cbom --app <id|name>    Filter by app (ID or name)");
        System.out.println("  java -jar quantum.jar cbom --env <tier>       Filter by environment (PRODUCTION, DEVELOPMENT, QA)");
        System.out.println("  java -jar quantum.jar cbom --list             List available applications with IDs");
        System.out.println("  java -jar quantum.jar cbom --analyze          Run Quantum Advisor AI analysis after CBOM generation");
        System.out.println("  java -jar quantum.jar cbom -o <file.json>     Specify output filename");
        System.out.println("  java -jar quantum.jar cbom -c <config.properties>  Use custom config file");
        System.out.println("\nConfig file (contrast.properties):");
        System.out.println("  contrast.url=https://eval.contrastsecurity.com/api/ns-ui/v1");
        System.out.println("  contrast.org_id=your-org-id");
        System.out.println("  contrast.auth_header=base64-encoded-credentials");
        System.out.println("  contrast.api_key=your-api-key");
        System.out.println("\nExamples:");
        System.out.println("  java -jar quantum.jar cbom                          # all apps -> cbom.json");
        System.out.println("  java -jar quantum.jar cbom --env PRODUCTION         # only prod observations");
        System.out.println("  java -jar quantum.jar cbom --app MyApp --env PRODUCTION");
        System.out.println("  java -jar quantum.jar cbom --analyze                # generate CBOM + AI analysis report");
        System.out.println("  java -jar quantum.jar cbom -c prod.properties --list");
    }

    /**
     * Run the Quantum Advisor Python tool to analyze the CBOM and generate an AI-powered
     * post-quantum cryptography readiness report.
     */
    private void runQuantumAdvisor(String cbomFile) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Running Quantum Advisor Analysis...");
        System.out.println("=".repeat(60));

        // Determine output filename (replace .json with -advisor.md)
        String advisorOutput = cbomFile.replace(".json", "-advisor.md");

        try {
            // Build the command
            ProcessBuilder pb = new ProcessBuilder(
                "python3",
                "tools/quantum_advisor.py",
                cbomFile,
                "--no-confirm",
                "-o", advisorOutput
            );

            pb.inheritIO(); // Show output in real-time
            pb.directory(new File(System.getProperty("user.dir")));

            Process process = pb.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                System.out.println("\nQuantum Advisor report written to: " + advisorOutput);
            } else {
                System.err.println("\nQuantum Advisor exited with code: " + exitCode);
            }
        } catch (IOException e) {
            System.err.println("\nFailed to run Quantum Advisor: " + e.getMessage());
            System.err.println("Make sure Python 3 is installed and tools/quantum_advisor.py exists");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("\nQuantum Advisor was interrupted");
        }
    }

    // Track raw counts per algorithm before deduplication
    private Map<String, Integer> algorithmRawCounts = new HashMap<>();

    // Application-level architecture/connection info from the Contrast graph, keyed by applicationId
    private Map<String, AppGraphInfo> appGraphInfo = new HashMap<>();

    public List<Observation> fetchObservations() throws IOException {
        System.out.println("\nFetching observations from Contrast API...");

        algorithmRawCounts.clear();

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            // Fetch list of observations
            JsonArray observationList = fetchObservationsList(httpClient);
            System.out.println("  Found " + observationList.size() + " total observations");

            // First pass: parse basic info, filter, count, and deduplicate
            // Dedup key: algorithm + applicationId + route (before fetching details)
            Map<String, Observation> uniqueObservations = new HashMap<>();
            Set<String> environmentsSeen = new HashSet<>();
            int skipped = 0;

            int nonCrypto = 0;
            for (JsonElement element : observationList) {
                JsonObject obs = element.getAsJsonObject();

                // The observations endpoint returns all OBSERVABILITY data (crypto, AI usage, etc.)
                // so filter client-side to just crypto algorithm findings.
                String ruleId = getStringOrNull(obs, "ruleId");
                if (!CRYPTO_ALGORITHM_RULE_ID.equals(ruleId)) {
                    nonCrypto++;
                    continue;
                }

                Observation observation = parseObservationFromList(obs);

                // Filter by environment if specified
                if (envFilter != null && !envFilter.equals(observation.environment)) {
                    skipped++;
                    continue;
                }

                if (observation.environment != null) {
                    environmentsSeen.add(observation.environment);
                }

                // Track raw count per algorithm (before dedup)
                if (observation.algorithm != null) {
                    algorithmRawCounts.merge(observation.algorithm, 1, Integer::sum);
                }

                // Deduplicate by algorithm + app + route
                String dedupKey = observation.algorithm + "|" + observation.applicationId + "|" + observation.route;
                if (!uniqueObservations.containsKey(dedupKey)) {
                    uniqueObservations.put(dedupKey, observation);
                }
            }

            System.out.println("  Filtered to " + (observationList.size() - nonCrypto) + " crypto algorithm observations");
            if (skipped > 0) {
                System.out.println("  Filtered to " + (observationList.size() - nonCrypto - skipped) + " (env: " + envFilter + ")");
            }
            System.out.println("  Deduplicated to " + uniqueObservations.size() + " unique observations");

            // Second pass: fetch details only for unique observations
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

    public int getRawCount(String algorithm) {
        return algorithmRawCounts.getOrDefault(algorithm, 0);
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
        obs.algorithm = getStringOrNull(listItem, "attackValue");
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

        if (obs.stackTrace != null && !obs.stackTrace.isEmpty()) {
            String[] frames = obs.stackTrace.split("\n");
            if (frames.length > 0) {
                obs.callee = frames[0].trim();
                obs.normalizedCallee = normalizeStackFrame(obs.callee);
            }
            if (frames.length > 1) {
                obs.caller = frames[1].trim();
                obs.normalizedCaller = normalizeStackFrame(obs.caller);
            }
        }
    }

    private String normalizeStackFrame(String frame) {
        if (frame == null) return null;
        int openParen = frame.indexOf('(');
        if (openParen != -1) {
            return frame.substring(0, openParen);
        }
        return frame;
    }

    private String getStringOrNull(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return null;
    }

    public void listApplications(List<Observation> observations) {
        // Map app ID to name and count
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

    // Result wrapper for generateCBOM
    static class CBOMResult {
        Bom bom;
        String resolvedAppName;
        CBOMResult(Bom bom, String resolvedAppName) {
            this.bom = bom;
            this.resolvedAppName = resolvedAppName;
        }
    }

    public CBOMResult generateCBOM(List<Observation> observations, String appFilter) {
        System.out.println("\nGenerating CBOM" + (appFilter != null ? " for " + appFilter : " for all applications"));

        // Filter observations by app if specified (match by ID or name)
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

        // Use resolved app name for CBOM metadata if filtering by ID
        final String cbomAppName = resolvedAppName != null ? resolvedAppName : appFilter;

        // Group observations by app, then by algorithm
        Map<String, Map<String, List<Observation>>> byAppThenAlgorithm = new HashMap<>();
        Map<String, String> appIdToName = new HashMap<>();
        Set<String> allAlgorithms = new HashSet<>();

        for (Observation obs : filtered) {
            if (obs.algorithm != null && !obs.algorithm.isEmpty()) {
                String appKey = obs.applicationId != null ? obs.applicationId : obs.applicationName;
                if (appKey != null) {
                    byAppThenAlgorithm
                        .computeIfAbsent(appKey, k -> new HashMap<>())
                        .computeIfAbsent(obs.algorithm, k -> new ArrayList<>())
                        .add(obs);
                    appIdToName.put(appKey, obs.applicationName);
                    allAlgorithms.add(obs.algorithm);
                }
            }
        }

        System.out.println("  Found " + byAppThenAlgorithm.size() + " applications");
        System.out.println("  Found " + allAlgorithms.size() + " unique algorithms");

        // Create BOM
        Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID().toString());
        bom.setVersion(1);

        // Create metadata
        Metadata metadata = new Metadata();
        metadata.setTimestamp(new Date());

        Component rootComponent = new Component();
        rootComponent.setType(Component.Type.APPLICATION);
        rootComponent.setName(cbomAppName != null ? cbomAppName : "Contrast Crypto Inventory");
        rootComponent.setVersion("1.0");
        rootComponent.setBomRef(cbomAppName != null ? sanitizeBomRef(cbomAppName) : "contrast-crypto-inventory");
        metadata.setComponent(rootComponent);
        bom.setMetadata(metadata);

        List<Component> components = new ArrayList<>();
        List<Dependency> dependencies = new ArrayList<>();

        // Create crypto components for each unique algorithm
        Map<String, String> algoBomRefs = new HashMap<>();
        for (String algorithm : allAlgorithms) {
            // Collect all observations for this algorithm across all apps
            List<Observation> allOccurrences = new ArrayList<>();
            for (Map<String, List<Observation>> appAlgos : byAppThenAlgorithm.values()) {
                List<Observation> obs = appAlgos.get(algorithm);
                if (obs != null) {
                    allOccurrences.addAll(obs);
                }
            }

            int rawCount = algorithmRawCounts.getOrDefault(algorithm, allOccurrences.size());
            Component cryptoComponent = createCryptoComponent(algorithm, allOccurrences, rawCount);
            components.add(cryptoComponent);
            algoBomRefs.put(algorithm, cryptoComponent.getBomRef());
        }

        // Create app components and their dependencies on crypto
        List<String> appBomRefs = new ArrayList<>();
        for (Map.Entry<String, Map<String, List<Observation>>> appEntry : byAppThenAlgorithm.entrySet()) {
            String appId = appEntry.getKey();
            String appName = appIdToName.get(appId);
            Map<String, List<Observation>> appAlgorithms = appEntry.getValue();

            // Create app component
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

            // Create dependency: app -> crypto algorithms it uses
            Dependency appDep = new Dependency(appComponent.getBomRef());
            for (String algo : appAlgorithms.keySet()) {
                String cryptoRef = algoBomRefs.get(algo);
                if (cryptoRef != null) {
                    appDep.addDependency(new Dependency(cryptoRef));
                }
            }
            dependencies.add(appDep);
        }

        // Root component depends on all apps (only if multiple apps)
        if (appFilter == null && appBomRefs.size() > 1) {
            Dependency rootDep = new Dependency(rootComponent.getBomRef());
            for (String appRef : appBomRefs) {
                rootDep.addDependency(new Dependency(appRef));
            }
            dependencies.add(rootDep);
        } else if (appBomRefs.size() == 1) {
            // Single app - root depends directly on crypto
            Dependency rootDep = new Dependency(rootComponent.getBomRef());
            for (String cryptoRef : algoBomRefs.values()) {
                rootDep.addDependency(new Dependency(cryptoRef));
            }
            dependencies.add(rootDep);
        }

        bom.setComponents(components);
        bom.setDependencies(dependencies);

        System.out.println("  Created " + components.size() + " components (" +
                          byAppThenAlgorithm.size() + " apps + " + allAlgorithms.size() + " crypto)");
        return new CBOMResult(bom, resolvedAppName);
    }

    private Component createCryptoComponent(String algorithm, List<Observation> occurrences, int rawCount) {
        AlgorithmParser parser = new AlgorithmParser(algorithm);

        Component component = new Component();
        component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        component.setName(algorithm);
        component.setBomRef("crypto-" + sanitizeBomRef(algorithm));

        // Add usage count as custom property
        List<Property> properties = new ArrayList<>();
        Property usageCount = new Property();
        usageCount.setName("contrast:usageCount");
        usageCount.setValue(String.valueOf(rawCount));
        properties.add(usageCount);

        Property uniqueLocations = new Property();
        uniqueLocations.setName("contrast:uniqueLocations");
        uniqueLocations.setValue(String.valueOf(occurrences.size()));
        properties.add(uniqueLocations);

        component.setProperties(properties);

        CryptoProperties cryptoProps = new CryptoProperties();
        cryptoProps.setAssetType(AssetType.ALGORITHM);

        if (parser.getOid() != null) {
            cryptoProps.setOid(parser.getOid());
        }

        AlgorithmProperties algoProps = new AlgorithmProperties();

        Primitive primitive = mapPrimitive(parser.getPrimitive());
        if (primitive != null) {
            algoProps.setPrimitive(primitive);
        }

        Mode mode = mapMode(parser.getMode());
        if (mode != null) {
            algoProps.setMode(mode);
        }

        Padding padding = mapPadding(parser.getPadding());
        if (padding != null) {
            algoProps.setPadding(padding);
        }

        if (parser.getClassicalSecurityLevel() > 0) {
            algoProps.setClassicalSecurityLevel(parser.getClassicalSecurityLevel());
        }
        algoProps.setNistQuantumSecurityLevel(parser.getNistQuantumSecurityLevel());

        List<CryptoFunction> functions = getCryptoFunctions(parser.getPrimitive());
        if (!functions.isEmpty()) {
            algoProps.setCryptoFunctions(functions);
        }

        if (parser.getKeySize() > 0) {
            algoProps.setParameterSetIdentifier(String.valueOf(parser.getKeySize()));
        }

        cryptoProps.setAlgorithmProperties(algoProps);
        component.setCryptoProperties(cryptoProps);

        // Add evidence
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

    private Primitive mapPrimitive(String primitive) {
        if (primitive == null) return Primitive.UNKNOWN;
        switch (primitive.toLowerCase()) {
            case "ae": return Primitive.AE;
            case "block-cipher": return Primitive.BLOCK_CIPHER;
            case "stream-cipher": return Primitive.STREAM_CIPHER;
            case "hash": return Primitive.HASH;
            case "mac": return Primitive.MAC;
            case "pke": return Primitive.PKE;
            case "signature": return Primitive.SIGNATURE;
            case "kex":
            case "key-agree": return Primitive.KEY_AGREE;
            case "kem": return Primitive.KEM;
            case "kdf": return Primitive.KDF;
            case "xof": return Primitive.XOF;
            case "drbg": return Primitive.DRBG;
            default: return Primitive.UNKNOWN;
        }
    }

    private Mode mapMode(String mode) {
        if (mode == null) return null;
        switch (mode.toLowerCase()) {
            case "gcm": return Mode.GCM;
            case "cbc": return Mode.CBC;
            case "ecb": return Mode.ECB;
            case "ctr": return Mode.CTR;
            case "cfb": return Mode.CFB;
            case "ofb": return Mode.OFB;
            case "ccm": return Mode.CCM;
            default: return Mode.OTHER;
        }
    }

    private Padding mapPadding(String padding) {
        if (padding == null) return null;
        switch (padding.toLowerCase()) {
            case "pkcs5": return Padding.PKCS5;
            case "pkcs7": return Padding.PKCS7;
            case "pkcs1v15": return Padding.PKCS1V15;
            case "oaep": return Padding.OAEP;
            case "none":
            case "nopadding": return Padding.RAW;
            default: return Padding.OTHER;
        }
    }

    private List<CryptoFunction> getCryptoFunctions(String primitive) {
        List<CryptoFunction> functions = new ArrayList<>();
        if (primitive == null) return functions;

        switch (primitive.toLowerCase()) {
            case "ae":
            case "block-cipher":
            case "stream-cipher":
                functions.add(CryptoFunction.ENCRYPT);
                functions.add(CryptoFunction.DECRYPT);
                functions.add(CryptoFunction.KEYGEN);
                break;
            case "hash":
                functions.add(CryptoFunction.DIGEST);
                break;
            case "mac":
                functions.add(CryptoFunction.TAG);
                functions.add(CryptoFunction.VERIFY);
                functions.add(CryptoFunction.KEYGEN);
                break;
            case "signature":
                functions.add(CryptoFunction.SIGN);
                functions.add(CryptoFunction.VERIFY);
                functions.add(CryptoFunction.KEYGEN);
                break;
            case "pke":
                functions.add(CryptoFunction.ENCRYPT);
                functions.add(CryptoFunction.DECRYPT);
                functions.add(CryptoFunction.KEYGEN);
                break;
            case "kex":
            case "key-agree":
                functions.add(CryptoFunction.KEYDERIVE);
                functions.add(CryptoFunction.KEYGEN);
                break;
            case "kem":
                functions.add(CryptoFunction.ENCAPSULATE);
                functions.add(CryptoFunction.DECAPSULATE);
                functions.add(CryptoFunction.KEYGEN);
                break;
            case "kdf":
                functions.add(CryptoFunction.KEYDERIVE);
                break;
        }
        return functions;
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

    public void writeCBOM(Bom bom, String filename) throws Exception {
        System.out.println("\nWriting CBOM to " + filename);

        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_16, bom);
        String json = generator.toJsonString();

        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(json);
        }

        System.out.println("  Done!");

        // Print summary
        int quantumVulnerable = 0;
        int quantumSafe = 0;
        if (bom.getComponents() != null) {
            for (Component c : bom.getComponents()) {
                if (c.getCryptoProperties() != null &&
                    c.getCryptoProperties().getAlgorithmProperties() != null) {
                    Integer level = c.getCryptoProperties().getAlgorithmProperties().getNistQuantumSecurityLevel();
                    if (level != null && level == 0) {
                        quantumVulnerable++;
                    } else {
                        quantumSafe++;
                    }
                }
            }
        }

        System.out.println("\n  Summary:");
        System.out.println("    Total algorithms: " + (bom.getComponents() != null ? bom.getComponents().size() : 0));
        System.out.println("    Quantum vulnerable: " + quantumVulnerable);
        System.out.println("    Quantum safe: " + quantumSafe);
        System.out.println("\n  Output: " + filename);
    }

    // Observation class for holding fetched data
    static class Observation {
        String id;
        String algorithm;
        String eventTime;
        String route;
        String applicationId;
        String applicationName;
        String serverName;
        String environment;
        String caller;
        String callee;
        String stackTrace;
        String normalizedCallee;
        String normalizedCaller;

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
            result = prime * result + ((route == null) ? 0 : route.hashCode());
            result = prime * result + ((normalizedCallee == null) ? 0 : normalizedCallee.hashCode());
            result = prime * result + ((normalizedCaller == null) ? 0 : normalizedCaller.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            Observation other = (Observation) obj;

            if (algorithm == null) {
                if (other.algorithm != null) return false;
            } else if (!algorithm.equals(other.algorithm)) return false;

            if (route == null) {
                if (other.route != null) return false;
            } else if (!route.equals(other.route)) return false;

            if (normalizedCallee == null) {
                if (other.normalizedCallee != null) return false;
            } else if (!normalizedCallee.equals(other.normalizedCallee)) return false;

            if (normalizedCaller == null) {
                if (other.normalizedCaller != null) return false;
            } else if (!normalizedCaller.equals(other.normalizedCaller)) return false;

            return true;
        }
    }
}
