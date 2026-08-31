package com.contrastsecurity.bomsquad;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Fetches the Contrast architecture graph (applications, servers, libraries, and their
 * connections) via the contrast-graph API, so a BOM can describe what an application
 * actually is and what it's connected to, not just which algorithm/model it uses.
 *
 * Shared by CBOMGenerator and AIBOMGenerator.
 */
public class ApplicationGraphFetcher {

    private ApplicationGraphFetcher() {
    }

    public static Map<String, AppGraphInfo> fetch(
            CloseableHttpClient httpClient,
            Gson gson,
            String baseUrl,
            String orgId,
            String authHeader,
            String apiKey,
            Set<String> environments) throws IOException {

        String url = baseUrl.replace("/ns-ui/v1", "/v2") + "/organizations/" + orgId + "/contrast-graph";
        HttpPost post = new HttpPost(url);

        post.setHeader("Authorization", authHeader);
        post.setHeader("API-Key", apiKey);
        post.setHeader("Content-Type", "application/json");
        post.setHeader("Accept", "application/json");

        JsonArray envArray = new JsonArray();
        for (String env : environments) {
            envArray.add(env);
        }

        JsonObject filters = new JsonObject();
        JsonArray nodeTypes = new JsonArray();
        for (String t : new String[]{"APPLICATION", "SERVER", "API", "DATABASE", "LIBRARY"}) {
            nodeTypes.add(t);
        }
        filters.add("nodeTypes", nodeTypes);
        filters.addProperty("naturalSearch", "");
        filters.add("languages", new JsonArray());
        filters.add("applications", new JsonArray());
        filters.add("repositories", new JsonArray());
        filters.add("openIssueSeverities", new JsonArray());
        filters.add("openIncidentSeverities", new JsonArray());
        filters.add("environments", envArray);
        filters.addProperty("includeStaticOnly", false);
        filters.addProperty("isArchived", false);

        JsonObject body = new JsonObject();
        body.add("filters", filters);

        post.setEntity(new StringEntity(gson.toJson(body)));

        HttpResponse response = httpClient.execute(post);
        int statusCode = response.getStatusLine().getStatusCode();
        String responseBody = EntityUtils.toString(response.getEntity());

        if (statusCode != 200) {
            throw new IOException("graph API returned status " + statusCode);
        }

        JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
        if (jsonResponse == null || !jsonResponse.has("nodes")) {
            throw new IOException("invalid graph API response");
        }

        JsonArray nodes = jsonResponse.getAsJsonArray("nodes");
        JsonArray edges = jsonResponse.has("edges") ? jsonResponse.getAsJsonArray("edges") : new JsonArray();

        Map<String, JsonObject> nodesByGraphId = new HashMap<>();
        Map<String, String> graphIdToAppId = new HashMap<>();
        Map<String, AppGraphInfo> result = new HashMap<>();

        for (JsonElement el : nodes) {
            JsonObject node = el.getAsJsonObject();
            String graphId = getStringOrNull(node, "id");
            if (graphId != null) {
                nodesByGraphId.put(graphId, node);
            }
            if ("APPLICATION".equals(getStringOrNull(node, "nodeType"))) {
                String appId = getStringOrNull(node, "applicationId");
                if (appId != null && graphId != null) {
                    graphIdToAppId.put(graphId, appId);

                    AppGraphInfo info = new AppGraphInfo();
                    info.nodeId = graphId;
                    info.language = getStringOrNull(node, "language");
                    if (node.has("postureScore") && node.get("postureScore").isJsonObject()) {
                        JsonObject posture = node.getAsJsonObject("postureScore");
                        if (posture.has("score") && !posture.get("score").isJsonNull()) {
                            info.postureScore = posture.get("score").getAsDouble();
                        }
                        info.postureSeverity = getStringOrNull(posture, "severity");
                    }
                    if (node.has("criticality") && node.get("criticality").isJsonObject()) {
                        JsonObject crit = node.getAsJsonObject("criticality");
                        if (crit.has("value") && !crit.get("value").isJsonNull()) {
                            info.criticality = crit.get("value").getAsInt();
                        }
                    }
                    if (node.has("issuesSeverityCount") && node.get("issuesSeverityCount").isJsonObject()) {
                        JsonObject issues = node.getAsJsonObject("issuesSeverityCount");
                        if (issues.has("totalCount") && !issues.get("totalCount").isJsonNull()) {
                            info.openIssuesTotal = issues.get("totalCount").getAsInt();
                        }
                    }
                    result.put(appId, info);
                }
            }
        }

        for (JsonElement el : edges) {
            JsonObject edge = el.getAsJsonObject();
            String source = getStringOrNull(edge, "source");
            String target = getStringOrNull(edge, "target");
            if (source == null || target == null) continue;

            String sourceAppId = graphIdToAppId.get(source);
            String targetAppId = graphIdToAppId.get(target);

            if (sourceAppId != null && targetAppId != null) {
                addConnection(result, sourceAppId, appNameFor(nodesByGraphId, target));
                addConnection(result, targetAppId, appNameFor(nodesByGraphId, source));
                continue;
            }

            if (sourceAppId != null) {
                tallyCluster(result, sourceAppId, nodesByGraphId.get(target));
            } else if (targetAppId != null) {
                tallyCluster(result, targetAppId, nodesByGraphId.get(source));
            }
        }

        return result;
    }

    private static String appNameFor(Map<String, JsonObject> nodesByGraphId, String graphId) {
        JsonObject node = nodesByGraphId.get(graphId);
        if (node == null) return graphId;
        String name = getStringOrNull(node, "name");
        return name != null ? name : graphId;
    }

    private static void addConnection(Map<String, AppGraphInfo> result, String appId, String connectedName) {
        AppGraphInfo info = result.get(appId);
        if (info != null && connectedName != null) {
            info.connectedApplications.add(connectedName);
        }
    }

    private static void tallyCluster(Map<String, AppGraphInfo> result, String appId, JsonObject clusterNode) {
        if (clusterNode == null) return;
        AppGraphInfo info = result.get(appId);
        if (info == null) return;

        String nodeType = getStringOrNull(clusterNode, "nodeType");
        if ("SERVER_CLUSTER".equals(nodeType)) {
            if (clusterNode.has("count") && !clusterNode.get("count").isJsonNull()) {
                info.serverCount += clusterNode.get("count").getAsInt();
            }
        } else if ("LIBRARY_CLUSTER".equals(nodeType)) {
            if (clusterNode.has("totalCount") && !clusterNode.get("totalCount").isJsonNull()) {
                info.libraryCount += clusterNode.get("totalCount").getAsInt();
            }
        }
    }

    private static String getStringOrNull(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return null;
    }
}
