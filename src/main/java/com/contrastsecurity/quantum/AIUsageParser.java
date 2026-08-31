package com.contrastsecurity.quantum;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses AI/LLM usage observations from Contrast (ruleId "ai-usage") into
 * structured AI-BOM-compatible properties: provider, model, endpoint, and
 * whether the endpoint is a known external cloud vendor or a local/self-hosted
 * deployment.
 */
public class AIUsageParser {

    private static final Pattern MODEL_PATTERN = Pattern.compile("model `([^`]+)`");
    private static final Pattern PROVIDER_PATTERN = Pattern.compile("provider `([^`]+)`");
    private static final Pattern ENDPOINT_PATTERN = Pattern.compile("provider `[^`]+` \\(`([^`]+)`\\)");

    private final String rawAttackValue;
    private String provider;
    private String model;
    private String endpoint;
    private String hostCategory; // "cloud", "local", "unknown"

    public AIUsageParser(String attackValue, String summary) {
        this.rawAttackValue = attackValue;
        parse(attackValue, summary);
    }

    private void parse(String attackValue, String summary) {
        if (summary != null) {
            Matcher modelMatcher = MODEL_PATTERN.matcher(summary);
            if (modelMatcher.find()) {
                model = modelMatcher.group(1);
            }
            Matcher providerMatcher = PROVIDER_PATTERN.matcher(summary);
            if (providerMatcher.find()) {
                provider = providerMatcher.group(1);
            }
            Matcher endpointMatcher = ENDPOINT_PATTERN.matcher(summary);
            if (endpointMatcher.find()) {
                endpoint = endpointMatcher.group(1);
            }
        }

        // Fall back to "<provider> <model>" from the attackValue (e.g. "openai smollm2:135m-tuned")
        if ((provider == null || model == null) && attackValue != null) {
            int spaceIdx = attackValue.indexOf(' ');
            if (spaceIdx > 0) {
                if (provider == null) provider = attackValue.substring(0, spaceIdx);
                if (model == null) model = attackValue.substring(spaceIdx + 1);
            } else if (model == null) {
                model = attackValue;
            }
        }

        hostCategory = classifyHost(endpoint);
    }

    private String classifyHost(String endpointUrl) {
        if (endpointUrl == null || endpointUrl.isEmpty()) {
            return "unknown";
        }
        String lower = endpointUrl.toLowerCase();
        if (lower.contains("localhost") || lower.contains("127.0.0.1") || lower.contains("ollama")
                || lower.matches(".*://10\\..*") || lower.matches(".*://192\\.168\\..*")
                || lower.matches(".*://172\\.(1[6-9]|2[0-9]|3[0-1])\\..*")) {
            return "local";
        }
        if (lower.contains("api.openai.com") || lower.contains("anthropic.com")
                || lower.contains("googleapis.com") || lower.contains("azure.com")
                || lower.contains("amazonaws.com") || lower.contains("bedrock")
                || lower.contains("cohere.ai") || lower.contains("mistral.ai")
                || lower.contains("huggingface.co")) {
            return "cloud";
        }
        return "unknown";
    }

    public String getRawAttackValue() {
        return rawAttackValue;
    }

    public String getProvider() {
        return provider;
    }

    public String getModel() {
        return model;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getHostCategory() {
        return hostCategory;
    }
}
