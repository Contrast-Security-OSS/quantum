package com.contrastsecurity.quantum;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

/**
 * Shells out to the `claude` CLI (already logged in to this shell) for AI calls,
 * with cost/token tracking. No separate API key or AWS/Bedrock credentials needed -
 * just requires `claude` to be on PATH and authenticated.
 */
public class ClaudeClient {

    public static class TokenUsage {
        public int inputTokens;
        public int outputTokens;
        public double costUsd;
    }

    private static final int MAX_RETRIES = 5;
    private static final int TIMEOUT_SECONDS = 180;

    private final Gson gson = new Gson();
    private int totalCalls = 0;
    private long totalInputTokens = 0;
    private long totalOutputTokens = 0;
    private double totalCost = 0.0;

    /**
     * Make an AI call. prompt is the system/instruction prompt, content is the user turn.
     */
    public String call(String prompt, String content, TokenUsage usageOut) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add("claude");
        cmd.add("-p");
        cmd.add("--system-prompt");
        cmd.add(prompt);
        cmd.add("--disallowed-tools");
        cmd.add("*");
        cmd.add("--output-format");
        cmd.add("json");
        cmd.add(content != null && !content.isEmpty() ? content : prompt);

        Exception lastError = null;

        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            try {
                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.redirectErrorStream(false);
                Process process = pb.start();

                String stdout = readStream(process.getInputStream());
                String stderr = readStream(process.getErrorStream());

                boolean finished = process.waitFor(TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS);
                if (!finished) {
                    process.destroyForcibly();
                    throw new IOException("claude CLI timed out after " + TIMEOUT_SECONDS + "s");
                }

                if (process.exitValue() != 0) {
                    throw new IOException("claude CLI exited " + process.exitValue() + ": " + truncate(stderr, 500));
                }

                JsonObject data = gson.fromJson(stdout, JsonObject.class);
                if (data == null) {
                    throw new IOException("claude CLI returned no output");
                }
                if (data.has("is_error") && data.get("is_error").getAsBoolean()) {
                    String result = data.has("result") ? data.get("result").toString() : "unknown error";
                    throw new IOException("claude CLI error: " + truncate(result, 500));
                }

                TokenUsage usage = new TokenUsage();
                if (data.has("usage") && data.get("usage").isJsonObject()) {
                    JsonObject u = data.getAsJsonObject("usage");
                    usage.inputTokens = getInt(u, "input_tokens");
                    usage.outputTokens = getInt(u, "output_tokens");
                }
                usage.costUsd = data.has("total_cost_usd") ? data.get("total_cost_usd").getAsDouble() : 0.0;

                totalCalls++;
                totalInputTokens += usage.inputTokens;
                totalOutputTokens += usage.outputTokens;
                totalCost += usage.costUsd;

                if (usageOut != null) {
                    usageOut.inputTokens = usage.inputTokens;
                    usageOut.outputTokens = usage.outputTokens;
                    usageOut.costUsd = usage.costUsd;
                }

                return data.has("result") && !data.get("result").isJsonNull() ? data.get("result").getAsString() : "";

            } catch (IOException e) {
                lastError = e;
                String message = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
                boolean transient_ = message.contains("throttl") || message.contains("rate")
                    || message.contains("overload") || message.contains("timed out");
                if (transient_ && attempt < MAX_RETRIES - 1) {
                    Thread.sleep((long) (Math.pow(2, attempt) * 1000 + Math.random() * 1000));
                    continue;
                }
                throw e;
            }
        }

        throw new IOException("Max retries exceeded", lastError);
    }

    private static String readStream(java.io.InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    private static int getInt(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsInt() : 0;
    }

    private static String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) : s;
    }

    /** Rough pre-task cost estimate; actual cost may be $0 under a subscription plan. */
    public double estimateCost(int numItems, int avgInputTokens, int avgOutputTokens) {
        double inputCost = (numItems * (double) avgInputTokens / 1_000_000) * 3.00;
        double outputCost = (numItems * (double) avgOutputTokens / 1_000_000) * 15.00;
        return inputCost + outputCost;
    }

    /** Prompt the user to confirm if the estimated cost exceeds the threshold. Returns true to proceed. */
    public static boolean confirmCost(double estimatedCost, int numItems, boolean noConfirm) {
        if (noConfirm || estimatedCost < 0.50) {
            return true;
        }
        System.out.println("\n[COST ESTIMATE]");
        System.out.println("  Items to process: " + numItems);
        System.out.printf("  Estimated cost:   $%.2f (ballpark - actual may be $0 under a subscription plan)%n", estimatedCost);

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("\nProceed? [y/n]: ");
            String choice = scanner.nextLine().trim().toLowerCase();
            if (choice.equals("y") || choice.equals("yes")) return true;
            if (choice.equals("n") || choice.equals("no")) return false;
            System.out.println("Please enter 'y' or 'n'");
        }
    }

    public void printSummary() {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("AI Usage Summary");
        System.out.println("=".repeat(50));
        System.out.println("  Calls:         " + totalCalls);
        System.out.println("  Input tokens:  " + totalInputTokens);
        System.out.println("  Output tokens: " + totalOutputTokens);
        System.out.printf("  Total cost:    $%.4f%n", totalCost);
    }
}
