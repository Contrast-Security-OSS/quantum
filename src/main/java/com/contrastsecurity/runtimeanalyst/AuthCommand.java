package com.contrastsecurity.runtimeanalyst;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code auth}: sets up contrast.properties by driving a real, visible browser through the
 * user's own login (including SSO/MFA), then reading their personal API key/service key/org id
 * straight off the User Settings > Your Keys page's DOM - no manual copy/paste, and the tool
 * never sees or stores a session cookie.
 *
 * The visible browser is used only for login. Once the org UUID appears in TeamServer's SPA
 * hash route (#/&lt;orgId&gt;/...), its session cookies are exported and the visible browser is
 * closed immediately - the account-page navigation and DOM scraping happen in a second, genuinely
 * headless browser reusing those cookies, so nothing past the login screen itself ever renders
 * on screen. (Earlier attempts to hide the same visible window via OS-level minimize/reposition
 * tricks were unreliable - Chromium's automation-driven navigate() re-activates a minimized
 * window, and macOS clamps windows to always keep part of them on screen - so this avoids that
 * class of problem entirely instead of chasing it further.)
 */
public class AuthCommand {

    private static final Pattern UUID_IN_FRAGMENT =
            Pattern.compile("#/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");

    public static void main(String[] args) {
        String host = null;
        String outputPath = "contrast.properties";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host":
                    host = args[++i];
                    break;
                case "-o":
                    outputPath = args[++i];
                    break;
                case "-h":
                case "--help":
                    printUsage();
                    return;
                default:
                    System.err.println("Unknown option: " + args[i]);
                    printUsage();
                    System.exit(1);
            }
        }

        String loginUrl = (host != null ? host : "https://cs004.contrastsecurity.com") + "/login";

        System.out.println("Opening a browser window - log in (or complete SSO/MFA) the same way you normally would.");
        System.out.println("The window will close as soon as you're logged in; the rest happens in the background.\n");

        try (Playwright playwright = Playwright.create()) {
            String orgId;
            String resolvedHost;
            String storageState;

            try (Browser loginBrowser = launchChromium(playwright, false)) {
                BrowserContext context = loginBrowser.newContext();
                context.newPage().navigate(loginUrl);

                LoggedInPage found = waitForOrgIdAcrossPages(loginBrowser);
                orgId = extractOrgId(found.url());
                resolvedHost = hostFrom(found.url());
                storageState = found.page().context().storageState();
                System.out.println("Logged in - organization " + orgId + " on " + resolvedHost);
            }

            String username;
            String apiKey;
            String serviceKey;
            try (Browser scrapeBrowser = launchChromium(playwright, true)) {
                BrowserContext context = scrapeBrowser.newContext(
                        new Browser.NewContextOptions().setStorageState(storageState));
                Page page = context.newPage();
                page.navigate(resolvedHost + "/Contrast/static/ng/index.html#/" + orgId + "/account");
                page.waitForSelector("[data-testid='service-key-code-block-code']");

                username = page.locator("[data-e2e='contrast-username']").innerText().trim();
                apiKey = page.locator("[data-testid='api-key-code-block-code']").innerText().trim();
                serviceKey = page.locator("[data-testid='service-key-code-block-code']").innerText().trim();
            }

            String authHeader = Base64.getEncoder().encodeToString(
                    (username + ":" + serviceKey).getBytes(StandardCharsets.UTF_8));

            System.out.println("Got your keys for " + username + ". Verifying against Contrast...");
            verifyCredentials(resolvedHost, authHeader, apiKey);

            writeConfig(outputPath, resolvedHost, orgId, authHeader, apiKey);
            System.out.println("\nWrote " + outputPath + ". You're ready to run cbom/aibom/blueprint.");
        } catch (Exception e) {
            System.err.println("Auth failed: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Playwright's Java library is bundled in this jar, but the actual Chromium binary it drives
     * (~150-300MB) isn't - it has to exist on disk separately. Rather than making a first-time
     * user run a separate install command themselves, download it automatically and transparently
     * the first time it's missing, then retry.
     */
    private static Browser launchChromium(Playwright playwright, boolean headless) throws Exception {
        try {
            return playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(headless));
        } catch (Exception firstAttempt) {
            System.out.println("Chromium isn't installed yet - downloading it now (one-time, ~150MB)...");
            installChromium();
            return playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(headless));
        }
    }

    /**
     * Runs Playwright's browser installer in a separate JVM, not in-process - CLI.main() calls
     * System.exit() internally (confirmed directly: code after the call never ran), which would
     * kill this whole auth run right after installing, before ever getting to actually launch
     * the browser it just downloaded.
     */
    private static void installChromium() throws Exception {
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
        String jarPath = new File(AuthCommand.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getAbsolutePath();
        Process installer = new ProcessBuilder(javaBin, "-cp", jarPath, "com.microsoft.playwright.CLI", "install", "chromium")
                .inheritIO()
                .start();
        int result = installer.waitFor();
        if (result != 0) {
            throw new IllegalStateException("Chromium install exited with code " + result);
        }
    }

    /**
     * Polls every tab in every context on the browser for the org UUID that appears in
     * TeamServer's SPA hash route once logged in, and returns whichever tab has it. Login can
     * land the user in a different tab/context than the one this code opened, so every tab in
     * every context on the browser has to be watched, not just the one Page reference created
     * up front.
     *
     * Deliberately queries window.location.href via JS evaluation rather than trusting
     * Page.url() - that property is a cache Playwright updates from CDP navigation events, and
     * those events can be dropped/delayed (observed directly: an independent check confirmed the
     * real browser had already navigated while Page.url() on this exact same page was still
     * reporting the old URL). Runtime.evaluate round-trips to the live DOM instead of relying on
     * that event-driven cache.
     */
    private record LoggedInPage(Page page, String url) {}

    private static LoggedInPage waitForOrgIdAcrossPages(Browser browser) throws InterruptedException {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(10).toMillis();
        while (System.currentTimeMillis() < deadline) {
            for (BrowserContext ctx : browser.contexts()) {
                for (Page p : ctx.pages()) {
                    String url;
                    try {
                        url = (String) p.evaluate("() => window.location.href");
                    } catch (Exception e) {
                        continue; // page mid-navigation or otherwise transiently unqueryable
                    }
                    if (UUID_IN_FRAGMENT.matcher(url).find()) {
                        return new LoggedInPage(p, url);
                    }
                }
            }
            Thread.sleep(200);
        }
        throw new IllegalStateException("Timed out waiting for login - didn't see an organization URL within 10 minutes");
    }

    private static String extractOrgId(String url) {
        Matcher m = UUID_IN_FRAGMENT.matcher(url);
        if (!m.find()) {
            throw new IllegalStateException("No organization UUID found in " + url);
        }
        return m.group(1);
    }

    private static String hostFrom(String url) {
        URI uri = URI.create(url);
        return uri.getScheme() + "://" + uri.getAuthority();
    }

    /** Confirms the scraped credentials actually authenticate before writing them to disk. */
    private static void verifyCredentials(String host, String authHeader, String apiKey) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(host + "/Contrast/api/ng/profile/organizations"))
                .header("Authorization", authHeader)
                .header("API-Key", apiKey)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Credential check failed (HTTP " + response.statusCode() + ") - the scraped keys don't seem to work");
        }
    }

    private static void writeConfig(String outputPath, String host, String orgId, String authHeader, String apiKey) throws IOException {
        String contents = "contrast.url=" + host + "/api/ns-ui/v1\n"
                + "contrast.org_id=" + orgId + "\n"
                + "contrast.auth_header=" + authHeader + "\n"
                + "contrast.api_key=" + apiKey + "\n";
        Files.writeString(Path.of(outputPath), contents);
    }

    private static void printUsage() {
        System.out.println("\nAuth - connect runtime-analyst to your Contrast account");
        System.out.println("\nOpens a real browser window, lets you log in (including SSO/MFA) the way you normally");
        System.out.println("would, then reads your personal API key/service key/org id off User Settings > Your Keys");
        System.out.println("directly - no manual copy/paste into the terminal. The window closes as soon as login");
        System.out.println("completes; everything after that runs in a background headless browser.");
        System.out.println("\nUsage:");
        System.out.println("  java -jar runtime-analyst.jar auth [--host <url>] [-o <contrast.properties>]");
    }
}
