package com.memhunter.it;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

/**
 * JUnit 5 extension that forks the test-target JVM for the active profile (sb27 / sb32),
 * waits for its HTTP entry-point to become ready, and invokes all six inject endpoints
 * so each integration test starts from a populated 6-finding state.
 *
 * <p>Pass <code>-Dtest-target.jar=...</code> and <code>-Dprofile.id=sb27|sb32</code>
 * (the integration-tests/pom.xml does this for both profiles via failsafe systemPropertyVariables).</p>
 */
public class ProfileFixture implements BeforeAllCallback, AfterAllCallback {

    public static final String[] INJECT_PATHS = {
            "/inject/filter",
            "/inject/servlet",
            "/inject/listener",
            "/inject/valve",
            "/inject/spring-interceptor",
            "/inject/spring-mapping"
    };

    private static final String BASE_URL = "http://localhost:8080";
    private static final int READY_TIMEOUT_SECONDS = 60;

    private Process target;
    private Path evidenceDir;
    private String pid;
    private String profile;

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        String jar = System.getProperty("test-target.jar");
        if (jar == null || jar.isEmpty()) {
            throw new IllegalStateException("-Dtest-target.jar system property is required");
        }
        profile = System.getProperty("profile.id", "sb27");

        evidenceDir = Paths.get("target", "evidence", profile).toAbsolutePath();
        Files.createDirectories(evidenceDir);

        // JDK 17 module encapsulation blocks the agent's reflective Thread/field walk
        // used by ClassLoadedContextProvider to locate Tomcat StandardEngine.
        // Open the relevant java.base packages so the attached agent can reach them.
        target = new ProcessBuilder("java",
                "--add-opens=java.base/java.lang=ALL-UNNAMED",
                "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
                "--add-opens=java.base/java.util=ALL-UNNAMED",
                "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
                "-jar", jar)
                .redirectErrorStream(true)
                .redirectOutput(evidenceDir.resolve("target.log").toFile())
                .start();
        pid = String.valueOf(target.pid());

        waitForReady(READY_TIMEOUT_SECONDS);
        for (String p : INJECT_PATHS) {
            int code = hit(BASE_URL + p);
            if (code < 200 || code >= 400) {
                throw new IllegalStateException("inject endpoint " + p + " returned " + code);
            }
        }
    }

    @Override
    public void afterAll(ExtensionContext context) {
        if (target != null && target.isAlive()) {
            target.destroyForcibly();
            try {
                target.waitFor(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public String pid()         { return pid; }
    public Path evidenceDir()   { return evidenceDir; }
    public String profile()     { return profile; }

    private void waitForReady(int timeoutSeconds) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (System.nanoTime() < deadline) {
            if (!target.isAlive()) {
                throw new IllegalStateException("target jvm exited before becoming ready; "
                        + "see " + evidenceDir.resolve("target.log"));
            }
            try {
                if (hit(BASE_URL + "/hello") == 200) return;
            } catch (IOException ignored) {
                // not yet listening
            }
            Thread.sleep(500);
        }
        throw new IllegalStateException("target /hello did not become ready in "
                + timeoutSeconds + "s; see " + evidenceDir.resolve("target.log"));
    }

    private int hit(String url) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(2000);
        c.setReadTimeout(5000);
        try {
            return c.getResponseCode();
        } finally {
            c.disconnect();
        }
    }
}
