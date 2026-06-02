package com.memhunter.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.*;

class E2eCleanIT {

    @RegisterExtension
    static final ProfileFixture FIXTURE = new ProfileFixture();

    @ParameterizedTest(name = "clean removes {0}")
    @ValueSource(strings = {
            "tomcat-filter",
            "tomcat-servlet",
            "tomcat-listener-request",   // emitted type is "tomcat-listener-" + kind
            "tomcat-valve",
            "spring-interceptor",
            "spring-mapping"
    })
    void cleanRemovesFinding(String type) throws Exception {
        Path evDir = FIXTURE.evidenceDir();
        Path scanReport = evDir.resolve("scan-" + type + ".json");

        int rc = AttachRunner.run(FIXTURE.pid(),
                "scan", "--output", scanReport.toString());
        assertEquals(0, rc, "scan must succeed for " + type);
        assertTrue(Files.exists(scanReport), "scan report missing for " + type);

        String id = findIdOfType(scanReport, type);
        assertNotNull(id, "scan must surface a " + type + " finding; report=" + scanReport);

        // dry-run: writes clean-plan.json
        rc = AttachRunner.run(FIXTURE.pid(),
                "clean", "--id", id, "--dry-run",
                "--evidence-dir", evDir.toString());
        assertEquals(0, rc, "dry-run clean must succeed for " + type);
        Path plan = evDir.resolve("evidence").resolve(id).resolve("clean-plan.json");
        assertTrue(Files.exists(plan), "clean-plan.json missing for " + type + " at " + plan);

        // confirm: stdin "yes" then attach invokes agent
        rc = AttachRunner.runWithStdin(FIXTURE.pid(), "yes\n",
                "clean", "--id", id, "--confirm",
                "--evidence-dir", evDir.toString());
        assertEquals(0, rc, "confirm clean must succeed for " + type);

        Path cleanResult = evDir.resolve("evidence").resolve(id).resolve("clean-result.json");
        assertTrue(Files.exists(cleanResult), "clean-result.json missing for " + type);
        JsonNode cr = new ObjectMapper().readTree(cleanResult.toFile());
        assertTrue(cr.get("success").asBoolean(),
                "clean-result.success must be true for " + type + "; result=" + cr);

        // verify
        rc = AttachRunner.run(FIXTURE.pid(),
                "verify", "--id", id, "--evidence-dir", evDir.toString());
        assertEquals(0, rc, "verify must exit 0 (finding absent) for " + type);

        Path verifyResult = evDir.resolve("evidence").resolve(id).resolve("verify-result.json");
        assertTrue(Files.exists(verifyResult), "verify-result.json missing for " + type);
        JsonNode vr = new ObjectMapper().readTree(verifyResult.toFile());
        assertFalse(vr.get("stillPresent").asBoolean(),
                "verify.stillPresent must be false for " + type + "; result=" + vr);
    }

    private String findIdOfType(Path scanReport, String type) throws Exception {
        JsonNode root = new ObjectMapper().readTree(scanReport.toFile());
        for (Iterator<JsonNode> it = root.get("findings").elements(); it.hasNext(); ) {
            JsonNode n = it.next();
            if (type.equals(n.get("type").asText())) return n.get("id").asText();
        }
        return null;
    }
}
