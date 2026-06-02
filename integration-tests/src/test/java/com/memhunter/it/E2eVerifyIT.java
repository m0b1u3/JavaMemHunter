package com.memhunter.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@Disabled("v0.9.1: pending fixture port-isolation fix in v0.9.2 — "
        + "depends on clean step succeeding, which depends on the second-fixture "
        + "issue described in E2eCleanIT.")
class E2eVerifyIT {

    @RegisterExtension
    static final ProfileFixture FIXTURE = new ProfileFixture();

    @Test
    void verifyAfterCleanIsIdempotent() throws Exception {
        Path evDir = FIXTURE.evidenceDir();
        Path scanReport = evDir.resolve("scan-for-verify.json");

        assertEquals(0, AttachRunner.run(FIXTURE.pid(),
                "scan", "--output", scanReport.toString()));

        // Pick first finding (any type) as the subject.
        JsonNode root = new ObjectMapper().readTree(scanReport.toFile());
        String id = root.get("findings").get(0).get("id").asText();

        assertEquals(0, AttachRunner.run(FIXTURE.pid(),
                "clean", "--id", id, "--dry-run",
                "--evidence-dir", evDir.toString()));

        assertEquals(0, AttachRunner.runWithStdin(FIXTURE.pid(), "yes\n",
                "clean", "--id", id, "--confirm",
                "--evidence-dir", evDir.toString()));

        // Run verify twice and assert both report absent.
        for (int i = 1; i <= 2; i++) {
            int rc = AttachRunner.run(FIXTURE.pid(),
                    "verify", "--id", id, "--evidence-dir", evDir.toString());
            assertEquals(0, rc, "verify run #" + i + " must exit 0");
            JsonNode vr = new ObjectMapper().readTree(
                    evDir.resolve("evidence").resolve(id).resolve("verify-result.json").toFile());
            assertFalse(vr.get("stillPresent").asBoolean(),
                    "verify run #" + i + " must report absent");
        }
    }
}
