package com.memhunter.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class E2eScanIT {

    @RegisterExtension
    static final ProfileFixture FIXTURE = new ProfileFixture();

    @Test
    void scanFindsAll6FindingTypes() throws Exception {
        Path evDir = FIXTURE.evidenceDir();
        Path scanReport = evDir.resolve("scan-report.json");

        int exit = AttachRunner.run(
                FIXTURE.pid(),
                "scan", "--output", scanReport.toString()
        );
        assertEquals(0, exit, "attach scan must exit 0; check " + evDir.resolve("attach-scan.log"));
        assertTrue(Files.exists(scanReport),
                "scan-report.json must exist at " + scanReport);

        JsonNode root = new ObjectMapper().readTree(scanReport.toFile());
        Set<String> seenTypes = new HashSet<>();
        JsonNode findings = root.get("findings");
        assertNotNull(findings, "scan report must have a 'findings' array");
        for (Iterator<JsonNode> it = findings.elements(); it.hasNext(); ) {
            seenTypes.add(it.next().get("type").asText());
        }
        // Note: TomcatListenerScanner emits "tomcat-listener-<kind>" where kind is derived
        // from the listener interface. FakeListener implements ServletRequestListener so
        // its type is "tomcat-listener-request" on both sb27 (javax) and sb32 (jakarta).
        Set<String> expected = Set.of(
                "tomcat-filter", "tomcat-servlet", "tomcat-listener-request",
                "tomcat-valve", "spring-interceptor", "spring-mapping");
        assertEquals(expected, seenTypes,
                "all 6 finding types must be reported; saw " + seenTypes);
    }
}
