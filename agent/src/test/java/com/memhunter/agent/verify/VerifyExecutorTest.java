package com.memhunter.agent.verify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

class VerifyExecutorTest {

    public static class FakeContext {
        public HashMap<String, Object> filterDefs = new HashMap<>();
        public FakeFilterMaps filterMaps = new FakeFilterMaps();
        public HashMap<String, Object> filterConfigs = new HashMap<>();
        public String getPath() { return "/app"; }
    }
    public static class FakeFilterMaps {
        public Object[] array = new Object[0];
    }
    public static class FakeFilterDef {
        public String filterClass;
        public String filterName;
    }
    public static class FakeFilterMap {
        public String filterName;
        public String[] urlPatterns;
    }

    @TempDir
    Path tempDir;

    @Test
    void writes_still_present_true_when_finding_exists() throws Exception {
        FakeContext ctx = contextWithFilter();
        String id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "EvilFilter");

        VerifyExecutor.VerifyResult result = new VerifyExecutor(ctx).verify(id, tempDir);

        assertTrue(result.stillPresent);
        JsonNode json = new ObjectMapper().readTree(tempDir.resolve("evidence").resolve(id)
                .resolve("verify-result.json").toFile());
        assertEquals(id, json.get("findingId").asText());
        assertTrue(json.get("stillPresent").asBoolean());
        assertTrue(json.get("verifiedAt").asLong() > 0);
    }

    @Test
    void writes_still_present_false_when_finding_is_absent() throws Exception {
        FakeContext ctx = new FakeContext();
        String id = "missing";

        VerifyExecutor.VerifyResult result = new VerifyExecutor(ctx).verify(id, tempDir);

        assertFalse(result.stillPresent);
        assertTrue(Files.exists(tempDir.resolve("evidence").resolve(id).resolve("verify-result.json")));
    }

    private FakeContext contextWithFilter() {
        FakeContext ctx = new FakeContext();
        FakeFilterDef def = new FakeFilterDef();
        def.filterClass = "com.evil.X";
        def.filterName = "EvilFilter";
        ctx.filterDefs.put("EvilFilter", def);

        FakeFilterMap map = new FakeFilterMap();
        map.filterName = "EvilFilter";
        map.urlPatterns = new String[]{"/*"};
        ctx.filterMaps.array = new Object[]{ map };
        return ctx;
    }
}
