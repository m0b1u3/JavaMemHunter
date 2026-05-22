package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TomcatFilterCleanerFullFlowTest {

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
    public static class FakeFilterConfig {
        public Object filter;
        public boolean released = false;
        public RuntimeException releaseThrow;
        public void release() {
            if (releaseThrow != null) throw releaseThrow;
            released = true;
        }
    }

    private FakeContext ctx;
    private FakeFilterConfig evilCfg;
    private String evilId;
    private static final String EVIL_CLASS = "com.evil.X";

    @BeforeEach
    void setUp() {
        ctx = new FakeContext();
        FakeFilterDef evilDef = new FakeFilterDef();
        evilDef.filterClass = EVIL_CLASS;
        evilDef.filterName = "EvilFilter";
        ctx.filterDefs.put("EvilFilter", evilDef);

        FakeFilterDef goodDef = new FakeFilterDef();
        goodDef.filterClass = "com.good.Y";
        goodDef.filterName = "GoodFilter";
        ctx.filterDefs.put("GoodFilter", goodDef);

        FakeFilterMap evilMap = new FakeFilterMap();
        evilMap.filterName = "EvilFilter";
        evilMap.urlPatterns = new String[]{"/*"};
        FakeFilterMap goodMap = new FakeFilterMap();
        goodMap.filterName = "GoodFilter";
        goodMap.urlPatterns = new String[]{"/good"};
        ctx.filterMaps.array = new Object[]{ evilMap, goodMap };

        evilCfg = new FakeFilterConfig();
        evilCfg.filter = new Object();
        ctx.filterConfigs.put("EvilFilter", evilCfg);
        FakeFilterConfig goodCfg = new FakeFilterConfig();
        goodCfg.filter = new Object();
        ctx.filterConfigs.put("GoodFilter", goodCfg);

        evilId = FindingIdGenerator.generate("tomcat-filter", EVIL_CLASS, "EvilFilter");
    }

    private Finding makeFinding() {
        Finding f = new Finding();
        f.id = evilId;
        f.type = "tomcat-filter";
        f.name = "EvilFilter";
        f.className = EVIL_CLASS;
        f.score = 12;
        f.level = "critical";
        f.attributes.put("urlPatterns", Arrays.asList("/*"));
        f.attributes.put("contextPath", "/app");
        return f;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readMap(String field) {
        return (Map<String, Object>) ReflectUtil.tryReadField(ctx, field).orElse(null);
    }

    private boolean stepsContain(CleanResult r, String token) {
        if (r.executedSteps == null) return false;
        for (String s : r.executedSteps) {
            if (s != null && s.contains(token)) return true;
        }
        return false;
    }

    @Test
    void executeFullFlowSucceedsOnHappyPath() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(makeFinding(), false);
        assertNotNull(plan);

        CleanResult result = cleaner.execute(plan, false);
        assertTrue(result.success, "success should be true. reason=" + result.failureReason);
        assertTrue(result.verifiedDisappeared);
        assertFalse(result.rolledBack);
        assertEquals(evilId, result.findingId);
        assertTrue(result.executedAt > 0);

        assertTrue(stepsContain(result, "phase-C"));
        assertTrue(stepsContain(result, "phase-D"));
        assertTrue(stepsContain(result, "phase-E: verified disappeared"));

        // release() invoked
        assertTrue(evilCfg.released, "release() should have been invoked on originalFilterConfig");

        // Bystander still present
        Map<String, Object> defs = readMap("filterDefs");
        Map<String, Object> configs = readMap("filterConfigs");
        assertTrue(defs.containsKey("GoodFilter"));
        assertTrue(configs.containsKey("GoodFilter"));
        assertEquals(1, ctx.filterMaps.array.length);
        assertEquals("GoodFilter", ReflectUtil.tryReadField(ctx.filterMaps.array[0], "filterName").orElse(null));
    }

    @Test
    void executeReturnsFailureWhenPlanNotCalled() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan dummy = new CleanPlan();
        dummy.findingId = "x";
        CleanResult r = cleaner.execute(dummy, false);
        assertFalse(r.success);
        assertNotNull(r.failureReason);
        assertTrue(r.failureReason.contains("plan() must be called"),
                "failureReason should mention plan() must be called, got: " + r.failureReason);
    }

    @Test
    void destroyThrowingIsToleratedNotRolledBack() {
        evilCfg.releaseThrow = new RuntimeException("destroy boom");
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(makeFinding(), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success, "destroy failure must NOT fail the clean. reason=" + result.failureReason);
        assertTrue(result.verifiedDisappeared);
        assertFalse(result.rolledBack);
        assertTrue(stepsContain(result, "tolerated"),
                "an executed step should mark destroy as tolerated, got: " + result.executedSteps);
    }

    @Test
    void verifyFailureTriggersRollback() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(makeFinding(), false);
        // After Phase C succeeds, re-inject the EvilFilter into filterDefs so the
        // re-scan still finds it (simulates Tomcat caching elsewhere).
        cleaner.hookAfterPhaseC = () -> {
            FakeFilterDef def = new FakeFilterDef();
            def.filterClass = EVIL_CLASS;
            def.filterName = "EvilFilter";
            @SuppressWarnings("unchecked")
            Map<String, Object> defs = (Map<String, Object>)
                    ReflectUtil.tryReadField(ctx, "filterDefs").orElse(null);
            Map<String, Object> copy = new HashMap<>(defs);
            copy.put("EvilFilter", def);
            ReflectUtil.setField(ctx, "filterDefs", copy);
            // Also re-inject a map so scanner sees urlPatterns (matches scanner expectations).
            FakeFilterMap fm = new FakeFilterMap();
            fm.filterName = "EvilFilter";
            fm.urlPatterns = new String[]{"/*"};
            Object[] cur = ctx.filterMaps.array;
            Object[] next = new Object[cur.length + 1];
            System.arraycopy(cur, 0, next, 0, cur.length);
            next[cur.length] = fm;
            ctx.filterMaps.array = next;
        };

        CleanResult result = cleaner.execute(plan, false);
        assertFalse(result.success);
        assertFalse(result.verifiedDisappeared);
        assertTrue(result.rolledBack, "verify failure should trigger rollback. reason=" + result.failureReason);
        assertNotNull(result.failureReason);
        assertTrue(result.failureReason.toLowerCase().contains("still present")
                || result.failureReason.toLowerCase().contains("verify"));

        // After rollback: EvilFilter should be in filterConfigs again (canonical restore).
        Map<String, Object> configs = readMap("filterConfigs");
        assertTrue(configs.containsKey("EvilFilter"));
        assertTrue(configs.containsKey("GoodFilter"));
    }

    @Test
    void phaseCFailureSurfacesAsCleanExecutionException() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(makeFinding(), false);
        // Corrupt filterMaps wrapper between step 1 and step 2 so Phase C fails.
        cleaner.hookAfterConfigsWrite = () -> ReflectUtil.setField(ctx.filterMaps, "array", null);

        CleanResult r = cleaner.execute(plan, false);
        assertFalse(r.success);
        assertTrue(r.rolledBack, "Phase C failure should report rolledBack=true");
        assertNotNull(r.failureReason);
        assertTrue(r.failureReason.toLowerCase().contains("phase c")
                        || r.failureReason.toLowerCase().contains("phase-c")
                        || r.failureReason.toLowerCase().contains("rolled back"),
                "failureReason should mention Phase C, got: " + r.failureReason);

        // Rollback should have restored filterConfigs.
        Map<String, Object> configs = readMap("filterConfigs");
        assertTrue(configs.containsKey("EvilFilter"));
    }
}
