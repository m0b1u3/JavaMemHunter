package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TomcatFilterCleanerPhaseCTest {

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
    }

    private FakeContext ctx;
    private String evilId;
    private static final String EVIL_CLASS = "com.evil.X";

    @BeforeEach
    void setUp() {
        ctx = new FakeContext();
        // Target filter
        FakeFilterDef evilDef = new FakeFilterDef();
        evilDef.filterClass = EVIL_CLASS;
        evilDef.filterName = "EvilFilter";
        ctx.filterDefs.put("EvilFilter", evilDef);

        // Bystander filter
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

        FakeFilterConfig evilCfg = new FakeFilterConfig();
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

    @Test
    void phaseCRemovesFilterFromAllThreeStructures() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        cleaner.plan(makeFinding(), false);
        cleaner.doPhaseC();

        Map<String, Object> defs = readMap("filterDefs");
        assertFalse(defs.containsKey("EvilFilter"));
        assertTrue(defs.containsKey("GoodFilter"));

        Map<String, Object> configs = readMap("filterConfigs");
        assertFalse(configs.containsKey("EvilFilter"));
        assertTrue(configs.containsKey("GoodFilter"));

        assertEquals(1, ctx.filterMaps.array.length);
        Object remaining = ctx.filterMaps.array[0];
        assertEquals("GoodFilter", ReflectUtil.tryReadField(remaining, "filterName").orElse(null));
    }

    @Test
    void phaseCPreservesOriginalReferencesViaCopy() {
        HashMap<String, Object> origConfigs = ctx.filterConfigs;
        HashMap<String, Object> origDefs = ctx.filterDefs;

        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        cleaner.plan(makeFinding(), false);
        cleaner.doPhaseC();

        Map<String, Object> newConfigs = readMap("filterConfigs");
        Map<String, Object> newDefs = readMap("filterDefs");
        assertNotSame(origConfigs, newConfigs, "filterConfigs must be a new map (copy-replace)");
        assertNotSame(origDefs, newDefs, "filterDefs must be a new map (copy-replace)");
        // Original map references must still contain the target (untouched).
        assertTrue(origConfigs.containsKey("EvilFilter"));
        assertTrue(origDefs.containsKey("EvilFilter"));
    }

    @Test
    void phaseCFailureTriggersRollback() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        cleaner.plan(makeFinding(), false);
        // Force step 2 (filterMaps) failure by corrupting wrapper.array to a non-array
        // between configs write and maps write. Rollback can still write a fresh Object[].
        cleaner.hookAfterConfigsWrite = () -> ReflectUtil.setField(ctx.filterMaps, "array", null);

        assertThrows(CleanExecutionException.class, cleaner::doPhaseC);

        // filterConfigs must be restored (EvilFilter present again).
        Map<String, Object> configs = readMap("filterConfigs");
        assertTrue(configs.containsKey("EvilFilter"), "configs rollback should re-add EvilFilter");
        assertTrue(configs.containsKey("GoodFilter"));
    }

    @Test
    void doPhaseCWithoutPlanThrows() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        assertThrows(CleanExecutionException.class, cleaner::doPhaseC);
    }
}
