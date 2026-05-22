package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.FilterBackup;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

public class TomcatFilterCleanerPhaseABTest {

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
        FakeFilterDef def = new FakeFilterDef();
        def.filterClass = EVIL_CLASS;
        def.filterName = "EvilFilter";
        ctx.filterDefs.put("EvilFilter", def);

        FakeFilterMap map = new FakeFilterMap();
        map.filterName = "EvilFilter";
        map.urlPatterns = new String[]{"/*"};
        ctx.filterMaps.array = new Object[]{ map };

        FakeFilterConfig cfg = new FakeFilterConfig();
        cfg.filter = new Object();
        ctx.filterConfigs.put("EvilFilter", cfg);

        evilId = FindingIdGenerator.generate("tomcat-filter", EVIL_CLASS, "EvilFilter");
    }

    private Finding makeFinding(int score, String level, String type) {
        Finding f = new Finding();
        f.id = evilId;
        f.type = type;
        f.name = "EvilFilter";
        f.className = EVIL_CLASS;
        f.score = score;
        f.level = level;
        f.attributes.put("urlPatterns", Arrays.asList("/*"));
        f.attributes.put("contextPath", "/app");
        return f;
    }

    @Test
    void planSucceedsWhenFindingPresentAndScoreHigh() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(makeFinding(12, "critical", "tomcat-filter"), false);
        assertNotNull(plan);
        assertEquals("EvilFilter", plan.filterName);
        assertEquals(EVIL_CLASS, plan.filterClass);
        assertEquals(12, plan.score);
        assertEquals("critical", plan.level);
        assertTrue(plan.rollbackSupported);
        assertNotNull(plan.steps);
        assertFalse(plan.steps.isEmpty());
        assertEquals(evilId, plan.findingId);
        assertEquals("tomcat-filter", plan.type);
        assertEquals("/app", plan.contextPath);
        assertEquals(Arrays.asList("/*"), plan.urlPatterns);
        assertFalse(plan.forced);
        assertTrue(plan.generatedAt > 0);
    }

    @Test
    void backupCapturesAllThreeFields() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        cleaner.plan(makeFinding(12, "critical", "tomcat-filter"), false);
        FilterBackup backup = cleaner.getCurrentBackup();
        assertNotNull(backup);
        assertNotNull(backup.originalFilterDef);
        assertNotNull(backup.originalFilterMaps);
        assertEquals(1, backup.originalFilterMaps.size());
        assertNotNull(backup.originalFilterConfig);
        assertNotNull(backup.originalFilterConfigsMap);
        assertTrue(backup.originalFilterConfigsMap.containsKey("EvilFilter"));
    }

    @Test
    void planReturnsNullWhenFindingMissing() {
        ctx.filterDefs.clear();
        ctx.filterMaps.array = new Object[0];
        ctx.filterConfigs.clear();
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        assertNull(cleaner.plan(makeFinding(12, "critical", "tomcat-filter"), false));
    }

    @Test
    void planReturnsNullWhenWrongType() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        assertNull(cleaner.plan(makeFinding(12, "critical", "tomcat-listener"), false));
    }

    @Test
    void planReturnsNullWhenScoreBelowThresholdAndNotForced() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        assertNull(cleaner.plan(makeFinding(5, "suspicious", "tomcat-filter"), false));
    }

    @Test
    void planSucceedsWhenScoreBelowThresholdButForced() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(makeFinding(5, "suspicious", "tomcat-filter"), true);
        assertNotNull(plan);
        assertTrue(plan.forced);
    }

    @Test
    void executeThrowsUnsupportedForNow() {
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(makeFinding(12, "critical", "tomcat-filter"), false);
        assertThrows(UnsupportedOperationException.class, () -> cleaner.execute(plan, false));
    }
}
