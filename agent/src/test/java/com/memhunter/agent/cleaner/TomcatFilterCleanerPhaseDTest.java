package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

class TomcatFilterCleanerPhaseDTest {

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

    public static class FilterConfigWithReleaseOk {
        public Object filter = new Object();
        public boolean released = false;
        public void release() { released = true; }
    }

    public static class FilterConfigWithoutRelease {
        public Object filter = new Object();
    }

    public static class FilterConfigWithReleaseThrowing {
        public Object filter = new Object();
        public void release() {
            throw new IllegalStateException("simulated destroy failure");
        }
    }

    private FakeContext setupContext(Object filterConfig) {
        FakeContext ctx = new FakeContext();
        FakeFilterDef def = new FakeFilterDef();
        def.filterName = "Evil";
        def.filterClass = "com.evil.X";
        ctx.filterDefs.put("Evil", def);
        FakeFilterMap fm = new FakeFilterMap();
        fm.filterName = "Evil";
        fm.urlPatterns = new String[]{"/*"};
        ctx.filterMaps.array = new Object[]{fm};
        ctx.filterConfigs.put("Evil", filterConfig);
        return ctx;
    }

    private Finding evilFinding() {
        Finding f = new Finding();
        f.id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "Evil");
        f.type = "tomcat-filter";
        f.name = "Evil";
        f.className = "com.evil.X";
        f.score = 12;
        f.level = "critical";
        return f;
    }

    @Test
    void phaseDLabelDestroyRan() {
        FilterConfigWithReleaseOk cfg = new FilterConfigWithReleaseOk();
        FakeContext ctx = setupContext(cfg);
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(evilFinding(), false);
        CleanResult result = cleaner.execute(plan, false);
        assertTrue(result.success, "should succeed");
        assertTrue(cfg.released, "release() should have been invoked");
        assertTrue(
            result.executedSteps.stream().anyMatch(s -> s.contains("phase-D: destroy-ran")),
            "executedSteps should contain phase-D: destroy-ran, was: " + result.executedSteps
        );
    }

    @Test
    void phaseDLabelNoReleaseMethod() {
        FakeContext ctx = setupContext(new FilterConfigWithoutRelease());
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(evilFinding(), false);
        CleanResult result = cleaner.execute(plan, false);
        assertTrue(result.success, "should still succeed (Phase D tolerant)");
        assertTrue(
            result.executedSteps.stream().anyMatch(s -> s.contains("phase-D: no-release-method")),
            "executedSteps should contain phase-D: no-release-method, was: " + result.executedSteps
        );
    }

    @Test
    void phaseDLabelDestroyThrew() {
        FakeContext ctx = setupContext(new FilterConfigWithReleaseThrowing());
        TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
        CleanPlan plan = cleaner.plan(evilFinding(), false);
        CleanResult result = cleaner.execute(plan, false);
        assertTrue(result.success, "Phase D exception is tolerated, overall success");
        assertTrue(
            result.executedSteps.stream().anyMatch(s -> s.startsWith("phase-D: destroy-threw:")
                    && s.contains("IllegalStateException")
                    && s.contains("simulated destroy failure")),
            "executedSteps should contain phase-D: destroy-threw with class+message, was: "
                + result.executedSteps
        );
    }
}
