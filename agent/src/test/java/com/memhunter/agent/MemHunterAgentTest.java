package com.memhunter.agent;

import com.memhunter.agent.cleaner.TomcatFilterCleanerPhaseDTest;
import com.memhunter.agent.cleaner.TomcatFilterCleanerPhaseDTest.FilterConfigWithReleaseOk;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import com.memhunter.agent.util.FindingIdGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class MemHunterAgentTest {

    private static final int EVIL_FILTER_CRITICAL_SCORE = 14;

    @TempDir
    Path tempDir;

    @Test
    void populate_summary_counts_levels_without_baseline_stats_when_baseline_empty() {
        ScanReport report = new ScanReport();

        MemHunterAgent.populateSummary(report, Arrays.asList(
                finding("known", "critical"),
                finding("new", "low")
        ), BaselineIndex.empty());

        assertEquals(2, report.summary.totalFindings);
        assertEquals(1, report.summary.critical);
        assertEquals(1, report.summary.low);
        assertEquals(0, report.summary.baselineNewCount);
        assertEquals(0, report.summary.baselineMatchedCount);
    }

    @Test
    void populate_summary_counts_baseline_matches_and_new_findings() {
        ScanReport report = new ScanReport();
        BaselineIndex baseline = new BaselineIndex(new HashSet<>(Collections.singletonList("known")));

        MemHunterAgent.populateSummary(report, Arrays.asList(
                finding("known", "critical"),
                finding("new", "high")
        ), baseline);

        assertEquals(1, report.summary.baselineMatchedCount);
        assertEquals(1, report.summary.baselineNewCount);
    }

    @Test
    void dispatch_verify_writes_verify_result_for_first_tomcat_context() throws Exception {
        FakeContext ctx = contextWithFilter();
        String id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "EvilFilter");

        boolean handled = MemHunterAgent.dispatchNonScanForTest(
                AgentArgs.parse("verify --id " + id + " --evidence-dir " + tempDir),
                Collections.singletonList(ctx));

        assertTrue(handled);
        assertTrue(Files.exists(tempDir.resolve("evidence").resolve(id).resolve("verify-result.json")));
    }

    @Test
    void dispatch_clean_dry_run_writes_clean_plan_bundle() throws Exception {
        FakeContext ctx = contextWithFilter();
        String id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "EvilFilter");

        boolean handled = MemHunterAgent.dispatchNonScanForTest(
                AgentArgs.parse("clean --id " + id + " --dry-run --evidence-dir " + tempDir),
                Collections.singletonList(ctx));

        assertTrue(handled);
        Path evidence = tempDir.resolve("evidence").resolve(id);
        assertTrue(Files.exists(evidence.resolve("finding.json")));
        assertTrue(Files.exists(evidence.resolve("clean-plan.json")));
        assertTrue(Files.exists(evidence.resolve("before-snapshot.json")));
    }

    @Test
    void dispatch_clean_confirm_executes_plan_and_writes_result() throws Exception {
        FakeContext ctx = contextWithFilter();
        String id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "EvilFilter");
        MemHunterAgent.dispatchNonScanForTest(
                AgentArgs.parse("clean --id " + id + " --dry-run --evidence-dir " + tempDir),
                Collections.singletonList(ctx));

        boolean handled = MemHunterAgent.dispatchNonScanForTest(
                AgentArgs.parse("clean --id " + id + " --confirm --evidence-dir " + tempDir),
                Collections.singletonList(ctx));

        assertTrue(handled);
        Path evidence = tempDir.resolve("evidence").resolve(id);
        assertTrue(Files.exists(evidence.resolve("clean-result.json")));
        assertFalse(ctx.filterDefs.containsKey("EvilFilter"));
    }

    private Finding finding(String id, String level) {
        Finding f = new Finding();
        f.id = id;
        f.level = level;
        return f;
    }

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

    @Test
    void confirmRejectsStalePlanWithoutMutating() throws Exception {
        TomcatFilterCleanerPhaseDTest.FakeContext ctx =
                newPhaseDFakeContextWithEvilFilter();
        String findingId = FindingIdGenerator.generate(
                "tomcat-filter", "com.evil.X", "Evil");

        Path findingDir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(findingDir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "tomcat-filter";
        persisted.targetName = "Evil";
        persisted.targetClass = "com.evil.X";
        persisted.score = EVIL_FILTER_CRITICAL_SCORE;
        persisted.level = "critical";
        persisted.forced = false;
        persisted.rollbackSupported = true;
        persisted.generatedAt = 1L;

        new ObjectMapper()
                .writerWithDefaultPrettyPrinter()
                .writeValue(findingDir.resolve("clean-plan.json").toFile(), persisted);

        HashMapSnapshot before = HashMapSnapshot.of(ctx);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --force --evidence-dir " + tempDir);
        int exitCode = MemHunterAgent.dispatchForTest(ctx, args);

        assertEquals(3, exitCode, "EXIT_PLAN_STALE must be 3");

        HashMapSnapshot after = HashMapSnapshot.of(ctx);
        assertTrue(before.equalsSnapshot(after),
                "runtime maps must not be mutated when plan is stale");

        Path resultFile = findingDir.resolve("clean-result.json");
        assertTrue(Files.exists(resultFile),
                "clean-result.json must be written even on stale rejection");
        CleanResult cr = new ObjectMapper()
                .readValue(resultFile.toFile(), CleanResult.class);
        assertFalse(cr.success);
        assertFalse(cr.rolledBack);
        assertNotNull(cr.failureReason);
        assertTrue(cr.failureReason.contains("forced"),
                "failureReason should mention forced, was: " + cr.failureReason);
    }

    @Test
    void confirmAcceptsConsistentPlan() throws Exception {
        TomcatFilterCleanerPhaseDTest.FakeContext ctx =
                newPhaseDFakeContextWithEvilFilter();
        String findingId = FindingIdGenerator.generate(
                "tomcat-filter", "com.evil.X", "Evil");

        Path findingDir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(findingDir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "tomcat-filter";
        persisted.targetName = "Evil";
        persisted.targetClass = "com.evil.X";
        persisted.score = EVIL_FILTER_CRITICAL_SCORE;
        persisted.level = "critical";
        persisted.forced = false;
        persisted.rollbackSupported = true;
        persisted.generatedAt = 1L;

        new ObjectMapper()
                .writerWithDefaultPrettyPrinter()
                .writeValue(findingDir.resolve("clean-plan.json").toFile(), persisted);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);
        int exitCode = MemHunterAgent.dispatchForTest(ctx, args);

        assertEquals(0, exitCode, "consistent plan must succeed");

        CleanResult cr = new ObjectMapper()
                .readValue(findingDir.resolve("clean-result.json").toFile(),
                        CleanResult.class);
        assertTrue(cr.success);
        assertTrue(cr.verifiedDisappeared);
    }

    private static TomcatFilterCleanerPhaseDTest.FakeContext
            newPhaseDFakeContextWithEvilFilter() {
        TomcatFilterCleanerPhaseDTest.FakeContext ctx =
                new TomcatFilterCleanerPhaseDTest.FakeContext();
        TomcatFilterCleanerPhaseDTest.FakeFilterDef def =
                new TomcatFilterCleanerPhaseDTest.FakeFilterDef();
        def.filterName = "Evil";
        def.filterClass = "com.evil.X";
        ctx.filterDefs.put("Evil", def);
        TomcatFilterCleanerPhaseDTest.FakeFilterMap fm =
                new TomcatFilterCleanerPhaseDTest.FakeFilterMap();
        fm.filterName = "Evil";
        fm.urlPatterns = new String[]{"/*"};
        ctx.filterMaps.array = new Object[]{fm};
        ctx.filterConfigs.put("Evil",
                new FilterConfigWithReleaseOk());
        return ctx;
    }

    private static class HashMapSnapshot {
        final java.util.Map<String, Object> defs;
        final java.util.Map<String, Object> configs;
        final int filterMapsLen;

        HashMapSnapshot(java.util.Map<String, Object> defs,
                        java.util.Map<String, Object> configs,
                        int filterMapsLen) {
            this.defs = new java.util.HashMap<>(defs);
            this.configs = new java.util.HashMap<>(configs);
            this.filterMapsLen = filterMapsLen;
        }

        @SuppressWarnings("unchecked")
        static HashMapSnapshot of(Object ctx) throws Exception {
            java.lang.reflect.Field fd = ctx.getClass().getField("filterDefs");
            java.lang.reflect.Field fc = ctx.getClass().getField("filterConfigs");
            java.lang.reflect.Field fm = ctx.getClass().getField("filterMaps");
            Object mapsWrapper = fm.get(ctx);
            Object[] arr = (Object[]) mapsWrapper.getClass().getField("array").get(mapsWrapper);
            return new HashMapSnapshot(
                    (java.util.Map<String, Object>) fd.get(ctx),
                    (java.util.Map<String, Object>) fc.get(ctx),
                    arr.length);
        }

        boolean equalsSnapshot(HashMapSnapshot other) {
            return defs.equals(other.defs)
                    && configs.equals(other.configs)
                    && filterMapsLen == other.filterMapsLen;
        }
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
