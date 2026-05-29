package com.memhunter.agent;

import com.memhunter.agent.cleaner.TomcatFilterCleanerPhaseDTest;
import com.memhunter.agent.cleaner.TomcatFilterCleanerPhaseDTest.FilterConfigWithReleaseOk;
import com.memhunter.agent.cleaner.TomcatListenerCleanerTest;
import com.memhunter.agent.cleaner.TomcatServletCleanerTest;
import com.memhunter.agent.cleaner.TomcatValveCleanerTest;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatListenerScanner;
import com.memhunter.agent.scanner.tomcat.TomcatServletScanner;
import com.memhunter.agent.scanner.tomcat.TomcatValveScanner;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.RuleEngine;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import com.memhunter.agent.util.FindingIdGenerator;
import java.util.List;
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

    private static Finding scoreOne(List<Finding> findings, String id) {
        new RuleEngine().evaluate(findings,
                new ScanContext(null, Whitelist.defaults(), false, BaselineIndex.empty()));
        for (Finding f : findings) {
            if (id.equals(f.id)) return f;
        }
        throw new IllegalStateException("scoring: id not found " + id);
    }

    @Test
    void confirmDispatchesServletCleaner() throws Exception {
        TomcatServletCleanerTest.FakeContext ctx = new TomcatServletCleanerTest.FakeContext();
        TomcatServletCleanerTest.StandardWrapper w = new TomcatServletCleanerTest.StandardWrapper();
        w.name = "EvilServlet";
        w.servletClass = TomcatServletCleanerTest.EvilServlet.class.getName();
        w.mappingsArray = new String[]{ "/EvilServlet" };
        w.servlet = new TomcatServletCleanerTest.EvilServlet();
        ctx.children.put("EvilServlet", w);
        ctx.servletMappings.put("/EvilServlet", "EvilServlet");

        List<Finding> scanned = new TomcatServletScanner(ctx).scan(new ScanReport());
        String findingId = FindingIdGenerator.generate(
                "tomcat-servlet",
                TomcatServletCleanerTest.EvilServlet.class.getName(),
                "EvilServlet");
        Finding scored = scoreOne(scanned, findingId);

        Path dir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "tomcat-servlet";
        persisted.targetName = "EvilServlet";
        persisted.targetClass = TomcatServletCleanerTest.EvilServlet.class.getName();
        persisted.score = scored.score;
        persisted.level = scored.level;
        persisted.forced = false;
        persisted.rollbackSupported = true;
        persisted.generatedAt = 1L;
        new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-plan.json").toFile(), persisted);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);
        int exit = MemHunterAgent.dispatchForTest(ctx, args);

        assertEquals(0, exit, "expected success exit");
        CleanResult cr = new ObjectMapper()
                .readValue(dir.resolve("clean-result.json").toFile(), CleanResult.class);
        assertTrue(cr.success);
        assertTrue(cr.verifiedDisappeared);
        assertNull(ctx.children.get("EvilServlet"));
    }

    @Test
    void confirmDispatchesListenerCleaner() throws Exception {
        TomcatListenerCleanerTest.FakeContext ctx = new TomcatListenerCleanerTest.FakeContext();
        TomcatListenerCleanerTest.EvilEventListener target =
                new TomcatListenerCleanerTest.EvilEventListener();
        ctx.applicationEventListeners = new Object[]{ target };

        List<Finding> scanned = new TomcatListenerScanner(ctx).scan(new ScanReport());
        String findingId = FindingIdGenerator.generate(
                "tomcat-listener-request",
                TomcatListenerCleanerTest.EvilEventListener.class.getName(),
                "");
        Finding scored = scoreOne(scanned, findingId);

        Path dir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "tomcat-listener-request";
        persisted.targetName = scored.name;
        persisted.targetClass = TomcatListenerCleanerTest.EvilEventListener.class.getName();
        persisted.score = scored.score;
        persisted.level = scored.level;
        persisted.forced = false;
        persisted.rollbackSupported = true;
        persisted.generatedAt = 1L;
        new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-plan.json").toFile(), persisted);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);
        int exit = MemHunterAgent.dispatchForTest(ctx, args);

        assertEquals(0, exit);
        assertEquals(0, ctx.applicationEventListeners.length);
    }

    @Test
    void confirmDispatchesValveCleaner() throws Exception {
        TomcatValveCleanerTest.FakeContext ctx = new TomcatValveCleanerTest.FakeContext();
        TomcatValveCleanerTest.FakeValve prev = new TomcatValveCleanerTest.FakeValve();
        prev.name = "Prev";
        TomcatValveCleanerTest.EvilValve target = new TomcatValveCleanerTest.EvilValve();
        target.name = "Evil";
        TomcatValveCleanerTest.FakeValve next = new TomcatValveCleanerTest.FakeValve();
        next.name = "Next";
        ctx.pipeline.first = prev;
        prev.next = target;
        target.next = next;

        List<Finding> scanned = new TomcatValveScanner(ctx).scan(new ScanReport());
        // The valve scanner derives its own id (using pipelineIndex).
        // Pick the EvilValve finding by className match.
        String findingId = null;
        for (Finding f : scanned) {
            if (TomcatValveCleanerTest.EvilValve.class.getName().equals(f.className)) {
                findingId = f.id;
                break;
            }
        }
        assertNotNull(findingId, "scanner must locate EvilValve");
        Finding scored = scoreOne(scanned, findingId);

        Path dir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "tomcat-valve";
        persisted.targetName = scored.name;
        persisted.targetClass = TomcatValveCleanerTest.EvilValve.class.getName();
        persisted.score = scored.score;
        persisted.level = scored.level;
        persisted.forced = false;
        persisted.rollbackSupported = true;
        persisted.generatedAt = 1L;
        new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-plan.json").toFile(), persisted);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);
        int exit = MemHunterAgent.dispatchForTest(ctx, args);

        assertEquals(0, exit);
        assertEquals(next, prev.next);
    }

    @Test
    void confirmRejectsUnknownType() throws Exception {
        // Bare Object — no scanner can map it; finding lookup fails first.
        Object ctx = new Object();
        String findingId = "finding-unknown-XYZ";
        Path dir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "tomcat-something-new";
        persisted.targetName = "X";
        persisted.targetClass = "com.X";
        persisted.score = 10;
        persisted.forced = false;
        new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-plan.json").toFile(), persisted);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);

        assertThrows(IllegalStateException.class,
                () -> MemHunterAgent.dispatchForTest(ctx, args));
    }

    @Test
    void confirmRejectsLegacyV06Plan() throws Exception {
        // Simulates a legacy v0.6 plan that lacks the v0.7 `targetClass` field
        // (filterClass/filterName were the legacy keys, dropped in v0.7).
        // The deserialized plan therefore has targetClass=null, which mismatches
        // the freshly re-scanned plan's targetClass — PlanReconciler must reject.
        TomcatFilterCleanerPhaseDTest.FakeContext ctx = newPhaseDFakeContextWithEvilFilter();

        String findingId = FindingIdGenerator.generate(
                "tomcat-filter", "com.evil.X", "Evil");
        Path dir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);

        String legacyJson = "{"
                + "\"findingId\":\"" + findingId + "\","
                + "\"type\":\"tomcat-filter\","
                + "\"targetName\":\"Evil\","
                + "\"score\":" + EVIL_FILTER_CRITICAL_SCORE + ","
                + "\"forced\":false,"
                + "\"rollbackSupported\":true,"
                + "\"generatedAt\":1"
                + "}";
        Files.write(dir.resolve("clean-plan.json"), legacyJson.getBytes("UTF-8"));

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);
        int exit = MemHunterAgent.dispatchForTest(ctx, args);

        assertEquals(MemHunterAgent.EXIT_PLAN_STALE, exit);
        CleanResult cr = new ObjectMapper()
                .readValue(dir.resolve("clean-result.json").toFile(), CleanResult.class);
        assertFalse(cr.success);
        assertNotNull(cr.failureReason);
        assertTrue(cr.failureReason.contains("targetClass"),
                "failureReason should mention targetClass, was: " + cr.failureReason);
    }

    // ---- v0.8 Task 9: Spring cleaner dispatch integration ----
    //
    // NOTE (design dependency, documented honestly):
    // MemHunterAgent.findFindingById drives the *raw scanners*
    // (SpringInterceptorScanner / SpringMappingScanner), NOT the cleaner-level
    // locateOnRescan fallback. Both Spring scanners bail and return EMPTY when
    // their anchor class (AbstractHandlerMapping / AbstractHandlerMethodMapping)
    // is not loadable via the ApplicationContext classloader — which is the case
    // with the fake test context here (no spring-webmvc on the classpath).
    //
    // Consequently, in the fake test environment findFindingById cannot locate a
    // Spring finding, so dispatch throws IllegalStateException("finding not
    // located"). These two tests assert exactly that — documenting the
    // classloader dependency of Spring dispatch.
    //
    // In a REAL Spring application the anchor classes ARE loadable, so the
    // scanners work and dispatch locates the finding normally; the gap is only
    // observable with a fake (non-loadable-Spring) context.

    @Test
    void confirmSpringFindingNotLocatedWithoutLoadableSpringClasses_interceptor() throws Exception {
        com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.FakeApplicationContext springCtx =
                new com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.FakeApplicationContext();
        com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.FakeHandlerMapping mapping =
                new com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.FakeHandlerMapping();
        com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.EvilInterceptor target =
                new com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.EvilInterceptor();
        mapping.adaptedInterceptors.add(target);

        String findingId = FindingIdGenerator.generate(
                "spring-interceptor",
                com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.EvilInterceptor.class.getName(),
                "");

        Path dir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "spring-interceptor";
        persisted.targetName = "EvilInterceptor";
        persisted.targetClass =
                com.memhunter.agent.cleaner.SpringInterceptorCleanerTest.EvilInterceptor.class.getName();
        persisted.score = 12;
        persisted.level = "critical";
        persisted.forced = false;
        persisted.rollbackSupported = true;
        persisted.generatedAt = 1L;
        new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-plan.json").toFile(), persisted);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> MemHunterAgent.dispatchForTest(null, springCtx, args));
        assertTrue(ex.getMessage().contains("finding not located"),
                "expected 'finding not located', was: " + ex.getMessage());
    }

    @Test
    void confirmSpringFindingNotLocatedWithoutLoadableSpringClasses_mapping() throws Exception {
        // The mapping fakes' bean wiring is package-private to the cleaner-test
        // package, but it is irrelevant here: SpringMappingScanner bails at the
        // unloadable-anchor-class check before ever calling getBeansOfType, so an
        // empty fake context is sufficient to drive the "not located" path.
        com.memhunter.agent.cleaner.SpringMappingCleanerTest.FakeApplicationContext springCtx =
                new com.memhunter.agent.cleaner.SpringMappingCleanerTest.FakeApplicationContext();
        String pattern = "/evil";

        String findingId = FindingIdGenerator.generate(
                "spring-mapping",
                com.memhunter.agent.cleaner.SpringMappingCleanerTest.EvilController.class.getName(),
                pattern);

        Path dir = tempDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);

        CleanPlan persisted = new CleanPlan();
        persisted.findingId = findingId;
        persisted.type = "spring-mapping";
        persisted.targetName = "m1#run";
        persisted.targetClass =
                com.memhunter.agent.cleaner.SpringMappingCleanerTest.EvilController.class.getName();
        persisted.score = 12;
        persisted.level = "critical";
        persisted.forced = false;
        persisted.rollbackSupported = true;
        persisted.generatedAt = 1L;
        new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-plan.json").toFile(), persisted);

        AgentArgs args = AgentArgs.parse(
                "clean --id " + findingId + " --confirm --evidence-dir " + tempDir);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> MemHunterAgent.dispatchForTest(null, springCtx, args));
        assertTrue(ex.getMessage().contains("finding not located"),
                "expected 'finding not located', was: " + ex.getMessage());
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
