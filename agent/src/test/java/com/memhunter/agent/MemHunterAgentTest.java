package com.memhunter.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import com.memhunter.agent.util.FindingIdGenerator;
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
