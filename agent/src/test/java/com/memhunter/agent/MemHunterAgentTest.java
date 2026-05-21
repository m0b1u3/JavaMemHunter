package com.memhunter.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MemHunterAgentTest {

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

    private Finding finding(String id, String level) {
        Finding f = new Finding();
        f.id = id;
        f.level = level;
        return f;
    }
}
