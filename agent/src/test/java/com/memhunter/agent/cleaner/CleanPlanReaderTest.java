package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

class CleanPlanReaderTest {

    @Test
    void roundTripCleanPlan(@TempDir Path tmp) throws Exception {
        EvidenceWriter w = new EvidenceWriter(tmp);
        Finding f = new Finding();
        f.id = "F-RT";
        f.type = "tomcat.filter";

        CleanPlan p = new CleanPlan();
        p.findingId = "F-RT";
        p.type = "tomcat.filter";
        p.targetName = "X";
        p.targetClass = "com.X";
        p.contextPath = "/app";
        p.level = "HIGH";
        p.details.put("urlPatterns", Arrays.asList("/a", "/b"));
        p.steps = Arrays.asList("s1", "s2");
        p.score = 42;
        p.forced = true;
        p.rollbackSupported = true;
        p.generatedAt = 7L;

        Path dir = w.writeBundle(f, p, new HashMap<>(), null);
        CleanPlan back = CleanPlanReader.read(dir.resolve("clean-plan.json"));

        assertEquals(p.findingId, back.findingId);
        assertEquals(p.type, back.type);
        assertEquals(p.targetName, back.targetName);
        assertEquals(p.targetClass, back.targetClass);
        assertEquals(p.contextPath, back.contextPath);
        assertEquals(p.level, back.level);
        assertEquals(p.details.get("urlPatterns"), back.details.get("urlPatterns"));
        assertEquals(p.steps, back.steps);
        assertEquals(p.score, back.score);
        assertEquals(p.forced, back.forced);
        assertEquals(p.rollbackSupported, back.rollbackSupported);
        assertEquals(p.generatedAt, back.generatedAt);
    }

    @Test
    void roundTripCleanResult(@TempDir Path tmp) throws Exception {
        EvidenceWriter w = new EvidenceWriter(tmp);
        Finding f = new Finding();
        f.id = "F-RR";
        CleanPlan p = new CleanPlan();
        p.findingId = "F-RR";
        w.writeBundle(f, p, new HashMap<>(), null);

        CleanResult r = new CleanResult();
        r.findingId = "F-RR";
        r.success = false;
        r.rolledBack = true;
        r.verifiedDisappeared = false;
        r.failureReason = "boom";
        r.executedSteps = Arrays.asList("s1");
        r.executedAt = 12L;

        w.writeResult("F-RR", r);
        CleanResult back = CleanPlanReader.readResult(
                tmp.resolve("evidence").resolve("F-RR").resolve("clean-result.json"));

        assertEquals(r.findingId, back.findingId);
        assertFalse(back.success);
        assertTrue(back.rolledBack);
        assertFalse(back.verifiedDisappeared);
        assertEquals("boom", back.failureReason);
        assertEquals(Arrays.asList("s1"), back.executedSteps);
        assertEquals(12L, back.executedAt);
    }
}
