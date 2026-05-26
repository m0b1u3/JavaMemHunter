package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TomcatValveCleanerTest {

    public static class FakeContext {
        public FakePipeline pipeline = new FakePipeline();
        public String getPath() { return "/app"; }
        public Object getPipeline() { return pipeline; }
    }
    public static class FakePipeline {
        public Object first;
        public Object getFirst() { return first; }
    }
    public static class FakeValve {
        public String name;
        public Object next;
        public boolean stopped = false;
        public Object getNext() { return next; }
        public void setNext(Object v) { this.next = v; }
        public void stop() { stopped = true; }
    }
    public static class EvilValve extends FakeValve {
        public boolean throwOnStop = false;
        @Override public void stop() {
            if (throwOnStop) throw new IllegalStateException("simulated stop failure");
            super.stop();
        }
    }

    private FakeContext build(FakeValve... valves) {
        FakeContext ctx = new FakeContext();
        if (valves.length == 0) return ctx;
        ctx.pipeline.first = valves[0];
        for (int i = 0; i < valves.length - 1; i++) {
            valves[i].next = valves[i + 1];
        }
        return ctx;
    }

    private Finding valveFinding(FakeValve v, int pipelineIndex) {
        Finding f = new Finding();
        f.attributes = new HashMap<>();
        f.type = "tomcat-valve";
        f.name = v.getClass().getSimpleName();
        f.className = v.getClass().getName();
        f.score = 12;
        f.level = "critical";
        f.attributes.put("contextPath", "/app");
        f.attributes.put("pipelineIndex", pipelineIndex);
        f.id = FindingIdGenerator.generate(f.type, f.className, "/app#" + pipelineIndex);
        return f;
    }

    @Test
    void planLocatesValveAndProducesValidPlan() {
        FakeValve prev = new FakeValve(); prev.name = "Prev";
        EvilValve target = new EvilValve(); target.name = "Evil";
        FakeValve next = new FakeValve(); next.name = "Next";
        FakeContext ctx = build(prev, target, next);

        TomcatValveCleaner cleaner = new TomcatValveCleaner(ctx);
        CleanPlan plan = cleaner.plan(valveFinding(target, 1), false);
        assertNotNull(plan);
        assertEquals("tomcat-valve", plan.type);
        assertEquals(EvilValve.class.getName(), plan.targetClass);
    }

    @Test
    void phaseCRemovesMiddleValve() {
        FakeValve prev = new FakeValve(); prev.name = "Prev";
        EvilValve target = new EvilValve(); target.name = "Evil";
        FakeValve next = new FakeValve(); next.name = "Next";
        FakeContext ctx = build(prev, target, next);

        TomcatValveCleaner cleaner = new TomcatValveCleaner(ctx);
        CleanPlan plan = cleaner.plan(valveFinding(target, 1), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success, "execute should succeed; was: " + result.failureReason);
        assertEquals(prev, ctx.pipeline.first, "prev still first");
        assertEquals(next, prev.next, "prev.next should now point at next directly");
    }

    @Test
    void phaseCRemovesFirstValve() {
        EvilValve target = new EvilValve(); target.name = "Evil";
        FakeValve next = new FakeValve(); next.name = "Next";
        FakeContext ctx = build(target, next);

        TomcatValveCleaner cleaner = new TomcatValveCleaner(ctx);
        CleanPlan plan = cleaner.plan(valveFinding(target, 0), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success);
        assertEquals(next, ctx.pipeline.first, "pipeline.first reassigned to next");
    }

    @Test
    void phaseDInvokesStop() {
        FakeValve prev = new FakeValve(); prev.name = "Prev";
        EvilValve target = new EvilValve(); target.name = "Evil";
        FakeContext ctx = build(prev, target);

        TomcatValveCleaner cleaner = new TomcatValveCleaner(ctx);
        CleanPlan plan = cleaner.plan(valveFinding(target, 1), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success);
        assertTrue(target.stopped, "valve.stop should be invoked");
        assertTrue(result.executedSteps.stream().anyMatch(s -> s.equals("phase-D: destroy-ran")));
    }

    @Test
    void phaseDToleratesStopThrowing() {
        FakeValve prev = new FakeValve(); prev.name = "Prev";
        EvilValve target = new EvilValve(); target.name = "Evil";
        target.throwOnStop = true;
        FakeContext ctx = build(prev, target);

        TomcatValveCleaner cleaner = new TomcatValveCleaner(ctx);
        CleanPlan plan = cleaner.plan(valveFinding(target, 1), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success, "Phase D exception tolerated, overall success");
        assertTrue(result.executedSteps.stream().anyMatch(
            s -> s.startsWith("phase-D: destroy-threw:") && s.contains("IllegalStateException")));
    }

    @Test
    void rollbackRestoresOnPhaseCFailure() {
        FakeValve prev = new FakeValve(); prev.name = "Prev";
        EvilValve target = new EvilValve(); target.name = "Evil";
        FakeValve next = new FakeValve(); next.name = "Next";
        FakeContext ctx = build(prev, target, next);

        TomcatValveCleaner cleaner = new TomcatValveCleaner(ctx);
        cleaner.hookAfterPipelineWrite = () -> {
            throw new RuntimeException("forced");
        };

        CleanPlan plan = cleaner.plan(valveFinding(target, 1), false);
        CleanResult result = cleaner.execute(plan, false);

        assertFalse(result.success);
        assertTrue(result.rolledBack);
        // After rollback, prev.next should be target again
        assertEquals(target, prev.next);
    }
}
