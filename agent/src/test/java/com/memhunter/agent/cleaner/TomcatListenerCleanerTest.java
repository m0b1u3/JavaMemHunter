package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatListenerScanner;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TomcatListenerCleanerTest {

    // Public for reuse from MemHunterAgentTest (Task 11)
    public static class FakeContext {
        public Object[] applicationEventListeners = new Object[0];
        public Object[] applicationLifecycleListeners = new Object[0];
        public String getPath() { return "/app"; }
    }

    public static class FakeTomcat9Context {
        public List<Object> applicationEventListenersList = new ArrayList<>();
        public Object[] applicationLifecycleListenersObjects = new Object[0];
        public String getPath() { return "/app"; }
        public Object[] getApplicationEventListeners() {
            return applicationEventListenersList.toArray();
        }
        public void setApplicationEventListeners(Object[] listeners) {
            applicationEventListenersList = new ArrayList<>(java.util.Arrays.asList(listeners));
        }
        public Object[] getApplicationLifecycleListeners() {
            return applicationLifecycleListenersObjects;
        }
        public void setApplicationLifecycleListeners(Object[] listeners) {
            applicationLifecycleListenersObjects = listeners;
        }
    }

    public static class EvilEventListener implements javax.servlet.ServletRequestListener {
        @Override public void requestDestroyed(javax.servlet.ServletRequestEvent sre) {}
        @Override public void requestInitialized(javax.servlet.ServletRequestEvent sre) {}
    }
    public static class EvilLifecycleListener implements javax.servlet.ServletContextListener {
        @Override public void contextInitialized(javax.servlet.ServletContextEvent sce) {}
        @Override public void contextDestroyed(javax.servlet.ServletContextEvent sce) {}
    }
    public static class BystanderRequestListener implements javax.servlet.ServletRequestListener {
        @Override public void requestDestroyed(javax.servlet.ServletRequestEvent sre) {}
        @Override public void requestInitialized(javax.servlet.ServletRequestEvent sre) {}
    }

    private Finding eventFinding(Object listener) {
        Finding f = new Finding();
        f.attributes = new HashMap<>();
        Class<?> clz = listener.getClass();
        f.type = "tomcat-listener-request";
        f.name = clz.getSimpleName();
        f.className = clz.getName();
        f.score = 12;
        f.level = "critical";
        f.id = FindingIdGenerator.generate(f.type, f.className, "");
        f.attributes.put("contextPath", "/app");
        return f;
    }

    @Test
    void planLocatesListenerAndProducesValidPlan() {
        FakeContext ctx = new FakeContext();
        Object target = new EvilEventListener();
        ctx.applicationEventListeners = new Object[]{ new BystanderRequestListener(), target };

        TomcatListenerCleaner cleaner = new TomcatListenerCleaner(ctx);
        CleanPlan plan = cleaner.plan(eventFinding(target), false);
        assertNotNull(plan);
        assertEquals("tomcat-listener-request", plan.type);
        assertEquals(EvilEventListener.class.getName(), plan.targetClass);
        assertTrue(plan.rollbackSupported);
    }

    @Test
    void phaseCRemovesFromEventListeners() {
        FakeContext ctx = new FakeContext();
        Object bystander = new BystanderRequestListener();
        Object target = new EvilEventListener();
        ctx.applicationEventListeners = new Object[]{ bystander, target };
        ctx.applicationLifecycleListeners = new Object[]{};

        TomcatListenerCleaner cleaner = new TomcatListenerCleaner(ctx);
        CleanPlan plan = cleaner.plan(eventFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success, "execute should succeed; was: " + result.failureReason);
        assertTrue(result.verifiedDisappeared);
        assertEquals(1, ctx.applicationEventListeners.length);
        assertEquals(bystander, ctx.applicationEventListeners[0]);
        assertTrue(result.executedSteps.stream().anyMatch(
            s -> s.contains("phase-D: no-release-method")),
            "Listener has no release method, expect no-release-method label, was: "
                + result.executedSteps);
    }

    @Test
    void phaseCRemovesFromLifecycleListeners() {
        FakeContext ctx = new FakeContext();
        Object target = new EvilLifecycleListener();
        ctx.applicationLifecycleListeners = new Object[]{ target };
        ctx.applicationEventListeners = new Object[]{};

        Finding f = new Finding();
        f.attributes = new HashMap<>();
        f.type = "tomcat-listener-context";
        f.name = target.getClass().getSimpleName();
        f.className = target.getClass().getName();
        f.score = 12;
        f.level = "critical";
        f.id = FindingIdGenerator.generate(f.type, f.className, "");
        f.attributes.put("contextPath", "/app");

        TomcatListenerCleaner cleaner = new TomcatListenerCleaner(ctx);
        CleanPlan plan = cleaner.plan(f, false);
        assertNotNull(plan);
        CleanResult result = cleaner.execute(plan, false);
        assertTrue(result.success);
        assertEquals(0, ctx.applicationLifecycleListeners.length);
    }

    @Test
    void scannerAndCleanerSupportTomcat9ListenerStorageNames() {
        FakeTomcat9Context ctx = new FakeTomcat9Context();
        Object target = new EvilEventListener();
        ctx.applicationEventListenersList.add(target);

        List<Finding> scanned = new TomcatListenerScanner(ctx).scan(new ScanReport());
        assertEquals(1, scanned.size());
        assertEquals("tomcat-listener-request", scanned.get(0).type);

        Finding f = scanned.get(0);
        f.score = 12;
        f.level = "critical";
        TomcatListenerCleaner cleaner = new TomcatListenerCleaner(ctx);
        CleanPlan plan = cleaner.plan(f, false);
        assertNotNull(plan);
        CleanResult result = cleaner.execute(plan, false);
        assertTrue(result.success);
        assertEquals(0, ctx.applicationEventListenersList.size());
    }

    @Test
    void rollbackRestoresOnPhaseCFailure() {
        FakeContext ctx = new FakeContext();
        Object bystander = new BystanderRequestListener();
        Object target = new EvilEventListener();
        ctx.applicationEventListeners = new Object[]{ bystander, target };

        TomcatListenerCleaner cleaner = new TomcatListenerCleaner(ctx);
        // Hook fires AFTER applicationEventListeners successful write, BEFORE
        // applicationLifecycleListeners write. Throw to trigger the catch path.
        cleaner.hookAfterEventWrite = () -> { throw new RuntimeException("forced"); };

        CleanPlan plan = cleaner.plan(eventFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertFalse(result.success);
        assertTrue(result.rolledBack);
        // After rollback, event listeners restored to original (length 2, target back)
        assertEquals(2, ctx.applicationEventListeners.length);
        assertTrue(java.util.Arrays.asList(ctx.applicationEventListeners).contains(target));
    }

    @Test
    void planReturnsNullWhenScoreBelowThresholdAndNotForced() {
        FakeContext ctx = new FakeContext();
        Object target = new EvilEventListener();
        ctx.applicationEventListeners = new Object[]{ target };

        Finding f = eventFinding(target);
        f.score = 4;

        TomcatListenerCleaner cleaner = new TomcatListenerCleaner(ctx);
        assertNull(cleaner.plan(f, false));

        // Re-construct cleaner because plan() carries state forward
        TomcatListenerCleaner forcedCleaner = new TomcatListenerCleaner(ctx);
        CleanPlan plan = forcedCleaner.plan(f, true);
        assertNotNull(plan);
        assertTrue(plan.forced);
    }
}
