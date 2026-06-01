package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SpringInterceptorCleanerTest {

    public static class FakeHandlerMapping {
        public List<Object> adaptedInterceptors = new ArrayList<>();
    }
    public static class EvilInterceptor {
        @Override public String toString() { return "EvilInterceptor"; }
    }
    public static class BystanderInterceptor {
        @Override public String toString() { return "BystanderInterceptor"; }
    }
    public static class FakeApplicationContext {
        final Map<String, Object> mappingBeans = new LinkedHashMap<>();
        public Map<String, Object> getBeansOfType(Class<?> type) {
            return new LinkedHashMap<>(mappingBeans);
        }
        public ClassLoader getClassLoader() { return getClass().getClassLoader(); }
    }

    private Finding interceptorFinding(Object interceptor) {
        Finding f = new Finding();
        f.attributes = new HashMap<>();
        f.type = "spring-interceptor";
        f.name = interceptor.getClass().getSimpleName();
        f.className = interceptor.getClass().getName();
        f.score = 12;
        f.level = "critical";
        f.id = FindingIdGenerator.generate(f.type, f.className, "");
        return f;
    }

    @Test
    void planLocatesInterceptorAndProducesValidPlan() {
        FakeApplicationContext ctx = new FakeApplicationContext();
        FakeHandlerMapping mapping = new FakeHandlerMapping();
        Object target = new EvilInterceptor();
        mapping.adaptedInterceptors.add(new BystanderInterceptor());
        mapping.adaptedInterceptors.add(target);
        ctx.mappingBeans.put("m1", mapping);

        SpringInterceptorCleaner cleaner = new SpringInterceptorCleaner(ctx);
        CleanPlan plan = cleaner.plan(interceptorFinding(target), false);
        assertNotNull(plan);
        assertEquals("spring-interceptor", plan.type);
        assertEquals(EvilInterceptor.class.getName(), plan.targetClass);
        assertTrue(plan.rollbackSupported);
    }

    @Test
    void phaseCRemovesInterceptorFromList() {
        FakeApplicationContext ctx = new FakeApplicationContext();
        FakeHandlerMapping mapping = new FakeHandlerMapping();
        Object bystander = new BystanderInterceptor();
        Object target = new EvilInterceptor();
        mapping.adaptedInterceptors.add(bystander);
        mapping.adaptedInterceptors.add(target);
        ctx.mappingBeans.put("m1", mapping);

        SpringInterceptorCleaner cleaner = new SpringInterceptorCleaner(ctx);
        CleanPlan plan = cleaner.plan(interceptorFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success, "execute should succeed; was: " + result.failureReason);
        assertTrue(result.verifiedDisappeared);
        assertEquals(1, mapping.adaptedInterceptors.size());
        assertEquals(BystanderInterceptor.class.getName(),
            mapping.adaptedInterceptors.get(0).getClass().getName());
        assertTrue(result.executedSteps.stream().anyMatch(
            s -> s.contains("phase-D: no-release-method")));
    }

    @Test
    void phaseCRemovesFromMultipleMappingBeans() {
        FakeApplicationContext ctx = new FakeApplicationContext();
        FakeHandlerMapping m1 = new FakeHandlerMapping();
        FakeHandlerMapping m2 = new FakeHandlerMapping();
        Object t1 = new EvilInterceptor();
        Object t2 = new EvilInterceptor();
        m1.adaptedInterceptors.add(t1);
        m2.adaptedInterceptors.add(new BystanderInterceptor());
        m2.adaptedInterceptors.add(t2);
        ctx.mappingBeans.put("m1", m1);
        ctx.mappingBeans.put("m2", m2);

        SpringInterceptorCleaner cleaner = new SpringInterceptorCleaner(ctx);
        CleanPlan plan = cleaner.plan(interceptorFinding(t1), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success);
        assertEquals(0, m1.adaptedInterceptors.size());
        assertEquals(1, m2.adaptedInterceptors.size(), "EvilInterceptor removed from m2 too");
        assertEquals(BystanderInterceptor.class.getName(),
            m2.adaptedInterceptors.get(0).getClass().getName());
    }

    @Test
    void rollbackRestoresOnVerifyFailure() {
        FakeApplicationContext ctx = new FakeApplicationContext();
        FakeHandlerMapping mapping = new FakeHandlerMapping();
        Object target = new EvilInterceptor();
        mapping.adaptedInterceptors.add(target);
        ctx.mappingBeans.put("m1", mapping);

        SpringInterceptorCleaner cleaner = new SpringInterceptorCleaner(ctx);
        cleaner.hookAfterPhaseC = () -> mapping.adaptedInterceptors.add(new EvilInterceptor());

        CleanPlan plan = cleaner.plan(interceptorFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertFalse(result.success);
        assertTrue(result.rolledBack);
        assertFalse(result.verifiedDisappeared);
        assertEquals(1, mapping.adaptedInterceptors.size());
        assertEquals(EvilInterceptor.class.getName(),
            mapping.adaptedInterceptors.get(0).getClass().getName());
    }

    @Test
    void planReturnsNullWhenScoreBelowThresholdAndNotForced() {
        FakeApplicationContext ctx = new FakeApplicationContext();
        FakeHandlerMapping mapping = new FakeHandlerMapping();
        Object target = new EvilInterceptor();
        mapping.adaptedInterceptors.add(target);
        ctx.mappingBeans.put("m1", mapping);

        Finding f = interceptorFinding(target);
        f.score = 4;

        SpringInterceptorCleaner cleaner = new SpringInterceptorCleaner(ctx);
        assertNull(cleaner.plan(f, false));

        SpringInterceptorCleaner forced = new SpringInterceptorCleaner(ctx);
        assertNotNull(forced.plan(f, true));
    }
}
