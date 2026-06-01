package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SpringMappingCleanerTest {

    public static class FakeRMI {
        final String s;
        FakeRMI(String s) { this.s = s; }
        @Override public String toString() { return s; }
    }

    public static class EvilController {
        public void run() {}
    }

    public static class FakeHandlerMethod {
        final Class<?> beanType;
        final Method method;
        final Object bean;
        FakeHandlerMethod(Class<?> beanType, Method method, Object bean) {
            this.beanType = beanType; this.method = method; this.bean = bean;
        }
        public Class<?> getBeanType() { return beanType; }
        public Method getMethod() { return method; }
        public Object getBean() { return bean; }
    }

    public static class FakeHandlerMapping {
        final Map<Object, Object> handlerMethods = new LinkedHashMap<>();
        public Map<Object, Object> getHandlerMethods() { return handlerMethods; }
        public void unregisterMapping(Object info) { handlerMethods.remove(info); }
        public void registerMapping(Object info, Object handler, Method method) {
            handlerMethods.put(info, new FakeHandlerMethod(
                handler == null ? Object.class : handler.getClass(), method, handler));
        }
    }

    public static class FakeApplicationContext {
        final Map<String, Object> mappingBeans = new LinkedHashMap<>();
        public Map<String, Object> getBeansOfType(Class<?> type) {
            return new LinkedHashMap<>(mappingBeans);
        }
        public ClassLoader getClassLoader() { return getClass().getClassLoader(); }
    }

    private Method evilRun() throws Exception {
        return EvilController.class.getMethod("run");
    }

    private Finding mappingFinding(String pattern) {
        Finding f = new Finding();
        f.attributes = new HashMap<>();
        f.type = "spring-mapping";
        f.className = EvilController.class.getName();
        f.name = "m1#run";
        f.score = 12;
        f.level = "critical";
        f.attributes.put("pattern", pattern);
        f.id = FindingIdGenerator.generate(f.type, f.className, pattern);
        return f;
    }

    private FakeApplicationContext ctxWith(String pattern, Object handlerMethod) {
        FakeApplicationContext ctx = new FakeApplicationContext();
        FakeHandlerMapping mapping = new FakeHandlerMapping();
        mapping.handlerMethods.put(new FakeRMI(pattern), handlerMethod);
        ctx.mappingBeans.put("m1", mapping);
        return ctx;
    }

    @Test
    void planLocatesMappingAndProducesValidPlan() throws Exception {
        EvilController bean = new EvilController();
        FakeHandlerMethod hm = new FakeHandlerMethod(EvilController.class, evilRun(), bean);
        FakeApplicationContext ctx = ctxWith("{GET [/evil]}", hm);

        SpringMappingCleaner cleaner = new SpringMappingCleaner(ctx);
        CleanPlan plan = cleaner.plan(mappingFinding("{GET [/evil]}"), false);
        assertNotNull(plan);
        assertEquals("spring-mapping", plan.type);
        assertEquals(EvilController.class.getName(), plan.targetClass);
        assertTrue(plan.rollbackSupported);
    }

    @Test
    void phaseCUnregistersMapping() throws Exception {
        EvilController bean = new EvilController();
        FakeHandlerMethod hm = new FakeHandlerMethod(EvilController.class, evilRun(), bean);
        FakeApplicationContext ctx = ctxWith("{GET [/evil]}", hm);
        FakeHandlerMapping mapping = (FakeHandlerMapping) ctx.mappingBeans.get("m1");

        SpringMappingCleaner cleaner = new SpringMappingCleaner(ctx);
        CleanPlan plan = cleaner.plan(mappingFinding("{GET [/evil]}"), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success, "execute should succeed; was: " + result.failureReason);
        assertTrue(result.verifiedDisappeared);
        assertEquals(0, mapping.handlerMethods.size(), "mapping unregistered");
        assertTrue(result.executedSteps.stream().anyMatch(
            s -> s.contains("phase-D: no-release-method")));
    }

    @Test
    void phaseCPreservesOtherMappings() throws Exception {
        EvilController bean = new EvilController();
        FakeHandlerMethod evilHm = new FakeHandlerMethod(EvilController.class, evilRun(), bean);
        FakeApplicationContext ctx = ctxWith("{GET [/evil]}", evilHm);
        FakeHandlerMapping mapping = (FakeHandlerMapping) ctx.mappingBeans.get("m1");
        mapping.handlerMethods.put(new FakeRMI("{GET [/legit]}"),
            new FakeHandlerMethod(EvilController.class, evilRun(), bean));

        SpringMappingCleaner cleaner = new SpringMappingCleaner(ctx);
        CleanPlan plan = cleaner.plan(mappingFinding("{GET [/evil]}"), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success);
        assertEquals(1, mapping.handlerMethods.size());
        assertEquals("{GET [/legit]}",
            mapping.handlerMethods.keySet().iterator().next().toString());
    }

    @Test
    void rollbackReRegistersOnVerifyFailure() throws Exception {
        EvilController bean = new EvilController();
        FakeHandlerMethod hm = new FakeHandlerMethod(EvilController.class, evilRun(), bean);
        FakeApplicationContext ctx = ctxWith("{GET [/evil]}", hm);
        FakeHandlerMapping mapping = (FakeHandlerMapping) ctx.mappingBeans.get("m1");

        SpringMappingCleaner cleaner = new SpringMappingCleaner(ctx);
        // After Phase C, re-add the mapping so Phase E still finds it -> rollback
        cleaner.hookAfterPhaseC = () ->
            mapping.handlerMethods.put(new FakeRMI("{GET [/evil]}"), hm);

        CleanPlan plan = cleaner.plan(mappingFinding("{GET [/evil]}"), false);
        CleanResult result = cleaner.execute(plan, false);

        assertFalse(result.success);
        assertTrue(result.rolledBack);
        assertFalse(result.verifiedDisappeared);
        assertTrue(mapping.handlerMethods.keySet().stream()
            .anyMatch(k -> k.toString().equals("{GET [/evil]}")));
    }

    @Test
    void planReturnsNullWhenMappingNotFound() throws Exception {
        EvilController bean = new EvilController();
        FakeHandlerMethod hm = new FakeHandlerMethod(EvilController.class, evilRun(), bean);
        FakeApplicationContext ctx = ctxWith("{GET [/evil]}", hm);

        SpringMappingCleaner cleaner = new SpringMappingCleaner(ctx);
        CleanPlan plan = cleaner.plan(mappingFinding("{GET [/ghost]}"), false);
        assertNull(plan);
    }

    @Test
    void planReturnsNullWhenScoreBelowThresholdAndNotForced() throws Exception {
        EvilController bean = new EvilController();
        FakeHandlerMethod hm = new FakeHandlerMethod(EvilController.class, evilRun(), bean);
        FakeApplicationContext ctx = ctxWith("{GET [/evil]}", hm);

        Finding f = mappingFinding("{GET [/evil]}");
        f.score = 4;

        SpringMappingCleaner cleaner = new SpringMappingCleaner(ctx);
        assertNull(cleaner.plan(f, false));

        SpringMappingCleaner forced = new SpringMappingCleaner(ctx);
        assertNotNull(forced.plan(f, true));
    }
}
