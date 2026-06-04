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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TomcatServletCleanerTest {

    public static class FakeContext {
        public HashMap<String, Object> children = new HashMap<>();
        public HashMap<String, String> servletMappings = new HashMap<>();
        public String getPath() { return "/app"; }
        public Object[] findChildren() { return children.values().toArray(); }
        public Object findChild(String name) { return children.get(name); }
    }

    public static class StandardWrapper {
        public String name;
        public String servletClass;
        public Object servlet;
        public String[] mappingsArray;
        public int loadOnStartup = -1;
        public boolean unloaded = false;
        public String getName() { return name; }
        public String getServletClass() { return servletClass; }
        public String[] findMappings() { return mappingsArray; }
        public int getLoadOnStartup() { return loadOnStartup; }
        public Object getServlet() { return servlet; }
        public void unload() { unloaded = true; }
    }

    public static class EvilServlet {
        /* no destroy method; carries a malicious bytecode signature (Runtime.exec)
           so v0.12 BenignComponentRule does not suppress it as a benign component. */
        @SuppressWarnings("unused")
        public Process payload(String cmd) throws Exception {
            return Runtime.getRuntime().exec(cmd);
        }
    }
    public static class EvilServletWithDestroy {
        public boolean destroyed = false;
        public void destroy() { destroyed = true; }
    }

    private Finding servletFinding(StandardWrapper wrapper) {
        Finding f = new Finding();
        f.attributes = new HashMap<>();
        f.type = "tomcat-servlet";
        f.name = wrapper.getName();
        f.className = wrapper.getServletClass();
        f.score = 12;
        f.level = "critical";
        f.id = FindingIdGenerator.generate(f.type,
            f.className == null ? "" : f.className,
            f.name == null ? "" : f.name);
        f.attributes.put("contextPath", "/app");
        return f;
    }

    private FakeContext setupContext(String name, String klass, Object servletInstance) {
        FakeContext ctx = new FakeContext();
        StandardWrapper w = new StandardWrapper();
        w.name = name;
        w.servletClass = klass;
        w.mappingsArray = new String[]{ "/" + name };
        w.servlet = servletInstance;
        ctx.children.put(name, w);
        ctx.servletMappings.put("/" + name, name);
        return ctx;
    }

    @Test
    void planLocatesServletAndProducesValidPlan() {
        FakeContext ctx = setupContext("EvilServlet", EvilServlet.class.getName(), new EvilServlet());
        StandardWrapper w = (StandardWrapper) ctx.children.get("EvilServlet");

        TomcatServletCleaner cleaner = new TomcatServletCleaner(ctx);
        CleanPlan plan = cleaner.plan(servletFinding(w), false);
        assertNotNull(plan);
        assertEquals("tomcat-servlet", plan.type);
        assertEquals(EvilServlet.class.getName(), plan.targetClass);
        assertTrue(plan.rollbackSupported);
    }

    @Test
    void phaseCRemovesFromChildrenAndMappings() {
        FakeContext ctx = setupContext("EvilServlet", EvilServlet.class.getName(), new EvilServlet());
        ctx.children.put("BystanderServlet", makeBystander());
        ctx.servletMappings.put("/BystanderServlet", "BystanderServlet");
        StandardWrapper target = (StandardWrapper) ctx.children.get("EvilServlet");

        TomcatServletCleaner cleaner = new TomcatServletCleaner(ctx);
        CleanPlan plan = cleaner.plan(servletFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success, "execute should succeed; was: " + result.failureReason);
        assertNull(ctx.children.get("EvilServlet"));
        assertNotNull(ctx.children.get("BystanderServlet"));
        assertNull(ctx.servletMappings.get("/EvilServlet"));
        assertEquals("BystanderServlet", ctx.servletMappings.get("/BystanderServlet"));
    }

    @Test
    void phaseDInvokesWrapperUnloadAndServletDestroy() {
        EvilServletWithDestroy servlet = new EvilServletWithDestroy();
        FakeContext ctx = setupContext("EvilServlet", EvilServletWithDestroy.class.getName(), servlet);
        StandardWrapper target = (StandardWrapper) ctx.children.get("EvilServlet");

        TomcatServletCleaner cleaner = new TomcatServletCleaner(ctx);
        CleanPlan plan = cleaner.plan(servletFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success);
        assertTrue(target.unloaded, "wrapper.unload should have been invoked");
        assertTrue(servlet.destroyed, "servlet.destroy should have been invoked");
        long destroyRanCount = result.executedSteps.stream()
            .filter(s -> s.equals("phase-D: destroy-ran")).count();
        assertEquals(2, destroyRanCount,
            "expected exactly 2 destroy-ran labels (unload + destroy), was: "
                + result.executedSteps);
    }

    @Test
    void phaseDTolerantOfServletWithoutDestroy() {
        FakeContext ctx = setupContext("EvilServlet", EvilServlet.class.getName(), new EvilServlet());
        StandardWrapper target = (StandardWrapper) ctx.children.get("EvilServlet");

        TomcatServletCleaner cleaner = new TomcatServletCleaner(ctx);
        CleanPlan plan = cleaner.plan(servletFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertTrue(result.success);
        // Wrapper has unload() (destroy-ran); EvilServlet has no destroy() (no-release-method)
        assertTrue(result.executedSteps.stream().anyMatch(s -> s.equals("phase-D: destroy-ran")),
            "expected wrapper.unload to emit destroy-ran");
        assertTrue(result.executedSteps.stream().anyMatch(s -> s.equals("phase-D: no-release-method")),
            "expected servlet.destroy missing to emit no-release-method; was: " + result.executedSteps);
    }

    @Test
    void rollbackRestoresOnPhaseCFailure() {
        FakeContext ctx = setupContext("EvilServlet", EvilServlet.class.getName(), new EvilServlet());
        ctx.children.put("BystanderServlet", makeBystander());
        ctx.servletMappings.put("/BystanderServlet", "BystanderServlet");
        StandardWrapper target = (StandardWrapper) ctx.children.get("EvilServlet");

        Object preEvil = ctx.children.get("EvilServlet");
        Object preBystander = ctx.children.get("BystanderServlet");

        TomcatServletCleaner cleaner = new TomcatServletCleaner(ctx);
        cleaner.hookAfterChildrenWrite = () -> {
            throw new RuntimeException("forced");
        };

        CleanPlan plan = cleaner.plan(servletFinding(target), false);
        CleanResult result = cleaner.execute(plan, false);

        assertFalse(result.success);
        assertTrue(result.rolledBack);
        assertEquals(preEvil, ctx.children.get("EvilServlet"));
        assertEquals(preBystander, ctx.children.get("BystanderServlet"));
        assertEquals("EvilServlet", ctx.servletMappings.get("/EvilServlet"));
    }

    @Test
    void planReturnsNullWhenScoreBelowThresholdAndNotForced() {
        FakeContext ctx = setupContext("EvilServlet", EvilServlet.class.getName(), new EvilServlet());
        StandardWrapper target = (StandardWrapper) ctx.children.get("EvilServlet");
        Finding f = servletFinding(target);
        f.score = 4;

        TomcatServletCleaner cleaner = new TomcatServletCleaner(ctx);
        assertNull(cleaner.plan(f, false));

        TomcatServletCleaner forced = new TomcatServletCleaner(ctx);
        assertNotNull(forced.plan(f, true));
    }

    private static StandardWrapper makeBystander() {
        StandardWrapper w = new StandardWrapper();
        w.name = "BystanderServlet";
        w.servletClass = "com.bystander.Y";
        w.mappingsArray = new String[]{ "/BystanderServlet" };
        return w;
    }
}
