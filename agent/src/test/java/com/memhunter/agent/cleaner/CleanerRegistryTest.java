package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CleanerRegistryTest {

    private static class StubCleaner implements Cleaner {
        final Object capturedCtx;
        StubCleaner(Object ctx) { this.capturedCtx = ctx; }
        @Override public CleanPlan plan(Finding f, boolean forced) { return null; }
        @Override public CleanResult execute(CleanPlan p, boolean forced) { return null; }
    }

    @Test
    void resolvesTomcatTypeWithTomcatContext() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-filter", false, ContextKind.TOMCAT, StubCleaner::new);
        Object tomcatCtx = new Object();
        Object springCtx = new Object();
        Cleaner c = reg.resolve("tomcat-filter", tomcatCtx, springCtx);
        assertNotNull(c);
        assertSame(tomcatCtx, ((StubCleaner) c).capturedCtx);
    }

    @Test
    void resolvesSpringTypeWithSpringContext() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("spring-mapping", false, ContextKind.SPRING, StubCleaner::new);
        Object tomcatCtx = new Object();
        Object springCtx = new Object();
        Cleaner c = reg.resolve("spring-mapping", tomcatCtx, springCtx);
        assertNotNull(c);
        assertSame(springCtx, ((StubCleaner) c).capturedCtx);
    }

    @Test
    void resolvesByPrefixWithCorrectContext() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-listener-", true, ContextKind.TOMCAT, StubCleaner::new);
        Object tomcatCtx = new Object();
        assertNotNull(reg.resolve("tomcat-listener-request", tomcatCtx, null));
        assertSame(tomcatCtx,
            ((StubCleaner) reg.resolve("tomcat-listener-session", tomcatCtx, null)).capturedCtx);
    }

    @Test
    void returnsNullWhenRequiredContextIsNull() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("spring-mapping", false, ContextKind.SPRING, StubCleaner::new);
        assertNull(reg.resolve("spring-mapping", new Object(), null));
    }

    @Test
    void returnsNullForUnknownType() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-filter", false, ContextKind.TOMCAT, StubCleaner::new);
        assertNull(reg.resolve("tomcat-unknown", new Object(), new Object()));
        assertNull(reg.resolve(null, new Object(), new Object()));
    }

    @Test
    void exactMatchTakesPrecedenceOverPrefix() {
        class ExactCleaner extends StubCleaner { ExactCleaner(Object c) { super(c); } }
        class PrefixCleaner extends StubCleaner { PrefixCleaner(Object c) { super(c); } }
        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-listener-", true, ContextKind.TOMCAT, PrefixCleaner::new)
            .register("tomcat-listener-request", false, ContextKind.TOMCAT, ExactCleaner::new);
        Cleaner c = reg.resolve("tomcat-listener-request", new Object(), null);
        assertTrue(c instanceof ExactCleaner);
    }

    @Test
    void defaultRegistryRegistersAllSixCleaners() {
        CleanerRegistry reg = CleanerRegistry.defaultRegistry();
        Object tomcatCtx = new Object();
        Object springCtx = new Object();
        assertNotNull(reg.resolve("tomcat-filter", tomcatCtx, springCtx));
        assertNotNull(reg.resolve("tomcat-servlet", tomcatCtx, springCtx));
        assertNotNull(reg.resolve("tomcat-listener-request", tomcatCtx, springCtx));
        assertNotNull(reg.resolve("tomcat-valve", tomcatCtx, springCtx));
        assertNotNull(reg.resolve("spring-mapping", tomcatCtx, springCtx));
        assertNotNull(reg.resolve("spring-interceptor", tomcatCtx, springCtx));
    }
}
