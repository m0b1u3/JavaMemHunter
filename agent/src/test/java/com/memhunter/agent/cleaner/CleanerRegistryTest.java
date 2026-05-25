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
    void resolvesByExactTypeMatch() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-filter", false, StubCleaner::new);
        Object ctx = new Object();
        Cleaner c = reg.resolve("tomcat-filter", ctx);
        assertNotNull(c);
        assertTrue(c instanceof StubCleaner);
        assertSame(ctx, ((StubCleaner) c).capturedCtx);
    }

    @Test
    void resolvesByPrefixMatch() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-listener-", true, StubCleaner::new);
        Object ctx = new Object();
        assertNotNull(reg.resolve("tomcat-listener-request", ctx));
        assertNotNull(reg.resolve("tomcat-listener-session", ctx));
        assertNotNull(reg.resolve("tomcat-listener-other", ctx));
    }

    @Test
    void returnsNullForUnknownType() {
        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-filter", false, StubCleaner::new);
        assertNull(reg.resolve("tomcat-unknown", new Object()));
        assertNull(reg.resolve(null, new Object()));
    }

    @Test
    void exactMatchTakesPrecedenceOverPrefix() {
        class ExactCleaner extends StubCleaner { ExactCleaner(Object c) { super(c); } }
        class PrefixCleaner extends StubCleaner { PrefixCleaner(Object c) { super(c); } }

        CleanerRegistry reg = new CleanerRegistry()
            .register("tomcat-listener-", true, PrefixCleaner::new)
            .register("tomcat-listener-request", false, ExactCleaner::new);

        Cleaner c = reg.resolve("tomcat-listener-request", new Object());
        assertTrue(c instanceof ExactCleaner);
    }
}
