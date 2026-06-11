package com.memhunter.agent;

import com.memhunter.agent.cleaner.SpringInterceptorCleanerTest;
import com.memhunter.agent.cleaner.TomcatFilterCleanerPhaseDTest;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class FindingLocatorTest {

    @Test
    void findsFindingFromTomcatScanner() {
        TomcatFilterCleanerPhaseDTest.FakeContext ctx =
                new TomcatFilterCleanerPhaseDTest.FakeContext();
        TomcatFilterCleanerPhaseDTest.FakeFilterDef def =
                new TomcatFilterCleanerPhaseDTest.FakeFilterDef();
        def.filterName = "Evil";
        def.filterClass = "com.evil.X";
        ctx.filterDefs.put("Evil", def);
        TomcatFilterCleanerPhaseDTest.FakeFilterMap fm =
                new TomcatFilterCleanerPhaseDTest.FakeFilterMap();
        fm.filterName = "Evil";
        fm.urlPatterns = new String[]{"/*"};
        ctx.filterMaps.array = new Object[]{fm};
        ctx.filterConfigs.put("Evil",
                new TomcatFilterCleanerPhaseDTest.FilterConfigWithReleaseOk());

        String id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "Evil");
        Finding f = FindingLocator.find(ctx, null, id);

        assertNotNull(f);
        assertEquals("tomcat-filter", f.type);
        assertEquals("com.evil.X", f.className);
        assertEquals(id, f.id);
    }

    @Test
    void findsFindingFromSpringScanner() {
        SpringInterceptorCleanerTest.FakeApplicationContext ctx =
                new SpringInterceptorCleanerTest.FakeApplicationContext();
        SpringInterceptorCleanerTest.FakeHandlerMapping mapping =
                new SpringInterceptorCleanerTest.FakeHandlerMapping();
        SpringInterceptorCleanerTest.EvilInterceptor target =
                new SpringInterceptorCleanerTest.EvilInterceptor();
        mapping.adaptedInterceptors.add(target);
        ctx.mappingBeans.put("m1", mapping);

        String id = FindingIdGenerator.generate("spring-interceptor",
                target.getClass().getName(), "");
        Finding f = FindingLocator.find(null, ctx, id);

        assertNotNull(f);
        assertEquals("spring-interceptor", f.type);
    }

    @Test
    void returnsNullForNonMatchingId() {
        TomcatFilterCleanerPhaseDTest.FakeContext ctx =
                new TomcatFilterCleanerPhaseDTest.FakeContext();
        // empty filterDefs; no findings will be produced
        assertNull(FindingLocator.find(ctx, null, "finding-does-not-exist"));
    }

    @Test
    void returnsNullWhenBothContextsAreNull() {
        assertNull(FindingLocator.find(null, null, "any-id"));
    }

    private static TomcatFilterCleanerPhaseDTest.FakeContext ctxWithFilter(
            String filterName, String filterClass) {
        TomcatFilterCleanerPhaseDTest.FakeContext ctx =
                new TomcatFilterCleanerPhaseDTest.FakeContext();
        TomcatFilterCleanerPhaseDTest.FakeFilterDef def =
                new TomcatFilterCleanerPhaseDTest.FakeFilterDef();
        def.filterName = filterName;
        def.filterClass = filterClass;
        ctx.filterDefs.put(filterName, def);
        TomcatFilterCleanerPhaseDTest.FakeFilterMap fm =
                new TomcatFilterCleanerPhaseDTest.FakeFilterMap();
        fm.filterName = filterName;
        fm.urlPatterns = new String[]{"/*"};
        ctx.filterMaps.array = new Object[]{fm};
        ctx.filterConfigs.put(filterName,
                new TomcatFilterCleanerPhaseDTest.FilterConfigWithReleaseOk());
        return ctx;
    }

    @Test
    void findsAcrossContexts_marInSecondContext() {
        TomcatFilterCleanerPhaseDTest.FakeContext c1 = ctxWithFilter("Benign", "com.ok.A");
        TomcatFilterCleanerPhaseDTest.FakeContext c2 = ctxWithFilter("Evil", "com.evil.X");
        String id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "Evil");
        Function<Object, Object> noSpring = c -> null;

        FindingLocator.Located loc =
                FindingLocator.findAcrossContexts(Arrays.asList(c1, c2), noSpring, id);

        assertNotNull(loc);
        assertEquals("com.evil.X", loc.finding.className);
        assertSame(c2, loc.tomcatCtx);
    }

    @Test
    void findsAcrossContexts_marInFirstContext() {
        TomcatFilterCleanerPhaseDTest.FakeContext c1 = ctxWithFilter("Evil", "com.evil.X");
        TomcatFilterCleanerPhaseDTest.FakeContext c2 = ctxWithFilter("Benign", "com.ok.A");
        String id = FindingIdGenerator.generate("tomcat-filter", "com.evil.X", "Evil");

        FindingLocator.Located loc =
                FindingLocator.findAcrossContexts(Arrays.asList(c1, c2), c -> null, id);

        assertNotNull(loc);
        assertSame(c1, loc.tomcatCtx);
    }

    @Test
    void findsAcrossContexts_noMatchReturnsNull() {
        TomcatFilterCleanerPhaseDTest.FakeContext c1 = ctxWithFilter("Benign", "com.ok.A");
        FindingLocator.Located loc = FindingLocator.findAcrossContexts(
                Arrays.asList(c1), c -> null, "finding-tomcat-filter-deadbeef");
        assertNull(loc);
    }

    @Test
    void findsAcrossContexts_emptyListReturnsNull() {
        assertNull(FindingLocator.findAcrossContexts(
                Collections.emptyList(), c -> null, "any-id"));
    }
}
