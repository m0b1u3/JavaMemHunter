package com.memhunter.agent;

import com.memhunter.agent.cleaner.SpringInterceptorCleanerTest;
import com.memhunter.agent.cleaner.TomcatFilterCleanerPhaseDTest;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

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
}
