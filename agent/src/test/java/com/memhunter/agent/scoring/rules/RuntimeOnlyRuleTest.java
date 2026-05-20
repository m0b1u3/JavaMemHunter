package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RuntimeOnlyRuleTest {
    private final RuntimeOnlyRule rule = new RuntimeOnlyRule();

    @Test
    void runtime_registry_finding_without_known_source_hits() {
        assertEquals(4, rule.evaluate(finding("tomcat-filter", "java.lang.String"), ctx(null)));
    }

    @Test
    void class_level_finding_misses() {
        assertEquals(0, rule.evaluate(finding("class-filter", "java.lang.String"), ctx(null)));
    }

    @Test
    void annotated_web_component_misses() {
        assertEquals(0, rule.evaluate(finding("tomcat-filter", AnnotatedFilter.class.getName()), ctx(null)));
    }

    @Test
    void spring_managed_component_misses() {
        FakeAppCtx appCtx = new FakeAppCtx();
        appCtx.beanTypes.add(ManagedFilter.class.getName());
        assertEquals(0, rule.evaluate(finding("tomcat-filter", ManagedFilter.class.getName()), ctx(appCtx)));
    }

    private ScanContext ctx(Object appCtx) {
        return new ScanContext(appCtx, Whitelist.defaults(), false);
    }

    private Finding finding(String type, String className) {
        Finding f = new Finding();
        f.type = type;
        f.className = className;
        return f;
    }

    @javax.servlet.annotation.WebFilter("/dummy")
    static class AnnotatedFilter {}

    static class ManagedFilter {}

    static class FakeAppCtx {
        java.util.Set<String> beanTypes = new java.util.HashSet<>();

        public Map<String, Object> getBeansOfType(Class<?> type) {
            Map<String, Object> r = new HashMap<>();
            if (beanTypes.contains(type.getName())) {
                r.put("bean", new Object());
            }
            return r;
        }
    }
}
