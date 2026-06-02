package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void returns_zero_for_tomcat_filter_with_isDynamic_false() {
        Finding f = new Finding();
        f.type = "tomcat-filter";
        f.className = "com.example.MyFilter";
        f.attributes.put("isDynamic", Boolean.FALSE);
        int score = new RuntimeOnlyRule().evaluate(f, null);
        assertEquals(0, score, "web.xml-declared filter must not trigger runtime-only penalty");
    }

    @Test
    void returns_positive_for_tomcat_filter_with_isDynamic_true() {
        Finding f = new Finding();
        f.type = "tomcat-filter";
        f.className = "com.evil.EvilFilter";
        f.attributes.put("isDynamic", Boolean.TRUE);
        int score = new RuntimeOnlyRule().evaluate(f, null);
        assertTrue(score > 0, "dynamically registered filter must trigger runtime-only penalty");
    }

    @Test
    void returns_positive_for_finding_without_isDynamic_attribute() {
        // backward compat: old findings have no isDynamic key → behave as before (return +4)
        Finding f = new Finding();
        f.type = "tomcat-servlet";
        f.className = "com.example.Servlet";
        // no attributes.put("isDynamic", ...)
        int score = new RuntimeOnlyRule().evaluate(f, null);
        assertTrue(score > 0, "missing isDynamic must behave as dynamic (backward compat)");
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
