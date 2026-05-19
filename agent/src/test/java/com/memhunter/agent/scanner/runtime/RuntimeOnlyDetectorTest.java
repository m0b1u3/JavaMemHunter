package com.memhunter.agent.scanner.runtime;

import com.memhunter.agent.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RuntimeOnlyDetectorTest {

    private Finding sampleFinding(String className, String name) {
        Finding f = new Finding();
        f.type = "tomcat-filter";
        f.className = className;
        f.name = name;
        f.level = "low";
        f.score = 3;
        return f;
    }

    @Test
    void all_chains_miss_marks_runtime_only() {
        RuntimeOnlyDetector det = new RuntimeOnlyDetector(null, null);
        Finding f = sampleFinding("java.lang.String", "missing");
        det.evaluate(f);
        assertEquals("suspicious", f.level);
        assertEquals(6, f.score);
        assertTrue(f.reasons.contains("runtime-only"));
    }

    @Test
    void annotation_hit_keeps_low() {
        RuntimeOnlyDetector det = new RuntimeOnlyDetector(null, null);
        Finding f = sampleFinding(AnnotatedSample.class.getName(), "annotated");
        det.evaluate(f);
        assertEquals("low", f.level);
        assertEquals(3, f.score);
        assertFalse(f.reasons.contains("runtime-only"));
    }

    @Test
    void spring_managed_hit_keeps_low() {
        FakeAppCtx appCtx = new FakeAppCtx();
        appCtx.beanTypes.add("java.lang.String");
        RuntimeOnlyDetector det = new RuntimeOnlyDetector(appCtx, null);
        Finding f = sampleFinding("java.lang.String", "spring-bean");
        det.evaluate(f);
        assertEquals("low", f.level);
        assertFalse(f.reasons.contains("runtime-only"));
    }

    @Test
    void unknown_class_does_not_throw() {
        RuntimeOnlyDetector det = new RuntimeOnlyDetector(null, null);
        Finding f = sampleFinding("no.such.Class", "phantom");
        det.evaluate(f);
        assertEquals("suspicious", f.level);
    }

    @javax.servlet.annotation.WebFilter("/dummy")
    static class AnnotatedSample {}

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
