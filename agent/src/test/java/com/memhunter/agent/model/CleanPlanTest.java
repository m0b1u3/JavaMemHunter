package com.memhunter.agent.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CleanPlanTest {

    @Test
    void roundTripsAllFields() throws Exception {
        CleanPlan p = new CleanPlan();
        p.findingId = "finding-tomcat-filter-abc";
        p.type = "tomcat-filter";
        p.targetName = "EvilFilter";
        p.targetClass = "com.evil.X";
        p.contextPath = "/app";
        p.level = "critical";
        p.evidenceDir = "/tmp/ev";
        p.planFile = "/tmp/ev/evidence/finding-tomcat-filter-abc/clean-plan.json";
        Map<String, Object> d = new HashMap<>();
        d.put("urlPatterns", Arrays.asList("/*"));
        p.details = d;
        p.steps = Arrays.asList("step1", "step2");
        p.score = 14;
        p.forced = false;
        p.rollbackSupported = true;
        p.generatedAt = 1716345600000L;

        ObjectMapper om = new ObjectMapper();
        String json = om.writeValueAsString(p);
        CleanPlan back = om.readValue(json, CleanPlan.class);

        assertEquals(p.findingId, back.findingId);
        assertEquals(p.type, back.type);
        assertEquals(p.targetName, back.targetName);
        assertEquals(p.targetClass, back.targetClass);
        assertEquals(p.contextPath, back.contextPath);
        assertEquals(p.level, back.level);
        assertEquals(p.evidenceDir, back.evidenceDir);
        assertEquals(p.planFile, back.planFile);
        assertEquals(p.details, back.details);
        assertEquals(p.steps, back.steps);
        assertEquals(p.score, back.score);
        assertEquals(p.forced, back.forced);
        assertEquals(p.rollbackSupported, back.rollbackSupported);
        assertEquals(p.generatedAt, back.generatedAt);
    }

    @Test
    void defaultsAreSensible() {
        CleanPlan p = new CleanPlan();
        assertFalse(p.forced);
        assertFalse(p.rollbackSupported);
        assertEquals(0, p.score);
        assertNotNull(p.details, "details must be non-null (empty HashMap)");
    }
}
