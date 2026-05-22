package com.memhunter.agent.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class CleanPlanTest {

    @Test
    void roundTripPreservesAllFields() throws Exception {
        CleanPlan plan = new CleanPlan();
        plan.findingId = "f-001";
        plan.type = "tomcat_filter";
        plan.filterName = "EvilFilter";
        plan.filterClass = "com.evil.Evil";
        plan.contextPath = "/app";
        plan.level = "high";
        plan.evidenceDir = "evidence/f-001";
        plan.planFile = "evidence/f-001/clean-plan.json";
        plan.urlPatterns = Arrays.asList("/*", "/admin/*");
        plan.steps = Arrays.asList("remove-filter-map", "remove-filter-def");
        plan.score = 42;
        plan.forced = true;
        plan.rollbackSupported = true;
        plan.generatedAt = 1234567890L;

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(plan);
        CleanPlan back = mapper.readValue(json, CleanPlan.class);

        assertEquals(plan.findingId, back.findingId);
        assertEquals(plan.type, back.type);
        assertEquals(plan.filterName, back.filterName);
        assertEquals(plan.filterClass, back.filterClass);
        assertEquals(plan.contextPath, back.contextPath);
        assertEquals(plan.level, back.level);
        assertEquals(plan.evidenceDir, back.evidenceDir);
        assertEquals(plan.planFile, back.planFile);
        assertEquals(plan.urlPatterns, back.urlPatterns);
        assertEquals(plan.steps, back.steps);
        assertEquals(plan.score, back.score);
        assertEquals(plan.forced, back.forced);
        assertEquals(plan.rollbackSupported, back.rollbackSupported);
        assertEquals(plan.generatedAt, back.generatedAt);
    }

    @Test
    void defaultsAreFalseAndZero() {
        CleanPlan plan = new CleanPlan();
        assertFalse(plan.rollbackSupported);
        assertFalse(plan.forced);
        assertEquals(0, plan.score);
    }
}
