package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlanReconcilerTest {

    private CleanPlan basePlan() {
        CleanPlan p = new CleanPlan();
        p.findingId = "finding-tomcat-filter-abc123";
        p.type = "tomcat-filter";
        p.filterName = "EvilFilter";
        p.filterClass = "com.evil.X";
        p.score = 12;
        p.level = "critical";
        p.forced = false;
        p.rollbackSupported = true;
        return p;
    }

    @Test
    void consistentPlansPass() {
        CleanPlan persisted = basePlan();
        CleanPlan fresh = basePlan();
        fresh.generatedAt = 999L;
        assertDoesNotThrow(() -> PlanReconciler.requireConsistent(persisted, fresh, false));
    }

    @Test
    void findingIdMismatchThrows() {
        CleanPlan persisted = basePlan();
        CleanPlan fresh = basePlan();
        fresh.findingId = "finding-tomcat-filter-DIFFERENT";
        PlanStaleException ex = assertThrows(PlanStaleException.class,
                () -> PlanReconciler.requireConsistent(persisted, fresh, false));
        assertTrue(ex.getMessage().contains("findingId"));
        assertTrue(ex.getMessage().contains("finding-tomcat-filter-abc123"));
        assertTrue(ex.getMessage().contains("finding-tomcat-filter-DIFFERENT"));
    }

    @Test
    void filterClassMismatchThrows() {
        CleanPlan persisted = basePlan();
        CleanPlan fresh = basePlan();
        fresh.filterClass = "com.evil.Y";
        PlanStaleException ex = assertThrows(PlanStaleException.class,
                () -> PlanReconciler.requireConsistent(persisted, fresh, false));
        assertTrue(ex.getMessage().contains("filterClass"));
        assertTrue(ex.getMessage().contains("com.evil.X"));
        assertTrue(ex.getMessage().contains("com.evil.Y"));
    }

    @Test
    void scoreMismatchThrows() {
        CleanPlan persisted = basePlan();
        CleanPlan fresh = basePlan();
        fresh.score = 8;
        PlanStaleException ex = assertThrows(PlanStaleException.class,
                () -> PlanReconciler.requireConsistent(persisted, fresh, false));
        assertTrue(ex.getMessage().contains("score"));
        assertTrue(ex.getMessage().contains("12"));
        assertTrue(ex.getMessage().contains("8"));
    }

    @Test
    void forcedFlagMismatchInPlansThrows() {
        CleanPlan persisted = basePlan();
        persisted.forced = false;
        CleanPlan fresh = basePlan();
        fresh.forced = true;
        PlanStaleException ex = assertThrows(PlanStaleException.class,
                () -> PlanReconciler.requireConsistent(persisted, fresh, true));
        assertTrue(ex.getMessage().contains("forced"));
        assertTrue(ex.getMessage().contains("confirmFlag"));
        assertTrue(ex.getMessage().contains("persisted=false"));
        assertTrue(ex.getMessage().contains("fresh=true"));
    }

    @Test
    void forcedFlagMismatchWithConfirmFlagThrows() {
        CleanPlan persisted = basePlan();
        persisted.forced = false;
        CleanPlan fresh = basePlan();
        fresh.forced = false;
        PlanStaleException ex = assertThrows(PlanStaleException.class,
                () -> PlanReconciler.requireConsistent(persisted, fresh, true));
        assertTrue(ex.getMessage().contains("forced"));
        assertTrue(ex.getMessage().contains("confirmFlag=true"));
    }
}
