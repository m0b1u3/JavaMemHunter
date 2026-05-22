package com.memhunter.agent.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class CleanResultTest {

    @Test
    void roundTripPreservesAllFields() throws Exception {
        CleanResult result = new CleanResult();
        result.findingId = "f-001";
        result.failureReason = "filter not found";
        result.success = true;
        result.rolledBack = true;
        result.verifiedDisappeared = true;
        result.executedSteps = Arrays.asList("remove-filter-map", "remove-filter-def");
        result.executedAt = 1234567890L;

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(result);
        CleanResult back = mapper.readValue(json, CleanResult.class);

        assertEquals(result.findingId, back.findingId);
        assertEquals(result.failureReason, back.failureReason);
        assertEquals(result.success, back.success);
        assertEquals(result.rolledBack, back.rolledBack);
        assertEquals(result.verifiedDisappeared, back.verifiedDisappeared);
        assertEquals(result.executedSteps, back.executedSteps);
        assertEquals(result.executedAt, back.executedAt);
    }

    @Test
    void defaultsAreFalse() {
        CleanResult r = new CleanResult();
        assertFalse(r.success);
        assertFalse(r.verifiedDisappeared);
        assertFalse(r.rolledBack);
    }
}
