package com.memhunter.attach;

import com.sun.tools.attach.AgentLoadException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AttachExecutorTest {

    @Test
    void zero_return_agent_load_exception_is_benign() {
        assertTrue(AttachExecutor.isBenignZeroReturn(new AgentLoadException("0")));
    }

    @Test
    void non_zero_agent_load_exception_is_not_benign() {
        assertFalse(AttachExecutor.isBenignZeroReturn(new AgentLoadException("100")));
        assertFalse(AttachExecutor.isBenignZeroReturn(new AgentLoadException("agent failed")));
    }

    @Test
    void extracts_explicit_output_path() {
        assertEquals("target/report.json",
                AttachExecutor.explicitOutputPath("scan --output target/report.json --explain"));
    }

    @Test
    void missing_explicit_output_path_returns_null() {
        assertNull(AttachExecutor.explicitOutputPath("scan --explain"));
    }
}
