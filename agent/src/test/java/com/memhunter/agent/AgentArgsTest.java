package com.memhunter.agent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.*;

class AgentArgsTest {

    private final ByteArrayOutputStream errOut = new ByteArrayOutputStream();
    private final PrintStream originalErr = System.err;

    @BeforeEach
    void redirectErr() {
        System.setErr(new PrintStream(errOut));
    }

    @AfterEach
    void restoreErr() {
        System.setErr(originalErr);
    }

    @Test
    void null_input_returns_default_scan() {
        AgentArgs args = AgentArgs.parse(null);
        assertEquals("scan", args.command);
        assertTrue(args.options.isEmpty());
    }

    @Test
    void empty_input_returns_default_scan() {
        AgentArgs args = AgentArgs.parse("");
        assertEquals("scan", args.command);
    }

    @Test
    void parses_command_and_known_option() {
        AgentArgs args = AgentArgs.parse("scan --output /tmp/x.json");
        assertEquals("scan", args.command);
        assertEquals("/tmp/x.json", args.options.get("output"));
        assertFalse(errOut.toString().contains("warning"));
    }

    @Test
    void unknown_option_prints_warning_but_does_not_throw() {
        AgentArgs args = AgentArgs.parse("scan --bogus value");
        assertEquals("scan", args.command);
        assertEquals("value", args.options.get("bogus"));
        assertTrue(errOut.toString().contains("[memhunter] warning: unknown option --bogus"),
                "Expected stderr to contain warning, got: " + errOut.toString());
    }
}
