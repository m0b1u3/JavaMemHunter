package com.memhunter.agent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AgentArgsCleanTest {

    @Test
    void clean_with_id_and_dry_run_parses() {
        AgentArgs args = AgentArgs.parse("clean --id F-123 --dry-run");
        assertEquals("clean", args.command);
        assertEquals("F-123", args.options.get("id"));
        assertEquals("true", args.options.get("dry-run"));
    }

    @Test
    void clean_with_id_and_confirm_parses() {
        AgentArgs args = AgentArgs.parse("clean --id F-123 --confirm");
        assertEquals("clean", args.command);
        assertEquals("F-123", args.options.get("id"));
        assertEquals("true", args.options.get("confirm"));
    }

    @Test
    void clean_with_id_confirm_and_force_parses() {
        AgentArgs args = AgentArgs.parse("clean --id F-123 --confirm --force");
        assertEquals("clean", args.command);
        assertEquals("true", args.options.get("force"));
    }

    @Test
    void clean_missing_dry_run_and_confirm_throws() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> AgentArgs.parse("clean --id F-123"));
        assertTrue(ex.getMessage().contains("--dry-run or --confirm"));
    }

    @Test
    void clean_with_both_dry_run_and_confirm_throws() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> AgentArgs.parse("clean --id F-123 --dry-run --confirm"));
        assertTrue(ex.getMessage().contains("cannot combine"));
    }

    @Test
    void clean_with_force_but_no_confirm_throws() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> AgentArgs.parse("clean --id F-123 --force --dry-run"));
        assertTrue(ex.getMessage().contains("--force"));
    }

    @Test
    void clean_missing_id_throws() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> AgentArgs.parse("clean --dry-run"));
        assertTrue(ex.getMessage().contains("clean requires --id"));
    }

    @Test
    void verify_with_id_parses() {
        AgentArgs args = AgentArgs.parse("verify --id F-123");
        assertEquals("verify", args.command);
        assertEquals("F-123", args.options.get("id"));
    }

    @Test
    void verify_missing_id_throws() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> AgentArgs.parse("verify"));
        assertTrue(ex.getMessage().contains("verify requires --id"));
    }

    @Test
    void scan_with_baseline_still_parses() {
        AgentArgs args = AgentArgs.parse("scan --baseline foo.json");
        assertEquals("scan", args.command);
        assertEquals("foo.json", args.options.get("baseline"));
    }
}
