package com.memhunter.agent.scoring.bytecode;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class BytecodeAnalysisTest {

    private BytecodeAnalysis with(String... calls) {
        return new BytecodeAnalysis(new HashSet<>(Arrays.asList(calls)));
    }

    @Test
    void has_method_call_exact_owner_partial_name() {
        BytecodeAnalysis a = with("java/lang/Runtime#exec", "java/lang/String#toString");
        assertTrue(a.hasMethodCall("java/lang/Runtime", "exec"));
        assertTrue(a.hasMethodCall("java/lang/Runtime", "ex"));         // partial name
        assertFalse(a.hasMethodCall("java/lang/Process", "exec"));      // wrong owner
        assertFalse(a.hasMethodCall("java/lang/Runtime", "doFinal"));   // name mismatch
    }

    @Test
    void has_method_call_by_name_any_owner() {
        BytecodeAnalysis a = with("sun/reflect/Foo#setAccessible", "java/lang/Foo#bar");
        assertTrue(a.hasMethodCallByName("setAccessible"));
        assertTrue(a.hasMethodCallByName("Accessible"));
        assertFalse(a.hasMethodCallByName("doFinal"));
    }

    @Test
    void empty_analysis_returns_false_for_any_query() {
        BytecodeAnalysis empty = new BytecodeAnalysis(Collections.<String>emptySet());
        assertFalse(empty.hasMethodCall("any", "any"));
        assertFalse(empty.hasMethodCallByName("any"));
    }

    @Test
    void malformed_entries_without_separator_are_skipped() {
        BytecodeAnalysis a = with("no-separator-here");
        assertFalse(a.hasMethodCall("foo", "bar"));
        assertFalse(a.hasMethodCallByName("bar"));
    }
}
