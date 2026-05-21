package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BytecodeReflectionAbuseRuleTest {

    private final BytecodeReflectionAbuseRule rule = new BytecodeReflectionAbuseRule();

    private Finding f() {
        Finding f = new Finding();
        f.className = "com.X";
        f.type = "class-filter";
        return f;
    }

    private ScanContext ctxWithCalls(String... calls) {
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);
        ctx.putBytecodeForTest("com.X",
                new BytecodeAnalysis(new HashSet<>(Arrays.asList(calls))));
        return ctx;
    }

    @Test
    void set_accessible_hits() {
        ScanContext ctx = ctxWithCalls("java/lang/reflect/AccessibleObject#setAccessible");
        assertEquals(2, rule.evaluate(f(), ctx));
    }

    @Test
    void get_declared_field_hits() {
        ScanContext ctx = ctxWithCalls("java/lang/Class#getDeclaredField");
        assertEquals(2, rule.evaluate(f(), ctx));
    }

    @Test
    void get_declared_method_hits() {
        ScanContext ctx = ctxWithCalls("java/lang/Class#getDeclaredMethod");
        assertEquals(2, rule.evaluate(f(), ctx));
    }

    @Test
    void ordinary_methods_miss() {
        ScanContext ctx = ctxWithCalls("java/util/HashMap#put", "java/lang/String#length");
        assertEquals(0, rule.evaluate(f(), ctx));
    }
}
