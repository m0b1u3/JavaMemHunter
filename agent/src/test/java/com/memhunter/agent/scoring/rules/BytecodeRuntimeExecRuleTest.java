package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BytecodeRuntimeExecRuleTest {

    private final BytecodeRuntimeExecRule rule = new BytecodeRuntimeExecRule();

    private Finding f(String className) {
        Finding f = new Finding();
        f.className = className;
        f.type = "class-filter";
        return f;
    }

    private ScanContext ctxWithCalls(String className, String... calls) {
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);
        ctx.putBytecodeForTest(className,
                new BytecodeAnalysis(new HashSet<>(Arrays.asList(calls))));
        return ctx;
    }

    @Test
    void runtime_exec_call_hits_plus_four() {
        ScanContext ctx = ctxWithCalls("com.X", "java/lang/Runtime#exec");
        assertEquals(4, rule.evaluate(f("com.X"), ctx));
    }

    @Test
    void runtime_other_method_does_not_hit() {
        ScanContext ctx = ctxWithCalls("com.X", "java/lang/Runtime#totalMemory");
        assertEquals(0, rule.evaluate(f("com.X"), ctx));
    }

    @Test
    void no_bytecode_does_not_hit() {
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);
        assertEquals(0, rule.evaluate(f("com.X"), ctx));
    }
}
