package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BytecodeDefineClassRuleTest {

    private final BytecodeDefineClassRule rule = new BytecodeDefineClassRule();

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
    void define_class_call_hits_three() {
        ScanContext ctx = ctxWithCalls("java/lang/ClassLoader#defineClass");
        assertEquals(3, rule.evaluate(f(), ctx));
    }

    @Test
    void other_classloader_method_misses() {
        ScanContext ctx = ctxWithCalls("java/lang/ClassLoader#getResource");
        assertEquals(0, rule.evaluate(f(), ctx));
    }
}
