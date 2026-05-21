package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BytecodeProcessBuilderRuleTest {

    private final BytecodeProcessBuilderRule rule = new BytecodeProcessBuilderRule();

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
    void process_builder_init_hits() {
        ScanContext ctx = ctxWithCalls("com.X", "java/lang/ProcessBuilder#<init>");
        assertEquals(4, rule.evaluate(f("com.X"), ctx));
    }

    @Test
    void process_builder_start_hits() {
        ScanContext ctx = ctxWithCalls("com.X", "java/lang/ProcessBuilder#start");
        assertEquals(4, rule.evaluate(f("com.X"), ctx));
    }
}
