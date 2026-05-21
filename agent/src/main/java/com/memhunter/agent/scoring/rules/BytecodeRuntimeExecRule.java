package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;

public class BytecodeRuntimeExecRule implements ScoringRule {

    @Override public String name() { return "bytecode-runtime-exec"; }

    @Override
    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null) return 0;
        if (ctx == null) return 0;
        BytecodeAnalysis a = ctx.bytecodeOf(finding.className);
        if (a == null) return 0;
        return a.hasMethodCall("java/lang/Runtime", "exec") ? 4 : 0;
    }
}
