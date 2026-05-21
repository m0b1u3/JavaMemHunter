package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;

public class BytecodeProcessBuilderRule implements ScoringRule {

    @Override public String name() { return "bytecode-process-builder"; }

    @Override
    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null) return 0;
        if (ctx == null) return 0;
        BytecodeAnalysis a = ctx.bytecodeOf(finding.className);
        if (a == null) return 0;
        if (a.hasMethodCall("java/lang/ProcessBuilder", "<init>")) return 4;
        if (a.hasMethodCall("java/lang/ProcessBuilder", "start")) return 4;
        return 0;
    }
}
