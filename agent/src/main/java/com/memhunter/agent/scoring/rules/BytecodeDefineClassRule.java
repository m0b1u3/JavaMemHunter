package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;

public class BytecodeDefineClassRule implements ScoringRule {

    @Override public String name() { return "bytecode-define-class"; }

    @Override
    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null) return 0;
        if (ctx == null) return 0;
        BytecodeAnalysis a = ctx.bytecodeOf(finding.className);
        if (a == null) return 0;
        return a.hasMethodCallByName("defineClass") ? 3 : 0;
    }
}
