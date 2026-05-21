package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class BaselineNewRule implements ScoringRule {

    @Override public String name() { return "baseline-new"; }

    @Override
    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.id == null) return 0;
        if (ctx == null || ctx.baselineIndex == null) return 0;
        if (ctx.baselineIndex.isEmpty()) return 0;
        return ctx.baselineIndex.contains(finding.id) ? 0 : 4;
    }
}
