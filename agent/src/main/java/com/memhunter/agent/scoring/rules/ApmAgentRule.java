package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class ApmAgentRule implements ScoringRule {
    public String name() { return "apm-agent"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || ctx == null || ctx.whitelist == null) return 0;
        return ctx.whitelist.isApmAgent(finding.className) ? -4 : 0;
    }
}
