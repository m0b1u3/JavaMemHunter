package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class WhitelistHitRule implements ScoringRule {
    public String name() { return "whitelist-hit"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || ctx == null || ctx.whitelist == null) return 0;
        if (ctx.whitelist.isFrameworkPackage(finding.className)) return -5;
        return 0;
    }
}
