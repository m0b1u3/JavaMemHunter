package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class NonBusinessPackageRule implements ScoringRule {
    public String name() { return "non-business-package"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null || ctx == null || ctx.whitelist == null) return 0;
        if (ctx.whitelist.isFrameworkPackage(finding.className)) return 0;
        if (ctx.whitelist.isBusinessPackage(finding.className)) return 0;
        return 2;
    }
}
