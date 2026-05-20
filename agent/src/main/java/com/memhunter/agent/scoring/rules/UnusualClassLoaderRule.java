package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class UnusualClassLoaderRule implements ScoringRule {
    public String name() { return "unusual-classloader"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.classLoader == null || ctx == null || ctx.whitelist == null) return 0;
        return ctx.whitelist.commonClassLoaders().contains(finding.classLoader) ? 0 : 2;
    }
}
