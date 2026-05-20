package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class MappingPathDisguiseRule implements ScoringRule {
    public String name() { return "mapping-path-disguise"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.attributes == null || ctx == null || ctx.whitelist == null) return 0;
        if (ctx.whitelist.isFrameworkPackage(finding.className)) return 0;
        String pattern = String.valueOf(finding.attributes.get("pattern")).toLowerCase();
        if (pattern.contains("/health") || pattern.contains("/actuator")
                || pattern.contains("/static") || pattern.contains("/favicon.ico")) {
            return 2;
        }
        return 0;
    }
}
