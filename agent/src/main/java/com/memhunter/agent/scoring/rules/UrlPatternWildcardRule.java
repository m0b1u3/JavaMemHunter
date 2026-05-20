package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

import java.util.Collection;

public class UrlPatternWildcardRule implements ScoringRule {
    public String name() { return "url-pattern-wildcard"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.attributes == null) return 0;
        Object patterns = finding.attributes.get("urlPatterns");
        if (!(patterns instanceof Collection)) return 0;
        for (Object pattern : (Collection<?>) patterns) {
            if ("/*".equals(pattern) || "/".equals(pattern)) return 2;
        }
        return 0;
    }
}
