package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class ImplementsWebComponentRule implements ScoringRule {
    public String name() { return "implements-web-component"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        String type = finding == null ? null : finding.type;
        if (type == null) return 0;
        return (type.startsWith("class-") || type.startsWith("tomcat-") || type.startsWith("spring-")) ? 3 : 0;
    }
}
