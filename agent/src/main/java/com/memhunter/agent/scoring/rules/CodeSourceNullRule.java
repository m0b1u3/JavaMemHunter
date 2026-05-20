package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class CodeSourceNullRule implements ScoringRule {
    public String name() { return "code-source-null"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        return finding != null && finding.codeSource == null ? 3 : 0;
    }
}
