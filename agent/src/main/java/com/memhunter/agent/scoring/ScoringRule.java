package com.memhunter.agent.scoring;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;

public interface ScoringRule {
    String name();
    int evaluate(Finding finding, ScanContext ctx);
}
