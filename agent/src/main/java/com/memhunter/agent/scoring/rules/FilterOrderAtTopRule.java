package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class FilterOrderAtTopRule implements ScoringRule {
    public String name() { return "filter-order-at-top"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.attributes == null) return 0;
        Object value = finding.attributes.containsKey("pipelineIndex")
                ? finding.attributes.get("pipelineIndex") : finding.attributes.get("order");
        if (value instanceof Number) return ((Number) value).intValue() <= 1 ? 2 : 0;
        try {
            return value != null && Integer.parseInt(String.valueOf(value)) <= 1 ? 2 : 0;
        } catch (Throwable t) {
            return 0;
        }
    }
}
