package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

public class CodeSourceTempDirRule implements ScoringRule {
    public String name() { return "code-source-temp-dir"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.codeSource == null) return 0;
        String s = finding.codeSource.replace('\\', '/').toLowerCase();
        return (s.contains("/tmp/") || s.contains("/var/tmp/")
                || s.contains("/appdata/local/temp/")) ? 3 : 0;
    }
}
