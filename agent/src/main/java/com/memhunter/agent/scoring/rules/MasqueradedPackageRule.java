package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

/**
 * Flags a class that claims to live under a trusted framework package (org.apache.coyote.* etc.)
 * yet has no code source. A genuine framework class is always loaded from a jar and therefore has
 * a non-empty codeSource; a class with a framework-package name but no jar source is a dynamically
 * defined impostor — a classic memshell evasion (Godzilla renames Jackson classes into
 * org.apache.coyote.* to abuse the framework-package whitelist). Strong, low-false-positive signal.
 */
public class MasqueradedPackageRule implements ScoringRule {

    @Override
    public String name() {
        return "masqueraded-package";
    }

    @Override
    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || ctx == null || ctx.whitelist == null) return 0;
        if (!ctx.whitelist.isFrameworkPackage(finding.className)) return 0;
        if (finding.codeSource == null || finding.codeSource.isEmpty()) return 5;
        return 0;
    }
}
