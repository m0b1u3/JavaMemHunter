package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

/**
 * Trusts framework classes by lowering their score — but only when there is positive evidence the
 * class really is a framework class: it must have a code source (i.e. it was loaded from a jar).
 *
 * <p>v0.13: a class claiming a trusted framework package (org.apache.coyote.* etc.) but with NO
 * code source is almost certainly a masquerading memshell (e.g. Godzilla renames Jackson classes
 * into org.apache.coyote.* and defines them dynamically, so they have no jar source). Such a class
 * must NOT receive the -5 trust discount. The positive "this is a masquerade" signal is scored
 * separately by MasqueradedPackageRule.
 */
public class WhitelistHitRule implements ScoringRule {
    public String name() { return "whitelist-hit"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || ctx == null || ctx.whitelist == null) return 0;
        if (!ctx.whitelist.isFrameworkPackage(finding.className)) return 0;
        if (finding.codeSource == null || finding.codeSource.isEmpty()) return 0;
        return -5;
    }
}
