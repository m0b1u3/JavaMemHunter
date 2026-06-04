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
 *
 * <p><b>Known limitation:</b> The trusted whitelist includes prefixes such as
 * {@code com.fasterxml.jackson.*} and {@code org.springframework.*}. Framework runtime-generated
 * classes — Jackson polymorphic-type resolver helpers and Spring CGLIB proxies — may have a null
 * codeSource and could therefore trigger this rule (+5 false positive). In practice the risk is
 * very low: this rule is only applied to findings that the scanner has already identified as
 * registered web components (Filter / Servlet / Listener). Ordinary CGLIB proxies and Jackson
 * helpers are never registered as web components, so they never appear as findings. This is an
 * intentional design trade-off favouring lower false-negatives over lower false-positives; the
 * limitation is documented here for future reference.
 */
public class MasqueradedPackageRule implements ScoringRule {

    @Override
    public String name() {
        return "masqueraded-package";
    }

    @Override
    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null || ctx == null || ctx.whitelist == null) return 0;
        if (!ctx.whitelist.isFrameworkPackage(finding.className)) return 0;
        if (finding.codeSource == null || finding.codeSource.isEmpty()) return 5;
        return 0;
    }
}
