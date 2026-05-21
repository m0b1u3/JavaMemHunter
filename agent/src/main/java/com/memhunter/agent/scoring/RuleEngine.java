package com.memhunter.agent.scoring;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.rules.ApmAgentRule;
import com.memhunter.agent.scoring.rules.CodeSourceNullRule;
import com.memhunter.agent.scoring.rules.CodeSourceTempDirRule;
import com.memhunter.agent.scoring.rules.FilterOrderAtTopRule;
import com.memhunter.agent.scoring.rules.HighEntropyClassNameRule;
import com.memhunter.agent.scoring.rules.ImplementsWebComponentRule;
import com.memhunter.agent.scoring.rules.MappingPathDisguiseRule;
import com.memhunter.agent.scoring.rules.NonBusinessPackageRule;
import com.memhunter.agent.scoring.rules.RuntimeOnlyRule;
import com.memhunter.agent.scoring.rules.UnusualClassLoaderRule;
import com.memhunter.agent.scoring.rules.UrlPatternWildcardRule;
import com.memhunter.agent.scoring.rules.WhitelistHitRule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RuleEngine {

    private final List<ScoringRule> rules;

    public RuleEngine() {
        this(defaultRules());
    }

    public RuleEngine(List<ScoringRule> rules) {
        this.rules = rules;
    }

    public static List<ScoringRule> defaultRules() {
        return Arrays.asList(
                new ImplementsWebComponentRule(),
                new CodeSourceNullRule(),
                new CodeSourceTempDirRule(),
                new RuntimeOnlyRule(),
                new UrlPatternWildcardRule(),
                new FilterOrderAtTopRule(),
                new HighEntropyClassNameRule(),
                new NonBusinessPackageRule(),
                new UnusualClassLoaderRule(),
                new MappingPathDisguiseRule(),
                new WhitelistHitRule(),
                new ApmAgentRule(),
                new com.memhunter.agent.scoring.rules.BytecodeRuntimeExecRule(),
                new com.memhunter.agent.scoring.rules.BytecodeProcessBuilderRule(),
                new com.memhunter.agent.scoring.rules.BytecodeDefineClassRule(),
                new com.memhunter.agent.scoring.rules.BytecodeReflectionAbuseRule(),
                new com.memhunter.agent.scoring.rules.BytecodeCryptoRule()
        );
    }

    public void evaluate(List<Finding> findings, ScanContext ctx) {
        if (findings == null) return;
        for (Finding finding : findings) {
            evaluateOne(finding, ctx);
        }
    }

    private void evaluateOne(Finding finding, ScanContext ctx) {
        if (finding == null) return;
        finding.score = 0;
        finding.reasons.clear();
        if (ctx != null && ctx.explain) finding.ruleHits = new ArrayList<>();

        for (ScoringRule rule : rules) {
            int delta;
            try {
                delta = rule.evaluate(finding, ctx);
            } catch (Throwable t) {
                continue;
            }
            if (delta == 0) continue;
            finding.score += delta;
            String sign = delta > 0 ? "+" : "";
            finding.reasons.add(rule.name() + " (" + sign + delta + ")");
            if (ctx != null && ctx.explain) {
                finding.ruleHits.add(new Finding.RuleHit(rule.name(), delta));
            }
        }

        if (finding.score < 0) finding.score = 0;
        finding.level = mapLevel(finding.score);
        finding.recommendation = recommend(finding.level);
    }

    static String mapLevel(int score) {
        if (score >= 10) return "critical";
        if (score >= 7) return "high";
        if (score >= 4) return "suspicious";
        return "low";
    }

    private static String recommend(String level) {
        if ("critical".equals(level)) return "Immediate review required: highly likely a memshell.";
        if ("high".equals(level)) return "Manual review strongly recommended.";
        if ("suspicious".equals(level)) return "Review finding and compare with known baseline.";
        return "Informational only.";
    }
}
