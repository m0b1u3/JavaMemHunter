package com.memhunter.agent.scoring;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {

    private Finding finding() {
        Finding f = new Finding();
        f.type = "tomcat-filter";
        f.className = "com.example.TestFilter";
        return f;
    }

    private ScanContext ctx(boolean explain) {
        return new ScanContext(null, Whitelist.defaults(), explain);
    }

    @Test
    void single_rule_hit_accumulates_score_and_reason() {
        RuleEngine engine = new RuleEngine(Collections.singletonList(rule("test-rule", 3)));
        Finding f = finding();
        engine.evaluate(Collections.singletonList(f), ctx(false));
        assertEquals(3, f.score);
        assertEquals("test-rule (+3)", f.reasons.get(0));
        assertEquals("low", f.level);
    }

    @Test
    void multiple_rules_accumulate_and_map_high() {
        RuleEngine engine = new RuleEngine(Arrays.asList(rule("a", 3), rule("b", 4)));
        Finding f = finding();
        engine.evaluate(Collections.singletonList(f), ctx(false));
        assertEquals(7, f.score);
        assertEquals("high", f.level);
    }

    @Test
    void negative_deltas_do_not_leave_negative_score() {
        RuleEngine engine = new RuleEngine(Collections.singletonList(rule("trust", -5)));
        Finding f = finding();
        engine.evaluate(Collections.singletonList(f), ctx(false));
        assertEquals(0, f.score);
        assertEquals("low", f.level);
        assertEquals("trust (-5)", f.reasons.get(0));
    }

    @Test
    void explain_mode_records_rule_hits() {
        RuleEngine engine = new RuleEngine(Collections.singletonList(rule("test-rule", 4)));
        Finding f = finding();
        engine.evaluate(Collections.singletonList(f), ctx(true));
        assertNotNull(f.ruleHits);
        assertEquals("test-rule", f.ruleHits.get(0).rule);
        assertEquals(4, f.ruleHits.get(0).delta);
    }

    @Test
    void non_explain_mode_leaves_rule_hits_null() {
        RuleEngine engine = new RuleEngine(Collections.singletonList(rule("test-rule", 4)));
        Finding f = finding();
        engine.evaluate(Collections.singletonList(f), ctx(false));
        assertNull(f.ruleHits);
    }

    @Test
    void rule_exceptions_are_ignored() {
        RuleEngine engine = new RuleEngine(Arrays.asList(throwingRule(), rule("ok", 4)));
        Finding f = finding();
        engine.evaluate(Collections.singletonList(f), ctx(false));
        assertEquals(4, f.score);
        assertEquals(1, f.reasons.size());
    }

    @Test
    void map_level_boundaries() {
        assertEquals("low", RuleEngine.mapLevel(3));
        assertEquals("suspicious", RuleEngine.mapLevel(4));
        assertEquals("high", RuleEngine.mapLevel(7));
        assertEquals("critical", RuleEngine.mapLevel(10));
    }

    @Test
    void default_rules_contains_eighteen_rules_including_baseline_new() {
        assertEquals(18, RuleEngine.defaultRules().size());
        assertTrue(RuleEngine.defaultRules().stream()
                .anyMatch(rule -> "baseline-new".equals(rule.name())));
    }

    @Test
    void agent_type_finding_keeps_its_fixed_score_and_level() {
        Finding agentFinding = new Finding();
        agentFinding.type = "agent-bytecode-tampered";
        agentFinding.score = 15;
        agentFinding.level = "critical";
        agentFinding.className = "org.apache.catalina.core.ApplicationFilterChain";

        java.util.List<Finding> findings = new java.util.ArrayList<>();
        findings.add(agentFinding);
        new RuleEngine().evaluate(findings, null);

        assertEquals(15, agentFinding.score, "agent-* finding 分数不应被 RuleEngine 重置");
        assertEquals("critical", agentFinding.level, "agent-* finding level 不应被改");
    }

    @Test
    void non_agent_finding_still_rescored_by_rules() {
        Finding tomcatFinding = new Finding();
        tomcatFinding.type = "tomcat-filter";
        tomcatFinding.score = 999;  // 故意设个假分数
        tomcatFinding.className = "com.example.SomeFilter";

        java.util.List<Finding> findings = new java.util.ArrayList<>();
        findings.add(tomcatFinding);
        new RuleEngine().evaluate(findings, null);

        assertNotEquals(999, tomcatFinding.score, "非 agent finding 应被规则重新评分");
    }

    private ScoringRule rule(String name, int delta) {
        return new ScoringRule() {
            public String name() { return name; }
            public int evaluate(Finding finding, ScanContext ctx) { return delta; }
        };
    }

    private ScoringRule throwingRule() {
        return new ScoringRule() {
            public String name() { return "boom"; }
            public int evaluate(Finding finding, ScanContext ctx) { throw new RuntimeException("boom"); }
        };
    }
}
