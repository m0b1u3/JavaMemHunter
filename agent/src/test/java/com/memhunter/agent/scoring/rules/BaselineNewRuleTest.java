package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BaselineNewRuleTest {

    private final BaselineNewRule rule = new BaselineNewRule();

    private Finding withId(String id) {
        Finding f = new Finding();
        f.id = id;
        f.type = "class-filter";
        return f;
    }

    private ScanContext ctxWithBaseline(String... ids) {
        BaselineIndex idx = new BaselineIndex(new HashSet<>(Arrays.asList(ids)));
        return new ScanContext(null, Whitelist.defaults(), false, idx);
    }

    @Test
    void empty_baseline_returns_zero() {
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false, BaselineIndex.empty());
        assertEquals(0, rule.evaluate(withId("finding-class-filter-aaaabbbb"), ctx));
    }

    @Test
    void finding_in_baseline_returns_zero() {
        ScanContext ctx = ctxWithBaseline("finding-class-filter-aaaabbbb");
        assertEquals(0, rule.evaluate(withId("finding-class-filter-aaaabbbb"), ctx));
    }

    @Test
    void finding_not_in_baseline_returns_plus_four() {
        ScanContext ctx = ctxWithBaseline("finding-class-filter-aaaabbbb");
        assertEquals(4, rule.evaluate(withId("finding-class-filter-newnew99"), ctx));
    }

    @Test
    void null_finding_id_returns_zero() {
        ScanContext ctx = ctxWithBaseline("finding-class-filter-aaaabbbb");
        Finding f = new Finding();
        f.id = null;
        assertEquals(0, rule.evaluate(f, ctx));
    }

    @Test
    void null_ctx_returns_zero() {
        assertEquals(0, rule.evaluate(withId("any"), null));
    }
}
