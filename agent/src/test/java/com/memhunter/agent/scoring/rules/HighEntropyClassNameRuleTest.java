package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HighEntropyClassNameRuleTest {
    private final HighEntropyClassNameRule rule = new HighEntropyClassNameRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void hits_randomish_simple_name() {
        assertEquals(1, rule.evaluate(finding("com.example.A9xQ7mN4pL2z"), ctx));
    }

    @Test
    void misses_plain_name() {
        assertEquals(0, rule.evaluate(finding("com.example.FakeFilter"), ctx));
    }

    @Test
    void evaluates_inner_class_simple_name_only() {
        assertEquals(0, rule.evaluate(finding("com.example.Xa9bZ3Q1KpRz$Filter"), ctx));
    }

    private Finding finding(String className) {
        Finding f = new Finding();
        f.className = className;
        return f;
    }
}
