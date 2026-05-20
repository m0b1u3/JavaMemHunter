package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ApmAgentRuleTest {
    private final ApmAgentRule rule = new ApmAgentRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void hits_known_apm_agent() {
        assertEquals(-4, rule.evaluate(finding("org.apache.skywalking.apm.agent.core.plugin.Plugin"), ctx));
    }

    @Test
    void misses_normal_class() {
        assertEquals(0, rule.evaluate(finding("com.example.NormalFilter"), ctx));
    }

    private Finding finding(String className) {
        Finding f = new Finding();
        f.className = className;
        return f;
    }
}
