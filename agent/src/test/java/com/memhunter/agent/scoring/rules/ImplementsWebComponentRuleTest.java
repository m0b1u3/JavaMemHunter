package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ImplementsWebComponentRuleTest {
    private final ImplementsWebComponentRule rule = new ImplementsWebComponentRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void hits_web_component_types() {
        assertEquals(3, rule.evaluate(finding("class-filter"), ctx));
        assertEquals(3, rule.evaluate(finding("tomcat-filter"), ctx));
        assertEquals(3, rule.evaluate(finding("spring-interceptor"), ctx));
    }

    @Test
    void misses_other_types() {
        assertEquals(0, rule.evaluate(finding("other"), ctx));
    }

    private Finding finding(String type) {
        Finding f = new Finding();
        f.type = type;
        f.className = "com.example.Normal";
        return f;
    }
}
