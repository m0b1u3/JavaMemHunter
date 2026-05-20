package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UrlPatternWildcardRuleTest {
    private final UrlPatternWildcardRule rule = new UrlPatternWildcardRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void hits_wildcard_url_pattern() {
        Finding f = finding();
        f.attributes.put("urlPatterns", Collections.singletonList("/*"));
        assertEquals(2, rule.evaluate(f, ctx));
    }

    @Test
    void hits_root_url_pattern() {
        Finding f = finding();
        f.attributes.put("urlPatterns", Collections.singletonList("/"));
        assertEquals(2, rule.evaluate(f, ctx));
    }

    @Test
    void misses_specific_url_pattern() {
        Finding f = finding();
        f.attributes.put("urlPatterns", Collections.singletonList("/admin/login"));
        assertEquals(0, rule.evaluate(f, ctx));
    }

    @Test
    void ignores_spring_pattern_attribute() {
        Finding f = finding();
        f.attributes.put("pattern", "{GET [/]}");
        assertEquals(0, rule.evaluate(f, ctx));
    }

    private Finding finding() {
        Finding f = new Finding();
        f.type = "tomcat-filter";
        f.className = "com.example.Filter";
        return f;
    }
}
