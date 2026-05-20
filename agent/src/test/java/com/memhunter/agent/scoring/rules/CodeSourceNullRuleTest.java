package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CodeSourceNullRuleTest {
    private final CodeSourceNullRule rule = new CodeSourceNullRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void hits_null_codesource() {
        assertEquals(3, rule.evaluate(new Finding(), ctx));
    }

    @Test
    void misses_present_codesource() {
        Finding f = new Finding();
        f.codeSource = "file:/opt/app/app.jar";
        assertEquals(0, rule.evaluate(f, ctx));
    }
}
