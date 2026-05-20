package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WhitelistHitRuleTest {
    private final WhitelistHitRule rule = new WhitelistHitRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void hits_framework_package() {
        assertEquals(-5, rule.evaluate(finding("org.apache.tomcat.websocket.server.WsFilter", null), ctx));
    }

    @Test
    void ignores_trusted_codesource_without_framework_package() {
        assertEquals(0, rule.evaluate(finding("com.example.NormalFilter", "file:/opt/app/app.jar"), ctx));
    }

    @Test
    void misses_unknown_package_and_codesource() {
        assertEquals(0, rule.evaluate(finding("com.attacker.FakeFilter", "file:/tmp/x.jar"), ctx));
    }

    private Finding finding(String className, String codeSource) {
        Finding f = new Finding();
        f.className = className;
        f.codeSource = codeSource;
        return f;
    }
}
