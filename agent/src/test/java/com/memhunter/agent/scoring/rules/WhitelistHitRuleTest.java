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
    void framework_package_with_codesource_is_trusted_minus5() {
        assertEquals(-5, rule.evaluate(
                finding("org.apache.tomcat.websocket.server.WsFilter",
                        "file:/opt/tomcat/lib/tomcat-websocket.jar"), ctx));
    }

    @Test
    void framework_package_with_null_codesource_is_not_trusted_zero() {
        assertEquals(0, rule.evaluate(
                finding("org.apache.coyote.jsontype.impl.TypeIdResolverBase", null), ctx));
    }

    @Test
    void framework_package_with_empty_codesource_is_not_trusted_zero() {
        assertEquals(0, rule.evaluate(
                finding("org.apache.coyote.ser.PropertyWriter", ""), ctx));
    }

    @Test
    void non_framework_package_is_zero() {
        assertEquals(0, rule.evaluate(finding("com.example.NormalFilter", "file:/opt/app/app.jar"), ctx));
    }

    private Finding finding(String className, String codeSource) {
        Finding f = new Finding();
        f.className = className;
        f.codeSource = codeSource;
        return f;
    }
}
