package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NonBusinessPackageRuleTest {
    private final NonBusinessPackageRule rule = new NonBusinessPackageRule();

    @Test
    void hits_unknown_non_framework_package() {
        assertEquals(2, rule.evaluate(finding("com.attacker.FakeFilter"), ctx(Whitelist.defaults())));
    }

    @Test
    void misses_framework_package() {
        assertEquals(0, rule.evaluate(finding("org.apache.tomcat.websocket.server.WsFilter"), ctx(Whitelist.defaults())));
    }

    @Test
    void misses_user_business_package() throws Exception {
        Path file = Files.createTempFile("wl", ".txt");
        Files.write(file, Collections.singletonList("business:com.example."));
        Whitelist whitelist = Whitelist.defaults();
        whitelist.loadFromFile(file.toString());
        assertEquals(0, rule.evaluate(finding("com.example.FakeFilter"), ctx(whitelist)));
    }

    private ScanContext ctx(Whitelist whitelist) {
        return new ScanContext(null, whitelist, false);
    }

    private Finding finding(String className) {
        Finding f = new Finding();
        f.className = className;
        return f;
    }
}
