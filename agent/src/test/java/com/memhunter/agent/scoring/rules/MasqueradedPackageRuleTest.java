package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MasqueradedPackageRuleTest {
    private final MasqueradedPackageRule rule = new MasqueradedPackageRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void framework_prefix_with_null_codesource_is_masquerade_plus5() {
        assertEquals(5, rule.evaluate(
                finding("org.apache.coyote.jsontype.impl.TypeIdResolverBase", null), ctx));
    }

    @Test
    void framework_prefix_with_empty_codesource_is_masquerade_plus5() {
        assertEquals(5, rule.evaluate(finding("org.apache.coyote.ser.PropertyWriter", ""), ctx));
    }

    @Test
    void framework_prefix_with_real_codesource_is_zero() {
        assertEquals(0, rule.evaluate(
                finding("org.apache.tomcat.websocket.server.WsFilter",
                        "file:/opt/tomcat/lib/tomcat-websocket.jar"), ctx));
    }

    @Test
    void normal_business_class_with_null_codesource_is_zero() {
        assertEquals(0, rule.evaluate(finding("com.example.UserServlet", null), ctx));
    }

    @Test
    void null_className_is_zero() {
        assertEquals(0, rule.evaluate(finding(null, null), ctx));
    }

    private Finding finding(String className, String codeSource) {
        Finding f = new Finding();
        f.className = className;
        f.codeSource = codeSource;
        return f;
    }

    private Finding findingTyped(String type, String className, String codeSource) {
        Finding f = new Finding();
        f.type = type;
        f.className = className;
        f.codeSource = codeSource;
        return f;
    }

    @Test
    void class_filter_masquerade_is_zero_dependency_not_critical() {
        assertEquals(0, rule.evaluate(
                findingTyped("class-filter", "org.apache.coyote.ser.PropertyWriter", null), ctx));
    }

    @Test
    void class_servlet_masquerade_is_zero() {
        assertEquals(0, rule.evaluate(
                findingTyped("class-servlet", "org.apache.coyote.deser.std.StackTraceElementDeserializer", null), ctx));
    }

    @Test
    void tomcat_filter_masquerade_still_plus5() {
        assertEquals(5, rule.evaluate(
                findingTyped("tomcat-filter", "org.apache.coyote.deser.BuilderBasedDeserializer", null), ctx));
    }

    @Test
    void spring_mapping_masquerade_still_plus5() {
        assertEquals(5, rule.evaluate(
                findingTyped("spring-mapping", "org.apache.coyote.X", null), ctx));
    }
}
