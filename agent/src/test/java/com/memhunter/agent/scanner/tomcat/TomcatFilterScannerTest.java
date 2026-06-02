package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TomcatFilterScannerTest {

    static class FakeFilterDef {
        public final boolean dynamic;
        public final String filterClass;
        FakeFilterDef(String cls, boolean dynamic) {
            this.filterClass = cls; this.dynamic = dynamic;
        }
    }

    static Object makeContext(String filterName, Object filterDef) {
        Map<String, Object> defs = new HashMap<>();
        defs.put(filterName, filterDef);
        return new Object() {
            public String getPath() { return "/app"; }
            public Map<String, Object> filterDefs = defs;
            public Object[] filterMaps = new Object[0];
            public Map<?, ?> filterConfigs = new HashMap<>();
        };
    }

    @Test
    void filter_with_dynamic_true_gets_isDynamic_true() {
        Object ctx = makeContext("evilFilter", new FakeFilterDef("com.evil.EvilFilter", true));
        TomcatFilterScanner scanner = new TomcatFilterScanner(ctx);
        List<Finding> findings = scanner.scan(new ScanReport());
        assertFalse(findings.isEmpty(), "should find the filter");
        assertEquals(Boolean.TRUE, findings.get(0).attributes.get("isDynamic"));
    }

    @Test
    void filter_with_dynamic_false_gets_isDynamic_false() {
        Object ctx = makeContext("safeFilter", new FakeFilterDef("com.example.SafeFilter", false));
        TomcatFilterScanner scanner = new TomcatFilterScanner(ctx);
        List<Finding> findings = scanner.scan(new ScanReport());
        assertFalse(findings.isEmpty(), "should find the filter");
        assertEquals(Boolean.FALSE, findings.get(0).attributes.get("isDynamic"));
    }

    @Test
    void filter_without_dynamic_field_defaults_to_isDynamic_true() {
        // FilterDef with no 'dynamic' field — tests the orElse(true) fallback
        Object noFieldDef = new Object() {
            public String filterClass = "com.old.Filter";
        };
        Object ctx = makeContext("oldFilter", noFieldDef);
        TomcatFilterScanner scanner = new TomcatFilterScanner(ctx);
        List<Finding> findings = scanner.scan(new ScanReport());
        assertFalse(findings.isEmpty(), "should find the filter");
        assertEquals(Boolean.TRUE, findings.get(0).attributes.get("isDynamic"),
                "missing dynamic field must default to isDynamic=true");
    }
}
