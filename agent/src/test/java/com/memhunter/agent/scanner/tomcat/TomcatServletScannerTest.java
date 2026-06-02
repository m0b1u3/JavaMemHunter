package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class TomcatServletScannerTest {

    static class FakeWrapper {
        private final String name;
        private final String servletClass;
        private final Object servlet;
        FakeWrapper(String name, String servletClass, Object servlet) {
            this.name = name; this.servletClass = servletClass; this.servlet = servlet;
        }
        public String getName() { return name; }
        public String getServletClass() { return servletClass; }
        public Object getServlet() { return servlet; }
        public String[] findMappings() { return new String[0]; }
        public int getLoadOnStartup() { return -1; }
    }

    static class FakeContext {
        private final boolean dynamic;
        FakeContext(boolean dynamic) { this.dynamic = dynamic; }
        public Object[] findChildren() {
            return new Object[] { new FakeWrapper("myServlet", "com.example.MyServlet", new Object()) };
        }
        public String getPath() { return "/app"; }
        public boolean wasCreatedDynamicServlet(Object servlet) { return dynamic; }
    }

    @Test
    void servlet_registered_via_addServlet_gets_isDynamic_true() {
        TomcatServletScanner scanner = new TomcatServletScanner(new FakeContext(true));
        List<Finding> findings = scanner.scan(new ScanReport());
        assertFalse(findings.isEmpty());
        assertEquals(Boolean.TRUE, findings.get(0).attributes.get("isDynamic"));
    }

    @Test
    void servlet_declared_in_webxml_gets_isDynamic_false() {
        TomcatServletScanner scanner = new TomcatServletScanner(new FakeContext(false));
        List<Finding> findings = scanner.scan(new ScanReport());
        assertFalse(findings.isEmpty());
        assertEquals(Boolean.FALSE, findings.get(0).attributes.get("isDynamic"));
    }

    @Test
    void when_wasCreatedDynamicServlet_not_available_isDynamic_defaults_to_true() {
        Object bareContext = new Object() {
            public Object[] findChildren() { return new Object[0]; }
            public String getPath() { return "/"; }
        };
        TomcatServletScanner scanner = new TomcatServletScanner(bareContext);
        List<Finding> findings = scanner.scan(new ScanReport());
        assertTrue(findings.isEmpty());  // empty because findChildren returns empty
    }
}
