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

    // v0.12.1: lazy-load servlet (no instance) still gets a code source resolved by class name.
    static class FakeLoader {
        private final ClassLoader cl;
        FakeLoader(ClassLoader cl) { this.cl = cl; }
        public ClassLoader getClassLoader() { return cl; }
    }
    static class LazyContext {
        private final String servletClass;
        private final Object loader;
        LazyContext(String servletClass, Object loader) {
            this.servletClass = servletClass; this.loader = loader;
        }
        public String getPath() { return "/examples"; }
        public Object getLoader() { return loader; }
        public Object[] findChildren() {
            // getServlet() returns null → not instantiated (lazy)
            return new Object[] { new FakeWrapper("lazy", servletClass, null) };
        }
    }

    @Test
    void lazy_servlet_without_instance_resolves_codesource_via_context_loader() {
        // Use a real loadable class so the webapp loader yields a real code source.
        String realClass = TomcatServletScannerTest.class.getName();
        ClassLoader webappCl = TomcatServletScannerTest.class.getClassLoader();
        LazyContext ctx = new LazyContext(realClass, new FakeLoader(webappCl));

        TomcatServletScanner scanner = new TomcatServletScanner(ctx);
        List<Finding> findings = scanner.scan(new ScanReport());

        assertFalse(findings.isEmpty(), "lazy servlet must still be reported");
        Finding f = findings.get(0);
        assertNotNull(f.codeSource,
                "v0.12.1: code source must be resolved by name even without a live instance");
        assertTrue(f.codeSource.startsWith("file:"),
                "resolved code source should be a real file location: " + f.codeSource);
    }

    @Test
    void lazy_servlet_with_unloadable_class_keeps_null_codesource() {
        ClassLoader webappCl = TomcatServletScannerTest.class.getClassLoader();
        LazyContext ctx = new LazyContext("com.nope.Missing_X", new FakeLoader(webappCl));
        TomcatServletScanner scanner = new TomcatServletScanner(ctx);
        List<Finding> findings = scanner.scan(new ScanReport());
        assertFalse(findings.isEmpty());
        assertNull(findings.get(0).codeSource, "unloadable class → null code source (unchanged)");
    }

    @Test
    void when_wasCreatedDynamicServlet_not_available_isDynamic_defaults_to_true() {
        // Context has a servlet wrapper but NO wasCreatedDynamicServlet method
        Object servlet = new Object();
        Object wrapper = new Object() {
            public String getName() { return "testServlet"; }
            public String getServletClass() { return "com.example.TestServlet"; }
            public Object getServlet() { return servlet; }
            public String[] findMappings() { return new String[0]; }
            public int getLoadOnStartup() { return -1; }
        };
        Object ctx = new Object() {
            public String getPath() { return "/app"; }
            public Object[] findChildren() { return new Object[]{wrapper}; }
            // NOTE: NO wasCreatedDynamicServlet method — tests the orElse(true) fallback
        };
        TomcatServletScanner scanner = new TomcatServletScanner(ctx);
        List<Finding> findings = scanner.scan(new ScanReport());
        assertFalse(findings.isEmpty(), "should find the servlet");
        assertEquals(Boolean.TRUE, findings.get(0).attributes.get("isDynamic"),
                "missing wasCreatedDynamicServlet API must default isDynamic=true");
    }
}
