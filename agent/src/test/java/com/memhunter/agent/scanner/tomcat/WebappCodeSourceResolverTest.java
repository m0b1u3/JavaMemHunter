package com.memhunter.agent.scanner.tomcat;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WebappCodeSourceResolverTest {

    // A fake StandardContext exposing getLoader() -> Loader exposing getClassLoader().
    static class FakeLoader {
        private final ClassLoader cl;
        FakeLoader(ClassLoader cl) { this.cl = cl; }
        public ClassLoader getClassLoader() { return cl; }
    }
    static class FakeContext {
        private final Object loader;
        FakeContext(Object loader) { this.loader = loader; }
        public Object getLoader() { return loader; }
    }

    @Test
    void resolves_code_source_for_uninstantiated_class_via_context_loader() {
        // The webapp loader can load this very test class -> its codeSource is the test-classes dir.
        ClassLoader webappCl = WebappCodeSourceResolverTest.class.getClassLoader();
        FakeContext ctx = new FakeContext(new FakeLoader(webappCl));

        String cs = WebappCodeSourceResolver.resolveByName(
                WebappCodeSourceResolverTest.class.getName(), ctx);

        assertNotNull(cs, "code source must be resolvable from the context loader");
        assertTrue(cs.contains("classes") || cs.endsWith(".jar") || cs.startsWith("file:"),
                "resolved code source should look like a real location: " + cs);
    }

    @Test
    void returns_null_for_null_inputs() {
        assertNull(WebappCodeSourceResolver.resolveByName(null, new Object()));
        assertNull(WebappCodeSourceResolver.resolveByName("java.lang.String", null));
    }

    @Test
    void returns_null_when_class_not_loadable() {
        ClassLoader webappCl = WebappCodeSourceResolverTest.class.getClassLoader();
        FakeContext ctx = new FakeContext(new FakeLoader(webappCl));
        assertNull(WebappCodeSourceResolver.resolveByName(
                "com.does.not.Exist_" + System.nanoTime(), ctx));
    }

    @Test
    void returns_null_when_context_has_no_loader() {
        // context without getLoader() — must not throw.
        assertNull(WebappCodeSourceResolver.resolveByName("java.lang.String", new Object()));
    }
}
