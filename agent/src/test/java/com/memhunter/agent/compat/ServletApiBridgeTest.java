package com.memhunter.agent.compat;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ServletApiBridgeTest {

    @Test
    void flavor_detected_from_current_classpath_is_javax() {
        // Build profile compiles against JDK 8 + javax (test-target has no jakarta on classpath).
        assertEquals(ServletApiBridge.Flavor.JAVAX, ServletApiBridge.flavor());
    }

    @Test
    void filterClass_returns_javax_servlet_Filter_when_flavor_is_javax() throws Exception {
        assertEquals(Class.forName("javax.servlet.Filter"), ServletApiBridge.filterClass());
    }

    @Test
    void isFilter_matches_javax_filter_instance() {
        Object fakeFilter = new javax.servlet.Filter() {
            public void init(javax.servlet.FilterConfig c) {}
            public void doFilter(javax.servlet.ServletRequest r, javax.servlet.ServletResponse s, javax.servlet.FilterChain c) {}
            public void destroy() {}
        };
        assertTrue(ServletApiBridge.isFilter(fakeFilter));
    }

    @Test
    void isFilter_rejects_arbitrary_object() {
        assertFalse(ServletApiBridge.isFilter("not a filter"));
    }

    @Test
    void servletClass_returns_javax_servlet_Servlet_when_flavor_is_javax() throws Exception {
        assertEquals(Class.forName("javax.servlet.Servlet"), ServletApiBridge.servletClass());
    }

    @Test
    void listenerClass_returns_javax_ServletContextListener_when_flavor_is_javax() throws Exception {
        assertEquals(Class.forName("javax.servlet.ServletContextListener"), ServletApiBridge.listenerClass());
    }

    @Test
    void isServlet_and_isListener_are_null_safe() {
        assertFalse(ServletApiBridge.isServlet(null));
        assertFalse(ServletApiBridge.isListener(null));
        assertFalse(ServletApiBridge.isFilter(null));
    }
}
