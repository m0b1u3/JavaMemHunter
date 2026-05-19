package com.memhunter.testinjector;

import javax.servlet.*;
import java.io.IOException;
import java.util.EnumSet;

public class FakeFilterInjector {

    private final ServletContext servletContext;

    public FakeFilterInjector(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void inject() {
        FilterRegistration.Dynamic reg = servletContext.addFilter("FakeFilter", new FakeFilter());
        if (reg != null) {
            reg.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, "/*");
        }
    }

    public static class FakeFilter implements Filter {
        @Override public void init(FilterConfig filterConfig) {}
        @Override public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {
            chain.doFilter(req, res);
        }
        @Override public void destroy() {}
    }
}
