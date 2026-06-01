package com.memhunter.testinjector;

import jakarta.servlet.*;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

/**
 * Simulates a real Java mem-shell Filter injection by directly mutating Tomcat
 * StandardContext internal data structures via reflection. The standard
 * ServletContext.addFilter() API is only valid during context initialization;
 * a real attacker bypasses that restriction the same way this class does.
 */
public class FakeFilterInjector {

    private final ServletContext servletContext;

    public FakeFilterInjector(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void inject() {
        try {
            Object standardContext = unwrapStandardContext(servletContext);
            if (standardContext == null) {
                throw new RuntimeException("could not unwrap StandardContext from ServletContext");
            }

            ClassLoader cl = standardContext.getClass().getClassLoader();

            // Build a FilterDef
            Class<?> filterDefClass = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef", true, cl);
            Object filterDef = filterDefClass.getDeclaredConstructor().newInstance();
            invoke(filterDefClass, filterDef, "setFilterName", String.class, "FakeFilter");
            invoke(filterDefClass, filterDef, "setFilterClass", String.class, FakeFilter.class.getName());
            invoke(filterDefClass, filterDef, "setFilter", jakarta.servlet.Filter.class, new FakeFilter());

            // Build a FilterMap
            Class<?> filterMapClass = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap", true, cl);
            Object filterMap = filterMapClass.getDeclaredConstructor().newInstance();
            invoke(filterMapClass, filterMap, "setFilterName", String.class, "FakeFilter");
            invoke(filterMapClass, filterMap, "addURLPattern", String.class, "/*");

            // Register filterDef
            Method addFilterDef = standardContext.getClass().getMethod("addFilterDef", filterDefClass);
            addFilterDef.invoke(standardContext, filterDef);

            // Register filterMap
            Method addFilterMapBefore = standardContext.getClass().getMethod("addFilterMapBefore", filterMapClass);
            addFilterMapBefore.invoke(standardContext, filterMap);

            // Build and register ApplicationFilterConfig so the filter is actually wired into the chain
            Class<?> appFilterConfigClass = Class.forName(
                    "org.apache.catalina.core.ApplicationFilterConfig", true, cl);
            java.lang.reflect.Constructor<?> ctor = appFilterConfigClass.getDeclaredConstructor(
                    Class.forName("org.apache.catalina.Context", true, cl),
                    filterDefClass);
            ctor.setAccessible(true);
            Object appFilterConfig = ctor.newInstance(standardContext, filterDef);

            Field configsField = findField(standardContext.getClass(), "filterConfigs");
            configsField.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<String, Object> filterConfigs = (Map<String, Object>) configsField.get(standardContext);
            filterConfigs.put("FakeFilter", appFilterConfig);
        } catch (Throwable t) {
            throw new RuntimeException("inject fake filter failed", t);
        }
    }

    private static void invoke(Class<?> targetClass, Object target, String methodName,
                               Class<?> paramType, Object arg) throws Exception {
        Method m = targetClass.getMethod(methodName, paramType);
        m.invoke(target, arg);
    }

    private static Field findField(Class<?> c, String name) {
        while (c != null) {
            try { return c.getDeclaredField(name); }
            catch (NoSuchFieldException e) { c = c.getSuperclass(); }
        }
        throw new RuntimeException("field not found: " + name);
    }

    /**
     * Unwrap ApplicationContextFacade → ApplicationContext → StandardContext.
     * In Spring Boot embedded Tomcat the final type is TomcatEmbeddedContext (a StandardContext subclass).
     */
    private static Object unwrapStandardContext(ServletContext sc) throws Exception {
        Object cur = sc;
        Field f1 = findFieldOpt(cur.getClass(), "context");
        if (f1 != null) { f1.setAccessible(true); cur = f1.get(cur); }
        if (cur == null) return null;
        Field f2 = findFieldOpt(cur.getClass(), "context");
        if (f2 != null) { f2.setAccessible(true); cur = f2.get(cur); }
        return isStandardContext(cur) ? cur : null;
    }

    private static boolean isStandardContext(Object obj) {
        if (obj == null) return false;
        Class<?> c = obj.getClass();
        while (c != null) {
            if ("org.apache.catalina.core.StandardContext".equals(c.getName())) return true;
            c = c.getSuperclass();
        }
        return false;
    }

    private static Field findFieldOpt(Class<?> c, String name) {
        while (c != null) {
            try { return c.getDeclaredField(name); }
            catch (NoSuchFieldException e) { c = c.getSuperclass(); }
        }
        return null;
    }

    public static class FakeFilter implements Filter {
        @Override public void init(FilterConfig filterConfig) {}
        @Override public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {
            deadCode();
            chain.doFilter(req, res);
        }
        @Override public void destroy() {}

        /**
         * WARNING: Dead code intentionally containing malicious-looking method calls
         * to exercise bytecode-* scoring rules. Wrapped in a runtime-impossible
         * condition so it never actually executes.
         */
        private void deadCode() {
            if (System.currentTimeMillis() < 0) {
                try {
                    Runtime.getRuntime().exec("echo nope");                          // bytecode-runtime-exec
                    new ProcessBuilder("nope").start();                              // bytecode-process-builder
                    java.lang.reflect.Method m =
                        getClass().getDeclaredMethod("doFilter",
                            ServletRequest.class, ServletResponse.class, FilterChain.class);
                    m.setAccessible(true);                                            // bytecode-reflection-abuse
                } catch (Throwable ignored) {}
            }
        }
    }
}
