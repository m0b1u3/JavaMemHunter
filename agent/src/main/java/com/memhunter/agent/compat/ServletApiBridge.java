package com.memhunter.agent.compat;

/**
 * Detects whether the target JVM uses {@code javax.servlet} (Spring Boot 2.x / Tomcat 9)
 * or {@code jakarta.servlet} (Spring Boot 3.x / Tomcat 10) and exposes the matching
 * Servlet API class objects for reflective use elsewhere in the agent.
 *
 * <p>Initialised once when the class is loaded inside the target JVM; the agent never
 * needs to switch flavors at runtime, because each target JVM hosts exactly one.</p>
 */
public final class ServletApiBridge {

    public enum Flavor { JAVAX, JAKARTA }

    private static final Flavor FLAVOR        = detect();
    private static final Class<?> FILTER_CLASS   = load(FLAVOR, "Filter");
    private static final Class<?> SERVLET_CLASS  = load(FLAVOR, "Servlet");
    private static final Class<?> LISTENER_CLASS = load(FLAVOR, "ServletContextListener");

    public static Flavor flavor()           { return FLAVOR; }
    public static Class<?> filterClass()    { return FILTER_CLASS; }
    public static Class<?> servletClass()   { return SERVLET_CLASS; }
    public static Class<?> listenerClass()  { return LISTENER_CLASS; }

    public static boolean isFilter(Object o)   { return o != null && FILTER_CLASS.isInstance(o); }
    public static boolean isServlet(Object o)  { return o != null && SERVLET_CLASS.isInstance(o); }
    public static boolean isListener(Object o) { return o != null && LISTENER_CLASS.isInstance(o); }

    private static Flavor detect() {
        try { Class.forName("jakarta.servlet.Filter"); return Flavor.JAKARTA; }
        catch (ClassNotFoundException e) { return Flavor.JAVAX; }
    }

    private static Class<?> load(Flavor flavor, String simpleName) {
        String pkg = flavor == Flavor.JAKARTA ? "jakarta.servlet." : "javax.servlet.";
        try { return Class.forName(pkg + simpleName); }
        catch (ClassNotFoundException e) {
            throw new IllegalStateException("ServletApiBridge: missing " + pkg + simpleName, e);
        }
    }

    private ServletApiBridge() {}
}
