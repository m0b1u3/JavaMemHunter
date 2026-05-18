package com.memhunter.agent.scanner;

public final class WebComponentDetector {

    private static final String[] INTERFACES = new String[] {
        "javax.servlet.Filter",
        "javax.servlet.Servlet",
        "javax.servlet.ServletRequestListener",
        "javax.servlet.ServletContextListener",
        "javax.servlet.http.HttpSessionListener",
        "jakarta.servlet.Filter",
        "jakarta.servlet.Servlet",
        "jakarta.servlet.ServletRequestListener",
        "jakarta.servlet.ServletContextListener",
        "jakarta.servlet.http.HttpSessionListener",
        "org.apache.catalina.Valve",
        "org.springframework.web.servlet.HandlerInterceptor"
    };

    private WebComponentDetector() {}

    /**
     * @return Web component short name ("Filter" / "Servlet" / "Listener" / "Valve" / "Interceptor"),
     *         or null if no known interface is implemented.
     */
    public static String classify(Class<?> clazz) {
        if (clazz == null) return null;
        for (String iface : INTERFACES) {
            if (implementsInterface(clazz, iface)) {
                return shortName(iface);
            }
        }
        return null;
    }

    private static boolean implementsInterface(Class<?> clazz, String ifaceName) {
        Class<?> c = clazz;
        while (c != null) {
            for (Class<?> i : c.getInterfaces()) {
                if (i.getName().equals(ifaceName)) return true;
                if (implementsInterface(i, ifaceName)) return true;
            }
            c = c.getSuperclass();
        }
        return false;
    }

    private static String shortName(String ifaceName) {
        if (ifaceName.endsWith(".Filter")) return "Filter";
        if (ifaceName.endsWith(".Servlet")) return "Servlet";
        if (ifaceName.contains("Listener")) return "Listener";
        if (ifaceName.endsWith(".Valve")) return "Valve";
        if (ifaceName.endsWith(".HandlerInterceptor")) return "Interceptor";
        return ifaceName;
    }
}
