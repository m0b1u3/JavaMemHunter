package com.memhunter.agent.scanner;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

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
        Set<Class<?>> visited = new HashSet<>();
        Deque<Class<?>> queue = new ArrayDeque<>();
        queue.add(clazz);
        while (!queue.isEmpty()) {
            Class<?> c = queue.poll();
            if (c == null || !visited.add(c)) continue;
            if (c.getName().equals(ifaceName)) return true;
            for (Class<?> i : c.getInterfaces()) queue.add(i);
            if (c.getSuperclass() != null) queue.add(c.getSuperclass());
        }
        return false;
    }

    private static String shortName(String ifaceName) {
        if (ifaceName.endsWith(".ServletRequestListener")) return "ListenerRequest";
        if (ifaceName.endsWith(".ServletContextListener")) return "ListenerContext";
        if (ifaceName.endsWith(".HttpSessionListener")) return "ListenerSession";
        if (ifaceName.endsWith(".Filter")) return "Filter";
        if (ifaceName.endsWith(".Servlet")) return "Servlet";
        if (ifaceName.endsWith(".Valve")) return "Valve";
        if (ifaceName.endsWith(".HandlerInterceptor")) return "Interceptor";
        return ifaceName;
    }
}
