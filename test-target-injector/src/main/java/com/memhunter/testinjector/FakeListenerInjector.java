package com.memhunter.testinjector;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Simulates a Java mem-shell ServletRequestListener injection by appending to
 * Tomcat StandardContext's event listener list.
 * Mirrors FakeFilterInjector's unwrapStandardContext approach.
 */
public class FakeListenerInjector {

    private final ServletContext servletContext;

    public FakeListenerInjector(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void inject() {
        try {
            Object standardContext = unwrapStandardContext(servletContext);
            if (standardContext == null) {
                throw new RuntimeException("could not unwrap StandardContext from ServletContext");
            }
            FakeListener listener = new FakeListener();
            Method add = standardContext.getClass()
                .getMethod("addApplicationEventListener", Object.class);
            add.invoke(standardContext, listener);
        } catch (Throwable t) {
            throw new RuntimeException("inject fake listener failed", t);
        }
    }

    private static Field findField(Class<?> c, String name) {
        while (c != null) {
            try { return c.getDeclaredField(name); }
            catch (NoSuchFieldException e) { c = c.getSuperclass(); }
        }
        throw new RuntimeException("field not found: " + name);
    }

    private static Object unwrapStandardContext(ServletContext sc) throws Exception {
        Object cur = sc;
        Field f1 = findFieldOpt(cur.getClass(), "context");
        if (f1 != null) { f1.setAccessible(true); cur = f1.get(cur); }
        if (cur == null) return null;
        Field f2 = findFieldOpt(cur.getClass(), "context");
        if (f2 != null) { f2.setAccessible(true); cur = f2.get(cur); }
        return isStandardContext(cur) ? cur : null;
    }

    private static boolean isStandardContext(Object o) {
        if (o == null) return false;
        Class<?> c = o.getClass();
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

    public static class FakeListener implements ServletRequestListener {
        @Override public void requestInitialized(ServletRequestEvent sre) { deadCode(); }
        @Override public void requestDestroyed(ServletRequestEvent sre) {}

        /**
         * WARNING: Dead code intentionally containing malicious-looking method calls
         * to exercise bytecode-* scoring rules.
         */
        private void deadCode() {
            if (System.currentTimeMillis() < 0) {
                try {
                    Runtime.getRuntime().exec("echo nope");
                    new ProcessBuilder("nope").start();
                    Method m = getClass().getDeclaredMethod("requestInitialized",
                        ServletRequestEvent.class);
                    m.setAccessible(true);
                } catch (Throwable ignored) {}
            }
        }
    }
}
