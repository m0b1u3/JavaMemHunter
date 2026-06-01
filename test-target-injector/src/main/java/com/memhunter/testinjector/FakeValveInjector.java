package com.memhunter.testinjector;

import javax.servlet.ServletContext;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Simulates a Tomcat Valve mem-shell injection by adding a dynamic-proxy Valve
 * onto the Context pipeline. Uses Pipeline.addValve(Valve) public API where
 * possible; the proxy implements both org.apache.catalina.Valve and
 * org.apache.catalina.Lifecycle so Tomcat can manage its lifecycle.
 */
public class FakeValveInjector {

    private final ServletContext servletContext;

    public FakeValveInjector(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void inject() {
        try {
            Object standardContext = unwrapStandardContext(servletContext);
            if (standardContext == null) {
                throw new RuntimeException("could not unwrap StandardContext");
            }
            ClassLoader cl = standardContext.getClass().getClassLoader();
            Class<?> valveIface = Class.forName("org.apache.catalina.Valve", true, cl);
            Class<?> lifecycleIface = Class.forName("org.apache.catalina.Lifecycle", true, cl);

            Method getPipeline = standardContext.getClass().getMethod("getPipeline");
            Object pipeline = getPipeline.invoke(standardContext);
            Method addValve = pipeline.getClass().getMethod("addValve", valveIface);

            Object valveProxy = Proxy.newProxyInstance(cl,
                new Class<?>[]{ valveIface, lifecycleIface },
                new FakeValveHandler());

            addValve.invoke(pipeline, valveProxy);
        } catch (Throwable t) {
            throw new RuntimeException("inject fake valve failed", t);
        }
    }

    private static class FakeValveHandler implements InvocationHandler {
        private Object next;

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String name = method.getName();
            if ("getNext".equals(name)) return next;
            if ("setNext".equals(name)) { next = args[0]; return null; }
            if ("invoke".equals(name)) {
                deadCode();
                if (next != null) {
                    // Tomcat's StandardContextValve.invoke() is public but lives in
                    // a JDK-module-encapsulated package; reflective Method.invoke
                    // requires setAccessible under JDK 17+ even on public methods.
                    Method nextInvoke = next.getClass().getMethod("invoke",
                        method.getParameterTypes());
                    nextInvoke.setAccessible(true);
                    return nextInvoke.invoke(next, args);
                }
                return null;
            }
            // Lifecycle stubs — return safe defaults
            if ("start".equals(name) || "stop".equals(name)
                || "init".equals(name) || "destroy".equals(name)
                || "addLifecycleListener".equals(name)
                || "removeLifecycleListener".equals(name)) return null;
            if ("findLifecycleListeners".equals(name)) {
                return java.lang.reflect.Array.newInstance(
                    Class.forName("org.apache.catalina.LifecycleListener"), 0);
            }
            if ("isAsyncSupported".equals(name)) return true;
            if ("getInfo".equals(name)) return "FakeValve/1.0";
            if ("getState".equals(name)) {
                // Return STARTED enum constant via reflection
                Class<?> stateClass = Class.forName("org.apache.catalina.LifecycleState",
                    true, method.getDeclaringClass().getClassLoader());
                for (Object c : stateClass.getEnumConstants()) {
                    if ("STARTED".equals(c.toString())) return c;
                }
                return null;
            }
            if ("getStateName".equals(name)) return "STARTED";
            if ("getContainer".equals(name) || "setContainer".equals(name)) {
                if ("setContainer".equals(name)) return null;
                return null;
            }
            if ("toString".equals(name)) return "FakeValveProxy";
            if ("hashCode".equals(name)) return System.identityHashCode(proxy);
            if ("equals".equals(name)) return proxy == args[0];
            return null;
        }

        /**
         * WARNING: Dead code with malicious-looking method calls. Never executes.
         */
        private void deadCode() {
            if (System.currentTimeMillis() < 0) {
                try {
                    Runtime.getRuntime().exec("echo nope");
                    new ProcessBuilder("nope").start();
                } catch (Throwable ignored) {}
            }
        }
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
}
