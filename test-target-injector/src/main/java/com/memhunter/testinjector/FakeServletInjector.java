package com.memhunter.testinjector;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Simulates a real Java mem-shell Servlet injection by reflectively creating
 * a StandardWrapper and inserting it as a child of StandardContext. Bypasses
 * the Servlet 3.0 addServlet() restriction that only allows registration at
 * context initialization time — same technique used by real attackers.
 */
public class FakeServletInjector {

    private final ServletContext servletContext;

    public FakeServletInjector(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void inject() {
        try {
            Object standardContext = unwrapStandardContext(servletContext);
            if (standardContext == null) {
                throw new RuntimeException("could not unwrap StandardContext from ServletContext");
            }

            ClassLoader cl = standardContext.getClass().getClassLoader();

            // Create a Wrapper through StandardContext.createWrapper()
            Method createWrapper = standardContext.getClass().getMethod("createWrapper");
            Object wrapper = createWrapper.invoke(standardContext);

            // Configure the wrapper
            invoke(wrapper, "setName", String.class, "FakeServlet");
            invoke(wrapper, "setServletClass", String.class, FakeServlet.class.getName());
            invoke(wrapper, "setServlet", javax.servlet.Servlet.class, new FakeServlet());

            // Add as child of StandardContext
            Class<?> containerClass = Class.forName("org.apache.catalina.Container", true, cl);
            Method addChild = standardContext.getClass().getMethod("addChild", containerClass);
            addChild.invoke(standardContext, wrapper);

            // Register URL mapping
            Method addServletMappingDecoded = standardContext.getClass().getMethod(
                    "addServletMappingDecoded", String.class, String.class);
            addServletMappingDecoded.invoke(standardContext, "/fake-api", "FakeServlet");
        } catch (Throwable t) {
            throw new RuntimeException("inject fake servlet failed", t);
        }
    }

    private static void invoke(Object target, String methodName, Class<?> paramType, Object arg) throws Exception {
        Method m = target.getClass().getMethod(methodName, paramType);
        m.invoke(target, arg);
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

    public static class FakeServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            deadCode();
            resp.getWriter().write("fake servlet response");
        }

        /** WARNING: dead code for bytecode rule exercise; never executed. */
        private void deadCode() {
            if (System.currentTimeMillis() < 0) {
                try {
                    Runtime.getRuntime().exec("echo nope");                          // bytecode-runtime-exec
                    java.lang.reflect.Field f =
                        getClass().getDeclaredField("serialVersionUID");             // bytecode-reflection-abuse
                    f.setAccessible(true);
                    javax.crypto.Cipher.getInstance("AES").doFinal(new byte[0]);     // bytecode-crypto
                } catch (Throwable ignored) {}
            }
        }
    }
}
