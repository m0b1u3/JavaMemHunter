package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.util.ReflectUtil;

import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.Optional;

/**
 * Resolves a class's code source <em>by name</em> using a Tomcat context's webapp class loader,
 * for components that have not been instantiated yet (e.g. lazy-load servlets / filters whose
 * {@code load-on-startup} is unset).
 *
 * <p>Background: {@code TomcatServletScanner}/{@code TomcatFilterScanner} previously only read the
 * code source from a live instance. Stock Tomcat example servlets are lazy — at scan time their
 * wrapper has no instance, so the scanner reported {@code codeSource=null}. That single gap caused
 * a cascade of false positives: {@code CodeSourceNullRule} added points for the "missing" source,
 * and {@code BenignComponentRule} could not recognise the component as a normal webapp class and so
 * did not suppress it. Resolving the code source from the declared class name + webapp loader closes
 * the gap without instantiating anything.
 *
 * <p>Loading the class through the webapp loader is read-only and does not run any servlet code —
 * {@code loadClass} performs linking but not the servlet lifecycle ({@code init}/{@code service}).
 */
public final class WebappCodeSourceResolver {

    private WebappCodeSourceResolver() {}

    /**
     * @return the code source location string for {@code className} as resolved through the
     *         context's webapp class loader, or {@code null} if the class name or context is null,
     *         the loader cannot be obtained, the class cannot be loaded, or it has no code source.
     */
    public static String resolveByName(String className, Object context) {
        if (className == null || className.isEmpty() || context == null) return null;
        ClassLoader cl = webappClassLoader(context);
        if (cl == null) return null;
        try {
            Class<?> clazz = Class.forName(className, false, cl);
            ProtectionDomain pd = clazz.getProtectionDomain();
            if (pd == null) return null;
            CodeSource cs = pd.getCodeSource();
            if (cs == null || cs.getLocation() == null) return null;
            return cs.getLocation().toString();
        } catch (Throwable t) {
            return null;
        }
    }

    /** context.getLoader().getClassLoader() — best effort, null on any failure. */
    public static ClassLoader webappClassLoader(Object context) {
        try {
            Optional<Object> loader = ReflectUtil.tryInvoke(context, "getLoader");
            if (!loader.isPresent() || loader.get() == null) return null;
            Optional<Object> cl = ReflectUtil.tryInvoke(loader.get(), "getClassLoader");
            if (cl.isPresent() && cl.get() instanceof ClassLoader) {
                return (ClassLoader) cl.get();
            }
            return null;
        } catch (Throwable t) {
            return null;
        }
    }
}
