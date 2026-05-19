package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.util.ReflectUtil;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Fallback context provider that walks loaded classes to find a Tomcat Engine,
 * then traverses Host → Context children.
 *
 * Strategy stack (each tried until one returns Engine):
 * <ol>
 *   <li>Static fields on every loaded class — works for standalone Tomcat where bootstrap
 *       classes (e.g. {@code Catalina}, {@code ServerFactory}) hold static references.</li>
 *   <li>Spring Boot integration class {@code TomcatWebServer} — scans loaded classes
 *       looking for an INSTANCE of TomcatWebServer (kept reachable via Spring's
 *       {@code ApplicationContext.webServer} field), then reflectively walks
 *       {@code TomcatWebServer.tomcat → server → services → engine}.</li>
 * </ol>
 */
public class ClassLoadedContextProvider implements StandardContextProvider {

    private static final String STANDARD_ENGINE = "org.apache.catalina.core.StandardEngine";
    private static final String STANDARD_CONTEXT = "org.apache.catalina.core.StandardContext";
    private static final String TOMCAT_WEB_SERVER =
            "org.springframework.boot.web.embedded.tomcat.TomcatWebServer";

    @Override
    public String name() {
        return "ClassLoadedContextProvider";
    }

    @Override
    public List<Object> findAllContexts(Instrumentation inst) {
        List<Object> contexts = new ArrayList<>();
        Set<Object> seen = newIdentitySet();

        try {
            // Strategy 0 (standalone Tomcat): walk from a WebappClassLoader's resources → context.
            // Each webapp class loaded by a WebappClassLoader holds a back-reference to its Context.
            // NOTE: Spring Boot embedded Tomcat does NOT use WebappClassLoader — all classes load via
            // LaunchedURLClassLoader, so this strategy returns empty there.
            List<Object> viaClassLoader = findContextsViaWebappClassLoader(inst, seen);
            contexts.addAll(viaClassLoader);
            if (!contexts.isEmpty()) return contexts;

            // Fallback: Engine → Host → Context traversal.
            Class<?> engineClass = findClass(inst, STANDARD_ENGINE);
            if (engineClass == null) return contexts;

            Object engine = locateEngine(inst, engineClass);
            if (engine != null) {
                collectContexts(engine, contexts, seen);
            }
        } catch (Throwable t) {
            // swallow — best effort
        }
        return contexts;
    }

    /** Try strategies in order; return first non-null Engine. */
    private Object locateEngine(Instrumentation inst, Class<?> engineClass) {
        Object engine = findEngineViaStaticFields(inst, engineClass);
        if (engine != null) return engine;
        engine = findEngineViaThreads(engineClass);
        if (engine != null) return engine;
        engine = findEngineViaSpringBoot(inst, engineClass);
        return engine;
    }

    /**
     * Walk all live threads, find Tomcat worker/acceptor threads (whose target Runnable
     * implements org.apache.tomcat internals), and reach Engine via:
     *   Thread.target → Acceptor/Poller.endpoint → AbstractEndpoint.handler → ConnectionHandler.proto
     *   → AbstractProtocol.adapter → CoyoteAdapter.connector → Connector.service → StandardService.container
     *   → StandardEngine
     *
     * Simpler approach: scan Thread fields recursively (depth ≤ 6) for any object that is an
     * Engine instance.
     */
    private Object findEngineViaThreads(Class<?> engineClass) {
        try {
            // Discover all threads in the JVM.
            ThreadGroup root = Thread.currentThread().getThreadGroup();
            while (root.getParent() != null) root = root.getParent();
            Thread[] threads = new Thread[root.activeCount() + 32];
            int n = root.enumerate(threads, true);
            for (int i = 0; i < n; i++) {
                Thread t = threads[i];
                if (t == null) continue;
                // Heuristic: only inspect Tomcat-ish threads to keep search bounded.
                String name = t.getName();
                if (name == null || !looksLikeTomcatThread(name)) continue;
                // Use a fresh visited set per thread so exhausted paths in one don't poison another.
                Set<Object> visited = newIdentitySet();
                Object engine = walkForType(t, engineClass, visited, 0, 12);
                if (engine != null) return engine;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private boolean looksLikeTomcatThread(String name) {
        return name.contains("http-")
                || name.contains("acceptor")
                || name.contains("Acceptor")
                || name.contains("poller")
                || name.contains("Poller")
                || name.contains("ContainerBackgroundProcessor")
                || name.contains("tomcat");
    }

    /** Generic field-graph walk looking for an instance of targetType. Bounded depth, identity-visited. */
    private Object walkForType(Object obj, Class<?> targetType, Set<Object> visited, int depth, int maxDepth) {
        if (obj == null || depth > maxDepth) return null;
        if (!visited.add(obj)) return null;
        if (targetType.isInstance(obj)) return obj;
        Class<?> c = obj.getClass();
        // Don't traverse into JDK collections/strings/etc that won't contain Tomcat objects.
        String cn = c.getName();
        if (cn.startsWith("java.lang.String") || cn.startsWith("[")) return null;
        while (c != null && !c.getName().equals("java.lang.Object")) {
            for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                Class<?> ft = f.getType();
                if (ft.isPrimitive()) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(obj);
                    if (v == null) continue;
                    // Skip arrays of primitives/strings to keep cost down.
                    if (ft.isArray()) {
                        Class<?> comp = ft.getComponentType();
                        if (comp.isPrimitive() || comp == String.class) continue;
                        if (v instanceof Object[]) {
                            for (Object e : (Object[]) v) {
                                Object found = walkForType(e, targetType, visited, depth + 1, maxDepth);
                                if (found != null) return found;
                            }
                        }
                        continue;
                    }
                    Object found = walkForType(v, targetType, visited, depth + 1, maxDepth);
                    if (found != null) return found;
                } catch (Throwable ignored) {}
            }
            c = c.getSuperclass();
        }
        return null;
    }

    /**
     * For Spring Boot embedded Tomcat: locate StandardContext directly by walking from a
     * WebappClassLoader's resources.context field. Every webapp class is loaded by a
     * WebappClassLoaderBase subclass (TomcatEmbeddedWebappClassLoader for Spring Boot), and
     * that classloader holds a back-reference to its owning Context.
     *
     * Returns Context objects directly (bypasses Engine traversal).
     */
    private List<Object> findContextsViaWebappClassLoader(Instrumentation inst, Set<Object> seen) {
        List<Object> out = new ArrayList<>();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            ClassLoader cl = c.getClassLoader();
            if (cl == null) continue;
            if (!isWebappClassLoader(cl)) continue;
            try {
                Object resources = ReflectUtil.tryReadField(cl, "resources").orElse(null);
                if (resources == null) continue;
                Object ctx = ReflectUtil.tryInvoke(resources, "getContext").orElse(null);
                if (ctx == null) {
                    ctx = ReflectUtil.tryReadField(resources, "context").orElse(null);
                }
                if (isStandardContext(ctx) && seen.add(ctx)) {
                    out.add(ctx);
                }
            } catch (Throwable ignored) {}
        }
        return out;
    }

    private boolean isWebappClassLoader(ClassLoader cl) {
        Class<?> c = cl.getClass();
        while (c != null) {
            String name = c.getName();
            if (name.endsWith("WebappClassLoaderBase")
                    || name.endsWith("ParallelWebappClassLoader")
                    || name.endsWith("WebappClassLoader")) {
                return true;
            }
            c = c.getSuperclass();
        }
        return false;
    }

    /** Original strategy: scan static fields of every loaded class for an Engine instance. */
    private Object findEngineViaStaticFields(Instrumentation inst, Class<?> engineClass) {
        try {
            for (Class<?> c : inst.getAllLoadedClasses()) {
                Object engine = scanStaticFields(c, engineClass);
                if (engine != null) return engine;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    /**
     * Spring Boot strategy: find TomcatWebServer class, then scan instance fields of every
     * loaded class for a TomcatWebServer instance. Spring's ServletWebServerApplicationContext
     * holds it in a non-static field. From TomcatWebServer.tomcat we get Server → Service[] → Engine.
     */
    private Object findEngineViaSpringBoot(Instrumentation inst, Class<?> engineClass) {
        try {
            Class<?> twsClass = findClass(inst, TOMCAT_WEB_SERVER);
            if (twsClass == null) return null;

            // Scan all loaded classes for instances of TomcatWebServer held in instance fields.
            // We need to find any object whose field references a TomcatWebServer — typically
            // the Spring ApplicationContext. Brute-force: walk all loaded classes' static
            // fields first (cheap), then for each Class, instantiation tracking would require
            // a transformer. Instead we scan static fields again, this time looking for
            // TomcatWebServer directly (Spring Boot does keep a static reference path via the
            // running SpringApplication, but not always).
            //
            // Best portable approach: scan all classes' static fields recursively (1 level)
            // looking for any object whose ".tomcat" field has type Tomcat.
            Object tws = findInstanceInStaticGraph(inst, twsClass);
            if (tws == null) return null;

            // TomcatWebServer.tomcat
            Optional<Object> tomcatOpt = ReflectUtil.tryReadField(tws, "tomcat");
            if (!tomcatOpt.isPresent()) return null;
            Object tomcat = tomcatOpt.get();

            // Tomcat.getServer() → Server
            Object server = ReflectUtil.tryInvoke(tomcat, "getServer").orElse(null);
            if (server == null) return null;

            // Server.findServices() → Service[]
            Object services = ReflectUtil.tryInvoke(server, "findServices").orElse(null);
            if (!(services instanceof Object[])) return null;
            for (Object svc : (Object[]) services) {
                if (svc == null) continue;
                Object containerObj = ReflectUtil.tryInvoke(svc, "getContainer").orElse(null);
                if (containerObj != null && engineClass.isInstance(containerObj)) {
                    return containerObj;
                }
            }
        } catch (Throwable ignored) {}
        return null;
    }

    /**
     * Find an instance of {@code targetType} reachable from any loaded class's static field,
     * up to 1 level deep (the static field itself, OR a single instance-field hop).
     */
    private Object findInstanceInStaticGraph(Instrumentation inst, Class<?> targetType) {
        Set<Object> visited = newIdentitySet();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            try {
                for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                    if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                    if (f.getType().isPrimitive()) continue;
                    try {
                        f.setAccessible(true);
                        Object v = f.get(null);
                        if (v == null || !visited.add(v)) continue;
                        if (targetType.isInstance(v)) return v;
                        // One level deeper: scan instance fields of v
                        Object found = scanInstanceFields(v, targetType, visited);
                        if (found != null) return found;
                    } catch (Throwable ignored) {}
                }
            } catch (Throwable ignored) {}
        }
        return null;
    }

    private Object scanInstanceFields(Object obj, Class<?> targetType, Set<Object> visited) {
        if (obj == null) return null;
        Class<?> c = obj.getClass();
        while (c != null && !c.getName().equals("java.lang.Object")) {
            for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                if (f.getType().isPrimitive() || f.getType().isArray()) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(obj);
                    if (v == null || !visited.add(v)) continue;
                    if (targetType.isInstance(v)) return v;
                } catch (Throwable ignored) {}
            }
            c = c.getSuperclass();
        }
        return null;
    }

    private Class<?> findClass(Instrumentation inst, String name) {
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if (name.equals(c.getName())) return c;
        }
        return null;
    }

    private Object scanStaticFields(Class<?> source, Class<?> targetType) {
        try {
            for (java.lang.reflect.Field f : source.getDeclaredFields()) {
                if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                f.setAccessible(true);
                Object v = f.get(null);
                if (v != null && targetType.isAssignableFrom(v.getClass())) return v;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    /** Recursively walk Container.findChildren() until StandardContext instances are found. */
    private void collectContexts(Object container, List<Object> out, Set<Object> seen) {
        try {
            Optional<Object> children = ReflectUtil.tryInvoke(container, "findChildren");
            if (!children.isPresent()) return;
            Object arr = children.get();
            if (!(arr instanceof Object[])) return;
            for (Object child : (Object[]) arr) {
                if (child == null) continue;
                if (isStandardContext(child)) {
                    if (seen.add(child)) out.add(child);
                } else {
                    // Recurse for Host (or other Container) children
                    collectContexts(child, out, seen);
                }
            }
        } catch (Throwable ignored) {}
    }

    /** Check if obj is (or extends) StandardContext — important for Spring Boot's TomcatEmbeddedContext. */
    private boolean isStandardContext(Object obj) {
        if (obj == null) return false;
        Class<?> c = obj.getClass();
        while (c != null) {
            if (STANDARD_CONTEXT.equals(c.getName())) return true;
            c = c.getSuperclass();
        }
        return false;
    }

    private static Set<Object> newIdentitySet() {
        return Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
    }
}
