package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.util.ReflectUtil;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class ClassLoadedContextProvider implements StandardContextProvider {

    private static final String STANDARD_ENGINE = "org.apache.catalina.core.StandardEngine";
    private static final String STANDARD_CONTEXT = "org.apache.catalina.core.StandardContext";

    @Override
    public String name() {
        return "ClassLoadedContextProvider";
    }

    @Override
    public List<Object> findAllContexts(Instrumentation inst) {
        List<Object> contexts = new ArrayList<>();
        Set<Object> seen = new HashSet<>();

        try {
            Class<?> engineClass = findClass(inst, STANDARD_ENGINE);
            if (engineClass != null) {
                Object engine = findEngineInstance(inst, engineClass);
                if (engine != null) {
                    collectContexts(engine, contexts, seen);
                }
            }
        } catch (Throwable t) {
            // swallow
        }
        return contexts;
    }

    private Class<?> findClass(Instrumentation inst, String name) {
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if (name.equals(c.getName())) return c;
        }
        return null;
    }

    private Object findEngineInstance(Instrumentation inst, Class<?> engineClass) {
        try {
            // Scan all loaded classes' static fields for any Engine instance.
            for (Class<?> c : inst.getAllLoadedClasses()) {
                Object engine = scanStaticFields(c, engineClass);
                if (engine != null) return engine;
            }
        } catch (Throwable t) {
            // swallow
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

    private void collectContexts(Object container, List<Object> out, Set<Object> seen) {
        try {
            Optional<Object> children = ReflectUtil.tryInvoke(container, "findChildren");
            if (!children.isPresent()) return;
            Object arr = children.get();
            if (!(arr instanceof Object[])) return;
            for (Object child : (Object[]) arr) {
                if (child == null) continue;
                String cname = child.getClass().getName();
                if (STANDARD_CONTEXT.equals(cname) && seen.add(child)) {
                    out.add(child);
                } else {
                    // Recurse for Host children
                    collectContexts(child, out, seen);
                }
            }
        } catch (Throwable ignored) {}
    }
}
