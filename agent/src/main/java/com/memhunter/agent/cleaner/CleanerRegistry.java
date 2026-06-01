package com.memhunter.agent.cleaner;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Type-based dispatch table for Cleaner factories. Each registration declares:
 *   - exact equals match or startsWith prefix match on Finding.type
 *   - the ContextKind the cleaner needs (TOMCAT or SPRING)
 *   - a factory taking the chosen context object
 *
 * Exact match takes precedence over prefix. Insertion order preserved per mode.
 * resolve() routes the correct context (tomcatCtx vs springCtx) by ContextKind;
 * if the required context is null, resolve returns null.
 */
public final class CleanerRegistry {

    private static final class Registration {
        final ContextKind kind;
        final Function<Object, Cleaner> factory;
        Registration(ContextKind kind, Function<Object, Cleaner> factory) {
            this.kind = kind;
            this.factory = factory;
        }
    }

    private final Map<String, Registration> byEquals = new LinkedHashMap<>();
    private final Map<String, Registration> byPrefix = new LinkedHashMap<>();

    public CleanerRegistry register(String typeOrPrefix, boolean prefix,
                                    ContextKind kind, Function<Object, Cleaner> factory) {
        Registration r = new Registration(kind, factory);
        (prefix ? byPrefix : byEquals).put(typeOrPrefix, r);
        return this;
    }

    public Cleaner resolve(String findingType, Object tomcatCtx, Object springCtx) {
        if (findingType == null) return null;
        Registration r = byEquals.get(findingType);
        if (r == null) {
            for (Map.Entry<String, Registration> e : byPrefix.entrySet()) {
                if (findingType.startsWith(e.getKey())) {
                    r = e.getValue();
                    break;
                }
            }
        }
        if (r == null) return null;
        Object ctx = (r.kind == ContextKind.SPRING) ? springCtx : tomcatCtx;
        if (ctx == null) return null;
        return r.factory.apply(ctx);
    }

    /**
     * Default registry. Ships all 6 cleaners: 4 Tomcat (v0.7) + 2 Spring (v0.8).
     */
    public static CleanerRegistry defaultRegistry() {
        return new CleanerRegistry()
            .register("tomcat-filter",      false, ContextKind.TOMCAT, TomcatFilterCleaner::new)
            .register("tomcat-servlet",     false, ContextKind.TOMCAT, TomcatServletCleaner::new)
            .register("tomcat-listener-",   true,  ContextKind.TOMCAT, TomcatListenerCleaner::new)
            .register("tomcat-valve",       false, ContextKind.TOMCAT, TomcatValveCleaner::new)
            .register("spring-mapping",     false, ContextKind.SPRING, SpringMappingCleaner::new)
            .register("spring-interceptor", false, ContextKind.SPRING, SpringInterceptorCleaner::new);
    }
}
