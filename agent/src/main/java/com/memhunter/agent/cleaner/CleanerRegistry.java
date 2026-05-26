package com.memhunter.agent.cleaner;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Type-based dispatch table for Cleaner factories. Two registration modes:
 * <ul>
 *   <li>{@code register(type, prefix=false, factory)} — exact equals match on Finding.type</li>
 *   <li>{@code register(prefix, prefix=true, factory)} — startsWith match on Finding.type</li>
 * </ul>
 *
 * <p>Exact match takes precedence over prefix match. Insertion order is preserved
 * within each mode.
 *
 * <p>Factories take the standardContext and return a fresh Cleaner instance per call,
 * matching AbstractTomcatCleaner's "fresh instance per dispatch" requirement.
 */
public final class CleanerRegistry {

    private final Map<String, Function<Object, Cleaner>> byEquals = new LinkedHashMap<>();
    private final Map<String, Function<Object, Cleaner>> byPrefix = new LinkedHashMap<>();

    public CleanerRegistry register(String typeOrPrefix, boolean prefix,
                                    Function<Object, Cleaner> factory) {
        (prefix ? byPrefix : byEquals).put(typeOrPrefix, factory);
        return this;
    }

    public Cleaner resolve(String findingType, Object standardContext) {
        if (findingType == null) return null;
        Function<Object, Cleaner> f = byEquals.get(findingType);
        if (f != null) return f.apply(standardContext);
        for (Map.Entry<String, Function<Object, Cleaner>> e : byPrefix.entrySet()) {
            if (findingType.startsWith(e.getKey())) return e.getValue().apply(standardContext);
        }
        return null;
    }

    /**
     * Default registry wired with all 4 Tomcat cleaners (filter / servlet /
     * listener-* / valve). Listener uses a prefix match because Finding.type
     * carries the listener subtype suffix (e.g. tomcat-listener-lifecycle).
     */
    public static CleanerRegistry defaultRegistry() {
        return new CleanerRegistry()
            .register("tomcat-filter",    false, TomcatFilterCleaner::new)
            .register("tomcat-servlet",   false, TomcatServletCleaner::new)
            .register("tomcat-listener-", true,  TomcatListenerCleaner::new)
            .register("tomcat-valve",     false, TomcatValveCleaner::new);
    }
}
