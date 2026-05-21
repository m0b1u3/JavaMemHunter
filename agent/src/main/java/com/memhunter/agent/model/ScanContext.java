package com.memhunter.agent.model;

import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import com.memhunter.agent.scoring.bytecode.ClassBytecodeReader;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-scan context passed to every ScoringRule. Carries:
 * - The resolved Spring ApplicationContext (may be null)
 * - The Whitelist
 * - The --explain flag
 * - A lazy bytecode cache populated on demand by bytecode-* rules
 */
public class ScanContext {

    public final Object applicationContext;
    public final Whitelist whitelist;
    public final boolean explain;

    // v0.4: bytecode lookup cache
    private final Map<String, BytecodeAnalysis> bytecodeCache = new ConcurrentHashMap<>();
    private static final BytecodeAnalysis MISS =
            new BytecodeAnalysis(Collections.<String>emptySet());

    public ScanContext(Object applicationContext, Whitelist whitelist, boolean explain) {
        this.applicationContext = applicationContext;
        this.whitelist = whitelist;
        this.explain = explain;
    }

    /**
     * Returns the BytecodeAnalysis for the given className, or null if bytecode
     * cannot be read (CGLIB proxy, bootstrap loader, IO error, etc.).
     * Result is cached for the lifetime of this ScanContext.
     */
    public BytecodeAnalysis bytecodeOf(String className) {
        if (className == null) return null;
        BytecodeAnalysis cached = bytecodeCache.get(className);
        if (cached != null) return cached == MISS ? null : cached;

        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(className, resolveClassLoader());
        bytecodeCache.put(className, result == null ? MISS : result);
        return result;
    }

    /**
     * Test seam: pre-populate the cache to avoid invoking the real reader.
     * Public to allow access from rule tests in a different package.
     * Do NOT call from production code.
     */
    public void putBytecodeForTest(String className, BytecodeAnalysis analysis) {
        if (className == null) return;
        bytecodeCache.put(className, analysis == null ? MISS : analysis);
    }

    private ClassLoader resolveClassLoader() {
        if (applicationContext != null) return applicationContext.getClass().getClassLoader();
        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        return tccl != null ? tccl : ClassLoader.getSystemClassLoader();
    }
}
