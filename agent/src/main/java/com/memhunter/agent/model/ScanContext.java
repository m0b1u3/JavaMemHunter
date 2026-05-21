package com.memhunter.agent.model;

import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
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
 * - The BaselineIndex (empty if no --baseline provided)
 * - A lazy bytecode cache populated on demand by bytecode-* rules
 */
public class ScanContext {

    public final Object applicationContext;
    public final Whitelist whitelist;
    public final boolean explain;
    public final BaselineIndex baselineIndex;

    private final Map<String, BytecodeAnalysis> bytecodeCache = new ConcurrentHashMap<>();
    private static final BytecodeAnalysis MISS =
            new BytecodeAnalysis(Collections.<String>emptySet());

    public ScanContext(Object applicationContext, Whitelist whitelist, boolean explain,
                       BaselineIndex baselineIndex) {
        this.applicationContext = applicationContext;
        this.whitelist = whitelist;
        this.explain = explain;
        this.baselineIndex = baselineIndex != null ? baselineIndex : BaselineIndex.empty();
    }

    /** @deprecated Use 4-arg constructor with explicit baselineIndex. */
    @Deprecated
    public ScanContext(Object applicationContext, Whitelist whitelist, boolean explain) {
        this(applicationContext, whitelist, explain, BaselineIndex.empty());
    }

    public BytecodeAnalysis bytecodeOf(String className) {
        if (className == null) return null;
        BytecodeAnalysis cached = bytecodeCache.get(className);
        if (cached != null) return cached == MISS ? null : cached;

        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(className, resolveClassLoader());
        bytecodeCache.put(className, result == null ? MISS : result);
        return result;
    }

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
